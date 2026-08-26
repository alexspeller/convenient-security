import Foundation
import CSECRootProtocol

// Domain K — csec's own coverage & integration (catalog HA-K01…HA-K05). ★ on-thesis.
//
// This domain is unusual: rather than probing macOS, it verifies that csec itself
// is actually protecting what it claims. It therefore reuses csec's *own* internal
// APIs (this file is inside the ConvenientSecurity module, so they are visible):
//   - `CodingAgentSetup.detect` / `.plan` — the exact same parser `csec setup`
//     uses to install the fail-closed PreToolUse redaction hook, so an audit here
//     shares one source of truth with setup (HA-K01, HA-K02).
//   - `StartupSecurityReport.currentAgent()` — the daemon-startup self-attestation
//     generalized into a user-facing verdict for csecd/csec/csec-rootd (HA-K03).
//
// Value-free discipline holds exactly as elsewhere: these checks read config JSON
// *structure* and code-signing *state*, never a credential value; evidence uses
// enum names, action labels, and counts, never file contents or raw paths.

public enum DomainK_Coverage {
    public static var checks: [any HostCheck] {
        [RedactionHookPresent(), HookNotShadowed(), AgentAndHelpersHealthy(),
         StrongDeliveryPath(), PlaintextOriginalsRemediated()]
    }

    /// The durable installed `csec` launcher path, derived from the running
    /// agent's own code-signed executable path (csecd and the csec launcher ship
    /// side-by-side in the same install directory). This is the path the
    /// fail-closed hook must invoke; used to plan against each agent's config.
    /// Value-free: a system install path, never a credential.
    static func durableCSECPath() -> String {
        let agentExecutable = StartupSecurityReport.currentAgent().executablePath
        let directory = (agentExecutable as NSString).deletingLastPathComponent
        return (directory as NSString).appendingPathComponent("csec")
    }

    /// Detect installed coding agents, tolerating any parser failure. Only
    /// `detected` clients (an executable on PATH or an existing config) are
    /// relevant to HA-K01/HA-K02.
    static func detectedAgents(_ ctx: HostAuditContext) -> [CodingAgentDetection] {
        guard let detections = try? CodingAgentSetup.detect(
            homeDirectory: ctx.files.homeDirectory,
            pathEnvironment: ctx.environment["PATH"]
        ) else {
            return []
        }
        return detections.filter(\.detected)
    }

    // MARK: HA-K01

    /// Redaction active in each detected coding agent — the exact fail-closed csec
    /// `PreToolUse` hook, pointing at the durable installed `csec`, is present.
    struct RedactionHookPresent: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-K01",
            title: "Redaction active in each detected coding agent",
            severity: .medium, tier: .runtimeReadable, onThesis: true,
            anchor: "Run `csec setup` to (re)install the fail-closed PreToolUse hook")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let agents = DomainK_Coverage.detectedAgents(ctx)
            guard !agents.isEmpty else {
                return meta.finding(.notApplicable, evidence: "No supported coding agent (Claude Code / Codex) is installed on this Mac.")
            }
            let csecPath = DomainK_Coverage.durableCSECPath()
            var present = 0
            var missing: [String] = []
            var unreadable: [String] = []
            for agent in agents {
                let label = agent.client.rawValue
                do {
                    let plan = try CodingAgentSetup.plan(
                        detection: agent,
                        csecExecutablePath: csecPath
                    )
                    switch plan.action {
                    case .unchanged:
                        present += 1
                    case .create, .merge:
                        // Hook absent or points elsewhere — setup would need to
                        // write it. That is a missing-redaction finding.
                        missing.append(label)
                    case .blocked:
                        // A conflicting/blocked state — HA-K02 owns the verdict on
                        // shadowing; here it means the exact csec hook is not the
                        // one that would run, so redaction is not confirmed active.
                        missing.append(label)
                    }
                } catch {
                    // Unsafe/non-user-owned config or a malformed file: cannot
                    // safely determine hook state → unknown, never a pass.
                    unreadable.append(label)
                }
            }
            if !unreadable.isEmpty && missing.isEmpty {
                return meta.finding(.unknown, evidence: "\(unreadable.count) detected coding agent(s) have an unsafe or unreadable configuration; the csec redaction hook could not be verified.")
            }
            if !missing.isEmpty {
                let unknownNote = unreadable.isEmpty ? "" : " \(unreadable.count) further agent(s) were unreadable."
                return meta.finding(.fail, evidence: "\(missing.count) of \(agents.count) detected coding agent(s) are missing the fail-closed csec redaction hook.\(unknownNote)")
            }
            return meta.finding(.pass, evidence: "The fail-closed csec redaction hook is present in all \(present) detected coding agent(s).")
        }
    }

    // MARK: HA-K02

    /// Hook not shadowed — `disableAllHooks`, a malformed policy, or a competing
    /// PreToolUse handler that would stop the csec hook from running.
    struct HookNotShadowed: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-K02",
            title: "Coding-agent redaction hook not shadowed",
            severity: .medium, tier: .runtimeReadable, onThesis: true,
            anchor: "Remove `disableAllHooks` / competing PreToolUse handlers, then rerun `csec setup`")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let agents = DomainK_Coverage.detectedAgents(ctx)
            guard !agents.isEmpty else {
                return meta.finding(.notApplicable, evidence: "No supported coding agent (Claude Code / Codex) is installed on this Mac.")
            }
            let csecPath = DomainK_Coverage.durableCSECPath()
            var shadowed: [String] = []
            var unreadable: [String] = []
            for agent in agents {
                let label = agent.client.rawValue
                do {
                    let plan = try CodingAgentSetup.plan(
                        detection: agent,
                        csecExecutablePath: csecPath
                    )
                    // `.blocked` is the parser's signal for a policy or competing
                    // hook that would suppress or supersede csec's hook
                    // (disableAllHooks=true, or a duplicate/older csec handler).
                    if plan.action == .blocked {
                        shadowed.append(label)
                    }
                } catch {
                    // Malformed disableAllHooks / unsafe config throws — cannot
                    // confirm the hook runs unshadowed → unknown, never a pass.
                    unreadable.append(label)
                }
            }
            if !shadowed.isEmpty {
                let unknownNote = unreadable.isEmpty ? "" : " \(unreadable.count) further agent(s) were unreadable."
                return meta.finding(.fail, evidence: "\(shadowed.count) detected coding agent(s) suppress or shadow the csec hook (disableAllHooks or a competing PreToolUse handler).\(unknownNote)")
            }
            if !unreadable.isEmpty {
                return meta.finding(.unknown, evidence: "\(unreadable.count) detected coding agent(s) have an unsafe or malformed configuration; whether the csec hook is shadowed could not be verified.")
            }
            return meta.finding(.pass, evidence: "No detected coding agent disables all hooks or shadows the csec hook with a competing handler.")
        }
    }

    // MARK: HA-K03

    /// Agent + helpers healthy — csecd/csec/csec-rootd signature, hardened runtime,
    /// entitlements, keychain group, and SIP match the signed-device release gates.
    struct AgentAndHelpersHealthy: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-K03",
            title: "csec agent and helpers healthy",
            severity: .medium, tier: .runtimeReadable, onThesis: true,
            anchor: "Reinstall csec from the signed release; verify SIP is enabled")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let report = StartupSecurityReport.currentAgent()
            if report.productionReady {
                return meta.finding(.pass, evidence: "The running csec agent is production-ready: valid signature, hardened runtime, no dangerous entitlements, expected identity, and SIP enabled.")
            }
            // Name the failing field(s) value-free — never emit the executable path,
            // identifier, or team id, only the boolean/enum state.
            var failing: [String] = []
            if !report.signatureValid { failing.append("code signature invalid") }
            if !report.productRequirementMatches { failing.append("product code requirement not satisfied") }
            if !report.hardenedRuntime { failing.append("hardened runtime off") }
            if !report.dangerousEntitlements.isEmpty {
                failing.append("\(report.dangerousEntitlements.count) dangerous entitlement(s)")
            }
            if !report.applicationIdentifierPresent { failing.append("application-identifier missing") }
            if !report.keychainAccessGroupPresent { failing.append("keychain-access-group missing") }
            if report.sipStatus != .enabled { failing.append("SIP \(report.sipStatus.rawValue)") }
            let detail = failing.isEmpty ? "one or more health gates" : failing.joined(separator: ", ")
            return meta.finding(.fail, evidence: "The running csec agent is not production-ready: \(detail).")
        }
    }

    // MARK: HA-K04

    /// Consumers on a strong delivery path — high-impact references still delivered
    /// via `csec exec` env-compat when a stronger path exists.
    struct StrongDeliveryPath: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-K04",
            title: "Consumers on a strong delivery path",
            severity: .low, tier: .runtimeReadable,
            anchor: "Review per-reference delivery in `csec` and prefer heap / credential-protocol / inherited-fd / protected-file over env-compat")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // Delivery-plan state is memory-only and expires with each grant; csec
            // deliberately keeps no durable, value-free registry of active
            // references and their mechanisms that this read-only audit can consult
            // without unlocking secret material. With no safe source to enumerate,
            // honest coverage requires reporting this unverifiable rather than a
            // green pass. (See docs/host-audit-catalog.md HA-K04.)
            return meta.finding(.unknown, evidence: "Per-reference delivery mechanisms are memory-only and not durably recorded; whether high-impact references use a strong delivery path cannot be verified from a read-only audit.")
        }
    }

    // MARK: HA-K05

    /// Known plaintext originals not yet remediated — imported references whose
    /// plaintext original file still exists on disk (M/V done, R outstanding).
    struct PlaintextOriginalsRemediated: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-K05",
            title: "Known plaintext originals not yet remediated",
            severity: .low, tier: .runtimeReadable,
            anchor: "Complete the migration tracker's remove (R) step for imported references")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // The secrets-migration tracker (M/V/R state) is a per-project artifact
            // with no fixed, stable location the audit can safely resolve, and csec
            // exposes no durable in-process API mapping imported references to their
            // originating plaintext files. Cross-referencing tracker state against
            // on-disk originals is therefore not safely determinable here; report
            // it as unverifiable rather than fabricate a pass.
            // (See docs/host-audit-catalog.md HA-K05.)
            return meta.finding(.unknown, evidence: "The secrets-migration tracker is not at a fixed audit-readable location and no durable reference-to-original mapping is exposed; surviving plaintext originals of imported references cannot be verified from a read-only audit.")
        }
    }
}
