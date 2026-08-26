import Foundation
import CSECRootProtocol

// Domain I — Time, logging & auditability (catalog HA-I01…HA-I03).
//
// Same shape as `DomainA_Platform`: each check reads the injected
// `HostAuditContext`, parses tolerantly, and returns a value-free `HostFinding`
// via `meta.finding(...)`. Honest coverage: a privileged read that comes back
// `.unavailable` (or an admin-gate refusal) is reported `.unknown`, never a
// pass; the NTP server host, crash-report contents, and any account/path
// detail never leave the parser — only on/off and enum-named state does.

public enum DomainI_Logging {
    public static var checks: [any HostCheck] {
        [NetworkTime(), AuditTrail(), CrashAnalyticsSharing()]
    }

    // MARK: HA-I01

    struct NetworkTime: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-I01", title: "Network time synchronization on",
            severity: .low, tier: .runtimePrivileged,
            remediation: .autoPrivileged, remediationKey: "HA-I01",
            anchor: "System Settings → General → Date & Time → Set time automatically")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.networkTime) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "Network-time state needs the root helper (systemsetup refuses non-admin callers).")
            case let .output(result):
                let out = result.output.lowercased()
                // The unprivileged admin-gate refusal exits 0 with this string, so
                // detect the refusal STRING first — never trust the exit code.
                if out.contains("need administrator access") {
                    return meta.finding(.unknown, evidence: "systemsetup returned an admin-access refusal; network-time state could not be read.")
                }
                // Parse on/off only; the configured NTP server host is discarded.
                if out.contains("network time: on") {
                    return meta.finding(.pass, evidence: "Automatic network time synchronization is on.")
                }
                if out.contains("network time: off") {
                    return meta.finding(.fail, evidence: "Automatic network time synchronization is off; certificate and token validation depend on a correct clock.")
                }
                return meta.finding(.unknown, evidence: "Network-time state could not be determined from the systemsetup output.")
            }
        }
    }

    // MARK: HA-I02

    struct AuditTrail: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-I02", title: "Audit trail (OpenBSM deprecated; prefer an Endpoint-Security tool)",
            severity: .low, tier: .runtimeReadable, remediation: .advise,
            anchor: "Adopt an Endpoint-Security-based auditing tool (ties to HA-A06/HA-B08); OpenBSM/auditd is deprecated")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // OpenBSM/auditd is deprecated on modern macOS. Its absence is the
            // expected default, never a failure; a surviving legacy config is only
            // an informational note. Either way the recommendation is an ES-based
            // tool, so this check is advisory (notApplicable), never pass/fail.
            let legacyPresent = ctx.files.fileExists("/etc/security/audit_control")
            if legacyPresent {
                return meta.finding(.notApplicable, evidence: "A legacy OpenBSM audit_control file is present, but the OpenBSM stack is deprecated; prefer an Endpoint-Security-based auditing tool.")
            }
            return meta.finding(.notApplicable, evidence: "OpenBSM/auditd is deprecated and absent on this macOS train; there is no kernel audit trail — use an Endpoint-Security-based tool instead.")
        }
    }

    // MARK: HA-I03

    struct CrashAnalyticsSharing: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-I03", title: "Crash/analytics not shared externally",
            severity: .low, tier: .runtimeReadable, remediation: .advise,
            anchor: "System Settings → Privacy & Security → Analytics & Improvements (Share Mac Analytics / with app developers)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // Authoritative flags (AutoSubmit / ThirdPartyDataSubmit) live under the
            // root:admin-owned SubmitDiagInfo prefs, so the authoritative read is a
            // privileged hop. If the helper is unavailable we cannot read the
            // sharing state (an unprivileged `defaults read` reports "does not
            // exist"), so report `unknown` rather than inferring anything.
            switch await ctx.privileged.read(.crashReporterSubmission) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "Crash/analytics submission flags need the root helper (the SubmitDiagInfo prefs are root-owned); sharing state could not be read.")
            case let .output(result):
                let out = result.output.lowercased()
                if out.contains("does not exist") {
                    return meta.finding(.unknown, evidence: "The SubmitDiagInfo submission prefs were not readable; crash/analytics sharing state could not be determined.")
                }
                let autoSubmit = DomainI_Logging.plistFlagIsOn(out, key: "autosubmit")
                let thirdParty = DomainI_Logging.plistFlagIsOn(out, key: "thirdpartydatasubmit")
                if autoSubmit == nil && thirdParty == nil {
                    return meta.finding(.unknown, evidence: "No submission flags were found in the SubmitDiagInfo prefs; crash/analytics sharing state could not be determined.")
                }
                if autoSubmit == true || thirdParty == true {
                    let scope = (thirdParty == true)
                        ? "diagnostics are shared with Apple and third-party developers"
                        : "diagnostics are auto-submitted to Apple"
                    return meta.finding(.fail, evidence: "Crash/analytics sharing is on (\(scope)); crash reports can contain memory contents.")
                }
                return meta.finding(.pass, evidence: "Crash/analytics auto-submission is off; nothing is shared externally.")
            }
        }
    }

    /// Parse a `SubmitDiagInfo`-style plist flag from lowercased command output:
    /// looks for `<key> = <0|1>` (as `defaults read` prints it) and returns
    /// whether the flag is on. Value-free: reads only the boolean-ish token.
    /// Returns nil when the key is absent.
    static func plistFlagIsOn(_ lowercasedOutput: String, key: String) -> Bool? {
        for rawLine in lowercasedOutput.split(whereSeparator: { $0 == "\n" || $0 == ";" }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix(key) else { continue }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("1") || value.hasPrefix("true") || value.hasPrefix("yes") {
                return true
            }
            if value.hasPrefix("0") || value.hasPrefix("false") || value.hasPrefix("no") {
                return false
            }
        }
        return nil
    }
}
