import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain K — csec's own coverage & integration (HA-K01…HA-K05).
//
// This domain is deliberately NOT unit-fakeable the way the macOS-probing
// domains are. Its two dependencies read real host state that the audit fakes
// cannot intercept:
//   - HA-K01 / HA-K02 call `CodingAgentSetup.detect(...)` / `.plan(...)`, which
//     resolve against the REAL filesystem and the REAL PATH (they take the home
//     dir and PATH string from the context, but then stat/read actual files —
//     they never route through `ctx.files`). There is no injection seam to feed
//     synthetic settings.json fixtures.
//   - HA-K03 calls `StartupSecurityReport.currentAgent()`, which inspects the
//     running process's real code signature, entitlements, and SIP state — again
//     with no injection seam.
//   - HA-K04 / HA-K05 have no safe durable source to read and are hard-coded to
//     report `.unknown` (honest-coverage guarantee).
//
// So per the domain guidance every K check gets a SMOKE assertion: evaluate it
// against a default context and assert the finding round-trips its id, carries
// non-empty value-free evidence, and lands on a valid `FindingStatus`. HA-K04
// and HA-K05 additionally have a deterministic `.unknown` verdict we assert
// exactly (they never depend on host state), which is itself the honest-coverage
// (never-a-false-pass) check for those two ids.
func hostAuditTests_K() async {
    // The valid outcomes any check may legitimately return. A K check must land
    // on one of these — and must never silently vanish or throw.
    let validStatuses: Set<FindingStatus> = [
        .pass, .fail, .unknown, .expectedSelf, .notApplicable,
    ]

    // HA-K01 — Redaction active in each detected coding agent.
    // SMOKE: real-FS agent detection + hook planning, no injection seam.
    if let f = await evaluateAudit("HA-K01", in: DomainK_Coverage.checks, makeAuditContext()) {
        check(f.id == "HA-K01", "HA-K01: finding id round-trips")
        check(!f.evidence.isEmpty, "HA-K01: emits non-empty value-free evidence")
        check(validStatuses.contains(f.status),
              "HA-K01: status is a valid FindingStatus [got \(f.status.rawValue)]")
    }

    // HA-K02 — Coding-agent redaction hook not shadowed.
    // SMOKE: same real-FS agent detection + shadow planning, no injection seam.
    if let f = await evaluateAudit("HA-K02", in: DomainK_Coverage.checks, makeAuditContext()) {
        check(f.id == "HA-K02", "HA-K02: finding id round-trips")
        check(!f.evidence.isEmpty, "HA-K02: emits non-empty value-free evidence")
        check(validStatuses.contains(f.status),
              "HA-K02: status is a valid FindingStatus [got \(f.status.rawValue)]")
    }

    // HA-K03 — csec agent and helpers healthy.
    // SMOKE: reads the running process's real code signature via
    // StartupSecurityReport.currentAgent(); no injection seam.
    if let f = await evaluateAudit("HA-K03", in: DomainK_Coverage.checks, makeAuditContext()) {
        check(f.id == "HA-K03", "HA-K03: finding id round-trips")
        check(!f.evidence.isEmpty, "HA-K03: emits non-empty value-free evidence")
        check(validStatuses.contains(f.status),
              "HA-K03: status is a valid FindingStatus [got \(f.status.rawValue)]")
    }

    // HA-K04 — Consumers on a strong delivery path.
    // Deterministic honest-coverage: delivery-plan state is memory-only with no
    // safe durable source, so this ALWAYS reports .unknown and never a green pass.
    await expectStatus("HA-K04", in: DomainK_Coverage.checks, makeAuditContext(),
        .unknown, "HA-K04 delivery mechanisms unrecorded -> unknown, never pass")
    if let f = await evaluateAudit("HA-K04", in: DomainK_Coverage.checks, makeAuditContext()) {
        check(!f.evidence.isEmpty, "HA-K04: emits non-empty value-free evidence")
    }

    // HA-K05 — Known plaintext originals not yet remediated.
    // Deterministic honest-coverage: the migration tracker has no fixed
    // audit-readable location and no durable reference-to-original mapping is
    // exposed, so this ALWAYS reports .unknown and never a green pass.
    await expectStatus("HA-K05", in: DomainK_Coverage.checks, makeAuditContext(),
        .unknown, "HA-K05 tracker not audit-readable -> unknown, never pass")
    if let f = await evaluateAudit("HA-K05", in: DomainK_Coverage.checks, makeAuditContext()) {
        check(!f.evidence.isEmpty, "HA-K05: emits non-empty value-free evidence")
    }
}
