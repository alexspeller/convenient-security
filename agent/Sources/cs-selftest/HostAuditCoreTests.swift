import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Critical-guarantee tests for the host audit: report ordering, the value-free
// sanitization boundary, the full-registry smoke run (every check returns a
// finding and no privileged/FDA read is ever rendered as a pass when the reader
// is unavailable), the digest binding that gates every reversible apply, and the
// batched-remediation apply loop (atomic per target, re-run safe).

func hostAuditCoreTests() async {
    reportOrderingTests()
    valueFreeGuaranteeTests()
    await registrySmokeTests()
    changeDigestTests()
    await remediationApplyTests()
}

// MARK: report model / ordering

private func makeFinding(
    _ id: String, _ severity: HostSeverity, _ status: FindingStatus,
    onThesis: Bool = false, remediation: RemediationClass = .advise, key: String? = nil
) -> HostFinding {
    HostFinding(id: id, title: id, severity: severity, tier: .runtimeReadable, status: status,
                onThesis: onThesis, evidence: "e", anchor: "a", remediation: remediation, remediationKey: key)
}

private func reportOrderingTests() {
    let ordered = HostAuditReport.ordered([
        makeFinding("HA-Z01", .low, .fail),
        makeFinding("HA-A01", .high, .fail, onThesis: true),
        makeFinding("HA-B01", .high, .fail),
        makeFinding("HA-C01", .medium, .fail, onThesis: true),
    ])
    check(ordered.first?.id == "HA-A01", "ordering: on-thesis high leads the report")
    check(ordered.map(\.id) == ["HA-A01", "HA-C01", "HA-B01", "HA-Z01"],
          "ordering: on-thesis first, then severity, then id")

    // isBatchFixable only for failing auto/autoPrivileged findings with a key.
    check(makeFinding("HA-X", .medium, .fail, remediation: .autoPrivileged, key: "HA-X").isBatchFixable,
          "batchFixable: failing autoPrivileged with a key is fixable")
    check(!makeFinding("HA-X", .medium, .pass, remediation: .autoPrivileged, key: "HA-X").isBatchFixable,
          "batchFixable: a passing check is never fixable")
    check(!makeFinding("HA-X", .medium, .fail, remediation: .advise, key: "HA-X").isBatchFixable,
          "batchFixable: an advise finding is never batch-fixable")
    check(!makeFinding("HA-X", .medium, .fail, remediation: .guided, key: "HA-X").isBatchFixable,
          "batchFixable: a guided finding is never batch-fixable")
}

// MARK: value-free sanitization boundary

private func valueFreeGuaranteeTests() {
    let meta = HostCheckMeta(id: "HA-T01", title: "t", severity: .low, tier: .runtimeReadable, anchor: "a")
    // Evidence carrying terminal control + bidi override characters must be
    // neutralized before it can reach a report/log.
    let nasty = "secret\u{202e}\u{0007}\nAKIA1234\u{200f}"
    let finding = meta.finding(.fail, evidence: nasty, anchorOverride: "path\u{202e}x")
    for scalar in finding.evidence.unicodeScalars {
        check(!CharacterSet.controlCharacters.contains(scalar),
              "value-free: evidence has no control characters")
    }
    check(!finding.evidence.unicodeScalars.contains { $0.value == 0x202e },
          "value-free: evidence strips the RTL-override bidi character")
    check(!finding.anchor.unicodeScalars.contains { $0.value == 0x202e },
          "value-free: anchor strips the RTL-override bidi character")
    // A non-fail status never carries a remediation key into the batch.
    check(meta.finding(.pass, evidence: "ok").remediationKey == nil,
          "value-free: a pass never carries a remediation key")
}

// MARK: full-registry smoke — honest coverage

private func registrySmokeTests() async {
    // Everything unavailable: no command output, no privileged reads, no FDA.
    let ctx = makeAuditContext()
    let report = await HostAuditEngine().run(ctx)
    check(report.findings.count == HostCheckRegistry.all.count,
          "registry: every registered check produced a finding")
    check(Set(report.findings.map(\.id)).count == report.findings.count,
          "registry: finding ids are unique (no duplicate catalog id)")
    // No privileged (R!) or FDA (F) check may report pass when its reader is down.
    for finding in report.findings where finding.tier == .runtimePrivileged || finding.tier == .fullDiskAccess {
        check(finding.status != .pass,
              "honest coverage: \(finding.id) (\(finding.tier.rawValue)) is not a pass when its reader is unavailable")
    }
    // The report is deterministically ordered and every evidence string is clean.
    for finding in report.findings {
        for scalar in finding.evidence.unicodeScalars {
            check(!CharacterSet.controlCharacters.contains(scalar),
                  "value-free: \(finding.id) evidence is control-character free")
        }
    }
}

// MARK: digest binding (the apply gate)

private func changeDigestTests() {
    let changes: [HostRootChange] = [
        .enableApplicationFirewall, .setFirewallStealthMode(true), .setFirewallStealthMode(false),
        .setSharingService(.remoteLogin, enabled: false), .disableRootAccount,
        .clearBootArgsToken(.amfiGetOutOfMyWay), .setSoftwareUpdateFlag(.configDataInstall, enabled: true),
    ]
    let digests = changes.compactMap { try? $0.digest() }
    check(digests.count == changes.count, "digest: every change hashes")
    check(Set(digests).count == digests.count, "digest: distinct changes hash distinctly")
    // Determinism: the same change hashes identically every time (the helper
    // relies on this to independently recompute and verify).
    check((try? HostRootChange.enableApplicationFirewall.digest())
            == (try? HostRootChange.enableApplicationFirewall.digest()),
          "digest: identical change is deterministic")
    check((try? HostRootChange.setFirewallStealthMode(true).digest())
            != (try? HostRootChange.setFirewallStealthMode(false).digest()),
          "digest: a changed associated value changes the digest")
}

// MARK: remediation apply loop — atomic per target, selection, re-run safety

private func remediationApplyTests() async {
    let firewall = HostRemediationPlan(
        item: HostRemediationItem(key: "HA-C01", title: "firewall", detail: "d", requiresRoot: true),
        privileged: [.enableApplicationFirewall], local: [])
    let root = HostRemediationPlan(
        item: HostRemediationItem(key: "HA-G04", title: "root", detail: "d", requiresRoot: true),
        privileged: [.disableRootAccount], local: [])
    let guest = HostRemediationPlan(
        item: HostRemediationItem(key: "HA-G05", title: "guest", detail: "d", requiresRoot: true),
        privileged: [.disableGuestAccount], local: [])
    let plans = [firewall, root, guest]

    // One change fails; the others still apply (atomic per target, not all-or-nothing).
    let stub = StubPrivilegedHostOps(
        applies: [.disableRootAccount: .failed("nope")], available: true)
    let ctx = makeAuditContext()
    let ctxWithStub = HostAuditContext(
        commands: FakeCommandRunner(), privileged: stub, tcc: FakeTCCReader(),
        files: FakeFileInspector(), environment: ctx.environment,
        baseline: InMemoryBaselineStore())

    let summary = await HostRemediationCoordinator.applySelected(
        plans, selectedKeys: ["HA-C01", "HA-G04"], ctx: ctxWithStub)
    check(summary.approved, "remediation: applySelected reports approved")
    check(summary.applied == ["HA-C01"], "remediation: the working target applied")
    check(summary.failed == ["HA-G04"], "remediation: the failing target is reported failed")
    check(summary.skipped == ["HA-G05"], "remediation: the deselected target is skipped, not applied")

    // Re-run with all selected and everything available → idempotent success.
    let allOk = HostAuditContext(
        commands: FakeCommandRunner(), privileged: StubPrivilegedHostOps(available: true),
        tcc: FakeTCCReader(), files: FakeFileInspector(), environment: ctx.environment,
        baseline: InMemoryBaselineStore())
    let rerun = await HostRemediationCoordinator.applySelected(
        plans, selectedKeys: plans.map(\.item.key), ctx: allOk)
    check(rerun.applied.count == 3 && rerun.failed.isEmpty,
          "remediation: re-run with all available applies every selected target")
}
