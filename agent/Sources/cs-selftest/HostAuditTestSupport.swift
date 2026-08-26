import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Shared helpers for the host-audit self-tests. `check(_:_:)` and `failures`
// come from main.swift (module globals). These builders assemble a
// `HostAuditContext` from fakes so each check can be evaluated against captured,
// synthetic, value-free fixture output.

/// Assemble a fake audit context. Everything defaults to "nothing available" so a
/// test opts in exactly the readers it exercises.
func makeAuditContext(
    commands: [String: HostCommandResult] = [:],
    commandFallback: @escaping @Sendable (HostCommand) -> HostCommandResult = { _ in .unavailable },
    privileged: [HostRootRead: HostPrivilegedRead] = [:],
    privilegedAvailable: Bool = false,
    tcc: [TCCService: TCCReadOutcome] = [:],
    files: FakeFileInspector = FakeFileInspector(),
    environment: [String: String] = ["PATH": "/usr/bin:/bin"],
    selfIdentity: HostSelfIdentity = .product,
    scanFilesystem: Bool = false
) -> HostAuditContext {
    HostAuditContext(
        commands: FakeCommandRunner(commands, fallback: commandFallback),
        privileged: StubPrivilegedHostOps(reads: privileged, available: privilegedAvailable),
        tcc: FakeTCCReader(tcc),
        files: files,
        environment: environment,
        baseline: InMemoryBaselineStore(),
        selfIdentity: selfIdentity,
        options: HostAuditOptions(scanFilesystem: scanFilesystem)
    )
}

/// Evaluate a single check by catalog id against a context, or fail the suite.
func evaluateAudit(_ id: String, in checks: [any HostCheck], _ ctx: HostAuditContext) async -> HostFinding? {
    guard let check = checks.first(where: { $0.id == id }) else {
        check(false, "\(id): check not found in its domain registry")
        return nil
    }
    return await check.evaluate(ctx)
}

/// Assert a check produces the expected status; also asserts the id round-trips.
func expectStatus(
    _ id: String, in checks: [any HostCheck], _ ctx: HostAuditContext,
    _ expected: FindingStatus, _ label: String
) async {
    guard let finding = await evaluateAudit(id, in: checks, ctx) else { return }
    check(finding.id == id, "\(id): finding id round-trips")
    check(finding.status == expected,
          "\(label) [\(id) expected \(expected.rawValue), got \(finding.status.rawValue)]")
}

/// A convenience `HostCommandResult` for a successful stdout capture.
func ok(_ stdout: String) -> HostCommandResult { HostCommandResult(exitCode: 0, standardOutput: stdout) }
