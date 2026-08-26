import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain D — Privacy / TCC (HA-D01…HA-D08). Every TCC-backed check reads through
// `ctx.tcc.grantees(service)` (FakeTCCReader keyed by TCCService). A grant with
// `allowed: true` (auth_value ≥ 2) is a holder; `allowed: false` is a denied row
// that must NOT count. A `.noFullDiskAccess` outcome must degrade to `.unknown`
// (the honest-coverage guarantee), never a green pass. HA-D08 (Location Services
// master flag) goes through the privileged root helper, so its unknown case is a
// `.unavailable` read or a permission-denied helper output. All fixtures are
// synthetic: fake bundle ids, fake counts — never a real secret or user path.

func hostAuditTests_D() async {
    // A synthetic non-self grantee that DOES hold the grant (auth_value 2).
    func other(_ client: String = "com.example.app") -> TCCGrant {
        TCCGrant(client: client, clientType: 0, allowed: true, database: .system)
    }
    // A synthetic grantee row that is present but DENIED (auth_value 0) — a holder
    // for schema purposes but not an *allowed* one, so it must count as zero.
    func denied(_ client: String = "com.example.denied") -> TCCGrant {
        TCCGrant(client: client, clientType: 0, allowed: false, database: .system)
    }
    // csec's own grant — matches `HostSelfIdentity.product` (agentIdentifier
    // "com.alexspeller.convenient-security"), so it is expected-self.
    let selfGrant = TCCGrant(
        client: "com.alexspeller.convenient-security",
        clientType: 0, allowed: true, database: .system)

    // MARK: HA-D01 — Full Disk Access grantees (tier F)

    // No allowed grantees at all -> pass.
    await expectStatus("HA-D01", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.allFiles: .grants([])]),
        .pass, "FDA: no grantees -> pass")
    // Only a denied row -> still pass (denied is not a holder).
    await expectStatus("HA-D01", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.allFiles: .grants([denied()])]),
        .pass, "FDA: only a denied grantee -> pass")
    // Only csec itself holds FDA -> expectedSelf.
    await expectStatus("HA-D01", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.allFiles: .grants([selfGrant])]),
        .expectedSelf, "FDA: only csec holds it -> expectedSelf")
    // An unexpected third-party app holds FDA -> fail.
    await expectStatus("HA-D01", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.allFiles: .grants([other()])]),
        .fail, "FDA: unexpected grantee -> fail")
    // csec plus an unexpected app -> fail (self excluded from count, others != 0).
    await expectStatus("HA-D01", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.allFiles: .grants([selfGrant, other()])]),
        .fail, "FDA: csec + unexpected grantee -> fail")
    // No FDA -> unknown, never pass.
    await expectStatus("HA-D01", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.allFiles: .noFullDiskAccess]),
        .unknown, "FDA: no Full Disk Access -> unknown")

    // MARK: HA-D02 — Accessibility grantees (tier F)

    await expectStatus("HA-D02", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.accessibility: .grants([])]),
        .pass, "Accessibility: no grantees -> pass")
    await expectStatus("HA-D02", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.accessibility: .grants([denied()])]),
        .pass, "Accessibility: only denied grantee -> pass")
    await expectStatus("HA-D02", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.accessibility: .grants([other()])]),
        .fail, "Accessibility: one allowed grantee -> fail")
    await expectStatus("HA-D02", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.accessibility: .noFullDiskAccess]),
        .unknown, "Accessibility: no Full Disk Access -> unknown")

    // MARK: HA-D03 — Screen Recording grantees (tier F)

    await expectStatus("HA-D03", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.screenCapture: .grants([])]),
        .pass, "ScreenCapture: no grantees -> pass")
    await expectStatus("HA-D03", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.screenCapture: .grants([other()])]),
        .fail, "ScreenCapture: one allowed grantee -> fail")
    await expectStatus("HA-D03", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.screenCapture: .noFullDiskAccess]),
        .unknown, "ScreenCapture: no Full Disk Access -> unknown")

    // MARK: HA-D04 — Input Monitoring grantees (tier F)

    await expectStatus("HA-D04", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.listenEvent: .grants([])]),
        .pass, "InputMonitoring: no grantees -> pass")
    await expectStatus("HA-D04", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.listenEvent: .grants([other(), other("com.example.two")])]),
        .fail, "InputMonitoring: two allowed grantees -> fail")
    await expectStatus("HA-D04", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.listenEvent: .noFullDiskAccess]),
        .unknown, "InputMonitoring: no Full Disk Access -> unknown")

    // MARK: HA-D05 — Automation (AppleEvents) grantees (tier F)

    await expectStatus("HA-D05", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.appleEvents: .grants([])]),
        .pass, "Automation: no grantees -> pass")
    await expectStatus("HA-D05", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.appleEvents: .grants([other()])]),
        .fail, "Automation: one allowed pair -> fail")
    await expectStatus("HA-D05", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.appleEvents: .noFullDiskAccess]),
        .unknown, "Automation: no Full Disk Access -> unknown")

    // MARK: HA-D06 — Developer Tools grantees (tier F)

    await expectStatus("HA-D06", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.developerTool: .grants([])]),
        .pass, "DeveloperTool: no grantees -> pass")
    await expectStatus("HA-D06", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.developerTool: .grants([other(), other("com.example.two")])]),
        .fail, "DeveloperTool: two allowed grantees -> fail")
    await expectStatus("HA-D06", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.developerTool: .noFullDiskAccess]),
        .unknown, "DeveloperTool: no Full Disk Access -> unknown")

    // MARK: HA-D07 — Camera / Microphone grantees (tier F)
    // Reads BOTH .camera and .microphone; either being .noFullDiskAccess makes
    // the combined result .unknown. FakeTCCReader defaults an absent service to
    // .noFullDiskAccess, so both must be supplied for pass/fail cases.

    await expectStatus("HA-D07", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.camera: .grants([]), .microphone: .grants([])]),
        .pass, "Camera/Mic: no grantees on either -> pass")
    await expectStatus("HA-D07", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.camera: .grants([denied()]), .microphone: .grants([])]),
        .pass, "Camera/Mic: only a denied camera row -> pass")
    await expectStatus("HA-D07", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.camera: .grants([other()]), .microphone: .grants([])]),
        .fail, "Camera/Mic: camera allowed for one app -> fail")
    await expectStatus("HA-D07", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.camera: .grants([]), .microphone: .grants([other()])]),
        .fail, "Camera/Mic: microphone allowed for one app -> fail")
    // Camera readable but microphone read blocked (no FDA on that DB) -> unknown.
    await expectStatus("HA-D07", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.camera: .grants([]), .microphone: .noFullDiskAccess]),
        .unknown, "Camera/Mic: microphone read blocked -> unknown")
    // Both reads blocked -> unknown.
    await expectStatus("HA-D07", in: DomainD_Privacy.checks,
        makeAuditContext(tcc: [.camera: .noFullDiskAccess, .microphone: .noFullDiskAccess]),
        .unknown, "Camera/Mic: no Full Disk Access -> unknown")

    // MARK: HA-D08 — Location Services state (tier R!, informational)
    // Privileged root-helper read of the master flag. Both "1" and "0" are a
    // definite (informational) pass; an unreachable helper or a permission-denied
    // helper output must render .unknown, never a pass.

    await expectStatus("HA-D08", in: DomainD_Privacy.checks,
        makeAuditContext(privileged: [.locationServices: .output(HostHelperResult(exitCode: 0, output: "1"))]),
        .pass, "Location: enabled (1) -> pass")
    await expectStatus("HA-D08", in: DomainD_Privacy.checks,
        makeAuditContext(privileged: [.locationServices: .output(HostHelperResult(exitCode: 0, output: "0"))]),
        .pass, "Location: disabled (0) -> pass")
    // Root helper unreachable -> unknown.
    await expectStatus("HA-D08", in: DomainD_Privacy.checks,
        makeAuditContext(privileged: [.locationServices: .unavailable]),
        .unknown, "Location: root helper unavailable -> unknown")
    // Helper ran but the read was permission-denied -> unknown (not "disabled").
    await expectStatus("HA-D08", in: DomainD_Privacy.checks,
        makeAuditContext(privileged: [.locationServices: .output(HostHelperResult(exitCode: 1, output: "Permission denied"))]),
        .unknown, "Location: permission denied -> unknown")
    // Helper returned an uninterpretable value -> unknown.
    await expectStatus("HA-D08", in: DomainD_Privacy.checks,
        makeAuditContext(privileged: [.locationServices: .output(HostHelperResult(exitCode: 0, output: "garbage"))]),
        .unknown, "Location: uninterpretable value -> unknown")
}
