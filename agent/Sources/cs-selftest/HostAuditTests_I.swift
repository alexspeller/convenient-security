import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain I — Time, logging & auditability (catalog HA-I01…HA-I03).
//
// Value-free fixtures only: synthetic on/off strings and fake flag toggles; no
// real NTP host, no path under /Users, no credential value. Each fixture is keyed
// by the EXACT privileged read case or file path the check reads.
//
//   HA-I01 NetworkTime            — ctx.privileged.read(.networkTime)  (tier R!)
//   HA-I02 AuditTrail             — ctx.files.fileExists("/etc/security/audit_control")  (advise-only)
//   HA-I03 CrashAnalyticsSharing  — ctx.privileged.read(.crashReporterSubmission)  (privileged read)

func hostAuditTests_I() async {
    // MARK: HA-I01 — Network time synchronization on (privileged .networkTime)

    // PASS: root read reports "Network Time: On".
    await expectStatus("HA-I01", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [
            .networkTime: .output(HostHelperResult(exitCode: 0, output: "Network Time: On"))
        ]),
        .pass, "network time on -> pass")

    // FAIL: root read reports "Network Time: Off".
    await expectStatus("HA-I01", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [
            .networkTime: .output(HostHelperResult(exitCode: 0, output: "Network Time: Off"))
        ]),
        .fail, "network time off -> fail")

    // UNKNOWN: the root helper was not reachable.
    await expectStatus("HA-I01", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [.networkTime: .unavailable]),
        .unknown, "network time helper unavailable -> unknown")

    // UNKNOWN: the unprivileged admin-gate refusal (exits 0, so the STRING must be
    // detected — never trust the exit code). Must never map to pass.
    await expectStatus("HA-I01", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [
            .networkTime: .output(HostHelperResult(exitCode: 0, output: "You need administrator access to run this tool... exiting!"))
        ]),
        .unknown, "network time admin-gate refusal (exit 0) -> unknown, never pass")

    // UNKNOWN: output that names neither on nor off is undeterminable.
    await expectStatus("HA-I01", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [
            .networkTime: .output(HostHelperResult(exitCode: 0, output: "unexpected systemsetup output"))
        ]),
        .unknown, "network time unparseable -> unknown")

    // MARK: HA-I02 — Audit trail (OpenBSM deprecated; advise-only, never pass/fail)

    // OpenBSM absent (the modern-macOS default): advisory notApplicable, not a fail.
    await expectStatus("HA-I02", in: DomainI_Logging.checks,
        makeAuditContext(files: FakeFileInspector()),
        .notApplicable, "openbsm absent -> notApplicable (advisory), never fail")

    // A surviving legacy audit_control file: still advisory notApplicable, never pass.
    await expectStatus("HA-I02", in: DomainI_Logging.checks,
        makeAuditContext(files: FakeFileInspector(
            texts: ["/etc/security/audit_control": "flags:lo,aa\n"]
        )),
        .notApplicable, "legacy audit_control present -> notApplicable (informational), never pass")

    // MARK: HA-I03 — Crash/analytics not shared externally (privileged .crashReporterSubmission)

    // PASS: both submission flags off.
    await expectStatus("HA-I03", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [
            .crashReporterSubmission: .output(HostHelperResult(exitCode: 0, output: """
            {
              AutoSubmit = 0;
              ThirdPartyDataSubmit = 0;
            }
            """))
        ]),
        .pass, "crash sharing both flags off -> pass")

    // FAIL: third-party (and auto) submission on.
    await expectStatus("HA-I03", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [
            .crashReporterSubmission: .output(HostHelperResult(exitCode: 0, output: """
            {
              AutoSubmit = 1;
              ThirdPartyDataSubmit = 1;
            }
            """))
        ]),
        .fail, "crash sharing third-party on -> fail")

    // FAIL: only AutoSubmit on (third-party off) still shares to Apple.
    await expectStatus("HA-I03", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [
            .crashReporterSubmission: .output(HostHelperResult(exitCode: 0, output: """
            {
              AutoSubmit = 1;
              ThirdPartyDataSubmit = 0;
            }
            """))
        ]),
        .fail, "crash sharing auto-submit on -> fail")

    // UNKNOWN: the root helper was not reachable.
    await expectStatus("HA-I03", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [.crashReporterSubmission: .unavailable]),
        .unknown, "crash sharing helper unavailable -> unknown")

    // UNKNOWN: unprivileged read returns "does not exist"; never infer off.
    await expectStatus("HA-I03", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [
            .crashReporterSubmission: .output(HostHelperResult(exitCode: 0, output: "Domain /Library/Application Support/CrashReporter/SubmitDiagInfo does not exist"))
        ]),
        .unknown, "crash sharing domain does-not-exist -> unknown, never pass")

    // UNKNOWN: readable output but neither flag key present.
    await expectStatus("HA-I03", in: DomainI_Logging.checks,
        makeAuditContext(privileged: [
            .crashReporterSubmission: .output(HostHelperResult(exitCode: 0, output: """
            {
              SomeOtherKey = 1;
            }
            """))
        ]),
        .unknown, "crash sharing no submission flags found -> unknown")
}
