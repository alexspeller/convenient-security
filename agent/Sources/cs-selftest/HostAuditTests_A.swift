import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain A — Platform & kernel integrity (HA-A01…HA-A09).
//
// Value-free unit tests: every fixture is synthetic (fake bundle ids, fake
// tokens, fake version strings) — never a real secret, token, or path under
// /Users. Each check gets a PASS (secure state) and FAIL (insecure state); the
// unverifiable / privileged tiers (HA-A05, HA-A08) additionally assert the
// honest UNKNOWN state and that it is never rendered as a pass.

func hostAuditTests_A() async {
    // MARK: HA-A01 — SIP, command label "csrutil.status"

    await expectStatus("HA-A01", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "csrutil.status": ok("System Integrity Protection status: enabled.")]),
        .pass, "SIP fully enabled -> pass")

    await expectStatus("HA-A01", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "csrutil.status": ok("System Integrity Protection status: disabled.")]),
        .fail, "SIP disabled -> fail")

    await expectStatus("HA-A01", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "csrutil.status": ok("""
            System Integrity Protection status: enabled (Custom Configuration).

            \tApple Internal: disabled
            \tKext Signing: disabled
            \tFilesystem Protections: enabled
            """)]),
        .fail, "SIP custom/partial configuration -> fail")

    await expectStatus("HA-A01", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "csrutil.status": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "SIP status unreadable -> unknown")

    // MARK: HA-A02 — Signed System Volume, label "csrutil.authenticated-root"

    await expectStatus("HA-A02", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "csrutil.authenticated-root": ok("Authenticated Root status: enabled")]),
        .pass, "SSV seal intact -> pass")

    await expectStatus("HA-A02", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "csrutil.authenticated-root": ok("Authenticated Root status: disabled")]),
        .fail, "SSV seal broken -> fail")

    await expectStatus("HA-A02", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "csrutil.authenticated-root": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "authenticated-root unreadable -> unknown")

    // MARK: HA-A03 — Clean boot-args, label "nvram.boot-args".
    // `nvram` exits non-zero when the variable is unset — the secure default —
    // so a non-succeeding result maps to .unset -> pass (never unknown).

    await expectStatus("HA-A03", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "nvram.boot-args": HostCommandResult(
                exitCode: 1,
                standardError: "nvram: Error getting variable - 'boot-args': (iokit/common) data was not found")]),
        .pass, "boot-args unset -> pass")

    await expectStatus("HA-A03", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "nvram.boot-args": ok("boot-args\t-no_compat_check")]),
        .pass, "boot-args set but benign -> pass")

    await expectStatus("HA-A03", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "nvram.boot-args": ok("boot-args\tamfi_get_out_of_my_way=1 cs_enforcement_disable=1")]),
        .fail, "boot-args with integrity-weakening tokens -> fail")

    // MARK: HA-A04 — Third-party kexts, label "kmutil.showloaded"

    await expectStatus("HA-A04", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "kmutil.showloaded": ok("""
                3  236 0 0 0 com.apple.kpi.bsd (99.9.9) 00000000-0000-0000-0000-000000000000 <>
               20   15 0 0 0 com.apple.driver.AppleMobileFileIntegrity (9.9.9) 00000000-0000-0000-0000-000000000000 <19 18>
            """)]),
        .pass, "only Apple kexts loaded -> pass")

    await expectStatus("HA-A04", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "kmutil.showloaded": ok("""
              128    4 0 0 0 com.examplevendor.driver.FakeKext (1.0.0) 00000000-0000-0000-0000-000000000000 <5 4 3>
            """)]),
        .fail, "third-party kext loaded -> fail")

    await expectStatus("HA-A04", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "kmutil.showloaded": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "kexts unenumerable -> unknown")

    // MARK: HA-A05 — Apple-Silicon boot security (tier X, not runtime-readable).
    // Proxy: a third-party kext (HA-A04 source) implies Reduced Security -> fail;
    // otherwise the honest unverifiable state -> unknown (never a green pass).

    await expectStatus("HA-A05", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "kmutil.showloaded": ok("""
              128    4 0 0 0 com.examplevendor.driver.FakeKext (1.0.0) 00000000-0000-0000-0000-000000000000 <5 4 3>
            """)]),
        .fail, "third-party kext implies Reduced Security -> fail")

    await expectStatus("HA-A05", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "kmutil.showloaded": ok("""
                3  236 0 0 0 com.apple.kpi.bsd (99.9.9) 00000000-0000-0000-0000-000000000000 <>
            """)]),
        .unknown, "no reduced-security indicators -> unknown (unverifiable)")

    await expectStatus("HA-A05", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "kmutil.showloaded": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "boot security not runtime-readable -> unknown")

    // MARK: HA-A06 — System extensions, label "systemextensionsctl.list"

    await expectStatus("HA-A06", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "systemextensionsctl.list": ok("0 extension(s)")]),
        .pass, "no activated system extensions -> pass")

    await expectStatus("HA-A06", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "systemextensionsctl.list": ok("""
            1 extension(s)
            --- com.apple.system_extension.endpoint_security (Go to 'System Settings' to modify these system extension(s))
            enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
            *\t*\tYYYYYYYYYY\tcom.example.unknown.es.extension (0.0.0/0.0.0)\tUnknownESAgent\t[activated enabled]
            """)]),
        .fail, "activated endpoint-security extension -> fail")

    await expectStatus("HA-A06", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "systemextensionsctl.list": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "system extensions unenumerable -> unknown")

    // MARK: HA-A07 — AMFI / library validation, inferred from HA-A03 boot-args
    // (same "nvram.boot-args" read source).

    await expectStatus("HA-A07", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "nvram.boot-args": HostCommandResult(
                exitCode: 1,
                standardError: "nvram: Error getting variable - 'boot-args': (iokit/common) data was not found")]),
        .pass, "no AMFI disabler in boot-args -> pass")

    await expectStatus("HA-A07", in: DomainA_Platform.checks,
        makeAuditContext(commands: [
            "nvram.boot-args": ok("boot-args\tamfi_get_out_of_my_way=1")]),
        .fail, "AMFI disabled via boot-args -> fail")

    // MARK: HA-A08 — Firmware password, privileged read .firmwarePassword (tier R!)

    await expectStatus("HA-A08", in: DomainA_Platform.checks,
        makeAuditContext(privileged: [
            .firmwarePassword: .output(HostHelperResult(exitCode: 0, output: "Password is set"))]),
        .pass, "firmware password set -> pass")

    await expectStatus("HA-A08", in: DomainA_Platform.checks,
        makeAuditContext(privileged: [
            .firmwarePassword: .output(HostHelperResult(exitCode: 0, output: "Password is not set"))]),
        .fail, "no firmware password set -> fail")

    await expectStatus("HA-A08", in: DomainA_Platform.checks,
        makeAuditContext(privileged: [
            .firmwarePassword: .unavailable]),
        .unknown, "firmware-password state needs root helper -> unknown")

    await expectStatus("HA-A08", in: DomainA_Platform.checks,
        makeAuditContext(privileged: [
            .firmwarePassword: .output(HostHelperResult(exitCode: 0, output: "arch=arm64; not applicable"))]),
        .notApplicable, "Apple Silicon has no firmware password -> notApplicable")

    // MARK: HA-A09 — Rosetta 2 presence (informational; always .pass).
    // Uses ctx.files.fileExists on the marker directory.

    await expectStatus("HA-A09", in: DomainA_Platform.checks,
        makeAuditContext(files: FakeFileInspector(
            directories: ["/Library/Apple/usr/libexec/oah"])),
        .pass, "Rosetta marker present -> pass (informational)")

    await expectStatus("HA-A09", in: DomainA_Platform.checks,
        makeAuditContext(files: FakeFileInspector()),
        .pass, "Rosetta marker absent -> pass (informational)")
}
