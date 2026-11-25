import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain H — Physical / device posture (HA-H01…HA-H04).
//
// Fixtures are keyed by the EXACT HostCommand `label:` strings each check runs:
//   HA-H01 ActivationLock   -> "system_profiler.hardware"
//   HA-H03 LockdownMode     -> "defaults.ldm-global-enabled"
//   HA-H04 SecureBootChain  -> "csrutil.status", "csrutil.authenticated-root", "kmutil.showloaded"
// HA-H02 USBAccessories reads no injectable signal (unverifiable X control); it
// always returns .unknown, so only that honest branch is assertable.
//
// Honest-coverage note: HA-H04's boot-policy sub-signal (HA-A05 proxy) is never
// .pass — a clean `kmutil.showloaded` with no third-party kext is .unknown, and a
// loaded third-party kext is .fail. Therefore the composite HA-H04 can only ever
// resolve to .fail or .unknown; a fully-green .pass is unreachable by design (SIP
// on + SSV sealed + no third-party kext => worst-of is the .unknown boot policy).
// The tests below assert that reachable truth rather than encode an impossible pass.

func hostAuditTests_H() async {
    // MARK: HA-H01 — Activation Lock (tier R): label "system_profiler.hardware"

    // PASS: the hardware block reports Activation Lock enabled (other fields ignored).
    await expectStatus("HA-H01", in: DomainH_Physical.checks,
        makeAuditContext(commands: ["system_profiler.hardware": ok("""
              Model Name: Mac Example
              Serial Number (system): XXXXFAKESERIAL
              Hardware UUID: 00000000-0000-0000-0000-000000000000
              Activation Lock Status: Enabled
        """)]),
        .pass, "Activation Lock enabled -> pass")

    // FAIL: the block reports Activation Lock disabled.
    await expectStatus("HA-H01", in: DomainH_Physical.checks,
        makeAuditContext(commands: ["system_profiler.hardware": ok("""
              Activation Lock Status: Disabled
        """)]),
        .fail, "Activation Lock disabled -> fail")

    // UNKNOWN (line absent): older/unenrolled hardware omits the Activation Lock line.
    await expectStatus("HA-H01", in: DomainH_Physical.checks,
        makeAuditContext(commands: ["system_profiler.hardware": ok("""
              Model Name: Mac Example
              Chip: Apple Example
        """)]),
        .unknown, "Activation Lock line absent -> unknown")

    // UNKNOWN (command unreadable): profile could not be read at all.
    await expectStatus("HA-H01", in: DomainH_Physical.checks,
        makeAuditContext(commands: ["system_profiler.hardware": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "hardware profile unreadable -> unknown")

    // MARK: HA-H02 — USB/Thunderbolt accessory auto-connect (tier X, unverifiable)

    // Only the honest .unknown branch is reachable: the runtime setting is not
    // injectable and the check never fabricates a pass. Even with an otherwise
    // populated context it must report unknown and NEVER pass.
    await expectStatus("HA-H02", in: DomainH_Physical.checks,
        makeAuditContext(),
        .unknown, "USB accessory-connect not runtime-readable -> unknown")

    // MARK: HA-H03 — Lockdown Mode (tier R, informational): label "defaults.ldm-global-enabled"

    // PASS (on): NSGlobalDomain LDMGlobalEnabled == "1".
    await expectStatus("HA-H03", in: DomainH_Physical.checks,
        makeAuditContext(commands: ["defaults.ldm-global-enabled": ok("1")]),
        .pass, "Lockdown Mode on -> pass (informational)")

    // PASS (off, key absent): `defaults` exits non-zero; absence is the expected
    // default and is a pass, never unknown and never fail (advise-only check).
    await expectStatus("HA-H03", in: DomainH_Physical.checks,
        makeAuditContext(commands: ["defaults.ldm-global-enabled": HostCommandResult(
            exitCode: 1,
            standardError: "The domain/default pair of (kCFPreferencesAnyApplication, LDMGlobalEnabled) does not exist")]),
        .pass, "Lockdown Mode off (key absent) -> pass (informational)")

    // MARK: HA-H04 — Secure boot chain (tier R, composite worst-of)
    // Signals: csrutil.status (SIP), csrutil.authenticated-root (SSV), kmutil.showloaded (boot policy).

    // FAIL: SSV seal broken (authenticated-root disabled) — any .fail dominates.
    await expectStatus("HA-H04", in: DomainH_Physical.checks,
        makeAuditContext(commands: [
            "csrutil.status": ok("System Integrity Protection status: enabled."),
            "csrutil.authenticated-root": ok("Authenticated Root status: disabled"),
            "kmutil.showloaded": ok("com.apple.driver.Example"),
        ]),
        .fail, "SSV seal broken -> fail")

    // FAIL: SIP disabled — dominates even with SSV sealed and no third-party kext.
    await expectStatus("HA-H04", in: DomainH_Physical.checks,
        makeAuditContext(commands: [
            "csrutil.status": ok("System Integrity Protection status: disabled."),
            "csrutil.authenticated-root": ok("Authenticated Root status: enabled"),
            "kmutil.showloaded": ok("com.apple.driver.Example"),
        ]),
        .fail, "SIP disabled -> fail")

    // FAIL: a loaded third-party kext implies Reduced Security (boot policy .fail),
    // even with SIP on and SSV sealed.
    await expectStatus("HA-H04", in: DomainH_Physical.checks,
        makeAuditContext(commands: [
            "csrutil.status": ok("System Integrity Protection status: enabled."),
            "csrutil.authenticated-root": ok("Authenticated Root status: enabled"),
            "kmutil.showloaded": ok("com.example.thirdparty.kext"),
        ]),
        .fail, "third-party kext implies Reduced Security -> fail")

    // UNKNOWN: SIP on, SSV sealed, no third-party kext -> boot policy is honestly
    // unknown (HA-A05 not runtime-readable). Nothing failed => .unknown, NEVER
    // .pass — this is the honest-coverage guarantee for the unverifiable signal.
    await expectStatus("HA-H04", in: DomainH_Physical.checks,
        makeAuditContext(commands: [
            "csrutil.status": ok("System Integrity Protection status: enabled."),
            "csrutil.authenticated-root": ok("Authenticated Root status: enabled"),
            "kmutil.showloaded": ok("com.apple.driver.AppleExample"),
        ]),
        .unknown, "SIP on + SSV sealed + no third-party kext -> unknown (boot policy unverifiable)")

    // UNKNOWN: SIP unreadable (csrutil launch failed) with no third-party kext
    // signal -> nothing fails, an unknown is present => .unknown, never .pass.
    await expectStatus("HA-H04", in: DomainH_Physical.checks,
        makeAuditContext(commands: [
            "csrutil.status": HostCommandResult(exitCode: 1, launchFailed: true),
            "csrutil.authenticated-root": ok("Authenticated Root status: enabled"),
            "kmutil.showloaded": HostCommandResult(exitCode: 1, launchFailed: true),
        ]),
        .unknown, "SIP unreadable + boot policy unverifiable -> unknown")
}
