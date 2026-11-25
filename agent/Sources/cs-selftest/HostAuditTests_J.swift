import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain J — Data leakage / sync (HA-J01…HA-J06). Value-free fixtures: every
// string here is synthetic (fake bundle-less process names, fake counts, fake
// enum states). No real secret, token, username, UUID, or path-under-/Users of a
// real account appears — the fake home directory is the harness default
// "/Users/tester", used only to key the injected file fixtures.
func hostAuditTests_J() async {
    // MARK: HA-J01 — ClipboardExposure (runtime-readable)
    // Signals: `defaults.useractivityd` (Universal Clipboard) + `pgrep.clipboard-managers`.

    // PASS: no known disk-persisting clipboard manager running (pgrep empty),
    // Universal Clipboard surfaced informationally.
    await expectStatus("HA-J01", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.useractivityd": ok("{\n  kRemotePasteboardBlobName = \"<blob>\";\n}"),
            "pgrep.clipboard-managers": ok(""),
        ]),
        .pass, "no clipboard manager running (Universal Clipboard active) -> pass")

    // PASS: no handoff keys and no manager running.
    await expectStatus("HA-J01", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.useractivityd": ok("{\n}"),
            "pgrep.clipboard-managers": ok(""),
        ]),
        .pass, "no handoff, no clipboard manager -> pass")

    // FAIL: a known disk-persisting clipboard manager name appears in pgrep output.
    await expectStatus("HA-J01", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.useractivityd": ok("{\n}"),
            "pgrep.clipboard-managers": ok("501 Maccy"),
        ]),
        .fail, "known clipboard manager running -> fail")

    // MARK: HA-J02 — TimeMachineEncryption (runtime-privileged, R!)
    // Privileged read `.timeMachineDestinations`.

    // PASS: every configured destination reports Encrypted.
    await expectStatus("HA-J02", in: DomainJ_Leakage.checks,
        makeAuditContext(privileged: [
            .timeMachineDestinations: .output(HostHelperResult(exitCode: 0, output: """
            Name          : REDACTED
            Kind          : Local
            LastKnownEncryptionState : Encrypted
            """)),
        ]),
        .pass, "encrypted Time Machine destination -> pass")

    // FAIL: a destination reports NotEncrypted.
    await expectStatus("HA-J02", in: DomainJ_Leakage.checks,
        makeAuditContext(privileged: [
            .timeMachineDestinations: .output(HostHelperResult(exitCode: 0, output: """
            Name          : REDACTED
            LastKnownEncryptionState : NotEncrypted
            """)),
        ]),
        .fail, "unencrypted Time Machine destination -> fail")

    // notApplicable: no destinations configured.
    await expectStatus("HA-J02", in: DomainJ_Leakage.checks,
        makeAuditContext(privileged: [
            .timeMachineDestinations: .output(HostHelperResult(exitCode: 0, output: "tmutil: No destinations configured.")),
        ]),
        .notApplicable, "no Time Machine destinations -> notApplicable")

    // UNKNOWN: destination present but encryption field absent — never assume unencrypted.
    await expectStatus("HA-J02", in: DomainJ_Leakage.checks,
        makeAuditContext(privileged: [
            .timeMachineDestinations: .output(HostHelperResult(exitCode: 0, output: """
            Name          : REDACTED
            Kind          : Local
            """)),
        ]),
        .unknown, "encryption field missing -> unknown")

    // UNKNOWN: root helper unavailable (honest-coverage guarantee for R! tier).
    await expectStatus("HA-J02", in: DomainJ_Leakage.checks,
        makeAuditContext(privileged: [.timeMachineDestinations: .unavailable]),
        .unknown, "root helper unavailable -> unknown, never pass")

    // MARK: HA-J03 — SafariAutoOpen (runtime-readable, FDA-gated unknown)
    // Reads ~/Library/Containers/com.apple.Safari/.../com.apple.Safari.plist.
    let safariPlistPath = "/Users/tester/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist"

    // PASS: no Safari container present -> secure default.
    await expectStatus("HA-J03", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector()),
        .pass, "no Safari container -> pass")

    // PASS: container present, AutoOpenSafeDownloads false.
    await expectStatus("HA-J03", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(
            plists: [safariPlistPath: ["AutoOpenSafeDownloads": false]])),
        .pass, "Safari auto-open off -> pass")

    // PASS: container present, key absent -> defaults to false.
    await expectStatus("HA-J03", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(
            plists: [safariPlistPath: ["SomeOtherKey": true]])),
        .pass, "Safari auto-open key absent -> pass")

    // FAIL: container present, AutoOpenSafeDownloads true.
    await expectStatus("HA-J03", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(
            plists: [safariPlistPath: ["AutoOpenSafeDownloads": true]])),
        .fail, "Safari auto-open on -> fail")

    // UNKNOWN: container present but unreadable (FDA-gated) — fileExists true via
    // perms fixture, but readPropertyList returns nil.
    await expectStatus("HA-J03", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(
            perms: [safariPlistPath: HostFilePermissions(mode: 0o600, ownerUID: 0, groupGID: 0)])),
        .unknown, "Safari container unreadable -> unknown, never pass")

    // MARK: HA-J04 — SpotlightIndexing (runtime-readable)
    // Command `mdutil.status.root`.

    // PASS: indexing enabled on root volume.
    await expectStatus("HA-J04", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: ["mdutil.status.root": ok("/:\n\tIndexing enabled.")]),
        .pass, "root indexing enabled -> pass")

    // PASS: indexing disabled on root volume (still a resolved, informational pass).
    await expectStatus("HA-J04", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: ["mdutil.status.root": ok("/:\n\tIndexing disabled.")]),
        .pass, "root indexing disabled -> pass")

    // UNKNOWN: unexpected/invalid-operation shape.
    await expectStatus("HA-J04", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: ["mdutil.status.root": ok("Error: unable to perform operation.")]),
        .unknown, "mdutil unexpected shape -> unknown")

    // UNKNOWN: command could not be launched.
    await expectStatus("HA-J04", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: ["mdutil.status.root": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "mdutil launch failed -> unknown, never pass")

    // MARK: HA-J05 — ICloudSyncScope (runtime-readable, informational pass)
    // Commands: `defaults.mobilemeaccounts`, `defaults.networkserviceproxy`, `scutil.nc.list`.
    // This check is advisory: it always resolves to .pass, reporting scope value-free.

    // PASS: broad iCloud sync on, Private Relay configured, one enabled tunnel.
    await expectStatus("HA-J05", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.mobilemeaccounts": ok("""
            Services = (
              { ServiceID = "com.apple.Dataclass.CloudDesktop"; },
              { ServiceID = "com.apple.Dataclass.Ubiquity"; }
            );
            """),
            "defaults.networkserviceproxy": ok("{\n  NSPServiceStatusManagerInfo = {length = 0, bytes = 0x};\n}"),
            "scutil.nc.list": ok("* (Connected)   AAAAAAAA-0000-0000-0000-000000000000 IPSec \"tunnel\""),
        ]),
        .pass, "iCloud sync scope surfaced (sync on, relay on, tunnel) -> pass")

    // PASS: no iCloud services, no relay, no tunnels.
    await expectStatus("HA-J05", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.mobilemeaccounts": ok("Services = ( );"),
            "defaults.networkserviceproxy": ok("{\n}"),
            "scutil.nc.list": ok(""),
        ]),
        .pass, "iCloud sync scope surfaced (nothing syncing) -> pass")

    // PASS: all three reads unavailable — still an informational resolved pass.
    await expectStatus("HA-J05", in: DomainJ_Leakage.checks,
        makeAuditContext(),
        .pass, "iCloud sync scope with no readable signals -> pass")

    // MARK: HA-J06 — ScreenshotDefaults (runtime-readable)
    // Command `defaults.screencapture`. Synced roots derive from ctx.files.homeDirectory.

    // PASS: domain absent -> secure default location.
    await expectStatus("HA-J06", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.screencapture": HostCommandResult(exitCode: 1, standardOutput: "Domain com.apple.screencapture does not exist"),
        ]),
        .pass, "screencapture domain absent -> pass")

    // PASS: target=clipboard (never touches disk).
    await expectStatus("HA-J06", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.screencapture": ok("{\n  target = clipboard;\n}"),
        ]),
        .pass, "screenshots to clipboard -> pass")

    // PASS: location set to a non-synced local directory.
    await expectStatus("HA-J06", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.screencapture": ok("{\n  location = \"/Users/tester/Screenshots\";\n  target = file;\n}"),
        ]),
        .pass, "screenshots to non-synced dir -> pass")

    // PASS: location key unset (only non-location keys present).
    await expectStatus("HA-J06", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.screencapture": ok("{\n  showsCursor = 1;\n}"),
        ]),
        .pass, "screenshot location unset -> pass")

    // FAIL: location under an iCloud-synced directory (Desktop).
    await expectStatus("HA-J06", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.screencapture": ok("{\n  location = \"/Users/tester/Desktop\";\n  target = file;\n}"),
        ]),
        .fail, "screenshots into iCloud-synced Desktop -> fail")

    // FAIL: location under an iCloud Drive Mobile Documents path.
    await expectStatus("HA-J06", in: DomainJ_Leakage.checks,
        makeAuditContext(commands: [
            "defaults.screencapture": ok("{\n  location = \"/Users/tester/Library/Mobile Documents/com~apple~CloudDocs/Shots\";\n  target = file;\n}"),
        ]),
        .fail, "screenshots into iCloud Drive -> fail")
}
