import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain B — Gatekeeper, notarization & malware defenses (HA-B01…HA-B09).
// Value-free fixtures: synthetic bundle ids, fake counts, fake version strings;
// never a real secret or a path under /Users. Fixtures are keyed by the EXACT
// HostCommand `label:` strings and file paths the checks read.

func hostAuditTests_B() async {
    // MARK: HA-B01 — Gatekeeper assessments enabled (label "spctl.status")

    await expectStatus("HA-B01", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["spctl.status": ok("assessments enabled")]),
        .pass, "Gatekeeper assessments enabled -> pass")
    await expectStatus("HA-B01", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["spctl.status": ok("assessments disabled")]),
        .fail, "Gatekeeper assessments disabled -> fail")
    await expectStatus("HA-B01", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["spctl.status": ok("")]),
        .unknown, "Gatekeeper status unrecognized -> unknown")
    await expectStatus("HA-B01", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["spctl.status": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "Gatekeeper status unreadable -> unknown")

    // MARK: HA-B02 — No per-app Gatekeeper overrides (label "spctl.assess.app")
    // Enumerates /Applications entries then assesses each with spctl.

    // PASS: all assessed bundles accepted (exit 0).
    await expectStatus("HA-B02", in: DomainB_Malware.checks,
        makeAuditContext(
            commands: ["spctl.assess.app": ok("")],
            files: FakeFileInspector(entries: ["/Applications": ["Alpha.app", "Bravo.app"]])),
        .pass, "All /Applications bundles accepted by Gatekeeper -> pass")

    // FAIL: at least one bundle would be rejected (non-zero exit, launch succeeded).
    await expectStatus("HA-B02", in: DomainB_Malware.checks,
        makeAuditContext(
            commands: ["spctl.assess.app": HostCommandResult(exitCode: 3)],
            files: FakeFileInspector(entries: ["/Applications": ["Alpha.app"]])),
        .fail, "A /Applications bundle rejected by Gatekeeper -> fail")

    // UNKNOWN: /Applications could not be enumerated (no .app entries).
    await expectStatus("HA-B02", in: DomainB_Malware.checks,
        makeAuditContext(files: FakeFileInspector(entries: ["/Applications": []])),
        .unknown, "Cannot enumerate /Applications -> unknown")

    // UNKNOWN: apps present but the assessment tool cannot launch for any of them.
    await expectStatus("HA-B02", in: DomainB_Malware.checks,
        makeAuditContext(
            commands: ["spctl.assess.app": HostCommandResult(exitCode: 127, launchFailed: true)],
            files: FakeFileInspector(entries: ["/Applications": ["Alpha.app"]])),
        .unknown, "spctl assessment tool unavailable -> unknown")

    // MARK: HA-B03 — XProtect + Remediator present (two Info.plist reads)

    let xprotectSig = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    let xprotectRem = "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"
    let sigPlist: [String: Any] = ["CFBundleShortVersionString": "5210"]
    let remPlist: [String: Any] = ["CFBundleShortVersionString": "157"]

    // PASS: both bundles present with a non-empty version string.
    await expectStatus("HA-B03", in: DomainB_Malware.checks,
        makeAuditContext(files: FakeFileInspector(
            plists: [xprotectSig: sigPlist, xprotectRem: remPlist])),
        .pass, "XProtect signatures + Remediator both present -> pass")

    // FAIL: signatures present but Remediator missing/unreadable.
    await expectStatus("HA-B03", in: DomainB_Malware.checks,
        makeAuditContext(files: FakeFileInspector(plists: [xprotectSig: sigPlist])),
        .fail, "XProtect Remediator missing -> fail")

    // UNKNOWN: neither bundle readable.
    await expectStatus("HA-B03", in: DomainB_Malware.checks,
        makeAuditContext(files: FakeFileInspector()),
        .unknown, "Neither XProtect bundle readable -> unknown")

    // MARK: HA-B04 — Automatic security-data updates on
    // Reads the plist at /Library/Preferences/com.apple.SoftwareUpdate.

    let softwareUpdatePath = "/Library/Preferences/com.apple.SoftwareUpdate"

    // PASS: both auto-delivery flags on.
    await expectStatus("HA-B04", in: DomainB_Malware.checks,
        makeAuditContext(files: FakeFileInspector(plists: [
            softwareUpdatePath: ["ConfigDataInstall": 1, "CriticalUpdateInstall": 1]])),
        .pass, "ConfigData + Critical auto-delivery on -> pass")

    // FAIL: a flag present and off.
    await expectStatus("HA-B04", in: DomainB_Malware.checks,
        makeAuditContext(files: FakeFileInspector(plists: [
            softwareUpdatePath: ["ConfigDataInstall": 0, "CriticalUpdateInstall": 1]])),
        .fail, "ConfigData auto-delivery disabled -> fail")

    // UNKNOWN: keys absent (macOS default — never assume off).
    await expectStatus("HA-B04", in: DomainB_Malware.checks,
        makeAuditContext(files: FakeFileInspector(plists: [
            softwareUpdatePath: ["AutomaticCheckEnabled": 1]])),
        .unknown, "Auto-delivery flags unset (default) -> unknown")

    // UNKNOWN: the SoftwareUpdate preferences are unreadable entirely.
    await expectStatus("HA-B04", in: DomainB_Malware.checks,
        makeAuditContext(files: FakeFileInspector()),
        .unknown, "SoftwareUpdate preferences unreadable -> unknown")

    // MARK: HA-B05 — OS on a supported, patched train (label "sw_vers.productVersion")

    // PASS: current major (26) is within the supported window (floor = 24).
    await expectStatus("HA-B05", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["sw_vers.productVersion": ok("26.2")]),
        .pass, "macOS major within supported window -> pass")

    // FAIL: major below the floor.
    await expectStatus("HA-B05", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["sw_vers.productVersion": ok("12.7")]),
        .fail, "macOS major older than supported window -> fail")

    // UNKNOWN: unparseable version.
    await expectStatus("HA-B05", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["sw_vers.productVersion": ok("macOS")]),
        .unknown, "macOS version unparseable -> unknown")

    // UNKNOWN: product version unreadable.
    await expectStatus("HA-B05", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["sw_vers.productVersion": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "macOS product version unreadable -> unknown")

    // MARK: HA-B06 — No pending security updates (label "softwareupdate.list")

    // PASS: catalog reachable, nothing pending.
    await expectStatus("HA-B06", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["softwareupdate.list":
            ok("Software Update Tool\n\nFinding available software\nNo new software available.")]),
        .pass, "No pending software updates -> pass")

    // FAIL: pending items listed as "* Label:" lines.
    await expectStatus("HA-B06", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["softwareupdate.list":
            ok("Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n* Label: PLACEHOLDER-UPDATE\n\tTitle: PLACEHOLDER, Version: 1.0, Size: 1234KiB, Recommended: YES, Action: restart,")]),
        .fail, "Pending software updates listed -> fail")

    // UNKNOWN: the update tool could not launch.
    await expectStatus("HA-B06", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["softwareupdate.list": HostCommandResult(exitCode: 127, launchFailed: true)]),
        .unknown, "Software-update tool unavailable -> unknown")

    // UNKNOWN: reached the tool but no terminal line (network stall / timeout).
    await expectStatus("HA-B06", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["softwareupdate.list":
            ok("Software Update Tool\n\nFinding available software\n")]),
        .unknown, "Update catalog unreachable / timed out -> unknown")

    // MARK: HA-B07 — Quarantine (LSQuarantine) intact (label "xattr.names")
    // Walks $HOME/Downloads for downloaded artifacts and reads xattr names.

    let downloads = "/Users/tester/Downloads"

    // PASS: no downloaded artifacts to check.
    await expectStatus("HA-B07", in: DomainB_Malware.checks,
        makeAuditContext(files: FakeFileInspector(entries: [downloads: ["notes.txt"]])),
        .pass, "No downloaded artifacts to check -> pass")

    // PASS: artifact retains the com.apple.quarantine xattr name.
    await expectStatus("HA-B07", in: DomainB_Malware.checks,
        makeAuditContext(
            commands: ["xattr.names": ok("com.apple.provenance\ncom.apple.quarantine")],
            files: FakeFileInspector(entries: [downloads: ["Installer.dmg"]])),
        .pass, "Downloaded artifact retains quarantine xattr -> pass")

    // FAIL: quarantine stripped from a downloaded artifact.
    await expectStatus("HA-B07", in: DomainB_Malware.checks,
        makeAuditContext(
            commands: ["xattr.names": ok("com.apple.provenance")],
            files: FakeFileInspector(entries: [downloads: ["Installer.dmg"]])),
        .fail, "Downloaded artifact had quarantine stripped -> fail")

    // UNKNOWN: xattr tool unavailable for all downloaded artifacts.
    await expectStatus("HA-B07", in: DomainB_Malware.checks,
        makeAuditContext(
            commands: ["xattr.names": HostCommandResult(exitCode: 127, launchFailed: true)],
            files: FakeFileInspector(entries: [downloads: ["Installer.dmg"]])),
        .unknown, "xattr tool unavailable for downloaded artifacts -> unknown")

    // MARK: HA-B08 — Binary allow-listing (Santa) (label "santactl.status")
    // Presence probed via /Applications/Santa.app dir or a santactl executable.

    let santaBundle = "/Applications/Santa.app"
    let santaCLILocal = "/usr/local/bin/santactl"

    // PASS: Santa present and running in LOCKDOWN mode.
    await expectStatus("HA-B08", in: DomainB_Malware.checks,
        makeAuditContext(
            commands: ["santactl.status": ok(">>> Daemon Info\n  Mode                   | Lockdown")],
            files: FakeFileInspector(directories: [santaBundle])),
        .pass, "Santa present in LOCKDOWN mode -> pass")

    // FAIL: Santa absent entirely (the guided-fix gap).
    await expectStatus("HA-B08", in: DomainB_Malware.checks,
        makeAuditContext(files: FakeFileInspector()),
        .fail, "Santa not installed -> fail")

    // FAIL: Santa present but only in MONITOR mode (observing, not blocking).
    await expectStatus("HA-B08", in: DomainB_Malware.checks,
        makeAuditContext(
            commands: ["santactl.status": ok(">>> Daemon Info\n  Mode                   | Monitor")],
            files: FakeFileInspector(executables: [santaCLILocal])),
        .fail, "Santa present in MONITOR mode -> fail")

    // UNKNOWN: Santa appears installed but its status could not be read.
    await expectStatus("HA-B08", in: DomainB_Malware.checks,
        makeAuditContext(
            commands: ["santactl.status": HostCommandResult(exitCode: 1)],
            files: FakeFileInspector(directories: [santaBundle])),
        .unknown, "Santa status unreadable -> unknown")

    // UNKNOWN: Santa installed but enforcement mode unrecognized.
    await expectStatus("HA-B08", in: DomainB_Malware.checks,
        makeAuditContext(
            commands: ["santactl.status": ok(">>> Daemon Info\n  Mode                   | Unknown")],
            files: FakeFileInspector(directories: [santaBundle])),
        .unknown, "Santa enforcement mode unrecognized -> unknown")

    // MARK: HA-B09 — EDR / Endpoint-Security presence (informational, label "systemextensionsctl.list")
    // Informational: always .pass when the enumeration succeeds; .unknown when it cannot run.

    // PASS: no active Endpoint-Security provider.
    await expectStatus("HA-B09", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["systemextensionsctl.list": ok("0 extension(s)")]),
        .pass, "No active EDR/ES provider -> pass (informational)")

    // PASS: an active Endpoint-Security provider present (still informational pass).
    await expectStatus("HA-B09", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["systemextensionsctl.list":
            ok("1 extension(s)\n--- com.apple.system_extension.endpoint_security (...)\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tTEAMIDXXXX\tcom.example.vendor.extension (1.0/1.0)\tPLACEHOLDER\t[activated enabled]")]),
        .pass, "Active EDR/ES provider present -> pass (informational)")

    // UNKNOWN: system extensions could not be enumerated.
    await expectStatus("HA-B09", in: DomainB_Malware.checks,
        makeAuditContext(commands: ["systemextensionsctl.list": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "Cannot enumerate system extensions -> unknown")
}
