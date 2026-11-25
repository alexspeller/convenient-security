import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain E — Persistence & background execution (HA-E01…HA-E07).
//
// Every fixture here is synthetic and value-free: fake bundle ids, fake team
// identifiers, fake counts, fake Apple-prefixed system paths. No real secret,
// token, or path under /Users appears. The FakeFileInspector defaults its home
// to /Users/tester, so the per-user LaunchAgents / shell-startup paths below are
// built from that synthetic home, not a real user directory.
func hostAuditTests_E() async {
    // MARK: HA-E01 — LaunchAgents/Daemons (ctx.files)

    // Plist bodies are explicitly `[String: Any]` so the heterogeneous ones
    // (String + nested dict / array) type-check against `FakeFileInspector.plists`.
    let applePlist: [String: Any] = ["Program": "/usr/libexec/somed"]
    let injectPlist: [String: Any] = [
        "Program": "/opt/x/agent",
        "EnvironmentVariables": ["DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"],
    ]
    let thirdPartyPlist: [String: Any] = ["ProgramArguments": ["/opt/vendor/helper", "--run"]]

    // PASS: one system LaunchDaemon whose Program targets an Apple prefix, plist
    // owned root:wheel and not group/other-writable, no injection env var.
    await expectStatus("HA-E01", in: DomainE_Persistence.checks,
        makeAuditContext(files: FakeFileInspector(
            plists: ["/Library/LaunchDaemons/com.example.pass.plist": applePlist],
            perms: ["/Library/LaunchDaemons/com.example.pass.plist":
                        HostFilePermissions(mode: 0o644, ownerUID: 0, groupGID: 0)],
            entries: ["/Library/LaunchDaemons": ["com.example.pass.plist"]],
            directories: ["/Library/LaunchDaemons"])),
        .pass, "Apple-signed system daemon, non-writable plist -> pass")

    // FAIL: a launchd job carrying a DYLD_INSERT_LIBRARIES injection variable in
    // its EnvironmentVariables dict.
    await expectStatus("HA-E01", in: DomainE_Persistence.checks,
        makeAuditContext(files: FakeFileInspector(
            plists: ["/Library/LaunchDaemons/com.example.inject.plist": injectPlist],
            perms: ["/Library/LaunchDaemons/com.example.inject.plist":
                        HostFilePermissions(mode: 0o644, ownerUID: 0, groupGID: 0)],
            entries: ["/Library/LaunchDaemons": ["com.example.inject.plist"]],
            directories: ["/Library/LaunchDaemons"])),
        .fail, "DYLD injection variable in launchd job -> fail")

    // FAIL: a group/other-writable job plist (a rewrite-me-anytime foothold).
    await expectStatus("HA-E01", in: DomainE_Persistence.checks,
        makeAuditContext(files: FakeFileInspector(
            plists: ["/Library/LaunchAgents/com.example.writable.plist": applePlist],
            perms: ["/Library/LaunchAgents/com.example.writable.plist":
                        HostFilePermissions(mode: 0o666, ownerUID: 0, groupGID: 0)],
            entries: ["/Library/LaunchAgents": ["com.example.writable.plist"]],
            directories: ["/Library/LaunchAgents"])),
        .fail, "world-writable launchd plist -> fail")

    // FAIL: a job whose Program target lives outside the Apple system prefixes.
    await expectStatus("HA-E01", in: DomainE_Persistence.checks,
        makeAuditContext(files: FakeFileInspector(
            plists: ["/Library/LaunchDaemons/com.example.thirdparty.plist": thirdPartyPlist],
            perms: ["/Library/LaunchDaemons/com.example.thirdparty.plist":
                        HostFilePermissions(mode: 0o644, ownerUID: 0, groupGID: 0)],
            entries: ["/Library/LaunchDaemons": ["com.example.thirdparty.plist"]],
            directories: ["/Library/LaunchDaemons"])),
        .fail, "non-Apple Program target -> fail")

    // NOT-APPLICABLE: none of the three launchd directories exist.
    await expectStatus("HA-E01", in: DomainE_Persistence.checks,
        makeAuditContext(files: FakeFileInspector()),
        .notApplicable, "no launchd directories present -> not applicable")

    // MARK: HA-E02 — Background Task Management (F tier, privileged read)

    // PASS: an item dump with a UUID record that maps to a known developer + team.
    await expectStatus("HA-E02", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.backgroundTaskManagement:
            .output(HostHelperResult(exitCode: 0, output: """
            UUID: 11111111-1111-1111-1111-111111111111
             Name: Updater
             Developer Name: ExampleVendor
             Team Identifier: ABCDE12345
             Disposition: [enabled, allowed]
            """))]),
        .pass, "BTM item with known developer + team -> pass")

    // FAIL: a login item whose Developer Name and Team Identifier are both null.
    await expectStatus("HA-E02", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.backgroundTaskManagement:
            .output(HostHelperResult(exitCode: 0, output: """
            UUID: 00000000-0000-0000-0000-000000000000
             Name: helper
             Developer Name: (null)
             Team Identifier: (null)
             Type: legacy daemon
             Disposition: [enabled, allowed, visible]
            """))]),
        .fail, "BTM item with unknown developer -> fail")

    // UNKNOWN: helper unreachable (needs root + FDA).
    await expectStatus("HA-E02", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.backgroundTaskManagement: .unavailable]),
        .unknown, "BTM helper unavailable -> unknown")

    // UNKNOWN: dump carried no UUID item records (non-FDA truncated output).
    await expectStatus("HA-E02", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.backgroundTaskManagement:
            .output(HostHelperResult(exitCode: 0, output: """
            ServiceManagement migrated: true
            LaunchServices registered: false
            """))]),
        .unknown, "BTM output without item records -> unknown")

    // MARK: HA-E03 — Configuration profiles (R! tier, privileged read)

    // PASS: no configuration profiles installed.
    await expectStatus("HA-E03", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.configurationProfiles:
            .output(HostHelperResult(exitCode: 0,
                output: "There are no configuration profiles installed"))]),
        .pass, "no configuration profiles -> pass")

    // FAIL: a profile installs a root-certificate (trust anchor) payload.
    await expectStatus("HA-E03", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.configurationProfiles:
            .output(HostHelperResult(exitCode: 0, output: """
            _computerlevel[1] attribute: PayloadType: com.apple.security.root
            _computerlevel[1] attribute: profileIdentifier: com.example.ca
            """))]),
        .fail, "rogue root-certificate profile -> fail")

    // UNKNOWN: system-scope enumeration needs the root helper.
    await expectStatus("HA-E03", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.configurationProfiles: .unavailable]),
        .unknown, "profile helper unavailable -> unknown")

    // UNKNOWN: enumeration ran but exited non-zero (unverifiable inventory).
    await expectStatus("HA-E03", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.configurationProfiles:
            .output(HostHelperResult(exitCode: 1, output: "profiles: requires root privileges"))]),
        .unknown, "profile enumeration failed -> unknown")

    // MARK: HA-E04 — cron / at / periodic (R tier, commands + files)

    // PASS: no user crontab, empty at-queue, periodic subsystem absent.
    await expectStatus("HA-E04", in: DomainE_Persistence.checks,
        makeAuditContext(commands: [
            "crontab.list": HostCommandResult(exitCode: 1,
                standardError: "crontab: no crontab for user"),
            "atq.list": ok(""),
        ]),
        .pass, "no cron, empty at-queue -> pass")

    // FAIL: a user crontab with a scheduled job line.
    await expectStatus("HA-E04", in: DomainE_Persistence.checks,
        makeAuditContext(commands: [
            "crontab.list": ok("* * * * * /opt/x/beacon.sh\n"),
            "atq.list": ok(""),
        ]),
        .fail, "user cron job configured -> fail")

    // FAIL: a queued `at` job even with no crontab.
    await expectStatus("HA-E04", in: DomainE_Persistence.checks,
        makeAuditContext(commands: [
            "crontab.list": HostCommandResult(exitCode: 1,
                standardError: "crontab: no crontab for user"),
            "atq.list": ok("42\tTue Aug 26 10:00:00 2026 a user"),
        ]),
        .fail, "queued at job -> fail")

    // MARK: HA-E05 — login/logout hooks (R tier, commands)

    // PASS: both hooks report "does not exist".
    await expectStatus("HA-E05", in: DomainE_Persistence.checks,
        makeAuditContext(commands: [
            "defaults.loginwindow.loginhook": HostCommandResult(exitCode: 1,
                standardError: "The domain/default pair of (com.apple.loginwindow, LoginHook) does not exist"),
            "defaults.loginwindow.logouthook": HostCommandResult(exitCode: 1,
                standardError: "The domain/default pair of (com.apple.loginwindow, LogoutHook) does not exist"),
        ]),
        .pass, "no login/logout hooks -> pass")

    // FAIL: a LoginHook key is present with a value.
    await expectStatus("HA-E05", in: DomainE_Persistence.checks,
        makeAuditContext(commands: [
            "defaults.loginwindow.loginhook": ok("/opt/shared/.hook.sh\n"),
            "defaults.loginwindow.logouthook": HostCommandResult(exitCode: 1,
                standardError: "The domain/default pair of (com.apple.loginwindow, LogoutHook) does not exist"),
        ]),
        .fail, "LoginHook present -> fail")

    // UNKNOWN: neither hook read could launch (state unreadable).
    await expectStatus("HA-E05", in: DomainE_Persistence.checks,
        makeAuditContext(commands: [
            "defaults.loginwindow.loginhook": HostCommandResult(exitCode: 1, launchFailed: true),
            "defaults.loginwindow.logouthook": HostCommandResult(exitCode: 1, launchFailed: true),
        ]),
        .unknown, "login/logout hook state unreadable -> unknown")

    // MARK: HA-E06 — shell startup files (R tier, ctx.files)

    // PASS: one startup file present, clean contents, not group/other-writable.
    await expectStatus("HA-E06", in: DomainE_Persistence.checks,
        makeAuditContext(files: FakeFileInspector(
            texts: ["/Users/tester/.zshrc": "export EDITOR=vim\nalias ll='ls -la'\n"],
            perms: ["/Users/tester/.zshrc":
                        HostFilePermissions(mode: 0o644, ownerUID: 501, groupGID: 20)])),
        .pass, "clean shell startup file -> pass")

    // FAIL: a startup file exporting a DYLD injection variable.
    await expectStatus("HA-E06", in: DomainE_Persistence.checks,
        makeAuditContext(files: FakeFileInspector(
            texts: ["/Users/tester/.zshenv":
                        "export DYLD_INSERT_LIBRARIES=/tmp/x.dylib\n"],
            perms: ["/Users/tester/.zshenv":
                        HostFilePermissions(mode: 0o644, ownerUID: 501, groupGID: 20)])),
        .fail, "DYLD export in shell startup -> fail")

    // FAIL: a startup file that is itself group/other-writable.
    await expectStatus("HA-E06", in: DomainE_Persistence.checks,
        makeAuditContext(files: FakeFileInspector(
            texts: ["/Users/tester/.bashrc": "alias ll='ls -la'\n"],
            perms: ["/Users/tester/.bashrc":
                        HostFilePermissions(mode: 0o666, ownerUID: 501, groupGID: 20)])),
        .fail, "world-writable shell startup file -> fail")

    // NOT-APPLICABLE: no shell startup files present.
    await expectStatus("HA-E06", in: DomainE_Persistence.checks,
        makeAuditContext(files: FakeFileInspector()),
        .notApplicable, "no shell startup files -> not applicable")

    // MARK: HA-E07 — launchd overrides (R! tier, privileged read)

    // PASS: overrides present but every entry disables (true), none re-enables.
    await expectStatus("HA-E07", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.launchdOverrides:
            .output(HostHelperResult(exitCode: 0, output: """
            <plist><dict><key>com.example.svc</key><true/></dict></plist>
            """))]),
        .pass, "overrides only disable services -> pass")

    // PASS: no overrides file at all (clean default state).
    await expectStatus("HA-E07", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.launchdOverrides:
            .output(HostHelperResult(exitCode: 0,
                output: "could not read /var/db/com.apple.xpc.launchd/disabled.plist"))]),
        .pass, "no overrides file -> pass")

    // FAIL: an override maps a service label to false (re-enabled).
    await expectStatus("HA-E07", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.launchdOverrides:
            .output(HostHelperResult(exitCode: 0, output: """
            <plist><dict><key>com.example.svc</key><false/></dict></plist>
            """))]),
        .fail, "override re-enables a service -> fail")

    // UNKNOWN: overrides need the root helper.
    await expectStatus("HA-E07", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.launchdOverrides: .unavailable]),
        .unknown, "launchd override helper unavailable -> unknown")

    // UNKNOWN: read did not complete cleanly (non-zero exit).
    await expectStatus("HA-E07", in: DomainE_Persistence.checks,
        makeAuditContext(privileged: [.launchdOverrides:
            .output(HostHelperResult(exitCode: 1))]),
        .unknown, "launchd override read failed -> unknown")
}
