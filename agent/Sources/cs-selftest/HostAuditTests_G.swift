import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain G — Accounts, authentication & physical (HA-G01…HA-G10).
//
// Value-free fixtures only: synthetic screen-lock states, fake integer flags,
// fake admin counts, synthetic policy tokens. No real usernames, hashes,
// password material, Apple IDs, or paths under /Users appear here.
//
// Fixtures are keyed by the EXACT HostCommand `label:` strings, privileged
// `HostRootRead` cases, and file paths each check reads (verified against
// DomainG_Accounts.swift). R!/X-tier checks additionally assert an UNKNOWN case
// (privileged `.unavailable`, or a non-locally-determinable control) that is
// never `.pass` — the honest-coverage guarantee.

func hostAuditTests_G() async {
    let checks = DomainG_Accounts.checks

    // MARK: HA-G01 — AutoLogin (tier R)
    // Reads: defaults.loginwindow.autoLoginUser, defaults.loginwindow.DisableFDEAutoLogin,
    // file /etc/kcpassword.

    // PASS: no autoLoginUser key, no /etc/kcpassword, DisableFDEAutoLogin=1.
    await expectStatus("HA-G01", in: checks,
        makeAuditContext(commands: [
            "defaults.loginwindow.DisableFDEAutoLogin": ok("1"),
        ]),
        .pass, "HA-G01: no auto-login user and no kcpassword -> pass")

    // FAIL: autoLoginUser key present (existence only; value is value-free synthetic).
    await expectStatus("HA-G01", in: checks,
        makeAuditContext(commands: [
            "defaults.loginwindow.autoLoginUser": ok("autologinaccount"),
        ]),
        .fail, "HA-G01: auto-login user configured -> fail")

    // FAIL: stored auto-login password present at /etc/kcpassword.
    await expectStatus("HA-G01", in: checks,
        makeAuditContext(
            commands: ["defaults.loginwindow.autoLoginUser": HostCommandResult(exitCode: 1, standardError: "does not exist")],
            files: FakeFileInspector(texts: ["/etc/kcpassword": "REDACTED"])),
        .fail, "HA-G01: /etc/kcpassword present -> fail")

    // MARK: HA-G02 — ScreenLock (tier R)
    // Reads: sysadminctl.screenLock.status (stderr), defaults.screensaver.askForPassword,
    // defaults.screensaver.askForPasswordDelay.

    // PASS: sysadminctl reports immediate + askForPassword=1.
    await expectStatus("HA-G02", in: checks,
        makeAuditContext(commands: [
            "sysadminctl.screenLock.status": HostCommandResult(exitCode: 0, standardError: "sysadminctl[123]: screenLock delay is immediate"),
            "defaults.screensaver.askForPassword": ok("1"),
        ]),
        .pass, "HA-G02: immediate lock + password required -> pass")

    // FAIL: askForPassword explicitly 0 (no password after screensaver).
    await expectStatus("HA-G02", in: checks,
        makeAuditContext(commands: [
            "defaults.screensaver.askForPassword": ok("0"),
        ]),
        .fail, "HA-G02: askForPassword=0 -> fail")

    // FAIL: sysadminctl reports screen lock off.
    await expectStatus("HA-G02", in: checks,
        makeAuditContext(commands: [
            "sysadminctl.screenLock.status": HostCommandResult(exitCode: 0, standardError: "sysadminctl[123]: screenLock is off"),
        ]),
        .fail, "HA-G02: screen lock off -> fail")

    // FAIL: long ask-for-password grace period.
    await expectStatus("HA-G02", in: checks,
        makeAuditContext(commands: [
            "defaults.screensaver.askForPasswordDelay": ok("300"),
        ]),
        .fail, "HA-G02: long grace period -> fail")

    // UNKNOWN: could not read the lock state or the password-after-screensaver setting.
    await expectStatus("HA-G02", in: checks,
        makeAuditContext(commands: [
            "sysadminctl.screenLock.status": HostCommandResult(exitCode: 1, launchFailed: true),
            "defaults.screensaver.askForPassword": HostCommandResult(exitCode: 1, standardError: "does not exist"),
            "defaults.screensaver.askForPasswordDelay": HostCommandResult(exitCode: 1, standardError: "does not exist"),
        ]),
        .unknown, "HA-G02: nothing readable -> unknown")

    // MARK: HA-G03 — FileVault (tier R)
    // Reads: fdesetup.status.

    await expectStatus("HA-G03", in: checks,
        makeAuditContext(commands: ["fdesetup.status": ok("FileVault is On.")]),
        .pass, "HA-G03: FileVault on -> pass")

    await expectStatus("HA-G03", in: checks,
        makeAuditContext(commands: ["fdesetup.status": ok("FileVault is Off.")]),
        .fail, "HA-G03: FileVault off -> fail")

    await expectStatus("HA-G03", in: checks,
        makeAuditContext(commands: ["fdesetup.status": ok("FileVault is Off. Deferred enablement appears to be active.")]),
        .fail, "HA-G03: deferred enablement -> fail")

    // UNKNOWN: fdesetup could not be launched.
    await expectStatus("HA-G03", in: checks,
        makeAuditContext(commands: ["fdesetup.status": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "HA-G03: fdesetup unreadable -> unknown")

    // MARK: HA-G04 — RootAccount (tier R!, privileged .rootAccount)

    // PASS: DisabledUser tag present.
    await expectStatus("HA-G04", in: checks,
        makeAuditContext(privileged: [
            .rootAccount: .output(HostHelperResult(exitCode: 0, output: ";DisabledUser;;ShadowHash;HEXBLOB_REDACTED")),
        ]),
        .pass, "HA-G04: root account DisabledUser -> pass")

    // FAIL: live ShadowHash and no DisabledUser tag.
    await expectStatus("HA-G04", in: checks,
        makeAuditContext(privileged: [
            .rootAccount: .output(HostHelperResult(exitCode: 0, output: ";ShadowHash;HEXBLOB_REDACTED")),
        ]),
        .fail, "HA-G04: root account enabled -> fail")

    // UNKNOWN: root helper not reachable.
    await expectStatus("HA-G04", in: checks,
        makeAuditContext(privileged: [.rootAccount: .unavailable]),
        .unknown, "HA-G04: root helper unavailable -> unknown")

    // UNKNOWN: non-root read returns "No such key" (attribute not exposed).
    await expectStatus("HA-G04", in: checks,
        makeAuditContext(privileged: [
            .rootAccount: .output(HostHelperResult(exitCode: 0, output: "No such key: AuthenticationAuthority")),
        ]),
        .unknown, "HA-G04: no such key -> unknown")

    // MARK: HA-G05 — GuestAccount (tier R)
    // Reads: defaults.loginwindow.GuestEnabled, .SHOWFULLNAME, .RetriesUntilHint.

    // PASS: guest off, name+password window, hints off.
    await expectStatus("HA-G05", in: checks,
        makeAuditContext(commands: [
            "defaults.loginwindow.GuestEnabled": ok("0"),
            "defaults.loginwindow.SHOWFULLNAME": ok("1"),
            "defaults.loginwindow.RetriesUntilHint": ok("0"),
        ]),
        .pass, "HA-G05: hardened login window -> pass")

    // FAIL: guest account enabled.
    await expectStatus("HA-G05", in: checks,
        makeAuditContext(commands: [
            "defaults.loginwindow.GuestEnabled": ok("1"),
            "defaults.loginwindow.SHOWFULLNAME": ok("1"),
            "defaults.loginwindow.RetriesUntilHint": ok("0"),
        ]),
        .fail, "HA-G05: guest enabled -> fail")

    // FAIL: login window shows the user list (SHOWFULLNAME not 1).
    await expectStatus("HA-G05", in: checks,
        makeAuditContext(commands: [
            "defaults.loginwindow.GuestEnabled": ok("0"),
            "defaults.loginwindow.SHOWFULLNAME": HostCommandResult(exitCode: 1, standardError: "does not exist"),
            "defaults.loginwindow.RetriesUntilHint": ok("0"),
        ]),
        .fail, "HA-G05: user list shown -> fail")

    // MARK: HA-G06 — AdminSurface (tier R)
    // Reads: dscl.groups.admin.membership.

    // PASS: a small admin set (below the wide-surface threshold of 5 non-root).
    await expectStatus("HA-G06", in: checks,
        makeAuditContext(commands: [
            "dscl.groups.admin.membership": ok("GroupMembership: root adminaccount"),
        ]),
        .pass, "HA-G06: small admin set -> pass")

    // FAIL: five or more non-root admins (wide privilege surface).
    await expectStatus("HA-G06", in: checks,
        makeAuditContext(commands: [
            "dscl.groups.admin.membership": ok("GroupMembership: root a1 a2 a3 a4 a5"),
        ]),
        .fail, "HA-G06: wide admin surface -> fail")

    // UNKNOWN: admin membership could not be enumerated.
    await expectStatus("HA-G06", in: checks,
        makeAuditContext(commands: [
            "dscl.groups.admin.membership": HostCommandResult(exitCode: 1, launchFailed: true),
        ]),
        .unknown, "HA-G06: membership unreadable -> unknown")

    // MARK: HA-G07 — SudoPosture (tier R!, privileged .sudoers)

    // PASS: no NOPASSWD, tty_tickets in effect.
    await expectStatus("HA-G07", in: checks,
        makeAuditContext(privileged: [
            .sudoers: .output(HostHelperResult(exitCode: 0, output: "Defaults tty_tickets\ntimestamp_timeout=5")),
        ]),
        .pass, "HA-G07: hardened sudoers -> pass")

    // FAIL: a NOPASSWD rule allows password-free sudo.
    await expectStatus("HA-G07", in: checks,
        makeAuditContext(privileged: [
            .sudoers: .output(HostHelperResult(exitCode: 0, output: "%admin ALL=(ALL) NOPASSWD: ALL")),
        ]),
        .fail, "HA-G07: NOPASSWD rule -> fail")

    // FAIL: tty_tickets disabled.
    await expectStatus("HA-G07", in: checks,
        makeAuditContext(privileged: [
            .sudoers: .output(HostHelperResult(exitCode: 0, output: "Defaults !tty_tickets")),
        ]),
        .fail, "HA-G07: tty_tickets disabled -> fail")

    // UNKNOWN: sudoers are root-only and the helper was not reachable.
    await expectStatus("HA-G07", in: checks,
        makeAuditContext(privileged: [.sudoers: .unavailable]),
        .unknown, "HA-G07: root helper unavailable -> unknown")

    // MARK: HA-G08 — SudoTouchID (tier R!, reads world-readable /etc/pam.d/sudo_local)

    // PASS: an active (uncommented) pam_tid.so line.
    await expectStatus("HA-G08", in: checks,
        makeAuditContext(files: FakeFileInspector(texts: [
            "/etc/pam.d/sudo_local": "auth       sufficient     pam_tid.so\n",
        ])),
        .pass, "HA-G08: active pam_tid.so line -> pass")

    // FAIL: no /etc/pam.d/sudo_local present at all.
    await expectStatus("HA-G08", in: checks,
        makeAuditContext(files: FakeFileInspector()),
        .fail, "HA-G08: sudo_local absent -> fail")

    // FAIL: sudo_local present but the pam_tid.so line is commented out.
    await expectStatus("HA-G08", in: checks,
        makeAuditContext(files: FakeFileInspector(texts: [
            "/etc/pam.d/sudo_local": "# auth       sufficient     pam_tid.so\n",
        ])),
        .fail, "HA-G08: pam_tid.so commented -> fail")

    // MARK: HA-G09 — AppleID2FA (tier X, unverifiable)
    // Reads: <home>/Library/Preferences/MobileMeAccounts.plist existence only.

    // UNKNOWN: iCloud signed in, but 2FA enrollment is server-side (never a pass).
    await expectStatus("HA-G09", in: checks,
        makeAuditContext(files: FakeFileInspector(
            texts: ["/Users/tester/Library/Preferences/MobileMeAccounts.plist": "REDACTED"],
            homeDirectory: "/Users/tester")),
        .unknown, "HA-G09: iCloud signed in, 2FA unverifiable -> unknown")

    // notApplicable: no iCloud account configured locally.
    await expectStatus("HA-G09", in: checks,
        makeAuditContext(files: FakeFileInspector(homeDirectory: "/Users/tester")),
        .notApplicable, "HA-G09: no iCloud account -> notApplicable")

    // MARK: HA-G10 — PasswordPolicy (tier R!, privileged .passwordPolicy)

    // PASS: a recognized policy key (minimum length/complexity) is present.
    await expectStatus("HA-G10", in: checks,
        makeAuditContext(privileged: [
            .passwordPolicy: .output(HostHelperResult(exitCode: 0, output: "policyContent minimumLength requiresAlpha")),
        ]),
        .pass, "HA-G10: policy configured -> pass")

    // FAIL: no account policies set.
    await expectStatus("HA-G10", in: checks,
        makeAuditContext(privileged: [
            .passwordPolicy: .output(HostHelperResult(exitCode: 0, output: "No accountPolicies set")),
        ]),
        .fail, "HA-G10: no password policy -> fail")

    // UNKNOWN: the authoritative policy needs the root helper, which was unreachable.
    await expectStatus("HA-G10", in: checks,
        makeAuditContext(privileged: [.passwordPolicy: .unavailable]),
        .unknown, "HA-G10: root helper unavailable -> unknown")

    // UNKNOWN: output present but without a recognizable length/complexity key.
    await expectStatus("HA-G10", in: checks,
        makeAuditContext(privileged: [
            .passwordPolicy: .output(HostHelperResult(exitCode: 0, output: "Getting global account policies")),
        ]),
        .unknown, "HA-G10: unrecognized policy output -> unknown")
}
