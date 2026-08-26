import Foundation
import CSECRootProtocol

// Domain G — Accounts, authentication & physical (catalog HA-G01…HA-G10).
//
// Same shape as `DomainA_Platform`: each check reads the injected
// `HostAuditContext`, parses tolerantly, and returns a value-free `HostFinding`.
// Usernames, password material, hashes, policy contents, and Apple IDs never
// enter evidence — only state, counts, and enum-like tokens do. An unavailable
// privileged (`R!`) read or a non-locally-determinable (`X`) control returns
// `.unknown`, never a pass.

public enum DomainG_Accounts {
    public static var checks: [any HostCheck] {
        [AutoLogin(), ScreenLock(), FileVault(), RootAccount(), GuestAccount(),
         AdminSurface(), SudoPosture(), SudoTouchID(), AppleID2FA(), PasswordPolicy()]
    }

    /// Read one integer-valued key from a `defaults` domain, tolerating the
    /// "key does not exist" error (treated as unset). Never returns the raw value
    /// for non-integer keys — callers only ask for numeric flags here.
    static func readDefaultsInt(_ ctx: HostAuditContext, domain: String, key: String, label: String) async -> Int? {
        let r = await ctx.commands.run(HostCommand(
            executable: "/usr/bin/defaults", arguments: ["read", domain, key], label: label))
        guard r.succeeded else { return nil }
        let text = r.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines)
        return Int(text)
    }

    /// Whether a `defaults` key is present with any value (existence only; the
    /// value itself is never surfaced — used for `autoLoginUser`, a username).
    static func defaultsKeyPresent(_ ctx: HostAuditContext, domain: String, key: String, label: String) async -> Bool {
        let r = await ctx.commands.run(HostCommand(
            executable: "/usr/bin/defaults", arguments: ["read", domain, key], label: label))
        // `defaults read` exits non-zero and prints "does not exist" when unset.
        guard r.succeeded else { return false }
        return !r.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    static let loginwindowDomain = "/Library/Preferences/com.apple.loginwindow"

    // MARK: HA-G01

    struct AutoLogin: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-G01", title: "No auto-login",
            severity: .high, tier: .runtimeReadable,
            remediation: .autoPrivileged, remediationKey: "HA-G01",
            anchor: "System Settings → Users & Groups → Automatic login = Off")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let autoLoginSet = await DomainG_Accounts.defaultsKeyPresent(
                ctx, domain: DomainG_Accounts.loginwindowDomain, key: "autoLoginUser",
                label: "defaults.loginwindow.autoLoginUser")
            let kcpasswordPresent = ctx.files.fileExists("/etc/kcpassword")
            let disableFDEAutoLogin = await DomainG_Accounts.readDefaultsInt(
                ctx, domain: DomainG_Accounts.loginwindowDomain, key: "DisableFDEAutoLogin",
                label: "defaults.loginwindow.DisableFDEAutoLogin")
            if autoLoginSet || kcpasswordPresent {
                let detail = autoLoginSet && kcpasswordPresent
                    ? "an auto-login user is configured and a stored auto-login password is present"
                    : (autoLoginSet ? "an auto-login user is configured" : "a stored auto-login password (/etc/kcpassword) is present")
                return meta.finding(.fail, evidence: "Automatic login is enabled — \(detail); this defeats FileVault-at-rest.")
            }
            let fdeNote = disableFDEAutoLogin == 1 ? " and FileVault auto-login is explicitly disabled" : ""
            return meta.finding(.pass, evidence: "No auto-login user is set and no stored auto-login password exists\(fdeNote).")
        }
    }

    // MARK: HA-G02

    struct ScreenLock: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-G02", title: "Screen lock immediate/short",
            severity: .medium, tier: .runtimeReadable,
            remediation: .auto, remediationKey: "HA-G02",
            anchor: "System Settings → Lock Screen → Require password after screen saver begins")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/sbin/sysadminctl", arguments: ["-screenLock", "status"],
                label: "sysadminctl.screenLock.status"))
            // sysadminctl writes the status line to stderr, prefixed with a PID/timestamp.
            let combined = (r.standardError + "\n" + r.standardOutput).lowercased()
            let askForPassword = await DomainG_Accounts.readDefaultsInt(
                ctx, domain: "com.apple.screensaver", key: "askForPassword",
                label: "defaults.screensaver.askForPassword")
            let askDelay = await DomainG_Accounts.readDefaultsInt(
                ctx, domain: "com.apple.screensaver", key: "askForPasswordDelay",
                label: "defaults.screensaver.askForPasswordDelay")

            let lockOff = combined.contains("screenlock is off") || combined.contains("screenlock delay is off")
            let lockImmediateOrShort = combined.contains("immediate")
            let couldReadLock = combined.contains("screenlock")

            // askForPassword explicitly 0 → no password required after the screensaver.
            if askForPassword == 0 {
                return meta.finding(.fail, evidence: "The screen does not require a password after the screensaver/display sleep starts.")
            }
            if lockOff {
                return meta.finding(.fail, evidence: "Screen lock is off; the Mac does not lock when the display sleeps.")
            }
            // A large ask-for-password delay is a weak posture even when a password is required.
            if let delay = askDelay, delay >= 300 {
                return meta.finding(.fail, evidence: "The screen-lock grace period is long (\(delay) seconds), leaving an unlocked window after sleep.")
            }
            if !couldReadLock && askForPassword == nil {
                return meta.finding(.unknown, evidence: "Could not read the screen-lock delay or password-after-screensaver setting.")
            }
            if lockImmediateOrShort || askForPassword == 1 {
                return meta.finding(.pass, evidence: "The screen locks promptly and requires a password after the screensaver starts.")
            }
            return meta.finding(.pass, evidence: "No weak screen-lock or password-delay setting was detected.")
        }
    }

    // MARK: HA-G03

    struct FileVault: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-G03", title: "FileVault on",
            severity: .high, tier: .runtimeReadable,
            remediation: .guided, remediationKey: "HA-G03",
            anchor: "System Settings → Privacy & Security → FileVault (guided `fdesetup enable`)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/fdesetup", arguments: ["status"], label: "fdesetup.status"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not read FileVault status.")
            }
            let out = r.standardOutput.lowercased()
            if out.contains("filevault is on") {
                return meta.finding(.pass, evidence: "FileVault full-disk encryption is on.")
            }
            if out.contains("deferred") {
                return meta.finding(.fail, evidence: "FileVault is not yet enabled (encryption is deferred to the next login).")
            }
            if out.contains("filevault is off") {
                return meta.finding(.fail, evidence: "FileVault is off; the volume is not encrypted at rest.")
            }
            return meta.finding(.unknown, evidence: "FileVault status was not in a recognized form.")
        }
    }

    // MARK: HA-G04

    struct RootAccount: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-G04", title: "Root account disabled",
            severity: .medium, tier: .runtimePrivileged,
            remediation: .autoPrivileged, remediationKey: "HA-G04",
            anchor: "Disable the root user (`dsenableroot -d`); root login should be off")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.rootAccount) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "Root-account authority needs the root helper; it was not reachable.")
            case let .output(result):
                let out = result.output.lowercased()
                if out.contains("disableduser") {
                    return meta.finding(.pass, evidence: "The root account is disabled (marked DisabledUser).")
                }
                if out.contains("shadowhash") {
                    return meta.finding(.fail, evidence: "The root account is enabled (a live credential is set with no DisabledUser tag).")
                }
                if out.contains("no such key") {
                    return meta.finding(.unknown, evidence: "Root-account state could not be determined from the available authority attribute.")
                }
                return meta.finding(.unknown, evidence: "Root-account authority was not in a recognized form.")
            }
        }
    }

    // MARK: HA-G05

    struct GuestAccount: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-G05", title: "Guest account off; hardened login window",
            severity: .low, tier: .runtimeReadable,
            remediation: .autoPrivileged, remediationKey: "HA-G05",
            anchor: "System Settings → Users & Groups → Guest User = Off")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let guestEnabled = await DomainG_Accounts.readDefaultsInt(
                ctx, domain: DomainG_Accounts.loginwindowDomain, key: "GuestEnabled",
                label: "defaults.loginwindow.GuestEnabled")
            let showFullName = await DomainG_Accounts.readDefaultsInt(
                ctx, domain: DomainG_Accounts.loginwindowDomain, key: "SHOWFULLNAME",
                label: "defaults.loginwindow.SHOWFULLNAME")
            let retriesUntilHint = await DomainG_Accounts.readDefaultsInt(
                ctx, domain: DomainG_Accounts.loginwindowDomain, key: "RetriesUntilHint",
                label: "defaults.loginwindow.RetriesUntilHint")

            var weaknesses: [String] = []
            if guestEnabled == 1 { weaknesses.append("the Guest account is enabled") }
            if showFullName != 1 { weaknesses.append("the login window shows the user list rather than name-and-password fields") }
            if let retries = retriesUntilHint, retries > 0 { weaknesses.append("password hints are shown at the login window") }

            if guestEnabled == 1 {
                // Guest enabled is the substantive failure this auto! fix targets.
                return meta.finding(.fail, evidence: "Guest login is available; \(weaknesses.joined(separator: ", ")).")
            }
            if !weaknesses.isEmpty {
                return meta.finding(.fail, evidence: "Login-window hardening is incomplete: \(weaknesses.joined(separator: ", ")).")
            }
            return meta.finding(.pass, evidence: "The Guest account is off, the login window hides the user list, and password hints are disabled.")
        }
    }

    // MARK: HA-G06

    struct AdminSurface: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-G06", title: "Admin surface",
            severity: .low, tier: .runtimeReadable, remediation: .advise,
            anchor: "System Settings → Users & Groups (limit accounts with Administrator role)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/dscl", arguments: [".", "-read", "/Groups/admin", "GroupMembership"],
                label: "dscl.groups.admin.membership"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not enumerate the admin group membership.")
            }
            // Line form: "GroupMembership: name1 name2 ...". Split off the prefix,
            // then count members — never emit any username.
            let text = r.standardOutput
            let afterColon = text.range(of: "GroupMembership:").map { String(text[$0.upperBound...]) } ?? text
            let members = afterColon
                .split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" })
                .map(String.init)
                .filter { !$0.isEmpty }
            let nonRootAdmins = members.filter { $0 != "root" }.count
            let currentUser = NSUserName()
            let currentIsAdmin = members.contains(currentUser)
            let adminNote = currentIsAdmin ? "the current account has Administrator rights" : "the current account is a standard (non-admin) user"
            // Advisory: a large admin set widens the blast radius; being admin is
            // common for developers, so surface rather than hard-fail on that alone.
            if nonRootAdmins >= 5 {
                return meta.finding(.fail, evidence: "\(nonRootAdmins) accounts hold Administrator rights, a wide privilege surface; \(adminNote).")
            }
            return meta.finding(.pass, evidence: "\(nonRootAdmins) account(s) hold Administrator rights; \(adminNote).")
        }
    }

    // MARK: HA-G07

    struct SudoPosture: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-G07", title: "sudo posture",
            severity: .medium, tier: .runtimePrivileged, remediation: .advise,
            anchor: "`/etc/sudoers` + `/etc/sudoers.d` (tty_tickets on, no unexpected NOPASSWD)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.sudoers) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "sudoers contents are root-only; the root helper needed to read them was not reachable.")
            case let .output(result):
                let out = result.output.lowercased()
                var weaknesses: [String] = []
                if out.contains("nopasswd") { weaknesses.append("a NOPASSWD rule allows password-free sudo") }
                if out.contains("!tty_tickets") || (out.contains("tty_tickets") && out.contains("off")) {
                    weaknesses.append("tty_tickets is disabled (one sudo unlocks all terminals)")
                }
                if !weaknesses.isEmpty {
                    return meta.finding(.fail, evidence: "sudo configuration is weak: \(weaknesses.joined(separator: ", ")).")
                }
                return meta.finding(.pass, evidence: "sudo requires a password (no unexpected NOPASSWD) and per-tty tickets are in effect.")
            }
        }
    }

    // MARK: HA-G08

    struct SudoTouchID: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-G08", title: "Touch ID for sudo",
            severity: .low, tier: .runtimePrivileged,
            remediation: .autoPrivileged, remediationKey: "HA-G08",
            anchor: "Add `auth sufficient pam_tid.so` to `/etc/pam.d/sudo_local`")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // /etc/pam.d/sudo_local is world-readable, so this is determinable
            // without the root helper; the R! tier reflects that the fix is privileged.
            guard let contents = ctx.files.readText("/etc/pam.d/sudo_local", maxBytes: 65_536) else {
                return meta.finding(.fail, evidence: "No /etc/pam.d/sudo_local is present, so Touch ID for sudo is not enabled (update-safe to add).")
            }
            let active = contents
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .contains { line in
                    !line.hasPrefix("#") && line.contains("pam_tid.so")
                }
            if active {
                return meta.finding(.pass, evidence: "Touch ID for sudo is enabled via an active pam_tid.so line in /etc/pam.d/sudo_local.")
            }
            return meta.finding(.fail, evidence: "/etc/pam.d/sudo_local has no active pam_tid.so line, so Touch ID for sudo is not enabled (update-safe to add).")
        }
    }

    // MARK: HA-G09

    struct AppleID2FA: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-G09", title: "Apple ID 2FA / iCloud",
            severity: .medium, tier: .unverifiable, remediation: .advise,
            anchor: "appleid.apple.com → Sign-In and Security → Two-Factor Authentication")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let plist = "\(ctx.files.homeDirectory)/Library/Preferences/MobileMeAccounts.plist"
            let signedIn = ctx.files.fileExists(plist)
            if signedIn {
                return meta.finding(.unknown, evidence: "An iCloud account is signed in, but two-factor-authentication enrollment is server-side and cannot be verified locally — confirm 2FA is on.")
            }
            return meta.finding(.notApplicable, evidence: "No iCloud account is configured on this Mac, so Apple ID 2FA does not apply locally.")
        }
    }

    // MARK: HA-G10

    struct PasswordPolicy: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-G10", title: "Password policy",
            severity: .low, tier: .runtimePrivileged, remediation: .advise,
            anchor: "`pwpolicy -getaccountpolicies` (set a minimum length/complexity; no blank passwords)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.passwordPolicy) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "The authoritative password policy needs the root helper; it was not reachable.")
            case let .output(result):
                let out = result.output.lowercased()
                if out.contains("no accountpolicies") || out.contains("no account policies") {
                    return meta.finding(.fail, evidence: "No password policy is set, so weak or blank passwords are permitted.")
                }
                // A recognized policy key (min length / complexity) proves a policy exists;
                // report presence only, never the values.
                let hasPolicyKey = out.contains("policycontent") || out.contains("minimumlength")
                    || out.contains("minchars") || out.contains("requiresalpha") || out.contains("policyidentifier")
                if hasPolicyKey {
                    return meta.finding(.pass, evidence: "A password policy (minimum length/complexity) is configured.")
                }
                return meta.finding(.unknown, evidence: "The password policy output did not contain a recognizable length/complexity key.")
            }
        }
    }
}
