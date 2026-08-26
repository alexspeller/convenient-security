import Foundation
import CSECRootProtocol

// Maps the host-audit's closed-enum privileged operations to fixed, audited
// commands and runs them as root. This is the *only* place csec-rootd turns an
// allow-listed `HostRootRead`/`HostRootChange` into an actual command line —
// there is no path from a caller-supplied string to execution. Output is bounded
// and returned verbatim for the verified agent to parse value-free; this layer
// never parses, logs, or interprets it.
enum HostOpsExecutor {
    /// Upper bound on captured output per operation (value-free, but bounded so a
    /// pathological command can't blow the 8 MB wire frame).
    private static let maximumOutputBytes = 512 * 1024
    private static let commandTimeout: TimeInterval = 25

    // MARK: Reads

    static func read(_ query: HostRootRead) -> HostHelperResult {
        runAll(commandList(for: query))
    }

    /// Deterministic stand-in used by cs-fake-rootd (synthetic, non-root) so the
    /// wire protocol can be exercised in tests without running privileged tools.
    static func syntheticRead(_ query: HostRootRead) -> HostHelperResult {
        HostHelperResult(exitCode: 0, output: "### synthetic \(query.rawValue)\n", applied: false)
    }

    private static func commandList(for query: HostRootRead) -> [(String, [String])] {
        switch query {
        case .sharingServices:
            return [
                ("/bin/launchctl", ["print-disabled", "system"]),
                ("/usr/sbin/systemsetup", ["-getremotelogin"]),
                ("/usr/sbin/systemsetup", ["-getremoteappleevents"]),
            ]
        case .firmwarePassword:
            return [("/usr/sbin/firmwarepasswd", ["-check"])]
        case .configurationProfiles:
            return [("/usr/bin/profiles", ["show", "-all"])]
        case .rootAccount:
            return [("/usr/bin/dscl", [".", "-read", "/Users/root", "AuthenticationAuthority"])]
        case .sudoers:
            // /etc/sudoers plus every regular file under /etc/sudoers.d — a fixed
            // directory policy, never a caller-chosen path.
            var commands: [(String, [String])] = [("/bin/cat", ["/etc/sudoers"])]
            if let entries = try? FileManager.default.contentsOfDirectory(atPath: "/etc/sudoers.d") {
                for entry in entries.sorted() where !entry.hasPrefix(".") {
                    commands.append(("/bin/cat", ["/etc/sudoers.d/\(entry)"]))
                }
            }
            return commands
        case .passwordPolicy:
            return [("/usr/bin/pwpolicy", ["-getaccountpolicies"])]
        case .networkTime:
            return [
                ("/usr/sbin/systemsetup", ["-getusingnetworktime"]),
                ("/usr/sbin/systemsetup", ["-getnetworktimeserver"]),
            ]
        case .timeMachineDestinations:
            return [("/usr/bin/tmutil", ["destinationinfo"])]
        case .locationServices:
            return [(
                "/usr/bin/defaults",
                ["read", "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd", "LocationServicesEnabled"]
            )]
        case .launchdOverrides:
            return [
                ("/usr/bin/plutil", ["-convert", "xml1", "-o", "-", "/var/db/com.apple.xpc.launchd/disabled.plist"]),
            ]
        case .crashReporterSubmission:
            return [(
                "/usr/bin/defaults",
                ["read", "/Library/Application Support/CrashReporter/SubmitDiagInfo", "AutoSubmit"]
            )]
        case .backgroundTaskManagement:
            return [("/usr/bin/sfltool", ["dumpbtm"])]
        }
    }

    // MARK: Applies

    static func apply(_ change: HostRootChange) -> HostHelperResult {
        let firewall = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        switch change {
        case .enableApplicationFirewall:
            return runApply([(firewall, ["--setglobalstate", "on"])])
        case let .setFirewallStealthMode(on):
            return runApply([(firewall, ["--setstealthmode", on ? "on" : "off"])])
        case let .setFirewallLogging(on):
            return runApply([(firewall, ["--setloggingmode", on ? "on" : "off"])])
        case let .setFirewallAllowSigned(on):
            return runApply([
                (firewall, ["--setallowsigned", on ? "on" : "off"]),
                (firewall, ["--setallowsignedapp", on ? "on" : "off"]),
            ])
        case let .setSharingService(service, enabled):
            return runApply(sharingCommands(service, enabled: enabled))
        case let .setSoftwareUpdateFlag(flag, enabled):
            return runApply([(
                "/usr/bin/defaults",
                ["write", "/Library/Preferences/com.apple.SoftwareUpdate", softwareUpdateKey(flag), "-bool", enabled ? "true" : "false"]
            )])
        case .removeAutoLoginUser:
            return runApply([
                ("/usr/bin/defaults", ["delete", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"]),
                ("/bin/rm", ["-f", "/etc/kcpassword"]),
            ], toleratingFailure: true)
        case let .setDisableFDEAutoLogin(on):
            return runApply([(
                "/usr/bin/defaults",
                ["write", "/Library/Preferences/com.apple.loginwindow", "DisableFDEAutoLogin", "-bool", on ? "true" : "false"]
            )])
        case .disableRootAccount:
            return runApply([("/usr/sbin/dsenableroot", ["-d"])])
        case .disableGuestAccount:
            return runApply([
                ("/usr/bin/defaults", ["write", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled", "-bool", "false"]),
                ("/usr/bin/sysadminctl", ["-guestAccount", "off"]),
            ], toleratingFailure: true)
        case .installSudoTouchID:
            return installSudoTouchID()
        case .enableNetworkTime:
            return runApply([("/usr/sbin/systemsetup", ["-setusingnetworktime", "on"])])
        case let .clearBootArgsToken(token):
            return clearBootArgsToken(token)
        }
    }

    private static func softwareUpdateKey(_ flag: HostSoftwareUpdateFlag) -> String {
        switch flag {
        case .configDataInstall: return "ConfigDataInstall"
        case .criticalUpdateInstall: return "CriticalUpdateInstall"
        case .automaticCheckEnabled: return "AutomaticCheckEnabled"
        case .automaticDownload: return "AutomaticDownload"
        }
    }

    private static func sharingCommands(_ service: HostSharingService, enabled: Bool) -> [(String, [String])] {
        // Remote Login has a first-class toggle; the rest are launchd system
        // services addressed by their stable label.
        if service == .remoteLogin {
            return [("/usr/sbin/systemsetup", ["-setremotelogin", enabled ? "on" : "off"])]
        }
        let verb = enabled ? "enable" : "disable"
        let target = "system/\(launchdLabel(service))"
        return [("/bin/launchctl", [verb, target])]
    }

    private static func launchdLabel(_ service: HostSharingService) -> String {
        switch service {
        case .remoteLogin: return "com.openssh.sshd"
        case .remoteManagement: return "com.apple.screensharing.agent"
        case .screenSharing: return "com.apple.screensharing"
        case .fileSharing: return "com.apple.smbd"
        case .printerSharing: return "org.cups.cupsd"
        case .remoteAppleEvents: return "com.apple.AEServer"
        case .internetSharing: return "com.apple.InternetSharing"
        case .contentCaching: return "com.apple.AssetCache.builtin"
        case .mediaSharing: return "com.apple.mediasharingd"
        }
    }

    private static func installSudoTouchID() -> HostHelperResult {
        // Additive, reversible, update-safe: create /etc/pam.d/sudo_local (which
        // /etc/pam.d/sudo includes) enabling pam_tid.so. Never edits /etc/pam.d/sudo.
        let path = "/etc/pam.d/sudo_local"
        let contents = "auth       sufficient     pam_tid.so\n"
        if FileManager.default.fileExists(atPath: path),
           let existing = try? String(contentsOfFile: path, encoding: .utf8),
           existing.contains("pam_tid.so") {
            return HostHelperResult(exitCode: 0, applied: true)
        }
        do {
            try contents.write(toFile: path, atomically: true, encoding: .utf8)
            _ = try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
            return HostHelperResult(exitCode: 0, applied: true)
        } catch {
            return HostHelperResult(exitCode: 1, output: "sudo_local write failed", applied: false)
        }
    }

    private static func clearBootArgsToken(_ token: HostDangerousBootArg) -> HostHelperResult {
        // Read the current boot-args, remove only the exact known-dangerous token,
        // and write back the remainder (or delete the key when empty). Guarded:
        // never touches any token that is not on the closed allow-list.
        let read = run("/usr/sbin/nvram", ["boot-args"])
        guard read.exitCode == 0 else {
            // No boot-args set at all — nothing to clear, treat as success.
            return HostHelperResult(exitCode: 0, applied: true)
        }
        // Output shape: "boot-args\t<value>".
        let raw = read.output
        guard let tab = raw.firstIndex(where: { $0 == "\t" || $0 == " " }) else {
            return HostHelperResult(exitCode: 0, applied: true)
        }
        let value = raw[raw.index(after: tab)...].trimmingCharacters(in: .whitespacesAndNewlines)
        let kept = value.split(separator: " ").filter { part in
            !String(part).hasPrefix(token.tokenPrefix)
        }
        if kept.isEmpty {
            return runApply([("/usr/sbin/nvram", ["-d", "boot-args"])])
        }
        return runApply([("/usr/sbin/nvram", ["boot-args=\(kept.joined(separator: " "))"])])
    }

    // MARK: Process runner

    private static func runAll(_ commands: [(String, [String])]) -> HostHelperResult {
        var combined = ""
        var lastExit: Int32 = 0
        for (path, args) in commands {
            let result = run(path, args)
            combined += "### \(URL(fileURLWithPath: path).lastPathComponent) \(args.joined(separator: " "))\n"
            combined += result.output
            if !combined.hasSuffix("\n") { combined += "\n" }
            lastExit = result.exitCode
            if combined.utf8.count >= maximumOutputBytes { break }
        }
        return HostHelperResult(exitCode: lastExit, output: bounded(combined), applied: false)
    }

    private static func runApply(_ commands: [(String, [String])], toleratingFailure: Bool = false) -> HostHelperResult {
        var lastExit: Int32 = 0
        var log = ""
        for (path, args) in commands {
            let result = run(path, args)
            log += "\(URL(fileURLWithPath: path).lastPathComponent): exit \(result.exitCode)\n"
            lastExit = result.exitCode
            if result.exitCode != 0, !toleratingFailure { break }
        }
        let ok = toleratingFailure || lastExit == 0
        return HostHelperResult(exitCode: lastExit, output: bounded(log), applied: ok)
    }

    private static func run(_ path: String, _ args: [String]) -> (exitCode: Int32, output: String) {
        guard FileManager.default.isExecutableFile(atPath: path) else {
            return (127, "")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        // Minimal, fixed environment so nothing the audit runs inherits an
        // attacker-influenced PATH or DYLD_* from the launching context.
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        var collected = Data()
        let handle = pipe.fileHandleForReading
        do {
            try process.run()
        } catch {
            return (126, "")
        }
        let deadline = DispatchTime.now() + commandTimeout
        let readerDone = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .utility).async {
            collected = handle.readDataToEndOfFile()
            readerDone.signal()
        }
        if readerDone.wait(timeout: deadline) == .timedOut {
            process.terminate()
            _ = readerDone.wait(timeout: .now() + 2)
        }
        process.waitUntilExit()
        let output = String(decoding: collected.prefix(maximumOutputBytes), as: UTF8.self)
        return (process.terminationStatus, output)
    }

    private static func bounded(_ value: String) -> String {
        let bytes = value.utf8
        guard bytes.count > maximumOutputBytes else { return value }
        return String(decoding: Array(bytes.prefix(maximumOutputBytes)), as: UTF8.self)
    }
}
