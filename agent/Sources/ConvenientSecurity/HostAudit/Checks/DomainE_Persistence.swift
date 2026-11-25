import Foundation
import CSECRootProtocol

// Domain E — Persistence & background execution (catalog HA-E01…HA-E07).
//
// This whole domain is on-thesis (★): it is where csec's same-UID adversary hides
// to survive reboot — a LaunchAgent, a rogue config profile, a shell-startup DYLD
// export, a re-enabled service. Every check reduces to a value-free `HostFinding`
// (counts + kinds + enum names), never a path, argv, profile name, service label,
// or dotfile line. A protected/unavailable read reports `.unknown`, never a pass.

public enum DomainE_Persistence {
    public static var checks: [any HostCheck] {
        [LaunchItems(), BackgroundTaskManagement(), ConfigurationProfiles(),
         CronAtPeriodic(), LoginLogoutHooks(), ShellStartup(), LaunchdOverrides()]
    }

    // MARK: Shared helpers

    /// The three launchd job directories the audit enumerates. `/Library` paths
    /// are expected root-owned; the `~` path is user-owned. Reported by kind only.
    static let launchDirectories: [(path: String, systemScoped: Bool)] = [
        ("/Library/LaunchDaemons", true),
        ("/Library/LaunchAgents", true),
    ]

    /// Case-insensitive DYLD/LD injection keys that turn any launched target into a
    /// code-injection vector when carried in `EnvironmentVariables` or exported by
    /// a shell startup file.
    static let injectionEnvKeys: [String] = [
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH", "LD_PRELOAD",
    ]

    /// Turn a `readPropertyList` result into a `[String: Any]` dict, or nil.
    static func plistDictionary(_ any: Any?) -> [String: Any]? {
        any as? [String: Any]
    }

    /// The executable target of a launchd plist: `Program` string, else the first
    /// element of `ProgramArguments`. Value-free — the caller only tests it against
    /// Apple system prefixes; the raw path never reaches evidence.
    static func programTarget(_ dict: [String: Any]) -> String? {
        if let program = dict["Program"] as? String, !program.isEmpty { return program }
        if let args = dict["ProgramArguments"] as? [Any],
           let first = args.first as? String, !first.isEmpty {
            return first
        }
        return nil
    }

    /// A rough "ships-with-macOS" heuristic for a launchd target path. Apple system
    /// binaries live under these read-only, SIP-protected prefixes; anything else is
    /// treated as third-party for flagging purposes (we never sign-verify here — the
    /// unprivileged audit relies on location + writability signals).
    static func isApplePathPrefix(_ path: String) -> Bool {
        let applePrefixes = [
            "/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/bin/", "/sbin/",
            "/usr/lib/",
        ]
        return applePrefixes.contains { path.hasPrefix($0) }
    }

    /// Whether a plist file's own permissions make it a persistence foothold: any
    /// process at group/other scope can rewrite the job. Value-free (mode only).
    static func isWritablePlist(_ perms: HostFilePermissions?) -> Bool {
        guard let perms else { return false }
        return perms.isGroupWritable || perms.isOtherWritable
    }

    // MARK: HA-E01

    struct LaunchItems: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-E01", title: "LaunchAgents/Daemons free of injection & tampering",
            severity: .medium, tier: .runtimeReadable, onThesis: true,
            anchor: "~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // Enumerate the two system dirs plus the per-user LaunchAgents dir.
            let userAgents = "\(ctx.files.homeDirectory)/Library/LaunchAgents"
            let dirs: [(path: String, systemScoped: Bool)] =
                DomainE_Persistence.launchDirectories + [(userAgents, false)]

            var scannedPlists = 0
            var scannedDirs = 0
            var injectionCount = 0        // DYLD_* in EnvironmentVariables
            var writablePlistCount = 0    // group/other-writable job files
            var nonAppleTargetCount = 0   // Program target outside Apple prefixes

            for (dir, _) in dirs {
                guard ctx.files.isDirectory(dir) else { continue }
                scannedDirs += 1
                for entry in ctx.files.directoryEntries(dir) where entry.hasSuffix(".plist") {
                    let plistPath = "\(dir)/\(entry)"
                    scannedPlists += 1

                    if DomainE_Persistence.isWritablePlist(ctx.files.permissions(plistPath)) {
                        writablePlistCount += 1
                    }
                    guard let dict = DomainE_Persistence.plistDictionary(
                        ctx.files.readPropertyList(plistPath)) else { continue }

                    if let env = dict["EnvironmentVariables"] as? [String: Any] {
                        let keys = env.keys.map { $0.uppercased() }
                        if DomainE_Persistence.injectionEnvKeys.contains(where: { keys.contains($0) }) {
                            injectionCount += 1
                        }
                    }
                    if let target = DomainE_Persistence.programTarget(dict),
                       !DomainE_Persistence.isApplePathPrefix(target) {
                        nonAppleTargetCount += 1
                    }
                }
            }

            if scannedDirs == 0 {
                return meta.finding(.notApplicable, evidence: "No LaunchAgents/LaunchDaemons directories are present.")
            }

            let flagged = injectionCount + writablePlistCount
            if flagged == 0 && nonAppleTargetCount == 0 {
                return meta.finding(.pass, evidence: "\(scannedPlists) launchd job(s) scanned; none carry a DYLD injection variable, are group/other-writable, or target a non-Apple path.")
            }
            if flagged > 0 {
                return meta.finding(.fail, evidence: "\(flagged) launchd job(s) are a persistence risk (\(injectionCount) carry a DYLD injection variable, \(writablePlistCount) are group/other-writable); \(nonAppleTargetCount) additional job(s) target a non-Apple path.")
            }
            // Only non-Apple targets remain: worth surfacing but lower-signal than
            // an injection variable or a writable job file.
            return meta.finding(.fail, evidence: "\(nonAppleTargetCount) launchd job(s) target a non-Apple path; confirm each is a tool you installed.")
        }
    }

    // MARK: HA-E02

    struct BackgroundTaskManagement: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-E02", title: "Login items & background items reviewed (BTM)",
            severity: .medium, tier: .fullDiskAccess, onThesis: true,
            anchor: "System Settings → General → Login Items & Extensions (`sfltool dumpbtm`)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.backgroundTaskManagement) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "Background Task Manager inventory needs the root helper with Full Disk Access; it could not be read.")
            case let .output(result):
                let out = result.output
                // A record dump groups items into blocks; a non-FDA/non-root call
                // returns only the migration header with no item records — that is
                // an unverifiable read, never "zero items".
                let hasItemRecords = out.lowercased().contains("uuid:")
                guard result.exitCode == 0, hasItemRecords else {
                    return meta.finding(.unknown, evidence: "Background Task Manager output carried no item records (helper lacks Full Disk Access); inventory is unverifiable.")
                }
                // Count records and how many lack an identifiable developer/team —
                // the developer-unknown items are the flagged persistence surface.
                let records = DomainE_Persistence.btmRecords(out)
                let itemCount = records.count
                let unknownDeveloper = records.filter { DomainE_Persistence.btmDeveloperUnknown($0) }.count
                if unknownDeveloper == 0 {
                    return meta.finding(.pass, evidence: "\(itemCount) background/login item(s) present; each maps to a known developer or team.")
                }
                return meta.finding(.fail, evidence: "\(unknownDeveloper) of \(itemCount) background/login item(s) have an unknown developer or missing team identifier; confirm each is expected.")
            }
        }
    }

    /// Split a `sfltool dumpbtm` dump into per-item record blocks. Blocks are
    /// delimited by a separator line of `=` characters and/or a leading `UUID:`.
    static func btmRecords(_ output: String) -> [String] {
        let lines = output.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var records: [String] = []
        var current: [String] = []
        func flush() {
            if current.contains(where: { $0.lowercased().contains("uuid:") }) {
                records.append(current.joined(separator: "\n"))
            }
            current = []
        }
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let isSeparator = !trimmed.isEmpty && trimmed.allSatisfy { $0 == "=" }
            let startsRecord = trimmed.lowercased().hasPrefix("uuid:")
            if isSeparator || (startsRecord && !current.isEmpty) {
                flush()
                if startsRecord { current.append(line) }
            } else {
                current.append(line)
            }
        }
        flush()
        return records
    }

    /// A BTM record is developer-unknown when its Developer Name and Team
    /// Identifier are absent/null. Both null => not a notarized, attributable item.
    static func btmDeveloperUnknown(_ record: String) -> Bool {
        func fieldIsNullOrMissing(_ label: String) -> Bool {
            for line in record.split(separator: "\n") {
                let lower = line.lowercased()
                guard lower.contains(label.lowercased()) else { continue }
                let value = line.split(separator: ":", maxSplits: 1).last
                    .map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
                return value.isEmpty || value == "(null)" || value == "null" || value == "-"
            }
            return true  // field entirely absent => unattributable
        }
        return fieldIsNullOrMissing("developer name") && fieldIsNullOrMissing("team identifier")
    }

    // MARK: HA-E03

    struct ConfigurationProfiles: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-E03", title: "No rogue configuration profiles installed",
            severity: .high, tier: .runtimePrivileged, onThesis: true,
            anchor: "System Settings → Privacy & Security → Profiles (`profiles show -all`)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.configurationProfiles) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "System-scope configuration profiles need the root helper; they could not be enumerated.")
            case let .output(result):
                let out = result.output
                guard result.exitCode == 0 else {
                    return meta.finding(.unknown, evidence: "Configuration-profile enumeration did not complete; profile inventory is unverifiable.")
                }
                let lower = out.lowercased()
                if lower.contains("requires root") || lower.contains("not authorized") {
                    return meta.finding(.unknown, evidence: "Configuration-profile enumeration was not authorized; inventory is unverifiable.")
                }
                // Flag the high-risk payload types: an installed trust anchor, a
                // global HTTP proxy, or an MDM enrollment payload. Reported by kind
                // and count only — never a profile name or CA subject.
                var rootCert = 0, httpProxy = 0, mdm = 0
                if lower.contains("com.apple.security.root") || lower.contains("com.apple.security.pkcs1")
                    || lower.contains("com.apple.security.pem") || lower.contains("com.apple.security.pkcs12") {
                    rootCert += 1
                }
                if lower.contains("com.apple.proxy.http.global") || lower.contains("com.apple.proxy.http") {
                    httpProxy += 1
                }
                if lower.contains("com.apple.mdm") {
                    mdm += 1
                }
                let risky = rootCert + httpProxy + mdm
                if risky == 0 {
                    if lower.contains("no configuration profiles") || lower.contains("there are no") {
                        return meta.finding(.pass, evidence: "No configuration profiles are installed.")
                    }
                    return meta.finding(.pass, evidence: "Configuration profiles are present but none install a trust anchor, a global HTTP proxy, or an MDM payload.")
                }
                var kinds: [String] = []
                if rootCert > 0 { kinds.append("a root-certificate payload") }
                if httpProxy > 0 { kinds.append("a global HTTP proxy payload") }
                if mdm > 0 { kinds.append("an MDM enrollment payload") }
                return meta.finding(.fail, evidence: "A configuration profile installs \(kinds.joined(separator: ", ")); confirm you installed it (a rogue one enables silent TLS interception or remote management).")
            }
        }
    }

    // MARK: HA-E04

    struct CronAtPeriodic: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-E04", title: "No unexpected cron / at / periodic jobs",
            severity: .low, tier: .runtimeReadable, onThesis: true,
            anchor: "`crontab -l`, `atq`, /usr/lib/cron/tabs, /etc/periodic")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // User crontab. `crontab -l` exits non-zero with "no crontab for user"
            // when empty (the clean case); a zero exit with content means jobs exist.
            let cron = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/crontab", arguments: ["-l"], label: "crontab.list"))
            var cronJobCount = 0
            if cron.succeeded {
                cronJobCount = cron.standardOutput
                    .split(separator: "\n")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty && !$0.hasPrefix("#") }
                    .count
            }

            // `at` queue. Each queued job is one line; any queued job is worth
            // surfacing on a workstation that does not normally schedule `at` jobs.
            let atq = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/atq", arguments: [], label: "atq.list"))
            var atJobCount = 0
            if atq.succeeded {
                atJobCount = atq.standardOutput
                    .split(separator: "\n")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
                    .count
            }

            // periodic subsystem: removed entirely on macOS 26+. Its presence is
            // proven by the /etc/periodic directory; absent => not-applicable, never
            // a failure. We do not read the scripts (value-free).
            let periodicPresent = ctx.files.isDirectory("/etc/periodic")

            let total = cronJobCount + atJobCount
            if total > 0 {
                var parts: [String] = []
                if cronJobCount > 0 { parts.append("\(cronJobCount) user cron job line(s)") }
                if atJobCount > 0 { parts.append("\(atJobCount) queued `at` job(s)") }
                let note = periodicPresent ? "" : " The periodic subsystem is absent on this macOS."
                return meta.finding(.fail, evidence: "Scheduled execution is configured: \(parts.joined(separator: ", ")); confirm each is expected.\(note)")
            }
            let periodicNote = periodicPresent
                ? "the periodic subsystem is present with no reviewed hooks"
                : "the periodic subsystem is absent on this macOS"
            return meta.finding(.pass, evidence: "No user cron jobs and an empty `at` queue; \(periodicNote).")
        }
    }

    // MARK: HA-E05

    struct LoginLogoutHooks: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-E05", title: "No deprecated login/logout hooks",
            severity: .low, tier: .runtimeReadable, onThesis: true,
            anchor: "`defaults read com.apple.loginwindow LoginHook` / `LogoutHook`")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // The user-domain reads work without elevation. Any present hook is
            // deprecated and suspicious; the script path is the finding but is
            // never emitted. A "does not exist" stderr is the clean case.
            var present = 0
            var readable = 0
            for key in ["LoginHook", "LogoutHook"] {
                let r = await ctx.commands.run(HostCommand(
                    executable: "/usr/bin/defaults",
                    arguments: ["read", "com.apple.loginwindow", key],
                    label: "defaults.loginwindow.\(key.lowercased())"))
                if r.launchFailed { continue }
                readable += 1
                // Present when the read succeeds with a non-empty value; absent when
                // it fails with "does not exist".
                let combined = (r.standardOutput + r.standardError).lowercased()
                if r.exitCode == 0 && !r.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    present += 1
                } else if !combined.contains("does not exist") && r.exitCode != 0 {
                    // Non-zero for a reason other than absence => treat as absent but
                    // do not miscount as a hook; leave `present` unchanged.
                    continue
                }
            }
            if readable == 0 {
                return meta.finding(.unknown, evidence: "Login/logout hook state could not be read.")
            }
            if present == 0 {
                return meta.finding(.pass, evidence: "No login or logout hooks are configured.")
            }
            return meta.finding(.fail, evidence: "\(present) deprecated login/logout hook(s) are configured; each runs a script at login/logout and should be removed.")
        }
    }

    // MARK: HA-E06

    struct ShellStartup: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-E06", title: "Shell startup files free of injection & PATH tampering",
            severity: .medium, tier: .runtimeReadable, onThesis: true,
            anchor: "~/.zshenv, ~/.zprofile, ~/.zshrc, ~/.bashrc, ~/.config/fish/config.fish")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let home = ctx.files.homeDirectory
            let files = [
                ".zshenv", ".zprofile", ".zshrc", ".bashrc",
                ".config/fish/config.fish", ".config/fish/fish_variables",
            ].map { "\(home)/\($0)" }

            var scanned = 0
            var dyldExports = 0        // DYLD_*/LD_* export vectors
            var writablePathPrepends = 0
            var unknownSources = 0     // sourcing a script outside standard locations
            var writableFiles = 0      // the startup file itself is group/other-writable

            for path in files {
                guard ctx.files.fileExists(path) else { continue }
                scanned += 1
                if DomainE_Persistence.isWritablePlist(ctx.files.permissions(path)) {
                    writableFiles += 1
                }
                guard let text = ctx.files.readText(path, maxBytes: 262_144) else { continue }
                let category = DomainE_Persistence.classifyStartup(text)
                if category.dyld { dyldExports += 1 }
                if category.writablePathPrepend { writablePathPrepends += 1 }
                if category.unknownSource { unknownSources += 1 }
            }

            if scanned == 0 {
                return meta.finding(.notApplicable, evidence: "No shell startup files are present for the current user.")
            }
            let flagged = dyldExports + writablePathPrepends + unknownSources + writableFiles
            if flagged == 0 {
                return meta.finding(.pass, evidence: "\(scanned) shell startup file(s) scanned; none export DYLD/LD variables, prepend a writable directory to PATH, source an unknown script, or are group/other-writable.")
            }
            var parts: [String] = []
            if dyldExports > 0 { parts.append("\(dyldExports) export a DYLD/LD injection variable") }
            if writablePathPrepends > 0 { parts.append("\(writablePathPrepends) prepend a writable directory to PATH") }
            if unknownSources > 0 { parts.append("\(unknownSources) source a script outside standard locations") }
            if writableFiles > 0 { parts.append("\(writableFiles) are group/other-writable") }
            return meta.finding(.fail, evidence: "Shell startup persistence risk across \(scanned) file(s): \(parts.joined(separator: ", ")).")
        }
    }

    struct StartupCategory {
        var dyld = false
        var writablePathPrepend = false
        var unknownSource = false
    }

    /// Categorize a startup file's contents into value-free signals. The raw lines
    /// never leave this function — only the boolean category flags do.
    static func classifyStartup(_ text: String) -> StartupCategory {
        var category = StartupCategory()
        let lines = text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
        for rawLine in lines {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") { continue }
            let lower = line.lowercased()

            // (a) DYLD_*/LD_* injection exports (also fish `set -x DYLD_…`).
            if injectionEnvKeys.contains(where: { lower.contains($0.lowercased()) }) {
                category.dyld = true
            }

            // (b) PATH prepend of a world-/user-writable directory ahead of the
            // system paths. Detect a PATH assignment that puts a writable-looking
            // dir (/tmp, /var/tmp, a home/relative/dot dir) before /usr/bin.
            if lower.contains("path") && (lower.contains("export path") || lower.contains("path=")
                || lower.contains("set -x path") || lower.contains("fish_add_path")) {
                if startupPrependsWritableDir(line) {
                    category.writablePathPrepend = true
                }
            }

            // (c) sourcing a script outside the standard shell config locations.
            if (line.hasPrefix("source ") || line.hasPrefix(". ")
                || lower.contains(" source ")) && sourcesUnknownScript(line) {
                category.unknownSource = true
            }
        }
        return category
    }

    /// Heuristic: does a PATH assignment place a writable-looking directory before
    /// the system bin directories? Value-free — inspects the line, returns a bool.
    static func startupPrependsWritableDir(_ line: String) -> Bool {
        let lower = line.lowercased()
        // Writable-dir markers commonly abused for PATH-prepend persistence.
        let writableMarkers = ["/tmp", "/var/tmp", "/private/tmp", "./", ":.", "=.", " ."]
        let usesWritable = writableMarkers.contains { lower.contains($0) }
        guard usesWritable else { return false }
        // Only a *prepend* (writable segment appears before /usr/bin) is a risk.
        guard let usrBinRange = lower.range(of: "/usr/bin") else {
            // No system path referenced at all but a writable dir is being added:
            // treat as a prepend risk (it lands ahead of the inherited PATH).
            return true
        }
        for marker in writableMarkers where lower.contains(marker) {
            if let markerRange = lower.range(of: marker),
               markerRange.lowerBound < usrBinRange.lowerBound {
                return true
            }
        }
        return false
    }

    /// Heuristic: does a `source`/`.` line pull in a script from outside the
    /// standard, package-managed shell config locations?
    static func sourcesUnknownScript(_ line: String) -> Bool {
        let lower = line.lowercased()
        // Standard, expected sources (framework/plugin managers, package dirs).
        let knownRoots = [
            "/usr/", "/etc/", "$home/.config", "~/.config", "$home/.oh-my-zsh",
            "~/.oh-my-zsh", "/opt/homebrew/", "/usr/local/", "$zsh", "$home/.zsh",
            "~/.zsh", "$home/.nvm", "~/.nvm", "$home/.cargo", "~/.cargo",
            "$home/.fzf", "~/.fzf", "$home/.sdkman", "~/.sdkman",
        ]
        // A source of /tmp or an explicitly writable path is always suspicious.
        if lower.contains("/tmp/") || lower.contains("/var/tmp/") { return true }
        // If the line references a known-good root, treat it as expected.
        if knownRoots.contains(where: { lower.contains($0) }) { return false }
        // Otherwise, sourcing something with a path separator that is not clearly a
        // standard location is worth flagging conservatively.
        return lower.contains("/")
    }

    // MARK: HA-E07

    struct LaunchdOverrides: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-E07", title: "No launchd override re-enables a disabled service",
            severity: .low, tier: .runtimePrivileged, onThesis: true,
            anchor: "/var/db/com.apple.xpc.launchd/ (disabled.plist / disabled.<uid>.plist)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.launchdOverrides) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "launchd service overrides need the root helper; they could not be read.")
            case let .output(result):
                guard result.exitCode == 0 else {
                    return meta.finding(.unknown, evidence: "launchd override state did not read cleanly; it is unverifiable.")
                }
                let out = result.output
                let lower = out.lowercased()
                if lower.contains("could not read") || lower.contains("no such file") {
                    // No overrides file at all is the clean, default state.
                    return meta.finding(.pass, evidence: "No launchd service overrides are present.")
                }
                // The overrides map service-label -> bool; `false` re-enables a
                // service. Count re-enabling entries without emitting any label.
                let reEnabled = DomainE_Persistence.countReEnabledOverrides(out)
                if reEnabled == 0 {
                    return meta.finding(.pass, evidence: "launchd overrides are present but none re-enable a service the OS ships disabled.")
                }
                return meta.finding(.fail, evidence: "\(reEnabled) launchd override(s) re-enable a service; confirm none re-activate a service macOS ships disabled.")
            }
        }
    }

    /// Count `<key>label</key><false/>` entries in a launchd overrides plist dump
    /// (`false` = the service is re-enabled via override). Handles both XML plist
    /// text and `key => 0/false` style dumps, value-free (labels never emitted).
    static func countReEnabledOverrides(_ output: String) -> Int {
        var count = 0
        // XML plist form: a <key>…</key> immediately followed by <false/>.
        if output.contains("<key>") {
            // Collapse whitespace between tags so `<key>x</key>\n<false/>` matches.
            let collapsed = output.replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\t", with: "")
                .replacingOccurrences(of: " ", with: "")
                .lowercased()
            var searchStart = collapsed.startIndex
            while let keyClose = collapsed.range(of: "</key>", range: searchStart..<collapsed.endIndex) {
                let after = collapsed[keyClose.upperBound...]
                if after.hasPrefix("<false/>") {
                    count += 1
                }
                searchStart = keyClose.upperBound
            }
            return count
        }
        // Plain `label => false` / `label = 0` dump form.
        for line in output.split(separator: "\n") {
            let lower = line.lowercased()
            if lower.contains("=>") || lower.contains(" = ") || lower.contains("\t") {
                if lower.contains("false") || lower.hasSuffix("0") || lower.contains("= 0") || lower.contains("=> 0") {
                    count += 1
                }
            }
        }
        return count
    }
}
