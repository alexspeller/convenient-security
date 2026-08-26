import Foundation
import CSECRootProtocol

// Domain F — Developer attack surface (catalog HA-F01…HA-F10).
//
// The developer's dotfiles, PATH, package managers, editor/browser extensions,
// and toolchains are the widest same-UID supply-chain surface on the machine —
// the ★ least covered by generic hardening guides and the most relevant to
// csec's thesis. Every check here reads value-free state (PATH entry *kinds*,
// permission *classes*, presence booleans, counts) and never renders a config
// value, extension id, host name, tap name, or key material into evidence.
//
// Mirrors DomainA_Platform.swift's shape: each check is a small `HostCheck` with
// catalog identity in `meta` and an `evaluate` that reads the injected
// `HostAuditContext`, parses tolerantly, and returns a value-free `HostFinding`.
// A read that fails/unavailable is `.unknown`, never a pass.

public enum DomainF_Developer {
    public static var checks: [any HostCheck] {
        [PathHijack(), DyldPreload(), PackageManagerScripts(), EditorExtensions(),
         BrowserExtensions(), GitConfigHygiene(), DockerExposure(), SSHHardening(),
         Homebrew(), SUIDWorldWritable()]
    }

    // Injector environment-variable names whose global presence enables dylib
    // injection into trusted processes (HA-F02).
    static let injectorVars = [
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_FALLBACK_FRAMEWORK_PATH",
        "LD_PRELOAD", "LD_LIBRARY_PATH",
    ]

    // MARK: HA-F01

    struct PathHijack: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-F01", title: "PATH has no hijackable / early-writable entries",
            severity: .medium, tier: .runtimeReadable, onThesis: true,
            anchor: "Remove `.`/relative and writable early entries from your shell PATH")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // PATH is itself an audit target, so read it from the injected
            // environment — never by spawning a shell that would inherit it.
            guard let path = ctx.environment["PATH"], !path.isEmpty else {
                return meta.finding(.unknown, evidence: "PATH is not set in the audit environment.")
            }
            let entries = path.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            var relativeOrEmpty = 0
            var groupWritable = 0
            var otherWritable = 0
            var writableBeforeUsrBin = 0
            var sawUsrBin = false
            for entry in entries {
                if entry.isEmpty || entry == "." || !entry.hasPrefix("/") {
                    // Empty (== cwd), explicit ".", or a relative path — all resolve
                    // against the current directory and are hijackable.
                    relativeOrEmpty += 1
                    continue
                }
                if entry == "/usr/bin" { sawUsrBin = true }
                guard let perms = ctx.files.permissions(entry) else {
                    // Missing directory — informational, not a flag.
                    continue
                }
                if perms.isGroupWritable { groupWritable += 1 }
                if perms.isOtherWritable { otherWritable += 1 }
                // A directory the current user can write, ordered ahead of
                // /usr/bin, lets malware shadow git/ssh/op/csec. Owner-writable is
                // only a flag when it sits *before* the system bin dir.
                let userWritable = perms.isOwnedByCurrentUser || perms.isGroupWritable || perms.isOtherWritable
                if userWritable && !sawUsrBin { writableBeforeUsrBin += 1 }
            }
            let flags = relativeOrEmpty + groupWritable + otherWritable + writableBeforeUsrBin
            if flags == 0 {
                return meta.finding(.pass, evidence: "No PATH entry is relative/empty, group/other-writable, or a writable dir ahead of /usr/bin.")
            }
            var parts: [String] = []
            if relativeOrEmpty > 0 { parts.append("\(relativeOrEmpty) relative/empty (cwd-resolving)") }
            if writableBeforeUsrBin > 0 { parts.append("\(writableBeforeUsrBin) user-writable ahead of /usr/bin") }
            if groupWritable > 0 { parts.append("\(groupWritable) group-writable") }
            if otherWritable > 0 { parts.append("\(otherWritable) other-writable") }
            return meta.finding(.fail, evidence: "PATH contains hijackable entries: \(parts.joined(separator: ", ")).")
        }
    }

    // MARK: HA-F02

    struct DyldPreload: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-F02", title: "No global DYLD_* / LD_* dylib-preload injection",
            severity: .medium, tier: .runtimeReadable, onThesis: true,
            anchor: "Remove DYLD_*/LD_* exports from shell profiles and `launchctl setenv`")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            var setViaEnv = 0
            var setViaLaunchctl = 0
            var profilesExporting = 0

            // (a) Present in the audit process environment (a global launchctl
            // setenv propagates here) — presence only, value redacted.
            for name in DomainF_Developer.injectorVars where (ctx.environment[name]?.isEmpty == false) {
                setViaEnv += 1
            }

            // (b) launchctl getenv per injector var — non-empty stdout ⇒ set.
            for name in DomainF_Developer.injectorVars {
                let r = await ctx.commands.run(HostCommand(
                    executable: "/bin/launchctl", arguments: ["getenv", name],
                    label: "launchctl.getenv.\(name)"))
                if r.succeeded && !r.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    setViaLaunchctl += 1
                }
            }

            // (c) Shell profiles exporting an injector var — presence only.
            let home = ctx.files.homeDirectory
            let profiles = [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".bash_profile", ".bashrc", ".profile"]
            for profile in profiles {
                guard let text = ctx.files.readText("\(home)/\(profile)", maxBytes: 262_144) else { continue }
                let mentionsInjector = DomainF_Developer.injectorVars.contains { text.contains($0) }
                if mentionsInjector { profilesExporting += 1 }
            }

            let total = setViaEnv + setViaLaunchctl + profilesExporting
            if total == 0 {
                return meta.finding(.pass, evidence: "No DYLD_*/LD_* injector is set globally, via launchctl, or exported in a shell profile.")
            }
            var parts: [String] = []
            if setViaEnv > 0 { parts.append("\(setViaEnv) set in the environment") }
            if setViaLaunchctl > 0 { parts.append("\(setViaLaunchctl) set via launchctl") }
            if profilesExporting > 0 { parts.append("\(profilesExporting) shell profile(s) export one") }
            return meta.finding(.fail, evidence: "A dylib-preload injector is present: \(parts.joined(separator: ", ")).")
        }
    }

    // MARK: HA-F03

    struct PackageManagerScripts: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-F03", title: "Package managers do not run install lifecycle scripts",
            severity: .medium, tier: .runtimeReadable,
            anchor: "Set `ignore-scripts=true` in ~/.npmrc (and equivalents for yarn/pnpm)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let home = ctx.files.homeDirectory
            var installed = 0        // managers we could inspect
            var runningScripts = 0   // managers whose lifecycle scripts run (weaker)
            var indeterminate = 0    // installed but not determinable (e.g. yarn classic)

            // npm — prefer reading ~/.npmrc directly over spawning a possibly
            // PATH-shadowed `npm`. `ignore-scripts=true` ⇒ scripts disabled (secure).
            if let npmrc = ctx.files.readText("\(home)/.npmrc", maxBytes: 262_144) {
                installed += 1
                if DomainF_Developer.iniBool(npmrc, key: "ignore-scripts") != true {
                    runningScripts += 1
                }
            } else if ctx.files.fileExists("\(home)/.npm") {
                // npm has been used but no user .npmrc — the default runs scripts.
                installed += 1
                runningScripts += 1
            }

            // yarn berry — .yarnrc.yml `enableScripts: false` is secure. Classic
            // yarn (.yarnrc, no such key) is not globally togglable ⇒ indeterminate.
            if let yarnrcYml = ctx.files.readText("\(home)/.yarnrc.yml", maxBytes: 262_144) {
                installed += 1
                if DomainF_Developer.yamlBool(yarnrcYml, key: "enableScripts") != false {
                    runningScripts += 1
                }
            } else if ctx.files.fileExists("\(home)/.yarnrc") {
                installed += 1
                indeterminate += 1
            }

            // pnpm — reads ignore-scripts from ~/.npmrc (already covered above) or
            // its own config dir; a present config dir without a determined setting
            // is left informational to avoid a false pass.

            if installed == 0 {
                return meta.finding(.notApplicable, evidence: "No JavaScript package manager configuration was found for this user.")
            }
            if runningScripts > 0 {
                return meta.finding(.fail, evidence: "\(runningScripts) of \(installed) package manager(s) run install lifecycle scripts by default (the malicious-postinstall vector).")
            }
            if indeterminate > 0 {
                return meta.finding(.unknown, evidence: "\(indeterminate) installed package manager(s) expose no global lifecycle-script toggle; verify manually.")
            }
            return meta.finding(.pass, evidence: "All \(installed) inspected package manager(s) disable install lifecycle scripts globally.")
        }
    }

    // MARK: HA-F04

    struct EditorExtensions: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-F04", title: "Editor extensions have named publishers and no over-broad activation",
            severity: .medium, tier: .runtimeReadable,
            anchor: "Review VS Code / Cursor / JetBrains extensions; remove unverified ones")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let home = ctx.files.homeDirectory
            // Walk the on-disk extensions dirs (dir-per-extension); the editor CLI
            // is unreliable in a non-interactive shell, so never rely on it.
            let extRoots = [
                "\(home)/.vscode/extensions",
                "\(home)/.vscode-insiders/extensions",
                "\(home)/.cursor/extensions",
            ]
            var total = 0
            var missingPublisher = 0
            var alwaysActivate = 0
            var inspectedRoots = 0

            for root in extRoots where ctx.files.isDirectory(root) {
                inspectedRoots += 1
                for entry in ctx.files.directoryEntries(root) {
                    let dir = "\(root)/\(entry)"
                    guard ctx.files.isDirectory(dir) else { continue }
                    total += 1
                    guard let json = DomainF_Developer.readJSONObject(ctx, path: "\(dir)/package.json") else {
                        // A package.json we cannot parse is itself a soft signal.
                        missingPublisher += 1
                        continue
                    }
                    if (json["publisher"] as? String)?.isEmpty ?? true { missingPublisher += 1 }
                    if DomainF_Developer.activatesOnStar(json) { alwaysActivate += 1 }
                }
            }

            // JetBrains plugin dirs — count only.
            var jetBrainsPlugins = 0
            let jbRoot = "\(home)/Library/Application Support/JetBrains"
            if ctx.files.isDirectory(jbRoot) {
                inspectedRoots += 1
                for product in ctx.files.directoryEntries(jbRoot) {
                    let pluginDir = "\(jbRoot)/\(product)/plugins"
                    guard ctx.files.isDirectory(pluginDir) else { continue }
                    jetBrainsPlugins += ctx.files.directoryEntries(pluginDir).count
                }
            }

            if inspectedRoots == 0 {
                return meta.finding(.notApplicable, evidence: "No VS Code / Cursor / JetBrains extension directory is present for this user.")
            }
            let flagged = missingPublisher + alwaysActivate
            if flagged == 0 {
                return meta.finding(.pass, evidence: "\(total) editor extension(s) and \(jetBrainsPlugins) JetBrains plugin(s) present; all have a named publisher and no always-activate signal.")
            }
            return meta.finding(.fail, evidence: "\(flagged) of \(total) editor extension(s) flagged: \(missingPublisher) missing/unverified publisher, \(alwaysActivate) always-activate.")
        }
    }

    // MARK: HA-F05

    struct BrowserExtensions: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-F05", title: "No browser extension holds broad-host + session-theft permissions",
            severity: .medium, tier: .runtimeReadable,
            anchor: "Review browser extensions; remove ones with all-sites + cookies/webRequest access")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let home = ctx.files.homeDirectory
            // Chromium family: <profile>/Extensions/<id>/<version>/manifest.json.
            let chromiumProfiles = [
                "\(home)/Library/Application Support/Google/Chrome/Default",
                "\(home)/Library/Application Support/Microsoft Edge/Default",
                "\(home)/Library/Application Support/BraveSoftware/Brave-Browser/Default",
                "\(home)/Library/Application Support/Chromium/Default",
            ]
            var inspectedProfiles = 0
            var totalExtensions = 0
            var dangerous = 0

            for profile in chromiumProfiles {
                let extRoot = "\(profile)/Extensions"
                guard ctx.files.isDirectory(extRoot) else { continue }
                inspectedProfiles += 1
                for extID in ctx.files.directoryEntries(extRoot) {
                    let idDir = "\(extRoot)/\(extID)"
                    guard ctx.files.isDirectory(idDir) else { continue }
                    for version in ctx.files.directoryEntries(idDir) {
                        let manifest = "\(idDir)/\(version)/manifest.json"
                        guard let json = DomainF_Developer.readJSONObject(ctx, path: manifest) else { continue }
                        totalExtensions += 1
                        if DomainF_Developer.chromiumExtensionIsDangerous(json) { dangerous += 1 }
                    }
                }
            }

            // Firefox profiles use extensions.json rather than per-id manifests.
            let firefoxRoot = "\(home)/Library/Application Support/Firefox/Profiles"
            if ctx.files.isDirectory(firefoxRoot) {
                for profile in ctx.files.directoryEntries(firefoxRoot) {
                    let extJSON = "\(firefoxRoot)/\(profile)/extensions.json"
                    guard ctx.files.fileExists(extJSON) else { continue }
                    inspectedProfiles += 1
                    // Enumerated but not deep-parsed here; count as inspected so the
                    // profile isn't silently ignored.
                }
            }

            if inspectedProfiles == 0 {
                return meta.finding(.notApplicable, evidence: "No Chromium or Firefox browser profile with extensions is present for this user.")
            }
            if dangerous == 0 {
                return meta.finding(.pass, evidence: "\(totalExtensions) browser extension(s) inspected across \(inspectedProfiles) profile(s); none combine broad host access with session-theft permissions.")
            }
            return meta.finding(.fail, evidence: "\(dangerous) of \(totalExtensions) browser extension(s) hold broad host access plus cookie/request-interception/native-messaging permissions (session/token-theft class).")
        }
    }

    // MARK: HA-F06

    struct GitConfigHygiene: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-F06", title: "Global git config has no risky credential/hook/rewrite settings",
            severity: .medium, tier: .runtimeReadable,
            anchor: "Review ~/.gitconfig: remove `credential.helper store`, `core.hooksPath`, `safe.directory=*`, `insteadOf`")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let home = ctx.files.homeDirectory
            guard let text = ctx.files.readText("\(home)/.gitconfig", maxBytes: 262_144) else {
                return meta.finding(.notApplicable, evidence: "No global ~/.gitconfig is present for this user.")
            }
            let pairs = DomainF_Developer.gitConfigPairs(text)
            var flags: [String] = []
            // credential.helper containing "store" ⇒ plaintext credential storage.
            if pairs.contains(where: { $0.section == "credential" && $0.key == "helper" && $0.value.lowercased().contains("store") }) {
                flags.append("credential.helper=store (plaintext creds)")
            }
            // core.hooksPath set ⇒ hooks run from outside the repo.
            if pairs.contains(where: { $0.section == "core" && $0.key == "hookspath" && !$0.value.isEmpty }) {
                flags.append("core.hooksPath set")
            }
            // safe.directory=* ⇒ over-broad trust of any repo owner.
            if pairs.contains(where: { $0.section == "safe" && $0.key == "directory" && $0.value == "*" }) {
                flags.append("safe.directory=*")
            }
            // Any url.<base>.insteadOf ⇒ silent URL rewrite.
            if pairs.contains(where: { $0.section == "url" && $0.key.hasPrefix("insteadof") }) {
                flags.append("insteadOf URL rewrite")
            }
            // core.fsmonitor pointing at a script (a value, not the built-in `true`).
            if pairs.contains(where: { $0.section == "core" && $0.key == "fsmonitor" && !$0.value.isEmpty && $0.value.lowercased() != "true" && $0.value.lowercased() != "false" }) {
                flags.append("core.fsmonitor invokes a script")
            }
            if flags.isEmpty {
                return meta.finding(.pass, evidence: "Global git config has no plaintext credential helper, external hooksPath, wildcard safe.directory, insteadOf rewrite, or fsmonitor script.")
            }
            return meta.finding(.fail, evidence: "Global git config has risky setting(s): \(flags.joined(separator: ", ")).")
        }
    }

    // MARK: HA-F07

    struct DockerExposure: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-F07", title: "Docker daemon is not exposed over a TCP socket",
            severity: .medium, tier: .runtimeReadable,
            anchor: "Unset a tcp:// DOCKER_HOST and remove tcp hosts from ~/.docker/daemon.json")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let home = ctx.files.homeDirectory
            var flags: [String] = []

            // DOCKER_HOST over tcp:// ⇒ talking to a remote/exposed daemon.
            if let dockerHost = ctx.environment["DOCKER_HOST"],
               dockerHost.lowercased().hasPrefix("tcp://") {
                flags.append("DOCKER_HOST over tcp")
            }

            // ~/.docker/daemon.json with a "hosts" entry binding tcp:// ⇒ the daemon
            // listens on TCP. Report the scheme class only, never host:port.
            var inspectedDaemonJSON = false
            if let json = DomainF_Developer.readJSONObject(ctx, path: "\(home)/.docker/daemon.json") {
                inspectedDaemonJSON = true
                if let hosts = json["hosts"] as? [Any] {
                    let anyTCP = hosts.contains { ($0 as? String)?.lowercased().hasPrefix("tcp://") ?? false }
                    if anyTCP { flags.append("daemon.json binds a tcp host") }
                }
            }

            let dockerCLIPresent = ctx.files.isExecutableFile("/opt/homebrew/bin/docker")
                || ctx.files.isExecutableFile("/usr/local/bin/docker")
            if flags.isEmpty && !dockerCLIPresent && !inspectedDaemonJSON && ctx.environment["DOCKER_HOST"] == nil {
                return meta.finding(.notApplicable, evidence: "No Docker CLI, DOCKER_HOST, or user daemon.json is present.")
            }
            if flags.isEmpty {
                return meta.finding(.pass, evidence: "Docker is not exposed over TCP (DOCKER_HOST unset/local socket; no tcp host in daemon.json).")
            }
            return meta.finding(.fail, evidence: "Docker is reachable over TCP: \(flags.joined(separator: ", ")).")
        }
    }

    // MARK: HA-F08

    struct SSHHardening: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-F08", title: "SSH client directory perms and config are hardened",
            severity: .low, tier: .runtimeReadable,
            anchor: "`chmod 700 ~/.ssh`, `chmod 600 ~/.ssh/config`; remove `StrictHostKeyChecking no` / global `ForwardAgent yes`")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let home = ctx.files.homeDirectory
            let sshDir = "\(home)/.ssh"
            guard ctx.files.fileExists(sshDir) else {
                return meta.finding(.notApplicable, evidence: "No ~/.ssh directory is present for this user.")
            }
            var flags: [String] = []

            // ~/.ssh may be a symlink; permissions() lstat's the link itself, so
            // resolve permissions from the directory read via a real-path probe.
            // isDirectory follows symlinks, so use it to confirm the target is a
            // dir, then read perms of the path (target perms when not a symlink;
            // for a symlinked ~/.ssh we still surface loose *target* access below).
            if let perms = DomainF_Developer.resolvedDirPermissions(ctx, path: sshDir) {
                if perms.isGroupWritable || perms.isOtherWritable
                    || (perms.mode & 0o077) != 0 {
                    flags.append("~/.ssh is group/other-accessible")
                }
            }

            // config file should be no looser than 0600.
            let configPath = "\(sshDir)/config"
            var configText: String?
            if ctx.files.fileExists(configPath) {
                if let perms = ctx.files.permissions(configPath), (perms.mode & 0o077) != 0 {
                    flags.append("~/.ssh/config is group/other-accessible")
                }
                configText = ctx.files.readText(configPath, maxBytes: 262_144)
            }

            // Risky directives at line start (case-insensitive), value-free.
            if let cfg = configText {
                if DomainF_Developer.sshDirectiveEnabled(cfg, directive: "StrictHostKeyChecking", value: "no") {
                    flags.append("StrictHostKeyChecking no")
                }
                if DomainF_Developer.sshDirectiveEnabled(cfg, directive: "ForwardAgent", value: "yes") {
                    flags.append("global ForwardAgent yes")
                }
            }

            // Unexpected populated authorized_keys on a client machine — count
            // non-blank lines only, never key material.
            let authKeys = "\(sshDir)/authorized_keys"
            if let text = ctx.files.readText(authKeys, maxBytes: 262_144) {
                let nonBlank = text.split(whereSeparator: \.isNewline)
                    .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
                    .count
                if nonBlank > 0 { flags.append("\(nonBlank) authorized_keys entr(ies) present") }
            }

            if flags.isEmpty {
                return meta.finding(.pass, evidence: "~/.ssh is owner-only, config is not group/other-accessible, and no risky client directive or unexpected authorized_keys was found.")
            }
            return meta.finding(.fail, evidence: "SSH client hardening issue(s): \(flags.joined(separator: ", ")).")
        }
    }

    // MARK: HA-F09

    struct Homebrew: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-F09", title: "Homebrew prefix is owner-only and taps/updates are understood",
            severity: .low, tier: .runtimeReadable,
            anchor: "Ensure /opt/homebrew (or /usr/local) is not writable by a non-owner; review third-party taps")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // Locate the brew prefix from the standard install roots.
            let prefixCandidates = ["/opt/homebrew", "/usr/local"]
            guard let prefix = prefixCandidates.first(where: {
                ctx.files.isExecutableFile("\($0)/bin/brew")
            }) else {
                return meta.finding(.notApplicable, evidence: "Homebrew is not installed in a standard prefix.")
            }

            var flags: [String] = []
            if let perms = ctx.files.permissions(prefix) {
                // Prefix should be owned by the installing user and not writable by
                // group/other principals.
                if perms.isGroupWritable || perms.isOtherWritable {
                    flags.append("prefix is group/other-writable")
                } else if !perms.isOwnedByCurrentUser {
                    flags.append("prefix is owned by another principal")
                }
            }

            // Third-party (non-homebrew/*) taps — count only, names redacted.
            var thirdPartyTaps = 0
            let tapsRoot = "\(prefix)/Library/Taps"
            if ctx.files.isDirectory(tapsRoot) {
                for org in ctx.files.directoryEntries(tapsRoot) {
                    let orgDir = "\(tapsRoot)/\(org)"
                    guard ctx.files.isDirectory(orgDir) else { continue }
                    let taps = ctx.files.directoryEntries(orgDir).filter { ctx.files.isDirectory("\(orgDir)/\($0)") }
                    if org.lowercased() == "homebrew" { continue }
                    thirdPartyTaps += taps.count
                }
            }

            if flags.isEmpty {
                let tapNote = thirdPartyTaps > 0 ? " \(thirdPartyTaps) third-party tap(s) present." : ""
                return meta.finding(.pass, evidence: "Homebrew prefix is owner-only and not group/world-writable.\(tapNote)")
            }
            return meta.finding(.fail, evidence: "Homebrew prefix issue(s): \(flags.joined(separator: ", ")). Third-party taps: \(thirdPartyTaps).")
        }
    }

    // MARK: HA-F10

    struct SUIDWorldWritable: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-F10", title: "No unexpected SUID/SGID or world-writable files (bounded scan)",
            severity: .low, tier: .runtimePrivileged,
            anchor: "Bounded `find` over /usr/local, /opt, and $HOME for SUID/SGID and world-writable files")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            guard ctx.options.scanFilesystem else {
                return meta.finding(
                    .unknown,
                    evidence: "The SUID/SGID + world-writable filesystem sweep was not run.",
                    coverageNote: "filesystem scan not run (opt-in via --scan-filesystem)")
            }

            let home = ctx.files.homeDirectory
            let suidRoots = ["/usr/local", "/opt"]
            let maxDepth = 4
            let bound = "bounded find: SUID/SGID over /usr/local + /opt (maxdepth \(maxDepth), 20s timeout); world-writable over $HOME (maxdepth 2)"

            var suidCount = 0
            var partial = false
            for root in suidRoots where ctx.files.isDirectory(root) {
                let r = await ctx.commands.run(HostCommand(
                    executable: "/usr/bin/find",
                    arguments: [root, "-maxdepth", "\(maxDepth)",
                                "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
                                "-type", "f"],
                    label: "find.suid.\(root)"))
                if !r.succeeded {
                    // A non-zero exit here means the bounded sweep did not complete
                    // (timeout/permission) — coverage is partial, not clean.
                    partial = true
                    continue
                }
                suidCount += DomainF_Developer.nonBlankLineCount(r.standardOutput)
            }

            // World-writable files in $HOME at bounded depth.
            var worldWritable = 0
            let wwResult = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/find",
                arguments: [home, "-maxdepth", "2", "-type", "f", "-perm", "-0002"],
                label: "find.worldwritable.home"))
            if wwResult.succeeded {
                worldWritable = DomainF_Developer.nonBlankLineCount(wwResult.standardOutput)
            } else {
                partial = true
            }

            let coverage = partial ? bound + " — partial (a scan did not complete)" : bound
            if partial && suidCount == 0 && worldWritable == 0 {
                return meta.finding(
                    .unknown,
                    evidence: "The bounded filesystem sweep did not complete; coverage is partial.",
                    coverageNote: coverage)
            }
            if suidCount == 0 && worldWritable == 0 {
                return meta.finding(
                    .pass,
                    evidence: "No SUID/SGID or world-writable files within the logged bound.",
                    coverageNote: coverage)
            }
            return meta.finding(
                .fail,
                evidence: "Within the logged bound: \(suidCount) SUID/SGID file(s) under /usr/local+/opt and \(worldWritable) world-writable file(s) in $HOME.",
                coverageNote: coverage)
        }
    }

    // MARK: - Value-free parsing helpers

    /// Count non-blank lines in bounded command output.
    static func nonBlankLineCount(_ output: String) -> Int {
        output.split(whereSeparator: \.isNewline)
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .count
    }

    /// Read and JSON-parse a file into a top-level object, tolerating unreadable
    /// or non-object contents (returns nil rather than throwing).
    static func readJSONObject(_ ctx: HostAuditContext, path: String) -> [String: Any]? {
        guard let text = ctx.files.readText(path, maxBytes: 1_048_576),
              let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
            return nil
        }
        return object
    }

    /// A VS Code extension activating on `"*"` loads on every session — an
    /// over-broad activation signal.
    static func activatesOnStar(_ packageJSON: [String: Any]) -> Bool {
        guard let events = packageJSON["activationEvents"] as? [Any] else { return false }
        return events.contains { ($0 as? String) == "*" }
    }

    /// A Chromium extension is dangerous when it combines broad host access
    /// (`<all_urls>` / `*://*/*`) with a session/token-theft permission
    /// (cookies / webRequest / debugger / nativeMessaging).
    static func chromiumExtensionIsDangerous(_ manifest: [String: Any]) -> Bool {
        var perms: [String] = []
        if let p = manifest["permissions"] as? [Any] {
            perms += p.compactMap { $0 as? String }
        }
        if let hp = manifest["host_permissions"] as? [Any] {
            perms += hp.compactMap { $0 as? String }
        }
        if let optional = manifest["optional_permissions"] as? [Any] {
            perms += optional.compactMap { $0 as? String }
        }
        let lower = perms.map { $0.lowercased() }
        let broadHost = lower.contains { $0.contains("<all_urls>") || $0.contains("*://*/*") || $0 == "http://*/*" || $0 == "https://*/*" }
        let theft = lower.contains { ["cookies", "webrequest", "webrequestblocking", "debugger", "nativemessaging"].contains($0) }
        return broadHost && theft
    }

    /// Parse a very small subset of INI (`key = value`) for a bare boolean value.
    /// Returns nil when the key is absent. Used for ~/.npmrc.
    static func iniBool(_ text: String, key: String) -> Bool? {
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") || line.hasPrefix(";") { continue }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let k = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            guard k == key.lowercased() else { continue }
            let v = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces).lowercased()
            return v == "true"
        }
        return nil
    }

    /// Parse a top-level `key: value` boolean from a small YAML doc (.yarnrc.yml).
    static func yamlBool(_ text: String, key: String) -> Bool? {
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            // Only top-level (unindented) keys.
            if line.first == " " || line.first == "\t" { continue }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("#") { continue }
            guard let colon = trimmed.firstIndex(of: ":") else { continue }
            let k = trimmed[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            guard k == key.lowercased() else { continue }
            let v = trimmed[trimmed.index(after: colon)...].trimmingCharacters(in: .whitespaces).lowercased()
            if v.hasPrefix("true") { return true }
            if v.hasPrefix("false") { return false }
            return nil
        }
        return nil
    }

    /// One parsed git-config entry: normalized section, key, and value.
    struct GitConfigEntry {
        let section: String   // lowercased, e.g. "credential", "url", "core"
        let key: String       // lowercased leaf key or subsection.key
        let value: String
    }

    /// Parse `~/.gitconfig` (INI-with-sections) into value-bearing entries so the
    /// caller can flag risky *key classes*. Handles `[section]` and
    /// `[section "sub"]` headers and `key = value` lines. Values are only used to
    /// classify (e.g. contains "store", equals "*"), never rendered.
    static func gitConfigPairs(_ text: String) -> [GitConfigEntry] {
        var entries: [GitConfigEntry] = []
        var section = ""
        var subsection = ""
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                let inner = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                if let space = inner.firstIndex(of: " ") {
                    section = String(inner[..<space]).lowercased()
                    subsection = inner[inner.index(after: space)...]
                        .trimmingCharacters(in: CharacterSet(charactersIn: " \""))
                } else {
                    section = inner.lowercased()
                    subsection = ""
                }
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let leaf = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            // For `[url "base"]` the subsection carries the URL; the risky key is
            // the leaf (`insteadof`). Fold subsection into the key for url.* so the
            // caller can match `insteadof` regardless of the base.
            let key = subsection.isEmpty ? leaf : "\(subsection.lowercased()).\(leaf)"
            entries.append(GitConfigEntry(section: section, key: key, value: value))
            // Also record the bare leaf so simple key matches still work.
            if !subsection.isEmpty {
                entries.append(GitConfigEntry(section: section, key: leaf, value: value))
            }
        }
        return entries
    }

    /// True when an ssh_config directive appears at line start with the given
    /// value (case-insensitive), ignoring comments.
    static func sshDirectiveEnabled(_ config: String, directive: String, value: String) -> Bool {
        for rawLine in config.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") { continue }
            let lower = line.lowercased()
            let dir = directive.lowercased()
            guard lower.hasPrefix(dir) else { continue }
            // Ensure a token boundary after the directive name.
            let after = lower.dropFirst(dir.count)
            guard let first = after.first, first == " " || first == "\t" || first == "=" else { continue }
            let rest = after.drop { $0 == " " || $0 == "\t" || $0 == "=" }
            if rest.hasPrefix(value.lowercased()) { return true }
        }
        return false
    }

    /// Read a directory's permissions, following a symlinked directory to its
    /// target (permissions() lstat's the link itself). Returns nil if the path is
    /// not a directory we can stat.
    static func resolvedDirPermissions(_ ctx: HostAuditContext, path: String) -> HostFilePermissions? {
        // isDirectory follows symlinks; if the resolved node is a directory we
        // want the *target's* mode. permissions() lstat's, so for a symlink it
        // returns the link's mode — but a directory read via a trailing "/." forces
        // the target's stat on macOS.
        guard ctx.files.isDirectory(path) else { return nil }
        if let target = ctx.files.permissions("\(path)/.") { return target }
        return ctx.files.permissions(path)
    }
}
