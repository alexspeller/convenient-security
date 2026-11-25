import Foundation

// HA-F13 — package managers hold back just-published releases.
//
// Most trojaned npm and PyPI releases are caught and pulled within days, so a
// manager that refuses any release younger than a week never installs one. Each
// manager reads that window from a user-level config file. csec reads only the
// keys that set, override or exempt it, and finds each installed copy of the
// manager from its install directory or package metadata, never by running it:
// a copy on PATH is exactly what a supply-chain attack replaces, and csecd does
// not execute it.
//
// Pass needs a seven-day window that no other key in the file overrides, and at
// least one installed copy, every one of which reads that file. A copy too old to
// honour the setting, a value the tool would misread, an override or exemption,
// or a manager with no copy found leaves the finding unknown, never a pass. The
// fix is offered for a manager only when writing its line would leave the file
// reading as a week, and withheld when a copy found would fail outright on the
// setting (uv before 0.9.17, pip 26.0), which would break every command it runs.
// Evidence names managers, files, keys, windows and copy versions; config
// contents never leave csecd.

public enum ReleaseCooldowns {
    /// The window every manager is held to (Alex's choice for csec: a week).
    public static let windowDays: Double = 7

    public enum Manager: String, CaseIterable, Sendable, Codable {
        case npm, pnpm, yarn, uv, pip, mise, bundler

        public var displayName: String {
            switch self {
            case .npm: return "npm"
            case .pnpm: return "pnpm"
            case .yarn: return "Yarn"
            case .uv: return "uv"
            case .pip: return "pip"
            case .mise: return "mise"
            case .bundler: return "Bundler"
            }
        }

        /// The remediation key of this manager's row in the audit picker.
        public var fixKey: String { "HA-F13.\(rawValue)" }
    }

    /// One user-level file a manager reads its window from.
    public struct Setting: Sendable, Equatable {
        public let relativePath: String
        public let format: CooldownConfigFormat
        public let key: String
        /// Days per unit of a bare number (npm and Bundler count days, pnpm and
        /// Yarn minutes).
        let bareUnitDays: Double
        /// What the fix writes, exactly as the tool's own `config set` writes it.
        public let literal: String
        /// The window the manager applies with no setting, if it has one.
        let builtInDays: Double?
        /// How the tool parses the value.
        var grammar: Grammar = .duration
        /// Keys in the same scope that override the window or exempt packages
        /// from it. csec does not judge them, so any of them makes the window
        /// unknown.
        var overrides: [String] = []
    }

    /// What a tool accepts as its window, so a value the tool would misread or
    /// reject is never counted as a week.
    public enum Grammar: Sendable, Equatable {
        /// A plain number (npm's and pnpm's `Number` settings: `7d` is NaN to them).
        case number
        /// A bare number or a duration (`7d`, `7 days`, `P7D`).
        case duration
        /// A leading integer, as JavaScript's parseInt reads it (Yarn 4.10 reads
        /// `7d` as seven minutes).
        case leadingInteger
        /// A whole number only (Bundler ignores anything else).
        case integer
        /// pip's `P<n>D` only (pip 26.1 rejects other durations).
        case isoDays
    }

    // MARK: What each manager reads

    static let npmrc = Setting(
        relativePath: ".npmrc", format: .ini(section: nil), key: "min-release-age",
        bareUnitDays: 1, literal: "7", builtInDays: nil, grammar: .number,
        // `before` in the same file beats min-release-age; the excludes exempt packages.
        overrides: ["before", "min-release-age-exclude", "min-release-age-exclude[]"])
    static let pnpmYAML = Setting(
        relativePath: "Library/Preferences/pnpm/config.yaml", format: .yaml, key: "minimumReleaseAge",
        bareUnitDays: 1.0 / 1_440, literal: "10080", builtInDays: 1, grammar: .number,
        overrides: ["minimumReleaseAgeExclude", "minimumReleaseAgeStrict"])
    static let pnpmRC = Setting(
        relativePath: "Library/Preferences/pnpm/rc", format: .ini(section: nil), key: "minimum-release-age",
        bareUnitDays: 1.0 / 1_440, literal: "10080", builtInDays: nil, grammar: .number,
        overrides: ["minimum-release-age-exclude", "minimum-release-age-exclude[]"])
    // Bare minutes, which Yarn 4.10 (a number) and 4.11+ (a duration whose bare
    // number is minutes) both read as a week.
    static let yarnrc = Setting(
        relativePath: ".yarnrc.yml", format: .yaml, key: "npmMinimalAgeGate",
        bareUnitDays: 1.0 / 1_440, literal: "10080", builtInDays: nil,
        overrides: ["npmPreapprovedPackages"])
    static let yarnrcInteger = Setting(
        relativePath: ".yarnrc.yml", format: .yaml, key: "npmMinimalAgeGate",
        bareUnitDays: 1.0 / 1_440, literal: "10080", builtInDays: nil, grammar: .leadingInteger,
        overrides: ["npmPreapprovedPackages"])
    static let uvToml = Setting(
        relativePath: ".config/uv/uv.toml", format: .toml(table: nil), key: "exclude-newer",
        bareUnitDays: 0, literal: "\"7 days\"", builtInDays: nil,
        overrides: ["exclude-newer-package"])
    // pip reads the legacy file, then the current one, which wins: on macOS
    // ~/Library/Application Support/pip/pip.conf when that directory exists,
    // ~/.config/pip/pip.conf otherwise (pip's configuration.py and platformdirs).
    // Within them `[install]` beats `[global]` for an install, whichever file
    // each is in.
    static let pipLegacyConfig = ".pip/pip.conf"
    static let pipConfigs = [pipLegacyConfig, ".config/pip/pip.conf", "Library/Application Support/pip/pip.conf"]
    static let miseToml = Setting(
        relativePath: ".config/mise/config.toml", format: .toml(table: "settings"), key: "minimum_release_age",
        bareUnitDays: 0, literal: "\"7d\"", builtInDays: 1,
        overrides: ["minimum_release_age_excludes"])
    /// The other global files mise reads settings from (config/mod.rs); any of
    /// them can set its own window.
    static let miseOtherConfigs = [
        ".config/mise/config.local.toml", ".config/mise/mise.toml", ".config/mise/mise.local.toml",
        ".mise.toml", "mise.toml", ".mise.local.toml", "mise.local.toml",
    ]
    static let bundleConfig = Setting(
        relativePath: ".bundle/config", format: .yaml, key: "BUNDLE_COOLDOWN",
        bareUnitDays: 1, literal: "\"7\"", builtInDays: nil, grammar: .integer)

    static func pipSetting(_ relativePath: String, section: String = "global") -> Setting {
        Setting(
            relativePath: relativePath, format: .configparser(section: section), key: "uploaded-prior-to",
            bareUnitDays: 0, literal: "P7D", builtInDays: nil, grammar: .isoDays)
    }

    // MARK: Which copies honour it

    /// How one installed copy treats its manager's setting.
    public enum Support: Sendable, Equatable {
        /// Reads `setting` and holds back releases younger than its window.
        case honours(Setting)
        /// Has no cooldown, so it installs releases of any age.
        case ignores(reason: String)
        /// Cannot read the setting and fails every command once it is written.
        case breaks
        /// Its version could not be read without running it.
        case undetermined
    }

    static func support(_ manager: Manager, version: [Int]?, pipSetting: Setting) -> Support {
        guard let v = version else { return .undetermined }
        switch manager {
        case .npm:
            return atLeast(v, [11, 10]) ? .honours(npmrc) : .ignores(reason: "before npm 11.10")
        case .pnpm:
            if atLeast(v, [11]) { return .honours(pnpmYAML) }
            if atLeast(v, [10, 16]) { return .honours(pnpmRC) }
            return .ignores(reason: "before pnpm 10.16")
        case .yarn:
            if !atLeast(v, [2]) { return .ignores(reason: "Yarn Classic has no cooldown") }
            if atLeast(v, [4, 11]) { return .honours(yarnrc) }
            return atLeast(v, [4, 10]) ? .honours(yarnrcInteger) : .ignores(reason: "before Yarn 4.10")
        case .uv:
            return atLeast(v, [0, 9, 17]) ? .honours(uvToml) : .breaks
        case .pip:
            if atLeast(v, [26, 1]) { return .honours(pipSetting) }
            if atLeast(v, [26]) { return .breaks }
            return .ignores(reason: "before pip 26.1")
        case .mise:
            if atLeast(v, [2026, 10, 17]) { return .honours(miseToml) }
            // 2026.4.22 named the setting; before 2026.10.17 mise cannot date a
            // vfox plugin's releases and lets every version of those tools through.
            return atLeast(v, [2026, 4, 22])
                ? .ignores(reason: "lets vfox-backed tools such as gcloud through; fixed in mise 2026.10.17")
                : .ignores(reason: "before mise 2026.4.22")
        case .bundler:
            return atLeast(v, [4, 0, 13]) ? .honours(bundleConfig) : .ignores(reason: "before Bundler 4.0.13")
        }
    }

    /// The setting a manager is held to when no copy's version says otherwise:
    /// the one its current releases read.
    static func primarySetting(_ manager: Manager, pipSetting: Setting) -> Setting {
        switch manager {
        case .npm: return npmrc
        case .pnpm: return pnpmYAML
        case .yarn: return yarnrc
        case .uv: return uvToml
        case .pip: return pipSetting
        case .mise: return miseToml
        case .bundler: return bundleConfig
        }
    }

    // MARK: State

    public struct Copy: Sendable, Equatable {
        public let manager: Manager
        public let version: [Int]?
        /// Where it was installed from, e.g. "Homebrew", "mise", "Corepack".
        public let source: String
        public let support: Support

        var label: String { label(nil) }

        /// `pnpm 10.7.1 (Corepack; before pnpm 10.16)`.
        func label(_ note: String?) -> String {
            let v = version.map { $0.map(String.init).joined(separator: ".") } ?? "of unknown version"
            return "\(manager.displayName) \(v) (\([source, note].compactMap { $0 }.joined(separator: "; ")))"
        }
    }

    public enum Window: Sendable, Equatable {
        case missing
        case short(days: Double, builtIn: Bool)
        case set(days: Double)
        /// Set, but to something that is not a rolling window (a fixed date, or
        /// a value the tool would misread). csec leaves a deliberate value alone.
        case notRolling
        /// A key csec does not judge overrides the window or exempts packages.
        case overridden(key: String, file: String)
        /// The file exists but is a symlink, unreadable or too large to read whole.
        case unreadable
    }

    public struct SettingState: Sendable, Equatable {
        public let setting: Setting
        public let window: Window
        /// The file as it is now, or nil when absent; used only to build the fix.
        let text: String?
    }

    public struct ManagerState: Sendable, Equatable {
        public let manager: Manager
        public let copies: [Copy]
        /// The settings this manager's copies read (the primary one when no
        /// copy's version is known), in a stable order.
        public let settings: [SettingState]
        /// Why the fix for this manager is withheld, if it is; set by `inspect`.
        public let fixWithheld: String?

        var needsFix: [SettingState] {
            settings.filter {
                switch $0.window {
                case .missing, .short: return true
                default: return false
                }
            }
        }
    }

    // MARK: Inspection

    /// Every manager this user has, with its copies and settings. Reads only
    /// install directories, package metadata and the settings files.
    public static func inspect(_ ctx: HostAuditContext) -> [ManagerState] {
        let files = ctx.files
        let pipFile = activePipConfig(files)
        // The fix edits the section pip's install reads: [install] when the
        // current file already sets the key there, since it beats [global].
        var pipSection = "global"
        if case let .text(text) = readFile(pipFile, files),
           ReleaseCooldownConfig.value(in: text, key: "uploaded-prior-to", format: .configparser(section: "install")) != nil {
            pipSection = "install"
        }
        let pip = pipSetting(pipFile, section: pipSection)
        var states: [ManagerState] = []
        for manager in Manager.allCases {
            let copies = findCopies(manager, files: files, pipSetting: pip)
            guard !copies.isEmpty || hasUserTrace(manager, files: files) else { continue }
            var wanted: [Setting] = []
            for copy in copies {
                if case let .honours(setting) = copy.support, !wanted.contains(setting) {
                    wanted.append(setting)
                }
            }
            if wanted.isEmpty { wanted = [primarySetting(manager, pipSetting: pip)] }
            let settings = wanted.map { read($0, files: files, manager: manager) }
            let withheld = withholding(manager, copies: copies, settings: settings, files: files)
            states.append(ManagerState(manager: manager, copies: copies, settings: settings, fixWithheld: withheld))
        }
        return states
    }

    /// pip's current user file on this Mac, which overrides the legacy one.
    static func activePipConfig(_ files: FileInspecting) -> String {
        files.isDirectory("\(files.homeDirectory)/Library/Application Support/pip")
            ? "Library/Application Support/pip/pip.conf" : ".config/pip/pip.conf"
    }

    /// The largest config file csec reads; a larger one is unreadable to it, so
    /// a fix never writes back a truncated copy.
    static let maxConfigBytes = 262_144

    enum FileRead: Equatable {
        case absent
        case unreadable
        case text(String)
    }

    /// A user file read whole and decoded strictly, or why it was not.
    static func readFile(_ relativePath: String, _ files: FileInspecting) -> FileRead {
        let path = "\(files.homeDirectory)/\(relativePath)"
        guard exists(path, files) else { return .absent }
        guard files.isRegularFile(path), let text = files.readText(path, maxBytes: maxConfigBytes + 1),
              text.utf8.count <= maxConfigBytes,
              // readText decodes leniently; a replacement character means bytes
              // that were not UTF-8, which a rewrite would destroy.
              !text.unicodeScalars.contains("\u{FFFD}")
        else { return .unreadable }
        return .text(text)
    }

    static func read(_ setting: Setting, files: FileInspecting, manager: Manager) -> SettingState {
        let file = readFile(setting.relativePath, files)
        let text: String?
        switch file {
        case .unreadable: return SettingState(setting: setting, window: .unreadable, text: nil)
        case .absent: text = nil
        case let .text(t): text = t
        }
        let value: String?
        switch manager {
        case .pip:
            switch effectivePipValue(setting, current: text, files: files) {
            case .legacyUnreadable:
                return SettingState(setting: setting, window: .unreadable, text: text)
            case let .value(found):
                value = found
            }
        case .mise:
            value = text.flatMap { miseValue($0, key: setting.key) }
        default:
            value = text.flatMap { ReleaseCooldownConfig.value(in: $0, key: setting.key, format: setting.format) }
        }
        var window = windowFor(value, setting)
        if case .set = window, let text,
           let key = setting.overrides.first(where: { overrideIsSet($0, in: text, setting: setting) }) {
            window = .overridden(key: key, file: setting.relativePath)
        }
        if case .set = window, manager == .mise,
           let conflict = miseConflict(setting, files: files) {
            window = conflict
        }
        return SettingState(setting: setting, window: window, text: text)
    }

    /// Whether an override key is present in the setting's scope. pnpm's
    /// `minimumReleaseAgeStrict` only overrides when turned off.
    static func overrideIsSet(_ key: String, in text: String, setting: Setting) -> Bool {
        if case .toml = setting.format, ReleaseCooldownConfig.hasTable(text, key) { return true }
        guard let value = ReleaseCooldownConfig.value(in: text, key: key, format: setting.format) else { return false }
        if key == "minimumReleaseAgeStrict" { return value.lowercased() == "false" }
        return true
    }

    enum PipLookup {
        case legacyUnreadable
        case value(String?)
    }

    /// pip's effective value: `[install]` of the current file, then of the
    /// legacy file, then `[global]` of each.
    static func effectivePipValue(_ setting: Setting, current: String?, files: FileInspecting) -> PipLookup {
        var legacy: String?
        switch readFile(pipLegacyConfig, files) {
        case .unreadable: return .legacyUnreadable
        case .absent: legacy = nil
        case let .text(t): legacy = t
        }
        for section in ["install", "global"] {
            for text in [current, legacy].compactMap({ $0 }) {
                if let value = ReleaseCooldownConfig.value(
                    in: text, key: setting.key, format: .configparser(section: section)) {
                    return .value(value)
                }
            }
        }
        return .value(nil)
    }

    /// mise's `[settings]` key, or the same key dotted at the root.
    static func miseValue(_ text: String, key: String) -> String? {
        ReleaseCooldownConfig.value(in: text, key: key, format: .toml(table: "settings"))
            ?? ReleaseCooldownConfig.value(in: text, key: "settings.\(key)", format: .toml(table: nil))
    }

    /// A window set differently in another file mise reads.
    static func miseConflict(_ setting: Setting, files: FileInspecting) -> Window? {
        let home = files.homeDirectory
        let confD = ".config/mise/conf.d"
        let others = miseOtherConfigs + files.directoryEntries("\(home)/\(confD)")
            .filter { $0.hasSuffix(".toml") }.sorted().map { "\(confD)/\($0)" }
        for relative in others {
            switch readFile(relative, files) {
            case .absent:
                continue
            case .unreadable:
                return .overridden(key: setting.key, file: relative)
            case let .text(text):
                guard let value = miseValue(text, key: setting.key) else { continue }
                if case .set = windowFor(value, setting) { continue }
                return .overridden(key: setting.key, file: relative)
            }
        }
        return nil
    }

    static func windowFor(_ raw: String?, _ setting: Setting) -> Window {
        guard let raw else {
            if let builtIn = setting.builtInDays {
                return builtIn >= windowDays ? .set(days: builtIn) : .short(days: builtIn, builtIn: true)
            }
            return .missing
        }
        let value = raw.trimmingCharacters(in: .whitespaces)
        let days: Double?
        switch setting.grammar {
        case .number:
            days = ReleaseCooldownConfig.plainNumber(value).map { $0 * setting.bareUnitDays }
        case .duration:
            days = ReleaseCooldownConfig.durationDays(value, bareUnitDays: setting.bareUnitDays)
        case .leadingInteger:
            days = ReleaseCooldownConfig.plainNumber(String(value.prefix { $0.isASCII && $0.isNumber }))
                .map { $0 * setting.bareUnitDays }
        case .integer:
            days = value.allSatisfy({ $0.isASCII && $0.isNumber }) && !value.isEmpty
                ? Double(value).map { $0 * setting.bareUnitDays } : nil
        case .isoDays:
            let body = value.dropFirst().dropLast()
            days = value.first == "P" && value.last == "D" && !body.isEmpty
                && body.allSatisfy({ $0.isASCII && $0.isNumber }) ? Double(body) : nil
        }
        guard let days, days.isFinite else { return .notRolling }
        return days >= windowDays ? .set(days: days) : .short(days: days, builtIn: false)
    }

    static func exists(_ path: String, _ files: FileInspecting) -> Bool {
        files.isRegularFile(path) || files.isSymbolicLink(path) || files.fileExists(path)
            || files.permissions(path) != nil
    }

    /// Signs the user has used a manager even when no copy was found (a config
    /// file, cache or data directory).
    static func hasUserTrace(_ manager: Manager, files: FileInspecting) -> Bool {
        let home = files.homeDirectory
        let traces: [String]
        switch manager {
        case .npm: traces = [".npmrc", ".npm"]
        case .pnpm: traces = [pnpmYAML.relativePath, pnpmRC.relativePath, "Library/pnpm", "Library/Caches/pnpm"]
        case .yarn: traces = [".yarnrc.yml", ".yarnrc", ".yarn", "Library/Caches/Yarn"]
        case .uv: traces = [".config/uv", ".cache/uv", ".local/share/uv", ".local/bin/uv", ".cargo/bin/uv"]
        case .pip: traces = pipConfigs + ["Library/Caches/pip"]
        case .mise: traces = [".config/mise", ".local/share/mise", ".local/bin/mise"]
        case .bundler: traces = [".bundle"]
        }
        return traces.contains { exists("\(home)/\($0)", files) }
    }

    // MARK: Fix eligibility

    /// Why `manager`'s fix is withheld, or nil when it may be offered.
    static func withholding(
        _ manager: Manager, copies: [Copy], settings: [SettingState], files: FileInspecting
    ) -> String? {
        if let broken = copies.first(where: { $0.support == .breaks }) {
            return "\(broken.label) cannot read the setting and would fail every command; update it first"
        }
        if manager == .uv, let unknown = copies.first(where: { $0.support == .undetermined }) {
            return "\(unknown.label) may be too old to read the setting, which makes uv fail every command; update it first"
        }
        let needed = settings.filter {
            switch $0.window {
            case .missing, .short: return true
            default: return false
            }
        }
        for state in needed {
            if let link = linkedComponent(state.setting.relativePath, files) {
                return "~/\(link) is a link, and csec does not write through links; set it in the linked file"
            }
            // Simulate the write and read the result back as the tool would, so
            // a fix is offered only when it actually leaves a week in effect.
            guard let updated = ReleaseCooldownConfig.setting(
                state.text, key: state.setting.key, literal: state.setting.literal, format: state.setting.format)
            else {
                return "csec cannot edit ~/\(state.setting.relativePath) safely; set \(state.setting.key) by hand"
            }
            let after = read(
                state.setting,
                files: OverlayFiles(base: files, overrides: [state.setting.relativePath: updated]),
                manager: manager)
            guard case .set = after.window else {
                return "another setting would still override the window after the edit; "
                    + "set \(state.setting.key) by hand"
            }
        }
        return nil
    }

    /// The first path component below the home directory that is a symlink.
    static func linkedComponent(_ relativePath: String, _ files: FileInspecting) -> String? {
        var partial = ""
        for component in relativePath.split(separator: "/") {
            partial = partial.isEmpty ? String(component) : "\(partial)/\(component)"
            if files.isSymbolicLink("\(files.homeDirectory)/\(partial)") { return partial }
        }
        return nil
    }

    /// The real files with some replaced by simulated contents.
    struct OverlayFiles: FileInspecting {
        let base: FileInspecting
        let overrides: [String: String]
        var homeDirectory: String { base.homeDirectory }
        private func replaced(_ path: String) -> String? {
            let prefix = homeDirectory + "/"
            guard path.hasPrefix(prefix) else { return nil }
            return overrides[String(path.dropFirst(prefix.count))]
        }
        func fileExists(_ path: String) -> Bool { replaced(path) != nil || base.fileExists(path) }
        func isExecutableFile(_ path: String) -> Bool { base.isExecutableFile(path) }
        func isDirectory(_ path: String) -> Bool { replaced(path) == nil && base.isDirectory(path) }
        func isRegularFile(_ path: String) -> Bool { replaced(path) != nil || base.isRegularFile(path) }
        func isSymbolicLink(_ path: String) -> Bool { replaced(path) == nil && base.isSymbolicLink(path) }
        func readText(_ path: String, maxBytes: Int) -> String? {
            replaced(path) ?? base.readText(path, maxBytes: maxBytes)
        }
        func readPropertyList(_ path: String) -> Any? { base.readPropertyList(path) }
        func permissions(_ path: String) -> HostFilePermissions? { base.permissions(path) }
        func directoryEntries(_ path: String) -> [String] { base.directoryEntries(path) }
    }

    // MARK: Finding copies without running them

    static let homebrewPrefixes = ["/opt/homebrew", "/usr/local"]

    /// Each Node install's global `lib/node_modules`, where its npm lives and
    /// where `npm install -g pnpm`/`yarn` put theirs.
    static func nodeModuleRoots(_ files: FileInspecting) -> [(path: String, source: String)] {
        let home = files.homeDirectory
        var roots: [(String, String)] = homebrewPrefixes.map { ("\($0)/lib/node_modules", "Homebrew") }
        let mise = "\(home)/.local/share/mise/installs/node"
        for v in fullVersionNames(files, mise) { roots.append(("\(mise)/\(v)/lib/node_modules", "mise")) }
        let managers: [(String, String, String)] = [
            ("\(home)/.nvm/versions/node", "lib/node_modules", "nvm"),
            ("\(home)/.local/share/fnm/node-versions", "installation/lib/node_modules", "fnm"),
            ("\(home)/Library/Application Support/fnm/node-versions", "installation/lib/node_modules", "fnm"),
            ("\(home)/.asdf/installs/nodejs", "lib/node_modules", "asdf"),
            ("\(home)/.volta/tools/image/node", "lib/node_modules", "Volta"),
        ]
        for (root, sub, source) in managers {
            for v in files.directoryEntries(root).sorted() where parseVersion(v) != nil {
                roots.append(("\(root)/\(v)/\(sub)", source))
            }
        }
        return roots
    }

    /// Each Python's `lib` directory, whose `pythonX.Y/site-packages` holds pip
    /// (and a pip-installed uv).
    static func pythonLibs(_ files: FileInspecting) -> [(path: String, source: String)] {
        let home = files.homeDirectory
        var libs: [(String, String)] = []
        let mise = "\(home)/.local/share/mise/installs/python"
        for v in fullVersionNames(files, mise) { libs.append(("\(mise)/\(v)/lib", "mise")) }
        for prefix in homebrewPrefixes { libs.append(("\(prefix)/lib", "Homebrew")) }
        for v in files.directoryEntries("\(home)/.pyenv/versions").sorted() {
            libs.append(("\(home)/.pyenv/versions/\(v)/lib", "pyenv"))
        }
        let uvPythons = "\(home)/.local/share/uv/python"
        for v in files.directoryEntries(uvPythons).sorted() { libs.append(("\(uvPythons)/\(v)/lib", "uv")) }
        let frameworks: [(String, String)] = [
            ("/Library/Frameworks/Python.framework/Versions", "python.org"),
            ("/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions",
             "Apple Command Line Tools"),
            ("/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions", "Xcode"),
        ]
        for (root, source) in frameworks {
            for v in files.directoryEntries(root).sorted() where v != "Current" {
                libs.append(("\(root)/\(v)/lib", source))
            }
        }
        return libs
    }

    /// Every `site-packages` directory found: each Python's, and the user site.
    static func sitePackages(_ files: FileInspecting) -> [(path: String, source: String)] {
        var dirs: [(String, String)] = []
        for (lib, source) in pythonLibs(files) {
            for python in files.directoryEntries(lib).sorted() where python.hasPrefix("python") {
                dirs.append(("\(lib)/\(python)/site-packages", source))
            }
        }
        let userSite = "\(files.homeDirectory)/Library/Python"
        for v in files.directoryEntries(userSite).sorted() {
            dirs.append(("\(userSite)/\(v)/lib/python/site-packages", "user site-packages"))
        }
        return dirs
    }

    static func findCopies(_ manager: Manager, files: FileInspecting, pipSetting: Setting) -> [Copy] {
        let home = files.homeDirectory
        let mise = "\(home)/.local/share/mise/installs"
        let corepack = "\(home)/.cache/node/corepack/v1"
        var found: [(version: [Int]?, source: String)] = []

        func packageJSON(_ path: String, _ source: String) {
            guard let json = readJSON(files, path), let v = json["version"] as? String,
                  let version = parseVersion(v) else { return }
            found.append((version, source))
        }
        func versionDirectories(_ directory: String, _ source: String) {
            for entry in fullVersionEntries(files, directory) { found.append((entry, source)) }
        }
        func homebrewFormula(_ formula: String) {
            for prefix in homebrewPrefixes {
                let receipt = "\(prefix)/opt/\(formula)/INSTALL_RECEIPT.json"
                guard let json = readJSON(files, receipt),
                      let source = json["source"] as? [String: Any],
                      let versions = source["versions"] as? [String: Any],
                      let stable = versions["stable"] as? String,
                      let version = parseVersion(stable) else { continue }
                found.append((version, "Homebrew"))
            }
        }
        func standalone(_ relative: String) {
            if exists("\(home)/\(relative)", files) { found.append((nil, "standalone")) }
        }
        func distInfo(_ package: String) {
            for (dir, source) in sitePackages(files) {
                for entry in files.directoryEntries(dir)
                where entry.hasPrefix("\(package)-") && entry.hasSuffix(".dist-info") {
                    let v = entry.dropFirst(package.count + 1).dropLast(".dist-info".count)
                    if let version = parseVersion(String(v)) { found.append((version, source)) }
                }
            }
        }

        switch manager {
        case .npm:
            for (root, source) in nodeModuleRoots(files) { packageJSON("\(root)/npm/package.json", source) }
            versionDirectories("\(mise)/npm", "mise")
            versionDirectories("\(home)/.volta/tools/image/npm", "Volta")
        case .pnpm:
            versionDirectories("\(corepack)/pnpm", "Corepack")
            versionDirectories("\(mise)/pnpm", "mise")
            homebrewFormula("pnpm")
            for (root, source) in nodeModuleRoots(files) {
                packageJSON("\(root)/pnpm/package.json", "\(source) npm global")
            }
            // pnpm's own installer and `pnpm self-update` keep each version under
            // PNPM_HOME/.tools/<package>/<version>.
            let tools = "\(home)/Library/pnpm/.tools"
            for package in files.directoryEntries(tools).sorted() {
                versionDirectories("\(tools)/\(package)", "pnpm installer")
            }
            if found.isEmpty { standalone("Library/pnpm/pnpm") }
        case .yarn:
            versionDirectories("\(corepack)/yarn", "Corepack")
            versionDirectories("\(mise)/yarn", "mise")
            homebrewFormula("yarn")
            for (root, source) in nodeModuleRoots(files) {
                packageJSON("\(root)/yarn/package.json", "\(source) npm global")
            }
        case .uv:
            versionDirectories("\(mise)/uv", "mise")
            homebrewFormula("uv")
            distInfo("uv")
            standalone(".local/bin/uv")
            standalone(".cargo/bin/uv")
        case .pip:
            distInfo("pip")
        case .mise:
            homebrewFormula("mise")
            standalone(".local/bin/mise")
        case .bundler:
            var gemRoots: [(String, String)] = []
            for ruby in fullVersionNames(files, "\(mise)/ruby") {
                gemRoots.append(("\(mise)/ruby/\(ruby)/lib/ruby/gems", "mise"))
            }
            for prefix in homebrewPrefixes { gemRoots.append(("\(prefix)/opt/ruby/lib/ruby/gems", "Homebrew")) }
            for ruby in files.directoryEntries("\(home)/.rbenv/versions").sorted() {
                gemRoots.append(("\(home)/.rbenv/versions/\(ruby)/lib/ruby/gems", "rbenv"))
            }
            gemRoots.append(("\(home)/.gem/ruby", "user gems"))
            for (root, source) in gemRoots {
                bundlerGems(files, root, source, into: &found)
            }
            let system = "/System/Library/Frameworks/Ruby.framework/Versions/Current/usr/lib/ruby"
            for abi in files.directoryEntries(system).sorted() {
                if let text = files.readText("\(system)/\(abi)/bundler/version.rb", maxBytes: 4_096),
                   let version = rubyVersionConstant(text) {
                    found.append((version, "macOS"))
                }
            }
        }

        var copies: [Copy] = []
        for item in found where !copies.contains(where: { $0.version == item.version && $0.source == item.source }) {
            copies.append(Copy(
                manager: manager, version: item.version, source: item.source,
                support: support(manager, version: item.version, pipSetting: pipSetting)))
        }
        return copies
    }

    /// Bundler in each Ruby ABI directory under `gems`: installed gems
    /// (`gems/bundler-<v>`) and the Ruby's default gem
    /// (`specifications/default/bundler-<v>.gemspec`).
    static func bundlerGems(
        _ files: FileInspecting, _ gems: String, _ source: String, into found: inout [(version: [Int]?, source: String)]
    ) {
        for abi in files.directoryEntries(gems).sorted() {
            var names = files.directoryEntries("\(gems)/\(abi)/gems").filter { $0.hasPrefix("bundler-") }
            names += files.directoryEntries("\(gems)/\(abi)/specifications/default")
                .filter { $0.hasPrefix("bundler-") && $0.hasSuffix(".gemspec") }
                .map { String($0.dropLast(".gemspec".count)) }
            for name in names.sorted() {
                // `bundler-audit-…` and the like parse as no version.
                if let version = parseVersion(String(name.dropFirst("bundler-".count))) {
                    found.append((version, source))
                }
            }
        }
    }

    static func rubyVersionConstant(_ text: String) -> [Int]? {
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("VERSION"), let open = trimmed.firstIndex(of: "\"") else { continue }
            let rest = trimmed[trimmed.index(after: open)...]
            guard let close = rest.firstIndex(of: "\"") else { continue }
            return parseVersion(String(rest[..<close]))
        }
        return nil
    }

    /// Entries of `directory` named as a full `X.Y.Z` version: mise's alias
    /// links (`22`, `22.18`, `latest`) are skipped, so each install counts once.
    static func fullVersionNames(_ files: FileInspecting, _ directory: String) -> [String] {
        files.directoryEntries(directory).filter { name in
            let parts = name.split(separator: ".")
            return parts.count >= 3 && parts.prefix(3).allSatisfy { part in
                part.first?.isNumber == true
            } && parseVersion(name) != nil
        }.sorted()
    }

    static func fullVersionEntries(_ files: FileInspecting, _ directory: String) -> [[Int]] {
        fullVersionNames(files, directory).compactMap(parseVersion)
    }

    static func readJSON(_ files: FileInspecting, _ path: String) -> [String: Any]? {
        guard let text = files.readText(path, maxBytes: 262_144), let data = text.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    /// `11.21.1`, `v24.1.0`, `3.15.0_1`, `4.0.0-rc.1` → their leading numbers.
    public static func parseVersion(_ raw: String) -> [Int]? {
        var text = Substring(raw)
        if text.first == "v" { text = text.dropFirst() }
        var parts: [Int] = []
        for piece in text.split(separator: ".", omittingEmptySubsequences: false) {
            let digits = piece.prefix { $0.isASCII && $0.isNumber }
            guard let n = Int(digits) else { break }
            parts.append(n)
            if digits.count != piece.count { break }
        }
        return parts.isEmpty ? nil : parts
    }

    static func atLeast(_ version: [Int], _ floor: [Int]) -> Bool {
        for i in 0..<max(version.count, floor.count) {
            let a = i < version.count ? version[i] : 0
            let b = i < floor.count ? floor[i] : 0
            if a != b { return a > b }
        }
        return true
    }

    // MARK: Fixes

    /// One manager's picker row: the settings files to write.
    public struct Fix: Sendable, Equatable {
        public let manager: Manager
        public let settings: [Setting]
    }

    public static func fixes(_ states: [ManagerState]) -> [Fix] {
        states.compactMap { state in
            guard state.fixWithheld == nil else { return nil }
            var settings: [Setting] = []
            for needed in state.needsFix.map(\.setting)
            where !settings.contains(where: { $0.relativePath == needed.relativePath && $0.key == needed.key }) {
                settings.append(needed)
            }
            return settings.isEmpty ? nil : Fix(manager: state.manager, settings: settings)
        }
    }

    /// Write each of `fix`'s settings, re-reading the file first so an edit made
    /// since the audit is kept. True only when every file was written.
    public static func apply(_ fix: Fix, ctx: HostAuditContext) -> Bool {
        let home = ctx.files.homeDirectory
        var ok = true
        for setting in fix.settings {
            let current: String?
            switch readFile(setting.relativePath, ctx.files) {
            case .unreadable:
                ok = false
                continue
            case .absent: current = nil
            case let .text(text): current = text
            }
            guard let updated = ReleaseCooldownConfig.setting(
                current, key: setting.key, literal: setting.literal, format: setting.format) else {
                ok = false
                continue
            }
            if !ctx.userConfig.replace(home: home, relativePath: setting.relativePath, contents: updated) {
                ok = false
            }
        }
        return ok
    }

    // MARK: Finding

    static func describe(_ window: Window) -> String {
        switch window {
        case .missing: return "not set"
        case let .short(days, builtIn):
            return builtIn ? "\(daysText(days)), its built-in default" : daysText(days)
        case let .set(days): return daysText(days)
        case .notRolling: return "set to a value that is not a rolling window"
        case let .overridden(key, file): return "\(key) in ~/\(file) overrides it or exempts packages"
        case .unreadable: return "its config file is a link, unreadable or too large"
        }
    }

    static func daysText(_ days: Double) -> String {
        if days >= 1, days == days.rounded() { return days == 1 ? "1 day" : "\(Int(days)) days" }
        let hours = days * 24
        if hours >= 1, hours == hours.rounded() { return hours == 1 ? "1 hour" : "\(Int(hours)) hours" }
        let minutes = days * 1_440
        if minutes >= 1, minutes == minutes.rounded() {
            return minutes == 1 ? "1 minute" : "\(Int(minutes)) minutes"
        }
        return String(format: "%.2g days", days)
    }

    public static func evaluate(_ states: [ManagerState]) -> (status: FindingStatus, evidence: String) {
        guard !states.isEmpty else {
            return (.notApplicable, "No npm, pnpm, Yarn, uv, pip, mise or Bundler was found for this user.")
        }
        var short: [String] = []
        var uncertain: [String] = []
        var gaps: [String] = []
        var withheld: [String] = []
        for state in states {
            let name = state.manager.displayName
            for setting in state.settings {
                switch setting.window {
                case .missing, .short:
                    short.append("\(name) (\(describe(setting.window)) in ~/\(setting.setting.relativePath))")
                case .notRolling, .unreadable:
                    uncertain.append("\(name) (\(describe(setting.window)): ~/\(setting.setting.relativePath))")
                case .overridden:
                    uncertain.append("\(name) (\(describe(setting.window)))")
                case .set:
                    break
                }
            }
            if state.copies.isEmpty {
                uncertain.append("\(name) (no installed copy found to confirm which file it reads)")
            }
            for copy in state.copies {
                switch copy.support {
                case let .ignores(reason): gaps.append(copy.label(reason))
                case .breaks: gaps.append(copy.label("cannot read the setting"))
                case .undetermined: gaps.append(copy.label)
                case .honours: break
                }
            }
            if !state.needsFix.isEmpty, let reason = state.fixWithheld {
                withheld.append("\(name): \(reason)")
            }
        }
        let window = daysText(windowDays)
        var parts: [String] = []
        if !short.isEmpty {
            parts.append("Under the \(window) release cooldown: \(short.joined(separator: "; ")).")
        }
        if !uncertain.isEmpty {
            parts.append("Not determined: \(uncertain.joined(separator: "; ")).")
        }
        if !gaps.isEmpty {
            parts.append("Copies that install releases of any age: \(gaps.joined(separator: "; ")).")
        }
        if !withheld.isEmpty {
            parts.append("Fix withheld for \(withheld.joined(separator: "; ")).")
        }
        let names = states.map(\.manager.displayName).joined(separator: ", ")
        if !short.isEmpty { return (.fail, parts.joined(separator: " ")) }
        if !parts.isEmpty {
            return (.unknown, "Found \(names); not every one is known to hold back releases for \(window). "
                    + parts.joined(separator: " "))
        }
        let copies = states.reduce(0) { $0 + $1.copies.count }
        return (.pass, "\(names) hold back releases for at least \(window); all \(copies) copies found honour it.")
    }
}
