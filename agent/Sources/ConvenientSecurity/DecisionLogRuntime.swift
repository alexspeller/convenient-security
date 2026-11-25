import Foundation
import Security
#if canImport(Darwin)
import Darwin
#endif

/// Kernel and code-signing facts about the running csecd, read once at start.
public enum CsecdRunFacts {
    /// `kern.bootsessionuuid`: changes on every boot, so a stored value from an
    /// earlier boot is recognized as such.
    public static func bootSessionUUID() -> String? {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1, size <= 256 else {
            return nil
        }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 else { return nil }
        let value = String(cString: buffer)
        return value.isEmpty ? nil : value
    }

    /// The running code's cdhash (lowercase hex), or nil for unsigned code.
    public static func currentCDHash() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(rawValue: 0), &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)), &information
        ) == errSecSuccess,
              let dictionary = information as? [String: Any],
              let unique = dictionary[kSecCodeInfoUnique as String] as? Data else { return nil }
        return unique.map { String(format: "%02x", $0) }.joined()
    }

    /// The bundle's marketing version and build, when csecd runs from the app.
    public static func currentVersion() -> String? {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String
        let build = info?["CFBundleVersion"] as? String
        switch (short, build) {
        case let (short?, build?): return "\(short) (\(build))"
        case let (short?, nil): return short
        case let (nil, build?): return build
        default: return nil
        }
    }
}

/// The `runtime`/`last-run-v1` protected item: who the previous csecd was and
/// whether it shut down cleanly. Written at every start and marked clean by
/// the SIGTERM handler, so the next start can say why it is restarting.
public struct CsecdLastRun: ProtectedDocument, Equatable {
    public static let protectedItem: ProtectedItem = .lastRun
    public static let formatVersion = 1
    /// It records no decision, and every start rewrites it whole: one this
    /// build cannot read only makes the restart cause `unknown`.
    public static let holdsUnreadableItem = false

    public var bootSessionUUID: String?
    public var pid: Int32
    public var startTimeMicros: UInt64
    public var cdHash: String?
    public var version: String?
    public var cleanShutdown: Bool

    public init(
        bootSessionUUID: String?,
        pid: Int32,
        startTimeMicros: UInt64,
        cdHash: String?,
        version: String?,
        cleanShutdown: Bool = false
    ) {
        self.bootSessionUUID = bootSessionUUID
        self.pid = pid
        self.startTimeMicros = startTimeMicros
        self.cdHash = cdHash
        self.version = version
        self.cleanShutdown = cleanShutdown
    }

    /// This process, as it would be recorded at start.
    public static func current() -> CsecdLastRun {
        let pid = getpid()
        return CsecdLastRun(
            bootSessionUUID: CsecdRunFacts.bootSessionUUID(),
            pid: pid,
            startTimeMicros: ProcessAncestry.startTime(of: pid) ?? 0,
            cdHash: CsecdRunFacts.currentCDHash(),
            version: CsecdRunFacts.currentVersion().map {
                ReviewDisplay.bounded(ReviewDisplay.sanitized($0), maxBytes: 128)
            }
        )
    }

    public var isWellFormed: Bool {
        pid > 0
            && (bootSessionUUID?.utf8.count ?? 0) <= 64
            && (cdHash?.utf8.count ?? 0) <= 128
            && (version?.utf8.count ?? 0) <= 128
    }
}

/// Why the previous csecd is no longer running, as the next start sees it.
public enum CsecdRestartCause: String, Codable, Sendable, CaseIterable {
    /// No record of a previous run.
    case firstStart = "first_start"
    /// The Mac rebooted since.
    case reboot
    /// A different build (an upgrade, or a downgrade).
    case upgrade
    /// The same build stopped cleanly on SIGTERM: `kickstart -k`, `bootout`,
    /// `csec doctor`, or any other SIGTERM, which look the same.
    case restart
    /// The same build stopped without its SIGTERM handler running: a crash,
    /// or SIGKILL.
    case crash
    /// The previous record exists but this build cannot read it.
    case unknown

    /// The restart classification, in order: a different boot is a reboot, a
    /// different cdhash an upgrade, a clean shutdown a restart, anything else
    /// a crash.
    public static func classify(previous: CsecdLastRun?, current: CsecdLastRun) -> CsecdRestartCause {
        guard let previous else { return .firstStart }
        if previous.bootSessionUUID != current.bootSessionUUID { return .reboot }
        if previous.cdHash != current.cdHash { return .upgrade }
        return previous.cleanShutdown ? .restart : .crash
    }
}

/// The one owner of `last-run-v1`: it records this run at start and marks it
/// clean at shutdown, and knows why the previous run ended.
public actor CsecdLifecycle {
    private let stores: ProtectedStores
    private let store: ProtectedStore<CsecdLastRun>
    private let log: DecisionLog?
    private var current: CsecdLastRun
    public private(set) var restartCause: CsecdRestartCause?
    public private(set) var previousRun: CsecdLastRun?

    public init(stores: ProtectedStores, log: DecisionLog?, current: CsecdLastRun = .current()) {
        self.stores = stores
        self.store = stores.store(for: CsecdLastRun.self)
        self.log = log
        self.current = current
    }

    /// Classifies the restart, records this run (not yet clean), and logs a
    /// `restart` record naming the cause, with what the persisted grants
    /// item restored and dropped when csecd loaded it.
    @discardableResult
    public func start(grantCounts: DecisionLogRecord.GrantCounts? = nil) async -> CsecdRestartCause {
        if let restartCause { return restartCause }
        let cause: CsecdRestartCause
        switch await store.load() {
        case .absent:
            cause = .firstStart
        case let .document(previous):
            previousRun = previous
            cause = CsecdRestartCause.classify(previous: previous, current: current)
        case .unreadable:
            cause = .unknown
        }
        restartCause = cause
        current.cleanShutdown = false
        if !stores.isUninstalled, let change = try? store.prepare(current) {
            _ = try? await change.commit()
        }
        var record = DecisionLogRecord(kind: .restart, cause: cause.rawValue)
        record.grants = grantCounts
        if let previousRun {
            record.detail = "previous csecd pid \(previousRun.pid)"
                + (previousRun.version.map { ", version \($0)" } ?? "")
                + (current.version.map { "; now version \($0)" } ?? "")
        }
        await log?.record(record)
        return cause
    }

    /// Marks this run as cleanly shut down. Writes nothing once uninstall has
    /// begun: the item it would recreate has just been deleted.
    @discardableResult
    public func markCleanShutdown() async -> Bool {
        guard !stores.isUninstalled else { return false }
        current.cleanShutdown = true
        guard let change = try? store.prepare(current) else { return false }
        return (try? await change.commit()) != nil
    }
}

/// What csecd does on SIGTERM before it exits.
public enum CsecdShutdown {
    /// How long the SIGTERM handler waits for the flush before exiting anyway.
    /// It bounds a hang (a wedged Keychain or disk write would otherwise hold
    /// a dying csecd until launchd's own exit timeout); it is not an expiry.
    public static let flushDeadlineSeconds = 3

    public struct Result: Sendable, Equatable {
        public var usageFlushed: Bool
        public var cleanShutdownMarked: Bool

        public init(usageFlushed: Bool, cleanShutdownMarked: Bool) {
            self.usageFlushed = usageFlushed
            self.cleanShutdownMarked = cleanShutdownMarked
        }
    }

    /// Flushes the usage checkpoint and marks the run clean, concurrently, so
    /// a busy log cannot keep the clean mark from being written before the
    /// deadline. Once uninstall has begun it writes nothing at all. It awaits
    /// only the log and the lifecycle actors, neither of which ever waits on a
    /// review, so a panel on screen cannot hold it up.
    public static func flush(
        stores: ProtectedStores?,
        log: DecisionLog?,
        lifecycle: CsecdLifecycle?
    ) async -> Result {
        guard let stores, !stores.isUninstalled else {
            return Result(usageFlushed: false, cleanShutdownMarked: false)
        }
        async let marked = lifecycle?.markCleanShutdown() ?? false
        async let flushed: Bool = {
            guard let log else { return false }
            await log.flushUsageCheckpoint()
            return true
        }()
        return Result(usageFlushed: await flushed, cleanShutdownMarked: await marked)
    }

    /// Catches SIGTERM with a handler that does nothing, so csecd's
    /// DispatchSource sees it and csecd decides when to exit. A caught signal
    /// (unlike an ignored one) goes back to its default action in every
    /// program csecd starts, so no child inherits a SIGTERM it cannot receive.
    public static func catchTerminationSignal() {
        signal(SIGTERM, csecdIgnoreTermination)
    }

    /// Puts SIGTERM back to its default action, so re-raising it ends csecd
    /// the way launchd expects.
    public static func restoreDefaultTerminationSignal() {
        signal(SIGTERM, SIG_DFL)
    }
}

/// The SIGTERM handler: it does nothing, because csecd's DispatchSource does
/// the shutdown work on its own queue.
private func csecdIgnoreTermination(_ signal: Int32) {}

/// What `uninstall_cleanup` removed, value-free.
public struct UninstallCleanupResult: Codable, Sendable, Equatable {
    /// `service/account` of each protected item that may remain, with why.
    public var remainingItems: [String]
    public var logDirectoryRemoved: Bool
    /// Other csecd files that could not be removed (by description).
    public var remainingFiles: [String]

    public init(remainingItems: [String], logDirectoryRemoved: Bool, remainingFiles: [String] = []) {
        self.remainingItems = remainingItems
        self.logDirectoryRemoved = logDirectoryRemoved
        self.remainingFiles = remainingFiles
    }

    public var isComplete: Bool {
        remainingItems.isEmpty && logDirectoryRemoved && remainingFiles.isEmpty
    }
}

/// csecd's side of `csec uninstall`: one Touch ID in csecd's settings panel, then the
/// terminal uninstalled state, then every protected item and the decision log
/// deleted. The state comes first so nothing csecd still does (a SIGTERM
/// flush, a log append, a grant or pairing write, a baseline save) can
/// recreate what is deleted.
public struct CsecdUninstaller: Sendable {
    /// Another csecd-owned file set to delete with the rest (the sealed host
    /// audit baseline). Returns a value-free description of what remains, or
    /// nil when it is gone.
    public typealias FileCleanup = @Sendable () async -> String?

    public enum Outcome: Sendable, Equatable {
        /// Touch ID was refused or cancelled: nothing changed.
        case denied
        case completed(UninstallCleanupResult)
    }

    private let consent: any ConsentProvider
    private let stores: ProtectedStores?
    private let log: DecisionLog?
    private let logDirectory: SealedRecordDirectory
    private let fileCleanups: [FileCleanup]
    private let delegation: ClaudeDelegationService?

    /// `logDirectory` is where the log lives on disk; it is deleted even when
    /// this csecd runs without a log (no protected stores this run), because
    /// an earlier run may have written one. It has no default: only the
    /// runtime names the real log, so no test or tool can delete it by
    /// leaving the argument out. `delegation`, when csecd runs one, drops
    /// the settings and pairings it holds in memory once the stores are
    /// uninstalled.
    public init(
        consent: any ConsentProvider,
        stores: ProtectedStores?,
        log: DecisionLog?,
        logDirectory: SealedRecordDirectory,
        fileCleanups: [FileCleanup] = [],
        delegation: ClaudeDelegationService? = nil
    ) {
        self.consent = consent
        self.stores = stores
        self.log = log
        self.logDirectory = logDirectory
        self.fileCleanups = fileCleanups
        self.delegation = delegation
    }

    /// What the cleanup deletes, as the Touch ID panel and `csec uninstall`
    /// say it: the eight protected items (grants, project pairings,
    /// delegation settings, and the last-run marker, log key, log checkpoint,
    /// baseline pointer and automation run leases that belong to the rest),
    /// the decision log and the sealed baseline.
    public static let deletedSummary =
        "protected Keychain items (grants, project pairings and delegation settings), "
        + "decision log and sealed host-audit baseline"

    /// What stays after an approved cleanup, and a reinstall uses again:
    /// csec data that is not csecd's approval state.
    public static let keptSummary =
        "cached secret values, native stores, the SSH key and automation catalogs, and the iPhone pairing"

    public static func reason(terminal: TerminalSessionContext?) -> String {
        "Uninstall Convenient Security and delete its \(deletedSummary)"
            + " — from \(ReviewDisplay.sanitized((terminal ?? .unidentified).summary))"
    }

    /// What csecd's settings panel lists for the cleanup.
    public static let change = SettingsChangeReviewDetails(
        title: "Uninstall Convenient Security",
        changes: ["Delete csecd's \(deletedSummary)", "Keep \(keptSummary), for a reinstall to use again"],
        footnote: "Touch ID approves exactly this cleanup. No secret is released."
    )

    /// One Touch ID in csecd's settings panel, naming the tab `caller` runs
    /// in (`caller.terminal`); `reason` is the line a provider with no panel
    /// shows instead.
    public func run(caller: CallerInfo) async -> Outcome {
        let authentication = await consent.authenticateSettingsChange(
            Self.change, caller: caller, reason: Self.reason(terminal: caller.terminal)
        )
        authentication.outcome.unlock?.invalidate()
        guard authentication.outcome.isApproved else { return .denied }
        await log?.record(DecisionLogRecord(
            kind: .uninstall, decider: .humanLocal,
            detail: "csec uninstall approved; deleting protected items and the decision log"
        ))
        stores?.enterUninstalledState()
        await delegation?.forgetForUninstall()
        let deletions = stores?.prepareDeletionOfAll()
        let logRemoved: Bool
        if let log {
            logRemoved = await log.eraseForUninstall()
        } else {
            logRemoved = (try? logDirectory.removeDirectory()) != nil || !logDirectory.exists()
        }
        var remainingFiles: [String] = []
        for cleanup in fileCleanups {
            if let remaining = await cleanup() { remainingFiles.append(remaining) }
        }
        let remainingItems: [String]
        if let deletions {
            remainingItems = await deletions.commit()
                .map { "\($0.key.description): \($0.value.description)" }
                .sorted()
        } else {
            // Without the access group this run, csecd cannot see its items,
            // let alone delete them: say so rather than report them gone.
            remainingItems = ProtectedItem.all.map {
                "\($0.description): not deleted (csecd has no Keychain access this run)"
            }
        }
        return .completed(UninstallCleanupResult(
            remainingItems: remainingItems,
            logDirectoryRemoved: logRemoved,
            remainingFiles: remainingFiles
        ))
    }
}
