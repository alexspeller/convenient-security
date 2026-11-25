import Foundation
import os
import ConvenientSecurity
import CSECRemoteApproval
import CSECBuildIdentity

/// csecd's stderr is discarded by launchd, so the unified log is the one place
/// a 1Password decision can be seen after the fact: which account served a
/// reference, when a bridge started or died, why the keepalive did or did not
/// run, and what the bridge itself reported on its stderr. Never a resolved
/// value.
///
/// The unified log is readable by any process that can run `log show` and is
/// copied into every sysdiagnose, so what it keeps in the clear is csec's own
/// fixed words, counts, timings and opaque tags. References, vault names,
/// account labels, error reasons and the bridge's stderr name things in the
/// user's 1Password; they are logged `.private`, which macOS redacts unless
/// private data logging was turned on for this Mac. A line names a reference
/// or an account by its tag (`ref#3`, `account#1`) so lines about the same one
/// still correlate, and the tag's first use logs one line pairing it with the
/// private text. `bin/ci` holds every `.public` interpolation in this adapter to
/// an allowlist.
///
/// Every line is written at `notice`, the lowest level macOS persists; `info`
/// lives only in a memory ring and is gone by the time anyone asks why a
/// prompt appeared.
///
///     /usr/bin/log show --last 1h --predicate 'subsystem == "IDENTIFIER" AND category == "onepassword"'
///
/// where IDENTIFIER is `CSEC_IDENTIFIER` in identity.xcconfig.
enum OnePasswordDiagnostics {
    static let log = Logger(
        subsystem: CSECBuildIdentity.identifier, category: "onepassword"
    )

    /// The tag a log line uses for an `op://` reference.
    static func reference(_ uri: String) -> String {
        tags.tag(kind: "ref", key: uri, text: uri)
    }

    /// The tag a log line uses for an account, keyed by its user UUID so a
    /// label that changes mid-run keeps one tag.
    static func account(_ account: OnePasswordAccount) -> String {
        tags.tag(kind: "account", key: account.userID, text: account.label)
    }

    static func account(userID: String, label: String?) -> String {
        tags.tag(kind: "account", key: userID, text: label ?? userID)
    }

    /// What kind of failure, in words that name nothing in 1Password: the
    /// error's type and case, and for a bridge failure the bridge's kind when
    /// it is one csec knows. The reason itself is logged private.
    static func kind(of error: Error) -> String {
        let type = String(describing: Swift.type(of: error))
        if case let .remote(kind, _)? = error as? OnePasswordBridgeError {
            return OnePasswordBridgeError.knownRemoteKinds.contains(kind)
                ? "\(type).remote(\(kind))" : "\(type).remote"
        }
        let mirror = Mirror(reflecting: error)
        if mirror.displayStyle == .enum, let label = mirror.children.first?.label {
            return "\(type).\(label)"
        }
        // A case without a payload has no label in its mirror, and its
        // description is the type's own text, which may name things; the
        // bridged code is the case's index.
        return "\(type) code \((error as NSError).code)"
    }

    private static let tags = Tags()

    /// Numbers each distinct reference or account by first appearance in this
    /// csecd process. A number says nothing about the name it stands for, and
    /// the table never leaves csecd.
    private final class Tags: @unchecked Sendable {
        private let lock = NSLock()
        private var assigned: [String: String] = [:]
        private var counts: [String: Int] = [:]

        func tag(kind: String, key: String, text: String) -> String {
            lock.lock()
            let slot = "\(kind)\u{0}\(key)"
            if let existing = assigned[slot] {
                lock.unlock()
                return existing
            }
            let next = (counts[kind] ?? 0) + 1
            counts[kind] = next
            let tag = "\(kind)#\(next)"
            assigned[slot] = tag
            lock.unlock()
            let shown = OnePasswordProvider.displaySafe(text)
            OnePasswordDiagnostics.log.notice(
                "\(tag, privacy: .public) is \(shown, privacy: .private)"
            )
            return tag
        }
    }
}

public enum OnePasswordConnectionStatus: String, Sendable, Equatable {
    case notStarted
    case cliUnavailable
    case connecting
    case connected
    case disconnected
}

public struct OnePasswordConnectionConfiguration: Sendable, Equatable {
    /// 1Password ends a desktop authorization after ten minutes of inactivity.
    /// Touching the session every four minutes holds one authorization open
    /// indefinitely, so the user authorizes once rather than once per read.
    public var keepaliveInterval: TimeInterval
    /// 1Password's documented idle window. csec never assumes a session
    /// outlives it.
    public var sessionIdleWindow: TimeInterval
    public var authenticationTimeout: TimeInterval
    /// How long a read that the bridge reports as "not found" is given to
    /// become found before csec believes it. A desktop session that has just
    /// re-authorized — every session does after the Mac sleeps — answers from
    /// an account whose vaults are still loading for a few seconds, and the SDK
    /// reports an item it has not loaded yet as absent. One pause per entry,
    /// re-reading after each; the total is the most a genuine typo can cost.
    public var missRetryDelays: [TimeInterval]
    /// How long a keepalive ping may take when it might be re-authorizing.
    /// Short: a ping that has to re-authorize puts up a prompt nobody asked
    /// for, and stopping its bridge takes the prompt down.
    public var keepalivePingDeadline: TimeInterval
    /// How long a keepalive ping may take when the session cannot have
    /// lapsed (`OnePasswordProvider.pingDeadline`). A busy Mac answers a
    /// healthy ping in seconds, and dropping that session costs the next
    /// real request a fresh authorization, which is a prompt; the bound
    /// remains for a 1Password that was locked by hand.
    public var patientKeepalivePingDeadline: TimeInterval
    /// How long a request that may be 1Password's authorizing one waits
    /// before csecd tells the person 1Password is asking
    /// (`OnePasswordProvider.authorizing`). An authorized first contact
    /// answers well inside it; one still waiting is almost always 1Password's
    /// prompt, which went unnoticed with the person at the Mac after 4 of 6
    /// installs (csec-0.64.17).
    public var authorizationNoticeDelay: TimeInterval

    public init(
        keepaliveInterval: TimeInterval = 4 * 60,
        sessionIdleWindow: TimeInterval = 10 * 60,
        authenticationTimeout: TimeInterval = 60,
        missRetryDelays: [TimeInterval] = [0.5, 1, 2],
        keepalivePingDeadline: TimeInterval = 2,
        patientKeepalivePingDeadline: TimeInterval = 15,
        authorizationNoticeDelay: TimeInterval = 8
    ) {
        self.keepaliveInterval = max(0.001, keepaliveInterval)
        self.sessionIdleWindow = max(0.001, sessionIdleWindow)
        self.authenticationTimeout = max(0.001, authenticationTimeout)
        self.missRetryDelays = missRetryDelays.map { max(0, $0) }
        self.keepalivePingDeadline = max(0.001, keepalivePingDeadline)
        self.patientKeepalivePingDeadline = max(self.keepalivePingDeadline, patientKeepalivePingDeadline)
        self.authorizationNoticeDelay = max(0, authorizationNoticeDelay)
    }
}

/// 1Password provider backed by one long-lived SDK client per account.
///
/// The `op` CLI has no session to keep: every invocation re-authorizes, and an
/// authorization attempted while the 1Password app is locked *unlocks the app*
/// — a Touch ID prompt. A resident agent polling the CLI therefore raises
/// prompts nobody asked for, every time the Mac is locked. Here each account is
/// served by a `csec-op-bridge` process holding one authorized SDK client;
/// reads over a live client cost no prompt and no unlock round-trip.
///
/// Two rules keep it that way. Nothing contacts 1Password except in response to
/// a request csecd chose to make, and the keepalive that holds a session open
/// runs while the screen is unlocked — a lock or sleep suspends it, since the
/// app revokes its session then anyway. The CLI is still used for one thing:
/// enumerating signed-in accounts, which reads local configuration and cannot
/// prompt.
public actor OnePasswordProvider: SecretProvider {
    public typealias CommandRunner = @Sendable (
        _ path: String,
        _ arguments: [String],
        _ timeout: TimeInterval
    ) async throws -> OnePasswordCLI.Result
    public typealias CLILocator = @Sendable () -> String?
    public typealias DateProvider = @Sendable () -> Date
    public typealias Sleeper = @Sendable (_ seconds: TimeInterval) async throws -> Void
    public typealias StatusObserver = @Sendable (_ status: OnePasswordConnectionStatus) -> Void
    /// Receives what a person at the Mac needs to hear about 1Password's own
    /// prompt (`ProviderAttention`); csecd posts it as a notification.
    public typealias AttentionObserver = @Sendable (_ attention: ProviderAttention) -> Void
    /// Whether 1Password locks with the device. Injected so the screen-lock
    /// handling is testable without a 1Password install or its settings file.
    public typealias DeviceLockPolicyReader = @Sendable () -> Bool
    /// 1Password's idle auto-lock. Injected for the same reason.
    public typealias IdleLockPolicyReader = @Sendable () -> OnePasswordAppSettings.IdleLock
    /// Seconds since someone last used the Mac, or nil when unknown.
    public typealias SystemIdleReader = @Sendable () -> TimeInterval?

    public nonisolated let schemes: Set<String> = ["op"]

    private let configuredCLIPath: String?
    private let configuration: OnePasswordConnectionConfiguration
    private let makeBackend: BackendFactory
    private let locateCLI: CLILocator
    private let runCommand: CommandRunner
    private let currentDate: DateProvider
    private let sleep: Sleeper
    private let statusObserver: StatusObserver
    private let attentionObserver: AttentionObserver
    private let locksOnDeviceLock: DeviceLockPolicyReader
    private let idleLockPolicy: IdleLockPolicyReader
    private let systemIdleTime: SystemIdleReader

    private var status: OnePasswordConnectionStatus = .notStarted
    private var lastConfirmedAt: Date?
    private var connectionAttempt: (id: UInt64, task: Task<Void, Error>)?
    private var nextConnectionAttemptID: UInt64 = 0
    private var commandRunning = false
    private var commandWaiters: [CheckedContinuation<Void, Never>] = []
    private var maintenanceRunning = false

    /// One bridge per signed-in account, created only when that account is
    /// actually needed. Creating one is what authorizes, so the set grows on
    /// demand and never on a timer.
    private var backends: [String: OnePasswordBackend] = [:]
    /// When each account's bridge last answered a read or a keepalive ping:
    /// the proof `resolveFromOpenSession` needs that its session is open.
    /// Dropped with the bridge.
    private var sessionAnsweredAt: [String: Date] = [:]
    /// Accounts as 1Password knows them. Read from local configuration, so
    /// refreshing this never prompts.
    private var knownAccounts: [OnePasswordAccount] = []
    /// Set while the screen is locked or the machine is asleep. 1Password
    /// revokes every authorization when the app locks, and the app locks with
    /// the device, so a keepalive in this state could only ever re-authorize —
    /// which means prompt. It stays suspended until the next real request.
    private var keepaliveSuspended = false
    /// Why the last backend connection failed, so `csec status` can name the
    /// bridge failure instead of treating every failed probe as an unlock issue.
    private var lastBackendFailure: Error?

    /// Which signed-in account owns which vault. Rebuilt by every connection
    /// probe, held in memory only, and never written to disk — see
    /// `OnePasswordAccountIndex`.
    private var accountIndex: OnePasswordAccountIndex?
    /// Item identities per `userID/vaultID`, populated only when a vault name is
    /// ambiguous across accounts and item presence has to break the tie.
    private var itemIdentities: [String: [OnePasswordItemIdentity]] = [:]
    /// The account each reference resolved from, keyed by canonical URI. Once a
    /// review has displayed an account, later resolutions of that reference stay
    /// on it rather than drifting when 1Password's own default moves.
    private var accountSelections: [String: AccountSelection] = [:]
    /// `op`'s own current default account, read only to break a tie.
    private var defaultAccountID: String?
    /// While a fetch ahead runs (non-nil), the accounts that failed it for
    /// any reason but a missing reference. Each new contact with such an
    /// account would be another 1Password prompt, or another wait for one
    /// to time out, so the rest of the batch skips it (`backend(for:)`).
    /// Requests that arrive meanwhile skip it too, which is the same answer
    /// they would have got a moment later.
    private var fetchAheadRefusals: Set<String>?
    private var fetchAheadDepth = 0
    /// Accounts whose authorization 1Password refused, or put up and nobody
    /// answered (`isRefusal`). Nothing starts a bridge for one again, for
    /// any request, until a person approves a csec panel at the Mac
    /// (`personApprovedAtMac`): each new bridge is another authorization, so
    /// another prompt, and without this every reference of every request and
    /// every unattended retry asked afresh, a dozen within seconds.
    private var refusedAccounts: Set<String> = []
    /// Accounts whose waiting authorization the person has been told about
    /// and not yet told is over (`authorizing`).
    private var announcedWaiting: Set<String> = []

    /// The account a reference resolves from, plus whether that answer required
    /// choosing between accounts.
    private enum AccountSelection: Sendable, Equatable {
        /// Exactly one signed-in account has this vault (and item).
        case unique(OnePasswordAccount)
        /// Several accounts qualified. `chosen` is the stable pick; `others` are
        /// the accounts a review must warn about.
        case ambiguous(chosen: OnePasswordAccount, others: [OnePasswordAccount])
        /// Several accounts have the vault, and only item listings csec does not
        /// hold could tell them apart. The review may not fetch them, so the
        /// read after consent decides, from listings it is then free to take.
        case undecided(candidates: [OnePasswordAccount])
        /// At least one account could not be listed, so the vault's absence is
        /// unproven: fall back to the account-less read, exactly as before this
        /// adapter became account-aware.
        case unindexed
        /// Every account answered and none has this vault.
        case notFound(searched: [OnePasswordAccount])

        /// The account to pass to `--account`, or nil to let `op` choose.
        var account: OnePasswordAccount? {
            switch self {
            case .unique(let account): return account
            case .ambiguous(let chosen, _): return chosen
            case .undecided, .unindexed, .notFound: return nil
            }
        }

        /// Only a settled choice is worth remembering; the other two are states
        /// of the index, not decisions about the reference.
        var isDecision: Bool {
            switch self {
            case .unique, .ambiguous: return true
            case .undecided, .unindexed, .notFound: return false
            }
        }

        /// One value-free line for the log.
        var summary: String {
            switch self {
            case .unique(let account):
                return "unique, \(OnePasswordDiagnostics.account(account))"
            case let .ambiguous(chosen, others):
                let rest = others.map { OnePasswordDiagnostics.account($0) }
                    .joined(separator: ", ")
                return "ambiguous, chose \(OnePasswordDiagnostics.account(chosen)) over \(rest)"
            case .undecided(let candidates):
                let all = candidates.map { OnePasswordDiagnostics.account($0) }
                    .joined(separator: ", ")
                return "undecided between \(all) (no item listings held)"
            case .unindexed:
                return "unindexed (an account could not be listed)"
            case .notFound(let searched):
                let all = searched.map { OnePasswordDiagnostics.account($0) }
                    .joined(separator: ", ")
                return "no account has this vault (searched \(all))"
            }
        }
    }

    /// Builds the backend that serves one account. Injected so tests can run
    /// the whole provider without a bridge process or a 1Password install.
    public typealias BackendFactory = @Sendable (OnePasswordAccount) throws -> OnePasswordBackend

    /// The shipping backend: one `csec-op-bridge` process per account. Both the
    /// bridge and the 1Password library it will load are checked before a
    /// process exists to load anything.
    public static func defaultBackendFactory() -> BackendFactory {
        { account in
            guard let path = OnePasswordBridgeExecutable.locate() else {
                throw OnePasswordBridgeError.executableNotFound
            }
            guard OnePasswordBridgeExecutable.onePasswordLibraryIsTrusted() else {
                throw OnePasswordBridgeError.executableUntrusted(
                    reason: "the 1Password app's SDK library is missing or not signed by AgileBits"
                )
            }
            return OnePasswordBridgeSession(account: account, executablePath: path)
        }
    }

    public init(
        cliPath: String? = nil,
        configuration: OnePasswordConnectionConfiguration = .init(),
        makeBackend: @escaping BackendFactory = OnePasswordProvider.defaultBackendFactory(),
        locateCLI: @escaping CLILocator = { OnePasswordCLI.locate() },
        runCommand: @escaping CommandRunner = { path, arguments, timeout in
            try await OnePasswordCLI.run(path, arguments, timeout: timeout)
        },
        currentDate: @escaping DateProvider = { Date() },
        sleep: @escaping Sleeper = { seconds in
            let nanoseconds = UInt64(min(seconds * 1_000_000_000, Double(UInt64.max)))
            try await Task.sleep(nanoseconds: nanoseconds)
        },
        statusObserver: @escaping StatusObserver = { _ in },
        locksOnDeviceLock: @escaping DeviceLockPolicyReader = {
            OnePasswordAppSettings.locksOnDeviceLock()
        },
        idleLockPolicy: @escaping IdleLockPolicyReader = { OnePasswordAppSettings.idleLock() },
        systemIdleTime: @escaping SystemIdleReader = { SystemIdleTime.seconds() },
        attentionObserver: @escaping AttentionObserver = { _ in }
    ) {
        self.configuredCLIPath = cliPath
        self.configuration = configuration
        self.makeBackend = makeBackend
        self.locateCLI = locateCLI
        self.runCommand = runCommand
        self.currentDate = currentDate
        self.sleep = sleep
        self.statusObserver = statusObserver
        self.attentionObserver = attentionObserver
        self.locksOnDeviceLock = locksOnDeviceLock
        self.idleLockPolicy = idleLockPolicy
        self.systemIdleTime = systemIdleTime
    }

    /// Starts the resident keepalive.
    ///
    /// It deliberately does not connect. Acquiring a 1Password authorization is
    /// exactly what puts a prompt on screen, so nothing here contacts 1Password
    /// until a real request already has. Once a session exists this holds it
    /// open for as long as the screen is unlocked; a lock or sleep suspends it
    /// (the app revokes its session then), and the next request resumes it.
    public func maintainConnection() async {
        guard !maintenanceRunning else { return }
        maintenanceRunning = true
        defer { maintenanceRunning = false }
        Self.log.notice(
            "keepalive: loop started (every \(Int(self.configuration.keepaliveInterval), privacy: .public)s while the screen is unlocked; a session is held for as long as the screen stays unlocked)"
        )

        while !Task.isCancelled {
            do {
                try await sleep(configuration.keepaliveInterval)
            } catch {
                return
            }
            if Task.isCancelled { return }
            await keepaliveTick()
        }
    }

    /// One keepalive pass. Refreshing a session and refreshing the vault→account
    /// index are the same call, so holding the session open also keeps account
    /// selection exact for free.
    public func keepaliveTick() async {
        if let reason = keepaliveSkipReason() {
            // The same reason every four minutes for a whole night is noise;
            // the transition is the information.
            if reason != lastKeepaliveSkipReason {
                Self.log.notice("keepalive: not pinging: \(reason, privacy: .public)")
                lastKeepaliveSkipReason = reason
            }
            return
        }
        lastKeepaliveSkipReason = nil

        for (accountID, backend) in backends {
            // A ping that has to re-authorize would raise a prompt nobody
            // asked for. It cannot be prevented outright, but it can be cut
            // short: stopping the bridge withdraws the request, and 1Password
            // takes its prompt down with it.
            let (deadline, why) = pingDeadline(for: accountID)
            let started = currentDate()
            let vaults = await pingWithDeadline(backend, deadline: deadline)
            // A real request may have replaced this bridge, or proved its
            // session alive, while the ping waited; neither is this ping's to
            // undo.
            guard backends[accountID] === backend else { continue }
            guard let vaults else {
                if let answeredAt = sessionAnsweredAt[accountID], answeredAt > started {
                    continue
                }
                Self.log.notice(
                    "keepalive: \(self.tag(forUserID: accountID), privacy: .public) did not answer within \(deadline, privacy: .public)s (\(why, privacy: .public)); stopping its bridge, the next request starts a new one and will prompt"
                )
                await backend.shutdown()
                if backends[accountID] === backend {
                    backends.removeValue(forKey: accountID)
                    sessionAnsweredAt.removeValue(forKey: accountID)
                }
                setStatus(backends.isEmpty ? .disconnected : .connected)
                continue
            }
            let took = currentDate().timeIntervalSince(started)
            let slow = took > configuration.keepalivePingDeadline ? ", slowly; held because \(why)" : ""
            Self.log.notice(
                "keepalive: \(self.tag(forUserID: accountID), privacy: .public) answered in \(String(format: "%.2f", took), privacy: .public)s (\(vaults.count, privacy: .public) vaults\(slow, privacy: .public)); session held"
            )
            refreshIndexEntry(accountID: accountID, vaults: vaults)
            sessionAnsweredAt[accountID] = currentDate()
            markConnected()
        }
    }

    private var lastKeepaliveSkipReason: String?

    /// Why this tick will not touch 1Password, or nil when it will.
    private func keepaliveSkipReason() -> String? {
        if backends.isEmpty { return "no bridge is running (nothing has been requested since launch, or every session was released)" }
        if keepaliveSuspended { return "suspended since the screen locked or the machine slept; the next request resumes it" }
        return nil
    }

    /// How long this account's ping may take, and why, for the log.
    ///
    /// An idle warm session answers in well under a second, so on a quiet
    /// Mac a slower ping usually means 1Password is re-authorizing and a
    /// prompt is on screen. A busy Mac (a build, a notarization) slows a
    /// healthy session past that too, and dropping it is what prompts. So
    /// the short deadline holds unless re-authorizing is implausible: the
    /// session answered within 1Password's idle window, so it cannot have
    /// idled out, and 1Password cannot have idle-locked, because it never
    /// does or because someone used the Mac more recently than its lock
    /// would need. Screen lock and sleep never reach here: they suspend the
    /// keepalive.
    private func pingDeadline(for accountID: String) -> (TimeInterval, String) {
        let short = configuration.keepalivePingDeadline
        guard let answeredAt = sessionAnsweredAt[accountID] else {
            return (short, "it has not answered since its bridge started, so it may be authorizing")
        }
        let since = currentDate().timeIntervalSince(answeredAt)
        guard since < configuration.sessionIdleWindow else {
            return (short, "its session last answered \(Int(since))s ago, past 1Password's idle window, so it had probably expired and 1Password was prompting")
        }
        let patient = configuration.patientKeepalivePingDeadline
        let answered = "its session answered \(Int(since))s ago"
        switch idleLockPolicy() {
        case .never:
            return (patient, "\(answered) and 1Password never locks on idle")
        case .after(let minutes):
            guard let idle = systemIdleTime(), idle < TimeInterval(minutes * 60) else {
                return (short, "1Password locks after \(minutes) idle minute(s) and the Mac may have been idle that long, so it may be prompting")
            }
            return (patient, "\(answered) and the Mac was used \(Int(idle))s ago, inside 1Password's \(minutes)-minute idle lock")
        case .unknown:
            return (short, "1Password's idle lock setting could not be read, so it may have locked and be prompting")
        }
    }

    private func pingWithDeadline(
        _ backend: OnePasswordBackend, deadline: TimeInterval
    ) async -> [OnePasswordVault]? {
        await withTaskGroup(of: [OnePasswordVault]?.self) { group in
            group.addTask { try? await backend.vaults() }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(deadline * 1_000_000_000))
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
    }

    /// Replace one account's vaults in the live index without discarding what
    /// is known about the others.
    private func refreshIndexEntry(accountID: String, vaults: [OnePasswordVault]) {
        guard let index = accountIndex else { return }
        var entries = index.entries
        guard let position = entries.firstIndex(where: { $0.account.userID == accountID })
        else { return }
        entries[position] = OnePasswordAccountIndex.Entry(
            account: entries[position].account,
            vaults: vaults,
            listingSucceeded: true
        )
        accountIndex = OnePasswordAccountIndex(entries: entries, builtAt: currentDate())
    }

    /// A real request means the user is present and has just authenticated to
    /// csec. That is the only thing that re-arms a suspended keepalive.
    private func noteDemand() {
        if keepaliveSuspended {
            Self.log.notice("keepalive: resumed by a request")
        }
        keepaliveSuspended = false
    }

    /// The machine is going to sleep, or its session resigned — states from which
    /// a keepalive ping can only re-authorize (a prompt): a sleeping process
    /// cannot ping at all, and by the time it wakes the desktop session has
    /// usually idled out. `reason` names the notification, for the log.
    public func suspendKeepalive(reason: String = "lock or sleep") {
        if !keepaliveSuspended {
            Self.log.notice(
                "keepalive: suspended (\(Self.displaySafe(reason), privacy: .public)); \(self.backends.count, privacy: .public) bridge(s) stay up but their desktop session does not survive this"
            )
        }
        keepaliveSuspended = true
    }

    /// The screen locked. Whether that revokes 1Password's session depends on
    /// 1Password's own `onDeviceLock` setting: when it locks with the device csec
    /// must suspend (a ping could only re-authorize — a prompt); when it does not,
    /// the session survives the lock and csec keeps it warm, so the next request
    /// after unlocking costs no prompt. Only a real request re-arms a suspend.
    public func handleScreenLock() {
        guard locksOnDeviceLock() else {
            Self.log.notice(
                "keepalive: screen locked but 1Password is set not to lock with the device (onDeviceLock=false); holding \(self.backends.count, privacy: .public) session(s) open across the lock"
            )
            return
        }
        suspendKeepalive(reason: "com.apple.screenIsLocked")
    }

    /// Stop every bridge, releasing the desktop sessions they hold.
    public func shutdownBackends() async {
        let live = backends
        Self.log.notice("shutting down \(live.count, privacy: .public) bridge(s)")
        backends = [:]
        sessionAnsweredAt = [:]
        for (_, backend) in live {
            await backend.shutdown()
        }
        setStatus(.disconnected)
    }

    /// Never: a read may open a bridge and raise a 1Password authorization,
    /// which a delegated release (no human on a panel) must not do. An op://
    /// value qualifies for delegation only while csecd holds it warm in its
    /// cache, which the resolver checks before asking any provider.
    public func resolveWithoutInteraction(_ ref: SecretRef) async -> ResolvedSecret? {
        nil
    }

    /// `ref` read over a session csecd already holds open, so a value edited
    /// in the 1Password app reaches the next release rather than csecd's cached
    /// copy of the old one. Nil, with 1Password untouched, unless all of these
    /// hold: the reference's account is known without building the index (a
    /// remembered decision, the only signed-in account, or a unique answer from
    /// the warm index); that account's bridge is running; the keepalive is not
    /// suspended by a lock or sleep, after which the session could only
    /// re-authorize; and the bridge answered within 1Password's idle window.
    /// It never starts a bridge, so it never authorizes and never prompts: that
    /// stays with a real request (`resolve`), which a cached value never needs.
    public func resolveFromOpenSession(_ ref: SecretRef) async -> ResolvedSecret? {
        guard !ref.isOneTimeCode, let (account, backend) = await provenOpenSession(for: ref) else { return nil }
        do {
            let value = try await backend.resolveOverRunningSession(ref.uri)
            sessionAnsweredAt[account.userID] = currentDate()
            markConnected()
            Self.log.notice(
                "revalidate \(Self.tag(ref), privacy: .public): read from \(Self.tag(account), privacy: .public)'s open session"
            )
            return ResolvedSecret(value: value, cacheHint: .cacheable)
        } catch {
            // A miss or a refusal here is settled by the ordinary read path if
            // the cache cannot serve. A miss or a seed refusal is the session
            // answering, so it stays proven; one that did not answer is not
            // proven open any more.
            if let answered = error as? OnePasswordBridgeError,
               Self.isReferenceMiss(answered) || answered.refusedSeed {
                sessionAnsweredAt[account.userID] = currentDate()
            } else {
                sessionAnsweredAt.removeValue(forKey: account.userID)
            }
            Self.log.notice(
                "revalidate \(Self.tag(ref), privacy: .public) from \(Self.tag(account), privacy: .public) failed: \(OnePasswordDiagnostics.kind(of: error), privacy: .public) (\(Self.boundedDescription(error), privacy: .private)); csecd's cached copy, if any, is served"
            )
            return nil
        }
    }

    /// Every op:// value can be edited in the 1Password app, which csec never
    /// sees; a one-time code is never cached, so has nothing to re-check.
    public nonisolated func valuesChangeOutsideCsec(_ ref: SecretRef) async -> Bool {
        !ref.isOneTimeCode
    }

    /// Unless csecd holds `ref`'s account's session open and recently proven
    /// (`provenOpenSession`), reading it starts a bridge, building the index
    /// authorizes every account, or the session may have lapsed: each raises
    /// 1Password's own prompt at the Mac. A one-time code is read the same way
    /// as any field, so it needs that session too.
    public func requiresAttendanceToResolve(_ ref: SecretRef) async -> Bool {
        await provenOpenSession(for: ref) == nil
    }

    /// The account and bridge whose session csecd holds open for `ref`: the
    /// account is known from warm state, its bridge is running, the keepalive
    /// is not suspended by a lock or sleep (after which the session could
    /// only re-authorize), and the bridge answered within 1Password's idle
    /// window. Never starts a bridge or contacts one.
    private func provenOpenSession(for ref: SecretRef) async -> (OnePasswordAccount, OnePasswordBackend)? {
        guard !keepaliveSuspended,
              let account = await openSessionAccount(for: ref),
              let backend = backends[account.userID],
              let answeredAt = sessionAnsweredAt[account.userID],
              currentDate().timeIntervalSince(answeredAt) < configuration.sessionIdleWindow
        else { return nil }
        return (account, backend)
    }

    /// The account `resolveFromOpenSession` may read `ref` from, decided from
    /// warm state only: never a probe, an index build or an item listing.
    private func openSessionAccount(for ref: SecretRef) async -> OnePasswordAccount? {
        if let account = optimisticAccount(for: ref) { return account }
        guard accountIndex?.isUsable == true,
              case let .unique(account)? = try? await selectAccount(for: ref, allowRefresh: false)
        else { return nil }
        return account
    }

    /// Each reference in turn, as `resolve` reads it, except that an account
    /// that refused once is not asked again in this batch: a person at the
    /// Mac who declines 1Password's prompt, or misses it, sees it once per
    /// account, not once per reference.
    public func fetchAhead(_ refs: [SecretRef]) async -> [FetchAheadResult] {
        fetchAheadDepth += 1
        if fetchAheadRefusals == nil { fetchAheadRefusals = [] }
        defer {
            fetchAheadDepth -= 1
            if fetchAheadDepth == 0 { fetchAheadRefusals = nil }
        }
        var results: [FetchAheadResult] = []
        for ref in refs {
            results.append(await FetchAheadResult.resolving(ref, with: self))
        }
        return results
    }

    public func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        noteDemand()
        try await ensureAccounts()

        // The common case is one signed-in account, or a reference a review has
        // already settled. Read it directly: building the vault→account index
        // means authorizing every account, and a reference that resolves never
        // needed to know where the other accounts keep their vaults.
        if let optimistic = optimisticAccount(for: ref) {
            let decided = accountSelections[ref.uri]?.isDecision == true
            Self.log.notice(
                "resolve \(Self.tag(ref), privacy: .public): reading from \(Self.tag(optimistic), privacy: .public) (\(decided ? "remembered decision" : "only signed-in account", privacy: .public))"
            )
            switch try await readConfirmingMisses(ref, from: optimistic) {
            case .value(let resolved):
                return resolved
            case .vaultAbsent(let vault) where decided:
                // The review displayed this account for this reference, and the
                // account no longer holds the vault. Delivering from whichever
                // account does now would make the window a lie; forget the
                // decision and let the next request show the new one.
                accountSelections.removeValue(forKey: ref.uri)
                throw OnePasswordError.vaultNoLongerInAccount(
                    vault: vault, account: optimistic.label
                )
            case .vaultAbsent:
                // A guess, not a decision: the ladder decides.
                break
            }
        }

        let account = try await resolvedAccount(for: ref)
        Self.log.notice(
            "resolve \(Self.tag(ref), privacy: .public): reading from \(Self.tag(account), privacy: .public) (index)"
        )
        switch try await readConfirmingMisses(ref, from: account) {
        case .value(let resolved):
            return resolved
        case .vaultAbsent(let vault):
            // The index named this account a moment ago and the account's own
            // vault list now disagrees: the vault went away mid-request.
            accountSelections.removeValue(forKey: ref.uri)
            throw OnePasswordError.vaultNoLongerInAccount(vault: vault, account: account.label)
        }
    }

    private enum ReadOutcome {
        case value(ResolvedSecret)
        /// The account's own vault list, refreshed after the miss, does not
        /// contain the vault the reference names.
        case vaultAbsent(vault: String)
    }

    /// One read whose "not found" is not taken on the bridge's word alone.
    ///
    /// The SDK reports a reference as absent when the account has not finished
    /// loading — which is exactly the state every account is in for the first
    /// seconds after 1Password unlocks, and every session re-authorizes after a
    /// lock. So a miss is first checked against the account's own vault list:
    /// a vault that is not there is a settled answer for the caller to act on.
    /// A vault that is there means the item is either loading or genuinely
    /// missing, and the read is repeated on a short schedule until it resolves
    /// or the schedule runs out. Either way the failure names the account that
    /// was asked, so "not found" can never again be mistaken for "wrong
    /// account".
    private func readConfirmingMisses(
        _ ref: SecretRef,
        from account: OnePasswordAccount
    ) async throws -> ReadOutcome {
        do {
            return .value(try await read(ref, from: account))
        } catch let error as OnePasswordBridgeError where Self.isReferenceMiss(error) {
            Self.log.notice(
                "miss: \(Self.tag(ref), privacy: .public) not found in \(Self.tag(account), privacy: .public); confirming against its vault list"
            )
        }

        let path = OnePasswordReferencePath(path: ref.path)
        let vaultQuery = path?.vault ?? ref.path
        let vaults = try await backend(for: account).vaults()
        refreshIndexEntry(accountID: account.userID, vaults: vaults)
        let ownEntry = OnePasswordAccountIndex(
            entries: [.init(account: account, vaults: vaults, listingSucceeded: true)],
            builtAt: currentDate()
        )
        guard let candidate = ownEntry.candidates(forVault: vaultQuery).first else {
            Self.log.notice(
                "miss confirmed: \(Self.tag(account), privacy: .public) has no vault \(Self.displaySafe(vaultQuery), privacy: .private) (\(Self.tag(ref), privacy: .public))"
            )
            return .vaultAbsent(vault: vaultQuery)
        }

        // The item listing and the read answer from the same still-loading
        // store, so a listed item does not prove a read should succeed yet: the
        // whole schedule is spent before a miss is believed. The listing is
        // taken once afterwards, only to say whether it is the item or a field
        // within it that is missing.
        for delay in configuration.missRetryDelays {
            try await sleep(delay)
            do {
                let resolved = try await read(ref, from: account)
                Self.log.notice(
                    "miss healed: \(Self.tag(ref), privacy: .public) resolved from \(Self.tag(account), privacy: .public) on retry"
                )
                return .value(resolved)
            } catch let error as OnePasswordBridgeError where Self.isReferenceMiss(error) {
                continue
            }
        }
        var itemListed = false
        if let item = path?.item {
            itemListed = await refreshedIdentities(in: candidate)?
                .contains { $0.matches(item) } ?? false
        }
        Self.log.notice(
            "miss confirmed: \(Self.tag(ref), privacy: .public) is not in \(Self.tag(account), privacy: .public) (item listed: \(itemListed, privacy: .public))"
        )
        throw OnePasswordError.referenceNotFound(
            vault: candidate.vault.name, account: account.label, itemListed: itemListed
        )
    }

    /// One read over a live session. No prompt, no unlock round-trip, and the
    /// value travels the bridge pipe only.
    private func read(
        _ ref: SecretRef,
        from account: OnePasswordAccount
    ) async throws -> ResolvedSecret {
        do {
            let backend = try backend(for: account)
            let value = try await authorizing(account) { try await backend.resolve(ref.uri) }
            sessionAnsweredAt[account.userID] = currentDate()
            markConnected()
            // 1Password makes a fresh code for every read of a one-time-code
            // reference; a kept copy would be stale within the minute.
            return ResolvedSecret(value: value, cacheHint: ref.isOneTimeCode ? .noCache : .cacheable)
        } catch let error as OnePasswordBridgeError where Self.isReferenceMiss(error) || error.refusedSeed {
            // The session answered; it just did not have the reference, or
            // the field is a 2FA seed the bridge would not send. That is not
            // a connection problem and must not read as one in `csec status`,
            // and the session it proves open serves a phone approval.
            sessionAnsweredAt[account.userID] = currentDate()
            throw error
        } catch {
            Self.log.notice(
                "read \(Self.tag(ref), privacy: .public) from \(Self.tag(account), privacy: .public) failed: \(OnePasswordDiagnostics.kind(of: error), privacy: .public) (\(Self.boundedDescription(error), privacy: .private))"
            )
            markConnectionFailure(error)
            fetchAheadRefusals?.insert(account.userID)
            if noteRefusal(error, by: account), let backend = backends.removeValue(forKey: account.userID) {
                // Its session is gone, and the SDK would re-authorize inside
                // the next call on it: that is the prompt being held back.
                sessionAnsweredAt.removeValue(forKey: account.userID)
                await backend.shutdown()
            }
            throw error
        }
    }

    /// Hold `account` as refused when `error` is 1Password declining to
    /// authorize it: refused outright, a session it ended, or a prompt nobody
    /// answered in time. True when it did.
    @discardableResult
    private func noteRefusal(_ error: Error, by account: OnePasswordAccount) -> Bool {
        guard Self.isRefusal(error) else { return false }
        if refusedAccounts.insert(account.userID).inserted {
            Self.log.notice(
                "\(Self.tag(account), privacy: .public) refused authorization: csecd will not ask it again until a person approves a csec panel at this Mac"
            )
            // Once per hold, which only an approval at the Mac lifts, so this
            // cannot repeat while nobody is there. It replaces any notice
            // that the prompt was waiting.
            announcedWaiting.remove(account.userID)
            let unanswered: Bool
            if case .timedOut? = error as? OnePasswordBridgeError { unanswered = true } else { unanswered = false }
            tell(account, .notAuthorized(unanswered: unanswered))
        }
        return true
    }

    /// `call` over `account`'s bridge when it may be the request 1Password
    /// authorizes, and so asks a person about in its own window, which csec
    /// neither draws nor sees. Still unanswered after
    /// `authorizationNoticeDelay`, the person is told 1Password is asking;
    /// when the call then ends without a refusal they are told it is over,
    /// and a refusal says so itself (`noteRefusal`). A session that answered
    /// within 1Password's idle window, with no lock or sleep since, cannot be
    /// prompting, so its calls are never announced.
    private func authorizing<T>(
        _ account: OnePasswordAccount,
        _ call: () async throws -> T
    ) async throws -> T {
        guard mayBeAuthorizing(account) else { return try await call() }
        // A real clock, not the injected `sleep`, which paces the miss
        // retries: this pause is no part of how a read is answered.
        let notice = Task { [delay = configuration.authorizationNoticeDelay] in
            try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            self.announceWaiting(account)
        }
        do {
            let result = try await call()
            notice.cancel()
            settleWaiting(account)
            return result
        } catch {
            notice.cancel()
            if !Self.isRefusal(error) { settleWaiting(account) }
            throw error
        }
    }

    private func mayBeAuthorizing(_ account: OnePasswordAccount) -> Bool {
        guard !keepaliveSuspended, let answeredAt = sessionAnsweredAt[account.userID] else { return true }
        return currentDate().timeIntervalSince(answeredAt) >= configuration.sessionIdleWindow
    }

    /// Runs on the actor, so when the call it watches ended first, the
    /// cancellation that call made is already visible here.
    private func announceWaiting(_ account: OnePasswordAccount) {
        guard !Task.isCancelled, announcedWaiting.insert(account.userID).inserted else { return }
        Self.log.notice(
            "\(Self.tag(account), privacy: .public) has not answered in \(Int(self.configuration.authorizationNoticeDelay), privacy: .public)s, so its authorization prompt is probably up: telling the person"
        )
        tell(account, .awaitingAuthorization)
    }

    private func settleWaiting(_ account: OnePasswordAccount) {
        guard announcedWaiting.remove(account.userID) != nil else { return }
        tell(account, .settled)
    }

    private func tell(_ account: OnePasswordAccount, _ kind: ProviderAttention.Kind) {
        attentionObserver(ProviderAttention(
            provider: "1Password", account: Self.displaySafe(account.label), kind: kind
        ))
    }

    private static func isRefusal(_ error: Error) -> Bool {
        switch error as? OnePasswordBridgeError {
        case .timedOut?:
            return true
        case let .remote(kind, _)?:
            return kind == "unauthorized" || kind == "session_expired"
        default:
            return false
        }
    }

    /// A person approved a csec panel at this Mac: an account that refused may
    /// be asked once more (`refusedAccounts`).
    public func personApprovedAtMac() async {
        guard !refusedAccounts.isEmpty else { return }
        Self.log.notice(
            "a person approved at the Mac: \(self.refusedAccounts.count, privacy: .public) account(s) that refused may be asked again"
        )
        refusedAccounts.removeAll()
    }

    /// Whether the bridge is saying "this account does not have that", which is
    /// the one failure worth re-deciding the account over.
    private static func isReferenceMiss(_ error: OnePasswordBridgeError) -> Bool {
        guard case let .remote(kind, _) = error else { return false }
        return kind == "not_found"
    }

    /// An account to try before paying for the index, or nil when there is no
    /// honest basis for a guess. With several accounts signed in the index is
    /// built by the first request and kept, so the only guess ever made is the
    /// one that cannot be wrong: the single signed-in account.
    private func optimisticAccount(for ref: SecretRef) -> OnePasswordAccount? {
        if let remembered = accountSelections[ref.uri]?.account { return remembered }
        // With an index in hand the ladder is exact, and exactness is cheaper
        // than a guess.
        if accountIndex?.isUsable == true { return nil }
        return knownAccounts.count == 1 ? knownAccounts[0] : nil
    }

    private static var log: Logger { OnePasswordDiagnostics.log }

    private func tag(forUserID userID: String) -> String {
        OnePasswordDiagnostics.account(
            userID: userID, label: knownAccounts.first { $0.userID == userID }?.label
        )
    }

    private static func tag(_ ref: SecretRef) -> String {
        OnePasswordDiagnostics.reference(ref.uri)
    }

    private static func tag(_ account: OnePasswordAccount) -> String {
        OnePasswordDiagnostics.account(account)
    }

    /// Which accounts are signed in. This reads 1Password's local
    /// configuration: it is the one `op` call csec still makes, and it cannot
    /// prompt or unlock anything.
    private func ensureAccounts() async throws {
        guard knownAccounts.isEmpty else { return }
        let result: OnePasswordCLI.Result
        do {
            result = try await execute(
                arguments: ["account", "list", "--format=json"],
                timeout: configuration.authenticationTimeout
            )
        } catch {
            markConnectionFailure(error)
            throw error
        }
        guard result.status == 0 else {
            throw OnePasswordError.authenticationFailed(status: result.status)
        }
        let accounts = OnePasswordAccountIndex.decodeAccounts(result.stdout)
        guard !accounts.isEmpty else { throw OnePasswordError.noSignedInAccounts }
        knownAccounts = accounts
        Self.log.notice(
            "accounts: \(accounts.map { Self.tag($0) }.joined(separator: ", "), privacy: .public)"
        )
    }

    /// The bridge serving one account, started on first use.
    private func backend(for account: OnePasswordAccount) throws -> OnePasswordBackend {
        if fetchAheadRefusals?.contains(account.userID) == true {
            throw OnePasswordError.accountRefusedThisFetch(account: account.label)
        }
        if refusedAccounts.contains(account.userID) {
            throw OnePasswordError.accountRefusedUntilApproval(account: account.label)
        }
        if let existing = backends[account.userID] { return existing }
        do {
            let created = try makeBackend(account)
            backends[account.userID] = created
            lastBackendFailure = nil
            Self.log.notice(
                "bridge for \(Self.tag(account), privacy: .public) created (\(self.backends.count, privacy: .public) live); its first request authorizes, which prompts unless 1Password already authorized this account"
            )
            return created
        } catch {
            Self.log.notice(
                "bridge for \(Self.tag(account), privacy: .public) could not be created: \(OnePasswordDiagnostics.kind(of: error), privacy: .public) (\(Self.boundedDescription(error), privacy: .private))"
            )
            lastBackendFailure = error
            throw error
        }
    }

    /// Build the vault→account index by asking every signed-in account for its
    /// vaults. This authorizes each account, so it runs only when a reference
    /// could not be served without it.
    private func buildIndex() async throws {
        try await ensureAccounts()
        var entries: [OnePasswordAccountIndex.Entry] = []
        var firstFailure: Error?
        for account in knownAccounts {
            var vaults: [OnePasswordVault]?
            do {
                vaults = try await authorizing(account) { try await backend(for: account).vaults() }
                Self.log.notice(
                    "index: \(Self.tag(account), privacy: .public) listed \(vaults?.count ?? 0, privacy: .public) vaults"
                )
            } catch {
                Self.log.notice(
                    "index: \(Self.tag(account), privacy: .public) could not be listed: \(OnePasswordDiagnostics.kind(of: error), privacy: .public) (\(Self.boundedDescription(error), privacy: .private))"
                )
                if firstFailure == nil { firstFailure = error }
                fetchAheadRefusals?.insert(account.userID)
                noteRefusal(error, by: account)
                sessionAnsweredAt.removeValue(forKey: account.userID)
                if let backend = backends.removeValue(forKey: account.userID) {
                    // An account that cannot answer is not one to keep a
                    // process for.
                    await backend.shutdown()
                }
            }
            entries.append(
                OnePasswordAccountIndex.Entry(
                    account: account,
                    vaults: vaults ?? [],
                    listingSucceeded: vaults != nil
                )
            )
        }
        let index = OnePasswordAccountIndex(entries: entries, builtAt: currentDate())
        guard index.isUsable else {
            let error = firstFailure ?? OnePasswordError.notAuthorized
            markConnectionFailure(error)
            throw error
        }
        adopt(index)
        markConnected()
    }

    /// Make the provider ready to serve without contacting 1Password.
    ///
    /// There is nothing to "pre-authorize" any more: an authorization is
    /// acquired by the read that needs it, so reaching for one here would only
    /// move a prompt earlier and detach it from the request that justifies it.
    public func authenticate() async throws {
        try await ensureAccounts()
    }

    /// How the trusted review names this reference: account › vault › item ›
    /// field. The field is everything after the item, so a sectioned
    /// reference (`op://vault/item/section/field`) shows `section/field`. The
    /// account is the one this reference will resolve from, with a warning
    /// when more than one signed-in account could serve it or none can.
    ///
    /// Answers from the warm index only — the review window is being built, so
    /// this never starts a connection probe; with no usable index the account
    /// is left unnamed. The decision is remembered, so the account displayed
    /// here is the account `resolve` then reads from; the window cannot name
    /// one source and deliver another.
    public func reviewDescription(for ref: SecretRef) async -> ReviewSecret? {
        let parts = ref.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 3, parts.allSatisfy({ !$0.isEmpty }) else { return nil }
        let vault = parts[0]
        let item = parts[1]
        // A one-time code's field is shown without its `?attribute=otp`: the
        // review says it is a code in words (`ReviewDisplay.oneTimeCodeNote`).
        let field = ref.oneTimeCodeSeedReference.map {
            $0.path.split(separator: "/", omittingEmptySubsequences: false).dropFirst(2).joined(separator: "/")
        } ?? parts[2...].joined(separator: "/")

        var account: String?
        var warnings: [String] = []
        if accountIndex?.isUsable == true,
           OnePasswordReferencePath(path: ref.path) != nil,
           let selection = try? await selectAccount(for: ref, allowRefresh: false) {
            if selection.isDecision { accountSelections[ref.uri] = selection }
            let vaultName = Self.displaySafe(vault)
            switch selection {
            case .unique(let chosen):
                account = Self.displaySafe(chosen.label)
            case let .ambiguous(chosen, others):
                let alternatives = others.map { Self.displaySafe($0.label) }
                    .joined(separator: ", ")
                account = Self.displaySafe(chosen.label)
                // The tree already says 1Password and names the account and
                // vault; the warning only has to say what is unusual about it.
                warnings.append(
                    "More than one signed-in account has a vault named “\(vaultName)”"
                        + " (also \(alternatives)). This value will come from"
                        + " \(Self.displaySafe(chosen.label)). To name one account exactly,"
                        + " use the vault's unique id in the reference."
                )
            case .undecided(let candidates):
                let accounts = candidates.map { Self.displaySafe($0.label) }
                    .joined(separator: ", ")
                warnings.append(
                    "More than one signed-in account has a vault named “\(vaultName)”"
                        + " (\(accounts)). This value will come from whichever of them"
                        + " holds “\(Self.displaySafe(item))”; if none or several do, the"
                        + " request will fail. To name one account exactly, use the"
                        + " vault's unique id in the reference."
                )
            case .notFound(let searched):
                let accounts = searched.map { Self.displaySafe($0.label) }.joined(separator: ", ")
                warnings.append(
                    "No signed-in 1Password account has a vault named “\(vaultName)”"
                        + " (searched \(accounts)), so this request will fail."
                )
            case .unindexed:
                break
            }
        }
        return ReviewSecret(
            provider: "1Password", tint: .teal, account: account,
            container: vault, item: item, field: field, warnings: warnings
        )
    }

    public func statusSummary() async -> ProviderStatusSummary? {
        let summary = connectionSummary()
        // Held accounts lead: nothing asks them again by itself, so the
        // person has to know what does.
        guard !refusedAccounts.isEmpty else { return summary }
        let held = refusedAccounts.map { userID in
            Self.displaySafe(knownAccounts.first { $0.userID == userID }?.label ?? userID)
        }.sorted().joined(separator: ", ")
        let detail = "not asking \(held) (declined, or its prompt went unanswered) until you approve a csec panel at this Mac"
        return ProviderStatusSummary(
            label: "1Password",
            detail: summary.map { "\(detail); \($0.detail)" } ?? detail,
            healthy: false
        )
    }

    private func connectionSummary() -> ProviderStatusSummary? {
        let label = "1Password"

        // A failed bridge connection is more specific than the generic account
        // state, whether construction or the first metadata request failed.
        if backends.isEmpty, let failure = lastBackendFailure as? ProviderDiagnosableError {
            return ProviderStatusSummary(
                label: label, detail: failure.boundedReason, healthy: false
            )
        }
        if status == .cliUnavailable {
            return ProviderStatusSummary(
                label: label,
                detail: "CLI not found or not the official signed binary",
                healthy: false
            )
        }

        if let index = accountIndex, index.isUsable {
            let authorized = index.entries.filter(\.listingSucceeded).count
            var detail = "\(Self.count(authorized, "account")),"
                + " \(Self.count(index.indexedVaultCount, "vault")) indexed"
            let lapsed = index.entries.count - authorized
            if lapsed > 0 {
                detail += "; \(Self.count(lapsed, "account")) not authorized"
            }
            if backends.isEmpty {
                // The index outlives the sessions that built it. Say so rather
                // than implying a session is live when 1Password has locked.
                detail += "; session lapsed, resumes on next request"
            }
            return ProviderStatusSummary(
                label: label, detail: detail, healthy: index.isComplete
            )
        }

        // No index. That is the ordinary state: a reference that resolves from
        // the account csec had reason to try never needs one built.
        if !backends.isEmpty {
            return ProviderStatusSummary(
                label: label,
                detail: "\(Self.count(backends.count, "session")) live",
                healthy: true
            )
        }
        if lastConfirmedAt != nil {
            // We have served 1Password before, so nothing is wrong; the session
            // has simply been revoked, most likely by the app locking.
            return ProviderStatusSummary(
                label: label,
                detail: "session lapsed, resumes on next request",
                healthy: true
            )
        }
        if status == .notStarted {
            // csecd sits here from launch until it is first asked for a secret.
            // Telling the user to unlock 1Password would invent a problem and
            // train them to ignore the row.
            return ProviderStatusSummary(
                label: label,
                detail: "idle; a session starts with the first request",
                healthy: true
            )
        }
        return ProviderStatusSummary(
            label: label,
            detail: "no authorized account; unlock 1Password and retry",
            healthy: false
        )
    }

    // MARK: - Account selection

    /// The account this reference must be read from. A remembered decision
    /// wins: once a review has displayed the account for a reference, that
    /// reference stays on it, so the window cannot name one source and the read
    /// deliver another.
    private func resolvedAccount(for ref: SecretRef) async throws -> OnePasswordAccount {
        if let remembered = accountSelections[ref.uri], let account = remembered.account {
            return account
        }
        let vault = OnePasswordReferencePath(path: ref.path)?.vault ?? ref.path
        let selection = try await selectAccount(for: ref, allowRefresh: true)
        switch selection {
        case .unique(let account):
            accountSelections[ref.uri] = selection
            return account
        case let .ambiguous(chosen, others):
            // Nothing displayed this choice to the user, so refuse rather than
            // silently pick one account's copy of the vault over another's.
            throw OnePasswordError.vaultAmbiguous(
                vault: vault,
                accounts: ([chosen] + others).map(\.label)
            )
        case .undecided(let candidates):
            // Only a selection that may not list items is left undecided, and
            // this one may; refuse rather than pick if that ever changes.
            throw OnePasswordError.vaultAmbiguous(vault: vault, accounts: candidates.map(\.label))
        case .unindexed:
            // Every account is unreachable: there is no session to read over,
            // and inventing one here would be an authorization the caller did
            // not ask for.
            throw OnePasswordError.notAuthorized
        case .notFound(let searched):
            throw OnePasswordError.vaultNotFoundInAnyAccount(
                vault: vault,
                accounts: searched.map(\.label)
            )
        }
    }

    /// Walk the selection ladder: unique vault id, unique vault name, then the
    /// account whose vault actually holds the item. `allowRefresh` is false on
    /// the consent path, where a cold index must yield no answer instead of a
    /// slow one, and a tie that only an item listing csec does not hold could
    /// break is left undecided: listing items opens a bridge, and its first
    /// request authorizes, which can raise 1Password's own prompt.
    private func selectAccount(
        for ref: SecretRef,
        allowRefresh: Bool
    ) async throws -> AccountSelection {
        guard let path = OnePasswordReferencePath(path: ref.path) else { return .unindexed }

        var refreshed = false
        if accountIndex == nil {
            guard allowRefresh else { return .unindexed }
            try await establishConnection(forceProbe: true)
            refreshed = true
        }
        guard var index = accountIndex else { return .unindexed }

        var candidates = index.candidates(forVault: path.vault)
        if candidates.isEmpty, allowRefresh, !refreshed {
            // A vault created since the last probe is worth one rebuild before
            // reporting it missing.
            try await establishConnection(forceProbe: true)
            guard let rebuilt = accountIndex else { return .unindexed }
            index = rebuilt
            candidates = index.candidates(forVault: path.vault)
        }

        let selection: AccountSelection
        if candidates.isEmpty {
            selection = index.isComplete ? .notFound(searched: index.accounts) : .unindexed
        } else if candidates.count == 1 {
            selection = .unique(candidates[0].account)
        } else if let narrowed = await narrow(
            candidates, toItem: path.item, mayList: allowRefresh
        ) {
            if narrowed.count == 1 {
                selection = .unique(narrowed[0].account)
            } else {
                let ordered = OnePasswordAccountIndex.stableOrder(
                    narrowed,
                    vaultQuery: path.vault,
                    defaultAccountID: await currentDefaultAccountID()
                )
                selection = .ambiguous(
                    chosen: ordered[0].account,
                    others: ordered.dropFirst().map(\.account)
                )
            }
        } else {
            selection = .undecided(candidates: candidates.map(\.account))
        }
        Self.log.notice(
            "select \(Self.tag(ref), privacy: .public): \(selection.summary, privacy: .public)"
        )
        return selection
    }

    /// Keep only the candidates whose vault actually contains the item. A
    /// candidate whose item listing fails is kept: an unlistable vault is
    /// unknown, not empty, and dropping it would turn a warning into a wrong
    /// answer. Without `mayList`, only listings already held count, and nil
    /// means a listing csec does not hold was needed.
    private func narrow(
        _ candidates: [OnePasswordVaultCandidate],
        toItem item: String?,
        mayList: Bool
    ) async -> [OnePasswordVaultCandidate]? {
        guard let item else { return candidates }
        if !mayList,
           candidates.contains(where: { itemIdentities[Self.identityKey($0)] == nil }) {
            return nil
        }
        var narrowed: [OnePasswordVaultCandidate] = []
        for candidate in candidates {
            guard let identities = await identities(in: candidate) else {
                narrowed.append(candidate)
                continue
            }
            if identities.contains(where: { $0.matches(item) }) {
                narrowed.append(candidate)
            }
        }
        return narrowed.isEmpty ? candidates : narrowed
    }

    /// Fresh item identities for one vault, replacing whatever was cached: a
    /// miss is being confirmed, and a listing taken before the account finished
    /// loading is exactly what must not be trusted here.
    private func refreshedIdentities(
        in candidate: OnePasswordVaultCandidate
    ) async -> [OnePasswordItemIdentity]? {
        itemIdentities.removeValue(forKey: Self.identityKey(candidate))
        return await identities(in: candidate)
    }

    /// Item titles and ids for one vault — never field values. Cached for the
    /// life of the index, and requested only to break a tie between accounts.
    private func identities(
        in candidate: OnePasswordVaultCandidate
    ) async -> [OnePasswordItemIdentity]? {
        let key = Self.identityKey(candidate)
        if let cached = itemIdentities[key] { return cached }
        guard let backend = try? backend(for: candidate.account),
              let identities = try? await backend.items(inVault: candidate.vault.id)
        else { return nil }
        itemIdentities[key] = identities
        return identities
    }

    private static func identityKey(_ candidate: OnePasswordVaultCandidate) -> String {
        "\(candidate.account.userID)/\(candidate.vault.id)"
    }

    /// A stable tiebreak that cannot prompt. Asking `op` which account is its
    /// default needs an authorized session, and a tiebreak is never worth a
    /// Touch ID prompt; the account already serving this daemon is both free to
    /// determine and the more useful answer.
    private func currentDefaultAccountID() async -> String? {
        if let defaultAccountID { return defaultAccountID }
        let warm = knownAccounts.filter { backends[$0.userID] != nil }
        defaultAccountID = warm.count == 1 ? warm[0].userID : nil
        return defaultAccountID
    }

    /// Vault names and account labels are untrusted metadata that reach a
    /// window and an error string: neutralize terminal/bidi controls and bound
    /// the length before either.
    static func displaySafe(_ text: String, limit: Int = 96) -> String {
        let sanitized = ReviewDisplay.sanitized(text)
        guard sanitized.count > limit else { return sanitized }
        return String(sanitized.prefix(limit)) + "…"
    }

    private static func count(_ value: Int, _ noun: String) -> String {
        "\(value) \(noun)\(value == 1 ? "" : "s")"
    }

    /// csec's own words for an error, for the log, where it is private: the
    /// words can name a vault or an account. Upstream text (op's stderr, the
    /// SDK's message) is untrusted metadata and stays out even here.
    private static func boundedDescription(_ error: Error) -> String {
        if let diagnosable = error as? ProviderDiagnosableError {
            return displaySafe(diagnosable.boundedReason, limit: 200)
        }
        return displaySafe(String(describing: type(of: error)))
    }

    /// True only while a recent authenticated command proves the provider can
    /// serve without beginning another interactive authorization ceremony.
    /// 1Password works out a TOTP field's current code itself
    /// (`?attribute=otp`), so the seed never leaves 1Password.
    public nonisolated func makesOneTimeCodes(_ ref: SecretRef) async -> Bool {
        ref.scheme == "op"
    }

    public func isAvailable() async -> Bool {
        guard connectionIsFresh else {
            if status == .connected { setStatus(.disconnected) }
            return false
        }
        return true
    }

    public func connectionStatus() -> OnePasswordConnectionStatus {
        status
    }

    private var connectionIsFresh: Bool {
        guard status == .connected, let lastConfirmedAt else { return false }
        let age = max(0, currentDate().timeIntervalSince(lastConfirmedAt))
        return age < configuration.sessionIdleWindow
    }

    private func establishConnection(forceProbe: Bool) async throws {
        if !forceProbe, connectionIsFresh { return }

        if let attempt = connectionAttempt {
            try await attempt.task.value
            return
        }

        nextConnectionAttemptID &+= 1
        let attemptID = nextConnectionAttemptID
        if status != .connected { setStatus(.connecting) }
        let task = Task { try await self.buildIndex() }
        connectionAttempt = (attemptID, task)

        do {
            try await task.value
            if connectionAttempt?.id == attemptID {
                connectionAttempt = nil
            }
        } catch {
            if connectionAttempt?.id == attemptID {
                connectionAttempt = nil
            }
            throw error
        }
    }

    /// Install a freshly built index and drop everything derived from the old
    /// one. A remembered account survives only while it is still signed in and
    /// still holds the vault it was chosen for; anything else is re-decided (and
    /// so re-displayed) rather than silently reused.
    private func adopt(_ index: OnePasswordAccountIndex) {
        accountIndex = index
        itemIdentities.removeAll()
        defaultAccountID = nil
        accountSelections = accountSelections.filter { uri, selection in
            guard let account = selection.account,
                  let path = referencePath(forURI: uri),
                  let entry = index.entries.first(where: { $0.account == account }),
                  entry.listingSucceeded
            else { return false }
            return index.candidates(forVault: path.vault)
                .contains { $0.account == account }
        }
    }

    private func referencePath(forURI uri: String) -> OnePasswordReferencePath? {
        guard let ref = try? SecretRef(uri) else { return nil }
        return OnePasswordReferencePath(path: ref.path)
    }

    private func execute(
        arguments: [String],
        timeout: TimeInterval
    ) async throws -> OnePasswordCLI.Result {
        await acquireCommandSlot()
        defer { releaseCommandSlot() }
        try Task.checkCancellation()

        guard let cliPath = configuredCLIPath ?? locateCLI() else {
            throw OnePasswordError.cliNotFound
        }
        return try await runCommand(cliPath, arguments, timeout)
    }

    private func acquireCommandSlot() async {
        if !commandRunning {
            commandRunning = true
            return
        }
        await withCheckedContinuation { continuation in
            commandWaiters.append(continuation)
        }
    }

    private func releaseCommandSlot() {
        if commandWaiters.isEmpty {
            commandRunning = false
            return
        }
        commandWaiters.removeFirst().resume()
    }

    private func markConnected() {
        lastBackendFailure = nil
        lastConfirmedAt = currentDate()
        setStatus(.connected)
    }

    private func markConnectionFailure(_ error: Error) {
        Self.log.notice(
            "connection marked failed: \(OnePasswordDiagnostics.kind(of: error), privacy: .public) (\(Self.boundedDescription(error), privacy: .private))"
        )
        lastBackendFailure = error
        if let onePasswordError = error as? OnePasswordError,
           case .cliNotFound = onePasswordError {
            setStatus(.cliUnavailable)
        } else {
            setStatus(.disconnected)
        }
    }

    private func setStatus(_ next: OnePasswordConnectionStatus) {
        guard status != next else { return }
        status = next
        statusObserver(next)
    }
}

public enum OnePasswordError: Error, CustomStringConvertible, ProviderDiagnosableError {
    case cliNotFound
    case authenticationFailed(status: Int32)
    case readFailed(reference: String, status: Int32, message: String)
    case notUTF8(String)
    /// `op account list` returned nothing: no account is set up on this device.
    case noSignedInAccounts
    /// Accounts exist, but not one of them could be listed.
    case notAuthorized
    /// Every signed-in account answered, and none has this vault.
    case vaultNotFoundInAnyAccount(vault: String, accounts: [String])
    /// Several accounts hold this vault and item, and no review has displayed
    /// which one would be used.
    case vaultAmbiguous(vault: String, accounts: [String])
    /// The account chosen for this reference has the vault, and after the
    /// retry schedule still reports the reference absent. `itemListed` tells a
    /// missing item from a missing section or field.
    case referenceNotFound(vault: String, account: String, itemListed: Bool)
    /// The account a review displayed for this reference no longer has the
    /// vault. The decision is forgotten; the next request shows the new one.
    case vaultNoLongerInAccount(vault: String, account: String)
    /// This account already failed the fetch ahead under way, so it was not
    /// asked again (`OnePasswordProvider.fetchAhead`).
    case accountRefusedThisFetch(account: String)
    /// This account refused authorization, and nobody has approved a csec
    /// panel at the Mac since, so it was not asked again
    /// (`OnePasswordProvider.personApprovedAtMac`).
    case accountRefusedUntilApproval(account: String)

    /// Internal detail, `op`'s own stderr included. For csecd's log — never for
    /// a client, which gets `boundedReason`.
    public var description: String {
        switch self {
        case .cliNotFound:
            return "the verified official 1Password CLI (op) was not found"
        case .authenticationFailed(let status):
            return "1Password desktop authorization failed (exit \(status))"
        case let .readFailed(reference, status, message):
            return "op read \(reference) failed (exit \(status)): \(message)"
        case let .notUTF8(reference):
            return "op returned non-UTF-8 data for \(reference)"
        case .noSignedInAccounts:
            return "no 1Password account is signed in on this device"
        case .notAuthorized:
            return "no signed-in 1Password account is currently authorized"
        case let .vaultNotFoundInAnyAccount(vault, accounts):
            return "no signed-in 1Password account has vault \(vault) (searched \(accounts))"
        case let .vaultAmbiguous(vault, accounts):
            return "vault \(vault) exists in more than one 1Password account \(accounts)"
        case let .referenceNotFound(vault, account, itemListed):
            return "reference not found in vault \(vault) of \(account)"
                + " (item listed: \(itemListed))"
        case let .vaultNoLongerInAccount(vault, account):
            return "\(account) no longer has vault \(vault)"
        case let .accountRefusedThisFetch(account):
            return "\(account) already failed this fetch ahead; not asked again"
        case let .accountRefusedUntilApproval(account):
            return "\(account) refused authorization; not asked again until an approval at the Mac"
        }
    }

    /// Text csec itself authored, safe to repeat to a client: fixed wording plus
    /// bounded, sanitized metadata. `op`'s stderr is deliberately excluded — it
    /// is unbounded and shaped by whatever the reference names.
    public var boundedReason: String {
        switch self {
        case .cliNotFound:
            return "the official 1Password CLI (op) was not found, or is not the signed binary"
        case .authenticationFailed, .notAuthorized:
            return "the 1Password CLI is not authorized; unlock 1Password and try again"
        case .noSignedInAccounts:
            return "no 1Password account is signed in on this device"
        case .readFailed:
            return "1Password rejected the read; check the vault, item, and field names"
        case .notUTF8:
            return "1Password returned data that is not a single text field"
        case let .vaultNotFoundInAnyAccount(vault, accounts):
            return "no signed-in 1Password account has vault “\(Self.safe(vault))”"
                + " (searched \(Self.safeList(accounts)))"
        case let .vaultAmbiguous(vault, accounts):
            return "vault “\(Self.safe(vault))” exists in more than one signed-in 1Password"
                + " account (\(Self.safeList(accounts))); request it again so the account can"
                + " be shown for approval, or name one account exactly by using the vault's"
                + " unique id in the reference"
        case let .referenceNotFound(vault, account, itemListed):
            if itemListed {
                return "1Password account \(Self.safe(account)) has that item in vault"
                    + " “\(Self.safe(vault))” but not that section or field; check the reference"
            }
            return "1Password account \(Self.safe(account)) has no such item in vault"
                + " “\(Self.safe(vault))”; check the reference, or name another account's"
                + " vault by its unique id"
        case let .vaultNoLongerInAccount(vault, account):
            return "1Password account \(Self.safe(account)), which was shown for this"
                + " reference, no longer has vault “\(Self.safe(vault))”; request it again"
                + " so the account can be shown for approval"
        case let .accountRefusedThisFetch(account):
            return "1Password account \(Self.safe(account)) did not serve an earlier value in this"
                + " fetch, so csec did not ask it again"
        case let .accountRefusedUntilApproval(account):
            return "1Password did not authorize csec for account \(Self.safe(account)), so csec"
                + " will not ask it again until you approve a csec panel at this Mac"
        }
    }

    private static func safe(_ text: String) -> String {
        OnePasswordProvider.displaySafe(text)
    }

    private static func safeList(_ values: [String]) -> String {
        values.prefix(8).map { safe($0) }.joined(separator: ", ")
    }
}
