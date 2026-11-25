import CryptoKit
import Darwin
import Foundation
import Security
import CSECBuildIdentity

// Delegated approvals: when csecd may accept Claude Code's auto-mode
// classifier verdict in place of a Touch ID panel.
//
// `csec hook claude` registers the exact program the matching `csec ai` will
// run, from a verified launcher whose kernel ancestry is `csec hook → shell →
// P`. When that `csec ai` asks for references, csecd walks `csec ai → shell →
// P`, binds the one registration to that `csec ai` incarnation, and checks,
// from the kernel and Claude Code's own settings, that only the classifier (or
// a human at its fallback prompt) could have approved the command: P's code
// identity, that P is the foreground job of a terminal, its launch options and
// environment, and G1/G2/G5/G6 in its settings. If every gate holds and every
// new reference is paired with P's project (a human approved it there on this
// Mac), the release goes ahead with no panel, mints no grant, and resolves
// warm-only: `Agent` and `SSHSigningService` do that, never this actor. Any
// failure is a decline with a reason the panel shows.
//
// Nothing here is a runtime switch. The opt-in lives only in the protected
// `delegation`/`settings-v1` item, written by `enable` behind csecd's own
// Touch ID sheet; no environment variable, argument or file changes it.

/// What `evaluateRelease` or `evaluateSSH` decided.
public enum DelegationEvaluation: Sendable, Equatable {
    /// Not a Claude Code request, or delegation is off: no note.
    case notApplicable
    /// A Claude Code request csecd did not approve on its own. `session` is
    /// the Claude Code process it came from when that is known, which a
    /// human approval of the panel may pair.
    case declined(DelegationDecline, session: DelegationSession?)
    /// Every gate holds and every new reference (or SSH use) is paired.
    case approved(DelegationTicket)
}

/// The Claude Code session (P) a request came from.
public struct DelegationSession: Sendable, Equatable {
    public let agent: ProcessIncarnation
    /// P's project, when its working directory is on a local disk: the git
    /// repository that directory is in (`ProjectRepository`), or the
    /// directory itself when it is in none. Pairings are keyed on it.
    public let project: ProjectKey?
    /// The build's display label (its version, for the native installer).
    public let buildLabel: String
    /// How csecd located P's live code for its identity check, when it
    /// could: recorded with the decision.
    public let identityLookup: ForeignCodeIdentity.Lookup?

    public init(
        agent: ProcessIncarnation, project: ProjectKey?, buildLabel: String,
        identityLookup: ForeignCodeIdentity.Lookup? = nil
    ) {
        self.agent = agent
        self.project = project
        self.buildLabel = buildLabel
        self.identityLookup = identityLookup
    }
}

/// One approved delegation: exactly one classifier-judged Bash call.
public struct DelegationTicket: Sendable, Equatable {
    public let session: DelegationSession
    /// The `csec ai` process the registration is bound to.
    public let command: ProcessIncarnation
    public let project: ProjectKey
    /// The pairing the approval drew on; nil for an SSH signing in a project
    /// with no pairing that holds its destination or the project.
    public let pairingID: String?
    /// The pairing recorded on P's own directory, when the approval also
    /// drew on it: a use counts for both.
    public let otherPairingIDs: [String]

    public init(
        session: DelegationSession, command: ProcessIncarnation, project: ProjectKey, pairingID: String?,
        otherPairingIDs: [String] = []
    ) {
        self.session = session
        self.command = command
        self.project = project
        self.pairingID = pairingID
        self.otherPairingIDs = otherPairingIDs
    }
}

/// The account csecd runs as: its home from the account record, never from
/// csecd's own `HOME`.
public struct DelegationAccount: Sendable, Equatable {
    public let homeDirectory: String
    public let userName: String
    /// The account's uid: a sudo is this account's when its real uid is.
    public let userID: uid_t

    public init(homeDirectory: String, userName: String, userID: uid_t = getuid()) {
        self.homeDirectory = homeDirectory
        self.userName = userName
        self.userID = userID
    }

    public static var current: DelegationAccount {
        guard let entry = getpwuid(getuid()), let home = entry.pointee.pw_dir,
              let name = entry.pointee.pw_name else {
            return DelegationAccount(homeDirectory: "", userName: "")
        }
        return DelegationAccount(homeDirectory: String(cString: home), userName: String(cString: name))
    }
}

/// Whether a process is the signed csec launcher, for the lazy SSH binding.
public struct DelegationLauncherCheck: Sendable {
    public let isVerifiedLauncher: @Sendable (ProcessIncarnation) -> Bool

    public init(isVerifiedLauncher: @escaping @Sendable (ProcessIncarnation) -> Bool) {
        self.isVerifiedLauncher = isVerifiedLauncher
    }

    /// The product's code requirement for the launcher, on the process's own
    /// audit token (exec-exact), or on its PID only when the kernel refuses
    /// csecd the task name port: the same fallback P's identity check takes
    /// (`ForeignCodeIdentity` knows nothing of product roles). Without it, a
    /// csecd refused the port would decline every `git push` whose `csec ai`
    /// sent no access request.
    public static let live = DelegationLauncherCheck { process in
        ProductCodeIdentity.resolve(pid: process.pid, startTime: process.startTime)?.identity.role == .launcher
    }
}

/// A Claude Code build on disk, for `trust_build`: csecd computes its cdhash
/// itself; the path a client sends is only where to look.
public struct InspectedClaudeBuild: Sendable, Equatable {
    public let cdHash: String
    public let signedByAnthropic: Bool

    public init(cdHash: String, signedByAnthropic: Bool) {
        self.cdHash = cdHash
        self.signedByAnthropic = signedByAnthropic
    }
}

public struct ClaudeBuildInspector: Sendable {
    public let inspect: @Sendable (String) -> InspectedClaudeBuild?

    public init(inspect: @escaping @Sendable (String) -> InspectedClaudeBuild?) {
        self.inspect = inspect
    }

    /// The host architecture's slice (the static code's default), strictly
    /// valid, with its code-directory hash: the cdhash a live process of this
    /// file reports.
    public static let live = ClaudeBuildInspector { path in
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        let strict = SecCSFlags(rawValue: UInt32(kSecCSStrictValidate))
        guard SecStaticCodeCheckValidity(staticCode, strict, nil) == errSecSuccess else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)), &information
        ) == errSecSuccess,
              let unique = (information as? [String: Any])?[kSecCodeInfoUnique as String] as? Data else {
            return nil
        }
        let cdHash = unique.map { String(format: "%02x", $0) }.joined()
        guard ForeignCodeIdentity.isWellFormedCDHash(cdHash) else { return nil }
        var requirement: SecRequirement?
        let anthropic = SecRequirementCreateWithString(
            ForeignCodeIdentity.anthropicClaudeCodeRequirement as CFString, [], &requirement
        ) == errSecSuccess && requirement.map {
            SecStaticCodeCheckValidity(staticCode, strict, $0) == errSecSuccess
        } == true
        return InspectedClaudeBuild(cdHash: cdHash, signedByAnthropic: anthropic)
    }
}

/// When things happened, on the kernel's monotonic clock (`mach_absolute_time`
/// ticks, which a wall-clock step never moves). At fork the kernel stamps a
/// process's start twice in one step (`microtime_with_abstime` in xnu's
/// `kern_fork.c`): the wall-clock `p_start` that `ProcessIncarnation.startTime`
/// carries, and `ps_start` on this clock, which `proc_pid_rusage` reports as
/// `ri_proc_start_abstime`. A registration's arrival is read from the same
/// clock, so "the registration arrived before this `csec ai` started" is a
/// comparison within one clock domain.
public struct DelegationProcessClock: Sendable {
    public let now: @Sendable () -> UInt64
    /// A process's start on this clock, or nil when it cannot be read for
    /// exactly this incarnation (gone, pid reused, or refused).
    public let start: @Sendable (ProcessIncarnation) -> UInt64?
    /// Milliseconds in a span of this clock's ticks, for diagnostics only.
    public let milliseconds: @Sendable (UInt64) -> UInt64

    public init(
        now: @escaping @Sendable () -> UInt64, start: @escaping @Sendable (ProcessIncarnation) -> UInt64?,
        milliseconds: @escaping @Sendable (UInt64) -> UInt64 = { $0 }
    ) {
        self.now = now
        self.start = start
        self.milliseconds = milliseconds
    }

    public static let live = DelegationProcessClock(
        now: { mach_absolute_time() },
        start: { process in
            // The wall-clock start is re-read on both sides, so the value
            // read between belongs to this incarnation.
            guard ProcessAncestry.startTime(of: process.pid) == process.startTime else { return nil }
            var usage = rusage_info_v0()
            let result = withUnsafeMutablePointer(to: &usage) { pointer in
                pointer.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) {
                    proc_pid_rusage(process.pid, RUSAGE_INFO_V0, $0)
                }
            }
            guard result == 0, usage.ri_proc_start_abstime > 0,
                  ProcessAncestry.startTime(of: process.pid) == process.startTime else { return nil }
            return usage.ri_proc_start_abstime
        },
        milliseconds: { ticks in
            var timebase = mach_timebase_info_data_t()
            guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.denom > 0 else { return 0 }
            return UInt64(Double(ticks) * Double(timebase.numer) / Double(timebase.denom) / 1_000_000)
        }
    )
}

/// Runs fact collection off the delegation actor, bounded. The kernel's own
/// cwd and descriptor reads stat the object they name (`vn_stat`), and code
/// validation reads the executable, so one Claude Code session sitting in a
/// hung network mount could stall a read indefinitely. The bound turns that
/// into a decline instead of a hang, which the design ethos accepts: it
/// prevents a hang, it is not a re-verification clock. A job that outlives
/// its bound keeps the queue marked stuck until it returns, and while it is
/// stuck every new job is refused at once, so a stuck read never piles up
/// threads behind it (queued jobs hold no thread).
///
/// The bound is on a job's own run, from when it starts: jobs run one at a
/// time, and a burst (the requests a rules-changed acknowledgement releases
/// together, many sessions at once) queues healthy jobs behind each other.
/// Counting that wait against each job's bound declined the later ones
/// `factsUnavailable` and marked the queue stuck, which then refused the
/// hook's registration read too, so the command's `ssh` declined
/// `notRegistered` (csec-0.64.8, csec-0.68). Waiting has its own, longer
/// limit (`waitBound`) so a caller behind a hung job is still answered; a
/// job given up on while it waited never runs and marks nothing stuck.
final class DelegationFactQueue: @unchecked Sendable {
    /// How long a job may wait for the jobs ahead of it before its caller is
    /// answered with nothing, unless its own bound is longer. Healthy jobs
    /// take milliseconds, so this is reached only behind a job that has hung
    /// (and is already past its own bound), and stays inside `csec hook`'s
    /// two-second registration wait.
    static let waitBound: Duration = .seconds(1)

    private let queue: DispatchQueue
    private let lock = NSLock()
    private var overdue = 0

    init(label: String) {
        queue = DispatchQueue(label: label)
    }

    var isStuck: Bool {
        lock.lock()
        defer { lock.unlock() }
        return overdue > 0
    }

    func run<T: Sendable>(
        within bound: Duration,
        waitingAtMost wait: Duration? = nil,
        _ work: @escaping @Sendable () -> T
    ) async -> T? {
        if isStuck { return nil }
        let wait = wait ?? max(Self.waitBound, bound)
        return await withCheckedContinuation { (continuation: CheckedContinuation<T?, Never>) in
            let job = DelegationFactJob()
            queue.async {
                // Its caller stopped waiting before its turn came: skip it.
                guard job.start() else { return }
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + Self.dispatchInterval(bound)) {
                    if job.claim() {
                        self.markOverdue()
                        continuation.resume(returning: nil)
                    }
                }
                let value = work()
                if job.claim() {
                    continuation.resume(returning: value)
                } else {
                    self.finishedOverdue()
                }
            }
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + Self.dispatchInterval(wait)) {
                if job.abandonIfWaiting() {
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    private static func dispatchInterval(_ duration: Duration) -> DispatchTimeInterval {
        let (seconds, attoseconds) = duration.components
        return .nanoseconds(max(0, Int(seconds) * 1_000_000_000 + Int(attoseconds / 1_000_000_000)))
    }

    private func markOverdue() {
        lock.lock()
        overdue += 1
        lock.unlock()
    }

    private func finishedOverdue() {
        lock.lock()
        overdue = max(0, overdue - 1)
        lock.unlock()
    }
}

/// One job's turn: waiting for the queue, running, then answered exactly
/// once, by its result, its run's bound, or (only while still waiting) the
/// wait limit.
private final class DelegationFactJob: @unchecked Sendable {
    private enum State { case waiting, running, answered }
    private let lock = NSLock()
    private var state = State.waiting

    /// Whether the job may run: false once its caller stopped waiting.
    func start() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard state == .waiting else { return false }
        state = .running
        return true
    }

    /// Answers a running job; false when it was already answered.
    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard state == .running else { return false }
        state = .answered
        return true
    }

    /// Answers a job that never started; false once it has.
    func abandonIfWaiting() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard state == .waiting else { return false }
        state = .answered
        return true
    }
}

/// Identities resolved for a process image, keyed by incarnation, the audit
/// token's PID version (which exec changes) and the trusted-build set they
/// were checked against. Never expired on a clock: an entry is dropped when
/// its process is gone, and the cache is bounded.
private final class DelegationIdentityCache: @unchecked Sendable {
    struct Key: Hashable {
        let process: ProcessIncarnation
        let pidVersion: Int32
        let trustGeneration: UInt64
    }

    private static let maximumEntries = 512
    private let lock = NSLock()
    private var entries: [Key: ForeignCodeIdentity] = [:]
    private var order: [Key] = []

    func identity(for key: Key) -> ForeignCodeIdentity? {
        lock.lock()
        defer { lock.unlock() }
        return entries[key]
    }

    func store(_ identity: ForeignCodeIdentity, for key: Key) {
        lock.lock()
        defer { lock.unlock() }
        if entries.updateValue(identity, forKey: key) == nil { order.append(key) }
        if order.count > Self.maximumEntries {
            let excess = order.count - Self.maximumEntries
            for key in order.prefix(excess) { entries[key] = nil }
            order.removeFirst(excess)
        }
    }

    /// A renamed image already encountered on a real request must still reach
    /// the release watchdog. The inventory revalidates each incarnation/exec.
    func observedClaudeProcesses() -> Set<ProcessIncarnation> {
        lock.lock()
        defer { lock.unlock() }
        return Set(entries.filter { $0.value.isClaudeCode }.map { $0.key.process })
    }

    func prune(keeping isLive: (ProcessIncarnation) -> Bool) {
        lock.lock()
        defer { lock.unlock() }
        order.removeAll { key in
            if isLive(key.process) { return false }
            entries[key] = nil
            return true
        }
    }
}

public actor ClaudeDelegationService {
    /// At most this many Claude Code processes hold registrations at once, as
    /// `Agent` bounds its registered sessions.
    public static let maximumRegisteredAgents = 64
    /// Pending registrations per P; the oldest pending goes first: a call
    /// long finished that sent no access request, or one that was blocked.
    public static let maximumPendingPerAgent = 256
    public static let maximumBoundPerAgent = 256
    /// How far above `ssh` its `csec ai` may be. Whatever stands between them
    /// is not judged, so a deep tree (a package manager's scripts, a deploy
    /// wrapper) still reaches its command.
    public static let maximumSSHAncestorHops = 32
    /// The shells `csec hook` runs under (`/bin/sh` execs the shell
    /// `/private/var/select/sh` names, `/bin/bash` here).
    public static let hookShellPaths: Set<String> = ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh"]
    /// The Bash tool's shell, by exec basename.
    public static let toolShellNames: Set<String> = ["zsh", "bash", "sh"]

    /// Bounds on reading kernel facts off the actor. A request's facts take
    /// about 0.1 ms, a first identity check 2–7 ms and a settings read a few
    /// more; 300 ms leaves two orders of magnitude of headroom and is still
    /// far below the classifier's own 1–5 s, so nobody waits on it unless a
    /// read has hung. Each bounds a job's own run, never its wait behind
    /// other jobs (`DelegationFactQueue`). Restore discovery checks every live interactive
    /// session's identity once (tens of milliseconds), and the settings reads
    /// behind `csec setup` and `csec status` scan plugins and project
    /// directories, so each gets its own queue and a larger bound.
    public static let factBound: Duration = .milliseconds(300)
    public static let discoveryBound: Duration = .seconds(1)
    public static let configurationBound: Duration = .seconds(2)
    /// The stored-sign-in check (`ClaudeCredentialStore`) lists the Keychain
    /// in a few milliseconds, but reading a Claude Code record that changed
    /// since the last request runs `security`, 60–190 ms a record, so it has
    /// its own queue and bound.
    public static let credentialBound: Duration = .seconds(2)

    private struct Registration: Sendable {
        let agent: ProcessIncarnation
        let programSHA256: String
        let permissionMode: String
        let hookCWD: String
        /// For a git command the hook left unwrapped: binds only to the Bash
        /// tool shell that evaluates it, never to a `csec ai`, and the other
        /// kind never binds to a tool shell.
        let unwrapped: Bool
        /// The verified csec launcher whose hook registered it: with no `csec
        /// ai` to name it, the csec whose own Claude Code hook G2 excludes.
        let launcherPath: String?
        /// When csecd received it, on `DelegationProcessClock`.
        let arrivedAt: UInt64
        var boundTo: ProcessIncarnation?
    }

    private enum SettingsState: Sendable {
        /// No protected stores: delegation cannot be turned on.
        case unavailable
        case absent
        case unreadable(String)
        case document(DelegationSettingsDocument)
    }

    private let stores: ProtectedStores?
    private let gate: any ClaudeSettingsGate
    private let compiledBuilds: ClaudeBuildVerification
    /// The held signed release manifest, whose Claude Code list adds to
    /// `compiledBuilds`; nil reads the compiled list alone.
    private let manifestStore: ReleaseManifestStore?
    /// Told when a request declines on an unchecked image, so csecd can look
    /// for a newer signed list sooner than its daily check.
    private let uncheckedBuildSeen: (@Sendable () -> Void)?
    private let consent: any ConsentProvider
    private let facts: any ClaudeSessionFactProvider
    private let account: DelegationAccount
    private let decisionLog: DecisionLog?
    private let terminalInspection: TerminalSessionInspector
    private let launcherCheck: DelegationLauncherCheck
    private let buildInspector: ClaudeBuildInspector
    private let volumeUUID: @Sendable (String) -> String?
    private let isOnLocalMounts: @Sendable (String) -> Bool
    /// The file system a session's git repository is found in.
    private let repositories: ProjectRepository.FileSystem
    private let allowUnverifiedCallersForTesting: Bool
    /// The delegation policy this build enforces (`DelegationPolicy
    /// .currentVersion`); settings consented to an older one leave delegation
    /// off until `csec setup` confirms again. Injectable for tests only; csecd
    /// constructs the service with the compiled version (bin/ci pins it).
    private let policyVersion: Int
    private let processClock: DelegationProcessClock
    private let clock: @Sendable () -> Date
    private let screenLocked: @Sendable () -> Bool
    private let bootSessionUUID: String?
    private let requestFacts = DelegationFactQueue(label: CSECBuildIdentity.named("delegation.facts"))
    private let discoveryFacts = DelegationFactQueue(label: CSECBuildIdentity.named("delegation.discovery"))
    private let configurationFacts = DelegationFactQueue(label: CSECBuildIdentity.named("delegation.configuration"))
    private let credentialFacts = DelegationFactQueue(label: CSECBuildIdentity.named("delegation.credentials"))
    private let factBound: Duration
    private let discoveryBound: Duration
    private let configurationBound: Duration
    private let credentialBound: Duration
    private let credentialStore: any ClaudeCredentialStore
    private let identityCache = DelegationIdentityCache()

    private var loadTask: Task<Void, Never>?
    private var settings: SettingsState
    /// The sequence of the last settings change prepared. Every change is
    /// prepared and made what this actor holds in one synchronous step, so
    /// the actor's view follows the order the store applies changes in.
    private var settingsSequence: UInt64 = 0
    /// Counts `disable`s. An authority-adding Touch ID sheet that was up
    /// across a disable is refused rather than turning delegation back on.
    private var disableGeneration: UInt64 = 0
    private var pairings: [ProjectPairing] = []
    /// When each pairing was last added to or used, in memory only: the item
    /// is rewritten only when a pairing is added or removed. Loaded pairings
    /// start in their stored (insertion) order.
    private var pairingRecency: [String: UInt64] = [:]
    private var recencyClock: UInt64 = 0
    private var registrations: [ProcessIncarnation: [Registration]] = [:]
    /// Set once the bound registrations a previous csecd persisted have been
    /// read back; nothing is written before, so a restart never overwrites
    /// them with an empty table.
    private var registrationsRestored = false
    private var pendingRegistrationWrite: Task<Void, Never>?
    private var trustGeneration: UInt64 = 0
    private var approvedCount = 0
    private var declinedCount = 0
    private var lastDecline: String?
    /// The latest registration csecd refused, and when (on `processClock`),
    /// so a `not_registered` decline soon after can name it. A refusal sends
    /// the hook nothing it shows, so otherwise it leaves no trace.
    private var lastRegistrationRefusal: (reason: String, at: UInt64)?
    /// How the most recent Claude Code identity check located P's code, for
    /// `csec status`: whether the kernel refuses this csecd the task name
    /// port is otherwise visible nowhere.
    private var lastIdentityLookup: ForeignCodeIdentity.Lookup?
    /// Requesters whose decline was counted and recorded, while they live.
    private var declinedRequesters: [ProcessIncarnation] = []
    /// The note each live sudo review helper's panel shows (`sudoNote(for:)`).
    private var sudoNotes: [ProcessIncarnation: SudoDelegationNote] = [:]
    /// The Claude Code process each declined sudo's helper served, as its
    /// `decline` record names it (`sudoAgent(for:)`).
    private var sudoAgents: [ProcessIncarnation: ProcessIncarnation] = [:]
    /// The setup notice for each live `csec ai` a request under it declined
    /// for a `needsSetup` reason, until that `csec ai` takes it
    /// (`takeSetupNotice(for:)`).
    private var setupNotices: [ProcessIncarnation: String] = [:]
    /// The pairing each live sudo review helper's panel offered, by helper.
    private var sudoOffers: [ProcessIncarnation: PendingSudoOffer] = [:]
    /// The changed classifier rules each live requester's decline found,
    /// until `Agent` asks whether to show them (`acknowledgeChangedRules`).
    private var changedRules: [ProcessIncarnation: [ClaudeHookSource]] = [:]
    /// The rules-changed panel on screen, if any, and the digests it shows:
    /// every other request that declines on changed rules waits for it.
    private var rulesReview: (id: UInt64, digests: Set<String>, task: Task<RulesReviewOutcome, Never>)?
    private var rulesReviewCount: UInt64 = 0
    /// Rule digests the human denied on the rules-changed panel this csecd
    /// run: they are not offered again, and their requests get their own
    /// panels, as before csec-0.64.
    private var refusedRuleDigests: Set<String> = []

    enum RulesReviewOutcome: Sendable, Equatable {
        case acknowledged
        /// The human's Deny.
        case refused
        /// The panel went with its requester (it exited, or the panel was
        /// withdrawn or timed out with it): a request still waiting may show
        /// it again.
        case requesterGone
        /// Not shown, not approved for another reason, or not recorded.
        case notAcknowledged
    }

    private struct PendingSudoOffer: Sendable {
        let session: DelegationSession
        let line: String
    }
    private static let maximumRecordedDeclines = 256

    public init(
        stores: ProtectedStores?,
        gate: any ClaudeSettingsGate,
        consent: any ConsentProvider,
        facts: any ClaudeSessionFactProvider = LiveClaudeSessionFactProvider(),
        account: DelegationAccount = .current,
        decisionLog: DecisionLog? = nil,
        terminalInspection: TerminalSessionInspector,
        launcherCheck: DelegationLauncherCheck = .live,
        buildInspector: ClaudeBuildInspector = .live,
        buildVerification: ClaudeBuildVerification = .shipped,
        manifestStore: ReleaseManifestStore? = nil,
        uncheckedBuildSeen: (@Sendable () -> Void)? = nil,
        volumeUUID: @escaping @Sendable (String) -> String? = { VolumeIdentity.uuid(ofMountPoint: $0) },
        isOnLocalMounts: @escaping @Sendable (String) -> Bool = { ProcessAncestry.pathIsOnLocalMounts($0) == true },
        repositories: ProjectRepository.FileSystem = .live,
        factBound: Duration = ClaudeDelegationService.factBound,
        discoveryBound: Duration = ClaudeDelegationService.discoveryBound,
        configurationBound: Duration = ClaudeDelegationService.configurationBound,
        credentialStore: any ClaudeCredentialStore,
        credentialBound: Duration = ClaudeDelegationService.credentialBound,
        policyVersion: Int = DelegationPolicy.currentVersion,
        processClock: DelegationProcessClock = .live,
        allowUnverifiedCallersForTesting: Bool = false,
        clock: @escaping @Sendable () -> Date = { Date() },
        screenLocked: @escaping @Sendable () -> Bool = { ScreenLockState.isScreenLocked },
        bootSessionUUID: String? = CsecdRunFacts.bootSessionUUID()
    ) {
        self.stores = stores
        self.gate = gate
        self.consent = consent
        self.facts = facts
        self.account = account
        self.decisionLog = decisionLog
        self.terminalInspection = terminalInspection
        self.launcherCheck = launcherCheck
        self.buildInspector = buildInspector
        self.compiledBuilds = buildVerification
        self.manifestStore = manifestStore
        self.uncheckedBuildSeen = uncheckedBuildSeen
        self.volumeUUID = volumeUUID
        self.isOnLocalMounts = isOnLocalMounts
        self.repositories = repositories
        self.factBound = factBound
        self.discoveryBound = discoveryBound
        self.configurationBound = configurationBound
        self.credentialStore = credentialStore
        self.credentialBound = credentialBound
        self.allowUnverifiedCallersForTesting = allowUnverifiedCallersForTesting
        self.policyVersion = policyVersion
        self.processClock = processClock
        self.clock = clock
        self.screenLocked = screenLocked
        self.bootSessionUUID = bootSessionUUID
        self.settings = stores == nil ? .unavailable : .absent
    }

    // MARK: - Loading

    /// Reads the settings and pairings once. Every entry point awaits it, so
    /// concurrent first callers share the one load.
    public func load() async {
        if let loadTask { return await loadTask.value }
        let task = Task { await self.performLoad() }
        loadTask = task
        await task.value
    }

    private func performLoad() async {
        guard let stores else {
            settings = .unavailable
            return
        }
        switch await stores.store(for: DelegationSettingsDocument.self).load() {
        case .absent:
            settings = .absent
        case let .document(document):
            settings = .document(document)
        case let .unreadable(reason):
            settings = .unreadable(reason.description)
            log("the delegation settings are unreadable (\(reason)); delegated approvals stay off")
        }
        switch await stores.store(for: PairingDocument.self).load() {
        case .absent:
            pairings = []
        case let .document(document):
            pairings = document.projects
        case let .unreadable(reason):
            pairings = []
            let held = stores.store(for: PairingDocument.self).heldReason != nil
            log("the project pairings are unreadable (\(reason)); none are used"
                + (held ? ", and the item is kept as found" : ""))
        }
        recencyClock = 0
        pairingRecency = [:]
        for pairing in pairings {
            recencyClock += 1
            pairingRecency[pairing.id] = recencyClock
        }
        await restoreRegistrations(from: stores.store(for: DelegationRegistrationsDocument.self))
    }

    /// Puts back the bound registrations the previous csecd persisted. One is
    /// restored only within the same boot session (process start times and
    /// `DelegationProcessClock` count from boot) while both P and the command
    /// it is bound to are the same incarnations. That keeps only what the
    /// previous csecd already knew, that csec's hook saw P's auto mode approve
    /// this program for this running command; every gate is judged again on
    /// each request. Pending registrations are never persisted: the hook makes
    /// one per Bash call, and only a command that already asked binds one.
    private func restoreRegistrations(from store: ProtectedStore<DelegationRegistrationsDocument>) async {
        defer { registrationsRestored = true }
        let document: DelegationRegistrationsDocument
        switch await store.load() {
        case .absent:
            return
        case let .unreadable(reason):
            // Not held (see `DelegationRegistrationsDocument`): the next bind
            // replaces it with this csecd's own.
            log("the auto-mode registrations are unreadable (\(reason)); none are restored")
            return
        case let .document(stored):
            document = stored
        }
        var restored = 0
        for record in document.registrations {
            let agent = ProcessIncarnation(pid: record.agentPID, startTime: record.agentStartTime)
            let command = ProcessIncarnation(pid: record.commandPID, startTime: record.commandStartTime)
            var entries = registrations[agent] ?? []
            guard let bootSessionUUID, record.bootSessionUUID == bootSessionUUID,
                  facts.incarnation(of: agent.pid) == agent,
                  facts.incarnation(of: command.pid) == command,
                  !entries.isEmpty || registrations.count < Self.maximumRegisteredAgents,
                  entries.count < Self.maximumBoundPerAgent,
                  !entries.contains(where: { $0.boundTo == command && $0.unwrapped == record.unwrapped })
            else { continue }
            entries.append(Registration(
                agent: agent,
                programSHA256: record.programSHA256,
                permissionMode: record.permissionMode,
                hookCWD: record.hookCWD,
                unwrapped: record.unwrapped,
                launcherPath: record.launcherPath,
                arrivedAt: record.arrivedAt,
                boundTo: command
            ))
            registrations[agent] = entries
            restored += 1
        }
        let dropped = document.registrations.count - restored
        if restored > 0 || dropped > 0 {
            log("restored \(restored) bound auto-mode registration(s) from the previous csecd"
                + (dropped > 0 ? "; \(dropped) left out (a later boot, or a process that has exited)" : ""))
        }
        if dropped > 0 { persistRegistrations() }
    }

    /// Writes the bound registrations behind, prepared in this synchronous
    /// section so a later change always supersedes an earlier one. A lost
    /// write only costs one panel after a restart; it can never widen
    /// anything, because a restore re-checks both processes and every request
    /// re-runs every gate. Newest first; what does not fit is left out.
    private func persistRegistrations() {
        guard let stores, registrationsRestored else { return }
        let store = stores.store(for: DelegationRegistrationsDocument.self)
        var records = registrations.values.flatMap { $0 }
            .compactMap { entry -> PersistedDelegationRegistration? in
                guard let command = entry.boundTo else { return nil }
                return PersistedDelegationRegistration(
                    agentPID: entry.agent.pid,
                    agentStartTime: entry.agent.startTime,
                    commandPID: command.pid,
                    commandStartTime: command.startTime,
                    programSHA256: entry.programSHA256,
                    permissionMode: entry.permissionMode,
                    hookCWD: entry.hookCWD,
                    unwrapped: entry.unwrapped,
                    launcherPath: entry.launcherPath,
                    arrivedAt: entry.arrivedAt,
                    bootSessionUUID: bootSessionUUID
                )
            }
            .filter(\.isWellFormed)
            .sorted { $0.arrivedAt > $1.arrivedAt }
            .prefix(DelegationRegistrationsDocument.maximumRegistrations)
            .map { $0 }
        var change: ProtectedChange?
        while change == nil {
            do {
                change = records.isEmpty
                    ? try store.prepareDeletion()
                    : try store.prepare(DelegationRegistrationsDocument(registrations: records))
            } catch ProtectedStoreError.rejected(.oversized) where !records.isEmpty {
                records.removeLast()
            } catch {
                return
            }
        }
        guard let change else { return }
        let previous = pendingRegistrationWrite
        pendingRegistrationWrite = Task {
            await previous?.value
            _ = try? await change.commit()
        }
    }

    /// Waits for every registration write prepared so far.
    public func flushPersistedRegistrations() async {
        await pendingRegistrationWrite?.value
    }

    // MARK: - State

    public var state: DelegationState {
        switch settings {
        case .unavailable: return .unavailable
        case .absent: return .off
        case .unreadable: return .unreadable
        case let .document(document):
            guard document.clients.contains(.claude) else { return .off }
            return document.consentedPolicyVersion >= policyVersion ? .on : .reconfirmationRequired
        }
    }

    public func isEnabled() async -> Bool {
        await load()
        return state == .on
    }

    private var document: DelegationSettingsDocument? {
        if case let .document(document) = settings { return document }
        return nil
    }

    // MARK: - Registration

    /// `register_agent_command`, routed here directly by csecd. Accepted only
    /// with delegation on, from a live verified launcher whose kernel argv is
    /// exactly `<csec> hook claude` under a platform shell's `-c` under P.
    /// Nothing about P is judged here; that happens when the command is used.
    public func register(_ registration: AgentCommandRegistration, caller: CallerInfo) async -> Bool {
        // Stamped on receipt, before anything is awaited: the later it is
        // read, the fewer `csec ai` it can belong to, never more.
        let arrivedAt = processClock.now()
        await load()
        // Delegation off refuses every Bash call's registration by design;
        // only the refusals that cost a delegated release are reported.
        guard state == .on else { return false }
        guard registration.isWellFormed, registration.client == .claude,
              allowUnverifiedCallersForTesting || caller.peerIdentity?.code.role == .launcher,
              caller.pid > 1, caller.startTime > 0 else {
            return registrationRefused("not from a verified csec hook", caller: caller, arrivedAt: arrivedAt)
        }
        let peer = ProcessIncarnation(pid: caller.pid, startTime: caller.startTime)
        let provider = facts
        let queueWasStuck = requestFacts.isStuck
        guard let chain = await requestFacts.run(within: factBound, {
            Self.hookChain(of: peer, provider: provider)
        }) else {
            return registrationRefused(
                queueWasStuck ? "fact reads stuck behind an overdue read" : "fact read did not finish in time",
                caller: caller, arrivedAt: arrivedAt
            )
        }
        guard let agent = chain else {
            return registrationRefused(
                "the hook's process chain did not verify (the hook may have exited)", caller: caller, arrivedAt: arrivedAt
            )
        }
        pruneRegistrations()
        var entries = registrations[agent] ?? []
        if entries.isEmpty, registrations.count >= Self.maximumRegisteredAgents {
            return registrationRefused(
                "\(Self.maximumRegisteredAgents) Claude Code processes already hold registrations",
                caller: caller, arrivedAt: arrivedAt
            )
        }
        noteSlowRegistration(caller: caller, arrivedAt: arrivedAt)
        entries.append(Registration(
            agent: agent,
            programSHA256: registration.programSHA256,
            permissionMode: registration.permissionMode,
            hookCWD: registration.hookCWD,
            unwrapped: registration.unwrapped,
            launcherPath: caller.peerIdentity?.code.executablePath,
            arrivedAt: arrivedAt
        ))
        let pending = entries.indices.filter { entries[$0].boundTo == nil }
        if pending.count > Self.maximumPendingPerAgent, let oldest = pending.first {
            entries.remove(at: oldest)
        }
        registrations[agent] = entries
        return true
    }

    /// The hook stops waiting for csecd's answer after one second of
    /// silence (`AgentLiveness.agentCommandRegistration`); a registration
    /// answered later than this is logged even when it was accepted.
    static let slowRegistrationMilliseconds: UInt64 = 750

    /// Logs a refused registration with its reason and timing, remembers it
    /// for the next `not_registered` decline, and returns false. Value-free:
    /// the reason is csecd's own text, never the command or its digest.
    private func registrationRefused(_ reason: String, caller: CallerInfo, arrivedAt: UInt64) -> Bool {
        lastRegistrationRefusal = (reason, processClock.now())
        log("\(Self.logTimestamp(clock())) auto-mode registration refused: \(reason); "
            + registrationTiming(caller: caller, arrivedAt: arrivedAt))
        return false
    }

    private func noteSlowRegistration(caller: CallerInfo, arrivedAt: UInt64) {
        guard let acceptedAt = caller.acceptedAt else { return }
        let now = processClock.now()
        guard now > acceptedAt,
              processClock.milliseconds(now - acceptedAt) >= Self.slowRegistrationMilliseconds else { return }
        log("\(Self.logTimestamp(clock())) auto-mode registration accepted late; "
            + registrationTiming(caller: caller, arrivedAt: arrivedAt))
    }

    private func registrationTiming(caller: CallerInfo, arrivedAt: UInt64) -> String {
        Self.registrationTiming(
            caller: caller, arrivedAt: arrivedAt, now: processClock.now(), milliseconds: processClock.milliseconds
        )
    }

    /// Where a registration's time went: from the hook's connection to the
    /// delegation actor taking it, split into csecd's check of the hook's
    /// code identity, the hook's own wait before it sent (its check of
    /// csecd's signature, which waits on trustd) and csecd's queue, and from
    /// the actor to the answer (fact reads).
    public static func registrationTiming(
        caller: CallerInfo, arrivedAt: UInt64, now: UInt64, milliseconds: (UInt64) -> UInt64
    ) -> String {
        func span(_ from: UInt64?, _ to: UInt64?) -> String {
            guard let from, let to, to >= from else { return "unknown" }
            return "\(milliseconds(to - from)) ms"
        }
        let handled = span(arrivedAt, now)
        guard let acceptedAt = caller.acceptedAt, arrivedAt >= acceptedAt else {
            return "handled in \(handled) (connection time unknown)"
        }
        return "reached the delegation actor \(milliseconds(arrivedAt - acceptedAt)) ms after the hook connected "
            + "(csecd's identity check \(span(acceptedAt, caller.identifiedAt)), "
            + "then the hook's request arrived \(span(caller.identifiedAt, caller.requestReadAt)) later, "
            + "then \(span(caller.requestReadAt, arrivedAt)) to reach the actor), handled in \(handled) "
            + "(the hook gives up 2000 ms after it starts, and 1000 ms after sending)"
    }

    static func logTimestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    /// Why a `csec ai`'s request found no registration to bind, for its
    /// `not_registered` decline record (`delegation.registration`).
    private func missingRegistrationNote(
        agent: ProcessIncarnation, digest: String?, commandStart: UInt64?, unwrapped: Bool
    ) -> String {
        var note: String
        let entries = registrations[agent] ?? []
        if digest == nil {
            note = "unreadable_command"
        } else if entries.isEmpty {
            note = "none_under_agent"
        } else if let commandStart, let late = entries.last(where: {
            $0.boundTo == nil && $0.programSHA256 == digest && $0.unwrapped == unwrapped && $0.arrivedAt >= commandStart
        }) {
            note = "late_by_\(processClock.milliseconds(late.arrivedAt - commandStart))ms"
        } else if commandStart == nil {
            note = "command_start_unreadable"
        } else {
            note = "no_match"
        }
        if let refusal = lastRegistrationRefusal {
            let now = processClock.now()
            let ago = now >= refusal.at ? processClock.milliseconds(now - refusal.at) : 0
            if ago <= Self.recentRefusalMilliseconds {
                note += "; a registration was refused \(ago) ms earlier: \(refusal.reason)"
            }
        }
        return note
    }

    static let recentRefusalMilliseconds: UInt64 = 60_000

    /// `peer → H → P` for a registration: the peer's argv is exactly
    /// `<path> hook claude`, H is a platform shell run with `-c`, and every
    /// link held across the reads. Returns P.
    private static func hookChain(
        of peer: ProcessIncarnation, provider: any ClaudeSessionFactProvider
    ) -> ProcessIncarnation? {
        guard let chain = ClaudeSessionFacts.verifiedAncestry(of: peer, hops: 2, provider: provider),
              chain.count == 3,
              let argv = provider.argv(of: peer), argv.count == 3,
              bytesEqual(argv[1], "hook"), bytesEqual(argv[2], "claude"),
              let shellPath = provider.executablePath(of: chain[1]),
              hookShellPaths.contains(shellPath),
              let shellArgv = provider.argv(of: chain[1]), shellArgv.count >= 2,
              bytesEqual(shellArgv[1], "-c") else { return nil }
        return chain[2]
    }

    private func pruneRegistrations() {
        var boundChanged = false
        for (agent, entries) in registrations {
            guard facts.incarnation(of: agent.pid) == agent else {
                if entries.contains(where: { $0.boundTo != nil }) { boundChanged = true }
                registrations[agent] = nil
                continue
            }
            let kept = entries.filter { entry in
                guard let command = entry.boundTo else { return true }
                return facts.incarnation(of: command.pid) == command
            }
            if kept.count != entries.count { boundChanged = true }
            registrations[agent] = kept.isEmpty ? nil : kept
        }
        if boundChanged { persistRegistrations() }
        identityCache.prune { [facts] in facts.incarnation(of: $0.pid) == $0 }
    }

    /// The registration for `digest` under P, bound to `command`: one already
    /// bound to this same `csec ai` (a request re-entering after a wait), or
    /// else the newest pending one, which becomes bound before any gate is
    /// judged, so a second `csec ai` with the same program finds nothing.
    ///
    /// Newest, never oldest: the hook registers each Bash call just before
    /// that call's `csec ai` runs, so the newest registration of this program
    /// is the run in progress. Older pending ones are common: every call that
    /// sent no access request leaves its registration pending until P exits
    /// or newer ones push it out, whether it ran (a secret-free command, one
    /// with no references, one a grant covered) or never did (the classifier
    /// or a human blocked it, or it was interrupted). Each was made in
    /// whatever mode Claude Code was in then; binding an older one would let
    /// a later identical run in `default`, `acceptEdits`, `plan` or `dontAsk`
    /// borrow a stale `auto`. Two pending registrations of one program in
    /// flight together (parallel identical calls) come from the same moment,
    /// so each `csec ai` still finds one.
    ///
    /// And only one that arrived before this `csec ai` started (`commandStart`,
    /// on the same clock): Claude Code runs a call's hook, which waits for
    /// csecd's reply, before it starts the call's shell, so a registration
    /// newer than the `csec ai` belongs to a later call (one that may still be
    /// classifying, or be blocked). A start that cannot be read binds nothing.
    ///
    /// Only a registration of the anchor's own kind binds: an unwrapped one to
    /// the Bash tool shell that evaluates its command, any other to a `csec
    /// ai`.
    ///
    /// The residual: when this call's own registration never reached csecd,
    /// or arrived only after its `csec ai` started (csecd busy past the hook's
    /// one-second wait), the newest earlier pending registration of the
    /// byte-identical program binds instead, with the mode it was made in.
    /// A call approved another way (an allow rule, `dontAsk`, a human's
    /// click) then inherits that registration's `auto`, which takes an
    /// identical program left pending in auto mode, a mode switch, and a lost
    /// or late registration together.
    private func bind(
        agent: ProcessIncarnation, command: ProcessIncarnation, digest: String, commandStart: UInt64?,
        unwrapped: Bool
    ) -> Registration? {
        guard var entries = registrations[agent] else { return nil }
        if let index = entries.firstIndex(where: {
            $0.boundTo == command && $0.programSHA256 == digest && $0.unwrapped == unwrapped
        }) {
            return entries[index]
        }
        guard let commandStart, let index = entries.lastIndex(where: {
            $0.boundTo == nil && $0.programSHA256 == digest && $0.unwrapped == unwrapped && $0.arrivedAt < commandStart
        }) else {
            return nil
        }
        entries[index].boundTo = command
        let bound = entries.indices.filter { entries[$0].boundTo != nil }
        if bound.count > Self.maximumBoundPerAgent, let oldest = bound.first, oldest != index {
            entries.remove(at: oldest)
        }
        registrations[agent] = entries
        persistRegistrations()
        return entries.first { $0.boundTo == command && $0.programSHA256 == digest && $0.unwrapped == unwrapped }
    }

    /// A registration of the anchor's kind already bound to `command` under
    /// P, whatever its program: the SSH path looks for the `csec ai`, or the
    /// Bash tool shell, that runs git.
    private func boundRegistration(
        agent: ProcessIncarnation, command: ProcessIncarnation, unwrapped: Bool
    ) -> Registration? {
        registrations[agent]?.first { $0.boundTo == command && $0.unwrapped == unwrapped }
    }

    /// Whether csec's hook registered this program for a `csec ai` under some
    /// Claude Code process, pending or already bound to `command`. When the
    /// walk to P could not be read, that is all that says a request is Claude
    /// Code's: only the hook in a Claude Code session writes a registration.
    private func registrationExists(forDigest digest: String, command: ProcessIncarnation) -> Bool {
        registrations.values.contains { entries in
            entries.contains {
                !$0.unwrapped && $0.programSHA256 == digest && ($0.boundTo == nil || $0.boundTo == command)
            }
        }
    }

    // MARK: - Evaluating a secret release

    /// Decides whether a `csec ai` request's new references may be released
    /// with no panel. `commandLine` is the request's `/bin/zsh -lc <program>`
    /// argv, which `AICommandExec.isAIRequest` has already matched to its
    /// plan; `caller` is the verified `csec ai` peer.
    public func evaluateRelease(
        caller: CallerInfo,
        commandLine: [String],
        newReferences: [SecretRef]
    ) async -> DelegationEvaluation {
        await load()
        guard state == .on, commandLine.count == 3, caller.pid > 1, caller.startTime > 0 else {
            return .notApplicable
        }
        let command = ProcessIncarnation(pid: caller.pid, startTime: caller.startTime)
        let provider = facts
        let processClock = processClock
        let program = commandLine[2]
        let digest = AICommandHook.programDigest(program)
        guard let walked = await requestFacts.run(within: factBound, {
            Self.commandWalk(from: command, provider: provider, processClock: processClock)
        }) else {
            // The walk to P could not be read, so nothing says which process
            // asked. Only a registration of this program says it is Claude
            // Code's; a terminal's or Codex's own `csec ai` gets no note.
            guard registrationExists(forDigest: digest, command: command) else { return .notApplicable }
            return await declined(
                .factsUnavailable, session: nil, references: newReferences.map(\.uri),
                surface: .secretAccess, requester: command
            )
        }
        guard let walk = walked,
              walk.shellPrefix || walk.shellPath.map({ Self.toolShellNames.contains(($0 as NSString).lastPathComponent) })
                == true else {
            return .notApplicable
        }
        pruneRegistrations()
        // The request names the program; the peer's own kernel argv must name
        // the same program byte for byte, which is also what keeps `csec
        // tool-exec` (`argv[1] != "ai"`) out. The registration names what the
        // hook saw: the same program, or, for the shell prefix, the command
        // inside its framing's `eval`.
        let registration: Registration?
        var registeredDigest: String?
        if let argv = walk.commandArgv,
           let running = AICommandExec.program(fromProcessArguments: argv),
           Self.bytesEqual(running, program),
           let registered = AICommandExec.registeredProgram(fromProcessArguments: argv) {
            registeredDigest = AICommandHook.programDigest(registered)
            registration = bind(
                agent: walk.chain.agent, command: command, digest: AICommandHook.programDigest(registered),
                commandStart: walk.commandStart, unwrapped: false
            )
        } else {
            registration = nil
        }
        let missingRegistration = registration == nil
            ? missingRegistrationNote(
                agent: walk.chain.agent, digest: registeredDigest, commandStart: walk.commandStart, unwrapped: false
            )
            : nil
        return await judge(
            agent: walk.chain.agent,
            shell: walk.chain.shell,
            command: command,
            registration: registration,
            commandExecutablePath: caller.peerIdentity?.code.executablePath ?? walk.commandPath,
            references: newReferences.map(\.uri),
            paired: { pairing in
                newReferences.first { !pairing.references.contains($0.uri) }.map(\.safeInlineURI)
            },
            // The program shell runs its startup files, with every released
            // value in its environment, before the approved text: ZDOTDIR on
            // the `csec ai` would point them at files the classifier never saw.
            chainFailure: SSHChainRule.shellSteering(walk.environment),
            surface: .secretAccess,
            requester: command,
            missingRegistration: missingRegistration
        )
    }

    /// Decides whether an access request that is not itself a `csec ai` (a
    /// language client over `csec bridge`, a nested `csec get` or `csec exec`)
    /// may be released with no panel because the command it runs under is one
    /// auto mode approved. The anchor is found as for SSH: the nearest
    /// ancestor whose argv is `csec ai …`, under the Bash tool shell under P,
    /// already bound to a registration or bound lazily when it is the signed
    /// launcher. What runs between the request and that `csec ai` is not
    /// judged, as for SSH (csec-0.11): auto mode approved the command. The
    /// rest is a secret release's: P's identity and gates, auto mode, ZDOTDIR
    /// on the `csec ai`, and every new reference paired with the project.
    /// A request with no `csec ai` above it (a terminal's, Codex's) is
    /// `.notApplicable` and its panel shows no note.
    ///
    /// `daemonUse` says csecd will use the values itself and release nothing
    /// (`daemon_proxy`): a reference paired only for that use covers it, and
    /// never a release. `lastingAccess` is set for csecd's use of the GitHub
    /// token on a request that can give lasting access, which always
    /// declines, paired or not.
    public func evaluateNested(
        caller: CallerInfo,
        newReferences: [SecretRef],
        daemonUse: Bool = false,
        lastingAccess: GitHubLastingAccess? = nil
    ) async -> DelegationEvaluation {
        await load()
        guard state == .on, caller.pid > 1, caller.startTime > 0 else { return .notApplicable }
        let requester = ProcessIncarnation(pid: caller.pid, startTime: caller.startTime)
        let provider = facts
        let launcherCheck = launcherCheck
        let processClock = processClock
        guard let walked = await requestFacts.run(within: factBound, {
            Self.sshWalk(from: requester, provider: provider, launcherCheck: launcherCheck, processClock: processClock)
                .map { walk in
                    (walk, SSHChainAnchorEnvironment.read(from: walk.chain[walk.commandIndex], provider: provider))
                }
        }), let (walk, environment) = walked, walk.anchor != .toolShell else {
            guard daemonUse else { return .notApplicable }
            return await evaluateOwnQuery(requester: requester, newReferences: newReferences, lastingAccess: lastingAccess)
        }
        let command = walk.chain[walk.commandIndex]
        let shell = walk.chain[walk.shellIndex]
        let agent = walk.chain[walk.shellIndex + 1]
        pruneRegistrations()
        var registration = boundRegistration(agent: agent, command: command, unwrapped: false)
        if registration == nil, walk.mayBindLazily, let program = walk.commandProgram {
            registration = bind(
                agent: agent, command: command, digest: AICommandHook.programDigest(program),
                commandStart: walk.commandStart, unwrapped: false
            )
        }
        return await judge(
            agent: agent,
            shell: shell,
            command: command,
            registration: registration,
            commandExecutablePath: walk.commandPath,
            references: newReferences.map(\.uri),
            paired: { pairing in
                newReferences.first { !pairing.covers($0.uri, daemonUse: daemonUse) }.map(\.safeInlineURI)
            },
            daemonUse: daemonUse,
            lastingAccess: lastingAccess,
            // The program shell ran its startup files before the approved
            // text: ZDOTDIR on the `csec ai` could have put code the
            // classifier never saw between it and this request.
            chainFailure: SSHChainRule.shellSteering(environment),
            surface: .secretAccess,
            requester: requester
        )
    }

    /// Claude Code's own `gh` queries. After a Bash command whose text
    /// matches `git … push` (or a checkout), Claude Code itself runs `gh pr
    /// view [<selector>] [--repo <owner>/<repo>] --json url`, with a five-second
    /// timeout, to link the session to its PR. And at most once a day per
    /// config (`closedIssuesLastChecked`) it runs `gh issue list -R
    /// anthropics/claude-code --author @me --state closed --search
    /// 'closed:><date>' --json number,title,closedAt,stateReason --limit 30`
    /// to say when issues you filed were fixed. Each `gh` is P's own child,
    /// not a command the classifier judged, so it has no `csec ai` above it
    /// and would raise a panel. Alex chose to let both through (csec-0.47.1,
    /// csec-0.64.10): each is a fixed, read-only query, the token stays inside
    /// csecd, and it is narrower than the `gh` use auto mode already has. So a
    /// `gh` whose parent is P, whose kernel argv is exactly one of those
    /// shapes, is judged as P's own request: every gate on P's identity,
    /// launch, environment and settings, and the reference paired for csecd's
    /// use. Only the permission mode is not read, since no hook registered
    /// anything. Any other `gh` P runs gets its panel, with a note saying
    /// Claude Code ran it itself, so the log says why.
    private func evaluateOwnQuery(
        requester: ProcessIncarnation, newReferences: [SecretRef], lastingAccess: GitHubLastingAccess?
    ) async -> DelegationEvaluation {
        let provider = facts
        guard let found = await requestFacts.run(within: factBound, {
            Self.ownQuery(of: requester, provider: provider)
        }), let query = found else { return .notApplicable }
        let agent: ProcessIncarnation
        switch query {
        case let .recognised(parent):
            agent = parent
        case let .unrecognised(subcommand):
            // Named Claude Code, not verified: the note only says why the
            // panel came, and nothing is released on it.
            return await declined(
                .agentOwnCommand(subcommand), session: nil, references: newReferences.map(\.uri),
                surface: .secretAccess, requester: requester
            )
        }
        return await judge(
            agent: agent,
            shell: requester,
            command: requester,
            registration: nil,
            pullRequestLookup: true,
            // No `csec ai` names a launcher, so G2 recognises csec's own hook
            // by the one every generated hook invokes.
            commandExecutablePath: CodingAgentSetup.installedLauncherPath,
            references: newReferences.map(\.uri),
            paired: { pairing in
                newReferences.first { !pairing.covers($0.uri, daemonUse: true) }.map(\.safeInlineURI)
            },
            daemonUse: true,
            lastingAccess: lastingAccess,
            chainFailure: nil,
            surface: .secretAccess,
            requester: requester
        )
    }

    /// A `gh` that is P's direct child: one of Claude Code's own fixed
    /// queries (`recognised`, with P), or any other `gh` a process named
    /// Claude Code ran (`unrecognised`, with its subcommand words).
    enum OwnQuery: Equatable {
        case recognised(ProcessIncarnation)
        case unrecognised(String)
    }

    static func ownQuery(of gh: ProcessIncarnation, provider: any ClaudeSessionFactProvider) -> OwnQuery? {
        guard let path = provider.executablePath(of: gh), (path as NSString).lastPathComponent == "gh",
              let argv = provider.argv(of: gh),
              let chain = ClaudeSessionFacts.verifiedAncestry(of: gh, hops: 1, provider: provider),
              chain.count == 2 else { return nil }
        if isClaudePullRequestLookup(argv) || isClaudeClosedIssuesCheck(argv) { return .recognised(chain[1]) }
        guard CodingAgentIdentity.client(name: nil, executablePath: provider.executablePath(of: chain[1])) == .claude else {
            return nil
        }
        return .unrecognised(ghSubcommand(argv))
    }

    /// P, when `gh` is its direct child running one of Claude Code's own
    /// queries.
    static func pullRequestLookupAgent(
        of gh: ProcessIncarnation, provider: any ClaudeSessionFactProvider
    ) -> ProcessIncarnation? {
        guard case let .recognised(agent) = ownQuery(of: gh, provider: provider) else { return nil }
        return agent
    }

    /// `gh` and up to two subcommand words, each a short lowercase word, for
    /// a note: never an option or argument, which could carry anything.
    static func ghSubcommand(_ argv: [String]) -> String {
        var words = ["gh"]
        for word in argv.dropFirst().prefix(2) {
            let bytes = Array(word.utf8)
            guard !bytes.isEmpty, bytes.count <= 32, bytes.first != UInt8(ascii: "-"),
                  bytes.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7a) || $0 == UInt8(ascii: "-") }) else { break }
            words.append(word)
        }
        return words.joined(separator: " ")
    }

    /// Whether `argv` is exactly the lookup Claude Code builds:
    /// `gh pr view [<selector>] [--repo <owner>/<repo>] --json url`. The
    /// selector is a branch name or PR number; Claude Code drops one that
    /// starts with `-` or is a URL, and so does this.
    public static func isClaudePullRequestLookup(_ argv: [String]) -> Bool {
        guard argv.count >= 5, argv.count <= 8, (argv[0] as NSString).lastPathComponent == "gh",
              argv[1] == "pr", argv[2] == "view", argv[argv.count - 2] == "--json", argv[argv.count - 1] == "url" else {
            return false
        }
        var middle = Array(argv[3..<(argv.count - 2)])
        if middle.count >= 2, middle[middle.count - 2] == "--repo" {
            guard isRepositoryName(middle[middle.count - 1]) else { return false }
            middle.removeLast(2)
        }
        switch middle.count {
        case 0: return true
        case 1: return isPullRequestSelector(middle[0])
        default: return false
        }
    }

    /// Whether `argv` is exactly Claude Code's closed-issues check, as
    /// 2.1.305 builds it: `gh issue list -R anthropics/claude-code --author
    /// @me --state closed --search closed:><YYYY-MM-DD> --json
    /// number,title,closedAt,stateReason --limit 30`. Only the date varies
    /// (thirty days before the check).
    public static func isClaudeClosedIssuesCheck(_ argv: [String]) -> Bool {
        guard argv.count == 15, (argv[0] as NSString).lastPathComponent == "gh" else { return false }
        let fixed = ["issue", "list", "-R", "anthropics/claude-code", "--author", "@me", "--state", "closed",
                     "--search", nil, "--json", "number,title,closedAt,stateReason", "--limit", "30"]
        for (index, expected) in fixed.enumerated() {
            let word = argv[index + 1]
            if let expected {
                guard word == expected else { return false }
            } else {
                guard isClosedSinceSearch(word) else { return false }
            }
        }
        return true
    }

    /// `closed:>` and a date, `YYYY-MM-DD`.
    private static func isClosedSinceSearch(_ value: String) -> Bool {
        let prefix = "closed:>"
        guard value.hasPrefix(prefix) else { return false }
        let date = Array(value.utf8.dropFirst(prefix.utf8.count))
        guard date.count == 10 else { return false }
        return date.enumerated().allSatisfy { index, byte in
            index == 4 || index == 7 ? byte == UInt8(ascii: "-") : (byte >= 0x30 && byte <= 0x39)
        }
    }

    private static func isPullRequestSelector(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return !bytes.isEmpty && bytes.count <= 255 && bytes.first != UInt8(ascii: "-")
            && bytes.allSatisfy { $0 > 0x20 && $0 < 0x7f } && !value.contains("://")
    }

    private static func isRepositoryName(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        return value.utf8.count <= 201 && parts.count == 2 && parts.allSatisfy { part in
            !part.isEmpty && part.utf8.allSatisfy { byte in
                (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a)
                    || byte == UInt8(ascii: "_") || byte == UInt8(ascii: ".") || byte == UInt8(ascii: "-")
            }
        }
    }

    private struct CommandWalk: Sendable {
        let chain: AgentCommandChain
        let shellPath: String?
        let commandPath: String?
        let commandArgv: [String]?
        /// When the `csec ai` started, on `DelegationProcessClock`.
        let commandStart: UInt64?
        /// The `csec ai`'s environment, which its program shell starts from.
        let environment: SSHChainAnchorEnvironment
        /// The `csec ai` is Claude Code's shell prefix, directly under P and
        /// its own tool shell (`ClaudeSessionFacts.shellPrefixChain`).
        let shellPrefix: Bool
    }

    private static func commandWalk(
        from command: ProcessIncarnation, provider: any ClaudeSessionFactProvider, processClock: DelegationProcessClock
    ) -> CommandWalk? {
        let argv = provider.argv(of: command)
        let shellPrefix = argv.map { AICommandExec.isShellPrefix(arguments: Array($0.dropFirst(2))) && $0.count >= 2
            && $0[1] == "ai" } ?? false
        guard let chain = shellPrefix
            ? ClaudeSessionFacts.shellPrefixChain(from: command, provider: provider)
            : ClaudeSessionFacts.commandChain(from: command, provider: provider) else { return nil }
        return CommandWalk(
            chain: chain,
            shellPath: shellPrefix ? nil : provider.executablePath(of: chain.shell),
            commandPath: provider.executablePath(of: command),
            commandArgv: argv,
            commandStart: processClock.start(command),
            environment: SSHChainAnchorEnvironment.read(from: command, provider: provider),
            shellPrefix: shellPrefix
        )
    }

    /// Everything after the walk, shared by secret, SSH and sudo requests: the
    /// registration, then P's identity, G3, G4, G5, its project, G1/G2/G6,
    /// the permission mode, and the pairing. The first failure is the reason.
    ///
    /// An SSH signing (`ssh` set) stops after the permission mode and the
    /// project: auto mode approved the command `ssh` runs under, in a verified
    /// Claude Code session, and that alone signs it (Alex, csec-0.11). No
    /// classifier-rule acknowledgement, launcher pin, chain shape or approved
    /// destination is asked for.
    private func judge(
        agent: ProcessIncarnation,
        shell: ProcessIncarnation,
        command: ProcessIncarnation,
        registration: Registration?,
        pullRequestLookup: Bool = false,
        commandExecutablePath: String?,
        references: [String],
        paired: (ProjectPairing) -> String?,
        daemonUse: Bool = false,
        lastingAccess: GitHubLastingAccess? = nil,
        ssh: PairedSSHUse? = nil,
        sudo: Bool = false,
        logCommand: String? = nil,
        chainFailure: DelegationDecline?,
        surface: DecisionLogRecord.Surface,
        requester: ProcessIncarnation,
        missingRegistration: String? = nil
    ) async -> DelegationEvaluation {
        let inputs = SessionInputs(
            agent: agent,
            shell: shell,
            trusted: document?.trustedCDHashes ?? [],
            trustGeneration: trustGeneration,
            hookCWD: registration?.hookCWD,
            evaluateGates: (registration != nil || pullRequestLookup) && chainFailure == nil,
            csecExecutablePath: commandExecutablePath ?? "/usr/local/bin/csec",
            account: account,
            acknowledgedDigests: document?.acknowledgedDigests ?? []
        )
        guard let session = await collectSession(inputs, on: requestFacts, within: factBound) else {
            // P's facts could not be read, so its identity is unknown. A
            // registration under P (only csec's hook in a Claude Code session
            // writes one) still says this is Claude Code's request; without
            // one, nothing does, and the request gets its panel with no note.
            guard registration != nil else { return .notApplicable }
            return await declined(.factsUnavailable, session: nil, references: references, surface: surface, requester: requester, command: logCommand)
        }
        let isClaude = session.identity?.isClaudeCode == true || session.namedClaude
        if let lookup = session.identity?.lookup { lastIdentityLookup = lookup }
        let delegationSession = DelegationSession(
            agent: agent, project: session.projectKey, buildLabel: session.buildLabel,
            identityLookup: session.identity?.lookup
        )
        // With no registration this is a Claude Code request only if P is
        // Claude Code; anything else (Codex, a terminal) gets no note.
        if registration == nil {
            guard isClaude else { return .notApplicable }
            guard pullRequestLookup else {
                return await declined(
                    .notRegistered, session: delegationSession, references: references,
                    surface: surface, requester: requester, command: logCommand, registration: missingRegistration
                )
            }
        }
        if let chainFailure {
            return await declined(chainFailure, session: delegationSession, references: references, surface: surface, requester: requester, command: logCommand)
        }
        if let failure = session.failure(
            acknowledgedDigests: document?.acknowledgedDigests ?? [], ignoringClassifierRules: ssh != nil
        ) {
            rememberSetupNotice(failure, for: command)
            // Declined on an unacknowledged G2 source (changed rules, or a
            // hook added since the last acknowledgement): the one-touch panel
            // can acknowledge exactly what was found (csec-0.64, csec-0.64.7).
            // An SSH signing ignores rules, so only a hook brings it here;
            // sudo is left out, since PAM bounds its review to 300 s.
            if failure.isUnacknowledgedSettings, !sudo, case let .evaluated(evaluation) = session.settings {
                let unacknowledged = evaluation.unacknowledgedHooks(
                    acknowledgedDigests: document?.acknowledgedDigests ?? []
                ).filter { ssh == nil || $0.kind != .classifierRules }
                rememberChangedRules(unacknowledged, for: requester)
            }
            return await declined(failure, session: delegationSession, references: references, surface: surface, requester: requester, command: logCommand)
        }
        // Claude Code's own PR lookup has no registration, so no permission
        // mode to read; the classifier judges none of P's own requests.
        if let registration, registration.permissionMode != AgentCommandRegistration.autoPermissionMode {
            return await declined(
                .notAutoMode(registration.permissionMode), session: delegationSession, references: references,
                surface: surface, requester: requester, command: logCommand
            )
        }
        guard let project = session.projectKey else {
            return await declined(.projectUnavailable, session: delegationSession, references: references, surface: surface, requester: requester, command: logCommand)
        }
        // Last of the session's gates, so a request that fails an earlier
        // one never lists the Keychain.
        if let failure = await gatewaySignInFailure(values: session.values) {
            return await declined(failure, session: delegationSession, references: references, surface: surface, requester: requester, command: logCommand)
        }
        let matching = Self.pairings(pairings, for: project, directory: session.directoryKey)
        // sudo runs only where a human let auto mode run it.
        if sudo {
            guard let holder = sudoApproval(matching: matching) else {
                return await declined(
                    .sudoNotApproved(project: project.displayName), session: delegationSession,
                    references: references, surface: surface, requester: requester, command: logCommand
                )
            }
            return .approved(DelegationTicket(
                session: delegationSession, command: command, project: project, pairingID: holder,
                otherPairingIDs: matching.map(\.id).filter { $0 != holder }
            ))
        }
        // An SSH signing auto mode approved signs, to any destination. A
        // pairing that holds this destination (the project's own first, then
        // any other) or the project's own pairing still counts as used.
        if let ssh {
            let holder = matching.first { $0.ssh.contains(ssh) }
                ?? pairings.first { $0.ssh.contains(ssh) }
                ?? matching.first
            return .approved(DelegationTicket(
                session: delegationSession, command: command, project: project, pairingID: holder?.id,
                otherPairingIDs: matching.map(\.id).filter { $0 != holder?.id }
            ))
        }
        // A one-time code is never released by auto mode, paired or not: a
        // person approves each one, so its panel says that rather than
        // offering to pair it.
        if let code = references.lazy.compactMap({ try? SecretRef($0) }).first(where: \.isOneTimeCode) {
            return await declined(
                .oneTimeCode(code.safeInlineURI),
                session: delegationSession, references: references,
                surface: surface, requester: requester, command: logCommand
            )
        }
        // Nor does it approve a GitHub request that can give lasting access:
        // the classifier judged the command, not the request csecd parsed,
        // and what the request adds outlasts the session it approved.
        if let lastingAccess {
            return await declined(
                .lastingAccess(lastingAccess.request),
                session: delegationSession, references: references,
                surface: surface, requester: requester, command: logCommand
            )
        }
        // csecd's own use of a value it never releases (the GitHub socket)
        // is paired once for every project: the token is the user's, not a
        // project's, and the classifier judges each command that uses it, so
        // a second project's panel would only re-ask what the human already
        // decided. A use any project's pairing holds covers it here, the
        // project's own first. A release still needs this project's pairing.
        if daemonUse, !references.isEmpty, references.allSatisfy({ reference in
            matching.contains { $0.covers(reference, daemonUse: true) }
                || pairings.contains { $0.usedReferences.contains(reference) }
        }) {
            let holder = matching.first { pairing in references.allSatisfy { pairing.covers($0, daemonUse: true) } }
                ?? pairings.first { $0.usedReferences.contains(references[0]) }
            return .approved(DelegationTicket(
                session: delegationSession, command: command, project: project, pairingID: holder?.id,
                otherPairingIDs: matching.map(\.id).filter { $0 != holder?.id }
            ))
        }
        guard let primary = matching.first else {
            let first = references.first.flatMap { try? SecretRef($0) }?.safeInlineURI ?? "this request"
            return await declined(
                .notApprovedForProject(reference: first, project: project.displayName),
                session: delegationSession, references: references,
                surface: surface, requester: requester, command: logCommand
            )
        }
        let pairing = matching.dropFirst().reduce(primary) { combined, other in
            var combined = combined
            combined.references += other.references.filter { !combined.references.contains($0) }
            combined.usedReferences += other.usedReferences.filter { !combined.usedReferences.contains($0) }
            combined.ssh += other.ssh.filter { !combined.ssh.contains($0) }
            return combined
        }
        if let unpaired = paired(pairing) {
            return await declined(
                .notApprovedForProject(reference: unpaired, project: project.displayName),
                session: delegationSession, references: references,
                surface: surface, requester: requester, command: logCommand
            )
        }
        return .approved(DelegationTicket(
            session: delegationSession, command: command, project: project, pairingID: primary.id,
            otherPairingIDs: matching.dropFirst().map(\.id)
        ))
    }

    /// A stored Cloud-gateway sign-in in any of Claude Code's credential
    /// records would answer the classifier (csec-kpep), and so does one
    /// csecd cannot check. G5 has already held, so P's configuration
    /// directory is unset or absolute and its secure-storage directory unset
    /// or empty.
    private func gatewaySignInFailure(values: [String: String]?) async -> DelegationDecline? {
        var configDirectory: String?
        if case let .directory(directory) = ClaudeSettingsScope.ConfigDirectory(
            environmentValue: values?["CLAUDE_CONFIG_DIR"]
        ) {
            configDirectory = directory
        }
        let path = ClaudeGatewaySignIn.plaintextPath(
            homeDirectory: account.homeDirectory, configDirectory: configDirectory
        )
        let store = credentialStore
        switch await credentialFacts.run(within: credentialBound, { store.gatewaySignIn(plaintextPath: path) }) {
        case .notSignedIn?: return nil
        case .signedIn?: return .gatewaySignIn
        case .unchecked?, nil: return .gatewaySignInUnchecked
        }
    }

    /// The pairings a session's request may use: its repository's, and the
    /// one recorded on its own working directory before pairings were keyed
    /// on the repository, which still holds there and nowhere else.
    private static func pairings(
        _ pairings: [ProjectPairing], for project: ProjectKey, directory: ProjectKey?
    ) -> [ProjectPairing] {
        var keys = [project]
        if let directory, directory != project { keys.append(directory) }
        return keys.compactMap { key in pairings.first { $0.project == key } }
    }

    private func declined(
        _ reason: DelegationDecline,
        session: DelegationSession?,
        references: [String],
        surface: DecisionLogRecord.Surface,
        requester: ProcessIncarnation,
        command: String? = nil,
        registration: String? = nil
    ) async -> DelegationEvaluation {
        await noteDecline(
            reason, session: session, references: references, surface: surface, requester: requester, command: command,
            registration: registration
        )
        return .declined(reason, session: session)
    }

    /// Counts and records a decline once per requesting process: a request
    /// that waited for its turn is judged again, and must not be counted or
    /// logged twice.
    private func noteDecline(
        _ reason: DelegationDecline,
        session: DelegationSession?,
        references: [String],
        surface: DecisionLogRecord.Surface,
        requester: ProcessIncarnation,
        command: String? = nil,
        registration: String? = nil
    ) async {
        lastDecline = reason.statusText
        if case .uncheckedBuild = reason { uncheckedBuildSeen?() }
        declinedRequesters.removeAll { facts.incarnation(of: $0.pid) != $0 }
        guard !declinedRequesters.contains(requester) else { return }
        declinedRequesters.append(requester)
        if declinedRequesters.count > Self.maximumRecordedDeclines {
            declinedRequesters.removeFirst(declinedRequesters.count - Self.maximumRecordedDeclines)
        }
        declinedCount += 1
        // Without a session P's facts were never read: the requester is
        // recorded as unknown, never as a verified Claude Code process.
        let record = DecisionLogRecord(
            kind: .decline,
            surface: surface,
            requester: DecisionLogRecord.Requester(
                class: session == nil ? "unknown" : "coding_agent:claude", rootPID: session?.agent.pid
            ),
            refs: references.sorted(),
            command: command,
            delegation: DecisionLogRecord.Delegation(
                decision: "declined", reason: reason.code, claudeBuild: session?.buildLabel,
                identityLookup: session?.identityLookup?.logDescription, registration: registration
            ),
            detail: reason.panelText
        )
        await decisionLog?.record(record.bounded())
    }

    /// A delegated release happened: counted, and the pairing counts as used
    /// (in memory only).
    public func noteDelegatedRelease(_ ticket: DelegationTicket) async {
        await load()
        approvedCount += 1
        for id in [ticket.pairingID].compactMap({ $0 }) + ticket.otherPairingIDs {
            recencyClock += 1
            pairingRecency[id] = recencyClock
        }
    }

    /// The warm-only resolution after an approval found `reference` cold.
    public func noteNotHeld(
        _ ticket: DelegationTicket,
        reference: SecretRef,
        reason providerReason: String? = nil,
        surface: DecisionLogRecord.Surface = .secretAccess,
        requester: ProcessIncarnation? = nil
    ) async -> DelegationDecline {
        let reason = DelegationDecline.notHeld(reference.safeInlineURI, reason: providerReason)
        await noteDecline(
            reason, session: ticket.session, references: [reference.uri], surface: surface,
            requester: requester ?? ticket.command
        )
        return reason
    }

    // MARK: - Evaluating an SSH signing

    /// Decides whether a signing request from a verified Apple `ssh` may be
    /// answered with no panel. The `csec ai` it runs under is the first
    /// ancestor already bound to a registration, or else is bound lazily (a
    /// `git push` from an environment with no references sends no access
    /// request): the nearest ancestor whose argv is `csec ai …`, under a
    /// shell under P, which must be the signed csec launcher. What runs
    /// between `ssh` and that `csec ai` is not judged, and no destination
    /// needs approving: auto mode approved the command, and that alone signs
    /// it (Alex, csec-0.11).
    ///
    /// With no `csec ai` in the chain, the anchor is Claude Code's Bash tool
    /// shell, for a git command the hook left unwrapped
    /// (`AICommandGitPassthrough`): the nearest ancestor that is
    /// `ClaudeToolShell`, `/bin/zsh -c` evaluating exactly one literal word.
    /// That word is the command. Only an unwrapped registration of its digest
    /// binds, one received before that shell started, and only when csecd's
    /// own reading of the command says the hook registers it (a git list that
    /// reaches a remote). The tool shell then stands where `csec ai` stands.
    public func evaluateSSH(
        sshCaller: CallerInfo,
        key: SSHKeyMetadata,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication
    ) async -> DelegationEvaluation {
        await load()
        guard state == .on, sshCaller.pid > 1, sshCaller.startTime > 0 else { return .notApplicable }
        let ssh = ProcessIncarnation(pid: sshCaller.pid, startTime: sshCaller.startTime)
        let provider = facts
        let launcherCheck = launcherCheck
        let processClock = processClock
        // A walk that could not be read leaves nothing that ties this `ssh`
        // to a Claude Code session (no `csec ai`, no registration), so it
        // gets its panel with no note.
        guard let walked = await requestFacts.run(within: factBound, {
            Self.sshWalk(from: ssh, provider: provider, launcherCheck: launcherCheck, processClock: processClock)
        }), let walk = walked else { return .notApplicable }
        let command = walk.chain[walk.commandIndex]
        let shell = walk.chain[walk.shellIndex]
        let agent = walk.chain[walk.shellIndex + 1]
        let unwrapped = walk.anchor == .toolShell
        pruneRegistrations()
        var registration = boundRegistration(agent: agent, command: command, unwrapped: unwrapped)
        if registration == nil, walk.mayBindLazily, let program = walk.commandProgram {
            registration = bind(
                agent: agent, command: command, digest: AICommandHook.programDigest(program),
                commandStart: walk.commandStart, unwrapped: unwrapped
            )
        }
        let use = PairedSSHUse(
            keyFingerprint: key.fingerprint,
            hostKeyFingerprint: binding.hostKeyFingerprint,
            remoteUser: authentication.remoteUser
        )
        let evaluation = await judge(
            agent: agent,
            shell: shell,
            command: command,
            registration: registration,
            // An unwrapped command has no `csec ai` to name the launcher: it
            // is the one whose hook registered the command.
            commandExecutablePath: unwrapped ? registration?.launcherPath : walk.commandPath,
            references: [key.reference],
            paired: { _ in nil },
            ssh: use,
            // What runs between the command and `ssh` is not judged: auto
            // mode approved the command, and that is the rule (csec-0.11).
            chainFailure: nil,
            surface: .sshSigning,
            requester: ssh
        )
        return evaluation
    }

    private struct SSHWalk: Sendable {
        /// `ssh` first, then its ancestors.
        let chain: [ProcessIncarnation]
        let anchor: SSHChainAnchor
        /// The anchor's index: the `csec ai`, or the Bash tool shell.
        let commandIndex: Int
        let commandPath: String?
        /// The `csec ai`'s program, or the command the tool shell evaluates.
        let commandProgram: String?
        /// Whether a registration may be bound to the anchor here, when none
        /// is bound to it already: the `csec ai` is the signed csec launcher,
        /// or the tool shell's command is one csec's hook registers unwrapped.
        let mayBindLazily: Bool
        /// When the anchor started, on `DelegationProcessClock`.
        let commandStart: UInt64?

        /// The Bash tool shell, whose parent is P: the `csec ai`'s parent, or
        /// the anchor itself.
        var shellIndex: Int { anchor == .csecAI ? commandIndex + 1 : commandIndex }
    }

    private static func sshWalk(
        from ssh: ProcessIncarnation,
        provider: any ClaudeSessionFactProvider,
        launcherCheck: DelegationLauncherCheck,
        processClock: DelegationProcessClock
    ) -> SSHWalk? {
        guard let chain = ancestry(of: ssh, maximumHops: maximumSSHAncestorHops, provider: provider),
              chain.count >= 4 else { return nil }
        var paths: [String?] = [provider.executablePath(of: chain[0])]
        var argvs: [[String]?] = [provider.argv(of: chain[0])]
        for index in 1..<(chain.count - 1) {
            let path = provider.executablePath(of: chain[index])
            let argv = provider.argv(of: chain[index])
            // csec as Claude Code's shell prefix stands where the Bash tool
            // shell stood, directly under P; what it binds is the command
            // inside its framing's `eval`, the one the hook registered.
            if let argv, argv.count >= 2, argv[1] == "ai",
               AICommandExec.isShellPrefix(arguments: Array(argv.dropFirst(2))) {
                return SSHWalk(
                    chain: chain,
                    anchor: .csecShellPrefix,
                    commandIndex: index,
                    commandPath: path,
                    commandProgram: AICommandExec.registeredProgram(fromProcessArguments: argv),
                    mayBindLazily: launcherCheck.isVerifiedLauncher(chain[index]),
                    commandStart: processClock.start(chain[index])
                )
            }
            guard index < chain.count - 2,
                  let argv, let program = AICommandExec.program(fromProcessArguments: argv),
                  let shellPath = provider.executablePath(of: chain[index + 1]),
                  toolShellNames.contains((shellPath as NSString).lastPathComponent) else {
                paths.append(path)
                argvs.append(argv)
                continue
            }
            return SSHWalk(
                chain: chain,
                anchor: .csecAI,
                commandIndex: index,
                commandPath: path,
                commandProgram: program,
                mayBindLazily: launcherCheck.isVerifiedLauncher(chain[index]),
                commandStart: processClock.start(chain[index])
            )
        }
        // No `csec ai`: a git command the hook left unwrapped runs straight
        // from Claude Code's Bash tool shell, whose parent is P.
        while paths.count < chain.count - 1 {
            let next = chain[paths.count]
            paths.append(provider.executablePath(of: next))
            argvs.append(provider.argv(of: next))
        }
        for index in 1..<(chain.count - 1) {
            guard let program = ClaudeToolShell.program(executablePath: paths[index], argv: argvs[index]) else {
                continue
            }
            return SSHWalk(
                chain: chain,
                anchor: .toolShell,
                commandIndex: index,
                commandPath: paths[index],
                commandProgram: program,
                mayBindLazily: AICommandGitPassthrough.classify(program).registersForDelegation,
                commandStart: processClock.start(chain[index])
            )
        }
        return nil
    }

    // MARK: - Evaluating a sudo

    /// Decides whether the sudo that spawned the sudo review helper `helper`
    /// may authenticate with no panel. `display` is the command the PAM module
    /// rendered for the helper's panel (`SudoCommandDisplay`): csecd cannot
    /// read a root process's argv, and the helper has it only from the PAM
    /// module over a private pipe. Everything else is the kernel's:
    ///
    /// - the helper's parent must be `/usr/bin/sudo`, valid and signed as
    ///   part of the OS, running as root for this account
    ///   (`KernelProcessRecord`);
    /// - sudo's parent, and every process above it up to the `csec ai` that
    ///   ran the approved text, must be one `SudoChainRule` allows (the
    ///   program shell, or `timeout`), under the Bash tool shell and P;
    /// - the `csec ai`'s registration, P and its gates, auto mode and the
    ///   project are judged as for SSH, and sudo's argv must match a `sudo`
    ///   command of the text.
    ///
    /// A helper whose parent is not such a sudo, or a sudo with no `csec ai`
    /// above it (a terminal's), is `.notApplicable`: its panel shows no note.
    public func evaluateSudo(helper: CallerInfo, command display: String) async -> DelegationEvaluation {
        await load()
        guard state == .on, helper.pid > 1, helper.startTime > 0,
              allowUnverifiedCallersForTesting || helper.peerIdentity?.code.role == .sudoReviewHelper else {
            return .notApplicable
        }
        let helperProcess = ProcessIncarnation(pid: helper.pid, startTime: helper.startTime)
        let provider = facts
        let launcherCheck = launcherCheck
        let processClock = processClock
        let userID = account.userID
        guard let walked = await requestFacts.run(within: factBound, {
            Self.sudoWalk(
                helper: helperProcess, userID: userID, provider: provider, launcherCheck: launcherCheck,
                processClock: processClock
            )
        }), let walk = walked else { return .notApplicable }
        let command = walk.chain[walk.commandIndex]
        let shell = walk.chain[walk.shellIndex]
        let agent = walk.chain[walk.shellIndex + 1]
        pruneRegistrations()
        var registration = boundRegistration(agent: agent, command: command, unwrapped: false)
        if registration == nil, walk.mayBindLazily, let program = walk.commandProgram {
            registration = bind(
                agent: agent, command: command, digest: AICommandHook.programDigest(program),
                commandStart: walk.commandStart, unwrapped: false
            )
        }
        return await judge(
            agent: agent,
            shell: shell,
            command: command,
            registration: registration,
            commandExecutablePath: walk.commandPath,
            references: [],
            paired: { _ in nil },
            sudo: true,
            logCommand: display,
            chainFailure: SudoChainRule.structuralFailure(
                parents: walk.parents, arguments: SudoCommandDisplay.arguments(display),
                program: walk.commandProgram, environment: walk.environment
            ),
            surface: .sudo,
            // csecd cannot read a root sudo's own start time through
            // `incarnation(of:)`, which the decline bookkeeping uses: the
            // helper, one per sudo, stands for it.
            requester: helperProcess
        )
    }

    /// `sudo_delegation`: `evaluateSudo`, answered and logged. An approval is
    /// recorded as a `delegated_release` on the sudo surface with the redacted
    /// command the panel would have shown; a decline was already recorded.
    public func sudoDelegation(_ request: SudoDelegationRequest, caller: CallerInfo) async -> SudoDelegationAnswer {
        guard request.isWellFormed else { return .notApplicable }
        switch await evaluateSudo(helper: caller, command: request.command) {
        case .notApplicable:
            return .notApplicable
        case let .declined(reason, session):
            let line = sudoPairingOffer(for: session, reason: reason, helper: caller)
            rememberSudoNote(SudoDelegationNote(note: reason.panelText, pairingLine: line), for: caller)
            if let session { rememberSudoAgent(session.agent, for: caller) }
            return SudoDelegationAnswer(decision: .declined, note: reason.panelText, pairingLine: line)
        case let .approved(ticket):
            await noteDelegatedRelease(ticket)
            await decisionLog?.record(DecisionLogRecord(
                kind: .delegatedRelease,
                surface: .sudo,
                requester: DecisionLogRecord.Requester(class: "coding_agent:claude", rootPID: ticket.session.agent.pid),
                command: request.command,
                outcome: .approved,
                decider: .delegated,
                delegation: DecisionLogRecord.Delegation(
                    decision: "approved", claudeBuild: ticket.session.buildLabel,
                    identityLookup: ticket.session.identityLookup?.logDescription
                )
            ).bounded())
            return SudoDelegationAnswer(decision: .approved)
        }
    }

    /// What a declined sudo's panel shows, for the phone's copy of that
    /// panel: csecd's own text, keyed by the helper that asked, never taken
    /// from the helper's `sudo_remote_review`.
    public func sudoNote(for helper: CallerInfo) -> SudoDelegationNote? {
        sudoNotes[ProcessIncarnation(pid: helper.pid, startTime: helper.startTime)]
    }

    private func rememberSudoNote(_ note: SudoDelegationNote, for helper: CallerInfo) {
        sudoNotes = sudoNotes.filter { facts.incarnation(of: $0.key.pid) == $0.key }
        guard sudoNotes.count < Self.maximumRememberedSudoNotes else { return }
        sudoNotes[ProcessIncarnation(pid: helper.pid, startTime: helper.startTime)] = note
    }

    /// The Claude Code process delegation declined this helper's sudo for:
    /// the `rootPID` of its `decline` record, so the review's end is logged
    /// under the same process (`SudoReviewAttributions`).
    public func sudoAgent(for helper: CallerInfo) -> ProcessIncarnation? {
        sudoAgents[ProcessIncarnation(pid: helper.pid, startTime: helper.startTime)]
    }

    private func rememberSudoAgent(_ agent: ProcessIncarnation, for helper: CallerInfo) {
        sudoAgents = sudoAgents.filter { facts.incarnation(of: $0.key.pid) == $0.key }
        guard sudoAgents.count < Self.maximumRememberedSudoNotes else { return }
        sudoAgents[ProcessIncarnation(pid: helper.pid, startTime: helper.startTime)] = agent
    }

    private static let maximumRememberedSudoNotes = 64

    /// Keeps `reason`'s setup notice for `command`, the `csec ai` the request
    /// ran under (for an unwrapped git command, Claude Code's tool shell,
    /// which never asks for it and is pruned once it exits).
    private func rememberSetupNotice(_ reason: DelegationDecline, for command: ProcessIncarnation) {
        guard let notice = reason.setupNotice else { return }
        setupNotices = setupNotices.filter { facts.incarnation(of: $0.key.pid) == $0.key }
        guard setupNotices[command] != nil || setupNotices.count < Self.maximumRememberedSudoNotes else { return }
        setupNotices[command] = notice
    }

    /// The setup notice a request under this `csec ai` left, once: the
    /// `access` reply and the `end_output_redaction` reply each hand over
    /// what is waiting, so the session hears why its approvals go to Touch
    /// ID. A caller with no start time gets none.
    public func takeSetupNotice(for caller: CallerInfo) -> String? {
        guard caller.pid > 1, caller.startTime > 0 else { return nil }
        return setupNotices.removeValue(forKey: ProcessIncarnation(pid: caller.pid, startTime: caller.startTime))
    }

    // MARK: - Changed classifier rules (csec-0.64)

    /// Keeps the unacknowledged G2 sources a request declined on (changed
    /// classifier rules, hooks added since the last acknowledgement) for that
    /// requester. The panel shows each hook's display and what its handlers
    /// run, which is more than `csec setup` lists, so a hook needs no detour
    /// through a terminal (csec-0.64.7).
    private func rememberChangedRules(_ unacknowledged: [ClaudeHookSource], for requester: ProcessIncarnation) {
        guard !unacknowledged.isEmpty else { return }
        changedRules = changedRules.filter { facts.incarnation(of: $0.key.pid) == $0.key }
        guard changedRules[requester] != nil || changedRules.count < Self.maximumRememberedSudoNotes else { return }
        changedRules[requester] = unacknowledged
    }

    /// A request that declined only because Claude Code's auto-mode rules
    /// changed: shows the change once, in one panel listing what was added
    /// and removed, and acknowledges exactly the rules it listed when the
    /// human approves, so `Agent` judges the request again and auto mode
    /// approves it as before. Alex, csec-0.64: "can't we just have a single
    /// approval: rules have changed, here's the diff, do you approve?" —
    /// before, each request went to its own secret panel while the rules
    /// stayed unacknowledged, until someone ran `csec setup auto-mode`.
    ///
    /// Every request that declines on the same change while the panel is up
    /// waits for it. A Deny is kept for this csecd run, so the same rules
    /// are not offered again and their requests get their own panels; the
    /// panel going with its requester leaves a waiting request to show it
    /// again. The paired phone can decide it as well as this Mac (av-rcqg):
    /// while the screen is locked it is offered only when the phone can,
    /// since nobody can see this Mac's panel; otherwise the request's own
    /// panel serves. True when the rules are acknowledged.
    public func acknowledgeChangedRules(for caller: CallerInfo) async -> Bool {
        guard caller.pid > 1, caller.startTime > 0 else { return false }
        let requester = ProcessIncarnation(pid: caller.pid, startTime: caller.startTime)
        guard let hooks = changedRules.removeValue(forKey: requester) else { return false }
        let digests = Set(hooks.map(\.digest))
        var phoneJudged = false
        while true {
            guard let document else { return false }
            if digests.isSubset(of: document.acknowledgedDigests) { return true }
            guard digests.isDisjoint(with: refusedRuleDigests) else { return false }
            if let review = rulesReview {
                let outcome = await review.task.value
                if outcome != .requesterGone, review.digests == digests {
                    return outcome == .acknowledged
                }
                // That panel may have been up for a long while: judge the
                // phone again before offering this one behind a locked screen.
                phoneJudged = false
                continue
            }
            guard facts.incarnation(of: requester.pid) == requester else { return false }
            if screenLocked(), !phoneJudged {
                let change = Self.changedRulesReview(hooks, acknowledged: document.acknowledgedHooks)
                guard await consent.settingsChangeReachesPhone(change, caller: caller) else { return false }
                // Everything above may have changed while it was judged.
                phoneJudged = true
                continue
            }
            rulesReviewCount += 1
            let id = rulesReviewCount
            // The task clears the panel's entry itself before it finishes,
            // so a waiter that resumes never finds the finished one again.
            let task = Task { () -> RulesReviewOutcome in
                let outcome = await self.reviewChangedRules(hooks, caller: caller)
                self.endRulesReview(id)
                return outcome
            }
            rulesReview = (id, digests, task)
            return await task.value == .acknowledged
        }
    }

    private func endRulesReview(_ id: UInt64) {
        if rulesReview?.id == id { rulesReview = nil }
    }

    private func reviewChangedRules(_ hooks: [ClaudeHookSource], caller: CallerInfo) async -> RulesReviewOutcome {
        guard let recorded = document else { return .notAcknowledged }
        let generation = disableGeneration
        let change = Self.changedRulesReview(hooks, acknowledged: recorded.acknowledgedHooks)
        let reason = ([change.title] + change.changes).joined(separator: " — ")
            + " — from \(ReviewDisplay.sanitized(caller.terminalSummary))"
        let panelName = hooks.allSatisfy { $0.kind == .classifierRules } ? "rules-changed" : "hooks-changed"
        let what = "acknowledging \(Self.acknowledgedCount(hooks)) from the \(panelName) panel"
        let decision = await consent.decideSettingsChange(change, caller: caller, reason: reason)
        if case let .refused(refusal) = decision.answer {
            await decisionLog?.record(DecisionLogRecord(
                kind: .settings, outcome: refusal.logOutcome, decider: refusal.logDecider, ttdMs: refusal.ttdMs,
                cause: refusal.logCause, detail: "\(what) was not approved: \(refusal.summary)"
            ).bounded())
            if refusal.isHumanRefusal {
                refusedRuleDigests.formUnion(hooks.map(\.digest))
                return .refused
            }
            return refusal.cause == .requesterGone ? .requesterGone : .notAcknowledged
        }
        // Recording the acknowledgement reads nothing the Mac's touch could
        // unlock.
        if case let .approved(unlock) = decision.answer { unlock?.invalidate() }
        // Exactly the rules the panel listed are added, to the settings as
        // they are now; a disable made while it was up is never undone.
        guard disableGeneration == generation, var current = document else { return .notAcknowledged }
        current.acknowledgedHooks = Self.acknowledging(hooks, in: current.acknowledgedHooks, at: clock())
        if let failure = await writeSettings(current) {
            log("\(what) was approved but not recorded: \(failure)")
            return .notAcknowledged
        }
        await decisionLog?.record(DecisionLogRecord(
            kind: .settings, decider: decision.decidedOn == .phone ? .humanPhone : .humanLocal,
            detail: "acknowledged \(Self.acknowledgedCount(hooks)) from the \(panelName) panel"
        ))
        return .acknowledged
    }

    /// The rules-changed panel: per source, its rules now, then each rule not
    /// in its last acknowledgement and how many of those are gone, as
    /// `csec setup auto-mode` shows them. The rules are csecd's own reading,
    /// the one the acknowledged digest covers. A hook added since the last
    /// acknowledgement (csec-0.64.7) is listed with what each of its handlers
    /// runs, and a warning when it runs code it downloads unpinned; the
    /// panel is then titled for hooks. It is bound to exactly the sources it
    /// acknowledges (`acknowledgementDigest`), so the paired phone may decide
    /// it too.
    public static func changedRulesReview(
        _ hooks: [ClaudeHookSource], acknowledged: [AcknowledgedClaudeHook]
    ) -> SettingsChangeReviewDetails {
        let shownRules = SettingsChangeReviewDetails.maximumChanges - 1
        var lines: [String] = []
        var hidden = 0
        var hiddenHooks = 0
        // Whether the panel lists every source whole. Only then may the
        // paired phone decide it: the phone cannot run `csec setup
        // auto-mode` to see the rest, and its approval would acknowledge
        // what it never showed. What the gate already cut short (a long
        // command, module path, matcher or source name) counts as not shown.
        var complete = hooks.allSatisfy(\.shownWhole)
        let ruleSources = hooks.filter { $0.kind == .classifierRules }
        let hookSources = hooks.filter { $0.kind != .classifierRules }
        for hook in hookSources {
            guard lines.count < shownRules else {
                hiddenHooks += 1
                continue
            }
            let effect = hook.event == configChangeEvent
                ? "can keep Claude Code from reloading its hooks" : "can approve shell commands"
            lines.append("New hook: \(ReviewDisplay.sanitized(hook.display)), which \(effect)")
            if let summaries = hook.handlerSummaries {
                for summary in summaries {
                    guard lines.count < shownRules else {
                        complete = false
                        break
                    }
                    lines.append("Runs \u{201C}\(ReviewDisplay.sanitized(summary))\u{201D}")
                }
            } else {
                // A hooks module's entry file and its digest say which file
                // the acknowledgement trusts, though csec cannot show what it
                // does or what it imports.
                for file in hook.moduleFiles ?? [] {
                    guard lines.count < shownRules else {
                        complete = false
                        break
                    }
                    lines.append("Its module \u{201C}\(ReviewDisplay.sanitized(file))\u{201D}")
                }
                if lines.count < shownRules {
                    lines.append("csec can't show what it runs: acknowledge it only if you have reviewed it where it "
                        + "is defined")
                } else {
                    complete = false
                }
            }
            if hook.fetchesUnpinnedCode {
                if lines.count < shownRules {
                    lines.append("It runs a package it downloads each time, with no version pinned: acknowledging "
                        + "it trusts whatever that download is")
                } else {
                    complete = false
                }
            }
        }
        for source in ruleSources {
            let previous = Set(acknowledged.compactMap(\.classifierRules)
                .first { $0.sourceID == source.sourceID }?.ruleDigests ?? [])
            lines.append(ReviewDisplay.sanitized(source.display) + (previous.isEmpty ? ", none acknowledged before" : ""))
            guard let rules = source.rules else {
                lines.append("csec could not list them here: csec setup auto-mode shows them")
                complete = false
                continue
            }
            let current = Set(rules.map(\.digest))
            for rule in rules where !previous.contains(rule.digest) {
                guard lines.count < shownRules else {
                    hidden += 1
                    continue
                }
                let text = rule.text == ClaudeClassifierRules.defaultsMarker
                    ? "$defaults (keeps Claude Code's built-in \(rule.section) rules)"
                    : "\u{201C}\(ReviewDisplay.sanitized(rule.text))\u{201D}"
                lines.append("Added to \(rule.section): \(text)")
            }
            var removed = previous.subtracting(current)
            for section in ["soft_deny", "hard_deny"] {
                let marker = ClaudeClassifierRules.ruleDigest(section: section, text: ClaudeClassifierRules.defaultsMarker)
                guard removed.contains(marker), lines.count < shownRules else { continue }
                lines.append("\(section) no longer keeps Claude Code's built-in \(section) rules")
                removed.remove(marker)
            }
            if !removed.isEmpty {
                if lines.count < shownRules {
                    lines.append("\(removed.count) rule\(removed.count == 1 ? "" : "s") you acknowledged "
                        + "\(removed.count == 1 ? "is" : "are") gone")
                } else {
                    complete = false
                }
            }
            if current.isSubset(of: previous), previous.isSubset(of: current) {
                if lines.count < shownRules {
                    lines.append("No rule was added or removed: their order changed, or a list is now empty, "
                        + "which removes that list's built-in rules")
                } else {
                    complete = false
                }
            }
        }
        var more: [String] = []
        if hiddenHooks > 0 { more.append("\(hiddenHooks) more hook\(hiddenHooks == 1 ? "" : "s")") }
        if hidden > 0 { more.append("\(hidden) more added rule\(hidden == 1 ? "" : "s")") }
        if !more.isEmpty {
            lines.append("and " + more.joined(separator: " and ") + ": csec setup auto-mode lists them all")
            complete = false
        }
        let title: String
        let footnote: String
        if hookSources.isEmpty {
            title = "Claude Code's Auto-Mode Rules Changed"
            footnote = changedRulesFootnote
        } else {
            title = ruleSources.isEmpty ? "New Claude Code Hook" + (hookSources.count == 1 ? "" : "s")
                : "Claude Code's Hooks and Auto-Mode Rules Changed"
            footnote = changedHooksFootnote
        }
        return SettingsChangeReviewDetails(
            title: title, changes: lines, footnote: footnote,
            phoneOperationDigest: complete ? acknowledgementDigest(hooks) : nil
        )
    }

    /// SHA-256 over exactly the sources a rules- or hooks-changed approval
    /// acknowledges: each one's digest, which covers its content (a hooks
    /// module's file digest, a source's rules), sorted and length-prefixed
    /// under a domain of its own. A phone approval is signed over it, so it
    /// approves those sources and nothing else, and a source that changes
    /// needs a new approval.
    public static func acknowledgementDigest(_ hooks: [ClaudeHookSource]) -> Data {
        acknowledgementDigest(digests: Set(hooks.map(\.digest)))
    }

    /// The same, from the sources' digests: what an acknowledgement records.
    public static func acknowledgementDigest(digests: Set<String>) -> Data {
        var bytes = Data("csec.claude-delegation.acknowledge-sources.v1".utf8)
        for digest in digests.sorted() {
            let utf8 = Data(digest.utf8)
            withUnsafeBytes(of: UInt32(utf8.count).bigEndian) { bytes.append(contentsOf: $0) }
            bytes.append(utf8)
        }
        return Data(SHA256.hash(data: bytes))
    }

    public static let changedRulesFootnote = "An allow or environment rule can tell the classifier to approve a command. "
        + "Approving acknowledges exactly these rules, and auto mode approves secret use again. Deny sends each "
        + "request to its own approval instead. No secret is released by this approval."

    public static let changedHooksFootnote = "A hook can approve a shell command without the classifier, so "
        + "acknowledging one trusts its code. Approving acknowledges exactly what is listed, and auto mode approves "
        + "secret use again. Deny sends each request to its own approval instead. No secret is released by this "
        + "approval."

    /// The pairing line a declined sudo's panel shows when approving it would
    /// let auto mode run sudo in the session's project, which no pairing
    /// there does yet. The offer is kept for exactly this helper, so only an
    /// approval of the panel that showed the line can record it. A `reason`
    /// pairing cannot end still pairs, and the line says when that counts.
    private func sudoPairingOffer(
        for session: DelegationSession?, reason: DelegationDecline, helper: CallerInfo
    ) -> String? {
        guard state == .on, let session, let project = session.project, project.isWellFormed,
              !Self.pairings(pairings, for: project, directory: nil).contains(where: \.sudo) else { return nil }
        sudoOffers = sudoOffers.filter { facts.incarnation(of: $0.key.pid) == $0.key }
        guard sudoOffers.count < Self.maximumRememberedSudoNotes else { return nil }
        let offer = SudoPairingOffer(projectName: project.displayName, condition: reason.pairingCondition)
        sudoOffers[ProcessIncarnation(pid: helper.pid, startTime: helper.startTime)] = PendingSudoOffer(
            session: session, line: offer.line
        )
        return offer.line
    }

    /// A human approved the sudo panel `helper` showed with its pairing line,
    /// on `surface`: auto mode may run sudo in that session's project from
    /// now on. Only the helper csecd offered it to, still alive under the
    /// root sudo it serves, can have it recorded; the offer is spent either
    /// way.
    public func recordSudoApproval(helper: CallerInfo, surface: HumanDecisionSurface) async -> Bool {
        await load()
        let process = ProcessIncarnation(pid: helper.pid, startTime: helper.startTime)
        guard let offer = sudoOffers.removeValue(forKey: process),
              let record = facts.kernelRecord(of: helper.pid), record.process == process,
              let sudo = facts.kernelRecord(of: record.parent),
              sudo.executablePath == SudoChainRule.sudoPath, sudo.effectiveUID == 0,
              sudo.realUID == account.userID else { return false }
        await addPairing(session: offer.session, references: [], sudo: true, surface: surface)
        return true
    }

    private struct SudoWalk: Sendable {
        let sudo: ProcessIncarnation
        /// sudo's parent first, then its ancestors up to P.
        let chain: [ProcessIncarnation]
        /// The `csec ai`'s index in `chain`; the Bash tool shell and P follow.
        let commandIndex: Int
        let commandPath: String?
        let commandProgram: String?
        /// The `csec ai` is the signed csec launcher, so a registration may be
        /// bound to it here when none is already.
        let mayBindLazily: Bool
        let commandStart: UInt64?
        /// Every process from sudo's parent up to just below the `csec ai`.
        let parents: [SudoChainLink]
        let environment: SSHChainAnchorEnvironment
        /// The `csec ai` is Claude Code's shell prefix, its own tool shell
        /// directly under P (`ClaudeSessionFacts.shellPrefixChain`).
        let shellPrefix: Bool

        var shellIndex: Int { shellPrefix ? commandIndex : commandIndex + 1 }
    }

    /// helper → sudo → … → `csec ai` → Bash tool shell → P, with the helper's
    /// and sudo's records read again once the rest is walked, so the sudo
    /// judged is the one still waiting on this helper, under the same parent.
    private static func sudoWalk(
        helper: ProcessIncarnation, userID: uid_t, provider: any ClaudeSessionFactProvider,
        launcherCheck: DelegationLauncherCheck, processClock: DelegationProcessClock
    ) -> SudoWalk? {
        guard let helperRecord = provider.kernelRecord(of: helper.pid), helperRecord.process == helper,
              let sudo = provider.kernelRecord(of: helperRecord.parent),
              sudo.executablePath == SudoChainRule.sudoPath, sudo.isValidPlatformBinary,
              sudo.effectiveUID == 0, sudo.realUID == userID,
              let parent = provider.incarnation(of: sudo.parent),
              let chain = ancestry(of: parent, maximumHops: maximumSSHAncestorHops, provider: provider),
              chain.count >= 3 else { return nil }
        var paths: [String?] = []
        var argvs: [[String]?] = []
        for index in 0..<(chain.count - 1) {
            let path = provider.executablePath(of: chain[index])
            let argv = provider.argv(of: chain[index])
            // As for SSH, csec as Claude Code's shell prefix is directly
            // under P and binds the command inside its framing's `eval`.
            let shellPrefix = argv.map {
                $0.count >= 2 && $0[1] == "ai" && AICommandExec.isShellPrefix(arguments: Array($0.dropFirst(2)))
            } ?? false
            let program: String?
            if shellPrefix, let argv {
                program = AICommandExec.registeredProgram(fromProcessArguments: argv)
            } else if index < chain.count - 2, let argv, let running = AICommandExec.program(fromProcessArguments: argv),
                      let shellPath = provider.executablePath(of: chain[index + 1]),
                      toolShellNames.contains((shellPath as NSString).lastPathComponent) {
                program = running
            } else {
                paths.append(path)
                argvs.append(argv)
                continue
            }
            guard let helperAfter = provider.kernelRecord(of: helper.pid),
                  helperAfter.process == helper, helperAfter.parent == sudo.process.pid,
                  let sudoAfter = provider.kernelRecord(of: sudo.process.pid),
                  sudoAfter.process == sudo.process, sudoAfter.parent == parent.pid else { return nil }
            return SudoWalk(
                sudo: sudo.process,
                chain: chain,
                commandIndex: index,
                commandPath: path,
                commandProgram: program,
                mayBindLazily: launcherCheck.isVerifiedLauncher(chain[index]),
                commandStart: processClock.start(chain[index]),
                parents: (0..<index).map { SudoChainLink(process: chain[$0], path: paths[$0], argv: argvs[$0]) },
                environment: SSHChainAnchorEnvironment.read(from: chain[index], provider: provider),
                shellPrefix: shellPrefix
            )
        }
        return nil
    }

    /// The pairing that lets auto mode run sudo in this project, by its id:
    /// a human approved a sudo panel there that said so (csec-2rno.1: once
    /// per project).
    private func sudoApproval(matching: [ProjectPairing]) -> String? {
        matching.first(where: \.sudo)?.id
    }

    /// `start` and its ancestors up to `maximumHops`, stopping below
    /// launchd or below the first ancestor csecd cannot read, with every link
    /// and incarnation re-read afterwards (the race rule of
    /// `ClaudeSessionFacts.verifiedAncestry`). An unreadable ancestor is
    /// usually another user's process: root's `login` sits above every
    /// iTerm2 and Terminal.app shell. The chain is only ever a verified
    /// prefix, and the SSH walk needs `ssh` up to Claude Code in it, so one
    /// that stops below Claude Code finds no `csec ai` and delegates nothing.
    static func ancestry(
        of start: ProcessIncarnation, maximumHops: Int, provider: any ClaudeSessionFactProvider
    ) -> [ProcessIncarnation]? {
        guard start.pid > 1, provider.incarnation(of: start.pid) == start else { return nil }
        var chain = [start]
        while chain.count <= maximumHops {
            guard let parentPID = provider.parent(of: chain[chain.count - 1].pid) else { return nil }
            if parentPID <= 1 { break }
            guard !chain.contains(where: { $0.pid == parentPID }) else { return nil }
            guard let parent = provider.incarnation(of: parentPID) else { break }
            chain.append(parent)
        }
        for (child, parent) in zip(chain, chain.dropFirst()) where provider.parent(of: child.pid) != parent.pid {
            return nil
        }
        for member in chain where provider.incarnation(of: member.pid) != member {
            return nil
        }
        return chain
    }

    // MARK: - P's facts

    private struct SessionInputs: Sendable {
        let agent: ProcessIncarnation
        let shell: ProcessIncarnation
        let trusted: Set<String>
        let trustGeneration: UInt64
        let hookCWD: String?
        /// False when only identity and the project are needed (no
        /// registration, or the chain already failed).
        let evaluateGates: Bool
        let csecExecutablePath: String
        let account: DelegationAccount
        /// The hooks the human acknowledged, so the launch-only check runs
        /// only when an unacknowledged one would decline.
        let acknowledgedDigests: Set<String>
    }

    private enum ProjectResolution: Sendable {
        case key(ProjectKey)
        case notLocal
        case unavailable
    }

    private enum SettingsResolution: Sendable {
        case evaluated(ClaudeSettingsGateEvaluation)
        case failed(DelegationDecline)
        case notEvaluated
    }

    private struct SessionFacts: Sendable {
        let identity: ForeignCodeIdentity?
        let namedClaude: Bool
        let buildLabel: String
        let checkedVersion: String?
        let interactivity: ClaudeInteractivity
        let argv: [String]?
        let presence: EnvironmentNamePresence?
        let values: [String: String]?
        /// P's working directory, which the gates and the settings scope
        /// read.
        let project: ProjectResolution
        /// What P's pairing is keyed on: the repository `project` is in, or
        /// `project` itself.
        let pairing: ProjectKey?
        let settings: SettingsResolution
        let account: DelegationAccount
        let isOnLocalMounts: @Sendable (String) -> Bool
        /// Unacknowledged hooks only P's launch options bring in
        /// (`launchOnlyHooks`).
        var launchOnly: LaunchOnlyHooks?

        var projectKey: ProjectKey? { pairing }

        /// P's working directory's own key, which a pairing made before
        /// pairings were keyed on the repository was recorded under.
        var directoryKey: ProjectKey? {
            if case let .key(key) = project { return key }
            return nil
        }

        /// The first gate P's facts fail, in the order a panel names:
        /// identity, G3, G4, G5 (with P's HOME and CLAUDE_CONFIG_DIR), the
        /// project, then G1/G2/G6 from the settings gate, which leaves
        /// classifier rules out for an SSH signing (`ignoringClassifierRules`).
        func failure(acknowledgedDigests: Set<String>, ignoringClassifierRules: Bool = false) -> DelegationDecline? {
            guard identity?.isClaudeCode == true else { return .unverifiedBuild(buildLabel) }
            guard checkedVersion != nil else { return .uncheckedBuild(buildLabel) }
            guard interactivity.isInteractive else { return .notInteractive }
            if let failure = launchFailure { return failure }
            if let failure = environmentFailure { return failure }
            switch project {
            case .unavailable: return .projectUnavailable
            case .notLocal: return .projectNotLocal
            case .key: break
            }
            switch settings {
            case let .failed(reason):
                return reason
            case .notEvaluated:
                return .settingsUnreadable(account.homeDirectory)
            case let .evaluated(evaluation):
                return evaluation.firstFailure(
                    acknowledgedDigests: acknowledgedDigests, ignoringClassifierRules: ignoringClassifierRules
                ).map { Self.decline($0, launchOnly: launchOnly) }
            }
        }

        /// G4 on P's argv.
        var launchFailure: DelegationDecline? {
            guard let argv else { return .environmentUnreadable }
            return ClaudeDelegationGateLists.launchOption(inArgv: argv).map(DelegationDecline.launchOption)
        }

        /// G5 on P's exec-time environment, and the paths that root what
        /// Claude Code reads: HOME must be the account's, CLAUDE_CONFIG_DIR
        /// absolute and local, CLAUDE_SECURESTORAGE_CONFIG_DIR unset or empty.
        var environmentFailure: DelegationDecline? {
            guard let presence, let values else { return .environmentUnreadable }
            for name in ClaudeDelegationGateLists.environmentNames where (presence.names[name] ?? 0) > 0 {
                // csec's own shell prefix, set exactly once, stays.
                if name == ClaudeDelegationGateLists.shellPrefixName, presence.names[name] == 1,
                   ClaudeCodeShellPrefix.isCsecPrefix(values[name], accepted: ClaudeCodeShellPrefix.installedPrefixPath) {
                    continue
                }
                return .injectedEnvironment(name)
            }
            for prefix in ClaudeDelegationGateLists.environmentPrefixes where (presence.prefixes[prefix] ?? 0) > 0 {
                return .injectedEnvironment(prefix + "*")
            }
            if let options = values[ClaudeDelegationGateLists.nodeOptionsName],
               let flag = ClaudeDelegationGateLists.nodeOptionsCodeLoadingFlag(in: options) {
                return .injectedEnvironment("\(ClaudeDelegationGateLists.nodeOptionsName) \(flag)")
            }
            if let directory = values[ClaudeDelegationGateLists.secureStorageDirectoryName], !directory.isEmpty {
                return .injectedEnvironment(ClaudeDelegationGateLists.secureStorageDirectoryName)
            }
            guard ClaudeDelegationGateLists.processHomeMatches(
                values[ClaudeDelegationGateLists.homeName], accountHome: account.homeDirectory
            ) else { return .homeMismatch }
            switch ClaudeSettingsScope.ConfigDirectory(environmentValue: values["CLAUDE_CONFIG_DIR"]) {
            case .unusable:
                return .configDirectoryUnusable
            case let .directory(directory) where !isOnLocalMounts(directory):
                return .configDirectoryUnusable
            case .unset, .directory:
                return nil
            }
        }

        static func decline(_ failure: ClaudeSettingsGateFailure, launchOnly: LaunchOnlyHooks? = nil) -> DelegationDecline {
            switch failure {
            case let .unreadable(setting): return .settingsUnreadable(shown(setting.path))
            case let .injectedEnvironment(finding):
                return .settingsEnvironment(name: finding.name, path: shown(finding.path))
            case .classifyAllShellNotSet: return .allowRulesActive
            case let .unacknowledgedHook(hook):
                let blocksReload = hook.event == ClaudeDelegationService.configChangeEvent
                // csec setup never sees P's argv, so it cannot offer this hook
                // (or these rules) for acknowledgment: name the launch, not a
                // review.
                let inline = hook.sourceID == ClaudeSettingsScope.launchSettingsPath
                if hook.kind == .classifierRules {
                    return inline ? .launchOption("--settings that add auto-mode classifier rules")
                        : .classifierRules(hook.display)
                }
                if hook.kind == .settings, inline {
                    return .launchOption(blocksReload
                        ? "--settings that add a ConfigChange hook" : "--settings that add a shell-command hook")
                }
                return .otherHook(
                    hook.display, blocksReload: blocksReload,
                    launch: launchOnly.flatMap { $0.digests.contains(hook.digest) ? $0.option : nil }
                )
            case let .sandboxEnabled(path): return .sandboxAutoAllow(shown(path))
            case let .bypassPermissionsDefault(path): return .bypassReachable(shown(path))
            case let .hooksDisabled(finding):
                return .hooksDisabled(setting: finding.setting.rawValue, path: shown(finding.path))
            }
        }

        /// A finding's path as a decline names it: P's `--settings` layer by
        /// what it is, a file by its path.
        static func shown(_ path: String) -> String {
            path == ClaudeSettingsScope.launchSettingsPath ? ClaudeSettingsScope.launchSettingsDisplay : path
        }
    }

    private func collectSession(
        _ inputs: SessionInputs, on queue: DelegationFactQueue, within bound: Duration
    ) async -> SessionFacts? {
        let provider = facts
        let gate = gate
        let compiledBuilds = compiledBuilds
        let manifestStore = manifestStore
        let volumeUUID = volumeUUID
        let isOnLocalMounts = isOnLocalMounts
        let repositories = repositories
        let cache = identityCache
        return await queue.run(within: bound) {
            Self.sessionFacts(
                inputs, provider: provider, gate: gate,
                buildVerification: Self.buildVerification(compiled: compiledBuilds, store: manifestStore), cache: cache,
                volumeUUID: volumeUUID, isOnLocalMounts: isOnLocalMounts, repositories: repositories
            )
        }
    }

    private static func sessionFacts(
        _ inputs: SessionInputs,
        provider: any ClaudeSessionFactProvider,
        gate: any ClaudeSettingsGate,
        buildVerification: ClaudeBuildVerification,
        cache: DelegationIdentityCache,
        volumeUUID: @Sendable (String) -> String?,
        isOnLocalMounts: @escaping @Sendable (String) -> Bool,
        repositories: ProjectRepository.FileSystem
    ) -> SessionFacts {
        let agent = inputs.agent
        let identity = cachedIdentity(
            of: agent, parentOf: inputs.shell.pid, trusted: inputs.trusted,
            generation: inputs.trustGeneration, provider: provider, cache: cache
        )
        let path = provider.executablePath(of: agent)
        let namedClaude = CodingAgentIdentity.client(name: nil, executablePath: path) == .claude
        let label = buildLabel(identity: identity, executablePath: path)
        let checkedVersion = buildVerification.checkedVersion(cdHash: identity?.cdHash)
        let project = projectResolution(
            provider.cwd(of: agent), volumeUUID: volumeUUID
        )
        let pairing = pairingKey(
            project, homeDirectory: inputs.account.homeDirectory, repositories: repositories, volumeUUID: volumeUUID
        )
        guard inputs.evaluateGates else {
            return SessionFacts(
                identity: identity, namedClaude: namedClaude, buildLabel: label, checkedVersion: checkedVersion,
                interactivity: .notInteractive(.factsUnavailable), argv: nil, presence: nil, values: nil,
                project: project, pairing: pairing, settings: .notEvaluated, account: inputs.account,
                isOnLocalMounts: isOnLocalMounts
            )
        }
        let interactivity = provider.interactivity(of: agent)
        let argv = provider.argv(of: agent)
        let presence = provider.envPresence(
            of: agent,
            names: ClaudeDelegationGateLists.environmentNames,
            prefixes: ClaudeDelegationGateLists.environmentPrefixes
        )
        let values = provider.envValues(
            of: agent,
            allowlistedKeys: [
                "CLAUDE_CONFIG_DIR", ClaudeDelegationGateLists.homeName, ClaudeDelegationGateLists.nodeOptionsName,
                ClaudeDelegationGateLists.secureStorageDirectoryName, ClaudeDelegationGateLists.shellPrefixName,
            ]
        )
        var facts = SessionFacts(
            identity: identity, namedClaude: namedClaude, buildLabel: label, checkedVersion: checkedVersion,
            interactivity: interactivity, argv: argv, presence: presence, values: values,
            project: project, pairing: pairing, settings: .notEvaluated, account: inputs.account,
            isOnLocalMounts: isOnLocalMounts
        )
        // The settings are read only when every earlier gate holds, so a
        // session that already fails never costs a settings scan, and no
        // file is read under a directory that is not on a local disk.
        guard identity?.isClaudeCode == true, checkedVersion != nil, interactivity.isInteractive,
              facts.launchFailure == nil, facts.environmentFailure == nil,
              case let .key(key) = project else { return facts }
        let settings: SettingsResolution
        var launchOnly: LaunchOnlyHooks?
        switch settingsScope(
            inputs: inputs, project: key, argv: argv ?? [], values: values ?? [:], isOnLocalMounts: isOnLocalMounts
        ) {
        case let .failure(failure):
            settings = .failed(failure.reason)
        case let .success(scope):
            let evaluation = gate.evaluate(scope)
            settings = .evaluated(evaluation)
            launchOnly = launchOnlyHooks(
                evaluation, scope: scope, acknowledgedDigests: inputs.acknowledgedDigests, gate: gate
            )
        }
        facts = SessionFacts(
            identity: identity, namedClaude: namedClaude, buildLabel: label, checkedVersion: checkedVersion,
            interactivity: interactivity, argv: argv, presence: presence, values: values,
            project: project, pairing: pairing, settings: settings, account: inputs.account,
            isOnLocalMounts: isOnLocalMounts, launchOnly: launchOnly
        )
        return facts
    }

    /// Unacknowledged hooks that only P's own launch options bring in, and
    /// the option to name: those `csec setup` cannot show, since it never
    /// sees P's argv. A hook in P's inline `--settings` itself already
    /// declines as that launch option; this finds the ones it reaches
    /// indirectly (a plugin it enables, a directory its
    /// `permissions.additionalDirectories` adds) and an `--add-dir`
    /// directory's. The second evaluation, without those options, runs only
    /// when such a hook would decline.
    struct LaunchOnlyHooks: Sendable, Equatable {
        let option: String
        let digests: Set<String>
    }

    private static func launchOnlyHooks(
        _ evaluation: ClaudeSettingsGateEvaluation,
        scope: ClaudeSettingsScope,
        acknowledgedDigests: Set<String>,
        gate: any ClaudeSettingsGate
    ) -> LaunchOnlyHooks? {
        let option: String
        switch (!scope.launchSettings.isEmpty, !scope.additionalDirectories.isEmpty) {
        case (true, false): option = ClaudeDelegationGateLists.settingsOption
        case (false, true): option = "--add-dir"
        case (true, true): option = ClaudeDelegationGateLists.settingsOption + " or --add-dir"
        case (false, false): return nil
        }
        let candidates = evaluation.unacknowledgedHooks(acknowledgedDigests: acknowledgedDigests).filter {
            $0.kind != .classifierRules && $0.sourceID != ClaudeSettingsScope.launchSettingsPath
        }
        guard !candidates.isEmpty else { return nil }
        var unlaunched = scope
        unlaunched.launchSettings = []
        unlaunched.additionalDirectories = []
        let seenWithout = Set(gate.evaluate(unlaunched).hooks.map(\.digest))
        let digests = Set(candidates.map(\.digest)).subtracting(seenWithout)
        return digests.isEmpty ? nil : LaunchOnlyHooks(option: option, digests: digests)
    }

    private struct ScopeFailure: Error {
        let reason: DelegationDecline
    }

    /// The settings scope for P: the account's home (P's HOME matched it),
    /// P's CLAUDE_CONFIG_DIR, P's project and the hook's working directory,
    /// and P's `--add-dir` directories. Every directory must be on a local
    /// disk; the hook's and the added ones can only add files to read, so
    /// one that is not declines.
    private static func settingsScope(
        inputs: SessionInputs,
        project: ProjectKey,
        argv: [String],
        values: [String: String],
        isOnLocalMounts: @Sendable (String) -> Bool
    ) -> Result<ClaudeSettingsScope, ScopeFailure> {
        guard isOnLocalMounts(inputs.account.homeDirectory) else {
            return .failure(ScopeFailure(reason: .settingsUnreadable(inputs.account.homeDirectory)))
        }
        var configDirectory: String?
        if case let .directory(directory) = ClaudeSettingsScope.ConfigDirectory(environmentValue: values["CLAUDE_CONFIG_DIR"]) {
            configDirectory = directory
        }
        var workingDirectories = [project.path]
        if let hookCWD = inputs.hookCWD, hookCWD != project.path {
            guard WireField.isAbsolutePath(hookCWD), isOnLocalMounts(hookCWD) else {
                return .failure(ScopeFailure(reason: .projectNotLocal))
            }
            workingDirectories.append(ClaudeSettingsScope.normalizedPath(hookCWD))
        }
        var additional: [String] = []
        for directory in addedDirectories(inArgv: argv) {
            let absolute = directory.hasPrefix("/")
                ? ClaudeSettingsScope.normalizedPath(directory)
                : ClaudeSettingsScope.normalizedPath(project.path + "/" + directory)
            guard WireField.isAbsolutePath(absolute), isOnLocalMounts(absolute) else {
                return .failure(ScopeFailure(reason: .projectNotLocal))
            }
            additional.append(absolute)
        }
        let scope = ClaudeSettingsScope(
            homeDirectory: inputs.account.homeDirectory,
            claudeConfigDirectory: configDirectory,
            workingDirectories: workingDirectories,
            additionalDirectories: additional,
            userName: inputs.account.userName,
            csecExecutablePath: inputs.csecExecutablePath,
            launchSettings: ClaudeDelegationGateLists.launchSettings(inArgv: argv)
        )
        guard scope.isWellFormed else {
            return .failure(ScopeFailure(reason: .settingsUnreadable(inputs.account.homeDirectory)))
        }
        return .success(scope)
    }

    /// P's `--add-dir` values. Claude Code declares it variadic, so every
    /// token after it up to the next option is a directory; `--add-dir=x`
    /// names one. Values are untrusted metadata and never logged.
    public static func addedDirectories(inArgv argv: [String]) -> [String] {
        var directories: [String] = []
        var index = 1
        while index < argv.count {
            let token = ArgvToken(argv[index])
            index += 1
            if token.name == "--add-dir", let value = token.inlineValue {
                directories.append(value)
            } else if token.text == "--add-dir" {
                while index < argv.count, !ArgvToken(argv[index]).hasPrefix("-") {
                    directories.append(argv[index])
                    index += 1
                }
            }
        }
        return directories.filter { !$0.isEmpty }
    }

    private static func projectResolution(
        _ cwd: ProcessWorkingDirectory?, volumeUUID: @Sendable (String) -> String?
    ) -> ProjectResolution {
        guard let cwd else { return .unavailable }
        // A cwd deeper than MAXPATHLEN comes back from the kernel as a tail
        // fragment that looks absolute; only on local mounts has the path been
        // checked to still name the directory. Pair nothing else.
        guard cwd.isOnLocalMounts else { return .notLocal }
        guard let uuid = volumeUUID(cwd.mount.mountPoint) else { return .unavailable }
        let key = ProjectKey(path: cwd.directory.path, volumeUUID: uuid, inode: cwd.directory.inode)
        return key.isWellFormed ? .key(key) : .unavailable
    }

    /// The key a pairing for a session in `project` is kept under: the git
    /// repository the directory is in, so one approval covers the main
    /// checkout, every worktree and any subdirectory, or the directory itself
    /// when it is in none. Nil when the directory has no key.
    private static func pairingKey(
        _ project: ProjectResolution, homeDirectory: String,
        repositories: ProjectRepository.FileSystem, volumeUUID: @Sendable (String) -> String?
    ) -> ProjectKey? {
        guard case let .key(directory) = project else { return nil }
        return repositoryKey(
            of: directory.path, homeDirectory: homeDirectory, repositories: repositories, volumeUUID: volumeUUID
        ) ?? directory
    }

    /// The key of the git repository `directory` is in, or nil when it is in
    /// none (`ProjectRepository.commonDirectory`).
    static func repositoryKey(
        of directory: String, homeDirectory: String,
        repositories: ProjectRepository.FileSystem, volumeUUID: @Sendable (String) -> String?
    ) -> ProjectKey? {
        guard let common = ProjectRepository.commonDirectory(
            of: directory, homeDirectory: homeDirectory, fileSystem: repositories
        ), let uuid = volumeUUID(common.mountPoint) else { return nil }
        let key = ProjectKey(path: common.path, volumeUUID: uuid, inode: common.inode)
        return key.isWellFormed ? key : nil
    }

    private static func cachedIdentity(
        of agent: ProcessIncarnation,
        parentOf child: pid_t?,
        trusted: Set<String>,
        generation: UInt64,
        provider: any ClaudeSessionFactProvider,
        cache: DelegationIdentityCache
    ) -> ForeignCodeIdentity? {
        guard let pidVersion = provider.pidVersion(of: agent) else {
            // No exec-exact key: resolve every time.
            return provider.codeIdentity(of: agent, parentOf: child, trustedCDHashes: trusted)
        }
        let key = DelegationIdentityCache.Key(process: agent, pidVersion: pidVersion, trustGeneration: generation)
        if let cached = cache.identity(for: key) {
            // The walk's link is re-read even for a cached image.
            if let child, provider.parent(of: child) != agent.pid { return nil }
            return cached
        }
        guard let identity = provider.codeIdentity(of: agent, parentOf: child, trustedCDHashes: trusted),
              provider.pidVersion(of: agent) == pidVersion else { return nil }
        cache.store(identity, for: key)
        return identity
    }

    /// What the panel calls this build: the native installer's version
    /// directory name, or the executable's name.
    private static func buildLabel(identity: ForeignCodeIdentity?, executablePath: String?) -> String {
        let path = identity?.executablePath ?? executablePath ?? ""
        return ReviewDisplay.bounded(
            ReviewDisplay.sanitized(ClaudeBuildVerification.versionLabel(executablePath: path)),
            maxBytes: ClaudeBuildSummary.maximumVersionLabelBytes
        )
    }

    // MARK: - Pairing

    /// The panel's pairing line: offered only with delegation on, for a
    /// declined request whose Claude Code session has a local project, when
    /// the window's default scope is that Claude Code process and a
    /// process-lifetime grant is on offer, and approving would pair a
    /// reference the project does not already have. The line shows while
    /// exactly that selection is made. An SSH panel never offers one: an SSH
    /// signing auto mode approved signs whatever its destination (csec-0.11),
    /// so there is nothing to pair. For a `daemonUse` panel the line pairs
    /// only csecd's use of the references, never their release, and that use
    /// holds in every project (`judge`), so its line says so. A `decline`
    /// pairing cannot end (`DelegationDecline.pairingCondition`) still
    /// offers it, and the line says when it starts to count.
    public func pairingOffer(
        for session: DelegationSession,
        decline: DelegationDecline? = nil,
        references: [SecretRef],
        daemonUse: Bool = false,
        scopeChoices: GrantScopeChoices?,
        durationChoices: GrantDurationChoices?
    ) async -> DelegationPairingOffer? {
        await load()
        guard state == .on, let project = session.project,
              let scope = scopeChoices?.defaultOption, scope.kind == .codingAgent,
              scope.pid == session.agent.pid, scope.startTime == session.agent.startTime,
              durationChoices?.options.contains(.processLifetime) == true else { return nil }
        let existing = pairings.first { $0.project == project }
        guard !references.allSatisfy({ reference in
            existing?.covers(reference.uri, daemonUse: daemonUse) == true
                || (daemonUse && pairings.contains { $0.usedReferences.contains(reference.uri) })
        }) else { return nil }
        return DelegationPairingOffer(
            projectName: project.displayName, scopeOptionID: scope.id, everyProject: daemonUse,
            condition: decline?.pairingCondition
        )
    }

    /// A human approved the panel of a declined Claude Code request, on a
    /// surface that showed the pairing line, with exactly the default Claude
    /// Code scope for its process lifetime: its new references are paired
    /// with the session's project. The caller checks the approval; this checks
    /// delegation is still on.
    /// With `daemonUse` the references are paired for csecd's use only.
    public func recordHumanApproval(
        session: DelegationSession, references: [SecretRef], daemonUse: Bool = false, surface: HumanDecisionSurface
    ) async {
        await load()
        await addPairing(session: session, references: references.map(\.uri), daemonUse: daemonUse, surface: surface)
    }

    /// Pairs `references` (for csecd's use only with `daemonUse`), and with
    /// `sudo` lets auto mode run sudo, in the session's project. Nothing adds
    /// SSH uses or launcher pins any more (csec-0.11); a pairing loaded with
    /// them keeps them until revoked.
    private func addPairing(
        session: DelegationSession, references: [String], daemonUse: Bool = false, sudo: Bool = false,
        surface: HumanDecisionSurface
    ) async {
        guard state == .on, let project = session.project, project.isWellFormed else { return }
        // A one-time code is never paired: auto mode never releases one.
        let valid = references.filter { reference in
            guard WireField.isReference(reference), let ref = try? SecretRef(reference) else { return false }
            return ref.uri == reference && !ref.isOneTimeCode
        }
        guard !valid.isEmpty || sudo else { return }
        let index: Int
        if let existing = pairings.firstIndex(where: { $0.project == project }) {
            index = existing
        } else {
            pairings.append(ProjectPairing(project: project, references: [], ssh: []))
            index = pairings.count - 1
        }
        var addedReferences: [String] = []
        for reference in valid where !pairings[index].covers(reference, daemonUse: daemonUse) {
            if daemonUse {
                pairings[index].usedReferences.append(reference)
            } else {
                // A release covers use, so the narrower entry goes.
                pairings[index].usedReferences.removeAll { $0 == reference }
                pairings[index].references.append(reference)
            }
            addedReferences.append(reference)
        }
        let addedSudo = sudo && !pairings[index].sudo
        if addedSudo { pairings[index].sudo = true }
        let pairingID = pairings[index].id
        recencyClock += 1
        pairingRecency[pairingID] = recencyClock
        // Approving what the project already has (a panel raised because a
        // paired value was not held, or because the session was not in auto
        // mode) adds nothing: the item is rewritten, and a pairing logged,
        // only when a pairing is added or removed. The use still counts for
        // recency, in memory.
        guard !addedReferences.isEmpty || addedSudo else { return }
        let trimmedReleases = max(0, pairings[index].references.count - DelegationPolicy.maximumPairedReferences)
        pairings[index].references.removeFirst(trimmedReleases)
        let trimmedUses = max(0, pairings[index].usedReferences.count - DelegationPolicy.maximumPairedReferences)
        pairings[index].usedReferences.removeFirst(trimmedUses)
        let trimmed = trimmedReleases + trimmedUses
        var evicted: [String] = []
        while pairings.count > DelegationPolicy.maximumPairedProjects,
              let victim = leastRecentPairing(except: pairingID) {
            evicted.append(victim.project.displayDescription)
            removePairing(id: victim.id)
        }
        let write = await persistPairings(keeping: pairingID)
        evicted += write.evicted
        await decisionLog?.record(DecisionLogRecord(
            kind: .settings,
            refs: addedReferences.sorted(),
            decider: DecisionLogRecord.decider(for: surface),
            detail: "paired \(addedReferences.count) reference\(addedReferences.count == 1 ? "" : "s")"
                + (daemonUse && !addedReferences.isEmpty ? " (used inside csec, never released)" : "")
                + (addedSudo ? " and sudo" : "")
                + " with \(project.displayDescription) for Claude Code auto mode"
                + (trimmed > 0 ? "; the oldest \(trimmed) left out" : "")
                + (write.written ? ""
                    : write.held.map { "; the saved pairings are kept as found because this csecd cannot read them ("
                        + "\($0)), so this pairing holds for this run only" }
                    ?? "; the pairing item could not be written, so it holds for this run only")
        ))
        let shedCount = write.shedReferences.count + write.shedSSHUses + write.shedLaunchers
        if shedCount > 0 {
            var parts: [String] = []
            if write.shedSSHUses > 0 { parts.append("\(write.shedSSHUses) SSH use\(write.shedSSHUses == 1 ? "" : "s")") }
            if write.shedLaunchers > 0 { parts.append("\(write.shedLaunchers) script\(write.shedLaunchers == 1 ? "" : "s")") }
            await decisionLog?.record(DecisionLogRecord(
                kind: .settings,
                refs: write.shedReferences.sorted(),
                detail: "the oldest \(shedCount) entr\(shedCount == 1 ? "y" : "ies") paired with \(project.displayDescription) "
                    + (parts.isEmpty ? "" : "(\(parts.joined(separator: ", "))) ")
                    + "\(shedCount == 1 ? "was" : "were") removed to stay within the pairing item's size"
            ))
        }
        for path in evicted {
            await decisionLog?.record(DecisionLogRecord(
                kind: .settings,
                detail: "the least recently used pairing (\(path)) was removed to stay within the pairing item's bounds"
            ))
        }
    }

    private func leastRecentPairing(except id: String) -> ProjectPairing? {
        pairings.filter { $0.id != id }.min { (pairingRecency[$0.id] ?? 0) < (pairingRecency[$1.id] ?? 0) }
    }

    private func removePairing(id: String) {
        pairings.removeAll { $0.id == id }
        pairingRecency[id] = nil
    }

    /// What writing the pairings did: whether the item holds them, and what
    /// was dropped to fit its size.
    private struct PairingWrite {
        var written = false
        /// Why the item was kept as found instead: this csecd could not read
        /// it, so nothing it pairs or unpairs reaches the item, and the
        /// change holds for this run only.
        var held: ProtectedUnreadableReason?
        /// Why a removal may come back at a later csecd start, or `nil` when
        /// the item now holds what this actor holds. A held item was never
        /// read, so it may pair the same project again once a build that
        /// reads it runs.
        var removalFailure: String? {
            if written { return nil }
            if held != nil {
                return "the saved pairings this csecd cannot read were kept as found and may pair it again "
                    + "once the current build runs; csec revoke --all removes them"
            }
            return "the pairing item could not be written"
        }
        /// Projects removed whole, least recently used first.
        var evicted: [String] = []
        /// `keeping`'s own oldest references, launcher scripts and SSH uses,
        /// in that order, once no other project was left to remove.
        var shedReferences: [String] = []
        var shedLaunchers = 0
        var shedSSHUses = 0
    }

    /// Writes the pairings synchronously. A document too large for the item
    /// sheds the least recently used project first (never `keeping`), then
    /// `keeping`'s oldest entries. A failed write deletes the item (the store's
    /// write-or-delete), so nothing stale is left for a restart. The change
    /// is prepared from what this actor holds in the same step it is taken,
    /// so the store applies the actor's changes in the actor's order.
    private func persistPairings(keeping id: String? = nil) async -> PairingWrite {
        var write = PairingWrite()
        guard let stores else { return write }
        let store = stores.store(for: PairingDocument.self)
        while true {
            let document = PairingDocument(projects: pairings)
            let change: ProtectedChange
            do {
                change = pairings.isEmpty ? try store.prepareDeletion() : try store.prepare(document)
            } catch ProtectedStoreError.rejected(.oversized) {
                if let victim = leastRecentPairing(except: id ?? "") {
                    write.evicted.append(victim.project.displayDescription)
                    removePairing(id: victim.id)
                    continue
                }
                if let id, let index = pairings.firstIndex(where: { $0.id == id }), !pairings[index].isEmpty {
                    // A launcher only lets a script reach destinations the
                    // pairing holds, so launchers go before SSH uses.
                    if !pairings[index].references.isEmpty {
                        write.shedReferences.append(pairings[index].references.removeFirst())
                    } else if !pairings[index].usedReferences.isEmpty {
                        write.shedReferences.append(pairings[index].usedReferences.removeFirst())
                    } else if !pairings[index].launchers.isEmpty {
                        pairings[index].launchers.removeFirst()
                        write.shedLaunchers += 1
                    } else {
                        pairings[index].ssh.removeFirst()
                        write.shedSSHUses += 1
                    }
                    continue
                }
                return write
            } catch ProtectedStoreError.uninstalled {
                return write
            } catch let ProtectedStoreError.held(reason) {
                write.held = reason
                return write
            } catch {
                log("the project pairings could not be prepared (\(error))")
                return write
            }
            do {
                _ = try await change.commit()
                write.written = true
                return write
            } catch {
                log("the project pairings could not be written (\(error))")
                return write
            }
        }
    }

    // MARK: - Listing and removal

    /// The delegated-approval entries `csec grants` lists: only while
    /// delegation is on.
    public func grantEntries() async -> (pairings: [ProjectPairing], builds: [TrustedClaudeBuild], hooks: [AcknowledgedClaudeHook])? {
        await load()
        guard state == .on, let document else { return nil }
        return (pairings, document.trustedBuilds, document.acknowledgedHooks)
    }

    public enum Removal: Sendable, Equatable {
        case removed([RevocableEntry])
        case ambiguous([RevocableEntry])
        /// Removed from memory, but the change could not be written.
        case notPersisted([RevocableEntry], String)
    }

    /// `csec revoke pair-…`, `build-…` or `hook-…`, and `untrust_build` /
    /// `forget_hook`: the one removal path. No Touch ID: it only removes
    /// authority. A prefix matching two or more entries removes nothing.
    public func remove(_ selector: GrantIDSelector) async -> Removal {
        await load()
        switch selector.kind {
        case .pairing:
            let matches = pairings.filter { selector.matches(id: $0.id) }
            if matches.count > 1 { return .ambiguous(matches.map(Self.entry)) }
            guard let match = matches.first else { return .removed([]) }
            removePairing(id: match.id)
            let failure = stores == nil ? nil : await persistPairings().removalFailure
            await decisionLog?.record(DecisionLogRecord(
                kind: .revoke, detail: "unpaired \(match.project.displayDescription) from Claude Code auto mode"
                    + (failure.map { "; \($0)" } ?? "")
            ))
            return failure.map { .notPersisted([Self.entry(match)], $0) } ?? .removed([Self.entry(match)])
        case .build, .hook:
            guard var document else { return .removed([]) }
            let removed: RevocableEntry
            if selector.kind == .build {
                let matches = document.trustedBuilds.filter { selector.matches(id: $0.cdHash) }
                if matches.count > 1 { return .ambiguous(matches.map(Self.entry)) }
                guard let match = matches.first else { return .removed([]) }
                document.trustedBuilds.removeAll { $0.cdHash == match.cdHash }
                removed = Self.entry(match)
                trustGeneration += 1
            } else {
                let matches = document.acknowledgedHooks.filter { selector.matches(id: $0.digest) }
                if matches.count > 1 { return .ambiguous(matches.map(Self.entry)) }
                guard let match = matches.first else { return .removed([]) }
                document.acknowledgedHooks.removeAll { $0.digest == match.digest }
                removed = Self.entry(match)
            }
            // A removal only takes authority away, so it holds for this run
            // even when it cannot be written: what the reply says is removed
            // is removed here, and the reply says it may come back.
            let failure = await writeSettings(document, keepOnFailure: true)
            await decisionLog?.record(DecisionLogRecord(
                kind: .settings,
                detail: "removed \(removed.label)" + (failure == nil ? "" : " for this run; the settings could not be written")
            ))
            return failure.map {
                .notPersisted([removed], "\($0); it may be trusted again after csecd restarts")
            } ?? .removed([removed])
        case .secret, .ssh:
            return .removed([])
        }
    }

    /// `csec revoke --all`: every pairing, whatever the delegation state
    /// (removing authority is always safe).
    public func removeAllPairings() async -> (removed: [RevocableEntry], failure: String?) {
        await load()
        let removed = pairings.map(Self.entry)
        // An item this csecd could not read is discarded too: the human asked
        // for every pairing to go, and a newer csecd would use what it holds.
        let held = stores?.store(for: PairingDocument.self).heldReason
        guard !removed.isEmpty || held != nil else { return ([], nil) }
        pairings = []
        pairingRecency = [:]
        let written: Bool
        if let held, let stores {
            do {
                _ = try await stores.store(for: PairingDocument.self).prepareDiscard().commit()
                written = true
            } catch {
                log("the project pairings could not be discarded (\(error))")
                written = false
            }
            await decisionLog?.record(DecisionLogRecord(
                kind: .revoke,
                detail: "discarded the saved pairings this csecd could not read (\(held))"
                    + (removed.isEmpty ? "" : " and unpaired \(removed.count) project\(removed.count == 1 ? "" : "s")")
                    + " (csec revoke --all)" + (written ? "" : "; the pairing item could not be deleted")
            ))
        } else {
            written = await persistPairings().written
            await decisionLog?.record(DecisionLogRecord(
                kind: .revoke, detail: "unpaired \(removed.count) project\(removed.count == 1 ? "" : "s") (csec revoke --all)"
            ))
        }
        return (removed, written || stores == nil ? nil : "the pairing item could not be deleted")
    }

    /// Revoking a grant rooted at a Claude Code process also unpairs what
    /// that grant covered from the process's project: its references, or
    /// (for an SSH grant) its key, server and user. `root` is the grant's own
    /// root incarnation, so a pid reused since the grant was listed is never
    /// read. Like every revocation, an unpair that could not be written is
    /// reported (`failure`): it would come back at the next csecd start.
    public func unpair(
        references: Set<String>, ssh: [PairedSSHUse], root: ProcessIncarnation
    ) async -> (removed: [RevocableEntry], failure: String?) {
        await load()
        guard !pairings.isEmpty, root.pid > 1, !references.isEmpty || !ssh.isEmpty,
              facts.incarnation(of: root.pid) == root else { return ([], nil) }
        let provider = facts
        let volumeUUID = volumeUUID
        let repositories = repositories
        let home = account.homeDirectory
        guard let resolved = await configurationFacts.run(within: configurationBound, { () -> [ProjectKey] in
            let directory = Self.projectResolution(provider.cwd(of: root), volumeUUID: volumeUUID)
            guard let project = Self.pairingKey(
                directory, homeDirectory: home, repositories: repositories, volumeUUID: volumeUUID
            ) else { return [] }
            guard case let .key(own) = directory, own != project else { return [project] }
            return [project, own]
        }) else { return ([], nil) }
        var entries: [RevocableEntry] = []
        var details: [String] = []
        for key in resolved {
            guard let index = pairings.firstIndex(where: { $0.project == key }) else { continue }
            let before = pairings[index]
            pairings[index].references.removeAll { references.contains($0) }
            pairings[index].usedReferences.removeAll { references.contains($0) }
            pairings[index].ssh.removeAll { ssh.contains($0) }
            guard pairings[index] != before else { continue }
            let removedCount = (before.references.count - pairings[index].references.count)
                + (before.usedReferences.count - pairings[index].usedReferences.count)
                + (before.ssh.count - pairings[index].ssh.count)
            entries.append(RevocableEntry(
                kind: .pairing, id: before.id,
                label: ReviewDisplay.bounded(
                    ReviewDisplay.sanitized("unpaired \(removedCount) from \(before.project.displayDescription)"),
                    maxBytes: RevocableEntry.maximumLabelBytes
                )
            ))
            details.append("unpaired \(removedCount) from \(before.project.displayDescription)")
            if pairings[index].isEmpty { removePairing(id: before.id) }
        }
        guard !entries.isEmpty else { return ([], nil) }
        let failure = stores == nil ? nil : await persistPairings().removalFailure
        await decisionLog?.record(DecisionLogRecord(
            kind: .revoke, refs: references.sorted(),
            detail: details.joined(separator: "; ") + " with the revoked grant" + (failure.map { "; \($0)" } ?? "")
        ))
        return (entries, failure)
    }

    /// Unpairs `references` from every project: what they name is gone, and a
    /// reference made again under the same name may release something else
    /// (a machine identity target removed, then added for another role).
    /// Returns how many pairings changed. Removing authority needs no touch.
    public func unpairEverywhere(references: Set<String>, because reason: String) async -> Int {
        await load()
        guard !references.isEmpty else { return 0 }
        var changed = 0
        for pairing in pairings {
            guard let index = pairings.firstIndex(where: { $0.id == pairing.id }) else { continue }
            let before = pairings[index]
            pairings[index].references.removeAll { references.contains($0) }
            pairings[index].usedReferences.removeAll { references.contains($0) }
            guard pairings[index] != before else { continue }
            changed += 1
            if pairings[index].isEmpty { removePairing(id: before.id) }
        }
        guard changed > 0 else { return 0 }
        let failure = stores == nil ? nil : await persistPairings().removalFailure
        await decisionLog?.record(DecisionLogRecord(
            kind: .revoke, refs: references.sorted(),
            detail: "unpaired from \(changed) project\(changed == 1 ? "" : "s") because \(reason)"
                + (failure.map { "; \($0)" } ?? "")
        ))
        return changed
    }

    private static func entry(_ pairing: ProjectPairing) -> RevocableEntry {
        RevocableEntry(
            kind: .pairing, id: pairing.id,
            label: ReviewDisplay.bounded(
                ReviewDisplay.sanitized(
                    "\(pairing.project.displayDescription): \(pairing.references.count) reference(s), "
                        + (pairing.usedReferences.isEmpty ? ""
                            : "\(pairing.usedReferences.count) used inside csec, ")
                        + "\(pairing.ssh.count) SSH use(s), \(pairing.launchers.count) script(s)"
                        + (pairing.sudo ? ", sudo" : "")
                ),
                maxBytes: RevocableEntry.maximumLabelBytes
            )
        )
    }

    private static func entry(_ build: TrustedClaudeBuild) -> RevocableEntry {
        RevocableEntry(
            kind: .build, id: build.cdHash,
            label: ReviewDisplay.bounded(
                ReviewDisplay.sanitized("trusted Claude Code build \(build.versionLabel) (\(build.path))"),
                maxBytes: RevocableEntry.maximumLabelBytes
            )
        )
    }

    private static func entry(_ hook: AcknowledgedClaudeHook) -> RevocableEntry {
        RevocableEntry(
            kind: .hook, id: hook.digest,
            label: ReviewDisplay.bounded(
                ReviewDisplay.sanitized("acknowledged hook \(hook.display)"),
                maxBytes: RevocableEntry.maximumLabelBytes
            )
        )
    }

    // MARK: - Restore discovery

    /// The pairings of every live, verified Claude Code session: each process
    /// of this user that is the interactive foreground job of a terminal and
    /// passes the Claude Code identity check, keyed by the repository its
    /// kernel working directory is in, and by that directory itself. Nothing with delegation off. The sweep reads job facts
    /// first (no file system), fd 0 only for foreground jobs, and identity
    /// only for those, cached per image; it runs off the actor, bounded, and a
    /// read that blocks ends it with what it found so far.
    public func pairingsOfLiveSessions() async -> [ProjectPairing] {
        await livePairings().projects
    }

    /// What a delegated request of a live session could use: its project's
    /// pairings (`pairingsOfLiveSessions`) and, while any live session
    /// exists, every use a pairing holds for csecd, which covers auto mode in
    /// every project (`judge`), in the order first paired.
    public func livePairings() async -> (projects: [ProjectPairing], everyProjectUses: [String]) {
        let projects = await liveSessionProjects()
        guard !projects.isEmpty else { return ([], []) }
        var uses: [String] = []
        for reference in pairings.flatMap(\.usedReferences) where !uses.contains(reference) {
            uses.append(reference)
        }
        return (pairings.filter { projects.contains($0.project) }, uses)
    }

    /// Every reference any pairing holds, released or used inside csecd, in
    /// the order first paired. Nothing with delegation off.
    public func allPairedReferences() async -> [String] {
        await load()
        guard state == .on else { return [] }
        var references: [String] = []
        var seen: Set<String> = []
        for pairing in pairings {
            for reference in pairing.references + pairing.usedReferences where seen.insert(reference).inserted {
                references.append(reference)
            }
        }
        return references
    }

    private func liveSessionProjects() async -> Set<ProjectKey> {
        await load()
        guard state == .on, !pairings.isEmpty else { return [] }
        let provider = facts
        let volumeUUID = volumeUUID
        let repositories = repositories
        let home = account.homeDirectory
        let cache = identityCache
        let trusted = document?.trustedCDHashes ?? []
        let generation = trustGeneration
        let found = DelegationDiscoveryResults()
        _ = await discoveryFacts.run(within: discoveryBound) {
            guard let processes = provider.liveProcesses() else { return false }
            for process in processes {
                guard provider.interactivity(of: process).isInteractive else { continue }
                guard let identity = Self.cachedIdentity(
                    of: process, parentOf: nil, trusted: trusted, generation: generation,
                    provider: provider, cache: cache
                ), identity.isClaudeCode else { continue }
                let directory = Self.projectResolution(provider.cwd(of: process), volumeUUID: volumeUUID)
                guard let key = Self.pairingKey(
                    directory, homeDirectory: home, repositories: repositories, volumeUUID: volumeUUID
                ) else { continue }
                found.add(key)
                // A pairing recorded on the directory itself still holds there.
                if case let .key(own) = directory { found.add(own) }
            }
            return true
        }
        return found.snapshot
    }

    // MARK: - configure_delegation

    /// `configure_delegation`. The caller (`Agent`) has checked the verified
    /// launcher. `enable`, `trust_build` and `acknowledge_hooks` raise one
    /// bare Touch ID sheet whose reason csecd writes from what it found,
    /// naming the terminal; the rest only read or remove authority.
    public func configure(
        _ request: DelegationConfigurationRequest, caller: CallerInfo, terminal: TerminalSessionContext?
    ) async -> Response {
        await load()
        switch request.action {
        case .status:
            return Response(requestID: request.requestID, delegationStatus: await status(for: request, caller: caller))
        case .enable:
            return await enable(request, caller: caller, terminal: terminal)
        case .trustBuild:
            return await trustBuild(request, caller: caller, terminal: terminal)
        case .acknowledgeHooks:
            return await acknowledgeHooks(request, caller: caller, terminal: terminal)
        case .untrustBuild, .forgetHook:
            guard let selector = request.targetSelector else {
                return .failed(.invalidRequest, message: "a build- or hook- id is required", requestID: request.requestID)
            }
            switch await remove(selector) {
            case let .ambiguous(matches):
                return Response(
                    requestID: request.requestID,
                    grantRevocation: GrantRevocation(ambiguousMatches: matches),
                    failure: ProtocolFailure(
                        .invalidRequest,
                        message: "\(request.target ?? "") matches more than one entry: "
                            + matches.map(\.displayID).joined(separator: ", ")
                    )
                )
            case let .notPersisted(removed, failure):
                return Response(
                    requestID: request.requestID,
                    grantRevocation: GrantRevocation(removed: removed),
                    failure: ProtocolFailure(.internalError, message: "removed for this csecd run, but \(failure)")
                )
            case let .removed(removed):
                return Response(
                    requestID: request.requestID,
                    grantRevocation: GrantRevocation(removed: removed),
                    delegationStatus: await status(for: request, caller: caller)
                )
            }
        case .disable:
            return await disable(request, caller: caller)
        }
    }

    private struct Inventory: Sendable {
        let settings: ClaudeSettingsGateEvaluation?
        let builds: [DiscoveredClaudeBuild]
        let liveBuilds: [DiscoveredClaudeBuild]
        let unreadableBuildPaths: [String]
        let problem: String?
    }

    /// Claude Code's settings and builds for a configuration request's
    /// scope, read off the actor within the configuration bound.
    private func inventory(for request: DelegationConfigurationRequest, caller: CallerInfo) async -> Inventory? {
        let account = account
        let gate = gate
        let provider = facts
        let isOnLocalMounts = isOnLocalMounts
        let cache = identityCache
        let trusted = document?.trustedCDHashes ?? []
        let generation = trustGeneration
        let csecPath = caller.peerIdentity?.code.executablePath
            ?? ProcessAncestry.executablePath(of: caller.pid) ?? "/usr/local/bin/csec"
        return await configurationFacts.run(within: configurationBound) {
            var problem: String?
            var configDirectory: String?
            if let directory = request.claudeConfigDirectory {
                var info = stat()
                let normalized = ClaudeSettingsScope.normalizedPath(directory)
                if isOnLocalMounts(normalized), stat(normalized, &info) == 0,
                   info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid() {
                    configDirectory = normalized
                } else {
                    problem = "CLAUDE_CONFIG_DIR is not a local directory this user owns"
                }
            }
            var workingDirectories: [String] = []
            if let project = request.projectDirectory {
                let normalized = ClaudeSettingsScope.normalizedPath(project)
                if isOnLocalMounts(normalized) { workingDirectories.append(normalized) }
            }
            let scope = ClaudeSettingsScope(
                homeDirectory: account.homeDirectory,
                claudeConfigDirectory: configDirectory,
                workingDirectories: workingDirectories,
                userName: account.userName,
                csecExecutablePath: csecPath
            )
            guard problem == nil, scope.isWellFormed, isOnLocalMounts(account.homeDirectory) else {
                return Inventory(settings: nil, builds: [], liveBuilds: [], unreadableBuildPaths: [account.homeDirectory],
                                 problem: problem ?? "the home directory is not local")
            }
            let evaluation = gate.evaluate(scope)
            let discovery = gate.discoverBuilds(scope)
            // Include signed new releases and custom images anywhere on disk.
            // A live image's identity is exec-bound, even if its path was replaced.
            var live: [DiscoveredClaudeBuild] = []
            var unreadable = discovery.unreadable.map(\.path)
            let processes = provider.liveProcesses()
            if processes == nil { unreadable.append(account.homeDirectory) }
            let observed = cache.observedClaudeProcesses()
            for process in Set(processes ?? []).union(observed).sorted(by: { $0.pid < $1.pid }) {
                guard provider.incarnation(of: process.pid) == process,
                      let path = provider.executablePath(of: process),
                      observed.contains(process) || ClaudeBuildVerification.isInventoryCandidate(path) else { continue }
                let identity = Self.cachedIdentity(
                    of: process, parentOf: nil, trusted: trusted, generation: generation,
                    provider: provider, cache: cache
                )
                let cdHash = identity?.signatureValid == true ? identity?.cdHash : nil
                guard !live.contains(where: { $0.path == path && $0.cdHash == cdHash }) else { continue }
                guard live.count < DelegationStatus.maximumDiscoveredBuilds else {
                    unreadable.append(path)
                    break
                }
                live.append(DiscoveredClaudeBuild(
                    path: path, versionLabel: Self.buildLabel(identity: identity, executablePath: path),
                    cdHash: cdHash, signedByAnthropic: identity?.satisfiesAnthropicRequirement == true
                ))
            }
            return Inventory(settings: evaluation, builds: discovery.builds, liveBuilds: live,
                             unreadableBuildPaths: unreadable, problem: nil)
        }
    }

    private func untrustedBuilds(_ inventory: Inventory?) -> [ClaudeBuildSummary] {
        guard let inventory else { return [] }
        let trusted = document?.trustedCDHashes ?? []
        var seen = Set<String>()
        var summaries: [ClaudeBuildSummary] = []
        let discovered = ClaudeBuildDiscovery(builds: inventory.builds + inventory.liveBuilds, unreadable: [])
            .untrusted(trustedCDHashes: trusted)
        for build in discovered {
            guard let cdHash = build.cdHash?.lowercased(), !trusted.contains(cdHash),
                  seen.insert(cdHash).inserted else { continue }
            let summary = ClaudeBuildSummary(
                cdHash: cdHash,
                versionLabel: ReviewDisplay.bounded(
                    ReviewDisplay.sanitized(build.versionLabel), maxBytes: ClaudeBuildSummary.maximumVersionLabelBytes
                ),
                path: build.path
            )
            if summary.isWellFormed { summaries.append(summary) }
        }
        return Array(summaries.prefix(DelegationStatus.maximumDiscoveredBuilds))
    }

    /// The checked list as of now: the compiled records plus the held signed
    /// manifest's, verified again on every read so a replaced file never
    /// counts.
    private static func buildVerification(
        compiled: ClaudeBuildVerification, store: ReleaseManifestStore?
    ) -> ClaudeBuildVerification {
        guard let store else { return compiled }
        return ClaudeBuildVerification.current(compiled: compiled, store: store)
    }

    private func verificationReport(_ inventory: Inventory?) -> ClaudeBuildVerificationReport {
        guard let inventory else {
            return ClaudeBuildVerificationReport(builds: [], unreadablePaths: [account.homeDirectory])
        }
        let buildVerification = Self.buildVerification(compiled: compiledBuilds, store: manifestStore)
        var builds: [ClaudeBuildVerificationReport.Build] = []
        var unreadable = inventory.unreadableBuildPaths
        // Live images win deduplication and retain their actual identity.
        for (build, running) in inventory.liveBuilds.map({ ($0, true) }) + inventory.builds.map({ ($0, false) }) {
            guard !builds.contains(where: { $0.cdHash == build.cdHash && $0.path == build.path }) else { continue }
            guard builds.count < DelegationStatus.maximumDiscoveredBuilds else {
                unreadable.append(build.path)
                break
            }
            let item = ClaudeBuildVerificationReport.Build(
                path: build.path,
                versionLabel: ReviewDisplay.bounded(
                    ReviewDisplay.sanitized(build.versionLabel), maxBytes: ClaudeBuildSummary.maximumVersionLabelBytes),
                cdHash: build.cdHash,
                checkedVersion: buildVerification.checkedVersion(cdHash: build.cdHash),
                running: running
            )
            if item.isWellFormed { builds.append(item) } else { unreadable.append(account.homeDirectory) }
        }
        return ClaudeBuildVerificationReport(
            builds: builds,
            unreadablePaths: Array(Set(unreadable).filter { WireField.isAbsolutePath($0) }.sorted()
                .prefix(DelegationStatus.maximumDiscoveredBuilds)),
            checkedReleases: Array(Set(buildVerification.records.map(\.version))).sorted()
        )
    }

    private func status(
        for request: DelegationConfigurationRequest, caller: CallerInfo, inventory known: Inventory? = nil
    ) async -> DelegationStatus {
        let inventory: Inventory?
        if let known {
            inventory = known
        } else if request.action == .status, stores != nil {
            inventory = await self.inventory(for: request, caller: caller)
        } else {
            inventory = nil
        }
        // Registrations are pruned on every register, consume and status.
        pruneRegistrations()
        let document = document
        let settingsEvaluation = inventory?.settings.flatMap { $0.isWellFormed ? $0 : nil }
        return DelegationStatus(
            state: state,
            policyVersion: policyVersion,
            consentedPolicyVersion: document?.consentedPolicyVersion,
            setClassifyAllShell: document?.setClassifyAllShell ?? false,
            claudeSettingsPath: document?.claudeSettingsPath,
            trustedBuilds: document?.trustedBuilds.map(\.summary) ?? [],
            acknowledgedHooks: document?.acknowledgedHooks.map(\.summary) ?? [],
            discoveredUntrustedBuilds: untrustedBuilds(inventory),
            buildVerification: verificationReport(inventory),
            settings: settingsEvaluation,
            pairingCount: state == .on ? min(pairings.count, DelegationGrantsListing.maximumPairings) : 0,
            counters: DelegationCounters(approved: approvedCount, declined: declinedCount),
            lastDecline: lastDecline,
            identityLookup: lastIdentityLookup?.logDescription
        )
    }

    private func enable(
        _ request: DelegationConfigurationRequest, caller: CallerInfo, terminal: TerminalSessionContext?
    ) async -> Response {
        guard stores != nil else {
            return .failed(
                .policyDenied, message: "delegated approvals need csecd's protected stores, which this build lacks",
                requestID: request.requestID
            )
        }
        guard let settingsPath = request.claudeSettingsPath, let setClassifyAllShell = request.setClassifyAllShell else {
            return .failed(.invalidRequest, message: "enable needs the settings path and record", requestID: request.requestID)
        }
        guard let inventory = await inventory(for: request, caller: caller), inventory.problem == nil,
              let evaluation = inventory.settings else {
            return .failed(
                .providerUnavailable,
                message: "csecd could not read Claude Code's settings and builds to show what enabling trusts",
                requestID: request.requestID
            )
        }
        let generation = disableGeneration
        let builds = untrustedBuilds(inventory)
        let hooks = evaluation.unacknowledgedHooks(acknowledgedDigests: document?.acknowledgedDigests ?? [])
        var parts = ["Let Claude Code auto mode approve csec secrets for its commands in projects you pair"]
        var changes = parts
        if !builds.isEmpty {
            let trusting = Self.listed(builds.map { "build \($0.versionLabel)" })
            parts.append("trusting \(trusting)")
            changes.append("Trust Claude Code \(trusting)")
        }
        if !hooks.isEmpty {
            parts.append("acknowledging " + Self.hookInventory(hooks))
            changes += Self.hookInventoryParts(hooks).map { "Acknowledge " + $0 }
        }
        // Once this is approved setup reverts the recorded file, and sessions
        // reading it get nothing: the touch has to say so.
        if let recordedPath = document?.claudeSettingsPath, recordedPath != settingsPath {
            let moving = "csec's Claude Code settings from \(ReviewDisplay.sanitized(recordedPath)) to "
                + ReviewDisplay.sanitized(settingsPath)
            parts.append("moving " + moving)
            changes.append("Move " + moving)
        }
        let reason = parts.joined(separator: " — ") + " — from \(ReviewDisplay.sanitized((terminal ?? .unidentified).summary))"
        if case let .refused(refusal) = await authenticate(
            SettingsChangeReviewDetails(title: "Turn On Claude Code Auto-Mode Approvals", changes: changes),
            caller: caller, terminal: terminal, reason: reason
        ) {
            return await refused(refusal, change: "enabling Claude Code auto-mode approvals", request: request)
        }
        // The sheet may have been up a while. What it listed is applied to
        // the settings as they are now, so an untrust or forget made meanwhile
        // stays made; a disable made meanwhile wins outright.
        guard disableGeneration == generation else {
            return Self.changedWhileSheetWasUp(request)
        }
        let current = document
        let now = clock()
        var trusted = current?.trustedBuilds ?? []
        for build in builds where !trusted.contains(where: { $0.cdHash == build.cdHash }) {
            trusted.append(TrustedClaudeBuild(
                cdHash: build.cdHash, versionLabel: build.versionLabel, path: build.path, trustedAt: now
            ))
        }
        let acknowledged = Self.acknowledging(hooks, in: current?.acknowledgedHooks ?? [], at: now)
        let samePath = current?.claudeSettingsPath == settingsPath
        let next = DelegationSettingsDocument(
            clients: [.claude],
            consentedPolicyVersion: policyVersion,
            setClassifyAllShell: samePath ? ((current?.setClassifyAllShell ?? false) || setClassifyAllShell) : setClassifyAllShell,
            claudeSettingsPath: settingsPath,
            trustedBuilds: Array(trusted.suffix(DelegationPolicy.maximumTrustedBuilds)),
            acknowledgedHooks: acknowledged
        )
        if let failure = await writeSettings(next) {
            return .failed(.internalError, message: "delegated approvals were not enabled: \(failure)", requestID: request.requestID)
        }
        trustGeneration += 1
        await decisionLog?.record(DecisionLogRecord(
            kind: .settings, decider: .humanLocal,
            detail: "Claude Code auto-mode approvals enabled (policy \(policyVersion)); "
                + "trusted \(builds.count) build\(builds.count == 1 ? "" : "s"), "
                + "acknowledged \(Self.acknowledgedCount(hooks))"
        ))
        return Response(
            requestID: request.requestID,
            delegationStatus: await status(for: request, caller: caller, inventory: inventory)
        )
    }

    private func trustBuild(
        _ request: DelegationConfigurationRequest, caller: CallerInfo, terminal: TerminalSessionContext?
    ) async -> Response {
        guard let before = document else {
            return .failed(.policyDenied, message: "delegated approvals are off; run csec setup", requestID: request.requestID)
        }
        let generation = disableGeneration
        guard let target = request.target, WireField.isAbsolutePath(target) else {
            return .failed(.invalidRequest, message: "trust_build needs an absolute path", requestID: request.requestID)
        }
        let path = ClaudeSettingsScope.normalizedPath(target)
        let inspector = buildInspector
        let isOnLocalMounts = isOnLocalMounts
        guard let inspected = await configurationFacts.run(within: configurationBound, {
            isOnLocalMounts(path) ? inspector.inspect(path) : nil
        }), let build = inspected else {
            return .failed(
                .invalidRequest, message: "that path is not a validly signed local executable", requestID: request.requestID
            )
        }
        if before.trustedCDHashes.contains(build.cdHash) || build.signedByAnthropic {
            return Response(requestID: request.requestID, delegationStatus: await status(for: request, caller: caller))
        }
        let label = ReviewDisplay.bounded(
            ReviewDisplay.sanitized((path as NSString).lastPathComponent),
            maxBytes: ClaudeBuildSummary.maximumVersionLabelBytes
        )
        let change = "Trust Claude Code build \(label) (cdhash \(build.cdHash.prefix(12))) for auto-mode approvals"
        let reason = change + " — from \(ReviewDisplay.sanitized((terminal ?? .unidentified).summary))"
        if case let .refused(refusal) = await authenticate(
            SettingsChangeReviewDetails(title: "Trust a Claude Code Build", changes: [change, "Path: \(path)"]),
            caller: caller, terminal: terminal, reason: reason
        ) {
            return await refused(refusal, change: "trusting Claude Code build \(label)", request: request)
        }
        let trusted = TrustedClaudeBuild(cdHash: build.cdHash, versionLabel: label, path: path, trustedAt: clock())
        guard trusted.isWellFormed else {
            return .failed(.invalidRequest, message: "that build cannot be recorded", requestID: request.requestID)
        }
        // Only the one build the sheet named is added, to the settings as
        // they are now: a removal made while the sheet was up stays removed,
        // and a disable made meanwhile is never undone.
        guard disableGeneration == generation, var current = document else {
            return Self.changedWhileSheetWasUp(request)
        }
        if current.trustedCDHashes.contains(trusted.cdHash) {
            return Response(requestID: request.requestID, delegationStatus: await status(for: request, caller: caller))
        }
        current.trustedBuilds.append(trusted)
        current.trustedBuilds = Array(current.trustedBuilds.suffix(DelegationPolicy.maximumTrustedBuilds))
        if let failure = await writeSettings(current) {
            return .failed(.internalError, message: "the build was not trusted: \(failure)", requestID: request.requestID)
        }
        trustGeneration += 1
        await decisionLog?.record(DecisionLogRecord(
            kind: .settings, decider: .humanLocal, detail: "trusted Claude Code build \(label) (\(path))"
        ))
        return Response(requestID: request.requestID, delegationStatus: await status(for: request, caller: caller))
    }

    private func acknowledgeHooks(
        _ request: DelegationConfigurationRequest, caller: CallerInfo, terminal: TerminalSessionContext?
    ) async -> Response {
        guard document != nil else {
            return .failed(.policyDenied, message: "delegated approvals are off; run csec setup", requestID: request.requestID)
        }
        let generation = disableGeneration
        guard let inventory = await inventory(for: request, caller: caller), inventory.problem == nil,
              let evaluation = inventory.settings else {
            return .failed(
                .providerUnavailable, message: "csecd could not read Claude Code's settings", requestID: request.requestID
            )
        }
        let hooks = evaluation.unacknowledgedHooks(acknowledgedDigests: document?.acknowledgedDigests ?? [])
        guard !hooks.isEmpty else {
            return Response(
                requestID: request.requestID,
                delegationStatus: await status(for: request, caller: caller, inventory: inventory)
            )
        }
        let reason = "Acknowledge " + Self.hookInventory(hooks)
            + " — from \(ReviewDisplay.sanitized((terminal ?? .unidentified).summary))"
        if case let .refused(refusal) = await authenticate(
            SettingsChangeReviewDetails(
                title: "Acknowledge Claude Code Hooks and Rules",
                changes: Self.hookInventoryParts(hooks).map { "Acknowledge " + $0 }
            ),
            caller: caller, terminal: terminal, reason: reason
        ) {
            return await refused(refusal, change: "acknowledging \(Self.acknowledgedCount(hooks))", request: request)
        }
        // Exactly the hooks the sheet listed are added, to the settings as
        // they are now (see `trustBuild`).
        guard disableGeneration == generation, var current = document else {
            return Self.changedWhileSheetWasUp(request)
        }
        current.acknowledgedHooks = Self.acknowledging(hooks, in: current.acknowledgedHooks, at: clock())
        if let failure = await writeSettings(current) {
            return .failed(.internalError, message: "the hooks were not acknowledged: \(failure)", requestID: request.requestID)
        }
        await decisionLog?.record(DecisionLogRecord(
            kind: .settings, decider: .humanLocal,
            detail: "acknowledged \(Self.acknowledgedCount(hooks))"
        ))
        return Response(
            requestID: request.requestID,
            delegationStatus: await status(for: request, caller: caller, inventory: inventory)
        )
    }

    /// Asks for the touch that approves `change`: in csecd's panel when its
    /// consent has one (`SettingsChangeConsent`), else as `reason`. The panel
    /// names the terminal tab the request came from, as `reason` does.
    private func authenticate(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, terminal: TerminalSessionContext?,
        reason: String
    ) async -> ConsentAnswer {
        var shown = caller
        shown.terminal = terminal ?? caller.terminal
        return await consent.authenticateSettingsChange(change, caller: shown, reason: reason)
    }

    /// A delegation sheet that did not approve: logged with why it ended
    /// (the human's Deny, a sheet macOS dismissed, a finger not recognised)
    /// and how long it was up, and answered `consentDenied` with that reason
    /// for `csec setup` to show. Nothing changed, so nothing else is written.
    private func refused(
        _ refusal: ConsentRefusal, change: String, request: DelegationConfigurationRequest
    ) async -> Response {
        await decisionLog?.record(DecisionLogRecord(
            kind: .settings, outcome: refusal.logOutcome, decider: refusal.logDecider, ttdMs: refusal.ttdMs,
            cause: refusal.logCause, detail: "\(change) was not approved: \(refusal.summary)"
        ).bounded())
        return .failed(.consentDenied, message: refusal.summary, requestID: request.requestID)
    }

    /// Turns delegation off: deletes the settings and every pairing. No
    /// Touch ID; it only removes authority.
    private func disable(_ request: DelegationConfigurationRequest, caller: CallerInfo) async -> Response {
        var failures: [String] = []
        // Both deletions are prepared, and what this actor holds cleared, in
        // one step, before anything is awaited: a sheet still up, or a
        // pairing written after, sees delegation off and cannot bring it back.
        var settingsDeletion: ProtectedChange?
        var pairingDeletion: ProtectedChange?
        var registrationDeletion: ProtectedChange?
        if let stores {
            // Discarded even when this csecd could not read them: turning
            // delegation off must not leave a newer csecd anything to bring
            // back.
            do {
                settingsDeletion = try stores.store(for: DelegationSettingsDocument.self).prepareDiscard()
            } catch {
                failures.append("the delegation settings could not be deleted (\(error))")
            }
            do {
                pairingDeletion = try stores.store(for: PairingDocument.self).prepareDiscard()
            } catch {
                failures.append("the project pairings could not be deleted (\(error))")
            }
            do {
                registrationDeletion = try stores.store(for: DelegationRegistrationsDocument.self).prepareDiscard()
            } catch {
                failures.append("the auto-mode registrations could not be deleted (\(error))")
            }
        }
        disableGeneration += 1
        settings = stores == nil ? .unavailable : .absent
        if let settingsDeletion { settingsSequence = settingsDeletion.sequence }
        let hadPairings = !pairings.isEmpty
        pairings = []
        pairingRecency = [:]
        registrations = [:]
        trustGeneration += 1
        if let settingsDeletion {
            do {
                _ = try await settingsDeletion.commit()
            } catch {
                failures.append("the delegation settings could not be deleted (\(error))")
            }
        }
        if let pairingDeletion {
            do {
                _ = try await pairingDeletion.commit()
            } catch {
                failures.append("the project pairings could not be deleted (\(error))")
            }
        }
        if let registrationDeletion {
            do {
                _ = try await registrationDeletion.commit()
            } catch {
                failures.append("the auto-mode registrations could not be deleted (\(error))")
            }
        }
        await decisionLog?.record(DecisionLogRecord(
            kind: .settings,
            detail: "Claude Code auto-mode approvals disabled" + (hadPairings ? "; every pairing removed" : "")
        ))
        guard failures.isEmpty else {
            return .failed(
                .internalError,
                message: "delegated approvals are off for this csecd run, but " + failures.joined(separator: "; "),
                requestID: request.requestID
            )
        }
        return Response(requestID: request.requestID, delegationStatus: await status(for: request, caller: caller))
    }

    /// `csec uninstall` approved: the uninstaller deletes the settings and
    /// pairing items with every other protected item, and this drops what
    /// this actor holds of them, so a csecd whose LaunchAgent is not
    /// unregistered after all (the last step failed or was interrupted) never
    /// delegates again on memory alone. Delegation reads as off from here; a
    /// Touch ID sheet still up for enable or trust is refused, as after a
    /// disable, and the items are never read back (the load has happened).
    /// Nothing is written or logged: the stores are already uninstalled.
    public func forgetForUninstall() async {
        await load()
        disableGeneration += 1
        settings = stores == nil ? .unavailable : .absent
        pairings = []
        pairingRecency = [:]
        registrations = [:]
        trustGeneration += 1
    }

    /// Writes the settings synchronously. The change is prepared, and made
    /// what this actor holds, before anything is awaited, so the actor's view
    /// follows the order the store applies changes in (a later change always
    /// wins in both). If the write fails and no later change was prepared
    /// meanwhile, the actor goes back to what it held, or to absent when the
    /// failed write deleted the item; a removal (`keepOnFailure`) keeps its
    /// smaller document instead, since holding less authority than the item
    /// is always safe. Returns a value-free failure.
    private func writeSettings(_ next: DelegationSettingsDocument, keepOnFailure: Bool = false) async -> String? {
        guard let stores else { return "csecd has no protected stores" }
        let previous = settings
        let change: ProtectedChange
        do {
            change = try stores.store(for: DelegationSettingsDocument.self).prepare(next)
        } catch {
            return "the settings could not be written (\(error))"
        }
        settings = .document(next)
        settingsSequence = change.sequence
        do {
            _ = try await change.commit()
            return nil
        } catch let error as ProtectedStoreError where error.itemIsAbsent {
            if settingsSequence == change.sequence { settings = .absent }
            return "the settings could not be written, so the item was deleted (\(error))"
        } catch {
            if settingsSequence == change.sequence, !keepOnFailure { settings = previous }
            return "the settings could not be written (\(error))"
        }
    }

    private static func changedWhileSheetWasUp(_ request: DelegationConfigurationRequest) -> Response {
        .failed(
            .policyDenied,
            message: "delegated approvals were turned off while Touch ID was up, so nothing was changed; run it again",
            requestID: request.requestID
        )
    }

    /// Claude Code's hook event that can block a settings reload.
    static let configChangeEvent = "ConfigChange"

    /// The hooks a sheet acknowledges, by what each can do: approve Claude
    /// Code's Bash commands, or (a `ConfigChange` hook) keep Claude Code from
    /// reloading its hooks, which keeps an approving hook in force.
    private static func hookInventory(_ hooks: [ClaudeHookSource]) -> String {
        hookInventoryParts(hooks).joined(separator: "; and ")
    }

    /// `hookInventory`'s parts: the hooks that approve, those that keep
    /// Claude Code from reloading, and the classifier rules, each one line.
    private static func hookInventoryParts(_ hooks: [ClaudeHookSource]) -> [String] {
        let rules = hooks.filter { $0.kind == .classifierRules }
        let reloading = hooks.filter { $0.kind != .classifierRules && $0.event == configChangeEvent }
        let approving = hooks.filter { $0.kind != .classifierRules && $0.event != configChangeEvent }
        var parts: [String] = []
        if !approving.isEmpty {
            parts.append("\(listed(approving.map(\.display))), which can approve Claude Code's shell commands")
        }
        if !reloading.isEmpty {
            parts.append("\(listed(reloading.map(\.display))), which can keep Claude Code from reloading its hooks")
        }
        if !rules.isEmpty {
            parts.append("\(listed(rules.map(\.display))), which steer the auto-mode classifier")
        }
        return parts
    }

    /// `acknowledged` with each of `hooks` added, as one entry per digest. A
    /// source's classifier rules replace that source's earlier acknowledged
    /// rules: the rules a source holds are one thing, as it is now.
    static func acknowledging(
        _ hooks: [ClaudeHookSource], in acknowledged: [AcknowledgedClaudeHook], at now: Date
    ) -> [AcknowledgedClaudeHook] {
        var result = acknowledged
        for hook in hooks where !result.contains(where: { $0.digest == hook.digest }) {
            var rules: AcknowledgedClassifierRules?
            if hook.kind == .classifierRules {
                result.removeAll { $0.classifierRules?.sourceID == hook.sourceID }
                rules = AcknowledgedClassifierRules(sourceID: hook.sourceID, ruleDigests: hook.ruleDigests ?? [])
            }
            result.append(AcknowledgedClaudeHook(
                digest: hook.digest, display: hook.display, acknowledgedAt: now, classifierRules: rules))
        }
        return DelegationSettingsDocument.bounded(result)
    }

    /// "2 hooks that can approve shell commands and 1 settings file's
    /// classifier rules", for the decision log.
    private static func acknowledgedCount(_ hooks: [ClaudeHookSource]) -> String {
        let rules = hooks.filter { $0.kind == .classifierRules }.count
        let others = hooks.count - rules
        var parts = ["\(others) hook\(others == 1 ? "" : "s") that can approve shell commands"]
        if rules > 0 { parts.append("the classifier rules of \(rules) settings source\(rules == 1 ? "" : "s")") }
        return parts.joined(separator: " and ")
    }

    private static func listed(_ items: [String]) -> String {
        let shown = items.prefix(3).map { ReviewDisplay.bounded(ReviewDisplay.sanitized($0), maxBytes: 96) }
        let rest = items.count - shown.count
        return shown.joined(separator: "; ") + (rest > 0 ? " and \(rest) more" : "")
    }

    // MARK: - Helpers

    /// Byte-exact comparison: Swift's `==` treats canonically equivalent
    /// strings (`"\u{037E}"` and `";"`) as equal.
    static func bytesEqual(_ left: String, _ right: String) -> Bool {
        Array(left.utf8) == Array(right.utf8)
    }

    private func log(_ message: String) {
        FileHandle.standardError.write(Data("csecd: \(message)\n".utf8))
    }
}

/// Projects restore discovery found, collected as it goes so a sweep that
/// hits its bound still yields what it read before the read that blocked.
private final class DelegationDiscoveryResults: @unchecked Sendable {
    private let lock = NSLock()
    private var projects: Set<ProjectKey> = []

    func add(_ project: ProjectKey) {
        lock.lock()
        projects.insert(project)
        lock.unlock()
    }

    var snapshot: Set<ProjectKey> {
        lock.lock()
        defer { lock.unlock() }
        return projects
    }
}
