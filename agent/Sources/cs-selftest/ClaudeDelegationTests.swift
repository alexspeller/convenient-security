import ConvenientSecurity
import CryptoKit
import CSECRemoteApproval
import Foundation
import LocalAuthentication
import OnePasswordAdapter

// Delegated approvals (csecd's side): when Claude Code auto mode may stand in
// for a panel. Every test here is hermetic: a synthetic process tree
// (`SyntheticClaudeSessionFacts`), a fake settings gate, in-memory protected
// stores and fake providers. Where a request must wait for the consent turn
// (anything that reaches a panel), the requesting `csec ai` is a real, live
// child process, because the queue re-checks it against the kernel.

// MARK: - Fixtures

private let delegationTerminal: UInt32 = 0x1000_0077
private let delegationHome = "/synthetic/home"
private let delegationVolume = "6D57CCC2-9639-4606-BC4A-BFE63AECF091"
private let alphaPath = "/synthetic/projects/alpha"
private let betaPath = "/synthetic/projects/beta"
private let alphaInode: UInt64 = 4_242
private let betaInode: UInt64 = 4_343
private let delegationCsecPath = "/synthetic/bin/csec"
private let alphaReference = "csec://alpha/TOKEN"
private let delegationAccount = DelegationAccount(homeDirectory: delegationHome, userName: "tester")
private let delegationVerifiedBuilds = ClaudeBuildVerification(records: ["a", "c"].map {
    .init(cdHash: String(repeating: $0, count: 40), version: "synthetic-checked", evidence: "synthetic fixture")
})

private func delegationCWD(_ path: String, inode: UInt64, local: Bool = true) -> ProcessWorkingDirectory {
    ProcessWorkingDirectory(
        directory: DirectoryIdentity(path: path, device: 16_777_232, inode: inode),
        mount: MountFacts(
            fileSystemID: FileSystemID(16_777_232, 26),
            mountPoint: local ? "/System/Volumes/Data" : "/Volumes/remote",
            fileSystemType: local ? "apfs" : "smbfs",
            isLocal: local
        ),
        isOnLocalMounts: local
    )
}

private func projectKey(_ path: String = alphaPath, inode: UInt64 = alphaInode) -> ProjectKey {
    ProjectKey(path: path, volumeUUID: delegationVolume, inode: inode)
}

private func pairing(
    _ path: String = alphaPath, inode: UInt64 = alphaInode, references: [String] = [alphaReference],
    ssh: [PairedSSHUse] = [], id: String = UUID().uuidString.lowercased()
) -> ProjectPairing {
    ProjectPairing(id: id, project: projectKey(path, inode: inode), references: references, ssh: ssh)
}

private func ref(_ uri: String) -> SecretRef {
    // Every fixture URI is canonical; a typo is a test bug worth a crash.
    try! SecretRef(uri)
}

/// A synthetic process tree plus the matching `ProcessInspection`, so the
/// delegation walk and the Agent's grant scopes see the same processes.
private struct DelegationTree {
    typealias Process = SyntheticClaudeSessionFacts.Process
    var processes: [pid_t: Process] = [:]
    var names: [pid_t: String] = [:]
    var terminals: Set<pid_t> = []

    mutating func terminal(_ fish: pid_t) {
        processes[fish] = Process(startTime: UInt64(fish) * 10, parent: 1, executablePath: "/opt/homebrew/bin/fish")
        names[fish] = "fish"
        terminals.insert(fish)
    }

    /// A Claude Code session P: the foreground job of its terminal, fd 0
    /// the terminal, a clean argv and environment, genuine identity.
    mutating func session(
        _ agent: pid_t, start: UInt64? = nil, parent: pid_t, path: String = alphaPath, inode: UInt64 = alphaInode,
        environment: [SyntheticClaudeSessionFacts.EnvironmentEntry]? = nil,
        argv: [String]? = ["claude"],
        identity: ForeignCodeIdentity? = nil,
        job: ProcessJobFacts? = nil,
        standardInput: ProcessFileDescriptorKind? = .characterDevice(delegationTerminal),
        cwd: ProcessWorkingDirectory?? = nil,
        executablePath: String = "/synthetic/.local/share/claude/versions/2.1.280",
        name: String = "claude"
    ) {
        let start = start ?? UInt64(agent) * 10
        processes[agent] = Process(
            startTime: start, parent: parent,
            executablePath: executablePath,
            argv: argv,
            job: job ?? SyntheticClaudeSessionFacts.foregroundJob(
                pid: agent, parent: parent, startTime: start, terminal: delegationTerminal
            ),
            standardInput: standardInput,
            cwd: cwd ?? delegationCWD(path, inode: inode),
            environment: environment ?? [.init(name: "HOME", value: delegationHome), .init(name: "TERM", value: "xterm")],
            identity: identity ?? SyntheticClaudeSessionFacts.genuineClaudeIdentity(pid: agent, startTime: start),
            pidVersion: Int32(agent % 10_000)
        )
        names[agent] = name
    }

    /// X → A: the Bash tool's shell and the `csec ai` it runs. `command`
    /// may be a real process (its real start time is given).
    mutating func command(
        _ command: pid_t, start: UInt64? = nil, shell: pid_t, agent: pid_t, program: String,
        argv: [String]? = nil, shellPath: String = "/bin/zsh",
        environment: [SyntheticClaudeSessionFacts.EnvironmentEntry]? = []
    ) {
        processes[shell] = Process(
            startTime: UInt64(shell) * 10, parent: agent, executablePath: shellPath,
            argv: [shellPath, "-c", "-l", "eval"]
        )
        names[shell] = (shellPath as NSString).lastPathComponent
        processes[command] = Process(
            startTime: start ?? UInt64(command) * 10, parent: shell, executablePath: delegationCsecPath,
            argv: argv ?? [delegationCsecPath, "ai", "--"] + program.split(separator: " ").map(String.init),
            environment: environment
        )
        names[command] = "csec"
    }

    /// A as Claude Code's shell prefix: `csec ai --claude-code-shell
    /// <framing>` directly under P, since zsh execs the single command its
    /// `-c` names, so there is no tool shell between them.
    mutating func shellPrefix(_ command: pid_t, agent: pid_t, framing: String) {
        processes[command] = Process(
            startTime: UInt64(command) * 10, parent: agent, executablePath: delegationCsecPath,
            argv: [delegationCsecPath, "ai", ClaudeCodeShellPrefix.option, framing], environment: []
        )
        names[command] = "csec"
    }

    /// H → hook peer:`/bin/sh -c <program> csec-ai-hook <csec> claude` under
    /// P, and `csec hook claude` under it.
    mutating func hook(
        _ hookPeer: pid_t, shell hookShell: pid_t, agent: pid_t,
        shellPath: String = "/bin/bash", shellFlag: String = "-c",
        peerArgv: [String] = [delegationCsecPath, "hook", "claude"]
    ) {
        processes[hookShell] = Process(
            startTime: UInt64(hookShell) * 10, parent: agent, executablePath: shellPath,
            argv: ["/bin/sh", shellFlag, "program", "csec-ai-hook", delegationCsecPath, "claude"]
        )
        names[hookShell] = "bash"
        processes[hookPeer] = Process(
            startTime: UInt64(hookPeer) * 10, parent: hookShell, executablePath: delegationCsecPath,
            argv: peerArgv
        )
        names[hookPeer] = "csec"
    }

    func build() -> (SyntheticClaudeSessionFacts, ProcessInspection) {
        let facts = SyntheticClaudeSessionFacts(processes)
        let names = self.names
        let terminals = self.terminals
        let inspection = ProcessInspection(
            startTime: { facts.incarnation(of: $0)?.startTime },
            parent: { facts.parent(of: $0) },
            name: { names[$0] },
            executablePath: { pid in facts.incarnation(of: pid).flatMap { facts.executablePath(of: $0) } },
            hasControllingTerminal: { terminals.contains($0) }
        )
        return (facts, inspection)
    }
}

/// A settings gate the test sets: every evaluation returns `evaluation`, and
/// every scope it was asked about is kept.
final class FakeSettingsGate: ClaudeSettingsGate, @unchecked Sendable {
    static let clean = ClaudeSettingsGateEvaluation(
        classifyAllShell: ClaudeClassifyAllShellFinding(setIn: [delegationHome + "/.claude/settings.json"], ignoredIn: []),
        hooks: [], environment: [], sandboxEnabled: [], bypassPermissionsDefault: [], hooksDisabled: [], unreadable: []
    )

    private let lock = NSLock()
    private var current: ClaudeSettingsGateEvaluation
    private var discovered: [DiscoveredClaudeBuild]
    private var asked: [ClaudeSettingsScope] = []
    /// When set, answers each scope itself: a gate whose findings depend on
    /// what the scope reads (P's `--settings`, its `--add-dir` directories).
    private let byScope: (@Sendable (ClaudeSettingsScope) -> ClaudeSettingsGateEvaluation)?

    init(_ evaluation: ClaudeSettingsGateEvaluation = FakeSettingsGate.clean, builds: [DiscoveredClaudeBuild] = [],
         byScope: (@Sendable (ClaudeSettingsScope) -> ClaudeSettingsGateEvaluation)? = nil) {
        current = evaluation
        discovered = builds
        self.byScope = byScope
    }

    func set(_ evaluation: ClaudeSettingsGateEvaluation) {
        lock.lock()
        current = evaluation
        lock.unlock()
    }

    var scopes: [ClaudeSettingsScope] {
        lock.lock()
        defer { lock.unlock() }
        return asked
    }

    func evaluate(_ scope: ClaudeSettingsScope) -> ClaudeSettingsGateEvaluation {
        lock.lock()
        defer { lock.unlock() }
        asked.append(scope)
        return byScope?(scope) ?? current
    }

    func discoverBuilds(_ scope: ClaudeSettingsScope) -> ClaudeBuildDiscovery {
        lock.lock()
        defer { lock.unlock() }
        return ClaudeBuildDiscovery(builds: discovered, unreadable: [])
    }

    func userSettingsPath(_ scope: ClaudeSettingsScope) -> String {
        scope.userSettingsPath
    }

    func planEnable(_ scope: ClaudeSettingsScope) -> ClaudeSettingsEditPlan {
        ClaudeSettingsEditPlan(
            settingsPath: scope.userSettingsPath, classifyAllShell: .unchanged,
            environmentEntry: .unchanged, outcome: .nothingToChange
        )
    }

    func planRevert(
        _ scope: ClaudeSettingsScope, recordedSettingsPath: String?, csecAddedClassifyAllShell: Bool
    ) -> ClaudeSettingsEditPlan {
        planEnable(scope)
    }
}

private func evaluation(
    classifyAllShell: ClaudeClassifyAllShellFinding = FakeSettingsGate.clean.classifyAllShell,
    hooks: [ClaudeHookSource] = [],
    environment: [ClaudeSettingsEnvironmentFinding] = [],
    sandbox: [String] = [],
    bypass: [String] = [],
    disabled: [ClaudeHooksDisabledFinding] = [],
    unreadable: [ClaudeUnreadableSetting] = []
) -> ClaudeSettingsGateEvaluation {
    ClaudeSettingsGateEvaluation(
        classifyAllShell: classifyAllShell, hooks: hooks, environment: environment,
        sandboxEnabled: sandbox, bypassPermissionsDefault: bypass, hooksDisabled: disabled, unreadable: unreadable
    )
}

private func hookSource(_ display: String, digest: String) -> ClaudeHookSource {
    ClaudeHookSource(
        kind: .plugin, sourceID: "cc-caffeine@samber", event: "PreToolUse", matcher: "*",
        digest: digest, display: display, fetchesUnpinnedCode: false
    )
}

/// Records every bare Touch ID sheet's reason, and approves or refuses it.
final class DelegationSheetConsent: ConsentProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var approving: Bool
    private var recorded: [String] = []

    init(approving: Bool = true) {
        self.approving = approving
    }

    func approve(_ value: Bool) {
        lock.lock()
        approving = value
        lock.unlock()
    }

    var reasons: [String] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .approved(unlock: CacheUnlock(LAContext()))
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        let approved = lock.withLock {
            recorded.append(reason)
            return approving
        }
        return approved ? .approved(unlock: nil) : .denied
    }
}

/// A bare Touch ID sheet that ends the way the test sets (`ConsentAnswer`),
/// with the reason a real `BiometricConsent` would give.
final class DelegationExplainingSheetConsent: ConsentProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var next: ConsentAnswer

    init(_ answer: ConsentAnswer) {
        next = answer
    }

    func answer(_ answer: ConsentAnswer) {
        lock.withLock { next = answer }
    }

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        await authenticateExplaining(reason: reason).outcome
    }

    func authenticateExplaining(reason: String) async -> ConsentAnswer {
        lock.withLock { next }
    }
}

/// The delegation service's process clock for synthetic trees: each
/// registration arrives one tick after the last, and a process started after
/// everything so far unless the test pins its start.
final class DelegationTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var ticks: UInt64 = 1_000
    private var starts: [pid_t: UInt64] = [:]

    /// The tick the next event gets.
    var next: UInt64 { lock.withLock { ticks + 1 } }

    /// Pins `pid`'s start at the current tick: anything that arrives after
    /// this call arrived after the process started.
    func started(_ pid: pid_t) {
        lock.withLock {
            ticks += 1
            starts[pid] = ticks
        }
    }

    var processClock: DelegationProcessClock {
        DelegationProcessClock(
            now: { self.lock.withLock { self.ticks += 1; return self.ticks } },
            start: { process in self.lock.withLock { self.starts[process.pid] ?? (self.ticks + 1) } }
        )
    }
}

/// A bare Touch ID sheet that stays up until the test answers it, so a test
/// can run another configuration command while it is on screen.
final class DelegationHeldSheetConsent: ConsentProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ConsentOutcome, Never>?

    var isUp: Bool { lock.withLock { continuation != nil } }

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        await withCheckedContinuation { next in lock.withLock { continuation = next } }
    }

    func answer(_ approve: Bool) {
        let held = lock.withLock { () -> CheckedContinuation<ConsentOutcome, Never>? in
            defer { continuation = nil }
            return continuation
        }
        held?.resume(returning: approve ? .approved(unlock: nil) : .denied)
    }
}

/// A provider that holds some values unlocked. `resolve` answers everything
/// (a human approved); `resolveWithoutInteraction` only what is held. `warm`
/// (a restore touch) makes the listed references held.
actor HeldFixtureProvider: SecretProvider {
    nonisolated let schemes: Set<String>
    private let values: [String: Data]
    private var held: Set<String>
    private(set) var interactiveResolves = 0

    init(schemes: Set<String>, values: [String: Data], held: Set<String>) {
        self.schemes = schemes
        self.values = values
        self.held = held
    }

    /// References this provider says do not exist (`presence(of:)`).
    private var absent: Set<String> = []

    func hold(_ uri: String) { held.insert(uri) }
    func release(_ uri: String) { held.remove(uri) }
    func markAbsent(_ uri: String) { absent.insert(uri) }

    func presence(of ref: SecretRef) async -> ReferencePresence {
        absent.contains(ref.uri) ? .absent(reason: "the fixture has no such key") : .unknown
    }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        interactiveResolves += 1
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        held.insert(ref.uri)
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func resolveWithoutInteraction(_ ref: SecretRef) async -> ResolvedSecret? {
        guard held.contains(ref.uri), let value = values[ref.uri] else { return nil }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func requiresUnlockToResolve(_ ref: SecretRef) async -> Bool { !held.contains(ref.uri) }

    func warm(_ refs: [SecretRef], unlock: CacheUnlock) async {
        for ref in refs where values[ref.uri] != nil { held.insert(ref.uri) }
    }

    nonisolated func authenticate() async throws {}
    nonisolated func isAvailable() async -> Bool { true }
}

/// Stands in for 1Password: it serves anything, but never without
/// interaction, and needs no csec unlock, so a delegated release fetches a
/// value csecd does not hold from it. The count shows each fetch.
actor InteractiveOnlyProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["op"]
    private(set) var interactiveResolves = 0

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        interactiveResolves += 1
        return ResolvedSecret(value: Data("synthetic-interactive-\(ref.path)".utf8), cacheHint: .cacheable)
    }

    nonisolated func authenticate() async throws {}
    nonisolated func isAvailable() async -> Bool { true }
}

/// Stands in for 1Password when it cannot serve anything (locked, or the
/// person declined in its own app).
actor FailingOnePasswordProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["op"]
    private let error: (any Error)?

    /// `error`, or by default one that gives no reason of its own.
    init(error: (any Error)? = nil) { self.error = error }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        throw error ?? ProviderError.unsupportedScheme(ref.scheme)
    }

    nonisolated func authenticate() async throws {}
    nonisolated func isAvailable() async -> Bool { true }
}

/// Records every review and answers it as the test says.
actor DelegationReview: PolicyReviewProvider {
    enum Answer: Sendable {
        /// `lineShown` overrides whether the surface drew the pairing line;
        /// nil draws it as the Mac panel and the phone card do, exactly while
        /// the selection is the offer's.
        case approve(scope: GrantScopeKind?, durationIndex: Int?, surface: HumanDecisionSurface?, lineShown: Bool? = nil)
        case deny
    }

    private(set) var reviews: [AccessPolicyReview] = []
    private var answer: Answer

    init(_ answer: Answer = .deny) {
        self.answer = answer
    }

    func answer(_ next: Answer) { answer = next }

    var count: Int { reviews.count }
    var last: AccessPolicyReview? { reviews.last }
    var restoreOnly: [AccessPolicyReview] { reviews.filter(\.isRestoreOnly) }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews.append(review)
        switch answer {
        case .deny:
            return .denied(.human(decidedAt: .now, on: .mac))
        case let .approve(kind, index, surface, override):
            let selected = kind.flatMap { kind in review.scopeChoices?.options.first { $0.kind == kind }?.id }
            // As the Mac panel and the phone card draw it: the line shows
            // exactly while the selection is the offer's. A reviewer that is
            // no human surface shows nothing.
            let scope = selected ?? review.scopeChoices?.defaultOption.id
            let duration = review.durationChoices?.resolved(selectedIndex: index)
            let lineShown = override ?? (surface != nil
                && review.pairingOffer?.applies(scopeOptionID: scope, duration: duration) == true)
            return .approved(AccessPolicyApproval(
                selectedScopeOptionID: selected, selectedDurationIndex: index,
                pairingLineShown: lineShown, decidedOn: surface
            ))
        }
    }
}

/// A real, live process to stand in for a `csec ai` whose request must wait
/// for the consent turn (the queue re-reads its start time from the kernel).
private final class LiveCommand {
    let process: Process
    let pid: pid_t
    let start: UInt64

    init?() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["60"]
        guard (try? process.run()) != nil else { return nil }
        let pid = process.processIdentifier
        guard let start = ProcessAncestry.startTime(of: pid) else {
            process.terminate()
            return nil
        }
        self.process = process
        self.pid = pid
        self.start = start
    }

    var caller: CallerInfo { CallerInfo(pid: pid, startTime: start, description: "csec [verified] (synthetic ai)") }

    /// Never `waitUntilExit()`: in an async test it can lose its wakeup and
    /// hang the run (see `ChildProcessExit`). Nothing here needs the exit
    /// observed; Foundation reaps the child.
    func stop() {
        process.terminate()
    }
}

private func enableDelegation(
    _ stores: ProtectedStores,
    trusted: [TrustedClaudeBuild] = [],
    acknowledged: [AcknowledgedClaudeHook] = [],
    settingsPath: String? = delegationHome + "/.claude/settings.json",
    setClassifyAllShell: Bool = true
) async {
    let document = DelegationSettingsDocument(
        setClassifyAllShell: setClassifyAllShell, claudeSettingsPath: settingsPath,
        trustedBuilds: trusted, acknowledgedHooks: acknowledged
    )
    _ = try? await stores.store(for: DelegationSettingsDocument.self).prepare(document).commit()
}

private func seedPairings(_ stores: ProtectedStores, _ projects: [ProjectPairing]) async {
    _ = try? await stores.store(for: PairingDocument.self).prepare(PairingDocument(projects: projects)).commit()
}

private func storedPairings(_ stores: ProtectedStores) async -> [ProjectPairing]? {
    switch await stores.store(for: PairingDocument.self).load() {
    case .absent: return []
    case let .document(document): return document.projects
    case .unreadable: return nil
    }
}

private func storedSettings(_ stores: ProtectedStores) async -> DelegationSettingsDocument? {
    if case let .document(document) = await stores.store(for: DelegationSettingsDocument.self).load() {
        return document
    }
    return nil
}

private func makeService(
    _ facts: any ClaudeSessionFactProvider,
    stores: ProtectedStores? = .processLocal(),
    gate: any ClaudeSettingsGate = FakeSettingsGate(),
    consent: any ConsentProvider = DelegationSheetConsent(),
    log: DecisionLog? = nil,
    launcher: DelegationLauncherCheck = DelegationLauncherCheck { _ in true },
    inspector: ClaudeBuildInspector = ClaudeBuildInspector { _ in nil },
    buildVerification: ClaudeBuildVerification = delegationVerifiedBuilds,
    manifestStore: ReleaseManifestStore? = nil,
    uncheckedBuildSeen: (@Sendable () -> Void)? = nil,
    volumeUUID: @escaping @Sendable (String) -> String? = { _ in delegationVolume },
    factBound: Duration = ClaudeDelegationService.factBound,
    credentials: any ClaudeCredentialStore = FakeCredentialStore(),
    credentialBound: Duration = ClaudeDelegationService.credentialBound,
    policyVersion: Int = DelegationPolicy.currentVersion,
    clock: DelegationTestClock = DelegationTestClock(),
    allowUnverified: Bool = true,
    repositories: ProjectRepository.FileSystem = .empty,
    screenLocked: Bool = false,
    bootSession: String? = "boot-session-1"
) -> ClaudeDelegationService {
    ClaudeDelegationService(
        stores: stores, gate: gate, consent: consent, facts: facts, account: delegationAccount,
        decisionLog: log, terminalInspection: .unavailable, launcherCheck: launcher,
        buildInspector: inspector, buildVerification: buildVerification, manifestStore: manifestStore,
        uncheckedBuildSeen: uncheckedBuildSeen, volumeUUID: volumeUUID,
        isOnLocalMounts: { !$0.hasPrefix("/Volumes/remote") },
        repositories: repositories,
        factBound: factBound, credentialStore: credentials, credentialBound: credentialBound,
        policyVersion: policyVersion, processClock: clock.processClock,
        allowUnverifiedCallersForTesting: allowUnverified,
        screenLocked: { screenLocked },
        bootSessionUUID: bootSession
    )
}

/// The hook's registration of `command`: for a `csec ai`, the digest of the
/// program it launches; for an unwrapped git command, of the text as typed.
private func registration(
    _ command: String, mode: String = "auto", hookCWD: String = alphaPath, session: String = "session-1",
    unwrapped: Bool = false
) -> AgentCommandRegistration {
    AgentCommandRegistration(
        sessionID: session, toolUseID: "toolu_\(abs(command.hashValue % 100_000))", agentID: nil,
        permissionMode: mode, hookCWD: hookCWD,
        programSHA256: AICommandHook.programDigest(
            unwrapped ? command : AICommandHook.launchedProgram(forCommand: command)
        ),
        unwrapped: unwrapped
    )!
}

private func register(
    _ service: ClaudeDelegationService, _ command: String, peer: pid_t, mode: String = "auto",
    hookCWD: String = alphaPath, unwrapped: Bool = false
) async -> Bool {
    await service.register(
        registration(command, mode: mode, hookCWD: hookCWD, unwrapped: unwrapped),
        caller: CallerInfo(pid: peer, startTime: UInt64(peer) * 10, description: "csec hook claude")
    )
}

private func evaluate(
    _ service: ClaudeDelegationService, command: pid_t, start: UInt64? = nil, program: String,
    references: [String] = [alphaReference]
) async -> DelegationEvaluation {
    await service.evaluateRelease(
        caller: CallerInfo(pid: command, startTime: start ?? UInt64(command) * 10, description: "csec ai"),
        commandLine: AICommandExec.commandLine(forProgram: program),
        newReferences: references.map(ref)
    )
}

private func decline(_ evaluation: DelegationEvaluation) -> DelegationDecline? {
    if case let .declined(reason, _) = evaluation { return reason }
    return nil
}

private func isApproved(_ evaluation: DelegationEvaluation) -> Bool {
    if case .approved = evaluation { return true }
    return false
}

private func makeDelegationLog(_ stores: ProtectedStores) async -> DecisionLog {
    let log = DecisionLog(
        directory: SealedRecordDirectory(path: (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("csec-delegation-log-\(UUID().uuidString)")),
        stores: stores
    )
    _ = await log.open()
    return log
}

/// The standard passing world: fish → P(61_010) → X(61_011) → A(61_012), with
/// the hook H(61_013) → peer(61_014) under P.
private enum Standard {
    static let fish: pid_t = 61_000
    static let agent: pid_t = 61_010
    static let shell: pid_t = 61_011
    static let command: pid_t = 61_012
    static let hookShell: pid_t = 61_013
    static let hookPeer: pid_t = 61_014
    static let program = "echo hello"

    static func tree(program: String = Standard.program, _ adjust: (inout DelegationTree) -> Void = { _ in }) -> DelegationTree {
        var tree = DelegationTree()
        tree.terminal(fish)
        tree.session(agent, parent: fish)
        tree.command(command, shell: shell, agent: agent, program: program)
        tree.hook(hookPeer, shell: hookShell, agent: agent)
        adjust(&tree)
        return tree
    }
}

/// Evaluates one request in a world built from `adjust`, with delegation on,
/// alpha paired with the reference, and a registration for `registered`.
private func evaluateStandard(
    program: String = Standard.program,
    registered: String? = Standard.program,
    mode: String = "auto",
    pairings: [ProjectPairing] = [pairing()],
    trusted: [TrustedClaudeBuild] = [],
    acknowledged: [AcknowledgedClaudeHook] = [],
    gate: FakeSettingsGate = FakeSettingsGate(),
    buildVerification: ClaudeBuildVerification = delegationVerifiedBuilds,
    manifestStore: ReleaseManifestStore? = nil,
    uncheckedBuildSeen: DelegationEventCounter? = nil,
    references: [String] = [alphaReference],
    hookCWD: String = alphaPath,
    volumeKnown: Bool = true,
    repositories: ProjectRepository.FileSystem = .empty,
    credentials: any ClaudeCredentialStore = FakeCredentialStore(),
    credentialBound: Duration = ClaudeDelegationService.credentialBound,
    _ adjust: (inout DelegationTree) -> Void = { _ in }
) async -> DelegationEvaluation {
    let (facts, _) = Standard.tree(program: program, adjust).build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores, trusted: trusted, acknowledged: acknowledged)
    await seedPairings(stores, pairings)
    let service = makeService(
        facts, stores: stores, gate: gate, buildVerification: buildVerification, manifestStore: manifestStore,
        uncheckedBuildSeen: uncheckedBuildSeen.map { counter in { counter.increment() } },
        volumeUUID: { _ in volumeKnown ? delegationVolume : nil },
        credentials: credentials, credentialBound: credentialBound,
        repositories: repositories
    )
    if let registered {
        _ = await register(service, registered, peer: Standard.hookPeer, mode: mode, hookCWD: hookCWD)
    }
    return await evaluate(service, command: Standard.command, program: program, references: references)
}

// MARK: - csec as Claude Code's shell prefix (csec-0.83.1, av-e2sa)

/// Claude Code 2.1.319's Bash framing around `command`, as its builder writes
/// it with a snapshot and a shell prefix set.
func claudeFraming(_ command: String, cwdFile: String = "/var/folders/xy/abc/T/claude-1a2b-cwd") -> String {
    "source '/synthetic/.claude/shell-snapshots/snapshot-zsh-1.sh' 2>/dev/null || true"
        + " && { shopt -u extglob || setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL; } >/dev/null 2>&1 || true"
        + " && eval '" + command.replacingOccurrences(of: "'", with: "'\"'\"'") + "' < /dev/null"
        + " && pwd -P >| " + cwdFile
}

private func delegationShellPrefixTests() async {
    let command = "printf '%s' \"$TOKEN\" | wc -c"
    let framing = claudeFraming(command)

    /// P → csec ai --claude-code-shell <framing>: zsh ran the prefix by exec,
    /// so the `csec ai` is directly under P. `underShell` puts a shell back
    /// between them, which no prefix launch has.
    func world(_ argument: String, underShell: Bool = false,
               agentEnvironment: [SyntheticClaudeSessionFacts.EnvironmentEntry]? = nil) -> DelegationTree {
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        tree.session(Standard.agent, parent: Standard.fish, environment: agentEnvironment)
        tree.shellPrefix(Standard.command, agent: Standard.agent, framing: argument)
        if underShell {
            tree.processes[Standard.shell] = .init(
                startTime: UInt64(Standard.shell) * 10, parent: Standard.agent, executablePath: "/bin/zsh",
                argv: ["/bin/zsh", "-c", "x"])
            tree.names[Standard.shell] = "zsh"
            tree.processes[Standard.command]?.parent = Standard.shell
        }
        tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
        return tree
    }

    func release(_ tree: DelegationTree, program: String, registered: String?) async -> DelegationEvaluation {
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        if let registered {
            _ = await service.register(
                AgentCommandRegistration(
                    sessionID: "session-1", toolUseID: "toolu_prefix", agentID: nil, permissionMode: "auto",
                    hookCWD: alphaPath, programSHA256: AICommandHook.programDigest(registered), unwrapped: false)!,
                caller: CallerInfo(pid: Standard.hookPeer, startTime: UInt64(Standard.hookPeer) * 10,
                                   description: "csec hook claude"))
        }
        return await evaluate(service, command: Standard.command, program: program)
    }

    check(isApproved(await release(world(framing), program: framing, registered: command)),
          "shell prefix: a csec ai directly under P, its framing's eval naming the registered command, is released")
    check(!isApproved(await release(world(framing), program: framing, registered: "printf other")),
          "shell prefix: a registration of another command releases nothing")
    check(!isApproved(await release(world(framing), program: framing, registered: framing)),
          "shell prefix: a registration of the whole framing binds nothing (the hook registers the command)")
    check(!isApproved(await release(world(framing, underShell: true), program: framing, registered: command)),
          "shell prefix: with a shell between it and P, no Claude Code session stands above the csec ai")
    let twoEvals = framing.replacingOccurrences(of: " && eval '", with: " && eval 'true' && eval '")
    check(!isApproved(await release(world(twoEvals), program: twoEvals, registered: command)),
          "shell prefix: a framing with a second eval names no registered command")
    check(!isApproved(await release(world(framing), program: claudeFraming("printf other"), registered: command)),
          "shell prefix: a request naming another program than the peer's argv is not bound")
    let prefixed = await release(
        world(framing, agentEnvironment: [
            .init(name: "HOME", value: delegationHome),
            .init(name: ClaudeDelegationGateLists.shellPrefixName, value: "/tmp/other-prefix"),
        ]),
        program: framing, registered: command)
    check(decline(prefixed) == .injectedEnvironment(ClaudeDelegationGateLists.shellPrefixName),
          "shell prefix: a prefix other than csec's own in P's environment still declines (\(String(describing: decline(prefixed))))")
}

// MARK: - Why a not_registered decline found nothing (csec-0.98)

/// A refused or missed registration sends the hook nothing it shows, so the
/// decline record is where its cause can be read afterwards.
private func delegationMissingRegistrationTests() async {
    func declined(
        _ tree: DelegationTree = Standard.tree(), program: String = Standard.program,
        clock: DelegationTestClock = DelegationTestClock(),
        _ setup: (ClaudeDelegationService) async -> Void = { _ in }
    ) async -> (DelegationDecline?, DecisionLogRecord.Delegation?) {
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let log = await makeDelegationLog(stores)
        let service = makeService(facts, stores: stores, log: log, clock: clock)
        await setup(service)
        let outcome = await evaluate(service, command: Standard.command, program: program)
        let records = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records
        return (decline(outcome), records.last?.delegation)
    }

    let (none, noneRecord) = await declined()
    check(none == .notRegistered && noneRecord?.registration == "none_under_agent",
          "missing registration: with nothing registered under P the decline says none_under_agent (\(String(describing: noneRecord?.registration)))")

    let (other, otherRecord) = await declined { service in
        _ = await register(service, "echo other", peer: Standard.hookPeer)
    }
    check(other == .notRegistered && otherRecord?.registration == "no_match",
          "missing registration: registrations of other programs only say no_match (\(String(describing: otherRecord?.registration)))")

    let clock = DelegationTestClock()
    let (late, lateRecord) = await declined(clock: clock) { service in
        clock.started(Standard.command)
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
    }
    check(late == .notRegistered && lateRecord?.registration?.hasPrefix("late_by_") == true,
          "missing registration: this program's registration arriving after the csec ai started says late_by (\(String(describing: lateRecord?.registration)))")

    let unreadable = claudeFraming("printf x").replacingOccurrences(of: " && eval '", with: " && eval 'true' && eval '")
    var prefixTree = DelegationTree()
    prefixTree.terminal(Standard.fish)
    prefixTree.session(Standard.agent, parent: Standard.fish)
    prefixTree.shellPrefix(Standard.command, agent: Standard.agent, framing: unreadable)
    prefixTree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
    let (unread, unreadRecord) = await declined(prefixTree, program: unreadable) { service in
        _ = await register(service, "printf x", peer: Standard.hookPeer)
    }
    check(unread == .notRegistered && unreadRecord?.registration == "unreadable_command",
          "missing registration: a framing csec ai cannot read says unreadable_command (\(String(describing: unreadRecord?.registration)))")

    // The hook peer is not in the tree, so its chain does not verify: the
    // refusal is named on the decline that follows.
    let (refused, refusedRecord) = await declined { service in
        let accepted = await register(service, Standard.program, peer: 61_099)
        check(!accepted, "missing registration: a hook whose process chain does not verify is refused")
    }
    check(refused == .notRegistered
            && refusedRecord?.registration?.hasPrefix("none_under_agent; a registration was refused ") == true
            && refusedRecord?.registration?.hasSuffix("the hook's process chain did not verify (the hook may have exited)") == true,
          "missing registration: a recent refusal is named on the decline (\(String(describing: refusedRecord?.registration)))")

    let (_, approvedRecord) = await declined { service in
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
    }
    check(approvedRecord == nil, "missing registration: a bound registration records no decline")

    // csecd.log splits a late registration's wait (csec-a1t2): csecd's
    // identity check, the hook's own wait before sending (its check of csecd
    // waits on trustd), and csecd's queue. Ticks are milliseconds here.
    let timed = CallerInfo(
        pid: 4242, startTime: 1, description: "hook",
        acceptedAt: 1_000, identifiedAt: 1_010, requestReadAt: 2_200
    )
    let timing = ClaudeDelegationService.registrationTiming(
        caller: timed, arrivedAt: 2_205, now: 2_208, milliseconds: { $0 }
    )
    check(timing.hasPrefix("reached the delegation actor 1205 ms after the hook connected "
            + "(csecd's identity check 10 ms, then the hook's request arrived 1190 ms later, "
            + "then 5 ms to reach the actor), handled in 3 ms"),
          "registration timing: csecd.log names csecd's check, the hook's wait and csecd's queue (\(timing))")
    let unstamped = ClaudeDelegationService.registrationTiming(
        caller: CallerInfo(pid: 4242, startTime: 1, description: "hook", acceptedAt: 1_000),
        arrivedAt: 1_900, now: 1_900, milliseconds: { $0 }
    )
    check(unstamped.contains("identity check unknown") && unstamped.contains("arrived unknown later"),
          "registration timing: a missing stamp reads unknown, never a made-up span (\(unstamped))")

    let gaveUp = SocketServer.silentCloseNote(acceptedAt: 1_000, identifiedAt: 1_008, now: 3_000, milliseconds: { $0 })
    check(gaveUp == "a verified csec client closed without sending a request 2000 ms after it connected "
            + "(csecd's identity check took 8 ms); a csec hook that gives up before sending its registration ends like this",
          "silent close: a client that connects and gives up before sending is logged (\(String(describing: gaveUp)))")
    check(SocketServer.silentCloseNote(acceptedAt: 1_000, identifiedAt: 1_008, now: 1_500, milliseconds: { $0 }) == nil,
          "silent close: a quick close is not logged")
}

// MARK: - Suite

func claudeDelegationTests() async {
    print("\n# Delegated approvals: csecd's delegation service")
    delegationCopyTests()
    delegationDocumentTests()
    await delegationRegistrationTests()
    await delegationEvaluatorTests()
    await delegationReleaseGateTests()
    await delegationSignedBuildListTests()
    await delegationGateOrderTests()
    claudeGatewaySignInTests()
    await delegationGatewaySignInGateTests()
    await delegationShellSteeringTests()
    await delegationShellPrefixTests()
    await delegationMissingRegistrationTests()
    await delegationConfigChangeTests()
    await delegationFactBoundTests()
    await delegationAgentTests()
    await delegationNestedRequestTests()
    await delegationDaemonUsePairingTests()
    await delegationPullRequestLookupTests()
    await delegationClosedIssuesCheckTests()
    await delegationPairingRuleTests()
    await delegationPhonePairingTests()
    await delegationPairingStoreTests()
    await delegationHeldPairingTests()
    await delegationLauncherStorageTests()
    projectRepositoryTests()
    await delegationRepositoryPairingTests()
    await delegationRevocationTests()
    await delegationUnpairEverywhereTests()
    await delegationConfigurationTests()
    await delegationBackendNeutralityTests()
    await delegationSSHTests()
    sudoDelegationRuleTests()
    await delegationSudoTests()
    await delegationRestoreTests()
    await delegationRestoreFetchAheadTests()
    await delegationRestoreRejudgeTests()
    await delegationUnrestorableTests()
    await delegationIdentityLookupTests()
    await delegationUninstallTests()
    await delegationRestoreDenyTests()
    await delegationClassifierRuleTests()
    await delegationChangedRulesTests()
    await delegationChangedHooksTests()
    await delegationRegistrationRestartTests()
    await delegationSharedAccountTests()
}

// MARK: - Copy and documents

private func delegationCopyTests() {
    check(DelegationDecline.notApprovedForProject(reference: "csec://alpha/TOKEN", project: "alpha").panelText
            == "Auto mode didn't approve this: csec://alpha/TOKEN hasn't been approved for alpha.",
          "delegation: .notApprovedForProject reads \"<ref> hasn't been approved for <project>\" (no \"since csecd started\")")
    check(DelegationPairingOffer(projectName: "alpha", scopeOptionID: "s").line
            == "Approving also lets Claude Code auto mode use these in alpha until you revoke them",
          "delegation: the pairing line names the project its references pair with")
    check(DelegationDecline.notAutoMode("default").panelText
            == "Auto mode didn't approve this: Claude Code was in manual mode.",
          "delegation: .notAutoMode names default mode as Claude Code shows it, manual mode")
    let modeNames = [("plan", "plan"), ("acceptEdits", "accept edits"), ("dontAsk", "don't ask"),
                     ("bypassPermissions", "bypass permissions"), ("laterMode", "laterMode")]
    for (mode, shown) in modeNames {
        check(DelegationDecline.notAutoMode(mode).reason == "Claude Code was in \(shown) mode.",
              "delegation: .notAutoMode(\(mode)) reads \"\(shown) mode\", Claude Code's own name for it")
    }
    check(DelegationDecline.notRegistered.panelText
            == "Auto mode didn't approve this: csec's Claude Code hook didn't register this command.",
          "delegation: .notRegistered copy")
    check(DelegationDecline.commandMismatch(process: "sudo").panelText
            == "Auto mode didn't approve this: sudo doesn't match the command auto mode approved.",
          "delegation: .commandMismatch names the process")
    check(DelegationDecline.environmentSteering(process: "the command's shell", name: "ZDOTDIR").panelText
            == "Auto mode didn't approve this: the command's shell was started with ZDOTDIR set.",
          "delegation: .environmentSteering names the process and the variable")
    check(DelegationDecline.otherHook("tee · ConfigChange *", blocksReload: true).panelText
            == "Auto mode didn't approve this: tee · ConfigChange * can keep Claude Code from reloading its hooks — review it with csec setup auto-mode."
            && DelegationDecline.otherHook("tee · PreToolUse *").panelText.contains("can approve shell commands"),
          "delegation: a ConfigChange hook's note says it can keep Claude Code from reloading its hooks, not that it approves")
    let hostile = DelegationDecline.otherHook("evil\u{202E}hook\nline")
    check(!hostile.panelText.unicodeScalars.contains { $0.value == 0x202E || $0 == "\n" },
          "delegation: a note's parameters are sanitized (no bidi override, no newline)")
    let long = DelegationDecline.settingsUnreadable(String(repeating: "/x", count: 2_000))
    check(long.statusText.utf8.count <= DelegationStatus.maximumLastDeclineBytes,
          "delegation: the status's lastDecline stays within its wire bound")
    let all: [DelegationDecline] = [
        .notRegistered, .notAutoMode("plan"), .notInteractive, .launchOption("--print"),
        .injectedEnvironment("DYLD_*"), .environmentUnreadable, .homeMismatch, .configDirectoryUnusable,
        .unverifiedBuild("2.1.257"), .uncheckedBuild("new release"), .projectNotLocal, .projectUnavailable, .factsUnavailable,
        .settingsUnreadable("/p"), .settingsEnvironment(name: "ANTHROPIC_BASE_URL", path: "/p"),
        .allowRulesActive, .otherHook("h"), .classifierRules("c"), .sandboxAutoAllow("/p"), .bypassReachable("/p"),
        .hooksDisabled(setting: "disableAllHooks", path: "/p"), .gatewaySignIn, .gatewaySignInUnchecked,
        .notApprovedForProject(reference: "r", project: "p"), .notHeld("r"), .oneTimeCode("r"),
        .lastingAccess("POST api.github.com/user/keys"), .agentOwnCommand("gh issue list"), .commandMismatch(process: "sudo"),
        .environmentSteering(process: "the command's shell", name: "ZDOTDIR"),
        .sudoIndirect("node"), .sudoOption("-E"), .sudoNotApproved(project: "p"),
    ]
    check(Set(all.map(\.code)).count == all.count && all.allSatisfy { $0.panelText.hasPrefix("Auto mode didn't approve this: ") },
          "delegation: every decline has its own code and the panel's prefix")
    check(DelegationDecline.notHeld("r", reason: "1Password is locked").panelText
            == "Auto mode didn't approve this: r couldn't be fetched without you: 1Password is locked."
            && DelegationDecline.notHeld("r").panelText == "Auto mode didn't approve this: r isn't unlocked in csecd yet.",
          "delegation: .notHeld names the provider's reason when it gave one")

    // The pairing line for a decline pairing can't end (csec-tcbq): every
    // gate the session as a whole fails says when the pairing starts to
    // count; a reason belonging to the one request, or the pairing itself,
    // keeps "until you revoke".
    let sessionLevel: Set<String> = [
        "not_interactive", "launch_option", "injected_environment", "environment_unreadable", "home_mismatch",
        "config_directory_unusable", "unverified_build", "unchecked_build", "project_not_local", "project_unavailable",
        "settings_unreadable", "settings_environment", "allow_rules_active", "other_hook", "classifier_rules",
        "sandbox_auto_allow", "bypass_reachable", "hooks_disabled", "gateway_sign_in", "gateway_sign_in_unchecked",
    ]
    let conditioned = all.filter { $0.pairingCondition != nil }
    check(Set(conditioned.map(\.code)) == sessionLevel
            && conditioned.allSatisfy { $0.pairingCondition!.hasPrefix("once ") },
          "pairing line: exactly the session-level declines carry a \"once …\" condition (\(conditioned.map(\.code)))")
    let launchSudo = SudoPairingOffer(
        projectName: "harbor", condition: DelegationDecline.launchOption("--settings").pairingCondition
    )
    check(launchSudo.line == "Approving also lets Claude Code auto mode run sudo in harbor once Claude Code is started without --settings",
          "pairing line: a sudo declined on --settings says the pairing counts once Claude Code is started without it")
    check(DelegationPairingOffer(projectName: "alpha", scopeOptionID: "s",
                                 condition: DelegationDecline.injectedEnvironment("NODE_EXTRA_CA_CERTS").pairingCondition).line
            == "Approving also lets Claude Code auto mode use these in alpha once Claude Code is started without NODE_EXTRA_CA_CERTS set"
            && DelegationPairingOffer(projectName: "alpha", scopeOptionID: "s", everyProject: true,
                                      condition: DelegationDecline.allowRulesActive.pairingCondition).line
            == "Approving also lets Claude Code auto mode use these, inside csec, in every project once you run csec setup auto-mode",
          "pairing line: a secret panel's line, per project or for csecd's use, takes the same condition")
    let longest = all.compactMap(\.pairingCondition).max { $0.utf8.count < $1.utf8.count } ?? ""
    let longSudo = SudoPairingOffer(projectName: String(repeating: "p", count: 400), condition: longest + String(repeating: "x", count: 400))
    check(longSudo.line.utf8.count <= SudoDelegationAnswer.maximumPairingLineBytes
            && SudoPairingOffer(projectName: "p", condition: "once evil\u{202E}x").line.unicodeScalars.allSatisfy { $0.value != 0x202E },
          "pairing line: a conditioned sudo line stays within the helper's bound, sanitized")

    // A hook only P's launch brings in, which csec setup can't see (csec-0.4
    // F3): the note names the launch, not setup, and asks for no setup.
    let launchHook = DelegationDecline.otherHook("cc-caffeine@samber · PreToolUse *", launch: "--settings")
    check(launchHook.panelText == "Auto mode didn't approve this: cc-caffeine@samber · PreToolUse * can approve shell commands "
            + "and comes from Claude Code's --settings, which csec setup can't see — start Claude Code without it."
            && !launchHook.needsSetup && launchHook.setupNotice == nil && launchHook.isUnacknowledgedSettings
            && launchHook.code == "other_hook"
            && launchHook.pairingCondition == "once Claude Code is started without the --settings that bring in that hook"
            && DelegationDecline.otherHook("h").needsSetup,
          "delegation: a launch-only hook's note names the launch option, needs no setup, and still takes the one-touch panel")
}

private func delegationDocumentTests() {
    let good = DelegationSettingsDocument(setClassifyAllShell: true, claudeSettingsPath: delegationHome + "/.claude/settings.json")
    check(good.isWellFormed, "delegation settings: a Claude opt-in with a recorded settings path is well formed")
    check(!DelegationSettingsDocument(clients: [.codex]).isWellFormed,
          "delegation settings: Codex can never be a delegated client")
    check(!DelegationSettingsDocument(setClassifyAllShell: true, claudeSettingsPath: nil).isWellFormed,
          "delegation settings: setClassifyAllShell needs the file it was set in")
    let build = TrustedClaudeBuild(cdHash: String(repeating: "b", count: 40), versionLabel: "2.1.257", path: "/b", trustedAt: Date())
    check(!DelegationSettingsDocument(trustedBuilds: Array(repeating: build, count: 2)).isWellFormed
            && !DelegationSettingsDocument(trustedBuilds: (0..<33).map {
                TrustedClaudeBuild(cdHash: String(format: "%040x", $0), versionLabel: "v", path: "/b", trustedAt: Date())
            }).isWellFormed,
          "delegation settings: at most 32 trusted builds, none twice")
    check(!DelegationSettingsDocument(trustedBuilds: [
        TrustedClaudeBuild(cdHash: String(repeating: "B", count: 40), versionLabel: "v", path: "/b", trustedAt: Date()),
    ]).isWellFormed, "delegation settings: a trusted cdhash is 40 lowercase hex")
    check(pairing().isWellFormed && PairingDocument(projects: [pairing(), pairing(betaPath, inode: betaInode)]).isWellFormed,
          "pairing: a project pairing and a document of two are well formed")
    check(!PairingDocument(projects: [pairing(), pairing()]).isWellFormed,
          "pairing: one project is paired at most once")
    check(!pairing(references: ["not a reference"]).isWellFormed,
          "pairing: only canonical references are paired")
    check(!ProjectKey(path: alphaPath, volumeUUID: delegationVolume.lowercased(), inode: 1).isWellFormed
            && !ProjectKey(path: "relative", volumeUUID: delegationVolume, inode: 1).isWellFormed,
          "pairing: a project key is an absolute path, a canonical volume UUID and an inode")
    check(!PairingDocument(projects: (0..<257).map { pairing("/p/\($0)", inode: UInt64($0 + 1)) }).isWellFormed,
          "pairing: at most 256 projects")
    let beforeFork = DelegationProcessClock.live.now()
    if let child = LiveCommand() {
        let afterFork = DelegationProcessClock.live.now()
        let start = DelegationProcessClock.live.start(ProcessIncarnation(pid: child.pid, startTime: child.start))
        let stale = DelegationProcessClock.live.start(ProcessIncarnation(pid: child.pid, startTime: child.start + 1))
        child.stop()
        check(start.map { beforeFork < $0 && $0 < afterFork } == true && stale == nil,
              "delegation clock: a live process's start reads on the clock registrations arrive on, and only for its own incarnation")
    } else {
        check(false, "delegation clock: a live child starts")
    }
    let rootVolume = VolumeIdentity.uuid(ofMountPoint: "/")
    check(rootVolume.flatMap(UUID.init(uuidString:))?.uuidString == rootVolume,
          "pairing: the live volume UUID lookup answers for / with a canonical UUID")
    check(VolumeIdentity.uuid(ofMountPoint: "/nonexistent-\(UUID().uuidString)") == nil,
          "pairing: a missing mount has no volume UUID")
    check(ClaudeDelegationService.addedDirectories(inArgv: ["claude", "--add-dir", "a", "/b", "--model", "x", "--add-dir=c"])
            == ["a", "/b", "c"],
          "delegation: --add-dir is variadic up to the next option, and --add-dir=x names one")
    check(ClaudeDelegationService.addedDirectories(inArgv: ["claude", "--add-dir=\u{301}x", "--add-dir", "y", "-\u{301}"])
            == ["\u{301}x", "y"],
          "delegation: --add-dir=<combining mark>x names a directory, split by code unit as commander does")

    // The pairing line shows exactly while the selection would pair.
    let offer = DelegationPairingOffer(projectName: "alpha", scopeOptionID: "coding_agent-1-2")
    check(offer.applies(scopeOptionID: "coding_agent-1-2", duration: .processLifetime)
            && !offer.applies(scopeOptionID: "requesting_command-3-4", duration: .processLifetime)
            && !offer.applies(scopeOptionID: "terminal_session-5-6", duration: .processLifetime)
            && !offer.applies(scopeOptionID: "coding_agent-1-2", duration: .bounded(seconds: 3_600))
            && !offer.applies(scopeOptionID: "coding_agent-1-2", duration: nil)
            && !offer.applies(scopeOptionID: nil, duration: .processLifetime),
          "pairing line: shown only for the default Claude Code scope with the process lifetime")
    check(offer.line == "Approving also lets Claude Code auto mode use these in alpha until you revoke them"
            && DelegationPairingOffer(projectName: "evil\u{202E}name", scopeOptionID: "x").line.unicodeScalars
                .allSatisfy { $0.value != 0x202E },
          "pairing line: the plan's copy, with the project name sanitized")
    let caller = CallerInfo(pid: 1, startTime: 1, description: "fixture")
    let plan = DeliveryPlan(
        mechanism: .directHeap, executable: PlannedExecutable(canonicalPath: "/bin/echo", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: nil, operationContext: "fixture"
    )
    let restoreOnly = AccessPolicyReview(
        caller: caller, reason: "r", plan: plan, credentials: [],
        restore: RestoreReviewDetails(cause: .restart, rows: [], storeCount: 1),
        delegationNote: .notHeld("r"), pairingOffer: offer
    )
    let mixed = AccessPolicyReview(
        caller: caller, reason: "r", plan: plan, credentials: [PolicyReviewCredential(references: [ref(alphaReference)])],
        restore: RestoreReviewDetails(cause: .restart, rows: [], storeCount: 1),
        delegationNote: .notHeld("r"), pairingOffer: offer
    )
    check(restoreOnly.delegationNote == nil && restoreOnly.pairingOffer == nil
            && mixed.delegationNote == .notHeld("r") && mixed.pairingOffer == offer,
          "review: a restore-only panel never carries the note or the pairing line; a mixed panel does")
}

// MARK: - Registration

private func delegationRegistrationTests() async {
    do {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        check(await register(service, Standard.program, peer: Standard.hookPeer),
              "registration: csecd stores a registration from csec hook claude under a shell's -c under P")
        check(isApproved(await evaluate(service, command: Standard.command, program: Standard.program)),
              "registration: the stored registration is what the matching csec ai consumes")
        check(await register(service, "ls", peer: Standard.hookPeer, mode: "default"),
              "registration: a registration from any permission mode is accepted and stored")
    }
    do {
        let (facts, _) = Standard.tree().build()
        let service = makeService(facts)
        check(!(await register(service, Standard.program, peer: Standard.hookPeer)),
              "registration: with delegation off nothing is stored")
    }
    func refused(_ label: String, allowUnverified: Bool = true, _ adjust: (inout DelegationTree) -> Void) async {
        let (facts, _) = Standard.tree(adjust).build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        let service = makeService(facts, stores: stores, allowUnverified: allowUnverified)
        check(!(await register(service, Standard.program, peer: Standard.hookPeer)), "registration: \(label)")
    }
    await refused("a peer that is not a verified launcher is refused", allowUnverified: false) { _ in }
    await refused("a peer whose argv is not exactly `csec hook claude` is refused") {
        $0.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent,
                peerArgv: [delegationCsecPath, "hook", "codex"])
    }
    await refused("a peer with an extra argument is refused") {
        $0.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent,
                peerArgv: [delegationCsecPath, "hook", "claude", "extra"])
    }
    await refused("a hook parent that is not an Apple platform shell is refused") {
        $0.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent, shellPath: "/opt/homebrew/bin/bash")
    }
    await refused("a hook shell not run with -c is refused") {
        $0.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent, shellFlag: "-lc")
    }
    do {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        let service = makeService(facts, stores: stores)
        facts.onParentRead { tree, pid, count in
            // The hook shell's parent changes between the walk's reads.
            if pid == Standard.hookShell, count == 1 {
                tree.mutate { $0[Standard.hookShell]?.parent = 1 }
            }
        }
        check(!(await register(service, Standard.program, peer: Standard.hookPeer)),
              "registration: a chain that changes between reads is refused")
    }
    // Bounds: 64 Claude Code processes, 256 pending registrations each.
    do {
        var tree = DelegationTree()
        tree.terminal(62_000)
        for index in 0..<65 {
            let agent = pid_t(62_100 + index * 4)
            tree.session(agent, parent: 62_000)
            tree.hook(agent + 2, shell: agent + 1, agent: agent)
        }
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        let service = makeService(facts, stores: stores)
        var accepted = 0
        for index in 0..<64 {
            if await register(service, "ls", peer: pid_t(62_100 + index * 4 + 2)) { accepted += 1 }
        }
        let sixtyFifth = await register(service, "ls", peer: pid_t(62_100 + 64 * 4 + 2))
        check(accepted == 64 && !sixtyFifth,
              "registration: at most 64 Claude Code processes hold registrations; a full table only declines")
    }
    do {
        let (facts, _) = Standard.tree(program: "echo 256").build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        for index in 0...256 { _ = await register(service, "echo \(index)", peer: Standard.hookPeer) }
        let newest = await evaluate(service, command: Standard.command, program: "echo 256")
        check(isApproved(newest), "registration: the newest of 257 pending registrations is kept")
        let (zeroFacts, _) = Standard.tree(program: "echo 0").build()
        let zeroStores = ProtectedStores.processLocal()
        await enableDelegation(zeroStores)
        await seedPairings(zeroStores, [pairing()])
        let zeroService = makeService(zeroFacts, stores: zeroStores)
        for index in 0...256 { _ = await register(zeroService, "echo \(index)", peer: Standard.hookPeer) }
        check(decline(await evaluate(zeroService, command: Standard.command, program: "echo 0")) == .notRegistered,
              "registration: past 256 pending registrations for one P the oldest pending one is evicted")
    }
}

// MARK: - The evaluator

private func delegationEvaluatorTests() async {
    let approved = await evaluateStandard()
    if case let .approved(ticket) = approved {
        check(ticket.session.agent == ProcessIncarnation(pid: Standard.agent, startTime: UInt64(Standard.agent) * 10)
                && ticket.project == projectKey() && ticket.command.pid == Standard.command,
              "evaluator: the positive chain A → zsh → P, registered, verified, paired and settled approves")
    } else {
        check(false, "evaluator: the positive chain approves (got \(approved))")
    }
    check(isApproved(await evaluateStandard(program: "echo hello", registered: "echo  hello")),
          "evaluator: a registration of \"echo  hello\" matches csec ai's rejoined \"echo hello\"")
    check(decline(await evaluateStandard(registered: "echo other")) == .notRegistered,
          "evaluator: a registration of another program declines .notRegistered")
    check(decline(await evaluateStandard(registered: nil)) == .notRegistered,
          "evaluator: no registration declines .notRegistered for a Claude Code P")

    // A registration from a different P, and the same pid with a new start.
    do {
        var tree = Standard.tree()
        tree.session(61_110, parent: Standard.fish)
        tree.hook(61_112, shell: 61_111, agent: 61_110)
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        _ = await register(service, Standard.program, peer: 61_112)
        check(decline(await evaluate(service, command: Standard.command, program: Standard.program)) == .notRegistered,
              "evaluator: a registration from a different Claude Code process does not match")
    }
    do {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        // P exits and its pid is reused by another Claude Code process.
        facts.mutate { tree in
            let reused = UInt64(Standard.agent) * 10 + 7
            tree[Standard.agent]?.startTime = reused
            tree[Standard.agent]?.job = SyntheticClaudeSessionFacts.foregroundJob(
                pid: Standard.agent, parent: Standard.fish, startTime: reused, terminal: delegationTerminal
            )
            tree[Standard.agent]?.identity = SyntheticClaudeSessionFacts.genuineClaudeIdentity(
                pid: Standard.agent, startTime: reused
            )
        }
        check(decline(await evaluate(service, command: Standard.command, program: Standard.program)) == .notRegistered,
              "evaluator: a registration of a P whose pid was reused never matches the new process")
    }
    // One registration, two csec ai: the second finds nothing; the first,
    // judged again after a wait, still holds it.
    do {
        var tree = Standard.tree()
        tree.command(61_022, shell: 61_021, agent: Standard.agent, program: Standard.program)
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        let first = await evaluate(service, command: Standard.command, program: Standard.program)
        let second = await evaluate(service, command: 61_022, program: Standard.program)
        let again = await evaluate(service, command: Standard.command, program: Standard.program)
        check(isApproved(first) && decline(second) == .notRegistered && isApproved(again),
              "evaluator: a registration is consumed once; a second csec ai with the same program declines, the bound one may be judged again")
    }
    // The newest pending registration is the run in progress. An older one
    // of the same program is a call that never ran (blocked, refused or
    // interrupted), and its mode is never lent to a later identical run.
    for mode in ["default", "acceptEdits", "plan", "dontAsk"] {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        _ = await register(service, Standard.program, peer: Standard.hookPeer, mode: "auto")
        _ = await register(service, Standard.program, peer: Standard.hookPeer, mode: mode)
        check(decline(await evaluate(service, command: Standard.command, program: Standard.program)) == .notAutoMode(mode),
              "evaluator: a stale auto registration never approves a later identical run in \(mode) (.notAutoMode(\(mode)))")
    }
    do {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        _ = await register(service, Standard.program, peer: Standard.hookPeer, mode: "default")
        _ = await register(service, Standard.program, peer: Standard.hookPeer, mode: "auto")
        check(isApproved(await evaluate(service, command: Standard.command, program: Standard.program)),
              "evaluator: a stale default registration never stops a later identical run in auto")
    }
    // A registration that arrived after the csec ai started belongs to a
    // later call: a csec ai whose own registration never reached csecd
    // declines .notRegistered rather than bind it, and the later call's own
    // csec ai (started after it) binds it.
    do {
        var tree = Standard.tree()
        tree.command(61_022, shell: 61_021, agent: Standard.agent, program: Standard.program)
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let clock = DelegationTestClock()
        let service = makeService(facts, stores: stores, clock: clock)
        clock.started(Standard.command)
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        let lost = await evaluate(service, command: Standard.command, program: Standard.program)
        let later = await evaluate(service, command: 61_022, program: Standard.program)
        check(decline(lost) == .notRegistered && isApproved(later),
              "evaluator: a csec ai never binds a registration that arrived after it started (.notRegistered); the later call's own csec ai does")
    }
    // The ordinary order still binds: the newest registration from before
    // the csec ai started, never one that arrived after.
    do {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let clock = DelegationTestClock()
        let service = makeService(facts, stores: stores, clock: clock)
        _ = await register(service, Standard.program, peer: Standard.hookPeer, mode: "auto")
        clock.started(Standard.command)
        _ = await register(service, Standard.program, peer: Standard.hookPeer, mode: "default")
        check(isApproved(await evaluate(service, command: Standard.command, program: Standard.program)),
              "evaluator: a csec ai binds the newest registration that arrived before it started, not a newer one")
    }
    do {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let unreadable = DelegationTestClock()
        let service = ClaudeDelegationService(
            stores: stores, gate: FakeSettingsGate(), consent: DelegationSheetConsent(), facts: facts,
            account: delegationAccount, terminalInspection: .unavailable, launcherCheck: DelegationLauncherCheck { _ in true },
            buildInspector: ClaudeBuildInspector { _ in nil }, buildVerification: delegationVerifiedBuilds,
            volumeUUID: { _ in delegationVolume },
            isOnLocalMounts: { _ in true },
            credentialStore: FakeCredentialStore(),
            processClock: DelegationProcessClock(now: unreadable.processClock.now, start: { _ in nil }),
            allowUnverifiedCallersForTesting: true
        )
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        check(decline(await evaluate(service, command: Standard.command, program: Standard.program)) == .notRegistered,
              "evaluator: a csec ai whose start cannot be read binds no registration")
    }
    // Parallel identical calls in one mode: each csec ai binds one of them.
    do {
        var tree = Standard.tree()
        tree.command(61_022, shell: 61_021, agent: Standard.agent, program: Standard.program)
        tree.command(61_032, shell: 61_031, agent: Standard.agent, program: Standard.program)
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        let first = await evaluate(service, command: Standard.command, program: Standard.program)
        let second = await evaluate(service, command: 61_022, program: Standard.program)
        let third = await evaluate(service, command: 61_032, program: Standard.program)
        check(isApproved(first) && isApproved(second) && decline(third) == .notRegistered,
              "evaluator: two parallel identical registrations in one mode serve one csec ai each; a third finds none")
    }
    do {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        facts.onParentRead { tree, pid, count in
            if pid == Standard.shell, count == 1 { tree.mutate { $0[Standard.shell]?.parent = 1 } }
        }
        check(await evaluate(service, command: Standard.command, program: Standard.program) == .notApplicable,
              "evaluator: a chain that changes between reads never reaches P")
    }
    check(decline(await evaluateStandard {
        $0.command(Standard.command, shell: Standard.shell, agent: Standard.agent, program: Standard.program,
                   argv: [delegationCsecPath, "tool-exec", "--", "echo", "hello"])
    }) == .notRegistered, "evaluator: csec tool-exec (argv[1] is not ai) never consumes a registration")
    check(decline(await evaluateStandard(program: "echo \u{037E}", registered: "echo \u{037E}") {
        $0.command(Standard.command, shell: Standard.shell, agent: Standard.agent, program: "echo \u{037E}",
                   argv: [delegationCsecPath, "ai", "--", "echo", ";"])
    }) == .notRegistered, "evaluator: the kernel argv is compared byte for byte (U+037E is not ';')")
    check(await evaluateStandard {
        $0.command(Standard.command, shell: Standard.shell, agent: Standard.agent, program: Standard.program,
                   shellPath: "/usr/bin/python3")
    } == .notApplicable, "evaluator: a csec ai whose parent is not a shell has no P: no note")
    check(await evaluateStandard(registered: nil) {
        $0.session(Standard.agent, parent: Standard.fish,
                   identity: codexIdentity(pid: Standard.agent), executablePath: "/opt/homebrew/bin/codex", name: "codex")
    } == .notApplicable, "evaluator: a Codex P (no registration, not Claude Code) gets no note")

    // Identity: Anthropic's requirement, or a trusted cdhash.
    let patched = String(repeating: "c", count: 40)
    let patchedIdentity: (inout DelegationTree) -> Void = {
        $0.session(Standard.agent, parent: Standard.fish,
                   identity: patchedClaudeIdentity(pid: Standard.agent, cdHash: patched),
                   executablePath: "/synthetic/.local/share/claude/versions/2.1.257")
    }
    check(decline(await evaluateStandard(patchedIdentity)) == .unverifiedBuild("2.1.257"),
          "evaluator: a build neither signed by Anthropic nor trusted declines .unverifiedBuild")
    check(isApproved(await evaluateStandard(
        trusted: [TrustedClaudeBuild(cdHash: patched, versionLabel: "2.1.257", path: "/b", trustedAt: Date())],
        patchedIdentity
    )), "evaluator: a build trusted by its cdhash delegates")

    // G3.
    func job(pgid: pid_t = Standard.agent, tpgid: pid_t = Standard.agent, controlling: Bool = true) -> ProcessJobFacts {
        ProcessJobFacts(
            pid: Standard.agent, parent: Standard.fish, processGroup: pgid, terminalProcessGroup: tpgid,
            terminalDevice: delegationTerminal, hasControllingTerminal: controlling,
            effectiveUID: getuid(), startTime: UInt64(Standard.agent) * 10
        )
    }
    for (label, facts, input) in [
        ("no controlling terminal", job(controlling: false), ProcessFileDescriptorKind.characterDevice(delegationTerminal)),
        ("pgid != pid", job(pgid: 1_234), .characterDevice(delegationTerminal)),
        ("tpgid != pgid", job(tpgid: 1_234), .characterDevice(delegationTerminal)),
        ("fd 0 a socket", job(), .other),
        ("fd 0 /dev/null", job(), .characterDevice(0x0300_0002)),
    ] {
        check(decline(await evaluateStandard {
            $0.session(Standard.agent, parent: Standard.fish, job: facts, standardInput: input)
        }) == .notInteractive, "evaluator G3: \(label) declines .notInteractive")
    }

    // G4: every listed launch option, bare and with a value.
    var launchDeclines = 0
    for option in ClaudeDelegationGateLists.launchOptions {
        for argv in [["claude", option], ["claude", option + "=value"]] {
            let result = await evaluateStandard { $0.session(Standard.agent, parent: Standard.fish, argv: argv) }
            if decline(result) == .launchOption(option) { launchDeclines += 1 }
        }
    }
    check(launchDeclines == ClaudeDelegationGateLists.launchOptions.count * 2,
          "evaluator G4: every launch option declines bare and as --flag=value (\(launchDeclines))")
    check(decline(await evaluateStandard { $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "-pc"]) })
            == .launchOption("-p"),
          "evaluator G4: -p inside a -pc cluster declines")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--permission-mode", "bypassPermissions"])
    }) == .launchOption("--permission-mode bypassPermissions"),
          "evaluator G4: --permission-mode bypassPermissions declines")
    check(isApproved(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--resume", "--model", "opus"])
    }), "evaluator G4: ordinary options delegate")

    // Inline --settings JSON: the settings gate reads it, from P's argv.
    let inline = #"{"env":{"CLAUDE_CODE_DISABLE_WORKFLOWS":"1"},"permissions":{"deny":["AskUserQuestion"]}}"#
    let settingsGate = FakeSettingsGate()
    check(isApproved(await evaluateStandard(gate: settingsGate) {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--model", "opus", "--settings", inline])
    }) && settingsGate.scopes.last?.launchSettings == [inline],
          "evaluator G4: inline --settings delegates, and the settings gate reads it from P's argv")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--settings", "/tmp/launch-settings.json"])
    }) == .launchOption("--settings"), "evaluator G4: a --settings file declines")
    let launch = ClaudeSettingsScope.launchSettingsPath
    func launchHook(_ event: String) -> ClaudeHookSource {
        ClaudeHookSource(kind: .settings, sourceID: launch, event: event, matcher: nil,
                         digest: String(repeating: "d", count: 64), display: "Claude Code's --settings · \(event) *",
                         fetchesUnpinnedCode: false)
    }
    let bashHook = decline(await evaluateStandard(gate: FakeSettingsGate(evaluation(hooks: [launchHook("PreToolUse")]))))
    let reloadHook = decline(await evaluateStandard(gate: FakeSettingsGate(evaluation(hooks: [launchHook("ConfigChange")]))))
    check(bashHook == .launchOption("--settings that add a shell-command hook")
          && reloadHook == .launchOption("--settings that add a ConfigChange hook"),
          "evaluator settings: a --settings hook declines as the launch, since csec setup cannot review it")
    check(DelegationDecline.launchOption("--settings that add a shell-command hook").panelText
            == "Auto mode didn't approve this: Claude Code was started with --settings that add a shell-command hook.",
          "evaluator settings: the --settings hook decline reads whole")
    let bypass = decline(await evaluateStandard(gate: FakeSettingsGate(evaluation(bypass: [launch]))))
    let unparseable = decline(await evaluateStandard(gate: FakeSettingsGate(evaluation(
        unreadable: [ClaudeUnreadableSetting(path: launch, reason: .unparseable)]))))
    let home = decline(await evaluateStandard(gate: FakeSettingsGate(evaluation(
        environment: [ClaudeSettingsEnvironmentFinding(name: "HOME", path: launch)]))))
    check(bypass == .bypassReachable("Claude Code's --settings")
          && unparseable == .settingsUnreadable("Claude Code's --settings")
          && home == .settingsEnvironment(name: "HOME", path: "Claude Code's --settings"),
          "evaluator settings: a --settings finding names Claude Code's --settings, not a path")

    // A hook P's inline --settings reaches only indirectly (a plugin it
    // enables), or an --add-dir directory's: csec setup never sees P's argv,
    // so the note names the launch, found by evaluating again without it
    // (csec-0.4 F3, csec-tcbq).
    let plugin = hookSource("cc-caffeine@samber · PreToolUse *", digest: String(repeating: "c", count: 64))
    let pluginWhenLaunched: @Sendable (ClaudeSettingsScope) -> ClaudeSettingsGateEvaluation = { scope in
        evaluation(hooks: scope.launchSettings.isEmpty && scope.additionalDirectories.isEmpty ? [] : [plugin])
    }
    let launchOnly = FakeSettingsGate(byScope: pluginWhenLaunched)
    let enablesPlugin = #"{"enabledPlugins":{"cc-caffeine@samber":true}}"#
    let viaSettings = decline(await evaluateStandard(gate: launchOnly) {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--settings", enablesPlugin])
    })
    check(viaSettings == .otherHook(plugin.display, launch: "--settings")
            && launchOnly.scopes.count == 2 && launchOnly.scopes.last?.launchSettings == []
            && launchOnly.scopes.last?.additionalDirectories == [],
          "evaluator settings: a hook only P's --settings brings in names the launch, from a second evaluation without it")
    let addDirOnly = FakeSettingsGate(byScope: pluginWhenLaunched)
    let viaAddDir = decline(await evaluateStandard(gate: addDirOnly) {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--add-dir", alphaPath + "/vendor"])
    })
    let bothGate = FakeSettingsGate(byScope: pluginWhenLaunched)
    let viaBoth = decline(await evaluateStandard(gate: bothGate) {
        $0.session(Standard.agent, parent: Standard.fish,
                   argv: ["claude", "--add-dir", alphaPath + "/vendor", "--settings", enablesPlugin])
    })
    check(viaAddDir == .otherHook(plugin.display, launch: "--add-dir")
            && viaBoth == .otherHook(plugin.display, launch: "--settings or --add-dir"),
          "evaluator settings: an --add-dir directory's hook names --add-dir, and both options when both are given")
    let everywhere = FakeSettingsGate(evaluation(hooks: [plugin]))
    let seenBySetup = decline(await evaluateStandard(gate: everywhere) {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--settings", enablesPlugin])
    })
    check(seenBySetup == .otherHook(plugin.display) && everywhere.scopes.count == 2,
          "evaluator settings: a hook csec setup also finds keeps its review-with-setup note")
    let acknowledgedPlugin = FakeSettingsGate(byScope: pluginWhenLaunched)
    check(isApproved(await evaluateStandard(
        acknowledged: [AcknowledgedClaudeHook(digest: plugin.digest, display: plugin.display, acknowledgedAt: Date())],
        gate: acknowledgedPlugin
    ) {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--settings", enablesPlugin])
    }) && acknowledgedPlugin.scopes.count == 1,
          "evaluator settings: with the hook acknowledged, nothing declines and no second evaluation runs")
    let plainSession = FakeSettingsGate(evaluation(hooks: [plugin]))
    check(decline(await evaluateStandard(gate: plainSession)) == .otherHook(plugin.display) && plainSession.scopes.count == 1,
          "evaluator settings: a session with no --settings or --add-dir never evaluates twice")

    // G5: every name and prefix, NODE_OPTIONS by value, HOME, CLAUDE_CONFIG_DIR.
    func environment(_ extra: [SyntheticClaudeSessionFacts.EnvironmentEntry], home: String? = delegationHome)
        -> [SyntheticClaudeSessionFacts.EnvironmentEntry] {
        (home.map { [.init(name: "HOME", value: $0)] } ?? []) + extra
    }
    var environmentDeclines = 0
    for name in ClaudeDelegationGateLists.environmentNames {
        let result = await evaluateStandard {
            $0.session(Standard.agent, parent: Standard.fish, environment: environment([.init(name: name, value: "1")]))
        }
        if decline(result) == .injectedEnvironment(name) { environmentDeclines += 1 }
    }
    for prefix in ClaudeDelegationGateLists.environmentPrefixes {
        let result = await evaluateStandard {
            $0.session(Standard.agent, parent: Standard.fish, environment: environment([.init(name: prefix + "X", value: "1")]))
        }
        if decline(result) == .injectedEnvironment(prefix + "*") { environmentDeclines += 1 }
    }
    check(environmentDeclines == ClaudeDelegationGateLists.environmentNames.count
            + ClaudeDelegationGateLists.environmentPrefixes.count,
          "evaluator G5: every listed name and prefix declines .injectedEnvironment (\(environmentDeclines))")
    check(isApproved(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish,
                   environment: environment([.init(name: "NODE_OPTIONS", value: "--max-old-space-size=8192")]))
    }), "evaluator G5: NODE_OPTIONS --max-old-space-size delegates")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish,
                   environment: environment([.init(name: "CLAUDE_CODE_EXTRA_BODY", value: "{\"system\":\"x\"}")]))
    }) == .injectedEnvironment("CLAUDE_CODE_EXTRA_BODY"),
          "evaluator G5: a request-body override for the classifier declines")
    check(isApproved(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish, environment: environment([
            .init(name: "CLAUDE_CODE_AUTO_MODE_GIT_STATUS", value: "1"),
            .init(name: "CLAUDE_CODE_AUTO_MODE_MODEL", value: "claude-opus-5-5"),
        ]))
    }), "evaluator G5: a quality-only or unread classifier knob delegates")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish,
                   environment: environment([.init(name: "NODE_OPTIONS", value: "--require ./preload.js")]))
    }) == .injectedEnvironment("NODE_OPTIONS --require"),
          "evaluator G5: NODE_OPTIONS --require declines")
    check(decline(await evaluateStandard {
        $0.processes[Standard.agent]?.environment = nil
    }) == .environmentUnreadable, "evaluator G5: an environment the kernel withholds declines, never passes")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish,
                   environment: environment([.init(name: "HOME", value: delegationHome)]))
    }) == .environmentUnreadable, "evaluator G5: a duplicated HOME is unreadable, never guessed")
    check(decline(await evaluateStandard { $0.session(Standard.agent, parent: Standard.fish, argv: nil) })
            == .environmentUnreadable, "evaluator G4: an unreadable argv declines")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish, environment: environment([], home: "/Users/other"))
    }) == .homeMismatch, "evaluator: a P whose HOME is not the account's home declines .homeMismatch")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish, environment: environment([], home: nil))
    }) == .homeMismatch, "evaluator: a P with no HOME declines .homeMismatch")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish,
                   environment: environment([.init(name: "CLAUDE_CONFIG_DIR", value: "relative/dir")]))
    }) == .configDirectoryUnusable, "evaluator: a relative CLAUDE_CONFIG_DIR declines")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish,
                   environment: environment([.init(name: "CLAUDE_CONFIG_DIR", value: "/Volumes/remote/claude")]))
    }) == .configDirectoryUnusable, "evaluator: a CLAUDE_CONFIG_DIR on a network mount declines")
    do {
        let gate = FakeSettingsGate()
        let result = await evaluateStandard(gate: gate, hookCWD: alphaPath + "/sub") {
            $0.session(Standard.agent, parent: Standard.fish,
                       environment: environment([.init(name: "CLAUDE_CONFIG_DIR", value: "/synthetic/claude-config/./")]),
                       argv: ["claude", "--add-dir", "../beta"])
        }
        let scope = gate.scopes.last
        check(isApproved(result)
                && scope?.homeDirectory == delegationHome
                && scope?.claudeConfigDirectory == "/synthetic/claude-config"
                && scope?.workingDirectories == [alphaPath, alphaPath + "/sub"]
                && scope?.additionalDirectories == [betaPath]
                && scope?.csecExecutablePath == delegationCsecPath
                && scope?.userName == "tester",
              "evaluator: the settings scope is the account home, P's CLAUDE_CONFIG_DIR, P's project, the hook cwd and --add-dir")
    }

    // The project: local, readable, on a known volume.
    check(decline(await evaluateStandard { $0.session(Standard.agent, parent: Standard.fish, cwd: .some(nil)) })
            == .projectUnavailable, "evaluator: an unreadable cwd declines .projectUnavailable")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish, cwd: delegationCWD("/Volumes/remote/alpha", inode: 9, local: false))
    }) == .projectNotLocal, "evaluator: a cwd on a network mount declines and is never read or paired")
    check(decline(await evaluateStandard(volumeKnown: false)) == .projectUnavailable,
          "evaluator: a volume with no UUID declines")
    check(decline(await evaluateStandard(hookCWD: "/Volumes/remote/elsewhere")) == .projectNotLocal,
          "evaluator: a hook cwd on a network mount declines")
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--add-dir", "/Volumes/remote/x"])
    }) == .projectNotLocal, "evaluator: an --add-dir on a network mount declines")

    // G1, G2, G6 from the gate, in its order.
    let digest = String(repeating: "d", count: 64)
    let settingsCases: [(String, ClaudeSettingsGateEvaluation, DelegationDecline?)] = [
        ("an unreadable settings file", evaluation(unreadable: [ClaudeUnreadableSetting(path: "/s/settings.json", reason: .unparseable)]),
         .settingsUnreadable("/s/settings.json")),
        ("generated policy the gate cannot inspect",
         evaluation(unreadable: [ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy)]),
         .settingsUnreadable("/s/managed-settings.json")),
        ("ANTHROPIC_BASE_URL in a settings env block",
         evaluation(environment: [ClaudeSettingsEnvironmentFinding(name: "ANTHROPIC_BASE_URL", path: "/s/settings.json")]),
         .settingsEnvironment(name: "ANTHROPIC_BASE_URL", path: "/s/settings.json")),
        ("classifyAllShell missing", evaluation(classifyAllShell: ClaudeClassifyAllShellFinding(setIn: [], ignoredIn: [])),
         .allowRulesActive),
        ("classifyAllShell only in project settings",
         evaluation(classifyAllShell: ClaudeClassifyAllShellFinding(setIn: [], ignoredIn: [alphaPath + "/.claude/settings.json"])),
         .allowRulesActive),
        ("an unacknowledged approving hook", evaluation(hooks: [hookSource("cc-caffeine@samber · PreToolUse *", digest: digest)]),
         .otherHook("cc-caffeine@samber · PreToolUse *")),
        ("sandbox.enabled", evaluation(sandbox: ["/s/settings.json"]), .sandboxAutoAllow("/s/settings.json")),
        ("defaultMode bypassPermissions", evaluation(bypass: ["/s/settings.json"]), .bypassReachable("/s/settings.json")),
        ("disableAllHooks",
         evaluation(disabled: [ClaudeHooksDisabledFinding(setting: .disableAllHooks, path: "/s/settings.json")]),
         .hooksDisabled(setting: "disableAllHooks", path: "/s/settings.json")),
    ]
    for (label, value, expected) in settingsCases {
        check(decline(await evaluateStandard(gate: FakeSettingsGate(value))) == expected,
              "evaluator settings: \(label) declines \(expected.map(\.code) ?? "-")")
    }
    let acknowledged = AcknowledgedClaudeHook(digest: digest, display: "cc-caffeine@samber · PreToolUse *", acknowledgedAt: Date())
    check(isApproved(await evaluateStandard(
        acknowledged: [acknowledged],
        gate: FakeSettingsGate(evaluation(hooks: [hookSource("cc-caffeine@samber · PreToolUse *", digest: digest)]))
    )), "evaluator settings: an acknowledged hook digest delegates")
    check(decline(await evaluateStandard(
        acknowledged: [acknowledged],
        gate: FakeSettingsGate(evaluation(hooks: [hookSource("cc-caffeine@samber · PreToolUse *", digest: String(repeating: "e", count: 64))]))
    )) == .otherHook("cc-caffeine@samber · PreToolUse *"),
          "evaluator settings: the same hook with a changed digest declines until acknowledged again")

    // The permission mode: only auto delegates.
    for mode in ["plan", "default", "acceptEdits", "dontAsk", "bypassPermissions"] {
        check(decline(await evaluateStandard(mode: mode)) == .notAutoMode(mode),
              "evaluator: a \(mode)-mode registration declines .notAutoMode(\(mode))")
    }

    // Pairing: the exact project, every reference.
    check(decline(await evaluateStandard(pairings: [])) == .notApprovedForProject(reference: alphaReference, project: "alpha"),
          "evaluator: an unpaired reference declines .notApprovedForProject")
    check(decline(await evaluateStandard(references: [alphaReference, "csec://alpha/OTHER"]))
            == .notApprovedForProject(reference: "csec://alpha/OTHER", project: "alpha"),
          "evaluator: every new reference must be paired; the first unpaired one is named")
    // A one-time code is never released by auto mode, even when a pairing
    // from before csec-0.65 names it: the panel says it needs a person.
    let alphaCode = alphaReference + "?attribute=otp"
    check(decline(await evaluateStandard(
        pairings: [pairing(references: [alphaReference, alphaCode])], references: [alphaCode]
    )) == .oneTimeCode(alphaCode),
          "evaluator: a one-time code declines .oneTimeCode however it is paired")
    check(decline(await evaluateStandard(
        pairings: [pairing(references: [alphaReference, alphaCode])], references: [alphaReference, alphaCode]
    )) == .oneTimeCode(alphaCode),
          "evaluator: a request with a paired secret and a one-time code declines for the code")
    check(DelegationDecline.oneTimeCode(alphaCode).panelText
            == "Auto mode didn't approve this: \(alphaCode) is a one-time code, and every one needs you.",
          "delegation: .oneTimeCode says every code needs a person")
    check(decline(await evaluateStandard(pairings: [pairing(inode: alphaInode + 1)]))
            == .notApprovedForProject(reference: alphaReference, project: "alpha"),
          "evaluator: a directory with another inode at the same path (a re-clone) is not the paired project")
    check(decline(await evaluateStandard(pairings: [ProjectPairing(
        project: ProjectKey(path: alphaPath, volumeUUID: "86D3F5FE-B679-4A74-A9AB-C9C1085150F3", inode: alphaInode),
        references: [alphaReference], ssh: []
    )])) == .notApprovedForProject(reference: alphaReference, project: "alpha"),
          "evaluator: the same path and inode on another volume is not the paired project")

    // Off, and an unreadable settings item.
    do {
        let (facts, _) = Standard.tree().build()
        let service = makeService(facts)
        check(await evaluate(service, command: Standard.command, program: Standard.program) == .notApplicable,
              "evaluator: with delegation off nothing is judged and no note is shown")
    }
    do {
        let backend = InMemoryProtectedItemBackend()
        await backend.setRawBytes(Data("not json".utf8), for: .delegationSettings)
        let (facts, _) = Standard.tree().build()
        let service = makeService(facts, stores: .processLocal(backend))
        let result = await evaluate(service, command: Standard.command, program: Standard.program)
        let state = await service.state
        check(result == .notApplicable && state == .unreadable,
              "evaluator: unreadable delegation settings mean delegation is off (state unreadable)")
    }
}

private func codexIdentity(pid: pid_t) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 3),
        identifier: "codex", teamIdentifier: "SYNTHETICX", cdHash: String(repeating: "f", count: 40),
        executablePath: "/opt/homebrew/bin/codex", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: false, trustedCDHash: nil, status: 0
    )
}

/// csec-0.39.14: an Anthropic image audited after this build was compiled
/// delegates once the held signed manifest lists it, and an unchecked image
/// asks csecd to look for a newer list. The default synthetic identity is
/// Anthropic-signed with an all-"a" hash, which the shipped catalog lacks.
private func delegationSignedBuildListTests() async {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("csec-delegation-manifest-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let signer = TestReleaseSigner(key: Curve25519.Signing.PrivateKey())
    let store = ReleaseManifestStore(directory: directory, trustedKeys: [signer.publicLine])
    let seen = DelegationEventCounter()

    let before = await evaluateStandard(buildVerification: .shipped, manifestStore: store,
                                        uncheckedBuildSeen: seen)
    check(decline(before) == .uncheckedBuild("claude") && seen.count == 1,
          "signed Claude list: an unchecked image declines and asks csecd to check for a newer list")

    let listed = Data(#"{"schema": 1, "sequence": 1, "claude_code": {"checked": [{"cdhash": "\#(String(repeating: "a", count: 40))", "version": "2.1.900"}]}}"#.utf8)
    _ = try? store.accept(bytes: listed, signature: signer.sign(listed))
    check(isApproved(await evaluateStandard(buildVerification: .shipped, manifestStore: store,
                                             uncheckedBuildSeen: seen)) && seen.count == 1,
          "signed Claude list: the same image delegates once the verified manifest lists it, with nothing to set up")

    let report = await signedListStatus(store: store)
    check(report?.checkedReleases.contains("2.1.900") == true
            && report?.builds.contains { $0.cdHash == String(repeating: "a", count: 40) && $0.checkedVersion == "2.1.900" } == true,
          "signed Claude list: status reports the manifest's image as checked")

    try? Data(listed).write(to: directory.appendingPathComponent("manifest.json.sig"))
    check(decline(await evaluateStandard(buildVerification: .shipped, manifestStore: store)) == .uncheckedBuild("claude"),
          "signed Claude list: a manifest whose signature no longer verifies admits nothing")

    let untrusted = ReleaseManifestStore(directory: directory, trustedKeys: [])
    _ = try? Data(signer.sign(listed).utf8).write(to: directory.appendingPathComponent("manifest.json.sig"))
    check(decline(await evaluateStandard(buildVerification: .shipped, manifestStore: untrusted)) == .uncheckedBuild("claude"),
          "signed Claude list: a build with no pinned key ignores a held manifest")
    check(DelegationDecline.uncheckedBuild("2.1.900").reason.contains("resumes by itself")
            && DelegationDecline.uncheckedBuild("2.1.900").pairingCondition
                == "once csec's list of checked releases includes Claude Code 2.1.900",
          "signed Claude list: the paused note says auto mode resumes by itself once the list includes the release")
}

private func signedListStatus(store: ReleaseManifestStore) async -> ClaudeBuildVerificationReport? {
    let (facts, _) = Standard.tree().build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    let service = makeService(facts, stores: stores, buildVerification: .shipped, manifestStore: store)
    _ = await register(service, Standard.program, peer: Standard.hookPeer)
    _ = await evaluate(service, command: Standard.command, program: Standard.program)
    let inventory = await service.configure(
        .status(claudeConfigDirectory: nil, projectDirectory: alphaPath),
        caller: CallerInfo(pid: Standard.command, startTime: UInt64(Standard.command) * 10, description: "csec"),
        terminal: nil
    )
    return inventory.delegationStatus?.buildVerification
}

/// Counts callbacks from the service's actor.
private final class DelegationEventCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.withLock { value += 1 } }
    var count: Int { lock.withLock { value } }
}

private func delegationReleaseGateTests() async {
    for hash in [auditedClaude301Hash, neighboringClaude301Hash] {
        let result = await evaluateStandard(buildVerification: .shipped) {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude301ModelEnvironment,
                       identity: claude301Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }
        check(hash == auditedClaude301Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.301"),
              "release 2.1.301 secret: only the exact audited identity delegates despite its filename and inactive selectors")
    }
    for boundary in claudeReleaseBoundaryCases(environment: claude301ModelEnvironment) {
        let result = await evaluateStandard(gate: boundary.gate, buildVerification: claude301BoundaryVerification) {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude301Identity(pid: Standard.agent))
        }
        check(decline(result) == boundary.reason,
              "release 2.1.301 secret: \(boundary.label) keeps the ordinary review boundary")
    }
    for release in claude319Releases {
        for hash in [release.audited, release.neighbor] {
            let result = await evaluateStandard(buildVerification: .shipped) {
                $0.session(Standard.agent, parent: Standard.fish, environment: claude319ModelEnvironment,
                           identity: claude319Identity(pid: Standard.agent, cdHash: hash, version: release.version),
                           executablePath: "/synthetic/renamed-image")
            }
            check(hash == release.audited ? isApproved(result) : decline(result) == .uncheckedBuild(release.version),
                  "release \(release.version) secret: only the audited identity delegates with the inspected selectors")
        }
    }
    for release in claude319Releases {
        for boundary in claude319BoundaryCases() {
            let result = await evaluateStandard(gate: boundary.gate, buildVerification: claude319BoundaryVerification) {
                $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                           identity: claude319Identity(pid: Standard.agent, cdHash: release.audited, version: release.version))
            }
            check(decline(result) == boundary.reason,
                  "release \(release.version) secret: \(boundary.label) keeps the ordinary review boundary")
        }
    }
    for hash in [auditedClaude314Hash, neighboringClaude314Hash] {
        let result = await evaluateStandard(buildVerification: .shipped) {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude314ModelEnvironment,
                       identity: claude314Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }
        check(hash == auditedClaude314Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.314"),
              "release 2.1.314 secret: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude314BoundaryCases() {
        let result = await evaluateStandard(gate: boundary.gate, buildVerification: claude314BoundaryVerification) {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude314Identity(pid: Standard.agent))
        }
        check(decline(result) == boundary.reason,
              "release 2.1.314 secret: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude312Hash, neighboringClaude312Hash] {
        let result = await evaluateStandard(buildVerification: .shipped) {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude312ModelEnvironment,
                       identity: claude312Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }
        check(hash == auditedClaude312Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.312"),
              "release 2.1.312 secret: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude312BoundaryCases() {
        let result = await evaluateStandard(gate: boundary.gate, buildVerification: claude312BoundaryVerification) {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude312Identity(pid: Standard.agent))
        }
        check(decline(result) == boundary.reason,
              "release 2.1.312 secret: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude311Hash, neighboringClaude311Hash] {
        let result = await evaluateStandard(buildVerification: .shipped) {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude311ModelEnvironment,
                       identity: claude311Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }
        check(hash == auditedClaude311Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.311"),
              "release 2.1.311 secret: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude311BoundaryCases() {
        let result = await evaluateStandard(gate: boundary.gate, buildVerification: claude311BoundaryVerification) {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude311Identity(pid: Standard.agent))
        }
        check(decline(result) == boundary.reason,
              "release 2.1.311 secret: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude310Hash, neighboringClaude310Hash] {
        let result = await evaluateStandard(buildVerification: .shipped) {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude310ModelEnvironment,
                       identity: claude310Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }
        check(hash == auditedClaude310Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.310"),
              "release 2.1.310 secret: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude310BoundaryCases() {
        let result = await evaluateStandard(gate: boundary.gate, buildVerification: claude310BoundaryVerification) {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude310Identity(pid: Standard.agent))
        }
        check(decline(result) == boundary.reason,
              "release 2.1.310 secret: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude305Hash, neighboringClaude305Hash] {
        let result = await evaluateStandard(buildVerification: .shipped) {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude305ModelEnvironment,
                       identity: claude305Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }
        check(hash == auditedClaude305Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.305"),
              "release 2.1.305 secret: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claudeReleaseBoundaryCases(environment: claude305ModelEnvironment) {
        let result = await evaluateStandard(gate: boundary.gate, buildVerification: claude305BoundaryVerification) {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude305Identity(pid: Standard.agent))
        }
        check(decline(result) == boundary.reason,
              "release 2.1.305 secret: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude302Hash, neighboringClaude302Hash] {
        let result = await evaluateStandard(buildVerification: .shipped) {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude302ModelEnvironment,
                       identity: claude302Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }
        check(hash == auditedClaude302Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.302"),
              "release 2.1.302 secret: model tuning admits only the exact audited identity, despite its filename")
    }
    check(decline(await evaluateStandard(buildVerification: claude302TransportVerification) {
        $0.session(Standard.agent, parent: Standard.fish, environment: claude302StandaloneEnvironment,
                   identity: claude302Identity(pid: Standard.agent))
    }) == .injectedEnvironment("CCR_AGENT_PROXY_RELAY_MODE"),
          "release 2.1.302 G5 secret: standalone relay without REMOTE requires ordinary review")
    for (hash, checked) in [(release282CDHash, true), (release282Neighbor, false)] {
        let result = await evaluateStandard(buildVerification: .shipped) {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: release282Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed")
        }
        check(checked ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.282"),
              "release 2.1.282 secret: exact code identity decides compatibility despite the filename")
    }
    let syncedResult = await evaluateStandard(
        gate: FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), buildVerification: .shipped
    ) {
        $0.session(Standard.agent, parent: Standard.fish, identity: release282Identity(pid: Standard.agent))
    }
    check(decline(syncedResult) == .otherHook(release282SyncedHook.display),
          "release 2.1.282 secret: an unacknowledged disk-synced hook requires ordinary review")
    check(decline(await evaluateStandard(buildVerification: .shipped)) == .uncheckedBuild("claude"),
          "release gate: an Anthropic identity with a checked-looking filename still needs its exact code hash checked")
    check(isApproved(await evaluateStandard {
        $0.processes[Standard.agent]?.executablePath = "/synthetic/renamed-claude"
    }), "release gate: a checked live identity does not depend on its filename")
    for cdHash in [auditedClaude278Hash, neighboringClaude278Hash] {
        let result = await evaluateStandard(buildVerification: .shipped) {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: claude278Identity(pid: Standard.agent, cdHash: cdHash),
                       executablePath: "/synthetic/renamed-image")
        }
        check(cdHash == auditedClaude278Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.278"),
              "release gate: signed 2.1.278 secret access admits only the audited hash, independent of filename (\(cdHash))")
    }
    check(decline(await evaluateStandard(buildVerification: .shipped) {
        $0.session(Standard.agent, parent: Standard.fish,
                   environment: claude278RelayEnvironment,
                   identity: claude278Identity(pid: Standard.agent, cdHash: auditedClaude278Hash))
    }) == .injectedEnvironment("CLAUDE_CODE_REMOTE"),
          "release 2.1.278 G5: a signed checked image's remote relay transport still declines secret delegation")
    let synced278 = await evaluateStandard(
        gate: FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), buildVerification: .shipped
    ) {
        $0.session(Standard.agent, parent: Standard.fish,
                   identity: claude278Identity(pid: Standard.agent, cdHash: auditedClaude278Hash))
    }
    check(decline(synced278) == .otherHook(release282SyncedHook.display),
          "release 2.1.278 G2: a checked image's disk-synced skill hook requires ordinary secret review")
    for cdHash in [auditedClaude295Hash, neighboringClaude295Hash] {
        let result = await evaluateStandard(buildVerification: .shipped) {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: claude295Identity(pid: Standard.agent, cdHash: cdHash),
                       executablePath: "/synthetic/renamed-image")
        }
        check(cdHash == auditedClaude295Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.295"),
              "release gate: signed 2.1.295 secret access admits only the audited hash, independent of filename (\(cdHash))")
    }
    check(decline(await evaluateStandard(buildVerification: .shipped) {
        $0.session(Standard.agent, parent: Standard.fish,
                   environment: claude295RelayEnvironment,
                   identity: claude295Identity(pid: Standard.agent, cdHash: auditedClaude295Hash))
    }) == .injectedEnvironment("CLAUDE_CODE_REMOTE"),
          "release 2.1.295 G5: a signed checked image's remote relay transport still declines secret delegation")
    let synced295 = await evaluateStandard(
        gate: FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), buildVerification: .shipped
    ) {
        $0.session(Standard.agent, parent: Standard.fish,
                   identity: claude295Identity(pid: Standard.agent, cdHash: auditedClaude295Hash))
    }
    check(decline(synced295) == .otherHook(release282SyncedHook.display),
          "release 2.1.295 G2: a checked image's disk-synced skill hook requires ordinary secret review")
    let policy278 = await evaluateStandard(gate: FakeSettingsGate(evaluation(unreadable: [
        ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy),
    ])), buildVerification: .shipped) {
        $0.session(Standard.agent, parent: Standard.fish,
                   identity: claude278Identity(pid: Standard.agent, cdHash: auditedClaude278Hash))
    }
    check(decline(policy278) == .settingsUnreadable("/s/managed-settings.json"),
          "release 2.1.278 secret: a checked image cannot delegate through generated policy")
    let custom = String(repeating: "c", count: 40)
    let trusted = TrustedClaudeBuild(cdHash: custom, versionLabel: "2.1.280", path: "/synthetic/custom", trustedAt: Date())
    check(decline(await evaluateStandard(trusted: [trusted], buildVerification: .shipped) {
        $0.session(Standard.agent, parent: Standard.fish,
                   identity: patchedClaudeIdentity(pid: Standard.agent, cdHash: custom),
                   executablePath: "/synthetic/.local/share/claude/versions/2.1.280")
    }) == .uncheckedBuild("2.1.257"), "release gate: trusting a custom publisher identity does not certify its settings loader")
    for trustCustom in [false, true] {
        let trust = trustCustom ? [auditedCustomClaudeBuild] : []
        let result = await evaluateStandard(trusted: trust, buildVerification: catalogWithAuditedCustomBuild) {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: patchedClaudeIdentity(pid: Standard.agent, cdHash: auditedCustomClaudeBuild.cdHash))
        }
        check(trustCustom ? isApproved(result) : decline(result) == .unverifiedBuild("2.1.257"),
              "release gate: audited custom 2.1.257 secret access requires independent publisher trust (trusted=\(trustCustom))")
    }
    check(delegationVerifiedBuilds.checkedVersion(cdHash: nil) == nil
            && delegationVerifiedBuilds.checkedVersion(cdHash: String(repeating: "A", count: 40)) == nil
            && ClaudeBuildVerification.shipped.checkedVersion(cdHash: String(repeating: "a", count: 40)) == nil,
          "release gate: missing, malformed and synthetic identities never match the shipped catalog")
    check(!DelegationDecline.uncheckedBuild("new\nrelease").needsSetup
            && DelegationDecline.uncheckedBuild("new release").setupNotice == nil,
          "release gate: setup cannot certify a release, and the decline never asks the human to repeat setup")
    var tree = Standard.tree()
    tree.processes[Standard.agent]?.executablePath = "/synthetic/renamed-image"
    let (facts, _) = tree.build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    let service = makeService(facts, stores: stores, buildVerification: .shipped)
    _ = await register(service, Standard.program, peer: Standard.hookPeer)
    _ = await evaluate(service, command: Standard.command, program: Standard.program)
    let inventory = await service.configure(
        .status(claudeConfigDirectory: nil, projectDirectory: alphaPath),
        caller: CallerInfo(pid: Standard.command, startTime: UInt64(Standard.command) * 10, description: "csec"),
        terminal: nil
    )
    check(inventory.delegationStatus?.buildVerification?.uncheckedBuilds.contains {
        $0.running && $0.path == "/synthetic/renamed-image" && $0.cdHash == String(repeating: "a", count: 40)
    } == true, "release inventory: a renamed live image encountered on a request reaches the automatic verifier")
}

private let auditedClaude301Hash = "c17da5ef4bfdb3894ec64fee484b9de17127def8"
private let neighboringClaude301Hash = "c17da5ef4bfdb3894ec64fee484b9de17127def0"
// These names have no behavioral reader in the exact 2.1.301 source.
private let claude301ModelEnvironment = claude302ModelEnvironment + [
    SyntheticClaudeSessionFacts.EnvironmentEntry(name: "CLAUDE_CODE_BG_CLASSIFIER_MODEL", value: "synthetic-ignored"),
    .init(name: "CLAUDE_CODE_TWO_STAGE_CLASSIFIER", value: "1"),
    .init(name: "CLAUDE_CODE_AUTO_MODE_EXTERNAL_PERMISSIONS", value: "1"),
    .init(name: "CLAUDE_CODE_ENABLE_AUTO_MODE", value: "1"),
]
private let claude301BoundaryVerification = ClaudeBuildVerification(records: [
    .init(cdHash: auditedClaude301Hash, version: "2.1.301", evidence: "synthetic boundary fixture"),
])

private func claude301Identity(pid: pid_t, cdHash: String = auditedClaude301Hash) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 1),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/2.1.301", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

// Exact audited identities; labels and neighboring hashes grant nothing.
// 2.1.318/319/325 retain the previous source/transport boundaries; 2.1.325
// adds the delegated-session refusal below.
private let claude319Releases: [(version: String, audited: String, neighbor: String)] = [
    ("2.1.325", "cb0b92a2ee6314aeadf4303ca2b503a181ad9f7f", "cb0b92a2ee6314aeadf4303ca2b503a181ad9f70"),
    ("2.1.319", "c3fca2f1fef791c80f93c36ca7b029950614005b", "c3fca2f1fef791c80f93c36ca7b0299506140050"),
    ("2.1.318", "f9106e5a4887c4904a64d3b9dd15e7154f6120d7", "f9106e5a4887c4904a64d3b9dd15e7154f6120d0"),
    ("2.1.317", "9fd02acbf815f7259d78c4f779c2930ad33ca9aa", "9fd02acbf815f7259d78c4f779c2930ad33ca9a0"),
    ("2.1.316", "e49e58a1feeb798a46fcdd8d07bcac4ee5ad1428", "e49e58a1feeb798a46fcdd8d07bcac4ee5ad1420"),
    ("2.1.315", "0be2f7d3dad265d1ef590ee83623569caab5fcdd", "0be2f7d3dad265d1ef590ee83623569caab5fcd0"),
]
// Inspected new selectors: classifier context, CA-store drop switches,
// connection reuse, effort and background-session peer timing. None changes
// the classifier's provider, endpoint, body or verdict, or supplies a source.
private let claude319ModelEnvironment = claude314ModelEnvironment + [
    SyntheticClaudeSessionFacts.EnvironmentEntry(name: "CLAUDE_CODE_AUTO_MODE_FULL_CONTEXT", value: "1"),
    .init(name: "CLAUDE_CODE_DISABLE_LOOPED_CROSS_CERT_DROP", value: "1"),
    .init(name: "CLAUDE_CODE_DISABLE_SELF_NAMED_CERT_DROP", value: "1"),
    .init(name: "CLAUDE_CODE_DISABLE_HTTPS_AGENT_KEEPING", value: "1"),
    .init(name: "CLAUDE_CODE_SUBAGENT_EFFORT", value: "high"),
    .init(name: "CLAUDE_CODE_DISABLE_ULTRATHINK", value: "1"),
    .init(name: "CLAUDE_BG_SOCK_ADMIT_SILENT_PEERS", value: "1"),
    .init(name: "CLAUDE_BG_SILENT_PEER_TIMEOUT_MS", value: "5000"),
    // 2.1.317: diagnostic hook text, task/handback suppression, temp-path
    // layout, nested transcript selection and a beta-gated use-case ID.
    .init(name: "CLAUDE_CODE_PERSONAL_HOOKS_OFF", value: "host"),
    .init(name: "CLAUDE_CODE_DISABLE_MCP_TASKS", value: "1"),
    .init(name: "CLAUDE_CODE_DISABLE_SUBAGENT_HANDBACK", value: "1"),
    .init(name: "CLAUDE_CODE_HOST_SHORT_TEMP_DIRS", value: "1"),
    .init(name: "CLAUDE_CODE_DISABLE_NESTED_SESSION_ID", value: "1"),
    .init(name: "CLAUDE_CODE_PROGRAM_USE_CASE_ID", value: "synthetic-use-case"),
    // 2.1.318/319: sealed REPL, context/compression and source-removal flags.
    // None supplies approval authority or an uninspected source.
    .init(name: "CLAUDE_CODE_EXPERIMENTAL_CODE_MODE", value: "1"),
    .init(name: "CLAUDE_CODE_DISABLE_STOP_OF_HELD_MESSAGES", value: "1"),
    .init(name: "CLAUDE_CODE_IGNORE_PERSISTED_TRUST", value: "1"),
    .init(name: "CLAUDE_CODE_DISABLE_FEATURE_FLAGS", value: "1"),
    .init(name: "CLAUDE_CODE_CRYPTIC_HORIZON", value: "1"),
    .init(name: "CLAUDE_CODE_NORMALIZE_PREFIX_CACHE", value: "1"),
]
// Isolate the existing source/transport boundaries from catalog admission.
private let claude319BoundaryVerification = ClaudeBuildVerification(records: claude319Releases.map {
    .init(cdHash: $0.audited, version: $0.version, evidence: "synthetic boundary fixture")
})

private func claude319Identity(
    pid: pid_t, cdHash: String = claude319Releases[0].audited, version: String = claude319Releases[0].version
) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 1),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/" + version, signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

// The new self-named-certificate switch only keeps certificates from an
// extra CA file, whose selector already declines.
private func claude319BoundaryCases() -> [(
    label: String, environment: [SyntheticClaudeSessionFacts.EnvironmentEntry],
    gate: FakeSettingsGate, reason: DelegationDecline
)] {
    claudeReleaseBoundaryCases(environment: claude319ModelEnvironment) + [
        ("extra CA file kept whole", claude319ModelEnvironment + [
            .init(name: "NODE_EXTRA_CA_CERTS", value: "/synthetic/ca.pem"),
        ], FakeSettingsGate(), .injectedEnvironment("NODE_EXTRA_CA_CERTS")),
        ("classifier endpoint override", claude319ModelEnvironment + [
            .init(name: "ANTHROPIC_BASE_URL", value: "https://synthetic.invalid"),
        ], FakeSettingsGate(), .injectedEnvironment("ANTHROPIC_BASE_URL")),
        ("classifier socket override", claude319ModelEnvironment + [
            .init(name: "ANTHROPIC_UNIX_SOCKET", value: "/synthetic/api.sock"),
        ], FakeSettingsGate(), .injectedEnvironment("ANTHROPIC_UNIX_SOCKET")),
        ("classifier provider override", claude319ModelEnvironment + [
            .init(name: "CLAUDE_CODE_USE_BEDROCK", value: "1"),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_USE_BEDROCK")),
    ] + [
        // 2.1.325's delegated-session mode picks the classifier's model ahead
        // of server/org precedence; each selector declines on presence.
        "CLAUDE_CODE_USER_DELEGATED_SESSION", "CLAUDE_CODE_USER_DELEGATED_SESSION_DIRECT_API",
        "CLAUDE_CODE_USER_DELEGATED_SESSION_ALLOWED_CHECK_MODELS",
        "CLAUDE_CODE_USER_DELEGATED_SESSION_ANY_CHECK_MODEL",
        "CLAUDE_CODE_USER_DELEGATED_SESSION_ALLOWED_PROVIDERS",
    ].map { name in
        ("delegated-session classifier selector \(name)", claude319ModelEnvironment + [
            .init(name: name, value: "1"),
        ], FakeSettingsGate(), .injectedEnvironment(name))
    }
}

private let auditedClaude314Hash = "33bc52834785912c4ff7dd9e2b9e8c1dd38ef9fd"
private let neighboringClaude314Hash = "33bc52834785912c4ff7dd9e2b9e8c1dd38ef9f0"
// Inspected classifier/context selectors retain the sealed-policy boundary.
private let claude314ModelEnvironment = claude312ModelEnvironment + [
    SyntheticClaudeSessionFacts.EnvironmentEntry(name: "CLAUDE_CODE_BRIDGE_CHILD_CLI_ENTRYPOINT", value: "1"),
    .init(name: "CLAUDE_CODE_CCR_LONG_POLL", value: "1"),
    .init(name: "CLAUDE_CODE_DISABLE_POOLED_CONNECTION_IDLE_LIMIT", value: "1"),
    .init(name: "CLAUDE_CODE_MEMORY_CONTEXT_NO_WAIT", value: "1"),
    .init(name: "CLAUDE_CODE_UPFRONT_TOOLS", value: "Read"),
]
// Isolate the existing source/transport boundaries from catalog admission.
private let claude314BoundaryVerification = ClaudeBuildVerification(records: [
    .init(cdHash: auditedClaude314Hash, version: "2.1.314", evidence: "synthetic boundary fixture"),
])

private func claude314Identity(pid: pid_t, cdHash: String = auditedClaude314Hash) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 1),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/2.1.314", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

private func claude314BoundaryCases() -> [(
    label: String, environment: [SyntheticClaudeSessionFacts.EnvironmentEntry],
    gate: FakeSettingsGate, reason: DelegationDecline
)] {
    [
        ("standalone relay without REMOTE", claude314ModelEnvironment + [
            .init(name: "CCR_AGENT_PROXY_RELAY_MODE", value: "agent_proxy_standalone"),
            .init(name: "SELF_HOSTED_RUNNER_AGENT_PROXY_URL", value: "https://proxy.synthetic.invalid"),
        ], FakeSettingsGate(), .injectedEnvironment("CCR_AGENT_PROXY_RELAY_MODE")),
        ("hosted relay", claude314ModelEnvironment + [
            .init(name: "CLAUDE_CODE_REMOTE", value: "1"),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_REMOTE")),
        ("classifier body override", claude314ModelEnvironment + [
            .init(name: "CLAUDE_CODE_EXTRA_BODY", value: #"{"messages":[]}"#),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_EXTRA_BODY")),
        ("generated managed policy", claude314ModelEnvironment, FakeSettingsGate(evaluation(unreadable: [
            ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy),
        ])), .settingsUnreadable("/s/managed-settings.json")),
        ("disk-synced skill hooks", claude314ModelEnvironment,
         FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), .otherHook(release282SyncedHook.display)),
    ]
}

private let auditedClaude312Hash = "9d4c442a850897e6cf0e68c0d022b98859161d2e"
private let neighboringClaude312Hash = "9d4c442a850897e6cf0e68c0d022b98859161d20"
// Inspected classifier/context selectors retain the sealed-policy boundary.
private let claude312ModelEnvironment = claude311ModelEnvironment
// Isolate the existing source/transport boundaries from catalog admission.
private let claude312BoundaryVerification = ClaudeBuildVerification(records: [
    .init(cdHash: auditedClaude312Hash, version: "2.1.312", evidence: "synthetic boundary fixture"),
])

private func claude312Identity(pid: pid_t, cdHash: String = auditedClaude312Hash) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 1),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/2.1.312", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

private func claude312BoundaryCases() -> [(
    label: String, environment: [SyntheticClaudeSessionFacts.EnvironmentEntry],
    gate: FakeSettingsGate, reason: DelegationDecline
)] {
    [
        ("standalone relay without REMOTE", claude312ModelEnvironment + [
            .init(name: "CCR_AGENT_PROXY_RELAY_MODE", value: "agent_proxy_standalone"),
            .init(name: "SELF_HOSTED_RUNNER_AGENT_PROXY_URL", value: "https://proxy.synthetic.invalid"),
        ], FakeSettingsGate(), .injectedEnvironment("CCR_AGENT_PROXY_RELAY_MODE")),
        ("hosted relay", claude312ModelEnvironment + [
            .init(name: "CLAUDE_CODE_REMOTE", value: "1"),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_REMOTE")),
        ("classifier body override", claude312ModelEnvironment + [
            .init(name: "CLAUDE_CODE_EXTRA_BODY", value: #"{"messages":[]}"#),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_EXTRA_BODY")),
        ("generated managed policy", claude312ModelEnvironment, FakeSettingsGate(evaluation(unreadable: [
            ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy),
        ])), .settingsUnreadable("/s/managed-settings.json")),
        ("disk-synced skill hooks", claude312ModelEnvironment,
         FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), .otherHook(release282SyncedHook.display)),
    ]
}

private let auditedClaude311Hash = "a9faecb664dd8b01e19cdfc12af95da1b267f10e"
private let neighboringClaude311Hash = "a9faecb664dd8b01e19cdfc12af95da1b267f100"
// Inspected classifier/context selectors retain the sealed-policy boundary.
private let claude311ModelEnvironment = claude310ModelEnvironment + [
    // The new removal waiver acts only in independently refused bypass mode.
    SyntheticClaudeSessionFacts.EnvironmentEntry(name: "CLAUDE_CODE_EVEN_MORE_DANGEROUSLY_SKIP_PERMISSIONS", value: "1"),
]
// Isolate the existing source/transport boundaries from catalog admission.
private let claude311BoundaryVerification = ClaudeBuildVerification(records: [
    .init(cdHash: auditedClaude311Hash, version: "2.1.311", evidence: "synthetic boundary fixture"),
])

private func claude311Identity(pid: pid_t, cdHash: String = auditedClaude311Hash) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 1),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/2.1.311", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

private func claude311BoundaryCases() -> [(
    label: String, environment: [SyntheticClaudeSessionFacts.EnvironmentEntry],
    gate: FakeSettingsGate, reason: DelegationDecline
)] {
    [
        ("standalone relay without REMOTE", claude311ModelEnvironment + [
            .init(name: "CCR_AGENT_PROXY_RELAY_MODE", value: "agent_proxy_standalone"),
            .init(name: "SELF_HOSTED_RUNNER_AGENT_PROXY_URL", value: "https://proxy.synthetic.invalid"),
        ], FakeSettingsGate(), .injectedEnvironment("CCR_AGENT_PROXY_RELAY_MODE")),
        ("hosted relay", claude311ModelEnvironment + [
            .init(name: "CLAUDE_CODE_REMOTE", value: "1"),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_REMOTE")),
        ("classifier body override", claude311ModelEnvironment + [
            .init(name: "CLAUDE_CODE_EXTRA_BODY", value: #"{"messages":[]}"#),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_EXTRA_BODY")),
        ("generated managed policy", claude311ModelEnvironment, FakeSettingsGate(evaluation(unreadable: [
            ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy),
        ])), .settingsUnreadable("/s/managed-settings.json")),
        ("disk-synced skill hooks", claude311ModelEnvironment,
         FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), .otherHook(release282SyncedHook.display)),
    ]
}

private let auditedClaude310Hash = "62f3298fb35e54f02451657e7bfbcd0b795657c7"
private let neighboringClaude310Hash = "62f3298fb35e54f02451657e7bfbcd0b795657c0"
// Inspected classifier/context selectors retain the sealed-policy boundary.
private let claude310ModelEnvironment = claude305ModelEnvironment + [
    SyntheticClaudeSessionFacts.EnvironmentEntry(name: "CLAUDE_CODE_AUTO_MODE_THREAD_ASK_HELD", value: "1"),
]
// Isolate the existing source/transport boundaries from catalog admission.
private let claude310BoundaryVerification = ClaudeBuildVerification(records: [
    .init(cdHash: auditedClaude310Hash, version: "2.1.310", evidence: "synthetic boundary fixture"),
])

private func claude310Identity(pid: pid_t, cdHash: String = auditedClaude310Hash) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 1),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/2.1.310", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

private func claude310BoundaryCases() -> [(
    label: String, environment: [SyntheticClaudeSessionFacts.EnvironmentEntry],
    gate: FakeSettingsGate, reason: DelegationDecline
)] {
    [
        ("standalone relay without REMOTE", claude310ModelEnvironment + [
            .init(name: "CCR_AGENT_PROXY_RELAY_MODE", value: "agent_proxy_standalone"),
            .init(name: "SELF_HOSTED_RUNNER_AGENT_PROXY_URL", value: "https://proxy.synthetic.invalid"),
        ], FakeSettingsGate(), .injectedEnvironment("CCR_AGENT_PROXY_RELAY_MODE")),
        ("hosted relay", claude310ModelEnvironment + [
            .init(name: "CLAUDE_CODE_REMOTE", value: "1"),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_REMOTE")),
        ("classifier body override", claude310ModelEnvironment + [
            .init(name: "CLAUDE_CODE_EXTRA_BODY", value: #"{"messages":[]}"#),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_EXTRA_BODY")),
        ("generated managed policy", claude310ModelEnvironment, FakeSettingsGate(evaluation(unreadable: [
            ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy),
        ])), .settingsUnreadable("/s/managed-settings.json")),
        ("disk-synced skill hooks", claude310ModelEnvironment,
         FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), .otherHook(release282SyncedHook.display)),
    ]
}

private let auditedClaude305Hash = "78d6b9ed85da6de5b0847587570cb3ae268a5c96"
private let neighboringClaude305Hash = "78d6b9ed85da6de5b0847587570cb3ae268a5c90"
private let claude305ModelEnvironment = claude302ModelEnvironment + [
    SyntheticClaudeSessionFacts.EnvironmentEntry(name: "CLAUDE_CODE_AUTO_MODE_EMAIL_SENDER_TURN", value: "1"),
    .init(name: "CLAUDE_CODE_AUTO_MODE_EMAIL_SENDER_REPLY_TURN", value: "1"),
    .init(name: "CLAUDE_CODE_AUTO_MODE_REMOTE_BROWSER", value: "1"),
]
// Isolate the existing source/transport boundaries from catalog admission.
private let claude305BoundaryVerification = ClaudeBuildVerification(records: [
    .init(cdHash: auditedClaude305Hash, version: "2.1.305", evidence: "synthetic boundary fixture"),
])

private func claude305Identity(pid: pid_t, cdHash: String = auditedClaude305Hash) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 1),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/2.1.305", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

private func claudeReleaseBoundaryCases(environment: [SyntheticClaudeSessionFacts.EnvironmentEntry]) -> [(
    label: String, environment: [SyntheticClaudeSessionFacts.EnvironmentEntry],
    gate: FakeSettingsGate, reason: DelegationDecline
)] {
    [
        ("standalone relay without REMOTE", environment + [
            .init(name: "CCR_AGENT_PROXY_RELAY_MODE", value: "agent_proxy_standalone"),
        ], FakeSettingsGate(), .injectedEnvironment("CCR_AGENT_PROXY_RELAY_MODE")),
        ("hosted relay", environment + [
            .init(name: "CLAUDE_CODE_REMOTE", value: "1"),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_REMOTE")),
        ("classifier body override", environment + [
            .init(name: "CLAUDE_CODE_EXTRA_BODY", value: #"{"messages":[]}"#),
        ], FakeSettingsGate(), .injectedEnvironment("CLAUDE_CODE_EXTRA_BODY")),
        ("generated managed policy", environment, FakeSettingsGate(evaluation(unreadable: [
            ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy),
        ])), .settingsUnreadable("/s/managed-settings.json")),
        ("disk-synced skill hooks", environment,
         FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), .otherHook(release282SyncedHook.display)),
    ]
}

private let auditedClaude302Hash = "3759f6c69569d1685ffcd6eea1c7e20539c2d4b5"
private let neighboringClaude302Hash = "3759f6c69569d1685ffcd6eea1c7e20539c2d4b0"
private let claude302ModelEnvironment: [SyntheticClaudeSessionFacts.EnvironmentEntry] = [
    .init(name: "HOME", value: delegationHome), .init(name: "TERM", value: "xterm"),
    .init(name: "CLAUDE_CODE_AUTO_MODE_MODEL", value: "claude-sonnet-5"),
]
// This selector starts its own forwarder without CLAUDE_CODE_REMOTE. The URL
// and session metadata alone do not select it.
private let claude302StandaloneEnvironment = claude302ModelEnvironment + [
    SyntheticClaudeSessionFacts.EnvironmentEntry(name: "CCR_AGENT_PROXY_RELAY_MODE", value: "agent_proxy_standalone"),
    .init(name: "CCR_AGENT_PROXY_STANDALONE_URL", value: "https://synthetic.invalid"),
    .init(name: "CLAUDE_CODE_ENVIRONMENT_KIND", value: "byoc"),
    .init(name: "CLAUDE_CODE_REMOTE_SESSION_ID", value: "synthetic-session"),
]
// Isolate the transport regression from catalog admission, which the three
// exact/neighboring-identity tests above and below check against .shipped.
private let claude302TransportVerification = ClaudeBuildVerification(records: [
    .init(cdHash: auditedClaude302Hash, version: "2.1.302", evidence: "synthetic transport fixture"),
])

private func claude302Identity(pid: pid_t, cdHash: String = auditedClaude302Hash) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 1),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/2.1.302", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

private let release282CDHash = "aec6b146f0cd2378b1489dd316f69d16e11591aa"
private let release282Neighbor = "aec6b146f0cd2378b1489dd316f69d16e11591ab"
private let release282SyncedHook = ClaudeHookSource(
    kind: .frontmatter, sourceID: delegationHome + "/.claude/skills/synced/account/review/SKILL.md",
    event: nil, matcher: nil, digest: String(repeating: "e", count: 64),
    display: "synced account/review · frontmatter hooks", fetchesUnpinnedCode: false
)

private func release282Identity(pid: pid_t, cdHash: String = release282CDHash) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 4),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/versions/2.1.282", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

private let auditedClaude278Hash = "af5e0f66b9fd8fdc7e615959dc602cd6386d8d11"
private let neighboringClaude278Hash = "af5e0f66b9fd8fdc7e615959dc602cd6386d8d10"
// Both audited releases use the same remote-session relay selectors.
private let claude278RelayEnvironment = claude295RelayEnvironment

private func claude278Identity(pid: pid_t, cdHash: String) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 1),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/2.1.278", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

private let auditedClaude295Hash = "7bfc0b1005fbcb70382ca4e4dd3ae9f7ff2f119b"
private let neighboringClaude295Hash = "7bfc0b1005fbcb70382ca4e4dd3ae9f7ff2f1190"
private let claude295RelayEnvironment: [SyntheticClaudeSessionFacts.EnvironmentEntry] = [
    .init(name: "HOME", value: delegationHome), .init(name: "TERM", value: "xterm"),
    .init(name: "CLAUDE_CODE_REMOTE", value: "1"), .init(name: "CCR_AGENT_PROXY_ENABLED", value: "1"),
    .init(name: "CLAUDE_CODE_REMOTE_SESSION_ID", value: "synthetic-session"),
    .init(name: "AGENT_PROXY_URL", value: "https://synthetic.invalid"),
]

private func claude295Identity(pid: pid_t, cdHash: String) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 1),
        identifier: "com.anthropic.claude-code", teamIdentifier: "Q6L2SF6YDW", cdHash: cdHash,
        executablePath: "/synthetic/2.1.295", signatureValid: true, hardenedRuntime: true,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
}

/// The shipped catalog no longer carries a custom image (csec-0.39.14 dropped
/// the tweakcc record); this one adds that audited custom build back, so
/// publisher trust stays tested apart from the settings-loader check.
private let catalogWithAuditedCustomBuild = ClaudeBuildVerification(
    records: ClaudeBuildVerification.shipped.records + [.init(
        cdHash: auditedCustomClaudeBuild.cdHash, version: "2.1.257", evidence: "synthetic: an audited custom image")]
)

private let auditedCustomClaudeBuild = TrustedClaudeBuild(
    cdHash: "64a09464023aa47514a78be456da5b89e01b50a6", versionLabel: "2.1.257",
    path: "/synthetic/.local/share/claude/versions/2.1.257", trustedAt: Date(timeIntervalSince1970: 1)
)

private func patchedClaudeIdentity(pid: pid_t, cdHash: String) -> ForeignCodeIdentity {
    ForeignCodeIdentity(
        pid: pid, startTime: UInt64(pid) * 10, lookup: .auditToken(pidVersion: 4),
        identifier: "2.1.257", teamIdentifier: nil, cdHash: cdHash,
        executablePath: "/synthetic/.local/share/claude/versions/2.1.257", signatureValid: true, hardenedRuntime: false,
        platformIdentifier: nil, entitlementKeys: [], appleAnchored: false,
        satisfiesAnthropicRequirement: false, trustedCDHash: nil, status: 0
    )
}

/// The first failing gate is the reason shown.
private func delegationConfigChangeTests() async {
    let reload = ClaudeHookSource(
        kind: .settings, sourceID: delegationHome + "/.claude/settings.json", event: "ConfigChange", matcher: nil,
        digest: String(repeating: "a", count: 64), display: "~/.claude/settings.json · ConfigChange *",
        fetchesUnpinnedCode: false
    )
    check(decline(await evaluateStandard(gate: FakeSettingsGate(evaluation(hooks: [reload]))))
            == .otherHook("~/.claude/settings.json · ConfigChange *", blocksReload: true),
          "evaluator settings: an unacknowledged ConfigChange hook declines as keeping Claude Code from reloading its hooks")
    let approving = hookSource("tee hook · PreToolUse *", digest: String(repeating: "b", count: 64))
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    let sheet = DelegationSheetConsent(approving: false)
    let (facts, _) = Standard.tree().build()
    let service = makeService(facts, stores: stores, gate: FakeSettingsGate(evaluation(hooks: [approving, reload])), consent: sheet)
    let caller = CallerInfo(pid: getpid(), startTime: ProcessAncestry.startTime(of: getpid()) ?? 1, description: "csec setup")
    _ = await service.configure(.acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: nil)
    let reason = sheet.reasons.last ?? ""
    check(reason.contains("tee hook · PreToolUse *, which can approve Claude Code's shell commands")
            && reason.contains("~/.claude/settings.json · ConfigChange *, which can keep Claude Code from reloading its hooks")
            && !reason.contains("ConfigChange *, which can approve"),
          "configure: the acknowledge sheet says what each hook can do (approve shell commands, or keep hooks from reloading)")
}

private func delegationGateOrderTests() async {
    let patched = String(repeating: "c", count: 40)
    check(decline(await evaluateStandard(mode: "default") {
        $0.session(Standard.agent, parent: Standard.fish, identity: patchedClaudeIdentity(pid: Standard.agent, cdHash: patched),
                   standardInput: .other)
    }) == .unverifiedBuild("2.1.257"),
          "gate order: identity comes before G3 and the mode")
    check(decline(await evaluateStandard(mode: "default", gate: FakeSettingsGate(evaluation(sandbox: ["/s"]))) {
        $0.session(Standard.agent, parent: Standard.fish, standardInput: .other)
    }) == .notInteractive, "gate order: G3 comes before the settings and the mode")
    check(decline(await evaluateStandard(mode: "plan", pairings: [],
                                         gate: FakeSettingsGate(evaluation(sandbox: ["/s"])))) == .sandboxAutoAllow("/s"),
          "gate order: the settings come before the mode and the pairing")
    check(decline(await evaluateStandard(mode: "plan", pairings: [])) == .notAutoMode("plan"),
          "gate order: the mode comes before the pairing")
}

// MARK: - A stored Cloud-gateway sign-in

/// The last of the session's gates (csec-kpep): a Cloud-gateway sign-in in
/// any of Claude Code's credential records, or one csecd cannot rule out,
/// declines, and only a session every earlier gate passed is checked.
private func delegationGatewaySignInGateTests() async {
    check(decline(await evaluateStandard(credentials: FakeCredentialStore(.signedIn))) == .gatewaySignIn,
          "gateway gate: a stored Cloud-gateway sign-in declines .gatewaySignIn")
    check(decline(await evaluateStandard(credentials: FakeCredentialStore(.unchecked))) == .gatewaySignInUnchecked,
          "gateway gate: records csecd cannot check decline .gatewaySignInUnchecked, never pass")
    check(decline(await evaluateStandard(
        credentials: FakeCredentialStore(.notSignedIn, delay: 0.5), credentialBound: .milliseconds(50)
    )) == .gatewaySignInUnchecked, "gateway gate: a check that overruns its bound declines unchecked")
    do {
        let store = FakeCredentialStore()
        check(isApproved(await evaluateStandard(credentials: store))
                && store.paths == [delegationHome + "/.claude/.credentials.json"],
              "gateway gate: no sign-in delegates, after checking ~/.claude/.credentials.json (\(store.paths))")
    }
    do {
        let store = FakeCredentialStore()
        let result = await evaluateStandard(credentials: store) {
            $0.session(Standard.agent, parent: Standard.fish, environment: [
                .init(name: "HOME", value: delegationHome), .init(name: "CLAUDE_CONFIG_DIR", value: "/synthetic/claude-config/./"),
            ])
        }
        check(isApproved(result) && store.paths == ["/synthetic/claude-config/.credentials.json"],
              "gateway gate: the plaintext record checked is P's CLAUDE_CONFIG_DIR's (\(store.paths))")
    }
    do {
        let store = FakeCredentialStore(.signedIn)
        check(decline(await evaluateStandard(mode: "plan", credentials: store)) == .notAutoMode("plan")
                && store.paths.isEmpty,
              "gateway gate: a request in another mode declines on the mode and never lists the Keychain")
        check(decline(await evaluateStandard(credentials: store) {
            $0.session(Standard.agent, parent: Standard.fish, standardInput: .other)
        }) == .notInteractive && store.paths.isEmpty,
              "gateway gate: a session that fails G3 never lists the Keychain")
        check(decline(await evaluateStandard(pairings: [], credentials: store)) == .gatewaySignIn,
              "gateway gate: the sign-in comes before the pairing")
    }

    // G5: the secure-storage directory moves the plaintext record.
    let name = ClaudeDelegationGateLists.secureStorageDirectoryName
    check(decline(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish, environment: [
            .init(name: "HOME", value: delegationHome), .init(name: name, value: "/tmp/planted"),
        ])
    }) == .injectedEnvironment(name), "evaluator G5: a non-empty CLAUDE_SECURESTORAGE_CONFIG_DIR declines")
    check(isApproved(await evaluateStandard {
        $0.session(Standard.agent, parent: Standard.fish, environment: [
            .init(name: "HOME", value: delegationHome), .init(name: name, value: ""),
        ])
    }), "evaluator G5: an empty CLAUDE_SECURESTORAGE_CONFIG_DIR keeps the default record and delegates")
    check(ClaudeDelegationGateLists.settingsEnvironmentEntry(matching: name) == name,
          "evaluator G5: a settings env block that sets CLAUDE_SECURESTORAGE_CONFIG_DIR declines")
}

// MARK: - The program shell's environment

/// `csec ai` runs its program as `/bin/zsh -lc`, which reads
/// `$ZDOTDIR/.zshenv` (and `.zprofile`, `.zlogin`) with every released value
/// in its environment before the approved text runs. ZDOTDIR on the `csec ai`,
/// however it got there, declines the release.
private func delegationShellSteeringTests() async {
    typealias Entry = SyntheticClaudeSessionFacts.EnvironmentEntry
    func steered(_ environment: [Entry]?, mode: String = "auto", registered: String? = Standard.program) async -> DelegationEvaluation {
        await evaluateStandard(registered: registered, mode: mode) { tree in
            tree.command(
                Standard.command, shell: Standard.shell, agent: Standard.agent, program: Standard.program,
                environment: environment
            )
        }
    }
    let steering = DelegationDecline.environmentSteering(process: "the command's shell", name: "ZDOTDIR")
    check(isApproved(await steered([Entry(name: "PATH", value: "/usr/bin:/bin"), Entry(name: "TERM", value: "xterm")])),
          "shell steering: a csec ai with no ZDOTDIR still approves")
    check(decline(await steered([Entry(name: "ZDOTDIR", value: "/tmp/planted")])) == steering,
          "shell steering: ZDOTDIR on the csec ai declines the release .environmentSteering")
    check(decline(await steered([Entry(name: "ZDOTDIR", value: "")])) == steering,
          "shell steering: an empty ZDOTDIR declines too (presence, not value, is checked)")
    check(decline(await steered([Entry(name: "csec_ZDOTDIR", value: "csec://store/zdotdir")])) == steering,
          "shell steering: csec_ZDOTDIR, which csec ai resolves to ZDOTDIR, declines")
    check(decline(await steered(nil)) == .factsUnavailable,
          "shell steering: a csec ai environment csecd cannot read declines .factsUnavailable")
    check(isApproved(await steered([Entry(name: "BASH_ENV", value: "/tmp/planted"), Entry(name: "CDPATH", value: "/tmp")])),
          "shell steering: bash's startup names reach only a bash the command itself starts, so a release still approves")

    // It ranks after the registration, before the identity, the gates and
    // the mode.
    let planted = [Entry(name: "ZDOTDIR", value: "/tmp/planted")]
    check(decline(await steered(planted, registered: nil)) == .notRegistered,
          "shell steering: an unregistered command declines .notRegistered first")
    check(decline(await steered(planted, mode: "plan")) == steering,
          "shell steering: comes before the permission mode")
    let patched = String(repeating: "c", count: 40)
    check(decline(await evaluateStandard { tree in
        tree.session(Standard.agent, parent: Standard.fish,
                     identity: patchedClaudeIdentity(pid: Standard.agent, cdHash: patched))
        tree.command(Standard.command, shell: Standard.shell, agent: Standard.agent, program: Standard.program,
                     environment: planted)
    }) == steering, "shell steering: comes before P's identity")
}

// MARK: - Bounded fact collection

/// A provider whose cwd read blocks while armed, as the kernel's cwd read
/// can on a hung network mount, or takes `delay` on every read, as a busy
/// Mac's healthy reads can.
private final class BlockingSessionFacts: ClaudeSessionFactProvider, @unchecked Sendable {
    let base: SyntheticClaudeSessionFacts
    private let lock = NSLock()
    private var armed = false
    private var delay: TimeInterval = 0
    private var slowedReads = 0
    private var longestSlowedRead: TimeInterval = 0
    private let gate = DispatchSemaphore(value: 0)

    init(_ base: SyntheticClaudeSessionFacts) { self.base = base }

    /// How many reads `slow` delayed, and the longest one took, so a burst
    /// check can say how far a slow Mac stretched them.
    func slowed() -> (reads: Int, longest: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        return (slowedReads, longestSlowedRead)
    }

    func slow(_ seconds: TimeInterval) {
        lock.lock()
        delay = seconds
        lock.unlock()
    }

    func arm() {
        lock.lock()
        armed = true
        lock.unlock()
    }

    func unblock() {
        lock.lock()
        armed = false
        lock.unlock()
        gate.signal()
    }

    func incarnation(of pid: pid_t) -> ProcessIncarnation? { base.incarnation(of: pid) }
    func parent(of pid: pid_t) -> pid_t? { base.parent(of: pid) }
    func executablePath(of process: ProcessIncarnation) -> String? { base.executablePath(of: process) }
    func argv(of process: ProcessIncarnation) -> [String]? { base.argv(of: process) }
    func jobFacts(of process: ProcessIncarnation) -> ProcessJobFacts? { base.jobFacts(of: process) }
    func fdCharDevice(of process: ProcessIncarnation, fd: Int32) -> ProcessFileDescriptorKind? {
        base.fdCharDevice(of: process, fd: fd)
    }
    func cwd(of process: ProcessIncarnation) -> ProcessWorkingDirectory? {
        lock.lock()
        let blocking = armed
        let delay = delay
        lock.unlock()
        if blocking { gate.wait() }
        if delay > 0 {
            let started = Date()
            Thread.sleep(forTimeInterval: delay)
            let took = Date().timeIntervalSince(started)
            lock.lock()
            slowedReads += 1
            longestSlowedRead = max(longestSlowedRead, took)
            lock.unlock()
        }
        return base.cwd(of: process)
    }
    func openFile(of process: ProcessIncarnation, fd: Int32) -> ProcessOpenFile? {
        base.openFile(of: process, fd: fd)
    }
    func envPresence(of process: ProcessIncarnation, names: [String], prefixes: [String]) -> EnvironmentNamePresence? {
        base.envPresence(of: process, names: names, prefixes: prefixes)
    }
    func envValues(of process: ProcessIncarnation, allowlistedKeys: [String]) -> [String: String]? {
        base.envValues(of: process, allowlistedKeys: allowlistedKeys)
    }
    func codeIdentity(of process: ProcessIncarnation, parentOf child: pid_t?, trustedCDHashes: Set<String>) -> ForeignCodeIdentity? {
        base.codeIdentity(of: process, parentOf: child, trustedCDHashes: trustedCDHashes)
    }
    func pidVersion(of process: ProcessIncarnation) -> Int32? { base.pidVersion(of: process) }
    func liveProcesses() -> [ProcessIncarnation]? { base.liveProcesses() }
}

private func delegationFactBoundTests() async {
    // Beside the Claude Code session: a terminal's own csec ai, and a Codex one.
    let (facts, _) = Standard.tree {
        $0.terminal(62_000)
        $0.command(62_002, shell: 62_001, agent: 62_000, program: "pwd")
        $0.session(61_110, parent: Standard.fish, identity: codexIdentity(pid: 61_110),
                   executablePath: "/opt/homebrew/bin/codex", name: "codex")
        $0.command(61_112, shell: 61_111, agent: 61_110, program: "pwd")
    }.build()
    let blocking = BlockingSessionFacts(facts)
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    await seedPairings(stores, [pairing()])
    let log = await makeDelegationLog(stores)
    let service = makeService(blocking, stores: stores, log: log, factBound: .milliseconds(150))
    let terminalHealthy = await evaluate(service, command: 62_002, program: "pwd")
    let codexHealthy = await evaluate(service, command: 61_112, program: "pwd")
    _ = await register(service, Standard.program, peer: Standard.hookPeer)
    blocking.arm()
    let clock = ContinuousClock()
    let started = clock.now
    let stuck = await evaluate(service, command: Standard.command, program: Standard.program)
    let stuckTook = clock.now - started
    let again = clock.now
    let whileStuck = await evaluate(service, command: Standard.command, program: Standard.program)
    let whileStuckTook = clock.now - again
    let registeredWhileStuck = await register(service, "ls", peer: Standard.hookPeer)
    check(decline(stuck) == .factsUnavailable && stuckTook >= .milliseconds(140) && stuckTook < .seconds(2),
          "fact bound: a read that blocks declines .factsUnavailable at the bound (\(stuckTook))")
    check(decline(whileStuck) == .factsUnavailable && whileStuckTook < .milliseconds(100) && !registeredWhileStuck,
          "fact bound: while a read is still stuck, later collections decline at once (\(whileStuckTook))")
    // Only a registration says a request is Claude Code's while nothing can
    // be read: a terminal's or Codex's own csec ai gets no note, and the one
    // Claude Code decline is logged with its requester unknown.
    let terminalWhileStuck = await evaluate(service, command: 62_002, program: "pwd")
    let codexWhileStuck = await evaluate(service, command: 61_112, program: "pwd")
    check(terminalHealthy == .notApplicable && codexHealthy == .notApplicable
            && terminalWhileStuck == .notApplicable && codexWhileStuck == .notApplicable,
          "fact bound: while reads are stuck, a csec ai with no registration (a terminal's, Codex's) gets no note")
    let stuckDeclines = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records
    check(stuckDeclines.count == 1 && stuckDeclines.first?.delegation?.reason == "facts_unavailable"
            && stuckDeclines.first?.requester?.class == "unknown" && stuckDeclines.first?.requester?.rootPID == nil,
          "fact bound: a decline made without P's facts records an unknown requester, never coding_agent:claude")
    blocking.unblock()
    var recovered = false
    for _ in 0..<100 {
        if isApproved(await evaluate(service, command: Standard.command, program: Standard.program)) {
            recovered = true
            break
        }
        try? await Task.sleep(nanoseconds: 20_000_000)
    }
    check(recovered, "fact bound: once the stuck read returns, collection works again")

    // A read that blocks while a request with no registration is judged
    // (its walk ran; P's own facts stuck): not known to be Claude Code's, so
    // no note and no decline record.
    let freshLog = await makeDelegationLog(stores)
    let fresh = makeService(blocking, stores: stores, log: freshLog, factBound: .milliseconds(150))
    blocking.arm()
    let unregisteredStuck = await evaluate(fresh, command: 62_002, program: "pwd")
    blocking.unblock()
    let freshDeclines = await freshLog.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records
    check(unregisteredStuck == .notApplicable && freshDeclines.isEmpty,
          "fact bound: a request with no registration whose P's facts stick gets no note and no decline record")

    // A burst of healthy reads (csec-0.64.8, csec-0.68): the requests a
    // rules-changed acknowledgement releases together, each read well inside
    // the bound, queue behind one another. The bound is on each read's own
    // run, so none declines, nothing is marked stuck, and the hook's next
    // registration is still taken. The burst runs under csecd's own bound,
    // not the stuck checks' 150 ms: a hosted Mac stalled one 40 ms read past
    // 150 ms (run 46141762136), so it was declined before any burst queued.
    let burstLog = await makeDelegationLog(stores)
    let slow = BlockingSessionFacts(facts)
    let burstBound = ClaudeDelegationService.factBound
    let burst = makeService(slow, stores: stores, log: burstLog, factBound: burstBound)
    _ = await register(burst, Standard.program, peer: Standard.hookPeer)
    check(isApproved(await evaluate(burst, command: Standard.command, program: Standard.program)),
          "fact bound: the burst's command is approved on its own")
    slow.slow(0.04)
    // Sized by what one slowed request takes on this Mac: enough of them that
    // the last waits well past one read's bound, which is what declined them
    // before, but well inside the queue's one-second wait limit, which
    // answers a caller behind a hung read and is checked below. A fixed ten
    // queued past that limit on a slow hosted Mac (run 45988638525). Ten
    // reads of at least 40 ms each already queue past the bound.
    let oneStarted = clock.now
    let alone = await evaluate(burst, command: Standard.command, program: Standard.program)
    let one = clock.now - oneStarted
    let oneSeconds = Double(one.components.seconds) + Double(one.components.attoseconds) / 1e18
    let burstSize = min(10, max(3, Int(0.65 / max(oneSeconds, 0.001))))
    check(isApproved(alone), "fact bound: one slowed read alone is approved (\(one))")
    let burstStarted = clock.now
    let burstResults = await withTaskGroup(of: DelegationEvaluation.self) { group in
        for _ in 0..<burstSize {
            group.addTask { await evaluate(burst, command: Standard.command, program: Standard.program) }
        }
        var results: [DelegationEvaluation] = []
        for await result in group { results.append(result) }
        return results
    }
    let burstTook = clock.now - burstStarted
    let registeredAfterBurst = await register(burst, "ls", peer: Standard.hookPeer)
    slow.slow(0)
    let slowed = slow.slowed()
    let burstDeclines = await burstLog.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records
    check(burstTook > burstBound,
          "fact bound: the burst of \(burstSize) queues past one read's bound (\(burstTook), one alone \(one))")
    check(burstResults.count == burstSize && burstResults.allSatisfy(isApproved) && burstDeclines.isEmpty,
          "fact bound: healthy reads queued behind one another are never declined for their wait "
            + "(\(burstResults.filter { !isApproved($0) }.count) of \(burstSize) not approved; \(slowed.reads) reads, "
            + "the longest \(Int(slowed.longest * 1000)) ms, in \(burstTook))")
    check(registeredAfterBurst, "fact bound: after a burst the hook's registration is still taken")

    // Behind a read that hangs, a request already queued is answered by the
    // wait limit, not left waiting on the hung read.
    let behindLog = await makeDelegationLog(stores)
    let behind = makeService(blocking, stores: stores, log: behindLog, factBound: .milliseconds(150))
    _ = await register(behind, Standard.program, peer: Standard.hookPeer)
    blocking.arm()
    let behindStarted = clock.now
    async let hung = evaluate(behind, command: Standard.command, program: Standard.program)
    try? await Task.sleep(nanoseconds: 20_000_000)
    let queued = await evaluate(behind, command: Standard.command, program: Standard.program)
    let queuedTook = clock.now - behindStarted
    blocking.unblock()
    _ = await hung
    check(decline(queued) == .factsUnavailable && queuedTook < .seconds(3),
          "fact bound: a request queued behind a hung read is answered within the wait limit (\(queuedTook))")
}

// MARK: - Agent integration

/// An Agent with a delegation service over one synthetic Claude Code session
/// whose `csec ai` processes are real (they may reach the consent queue).
private struct AgentHarness {
    let agent: Agent
    let service: ClaudeDelegationService
    let review: DelegationReview
    let grants: GrantTable
    let stores: ProtectedStores
    let facts: SyntheticClaudeSessionFacts
    let provider: HeldFixtureProvider
    let log: DecisionLog
    let resolver: SecretResolver
}

private func makeAgentHarness(
    commands: [(LiveCommand, String)],
    enabled: Bool = true,
    pairings: [ProjectPairing] = [pairing()],
    held: Set<String> = [alphaReference],
    review: DelegationReview = DelegationReview(),
    policyReview: (any PolicyReviewProvider)? = nil,
    extraTree: (inout DelegationTree) -> Void = { _ in },
    restoration: Bool = false,
    repositories: ProjectRepository.FileSystem = .empty,
    gate: FakeSettingsGate = FakeSettingsGate(),
    serviceConsent: (any ConsentProvider)? = nil,
    screenLocked: Bool = false
) async -> AgentHarness {
    var tree = DelegationTree()
    tree.terminal(Standard.fish)
    tree.session(Standard.agent, parent: Standard.fish)
    tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
    for (index, (command, program)) in commands.enumerated() {
        tree.command(command.pid, start: command.start, shell: pid_t(61_200 + index), agent: Standard.agent, program: program)
    }
    extraTree(&tree)
    let (facts, inspection) = tree.build()
    let stores = ProtectedStores.processLocal()
    if enabled { await enableDelegation(stores) }
    await seedPairings(stores, pairings)
    let log = await makeDelegationLog(stores)
    let provider = HeldFixtureProvider(
        schemes: ["csec"],
        values: [
            alphaReference: Data("synthetic-alpha-value".utf8),
            "csec://alpha/OTHER": Data("synthetic-other".utf8),
            "csec://beta/KEY": Data("synthetic-beta".utf8),
        ],
        held: held
    )
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(provider)
    let consent = DelegationSheetConsent()
    let service = makeService(
        facts, stores: stores, gate: gate, consent: serviceConsent ?? consent, log: log, repositories: repositories,
        screenLocked: screenLocked
    )
    let grants = GrantTable()
    let reviewer = policyReview ?? review
    var restorer: GrantRestoration?
    if restoration {
        let restore = GrantRestoration(
            resolver: resolver, policyReview: reviewer, consent: consent, terminalInspection: .unavailable
        )
        await restore.addGrantSource(grants)
        await restore.addItemSource(DelegationRestoreSource(delegation: service, resolver: resolver))
        restorer = restore
    }
    let agent = Agent(
        resolver: resolver, grants: grants, consent: consent, policyReview: reviewer,
        allowUnverifiedPlansForTesting: true, processInspection: inspection,
        terminalInspection: .unavailable, decisionLog: log, restoration: restorer, delegation: service
    )
    return AgentHarness(
        agent: agent, service: service, review: review, grants: grants, stores: stores, facts: facts,
        provider: provider, log: log, resolver: resolver
    )
}

private func aiRequest(_ program: String, references: [String] = [alphaReference]) -> AccessRequest? {
    let line = AICommandExec.commandLine(forProgram: program)
    guard let digest = try? ExecutableInspection.commandDigest(line) else { return nil }
    let plan = AICommandExec.deliveryPlan(executablePath: AICommandExec.shellPath, ttlSeconds: nil, commandDigest: digest)
    return try? AccessRequest(references: references, reason: "AI tool command", deliveryPlan: plan, commandLine: line)
}

private func execRequest(references: [String] = [alphaReference]) -> AccessRequest? {
    let plan = DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/env", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: nil, operationContext: "csec exec env",
        outputGuard: OutputGuardPlan(mode: .tty)
    )
    return try? AccessRequest(references: references, reason: "csec exec env", deliveryPlan: plan, commandLine: ["env"])
}

private actor DelegationResponseBox {
    private(set) var response: Response?

    func set(_ response: Response) {
        self.response = response
    }
}

private func delegationAgentTests() async {
    guard let first = LiveCommand(), let second = LiveCommand(), let third = LiveCommand() else {
        check(false, "delegation agent: live command fixtures start")
        return
    }
    defer { first.stop(); second.stop(); third.stop() }
    let harness = await makeAgentHarness(commands: [(first, Standard.program), (second, Standard.program), (third, "ls")])
    _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
    guard let request = aiRequest(Standard.program), let lsRequest = aiRequest("ls"),
          let widerRequest = aiRequest(Standard.program, references: [alphaReference, "csec://alpha/OTHER"]) else {
        check(false, "delegation agent: request fixtures build")
        return
    }
    let released = await harness.agent.handle(request: request, caller: first.caller)
    let reviewsAfterRelease = await harness.review.count
    let minted = await harness.grants.summaries(now: Date())
    let redaction = await harness.agent.beginOutputRedaction(
        request: BeginOutputRedactionRequest(destination: .aiTool, streams: [.stdout]),
        caller: first.caller
    )
    check(released.values?[alphaReference] == Data("synthetic-alpha-value".utf8) && released.failure == nil
            && released.accessExpiresAt == nil && reviewsAfterRelease == 0,
          "delegation agent: a delegated csec ai request is released with no review")
    check(minted.isEmpty, "delegation agent: a delegated release mints no grant")
    check((redaction.protectedValueCount ?? 0) >= 1,
          "delegation agent: the delegated values join the redaction registry")
    let usage = await harness.log.read(DecisionLogQuery(streams: [.usage], kinds: [.delegatedRelease])).records
    check(usage.count == 1 && usage.first?.decider == .delegated && usage.first?.delegation?.decision == "approved"
            && usage.first?.refs == [alphaReference],
          "delegation agent: a delegated release is logged in usage with decider delegated")

    // The same command again, from another csec ai, with no new registration
    // (and one reference alpha is not yet paired with, which approving pairs).
    let secondResponse = await harness.agent.handle(request: widerRequest, caller: second.caller)
    let noted = await harness.review.last
    check(secondResponse.failure?.code == .consentDenied && noted?.delegationNote == .notRegistered,
          "delegation agent: a second identical command without a registration goes to review with .notRegistered")
    check(noted?.pairingOffer?.projectName == "alpha" && noted?.pairingOffer?.scopeOptionID == noted?.scopeChoices?.defaultOptionID,
          "delegation agent: the declined Claude Code request's review offers the pairing line for its default scope")
    let declines = await harness.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records
    check(declines.count == 1 && declines.first?.delegation?.reason == "not_registered",
          "delegation agent: the decline is recorded once, although the request was judged again after its wait")

    // A default-mode command: the note names the mode.
    _ = await register(harness.service, "ls", peer: Standard.hookPeer, mode: "default")
    _ = await harness.agent.handle(request: lsRequest, caller: third.caller)
    check(await harness.review.last?.delegationNote == .notAutoMode("default"),
          "delegation agent: a declined request's review carries the note")

    // A request that is not csec ai, with no csec ai above it (here the
    // `csec ai` peer itself, whose parent is the Bash tool shell), is not
    // judged: no note. One under a `csec ai` is (delegationNestedRequestTests).
    guard let exec = execRequest() else { return }
    _ = await harness.agent.handle(request: exec, caller: second.caller)
    let execReview = await harness.review.last
    check(execReview?.delegationNote == nil && execReview?.pairingOffer == nil,
          "delegation agent: a request that is not csec ai, with no csec ai above it, is not judged and carries no note")

    // Paired but not held, with no restore: .notHeld.
    guard let cold = LiveCommand() else { return }
    defer { cold.stop() }
    let coldHarness = await makeAgentHarness(commands: [(cold, Standard.program)], held: [])
    _ = await register(coldHarness.service, Standard.program, peer: Standard.hookPeer)
    _ = await coldHarness.agent.handle(request: request, caller: cold.caller)
    let coldNote = await coldHarness.review.last?.delegationNote
    let coldResolves = await coldHarness.provider.interactiveResolves
    check(coldNote == .notHeld(alphaReference) && coldResolves == 0,
          "delegation agent: a paired reference csecd does not hold declines .notHeld, and nothing is resolved interactively")
    check(await coldHarness.review.last?.pairingOffer == nil,
          "delegation agent: a panel for references the project already has offers no pairing line (approving would pair nothing)")

    // A session that fails a gate pairing can't end still offers the
    // pairing, and its line says when it starts to count (csec-tcbq).
    guard let launched = LiveCommand() else { return }
    defer { launched.stop() }
    let launchHarness = await makeAgentHarness(commands: [(launched, Standard.program)], pairings: []) {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--settings", "/tmp/launch-settings.json"])
    }
    _ = await register(launchHarness.service, Standard.program, peer: Standard.hookPeer)
    _ = await launchHarness.agent.handle(request: request, caller: launched.caller)
    let launchReview = await launchHarness.review.last
    check(launchReview?.delegationNote == .launchOption("--settings")
            && launchReview?.pairingOffer?.scopeOptionID == launchReview?.scopeChoices?.defaultOptionID
            && launchReview?.pairingOffer?.line
                == "Approving also lets Claude Code auto mode use these in alpha once Claude Code is started without --settings",
          "delegation agent: a session-level decline's pairing line says when the pairing counts, not that it does now")

    // Paired, but its provider knows it does not exist: refused before
    // delegation judges it, with the true reason rather than .notHeld.
    guard let missing = LiveCommand() else { return }
    defer { missing.stop() }
    let missingHarness = await makeAgentHarness(commands: [(missing, Standard.program)], held: [])
    await missingHarness.provider.markAbsent(alphaReference)
    _ = await register(missingHarness.service, Standard.program, peer: Standard.hookPeer)
    let missingResponse = await missingHarness.agent.handle(request: request, caller: missing.caller)
    let missingReviews = await missingHarness.review.count
    let missingDeclines = await missingHarness.log.read(
        DecisionLogQuery(streams: [.decisions], kinds: [.decline, .absentReference])
    ).records
    check(missingResponse.failure?.code == .referenceNotFound && missingReviews == 0
            && missingDeclines.map(\.kind) == [.absentReference],
          "delegation agent: a paired reference that does not exist is refused before delegation, with no review or decline")

    // A setup decline's notice rides the access reply to its csec ai, and
    // one a later request under it leaves rides the end of its output
    // session; each is handed over once.
    guard let waiting = LiveCommand() else { return }
    defer { waiting.stop() }
    let hook = hookSource("tee · PreToolUse *", digest: String(repeating: "d", count: 64))
    // The hooks-changed panel refused (csec-0.64.7): each request then gets
    // its own panel and the notice.
    let setupHarness = await makeAgentHarness(
        commands: [(waiting, Standard.program)], gate: FakeSettingsGate(evaluation(hooks: [hook])),
        serviceConsent: RulesPanelConsent([.deny]))
    _ = await register(setupHarness.service, Standard.program, peer: Standard.hookPeer)
    let waitingResponse = await setupHarness.agent.handle(request: request, caller: waiting.caller)
    let expected = DelegationDecline.otherHook(hook.display).setupNotice
    check(await setupHarness.review.last?.delegationNote == .otherHook(hook.display)
            && waitingResponse.delegationNotice == expected && expected != nil,
          "delegation agent: a request declined for a setup reason carries the setup notice back to its csec ai")
    let session = await setupHarness.agent.beginOutputRedaction(
        request: BeginOutputRedactionRequest(destination: .aiTool, streams: [.stdout]), caller: waiting.caller)
    _ = await setupHarness.service.evaluateRelease(
        caller: waiting.caller, commandLine: AICommandExec.commandLine(forProgram: Standard.program),
        newReferences: [ref(alphaReference)])
    let ended = await setupHarness.agent.endOutputRedaction(
        request: EndOutputRedactionRequest(sessionID: session.outputRedactionSessionID ?? ""), caller: waiting.caller)
    let afterEnd = await setupHarness.service.takeSetupNotice(for: waiting.caller)
    check(ended.failure == nil && ended.delegationNotice == expected && afterEnd == nil,
          "delegation agent: a notice left after the access reply rides the end of the csec ai's output session, once")
    let plain = await harness.agent.handle(request: lsRequest, caller: third.caller)
    check(plain.delegationNotice == nil, "delegation agent: a decline setup cannot fix carries no setup notice")

    // The capability is advertised only with a delegation service.
    check(await harness.agent.capabilities().capabilities?.features.contains(.delegatedApprovals) == true,
          "delegation agent: an agent with a delegation service advertises delegated_approvals")

    // Queue bypass: a delegated request completes while another panel is up.
    guard let holder = LiveCommand(), let bypass = LiveCommand() else { return }
    defer { holder.stop(); bypass.stop() }
    let gated = GatedPolicyReview()
    let queueHarness = await makeAgentHarness(
        commands: [(holder, "hold"), (bypass, Standard.program)],
        policyReview: QueuedPolicyReview(underlying: gated, queue: ConsentQueue())
    )
    _ = await register(queueHarness.service, Standard.program, peer: Standard.hookPeer)
    guard let holdRequest = aiRequest("hold") else { return }
    let heldTask = Task { await queueHarness.agent.handle(request: holdRequest, caller: holder.caller) }
    let panelUp = await eventuallyTrue { await gated.pendingCount == 1 }
    // Watched with a bound rather than awaited: a release that waited for the
    // panel's turn would not finish while the panel is up.
    let bypassBox = DelegationResponseBox()
    let bypassTask = Task { await bypassBox.set(await queueHarness.agent.handle(request: request, caller: bypass.caller)) }
    let bypassFinished = await eventuallyTrue { await bypassBox.response != nil }
    let bypassed = await bypassBox.response
    let stillHeld = await gated.pendingCount
    if !bypassFinished { bypassTask.cancel() }
    await gated.decideAll(.deny(.human(decidedAt: .now)))
    _ = await heldTask.value
    if bypassFinished { await bypassTask.value }
    check(panelUp && bypassFinished && bypassed?.values?[alphaReference] != nil && stillHeld == 1,
          "delegation agent: a delegated release completes while another request's panel is on screen")

    // Two identical requests, both declined (alpha is not paired yet): the
    // second waits behind the first's panel. While it waits the reference is
    // paired, then a human Denies the first. The waiter is answered by that
    // Deny before delegation could judge it again and release it.
    guard let denied = LiveCommand(), let waiter = LiveCommand() else { return }
    defer { denied.stop(); waiter.stop() }
    let denyGate = GatedPolicyReview()
    let denyHarness = await makeAgentHarness(
        commands: [(denied, Standard.program), (waiter, Standard.program)], pairings: [],
        policyReview: QueuedPolicyReview(underlying: denyGate, queue: ConsentQueue())
    )
    _ = await register(denyHarness.service, Standard.program, peer: Standard.hookPeer)
    _ = await register(denyHarness.service, Standard.program, peer: Standard.hookPeer)
    let deniedBox = DelegationResponseBox()
    let waiterBox = DelegationResponseBox()
    let deniedTask = Task { await deniedBox.set(await denyHarness.agent.handle(request: request, caller: denied.caller)) }
    let deniedPanelUp = await eventuallyTrue { await denyGate.pendingCount == 1 }
    let waiterTask = Task { await waiterBox.set(await denyHarness.agent.handle(request: request, caller: waiter.caller)) }
    let waiterDeclined = await eventuallyTrue {
        await denyHarness.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records.count == 2
    }
    await denyHarness.service.recordHumanApproval(
        session: DelegationSession(
            agent: ProcessIncarnation(pid: Standard.agent, startTime: UInt64(Standard.agent) * 10),
            project: projectKey(), buildLabel: "2.1.280"
        ),
        references: [ref(alphaReference)], surface: .mac
    )
    await denyGate.decideAll(.deny(.human(decidedAt: .now)))
    let waiterAnswered = await eventuallyTrue { await waiterBox.response != nil }
    if waiterAnswered { await waiterTask.value } else { waiterTask.cancel() }
    await deniedTask.value
    let waiterResponse = await waiterBox.response
    let deniedResponse = await deniedBox.response
    let panels = await denyGate.reviews
    check(deniedPanelUp && waiterDeclined && waiterAnswered && deniedResponse?.failure?.code == .consentDenied
            && waiterResponse?.failure?.code == .consentDenied && waiterResponse?.values == nil && panels == 1,
          "delegation agent: a waiter answered by a human Deny of an identical request is refused before delegation judges it again")
}

/// A bridge client's request, as `csec bridge` sends it for a language client.
private func bridgeRequest(references: [String] = [alphaReference]) -> AccessRequest? {
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/python3", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: nil, operationContext: "csec bridge"
    )
    return try? AccessRequest(references: references, reason: "av slack: read Slack", deliveryPlan: plan)
}

// MARK: - Requests nested in an approved command

/// A csec request the approved command makes itself (a language client over
/// `csec bridge`, a nested `csec exec`) rides the approval of the `csec ai` it
/// runs under, however deep, as an SSH signing does (csec-0.20): the same
/// gates, auto mode, ZDOTDIR on the `csec ai`, and pairing with the project.
private func delegationNestedRequestTests() async {
    let program = "av slack read general"
    let python: pid_t = 61_300

    /// P → X → A (`csec ai`, live) → python (synthetic) → requester (live).
    func harness(
        ai: LiveCommand, nested: LiveCommand, pairings: [ProjectPairing] = [pairing()],
        aiEnvironment: [SyntheticClaudeSessionFacts.EnvironmentEntry]? = []
    ) async -> AgentHarness {
        await makeAgentHarness(commands: [(ai, program)], pairings: pairings) { tree in
            tree.command(ai.pid, start: ai.start, shell: 61_200, agent: Standard.agent, program: program,
                         environment: aiEnvironment)
            tree.processes[python] = SyntheticClaudeSessionFacts.Process(
                startTime: UInt64(python) * 10, parent: ai.pid, executablePath: "/usr/bin/python3",
                argv: ["/usr/bin/python3", "/synthetic/bin/av", "slack", "read", "general"]
            )
            tree.names[python] = "python3"
            tree.processes[nested.pid] = SyntheticClaudeSessionFacts.Process(
                startTime: nested.start, parent: python, executablePath: delegationCsecPath,
                argv: [delegationCsecPath, "bridge"]
            )
            tree.names[nested.pid] = "csec"
        }
    }
    guard let bridge = bridgeRequest(), let exec = execRequest(), let aiAccess = aiRequest(program) else {
        check(false, "nested delegation: request fixtures build")
        return
    }

    // A bridge two processes below an auto-approved `csec ai` that sent no
    // request of its own: its registration binds lazily, and the paired,
    // held reference is released with no panel and no grant.
    guard let ai = LiveCommand(), let client = LiveCommand() else { return }
    defer { ai.stop(); client.stop() }
    let world = await harness(ai: ai, nested: client)
    _ = await register(world.service, program, peer: Standard.hookPeer)
    let released = await world.agent.handle(request: bridge, caller: client.caller)
    let usage = await world.log.read(DecisionLogQuery(streams: [.usage], kinds: [.delegatedRelease])).records
    let releaseReviews = await world.review.count
    let releaseGrants = await world.grants.summaries(now: Date())
    check(released.values?[alphaReference] == Data("synthetic-alpha-value".utf8) && released.failure == nil
            && releaseReviews == 0 && releaseGrants.isEmpty,
          "nested delegation: a bridge request under an auto-approved csec ai is released with no review and no grant")
    check(usage.count == 1 && usage.first?.decider == .delegated && usage.first?.requester?.class == "coding_agent:claude",
          "nested delegation: the release is logged as delegated")

    // A nested `csec exec` under a `csec ai` that was already bound by its own
    // release rides that same registration.
    guard let boundAI = LiveCommand(), let execClient = LiveCommand() else { return }
    defer { boundAI.stop(); execClient.stop() }
    let bound = await harness(ai: boundAI, nested: execClient)
    _ = await register(bound.service, program, peer: Standard.hookPeer)
    let own = await bound.agent.handle(request: aiAccess, caller: boundAI.caller)
    let nestedExec = await bound.agent.handle(request: exec, caller: execClient.caller)
    let boundReviews = await bound.review.count
    check(own.values?[alphaReference] != nil && nestedExec.values?[alphaReference] != nil && boundReviews == 0,
          "nested delegation: a nested csec exec rides the registration its csec ai already bound")

    // Not paired with the project: a panel, which says why and offers the
    // pairing line for the default Claude Code scope.
    guard let unpairedAI = LiveCommand(), let unpairedClient = LiveCommand() else { return }
    defer { unpairedAI.stop(); unpairedClient.stop() }
    let unpaired = await harness(ai: unpairedAI, nested: unpairedClient, pairings: [])
    _ = await register(unpaired.service, program, peer: Standard.hookPeer)
    let refused = await unpaired.agent.handle(request: bridge, caller: unpairedClient.caller)
    let unpairedReview = await unpaired.review.last
    check(refused.failure?.code == .consentDenied
            && unpairedReview?.delegationNote == .notApprovedForProject(reference: alphaReference, project: "alpha")
            && unpairedReview?.pairingOffer?.projectName == "alpha"
            && unpairedReview?.pairingOffer?.scopeOptionID == unpairedReview?.scopeChoices?.defaultOptionID,
          "nested delegation: an unpaired reference gets a panel with the note and the pairing line")

    // A one-time code gets its panel even when an older pairing names it: the
    // note says every code needs a person, and no pairing line is offered.
    let alphaCode = alphaReference + "?attribute=otp"
    guard let codeAI = LiveCommand(), let codeClient = LiveCommand(),
          let codeBridge = bridgeRequest(references: [alphaCode]) else { return }
    defer { codeAI.stop(); codeClient.stop() }
    let codes = await harness(
        ai: codeAI, nested: codeClient, pairings: [pairing(references: [alphaReference, alphaCode])]
    )
    _ = await register(codes.service, program, peer: Standard.hookPeer)
    let codeRefused = await codes.agent.handle(request: codeBridge, caller: codeClient.caller)
    let codeReview = await codes.review.last
    let codeUsage = await codes.log.read(DecisionLogQuery(streams: [.usage], kinds: [.delegatedRelease])).records
    check(codeRefused.values == nil && codeUsage.isEmpty
            && codeReview?.delegationNote == .oneTimeCode(alphaCode) && codeReview?.pairingOffer == nil,
          "nested delegation: a paired one-time code is never released by auto mode, and its panel offers no pairing")

    // Approving that panel with the default scope pairs the reference, so the
    // next session's bridge in this project is released with no panel.
    guard let pairAI = LiveCommand(), let pairClient = LiveCommand(),
          let laterAI = LiveCommand(), let laterClient = LiveCommand() else { return }
    defer { pairAI.stop(); pairClient.stop(); laterAI.stop(); laterClient.stop() }
    let pairs = await harness(ai: pairAI, nested: pairClient, pairings: [])
    await pairs.review.answer(.approve(scope: .codingAgent, durationIndex: nil, surface: .mac))
    _ = await register(pairs.service, program, peer: Standard.hookPeer)
    let approved = await pairs.agent.handle(request: bridge, caller: pairClient.caller)
    let paired = await storedPairings(pairs.stores)
    check(approved.values?[alphaReference] != nil
            && paired?.first?.references == [alphaReference] && paired?.first?.project == projectKey(),
          "nested delegation: approving the bridge's panel with the pairing line pairs its reference with the project")

    // Default mode: declined, and the note names the mode.
    guard let modeAI = LiveCommand(), let modeClient = LiveCommand() else { return }
    defer { modeAI.stop(); modeClient.stop() }
    let mode = await harness(ai: modeAI, nested: modeClient)
    _ = await register(mode.service, program, peer: Standard.hookPeer, mode: "default")
    _ = await mode.agent.handle(request: bridge, caller: modeClient.caller)
    let modeNote = await mode.review.last?.delegationNote
    check(modeNote == .notAutoMode("default"),
          "nested delegation: a bridge under a command approved outside auto mode declines .notAutoMode")

    // Not registered: the `csec ai` above it was never judged by auto mode.
    guard let bareAI = LiveCommand(), let bareClient = LiveCommand() else { return }
    defer { bareAI.stop(); bareClient.stop() }
    let bare = await harness(ai: bareAI, nested: bareClient)
    _ = await bare.agent.handle(request: bridge, caller: bareClient.caller)
    let bareNote = await bare.review.last?.delegationNote
    check(bareNote == .notRegistered,
          "nested delegation: a bridge under a csec ai with no registration declines .notRegistered")

    // ZDOTDIR on the `csec ai`: its startup files ran before the approved
    // text, so what asks may not be what the classifier read.
    guard let steeredAI = LiveCommand(), let steeredClient = LiveCommand() else { return }
    defer { steeredAI.stop(); steeredClient.stop() }
    let steered = await harness(
        ai: steeredAI, nested: steeredClient, aiEnvironment: [.init(name: "ZDOTDIR", value: "/tmp/planted")]
    )
    _ = await register(steered.service, program, peer: Standard.hookPeer)
    let steeredResponse = await steered.agent.handle(request: bridge, caller: steeredClient.caller)
    let steeredNote = await steered.review.last?.delegationNote
    check(steeredResponse.values == nil
            && steeredNote == .environmentSteering(process: "the command's shell", name: "ZDOTDIR"),
          "nested delegation: ZDOTDIR on the csec ai declines the nested request .environmentSteering")

    // A bridge in a terminal, under no `csec ai`, is not Claude Code's: its
    // panel carries no note and no pairing line.
    guard let terminalClient = LiveCommand() else { return }
    defer { terminalClient.stop() }
    let terminal = await makeAgentHarness(commands: []) { tree in
        tree.processes[terminalClient.pid] = SyntheticClaudeSessionFacts.Process(
            startTime: terminalClient.start, parent: Standard.fish, executablePath: delegationCsecPath,
            argv: [delegationCsecPath, "bridge"]
        )
    }
    _ = await terminal.agent.handle(request: bridge, caller: terminalClient.caller)
    let terminalReview = await terminal.review.last
    check(terminalReview != nil && terminalReview?.delegationNote == nil && terminalReview?.pairingOffer == nil,
          "nested delegation: a bridge with no csec ai above it is not judged")
}

/// csecd's own use of a value (`daemon_proxy`, the GitHub socket) under an
/// auto-approved command pairs that use only. Approving gh's panel must not
/// let auto mode release the token's bytes into a later command's
/// environment, while a release pairing still covers the narrower use.
/// Claude Code's own PR lookup (csec-0.47): after a Bash command that
/// mentions a push, Claude Code runs `gh pr view [<selector>] [--repo r]
/// --json url` itself, as P's direct child with no `csec ai` above it. That
/// exact read-only shape is judged as P's own request; anything else P runs
/// keeps its panel.
private func delegationPullRequestLookupTests() async {
    let ghPath = "/opt/homebrew/Cellar/gh/2.83.0/bin/gh"
    let use = GitHubProxyUse(method: "POST", host: "api.github.com", path: "/graphql")
    let lookup = ["gh", "pr", "view", "--json", "url"]

    for argv in [
        lookup,
        ["gh", "pr", "view", "alexspeller/staging-db-5436-narrow", "--json", "url"],
        ["gh", "pr", "view", "7173", "--repo", "acme/WebApp", "--json", "url"],
        ["gh", "pr", "view", "--repo", "owner/repo.name", "--json", "url"],
        [ghPath, "pr", "view", "main", "--json", "url"],
    ] {
        check(ClaudeDelegationService.isClaudePullRequestLookup(argv),
              "PR lookup: Claude Code's shape is recognised: \(argv.joined(separator: " "))")
    }
    for argv in [
        ["gh", "pr", "view", "--json", "url,body"],
        ["gh", "pr", "view", "--json", "url", "--jq", ".url"],
        ["gh", "pr", "merge", "--json", "url"],
        ["gh", "api", "user", "--json", "url"],
        ["gh", "pr", "view", "--web", "--json", "url"],
        ["gh", "pr", "view", "https://github.com/o/r/pull/1", "--json", "url"],
        ["gh", "pr", "view", "a", "b", "--json", "url"],
        ["gh", "pr", "view", "1", "--repo", "o/r/x", "--json", "url"],
        ["gh", "pr", "view", "1", "--repo", "o r/x", "--json", "url"],
        ["gh", "pr", "view", "1", "-R", "o/r", "--json", "url"],
        ["gh", "pr", "view", "a b", "--json", "url"],
        ["git", "pr", "view", "--json", "url"],
        ["gh", "pr", "view"],
    ] {
        check(!ClaudeDelegationService.isClaudePullRequestLookup(argv),
              "PR lookup: any other argv is not the lookup: \(argv.joined(separator: " "))")
    }

    /// P → gh (live), with `gh`'s path, argv and parent as given.
    func harness(
        gh: LiveCommand, argv: [String], path: String = ghPath, parent: pid_t = Standard.agent,
        pairings: [ProjectPairing], agentEnvironment: [SyntheticClaudeSessionFacts.EnvironmentEntry]? = nil,
        gate: FakeSettingsGate = FakeSettingsGate()
    ) async -> AgentHarness {
        await makeAgentHarness(commands: [], pairings: pairings, extraTree: { tree in
            if let agentEnvironment {
                tree.session(Standard.agent, parent: Standard.fish, environment: agentEnvironment)
            }
            tree.processes[gh.pid] = SyntheticClaudeSessionFacts.Process(
                startTime: gh.start, parent: parent, executablePath: path, argv: argv
            )
            tree.names[gh.pid] = (path as NSString).lastPathComponent
        }, gate: gate)
    }
    let betaUse = ProjectPairing(
        project: projectKey(betaPath, inode: betaInode), references: [], usedReferences: [alphaReference], ssh: []
    )

    // Paired for csecd's use (in any project): the lookup gets the token
    // with no panel, logged as a delegated release.
    guard let paired = LiveCommand() else { return }
    defer { paired.stop() }
    let pairedGate = FakeSettingsGate()
    let lookedUp = await harness(gh: paired, argv: lookup, pairings: [betaUse], gate: pairedGate)
    let token = await lookedUp.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: paired.caller)
    let pairedReviews = await lookedUp.review.count
    if case .token = token {} else { check(false, "PR lookup: a paired use gets the token") }
    check(pairedReviews == 0, "PR lookup: Claude Code's own lookup needs no panel once the use is paired")
    // No csec ai names a launcher here, so G2 must recognise csec's own hook
    // by the launcher csec setup writes into it; any other path makes that
    // hook a foreign one and every lookup declines other_hook.
    check(!pairedGate.scopes.isEmpty
            && pairedGate.scopes.allSatisfy { $0.csecExecutablePath == CodingAgentSetup.installedLauncherPath },
          "PR lookup: the settings gate matches csec's own hook against the installed launcher")
    let delegated = await lookedUp.log.read(DecisionLogQuery(streams: [.usage], kinds: [.delegatedRelease])).records
    check(delegated.count == 1 && delegated.first?.delegation?.decision == "approved"
            && delegated.first?.requester?.class == "coding_agent:claude",
          "PR lookup: the release is logged as auto mode's")

    // A release pairing of this project covers the narrower use too.
    guard let released = LiveCommand() else { return }
    defer { released.stop() }
    let releasePaired = await harness(gh: released, argv: lookup, pairings: [pairing()])
    let releaseToken = await releasePaired.agent.authorizeGitHubTokenUse(
        reference: ref(alphaReference), use: use, caller: released.caller
    )
    let releaseReviews = await releasePaired.review.count
    if case .token = releaseToken {} else { check(false, "PR lookup: a release pairing covers it") }
    check(releaseReviews == 0, "PR lookup: a reference paired for release needs no panel")

    // Unpaired: a panel, which says why and offers the every-project pairing.
    guard let unpaired = LiveCommand() else { return }
    defer { unpaired.stop() }
    let first = await harness(gh: unpaired, argv: lookup, pairings: [])
    _ = await first.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: unpaired.caller)
    let firstReview = await first.review.last
    check(firstReview?.delegationNote == .notApprovedForProject(reference: alphaReference, project: "alpha")
            && firstReview?.pairingOffer?.everyProject == true,
          "PR lookup: unpaired, it gets a panel with the note and the every-project pairing line")

    // P failing a gate: a panel naming the gate.
    guard let injected = LiveCommand() else { return }
    defer { injected.stop() }
    let gated = await harness(
        gh: injected, argv: lookup, pairings: [betaUse],
        agentEnvironment: [
            .init(name: "HOME", value: delegationHome), .init(name: "CLAUDE_CODE_EXTRA_BODY", value: "{}"),
        ]
    )
    _ = await gated.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: injected.caller)
    let gatedReview = await gated.review.last
    check(gatedReview?.delegationNote == .injectedEnvironment("CLAUDE_CODE_EXTRA_BODY"),
          "PR lookup: a session that fails a gate gets a panel naming it")

    // Anything else keeps its panel: another gh command P runs (its note
    // says Claude Code ran it itself, naming only gh's subcommand words), the
    // lookup's argv on something that is not gh, and the lookup run by
    // something other than P (no note).
    for (label, argv, path, parent, note) in [
        ("another gh command", ["gh", "api", "-H", "Authorization: token planted", "user"], ghPath, Standard.agent,
         DelegationDecline.agentOwnCommand("gh api")),
        ("another gh pr view", ["gh", "pr", "view", "--json", "url,body"], ghPath, Standard.agent,
         .agentOwnCommand("gh pr view")),
        ("a program that is not gh", lookup, "/tmp/gh-lookalike/not-gh", Standard.agent, nil),
        ("a terminal's gh", lookup, ghPath, Standard.fish, nil),
    ] {
        guard let other = LiveCommand() else { return }
        defer { other.stop() }
        let refused = await harness(gh: other, argv: argv, path: path, parent: parent, pairings: [betaUse])
        await refused.review.answer(.deny)
        let result = await refused.agent.authorizeGitHubTokenUse(
            reference: ref(alphaReference), use: use, caller: other.caller
        )
        let review = await refused.review.last
        if case .token = result { check(false, "PR lookup: \(label) is not given the token without a panel") }
        check(review != nil && review?.delegationNote == note,
              "PR lookup: \(label) gets its panel, \(note.map { "noting \($0.code)" } ?? "with no note")")
        // Before csec-0.64.9 these left no decline record, so the log could
        // not say why the panel came; the record names no argument.
        let declines = await refused.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records
        if let note {
            check(declines.count == 1 && declines.first?.delegation?.reason == "agent_own_command"
                    && declines.first?.requester?.class == "unknown"
                    && !"\(declines)".contains("planted") && !note.panelText.contains("planted"),
                  "PR lookup: \(label) logs agent_own_command, with gh's subcommand words only")
        } else {
            check(declines.isEmpty, "PR lookup: \(label) logs no decline")
        }
    }
}

/// Claude Code's closed-issues check (csec-0.64.10, Alex's “Let it through”):
/// at most once a day per config, Claude Code runs `gh issue list -R
/// anthropics/claude-code --author @me --state closed --search
/// 'closed:><date>' --json number,title,closedAt,stateReason --limit 30`
/// itself, as P's direct child. That exact shape (any date) is judged as P's
/// own request, as the PR lookup is.
private func delegationClosedIssuesCheckTests() async {
    let ghPath = "/opt/homebrew/Cellar/gh/2.83.0/bin/gh"
    let use = GitHubProxyUse(method: "POST", host: "api.github.com", path: "/graphql")
    func checkArgv(date: String = "closed:>2026-10-04") -> [String] {
        ["gh", "issue", "list", "-R", "anthropics/claude-code", "--author", "@me", "--state", "closed",
         "--search", date, "--json", "number,title,closedAt,stateReason", "--limit", "30"]
    }
    let exact = checkArgv()
    for argv in [exact, checkArgv(date: "closed:>2026-09-29"), [ghPath] + exact.dropFirst()] {
        check(ClaudeDelegationService.isClaudeClosedIssuesCheck(argv),
              "closed-issues check: Claude Code's shape is recognised: \(argv.joined(separator: " "))")
    }
    var variants: [[String]] = [
        checkArgv(date: "closed:>2026-9-29"), checkArgv(date: "closed:>2026-09-29 is:open"), checkArgv(date: "is:open"),
        checkArgv(date: "closed:>2026-09-2x"), Array(exact.dropLast(2)), exact + ["--web"],
    ]
    for index in 1..<exact.count where index != 10 {
        var changed = exact
        changed[index] += "x"
        variants.append(changed)
    }
    var other = exact
    other[0] = "git"
    variants.append(other)
    for argv in variants {
        check(!ClaudeDelegationService.isClaudeClosedIssuesCheck(argv),
              "closed-issues check: any other argv is not the check: \(argv.joined(separator: " "))")
    }

    /// P → gh (live), as Claude Code runs the check.
    func harness(gh: LiveCommand, argv: [String], parent: pid_t = Standard.agent, pairings: [ProjectPairing]) async
        -> AgentHarness {
        await makeAgentHarness(commands: [], pairings: pairings, extraTree: { tree in
            tree.processes[gh.pid] = SyntheticClaudeSessionFacts.Process(
                startTime: gh.start, parent: parent, executablePath: ghPath, argv: argv
            )
            tree.names[gh.pid] = "gh"
        })
    }
    let betaUse = ProjectPairing(
        project: projectKey(betaPath, inode: betaInode), references: [], usedReferences: [alphaReference], ssh: []
    )

    guard let paired = LiveCommand() else { return }
    defer { paired.stop() }
    let checked = await harness(gh: paired, argv: exact, pairings: [betaUse])
    let token = await checked.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: paired.caller)
    let reviews = await checked.review.count
    if case .token = token {} else { check(false, "closed-issues check: a paired use gets the token") }
    check(reviews == 0, "closed-issues check: Claude Code's own check needs no panel once the use is paired")
    let delegated = await checked.log.read(DecisionLogQuery(streams: [.usage], kinds: [.delegatedRelease])).records
    check(delegated.count == 1 && delegated.first?.requester?.class == "coding_agent:claude",
          "closed-issues check: the release is logged as auto mode's")

    // Unpaired, or run by a terminal: a panel, as for any gh.
    guard let unpaired = LiveCommand(), let terminal = LiveCommand() else { return }
    defer { unpaired.stop(); terminal.stop() }
    let first = await harness(gh: unpaired, argv: exact, pairings: [])
    _ = await first.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: unpaired.caller)
    let firstNote = await first.review.last?.delegationNote
    check(firstNote == .notApprovedForProject(reference: alphaReference, project: "alpha"),
          "closed-issues check: unpaired, it gets a panel saying why")
    let fromTerminal = await harness(gh: terminal, argv: exact, parent: Standard.fish, pairings: [betaUse])
    await fromTerminal.review.answer(.deny)
    let terminalResult = await fromTerminal.agent.authorizeGitHubTokenUse(
        reference: ref(alphaReference), use: use, caller: terminal.caller
    )
    let terminalReview = await fromTerminal.review.last
    if case .token = terminalResult { check(false, "closed-issues check: a terminal's is not let through") }
    check(terminalReview != nil && terminalReview?.delegationNote == nil,
          "closed-issues check: a terminal's gets its panel, with no note")
}

private func delegationDaemonUsePairingTests() async {
    let program = "gh api user"
    let ghPath = "/opt/homebrew/bin/gh"
    let use = GitHubProxyUse(method: "GET", host: "api.github.com", path: "/user")

    /// P → X → A (`csec ai`, live) → gh (live), and a `csec bridge` beside it.
    func harness(
        ai: LiveCommand, gh: LiveCommand, bridge: LiveCommand, pairings: [ProjectPairing]
    ) async -> AgentHarness {
        await makeAgentHarness(commands: [(ai, program)], pairings: pairings) { tree in
            tree.command(ai.pid, start: ai.start, shell: 61_200, agent: Standard.agent, program: program, environment: [])
            tree.processes[gh.pid] = SyntheticClaudeSessionFacts.Process(
                startTime: gh.start, parent: ai.pid, executablePath: ghPath, argv: [ghPath, "api", "user"]
            )
            tree.names[gh.pid] = "gh"
            tree.processes[bridge.pid] = SyntheticClaudeSessionFacts.Process(
                startTime: bridge.start, parent: ai.pid, executablePath: delegationCsecPath,
                argv: [delegationCsecPath, "bridge"]
            )
            tree.names[bridge.pid] = "csec"
        }
    }
    guard let bridgeAccess = bridgeRequest() else {
        check(false, "daemon-use pairing: request fixtures build")
        return
    }

    // Unpaired: gh's use gets a panel with the pairing line; approving it
    // pairs the reference for csecd's use only.
    guard let ai = LiveCommand(), let gh = LiveCommand(), let bridge = LiveCommand() else { return }
    defer { ai.stop(); gh.stop(); bridge.stop() }
    let first = await harness(ai: ai, gh: gh, bridge: bridge, pairings: [])
    await first.review.answer(.approve(scope: .codingAgent, durationIndex: nil, surface: .mac))
    _ = await register(first.service, program, peer: Standard.hookPeer)
    let authorized = await first.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: gh.caller)
    let firstReview = await first.review.last
    let paired = await storedPairings(first.stores)
    if case .token = authorized {} else { check(false, "daemon-use pairing: the approved use gets the token") }
    check(firstReview?.plan.mechanism == .daemonProxy
            && firstReview?.delegationNote == .notApprovedForProject(reference: alphaReference, project: "alpha")
            && firstReview?.pairingOffer?.projectName == "alpha",
          "daemon-use pairing: an unpaired use gets a panel with the note and the pairing line")
    check(firstReview?.pairingOffer?.everyProject == true
            && firstReview?.pairingOffer?.line
                == "Approving also lets Claude Code auto mode use these, inside csec, in every project until you revoke them",
          "daemon-use pairing: the pairing line says the use holds in every project")
    check(paired?.first?.usedReferences == [alphaReference] && paired?.first?.references == [],
          "daemon-use pairing: approving it pairs csecd's use of the reference, never its release")

    // Paired for use: auto mode's next gh uses it with no panel, but a
    // release of the same reference into a command still asks.
    guard let laterAI = LiveCommand(), let laterGH = LiveCommand(), let laterBridge = LiveCommand() else { return }
    defer { laterAI.stop(); laterGH.stop(); laterBridge.stop() }
    let usePairing = ProjectPairing(project: projectKey(), references: [], usedReferences: [alphaReference], ssh: [])
    let later = await harness(ai: laterAI, gh: laterGH, bridge: laterBridge, pairings: [usePairing])
    _ = await register(later.service, program, peer: Standard.hookPeer)
    let reused = await later.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: laterGH.caller)
    let reviewsAfterUse = await later.review.count
    if case .token = reused {} else { check(false, "daemon-use pairing: a paired use is approved") }
    check(reviewsAfterUse == 0, "daemon-use pairing: a use paired with the project needs no panel")
    let release = await later.agent.handle(request: bridgeAccess, caller: laterBridge.caller)
    let releaseReview = await later.review.last
    check(release.values == nil && releaseReview?.delegationNote == .notApprovedForProject(reference: alphaReference, project: "alpha"),
          "daemon-use pairing: a use pairing never lets auto mode release the value into a command")

    // A request that can give lasting access is never auto mode's, paired
    // or not: each gets its own panel, which pairs and grants nothing, so
    // the next one asks again (csec-0.49).
    let lastingUse = GitHubProxyUse(
        method: "POST", host: "api.github.com", path: "/user/keys",
        lastingAccess: GitHubLastingAccess(kind: .sshKey, request: "POST api.github.com/user/keys")
    )
    await later.review.answer(.approve(scope: .codingAgent, durationIndex: nil, surface: .mac))
    let reviewsBeforeLasting = await later.review.count
    for attempt in 1 ... 2 {
        let lasting = await later.agent.authorizeGitHubTokenUse(
            reference: ref(alphaReference), use: lastingUse, caller: laterGH.caller
        )
        let lastingReview = await later.review.last
        let lastingReviews = await later.review.count
        if case .token = lasting {} else { check(false, "daemon-use pairing: an approved lasting request gets the token (\(attempt))") }
        check(lastingReviews == reviewsBeforeLasting + attempt
                && lastingReview?.delegationNote == .lastingAccess("POST api.github.com/user/keys")
                && lastingReview?.pairingOffer == nil && lastingReview?.durationChoices == nil
                && (lastingReview?.scopeChoices?.options.map(\.kind) ?? [.requestingCommand]) == [.requestingCommand],
              "daemon-use pairing: a paired use's lasting request gets its own panel every time, with no pairing line or wider scope (\(attempt))")
    }
    let afterLasting = await storedPairings(later.stores)
    check(afterLasting?.count == 1 && afterLasting?.first?.references == []
            && afterLasting?.first?.usedReferences == [alphaReference],
          "daemon-use pairing: approving a lasting request pairs nothing")
    let ordinaryAgain = await later.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: laterGH.caller)
    let reviewsAfterOrdinary = await later.review.count
    if case .token = ordinaryAgain {} else { check(false, "daemon-use pairing: ordinary use still approved after a lasting request") }
    check(reviewsAfterOrdinary == reviewsBeforeLasting + 2,
          "daemon-use pairing: ordinary gh use still needs no panel after a lasting request")
    check(DelegationDecline.lastingAccess("POST api.github.com/user/keys").panelText
            == "Auto mode didn't approve this: POST api.github.com/user/keys can give access that outlasts any approval, and every such request needs you.",
          "delegation: .lastingAccess says every such request needs a person")

    // A release pairing covers the narrower use.
    guard let releaseAI = LiveCommand(), let releaseGH = LiveCommand(), let releaseBridge = LiveCommand() else { return }
    defer { releaseAI.stop(); releaseGH.stop(); releaseBridge.stop() }
    let released = await harness(ai: releaseAI, gh: releaseGH, bridge: releaseBridge, pairings: [pairing()])
    _ = await register(released.service, program, peer: Standard.hookPeer)
    let covered = await released.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: releaseGH.caller)
    let releaseReviews = await released.review.count
    if case .token = covered {} else { check(false, "daemon-use pairing: a release pairing covers use") }
    check(releaseReviews == 0, "daemon-use pairing: a reference paired for release needs no panel for csecd's use")

    // A use paired in another project covers auto mode's gh here too, with
    // or without a pairing of this project's own: the token is the user's,
    // and asking again per project only re-asks what the human decided
    // (csec-0.46). A release here still needs this project's own pairing.
    let betaUse = ProjectPairing(
        project: projectKey(betaPath, inode: betaInode), references: [], usedReferences: [alphaReference], ssh: []
    )
    for (label, pairings) in [
        ("an unpaired project", [betaUse]),
        ("a project paired for other references", [pairing(references: ["csec://alpha/OTHER"]), betaUse]),
    ] {
        guard let crossAI = LiveCommand(), let crossGH = LiveCommand(), let crossBridge = LiveCommand() else { return }
        defer { crossAI.stop(); crossGH.stop(); crossBridge.stop() }
        let cross = await harness(ai: crossAI, gh: crossGH, bridge: crossBridge, pairings: pairings)
        _ = await register(cross.service, program, peer: Standard.hookPeer)
        let crossed = await cross.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: crossGH.caller)
        let crossedReviews = await cross.review.count
        if case .token = crossed {} else { check(false, "daemon-use pairing: another project's use pairing covers \(label)") }
        check(crossedReviews == 0, "daemon-use pairing: gh in \(label) needs no panel once any project paired the use")
        let crossRelease = await cross.agent.handle(request: bridgeAccess, caller: crossBridge.caller)
        let crossReleaseReview = await cross.review.last
        check(crossRelease.values == nil
                && crossReleaseReview?.delegationNote == .notApprovedForProject(reference: alphaReference, project: "alpha")
                && crossReleaseReview?.pairingOffer?.everyProject == false,
              "daemon-use pairing: another project's use pairing never releases the value in \(label)")
    }

    // A release pairing in another project was approved for that project's
    // commands only: it does not cover a use here.
    guard let otherAI = LiveCommand(), let otherGH = LiveCommand(), let otherBridge = LiveCommand() else { return }
    defer { otherAI.stop(); otherGH.stop(); otherBridge.stop() }
    let otherRelease = await harness(
        ai: otherAI, gh: otherGH, bridge: otherBridge, pairings: [pairing(betaPath, inode: betaInode)]
    )
    _ = await register(otherRelease.service, program, peer: Standard.hookPeer)
    _ = await otherRelease.agent.authorizeGitHubTokenUse(reference: ref(alphaReference), use: use, caller: otherGH.caller)
    let otherReview = await otherRelease.review.last
    check(otherReview?.delegationNote == .notApprovedForProject(reference: alphaReference, project: "alpha"),
          "daemon-use pairing: another project's release pairing does not cover a use here")

    // The document: the two lists never share a reference, and format 3
    // items migrate with no use pairings.
    check(usePairing.covers(alphaReference, daemonUse: true) && !usePairing.covers(alphaReference, daemonUse: false)
            && pairing().covers(alphaReference, daemonUse: true) && !usePairing.isEmpty,
          "daemon-use pairing: a use pairing covers only use; a release pairing covers both")
    check(!ProjectPairing(project: projectKey(), references: [alphaReference], usedReferences: [alphaReference], ssh: []).isWellFormed,
          "daemon-use pairing: a reference is paired for release or for use, not both")
    let pairingID = "00000000-0000-4000-8000-000000000003"
    let legacy = #"{"document":{"projects":[{"id":"\#(pairingID)","project":{"inode":\#(alphaInode),"path":"\#(alphaPath)","volumeUUID":"\#(delegationVolume)"},"references":["\#(alphaReference)"],"ssh":[],"launchers":[],"sudo":true}]},"formatVersion":3}"#
    let backend = InMemoryProtectedItemBackend()
    await backend.setRawBytes(Data(legacy.utf8), for: .pairing)
    let migrated = await ProtectedStores.processLocal(backend).store(for: PairingDocument.self).load()
    check(migrated == .document(PairingDocument(projects: [
        ProjectPairing(id: pairingID, project: projectKey(), references: [alphaReference], ssh: [], sudo: true),
    ])), "daemon-use pairing: a format 3 pairing item migrates with no use pairings")
}

// MARK: - Pairing rules

// MARK: - Pairing per repository

/// A pairing is keyed on the git repository a session's directory is in, so
/// one approval covers the main checkout, every worktree and any
/// subdirectory, in real layouts `git` wrote.
private func delegationRepositoryPairingTests() async {
    guard let fixture = GitRepositoryFixture() else {
        check(false, "pairing per repository: the git fixture builds")
        return
    }
    defer { fixture.remove() }
    let mainGit = fixture.main + "/.git"
    let repositoryKey = ProjectKey(path: mainGit, volumeUUID: delegationVolume, inode: fixture.inode(mainGit))
    func directoryKey(_ path: String) -> ProjectKey {
        ProjectKey(path: path, volumeUUID: delegationVolume, inode: fixture.inode(path))
    }
    func inDirectory(_ path: String) -> (inout DelegationTree) -> Void {
        { tree in tree.processes[Standard.agent]?.cwd = delegationCWD(path, inode: fixture.inode(path)) }
    }
    let repositoryPairing = ProjectPairing(project: repositoryKey, references: [alphaReference], ssh: [])

    for (label, path) in [
        ("the main checkout", fixture.main), ("a subdirectory of it", fixture.mainDeep),
        ("a linked worktree", fixture.worktree), ("a subdirectory of the worktree", fixture.worktreeSub),
    ] {
        check(isApproved(await evaluateStandard(pairings: [repositoryPairing], repositories: .live, inDirectory(path))),
              "pairing per repository: a session in \(label) uses the repository's pairing")
    }
    check(decline(await evaluateStandard(pairings: [repositoryPairing], repositories: .live, inDirectory(fixture.nested)))
            == .notApprovedForProject(reference: alphaReference, project: "nested"),
          "pairing per repository: a repository nested inside it has its own pairing, named for its checkout")
    check(decline(await evaluateStandard(pairings: [repositoryPairing], repositories: .live, inDirectory(fixture.plain)))
            == .notApprovedForProject(reference: alphaReference, project: "plain"),
          "pairing per repository: a directory in no repository is its own project")
    check(isApproved(await evaluateStandard(
        pairings: [ProjectPairing(project: directoryKey(fixture.plain), references: [alphaReference], ssh: [])],
        repositories: .live, inDirectory(fixture.plain)
    )), "pairing per repository: a directory in no repository still pairs on itself")

    // A human approval in a worktree pairs the repository.
    if let command = LiveCommand() {
        let harness = await makeAgentHarness(
            commands: [(command, Standard.program)], pairings: [],
            review: DelegationReview(.approve(scope: nil, durationIndex: nil, surface: .mac)),
            extraTree: inDirectory(fixture.worktreeSub), repositories: .live
        )
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        if let request = aiRequest(Standard.program) {
            _ = await harness.agent.handle(request: request, caller: command.caller)
        }
        command.stop()
        let stored = await storedPairings(harness.stores)
        check(stored?.count == 1 && stored?.first?.project == repositoryKey && stored?.first?.references == [alphaReference],
              "pairing per repository: approving in a worktree's subdirectory pairs the repository")
        check(await harness.review.last?.pairingOffer?.line
                == "Approving also lets Claude Code auto mode use these in main until you revoke them",
              "pairing per repository: the pairing line names the repository's checkout")
        let listed = await harness.service.grantEntries()?.pairings.first?.project.displayDescription
        check(listed == fixture.main + " (git repository)", "pairing per repository: csec grants shows the repository's checkout")
    } else {
        check(false, "pairing per repository: a live csec ai stand-in starts")
    }

    // Restore discovery and revocation follow the repository.
    do {
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        tree.session(64_110, parent: Standard.fish, path: fixture.worktreeSub, inode: fixture.inode(fixture.worktreeSub))
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [
            ProjectPairing(project: repositoryKey, references: [alphaReference, "csec://alpha/OTHER"], ssh: []),
        ])
        let service = makeService(facts, stores: stores, repositories: .live)
        check(await service.pairingsOfLiveSessions().map(\.project) == [repositoryKey],
              "pairing per repository: restore discovery finds the repository's pairing for a session in a worktree")
        let (removed, failure) = await service.unpair(
            references: [alphaReference], ssh: [], root: ProcessIncarnation(pid: 64_110, startTime: 641_100)
        )
        let stored = await storedPairings(stores)
        check(removed.count == 1 && failure == nil && stored?.first?.references == ["csec://alpha/OTHER"],
              "pairing per repository: revoking a grant rooted in a worktree unpairs from the repository")
    }

    // A pairing recorded on a directory before pairings were keyed on the
    // repository still holds in that directory, and only there.
    let mainDirectoryPairing = ProjectPairing(project: directoryKey(fixture.main), references: [alphaReference], ssh: [])
    check(isApproved(await evaluateStandard(pairings: [mainDirectoryPairing], repositories: .live, inDirectory(fixture.main))),
          "pairing per repository: a pairing recorded on the checkout's directory still holds there")
    check(decline(await evaluateStandard(pairings: [mainDirectoryPairing], repositories: .live, inDirectory(fixture.worktree)))
            == .notApprovedForProject(reference: alphaReference, project: "main"),
          "pairing per repository: it does not stretch to a worktree, which asks once for the repository")
    let other = "csec://alpha/OTHER"
    let worktreeDirectoryPairing = ProjectPairing(project: directoryKey(fixture.worktree), references: [other], ssh: [])
    check(isApproved(await evaluateStandard(
        pairings: [repositoryPairing, worktreeDirectoryPairing], references: [alphaReference, other],
        repositories: .live, inDirectory(fixture.worktree)
    )), "pairing per repository: the repository's pairing and the directory's own combine")
    check(decline(await evaluateStandard(
        pairings: [repositoryPairing, worktreeDirectoryPairing], references: [alphaReference, other],
        repositories: .live, inDirectory(fixture.worktreeSub)
    )) == .notApprovedForProject(reference: other, project: "main"),
          "pairing per repository: a directory's own pairing does not reach its subdirectories")

    // A downloaded directory whose .git names the paired repository borrows nothing.
    let borrowed = fixture.root + "/borrowed"
    let plantedPointer = fixture.write("gitdir: \(mainGit)/worktrees/worktree\n", to: borrowed + "/.git")
    let borrowing = await evaluateStandard(pairings: [repositoryPairing], repositories: .live, inDirectory(borrowed))
    check(plantedPointer && decline(borrowing) == .notApprovedForProject(reference: alphaReference, project: "borrowed"),
          "pairing per repository: a planted .git pointer to a paired repository's worktree borrows nothing")

    // Revocation and restore discovery see both keys.
    do {
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        tree.session(64_120, parent: Standard.fish, path: fixture.worktree, inode: fixture.inode(fixture.worktree))
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [
            ProjectPairing(project: repositoryKey, references: [alphaReference, other], ssh: []),
            ProjectPairing(project: directoryKey(fixture.worktree), references: [alphaReference], ssh: []),
        ])
        let service = makeService(facts, stores: stores, repositories: .live)
        let discovered = Set(await service.pairingsOfLiveSessions().map(\.project))
        check(discovered == [repositoryKey, directoryKey(fixture.worktree)],
              "pairing per repository: restore discovery finds the repository's pairing and the directory's own")
        let (removed, failure) = await service.unpair(
            references: [alphaReference], ssh: [], root: ProcessIncarnation(pid: 64_120, startTime: 641_200)
        )
        let stored = await storedPairings(stores)
        check(removed.count == 2 && failure == nil && stored?.map(\.project) == [repositoryKey]
                && stored?.first?.references == [other],
              "pairing per repository: revoking unpairs from both, dropping the directory's emptied pairing")
    }

    // Nothing is rewritten when csecd loads pairings.
    do {
        let (facts, _) = Standard.tree().build()
        let backend = InMemoryProtectedItemBackend()
        let stores = ProtectedStores.processLocal(backend)
        await enableDelegation(stores)
        await seedPairings(stores, [mainDirectoryPairing, worktreeDirectoryPairing])
        let writes = await backend.operations(on: .pairing).filter { $0 != .read }.count
        let service = makeService(facts, stores: stores, repositories: .live)
        _ = await service.isEnabled()
        let writesAfter = await backend.operations(on: .pairing).filter { $0 != .read }.count
        let after = await storedPairings(stores)
        check(after == [mainDirectoryPairing, worktreeDirectoryPairing] && writesAfter == writes,
              "pairing per repository: loading pairings rewrites none of them")
    }
}

private func delegationPairingRuleTests() async {
    /// One declined request (unpaired) under the given reviewer answer;
    /// returns what the pairing item holds afterwards.
    func pairAfter(
        _ answer: DelegationReview.Answer, enabled: Bool = true, request makeRequest: () -> AccessRequest? = { aiRequest(Standard.program) }
    ) async -> (paired: [ProjectPairing]?, harness: AgentHarness?) {
        guard let command = LiveCommand() else { return (nil, nil) }
        defer { command.stop() }
        let harness = await makeAgentHarness(
            commands: [(command, Standard.program)], enabled: enabled, pairings: [], review: DelegationReview(answer)
        )
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        guard let request = makeRequest() else { return (nil, harness) }
        _ = await harness.agent.handle(request: request, caller: command.caller)
        return (await storedPairings(harness.stores), harness)
    }
    let mac = DelegationReview.Answer.approve(scope: nil, durationIndex: nil, surface: .mac)
    let (paired, pairedHarness) = await pairAfter(mac)
    check(paired?.count == 1 && paired?.first?.project == projectKey() && paired?.first?.references == [alphaReference],
          "pairing: approving on the Mac with the default Claude Code scope for its lifetime pairs the reference")
    let offer = await pairedHarness?.review.last?.pairingOffer
    check(offer?.line == "Approving also lets Claude Code auto mode use these in alpha until you revoke them",
          "pairing: the panel's pairing line names the project")
    check(await pairingCount(pairAfter(mac, enabled: false)) == 0, "pairing: with delegation off nothing is paired")
    check(await pairingCount(pairAfter(.approve(scope: nil, durationIndex: nil, surface: .phone))) == 1,
          "pairing: a phone approval that showed the pairing line pairs")
    check(await pairingCount(pairAfter(.approve(scope: nil, durationIndex: nil, surface: .phone, lineShown: false))) == 0,
          "pairing: a phone approval that did not show the line does not pair")
    check(await pairingCount(pairAfter(.approve(scope: nil, durationIndex: 1, surface: .phone))) == 0,
          "pairing: a phone approval with a lifetime cap does not pair")
    check(await pairingCount(pairAfter(.approve(scope: nil, durationIndex: nil, surface: .mac, lineShown: false))) == 0,
          "pairing: a Mac approval whose line was hidden does not pair")
    check(await pairingCount(pairAfter(.approve(scope: nil, durationIndex: nil, surface: nil))) == 0,
          "pairing: an approval that names no surface is never taken as the Mac")
    check(await pairingCount(pairAfter(.approve(scope: .requestingCommand, durationIndex: nil, surface: .mac))) == 0,
          "pairing: narrowing the scope to the command does not pair")
    check(await pairingCount(pairAfter(.approve(scope: .terminalSession, durationIndex: nil, surface: .mac))) == 0,
          "pairing: widening the scope to the terminal does not pair")
    check(await pairingCount(pairAfter(.approve(scope: nil, durationIndex: 1, surface: .mac))) == 0,
          "pairing: picking a lifetime cap does not pair")
    check(await pairingCount(pairAfter(mac, request: { execRequest() })) == 0,
          "pairing: a request delegation did not judge (a nested csec exec) never pairs")
    check(!AICommandExec.isAIRequest(plan: csecGetPlan(), commandLine: nil),
          "pairing: a nested csec get is not a csec ai request, so delegation never judges or pairs it")

    // Only the references this approval authorized are paired: one a live
    // grant already covered (here in another store, so not even on the
    // panel) was not part of the decision.
    if let covered = LiveCommand() {
        defer { covered.stop() }
        let coveredReference = "csec://beta/KEY"
        let coveredReview = DelegationReview(.approve(scope: .requestingCommand, durationIndex: nil, surface: .mac))
        let coveredHarness = await makeAgentHarness(
            commands: [(covered, Standard.program)], pairings: [], review: coveredReview
        )
        _ = await register(coveredHarness.service, Standard.program, peer: Standard.hookPeer)
        if let first = aiRequest(Standard.program, references: [coveredReference]),
           let second = aiRequest(Standard.program, references: [coveredReference, alphaReference]) {
            let firstReleased = await coveredHarness.agent.handle(request: first, caller: covered.caller)
            await coveredReview.answer(mac)
            let secondReleased = await coveredHarness.agent.handle(request: second, caller: covered.caller)
            let shown = await coveredReview.last?.credentials.flatMap(\.references).map(\.uri)
            let stored = await storedPairings(coveredHarness.stores)
            check(firstReleased.values?[coveredReference] != nil
                    && secondReleased.values?[coveredReference] != nil && secondReleased.values?[alphaReference] != nil
                    && shown == [alphaReference]
                    && stored?.count == 1 && stored?.first?.references == [alphaReference],
                  "pairing: only the references the approval authorized are paired, never one a live grant already covered")
        } else {
            check(false, "pairing: only the references the approval authorized are paired, never one a live grant already covered")
        }
    }

    // After pairing, a new Claude Code session in the same project delegates.
    guard let pairedHarness else { return }
    let newAgent: pid_t = 61_310
    pairedHarness.facts.mutate { tree in
        var extra = DelegationTree()
        extra.session(newAgent, parent: Standard.fish)
        extra.command(61_312, shell: 61_311, agent: newAgent, program: Standard.program)
        extra.hook(61_314, shell: 61_313, agent: newAgent)
        for (pid, process) in extra.processes { tree[pid] = process }
    }
    _ = await register(pairedHarness.service, Standard.program, peer: 61_314)
    let reviews = await pairedHarness.review.count
    guard let request = aiRequest(Standard.program) else { return }
    let released = await pairedHarness.agent.handle(
        request: request, caller: CallerInfo(pid: 61_312, startTime: 613_120, description: "csec ai")
    )
    let reviewsAfter = await pairedHarness.review.count
    check(released.values?[alphaReference] != nil && reviewsAfter == reviews,
          "pairing: a new session in the paired project then delegates with no panel")

    // Approving a panel for references the project already has (a default-
    // mode run in a paired project) adds nothing: no pairing line, no write
    // to the pairing item, no "paired" record.
    guard let repeatCommand = LiveCommand() else { return }
    defer { repeatCommand.stop() }
    var repeatTree = DelegationTree()
    repeatTree.terminal(Standard.fish)
    repeatTree.session(Standard.agent, parent: Standard.fish)
    repeatTree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
    repeatTree.command(repeatCommand.pid, start: repeatCommand.start, shell: 61_320, agent: Standard.agent, program: Standard.program)
    let (repeatFacts, repeatInspection) = repeatTree.build()
    let backend = InMemoryProtectedItemBackend()
    let repeatStores = ProtectedStores.processLocal(backend)
    await enableDelegation(repeatStores)
    await seedPairings(repeatStores, [pairing()])
    let repeatLog = await makeDelegationLog(repeatStores)
    let repeatProvider = HeldFixtureProvider(
        schemes: ["csec"], values: [alphaReference: Data("synthetic-alpha-value".utf8)], held: [alphaReference]
    )
    let repeatResolver = SecretResolver(cache: NullSecretCache())
    await repeatResolver.register(repeatProvider)
    let repeatConsent = DelegationSheetConsent()
    let repeatService = makeService(repeatFacts, stores: repeatStores, consent: repeatConsent, log: repeatLog)
    let repeatReview = DelegationReview(mac)
    let repeatAgent = Agent(
        resolver: repeatResolver, grants: GrantTable(), consent: repeatConsent, policyReview: repeatReview,
        allowUnverifiedPlansForTesting: true, processInspection: repeatInspection,
        terminalInspection: .unavailable, decisionLog: repeatLog, delegation: repeatService
    )
    _ = await register(repeatService, Standard.program, peer: Standard.hookPeer, mode: "default")
    func pairingWrites() async -> Int { await backend.operations(on: .pairing).filter { $0 != .read }.count }
    let pairingWritesBefore = await pairingWrites()
    guard let repeatRequest = aiRequest(Standard.program) else { return }
    let repeatReleased = await repeatAgent.handle(request: repeatRequest, caller: repeatCommand.caller)
    let pairingWritesAfter = await pairingWrites()
    let repeatNote = await repeatReview.last?.delegationNote
    let repeatOffer = await repeatReview.last?.pairingOffer
    let pairedRecords = await repeatLog.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
        .filter { $0.detail?.hasPrefix("paired") == true }
    let storedRepeat = await storedPairings(repeatStores)
    check(repeatReleased.values?[alphaReference] != nil && repeatNote == .notAutoMode("default") && repeatOffer == nil
            && pairingWritesAfter == pairingWritesBefore && pairedRecords.isEmpty
            && storedRepeat?.first?.references == [alphaReference],
          "pairing: approving references the project already has shows no pairing line, rewrites nothing and logs no pairing")
    // Re-approving through the service directly (the SSH or .notHeld path)
    // is the same: recency only, in memory.
    await repeatService.recordHumanApproval(
        session: DelegationSession(
            agent: ProcessIncarnation(pid: Standard.agent, startTime: UInt64(Standard.agent) * 10),
            project: projectKey(), buildLabel: "2.1.280"
        ),
        references: [ref(alphaReference)], surface: .mac
    )
    let pairingWritesAtEnd = await pairingWrites()
    let pairedAtEnd = await repeatLog.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
        .filter { $0.detail?.hasPrefix("paired") == true }
    check(pairingWritesAtEnd == pairingWritesBefore && pairedAtEnd.isEmpty,
          "pairing: recording an approval of already-paired references writes nothing and logs no pairing")
}

private func pairingCount(_ result: (paired: [ProjectPairing]?, harness: AgentHarness?)) -> Int {
    result.paired?.count ?? -1
}

private func csecGetPlan() -> DeliveryPlan {
    DeliveryPlan(
        mechanism: .rawStandardOutput,
        executable: PlannedExecutable(
            canonicalPath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec", assurance: .verifiedProduct
        ),
        requestingExecutable: PlannedExecutable(canonicalPath: "/bin/zsh", assurance: .independentlyProtected),
        root: .directParent(pid: 4242, startTime: 999_999),
        descendantScope: .subtree,
        destination: .humanOutput,
        recipientAssurance: .interactiveTerminal,
        requestedTTLSeconds: nil,
        operationContext: "interactive get"
    )
}

// MARK: - The pairing store

private func delegationPairingStoreTests() async {
    let (facts, _) = Standard.tree().build()
    let backend = InMemoryProtectedItemBackend()
    let stores = ProtectedStores.processLocal(backend)
    await enableDelegation(stores)
    let log = await makeDelegationLog(stores)
    // A pairing written before csec-0.11 holds an SSH use and a pinned
    // launcher, which nothing adds any more: a later reference approval
    // keeps both, so they still list and revoke.
    let use = PairedSSHUse(keyFingerprint: "SHA256:key", hostKeyFingerprint: "SHA256:host", remoteUser: "git")
    let pinned = PinnedLauncher(path: "bin/push", digest: String(repeating: "a", count: 64), sources: [])
    var earlier = pairing(references: [], ssh: [use])
    earlier.launchers = [pinned]
    await seedPairings(stores, [earlier])
    let service = makeService(facts, stores: stores, log: log)
    let session = DelegationSession(
        agent: ProcessIncarnation(pid: Standard.agent, startTime: UInt64(Standard.agent) * 10),
        project: projectKey(), buildLabel: "2.1.280"
    )
    await service.recordHumanApproval(session: session, references: [ref(alphaReference)], surface: .mac)
    let restarted = makeService(facts, stores: stores)
    let entries = await restarted.grantEntries()
    check(entries?.pairings.count == 1 && entries?.pairings.first?.references == [alphaReference]
            && entries?.pairings.first?.ssh.count == 1 && entries?.pairings.first?.launchers.map(\.path) == ["bin/push"],
          "pairing store: pairings persist across a csecd restart, with the SSH uses and launchers an earlier csecd wrote")
    let writes = await backend.operations(on: .pairing).count
    _ = await register(restarted, Standard.program, peer: Standard.hookPeer)
    let used = await evaluate(restarted, command: Standard.command, program: Standard.program)
    if case let .approved(ticket) = used { await restarted.noteDelegatedRelease(ticket) }
    let writesAfter = await backend.operations(on: .pairing).count
    check(isApproved(used) && writesAfter == writes,
          "pairing store: using a pairing writes nothing (recency is kept in memory)")
    let settingsRecords = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
    check(settingsRecords.contains { $0.detail?.contains("paired 1 reference") == true && $0.decider == .humanLocal },
          "pairing store: adding a pairing is a decisions record")

    // Overflow by count: the least recent project goes first; a use counts.
    do {
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        let log = await makeDelegationLog(stores)
        await seedPairings(stores, (0..<256).map { pairing("/p/\($0)", inode: UInt64($0 + 1), id: String(format: "00000000-0000-4000-8000-%012d", $0)) })
        let service = makeService(facts, stores: stores, log: log)
        // Project 0 is used (its recency moves up), so project 1 is least recent.
        await service.noteDelegatedRelease(DelegationTicket(
            session: session, command: ProcessIncarnation(pid: 1_234, startTime: 1),
            project: projectKey("/p/0", inode: 1), pairingID: "00000000-0000-4000-8000-000000000000"
        ))
        await service.recordHumanApproval(
            session: DelegationSession(agent: session.agent, project: projectKey("/p/new", inode: 999), buildLabel: "x"),
            references: [ref(alphaReference)], surface: .mac
        )
        let projects = await storedPairings(stores)?.map(\.project.path) ?? []
        let evictions = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
            .filter { $0.detail?.contains("least recently used") == true }
        check(projects.count == 256 && projects.contains("/p/0") && !projects.contains("/p/1") && projects.contains("/p/new"),
              "pairing store: past 256 projects the least recently used goes first (a use counts, insertion order otherwise)")
        check(evictions.count == 1 && evictions.first?.detail?.contains("/p/1") == true,
              "pairing store: an eviction is logged")
    }
    // A use that drew on a directory's own pairing as well counts for both.
    do {
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, (0..<256).map { pairing("/p/\($0)", inode: UInt64($0 + 1), id: String(format: "00000000-0000-4000-8000-%012d", $0)) })
        let service = makeService(facts, stores: stores)
        await service.noteDelegatedRelease(DelegationTicket(
            session: session, command: ProcessIncarnation(pid: 1_234, startTime: 1),
            project: projectKey("/p/0", inode: 1), pairingID: "00000000-0000-4000-8000-000000000000",
            otherPairingIDs: ["00000000-0000-4000-8000-000000000001"]
        ))
        await service.recordHumanApproval(
            session: DelegationSession(agent: session.agent, project: projectKey("/p/new", inode: 999), buildLabel: "x"),
            references: [ref(alphaReference)], surface: .mac
        )
        let projects = await storedPairings(stores)?.map(\.project.path) ?? []
        check(projects.contains("/p/0") && projects.contains("/p/1") && !projects.contains("/p/2"),
              "pairing store: a use drawing on a directory's own pairing too keeps both recent")
    }
    // Overflow by size: the whole document stays within the item's 512 KiB.
    do {
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        let sizeLog = await makeDelegationLog(stores)
        let service = makeService(facts, stores: stores, log: sizeLog)
        let big = String(repeating: "k", count: 3_000)
        func references(_ tag: String) -> [SecretRef] { (0..<100).map { ref("csec://\(tag)/\(big)\($0)") } }
        let older = DelegationSession(agent: session.agent, project: projectKey("/p/older", inode: 11), buildLabel: "x")
        let newer = DelegationSession(agent: session.agent, project: projectKey("/p/newer", inode: 12), buildLabel: "x")
        await service.recordHumanApproval(session: older, references: references("older"), surface: .mac)
        await service.recordHumanApproval(session: newer, references: references("newer"), surface: .mac)
        let projects = await storedPairings(stores)?.map(\.project.path) ?? []
        check(projects == ["/p/newer"], "pairing store: a document over the item's size sheds the least recent project")
        let huge = DelegationSession(agent: session.agent, project: projectKey("/p/huge", inode: 13), buildLabel: "x")
        await service.recordHumanApproval(session: huge, references: (0..<256).map { ref("csec://huge/\(big)\($0)") }, surface: .mac)
        let kept = await storedPairings(stores)
        let hugeReferences = kept?.first { $0.project.path == "/p/huge" }?.references ?? []
        check(kept?.map(\.project.path) == ["/p/huge"] && hugeReferences.count < 256 && hugeReferences.count > 100
                && hugeReferences.last?.hasSuffix("255") == true,
              "pairing store: one project too large for the item keeps its newest references")
        let shedRecords = await sizeLog.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
            .filter { $0.detail?.contains("pairing item's size") == true }
        let shedCount = 256 - hugeReferences.count
            check(shedRecords.count == 1 && shedRecords.first?.detail?.contains("the oldest \(shedCount) entries") == true
                && shedRecords.first?.refs?.isEmpty == false
                && shedRecords.first?.detail?.contains("/p/huge") == true,
              "pairing store: the references one project sheds to fit the item are logged, by reference")
    }
    // Off: nothing is written.
    do {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        let service = makeService(facts, stores: stores)
        await service.recordHumanApproval(session: session, references: [ref(alphaReference)], surface: .mac)
        check(await storedPairings(stores)?.isEmpty == true, "pairing store: with delegation off no pairing is written")
    }
    // Not cleared by invalidate_cached_references.
    guard let command = LiveCommand() else { return }
    defer { command.stop() }
    let harness = await makeAgentHarness(commands: [(command, Standard.program)])
    _ = await harness.agent.invalidateCachedReferences(
        request: InvalidateCachedReferencesRequest(references: [alphaReference]), caller: command.caller
    )
    check(await storedPairings(harness.stores)?.first?.references == [alphaReference],
          "pairing store: invalidating a cached reference does not unpair it")
}

/// The pairing item a newer csecd wrote, as an older one finds it: kept as
/// found, so what the older one pairs lasts for its run and every pairing the
/// newer one saved is still there after the upgrade.
private func delegationHeldPairingTests() async {
    let newer = Data(#"{"document":{"projects":[{"future":true}]},"formatVersion":99}"#.utf8)
    let session = DelegationSession(
        agent: ProcessIncarnation(pid: Standard.agent, startTime: UInt64(Standard.agent) * 10),
        project: projectKey(), buildLabel: "2.1.280"
    )
    let (facts, _) = Standard.tree().build()
    let backend = InMemoryProtectedItemBackend()
    let stores = ProtectedStores.processLocal(backend)
    await enableDelegation(stores)
    let log = await makeDelegationLog(stores)
    await backend.setRawBytes(newer, for: .pairing)
    await backend.clearOperations()
    let service = makeService(facts, stores: stores, log: log)
    await service.recordHumanApproval(session: session, references: [ref(alphaReference)], surface: .mac)
    let afterPairing = await backend.rawBytes(for: .pairing)
    let writes = await backend.operations(on: .pairing).filter { $0 != .read }
    check(afterPairing == newer && writes.isEmpty,
          "held pairings: a pairing approved by a csecd that cannot read the item never writes it")
    _ = await register(service, Standard.program, peer: Standard.hookPeer)
    let used = await evaluate(service, command: Standard.command, program: Standard.program)
    let entries = await service.grantEntries()
    check(isApproved(used) && entries?.pairings.count == 1,
          "held pairings: the pairing holds for this csecd run")
    let heldStatus = await log.status().heldItems
    check(heldStatus == [HeldProtectedItem(item: .pairing, reason: .unsupportedFormatVersion(found: 99, supported: PairingDocument.formatVersion))]
            && heldStatus?.first?.cause == .newerFormat
            && heldStatus?.first?.remedy.contains("Install the latest Convenient Security package") == true,
          "held pairings: csec status is told the pairing item is held, and to install the latest Convenient Security package")
    let records = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
    check(records.contains { $0.detail?.contains("kept as found because this csecd cannot read them") == true
            && $0.detail?.contains("holds for this run only") == true },
          "held pairings: the pairing's record says it holds for this run only, and why")

    // Revoking the run's pairing removes it for this run, but the item this
    // csecd never read may pair the same project again: said, not hidden.
    guard let id = entries?.pairings.first?.id, let selector = GrantIDSelector("pair-" + id) else {
        check(false, "held pairings: the pairing's id parses")
        return
    }
    let removal = await service.remove(selector)
    let afterRemoval = await backend.rawBytes(for: .pairing)
    let remaining = await service.grantEntries()
    if case let .notPersisted(removed, failure) = removal {
        check(removed.count == 1 && afterRemoval == newer && remaining?.pairings.isEmpty == true
                && failure.contains("csec revoke --all"),
              "held pairings: revoking a pairing during a hold removes it for the run and says the item may restore it")
    } else {
        check(false, "held pairings: revoking a pairing during a hold is reported as not persisted (\(removal))")
    }

    // csec revoke --all: the human asked for every pairing to go, so the item
    // this csecd could not read goes too, and pairings persist again after.
    let all = await service.removeAllPairings()
    let afterAll = await backend.rawBytes(for: .pairing)
    let revokes = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.revoke])).records
    let heldAfterAll = await log.status().heldItems
    check(all.failure == nil && afterAll == nil && heldAfterAll == []
            && revokes.contains { $0.detail?.contains("discarded the saved pairings this csecd could not read") == true },
          "held pairings: revoke --all discards the item this csecd could not read, and logs it")
    await service.recordHumanApproval(session: session, references: [ref(alphaReference)], surface: .mac)
    check(await storedPairings(stores)?.count == 1, "held pairings: after the discard, a pairing is saved again")

    // A Keychain read that failed at startup holds the item the same way.
    do {
        let (facts, _) = Standard.tree().build()
        let backend = InMemoryProtectedItemBackend()
        let stores = ProtectedStores.processLocal(backend)
        await enableDelegation(stores)
        let saved = [pairing(references: [alphaReference, "csec://alpha/OTHER"])]
        await seedPairings(stores, saved)
        let savedBytes = await backend.rawBytes(for: .pairing)
        await backend.inject(.init(read: errSecInteractionNotAllowed), for: .pairing)
        let service = makeService(facts, stores: stores)
        await service.recordHumanApproval(
            session: DelegationSession(agent: session.agent, project: projectKey("/p/other", inode: 77), buildLabel: "x"),
            references: [ref(alphaReference)], surface: .mac
        )
        await backend.inject(.init(), for: .pairing)
        let afterFailedRead = await backend.rawBytes(for: .pairing)
        check(savedBytes != nil && afterFailedRead == savedBytes,
              "held pairings: after a failed Keychain read, a new pairing does not overwrite the saved ones")
    }

    // Turning delegation off discards held settings and pairings: off must
    // not leave a newer csecd anything to turn back on.
    do {
        guard let command = LiveCommand() else { return }
        defer { command.stop() }
        let (facts, _) = Standard.tree().build()
        let backend = InMemoryProtectedItemBackend()
        let stores = ProtectedStores.processLocal(backend)
        await backend.setRawBytes(Data(#"{"document":{},"formatVersion":99}"#.utf8), for: .delegationSettings)
        await backend.setRawBytes(newer, for: .pairing)
        let service = makeService(facts, stores: stores)
        let disabled = await service.configure(.disable(), caller: command.caller, terminal: nil)
        let settingsAfter = await backend.rawBytes(for: .delegationSettings)
        let pairingAfter = await backend.rawBytes(for: .pairing)
        check(disabled.failure == nil && settingsAfter == nil && pairingAfter == nil,
              "held pairings: turning delegation off discards settings and pairings this csecd could not read")
    }
}

// MARK: - Revocation

/// A reference whose source is gone (a machine identity target removed) is
/// unpaired from every project, so one made later under the same name never
/// inherits auto mode's approval.
private func delegationUnpairEverywhereTests() async {
    let signIn = "csec-identity://default/admin"
    let pairingA = pairing(references: [alphaReference, signIn], id: "b1111111-0000-4000-8000-000000000001")
    let pairingB = pairing(betaPath, inode: betaInode, references: [signIn], id: "b2222222-0000-4000-8000-000000000002")
    let harness = await makeAgentHarness(commands: [], pairings: [pairingA, pairingB])
    let changed = await harness.service.unpairEverywhere(references: [signIn], because: "the sign-in was removed")
    let stored = await storedPairings(harness.stores)
    check(changed == 2 && stored?.map(\.id) == [pairingA.id] && stored?.first?.references == [alphaReference],
          "unpair everywhere: the reference leaves every project, and a pairing left empty goes")
    let revokes = await harness.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.revoke])).records
    check(revokes.contains { $0.refs == [signIn] && $0.detail?.contains("the sign-in was removed") == true },
          "unpair everywhere: the decision log says what was unpaired and why")
    check(await harness.service.unpairEverywhere(references: [signIn], because: "again") == 0,
          "unpair everywhere: a reference no pairing holds changes nothing")
}

private func delegationRevocationTests() async {
    guard let command = LiveCommand() else { return }
    defer { command.stop() }
    let pairingA = pairing(id: "a1111111-0000-4000-8000-000000000001")
    let pairingB = pairing(betaPath, inode: betaInode, id: "a2222222-0000-4000-8000-000000000002")
    let harness = await makeAgentHarness(commands: [(command, Standard.program)], pairings: [pairingA, pairingB])
    let build = TrustedClaudeBuild(cdHash: String(repeating: "c", count: 40), versionLabel: "2.1.257", path: "/b", trustedAt: Date())
    let hook = AcknowledgedClaudeHook(digest: String(repeating: "d", count: 64), display: "tee hook", acknowledgedAt: Date())
    await enableDelegation(harness.stores, trusted: [build], acknowledged: [hook])
    let caller = command.caller
    func grants(_ request: GrantsRequest) async -> Response { await harness.agent.handleGrants(request: request, caller: caller) }

    let listed = await grants(GrantsRequest(action: .list))
    check(listed.delegationGrants?.pairings.count == 2 && listed.delegationGrants?.trustedBuilds.map(\.cdHash) == [build.cdHash]
            && listed.delegationGrants?.acknowledgedHooks.map(\.digest) == [hook.digest]
            && listed.delegationGrants?.isWellFormed == true && listed.grants?.isEmpty == true,
          "revocation: csec grants lists pairings, trusted builds and acknowledged hooks beside (not inside) grants")
    let ambiguous = await grants(GrantsRequest(action: .revoke, grantID: "pair-a"))
    let afterAmbiguous = await storedPairings(harness.stores)
    check(ambiguous.failure?.code == .invalidRequest && ambiguous.grantRevocation?.ambiguousMatches.count == 2
            && ambiguous.grantRevocation?.removed.isEmpty == true && afterAmbiguous?.count == 2,
          "revocation: an ambiguous pair- prefix removes nothing and lists both")
    let removed = await grants(GrantsRequest(action: .revoke, grantID: "pair-a1"))
    let afterRemoval = await storedPairings(harness.stores)
    check(removed.grantRevocation?.removed.map(\.kind) == [.pairing] && removed.revokedGrantCount == 1
            && afterRemoval?.map(\.id) == [pairingB.id],
          "revocation: csec revoke pair-<id> removes that pairing and persists it before replying")
    let untrusted = await grants(GrantsRequest(action: .revoke, grantID: "build-ccc"))
    let unhooked = await grants(GrantsRequest(action: .revoke, grantID: "hook-ddd"))
    let settings = await storedSettings(harness.stores)
    check(untrusted.grantRevocation?.removed.map(\.kind) == [.build] && unhooked.grantRevocation?.removed.map(\.kind) == [.hook]
            && settings?.trustedBuilds.isEmpty == true && settings?.acknowledgedHooks.isEmpty == true,
          "revocation: build- and hook- ids take the untrust/forget path")

    // A grant rooted at Claude Code: revoking it also unpairs its references.
    // The grant table checks its root against the kernel, so this Claude
    // Code process is a real one.
    guard let claude = LiveCommand() else { return }
    defer { claude.stop() }
    let fresh = await makeAgentHarness(
        commands: [(command, Standard.program)],
        pairings: [pairing(references: [alphaReference, "csec://alpha/OTHER"])],
        extraTree: { $0.session(claude.pid, start: claude.start, parent: Standard.fish) }
    )
    let grant = Grant(
        rootPID: claude.pid, rootStartTime: claude.start,
        references: [alphaReference], reason: "approved", scopeKind: .codingAgent, rootProcessLabel: "Claude Code"
    )
    await fresh.grants.add(grant)
    let revoked = await fresh.agent.handleGrants(
        request: GrantsRequest(action: .revoke, grantID: "grant-" + String(grant.id.uuidString.lowercased().prefix(8))),
        caller: caller
    )
    let remaining = await storedPairings(fresh.stores)
    check(revoked.grantRevocation?.removed.map(\.kind) == [.secret, .pairing] && revoked.revokedGrantCount == 2
            && remaining?.first?.references == ["csec://alpha/OTHER"],
          "revocation: revoking a grant rooted at a Claude Code P also unpairs its references for that project")
    // The grant's own root is what unpairs: another process with its pid
    // (the grant's root has exited) never does.
    let staleRoot = ProcessIncarnation(pid: claude.pid, startTime: claude.start + 1)
    let stale = await fresh.service.unpair(references: ["csec://alpha/OTHER"], ssh: [], root: staleRoot)
    let afterStale = await storedPairings(fresh.stores)
    check(stale.removed.isEmpty && stale.failure == nil && afterStale?.first?.references == ["csec://alpha/OTHER"],
          "revocation: an unpairing whose root is not the grant's own process (a reused pid) unpairs nothing")
    let all = await fresh.agent.handleGrants(request: GrantsRequest(action: .revoke, all: true), caller: caller)
    let pairingsAfterAll = await storedPairings(fresh.stores)
    let settingsAfterAll = await storedSettings(fresh.stores)
    check(all.grantRevocation?.removed.map(\.kind) == [.pairing] && pairingsAfterAll?.isEmpty == true
            && settingsAfterAll != nil,
          "revocation: revoke --all clears every pairing; delegation settings stay")

    // A revocation that unpairs, where the pairing item cannot be written
    // (the write and the fallback delete both fail): reported, never success.
    do {
        guard let failing = LiveCommand() else { return }
        defer { failing.stop() }
        let backend = InMemoryProtectedItemBackend()
        let failingStores = ProtectedStores.processLocal(backend)
        await enableDelegation(failingStores)
        await seedPairings(failingStores, [pairing(references: [alphaReference, "csec://alpha/OTHER"])])
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        tree.session(failing.pid, start: failing.start, parent: Standard.fish)
        let (facts, inspection) = tree.build()
        let service = makeService(facts, stores: failingStores)
        let grants = GrantTable()
        let agent = Agent(
            resolver: SecretResolver(cache: NullSecretCache()), grants: grants, consent: DelegationSheetConsent(),
            policyReview: DelegationReview(), allowUnverifiedPlansForTesting: true, processInspection: inspection,
            terminalInspection: .unavailable, delegation: service
        )
        let rooted = Grant(
            rootPID: failing.pid, rootStartTime: failing.start,
            references: [alphaReference], reason: "approved", scopeKind: .codingAgent, rootProcessLabel: "Claude Code"
        )
        await grants.add(rooted)
        _ = await service.grantEntries()
        await backend.inject(.failingWrites(-25_308, delete: -25_308), for: .pairing)
        let reply = await agent.handleGrants(
            request: GrantsRequest(action: .revoke, grantID: "grant-" + String(rooted.id.uuidString.lowercased().prefix(8))),
            caller: caller
        )
        check(reply.failure?.code == .internalError && reply.failure?.message.contains("pairing item") == true,
              "revocation: an unpairing whose pairing item cannot be written is reported as a failure, never as removed")
        // disable, where the pairing item cannot be deleted: reported too.
        await backend.inject(InMemoryProtectedItemBackend.Failures(delete: -25_308), for: .pairing)
        let disabled = await service.configure(.disable(), caller: caller, terminal: nil)
        check(disabled.failure?.code == .internalError && disabled.failure?.message.contains("pairings") == true,
              "revocation: a disable whose pairing item cannot be deleted is reported as a failure")
    }

    // Secret grants: a prefix shared by two is ambiguous.
    let me = getpid()
    let myStart = ProcessAncestry.startTime(of: me) ?? 1
    let twinA = Grant(id: UUID(uuidString: "abcd0000-0000-4000-8000-000000000001")!, rootPID: me, rootStartTime: myStart, references: ["csec://x/A"], reason: "a")
    let twinB = Grant(id: UUID(uuidString: "abcd0000-0000-4000-8000-000000000002")!, rootPID: me, rootStartTime: myStart, references: ["csec://x/B"], reason: "b")
    let twins = GrantTable()
    await twins.add(twinA)
    await twins.add(twinB)
    let twinAgent = Agent(
        resolver: SecretResolver(cache: NullSecretCache()), grants: twins, consent: DelegationSheetConsent(),
        policyReview: DelegationReview(), allowUnverifiedPlansForTesting: true,
        processInspection: ProcessInspection(
            startTime: { $0 == me ? myStart : nil }, parent: { _ in 0 }, name: { _ in nil }, executablePath: { _ in nil }
        ),
        terminalInspection: .unavailable
    )
    let twinReply = await twinAgent.handleGrants(request: GrantsRequest(action: .revoke, grantID: "abcd"), caller: caller)
    let twinsLeft = await twins.summaries(now: Date()).count
    check(twinReply.failure?.code == .invalidRequest && twinReply.grantRevocation?.ambiguousMatches.count == 2
            && twinsLeft == 2,
          "revocation: a secret-grant prefix matching two grants removes nothing and lists both")
}

// MARK: - configure_delegation

private func delegationConfigurationTests() async {
    let (facts, _) = Standard.tree().build()
    let caller = CallerInfo(pid: getpid(), startTime: ProcessAncestry.startTime(of: getpid()) ?? 1, description: "csec setup")
    let untrustedBuild = DiscoveredClaudeBuild(
        path: "/synthetic/.local/share/claude/versions/2.1.257", versionLabel: "2.1.257",
        cdHash: String(repeating: "c", count: 40), signedByAnthropic: false
    )
    let signedBuild = DiscoveredClaudeBuild(
        path: "/synthetic/.local/share/claude/versions/2.1.280", versionLabel: "2.1.280",
        cdHash: String(repeating: "a", count: 40), signedByAnthropic: true
    )
    let hook = hookSource("cc-caffeine@samber · PreToolUse *", digest: String(repeating: "d", count: 64))
    let gate = FakeSettingsGate(evaluation(hooks: [hook]), builds: [untrustedBuild, signedBuild])
    let consent = DelegationSheetConsent(approving: false)
    let stores = ProtectedStores.processLocal()
    let log = await makeDelegationLog(stores)
    let service = makeService(facts, stores: stores, gate: gate, consent: consent, log: log)
    let settingsPath = delegationHome + "/.claude/settings.json"
    func configure(_ request: DelegationConfigurationRequest) async -> Response {
        await service.configure(request, caller: caller, terminal: TerminalSessionContext(
            application: "iTerm2", title: "tab", windowIndex: 1, tabIndex: 3, tty: "ttys001"
        ))
    }

    let off = await configure(.status(claudeConfigDirectory: nil, projectDirectory: alphaPath))
    check(off.delegationStatus?.state == .off && off.delegationStatus?.discoveredUntrustedBuilds.map(\.cdHash) == [untrustedBuild.cdHash!]
            && off.delegationStatus?.settings?.hooks == [hook] && off.delegationStatus?.isWellFormed == true,
          "configure: status reports off, the untrusted build and csecd's own reading of the settings")

    let denied = await configure(.enable(claudeConfigDirectory: nil, projectDirectory: alphaPath,
                                         setClassifyAllShell: true, claudeSettingsPath: settingsPath))
    let settingsAfterDenial = await storedSettings(stores)
    let stateAfterDenial = await service.state
    check(denied.failure?.code == .consentDenied && settingsAfterDenial == nil && stateAfterDenial == .off
            && consent.reasons.count == 1,
          "configure: enable raises one Touch ID sheet; refusing it changes nothing")
    let reason = consent.reasons.last ?? ""
    check(reason.contains("build 2.1.257") && reason.contains("cc-caffeine@samber · PreToolUse *")
            && reason.contains("iTerm2") && !reason.contains("2.1.280"),
          "configure: the enable sheet's reason is csecd's inventory (untrusted builds, other hooks) and names the terminal")
    consent.approve(true)
    let enabled = await configure(.enable(claudeConfigDirectory: nil, projectDirectory: alphaPath,
                                          setClassifyAllShell: true, claudeSettingsPath: settingsPath))
    let document = await storedSettings(stores)
    check(enabled.delegationStatus?.state == .on && document?.trustedCDHashes == [untrustedBuild.cdHash!]
            && document?.acknowledgedDigests == [hook.digest] && document?.setClassifyAllShell == true
            && document?.claudeSettingsPath == settingsPath && enabled.delegationStatus?.claudeSettingsPath == settingsPath,
          "configure: an approved enable stores the opt-in, the builds and hooks it listed, and the settings record")
    _ = await configure(.enable(claudeConfigDirectory: nil, projectDirectory: alphaPath,
                                setClassifyAllShell: false, claudeSettingsPath: settingsPath))
    check(await storedSettings(stores)?.setClassifyAllShell == true,
          "configure: re-enabling the same settings file keeps a recorded setClassifyAllShell")
    let moved = "/synthetic/other/settings.json"
    _ = await configure(.enable(claudeConfigDirectory: nil, projectDirectory: alphaPath,
                                setClassifyAllShell: false, claudeSettingsPath: moved))
    let movedReason = consent.reasons.last ?? ""
    check(movedReason.contains("moving csec's Claude Code settings from \(settingsPath) to \(moved)")
            && consent.reasons.dropLast().allSatisfy { !$0.contains("moving csec's") },
          "configure: an enable for another settings file names both files on its sheet; one for the same file does not")
    let movedDocument = await storedSettings(stores)
    check(movedDocument?.claudeSettingsPath == moved && movedDocument?.setClassifyAllShell == false,
          "configure: enabling for another settings file replaces the record")

    // trust_build: csecd computes the cdhash; the sheet names the build.
    let inspected = String(repeating: "e", count: 40)
    let trustConsent = DelegationSheetConsent(approving: false)
    let trustService = makeService(
        facts, stores: stores, gate: gate, consent: trustConsent, log: log,
        inspector: ClaudeBuildInspector { $0.hasSuffix("2.1.300") ? InspectedClaudeBuild(cdHash: inspected, signedByAnthropic: false) : nil }
    )
    let trustPath = "/synthetic/.local/share/claude/versions/2.1.300"
    let trustDenied = await trustService.configure(
        .trustBuild(path: trustPath, claudeConfigDirectory: nil, projectDirectory: nil), caller: caller, terminal: nil
    )
    let trustedAfterDenial = await storedSettings(stores)?.trustedCDHashes.contains(inspected) ?? true
    check(trustDenied.failure?.code == .consentDenied && !trustedAfterDenial,
          "configure: trust_build raises one sheet; refusing it trusts nothing")
    trustConsent.approve(true)
    _ = await trustService.configure(
        .trustBuild(path: trustPath, claudeConfigDirectory: nil, projectDirectory: nil), caller: caller, terminal: nil
    )
    let sheets = trustConsent.reasons.count
    _ = await trustService.configure(
        .trustBuild(path: trustPath, claudeConfigDirectory: nil, projectDirectory: nil), caller: caller, terminal: nil
    )
    let trustedNow = await storedSettings(stores)?.trustedCDHashes.contains(inspected) == true
    check(trustedNow && trustConsent.reasons.count == sheets
            && trustConsent.reasons.first?.contains("2.1.300") == true,
          "configure: an approved trust_build stores csecd's cdhash; trusting it again raises no sheet")
    let notSigned = await trustService.configure(
        .trustBuild(path: "/synthetic/not-a-build", claudeConfigDirectory: nil, projectDirectory: nil), caller: caller, terminal: nil
    )
    check(notSigned.failure?.code == .invalidRequest, "configure: trust_build refuses a path that is not a signed executable")

    // acknowledge_hooks.
    let newHook = hookSource("tee hook · PermissionRequest", digest: String(repeating: "f", count: 64))
    gate.set(evaluation(hooks: [hook, newHook]))
    let ackConsent = DelegationSheetConsent(approving: false)
    let ackService = makeService(facts, stores: stores, gate: gate, consent: ackConsent, log: log)
    let ackDenied = await ackService.configure(.acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: nil)
    let acknowledgedAfterDenial = await storedSettings(stores)?.acknowledgedDigests.contains(newHook.digest) ?? true
    check(ackDenied.failure?.code == .consentDenied && !acknowledgedAfterDenial
            && ackConsent.reasons.first?.contains("tee hook") == true && ackConsent.reasons.first?.contains("cc-caffeine") == false,
          "configure: acknowledge_hooks lists only the new hooks; refusing it acknowledges nothing")
    ackConsent.approve(true)
    _ = await ackService.configure(.acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: nil)
    let ackSheets = ackConsent.reasons.count
    _ = await ackService.configure(.acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: nil)
    let acknowledgedNow = await storedSettings(stores)?.acknowledgedDigests.contains(newHook.digest) == true
    check(acknowledgedNow && ackConsent.reasons.count == ackSheets,
          "configure: an approved acknowledge_hooks stores the digests; nothing new raises no sheet")

    // untrust_build / forget_hook: no Touch ID.
    let removals = DelegationSheetConsent(approving: false)
    let removalService = makeService(facts, stores: stores, gate: gate, consent: removals, log: log)
    let untrusted = await removalService.configure(.untrustBuild(id: "build-eee"), caller: caller, terminal: nil)
    let forgotten = await removalService.configure(.forgetHook(id: "hook-fff"), caller: caller, terminal: nil)
    check(untrusted.grantRevocation?.removed.map(\.kind) == [.build] && forgotten.grantRevocation?.removed.map(\.kind) == [.hook]
            && untrusted.delegationStatus != nil && removals.reasons.isEmpty,
          "configure: untrust_build and forget_hook remove with no Touch ID and reply with the status")

    // disable: no Touch ID; the settings and every pairing go.
    await seedPairings(stores, [pairing()])
    let disabler = makeService(facts, stores: stores, gate: gate, consent: removals, log: log)
    let disabled = await disabler.configure(.disable(), caller: caller, terminal: nil)
    let settingsAfterDisable = await storedSettings(stores)
    let pairingsAfterDisable = await storedPairings(stores)
    check(disabled.delegationStatus?.state == .off && disabled.delegationStatus?.setClassifyAllShell == false
            && disabled.delegationStatus?.claudeSettingsPath == nil && settingsAfterDisable == nil
            && pairingsAfterDisable?.isEmpty == true && removals.reasons.isEmpty,
          "configure: disable deletes the settings and every pairing, with no Touch ID")
    let settingsRecords = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
    check(settingsRecords.contains { $0.detail?.contains("enabled") == true && $0.decider == .humanLocal }
            && settingsRecords.contains { $0.detail?.contains("trusted Claude Code build") == true }
            && settingsRecords.contains { $0.detail?.contains("acknowledged") == true }
            && settingsRecords.contains { $0.detail?.contains("disabled") == true },
          "configure: every settings mutation is a decisions record")

    // No protected stores: unavailable.
    let bare = makeService(facts, stores: nil)
    let unavailable = await bare.configure(.status(claudeConfigDirectory: nil, projectDirectory: nil), caller: caller, terminal: nil)
    let refused = await bare.configure(.enable(claudeConfigDirectory: nil, projectDirectory: nil, setClassifyAllShell: false,
                                               claudeSettingsPath: settingsPath), caller: caller, terminal: nil)
    check(unavailable.delegationStatus?.state == .unavailable && refused.failure?.code == .policyDenied,
          "configure: without protected stores delegation is unavailable and cannot be enabled")

    await delegationRefusalReasonTests(facts: facts, caller: caller)
    await delegationSettingsPanelTests(facts: facts, caller: caller)
    settingsChangeReviewShapeTests()
    await delegationSheetRaceTests(facts: facts, caller: caller)
    await delegationPolicyVersionTests(facts: facts, caller: caller)
    await delegationUnwrittenRemovalTests(facts: facts, caller: caller)
}

/// A delegation sheet that does not approve says why (csec-0.51): the
/// human's Deny, a sheet macOS dismissed and a finger Touch ID did not
/// recognise each reach `csec setup` and the decision log as their own
/// reason, with how long the sheet was up, and change nothing.
private func delegationRefusalReasonTests(facts: any ClaudeSessionFactProvider, caller: CallerInfo) async {
    let hook = hookSource("cc-caffeine@samber · PreToolUse *", digest: String(repeating: "d", count: 64))
    let gate = FakeSettingsGate(evaluation(hooks: [hook]))
    let stores = ProtectedStores.processLocal()
    let log = await makeDelegationLog(stores)
    let deny = ConsentRefusal(errorCode: LAError.Code.userCancel.rawValue, shownFor: .milliseconds(8_000))
    let consent = DelegationExplainingSheetConsent(.refused(deny))
    let service = makeService(facts, stores: stores, gate: gate, consent: consent, log: log)
    let settingsPath = delegationHome + "/.claude/settings.json"
    let enable = DelegationConfigurationRequest.enable(
        claudeConfigDirectory: nil, projectDirectory: alphaPath, setClassifyAllShell: true, claudeSettingsPath: settingsPath)
    func lastSettingsRecord() async -> DecisionLogRecord? {
        await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records.last
    }

    let denied = await service.configure(enable, caller: caller, terminal: nil)
    let deniedRecord = await lastSettingsRecord()
    let deniedSettings = await storedSettings(stores)
    check(denied.failure?.code == .consentDenied && denied.failure?.message.hasPrefix("you pressed Deny") == true
            && denied.failure?.message.contains("8.0s") == true && deniedSettings == nil,
          "refusal reason: a Deny on the enable sheet answers consentDenied saying so, and enables nothing")
    check(deniedRecord?.outcome == .denied && deniedRecord?.decider == .humanLocal && deniedRecord?.cause == "user_cancel"
            && deniedRecord?.ttdMs == 8_000
            && deniedRecord?.detail?.hasPrefix("enabling Claude Code auto-mode approvals was not approved: you pressed Deny") == true,
          "refusal reason: a Deny is logged as the human's denial, with its cause and how long the sheet was up")

    let dismissed = ConsentRefusal(
        errorCode: LAError.Code.systemCancel.rawValue, shownFor: .milliseconds(1_500), shownAgain: true)
    consent.answer(.refused(dismissed))
    let dismissedResponse = await service.configure(enable, caller: caller, terminal: nil)
    let dismissedRecord = await lastSettingsRecord()
    check(dismissedResponse.failure?.code == .consentDenied
            && dismissedResponse.failure?.message.hasPrefix("macOS dismissed the sheet") == true
            && dismissedResponse.failure?.message.contains("shown again") == true,
          "refusal reason: a sheet macOS dismissed (after being shown again) says so, not that the human denied it")
    check(dismissedRecord?.outcome == .authenticationFailed && dismissedRecord?.decider == nil
            && dismissedRecord?.cause == "system_cancel" && dismissedRecord?.ttdMs == 1_500,
          "refusal reason: a dismissed sheet is logged as system_cancel, never as a human denial")

    consent.answer(.refused(ConsentRefusal(
        errorCode: LAError.Code.authenticationFailed.rawValue, shownFor: .milliseconds(12_250))))
    let failedResponse = await service.configure(enable, caller: caller, terminal: nil)
    let failedRecord = await lastSettingsRecord()
    check(failedResponse.failure?.message.hasPrefix("Touch ID did not recognise the finger") == true
            && failedRecord?.outcome == .authenticationFailed && failedRecord?.cause == "auth_failed"
            && failedRecord?.ttdMs == 12_250,
          "refusal reason: a finger Touch ID did not recognise is its own logged reason")
    let reasons = Set([deniedRecord?.cause, dismissedRecord?.cause, failedRecord?.cause].compactMap { $0 })
    let messages = Set([denied, dismissedResponse, failedResponse].compactMap { $0.failure?.message })
    check(reasons.count == 3 && messages.count == 3,
          "refusal reason: cancelled, dismissed and failed sheets each produce a distinct logged reason and message")
    check(await storedSettings(stores) == nil, "refusal reason: no refusal enabled anything")

    // The trust_build and acknowledge_hooks sheets log their refusals too.
    consent.answer(.approved(unlock: nil))
    _ = await service.configure(enable, caller: caller, terminal: nil)
    let inspected = String(repeating: "e", count: 40)
    let trustService = makeService(
        facts, stores: stores, gate: gate, consent: consent, log: log,
        inspector: ClaudeBuildInspector { _ in InspectedClaudeBuild(cdHash: inspected, signedByAnthropic: false) }
    )
    consent.answer(.refused(deny))
    let trust = await trustService.configure(
        .trustBuild(path: "/synthetic/.local/share/claude/versions/2.1.300", claudeConfigDirectory: nil, projectDirectory: nil),
        caller: caller, terminal: nil)
    let trustRecord = await lastSettingsRecord()
    check(trust.failure?.code == .consentDenied && trust.failure?.message.hasPrefix("you pressed Deny") == true
            && trustRecord?.cause == "user_cancel"
            && trustRecord?.detail?.hasPrefix("trusting Claude Code build 2.1.300 was not approved") == true,
          "refusal reason: a refused trust_build sheet is logged with its reason")
    gate.set(evaluation(hooks: [hook, hookSource("tee hook · PermissionRequest", digest: String(repeating: "f", count: 64))]))
    let ackService = makeService(facts, stores: stores, gate: gate, consent: consent, log: log)
    consent.answer(.refused(dismissed))
    let ack = await ackService.configure(
        .acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: nil)
    let ackRecord = await lastSettingsRecord()
    check(ack.failure?.code == .consentDenied && ackRecord?.cause == "system_cancel"
            && ackRecord?.detail?.hasPrefix("acknowledging 1 hook that can approve shell commands was not approved") == true,
          "refusal reason: a refused acknowledge_hooks sheet is logged with its reason")
}

/// csecd's queued reviewer as `SettingsChangeConsent` reaches it: records
/// each review and answers as the test sets. An approval carries a panel
/// session, as the trusted window's does, unless `headless`.
final class DelegationPanelReviewer: PolicyReviewProvider, @unchecked Sendable {
    enum Answer {
        case deny(shownFor: Duration)
        case approve
        case approveHeadless
        case fail
        case requesterGone
    }

    private struct ApprovedPanel: AccessPolicyAuthenticationSession {
        func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome { .approved(unlock: nil) }
        func cancel() async {}
    }

    private let lock = NSLock()
    private var answer: Answer
    private var recorded: [AccessPolicyReview] = []

    init(_ answer: Answer) {
        self.answer = answer
    }

    func answer(_ next: Answer) {
        lock.withLock { answer = next }
    }

    var reviews: [AccessPolicyReview] { lock.withLock { recorded } }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        let answer = lock.withLock { () -> Answer in
            recorded.append(review)
            return self.answer
        }
        switch answer {
        case let .deny(shownFor):
            let now = ContinuousClock.now
            return .denied(.human(decidedAt: now, on: .mac, shownAt: now - shownFor))
        case .approve:
            return .approved(AccessPolicyApproval(authenticationSession: ApprovedPanel(), decidedOn: .mac))
        case .approveHeadless:
            return .approved(AccessPolicyApproval())
        case .fail:
            return .denied(.authenticationFailed)
        case .requesterGone:
            return .denied(.requesterGone)
        }
    }
}

/// Enabling, trusting a build and acknowledging hooks or classifier rules
/// show csecd's settings panel, not Apple's bare sheet:
/// the sheet took a Space typed as it appeared for its Deny. The panel's
/// typing guard itself is `cs-selftest --prompt-grace-only`'s settings panel.
private func delegationSettingsPanelTests(facts: any ClaudeSessionFactProvider, caller: CallerInfo) async {
    let hook = hookSource("cc-caffeine@samber · PreToolUse *", digest: String(repeating: "d", count: 64))
    let gate = FakeSettingsGate(evaluation(hooks: [hook]))
    let stores = ProtectedStores.processLocal()
    let log = await makeDelegationLog(stores)
    let sheet = DelegationSheetConsent(approving: true)
    let reviewer = DelegationPanelReviewer(.deny(shownFor: .milliseconds(8_000)))
    let consent = SettingsChangeConsent(underlying: sheet, review: reviewer)
    let service = makeService(facts, stores: stores, gate: gate, consent: consent, log: log)
    let settingsPath = delegationHome + "/.claude/settings.json"
    let enable = DelegationConfigurationRequest.enable(
        claudeConfigDirectory: nil, projectDirectory: alphaPath, setClassifyAllShell: true, claudeSettingsPath: settingsPath)
    let tab = TerminalSessionContext(application: "iTerm2", title: "setup", location: "window 1, tab 3", tty: "ttys004")
    func lastSettingsRecord() async -> DecisionLogRecord? {
        await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records.last
    }

    let denied = await service.configure(enable, caller: caller, terminal: tab)
    let deniedRecord = await lastSettingsRecord()
    let shown = reviewer.reviews.last
    check(shown?.settingsChange?.title == "Turn On Claude Code Auto-Mode Approvals"
            && shown?.settingsChange?.changes.first
                == "Let Claude Code auto mode approve csec secrets for its commands in projects you pair"
            && shown?.settingsChange?.changes.contains {
                $0.hasPrefix("Acknowledge cc-caffeine@samber · PreToolUse *, which can approve")
            } == true,
          "settings panel: enabling shows the panel, listing what turning it on approves")
    check(shown?.macOnly == true && shown?.credentials.isEmpty == true && shown?.scopeChoices == nil
            && shown?.durationChoices == nil && shown?.delegationNote == nil && shown?.pairingOffer == nil
            && shown?.caller.pid == caller.pid && shown?.caller.terminal?.location == "window 1, tab 3",
          "settings panel: decided at this Mac only, releasing nothing, naming the tab the request came from")
    check(sheet.reasons.isEmpty, "settings panel: no bare Touch ID sheet is shown for it")
    let deniedSettings = await storedSettings(stores)
    check(denied.failure?.code == .consentDenied
            && denied.failure?.message == "you pressed Deny; the panel was up 8.0s" && deniedSettings == nil
            && deniedRecord?.outcome == .denied && deniedRecord?.decider == .humanLocal
            && deniedRecord?.cause == "user_cancel" && deniedRecord?.ttdMs == 8_000,
          "settings panel: its Deny refuses as the sheet's did, logged as the human's denial, and enables nothing")

    reviewer.answer(.fail)
    let failed = await service.configure(enable, caller: caller, terminal: tab)
    let failedRecord = await lastSettingsRecord()
    check(failed.failure?.code == .consentDenied && failedRecord?.outcome == .authenticationFailed
            && failedRecord?.decider == nil && failedRecord?.cause == "panel_failed",
          "settings panel: a panel that ended without Touch ID or Deny is logged as its failure, never a human denial")
    reviewer.answer(.requesterGone)
    let gone = await service.configure(enable, caller: caller, terminal: tab)
    let goneRecord = await lastSettingsRecord()
    let notEnabled = await storedSettings(stores)
    check(gone.failure?.code == .consentDenied && goneRecord?.outcome == .requesterGone && notEnabled == nil,
          "settings panel: a request that went away changes nothing")

    reviewer.answer(.approve)
    let enabled = await service.configure(enable, caller: caller, terminal: tab)
    let enabledSettings = await storedSettings(stores)
    check(enabled.failure == nil && enabled.delegationStatus?.state == .on && enabledSettings != nil
            && sheet.reasons.isEmpty,
          "settings panel: Touch ID on the panel turns delegation on, with no sheet")

    // trust_build and acknowledge_hooks take the same panel.
    let inspected = String(repeating: "e", count: 40)
    let trustService = makeService(
        facts, stores: stores, gate: gate, consent: consent, log: log,
        inspector: ClaudeBuildInspector { _ in InspectedClaudeBuild(cdHash: inspected, signedByAnthropic: false) }
    )
    let buildPath = "/synthetic/.local/share/claude/versions/2.1.300"
    let trusted = await trustService.configure(
        .trustBuild(path: buildPath, claudeConfigDirectory: nil, projectDirectory: nil), caller: caller, terminal: tab)
    let trustShown = reviewer.reviews.last?.settingsChange
    let trustedSettings = await storedSettings(stores)
    check(trusted.failure == nil && trustShown?.title == "Trust a Claude Code Build"
            && trustShown?.changes == [
                "Trust Claude Code build 2.1.300 (cdhash eeeeeeeeeeee) for auto-mode approvals", "Path: \(buildPath)",
            ]
            && trustedSettings?.trustedCDHashes.contains(inspected) == true,
          "settings panel: trusting a build names it, its cdhash and its path, and trusts it on Touch ID")
    gate.set(evaluation(hooks: [hook, hookSource("tee hook · PermissionRequest", digest: String(repeating: "f", count: 64))]))
    let ackService = makeService(facts, stores: stores, gate: gate, consent: consent, log: log)
    let acknowledged = await ackService.configure(
        .acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: tab)
    let ackShown = reviewer.reviews.last?.settingsChange
    check(acknowledged.failure == nil && ackShown?.title == "Acknowledge Claude Code Hooks and Rules"
            && ackShown?.changes == ["Acknowledge tee hook · PermissionRequest, which can approve Claude Code's shell commands"]
            && sheet.reasons.isEmpty,
          "settings panel: acknowledging hooks lists each one and acknowledges them on Touch ID")

    // A reviewer with no panel of its own (injected, headless) still has the
    // touch asked for, on the sheet, with the reason it always had.
    let headless = DelegationPanelReviewer(.approveHeadless)
    let refusingSheet = DelegationSheetConsent(approving: false)
    gate.set(evaluation(hooks: [hook, hookSource("other hook · PreToolUse Bash", digest: String(repeating: "a", count: 64))]))
    let headlessService = makeService(
        facts, stores: stores, gate: gate,
        consent: SettingsChangeConsent(underlying: refusingSheet, review: headless), log: log)
    let headlessAck = await headlessService.configure(
        .acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: tab)
    check(headless.reviews.count == 1 && refusingSheet.reasons.count == 1
            && refusingSheet.reasons.first?.hasPrefix("Acknowledge other hook · PreToolUse Bash") == true
            && headlessAck.failure?.code == .consentDenied,
          "settings panel: a reviewer with no panel session leaves the touch to the sheet, which still decides")

    // A provider with no panel keeps asking as it did, reason unchanged.
    let plain = DelegationSheetConsent(approving: false)
    let answer = await plain.authenticateSettingsChange(
        SettingsChangeReviewDetails(title: "T", changes: ["c"]), caller: caller, reason: "the reason")
    check(answer.refusal != nil && plain.reasons == ["the reason"],
          "settings panel: a consent provider without a panel shows the sheet with the one-line reason")
}

/// The settings layout's details are value-free and bounded, and its review
/// can carry nothing a release panel would.
private func settingsChangeReviewShapeTests() {
    let long = String(repeating: "x", count: 5_000)
    let details = SettingsChangeReviewDetails(
        title: "Title\u{1b}[31m", changes: (1...9).map { "change \($0)" } + [long])
    check(details.changes.count == SettingsChangeReviewDetails.maximumChanges + 1
            && details.changes.last == "and 4 more changes"
            && details.changes.allSatisfy { $0.utf8.count <= SettingsChangeReviewDetails.maximumChangeBytes }
            && !details.title.contains("\u{1b}"),
          "settings change: at most six lines, each bounded and sanitized, then how many more")
    let caller = CallerInfo(pid: 51, startTime: 9, description: "csec")
    let review = AccessPolicyReview(
        caller: caller, reason: "r",
        plan: AccessPolicyReview.settingsChange(caller: caller, change: details).plan,
        credentials: [],
        delegationNote: .notAutoMode("default"),
        pairingOffer: DelegationPairingOffer(projectName: "dev", scopeOptionID: "x"),
        settingsChange: details
    )
    check(review.macOnly && review.delegationNote == nil && review.pairingOffer == nil
            && review.requesterCommandLine == nil && !review.isRestoreOnly
            && DeliveryReviewCopy.warning(for: review) == nil
            && DeliveryReviewCopy.footnote(for: review) == SettingsChangeReviewDetails.settingsFootnote,
          "settings change: Mac-only unless it names a phone operation, with no delegation note, pairing line or delivery warning")
    check(ConsentRefusal(panelDenial: .withdrawn).cause == .requesterGone
            && ConsentRefusal(panelDenial: .timedOut).cause == .requesterGone
            && ConsentRefusal(panelDenial: .authenticationFailed).logOutcome == .authenticationFailed
            && ConsentRefusal(panelDenial: .human(decidedAt: .now)).isHumanRefusal,
          "settings change: only the panel's Deny is the human refusing")
}

/// An untrust_build or forget_hook whose settings write and fallback delete
/// both fail: the removal still holds for this run (less trust is always
/// safe), and the reply says it could not be written.
private func delegationUnwrittenRemovalTests(facts: SyntheticClaudeSessionFacts, caller: CallerInfo) async {
    // P runs a build trusted only by its cdhash.
    let patched = String(repeating: "c", count: 40)
    let (patchedFacts, _) = Standard.tree {
        $0.session(Standard.agent, parent: Standard.fish, identity: patchedClaudeIdentity(pid: Standard.agent, cdHash: patched))
    }.build()
    let backend = InMemoryProtectedItemBackend()
    let stores = ProtectedStores.processLocal(backend)
    let build = TrustedClaudeBuild(cdHash: patched, versionLabel: "2.1.257", path: "/b", trustedAt: Date())
    let hook = AcknowledgedClaudeHook(digest: String(repeating: "d", count: 64), display: "tee hook", acknowledgedAt: Date())
    await enableDelegation(stores, trusted: [build], acknowledged: [hook])
    await seedPairings(stores, [pairing()])
    let service = makeService(patchedFacts, stores: stores)
    _ = await register(service, Standard.program, peer: Standard.hookPeer)
    let before = await evaluate(service, command: Standard.command, program: Standard.program)
    await backend.inject(.failingWrites(-25_308, delete: -25_308), for: .delegationSettings)
    let untrust = await service.configure(.untrustBuild(id: "build-ccc"), caller: caller, terminal: nil)
    let forget = await service.configure(.forgetHook(id: "hook-ddd"), caller: caller, terminal: nil)
    let entries = await service.grantEntries()
    let after = await evaluate(service, command: Standard.command, program: Standard.program)
    let untrustMessage = untrust.failure?.message ?? ""
    check(untrust.failure?.code == .internalError && untrustMessage.contains("removed for this csecd run")
            && untrustMessage.contains("could not be written") && untrustMessage.contains("after csecd restarts")
            && untrust.grantRevocation?.removed.map(\.kind) == [.build]
            && forget.failure?.code == .internalError && forget.grantRevocation?.removed.map(\.kind) == [.hook]
            && entries?.builds.isEmpty == true && entries?.hooks.isEmpty == true,
          "configure: an untrust or forget that cannot be written still holds for this run, and the reply says it was not written")
    check(isApproved(before) && decline(after) == .unverifiedBuild("2.1.257"),
          "configure: a build untrusted without being written no longer delegates for this run")
    _ = facts
}

/// A removal made while an authority-adding Touch ID sheet is up stays made:
/// the sheet's approval adds exactly what it listed to the settings as they
/// are then, and a disable made meanwhile is never undone.
private func delegationSheetRaceTests(facts: SyntheticClaudeSessionFacts, caller: CallerInfo) async {
    let settingsPath = delegationHome + "/.claude/settings.json"
    // untrust_build while acknowledge_hooks' sheet is up.
    do {
        let stores = ProtectedStores.processLocal()
        let build = TrustedClaudeBuild(cdHash: String(repeating: "c", count: 40), versionLabel: "2.1.257", path: "/b", trustedAt: Date())
        await enableDelegation(stores, trusted: [build])
        let newHook = hookSource("tee hook · PermissionRequest", digest: String(repeating: "f", count: 64))
        let sheet = DelegationHeldSheetConsent()
        let service = makeService(facts, stores: stores, gate: FakeSettingsGate(evaluation(hooks: [newHook])), consent: sheet)
        let ack = Task {
            await service.configure(.acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: nil)
        }
        let up = await eventuallyTrue { sheet.isUp }
        let untrust = await service.configure(.untrustBuild(id: "build-ccc"), caller: caller, terminal: nil)
        sheet.answer(true)
        let acknowledged = await ack.value
        let stored = await storedSettings(stores)
        check(up && untrust.grantRevocation?.removed.map(\.kind) == [.build] && acknowledged.failure == nil
                && stored?.trustedCDHashes.isEmpty == true && stored?.acknowledgedDigests == [newHook.digest],
              "configure: an untrust_build made while acknowledge_hooks' sheet is up stays made; the sheet adds only its hooks")
    }
    // forget_hook while trust_build's sheet is up.
    do {
        let stores = ProtectedStores.processLocal()
        let known = AcknowledgedClaudeHook(digest: String(repeating: "d", count: 64), display: "cc-caffeine", acknowledgedAt: Date())
        await enableDelegation(stores, acknowledged: [known])
        let inspected = String(repeating: "e", count: 40)
        let sheet = DelegationHeldSheetConsent()
        let service = makeService(
            facts, stores: stores, consent: sheet,
            inspector: ClaudeBuildInspector { _ in InspectedClaudeBuild(cdHash: inspected, signedByAnthropic: false) }
        )
        let trust = Task {
            await service.configure(
                .trustBuild(path: "/synthetic/.local/share/claude/versions/2.1.300", claudeConfigDirectory: nil, projectDirectory: nil),
                caller: caller, terminal: nil
            )
        }
        let up = await eventuallyTrue { sheet.isUp }
        let forget = await service.configure(.forgetHook(id: "hook-ddd"), caller: caller, terminal: nil)
        sheet.answer(true)
        let trusted = await trust.value
        let stored = await storedSettings(stores)
        check(up && forget.grantRevocation?.removed.map(\.kind) == [.hook] && trusted.failure == nil
                && stored?.acknowledgedDigests.isEmpty == true && stored?.trustedCDHashes == [inspected],
              "configure: a forget_hook made while trust_build's sheet is up stays made; the sheet adds only its build")
    }
    // disable while enable's sheet is up.
    do {
        let stores = ProtectedStores.processLocal()
        let sheet = DelegationHeldSheetConsent()
        let service = makeService(facts, stores: stores, consent: sheet)
        let enable = Task {
            await service.configure(
                .enable(claudeConfigDirectory: nil, projectDirectory: alphaPath, setClassifyAllShell: true, claudeSettingsPath: settingsPath),
                caller: caller, terminal: nil
            )
        }
        let up = await eventuallyTrue { sheet.isUp }
        let disabled = await service.configure(.disable(), caller: caller, terminal: nil)
        sheet.answer(true)
        let enabled = await enable.value
        let state = await service.state
        let stored = await storedSettings(stores)
        check(up && disabled.delegationStatus?.state == .off && enabled.failure?.code == .policyDenied
                && state == .off && stored == nil,
              "configure: a disable made while enable's sheet is up wins; the approved sheet turns nothing back on")
    }
    // disable while trust_build's sheet is up: the trust is refused too.
    do {
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        let sheet = DelegationHeldSheetConsent()
        let service = makeService(
            facts, stores: stores, consent: sheet,
            inspector: ClaudeBuildInspector { _ in InspectedClaudeBuild(cdHash: String(repeating: "9", count: 40), signedByAnthropic: false) }
        )
        let trust = Task {
            await service.configure(
                .trustBuild(path: "/synthetic/.local/share/claude/versions/2.1.301", claudeConfigDirectory: nil, projectDirectory: nil),
                caller: caller, terminal: nil
            )
        }
        let up = await eventuallyTrue { sheet.isUp }
        _ = await service.configure(.disable(), caller: caller, terminal: nil)
        sheet.answer(true)
        let trusted = await trust.value
        let stored = await storedSettings(stores)
        let state = await service.state
        check(up && trusted.failure?.code == .policyDenied && stored == nil && state == .off,
              "configure: a disable made while trust_build's sheet is up is never undone")
    }
}

/// Settings consented to an older delegation policy than the build's leave
/// delegation off (reconfirmation_required) until `enable` confirms again.
private func delegationPolicyVersionTests(facts: SyntheticClaudeSessionFacts, caller: CallerInfo) async {
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    await seedPairings(stores, [pairing()])
    let sheet = DelegationSheetConsent()
    let service = makeService(
        facts, stores: stores, consent: sheet,
        inspector: ClaudeBuildInspector { _ in InspectedClaudeBuild(cdHash: String(repeating: "7", count: 40), signedByAnthropic: false) },
        policyVersion: DelegationPolicy.currentVersion + 1
    )
    _ = await service.isEnabled()
    let state = await service.state
    let registered = await register(service, Standard.program, peer: Standard.hookPeer)
    let evaluated = await evaluate(service, command: Standard.command, program: Standard.program)
    let listed = await service.grantEntries()
    let discovered = await service.pairingsOfLiveSessions()
    let status = await service.configure(.status(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: nil)
    check(state == .reconfirmationRequired && !registered && evaluated == .notApplicable && listed == nil && discovered.isEmpty
            && status.delegationStatus?.state == .reconfirmationRequired && status.delegationStatus?.pairingCount == 0
            && status.delegationStatus?.policyVersion == DelegationPolicy.currentVersion + 1
            && status.delegationStatus?.consentedPolicyVersion == DelegationPolicy.currentVersion,
          "configure: settings consented to an older policy leave delegation off (reconfirmation_required): nothing registers, delegates, lists or restores")
    _ = await service.configure(
        .trustBuild(path: "/synthetic/.local/share/claude/versions/2.1.302", claudeConfigDirectory: nil, projectDirectory: nil),
        caller: caller, terminal: nil
    )
    let afterTrust = await storedSettings(stores)
    let stateAfterTrust = await service.state
    check(afterTrust?.trustedCDHashes == [String(repeating: "7", count: 40)]
            && afterTrust?.consentedPolicyVersion == DelegationPolicy.currentVersion && stateAfterTrust == .reconfirmationRequired,
          "configure: trust_build under an older consent keeps that consent's version (only enable confirms the new policy)")
    let enabled = await service.configure(
        .enable(claudeConfigDirectory: nil, projectDirectory: alphaPath, setClassifyAllShell: true,
                claudeSettingsPath: delegationHome + "/.claude/settings.json"),
        caller: caller, terminal: nil
    )
    let afterEnable = await storedSettings(stores)
    check(enabled.delegationStatus?.state == .on
            && afterEnable?.consentedPolicyVersion == DelegationPolicy.currentVersion + 1
            && afterEnable?.trustedCDHashes == [String(repeating: "7", count: 40)],
          "configure: enable confirms the build's policy (one sheet) and delegation is on again, keeping what was trusted")
}

// MARK: - Backend neutrality

private func delegationBackendNeutralityTests() async {
    guard let command = LiveCommand(), let coldCommand = LiveCommand(), let nestedClient = LiveCommand() else { return }
    defer { command.stop(); coldCommand.stop(); nestedClient.stop() }
    let nativeRef = "csec://neutral/TOKEN"
    let opRef = "op://Neutral/Item/credential"
    let vaultRef = "vault://neutral/key"
    var tree = DelegationTree()
    tree.terminal(Standard.fish)
    tree.session(Standard.agent, parent: Standard.fish)
    tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
    tree.command(command.pid, start: command.start, shell: 61_400, agent: Standard.agent, program: Standard.program)
    tree.command(coldCommand.pid, start: coldCommand.start, shell: 61_401, agent: Standard.agent, program: "cold")
    tree.processes[nestedClient.pid] = SyntheticClaudeSessionFacts.Process(
        startTime: nestedClient.start, parent: command.pid, executablePath: delegationCsecPath,
        argv: [delegationCsecPath, "bridge"]
    )
    let (facts, inspection) = tree.build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    await seedPairings(stores, [pairing(references: [nativeRef, opRef, vaultRef])])
    let service = makeService(facts, stores: stores)

    // csec:// through the native store, opened once by a release with an unlock.
    let unlock = CacheUnlock(LAContext())
    let native = NativeEncryptedFileProvider(
        keyBackend: InMemoryNativeStoreKeyBackend(), fileBackend: InMemoryNativeStoreFileBackend()
    )
    do {
        let store = try NativeStoreName("neutral")
        let edit = try await native.beginEdit(store: store, callerPID: 4_100, callerStartTime: 9, unlock: unlock)
        _ = try await native.commitEdit(
            sessionID: edit.sessionID, document: Data(#"{"TOKEN":"synthetic-native-value"}"#.utf8),
            callerPID: 4_100, callerStartTime: 9
        )
    } catch {
        check(false, "neutrality: the native store fixture builds (\(error))")
        return
    }
    let keychain = FakeKeychainBackend()
    let cache = KeychainSecretCache(backend: keychain)
    try? await cache.put(opRef, value: Data("synthetic-op-value".utf8))
    let onePassword = InteractiveOnlyProvider()
    let vault = HeldFixtureProvider(schemes: ["vault"], values: [vaultRef: Data("synthetic-vault-value".utf8)], held: [vaultRef])
    let resolver = SecretResolver(cache: cache)
    await resolver.register(native)
    await resolver.register(onePassword)
    await resolver.register(vault)
    let review = DelegationReview()
    let agent = Agent(
        resolver: resolver, grants: GrantTable(), consent: DelegationSheetConsent(), policyReview: review,
        nativeStore: native, allowUnverifiedPlansForTesting: true, processInspection: inspection,
        terminalInspection: .unavailable, delegation: service
    )
    _ = await register(service, Standard.program, peer: Standard.hookPeer)
    guard let request = aiRequest(Standard.program, references: [nativeRef, opRef, vaultRef]) else { return }
    let released = await agent.handle(request: request, caller: command.caller)
    let neutralReviews = await review.count
    let neutralResolves = await onePassword.interactiveResolves
    let neutralLoads = await keychain.loadCount
    check(released.values?[nativeRef] == Data("synthetic-native-value".utf8)
            && released.values?[opRef] == Data("synthetic-op-value".utf8)
            && released.values?[vaultRef] == Data("synthetic-vault-value".utf8)
            && neutralReviews == 0 && neutralResolves == 0 && neutralLoads == 0,
          "neutrality: csec://, a warm op:// and a third scheme release together, warm-only, with no interactive resolve")

    // A bridge client under the same approved command: the same references,
    // whatever their provider, through the same warm-only release.
    guard let nested = bridgeRequest(references: [opRef, vaultRef]) else { return }
    let nestedReleased = await agent.handle(request: nested, caller: nestedClient.caller)
    let nestedReviews = await review.count
    let nestedResolves = await onePassword.interactiveResolves
    check(nestedReleased.values?[opRef] == Data("synthetic-op-value".utf8)
            && nestedReleased.values?[vaultRef] == Data("synthetic-vault-value".utf8)
            && nestedReviews == 0 && nestedResolves == 0,
          "neutrality: a bridge request nested in the approved command releases op:// and a third scheme, warm-only")

    // A cold op:// (not held warm) is fetched from 1Password, whose provider
    // needs no csec unlock, with no panel.
    await cache.invalidate(opRef)
    _ = await register(service, "cold", peer: Standard.hookPeer)
    guard let coldRequest = aiRequest("cold", references: [opRef]) else { return }
    let coldReleased = await agent.handle(request: coldRequest, caller: coldCommand.caller)
    let coldReviews = await review.count
    let opResolves = await onePassword.interactiveResolves
    check(coldReleased.values?[opRef] == Data("synthetic-interactive-\(ref(opRef).path)".utf8)
            && coldReviews == nestedReviews && opResolves == 1,
          "neutrality: an op:// value csecd does not hold warm is fetched from 1Password, with no panel")
    let nativeCold = NativeEncryptedFileProvider(keyBackend: InMemoryNativeStoreKeyBackend(), fileBackend: InMemoryNativeStoreFileBackend())
    check(await nativeCold.resolveWithoutInteraction(ref(nativeRef)) == nil,
          "neutrality: a native store not opened in this lifetime is not held (no Keychain read, no prompt)")
    check(await OnePasswordProvider().resolveWithoutInteraction(ref(opRef)) == nil,
          "neutrality: the 1Password provider never resolves without interaction")
}

// MARK: - SSH

private func delegationSSHTests() async {
    guard let key = try? Ed25519SSHFixture(seed: 211), let host = try? Ed25519SSHFixture(seed: 223) else {
        check(false, "delegation SSH: key fixtures build")
        return
    }
    let session = Data(repeating: 0x55, count: 32)
    guard let binding = try? SSHDestinationBinding(
        hostKeyBlob: host.publicKeyBlob, sessionIdentifier: session,
        signature: host.signatureBlob(for: session), isForwarding: false
    ) else {
        check(false, "delegation SSH: the binding builds")
        return
    }
    let keyReference = "csec://ssh-delegation/key"
    let metadata = SSHKeyMetadata(
        reference: keyReference, fingerprint: sshFingerprint(key.publicKeyBlob),
        algorithm: "ssh-ed25519", publicKeyBlob: key.publicKeyBlob, label: "delegation key"
    )
    let use = PairedSSHUse(keyFingerprint: metadata.fingerprint, hostKeyFingerprint: binding.hostKeyFingerprint, remoteUser: "git")
    let ssh: pid_t = 63_001
    let command: pid_t = 63_010
    let shell: pid_t = 63_011

    typealias Link = SSHChainTestLink
    /// ssh ← links… ← A (csec ai) ← X ← P, returning (service, signing service, review).
    func world(
        _ links: [Link], program: String = "git push", sshArgv: [String] = ["ssh", "git@github.com"],
        held: Bool = true, pairings: [ProjectPairing]? = nil,
        launcher: Bool = true, register registered: Bool = true,
        reviewer: (any PolicyReviewProvider)? = nil, log: DecisionLog? = nil,
        factBound: Duration = ClaudeDelegationService.factBound,
        wrapFacts: (SyntheticClaudeSessionFacts) -> any ClaudeSessionFactProvider = { $0 },
        extra: (inout DelegationTree) -> Void = { _ in },
        clock: DelegationTestClock = DelegationTestClock(),
        repositories: ProjectRepository.FileSystem = .empty,
        gate: FakeSettingsGate = FakeSettingsGate(),
        buildVerification: ClaudeBuildVerification = delegationVerifiedBuilds,
        trusted: [TrustedClaudeBuild] = [],
        // csecd's own hooks-changed panel is answered Deny unless a test says
        // otherwise, so a hook decline keeps its signing panel (csec-0.64.7).
        serviceConsent: any ConsentProvider = RulesPanelConsent([.deny]),
        shellPrefix framing: String? = nil
    ) async -> (ClaudeDelegationService, SSHSigningService, DelegationReview, ProtectedStores) {
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        tree.session(Standard.agent, parent: Standard.fish)
        tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
        if let framing {
            tree.shellPrefix(command, agent: Standard.agent, framing: framing)
        } else {
            tree.command(command, shell: shell, agent: Standard.agent, program: program)
        }
        var parent = command
        for link in links.reversed() {
            tree.processes[link.pid] = SyntheticClaudeSessionFacts.Process(
                startTime: UInt64(link.pid) * 10, parent: parent, executablePath: link.path, argv: link.argv
            )
            tree.names[link.pid] = (link.path as NSString).lastPathComponent
            parent = link.pid
        }
        tree.processes[ssh] = SyntheticClaudeSessionFacts.Process(
            startTime: UInt64(ssh) * 10, parent: parent, executablePath: "/usr/bin/ssh", argv: sshArgv
        )
        tree.names[ssh] = "ssh"
        extra(&tree)
        let (facts, inspection) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores, trusted: trusted)
        await seedPairings(stores, pairings ?? [pairing(references: [], ssh: [use])])
        let service = makeService(
            wrapFacts(facts), stores: stores, gate: gate, consent: serviceConsent, log: log,
            launcher: DelegationLauncherCheck { _ in launcher }, buildVerification: buildVerification,
            factBound: factBound, clock: clock, repositories: repositories
        )
        if registered { _ = await register(service, program, peer: Standard.hookPeer) }
        let provider = HeldFixtureProvider(
            schemes: ["csec"], values: [keyReference: key.privateKeyPEM], held: held ? [keyReference] : []
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(provider)
        let review = DelegationReview()
        let signing = SSHSigningService(
            resolver: resolver, catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [metadata])),
            consent: DelegationSheetConsent(), policyReview: reviewer ?? review, allowUnverifiedCallersForTesting: true,
            processInspection: inspection, knownHostsLookup: SSHKnownHostsLookup { _ in ["github.com"] },
            terminalInspection: .unavailable, decisionLog: log, delegation: service
        )
        return (service, signing, review, stores)
    }
    func sign(_ signing: SSHSigningService, user: String = "git", from requester: pid_t = ssh) async -> Data? {
        try? await signing.signSSHAuthentication(
            publicKeyBlob: key.publicKeyBlob,
            signedData: userAuthenticationRequest(
                sessionIdentifier: session, remoteUser: user,
                publicKeyBlob: key.publicKeyBlob, hostKeyBlob: host.publicKeyBlob
            ),
            flags: 0, binding: binding,
            caller: CallerInfo(pid: requester, startTime: UInt64(requester) * 10, description: "Apple SSH")
        )
    }
    let git = Link(pid: 63_002, path: "/usr/bin/git", argv: ["git", "push"])
    let programShell = Link(pid: 63_003, path: "/bin/zsh", argv: ["/bin/zsh", "-lc", "git push"])

    let (_, signing, review, _) = await world([git, programShell])
    let signature = await sign(signing)
    let signingReviews = await review.count
    let signingGrants = await signing.grantSummaries()
    check(signature != nil && signingReviews == 0 && signingGrants.isEmpty,
          "delegation SSH: git → zsh -lc → csec ai signs with no panel and no grant (a lazily bound csec ai)")
    let (_, directSigning, directReview, _) = await world([], program: "ssh git@github.com")
    let directSignature = await sign(directSigning)
    let directReviews = await directReview.count
    check(directSignature != nil && directReviews == 0,
          "delegation SSH: ssh run directly by the command delegates")
    let (_, scpSigning, scpReview, _) = await world([Link(pid: 63_004, path: "/usr/bin/scp", argv: ["scp", "a", "b:"])], program: "scp a b:")
    let scpSignature = await sign(scpSigning)
    let scpReviews = await scpReview.count
    check(scpSignature != nil && scpReviews == 0, "delegation SSH: scp delegates")
    // The grammar hangs a heredoc after `&&` on the whole list and drops the
    // `-` before it; the text must still parse for the ssh in it to match.
    let stdinScript = "ssh nimbus 'cat /data/a.jsonl' > a.jsonl; cd /tmp/s && wc -l a.jsonl && python3 - <<'EOF'\n"
        + "import json\nprint(len(open(\"a.jsonl\").readlines()))\nEOF"
    let (_, stdinSigning, stdinReview, _) = await world(
        [], program: stdinScript, sshArgv: ["ssh", "nimbus", "cat /data/a.jsonl"]
    )
    let stdinSignature = await sign(stdinSigning)
    let stdinReviews = await stdinReview.count
    check(stdinSignature != nil && stdinReviews == 0,
          "delegation SSH: ssh in a command that ends `&& python3 - <<'EOF'` delegates")

    // `timeout N ssh|git|scp …` (csec-zxr2): GNU timeout forks and runs the
    // rest of its argv, so the timeout must be a command of the text and the
    // link below it exactly the command it runs.
    let gtimeoutPath = "/opt/homebrew/Cellar/coreutils/9.7/bin/gtimeout"
    let probe = ["ssh", "-o", "BatchMode=yes", "nimbus", "uptime"]
    func timed(
        _ links: [Link], program: String, sshArgv: [String] = probe
    ) async -> (signed: Bool, panels: Int, note: DelegationDecline?) {
        let (_, signing, review, _) = await world(
            links + [Link(pid: 63_009, path: "/bin/zsh", argv: ["/bin/zsh", "-lc", program])], program: program, sshArgv: sshArgv
        )
        let signature = await sign(signing)
        return (signature != nil, await review.count, await review.last?.delegationNote)
    }
    for options in [
        ["15"], ["-k", "5", "15"], ["--kill-after=5", "-s", "KILL", "15"], ["-fk5", "15"],
        ["-v", "--", "15"], ["--signal", "TERM", "--preserve-status", "15"], ["--foreground", "1m"],
    ] {
        let argv = ["timeout"] + options + probe
        let result = await timed(
            [Link(pid: 63_005, path: gtimeoutPath, argv: argv)], program: argv.joined(separator: " ") + " 2>&1 | head -40"
        )
        check(result.signed && result.panels == 0,
              "delegation SSH: `\(argv.prefix(options.count + 1).joined(separator: " "))` running ssh delegates (\(result))")
    }
    let gtimeoutNamed = await timed(
        [Link(pid: 63_005, path: gtimeoutPath, argv: ["gtimeout", "15"] + probe)], program: "gtimeout 15 " + probe.joined(separator: " ")
    )
    check(gtimeoutNamed.signed && gtimeoutNamed.panels == 0, "delegation SSH: `gtimeout 15 ssh …` delegates (\(gtimeoutNamed))")
    let timedPush = await timed(
        [
            Link(pid: 63_002, path: "/usr/bin/git", argv: ["git", "push"]),
            Link(pid: 63_005, path: gtimeoutPath, argv: ["timeout", "60", "git", "push"]),
        ],
        program: "timeout 60 git push", sshArgv: ["ssh", "git@github.com"]
    )
    check(timedPush.signed && timedPush.panels == 0, "delegation SSH: `timeout 60 git push` delegates (\(timedPush))")
    let untyped = await timed(
        [Link(pid: 63_005, path: gtimeoutPath, argv: ["timeout", "15"] + probe)], program: probe.joined(separator: " ")
    )
    check(untyped.signed && untyped.panels == 0,
          "delegation SSH: a timeout the text never ran signs (csec-0.11: auto mode approved the command, so it signs) (\(untyped))")
    let swapped = await timed(
        [Link(pid: 63_005, path: gtimeoutPath, argv: ["timeout", "15"] + probe)],
        program: "timeout 15 " + probe.joined(separator: " "), sshArgv: ["ssh", "-o", "BatchMode=yes", "nimbus", "rm -rf /"]
    )
    check(swapped.signed && swapped.panels == 0,
          "delegation SSH: an ssh other than the one timeout was given signs (csec-0.11: auto mode approved the command, so it signs) (\(swapped))")
    for options in [["--fore", "15"], ["-x", "15"], ["--foreground=1", "15"], ["--help"]] {
        let argv = ["timeout"] + options + probe
        let result = await timed([Link(pid: 63_005, path: gtimeoutPath, argv: argv)], program: argv.joined(separator: " "))
        check(result.signed && result.panels == 0,
              "delegation SSH: timeout with `\(options[0])` signs (csec-0.11: auto mode approved the command, so it signs) (\(result))")
    }
    let timedShell = await timed(
        [
            Link(pid: 63_006, path: "/bin/bash", argv: ["bash", "-c", "ssh nimbus uptime"]),
            Link(pid: 63_005, path: gtimeoutPath, argv: ["timeout", "15", "bash", "-c", "ssh nimbus uptime"]),
        ],
        program: "timeout 15 bash -c 'ssh nimbus uptime'", sshArgv: ["ssh", "nimbus", "uptime"]
    )
    check(timedShell.signed && timedShell.panels == 0,
          "delegation SSH: a shell under timeout signs (csec-0.11: auto mode approved the command, so it signs) (\(timedShell))")
    // A shell's subshell, a fork of the program shell: zsh forks one for
    // `$(a | b)`, `( a; b )` and `{ a; b; } | c` (measured), so ssh's parent
    // is that fork. The text is the shape of 14 Oct 00:05's, declined then
    // as "ssh was started by zsh".
    let subshellProgram = "cd ~/projects/harbor/watch/agent && "
        + "LIVE=$(ssh nimbus 'docker exec harbor-agent sha256sum /workspace/CLAUDE.md' | cut -d' ' -f1); "
        + "echo live=$LIVE; python3 - \"$LIVE\" <<'EOF'\nimport sys\nprint(sys.argv[1])\nEOF"
    let subshellSSH = ["ssh", "nimbus", "docker exec harbor-agent sha256sum /workspace/CLAUDE.md"]
    func subshell(_ pid: pid_t, argv: [String]? = nil) -> Link {
        Link(pid: pid, path: "/bin/zsh", argv: argv ?? ["/bin/zsh", "-lc", subshellProgram])
    }
    let inSubshell = await timed([subshell(63_020)], program: subshellProgram, sshArgv: subshellSSH)
    check(inSubshell.signed && inSubshell.panels == 0,
          "delegation SSH: ssh in the command's `$(ssh … | cut …)` subshell delegates (\(inSubshell))")
    let nestedSubshell = await timed([subshell(63_020), subshell(63_021)], program: subshellProgram, sshArgv: subshellSSH)
    check(nestedSubshell.signed && nestedSubshell.panels == 0,
          "delegation SSH: ssh in a subshell of a subshell delegates (\(nestedSubshell))")
    let subshellOther = await timed([subshell(63_020)], program: subshellProgram, sshArgv: ["ssh", "nimbus", "rm -rf /"])
    check(subshellOther.signed && subshellOther.panels == 0,
          "delegation SSH: a subshell's ssh that is not one of the text's commands signs (csec-0.11: auto mode approved the command, so it signs) (\(subshellOther))")
    let otherZsh = await timed(
        [subshell(63_020, argv: ["/bin/zsh", "-c", "ssh nimbus 'docker exec harbor-agent sha256sum /workspace/CLAUDE.md'"])],
        program: subshellProgram, sshArgv: subshellSSH
    )
    check(otherZsh.signed && otherZsh.panels == 0,
          "delegation SSH: a zsh -c the command started signs (csec-0.11: auto mode approved the command, so it signs) (\(otherZsh))")
    let node = Link(pid: 63_022, path: "/opt/homebrew/bin/node", argv: ["node", "x.js"])
    let nodeFork = await timed(
        [Link(pid: 63_023, path: node.path, argv: node.argv), node], program: "node x.js", sshArgv: subshellSSH
    )
    check(nodeFork.signed && nodeFork.panels == 0,
          "delegation SSH: ssh under an interpreter (node and its fork) signs (csec-0.11: auto mode approved the command, so it signs) (\(nodeFork))")
    let (_, unreadSigning, unreadReview, _) = await world(
        [subshell(63_020), Link(pid: 63_009, path: "/bin/zsh", argv: ["/bin/zsh", "-lc", subshellProgram])],
        program: subshellProgram, sshArgv: subshellSSH, wrapFacts: { BlockingSessionFacts($0) }
    )
    let unreadSignature = await sign(unreadSigning)
    let unreadReviews = await unreadReview.count
    check(unreadSignature != nil && unreadReviews == 0,
          "delegation SSH: a zsh csecd cannot read signs; nothing below the command is judged (csec-0.11: auto mode approved the command, so it signs)")

    let underNode = await timed(
        [
            Link(pid: 63_005, path: gtimeoutPath, argv: ["timeout", "15"] + probe),
            Link(pid: 63_007, path: "/opt/homebrew/bin/node", argv: ["node", "x.js"]),
        ],
        program: "node x.js"
    )
    check(underNode.signed && underNode.panels == 0,
          "delegation SSH: a timeout a node program started signs (csec-0.11: auto mode approved the command, so it signs) (\(underNode))")
    // `mise exec … --` and `direnv exec DIR` exec the command in place, so
    // what timeout starts is the command after them.
    for (wrapper, label) in [
        (["mise", "exec", "--"], "mise exec --"), (["mise", "x", "node@20", "--"], "mise x TOOL --"),
        (["direnv", "exec", "."], "direnv exec ."), (["env", "GIT_TRACE=0"], "env NAME=value"),
    ] {
        let argv = ["timeout", "180"] + wrapper + ["git", "push", "-u", "origin", "HEAD"]
        let result = await timed(
            [
                Link(pid: 63_002, path: "/usr/bin/git", argv: ["git", "push", "-u", "origin", "HEAD"]),
                Link(pid: 63_005, path: gtimeoutPath, argv: argv),
            ],
            program: argv.joined(separator: " ") + " 2>&1 | tail -8", sshArgv: ["ssh", "git@github.com"]
        )
        check(result.signed && result.panels == 0, "delegation SSH: `timeout 180 \(label) git push` delegates (\(result))")
    }
    let miseShell = await timed(
        [
            Link(pid: 63_002, path: "/usr/bin/git", argv: ["git", "push"]),
            Link(pid: 63_005, path: gtimeoutPath, argv: ["timeout", "180", "mise", "exec", "-c", "git push", "--", "git", "push"]),
        ],
        program: "timeout 180 mise exec -c 'git push' -- git push", sshArgv: ["ssh", "git@github.com"]
    )
    check(miseShell.signed && miseShell.panels == 0,
          "delegation SSH: mise exec -c, which runs a shell, signs (csec-0.11: auto mode approved the command, so it signs) (\(miseShell))")
    let miseTyped = await timed(
        [Link(pid: 63_002, path: "/usr/bin/git", argv: ["git", "push"])],
        program: "mise exec -- git push", sshArgv: ["ssh", "git@github.com"]
    )
    check(miseTyped.signed && miseTyped.panels == 0, "delegation SSH: `mise exec -- git push` (mise execs git) delegates (\(miseTyped))")
    let direnvTyped = await timed(
        [Link(pid: 63_002, path: "/usr/bin/git", argv: ["git", "push"])],
        program: "direnv exec . git push", sshArgv: ["ssh", "git@github.com"]
    )
    check(direnvTyped.signed && direnvTyped.panels == 0, "delegation SSH: `direnv exec . git push` delegates (\(direnvTyped))")

    // An SSH client starts its own ssh to the host its arguments name:
    // rsync (Apple's openrsync or Homebrew's), sftp and scp.
    for (client, path, program) in [
        ("rsync", "/usr/bin/rsync", "rsync -az --delete server/ nimbus:/mnt/cache/appdata/x/src/"),
        ("rsync", "/opt/homebrew/bin/rsync", "rsync -e ssh -a out/ nimbus:/tmp/out"),
        ("sftp", "/usr/bin/sftp", "sftp -b batch.txt nimbus"),
        ("scp", "/usr/bin/scp", "scp a.txt nimbus:/tmp/"),
    ] {
        let argv = program.split(separator: " ").map(String.init)
        let result = await timed(
            [Link(pid: 63_008, path: path, argv: argv)], program: program,
            sshArgv: ["ssh", "-l", "root", "nimbus", client == "rsync" ? "rsync --server -logDtprze.iLsfxC . /tmp" : "x"]
        )
        check(result.signed && result.panels == 0, "delegation SSH: ssh under `\(client)` (\(path)) delegates (\(result))")
    }
    let untypedRsync = await timed(
        [Link(pid: 63_008, path: "/usr/bin/rsync", argv: ["rsync", "-a", "x/", "nimbus:/y"])], program: "rsync -a x/ elsewhere:/y"
    )
    check(untypedRsync.signed && untypedRsync.panels == 0,
          "delegation SSH: an rsync the text never ran signs (csec-0.11: auto mode approved the command, so it signs) (\(untypedRsync))")
    let rshShell = await timed(
        [
            Link(pid: 63_006, path: "/bin/bash", argv: ["bash", "-c", "ssh nimbus rsync --server"]),
            Link(pid: 63_008, path: "/usr/bin/rsync", argv: ["rsync", "-e", "bash -c", "x/", "nimbus:/y"]),
        ],
        program: "rsync -e 'bash -c' x/ nimbus:/y"
    )
    check(rshShell.signed && rshShell.panels == 0,
          "delegation SSH: a program rsync's -e names in place of ssh signs (csec-0.11: auto mode approved the command, so it signs) (\(rshShell))")

    // An iTerm2 or Terminal.app tab: the terminal's shell is a child of root's
    // `login`, which csecd cannot read. The walk needs only `ssh` up to Claude
    // Code, so an unreadable ancestor above Claude ends the chain as launchd
    // does.
    let login: pid_t = 63_020
    let terminalServer: pid_t = 63_021
    let (_, loginSigning, loginReview, _) = await world([git, programShell], extra: { tree in
        tree.processes[Standard.fish]?.parent = login
        tree.processes[login] = DelegationTree.Process(
            startTime: UInt64(login) * 10, parent: terminalServer, executablePath: "/usr/bin/login",
            argv: ["login", "-fp", "u"], readable: false
        )
        tree.processes[terminalServer] = DelegationTree.Process(
            startTime: UInt64(terminalServer) * 10, parent: 1,
            executablePath: "/Applications/iTerm.app/Contents/MacOS/iTermServer"
        )
    })
    let loginSignature = await sign(loginSigning)
    let loginReviews = await loginReview.count
    check(loginSignature != nil && loginReviews == 0,
          "delegation SSH: a session whose terminal shell is under root's unreadable login delegates")
    // An unreadable process between `ssh` and its `csec ai` hides the csec ai:
    // the walk never steps over a process it cannot read, so the SSH panel
    // shows with no note.
    let setuid = Link(pid: 63_022, path: "/usr/bin/sudo", argv: ["sudo", "ssh", "host"])
    let (_, hiddenSigning, hiddenReview, _) = await world([setuid], program: "sudo ssh host", extra: { tree in
        tree.processes[setuid.pid]?.readable = false
    })
    _ = await sign(hiddenSigning)
    let hiddenReviews = await hiddenReview.count
    let hiddenNote = await hiddenReview.last?.delegationNote
    check(hiddenReviews == 1 && hiddenNote == nil,
          "delegation SSH: an unreadable process between ssh and its csec ai leaves the panel with no note")

    // An SSH use paired in the main checkout signs from a linked worktree.
    if let fixture = GitRepositoryFixture() {
        let mainGit = fixture.main + "/.git"
        let repository = ProjectKey(path: mainGit, volumeUUID: delegationVolume, inode: fixture.inode(mainGit))
        let (_, worktreeSigning, worktreeReview, _) = await world(
            [git, programShell], pairings: [ProjectPairing(project: repository, references: [], ssh: [use])],
            extra: { tree in
                tree.processes[Standard.agent]?.cwd = delegationCWD(fixture.worktree, inode: fixture.inode(fixture.worktree))
            },
            repositories: .live
        )
        let worktreeSignature = await sign(worktreeSigning)
        let worktreeReviews = await worktreeReview.count
        check(worktreeSignature != nil && worktreeReviews == 0,
              "delegation SSH: an SSH use paired for the repository signs from a linked worktree with no panel")
        // An SSH use recorded on the worktree's own directory still signs there.
        let (_, ownSigning, ownReview, _) = await world(
            [git, programShell],
            pairings: [ProjectPairing(
                project: ProjectKey(path: fixture.worktree, volumeUUID: delegationVolume, inode: fixture.inode(fixture.worktree)),
                references: [], ssh: [use]
            )],
            extra: { tree in
                tree.processes[Standard.agent]?.cwd = delegationCWD(fixture.worktree, inode: fixture.inode(fixture.worktree))
            },
            repositories: .live
        )
        let ownSignature = await sign(ownSigning)
        let ownReviews = await ownReview.count
        check(ownSignature != nil && ownReviews == 0,
              "delegation SSH: an SSH use recorded on the worktree's own directory still signs there")
        fixture.remove()
    } else {
        check(false, "delegation SSH: the git fixture builds")
    }

    for (label, links, name) in [
        ("node → git", [git, Link(pid: 63_005, path: "/opt/homebrew/bin/node", argv: ["node", "install.js"]), programShell], "node"),
        // A real `#!/bin/sh` hook runs as /bin/bash with argv0 /bin/sh, and a
        // file inside .git is never a launcher script.
        ("a git hook (sh → git)", [Link(pid: 63_006, path: "/bin/bash", argv: ["/bin/sh", ".git/hooks/pre-push"]), git, programShell], "bash"),
        ("rsync under node", [Link(pid: 63_007, path: "/usr/bin/rsync", argv: ["rsync", "a", "host:b"]),
                              Link(pid: 63_005, path: "/opt/homebrew/bin/node", argv: ["node", "sync.js"]), programShell], "node"),
    ] {
        let (_, indirect, indirectReview, _) = await world(links)
        let indirectSignature = await sign(indirect)
        let indirectReviews = await indirectReview.count
        check(indirectSignature != nil && indirectReviews == 0,
              "delegation SSH: \(label) (once ssh_indirect, \(name)) signs with no panel (csec-0.11: auto mode approved the command, so it signs)")
    }
    let (_, unpaired, unpairedReview, _) = await world([git, programShell])
    let unpairedSignature = await sign(unpaired, user: "other")
    let unpairedReviews = await unpairedReview.count
    check(unpairedSignature != nil && unpairedReviews == 0,
          "delegation SSH: a remote user no pairing holds signs (csec-0.11: auto mode approved the command, so it signs, to any destination)")
    // An SSH destination approved in one project holds in every project
    // (csec-1vmv.2): the key, server and user are what was approved.
    let elsewhere = ProjectKey(path: "/synthetic/elsewhere/.git", volumeUUID: delegationVolume, inode: 9_191)
    let (_, globalSigning, globalReview, _) = await world(
        [git, programShell], pairings: [ProjectPairing(project: elsewhere, references: [], ssh: [use])]
    )
    let globalSignature = await sign(globalSigning)
    let globalReviews = await globalReview.count
    check(globalSignature != nil && globalReviews == 0,
          "delegation SSH: a destination approved in another project signs here with no panel")
    let (_, otherUserSigning, otherUserReview, _) = await world(
        [git, programShell], pairings: [ProjectPairing(project: elsewhere, references: [], ssh: [use])]
    )
    let otherUserSignature = await sign(otherUserSigning, user: "other")
    let otherUserReviews = await otherUserReview.count
    check(otherUserSignature != nil && otherUserReviews == 0,
          "delegation SSH: another user on the same server signs (csec-0.11: auto mode approved the command, so it signs, to any destination)")
    let noneLog = await makeDelegationLog(ProtectedStores.processLocal())
    let (_, noneSigning, noneReview, noneStores) = await world([git, programShell], pairings: [], log: noneLog)
    let noneSignature = await sign(noneSigning)
    let noneReviews = await noneReview.count
    let noneReleases = await noneLog.read(DecisionLogQuery(streams: [.usage], kinds: [.delegatedRelease])).records
    check(noneSignature != nil && noneReviews == 0 && noneReleases.count == 1 && noneReleases.first?.surface == .sshSigning
            && noneReleases.first?.decider == .delegated && noneReleases.first?.delegation?.decision == "approved",
          "delegation SSH: a destination approved nowhere, in a project with no pairing, signs and logs a delegated release (csec-0.11: auto mode approved the command, so it signs)")
    check(await storedPairings(noneStores)?.isEmpty == true,
          "delegation SSH: signing a destination pairs nothing")
    let (_, coldSigning, coldReview, _) = await world([git, programShell], held: false)
    _ = await sign(coldSigning)
    check(await coldReview.last?.delegationNote == .notHeld(keyReference),
          "delegation SSH: a key csecd does not hold declines .notHeld")
    let (_, unsigned, unsignedReview, _) = await world([git, programShell], launcher: false)
    _ = await sign(unsigned)
    check(await unsignedReview.last?.delegationNote == .notRegistered,
          "delegation SSH: a lazily bound csec ai must be the signed launcher")
    // The csec ai already bound by its own access request is found without
    // the lazy binding's launcher check.
    let (boundService, boundSigning, boundReview, _) = await world([git, programShell], launcher: false)
    _ = await boundService.evaluateRelease(
        caller: CallerInfo(pid: command, startTime: UInt64(command) * 10, description: "csec ai"),
        commandLine: AICommandExec.commandLine(forProgram: "git push"), newReferences: [ref(alphaReference)]
    )
    let boundSignature = await sign(boundSigning)
    let boundReviews = await boundReview.count
    check(boundSignature != nil && boundReviews == 0,
          "delegation SSH: ssh under a csec ai its access request already bound delegates")

    // csec as Claude Code's shell prefix (av-e2sa): ssh ← git ← program shell
    // ← csec ai --claude-code-shell <framing> ← P. The hook registered the
    // command inside the framing's eval, and that is what binds.
    let pushFraming = claudeFraming("git push")
    let framingShell = Link(pid: 63_003, path: "/bin/zsh", argv: ["/bin/zsh", "-lc", pushFraming])
    let (_, prefixSigning, prefixReview, _) = await world([git, framingShell], shellPrefix: pushFraming)
    let prefixSignature = await sign(prefixSigning)
    let prefixReviews = await prefixReview.count
    check(prefixSignature != nil && prefixReviews == 0,
          "delegation SSH: git under csec as the shell prefix, its eval naming the registered command, signs with no panel")
    let (otherPrefixService, otherPrefixSigning, otherPrefixReview, _) = await world(
        [git, framingShell], register: false, shellPrefix: pushFraming
    )
    _ = await register(otherPrefixService, "git fetch", peer: Standard.hookPeer)
    let otherPrefixSignature = await sign(otherPrefixSigning)
    let otherPrefixNote = await otherPrefixReview.last?.delegationNote
    check(otherPrefixSignature == nil && otherPrefixNote == .notRegistered,
          "delegation SSH: a shell prefix whose eval names another command than the registered one declines .notRegistered (\(String(describing: otherPrefixNote)))")
    let (_, unsignedPrefix, unsignedPrefixReview, _) = await world(
        [git, framingShell], launcher: false, shellPrefix: pushFraming
    )
    _ = await sign(unsignedPrefix)
    check(await unsignedPrefixReview.last?.delegationNote == .notRegistered,
          "delegation SSH: a lazily bound shell prefix must be the signed launcher")
    let (_, shelledPrefix, shelledPrefixReview, _) = await world(
        [git, framingShell], extra: { tree in
            tree.processes[shell] = SyntheticClaudeSessionFacts.Process(
                startTime: UInt64(shell) * 10, parent: Standard.agent, executablePath: "/bin/zsh",
                argv: ["/bin/zsh", "-c", "-l", "eval"]
            )
            tree.names[shell] = "zsh"
            tree.processes[command]?.parent = shell
        }, shellPrefix: pushFraming
    )
    let shelledPrefixSignature = await sign(shelledPrefix)
    let shelledPrefixReviews = await shelledPrefixReview.count
    check(shelledPrefixSignature == nil && shelledPrefixReviews == 1,
          "delegation SSH: a shell prefix with a shell between it and P is no Claude Code command and gets the panel")

    // An SSH panel that still appears (here: the command ran in default
    // mode) offers no pairing line, and approving it on either surface signs
    // and pairs nothing: a destination pairing no longer decides anything
    // (csec-0.11).
    for (label, surface) in [("on the Mac", HumanDecisionSurface.mac), ("on the phone", .phone)] {
        let (pairingService, pairingSigning, pairingReview, pairingStores) = await world(
            [git, programShell], pairings: [], register: false
        )
        _ = await register(pairingService, "git push", peer: Standard.hookPeer, mode: "default")
        await pairingReview.answer(.approve(scope: nil, durationIndex: nil, surface: surface))
        let signed = await sign(pairingSigning)
        let note = await pairingReview.last?.delegationNote
        let offer = await pairingReview.last?.pairingOffer
        let stored = await storedPairings(pairingStores)
        check(signed != nil && note == .notAutoMode("default") && offer == nil && stored?.isEmpty == true,
              "delegation SSH: an SSH panel approved \(label) offers no pairing line and pairs nothing (csec-0.11)")
    }

    // The newest registration binds on the SSH path too: a git push made in
    // default mode never borrows an earlier, stale auto registration.
    let (staleService, staleSigning, staleReview, _) = await world([git, programShell], register: false)
    _ = await register(staleService, "git push", peer: Standard.hookPeer, mode: "auto")
    _ = await register(staleService, "git push", peer: Standard.hookPeer, mode: "default")
    let staleSignature = await sign(staleSigning)
    let staleNote = await staleReview.last?.delegationNote
    check(staleSignature == nil && staleNote == .notAutoMode("default"),
          "delegation SSH: a lazily bound csec ai under a stale auto registration and a current default one declines .notAutoMode(default)")

    // A lazily bound csec ai never binds a registration that arrived after it
    // started (its own never reached csecd).
    let lateClock = DelegationTestClock()
    let (lateService, lateSigning, lateReview, _) = await world([git, programShell], register: false, clock: lateClock)
    lateClock.started(command)
    _ = await register(lateService, "git push", peer: Standard.hookPeer)
    let lateSignature = await sign(lateSigning)
    let lateNote = await lateReview.last?.delegationNote
    check(lateSignature == nil && lateNote == .notRegistered,
          "delegation SSH: a lazily bound csec ai never binds a registration that arrived after it started (.notRegistered)")

    // Judged again once it holds the review turn: a Claude Code ssh that
    // waited behind another panel, declined at first because its command
    // was not registered yet, signs with no panel of its own once the
    // registration has arrived.
    let terminalSSH: pid_t = 63_060
    let turnGate = GatedPolicyReview()
    let (turnService, turnSigning, _, _) = await world(
        [git, programShell], pairings: [], register: false, reviewer: turnGate,
        extra: { tree in
            tree.processes[terminalSSH] = SyntheticClaudeSessionFacts.Process(
                startTime: UInt64(terminalSSH) * 10, parent: Standard.fish, executablePath: "/usr/bin/ssh", argv: ["ssh", "git@github.com"]
            )
            tree.names[terminalSSH] = "ssh"
        }
    )
    let holder = Task { await sign(turnSigning, from: terminalSSH) }
    let holderPanelUp = await eventuallyTrue { await turnGate.pendingCount == 1 }
    let waiterBox = SSHSignatureBox()
    let waiterTask = Task { await waiterBox.set(await sign(turnSigning)) }
    // The waiter's first judgment (not registered) is made before it waits.
    try? await Task.sleep(nanoseconds: 200_000_000)
    _ = await register(turnService, "git push", peer: Standard.hookPeer)
    await turnGate.decideAll(.deny(.authenticationFailed))
    _ = await holder.value
    let waiterDone = await eventuallyTrue { await waiterBox.finished }
    if waiterDone { await waiterTask.value } else { waiterTask.cancel() }
    let waiterSignature = await waiterBox.signature
    let turnPanels = await turnGate.reviews
    check(holderPanelUp && waiterDone && waiterSignature != nil && turnPanels == 1,
          "delegation SSH: judged again after the review turn, an ssh whose command was registered while it waited signs with no panel")

    // A stuck read: an ssh whose walk cannot be read is not known to be
    // Claude Code's, so its panel carries no note; the Claude Code ssh whose
    // own read stuck keeps its note, logged with an unknown requester.
    let stuckSSH: pid_t = 63_070
    var blockingFacts: BlockingSessionFacts?
    let stuckStores = ProtectedStores.processLocal()
    let stuckLog = await makeDelegationLog(stuckStores)
    let (_, stuckSigning, stuckReview, _) = await world(
        [git, programShell], log: stuckLog, factBound: .milliseconds(150),
        wrapFacts: { base in
            let blocking = BlockingSessionFacts(base)
            blockingFacts = blocking
            return blocking
        },
        extra: { tree in
            tree.processes[stuckSSH] = SyntheticClaudeSessionFacts.Process(
                startTime: UInt64(stuckSSH) * 10, parent: Standard.fish, executablePath: "/usr/bin/ssh", argv: ["ssh", "git@github.com"]
            )
            tree.names[stuckSSH] = "ssh"
        }
    )
    blockingFacts?.arm()
    _ = await sign(stuckSigning)
    let claudeStuckNote = await stuckReview.last?.delegationNote
    _ = await sign(stuckSigning, from: stuckSSH)
    let terminalStuckNote = await stuckReview.last?.delegationNote
    let terminalStuckReviews = await stuckReview.count
    blockingFacts?.unblock()
    let stuckDeclines = await stuckLog.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records
    check(claudeStuckNote == .factsUnavailable && terminalStuckReviews == 2 && terminalStuckNote == nil
            && stuckDeclines.count == 1 && stuckDeclines.first?.requester?.class == "unknown",
          "delegation SSH: while reads are stuck a terminal's ssh gets no note, and a Claude Code decline logs an unknown requester")

    await delegationToolShellAnchorTests(
        key: key, host: host, session: session, binding: binding, metadata: metadata, use: use
    )

    // csec-0.11, Alex: "always approve an ssh panel that has been approved by
    // claude code's auto mode. The approval rule needs to be that simple."
    // What ran between the approved command and ssh, the destination, and
    // classifier rules nobody acknowledged no longer matter; the base fact
    // (csec's hook registered the command in auto mode, in a verified
    // Claude Code session) still does.
    func simple(
        _ links: [Link], program: String = "git push", sshArgv: [String] = ["ssh", "git@github.com"],
        pairings: [ProjectPairing]? = nil, gate: FakeSettingsGate = FakeSettingsGate(),
        extra: @escaping (inout DelegationTree) -> Void = { _ in }
    ) async -> (signed: Bool, panels: Int, note: DelegationDecline?) {
        let (_, signing, review, _) = await world(
            links, program: program, sshArgv: sshArgv, pairings: pairings, extra: extra, gate: gate
        )
        let signature = await sign(signing)
        return (signature != nil, await review.count, await review.last?.delegationNote)
    }
    let deployScript = Link(pid: 63_201, path: "/bin/bash", argv: ["bash", "/Users/u/projects/harbor/watch/bin/deploy-agent"])
    let deployLock = Link(pid: 63_202, path: "/opt/homebrew/bin/python3", argv: ["python3", "watch/bin/deploy-lock", "watch/bin/deploy-agent"])
    let scratch = Link(pid: 63_203, path: "/bin/bash", argv: ["bash", "/tmp/av072/refresh.sh"])
    let heredoc = Link(pid: 63_204, path: "/bin/bash", argv: ["bash", "-euo", "pipefail"])
    let programOf: (String) -> Link = { Link(pid: 63_209, path: "/bin/zsh", argv: ["/bin/zsh", "-lc", $0]) }
    let rules = rulesSource(
        "/Users/u/.claude/settings.json", digest: String(repeating: "7", count: 64), rules: ["allow deploys", "allow pushes"]
    )
    for (label, links, program, sshArgv, gate) in [
        ("an unpinned repo script (launcher_not_trusted)", [deployScript, programOf("watch/bin/deploy-agent")],
         "watch/bin/deploy-agent", ["ssh", "nimbus", "docker restart harbor-agent"], FakeSettingsGate()),
        ("a Python deploy-lock wrapper around a script (ssh_indirect python3)",
         [deployScript, deployLock, programOf("watch/bin/deploy-lock watch/bin/deploy-agent")],
         "watch/bin/deploy-lock watch/bin/deploy-agent", ["ssh", "nimbus", "true"], FakeSettingsGate()),
        ("a scratch script outside any repo (launcher_unverifiable)", [scratch, programOf("bash /tmp/av072/refresh.sh")],
         "bash /tmp/av072/refresh.sh", ["ssh", "root@nimbus", "uptime"], FakeSettingsGate()),
        ("a bash heredoc script (ssh_indirect bash)", [heredoc, programOf("bash -euo pipefail <<'SCRIPT'\nssh nimbus true\nSCRIPT")],
         "bash -euo pipefail <<'SCRIPT'\nssh nimbus true\nSCRIPT", ["ssh", "nimbus", "true"], FakeSettingsGate()),
        ("unacknowledged classifier rules in ~/.claude/settings.json (classifier_rules)", [git, programShell],
         "git push", ["ssh", "git@github.com"], FakeSettingsGate(evaluation(hooks: [rules]))),
    ] {
        let result = await simple(links, program: program, sshArgv: sshArgv, pairings: [], gate: gate)
        check(result.signed && result.panels == 0,
              "delegation SSH (csec-0.11): \(label) signs with no panel (\(result))")
    }
    // The classifier-rule exemption is SSH's alone: a secret release under
    // the same rules still declines for review.
    let (rulesService, _, _, _) = await world([git, programShell], gate: FakeSettingsGate(evaluation(hooks: [rules])))
    let rulesRelease = await rulesService.evaluateRelease(
        caller: CallerInfo(pid: command, startTime: UInt64(command) * 10, description: "csec ai"),
        commandLine: AICommandExec.commandLine(forProgram: "git push"), newReferences: [ref(alphaReference)]
    )
    check(decline(rulesRelease) == .classifierRules(rules.display),
          "delegation SSH (csec-0.11): unacknowledged classifier rules still decline a secret release")
    // Still the panel: no auto-mode approval to stand on.
    let (unregisteredService, unregisteredSigning, unregisteredReview, _) = await world([git, programShell], register: false)
    _ = unregisteredService
    let (_, uncheckedSigning, uncheckedReview, _) = await world([git, programShell], buildVerification: .shipped)
    let uncheckedSignature = await sign(uncheckedSigning)
    let uncheckedNote = await uncheckedReview.last?.delegationNote
    check(uncheckedSignature == nil && uncheckedNote == .uncheckedBuild("claude"),
          "release gate SSH: an unchecked signed image reaches the ordinary panel with the shared reason")
    for hash in [auditedClaude301Hash, neighboringClaude301Hash] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude301ModelEnvironment,
                       identity: claude301Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }, buildVerification: .shipped)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(hash == auditedClaude301Hash ? signature != nil && note == nil
                : signature == nil && note == .uncheckedBuild("2.1.301"),
              "release 2.1.301 SSH: only the exact audited identity delegates despite its filename and inactive selectors")
    }
    for boundary in claudeReleaseBoundaryCases(environment: claude301ModelEnvironment) {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude301Identity(pid: Standard.agent))
        }, gate: boundary.gate, buildVerification: claude301BoundaryVerification)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(signature == nil && note == boundary.reason,
              "release 2.1.301 SSH: \(boundary.label) keeps the ordinary review boundary")
    }
    for release in claude319Releases {
        for hash in [release.audited, release.neighbor] {
            let (_, signing, review, _) = await world([git, programShell], extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: claude319ModelEnvironment,
                           identity: claude319Identity(pid: Standard.agent, cdHash: hash, version: release.version),
                           executablePath: "/synthetic/renamed-image")
            }, buildVerification: .shipped)
            let signature = await sign(signing)
            let note = await review.last?.delegationNote
            check(hash == release.audited ? signature != nil && note == nil
                    : signature == nil && note == .uncheckedBuild(release.version),
                  "release \(release.version) SSH: only the audited identity delegates with the inspected selectors")
        }
    }
    for release in claude319Releases {
        for boundary in claude319BoundaryCases() {
            let (_, signing, review, _) = await world([git, programShell], extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                           identity: claude319Identity(pid: Standard.agent, cdHash: release.audited, version: release.version))
            }, gate: boundary.gate, buildVerification: claude319BoundaryVerification)
            let signature = await sign(signing)
            let note = await review.last?.delegationNote
            check(signature == nil && note == boundary.reason,
                  "release \(release.version) SSH: \(boundary.label) keeps the ordinary review boundary")
        }
    }
    for hash in [auditedClaude314Hash, neighboringClaude314Hash] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude314ModelEnvironment,
                       identity: claude314Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }, buildVerification: .shipped)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(hash == auditedClaude314Hash ? signature != nil && note == nil
                : signature == nil && note == .uncheckedBuild("2.1.314"),
              "release 2.1.314 SSH: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude314BoundaryCases() {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude314Identity(pid: Standard.agent))
        }, gate: boundary.gate, buildVerification: claude314BoundaryVerification)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(signature == nil && note == boundary.reason,
              "release 2.1.314 SSH: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude312Hash, neighboringClaude312Hash] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude312ModelEnvironment,
                       identity: claude312Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }, buildVerification: .shipped)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(hash == auditedClaude312Hash ? signature != nil && note == nil
                : signature == nil && note == .uncheckedBuild("2.1.312"),
              "release 2.1.312 SSH: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude312BoundaryCases() {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude312Identity(pid: Standard.agent))
        }, gate: boundary.gate, buildVerification: claude312BoundaryVerification)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(signature == nil && note == boundary.reason,
              "release 2.1.312 SSH: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude311Hash, neighboringClaude311Hash] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude311ModelEnvironment,
                       identity: claude311Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }, buildVerification: .shipped)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(hash == auditedClaude311Hash ? signature != nil && note == nil
                : signature == nil && note == .uncheckedBuild("2.1.311"),
              "release 2.1.311 SSH: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude311BoundaryCases() {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude311Identity(pid: Standard.agent))
        }, gate: boundary.gate, buildVerification: claude311BoundaryVerification)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(signature == nil && note == boundary.reason,
              "release 2.1.311 SSH: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude310Hash, neighboringClaude310Hash] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude310ModelEnvironment,
                       identity: claude310Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }, buildVerification: .shipped)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(hash == auditedClaude310Hash ? signature != nil && note == nil
                : signature == nil && note == .uncheckedBuild("2.1.310"),
              "release 2.1.310 SSH: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude310BoundaryCases() {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude310Identity(pid: Standard.agent))
        }, gate: boundary.gate, buildVerification: claude310BoundaryVerification)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(signature == nil && note == boundary.reason,
              "release 2.1.310 SSH: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude305Hash, neighboringClaude305Hash] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude305ModelEnvironment,
                       identity: claude305Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }, buildVerification: .shipped)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(hash == auditedClaude305Hash ? signature != nil && note == nil
                : signature == nil && note == .uncheckedBuild("2.1.305"),
              "release 2.1.305 SSH: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claudeReleaseBoundaryCases(environment: claude305ModelEnvironment) {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                       identity: claude305Identity(pid: Standard.agent))
        }, gate: boundary.gate, buildVerification: claude305BoundaryVerification)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(signature == nil && note == boundary.reason,
              "release 2.1.305 SSH: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude302Hash, neighboringClaude302Hash] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude302ModelEnvironment,
                       identity: claude302Identity(pid: Standard.agent, cdHash: hash),
                       executablePath: "/synthetic/renamed-image")
        }, buildVerification: .shipped)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(hash == auditedClaude302Hash ? signature != nil && note == nil
                : signature == nil && note == .uncheckedBuild("2.1.302"),
              "release 2.1.302 SSH: model tuning admits only the exact audited identity")
    }
    let (_, standaloneSigning, standaloneReview, _) = await world([git, programShell], extra: {
        $0.session(Standard.agent, parent: Standard.fish, environment: claude302StandaloneEnvironment,
                   identity: claude302Identity(pid: Standard.agent))
    }, buildVerification: claude302TransportVerification)
    let standaloneSignature = await sign(standaloneSigning)
    let standaloneNote = await standaloneReview.last?.delegationNote
    check(standaloneSignature == nil && standaloneNote == .injectedEnvironment("CCR_AGENT_PROXY_RELAY_MODE"),
          "release 2.1.302 G5 SSH: standalone relay without REMOTE requires ordinary review")
    for (hash, checked) in [(release282CDHash, true), (release282Neighbor, false)] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: release282Identity(pid: Standard.agent, cdHash: hash))
        }, buildVerification: .shipped)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(checked ? signature != nil && note == nil : signature == nil && note == .uncheckedBuild("2.1.282"),
              "release 2.1.282 SSH: only the exact audited identity can delegate")
    }
    let (_, syncedSigning, syncedReview, _) = await world([git, programShell], extra: {
        $0.session(Standard.agent, parent: Standard.fish, identity: release282Identity(pid: Standard.agent))
    }, gate: FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), buildVerification: .shipped)
    let syncedSignature = await sign(syncedSigning)
    let syncedNote = await syncedReview.last?.delegationNote
    check(syncedSignature == nil && syncedNote == .otherHook(release282SyncedHook.display),
          "release 2.1.282 SSH: the classifier-rule exemption does not exempt disk-synced hooks")
    for cdHash in [auditedClaude278Hash, neighboringClaude278Hash] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: claude278Identity(pid: Standard.agent, cdHash: cdHash),
                       executablePath: "/synthetic/renamed-image")
        }, buildVerification: .shipped)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(cdHash == auditedClaude278Hash ? signature != nil && note == nil
                : signature == nil && note == .uncheckedBuild("2.1.278"),
              "release gate SSH: signed 2.1.278 admits only the audited hash (\(cdHash))")
    }
    let (_, relay278Signing, relay278Review, _) = await world([git, programShell], extra: {
        $0.session(Standard.agent, parent: Standard.fish,
                   environment: claude278RelayEnvironment,
                   identity: claude278Identity(pid: Standard.agent, cdHash: auditedClaude278Hash))
    }, buildVerification: .shipped)
    let relay278Signature = await sign(relay278Signing)
    let relay278Note = await relay278Review.last?.delegationNote
    check(relay278Signature == nil && relay278Note == .injectedEnvironment("CLAUDE_CODE_REMOTE"),
          "release 2.1.278 G5 SSH: a checked image's remote relay transport still requires review")
    let (_, synced278Signing, synced278Review, _) = await world([git, programShell], extra: {
        $0.session(Standard.agent, parent: Standard.fish,
                   identity: claude278Identity(pid: Standard.agent, cdHash: auditedClaude278Hash))
    }, gate: FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), buildVerification: .shipped)
    let synced278Signature = await sign(synced278Signing)
    let synced278Note = await synced278Review.last?.delegationNote
    check(synced278Signature == nil && synced278Note == .otherHook(release282SyncedHook.display),
          "release 2.1.278 G2 SSH: the classifier-rule exemption does not exempt disk-synced skill hooks")
    for cdHash in [auditedClaude295Hash, neighboringClaude295Hash] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: claude295Identity(pid: Standard.agent, cdHash: cdHash),
                       executablePath: "/synthetic/renamed-image")
        }, buildVerification: .shipped)
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(cdHash == auditedClaude295Hash ? signature != nil && note == nil
                : signature == nil && note == .uncheckedBuild("2.1.295"),
              "release gate SSH: signed 2.1.295 admits only the audited hash (\(cdHash))")
    }
    let (_, relaySigning, relayReview, _) = await world([git, programShell], extra: {
        $0.session(Standard.agent, parent: Standard.fish,
                   environment: claude295RelayEnvironment,
                   identity: claude295Identity(pid: Standard.agent, cdHash: auditedClaude295Hash))
    }, buildVerification: .shipped)
    let relaySignature = await sign(relaySigning)
    let relayNote = await relayReview.last?.delegationNote
    check(relaySignature == nil && relayNote == .injectedEnvironment("CLAUDE_CODE_REMOTE"),
          "release 2.1.295 G5 SSH: a checked image's remote relay transport still requires review")
    let (_, synced295Signing, synced295Review, _) = await world([git, programShell], extra: {
        $0.session(Standard.agent, parent: Standard.fish,
                   identity: claude295Identity(pid: Standard.agent, cdHash: auditedClaude295Hash))
    }, gate: FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), buildVerification: .shipped)
    let synced295Signature = await sign(synced295Signing)
    let synced295Note = await synced295Review.last?.delegationNote
    check(synced295Signature == nil && synced295Note == .otherHook(release282SyncedHook.display),
          "release 2.1.295 G2 SSH: the classifier-rule exemption does not exempt disk-synced skill hooks")
    for trustCustom in [false, true] {
        let (_, signing, review, _) = await world([git, programShell], extra: {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: patchedClaudeIdentity(pid: Standard.agent, cdHash: auditedCustomClaudeBuild.cdHash))
        }, buildVerification: catalogWithAuditedCustomBuild, trusted: trustCustom ? [auditedCustomClaudeBuild] : [])
        let signature = await sign(signing)
        let note = await review.last?.delegationNote
        check(trustCustom ? signature != nil && note == nil : signature == nil && note == .unverifiedBuild("2.1.257"),
              "release gate SSH: audited custom 2.1.257 requires independent publisher trust (trusted=\(trustCustom))")
    }
    let (_, policy278Signing, policy278Review, _) = await world([git, programShell], extra: {
        $0.session(Standard.agent, parent: Standard.fish,
                   identity: claude278Identity(pid: Standard.agent, cdHash: auditedClaude278Hash))
    }, gate: FakeSettingsGate(evaluation(unreadable: [
        ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy),
    ])), buildVerification: .shipped)
    let policy278Signature = await sign(policy278Signing)
    let policy278Note = await policy278Review.last?.delegationNote
    check(policy278Signature == nil && policy278Note == .settingsUnreadable("/s/managed-settings.json"),
          "release 2.1.278 SSH: the classifier-rule exemption does not exempt generated policy")
    let generatedPolicy = await simple([git, programShell], gate: FakeSettingsGate(evaluation(unreadable: [
        ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy),
    ])))
    check(!generatedPolicy.signed && generatedPolicy.panels == 1
            && generatedPolicy.note == .settingsUnreadable("/s/managed-settings.json"),
          "release gate SSH: generated policy still requires review despite the classifier-rule exemption")
    let unregisteredSignature = await sign(unregisteredSigning)
    let unregisteredNote = await unregisteredReview.last?.delegationNote
    check(unregisteredSignature == nil && unregisteredNote == .notRegistered,
          "delegation SSH (csec-0.11): a command csec's hook never registered still gets the panel (.notRegistered)")
    let (defaultService, defaultSigning, defaultReview, _) = await world([git, programShell], register: false)
    _ = await register(defaultService, "git push", peer: Standard.hookPeer, mode: "default")
    let defaultSignature = await sign(defaultSigning)
    let defaultNote = await defaultReview.last?.delegationNote
    check(defaultSignature == nil && defaultNote == .notAutoMode("default"),
          "delegation SSH (csec-0.11): a command approved outside auto mode still gets the panel (.notAutoMode)")
    let bypass = await simple([git, programShell], extra: { tree in
        tree.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--dangerously-skip-permissions"])
    })
    check(!bypass.signed && bypass.panels == 1 && bypass.note == .launchOption("--dangerously-skip-permissions"),
          "delegation SSH (csec-0.11): a --dangerously-skip-permissions session still gets the panel (\(bypass))")
    let unverified = await simple([git, programShell], extra: { tree in
        tree.session(Standard.agent, parent: Standard.fish,
                     identity: patchedClaudeIdentity(pid: Standard.agent, cdHash: String(repeating: "c", count: 40)),
                     executablePath: "/synthetic/.local/share/claude/versions/2.1.257")
    })
    check(!unverified.signed && unverified.panels == 1 && unverified.note == .unverifiedBuild("2.1.257"),
          "delegation SSH (csec-0.11): a build that is not verified Claude Code still gets the panel (\(unverified))")
    let terminal: pid_t = 63_250
    let (_, terminalSigning, terminalReview, _) = await world([git, programShell], extra: { tree in
        tree.processes[terminal] = SyntheticClaudeSessionFacts.Process(
            startTime: UInt64(terminal) * 10, parent: Standard.fish, executablePath: "/usr/bin/ssh", argv: ["ssh", "nimbus"]
        )
        tree.names[terminal] = "ssh"
    })
    let terminalSignature = await sign(terminalSigning, from: terminal)
    let terminalReviews = await terminalReview.count
    let terminalNote = await terminalReview.last?.delegationNote
    check(terminalSignature == nil && terminalReviews == 1 && terminalNote == nil,
          "delegation SSH (csec-0.11): an ssh a human runs in a terminal still gets the panel, with no note")

    // A hook added since the last acknowledgement: the signing takes csecd's
    // one hooks-changed panel, and signs once it is acknowledged
    // (csec-0.64.7).
    let newHook = ClaudeHookSource(
        kind: .settings, sourceID: delegationHome + "/.claude/settings.json", event: "PreToolUse", matcher: "Bash",
        digest: String(repeating: "e", count: 64), display: "~/.claude/settings.json · PreToolUse Bash",
        fetchesUnpinnedCode: false, handlerSummaries: ["python3 ~/.local/share/harbor/harbor-hook.py pr-cap claude"])
    let hookConsent = RulesPanelConsent([.approve])
    let (_, hookSigning, hookReview, hookStores) = await world(
        [git, programShell], gate: FakeSettingsGate(evaluation(hooks: [newHook])), serviceConsent: hookConsent)
    let hookSignature = await sign(hookSigning)
    let hookPanels = await hookReview.count
    let hookStored = await storedSettings(hookStores)?.acknowledgedHooks ?? []
    check(hookSignature != nil && hookPanels == 0 && hookConsent.panels.count == 1
            && hookConsent.panels.first?.title == "New Claude Code Hook"
            && hookStored.contains { $0.digest == newHook.digest },
          "delegation SSH: a new hook takes the hooks-changed panel, and the signing goes through once it is acknowledged")

}

// MARK: - SSH under the Bash tool shell (a git command left unwrapped)

/// `ssh` with no `csec ai` above it: a git command csec's hook left unwrapped
/// (`AICommandGitPassthrough`), run straight from Claude Code's Bash tool shell
/// (`ClaudeToolShell`), which csecd anchors the chain on.
// MARK: - sudo

/// A sudo that Claude Code ran, as csecd sees it from the sudo review helper:
/// P → X (Bash tool shell) → A (`csec ai`) → `parents`… → sudo → helper. sudo
/// is set-id root, so only its kernel record is readable, never its argv or
/// `proc_pidinfo`; its argv comes from the PAM module's display.
private func delegationSudoTests() async {
    let command: pid_t = 64_010
    let shell: pid_t = 64_011
    let programShellPID: pid_t = 64_012
    let sudo: pid_t = 64_013
    let helper: pid_t = 64_014
    let platformValid: UInt32 = 0x2601_5b11  // /usr/bin/top's flags, measured
    typealias Link = SSHChainTestLink
    func programShell(_ program: String) -> Link {
        Link(pid: programShellPID, path: "/bin/zsh", argv: ["/bin/zsh", "-lc", program])
    }

    func world(
        program: String, parents: [Link]? = nil, register registered: Bool = true, mode: String = "auto",
        sudoPath: String = "/usr/bin/sudo", sudoUID: uid_t = 0, sudoFlags: UInt32? = platformValid,
        commandEnvironment: [SyntheticClaudeSessionFacts.EnvironmentEntry]? = nil,
        log: DecisionLog? = nil, pairings: [ProjectPairing] = [pairing()],
        stores: ProtectedStores = .processLocal(),
        gate: FakeSettingsGate = FakeSettingsGate(),
        buildVerification: ClaudeBuildVerification = delegationVerifiedBuilds,
        trusted: [TrustedClaudeBuild] = [],
        shellPrefix framing: String? = nil,
        extra: (inout DelegationTree) -> Void = { _ in }
    ) async -> ClaudeDelegationService {
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        tree.session(Standard.agent, parent: Standard.fish)
        tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
        if let framing {
            tree.shellPrefix(command, agent: Standard.agent, framing: framing)
        } else {
            tree.command(command, shell: shell, agent: Standard.agent, program: program)
        }
        if let commandEnvironment { tree.processes[command]?.environment = commandEnvironment }
        var parent = command
        for link in (parents ?? [programShell(framing ?? program)]).reversed() {
            tree.processes[link.pid] = SyntheticClaudeSessionFacts.Process(
                startTime: UInt64(link.pid) * 10, parent: parent, executablePath: link.path, argv: link.argv
            )
            tree.names[link.pid] = (link.path as NSString).lastPathComponent
            parent = link.pid
        }
        tree.processes[sudo] = SyntheticClaudeSessionFacts.Process(
            startTime: UInt64(sudo) * 10, parent: parent, executablePath: sudoPath,
            effectiveUID: sudoUID, codeSigningFlags: sudoFlags, readable: false
        )
        tree.processes[helper] = SyntheticClaudeSessionFacts.Process(
            startTime: UInt64(helper) * 10, parent: sudo, executablePath: "/usr/local/libexec/csec-sudo-review",
            argv: ["/usr/local/libexec/csec-sudo-review"]
        )
        extra(&tree)
        let (facts, _) = tree.build()
        await enableDelegation(stores, trusted: trusted)
        await seedPairings(stores, pairings)
        let service = makeService(facts, stores: stores, gate: gate, log: log, buildVerification: buildVerification)
        if registered { _ = await register(service, program, peer: Standard.hookPeer, mode: mode) }
        return service
    }
    let helperCaller = CallerInfo(pid: helper, startTime: UInt64(helper) * 10, description: "csec-sudo-review")
    func judged(_ service: ClaudeDelegationService, _ display: String) async -> DelegationEvaluation {
        await service.evaluateSudo(helper: helperCaller, command: display)
    }
    let unchecked = await judged(await world(program: "sudo id", buildVerification: .shipped), "sudo id")
    check(decline(unchecked) == .uncheckedBuild("claude"),
          "release gate sudo: an unchecked signed image needs the ordinary panel and shares its reason")
    for hash in [auditedClaude301Hash, neighboringClaude301Hash] {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            buildVerification: .shipped, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: claude301ModelEnvironment,
                           identity: claude301Identity(pid: Standard.agent, cdHash: hash),
                           executablePath: "/synthetic/renamed-image")
            }
        )
        let result = await judged(service, "sudo id")
        check(hash == auditedClaude301Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.301"),
              "release 2.1.301 sudo: only the exact audited identity delegates despite its filename and inactive selectors")
    }
    for boundary in claudeReleaseBoundaryCases(environment: claude301ModelEnvironment) {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            gate: boundary.gate, buildVerification: claude301BoundaryVerification, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                           identity: claude301Identity(pid: Standard.agent))
            }
        )
        check(decline(await judged(service, "sudo id")) == boundary.reason,
              "release 2.1.301 sudo: \(boundary.label) keeps the ordinary review boundary")
    }
    for release in claude319Releases {
        for hash in [release.audited, release.neighbor] {
            let service = await world(
                program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
                buildVerification: .shipped, extra: {
                    $0.session(Standard.agent, parent: Standard.fish, environment: claude319ModelEnvironment,
                               identity: claude319Identity(pid: Standard.agent, cdHash: hash, version: release.version),
                               executablePath: "/synthetic/renamed-image")
                }
            )
            let result = await judged(service, "sudo id")
            check(hash == release.audited ? isApproved(result) : decline(result) == .uncheckedBuild(release.version),
                  "release \(release.version) sudo: only the audited identity delegates with the inspected selectors")
        }
    }
    for release in claude319Releases {
        for boundary in claude319BoundaryCases() {
            let service = await world(
                program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
                gate: boundary.gate, buildVerification: claude319BoundaryVerification, extra: {
                    $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                               identity: claude319Identity(pid: Standard.agent, cdHash: release.audited, version: release.version))
                }
            )
            check(decline(await judged(service, "sudo id")) == boundary.reason,
                  "release \(release.version) sudo: \(boundary.label) keeps the ordinary review boundary")
        }
    }
    for hash in [auditedClaude314Hash, neighboringClaude314Hash] {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            buildVerification: .shipped, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: claude314ModelEnvironment,
                           identity: claude314Identity(pid: Standard.agent, cdHash: hash),
                           executablePath: "/synthetic/renamed-image")
            }
        )
        let result = await judged(service, "sudo id")
        check(hash == auditedClaude314Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.314"),
              "release 2.1.314 sudo: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude314BoundaryCases() {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            gate: boundary.gate, buildVerification: claude314BoundaryVerification, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                           identity: claude314Identity(pid: Standard.agent))
            }
        )
        check(decline(await judged(service, "sudo id")) == boundary.reason,
              "release 2.1.314 sudo: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude312Hash, neighboringClaude312Hash] {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            buildVerification: .shipped, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: claude312ModelEnvironment,
                           identity: claude312Identity(pid: Standard.agent, cdHash: hash),
                           executablePath: "/synthetic/renamed-image")
            }
        )
        let result = await judged(service, "sudo id")
        check(hash == auditedClaude312Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.312"),
              "release 2.1.312 sudo: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude312BoundaryCases() {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            gate: boundary.gate, buildVerification: claude312BoundaryVerification, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                           identity: claude312Identity(pid: Standard.agent))
            }
        )
        check(decline(await judged(service, "sudo id")) == boundary.reason,
              "release 2.1.312 sudo: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude311Hash, neighboringClaude311Hash] {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            buildVerification: .shipped, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: claude311ModelEnvironment,
                           identity: claude311Identity(pid: Standard.agent, cdHash: hash),
                           executablePath: "/synthetic/renamed-image")
            }
        )
        let result = await judged(service, "sudo id")
        check(hash == auditedClaude311Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.311"),
              "release 2.1.311 sudo: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude311BoundaryCases() {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            gate: boundary.gate, buildVerification: claude311BoundaryVerification, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                           identity: claude311Identity(pid: Standard.agent))
            }
        )
        check(decline(await judged(service, "sudo id")) == boundary.reason,
              "release 2.1.311 sudo: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude310Hash, neighboringClaude310Hash] {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            buildVerification: .shipped, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: claude310ModelEnvironment,
                           identity: claude310Identity(pid: Standard.agent, cdHash: hash),
                           executablePath: "/synthetic/renamed-image")
            }
        )
        let result = await judged(service, "sudo id")
        check(hash == auditedClaude310Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.310"),
              "release 2.1.310 sudo: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claude310BoundaryCases() {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            gate: boundary.gate, buildVerification: claude310BoundaryVerification, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                           identity: claude310Identity(pid: Standard.agent))
            }
        )
        check(decline(await judged(service, "sudo id")) == boundary.reason,
              "release 2.1.310 sudo: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude305Hash, neighboringClaude305Hash] {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            buildVerification: .shipped, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: claude305ModelEnvironment,
                           identity: claude305Identity(pid: Standard.agent, cdHash: hash),
                           executablePath: "/synthetic/renamed-image")
            }
        )
        let result = await judged(service, "sudo id")
        check(hash == auditedClaude305Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.305"),
              "release 2.1.305 sudo: only the audited identity delegates with the inspected classifier tuning")
    }
    for boundary in claudeReleaseBoundaryCases(environment: claude305ModelEnvironment) {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            gate: boundary.gate, buildVerification: claude305BoundaryVerification, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: boundary.environment,
                           identity: claude305Identity(pid: Standard.agent))
            }
        )
        check(decline(await judged(service, "sudo id")) == boundary.reason,
              "release 2.1.305 sudo: \(boundary.label) keeps the ordinary review boundary")
    }
    for hash in [auditedClaude302Hash, neighboringClaude302Hash] {
        let service = await world(
            program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            buildVerification: .shipped, extra: {
                $0.session(Standard.agent, parent: Standard.fish, environment: claude302ModelEnvironment,
                           identity: claude302Identity(pid: Standard.agent, cdHash: hash),
                           executablePath: "/synthetic/renamed-image")
            }
        )
        let result = await judged(service, "sudo id")
        check(hash == auditedClaude302Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.302"),
              "release 2.1.302 sudo: model tuning admits only the exact audited identity")
    }
    let standaloneService = await world(
        program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
        buildVerification: claude302TransportVerification, extra: {
            $0.session(Standard.agent, parent: Standard.fish, environment: claude302StandaloneEnvironment,
                       identity: claude302Identity(pid: Standard.agent))
        }
    )
    check(decline(await judged(standaloneService, "sudo id")) == .injectedEnvironment("CCR_AGENT_PROXY_RELAY_MODE"),
          "release 2.1.302 G5 sudo: standalone relay without REMOTE requires ordinary review")
    for (hash, checked) in [(release282CDHash, true), (release282Neighbor, false)] {
        let service = await world(
            program: "sudo id",
            pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
            buildVerification: .shipped, extra: {
                $0.session(Standard.agent, parent: Standard.fish,
                           identity: release282Identity(pid: Standard.agent, cdHash: hash))
            }
        )
        let result = await judged(service, "sudo id")
        check(checked ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.282"),
              "release 2.1.282 sudo: only the exact audited identity can delegate")
    }
    let syncedService = await world(
        program: "sudo id", gate: FakeSettingsGate(evaluation(hooks: [release282SyncedHook])),
        buildVerification: .shipped, extra: {
            $0.session(Standard.agent, parent: Standard.fish, identity: release282Identity(pid: Standard.agent))
        }
    )
    check(decline(await judged(syncedService, "sudo id")) == .otherHook(release282SyncedHook.display),
          "release 2.1.282 sudo: an unacknowledged disk-synced hook uses the shared review fallback")
    for cdHash in [auditedClaude278Hash, neighboringClaude278Hash] {
        let service = await world(
            program: "sudo id", pairings: [
                ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true),
            ], buildVerification: .shipped, extra: {
                $0.session(Standard.agent, parent: Standard.fish,
                           identity: claude278Identity(pid: Standard.agent, cdHash: cdHash),
                           executablePath: "/synthetic/renamed-image")
            }
        )
        let result = await judged(service, "sudo id")
        check(cdHash == auditedClaude278Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.278"),
              "release gate sudo: signed 2.1.278 admits only the audited hash (\(cdHash))")
    }
    let relay278Service = await world(
        program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
        buildVerification: .shipped, extra: {
            $0.session(Standard.agent, parent: Standard.fish,
                       environment: claude278RelayEnvironment,
                       identity: claude278Identity(pid: Standard.agent, cdHash: auditedClaude278Hash))
        }
    )
    check(decline(await judged(relay278Service, "sudo id")) == .injectedEnvironment("CLAUDE_CODE_REMOTE"),
          "release 2.1.278 G5 sudo: a checked image's remote relay transport still requires review")
    let synced278Service = await world(
        program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
        gate: FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), buildVerification: .shipped, extra: {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: claude278Identity(pid: Standard.agent, cdHash: auditedClaude278Hash))
        }
    )
    check(decline(await judged(synced278Service, "sudo id")) == .otherHook(release282SyncedHook.display),
          "release 2.1.278 G2 sudo: a checked image's disk-synced skill hook uses the shared review fallback")
    for cdHash in [auditedClaude295Hash, neighboringClaude295Hash] {
        let service = await world(
            program: "sudo id", pairings: [
                ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true),
            ], buildVerification: .shipped, extra: {
                $0.session(Standard.agent, parent: Standard.fish,
                           identity: claude295Identity(pid: Standard.agent, cdHash: cdHash),
                           executablePath: "/synthetic/renamed-image")
            }
        )
        let result = await judged(service, "sudo id")
        check(cdHash == auditedClaude295Hash ? isApproved(result) : decline(result) == .uncheckedBuild("2.1.295"),
              "release gate sudo: signed 2.1.295 admits only the audited hash (\(cdHash))")
    }
    let relayService = await world(
        program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
        buildVerification: .shipped, extra: {
            $0.session(Standard.agent, parent: Standard.fish,
                       environment: claude295RelayEnvironment,
                       identity: claude295Identity(pid: Standard.agent, cdHash: auditedClaude295Hash))
        }
    )
    check(decline(await judged(relayService, "sudo id")) == .injectedEnvironment("CLAUDE_CODE_REMOTE"),
          "release 2.1.295 G5 sudo: a checked image's remote relay transport still requires review")
    let synced295Service = await world(
        program: "sudo id", pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)],
        gate: FakeSettingsGate(evaluation(hooks: [release282SyncedHook])), buildVerification: .shipped, extra: {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: claude295Identity(pid: Standard.agent, cdHash: auditedClaude295Hash))
        }
    )
    check(decline(await judged(synced295Service, "sudo id")) == .otherHook(release282SyncedHook.display),
          "release 2.1.295 G2 sudo: a checked image's disk-synced skill hook uses the shared review fallback")
    for trustCustom in [false, true] {
        let service = await world(
            program: "sudo id", pairings: [
                ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true),
            ], buildVerification: catalogWithAuditedCustomBuild, trusted: trustCustom ? [auditedCustomClaudeBuild] : [], extra: {
                $0.session(Standard.agent, parent: Standard.fish,
                           identity: patchedClaudeIdentity(pid: Standard.agent, cdHash: auditedCustomClaudeBuild.cdHash))
            }
        )
        let result = await judged(service, "sudo id")
        check(trustCustom ? isApproved(result) : decline(result) == .unverifiedBuild("2.1.257"),
              "release gate sudo: audited custom 2.1.257 requires independent publisher trust (trusted=\(trustCustom))")
    }
    let policy278Service = await world(
        program: "sudo id", gate: FakeSettingsGate(evaluation(unreadable: [
            ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy),
        ])), buildVerification: .shipped, extra: {
            $0.session(Standard.agent, parent: Standard.fish,
                       identity: claude278Identity(pid: Standard.agent, cdHash: auditedClaude278Hash))
        }
    )
    check(decline(await judged(policy278Service, "sudo id")) == .settingsUnreadable("/s/managed-settings.json"),
          "release 2.1.278 sudo: a checked image cannot delegate through generated policy")
    let generatedPolicy = await judged(await world(program: "sudo id", gate: FakeSettingsGate(evaluation(unreadable: [
        ClaudeUnreadableSetting(path: "/s/managed-settings.json", reason: .generatedPolicy),
    ]))), "sudo id")
    check(decline(generatedPolicy) == .settingsUnreadable("/s/managed-settings.json"),
          "release gate sudo: generated policy uses the same settings-unreadable fallback as secret access and SSH")

    // Everything up to the consent holds: the sudo the text ran, its argv
    // matching the text, in auto mode, from a verified Claude Code session.
    let investigate = "sudo fs_usage -w -f pathname -t 8 > /tmp/fs_usage.txt; wc -l /tmp/fs_usage.txt"
    let typical = await judged(await world(program: investigate), "sudo fs_usage -w -f pathname -t 8")
    check(decline(typical) == .sudoNotApproved(project: "alpha"),
          "delegation sudo: the investigation's sudo, under the program shell, reaches the consent check (\(typical))")
    let single = await judged(await world(program: "sudo killall fseventsd", parents: []), "sudo killall fseventsd")
    check(decline(single) == .sudoNotApproved(project: "alpha"),
          "delegation sudo: a text that is the one sudo (zsh execs it, so its parent is csec ai) reaches the consent check")
    let piped = await judged(
        await world(program: "sudo launchctl print system/com.apple.fseventsd | grep -i state"),
        "sudo launchctl print system/com.apple.fseventsd"
    )
    check(decline(piped) == .sudoNotApproved(project: "alpha"), "delegation sudo: sudo in a pipeline reaches the consent check")

    // csec as Claude Code's shell prefix (av-e2sa): sudo ← program shell ←
    // csec ai --claude-code-shell <framing> ← P, matched against the command
    // inside the framing's eval, the one the hook registered.
    let investigateFraming = claudeFraming(investigate)
    let prefixPaired = [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)]
    let prefixed = await judged(
        await world(program: investigate, pairings: prefixPaired, shellPrefix: investigateFraming),
        "sudo fs_usage -w -f pathname -t 8"
    )
    check(isApproved(prefixed), "delegation sudo: sudo under csec as the shell prefix, paired for sudo, delegates (\(prefixed))")
    let prefixedUnpaired = await judged(
        await world(program: investigate, shellPrefix: investigateFraming), "sudo fs_usage -w -f pathname -t 8"
    )
    check(decline(prefixedUnpaired) == .sudoNotApproved(project: "alpha"),
          "delegation sudo: under the shell prefix an unpaired project still reaches the consent check")
    let prefixedSwapped = await judged(
        await world(program: investigate, pairings: prefixPaired, shellPrefix: investigateFraming),
        "sudo rm -rf /Library/Preferences"
    )
    check(decline(prefixedSwapped) == .commandMismatch(process: "sudo"),
          "delegation sudo: under the shell prefix an argv the eval never ran declines .commandMismatch(sudo)")
    let prefixedFromNode = await judged(
        await world(program: investigate, parents: [
            Link(pid: 64_021, path: "/opt/homebrew/bin/node", argv: ["node", "install.js"]), programShell(investigateFraming),
        ], pairings: prefixPaired,
                    shellPrefix: investigateFraming),
        "sudo fs_usage -w -f pathname -t 8"
    )
    check(decline(prefixedFromNode) == .sudoIndirect("node"),
          "delegation sudo: under the shell prefix sudo started by node declines .sudoIndirect(node)")
    let prefixedOther = await world(program: investigate, register: false, pairings: prefixPaired, shellPrefix: investigateFraming)
    _ = await register(prefixedOther, "sudo id", peer: Standard.hookPeer)
    let prefixedOtherResult = await judged(prefixedOther, "sudo fs_usage -w -f pathname -t 8")
    check(decline(prefixedOtherResult) == .notRegistered,
          "delegation sudo: a shell prefix whose eval names another command than the registered one declines .notRegistered (\(prefixedOtherResult))")
    // An empty backquote pair in a commit message is an ERROR to the grammar
    // that the analysis repairs (csec-7eoh); a sudo after it still matches.
    let emptyBackquotes = "git commit -m \"before `` after\" && sudo /usr/bin/true"
    let afterBackquotes = await judged(await world(program: emptyBackquotes), "sudo /usr/bin/true")
    check(decline(afterBackquotes) == .sudoNotApproved(project: "alpha"),
          "delegation sudo: sudo after an empty backquote pair in a quoted argument reaches the consent check")
    let otherAfterBackquotes = await judged(await world(program: emptyBackquotes), "sudo /usr/bin/false")
    check(decline(otherAfterBackquotes) == .commandMismatch(process: "sudo"),
          "delegation sudo: after an empty backquote pair, an argv the text never ran still declines")
    let brokenAfterBackquotes = await judged(await world(program: emptyBackquotes + " )"), "sudo /usr/bin/true")
    check(decline(brokenAfterBackquotes) == .commandMismatch(process: "sudo"),
          "delegation sudo: an empty backquote pair beside another syntax error leaves the text unread")
    let timed = "timeout 8 sudo tcpdump -n -i any"
    let timeout = Link(pid: 64_020, path: "/opt/homebrew/bin/timeout", argv: ["timeout", "8", "sudo", "tcpdump", "-n", "-i", "any"])
    let underTimeout = await judged(await world(program: timed, parents: [timeout]), "sudo tcpdump -n -i any")
    check(decline(underTimeout) == .sudoNotApproved(project: "alpha"),
          "delegation sudo: sudo that the text's timeout runs reaches the consent check")
    let redactedTimeout = await judged(
        await world(program: "timeout 8 sudo tool \"$TOKEN\"", parents: [Link(
            pid: 64_020, path: "/opt/homebrew/bin/timeout", argv: ["timeout", "8", "sudo", "tool", "secret"]
        )]),
        #"sudo tool "[csec:secret-like]""#
    )
    check(decline(redactedTimeout) == .commandMismatch(process: "sudo"),
          "delegation sudo: under timeout sudo's argv must be known exactly, so a redacted one declines")
    let otherTimeout = await judged(
        await world(program: timed, parents: [Link(pid: 64_020, path: "/opt/homebrew/bin/timeout", argv: ["timeout", "8", "sudo", "tcpdump"])]),
        "sudo tcpdump -n -i any"
    )
    check(decline(otherTimeout) == .commandMismatch(process: "timeout"),
          "delegation sudo: a timeout the text did not run declines .commandMismatch(timeout)")

    // The chain: only the text's own shell, csec ai or timeout may start sudo.
    let node = Link(pid: 64_021, path: "/opt/homebrew/bin/node", argv: ["node", "install.js"])
    let fromNode = await judged(
        await world(program: "npm install && sudo id", parents: [node, programShell("npm install && sudo id")]), "sudo id"
    )
    check(decline(fromNode) == .sudoIndirect("node"), "delegation sudo: sudo started by node declines .sudoIndirect(node)")
    let script = Link(pid: 64_022, path: "/bin/bash", argv: ["/bin/bash", "bin/deploy"])
    let fromScript = await judged(await world(program: "bin/deploy", parents: [script]), "sudo id")
    check(decline(fromScript) == .sudoIndirect("bash"), "delegation sudo: sudo started by a script declines, pinned or not")
    let doubleTimeout = await judged(
        await world(program: "timeout 9 timeout 8 sudo id", parents: [
            Link(pid: 64_023, path: "/opt/homebrew/bin/timeout", argv: ["timeout", "8", "sudo", "id"]),
            Link(pid: 64_024, path: "/opt/homebrew/bin/timeout", argv: ["timeout", "9", "timeout", "8", "sudo", "id"]),
        ]),
        "sudo id"
    )
    check(decline(doubleTimeout) == .sudoIndirect("timeout"), "delegation sudo: a timeout under a timeout declines")

    // The argv: what the text ran, with no option that gives root what the
    // classifier never read.
    let swapped = await judged(await world(program: investigate), "sudo rm -rf /Library/Preferences")
    check(decline(swapped) == .commandMismatch(process: "sudo"),
          "delegation sudo: an argv the text never ran declines .commandMismatch(sudo)")
    let garbled = await judged(await world(program: investigate), #"sudo "fs_usage""#)
    check(decline(garbled) == .commandMismatch(process: "sudo"),
          "delegation sudo: a display the PAM module would never write declines")
    let preserve = await judged(await world(program: "sudo -E make install"), "sudo -E make install")
    check(decline(preserve) == .sudoOption("-E"), "delegation sudo: sudo -E declines .sudoOption(-E)")
    let login = await judged(await world(program: "sudo -i"), "sudo -i")
    check(decline(login) == .sudoOption("-i"), "delegation sudo: sudo -i declines .sudoOption(-i)")
    let hostThenE = await judged(
        await world(program: "sudo -h MacBook.local -E make install"), "sudo -h MacBook.local -E make install"
    )
    check(decline(hostThenE) == .sudoOption("-E"),
          "delegation sudo: -E after a bare -h and its host still declines (sudo parses on past the host)")
    let redacted = await judged(await world(program: "sudo tool --token \"$TOKEN\""), #"sudo tool --token "[csec:secret-like]""#)
    check(decline(redacted) == .sudoNotApproved(project: "alpha"),
          "delegation sudo: an argument the PAM module redacted matches the text's expansion")

    // The gates P's other requests pass.
    let planMode = await judged(await world(program: "sudo id", parents: [], mode: "plan"), "sudo id")
    check(decline(planMode) == .notAutoMode("plan"), "delegation sudo: a command registered in plan mode declines")
    let unregistered = await judged(await world(program: "sudo id", parents: [], register: false), "sudo id")
    check(decline(unregistered) == .notRegistered, "delegation sudo: an unregistered command declines .notRegistered")
    let zdotdir = await judged(
        await world(program: "sudo id", parents: [], commandEnvironment: [.init(name: "ZDOTDIR", value: "/tmp/planted")]),
        "sudo id"
    )
    check(decline(zdotdir) == .environmentSteering(process: "the command's shell", name: "ZDOTDIR"),
          "delegation sudo: ZDOTDIR in csec ai's environment declines .environmentSteering")

    // Not a Claude Code sudo, or not sudo at all: no note.
    for (label, service) in [
        ("su", await world(program: "sudo id", parents: [], sudoPath: "/usr/bin/su")),
        ("a sudo not running as root", await world(program: "sudo id", parents: [], sudoUID: getuid())),
        ("a sudo the OS did not sign", await world(program: "sudo id", parents: [], sudoFlags: 0x0000_0001)),
        ("a sudo whose signing status is unknown", await world(program: "sudo id", parents: [], sudoFlags: nil)),
    ] {
        check(await judged(service, "sudo id") == .notApplicable, "delegation sudo: a helper under \(label) is not applicable")
    }
    let terminalSudo = await world(program: "echo unused") { tree in
        tree.processes[sudo]?.parent = Standard.fish
    }
    check(await judged(terminalSudo, "sudo id") == .notApplicable,
          "delegation sudo: a terminal's sudo, with no csec ai above it, is not applicable")
    let strangerHelper = CallerInfo(pid: Standard.agent, startTime: UInt64(Standard.agent) * 10, description: "claude")
    check(await (await world(program: "sudo id", parents: [])).evaluateSudo(helper: strangerHelper, command: "sudo id")
            == .notApplicable,
          "delegation sudo: a caller whose parent is not sudo is not applicable")

    // The answer the helper gets, what csecd keeps for the phone's copy, and
    // the decline in the log with the redacted command. alpha has no sudo
    // pairing yet, so the panel offers one, whatever stopped this sudo.
    let stores = ProtectedStores.processLocal()
    let log = await makeDelegationLog(stores)
    let logged = await world(program: "sudo -E make install", log: log, stores: stores)
    let answer = await logged.sudoDelegation(SudoDelegationRequest(command: "sudo -E make install"), caller: helperCaller)
    let note = DelegationDecline.sudoOption("-E").panelText
    let line = SudoPairingOffer(projectName: "alpha").line
    check(line == "Approving also lets Claude Code auto mode run sudo in alpha until you revoke it",
          "delegation sudo: the pairing line says what approving lets auto mode do, and where")
    check(answer == SudoDelegationAnswer(decision: .declined, note: note, pairingLine: line),
          "delegation sudo: a decline answers the helper with the panel's note and the pairing line")
    check(await logged.sudoNote(for: helperCaller) == SudoDelegationNote(note: note, pairingLine: line),
          "delegation sudo: csecd keeps its note and line for the phone's copy")
    let declines = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records
    check(declines.count == 1 && declines.first?.surface == .sudo && declines.first?.command == "sudo -E make install"
            && declines.first?.delegation?.reason == "sudo_option",
          "delegation sudo: the decline is logged on the sudo surface with the redacted command")
    // The review's end is logged under the very process the decline names, so
    // a supervisor that saw the decline matches its end.
    let declinedFor = await logged.sudoAgent(for: helperCaller)
    check(declinedFor != nil && declinedFor?.pid == declines.first?.requester?.rootPID
            && declines.first?.requester?.class == "coding_agent:claude",
          "delegation sudo: csecd keeps the Claude Code process its decline names, for the review's end")
    let unknown = await logged.sudoDelegation(SudoDelegationRequest(command: "sudo -E make install"), caller: strangerHelper)
    check(unknown == .notApplicable, "delegation sudo: a caller that is not under sudo is answered not_applicable")

    // An approval of the panel that showed the line pairs sudo with alpha,
    // once: then auto mode's approval stands for the next sudo there.
    check(await logged.recordSudoApproval(helper: strangerHelper, surface: .mac) == false,
          "delegation sudo: no offer was made to that caller, so nothing pairs")
    check(await logged.recordSudoApproval(helper: helperCaller, surface: .mac),
          "delegation sudo: the approval of the panel csecd offered the line on is recorded")
    check(await logged.recordSudoApproval(helper: helperCaller, surface: .mac) == false,
          "delegation sudo: an offer is spent by the approval that used it")
    let paired = await storedPairings(stores)
    check(paired?.count == 1 && paired?.first?.sudo == true && paired?.first?.references == [alphaReference],
          "delegation sudo: sudo joins alpha's pairing, which keeps what it held")
    let settings = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
    check(settings.contains { $0.detail?.contains("and sudo with") == true && $0.decider == .humanLocal },
          "delegation sudo: the pairing is logged, decided on the Mac")
    let approvedAnswer = await logged.sudoDelegation(SudoDelegationRequest(command: "sudo -E make install"), caller: helperCaller)
    check(approvedAnswer == SudoDelegationAnswer(decision: .declined, note: note),
          "delegation sudo: with sudo paired, an option auto mode never approves still declines, now with no line")

    // 14 Oct: a session started with a --settings file fails G4 before any
    // pairing is consulted, so its next sudo asks again. The panel still
    // offers the pairing, and approving it still pairs, but the line says it
    // counts only once Claude Code is started without --settings (csec-tcbq).
    let launchStores = ProtectedStores.processLocal()
    let launched = await world(program: "sudo id", parents: [], stores: launchStores) {
        $0.session(Standard.agent, parent: Standard.fish, argv: ["claude", "--settings", "/tmp/launch-settings.json"])
    }
    let launchAnswer = await launched.sudoDelegation(SudoDelegationRequest(command: "sudo id"), caller: helperCaller)
    check(launchAnswer == SudoDelegationAnswer(
            decision: .declined, note: DelegationDecline.launchOption("--settings").panelText,
            pairingLine: "Approving also lets Claude Code auto mode run sudo in alpha once Claude Code is started without --settings"),
          "delegation sudo: a session-level decline's line says when the pairing counts, not that it does now")
    let launchPaired = await launched.recordSudoApproval(helper: helperCaller, surface: .mac)
    let launchPairings = await storedPairings(launchStores)
    check(launchPaired && launchPairings?.first?.sudo == true,
          "delegation sudo: approving the conditioned line still pairs sudo with the project")
    check(decline(await judged(launched, "sudo id")) == .launchOption("--settings"),
          "delegation sudo: the same session's next sudo still declines at G4, as its line said")

    let sudoPaired = [pairing(), ProjectPairing(project: projectKey(betaPath, inode: betaInode), references: [], ssh: [], sudo: true)]
    let notHere = await judged(await world(program: "sudo id", parents: [], pairings: sudoPaired), "sudo id")
    check(decline(notHere) == .sudoNotApproved(project: "alpha"), "delegation sudo: a pairing of another project does not count")
    let approvedLog = await makeDelegationLog(ProtectedStores.processLocal())
    let approvedService = await world(
        program: investigate, log: approvedLog,
        pairings: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)]
    )
    check(isApproved(await judged(approvedService, "sudo fs_usage -w -f pathname -t 8")),
          "delegation sudo: with sudo paired for alpha, the investigation's sudo is approved")
    let delegatedAnswer = await approvedService.sudoDelegation(
        SudoDelegationRequest(command: "sudo fs_usage -w -f pathname -t 8"), caller: helperCaller
    )
    check(delegatedAnswer == SudoDelegationAnswer(decision: .approved), "delegation sudo: the helper is told approved")
    let usage = await approvedLog.read(DecisionLogQuery(streams: [.usage], kinds: [.delegatedRelease])).records
    check(usage.count == 1 && usage.first?.surface == .sudo && usage.first?.decider == .delegated
            && usage.first?.command == "sudo fs_usage -w -f pathname -t 8" && usage.first?.delegation?.decision == "approved",
          "delegation sudo: a delegated sudo is logged on the sudo surface with the redacted command")
    let mismatchWhenPaired = await judged(approvedService, "sudo rm -rf /Library")
    check(decline(mismatchWhenPaired) == .commandMismatch(process: "sudo"),
          "delegation sudo: pairing never lets a sudo the text did not run through")

    // Format 2 pairing items migrate with no sudo; format 3 keeps it.
    let pairingID = "00000000-0000-4000-8000-000000000002"
    let legacy = #"{"document":{"projects":[{"id":"\#(pairingID)","project":{"inode":\#(alphaInode),"path":"\#(alphaPath)","volumeUUID":"\#(delegationVolume)"},"references":["\#(alphaReference)"],"ssh":[],"launchers":[]}]},"formatVersion":2}"#
    let backend = InMemoryProtectedItemBackend()
    await backend.setRawBytes(Data(legacy.utf8), for: .pairing)
    let migrated = await ProtectedStores.processLocal(backend).store(for: PairingDocument.self).load()
    check(migrated == .document(PairingDocument(projects: [
        ProjectPairing(id: pairingID, project: projectKey(), references: [alphaReference], ssh: []),
    ])), "delegation sudo: a format 2 pairing item migrates with no sudo")
    let roundTrip = ProtectedStores.processLocal()
    let document = PairingDocument(projects: [ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true)])
    _ = try? await roundTrip.store(for: PairingDocument.self).prepare(document).commit()
    check(await roundTrip.store(for: PairingDocument.self).load() == .document(document),
          "delegation sudo: format 3 keeps sudo across a restart")
    check(!ProjectPairing(project: projectKey(), references: [], ssh: [], sudo: true).isEmpty,
          "delegation sudo: a sudo pairing alone keeps the pairing")
}

private func delegationToolShellAnchorTests(
    key: Ed25519SSHFixture, host: Ed25519SSHFixture, session: Data, binding: SSHDestinationBinding,
    metadata: SSHKeyMetadata, use: PairedSSHUse
) async {
    typealias Link = SSHChainTestLink
    let toolShell: pid_t = 63_100
    let gitPID: pid_t = 63_101
    let ssh: pid_t = 63_102
    let secondSSH: pid_t = 63_103
    let csecAI: pid_t = 63_104
    let programShell: pid_t = 63_105

    struct Registered {
        var command: String
        var unwrapped = true
        var mode = "auto"
    }
    /// ssh ← links… ← the Bash tool shell (`shellArgv`, by default Claude
    /// Code's framing of `command`) ← P, with `registered` sent by the hook
    /// before the shell started (or, with `late`, after).
    func world(
        _ command: String = "git push",
        links: [Link]? = nil,
        shellPath: String = "/bin/zsh",
        shellArgv: [String]? = nil,
        shellEnvironment: [SyntheticClaudeSessionFacts.EnvironmentEntry] = [],
        agentEnvironment: [SyntheticClaudeSessionFacts.EnvironmentEntry] = [],
        registered: [Registered]? = nil,
        late: Bool = false,
        csecAIAnchor: Bool = false,
        extra: (inout DelegationTree) -> Void = { _ in }
    ) async -> (SSHSigningService, DelegationReview) {
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        tree.session(
            Standard.agent, parent: Standard.fish,
            environment: [.init(name: "HOME", value: delegationHome), .init(name: "TERM", value: "xterm")] + agentEnvironment
        )
        tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
        var parent: pid_t
        if csecAIAnchor {
            // The `csec ai` shape, for the cross-kind check: tool shell →
            // csec ai → zsh -lc → git.
            tree.command(csecAI, shell: toolShell, agent: Standard.agent, program: command)
            tree.processes[programShell] = SyntheticClaudeSessionFacts.Process(
                startTime: UInt64(programShell) * 10, parent: csecAI, executablePath: "/bin/zsh",
                argv: ["/bin/zsh", "-lc", command]
            )
            parent = programShell
        } else {
            tree.processes[toolShell] = SyntheticClaudeSessionFacts.Process(
                startTime: UInt64(toolShell) * 10, parent: Standard.agent, executablePath: shellPath,
                argv: shellArgv ?? claudeToolShellArgv(command), environment: shellEnvironment
            )
            tree.names[toolShell] = "zsh"
            parent = toolShell
        }
        for link in (links ?? [Link(pid: gitPID, path: "/usr/bin/git", argv: ["git", "push"])]).reversed() {
            tree.processes[link.pid] = SyntheticClaudeSessionFacts.Process(
                startTime: UInt64(link.pid) * 10, parent: parent, executablePath: link.path, argv: link.argv
            )
            tree.names[link.pid] = (link.path as NSString).lastPathComponent
            parent = link.pid
        }
        for pid in [ssh, secondSSH] {
            tree.processes[pid] = SyntheticClaudeSessionFacts.Process(
                startTime: UInt64(pid) * 10, parent: parent, executablePath: "/usr/bin/ssh",
                argv: ["ssh", "git@github.com", "git-receive-pack 'synthetic/repo.git'"]
            )
            tree.names[pid] = "ssh"
        }
        extra(&tree)
        let (facts, inspection) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing(references: [], ssh: [use])])
        let clock = DelegationTestClock()
        let service = makeService(facts, stores: stores, clock: clock)
        if late { clock.started(csecAIAnchor ? csecAI : toolShell) }
        for entry in registered ?? [Registered(command: command)] {
            _ = await register(service, entry.command, peer: Standard.hookPeer, mode: entry.mode, unwrapped: entry.unwrapped)
        }
        let provider = HeldFixtureProvider(
            schemes: ["csec"], values: [metadata.reference: key.privateKeyPEM], held: [metadata.reference]
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(provider)
        let review = DelegationReview()
        let signing = SSHSigningService(
            resolver: resolver, catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [metadata])),
            consent: DelegationSheetConsent(), policyReview: review, allowUnverifiedCallersForTesting: true,
            processInspection: inspection, knownHostsLookup: SSHKnownHostsLookup { _ in ["github.com"] },
            terminalInspection: .unavailable, delegation: service
        )
        return (signing, review)
    }
    func sign(_ signing: SSHSigningService, from requester: pid_t = ssh) async -> Data? {
        try? await signing.signSSHAuthentication(
            publicKeyBlob: key.publicKeyBlob,
            signedData: userAuthenticationRequest(
                sessionIdentifier: session, remoteUser: "git",
                publicKeyBlob: key.publicKeyBlob, hostKeyBlob: host.publicKeyBlob
            ),
            flags: 0, binding: binding,
            caller: CallerInfo(pid: requester, startTime: UInt64(requester) * 10, description: "Apple SSH")
        )
    }
    /// Signs once and returns (signed, panels shown, the last panel's note).
    func outcome(_ built: (SSHSigningService, DelegationReview)) async -> (Bool, Int, DelegationDecline?) {
        let signature = await sign(built.0)
        return (signature != nil, await built.1.count, await built.1.last?.delegationNote)
    }

    // Delegated: the hook's unwrapped registration of exactly the text the
    // tool shell evaluates, made in auto mode before the shell started.
    let plain = await outcome(world())
    check(plain.0 && plain.1 == 0,
          "delegation SSH (tool shell): an unwrapped git push signs with no panel (\(plain))")
    let commitPush = "git add -A && git commit -m \"$(cat <<'EOF'\nShip it\nEOF\n)\" && git push -u origin HEAD"
    let listed = await outcome(world(
        commitPush, links: [Link(pid: gitPID, path: "/usr/bin/git", argv: ["git", "push", "-u", "origin", "HEAD"])]
    ))
    check(listed.0 && listed.1 == 0,
          "delegation SSH (tool shell): the push of an add, heredoc commit and push list signs with no panel (\(listed))")
    let pulled = await outcome(world(
        "git pull --rebase", links: [
            Link(pid: 63_106, path: "/Library/Developer/CommandLineTools/usr/libexec/git-core/git", argv: ["git", "fetch", "--update-head-ok"]),
            Link(pid: gitPID, path: "/usr/bin/git", argv: ["git", "pull", "--rebase"]),
        ]
    ))
    check(pulled.0 && pulled.1 == 0,
          "delegation SSH (tool shell): git pull's own git fetch below it signs with no panel (\(pulled))")
    // In a linked worktree `git pull` gives its `git fetch` GIT_DIR, the
    // worktree's directory under the common .git (measured with git 2.50.1).
    // That is git's own doing, never steering; the same GIT_DIR on the git the
    // shell started still is.
    let pullLinks = [
        Link(pid: 63_106, path: "/Library/Developer/CommandLineTools/usr/libexec/git-core/git", argv: ["git", "fetch", "--update-head-ok"]),
        Link(pid: gitPID, path: "/usr/bin/git", argv: ["git", "pull", "--rebase"]),
    ]
    let worktreeGitDir = SyntheticClaudeSessionFacts.EnvironmentEntry(name: "GIT_DIR", value: "/Users/u/repo/.git/worktrees/wt")
    let worktreePull = await outcome(world("git pull --rebase", links: pullLinks, extra: { tree in
        tree.processes[63_106]?.environment = [worktreeGitDir]
    }))
    check(worktreePull.0 && worktreePull.1 == 0,
          "delegation SSH (tool shell): a worktree's git pull, whose git fetch git gave GIT_DIR, signs with no panel (\(worktreePull))")
    let steeredPull = await outcome(world("git pull --rebase", links: pullLinks, extra: { tree in
        tree.processes[gitPID]?.environment = [worktreeGitDir]
        tree.processes[63_106]?.environment = [worktreeGitDir]
    }))
    check(steeredPull.0 && steeredPull.1 == 0,
          "delegation SSH (tool shell): GIT_DIR on the git pull the shell started signs (csec-0.11: auto mode approved the command, so it signs) (\(steeredPull))")
    // A second connection under the same tool shell finds the registration
    // already bound to it.
    let twice = await world()
    let first = await sign(twice.0)
    let second = await sign(twice.0, from: secondSSH)
    let twiceReviews = await twice.1.count
    check(first != nil && second != nil && twiceReviews == 0,
          "delegation SSH (tool shell): a second ssh under the same tool shell reuses its binding with no panel")

    // Declined, with the panel and its note.
    let wrappedKind = await outcome(world(registered: [Registered(command: "git push", unwrapped: false)]))
    check(!wrappedKind.0 && wrappedKind.2 == .notRegistered,
          "delegation SSH (tool shell): a csec ai's registration of the same text never binds to a tool shell (\(wrappedKind))")
    let crossKind = await outcome(world(
        csecAIAnchor: true, extra: { tree in tree.processes[csecAI]?.argv = [delegationCsecPath, "ai", "--", "git", "push"] }
    ))
    check(!crossKind.0 && crossKind.2 == .notRegistered,
          "delegation SSH (tool shell): an unwrapped registration never binds to a csec ai (\(crossKind))")
    let late = await outcome(world(late: true))
    check(!late.0 && late.2 == .notRegistered,
          "delegation SSH (tool shell): a registration that arrived after the tool shell started never binds (\(late))")
    let defaultMode = await outcome(world(registered: [Registered(command: "git push", mode: "default")]))
    check(!defaultMode.0 && defaultMode.2 == .notAutoMode("default"),
          "delegation SSH (tool shell): a git push registered in default mode declines .notAutoMode (\(defaultMode))")
    let staleAuto = await outcome(world(registered: [
        Registered(command: "git push"), Registered(command: "git push", mode: "default"),
    ]))
    check(!staleAuto.0 && staleAuto.2 == .notAutoMode("default"),
          "delegation SSH (tool shell): the newest registration binds, never an older auto one (\(staleAuto))")
    // A local git command the hook registers nothing for: even a registration
    // of its text binds nothing, since csecd's own reading of it says the hook
    // never registers it (auto mode approves read-only git without the
    // classifier).
    let local = await outcome(world(
        "git log --oneline -1", links: [Link(pid: gitPID, path: "/usr/bin/git", argv: ["git", "log", "--oneline", "-1"])]
    ))
    check(!local.0 && local.2 == .notRegistered,
          "delegation SSH (tool shell): ssh under a local git command (a lazy fetch) declines .notRegistered (\(local))")
    let mismatch = await outcome(world(links: [Link(pid: gitPID, path: "/usr/bin/git", argv: ["git", "push", "elsewhere", "main"])]))
    check(mismatch.0 && mismatch.1 == 0,
          "delegation SSH (tool shell): a git whose argv the text does not hold signs (csec-0.11: auto mode approved the command, so it signs) (\(mismatch))")
    // No environment below the anchor is judged for SSH (csec-0.11).
    let zdotdir = await outcome(world(agentEnvironment: [.init(name: "ZDOTDIR", value: "/tmp/planted")]))
    check(zdotdir.0 && zdotdir.1 == 0,
          "delegation SSH (tool shell): ZDOTDIR in Claude Code's environment signs (csec-0.11: auto mode approved the command, so it signs) (\(zdotdir))")
    let shellOnly = await outcome(world(shellEnvironment: [.init(name: "ZDOTDIR", value: "/tmp/planted")]))
    check(shellOnly.0 && shellOnly.1 == 0,
          "delegation SSH (tool shell): the tool shell's own environment, which the kernel withholds, is never needed (\(shellOnly))")
    let gitDir = await outcome(world(extra: { tree in
        tree.processes[gitPID]?.environment = [.init(name: "GIT_DIR", value: "/tmp/other.git")]
    }))
    check(gitDir.0 && gitDir.1 == 0,
          "delegation SSH (tool shell): GIT_DIR on git signs (csec-0.11: auto mode approved the command, so it signs) (\(gitDir))")
    // Whatever stands between the tool shell and ssh is not judged.
    let nested = await outcome(world(links: [
        Link(pid: gitPID, path: "/usr/bin/git", argv: ["git", "push"]),
        Link(pid: 63_107, path: "/bin/zsh", argv: ["/bin/zsh", "-lc", "git push"]),
    ]))
    check(nested.0 && nested.1 == 0,
          "delegation SSH (tool shell): a zsh -lc between git and the tool shell signs (csec-0.11: auto mode approved the command, so it signs) (\(nested))")
    let hook = await outcome(world(links: [
        Link(pid: 63_108, path: "/bin/bash", argv: ["/bin/sh", ".git/hooks/pre-push"]),
        Link(pid: gitPID, path: "/usr/bin/git", argv: ["git", "push"]),
    ]))
    check(hook.0 && hook.1 == 0,
          "delegation SSH (tool shell): ssh from a pre-push hook signs (csec-0.11: auto mode approved the command, so it signs) (\(hook))")

    // No anchor at all: the panel, with no note.
    let framing = claudeToolShellArgv("git push")
    for (label, path, argv) in [
        ("a bash tool shell", "/bin/bash", ["/bin/bash", "-c", framing[2]]),
        ("-lc in place of -c", "/bin/zsh", ["/bin/zsh", "-lc", framing[2]]),
        ("a second eval", "/bin/zsh", ["/bin/zsh", "-c", framing[2] + "; eval 'git push'"]),
        ("an eval with two words", "/bin/zsh", ["/bin/zsh", "-c", "eval 'git push' 'x'"]),
    ] {
        let none = await outcome(world(shellPath: path, shellArgv: argv))
        check(!none.0 && none.1 == 1 && none.2 == nil,
              "delegation SSH (tool shell): \(label) is no anchor, so the panel shows with no note (\(none))")
    }
}

/// What a background SSH signing returned, once it has.
private actor SSHSignatureBox {
    private(set) var finished = false
    private(set) var signature: Data?

    func set(_ signature: Data?) {
        self.signature = signature
        finished = true
    }
}

// MARK: - Restore

private func delegationRestoreTests() async {
    // Discovery: live, interactive, verified Claude Code sessions select
    // their projects' pairings; nothing else does.
    do {
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        tree.session(64_010, parent: Standard.fish)
        tree.session(64_020, parent: Standard.fish, path: "/synthetic/projects/gamma", inode: 77, standardInput: .other)
        tree.session(64_030, parent: Standard.fish, path: "/synthetic/projects/gamma", inode: 77,
                     identity: codexIdentity(pid: 64_030), executablePath: "/opt/homebrew/bin/codex", name: "codex")
        tree.session(64_040, parent: Standard.fish, path: betaPath, inode: betaInode)
        let (facts, _) = tree.build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing(), pairing("/synthetic/projects/gamma", inode: 77), pairing("/synthetic/projects/delta", inode: 88)])
        let service = makeService(facts, stores: stores)
        let found = await service.pairingsOfLiveSessions().map(\.project.path)
        check(found == [alphaPath], "restore: discovery selects only projects of live interactive verified Claude Code sessions")
        let disabled = makeService(facts, stores: .processLocal())
        check(await disabled.pairingsOfLiveSessions().isEmpty, "restore: with delegation off there are no paired rows")
    }

    // A use paired for csecd alone covers every project, so a live session
    // in a project with no pairing still needs it reopened: its own row,
    // and none while no session is live or a live project's row lists it.
    do {
        let deltaUse = ProjectPairing(
            project: projectKey("/synthetic/projects/delta", inode: 88), references: [],
            usedReferences: [alphaReference], ssh: []
        )
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [deltaUse])
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(HeldFixtureProvider(
            schemes: ["csec"], values: [alphaReference: Data("synthetic-token".utf8)], held: []
        ))
        var tree = DelegationTree()
        tree.terminal(Standard.fish)
        tree.session(64_040, parent: Standard.fish, path: betaPath, inode: betaInode)
        let service = makeService(tree.build().0, stores: stores)
        let live = await service.livePairings()
        let rows = await DelegationRestoreSource(delegation: service, resolver: resolver).restoreItems()
        check(live.projects.isEmpty && live.everyProjectUses == [alphaReference]
                && rows.count == 1 && rows.first?.row.kind == .pairedProject && rows.first?.row.title == "Every project"
                && rows.first?.references.map(\.uri) == [alphaReference],
              "restore: a live session in an unpaired project reopens the every-project uses in their own row")

        var quietTree = DelegationTree()
        quietTree.terminal(Standard.fish)
        let quiet = makeService(quietTree.build().0, stores: stores)
        let quietRows = await DelegationRestoreSource(delegation: quiet, resolver: resolver).restoreItems()
        check(quietRows.isEmpty, "restore: with no live session nothing paired for every project is reopened")

        var deltaTree = DelegationTree()
        deltaTree.terminal(Standard.fish)
        deltaTree.session(64_050, parent: Standard.fish, path: "/synthetic/projects/delta", inode: 88)
        let paired = makeService(deltaTree.build().0, stores: stores)
        let pairedRows = await DelegationRestoreSource(delegation: paired, resolver: resolver).restoreItems()
        check(pairedRows.map(\.row.title) == ["delta"],
              "restore: a use a live project's row already lists gets no second row")
    }

    // A delegation-eligible cold request raises the restore panel; approving
    // it reopens the paired references and the request is released.
    guard let command = LiveCommand(), let later = LiveCommand(), let defaultMode = LiveCommand() else { return }
    defer { command.stop(); later.stop(); defaultMode.stop() }
    let review = DelegationReview(.approve(scope: nil, durationIndex: nil, surface: .mac))
    let harness = await makeAgentHarness(
        commands: [(command, Standard.program), (later, "later"), (defaultMode, "default")],
        held: [], review: review, restoration: true
    )
    // A default-mode request never triggers the restore through pairing.
    _ = await register(harness.service, "default", peer: Standard.hookPeer, mode: "default")
    await review.answer(.deny)
    guard let defaultRequest = aiRequest("default") else { return }
    _ = await harness.agent.handle(request: defaultRequest, caller: defaultMode.caller)
    let restoresAfterDefault = await review.restoreOnly
    let defaultNote = await review.last?.delegationNote
    check(restoresAfterDefault.isEmpty && defaultNote == .notAutoMode("default"),
          "restore: a default-mode request never raises the restore panel; it gets its own")
    await review.answer(.approve(scope: nil, durationIndex: nil, surface: .mac))
    _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
    guard let request = aiRequest(Standard.program) else { return }
    let released = await harness.agent.handle(request: request, caller: command.caller)
    let restorePanels = await review.restoreOnly
    let row = restorePanels.first?.restore?.rows.first
    check(released.values?[alphaReference] != nil && restorePanels.count == 1
            && row?.kind == .pairedProject && row?.title == "alpha" && row?.references == [alphaReference]
            && restorePanels.first?.delegationNote == nil && restorePanels.first?.pairingOffer == nil,
          "restore: a cold paired request raises one restore panel listing the paired project, then is released")
    // The restore is used up: a later cold paired reference declines .notHeld.
    await harness.provider.release(alphaReference)
    _ = await register(harness.service, "later", peer: Standard.hookPeer)
    await review.answer(.deny)
    guard let laterRequest = aiRequest("later") else { return }
    _ = await harness.agent.handle(request: laterRequest, caller: later.caller)
    let restoresAfterLater = await review.restoreOnly
    let laterNote = await review.last?.delegationNote
    check(restoresAfterLater.count == 1 && laterNote == .notHeld(alphaReference),
          "restore: once used up, a later cold paired reference declines .notHeld and gets its panel")

    // op://: after a restart a paired op:// value is fetched from 1Password
    // for auto mode, with no csec panel, though the biometric cache tier
    // still holds what an earlier run cached at rest.
    guard let opCommand = LiveCommand() else { return }
    defer { opCommand.stop() }
    let opRef = "op://Paired/Item/credential"
    var opTree = DelegationTree()
    opTree.terminal(Standard.fish)
    opTree.session(Standard.agent, parent: Standard.fish)
    opTree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
    opTree.command(opCommand.pid, start: opCommand.start, shell: 61_500, agent: Standard.agent, program: "op")
    let (opFacts, opInspection) = opTree.build()
    let opStores = ProtectedStores.processLocal()
    await enableDelegation(opStores)
    await seedPairings(opStores, [pairing(references: [opRef])])
    let keychain = FakeKeychainBackend()
    try? await KeychainSecretCache(backend: keychain).put(opRef, value: Data("synthetic-cached-op".utf8))
    // A restarted csecd: the same at-rest items, an empty warm tier.
    let restartedCache = KeychainSecretCache(backend: keychain)
    let onePassword = InteractiveOnlyProvider()
    let opResolver = SecretResolver(cache: restartedCache)
    await opResolver.register(onePassword)
    let opConsent = DelegationSheetConsent()
    let opService = makeService(opFacts, stores: opStores, consent: opConsent)
    let opReview = DelegationReview(.approve(scope: nil, durationIndex: nil, surface: .mac))
    let opRestoration = GrantRestoration(
        resolver: opResolver, policyReview: opReview, consent: opConsent, terminalInspection: .unavailable
    )
    await opRestoration.addItemSource(DelegationRestoreSource(delegation: opService, resolver: opResolver))
    let opAgent = Agent(
        resolver: opResolver, grants: GrantTable(), consent: opConsent, policyReview: opReview,
        allowUnverifiedPlansForTesting: true, processInspection: opInspection, terminalInspection: .unavailable,
        restoration: opRestoration, delegation: opService
    )
    _ = await register(opService, "op", peer: Standard.hookPeer)
    guard let opRequest = aiRequest("op", references: [opRef]) else { return }
    let opReleased = await opAgent.handle(request: opRequest, caller: opCommand.caller)
    let opPanels = await opReview.reviews
    let opResolves = await onePassword.interactiveResolves
    let opRows = await DelegationRestoreSource(delegation: opService, resolver: opResolver).restoreItems()
    check(opReleased.values?[opRef] == Data("synthetic-interactive-\(ref(opRef).path)".utf8)
            && opPanels.isEmpty && opRows.isEmpty && opResolves == 1,
          "restore: a cold paired op:// value is fetched from 1Password with no panel, and no restore row lists it")
}

// MARK: - Fetched ahead by the attended restore

/// csec-0.64.6: after an unattended install restart, 1Password refused every
/// paired fetch until someone came back to the Mac (218 of 221 op:// not-held
/// declines in 48 h fell in that gap), because the restarted bridge's first
/// fetch needs 1Password's own authorization. The install's attended
/// `csec restore` now fetches every paired value ahead, in every project,
/// while that person is there.
private func delegationRestoreFetchAheadTests() async {
    let opRef = "op://Paired/Item/credential"
    let betaRef = "op://Paired/Beta/credential"
    let betaPath = "/synthetic/projects/beta"

    guard let installer = LiveCommand() else { return }
    defer { installer.stop() }

    func world(
        provider: any SecretProvider, delegationOn: Bool = true,
        alsoPaired: [String] = [], nativeHeld: Set<String> = []
    ) async -> (agent: Agent, resolver: SecretResolver, log: DecisionLog, native: ColdUntilWarmedProvider) {
        let stores = ProtectedStores.processLocal()
        if delegationOn { await enableDelegation(stores) }
        await seedPairings(stores, [
            pairing(references: [opRef, alphaReference] + alsoPaired),
            // No live session in this project: it is fetched all the same.
            pairing(betaPath, inode: 9_191, references: [betaRef]),
        ])
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: FakeKeychainBackend()))
        await resolver.register(provider)
        let native = ColdUntilWarmedProvider(values: [alphaReference: Data("synthetic-native".utf8)], held: nativeHeld)
        await resolver.register(native)
        // The installer's `csec restore` is a live process, and no Claude
        // Code session is running anywhere.
        var tree = DelegationTree()
        tree.processes[installer.pid] = .init(startTime: installer.start, parent: 1, executablePath: "/usr/local/bin/csec")
        let (facts, inspection) = tree.build()
        let consent = DelegationSheetConsent()
        let service = makeService(facts, stores: stores, consent: consent)
        let review = DelegationReview(.deny)
        let log = await makeDelegationLog(stores)
        let restoration = GrantRestoration(
            resolver: resolver, policyReview: review, consent: consent, decisionLog: log,
            terminalInspection: .unavailable
        )
        await restoration.addItemSource(DelegationRestoreSource(delegation: service, resolver: resolver))
        let agent = Agent(
            resolver: resolver, grants: GrantTable(), consent: consent, policyReview: review,
            allowUnverifiedPlansForTesting: true, processInspection: inspection, terminalInspection: .unavailable,
            restoration: restoration, delegation: service
        )
        return (agent, resolver, log, native)
    }

    let onePassword = InteractiveOnlyProvider()
    let fetching = await world(provider: onePassword)
    let reply = await fetching.agent.restoreApprovals(request: RestoreApprovalsRequest(), caller: installer.caller)
    let held = await fetching.resolver.resolveWithoutInteraction(ref(opRef))
    let heldBeta = await fetching.resolver.resolveWithoutInteraction(ref(betaRef))
    let nativeHeld = await fetching.native.resolveWithoutInteraction(ref(alphaReference))
    check(reply.restorationStatus == .notNeeded
            && reply.restoreFetchAhead == FetchAheadSummary(fetched: 2, alreadyHeld: 0, failures: [])
            && held == Data("synthetic-interactive-\(ref(opRef).path)".utf8)
            && heldBeta == Data("synthetic-interactive-\(ref(betaRef).path)".utf8),
          "restore: the attended restore fetches every paired 1Password value ahead, live session or not, and holds it")
    check(nativeHeld == nil,
          "restore: a paired value that needs csec's touch is not fetched ahead; the restore panel owns it")
    let fetchRecords = await fetching.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.fetchAhead])).records
    check(fetchRecords.count == 1 && fetchRecords.first?.refs == nil
            && fetchRecords.first?.detail?.contains("fetched 2, already held 0, failed 0") == true,
          "restore: the fetch ahead is logged once, value-free")

    // A second restore asks 1Password for nothing it already holds.
    let again = await fetching.agent.restoreApprovals(request: RestoreApprovalsRequest(), caller: installer.caller)
    let resolves = await onePassword.interactiveResolves
    check(again.restoreFetchAhead == FetchAheadSummary(fetched: 0, alreadyHeld: 2, failures: []) && resolves == 2,
          "restore: a value already held is not fetched again")

    // 1Password refusing is reported, never a failed restore: the install
    // goes on, and those values are fetched on first use as before.
    let refused = await world(provider: FailingOnePasswordProvider(error: OnePasswordBridgeError.remote(
        kind: "unauthorized", message: "synthetic"
    )))
    let refusedReply = await refused.agent.restoreApprovals(request: RestoreApprovalsRequest(), caller: installer.caller)
    let refusedRecord = await refused.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.fetchAhead])).records.first
    check(refusedReply.failure == nil && refusedReply.restorationStatus == .notNeeded
            && refusedReply.restoreFetchAhead?.fetched == 0 && refusedReply.restoreFetchAhead?.failureCount == 2
            && refusedReply.restoreFetchAhead?.failures.allSatisfy({ $0.reason == "1Password did not authorize this request" }) == true,
          "restore: what 1Password refused is reported with its reason, and the restore still succeeds")
    check(refusedRecord?.refs == [opRef, betaRef]
            && refusedRecord?.detail?.contains("1Password did not authorize this request (2)") == true,
          "restore: the log names what was not fetched and why")

    // csec-0.64.12: the install's restore had just opened the native stores,
    // so every warm csec:// value was read, then reported as a failure
    // because its provider keeps no cached copy. A delegated release already
    // serves it, so it is held, and is not fetched.
    let opened = await world(provider: InteractiveOnlyProvider(), nativeHeld: [alphaReference])
    let openedReply = await opened.agent.restoreApprovals(request: RestoreApprovalsRequest(), caller: installer.caller)
    let openedFetches = await opened.native.resolves
    check(openedReply.restoreFetchAhead == FetchAheadSummary(fetched: 2, alreadyHeld: 1, failures: [])
            && openedFetches == 0,
          "restore: a paired value its provider already holds open counts as held, not as a failure")

    // csec-0.64.12: the reply lists at most maximumFailures, but the log's
    // reasons count every failure, or the ones past the list go unexplained.
    let many = (0..<40).map { "op://Paired/Many\($0)/credential" }
    let crowded = await world(
        provider: FailingOnePasswordProvider(error: OnePasswordBridgeError.remote(kind: "unauthorized", message: "synthetic")),
        alsoPaired: many
    )
    let crowdedReply = await crowded.agent.restoreApprovals(request: RestoreApprovalsRequest(), caller: installer.caller)
    let crowdedRecord = await crowded.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.fetchAhead])).records.first
    check(crowdedReply.restoreFetchAhead?.failureCount == 42
            && crowdedReply.restoreFetchAhead?.failures.count == FetchAheadSummary.maximumFailures
            && crowdedRecord?.detail?.contains("failed 42: 1Password did not authorize this request (42)") == true,
          "restore: the log counts the reasons of every failure, not only those the reply lists")

    // Delegated approvals off: pairings decide nothing, so nothing is fetched.
    let offProvider = InteractiveOnlyProvider()
    let off = await world(provider: offProvider, delegationOn: false)
    let offReply = await off.agent.restoreApprovals(request: RestoreApprovalsRequest(), caller: installer.caller)
    let offResolves = await offProvider.interactiveResolves
    check(offReply.restoreFetchAhead == nil && offResolves == 0,
          "restore: with delegated approvals off nothing is fetched ahead")
}

// MARK: - Judged again after the restore panel

/// A native-like provider: `resolve` with no unlock fails while a value is
/// cold (as the native store throws authenticationRequired), and a restore's
/// `warm` makes it held.
private actor ColdUntilWarmedProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["csec"]
    private let values: [String: Data]
    private var held: Set<String>

    init(values: [String: Data], held: Set<String>) {
        self.values = values
        self.held = held
    }

    /// Every `resolve`, the call a fetch makes; `resolveWithoutInteraction`
    /// is not counted.
    private(set) var resolves = 0

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        guard held.contains(ref.uri) || unlock != nil else { throw ProviderError.notAuthenticated }
        held.insert(ref.uri)
        resolves += 1
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func resolveWithoutInteraction(_ ref: SecretRef) async -> ResolvedSecret? {
        guard held.contains(ref.uri), let value = values[ref.uri] else { return nil }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func requiresUnlockToResolve(_ ref: SecretRef) async -> Bool { !held.contains(ref.uri) }

    func warm(_ refs: [SecretRef], unlock: CacheUnlock) async {
        for ref in refs where values[ref.uri] != nil { held.insert(ref.uri) }
    }

    nonisolated func authenticate() async throws {}
    nonisolated func isAvailable() async -> Bool { true }
}

/// Holds a restore-only panel on screen until the test releases it, then
/// approves it (its context comes from the consent provider). Every other
/// panel is refused as a human's Deny and kept, so a test can see which
/// request got one and what it said.
private actor HeldRestoreReview: PolicyReviewProvider {
    private(set) var restoreShown = 0
    private(set) var others: [AccessPolicyReview] = []
    private var held: CheckedContinuation<Void, Never>?

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        guard review.isRestoreOnly else {
            others.append(review)
            return .denied(.human(decidedAt: .now, on: .mac))
        }
        restoreShown += 1
        await withCheckedContinuation { held = $0 }
        return .approved(AccessPolicyApproval(decidedOn: .mac))
    }

    func release() {
        held?.resume()
        held = nil
    }

    var isHolding: Bool { held != nil }

    func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome { .denied }
}

private struct RestoreWorld {
    let agent: Agent
    let service: ClaudeDelegationService
    let grants: GrantTable
    let restore: GrantRestoration
    let review: HeldRestoreReview
}

/// A restarted csecd: delegation on, alpha's project paired with
/// `alphaReference`, values served by a provider whose unheld values are
/// cold, and the one restore panel, which lists restored grants and paired
/// projects and stays up until the test releases it.
private func makeRestoreWorld(
    commands: [(LiveCommand, String)], values: [String: Data], held: Set<String>
) async -> RestoreWorld {
    var tree = DelegationTree()
    tree.terminal(Standard.fish)
    tree.session(Standard.agent, parent: Standard.fish)
    tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
    for (index, (command, program)) in commands.enumerated() {
        tree.command(command.pid, start: command.start, shell: pid_t(61_700 + index), agent: Standard.agent, program: program)
    }
    let (facts, inspection) = tree.build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    await seedPairings(stores, [pairing()])
    let log = await makeDelegationLog(stores)
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(ColdUntilWarmedProvider(values: values, held: held))
    let consent = DelegationSheetConsent()
    let service = makeService(facts, stores: stores, consent: consent, log: log)
    let grants = GrantTable()
    let review = HeldRestoreReview()
    let restore = GrantRestoration(resolver: resolver, policyReview: review, consent: consent, terminalInspection: .unavailable)
    await restore.addGrantSource(grants)
    await restore.addItemSource(DelegationRestoreSource(delegation: service, resolver: resolver))
    let agent = Agent(
        resolver: resolver, grants: grants, consent: consent, policyReview: review,
        allowUnverifiedPlansForTesting: true, processInspection: inspection,
        terminalInspection: .unavailable, decisionLog: log, restoration: restore, delegation: service
    )
    for (_, program) in commands { _ = await register(service, program, peer: Standard.hookPeer) }
    return RestoreWorld(agent: agent, service: service, grants: grants, restore: restore, review: review)
}

private func restoreIsHeld(_ review: HeldRestoreReview) async -> Bool {
    await eventuallyTrue { await review.isHolding }
}

private enum RestoreWaitChange: String {
    case nothing, grantRevoked, grantExpired, unpaired, delegationDisabled
}

private func delegationRestoreRejudgeTests() async {
    for change in [RestoreWaitChange.nothing, .grantRevoked, .grantExpired] {
        await restoreRejudgeCoveredGrant(change)
    }
    for change in [RestoreWaitChange.nothing, .unpaired, .delegationDisabled] {
        await restoreRejudgePairing(change)
    }
    for change in [RestoreWaitChange.nothing, .unpaired, .delegationDisabled] {
        await restoreRejudgeSSH(change)
    }
    await restoreInFlightJoinTests()
}

/// alpha is paired and held; beta is not paired, but a restored grant still
/// sealed covers it, so the delegated request waits on the restore panel.
/// The grant ends while the panel is up: beta is new again, unpaired, and
/// gets an ordinary panel rather than riding the approval made before.
private func restoreRejudgeCoveredGrant(_ change: RestoreWaitChange) async {
    let label = "delegation restore [\(change.rawValue)]"
    guard let command = LiveCommand(), let myStart = ProcessAncestry.startTime(of: getpid()) else {
        check(false, "\(label): fixtures start")
        return
    }
    defer { command.stop() }
    let betaReference = "csec://beta/KEY"
    let world = await makeRestoreWorld(
        commands: [(command, Standard.program)],
        values: [alphaReference: Data("synthetic-alpha".utf8), betaReference: Data("synthetic-beta".utf8)],
        held: [alphaReference]
    )
    guard let request = aiRequest(Standard.program, references: [alphaReference, betaReference]),
          let shape = try? request.deliveryPlan?.releaseShapeDigest() else {
        check(false, "\(label): the request builds")
        return
    }
    // Restored after a restart: rooted at this process (an ancestor of the
    // live command), widened to the release shape, covering beta, sealed.
    let restoredID = UUID()
    await world.grants.restore([Grant(
        id: restoredID, rootPID: getpid(), rootStartTime: myStart, references: [betaReference],
        reason: "restored", expiresAt: change == .grantExpired ? Date().addingTimeInterval(1) : nil,
        scopeKind: .codingAgent, scopeReuseDigest: shape, restored: true, warm: false
    )])
    let pending = Task { await world.agent.handle(request: request, caller: command.caller) }
    let shown = await restoreIsHeld(world.review)
    check(shown, "\(label): the delegated request raised the restore panel for its covered, sealed reference")
    switch change {
    case .grantRevoked:
        check(await world.grants.revoke(idPrefix: restoredID.uuidString.lowercased()) == 1,
              "\(label): the covering grant is revoked while the panel is up")
    case .grantExpired:
        try? await Task.sleep(nanoseconds: 1_500_000_000)
    default:
        break
    }
    await world.review.release()
    let response = await pending.value
    let others = await world.review.others
    if change == .nothing {
        check(response.values?[alphaReference] != nil && response.values?[betaReference] != nil && others.isEmpty,
              "\(label): with the restored grant intact, the delegated request gets both values after the restore")
    } else {
        check(response.values == nil && response.failure?.code == .consentDenied && others.count == 1
                && others.first?.delegationNote == .notApprovedForProject(reference: betaReference, project: "alpha"),
              "\(label): a reference whose covering grant ended while the restore panel was up is not released "
                + "without a panel; its panel says it is not paired")
    }
}

/// alpha is paired and cold, so the delegated request waits on the restore
/// panel that lists alpha's project; the pairing, or delegation itself, goes
/// away while the panel is up.
private func restoreRejudgePairing(_ change: RestoreWaitChange) async {
    let label = "delegation restore [\(change.rawValue)]"
    guard let command = LiveCommand() else {
        check(false, "\(label): fixtures start")
        return
    }
    defer { command.stop() }
    let world = await makeRestoreWorld(
        commands: [(command, Standard.program)], values: [alphaReference: Data("synthetic-alpha".utf8)], held: []
    )
    guard let request = aiRequest(Standard.program) else { return }
    let pending = Task { await world.agent.handle(request: request, caller: command.caller) }
    check(await restoreIsHeld(world.review),
          "\(label): the delegated request raised the restore panel for its cold paired reference")
    switch change {
    case .unpaired:
        check(await world.service.removeAllPairings().removed.count == 1,
              "\(label): the project is unpaired while the panel is up")
    case .delegationDisabled:
        let reply = await world.service.configure(.disable(), caller: command.caller, terminal: nil)
        check(reply.failure == nil, "\(label): delegation is turned off while the panel is up")
    default:
        break
    }
    await world.review.release()
    let response = await pending.value
    let others = await world.review.others
    let restoreShown = await world.review.restoreShown
    switch change {
    case .unpaired:
        check(response.values == nil && others.count == 1
                && others.first?.delegationNote == .notApprovedForProject(reference: alphaReference, project: "alpha"),
              "\(label): unpaired while the restore panel was up, the request is not released without a panel")
    case .delegationDisabled:
        check(response.values == nil && others.count == 1 && others.first?.delegationNote == nil
                && others.first?.pairingOffer == nil,
              "\(label): with delegation turned off while the restore panel was up, the request gets an "
                + "ordinary panel with no note")
    default:
        check(response.values?[alphaReference] == Data("synthetic-alpha".utf8) && others.isEmpty && restoreShown == 1,
              "\(label): the paired reference is released once the restore reopens it, with one panel")
    }
}

/// The SSH twin: a delegated signing whose key is cold waits on the restore
/// panel, and is judged again once it closes. Unpairing changes nothing for
/// SSH (csec-0.11); delegation turned off while it is up gives the
/// connection its SSH panel.
private func restoreRejudgeSSH(_ change: RestoreWaitChange) async {
    let label = "delegation restore SSH [\(change.rawValue)]"
    guard let key = try? Ed25519SSHFixture(seed: 211), let host = try? Ed25519SSHFixture(seed: 223) else {
        check(false, "\(label): key fixtures build")
        return
    }
    let session = Data(repeating: 0x55, count: 32)
    guard let binding = try? SSHDestinationBinding(
        hostKeyBlob: host.publicKeyBlob, sessionIdentifier: session,
        signature: host.signatureBlob(for: session), isForwarding: false
    ) else {
        check(false, "\(label): the binding builds")
        return
    }
    let keyReference = "csec://ssh-delegation/key"
    let metadata = SSHKeyMetadata(
        reference: keyReference, fingerprint: sshFingerprint(key.publicKeyBlob),
        algorithm: "ssh-ed25519", publicKeyBlob: key.publicKeyBlob, label: "delegation key"
    )
    let use = PairedSSHUse(keyFingerprint: metadata.fingerprint, hostKeyFingerprint: binding.hostKeyFingerprint, remoteUser: "git")
    let ssh: pid_t = 63_401
    let command: pid_t = 63_410
    var tree = DelegationTree()
    tree.terminal(Standard.fish)
    tree.session(Standard.agent, parent: Standard.fish)
    tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
    tree.command(command, shell: 63_411, agent: Standard.agent, program: "git push")
    tree.processes[63_403] = SyntheticClaudeSessionFacts.Process(
        startTime: 634_030, parent: command, executablePath: "/bin/zsh", argv: ["/bin/zsh", "-lc", "git push"]
    )
    tree.names[63_403] = "zsh"
    tree.processes[63_402] = SyntheticClaudeSessionFacts.Process(
        startTime: 634_020, parent: 63_403, executablePath: "/usr/bin/git", argv: ["git", "push"]
    )
    tree.names[63_402] = "git"
    tree.processes[ssh] = SyntheticClaudeSessionFacts.Process(
        startTime: UInt64(ssh) * 10, parent: 63_402, executablePath: "/usr/bin/ssh", argv: ["ssh", "git@github.com"]
    )
    tree.names[ssh] = "ssh"
    let (facts, inspection) = tree.build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    await seedPairings(stores, [pairing(references: [], ssh: [use])])
    let service = makeService(facts, stores: stores)
    _ = await register(service, "git push", peer: Standard.hookPeer)
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(ColdUntilWarmedProvider(values: [keyReference: key.privateKeyPEM], held: []))
    let consent = DelegationSheetConsent()
    let review = HeldRestoreReview()
    let restore = GrantRestoration(resolver: resolver, policyReview: review, consent: consent, terminalInspection: .unavailable)
    let signing = SSHSigningService(
        resolver: resolver, catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [metadata])),
        consent: consent, policyReview: review, allowUnverifiedCallersForTesting: true,
        processInspection: inspection, knownHostsLookup: SSHKnownHostsLookup { _ in ["github.com"] },
        terminalInspection: .unavailable, restoration: restore, delegation: service
    )
    await restore.addGrantSource(signing)
    await restore.addItemSource(DelegationRestoreSource(delegation: service, resolver: resolver, sshKeys: signing))
    let pending = Task { () -> Data? in
        try? await signing.signSSHAuthentication(
            publicKeyBlob: key.publicKeyBlob,
            signedData: userAuthenticationRequest(
                sessionIdentifier: session, remoteUser: "git",
                publicKeyBlob: key.publicKeyBlob, hostKeyBlob: host.publicKeyBlob
            ),
            flags: 0, binding: binding,
            caller: CallerInfo(pid: ssh, startTime: UInt64(ssh) * 10, description: "Apple SSH")
        )
    }
    check(await restoreIsHeld(review), "\(label): a delegated signing with a cold key raised the restore panel")
    switch change {
    case .unpaired:
        check(await service.removeAllPairings().removed.count == 1, "\(label): the SSH use is unpaired while the panel is up")
    case .delegationDisabled:
        let reply = await service.configure(
            .disable(), caller: CallerInfo(pid: command, startTime: UInt64(command) * 10, description: "csec"), terminal: nil
        )
        check(reply.failure == nil, "\(label): delegation is turned off while the panel is up")
    default:
        break
    }
    await review.release()
    let signature = await pending.value
    let others = await review.others
    switch change {
    case .delegationDisabled:
        check(signature == nil && others.count == 1 && others.first?.ssh != nil && others.first?.delegationNote == nil,
              "\(label): with delegation turned off while the restore panel was up, the connection gets its SSH panel")
    default:
        check(signature != nil && others.isEmpty,
              "\(label): the delegated SSH signing is signed once the restore reopens the key (pairings don't matter, csec-0.11)")
    }
}

/// The plan's "evaluateRelease waits for an in-flight restore before
/// declining": a delegation-eligible request whose paired value is cold, and
/// which arrives while the restore panel is already up, joins that panel
/// rather than raising a second one or declining as not held.
private func restoreInFlightJoinTests() async {
    guard let first = LiveCommand(), let second = LiveCommand() else {
        check(false, "delegation restore join: fixtures start")
        return
    }
    defer { first.stop(); second.stop() }
    let world = await makeRestoreWorld(
        commands: [(first, "first"), (second, "second")],
        values: [alphaReference: Data("synthetic-alpha".utf8)], held: []
    )
    guard let firstRequest = aiRequest("first"), let secondRequest = aiRequest("second") else { return }
    let firstPending = Task { await world.agent.handle(request: firstRequest, caller: first.caller) }
    check(await restoreIsHeld(world.review), "delegation restore join: the first request raised the restore panel")
    let secondPending = Task { await world.agent.handle(request: secondRequest, caller: second.caller) }
    let joined = await eventuallyTrue { await world.restore.waitingCount == 2 }
    let shownWhileUp = await world.review.restoreShown
    let othersWhileUp = await world.review.others.count
    check(joined && shownWhileUp == 1 && othersWhileUp == 0,
          "delegation restore join: a delegation-eligible request arriving during the restore joins it, "
            + "with no second panel and no decline")
    await world.review.release()
    let firstResponse = await firstPending.value
    let secondResponse = await secondPending.value
    let restoreShown = await world.review.restoreShown
    let others = await world.review.others.count
    check(firstResponse.values?[alphaReference] != nil && secondResponse.values?[alphaReference] != nil
            && restoreShown == 1 && others == 0,
          "delegation restore join: both requests are released after the one restore, with no other panel")
}

// MARK: - Unrestorable values, identity lookups, uninstall

/// A paired 1Password value no touch can reopen (never cached, or its cache
/// entry invalidated) neither raises nor appears on a restore panel: it stays
/// cold and declines as not held to the ordinary panel, and the restore stays
/// unused for what a touch can reopen.
private func delegationUnrestorableTests() async {
    guard let command = LiveCommand() else {
        check(false, "restore: live command fixture starts")
        return
    }
    defer { command.stop() }
    let opRef = "op://Paired/Invalidated/credential"
    let nativeRef = "csec://alpha/COLD"
    var tree = DelegationTree()
    tree.terminal(Standard.fish)
    tree.session(Standard.agent, parent: Standard.fish)
    tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
    tree.command(command.pid, start: command.start, shell: 61_800, agent: Standard.agent, program: "op")
    let (facts, inspection) = tree.build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    await seedPairings(stores, [pairing(references: [opRef])])
    let keychain = FakeKeychainBackend()
    let cache = KeychainSecretCache(backend: keychain)
    try? await cache.put(opRef, value: Data("synthetic-cached-op".utf8))
    let heldBeforeInvalidation = await cache.holds(opRef)
    // `invalidate_cached_references` deletes both tiers.
    await cache.invalidate(opRef)
    let heldAfterInvalidation = await cache.holds(opRef)
    let loadsBefore = await keychain.loadCount
    let onePassword = InteractiveOnlyProvider()
    let native = HeldFixtureProvider(schemes: ["csec"], values: [nativeRef: Data("synthetic-native".utf8)], held: [])
    let resolver = SecretResolver(cache: cache)
    await resolver.register(onePassword)
    await resolver.register(native)
    let restorable = await resolver.referencesRestorable([ref(opRef), ref(nativeRef)])
    let loadsAfter = await keychain.loadCount
    check(heldBeforeInvalidation && !heldAfterInvalidation && restorable == [nativeRef] && loadsAfter == loadsBefore,
          "restore: only what a touch can reopen is restorable (a cold native value, not an uncached op:// one), "
            + "found without reading a cached value")
    let consent = DelegationSheetConsent()
    let service = makeService(facts, stores: stores, consent: consent)
    let review = DelegationReview(.deny)
    let restoration = GrantRestoration(resolver: resolver, policyReview: review, consent: consent, terminalInspection: .unavailable)
    await restoration.addItemSource(DelegationRestoreSource(delegation: service, resolver: resolver))
    let agent = Agent(
        resolver: resolver, grants: GrantTable(), consent: consent, policyReview: review,
        allowUnverifiedPlansForTesting: true, processInspection: inspection, terminalInspection: .unavailable,
        restoration: restoration, delegation: service
    )
    _ = await register(service, "op", peer: Standard.hookPeer)
    guard let request = aiRequest("op", references: [opRef]) else { return }
    let response = await agent.handle(request: request, caller: command.caller)
    let reviews = await review.reviews
    let usedUp = await restoration.isUsedUp
    let rows = await DelegationRestoreSource(delegation: service, resolver: resolver).restoreItems()
    let interactive = await onePassword.interactiveResolves
    check(response.values?[opRef] == Data("synthetic-interactive-\(ref(opRef).path)".utf8)
            && reviews.isEmpty && !usedUp && rows.isEmpty && interactive == 1,
          "restore: a paired op:// value csecd never cached is fetched from 1Password with no panel; "
            + "it never appears on a restore panel and the restore stays unused")

    // 1Password failing to serve it declines .notHeld to the ordinary panel,
    // still with no restore panel.
    let failing = FailingOnePasswordProvider()
    let failingResolver = SecretResolver(cache: KeychainSecretCache(backend: FakeKeychainBackend()))
    await failingResolver.register(failing)
    let failingReview = DelegationReview(.deny)
    let failingRestoration = GrantRestoration(
        resolver: failingResolver, policyReview: failingReview, consent: consent, terminalInspection: .unavailable
    )
    await failingRestoration.addItemSource(DelegationRestoreSource(delegation: service, resolver: failingResolver))
    let failingAgent = Agent(
        resolver: failingResolver, grants: GrantTable(), consent: consent, policyReview: failingReview,
        allowUnverifiedPlansForTesting: true, processInspection: inspection, terminalInspection: .unavailable,
        restoration: failingRestoration, delegation: service
    )
    _ = await register(service, "op", peer: Standard.hookPeer)
    let failed = await failingAgent.handle(request: request, caller: command.caller)
    let failedReviews = await failingReview.reviews
    let failingUsedUp = await failingRestoration.isUsedUp
    check(failed.values == nil && failedReviews.count == 1 && failedReviews.first?.isRestoreOnly == false
            && failedReviews.first?.delegationNote == .notHeld(opRef) && !failingUsedUp,
          "restore: a paired op:// value 1Password cannot serve declines .notHeld to the ordinary panel, with no restore panel")

    // Why 1Password could not serve it is the provider's own value-free
    // reason, on the note and in the decline record (csec-0.64.6): before,
    // `try?` dropped it and the log could not say.
    let locked = FailingOnePasswordProvider(error: OnePasswordError.notAuthorized)
    let lockedResolver = SecretResolver(cache: KeychainSecretCache(backend: FakeKeychainBackend()))
    await lockedResolver.register(locked)
    let lockedReview = DelegationReview(.deny)
    let lockedLog = await makeDelegationLog(stores)
    let lockedService = makeService(facts, stores: stores, consent: consent, log: lockedLog)
    let lockedAgent = Agent(
        resolver: lockedResolver, grants: GrantTable(), consent: consent, policyReview: lockedReview,
        allowUnverifiedPlansForTesting: true, processInspection: inspection, terminalInspection: .unavailable,
        delegation: lockedService
    )
    _ = await register(lockedService, "op", peer: Standard.hookPeer)
    let lockedResponse = await lockedAgent.handle(request: request, caller: command.caller)
    let lockedNote = await lockedReview.last?.delegationNote
    let lockedDeclines = await lockedLog.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records
    let reason = OnePasswordError.notAuthorized.boundedReason
    check(lockedResponse.values == nil && lockedNote == .notHeld(opRef, reason: reason)
            && lockedNote?.panelText.contains("couldn't be fetched without you: \(reason)") == true,
          "restore: a paired op:// value 1Password cannot serve says why on its panel: \(lockedNote?.panelText ?? "none")")
    check(lockedDeclines.count == 1 && lockedDeclines.first?.delegation?.reason == "not_held"
            && lockedDeclines.first?.detail?.contains(reason) == true,
          "restore: the not_held decline record carries 1Password's reason")
}

/// Which way csecd located Claude Code's code is recorded with each decision
/// and reported by `configure_delegation status` and `csec status`, so a
/// kernel that refuses the signed csecd the task name port shows on device.
private func delegationIdentityLookupTests() async {
    let fallback = ForeignCodeIdentity(
        pid: Standard.agent, startTime: UInt64(Standard.agent) * 10, lookup: .processID(taskNameStatus: 5),
        identifier: "synthetic.claude-code", teamIdentifier: "SYNTHETIC0", cdHash: String(repeating: "a", count: 40),
        executablePath: "/synthetic/claude", signatureValid: true, hardenedRuntime: true, platformIdentifier: nil,
        entitlementKeys: [], appleAnchored: false, satisfiesAnthropicRequirement: true, trustedCDHash: nil, status: 0
    )
    let fallbackText = "pid fallback (not exec-exact; task_name_for_pid refused: kern_return 5)"
    let (facts, _) = Standard.tree { tree in
        tree.session(Standard.agent, parent: Standard.fish, identity: fallback)
    }.build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    await seedPairings(stores, [pairing()])
    let log = await makeDelegationLog(stores)
    let service = makeService(facts, stores: stores, log: log)
    let caller = CallerInfo(pid: Standard.hookPeer, startTime: UInt64(Standard.hookPeer) * 10, description: "csec")
    let before = await service.configure(.status(claudeConfigDirectory: nil, projectDirectory: nil), caller: caller, terminal: nil)
    _ = await register(service, Standard.program, peer: Standard.hookPeer, mode: "default")
    let declined = decline(await evaluate(service, command: Standard.command, program: Standard.program))
    let records = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline])).records
    let after = await service.configure(.status(claudeConfigDirectory: nil, projectDirectory: nil), caller: caller, terminal: nil)
    check(before.delegationStatus != nil && before.delegationStatus?.identityLookup == nil,
          "identity lookup: nothing is reported before csecd has checked a Claude Code identity")
    check(declined == .notAutoMode("default") && records.last?.delegation?.identityLookup == fallbackText
            && after.delegationStatus?.identityLookup == fallbackText
            && after.delegationStatus?.isWellFormed == true,
          "identity lookup: a decline records the PID fallback, and the status reports it")
    let rows = after.delegationStatus.map {
        ClaudeDelegationStatusRows.rows(.status($0), displayPath: { $0 })
    } ?? []
    check(rows.contains(StatusRow(label: "Claude Code identity check", value: fallbackText, state: .neutral))
            && rows.contains(StatusRow(label: "Claude auto-mode last decline", value: "Claude Code was in manual mode.",
                                       state: .neutral)),
          "csec status: the identity lookup and the last decline's reason each get a neutral row")

    // The exec-exact path, on a delegated release.
    guard let command = LiveCommand() else {
        check(false, "identity lookup: live command fixture starts")
        return
    }
    defer { command.stop() }
    let harness = await makeAgentHarness(commands: [(command, Standard.program)])
    _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
    guard let request = aiRequest(Standard.program) else { return }
    let released = await harness.agent.handle(request: request, caller: command.caller)
    let usage = await harness.log.read(DecisionLogQuery(streams: [.usage], kinds: [.delegatedRelease])).records
    check(released.values?[alphaReference] != nil
            && usage.last?.delegation?.identityLookup == "audit-token (exec-exact)",
          "identity lookup: a delegated release records the exec-exact audit-token path")
}

/// `uninstall_cleanup` drops what the delegation service holds in memory, so
/// a csecd left running after an interrupted uninstall never delegates on it;
/// a refused cleanup leaves delegation as it was.
private func delegationUninstallTests() async {
    let (facts, _) = Standard.tree().build()
    for approve in [false, true] {
        let label = approve ? "approved" : "refused"
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores)
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        let before = await service.state
        let directory = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("csec-delegation-uninstall-\(UUID().uuidString)")
        let outcome = await CsecdUninstaller(
            consent: DelegationSheetConsent(approving: approve), stores: stores, log: nil,
            logDirectory: SealedRecordDirectory(path: directory), delegation: service
        ).run(caller: setupCaller)
        let state = await service.state
        let entries = await service.grantEntries()
        let registered = await register(service, Standard.program, peer: Standard.hookPeer)
        let evaluation = await evaluate(service, command: Standard.command, program: Standard.program)
        if approve {
            check(before == .on && outcome != .denied && state == .off && entries == nil && !registered
                    && evaluation == .notApplicable,
                  "uninstall [\(label)]: the delegation service forgets its settings, pairings and registrations")
        } else {
            check(outcome == .denied && state == .on && entries?.pairings.count == 1 && registered
                    && isApproved(evaluation),
                  "uninstall [\(label)]: delegation is untouched")
        }
        try? FileManager.default.removeItem(atPath: directory)
    }
}

// MARK: - A human Deny made while a delegated request waits on the restore

/// Holds the first ordinary panel until the test answers it with a human's
/// Deny; approves every restore-only panel at once; denies any later ordinary
/// panel and counts it. Wrapped in `QueuedPolicyReview`, as csecd wraps its
/// reviewer, so the restore panel waits behind the held one.
private actor DenyFirstPanelReview: PolicyReviewProvider {
    private(set) var restoreShown = 0
    private(set) var otherPanels = 0
    private var held: CheckedContinuation<Void, Never>?

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        if review.isRestoreOnly {
            restoreShown += 1
            return .approved(AccessPolicyApproval(decidedOn: .mac))
        }
        otherPanels += 1
        if otherPanels == 1 {
            await withCheckedContinuation { held = $0 }
        }
        return .denied(.human(decidedAt: .now, on: .mac))
    }

    func denyHeld() {
        held?.resume()
        held = nil
    }

    var isHolding: Bool { held != nil }

    func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome { .denied }
}

private func delegationRestoreDenyTests() async {
    await restoreDenyAccess(identical: true)
    await restoreDenyAccess(identical: false)
    await restoreDenySSH(identical: true)
    await restoreDenySSH(identical: false)
}

/// A request delegation declined (its program was never registered) has its
/// panel on screen. A delegated request for the same references in the same
/// release shape and Claude Code session, whose paired value is cold, waits on
/// the restore panel queued behind it. The human denies the first panel, then
/// approves the restore: the waiting request is the question the human just
/// answered, so it is refused, not released. A Deny of a different question
/// leaves it released after the restore.
private func restoreDenyAccess(identical: Bool) async {
    let label = "delegation restore deny [\(identical ? "identical" : "other question")]"
    guard let denied = LiveCommand(), let waiting = LiveCommand() else {
        check(false, "\(label): live commands start")
        return
    }
    defer { denied.stop(); waiting.stop() }
    var tree = DelegationTree()
    tree.terminal(Standard.fish)
    tree.session(Standard.agent, parent: Standard.fish)
    tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
    tree.command(denied.pid, start: denied.start, shell: 61_900, agent: Standard.agent, program: "ls")
    tree.command(waiting.pid, start: waiting.start, shell: 61_901, agent: Standard.agent, program: Standard.program)
    let (facts, inspection) = tree.build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    await seedPairings(stores, [pairing()])
    let log = await makeDelegationLog(stores)
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(ColdUntilWarmedProvider(values: [alphaReference: Data("synthetic-alpha".utf8)], held: []))
    let consent = DelegationSheetConsent()
    let service = makeService(facts, stores: stores, consent: consent, log: log)
    let grants = GrantTable()
    let reviewer = DenyFirstPanelReview()
    let queued = QueuedPolicyReview(underlying: reviewer, queue: ConsentQueue())
    let restore = GrantRestoration(resolver: resolver, policyReview: queued, consent: consent, terminalInspection: .unavailable)
    await restore.addGrantSource(grants)
    await restore.addItemSource(DelegationRestoreSource(delegation: service, resolver: resolver))
    let agent = Agent(
        resolver: resolver, grants: grants, consent: consent, policyReview: queued,
        allowUnverifiedPlansForTesting: true, processInspection: inspection,
        terminalInspection: .unavailable, decisionLog: log, restoration: restore, delegation: service
    )
    guard let deniedRequest = aiRequest("ls", references: [identical ? alphaReference : "csec://alpha/OTHER"]),
          let waitingRequest = aiRequest(Standard.program),
          let deniedShape = try? deniedRequest.deliveryPlan?.releaseShapeDigest(),
          let waitingShape = try? waitingRequest.deliveryPlan?.releaseShapeDigest() else {
        check(false, "\(label): fixtures build")
        return
    }
    // Only the waiting request's program is registered: the other declines
    // .notRegistered and gets the ordinary panel the reviewer holds.
    _ = await register(service, Standard.program, peer: Standard.hookPeer)
    let first = Task { await agent.handle(request: deniedRequest, caller: denied.caller) }
    let panelUp = await eventuallyTrue { await reviewer.isHolding }
    let second = Task { await agent.handle(request: waitingRequest, caller: waiting.caller) }
    let joined = await eventuallyTrue { await restore.waitingCount == 1 }
    let restoreBeforeDeny = await reviewer.restoreShown
    check(deniedShape == waitingShape && panelUp && joined && restoreBeforeDeny == 0,
          "\(label): the delegated request waits on the restore panel queued behind the other request's panel")
    await reviewer.denyHeld()
    let firstResponse = await first.value
    let secondResponse = await second.value
    let restores = await reviewer.restoreShown
    let others = await reviewer.otherPanels
    let refusals = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.refusal])).records
    if identical {
        check(firstResponse.failure?.code == .consentDenied && secondResponse.values == nil
                && secondResponse.failure?.code == .consentDenied
                && secondResponse.failure?.message.contains("an identical request waiting with this one was denied") == true
                && restores == 1 && others == 1
                && refusals.contains { $0.detail == "answered by the Deny of an identical request it waited behind" },
              "\(label): a human Deny of the identical question made while it waited on the restore refuses it, "
                + "with no panel of its own, instead of releasing it")
    } else {
        check(firstResponse.failure?.code == .consentDenied
                && secondResponse.values?[alphaReference] == Data("synthetic-alpha".utf8)
                && restores == 1 && others == 1 && refusals.isEmpty,
              "\(label): a Deny of a different question leaves the waiting request released after the restore")
    }
}

/// The SSH twin: a connection whose delegation declines (its `csec ai` was
/// never registered) has its SSH panel on screen; a delegated connection for
/// the same key, server and user, offered the same default scope (the Claude
/// Code session), waits on the restore panel for its cold key. The human
/// denies the first panel, then approves the restore: the waiting connection
/// is refused, not signed. A Deny for another remote user leaves it signed.
private func restoreDenySSH(identical: Bool) async {
    let label = "delegation restore deny SSH [\(identical ? "identical" : "other user")]"
    guard let key = try? Ed25519SSHFixture(seed: 211), let host = try? Ed25519SSHFixture(seed: 223) else {
        check(false, "\(label): key fixtures build")
        return
    }
    let session = Data(repeating: 0x55, count: 32)
    guard let binding = try? SSHDestinationBinding(
        hostKeyBlob: host.publicKeyBlob, sessionIdentifier: session,
        signature: host.signatureBlob(for: session), isForwarding: false
    ) else {
        check(false, "\(label): the binding builds")
        return
    }
    let keyReference = "csec://ssh-delegation/key"
    let metadata = SSHKeyMetadata(
        reference: keyReference, fingerprint: sshFingerprint(key.publicKeyBlob),
        algorithm: "ssh-ed25519", publicKeyBlob: key.publicKeyBlob, label: "delegation key"
    )
    let use = PairedSSHUse(keyFingerprint: metadata.fingerprint, hostKeyFingerprint: binding.hostKeyFingerprint, remoteUser: "git")
    // Two `csec ai … → zsh -lc → git → ssh` chains under the one session: the
    // denied one's program ("git fetch") is not registered, the waiting one's
    // ("git push") is.
    func chain(_ tree: inout DelegationTree, base: pid_t, program: String) -> pid_t {
        tree.command(base, shell: base + 1, agent: Standard.agent, program: program)
        tree.processes[base + 3] = SyntheticClaudeSessionFacts.Process(
            startTime: UInt64(base + 3) * 10, parent: base, executablePath: "/bin/zsh", argv: ["/bin/zsh", "-lc", program]
        )
        tree.names[base + 3] = "zsh"
        tree.processes[base + 2] = SyntheticClaudeSessionFacts.Process(
            startTime: UInt64(base + 2) * 10, parent: base + 3, executablePath: "/usr/bin/git",
            argv: program.split(separator: " ").map(String.init)
        )
        tree.names[base + 2] = "git"
        let ssh = base + 4
        tree.processes[ssh] = SyntheticClaudeSessionFacts.Process(
            startTime: UInt64(ssh) * 10, parent: base + 2, executablePath: "/usr/bin/ssh", argv: ["ssh", "git@github.com"]
        )
        tree.names[ssh] = "ssh"
        return ssh
    }
    var tree = DelegationTree()
    tree.terminal(Standard.fish)
    tree.session(Standard.agent, parent: Standard.fish)
    tree.hook(Standard.hookPeer, shell: Standard.hookShell, agent: Standard.agent)
    let deniedSSH = chain(&tree, base: 63_600, program: "git fetch")
    let waitingSSH = chain(&tree, base: 63_610, program: "git push")
    let (facts, inspection) = tree.build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    await seedPairings(stores, [pairing(references: [], ssh: [use])])
    let service = makeService(facts, stores: stores)
    _ = await register(service, "git push", peer: Standard.hookPeer)
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(ColdUntilWarmedProvider(values: [keyReference: key.privateKeyPEM], held: []))
    let consent = DelegationSheetConsent()
    let reviewer = DenyFirstPanelReview()
    let queued = QueuedPolicyReview(underlying: reviewer, queue: ConsentQueue())
    let restore = GrantRestoration(resolver: resolver, policyReview: queued, consent: consent, terminalInspection: .unavailable)
    let signing = SSHSigningService(
        resolver: resolver, catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [metadata])),
        consent: consent, policyReview: queued, allowUnverifiedCallersForTesting: true,
        processInspection: inspection, knownHostsLookup: SSHKnownHostsLookup { _ in ["github.com"] },
        terminalInspection: .unavailable, restoration: restore, delegation: service
    )
    await restore.addGrantSource(signing)
    await restore.addItemSource(DelegationRestoreSource(delegation: service, resolver: resolver, sshKeys: signing))
    func sign(from ssh: pid_t, as user: String) -> Task<Data?, Never> {
        Task {
            try? await signing.signSSHAuthentication(
                publicKeyBlob: key.publicKeyBlob,
                signedData: userAuthenticationRequest(
                    sessionIdentifier: session, remoteUser: user,
                    publicKeyBlob: key.publicKeyBlob, hostKeyBlob: host.publicKeyBlob
                ),
                flags: 0, binding: binding,
                caller: CallerInfo(pid: ssh, startTime: UInt64(ssh) * 10, description: "Apple SSH")
            )
        }
    }
    let first = sign(from: deniedSSH, as: identical ? "git" : "deploy")
    let panelUp = await eventuallyTrue { await reviewer.isHolding }
    let second = sign(from: waitingSSH, as: "git")
    let joined = await eventuallyTrue { await restore.waitingCount == 1 }
    check(panelUp && joined,
          "\(label): the delegated connection waits on the restore panel queued behind the other connection's panel")
    await reviewer.denyHeld()
    let firstSignature = await first.value
    let secondSignature = await second.value
    let restores = await reviewer.restoreShown
    let others = await reviewer.otherPanels
    if identical {
        check(firstSignature == nil && secondSignature == nil && restores == 1 && others == 1,
              "\(label): a human Deny of the identical question made while it waited on the restore refuses it, "
                + "with no panel of its own, instead of signing")
    } else {
        check(firstSignature == nil && secondSignature != nil && restores == 1 && others == 1,
              "\(label): a Deny for another remote user leaves the waiting connection signed after the restore")
    }
}

// MARK: - Synthetic chains

/// One process between `ssh` (or sudo) and its `csec ai` in a synthetic chain.
private struct SSHChainTestLink {
    let pid: pid_t
    let path: String
    let argv: [String]
}

// MARK: - Pinned launchers in the pairing item

/// What a pin may hold, the pairing item's format 2 and its migration, and how
/// the pins an earlier csecd wrote are listed and revoked. Nothing adds a pin
/// since csec-0.11.
private func delegationLauncherStorageTests() async {
    let digest = String(repeating: "a", count: 64)
    let other = String(repeating: "b", count: 64)
    for (path, valid) in [
        ("bin/x", true), ("x.sh", true), (".envrc", true), ("/bin/x", false), ("", false), ("a/../b", false),
        ("./x", false), ("a//b", false), ("a/", false), (".git/hooks/pre-push", false), ("sub/.git/x", false),
        (String(repeating: "x", count: 1_025), false), ("a\u{0}b", false),
    ] {
        check(PinnedFile.isCheckoutRelativePath(path) == valid,
              "launcher pin: \(path.prefix(24)) is \(valid ? "" : "not ")a checkout-relative path")
    }
    let good = PinnedLauncher(path: "bin/push", digest: digest, sources: [
        PinnedFile(path: "bin/_common.sh", digest: other), PinnedFile(path: ".envrc", digest: nil),
    ])
    check(good.isWellFormed, "launcher pin: a script with a sourced file and an absent one is well formed")
    for (label, launcher) in [
        ("an uppercase digest", PinnedLauncher(path: "bin/x", digest: digest.uppercased(), sources: [])),
        ("a short digest", PinnedLauncher(path: "bin/x", digest: "abc", sources: [])),
        ("a duplicate source", PinnedLauncher(path: "bin/x", digest: digest, sources: [
            PinnedFile(path: "a", digest: digest), PinnedFile(path: "a", digest: other),
        ])),
        ("itself as a source", PinnedLauncher(path: "bin/x", digest: digest, sources: [PinnedFile(path: "bin/x", digest: digest)])),
        ("sixteen sources", PinnedLauncher(path: "bin/x", digest: digest, sources: (0..<16).map {
            PinnedFile(path: "lib/\($0)", digest: digest)
        })),
    ] {
        check(!launcher.isWellFormed, "launcher pin: \(label) is not well formed")
    }
    let use = PairedSSHUse(keyFingerprint: "SHA256:key", hostKeyFingerprint: "SHA256:host", remoteUser: "git")
    let manyLaunchers = (0..<65).map { PinnedLauncher(path: "bin/\($0)", digest: digest, sources: []) }
    check(!ProjectPairing(project: projectKey(), references: [], ssh: [use], launchers: manyLaunchers).isWellFormed,
          "launcher pin: a project holds at most 64 launchers")
    check(!ProjectPairing(project: projectKey(), references: [], ssh: [use], launchers: [good, good]).isWellFormed,
          "launcher pin: a project pins a path once")
    check(ProjectPairing(project: projectKey(), references: [], ssh: [], launchers: [good]).isEmpty,
          "launcher pin: pins alone do not keep a pairing")

    // Format 1 items migrate with no launchers; format 2 round-trips them.
    let pairingID = "00000000-0000-4000-8000-000000000001"
    let legacy = #"{"document":{"projects":[{"id":"\#(pairingID)","project":{"inode":\#(alphaInode),"path":"\#(alphaPath)","volumeUUID":"\#(delegationVolume)"},"references":["\#(alphaReference)"],"ssh":[{"hostKeyFingerprint":"SHA256:host","keyFingerprint":"SHA256:key","remoteUser":"git"}]}]},"formatVersion":1}"#
    let backend = InMemoryProtectedItemBackend()
    await backend.setRawBytes(Data(legacy.utf8), for: .pairing)
    let migrated = await ProtectedStores.processLocal(backend).store(for: PairingDocument.self).load()
    check(migrated == .document(PairingDocument(projects: [
        ProjectPairing(id: pairingID, project: projectKey(), references: [alphaReference], ssh: [use], launchers: []),
    ])), "launcher pin: a format 1 pairing item migrates with no launchers")
    let roundTrip = ProtectedStores.processLocal()
    let document = PairingDocument(projects: [
        ProjectPairing(project: projectKey(), references: [], ssh: [use], launchers: [good]),
    ])
    _ = try? await roundTrip.store(for: PairingDocument.self).prepare(document).commit()
    check(await roundTrip.store(for: PairingDocument.self).load() == .document(document),
          "launcher pin: format 2 keeps launchers across a restart")

    // Pins an earlier csecd wrote: listed by path, kept when an SSH use is
    // unpaired, removed with the pairing.
    let (facts, _) = Standard.tree().build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    let second = PairedSSHUse(keyFingerprint: "SHA256:key", hostKeyFingerprint: "SHA256:other", remoteUser: "root")
    var earlier = pairing(references: [], ssh: [use, second])
    earlier.launchers = [good]
    await seedPairings(stores, [earlier])
    let service = makeService(facts, stores: stores)
    let entries = await service.grantEntries()
    check(entries?.pairings.first?.launchers == [good],
          "launcher pin: a pin an earlier csecd wrote is listed")
    let removedUse = await service.unpair(
        references: [], ssh: [second], root: ProcessIncarnation(pid: Standard.agent, startTime: UInt64(Standard.agent) * 10)
    )
    let afterUnpair = await service.grantEntries()
    check(!removedUse.removed.isEmpty && afterUnpair?.pairings.first?.launchers == entries?.pairings.first?.launchers
            && afterUnpair?.pairings.first?.ssh.count == 1,
          "launcher pin: unpairing an SSH use keeps the project's pins")
    guard let id = afterUnpair?.pairings.first?.id, let selector = GrantIDSelector("pair-" + id) else {
        check(false, "launcher pin: the pairing's id parses")
        return
    }
    let removal = await service.remove(selector)
    let afterRevoke = await service.grantEntries()
    if case let .removed(removed) = removal {
        check(removed.first?.label.contains("1 script(s)") == true && afterRevoke?.pairings.isEmpty == true,
              "launcher pin: revoking the pairing removes its pins, and its entry counts them")
    } else {
        check(false, "launcher pin: revoking the pairing removes its pins, and its entry counts them")
    }

    // The listing's wire form carries paths only, and reads a csecd that
    // predates launchers as having none.
    let summary = ProjectPairingSummary(
        id: pairingID, projectPath: alphaPath, references: [], ssh: [],
        launchers: [LauncherPairingSummary(path: "bin/push", sources: ["bin/_common.sh"])]
    )
    let encoded = (try? JSONEncoder().encode(summary)).flatMap { String(data: $0, encoding: .utf8) } ?? ""
    check(summary.isWellFormed && encoded.contains("_common.sh") && !encoded.contains(digest),
          "launcher pin: the listing names a pin's paths, never its digests")
    let older = #"{"id":"\#(pairingID)","projectPath":"\#(alphaPath)","references":[],"ssh":[]}"#
    check((try? JSONDecoder().decode(ProjectPairingSummary.self, from: Data(older.utf8)))?.launchers == [],
          "launcher pin: a listing from a csecd that predates launchers decodes with none")
}

// MARK: - Pairing from the phone

/// The paired phone as its card behaves: it approves the review's default
/// scope (and the given lifetime, or the default), showing the pairing line
/// exactly when `pairingLineApplies` says so, and records what it was sent.
private actor CardPhone: RemoteAccessPolicyReviewProvider {
    private let durationIndex: UInt16?
    private(set) var reviews: [RemoteApprovalReview] = []

    init(durationIndex: UInt16? = nil) { self.durationIndex = durationIndex }

    nonisolated func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        .ready(unlock: .notNeeded)
    }

    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        reviews.append(review)
        let scope = review.defaultScopeID
        let duration = durationIndex ?? review.defaultDurationIndex
        return .approved(selection: RemoteApprovalSelection(
            scopeOptionID: scope, durationIndex: duration.map(Int.init), unlockAnswer: nil,
            pairingLineShown: review.pairingLineApplies(scopeID: scope, durationIndex: duration)
        ), unlock: nil)
    }
}

/// A declined Claude Code request mirrored to the phone: the frozen review
/// carries the decline note and the pairing line, and a phone approval made
/// with the line on its card pairs, through the real mirror and agent.
private func delegationPhonePairingTests() async {
    for (label, phone, pairs) in [
        ("with the line shown", CardPhone(), true),
        ("with a lifetime cap", CardPhone(durationIndex: 1), false),
    ] {
        guard let command = LiveCommand() else {
            check(false, "phone pairing: the live command starts")
            return
        }
        defer { command.stop() }
        let harness = await makeAgentHarness(
            commands: [(command, Standard.program)], pairings: [],
            policyReview: MirroredPolicyReview(local: GatedPolicyReview(), remote: phone, log: { _ in })
        )
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        guard let request = aiRequest(Standard.program) else {
            check(false, "phone pairing: the request builds")
            return
        }
        _ = await harness.agent.handle(request: request, caller: command.caller)
        let sent = await phone.reviews.last
        let stored = await storedPairings(harness.stores)
        check(sent?.delegation?.note
                == DelegationDecline.notApprovedForProject(reference: alphaReference, project: "alpha").panelText
                && sent?.delegation?.pairing?.line == "Approving also lets Claude Code auto mode use these in alpha until you revoke them",
              "phone pairing (\(label)): the phone is sent the decline note and the pairing line")
        check((stored?.first?.references == [alphaReference]) == pairs && (stored?.isEmpty == true) == !pairs,
              "phone pairing (\(label)): " + (pairs ? "the phone's approval pairs" : "nothing is paired"))
        let records = await harness.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
        check(!pairs || records.contains { $0.detail?.contains("paired 1 reference") == true && $0.decider == .humanPhone },
              "phone pairing (\(label)): a phone pairing is logged as the phone's decision")
    }
}

// MARK: - Classifier rules and setup notices

private func rulesSource(_ sourceID: String, digest: String, rules: [String]) -> ClaudeHookSource {
    ClaudeHookSource(
        kind: .classifierRules, sourceID: sourceID, event: nil, matcher: nil, digest: digest,
        display: "~/.claude/settings.json · \(rules.count) auto-mode classifier rules", fetchesUnpinnedCode: false,
        ruleDigests: rules.map { ClaudeClassifierRules.ruleDigest(section: "allow", text: $0) })
}

private func delegationClassifierRuleTests() async {
    let settingsPath = delegationHome + "/.claude/settings.json"
    let launch = ClaudeSettingsScope.launchSettingsPath

    // Copy.
    let rulesDecline = DelegationDecline.classifierRules("~/.claude/settings.json · 3 auto-mode classifier rules")
    check(rulesDecline.panelText
            == "Auto mode didn't approve this: ~/.claude/settings.json · 3 auto-mode classifier rules steer the "
                + "classifier and aren't acknowledged as they are now — review them with csec setup auto-mode."
            && rulesDecline.code == "classifier_rules",
          "classifier rules: the panel note names the source and the command that reviews it")
    let setupReasons: [DelegationDecline] = [.unverifiedBuild("2.1.257"), .allowRulesActive, .otherHook("h"), rulesDecline]
    let otherReasons: [DelegationDecline] = [
        .notApprovedForProject(reference: "r", project: "p"), .notInteractive, .launchOption("--print"),
        .settingsUnreadable("/p"), .sudoNotApproved(project: "p"),
    ]
    check(setupReasons.allSatisfy { $0.needsSetup && $0.reason.contains("csec setup auto-mode") }
            && otherReasons.allSatisfy { !$0.needsSetup && $0.setupNotice == nil },
          "setup notice: only reasons `csec setup auto-mode` fixes need setup, and their notes name it")
    let notice = rulesDecline.setupNotice ?? ""
    check(notice.hasPrefix("delegated approvals are waiting on setup")
            && notice.contains(rulesDecline.reason) && notice.hasSuffix("Ask the user to run `csec setup auto-mode` in a terminal."),
          "setup notice: it says setup is waiting, why, and what the user runs")
    check((DelegationDecline.otherHook(String(repeating: "h", count: 5_000)).setupNotice?.utf8.count ?? .max)
            <= DelegationDecline.maximumSetupNoticeBytes,
          "setup notice: it stays within its bound")

    // The gate's finding maps to a decline: a file's rules to a review, the
    // --settings layer's to the launch (setup never sees P's argv).
    let fileRules = rulesSource(settingsPath, digest: String(repeating: "1", count: 64), rules: ["a", "b"])
    let inlineRules = rulesSource(launch, digest: String(repeating: "2", count: 64), rules: ["a"])
    check(decline(await evaluateStandard(gate: FakeSettingsGate(evaluation(hooks: [fileRules]))))
            == .classifierRules(fileRules.display),
          "classifier rules: unacknowledged rules in a settings file decline for review")
    check(decline(await evaluateStandard(gate: FakeSettingsGate(evaluation(hooks: [inlineRules]))))
            == .launchOption("--settings that add auto-mode classifier rules"),
          "classifier rules: rules in --settings decline as the launch")
    check(isApproved(await evaluateStandard(
        acknowledged: [AcknowledgedClaudeHook(digest: fileRules.digest, display: fileRules.display, acknowledgedAt: Date())],
        gate: FakeSettingsGate(evaluation(hooks: [fileRules])))),
          "classifier rules: rules acknowledged as they are delegate")

    // The notice waits for the `csec ai` the request ran under, once.
    do {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let service = makeService(facts, stores: stores, gate: FakeSettingsGate(evaluation(hooks: [fileRules])))
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        let command = CallerInfo(pid: Standard.command, startTime: UInt64(Standard.command) * 10, description: "csec ai")
        let other = CallerInfo(pid: Standard.shell, startTime: UInt64(Standard.shell) * 10, description: "shell")
        let declined = decline(await evaluate(service, command: Standard.command, program: Standard.program))
        let otherTake = await service.takeSetupNotice(for: other)
        let taken = await service.takeSetupNotice(for: command)
        let again = await service.takeSetupNotice(for: command)
        check(declined == .classifierRules(fileRules.display) && otherTake == nil
                && taken == declined?.setupNotice && taken != nil && again == nil,
              "setup notice: a setup decline leaves its notice for that csec ai alone, taken once")
    }
    do {
        let (facts, _) = Standard.tree().build()
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        let service = makeService(facts, stores: stores)
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        let command = CallerInfo(pid: Standard.command, startTime: UInt64(Standard.command) * 10, description: "csec ai")
        let declined = decline(await evaluate(service, command: Standard.command, program: Standard.program))
        let taken = await service.takeSetupNotice(for: command)
        check(declined?.needsSetup == false && declined != nil && taken == nil,
              "setup notice: a decline setup cannot fix (an unpaired project) leaves none")
    }

    // Acknowledging: the sheet names the rules, the document keeps their
    // digests, and a source's new rules replace its old ones.
    do {
        let (facts, _) = Standard.tree().build()
        let caller = CallerInfo(pid: getpid(), startTime: ProcessAncestry.startTime(of: getpid()) ?? 1, description: "csec setup")
        let stores = ProtectedStores.processLocal()
        await enableDelegation(stores)
        let hook = hookSource("cc-caffeine@samber · PreToolUse *", digest: String(repeating: "d", count: 64))
        let gate = FakeSettingsGate(evaluation(hooks: [hook, fileRules]))
        let consent = DelegationSheetConsent()
        let service = makeService(facts, stores: stores, gate: gate, consent: consent)
        let first = await service.configure(
            .acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: nil)
        let stored = await storedSettings(stores)?.acknowledgedHooks ?? []
        check(consent.reasons.last?.contains("\(fileRules.display), which steer the auto-mode classifier") == true
                && consent.reasons.last?.contains("cc-caffeine@samber · PreToolUse *, which can approve") == true,
              "classifier rules: the acknowledgement sheet names the rules apart from the hooks")
        check(stored.map(\.digest) == [hook.digest, fileRules.digest]
                && stored.last?.classifierRules == AcknowledgedClassifierRules(sourceID: settingsPath, ruleDigests: fileRules.ruleDigests ?? [])
                && stored.first?.classifierRules == nil
                && first.delegationStatus?.acknowledgedHooks.last?.classifierRules?.ruleDigests == fileRules.ruleDigests,
              "classifier rules: an acknowledgement stores the source and its rule digests, and the status returns them")
        let changed = rulesSource(settingsPath, digest: String(repeating: "3", count: 64), rules: ["a", "b", "c"])
        gate.set(evaluation(hooks: [hook, changed]))
        _ = await service.configure(
            .acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: nil)
        let replaced = await storedSettings(stores)?.acknowledgedHooks ?? []
        check(replaced.map(\.digest) == [hook.digest, changed.digest]
                && replaced.last?.classifierRules?.ruleDigests == changed.ruleDigests,
              "classifier rules: acknowledging a source's changed rules replaces its earlier acknowledgement")
        let listing = await service.grantEntries()
        check(listing?.hooks.count == 2, "classifier rules: csec grants lists acknowledged rules beside hooks")
    }

    // The document: bounds, and format 1 items read as format 2.
    let digests = (0..<ClaudeClassifierRules.maximumRulesPerSource).map {
        ClaudeClassifierRules.ruleDigest(section: "allow", text: "rule \($0)")
    }
    let entries = (0..<5).map { index in
        AcknowledgedClaudeHook(
            digest: String(format: "%064x", index), display: "source \(index)", acknowledgedAt: Date(),
            classifierRules: AcknowledgedClassifierRules(sourceID: "/s/\(index)/settings.json", ruleDigests: digests))
    }
    check(!DelegationSettingsDocument(acknowledgedHooks: entries).isWellFormed,
          "delegation settings: rule digests past the document's bound are not well formed")
    let bounded = DelegationSettingsDocument.bounded(entries)
    check(DelegationSettingsDocument(acknowledgedHooks: bounded).isWellFormed
            && bounded.map(\.digest) == entries.map(\.digest)
            && bounded.first?.classifierRules?.ruleDigests.isEmpty == true
            && bounded.last?.classifierRules?.ruleDigests == digests,
          "delegation settings: past the bound the oldest sources lose their rule digests, never their acknowledgement")
    // A full document — every hook slot, long displays, sixteen rule
    // sources with long paths and every rule digest — still fits the item.
    let display = String(repeating: "x", count: AcknowledgedHookSummary.maximumDisplayBytes)
    let full = DelegationSettingsDocument.bounded((0..<DelegationPolicy.maximumAcknowledgedHooks).map { index in
        AcknowledgedClaudeHook(
            digest: String(format: "%064x", index + 100), display: display, acknowledgedAt: Date(),
            classifierRules: index < 16 ? AcknowledgedClassifierRules(
                sourceID: "/" + String(repeating: "p", count: 1_000) + "/\(index)/settings.json",
                ruleDigests: Array(digests.prefix(DelegationPolicy.maximumAcknowledgedRuleDigests / 16))) : nil)
    })
    let fullStores = ProtectedStores.processLocal()
    let fullWritten = (try? await fullStores.store(for: DelegationSettingsDocument.self)
        .prepare(DelegationSettingsDocument(acknowledgedHooks: full)).commit()) != nil
    let readBack = await storedSettings(fullStores)
    check(fullWritten && readBack?.acknowledgedHooks == full,
          "delegation settings: a document at its bounds fits the item and reads back")
    check(!AcknowledgedClassifierRules(sourceID: settingsPath, ruleDigests: ["ABC"]).isWellFormed
            && !AcknowledgedClassifierRules(sourceID: settingsPath, ruleDigests: digests + digests).isWellFormed,
          "delegation settings: a rule digest is 32 lowercase hex, at most 512 per source")
    do {
        let hookDigest = String(repeating: "d", count: 64)
        let legacy = #"{"document":{"acknowledgedHooks":[{"acknowledgedAt":0,"digest":"\#(hookDigest)","display":"tee hook"}],"clients":["claude"],"consentedPolicyVersion":2,"setClassifyAllShell":false,"trustedBuilds":[]},"formatVersion":1}"#
        let backend = InMemoryProtectedItemBackend()
        await backend.setRawBytes(Data(legacy.utf8), for: .delegationSettings)
        let migrated = await ProtectedStores.processLocal(backend).store(for: DelegationSettingsDocument.self).load()
        if case let .document(document) = migrated {
            check(document.acknowledgedDigests == [hookDigest] && document.acknowledgedHooks.first?.classifierRules == nil
                    && document.consentedPolicyVersion == 2,
                  "delegation settings: a format 1 item migrates with its hooks and no classifier rules")
        } else {
            check(false, "delegation settings: a format 1 item migrates with its hooks and no classifier rules")
        }
    }
}

// MARK: - An account config dir linked to ~/.claude

/// The live file system with `/synthetic` mapped onto a temporary directory,
/// which is also visible under its own path, and nothing else, so the real
/// settings gate reads a fixture under the service's synthetic home and never
/// this Mac's files.
private struct SyntheticRootFiles: ClaudeSettingsFileAccess {
    let root: String
    private let live = LiveClaudeSettingsFileAccess()

    init(root: String) { self.root = root }

    func real(_ path: String) -> String? {
        if path == root || path.hasPrefix(root + "/") { return path }
        return path == "/synthetic" || path.hasPrefix("/synthetic/") ? root + path.dropFirst("/synthetic".count) : nil
    }

    func status(of path: String) -> ClaudeSettingsPathStatus { real(path).map(live.status(of:)) ?? .missing }

    func contents(of path: String, maximumBytes: Int) -> ClaudeSettingsFileContents {
        real(path).map { live.contents(of: $0, maximumBytes: maximumBytes) } ?? .missing
    }

    func entries(of directory: String, maximumCount: Int) -> ClaudeSettingsDirectoryListing {
        real(directory).map { live.entries(of: $0, maximumCount: maximumCount) } ?? .missing
    }
}

/// csecd with the real gate: a hook and classifier rules acknowledged in a
/// default session delegate in an account session whose settings.json links
/// to ~/.claude's, with no further sheet; a change acknowledged from the
/// account replaces the one record.
private func delegationSharedAccountTests() async {
    let root = (NSTemporaryDirectory() as NSString)
        .appendingPathComponent("csec-delegation-shared-\(UUID().uuidString.prefix(8))")
    defer { try? FileManager.default.removeItem(atPath: root) }
    try? FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
    let files = SyntheticRootFiles(root: (root as NSString).resolvingSymlinksInPath)
    // A real directory: csecd checks that CLAUDE_CONFIG_DIR is one this user owns.
    let account = files.root + "/accounts/second"
    let settingsPath = delegationHome + "/.claude/settings.json"
    func write(rule: String) {
        let object: [String: Any] = [
            "autoMode": ["classifyAllShell": true, "allow": [rule]],
            "hooks": ["PreToolUse": [["matcher": "Bash", "hooks": [["type": "command", "command": "/bin/approver"]]]]],
        ]
        let url = URL(fileURLWithPath: files.real(settingsPath)!)
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? JSONSerialization.data(withJSONObject: object).write(to: url)
    }
    write(rule: "builds may run")
    try? FileManager.default.createDirectory(atPath: files.real(account)!, withIntermediateDirectories: true)
    _ = symlink(files.real(settingsPath)!, files.real(account + "/settings.json")!)

    let gate = makeClaudeSettingsGate(fileAccess: files)
    // One csecd, two Claude Code sessions: Standard's default one, and an
    // account session beside it with its own command and hook.
    let accountAgent: pid_t = 62_010, accountShell: pid_t = 62_011, accountCommand: pid_t = 62_012
    let accountHookShell: pid_t = 62_013, accountHookPeer: pid_t = 62_014
    let (facts, _) = Standard.tree { tree in
        tree.session(accountAgent, parent: Standard.fish, environment: [
            .init(name: "HOME", value: delegationHome), .init(name: "CLAUDE_CONFIG_DIR", value: account)])
        tree.command(accountCommand, shell: accountShell, agent: accountAgent, program: Standard.program)
        tree.hook(accountHookPeer, shell: accountHookShell, agent: accountAgent)
    }.build()
    let stores = ProtectedStores.processLocal()
    await enableDelegation(stores)
    await seedPairings(stores, [pairing()])
    let consent = DelegationSheetConsent()
    let caller = CallerInfo(pid: getpid(), startTime: ProcessAncestry.startTime(of: getpid()) ?? 1, description: "csec setup")
    let service = makeService(facts, stores: stores, gate: gate, consent: consent)
    func requestFromAccount() async -> DelegationEvaluation {
        _ = await register(service, Standard.program, peer: accountHookPeer)
        return await evaluate(service, command: accountCommand, program: Standard.program)
    }
    func requestFromDefault() async -> DelegationEvaluation {
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        return await evaluate(service, command: Standard.command, program: Standard.program)
    }

    let before = decline(await requestFromAccount())
    check(before == .classifierRules("~/.claude/settings.json · 1 auto-mode classifier rule"),
          "shared account: unacknowledged ~/.claude settings decline in an account session too, named as ~/.claude's")
    let fromDefault = await service.configure(
        .acknowledgeHooks(claudeConfigDirectory: nil, projectDirectory: alphaPath), caller: caller, terminal: nil)
    let sheets = consent.reasons.count
    let acknowledged = await storedSettings(stores)?.acknowledgedHooks ?? []
    check(fromDefault.failure == nil && sheets == 1 && acknowledged.count == 2 && consent.reasons.first?.contains("~/.claude/settings.json") == true,
          "shared account: a default session acknowledges ~/.claude's hook and rules with one sheet")
    let accountApproved = await requestFromAccount()
    let defaultApproved = await requestFromDefault()
    check(isApproved(accountApproved) && isApproved(defaultApproved),
          "shared account: the account session delegates on the default session's acknowledgement")
    let unchanged = await service.configure(
        .acknowledgeHooks(claudeConfigDirectory: account, projectDirectory: alphaPath), caller: caller, terminal: nil)
    check(unchanged.failure == nil && consent.reasons.count == sheets, "shared account: acknowledging from the account finds nothing new, no sheet")

    write(rule: "deploys may run")
    let accountChanged = decline(await requestFromAccount())
    let defaultChanged = decline(await requestFromDefault())
    check(accountChanged == .classifierRules("~/.claude/settings.json · 1 auto-mode classifier rule")
            && defaultChanged == accountChanged,
          "shared account: a rule change declines in both sessions, for the same source")
    let changed = await service.configure(
        .acknowledgeHooks(claudeConfigDirectory: account, projectDirectory: alphaPath), caller: caller, terminal: nil)
    let rules = (await storedSettings(stores)?.acknowledgedHooks ?? []).compactMap(\.classifierRules)
    let defaultAfter = isApproved(await requestFromDefault())
    let accountAfter = isApproved(await requestFromAccount())
    check(changed.failure == nil && consent.reasons.count == sheets + 1 && consent.reasons.last?.contains("~/.claude/settings.json") == true
            && rules.map(\.sourceID) == [settingsPath] && defaultAfter && accountAfter,
          "shared account: the change acknowledged from the account replaces ~/.claude's one rules record, for "
            + "both sessions")
}

// MARK: - The rules-changed panel (csec-0.64)

/// The rules-changed panel as csecd's settings consent shows it: records each
/// panel, and answers approve, the human's Deny, or the panel going with its
/// requester. `hold` keeps the next panel up until `release()`.
final class RulesPanelConsent: ConsentProvider, @unchecked Sendable {
    enum Answer { case approve, deny, requesterGone }

    private let lock = NSLock()
    private var answers: [Answer]
    private var shown: [SettingsChangeReviewDetails] = []
    private var held: CheckedContinuation<Void, Never>?
    private var holding: Bool
    /// Whether the paired phone could decide a change csecd offers it:
    /// `reachAnswers` in the order the questions are answered, then
    /// `phoneReady`.
    private let phoneReady: Bool
    private var reachAnswers: [Bool]
    private var reachAsked: [SettingsChangeReviewDetails] = []
    /// The first question waits for `releaseReach()`.
    private var holdingReach: Bool
    private var heldReach: CheckedContinuation<Void, Never>?
    /// Where each answer is given: `.phone` answers as the paired phone.
    private let decidedOn: HumanDecisionSurface?

    init(
        _ answers: [Answer], hold: Bool = false, phoneReady: Bool = false, reachAnswers: [Bool] = [],
        holdFirstReach: Bool = false, decidedOn: HumanDecisionSurface? = nil
    ) {
        self.answers = answers
        self.holding = hold
        self.phoneReady = phoneReady
        self.reachAnswers = reachAnswers
        self.holdingReach = holdFirstReach
        self.decidedOn = decidedOn
    }

    func decideSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> SettingsChangeDecision {
        let answer = await authenticateSettingsChange(change, caller: caller, reason: reason)
        if decidedOn == .phone, var refusal = answer.refusal {
            refusal.onPhone = true
            return SettingsChangeDecision(answer: .refused(refusal))
        }
        return SettingsChangeDecision(answer: answer, decidedOn: decidedOn)
    }

    var reachQuestions: [SettingsChangeReviewDetails] { lock.withLock { reachAsked } }

    func settingsChangeReachesPhone(_ change: SettingsChangeReviewDetails, caller: CallerInfo) async -> Bool {
        let hold = lock.withLock { () -> Bool in
            reachAsked.append(change)
            return holdingReach && reachAsked.count == 1
        }
        if hold {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let resumeNow = lock.withLock { () -> Bool in
                    guard holdingReach else { return true }
                    heldReach = continuation
                    return false
                }
                if resumeNow { continuation.resume() }
            }
        }
        return lock.withLock { reachAnswers.isEmpty ? phoneReady : reachAnswers.removeFirst() }
    }

    func releaseReach() {
        let waiting: CheckedContinuation<Void, Never>? = lock.withLock {
            holdingReach = false
            defer { heldReach = nil }
            return heldReach
        }
        waiting?.resume()
    }

    var panels: [SettingsChangeReviewDetails] { lock.withLock { shown } }

    func release() {
        let waiting: CheckedContinuation<Void, Never>? = lock.withLock {
            holding = false
            defer { held = nil }
            return held
        }
        waiting?.resume()
    }

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .approved(unlock: CacheUnlock(LAContext()))
    }

    func authenticate(reason: String) async -> ConsentOutcome { .denied }

    func authenticateSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> ConsentAnswer {
        let hold = lock.withLock { () -> Bool in
            shown.append(change)
            return holding
        }
        if hold {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let resumeNow = lock.withLock { () -> Bool in
                    guard holding else { return true }
                    held = continuation
                    return false
                }
                if resumeNow { continuation.resume() }
            }
        }
        let answer = lock.withLock { answers.isEmpty ? Answer.approve : answers.removeFirst() }
        switch answer {
        case .approve: return .approved(unlock: nil)
        case .deny: return .refused(ConsentRefusal(cause: .userCancel, onPanel: true))
        case .requesterGone: return .refused(ConsentRefusal(cause: .requesterGone, onPanel: true))
        }
    }
}

private func rulesSource(_ sourceID: String, digest: String, rules: [ClaudeClassifierRules.Rule]) -> ClaudeHookSource {
    ClaudeHookSource(
        kind: .classifierRules, sourceID: sourceID, event: nil, matcher: nil, digest: digest,
        display: "~/.claude/settings.json · \(rules.count) auto-mode classifier rules", fetchesUnpinnedCode: false,
        ruleDigests: rules.map(\.digest), rules: rules, shownWhole: true)
}

private func delegationChangedRulesTests() async {
    let settingsPath = delegationHome + "/.claude/settings.json"
    let a = ClaudeClassifierRules.Rule(section: "allow", text: "Routine PR merges are allowed")
    let b = ClaudeClassifierRules.Rule(section: "allow", text: "csec exec is fine")
    let c = ClaudeClassifierRules.Rule(section: "environment", text: "Org-specific CLIs: dv, av")
    let keep = ClaudeClassifierRules.Rule(section: "soft_deny", text: ClaudeClassifierRules.defaultsMarker)
    let before = AcknowledgedClaudeHook(
        digest: String(repeating: "1", count: 64), display: "~/.claude/settings.json · 3 auto-mode classifier rules",
        acknowledgedAt: Date(),
        classifierRules: AcknowledgedClassifierRules(sourceID: settingsPath, ruleDigests: [a, b, keep].map(\.digest)))

    // What the panel lists: the source, each rule added since the last
    // acknowledgement, a lost "$defaults", and how many are gone.
    let changed = rulesSource(settingsPath, digest: String(repeating: "2", count: 64), rules: [a, c])
    let review = ClaudeDelegationService.changedRulesReview([changed], acknowledged: [before])
    check(review.title == "Claude Code's Auto-Mode Rules Changed"
            && review.changes == [
                "~/.claude/settings.json · 2 auto-mode classifier rules",
                "Added to environment: \u{201C}Org-specific CLIs: dv, av\u{201D}",
                "soft_deny no longer keeps Claude Code's built-in soft_deny rules",
                "1 rule you acknowledged is gone",
            ]
            && review.footnote == ClaudeDelegationService.changedRulesFootnote,
          "rules panel: it lists the source, the added rule, the lost $defaults and the removed count")
    let many = (0..<9).map { ClaudeClassifierRules.Rule(section: "allow", text: "rule \($0)") }
    let crowded = ClaudeDelegationService.changedRulesReview(
        [rulesSource(settingsPath, digest: String(repeating: "3", count: 64), rules: many)], acknowledged: [])
    check(crowded.changes.count == SettingsChangeReviewDetails.maximumChanges
            && crowded.changes.first?.hasSuffix(", none acknowledged before") == true
            && crowded.changes.last == "and 5 more added rules: csec setup auto-mode lists them all",
          "rules panel: past its line limit it says how many more and where to see them")
    let reordered = ClaudeDelegationService.changedRulesReview(
        [rulesSource(settingsPath, digest: String(repeating: "4", count: 64), rules: [b, a, keep])], acknowledged: [before])
    check(reordered.changes.last?.hasPrefix("No rule was added or removed") == true,
          "rules panel: a change with nothing added or removed says so")
    let unlisted = ClaudeHookSource(
        kind: .classifierRules, sourceID: settingsPath, event: nil, matcher: nil, digest: String(repeating: "5", count: 64),
        display: "~/.claude/settings.json · 2 auto-mode classifier rules", fetchesUnpinnedCode: false,
        ruleDigests: [a, c].map(\.digest))
    check(ClaudeDelegationService.changedRulesReview([unlisted], acknowledged: [before]).changes.last
            == "csec could not list them here: csec setup auto-mode shows them",
          "rules panel: rules it has no text for point at csec setup")
    let encoded = try? JSONEncoder().encode(changed)
    let wire = encoded.flatMap { try? JSONDecoder().decode(ClaudeHookSource.self, from: $0) }
    let wireObject = encoded.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    check(wire == changed && wire?.rules == nil && wireObject != nil && wireObject?["rules"] == nil
            && wire?.shownWhole == false && wireObject?["shownWhole"] == nil,
          "rules panel: rule texts never go on the wire, and a decoded source still equals csecd's")

    let gate = { FakeSettingsGate(evaluation(hooks: [changed])) }

    // Approved: one panel, then the request delegates with no panel of its
    // own, and the acknowledgement holds exactly the listed rules.
    if let command = LiveCommand(), let request = aiRequest(Standard.program) {
        defer { command.stop() }
        let consent = RulesPanelConsent([.approve])
        let harness = await makeAgentHarness(commands: [(command, Standard.program)], gate: gate(), serviceConsent: consent)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        let released = await harness.agent.handle(request: request, caller: command.caller)
        let secretPanels = await harness.review.count
        let stored = await storedSettings(harness.stores)?.acknowledgedHooks ?? []
        let records = await harness.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
        check(released.values?[alphaReference] != nil && secretPanels == 0 && consent.panels.count == 1
                && consent.panels.first?.title == "Claude Code's Auto-Mode Rules Changed"
                && stored.contains { $0.digest == changed.digest && $0.classifierRules?.ruleDigests == changed.ruleDigests }
                && records.contains { $0.detail?.hasSuffix("from the rules-changed panel") == true && $0.decider == .humanLocal },
              "rules panel: approving it acknowledges the rules and the request goes through with no secret panel")
    } else {
        check(false, "rules panel: approving it acknowledges the rules and the request goes through with no secret panel")
    }

    // Denied: the request gets its own panel with the note, and the same
    // rules are not offered again this run.
    if let first = LiveCommand(), let second = LiveCommand(), let request = aiRequest(Standard.program) {
        defer { first.stop(); second.stop() }
        let consent = RulesPanelConsent([.deny])
        let harness = await makeAgentHarness(
            commands: [(first, Standard.program), (second, Standard.program)], gate: gate(), serviceConsent: consent)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        _ = await harness.agent.handle(request: request, caller: first.caller)
        let firstNote = await harness.review.last?.delegationNote
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        _ = await harness.agent.handle(request: request, caller: second.caller)
        let secretPanels = await harness.review.count
        let stored = await storedSettings(harness.stores)?.acknowledgedHooks ?? []
        check(consent.panels.count == 1 && secretPanels == 2 && firstNote == .classifierRules(changed.display)
                && !stored.contains { $0.digest == changed.digest },
              "rules panel: after a Deny each request gets its own panel, and the rules are not offered again")
    } else {
        check(false, "rules panel: after a Deny each request gets its own panel, and the rules are not offered again")
    }

    // The panel went with its requester: the next request offers it again.
    if let first = LiveCommand(), let second = LiveCommand(), let request = aiRequest(Standard.program) {
        defer { first.stop(); second.stop() }
        let consent = RulesPanelConsent([.requesterGone, .approve])
        let harness = await makeAgentHarness(
            commands: [(first, Standard.program), (second, Standard.program)], gate: gate(), serviceConsent: consent)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        _ = await harness.agent.handle(request: request, caller: first.caller)
        let panelsAfterFirst = await harness.review.count
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        let released = await harness.agent.handle(request: request, caller: second.caller)
        let secretPanels = await harness.review.count
        check(consent.panels.count == 2 && panelsAfterFirst == 1 && secretPanels == 1
                && released.values?[alphaReference] != nil,
              "rules panel: one that went with its requester is offered again to the next request")
    } else {
        check(false, "rules panel: one that went with its requester is offered again to the next request")
    }

    // A locked screen: the request's own panel, which the phone mirrors.
    if let command = LiveCommand(), let request = aiRequest(Standard.program) {
        defer { command.stop() }
        let consent = RulesPanelConsent([.approve])
        let harness = await makeAgentHarness(
            commands: [(command, Standard.program)], gate: gate(), serviceConsent: consent, screenLocked: true)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        _ = await harness.agent.handle(request: request, caller: command.caller)
        let secretPanels = await harness.review.count
        check(consent.panels.isEmpty && secretPanels == 1,
              "rules panel: not offered while the screen is locked; the request gets its own panel")
    } else {
        check(false, "rules panel: not offered while the screen is locked; the request gets its own panel")
    }

    // A locked screen with a paired phone that can decide it: offered, so
    // the phone can acknowledge the rules once (av-rcqg), and the request
    // goes through with no panel of its own.
    if let command = LiveCommand(), let request = aiRequest(Standard.program) {
        defer { command.stop() }
        let consent = RulesPanelConsent([.approve], phoneReady: true)
        let harness = await makeAgentHarness(
            commands: [(command, Standard.program)], gate: gate(), serviceConsent: consent, screenLocked: true)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        let earlier = Set((await storedSettings(harness.stores)?.acknowledgedHooks ?? []).map(\.digest))
        let released = await harness.agent.handle(request: request, caller: command.caller)
        let secretPanels = await harness.review.count
        let stored = await storedSettings(harness.stores)?.acknowledgedHooks ?? []
        check(consent.reachQuestions.count == 1 && consent.panels.count == 1 && secretPanels == 0
                && released.values?[alphaReference] != nil && stored.contains { $0.digest == changed.digest },
              "rules panel: while the screen is locked it is offered when the phone can decide it, and its "
                + "approval acknowledges the rules")
        let recorded = Set(stored.map(\.digest)).subtracting(earlier)
        check(!recorded.isEmpty && consent.panels.first?.phoneOperationDigest
                == ClaudeDelegationService.acknowledgementDigest(digests: recorded),
              "rules panel: what the phone signs over is exactly what the acknowledgement records")
    } else {
        check(false, "rules panel: while the screen is locked it is offered when the phone can decide it, and its "
                + "approval acknowledges the rules")
    }

    // Judged ready, then held behind another request's panel that went with
    // its requester: by the time it could be offered the phone may be gone,
    // so it is judged again, and the request gets its own panel.
    if let waiting = LiveCommand(), let other = LiveCommand(), let request = aiRequest(Standard.program) {
        defer { waiting.stop(); other.stop() }
        let consent = RulesPanelConsent(
            [.requesterGone], hold: true, reachAnswers: [true, true, false], holdFirstReach: true)
        let harness = await makeAgentHarness(
            commands: [(waiting, Standard.program), (other, Standard.program)], gate: gate(), serviceConsent: consent,
            screenLocked: true)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        let first = Task { await harness.agent.handle(request: request, caller: waiting.caller) }
        let judging = await eventuallyTrue { consent.reachQuestions.count == 1 }
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        let second = Task { await harness.agent.handle(request: request, caller: other.caller) }
        let otherPanel = await eventuallyTrue { consent.panels.count == 1 }
        consent.releaseReach()
        // Nothing outside the service shows the first request waiting on the
        // other panel; it does as soon as it runs again, with nothing to
        // await on the way.
        try? await Task.sleep(nanoseconds: 1_000_000_000)
        consent.release()
        _ = await first.value
        _ = await second.value
        // Both go to their own approval; its Deny answers the identical
        // request waiting beside it too (the Deny ledger), so one may serve.
        let secretPanels = await harness.review.count
        check(judging && otherPanel && consent.reachQuestions.count == 3 && consent.panels.count == 1
                && secretPanels >= 1,
              "rules panel: one held behind another panel is judged again before it is offered on a locked screen "
                + "(\(consent.reachQuestions.count) questions, \(consent.panels.count) panels, \(secretPanels) own)")
    } else {
        check(false, "rules panel: one held behind another panel is judged again before it is offered on a locked "
                + "screen")
    }

    // Decided on the phone: the decision log says so, for an approval and
    // for a Deny.
    for (answer, label) in [(RulesPanelConsent.Answer.approve, "approval"), (.deny, "Deny")] {
        guard let command = LiveCommand(), let request = aiRequest(Standard.program) else {
            check(false, "rules panel: a phone \(label) is logged as the human's on the phone")
            continue
        }
        defer { command.stop() }
        let consent = RulesPanelConsent([answer], phoneReady: true, decidedOn: .phone)
        let harness = await makeAgentHarness(commands: [(command, Standard.program)], gate: gate(), serviceConsent: consent)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        _ = await harness.agent.handle(request: request, caller: command.caller)
        let records = await harness.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
        let stored = await storedSettings(harness.stores)?.acknowledgedHooks ?? []
        let acknowledged = stored.contains { $0.digest == changed.digest }
        let logged = answer == .approve
            ? records.contains { $0.detail?.hasSuffix("from the rules-changed panel") == true && $0.decider == .humanPhone }
            : records.contains { $0.outcome == .denied && $0.decider == .humanPhone
                && $0.detail?.contains("you pressed Deny on the iPhone") == true }
        check(logged && acknowledged == (answer == .approve) && !records.contains { $0.decider == .humanLocal },
              "rules panel: a phone \(label) is logged as the human's on the phone (\(records.map { $0.detail ?? "" }))")
    }

    // Changed rules and a new hook together: one panel lists both, and one
    // touch acknowledges both (csec-0.64.7).
    if let command = LiveCommand(), let request = aiRequest(Standard.program) {
        defer { command.stop() }
        let consent = RulesPanelConsent([.approve])
        let hook = hookSource("cc-caffeine@samber · PreToolUse *", digest: String(repeating: "d", count: 64))
        let harness = await makeAgentHarness(
            commands: [(command, Standard.program)], gate: FakeSettingsGate(evaluation(hooks: [changed, hook])),
            serviceConsent: consent)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        let released = await harness.agent.handle(request: request, caller: command.caller)
        let secretPanels = await harness.review.count
        let stored = Set((await storedSettings(harness.stores)?.acknowledgedHooks ?? []).map(\.digest))
        check(consent.panels.count == 1 && consent.panels.first?.title == "Claude Code's Hooks and Auto-Mode Rules Changed"
                && secretPanels == 0 && released.values?[alphaReference] != nil
                && stored.isSuperset(of: [changed.digest, hook.digest]),
              "rules panel: changed rules and a new hook share one panel, and one touch acknowledges both")
    } else {
        check(false, "rules panel: changed rules and a new hook share one panel, and one touch acknowledges both")
    }

    // Requests that decline while the panel is up wait for it: one panel,
    // and both go through when it is approved.
    if let first = LiveCommand(), let second = LiveCommand(), let request = aiRequest(Standard.program) {
        defer { first.stop(); second.stop() }
        let consent = RulesPanelConsent([.approve], hold: true)
        let harness = await makeAgentHarness(
            commands: [(first, Standard.program), (second, Standard.program)], gate: gate(), serviceConsent: consent)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        async let firstReleased = harness.agent.handle(request: request, caller: first.caller)
        for _ in 0..<500 where consent.panels.isEmpty { try? await Task.sleep(for: .milliseconds(2)) }
        async let secondReleased = harness.agent.handle(request: request, caller: second.caller)
        try? await Task.sleep(for: .milliseconds(100))
        consent.release()
        let (one, two) = await (firstReleased, secondReleased)
        let secretPanels = await harness.review.count
        check(one.values?[alphaReference] != nil && two.values?[alphaReference] != nil
                && consent.panels.count == 1 && secretPanels == 0,
              "rules panel: requests that decline while it is up wait for it, and one approval serves them all")
    } else {
        check(false, "rules panel: requests that decline while it is up wait for it, and one approval serves them all")
    }
}

// MARK: - The hooks-changed panel (csec-0.64.7)

private func settingsHook(
    _ command: String, digest: String, event: String = "PreToolUse", unpinned: Bool = false,
    summaries: [String]?? = nil
) -> ClaudeHookSource {
    ClaudeHookSource(
        kind: .settings, sourceID: delegationHome + "/.claude/settings.json", event: event, matcher: "Bash",
        digest: digest, display: "~/.claude/settings.json · \(event) Bash", fetchesUnpinnedCode: unpinned,
        handlerSummaries: summaries ?? [command], shownWhole: true)
}

/// A hook added to Claude Code's settings (a pr-cap hook)
/// used to decline every request other_hook, each with its own panel, until
/// someone ran `csec setup auto-mode`. Now csecd shows it in one panel, with
/// what it runs, and one touch acknowledges it.
private func delegationChangedHooksTests() async {
    let prCap = settingsHook(
        "python3 ~/.local/share/harbor/harbor-hook.py pr-cap claude", digest: String(repeating: "e", count: 64))
    let review = ClaudeDelegationService.changedRulesReview([prCap], acknowledged: [])
    check(review.title == "New Claude Code Hook"
            && review.changes == [
                "New hook: ~/.claude/settings.json · PreToolUse Bash, which can approve shell commands",
                "Runs \u{201C}python3 ~/.local/share/harbor/harbor-hook.py pr-cap claude\u{201D}",
            ]
            && review.footnote == ClaudeDelegationService.changedHooksFootnote,
          "hooks panel: it names the new hook and what it runs")
    check(review.phoneOperationDigest == ClaudeDelegationService.acknowledgementDigest([prCap]),
          "hooks panel: a panel that lists its hooks whole may be decided on the phone, bound to exactly them")
    let unpinned = settingsHook("npx cc-caffeine caffeinate", digest: String(repeating: "f", count: 64), unpinned: true)
    let reload = settingsHook("/usr/local/bin/keep", digest: String(repeating: "a", count: 64), event: "ConfigChange")
    let unlisted = settingsHook("x", digest: String(repeating: "b", count: 64), summaries: .some(nil))
    let mixed = ClaudeDelegationService.changedRulesReview([unpinned, reload, unlisted], acknowledged: [])
    check(mixed.title == "New Claude Code Hooks"
            && mixed.changes.count == SettingsChangeReviewDetails.maximumChanges
            && mixed.changes[2].hasPrefix("It runs a package it downloads each time")
            && mixed.changes[3].hasSuffix("which can keep Claude Code from reloading its hooks")
            && mixed.changes.last == "and 1 more hook: csec setup auto-mode lists them all",
          "hooks panel: an unpinned download is warned about, a ConfigChange hook says so, and the rest are counted")
    check(mixed.phoneOperationDigest == nil,
          "hooks panel: one that leaves a hook to csec setup auto-mode stays on this Mac")
    let busy = settingsHook("a", digest: String(repeating: "c", count: 64), summaries: .some(["a", "b", "c", "d", "e"]))
    let crowded = ClaudeDelegationService.changedRulesReview([busy], acknowledged: [])
    check(crowded.changes.count == SettingsChangeReviewDetails.maximumChanges - 1 && crowded.phoneOperationDigest == nil,
          "hooks panel: one with no room for everything a hook runs stays on this Mac")
    check(ClaudeDelegationService.changedRulesReview([unlisted], acknowledged: []).changes.last
            == "csec can't show what it runs: acknowledge it only if you have reviewed it where it is defined",
          "hooks panel: a hook it cannot show the code of says so, in words that hold on either device")
    let module = ClaudeHookSource(
        kind: .plugin, sourceID: "harbor-artifact-defer@harbor", event: nil, matcher: nil,
        digest: String(repeating: "d", count: 64), display: "harbor-artifact-defer@harbor · hooks module",
        fetchesUnpinnedCode: false, moduleFiles: ["register.mjs sha256:" + String(repeating: "5", count: 64)],
        shownWhole: true)
    let modulePanel = ClaudeDelegationService.changedRulesReview([module], acknowledged: [])
    check(modulePanel.changes == [
                "New hook: harbor-artifact-defer@harbor · hooks module, which can approve shell commands",
                "Its module \u{201C}register.mjs sha256:\(String(repeating: "5", count: 64))\u{201D}",
                "csec can't show what it runs: acknowledge it only if you have reviewed it where it is defined",
            ]
            && modulePanel.phoneOperationDigest == ClaudeDelegationService.acknowledgementDigest([module]),
          "hooks panel: a hooks module is named with its file's digest, so either device can tell which file it "
            + "trusts")
    let cut = ClaudeHookSource(
        kind: prCap.kind, sourceID: prCap.sourceID, event: prCap.event, matcher: prCap.matcher, digest: prCap.digest,
        display: prCap.display, fetchesUnpinnedCode: false, handlerSummaries: prCap.handlerSummaries)
    check(ClaudeDelegationService.changedRulesReview([cut], acknowledged: []).changes == review.changes
            && ClaudeDelegationService.changedRulesReview([cut], acknowledged: []).phoneOperationDigest == nil
            && ClaudeDelegationService.changedRulesReview([prCap, cut], acknowledged: []).phoneOperationDigest == nil,
          "hooks panel: a source the gate did not show whole keeps the panel on this Mac, whatever it lists")

    let gate = { FakeSettingsGate(evaluation(hooks: [prCap])) }

    // Approved: one panel, the request delegates with no panel of its own,
    // and the acknowledgement holds exactly the hook.
    if let command = LiveCommand(), let request = aiRequest(Standard.program) {
        defer { command.stop() }
        let consent = RulesPanelConsent([.approve])
        let harness = await makeAgentHarness(commands: [(command, Standard.program)], gate: gate(), serviceConsent: consent)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        let released = await harness.agent.handle(request: request, caller: command.caller)
        let secretPanels = await harness.review.count
        let stored = await storedSettings(harness.stores)?.acknowledgedHooks ?? []
        let records = await harness.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.settings])).records
        check(released.values?[alphaReference] != nil && secretPanels == 0 && consent.panels.count == 1
                && consent.panels.first?.title == "New Claude Code Hook"
                && stored.contains { $0.digest == prCap.digest }
                && records.contains { $0.detail?.hasSuffix("from the hooks-changed panel") == true && $0.decider == .humanLocal },
              "hooks panel: approving it acknowledges the hook and the request goes through with no secret panel")
    } else {
        check(false, "hooks panel: approving it acknowledges the hook and the request goes through with no secret panel")
    }

    // Denied: each request gets its own panel with the note, and the hook is
    // not offered again this run.
    if let first = LiveCommand(), let second = LiveCommand(), let request = aiRequest(Standard.program) {
        defer { first.stop(); second.stop() }
        let consent = RulesPanelConsent([.deny])
        let harness = await makeAgentHarness(
            commands: [(first, Standard.program), (second, Standard.program)], gate: gate(), serviceConsent: consent)
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        _ = await harness.agent.handle(request: request, caller: first.caller)
        let firstNote = await harness.review.last?.delegationNote
        _ = await register(harness.service, Standard.program, peer: Standard.hookPeer)
        _ = await harness.agent.handle(request: request, caller: second.caller)
        let secretPanels = await harness.review.count
        check(consent.panels.count == 1 && secretPanels == 2 && firstNote == .otherHook(prCap.display),
              "hooks panel: after a Deny each request gets its own panel, and the hook is not offered again")
    } else {
        check(false, "hooks panel: after a Deny each request gets its own panel, and the hook is not offered again")
    }

}

/// A restarted csecd keeps the registrations already bound to a running
/// command (csec-gazp), so a long-running `csec ai` is not asked about again,
/// and only those: same boot, same P, same command, delegation still on.
private func delegationRegistrationRestartTests() async {
    // Two services over one backend model csecd restarting over its items.
    func restarted(
        bind: Bool = true, bootSession: String? = "boot-session-1",
        between: (SyntheticClaudeSessionFacts) -> Void = { _ in },
        commandStart: UInt64? = nil,
        disable: Bool = false
    ) async -> (DelegationEvaluation, InMemoryProtectedItemBackend) {
        let (facts, _) = Standard.tree().build()
        let backend = InMemoryProtectedItemBackend()
        let stores = ProtectedStores.processLocal(backend)
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        let before = makeService(facts, stores: stores)
        _ = await register(before, Standard.program, peer: Standard.hookPeer)
        if bind {
            check(isApproved(await evaluate(before, command: Standard.command, program: Standard.program)),
                  "registration restart: the first csecd releases the bound command")
        }
        if disable {
            let disabled = await before.configure(
                .disable(), caller: CallerInfo(pid: 4_242, startTime: 42_420, description: "csec setup"), terminal: nil
            )
            check(disabled.delegationStatus?.state == .off, "registration restart: delegation turned off")
            await enableDelegation(stores)
            await seedPairings(stores, [pairing()])
        }
        await before.flushPersistedRegistrations()
        between(facts)
        let after = makeService(facts, stores: .processLocal(backend), bootSession: bootSession)
        return (await evaluate(after, command: Standard.command, start: commandStart, program: Standard.program), backend)
    }

    let (kept, keptBackend) = await restarted()
    check(isApproved(kept),
          "registration restart: a command bound before the restart is released again with no panel")
    check(await keptBackend.rawBytes(for: .delegationRegistrations) != nil,
          "registration restart: the bound registration is written to delegation/registrations-v1")

    check(decline(await restarted(bind: false).0) == .notRegistered,
          "registration restart: a pending registration is not persisted, so its command declines .notRegistered")
    check(decline(await restarted(bootSession: "boot-session-2").0) == .notRegistered,
          "registration restart: a registration from another boot session is not restored")
    check(decline(await restarted(bootSession: nil).0) == .notRegistered,
          "registration restart: an unknown boot session restores nothing")
    check(decline(await restarted(between: { facts in
        facts.mutate { tree in tree[Standard.command]?.startTime = UInt64(Standard.command) * 10 + 3 }
    }, commandStart: UInt64(Standard.command) * 10 + 3).0) == .notRegistered,
          "registration restart: a command pid reused by another process is not the bound command")
    check(decline(await restarted(between: { facts in
        facts.mutate { tree in tree[Standard.agent]?.startTime = UInt64(Standard.agent) * 10 + 7 }
    }).0) == .notRegistered,
          "registration restart: a Claude Code pid reused by another process restores nothing for it")
    let (afterDisable, disabledBackend) = await restarted(disable: true)
    let leftAfterDisable = await disabledBackend.rawBytes(for: .delegationRegistrations)
    check(decline(afterDisable) == .notRegistered && leftAfterDisable == nil,
          "registration restart: turning delegation off deletes the persisted registrations")

    // A corrupt item restores nothing and is replaced by the next bind.
    do {
        let (facts, _) = Standard.tree().build()
        let backend = InMemoryProtectedItemBackend()
        let stores = ProtectedStores.processLocal(backend)
        await enableDelegation(stores)
        await seedPairings(stores, [pairing()])
        await backend.setRawBytes(Data("not json".utf8), for: .delegationRegistrations)
        let service = makeService(facts, stores: stores)
        _ = await register(service, Standard.program, peer: Standard.hookPeer)
        let released = await evaluate(service, command: Standard.command, program: Standard.program)
        await service.flushPersistedRegistrations()
        let after = makeService(facts, stores: .processLocal(backend))
        let restored = await evaluate(after, command: Standard.command, program: Standard.program)
        check(isApproved(released) && isApproved(restored),
              "registration restart: an unreadable item restores nothing and the next bind replaces it")
    }
}
