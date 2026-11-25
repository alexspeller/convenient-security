import ConvenientSecurity
import CSecuritySupport
import Foundation
import Security
#if canImport(Darwin)
import Darwin
#endif

// Kernel facts about a coding-agent process (plumbing §2.2, §2.3): job control,
// fd 0, the working directory, argv, environment-name presence, the task audit
// token, and ForeignCodeIdentity with both of its lookup paths. The live checks
// spawn real processes under a real PTY, so they re-verify every shim from this
// binary; nothing here needs Claude Code. The walk checks drive a synthetic
// tree that mutates mid-walk. Every argv and environment value is synthetic.

func claudeSessionFactsTests() {
    print("\n# Claude session facts")
    interactivityRuleTests()
    procargsLayoutTests()
    ancestryRaceTests()
    syntheticProviderContractTests()
    taskAuditTokenFallbackTests()
    liveForegroundProbeTests()
    liveWorkingDirectoryTests()
    liveOpenFileTests()
    liveOversizedArgumentBlockTests()
    liveEnvironmentProbeTests()
    liveNonInteractiveProbeTests()
    liveArgumentLayoutTests()
    liveEnvironmentEdgeTests()
    anthropicRequirementTests()
    liveClaudeOptInTests()
}

// MARK: - Synthetic provider

/// A synthetic process tree behind `ClaudeSessionFactProvider`. Every read is
/// bound to an incarnation exactly as the live provider binds it, and a hook
/// runs after each parent read so a test can change the tree mid-walk. Later
/// delegation tests in this target reuse it.
final class SyntheticClaudeSessionFacts: ClaudeSessionFactProvider, @unchecked Sendable {
    struct EnvironmentEntry: Equatable {
        let name: String
        let value: String
    }

    struct Process {
        var startTime: UInt64
        var parent: pid_t
        var executablePath: String?
        var argv: [String]?
        var job: ProcessJobFacts?
        var standardInput: ProcessFileDescriptorKind?
        var cwd: ProcessWorkingDirectory?
        /// Regular files the process holds open, by descriptor (a shell's
        /// script on fd 255).
        var openFiles: [Int32: ProcessOpenFile]
        /// Nil models an environment the kernel withheld.
        var environment: [EnvironmentEntry]?
        var identity: ForeignCodeIdentity?
        var pidVersion: Int32?
        /// The effective uid `KERN_PROC_PID` reports; nil is the test's own.
        /// A set-id root sudo is `0` with `readable: false`.
        var effectiveUID: uid_t?
        /// The CS_OPS_STATUS flags `csops` reports.
        var codeSigningFlags: UInt32?
        /// False models a process of another user, such as root's `login`
        /// above every iTerm2 and Terminal.app shell: the kernel still reports
        /// its parent (`PROC_PIDT_SHORTBSDINFO` answers any caller) but not
        /// its start time (`PROC_PIDTBSDINFO` is refused), so it has no
        /// incarnation.
        var readable: Bool

        init(
            startTime: UInt64,
            parent: pid_t,
            executablePath: String? = nil,
            argv: [String]? = nil,
            job: ProcessJobFacts? = nil,
            standardInput: ProcessFileDescriptorKind? = nil,
            cwd: ProcessWorkingDirectory? = nil,
            openFiles: [Int32: ProcessOpenFile] = [:],
            environment: [EnvironmentEntry]? = [],
            identity: ForeignCodeIdentity? = nil,
            pidVersion: Int32? = nil,
            effectiveUID: uid_t? = nil,
            codeSigningFlags: UInt32? = nil,
            readable: Bool = true
        ) {
            self.startTime = startTime
            self.parent = parent
            self.executablePath = executablePath
            self.argv = argv
            self.job = job
            self.standardInput = standardInput
            self.cwd = cwd
            self.openFiles = openFiles
            self.environment = environment
            self.identity = identity
            self.pidVersion = pidVersion
            self.effectiveUID = effectiveUID
            self.codeSigningFlags = codeSigningFlags
            self.readable = readable
        }
    }

    /// Apple's shells are `CS_RESTRICT` (measured: flags 0x26010b01 for
    /// `/bin/zsh` and `/bin/bash`), and the kernel withholds a restricted
    /// process's environment from every other process (XNU
    /// `sysctl_procargsx`), so the provider reads none of theirs, whatever a
    /// test gives them. A running git is never `/usr/bin/git`: that shim
    /// execs the developer tool, whose environment is readable.
    static let withheldEnvironmentPaths: Set<String> = ["/bin/bash", "/bin/zsh", "/bin/sh"]

    private let lock = NSLock()
    private var processes: [pid_t: Process]
    private var parentReadCounts: [pid_t: Int] = [:]
    private var descriptorReads = 0

    /// How many descriptor reads the provider has answered.
    var descriptorReadCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return descriptorReads
    }
    private var afterParentRead: ((SyntheticClaudeSessionFacts, pid_t, Int) -> Void)?

    init(_ processes: [pid_t: Process]) {
        self.processes = processes
    }

    /// Run `hook(tree, pid, n)` after the n-th parent read of `pid` returns.
    func onParentRead(_ hook: @escaping (SyntheticClaudeSessionFacts, pid_t, Int) -> Void) {
        lock.lock()
        afterParentRead = hook
        lock.unlock()
    }

    func mutate(_ body: (inout [pid_t: Process]) -> Void) {
        lock.lock()
        body(&processes)
        lock.unlock()
    }

    /// Model an exit: the process disappears and the kernel reparents its
    /// children to launchd.
    func exit(_ pid: pid_t) {
        mutate { tree in
            tree[pid] = nil
            for (child, var process) in tree where process.parent == pid {
                process.parent = 1
                tree[child] = process
            }
        }
    }

    private func process(_ incarnation: ProcessIncarnation) -> Process? {
        lock.lock()
        defer { lock.unlock() }
        guard let process = processes[incarnation.pid], process.readable,
              process.startTime == incarnation.startTime else { return nil }
        return process
    }

    /// The environment the kernel would show another process.
    private func environment(_ incarnation: ProcessIncarnation) -> [EnvironmentEntry]? {
        guard let process = process(incarnation),
              !Self.withheldEnvironmentPaths.contains(process.executablePath ?? "") else { return nil }
        return process.environment
    }

    func incarnation(of pid: pid_t) -> ProcessIncarnation? {
        lock.lock()
        defer { lock.unlock() }
        guard let process = processes[pid], process.readable else { return nil }
        return ProcessIncarnation(pid: pid, startTime: process.startTime)
    }

    func parent(of pid: pid_t) -> pid_t? {
        lock.lock()
        let parent = processes[pid]?.parent
        let count = (parentReadCounts[pid] ?? 0) + 1
        parentReadCounts[pid] = count
        let hook = afterParentRead
        lock.unlock()
        hook?(self, pid, count)
        return parent
    }

    func executablePath(of process: ProcessIncarnation) -> String? {
        self.process(process)?.executablePath
    }

    func argv(of process: ProcessIncarnation) -> [String]? {
        self.process(process)?.argv
    }

    func jobFacts(of process: ProcessIncarnation) -> ProcessJobFacts? {
        guard let job = self.process(process)?.job, job.startTime == process.startTime else { return nil }
        return job
    }

    func fdCharDevice(of process: ProcessIncarnation, fd: Int32) -> ProcessFileDescriptorKind? {
        lock.lock()
        descriptorReads += 1
        lock.unlock()
        return fd == 0 ? self.process(process)?.standardInput : nil
    }

    func cwd(of process: ProcessIncarnation) -> ProcessWorkingDirectory? {
        self.process(process)?.cwd
    }

    func openFile(of process: ProcessIncarnation, fd: Int32) -> ProcessOpenFile? {
        self.process(process)?.openFiles[fd]
    }

    func envPresence(
        of process: ProcessIncarnation, names: [String], prefixes: [String]
    ) -> EnvironmentNamePresence? {
        guard let environment = environment(process) else { return nil }
        var nameCounts: [String: Int] = [:]
        var prefixCounts: [String: Int] = [:]
        for entry in environment {
            for name in names where entry.name == name { nameCounts[name, default: 0] += 1 }
            for prefix in prefixes where entry.name.hasPrefix(prefix) { prefixCounts[prefix, default: 0] += 1 }
        }
        return EnvironmentNamePresence(names: nameCounts, prefixes: prefixCounts)
    }

    func envValues(of process: ProcessIncarnation, allowlistedKeys: [String]) -> [String: String]? {
        guard allowlistedKeys.allSatisfy(ClaudeSessionFacts.valueReadableEnvironmentKeys.contains),
              let environment = environment(process) else { return nil }
        var values: [String: String] = [:]
        for key in allowlistedKeys {
            let matches = environment.filter { $0.name == key }
            guard matches.count <= 1 else { return nil }
            if let match = matches.first { values[key] = match.value }
        }
        return values
    }

    func codeIdentity(
        of process: ProcessIncarnation, parentOf child: pid_t?, trustedCDHashes: Set<String>
    ) -> ForeignCodeIdentity? {
        guard let identity = self.process(process)?.identity else { return nil }
        if let child, parent(of: child) != process.pid { return nil }
        let trusted = identity.cdHash.flatMap { hash in
            identity.signatureValid && trustedCDHashes.contains(hash) ? hash : nil
        }
        return ForeignCodeIdentity(
            pid: identity.pid, startTime: identity.startTime, lookup: identity.lookup,
            identifier: identity.identifier, teamIdentifier: identity.teamIdentifier,
            cdHash: identity.cdHash, executablePath: identity.executablePath,
            signatureValid: identity.signatureValid, hardenedRuntime: identity.hardenedRuntime,
            platformIdentifier: identity.platformIdentifier, entitlementKeys: identity.entitlementKeys,
            appleAnchored: identity.appleAnchored,
            satisfiesAnthropicRequirement: identity.satisfiesAnthropicRequirement,
            trustedCDHash: trusted, status: identity.status
        )
    }

    func pidVersion(of process: ProcessIncarnation) -> Int32? {
        self.process(process)?.pidVersion
    }

    /// What `KERN_PROC_PID`, `proc_pidpath` and `csops` report: answered for
    /// every process, a set-id root one included, as the kernel answers them.
    func kernelRecord(of pid: pid_t) -> KernelProcessRecord? {
        lock.lock()
        defer { lock.unlock() }
        guard let process = processes[pid] else { return nil }
        return KernelProcessRecord(
            process: ProcessIncarnation(pid: pid, startTime: process.startTime),
            parent: process.parent,
            effectiveUID: process.effectiveUID ?? getuid(),
            realUID: getuid(),
            executablePath: process.executablePath,
            codeSigningFlags: process.codeSigningFlags
        )
    }

    func liveProcesses() -> [ProcessIncarnation]? {
        lock.lock()
        defer { lock.unlock() }
        return processes.map { ProcessIncarnation(pid: $0.key, startTime: $0.value.startTime) }
            .sorted { $0.pid < $1.pid }
    }

    /// Job facts of the interactive foreground leader of terminal `terminal`.
    static func foregroundJob(pid: pid_t, parent: pid_t, startTime: UInt64, terminal: UInt32) -> ProcessJobFacts {
        ProcessJobFacts(
            pid: pid, parent: parent, processGroup: pid, terminalProcessGroup: pid,
            terminalDevice: terminal, hasControllingTerminal: true,
            effectiveUID: getuid(), startTime: startTime
        )
    }

    /// A validated identity that satisfies Anthropic's requirement.
    static func genuineClaudeIdentity(pid: pid_t, startTime: UInt64) -> ForeignCodeIdentity {
        ForeignCodeIdentity(
            pid: pid, startTime: startTime, lookup: .auditToken(pidVersion: 1),
            identifier: "synthetic.claude-code", teamIdentifier: "SYNTHETIC0",
            cdHash: String(repeating: "a", count: 40), executablePath: "/synthetic/claude",
            signatureValid: true, hardenedRuntime: true, platformIdentifier: nil,
            entitlementKeys: [], appleAnchored: false, satisfiesAnthropicRequirement: true,
            trustedCDHash: nil, status: 0
        )
    }
}

// MARK: - Pure rules

private func interactivityRuleTests() {
    let terminal: UInt32 = 0x1000_0042
    let leader = SyntheticClaudeSessionFacts.foregroundJob(pid: 400, parent: 300, startTime: 7, terminal: terminal)
    func job(
        processGroup: pid_t = 400, terminalProcessGroup: pid_t = 400,
        device: UInt32? = terminal, controlling: Bool = true, sessionLeader: Bool = false
    ) -> ProcessJobFacts {
        ProcessJobFacts(
            pid: 400, parent: 300, processGroup: processGroup, terminalProcessGroup: terminalProcessGroup,
            terminalDevice: device, hasControllingTerminal: controlling, isSessionLeader: sessionLeader,
            effectiveUID: getuid(), startTime: 7
        )
    }
    let tty = ProcessFileDescriptorKind.characterDevice(terminal)
    check(ClaudeSessionFacts.interactivity(job: leader, standardInput: tty) == .interactive,
          "facts: the foreground group leader with its terminal on fd 0 is interactive")
    check(ClaudeSessionFacts.interactivity(job: job(sessionLeader: false), standardInput: tty).isInteractive,
          "facts: session leadership is not required (the login process leads the session, not the agent)")
    check(ClaudeSessionFacts.interactivity(job: job(controlling: false), standardInput: tty)
            == .notInteractive(.noControllingTerminal),
          "facts: no PROC_FLAG_CONTROLT is not interactive")
    check(ClaudeSessionFacts.interactivity(job: job(device: nil), standardInput: tty)
            == .notInteractive(.noControllingTerminal),
          "facts: a NODEV controlling terminal is not interactive")
    check(ClaudeSessionFacts.interactivity(job: job(processGroup: 399), standardInput: tty)
            == .notInteractive(.notProcessGroupLeader),
          "facts: a member of another process group (pgid != pid) is not interactive")
    check(ClaudeSessionFacts.interactivity(job: job(terminalProcessGroup: 399), standardInput: tty)
            == .notInteractive(.notForegroundProcessGroup),
          "facts: a background group (tpgid != pid) is not interactive")
    check(ClaudeSessionFacts.interactivity(job: leader, standardInput: .other)
            == .notInteractive(.standardInputNotTerminal),
          "facts: fd 0 a pipe or socket is not interactive")
    check(ClaudeSessionFacts.interactivity(job: leader, standardInput: .characterDevice(0x0300_0002))
            == .notInteractive(.standardInputNotTerminal),
          "facts: fd 0 a different character device (/dev/null) is not interactive")
    check(ClaudeSessionFacts.interactivity(job: nil, standardInput: tty)
            == .notInteractive(.factsUnavailable)
            && ClaudeSessionFacts.interactivity(job: leader, standardInput: nil)
            == .notInteractive(.factsUnavailable),
          "facts: unreadable job facts or fd 0 is not interactive")

    // CLAUDE_CODE_SHELL_PREFIX is read so G5 can accept csec's own prefix
    // path and nothing else (`ClaudeCodeShellPrefix`); its value is a path.
    check(ClaudeSessionFacts.valueReadableEnvironmentKeys == [
        "CDPATH", "CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR", "HOME",
        "NODE_OPTIONS", "PWD",
    ], "facts: only CDPATH, CLAUDE_CODE_SHELL_PREFIX, CLAUDE_CONFIG_DIR, CLAUDE_SECURESTORAGE_CONFIG_DIR, HOME, "
        + "NODE_OPTIONS and PWD values are readable from another process")
    check(ForeignCodeIdentity.isWellFormedCDHash(String(repeating: "0", count: 40))
            && !ForeignCodeIdentity.isWellFormedCDHash(String(repeating: "A", count: 40))
            && !ForeignCodeIdentity.isWellFormedCDHash(String(repeating: "0", count: 39))
            && !ForeignCodeIdentity.isWellFormedCDHash("\" or anchor apple generic or cdhash H\""),
          "identity: only 40 lowercase hex digits can become a cdhash requirement")
}

/// A(100) → X(200) → P(300) → login(50) → launchd.
private func syntheticChain() -> SyntheticClaudeSessionFacts {
    SyntheticClaudeSessionFacts([
        50: .init(startTime: 5, parent: 1),
        300: .init(startTime: 30, parent: 50),
        200: .init(startTime: 20, parent: 300),
        100: .init(startTime: 10, parent: 200),
    ])
}

private func ancestryRaceTests() {
    let a = ProcessIncarnation(pid: 100, startTime: 10)
    let x = ProcessIncarnation(pid: 200, startTime: 20)
    let p = ProcessIncarnation(pid: 300, startTime: 30)

    let stable = syntheticChain()
    check(ClaudeSessionFacts.commandChain(from: a, provider: stable)
            == AgentCommandChain(command: a, shell: x, agent: p),
          "walk: a stable A → X → P chain is returned with each incarnation")
    check(ClaudeSessionFacts.verifiedAncestry(of: a, hops: 0, provider: stable) == [a],
          "walk: zero hops returns the verified start alone")
    check(ClaudeSessionFacts.verifiedAncestry(of: ProcessIncarnation(pid: 100, startTime: 11), hops: 2,
                                              provider: stable) == nil,
          "walk: a start incarnation whose PID now belongs to another process is refused")

    // P exits right after X's parent was read; X is reparented to launchd.
    let parentDied = syntheticChain()
    parentDied.onParentRead { tree, pid, count in
        if pid == 200 && count == 1 { tree.exit(300) }
    }
    check(ClaudeSessionFacts.commandChain(from: a, provider: parentDied) == nil,
          "walk: P exiting mid-walk (X reparented to launchd) is refused")

    // P exits and a new process reuses its PID before P's start time is read.
    // Without the parent re-read the walk would bind that impostor as P.
    let pidReused = syntheticChain()
    pidReused.onParentRead { tree, pid, count in
        guard pid == 200 && count == 1 else { return }
        tree.exit(300)
        tree.mutate { $0[300] = .init(startTime: 999, parent: 50) }
    }
    check(ClaudeSessionFacts.commandChain(from: a, provider: pidReused) == nil,
          "walk: P's PID reused mid-walk is refused by the ppid(X) re-read")

    // X exits and its PID is reused after A's parent was read.
    let shellReused = syntheticChain()
    shellReused.onParentRead { tree, pid, count in
        guard pid == 100 && count == 1 else { return }
        tree.exit(200)
        tree.mutate { $0[200] = .init(startTime: 888, parent: 300) }
    }
    check(ClaudeSessionFacts.commandChain(from: a, provider: shellReused) == nil,
          "walk: X's PID reused mid-walk is refused by the ppid(A) re-read")

    // A itself exits after the walk started and its PID is reused by a child
    // of the same shell: every link still reads, but A is not A any more.
    let commandReused = syntheticChain()
    commandReused.onParentRead { tree, pid, count in
        guard pid == 200 && count == 2 else { return }
        tree.mutate { $0[100] = .init(startTime: 777, parent: 200) }
    }
    check(ClaudeSessionFacts.commandChain(from: a, provider: commandReused) == nil,
          "walk: the command's own PID reused during the re-reads is refused")

    // A late re-read that still sees the original tree passes: the rule only
    // refuses a chain whose links changed.
    let lateNoop = syntheticChain()
    lateNoop.onParentRead { _, _, _ in }
    check(ClaudeSessionFacts.commandChain(from: a, provider: lateNoop) != nil,
          "walk: re-reads that see an unchanged tree pass")

    let orphan = SyntheticClaudeSessionFacts([
        200: .init(startTime: 20, parent: 1),
        100: .init(startTime: 10, parent: 200),
    ])
    check(ClaudeSessionFacts.commandChain(from: a, provider: orphan) == nil,
          "walk: a chain that reaches launchd (an orphaned shell) is refused")
    let loop = SyntheticClaudeSessionFacts([
        200: .init(startTime: 20, parent: 100),
        100: .init(startTime: 10, parent: 200),
    ])
    check(ClaudeSessionFacts.commandChain(from: a, provider: loop) == nil,
          "walk: a parent loop is refused")
    let missingParent = SyntheticClaudeSessionFacts([100: .init(startTime: 10, parent: 200)])
    check(ClaudeSessionFacts.commandChain(from: a, provider: missingParent) == nil,
          "walk: a parent that is already gone is refused")
}

private func syntheticProviderContractTests() {
    let terminal: UInt32 = 0x1000_0001
    let facts = SyntheticClaudeSessionFacts([
        300: .init(
            startTime: 30, parent: 50, argv: ["claude"],
            job: SyntheticClaudeSessionFacts.foregroundJob(pid: 300, parent: 50, startTime: 30, terminal: terminal),
            standardInput: .characterDevice(terminal),
            environment: [
                .init(name: "NODE_OPTIONS", value: "--max-old-space-size=64"),
                .init(name: "CLAUDE_CONFIG_DIR", value: "/synthetic/a"),
                .init(name: "CLAUDE_CONFIG_DIR", value: "/synthetic/b"),
                .init(name: "BUN_OPTIONS", value: "--synthetic"),
            ],
            identity: SyntheticClaudeSessionFacts.genuineClaudeIdentity(pid: 300, startTime: 30)
        ),
    ])
    let p = ProcessIncarnation(pid: 300, startTime: 30)
    let stale = ProcessIncarnation(pid: 300, startTime: 31)
    check(facts.interactivity(of: p) == .interactive && facts.interactivity(of: stale) != .interactive,
          "synthetic: facts are bound to the incarnation, as the live provider binds them")

    // fd 0 is read only for a process the job facts already qualify.
    let background = SyntheticClaudeSessionFacts([
        301: .init(
            startTime: 31, parent: 50,
            job: ProcessJobFacts(
                pid: 301, parent: 50, processGroup: 301, terminalProcessGroup: 999,
                terminalDevice: terminal, hasControllingTerminal: true, effectiveUID: getuid(), startTime: 31
            ),
            standardInput: .characterDevice(terminal)
        ),
    ])
    let backgroundJob = ProcessIncarnation(pid: 301, startTime: 31)
    check(background.interactivity(of: backgroundJob) == .notInteractive(.notForegroundProcessGroup)
            && background.descriptorReadCount == 0,
          "synthetic: a background job is ruled out without reading its fd 0")
    let readsBefore = facts.descriptorReadCount
    _ = facts.interactivity(of: p)
    check(facts.descriptorReadCount == readsBefore + 1,
          "synthetic: a foreground leader's fd 0 is read once")
    check(facts.envValues(of: p, allowlistedKeys: ["NODE_OPTIONS"]) == ["NODE_OPTIONS": "--max-old-space-size=64"],
          "synthetic: an allow-listed value is read")
    check(facts.envValues(of: p, allowlistedKeys: ["CLAUDE_CONFIG_DIR"]) == nil,
          "synthetic: a duplicated allow-listed key is unreadable, as in the live provider")
    check(facts.envValues(of: p, allowlistedKeys: ["BUN_OPTIONS"]) == nil,
          "synthetic: a key outside the value allow-list is refused")
    check(facts.envPresence(of: p, names: ["BUN_OPTIONS"], prefixes: ["BUN_"])
            == EnvironmentNamePresence(names: ["BUN_OPTIONS": 1], prefixes: ["BUN_": 1]),
          "synthetic: presence reports names and prefixes")
    check(facts.codeIdentity(of: p, parentOf: nil, trustedCDHashes: [])?.isClaudeCode == true,
          "synthetic: a genuine identity is Claude Code")
}

// MARK: - Live probes

/// A process this suite started, and everything needed to stop it.
struct SpawnedProbe {
    let pid: pid_t
    let ptyMaster: Int32

    func stop() {
        // Each probe leads its own process group, so this also stops anything
        // it started in the background.
        _ = kill(-pid, SIGKILL)
        _ = kill(pid, SIGKILL)
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
        if ptyMaster >= 0 { close(ptyMaster) }
    }
}

/// Spawn `path` in a new session. With `ptyStandardInput`, the child becomes the
/// foreground process group of a fresh PTY that is its controlling terminal and
/// its fd 0 (setsid, TIOCSCTTY, tcsetpgrp), as a terminal launches a job.
func spawnProbe(
    path: String,
    argv: [String],
    environment: [String],
    workingDirectory: String? = nil,
    ptyStandardInput: Bool = true
) -> SpawnedProbe? {
    let argvPointers = argv.map { strdup($0) } + [nil]
    let environmentPointers = environment.map { strdup($0) } + [nil]
    defer {
        argvPointers.forEach { free($0) }
        environmentPointers.forEach { free($0) }
    }
    var childPID: Int32 = -1
    var ptyMaster: Int32 = -1
    var stdoutRead: Int32 = -1
    var stderrRead: Int32 = -1
    var failedStep = CS_SPAWN_STEP_NONE
    var mutableArgv = argvPointers
    var mutableEnvironment = environmentPointers
    let result = mutableArgv.withUnsafeMutableBufferPointer { argvBuffer in
        mutableEnvironment.withUnsafeMutableBufferPointer { environmentBuffer in
            path.withCString { pathPointer in
                withOptionalCString(workingDirectory) { directory in
                    cs_spawn_supervised(
                        pathPointer, argvBuffer.baseAddress, environmentBuffer.baseAddress, directory,
                        ptyStandardInput ? 1 : 0, CS_OUTPUT_PTY, CS_OUTPUT_PTY,
                        nil, 0, &childPID, &ptyMaster, &stdoutRead, &stderrRead, &failedStep
                    )
                }
            }
        }
    }
    guard result == 0, childPID > 0 else { return nil }
    return SpawnedProbe(pid: childPID, ptyMaster: ptyMaster)
}

private func withOptionalCString<T>(_ string: String?, _ body: (UnsafePointer<CChar>?) -> T) -> T {
    guard let string else { return body(nil) }
    return string.withCString { body($0) }
}

/// Poll `condition` for up to two seconds.
private func eventually(_ condition: () -> Bool) -> Bool {
    for _ in 0..<200 {
        if condition() { return true }
        usleep(10_000)
    }
    return condition()
}

private func milliseconds(_ body: () -> Void) -> Double {
    let start = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
    body()
    return Double(clock_gettime_nsec_np(CLOCK_UPTIME_RAW) - start) / 1_000_000
}

private func median(_ samples: [Double]) -> Double {
    let sorted = samples.sorted()
    return sorted.isEmpty ? 0 : sorted[sorted.count / 2]
}

private func makeProbeDirectory() -> String? {
    let base = FileManager.default.temporaryDirectory
        .appendingPathComponent("csec-session-facts-\(UUID().uuidString.prefix(8))", isDirectory: true)
    do {
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base.path
    } catch {
        check(false, "live facts: temp directory setup threw (\(error))")
        return nil
    }
}

private func realPath(_ path: String) -> String? {
    guard let resolved = realpath(path, nil) else { return nil }
    defer { free(resolved) }
    return String(cString: resolved)
}

/// This test binary, as the kernel names its image.
private func selftestExecutablePath() -> String? {
    ProcessAncestry.executablePath(of: getpid())
}

/// Spawn this binary in its `--session-facts-probe` mode: a live process that,
/// unlike an Apple platform binary, does not have its environment withheld.
private func spawnSelftestProbe(
    argv0: String? = nil,
    environment: [String],
    workingDirectory: String? = nil
) -> SpawnedProbe? {
    guard let path = selftestExecutablePath() else { return nil }
    return spawnProbe(
        path: path, argv: [argv0 ?? path, "--session-facts-probe"],
        environment: environment, workingDirectory: workingDirectory
    )
}

private let syntheticEnvironment = [
    "PATH=/usr/bin:/bin",
    "BUN_OPTIONS=--csec-selftest-synthetic-preload",
    "NODE_OPTIONS=--max-old-space-size=64",
    "CLAUDE_CONFIG_DIR=/tmp/csec-selftest-synthetic-claude",
    "HOME=/tmp/csec-selftest-synthetic-home",
    "CSEC_SELFTEST_SYNTHETIC_MARKER=synthetic-marker-value",
]

private func liveForegroundProbeTests() {
    let facts = LiveClaudeSessionFactProvider()
    guard let directory = makeProbeDirectory() else { return }
    defer { try? FileManager.default.removeItem(atPath: directory) }
    guard let probe = spawnProbe(
        path: "/bin/sleep", argv: ["csec-selftest-argv0", "30"],
        environment: syntheticEnvironment, workingDirectory: directory
    ) else {
        check(false, "live facts: /bin/sleep spawns under a PTY")
        return
    }
    defer { probe.stop() }

    guard let child = facts.incarnation(of: probe.pid) else {
        check(false, "live facts: the probe has a live incarnation")
        return
    }
    let me = getpid()
    let job = facts.jobFacts(of: child)
    check(job?.pid == probe.pid && job?.parent == me && job?.effectiveUID == getuid(),
          "live facts: job facts name the probe, its parent (this process) and this user")
    check(job?.processGroup == probe.pid && job?.terminalProcessGroup == probe.pid,
          "live facts: the probe leads the PTY's foreground process group (pgid == tpgid == pid)")
    check(job?.hasControllingTerminal == true && job?.terminalDevice != nil && job?.isSessionLeader == true,
          "live facts: the probe has the PTY as controlling terminal (and leads its session, as setsid made it)")
    let standardInput = facts.fdCharDevice(of: child, fd: 0)
    if let terminal = job?.terminalDevice {
        check(standardInput == .characterDevice(terminal),
              "live facts: fd 0 is a character device whose rdev equals the controlling terminal")
    } else {
        check(false, "live facts: fd 0 is a character device whose rdev equals the controlling terminal")
    }
    check(facts.interactivity(of: child) == .interactive,
          "live facts: the PTY foreground probe is interactive")
    check(facts.fdCharDevice(of: child, fd: 97) == nil,
          "live facts: a descriptor that is not open reads as unavailable")

    let expectedDirectory = realPath(directory) ?? directory
    var directoryInfo = stat()
    let statted = stat(expectedDirectory, &directoryInfo) == 0
    let workingDirectory = facts.cwd(of: child)
    check(workingDirectory?.directory.path == expectedDirectory,
          "live facts: cwd resolves to the realpath of the directory the probe was started in")
    check(statted
            && workingDirectory?.directory.device == UInt64(UInt32(bitPattern: directoryInfo.st_dev))
            && workingDirectory?.directory.inode == UInt64(directoryInfo.st_ino),
          "live facts: cwd carries that directory's device and inode")
    check(workingDirectory?.isOnLocalMounts == true && workingDirectory?.mount.isLocal == true
            && workingDirectory?.mount.fileSystemID == fileSystemID(of: expectedDirectory),
          "live facts: cwd names its local mount (the directory's f_fsid) from the kernel's cached mount table")

    let arguments = facts.argv(of: child)
    check(arguments == ["csec-selftest-argv0", "30"],
          "live facts: argv is exactly the probe's argv, argv[0] included")
    check(arguments?.contains(where: { $0.contains("=") }) == false,
          "live facts: argv carries no environment entry")
    check(facts.executablePath(of: child) == "/bin/sleep",
          "live facts: the executable path is the image, not argv[0]")

    // The kernel withholds a platform binary's environment (it is restricted),
    // so this probe's environment reads as unreadable, never as clean.
    let platformPresence = facts.envPresence(of: child, names: ["BUN_OPTIONS"], prefixes: [])
    check(platformPresence == nil || platformPresence?.names == ["BUN_OPTIONS": 1],
          "live facts: /bin/sleep's environment is either unreadable or shows the synthetic name")

    let stale = ProcessIncarnation(pid: child.pid, startTime: child.startTime + 1)
    check(facts.jobFacts(of: stale) == nil && facts.argv(of: stale) == nil && facts.cwd(of: stale) == nil
            && facts.envPresence(of: stale, names: ["BUN_OPTIONS"], prefixes: []) == nil
            && facts.fdCharDevice(of: stale, fd: 0) == nil
            && facts.codeIdentity(of: stale, parentOf: nil, trustedCDHashes: []) == nil,
          "live facts: every fact about a stale incarnation (same PID, other start time) is refused")

    // Code identity: the audit-token path, then the forced PID fallback.
    guard case let .token(audit) = AuditIdentity.task(pid: probe.pid) else {
        check(false, "identity: task_name_for_pid yields the probe's audit token from this binary")
        return
    }
    check(audit.pid == probe.pid && audit.pidVersion >= 0 && audit.effectiveUID == getuid()
            && audit.startTime == child.startTime && audit.executablePath == "/bin/sleep",
          "identity: task_name_for_pid yields the probe's audit token from this binary")
    check(facts.pidVersion(of: child) == audit.pidVersion,
          "identity: the provider reports the token's PID version")
    let identity = facts.codeIdentity(of: child, parentOf: nil, trustedCDHashes: [])
    print("info - probe identity via \(identity?.lookup.logDescription ?? "none"): "
          + "\(identity?.identifier ?? "nil") platform \(identity?.platformIdentifier.map { String($0) } ?? "nil")")
    check(identity?.lookup == .auditToken(pidVersion: audit.pidVersion),
          "identity: the probe resolves through its audit token (task_name_for_pid accepted)")
    check(identity?.isApplePlatformBinary == true && identity?.identifier == "com.apple.sleep"
            && identity?.teamIdentifier == nil,
          "identity: /bin/sleep resolves as a valid Apple platform binary")
    check(identity?.satisfiesAnthropicRequirement == false && identity?.isClaudeCode == false,
          "identity: an Apple binary fails Anthropic's designated requirement")
    check(identity?.trustedCDHash == nil,
          "identity: with no trusted cdhash, no cdhash is trusted")
    guard let cdHash = identity?.cdHash, ForeignCodeIdentity.isWellFormedCDHash(cdHash) else {
        check(false, "identity: the probe reports a 40-hex cdhash")
        return
    }
    let trusted = facts.codeIdentity(of: child, parentOf: nil, trustedCDHashes: [cdHash])
    check(trusted?.trustedCDHash == cdHash && trusted?.isClaudeCode == true,
          "identity: the probe's own cdhash, when trusted, satisfies cdhash H\"…\"")
    let otherHash = String(cdHash.dropLast()) + (cdHash.hasSuffix("0") ? "1" : "0")
    check(facts.codeIdentity(of: child, parentOf: nil, trustedCDHashes: [otherHash])?.trustedCDHash == nil,
          "identity: a different trusted cdhash does not match")
    check(facts.codeIdentity(of: child, parentOf: nil, trustedCDHashes: [cdHash.uppercased()])?.trustedCDHash == nil,
          "identity: a malformed trusted cdhash is ignored, never compiled")

    let fallback = ForeignCodeIdentity.resolve(
        pid: child.pid, startTime: child.startTime, trustedCDHashes: [cdHash],
        taskAuditToken: { _ in .refused(kernelStatus: KERN_FAILURE) }
    )
    check(fallback?.lookup == .processID(taskNameStatus: KERN_FAILURE)
            && fallback?.lookup.isExecExact == false,
          "identity: a refused task name port falls back to the PID and says why")
    check(fallback?.isApplePlatformBinary == true && fallback?.cdHash == cdHash
            && fallback?.trustedCDHash == cdHash && fallback?.satisfiesAnthropicRequirement == false,
          "identity: the PID fallback validates the same code and requirements")

    // SSH lazy binding's launcher check takes the same two paths, and the
    // same refusals: only a refused task name port falls back to the PID.
    let productToken = ProductCodeIdentity.resolve(pid: child.pid, startTime: child.startTime)
    let productFallback = ProductCodeIdentity.resolve(
        pid: child.pid, startTime: child.startTime,
        taskAuditToken: { _ in .refused(kernelStatus: KERN_FAILURE) }
    )
    check(productToken?.lookup == .auditToken(pidVersion: audit.pidVersion)
            && productToken?.identity.identifier == "com.apple.sleep" && productToken?.identity.role == .other,
          "launcher check: the audit-token path resolves the process's product identity")
    check(productFallback?.lookup == .processID(taskNameStatus: KERN_FAILURE)
            && productFallback?.identity.identifier == productToken?.identity.identifier
            && productFallback?.identity.cdHash == productToken?.identity.cdHash
            && productFallback?.identity.role == .other,
          "launcher check: a refused task name port falls back to the PID and validates the same code")
    check(ProductCodeIdentity.resolve(
            pid: child.pid, startTime: child.startTime,
            taskAuditToken: { _ in .changed(kernelStatus: KERN_FAILURE) }) == nil,
          "launcher check: a token that could not be read after the port was granted never falls back")
    check(ProductCodeIdentity.resolve(
            pid: child.pid, startTime: child.startTime + 1,
            taskAuditToken: { _ in .refused(kernelStatus: KERN_FAILURE) }) == nil,
          "launcher check: the PID fallback refuses another incarnation of the PID")
    check(!DelegationLauncherCheck.live.isVerifiedLauncher(child),
          "launcher check: /bin/sleep is not the signed csec launcher")

    // The parent re-check: this process is the probe's parent, launchd is not.
    if let myStart = ProcessAncestry.startTime(of: me) {
        check(ForeignCodeIdentity.resolve(pid: me, startTime: myStart, parentOf: probe.pid) != nil,
              "identity: resolving a parent re-checks ppid(child) == pid and passes for the real parent")
        check(ForeignCodeIdentity.resolve(pid: me, startTime: myStart, parentOf: 1) == nil,
              "identity: resolving a 'parent' of a process it does not parent is refused")
    }

    // Enumeration.
    let enumerated = facts.liveProcesses() ?? []
    check(enumerated.contains(child) && enumerated.contains { $0.pid == me },
          "enumeration: this user's live processes include this process and its probe")
    check(!enumerated.contains { $0.pid == 1 },
          "enumeration: another user's process (launchd) is not listed")
    reportCost(of: child, facts: facts, label: "/bin/sleep, environment withheld")
}

/// Print the cost of one full fact collection (with a per-fact breakdown), one
/// identity resolution, and an enumeration sweep that applies the cheap
/// interactivity facts to every process of this user.
private func reportCost(of child: ProcessIncarnation, facts: LiveClaudeSessionFactProvider, label: String) {
    let steps: [(String, () -> Void)] = [
        ("incarnation", { _ = facts.incarnation(of: child.pid) }),
        ("path", { _ = facts.executablePath(of: child) }),
        ("job", { _ = facts.jobFacts(of: child) }),
        ("fd0", { _ = facts.fdCharDevice(of: child, fd: 0) }),
        ("cwd", { _ = facts.cwd(of: child) }),
        ("argv", { _ = facts.argv(of: child) }),
        ("envPresence", {
            _ = facts.envPresence(of: child, names: ["BUN_OPTIONS", "ANTHROPIC_BASE_URL"], prefixes: ["DYLD_"])
        }),
        ("envValues", { _ = facts.envValues(of: child, allowlistedKeys: ["NODE_OPTIONS", "CLAUDE_CONFIG_DIR"]) }),
    ]
    var stepSamples = [[Double]](repeating: [], count: steps.count)
    var collectionSamples: [Double] = []
    var identitySamples: [Double] = []
    for _ in 0..<15 {
        var total = 0.0
        for (index, step) in steps.enumerated() {
            let elapsed = milliseconds(step.1)
            stepSamples[index].append(elapsed)
            total += elapsed
        }
        collectionSamples.append(total)
        identitySamples.append(milliseconds {
            _ = facts.codeIdentity(of: child, parentOf: nil, trustedCDHashes: [])
        })
    }
    let breakdown = zip(steps, stepSamples)
        .map { String(format: "%@ %.3f", $0.0.0, median($0.1)) }
        .joined(separator: ", ")
    var processCount = 0
    var interactiveCount = 0
    let sweep = milliseconds {
        let processes = facts.liveProcesses() ?? []
        processCount = processes.count
        interactiveCount = processes.filter { facts.interactivity(of: $0).isInteractive }.count
    }
    print(String(
        format: "info - cost (%@): full fact collection median %.3f ms (max %.3f) [%@]; "
            + "identity median %.3f ms (first %.3f, max %.3f); "
            + "enumerate %d processes + interactivity %.3f ms (%d interactive)",
        label, median(collectionSamples), collectionSamples.max() ?? 0, breakdown,
        median(identitySamples), identitySamples.first ?? 0, identitySamples.max() ?? 0,
        processCount, sweep, interactiveCount
    ))
}

private func liveEnvironmentProbeTests() {
    let facts = LiveClaudeSessionFactProvider()
    guard let directory = makeProbeDirectory() else { return }
    defer { try? FileManager.default.removeItem(atPath: directory) }
    guard let selfPath = selftestExecutablePath(),
          let probe = spawnSelftestProbe(environment: syntheticEnvironment, workingDirectory: directory),
          let child = facts.incarnation(of: probe.pid) else {
        check(false, "live environment: this binary spawns as a probe under a PTY")
        return
    }
    defer { probe.stop() }

    let presence = facts.envPresence(
        of: child,
        names: ["BUN_OPTIONS", "ANTHROPIC_BASE_URL", "CSEC_SELFTEST_SYNTHETIC_MARKER"],
        prefixes: ["BUN_", "DYLD_", "CSEC_SELFTEST_"]
    )
    check(presence?.names == ["BUN_OPTIONS": 1, "CSEC_SELFTEST_SYNTHETIC_MARKER": 1],
          "live environment: exact names are reported present or absent")
    check(presence?.prefixes == ["BUN_": 1, "CSEC_SELFTEST_": 1],
          "live environment: name prefixes are reported present or absent")
    check(facts.envValues(of: child, allowlistedKeys: ["NODE_OPTIONS", "CLAUDE_CONFIG_DIR", "HOME"])
            == ["NODE_OPTIONS": "--max-old-space-size=64",
                "CLAUDE_CONFIG_DIR": "/tmp/csec-selftest-synthetic-claude",
                "HOME": "/tmp/csec-selftest-synthetic-home"],
          "live environment: allow-listed values are read")
    check(facts.envValues(of: child, allowlistedKeys: ["CSEC_SELFTEST_SYNTHETIC_MARKER"]) == nil
            && facts.envValues(of: child, allowlistedKeys: ["NODE_OPTIONS", "BUN_OPTIONS"]) == nil,
          "live environment: a value outside the allow-list is never read, even beside an allowed key")
    check(facts.envValues(of: child, allowlistedKeys: []) == [:],
          "live environment: asking for no values reads nothing")
    check(facts.argv(of: child) == [selfPath, "--session-facts-probe"]
            && facts.argv(of: child)?.contains(where: { $0.contains("synthetic") }) == false,
          "live environment: argv of a process with a readable environment holds no environment entry")
    check(facts.interactivity(of: child) == .interactive
            && facts.cwd(of: child)?.directory.path == realPath(directory),
          "live environment: the probe is also an interactive PTY job in its directory")

    // A third-party signature: valid, not Apple's, trusted only by cdhash.
    let identity = facts.codeIdentity(of: child, parentOf: nil, trustedCDHashes: [])
    check(identity?.lookup.isExecExact == true && identity?.isApplePlatformBinary == false
            && identity?.satisfiesAnthropicRequirement == false && identity?.isClaudeCode == false,
          "identity: this binary resolves by audit token as neither Apple's nor Anthropic's")
    reportCost(of: child, facts: facts, label: "this binary, environment readable")
    if let cdHash = identity?.cdHash, identity?.signatureValid == true {
        check(facts.codeIdentity(of: child, parentOf: nil, trustedCDHashes: [cdHash])?.trustedCDHash == cdHash,
              "identity: a validly signed non-Apple binary is trusted by its own cdhash")
    } else {
        print("info - this binary's signature does not validate strictly (status \(identity?.status ?? 0)); cdhash trust not exercised")
    }
}

private func liveNonInteractiveProbeTests() {
    let facts = LiveClaudeSessionFactProvider()

    // Foreground leader of the PTY, but fd 0 is /dev/null (the `claude -p` shape).
    if let probe = spawnProbe(
        path: "/bin/sh", argv: ["/bin/sh", "-c", "exec /bin/sleep 30 </dev/null"],
        environment: ["PATH=/usr/bin:/bin"]
    ) {
        defer { probe.stop() }
        let execed = eventually {
            facts.incarnation(of: probe.pid).flatMap { facts.executablePath(of: $0) } == "/bin/sleep"
        }
        let child = facts.incarnation(of: probe.pid)
        let job = child.flatMap { facts.jobFacts(of: $0) }
        check(execed && job?.processGroup == probe.pid && job?.terminalProcessGroup == probe.pid,
              "live facts: the /dev/null probe still leads the PTY's foreground group")
        var devNullIsOtherDevice = false
        if case let .characterDevice(device)? = child.flatMap({ facts.fdCharDevice(of: $0, fd: 0) }),
           let terminal = job?.terminalDevice {
            devNullIsOtherDevice = device != terminal
        }
        check(devNullIsOtherDevice,
              "live facts: fd 0 /dev/null is a character device, but not the terminal")
        check(child.map { facts.interactivity(of: $0) } == .notInteractive(.standardInputNotTerminal),
              "live facts: a foreground leader reading /dev/null is not interactive")
    } else {
        check(false, "live facts: the /dev/null probe spawns")
    }

    // A background member of the PTY's session: the job of a non-interactive
    // shell stays in the shell's process group.
    if let probe = spawnProbe(
        path: "/bin/sh", argv: ["/bin/sh", "-c", "/bin/sleep 30 & wait"],
        environment: ["PATH=/usr/bin:/bin"]
    ) {
        defer { probe.stop() }
        var member: ProcessIncarnation?
        _ = eventually {
            member = (facts.liveProcesses() ?? []).first { candidate in
                facts.parent(of: candidate.pid) == probe.pid
                    && facts.executablePath(of: candidate) == "/bin/sleep"
            }
            return member != nil
        }
        if let member {
            check(facts.interactivity(of: member) == .notInteractive(.notProcessGroupLeader),
                  "live facts: a job inside another process group is not interactive")
            let chain = facts.incarnation(of: probe.pid).map { shell in
                ClaudeSessionFacts.verifiedAncestry(of: member, hops: 2, provider: facts)
                    == [member, shell, facts.incarnation(of: getpid())].compactMap { $0 }
            }
            check(chain == true,
                  "walk: the live chain sleep → sh → this process verifies against the kernel")
        } else {
            check(false, "live facts: the background sleep is found by enumeration")
        }
    } else {
        check(false, "live facts: the background-job probe spawns")
    }

    // fd 0 a pipe, spawned outside any PTY.
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sleep")
    process.arguments = ["30"]
    let input = Pipe()
    process.standardInput = input
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
        defer {
            process.terminate()
            process.waitUntilExit()
        }
        let child = facts.incarnation(of: process.processIdentifier)
        check(child.flatMap { facts.fdCharDevice(of: $0, fd: 0) } == .other,
              "live facts: fd 0 a pipe reads as not a character device")
        check(child.map { facts.interactivity(of: $0).isInteractive } == false,
              "live facts: a child reading a pipe is not interactive")
    } catch {
        check(false, "live facts: the pipe probe spawns (\(error))")
    }
}

private func liveArgumentLayoutTests() {
    let facts = LiveClaudeSessionFactProvider()
    // argv[0] "" is indistinguishable from the exec path's alignment padding
    // unless the padding is measured; a parser that skips every NUL would
    // shift the first environment entry into argv, and the rest of the
    // environment out of view.
    guard let probe = spawnSelftestProbe(
        argv0: "",
        environment: ["BUN_OPTIONS=--csec-selftest-synthetic-preload", "NODE_OPTIONS=--csec-selftest"]
    ) else {
        check(false, "argv layout: the empty-argv[0] probe spawns")
        return
    }
    defer { probe.stop() }
    guard let child = facts.incarnation(of: probe.pid) else {
        check(false, "argv layout: the empty-argv[0] probe is live")
        return
    }
    check(facts.argv(of: child) == nil,
          "argv layout: an empty argv[0] makes argv unreadable rather than shifted")
    check(facts.envPresence(of: child, names: ["BUN_OPTIONS"], prefixes: []) == nil,
          "argv layout: an empty argv[0] makes environment presence unreadable, never clean")
    check(facts.envValues(of: child, allowlistedKeys: ["NODE_OPTIONS"]) == nil
            && ProcessAncestry.environmentSubset(of: probe.pid, keys: ["NODE_OPTIONS"]) == nil,
          "argv layout: an empty argv[0] makes environment values unreadable")
}

private func liveEnvironmentEdgeTests() {
    let facts = LiveClaudeSessionFactProvider()

    // An empty environment entry does not end the environment.
    if let probe = spawnSelftestProbe(
        environment: ["", "BUN_OPTIONS=--csec-selftest-synthetic-preload", "NODE_OPTIONS=--csec-selftest"]
    ), let child = facts.incarnation(of: probe.pid) {
        defer { probe.stop() }
        check(facts.envPresence(of: child, names: ["BUN_OPTIONS"], prefixes: [])?.names == ["BUN_OPTIONS": 1],
              "environment: a name after an empty environment entry is still seen")
        check(facts.envValues(of: child, allowlistedKeys: ["NODE_OPTIONS"]) == ["NODE_OPTIONS": "--csec-selftest"],
              "environment: a value after an empty environment entry is still read")
    } else {
        check(false, "environment: the empty-entry probe spawns")
    }

    // A duplicated allow-listed key is ambiguous: which one the process honours
    // is its runtime's choice, not knowable from outside.
    if let probe = spawnSelftestProbe(
        environment: ["CLAUDE_CONFIG_DIR=/tmp/csec-selftest-a", "CLAUDE_CONFIG_DIR=/tmp/csec-selftest-b",
                      "NODE_OPTIONS=--csec-selftest"]
    ), let child = facts.incarnation(of: probe.pid) {
        defer { probe.stop() }
        check(facts.envPresence(of: child, names: ["CLAUDE_CONFIG_DIR"], prefixes: [])?.names
                == ["CLAUDE_CONFIG_DIR": 2],
              "environment: presence counts a duplicated name")
        check(facts.envValues(of: child, allowlistedKeys: ["CLAUDE_CONFIG_DIR"]) == nil,
              "environment: a duplicated allow-listed key is unreadable")
        check(facts.envValues(of: child, allowlistedKeys: ["NODE_OPTIONS"]) == ["NODE_OPTIONS": "--csec-selftest"],
              "environment: an unduplicated key beside it is still read")
    } else {
        check(false, "environment: the duplicate-key probe spawns")
    }

    // The kernel withholds the environment of a restricted process by ending
    // the block at argv. Whatever this macOS restricts, an environment must
    // never read as clean when the marker is in it: either unreadable, or seen.
    var withheld = 0
    var readable = 0
    for path in ["/bin/zsh", "/bin/bash", "/bin/ksh"] where FileManager.default.isExecutableFile(atPath: path) {
        guard let probe = spawnProbe(
            path: path, argv: [path, "-c", "/bin/sleep 30; :"],
            environment: ["PATH=/usr/bin:/bin", "BUN_OPTIONS=--csec-selftest-synthetic-preload"]
        ) else { continue }
        defer { probe.stop() }
        guard let child = facts.incarnation(of: probe.pid) else { continue }
        let presence = facts.envPresence(of: child, names: ["BUN_OPTIONS"], prefixes: [])
        if presence == nil {
            withheld += 1
            check(facts.envValues(of: child, allowlistedKeys: ["NODE_OPTIONS"]) == nil
                    && ProcessAncestry.environmentSubset(of: probe.pid, keys: ["PATH"]) == nil,
                  "environment: \(path)'s withheld environment is unreadable for values too")
        } else {
            readable += 1
            check(presence?.names == ["BUN_OPTIONS": 1],
                  "environment: \(path)'s readable environment shows the synthetic name")
        }
        check(facts.argv(of: child) == [path, "-c", "/bin/sleep 30; :"],
              "environment: \(path)'s argv reads whether or not its environment is withheld")
    }
    print("info - shell probes: \(withheld) with a withheld environment, \(readable) readable")
}

// MARK: - KERN_PROCARGS2 layout

/// A KERN_PROCARGS2-shaped block: argc, the exec path, NUL padding (by
/// default exactly what xnu writes: up to the next 8-byte offset from the path),
/// then each string NUL-terminated.
private func procargsBlock(argc: Int32, path: String, padding: [UInt8]? = nil, strings: [String]) -> [UInt8] {
    var block = withUnsafeBytes(of: argc) { Array($0) }
    block += Array(path.utf8)
    let length = path.utf8.count
    block += padding ?? [UInt8](repeating: 0, count: ((length + 1 + 7) & ~7) - length)
    for string in strings { block += Array(string.utf8) + [0] }
    return block
}

/// `cs_procargs_layout` over `block` as if the kernel returned it into a
/// buffer of `capacity` bytes: argc and the argv strings, or nil.
private func layout(_ block: [UInt8], capacity: Int? = nil, requireEnvironment: Bool = true) -> (argc: Int32, argv: [String])? {
    var argvOffset: UInt64 = 0
    var afterArgvOffset: UInt64 = 0
    let argc = block.withUnsafeBufferPointer { bytes in
        bytes.withMemoryRebound(to: CChar.self) { characters in
            cs_procargs_layout(
                characters.baseAddress, UInt64(block.count), UInt64(capacity ?? block.count + 64),
                requireEnvironment ? 1 : 0, &argvOffset, &afterArgvOffset
            )
        }
    }
    guard argc >= 0 else { return nil }
    let argvBytes = block[Int(argvOffset)..<Int(afterArgvOffset)]
    let argv = argvBytes.split(separator: 0, omittingEmptySubsequences: false).dropLast()
        .map { String(decoding: $0, as: UTF8.self) }
    return (argc, Array(argv))
}

private func procargsLayoutTests() {
    let apple = ["ptr_munge=", "main_stack="]
    let wellFormed = procargsBlock(
        argc: 2, path: "/bin/probe", strings: ["probe", "30", "BUN_OPTIONS=x", "", "Q=1"] + apple
    )
    let parsed = layout(wellFormed)
    check(parsed?.argc == 2 && parsed?.argv == ["probe", "30"],
          "procargs: a well-formed block yields exactly its argv")
    check(layout(wellFormed, capacity: wellFormed.count) == nil,
          "procargs: a block that fills the buffer is unreadable, even an exact fit")
    check(layout([0, 0, 0], capacity: 64) == nil, "procargs: a block shorter than argc is unreadable")

    // The reviewer's truncated layouts (A4 review F1). The kernel keeps the
    // tail of a block larger than the buffer, argc still in front: a run of a
    // large environment entry, NULs, then later entries. When the run's length
    // and the NULs line up with xnu's padding rule, the tail parses as a path
    // and an argv of environment entries. Only the size rule refuses it.
    var refusedAtCapacity = 0
    var wouldParseUncapped = 0
    var shapes = 0
    for runLength in 8..<24 {
        for emptyEntries in 0..<8 {
            let tail = procargsBlock(
                argc: 1, path: String(repeating: "a", count: runLength),
                padding: [UInt8](repeating: 0, count: 1 + emptyEntries),
                strings: ["Q=1", "R=2"] + apple
            )
            shapes += 1
            if layout(tail, capacity: tail.count) == nil { refusedAtCapacity += 1 }
            if let shifted = layout(tail), shifted.argv == ["Q=1"] { wouldParseUncapped += 1 }
        }
    }
    check(refusedAtCapacity == shapes,
          "procargs: every truncated tail (\(shapes) shapes) that fills the buffer is unreadable")
    check(wouldParseUncapped > 0,
          "procargs: \(wouldParseUncapped) of those tails would parse with an environment entry as argv[0] "
            + "if the size rule were absent, so the rule is load-bearing")

    check(layout(procargsBlock(argc: 2, path: "/bin/probe", strings: ["", "30", "K=V"] + apple)) == nil,
          "procargs: an empty argv[0] is unreadable")
    var dirtyPadding = [UInt8](repeating: 0, count: 6)
    dirtyPadding[3] = UInt8(ascii: "x")
    check(layout(procargsBlock(argc: 1, path: "/bin/probe", padding: dirtyPadding, strings: ["probe", "K=V"] + apple)) == nil,
          "procargs: padding that is not all NUL is unreadable")
    check(layout(procargsBlock(argc: 1, path: "/bin/probe", padding: [0, 0], strings: ["probe", "K=V"] + apple)) == nil,
          "procargs: argv[0] off xnu's alignment is unreadable")
    let withheld = procargsBlock(argc: 2, path: "/bin/probe", strings: ["probe", "30"])
    check(layout(withheld) == nil && layout(withheld, requireEnvironment: false)?.argv == ["probe", "30"],
          "procargs: nothing after argv is an unreadable environment, while argv still reads")
    check(layout(procargsBlock(argc: 5, path: "/bin/probe", strings: ["probe", "30"])) == nil,
          "procargs: an argc larger than the strings present is unreadable")
    check(layout(procargsBlock(argc: -1, path: "/bin/probe", strings: ["probe"] + apple)) == nil,
          "procargs: a negative argc is unreadable")
    let unterminated = withUnsafeBytes(of: Int32(1)) { Array($0) } + Array("/bin/probe".utf8)
    check(layout(unterminated) == nil, "procargs: an unterminated exec path is unreadable")
    let withEmptyEntries = procargsBlock(argc: 1, path: "/bin/probe", strings: ["probe", "", "", "K=V"] + apple)
    check(layout(withEmptyEntries)?.argv == ["probe"],
          "procargs: empty environment entries after argv leave argv intact")
}

private func procargsSize(of pid: pid_t) -> Int? {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0 else { return nil }
    return size
}

private func argumentMaximum() -> Int? {
    var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
    var value: Int32 = 0
    var size = MemoryLayout<Int32>.size
    guard sysctl(&mib, 2, &value, &size, nil, 0) == 0, value > 0 else { return nil }
    return Int(value)
}

/// A live process whose argv+environment block is larger than kern.argmax,
/// so the kernel returns only its tail: every reader must call it unreadable.
/// The environment has the reviewer's shape (a banned name, one huge entry,
/// empty entries, then short entries), across every alignment of the cut.
private func liveOversizedArgumentBlockTests() {
    let facts = LiveClaudeSessionFactProvider()
    guard let selfPath = selftestExecutablePath(), let capacity = argumentMaximum() else {
        check(false, "oversized block: this binary and kern.argmax are known")
        return
    }
    func environment(pad: Int, emptyEntries: Int) -> [String] {
        ["BUN_OPTIONS=--csec-selftest-synthetic-preload", "PAD=" + String(repeating: "a", count: pad)]
            + [String](repeating: "", count: emptyEntries) + ["Q=1", "R=2"]
    }
    // The largest entry exec accepts with the most entries used below.
    var low = capacity - 64 * 1_024
    var high = capacity
    guard let floor = spawnSelftestProbe(environment: environment(pad: low, emptyEntries: 7)) else {
        check(false, "oversized block: a probe with a large environment spawns")
        return
    }
    floor.stop()
    while high - low > 1 {
        let middle = (low + high) / 2
        if let probe = spawnSelftestProbe(environment: environment(pad: middle, emptyEntries: 7)) {
            probe.stop()
            low = middle
        } else {
            high = middle
        }
    }

    var truncated = 0
    var complete = 0
    var truncatedReadable = 0
    var completeUnreadable = 0
    let pads = (0..<8).map { low - $0 } + [low - 4_096]
    for pad in pads {
        for emptyEntries in 0..<8 {
            guard let probe = spawnSelftestProbe(environment: environment(pad: pad, emptyEntries: emptyEntries)) else {
                check(false, "oversized block: a probe with pad \(pad) and \(emptyEntries) empty entries spawns")
                continue
            }
            defer { probe.stop() }
            guard let child = facts.incarnation(of: probe.pid), let size = procargsSize(of: probe.pid) else {
                continue
            }
            let argv = facts.argv(of: child)
            let presence = facts.envPresence(of: child, names: ["BUN_OPTIONS"], prefixes: [])
            let values = facts.envValues(of: child, allowlistedKeys: ["NODE_OPTIONS"])
            let subset = ProcessAncestry.environmentSubset(of: probe.pid, keys: ["Q"])
            if size >= capacity {
                truncated += 1
                if argv != nil || presence != nil || values != nil || subset != nil { truncatedReadable += 1 }
            } else {
                complete += 1
                // A block that fits must parse exactly. Under heavy concurrent
                // load the kernel copy itself can still fail (EIO) after the
                // shim's retries, which is an unreadable read, not a parse:
                // re-read a few times so only a failure that persists counts.
                func readsExactly() -> Bool {
                    facts.argv(of: child) == [selfPath, "--session-facts-probe"]
                        && facts.envPresence(of: child, names: ["BUN_OPTIONS"], prefixes: [])?.names
                            == ["BUN_OPTIONS": 1]
                        && facts.envValues(of: child, allowlistedKeys: ["NODE_OPTIONS"]) == [:]
                        && ProcessAncestry.environmentSubset(of: probe.pid, keys: ["Q"]) == ["Q": "1"]
                }
                if argv != [selfPath, "--session-facts-probe"] || presence?.names != ["BUN_OPTIONS": 1]
                    || values != [:] || subset != ["Q": "1"] {
                    if !(0..<4).contains(where: { _ in usleep(20_000); return readsExactly() }) {
                        completeUnreadable += 1
                    }
                }
            }
        }
    }
    print("info - oversized block: \(truncated) layouts beyond kern.argmax (\(capacity)), \(complete) within")
    check(truncated > 0 && truncatedReadable == 0,
          "oversized block: argv, presence, values and the subset are all unreadable for every layout beyond "
            + "kern.argmax (\(truncatedReadable) of \(truncated) read)")
    check(complete > 0 && completeUnreadable == 0,
          "oversized block: a large block within kern.argmax still reads exactly (\(completeUnreadable) of \(complete) did not)")
}

// MARK: - Task audit token

private func taskAuditTokenFallbackTests() {
    let me = getpid()
    guard let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "task token: this process has a start time")
        return
    }
    check(ForeignCodeIdentity.resolve(
        pid: me, startTime: myStart, taskAuditToken: { _ in .changed(kernelStatus: KERN_FAILURE) }
    ) == nil,
          "task token: a failure after the name port was granted returns nil, never the PID fallback")
    let refused = ForeignCodeIdentity.resolve(
        pid: me, startTime: myStart, taskAuditToken: { _ in .refused(kernelStatus: KERN_FAILURE) }
    )
    check(refused?.lookup == .processID(taskNameStatus: KERN_FAILURE)
            && refused?.lookup.logDescription.contains("task_name_for_pid refused") == true,
          "task token: only a refused task_name_for_pid takes the PID fallback, and says so")
    if case .token = AuditIdentity.task(pid: me) {
        check(true, "task token: this process's own token reads")
    } else {
        check(false, "task token: this process's own token reads")
    }

    // A PID with no process: task_name_for_pid itself refuses (-1), so it is
    // `.refused`, and the fallback's start-time check then finds no process.
    let exited = Process()
    exited.executableURL = URL(fileURLWithPath: "/usr/bin/true")
    do {
        try exited.run()
        exited.waitUntilExit()
        if case .refused = AuditIdentity.task(pid: exited.processIdentifier) {
            check(true, "task token: an exited PID is refused by task_name_for_pid")
        } else if ProcessAncestry.startTime(of: exited.processIdentifier) != nil {
            print("skip - task token: the exited PID was already reused")
        } else {
            check(false, "task token: an exited PID is refused by task_name_for_pid")
        }
    } catch {
        check(false, "task token: /usr/bin/true runs (\(error))")
    }
}

// MARK: - Working directory

private func fileSystemID(of path: String) -> FileSystemID? {
    var info = statfs()
    guard statfs(path, &info) == 0 else { return nil }
    return FileSystemID(info.f_fsid.val.0, info.f_fsid.val.1)
}

/// Spawn /bin/sleep entering `directory` by exactly that path, then run
/// `after` (to rename or remove it) before `body` reads its cwd.
private func withSleeper(
    in directory: String, after: () -> Void = {}, _ body: (LiveClaudeSessionFactProvider, ProcessIncarnation) -> Void
) {
    let facts = LiveClaudeSessionFactProvider()
    guard let probe = spawnProbe(
        path: "/bin/sleep", argv: ["/bin/sleep", "30"], environment: ["PATH=/usr/bin:/bin"],
        workingDirectory: directory
    ) else {
        check(false, "cwd: /bin/sleep spawns in \(directory)")
        return
    }
    defer { probe.stop() }
    after()
    guard let child = facts.incarnation(of: probe.pid) else {
        check(false, "cwd: the sleeper in \(directory) is live")
        return
    }
    body(facts, child)
}

/// The script a real `/bin/bash` runs, read from fd 255 as csecd reads a
/// pinned launcher script, and the status-change time that pin check rests on.
private func liveOpenFileTests() {
    guard let base = makeProbeDirectory().flatMap(realPath) else { return }
    defer { try? FileManager.default.removeItem(atPath: base) }
    let script = base + "/script.sh"
    let body = "#!/bin/bash\nsleep 30\n"
    guard FileManager.default.createFile(atPath: script, contents: Data(body.utf8)),
          chmod(script, 0o755) == 0 else {
        check(false, "open file: the probe script is written")
        return
    }
    let facts = LiveClaudeSessionFactProvider()
    guard let probe = spawnProbe(
        path: "/bin/bash", argv: ["/bin/bash", script], environment: ["PATH=/usr/bin:/bin"],
        workingDirectory: base
    ) else {
        check(false, "open file: /bin/bash spawns with the probe script")
        return
    }
    defer { probe.stop() }
    guard let child = facts.incarnation(of: probe.pid) else {
        check(false, "open file: the bash probe is live")
        return
    }
    // bash opens its script before it runs a line of it; allow it a moment.
    var file: ProcessOpenFile?
    for _ in 0..<200 {
        file = facts.openFile(of: child, fd: 255)
        if file != nil { break }
        usleep(10_000)
    }
    var info = stat()
    let stated = stat(script, &info) == 0
    check(file?.vnode.path == script, "open file: bash holds its script on fd 255, by its real path")
    check(stated && file?.vnode.inode == UInt64(info.st_ino)
            && file?.vnode.device == UInt64(UInt32(bitPattern: info.st_dev)),
          "open file: fd 255's device and inode are the script's")
    check(stated && file?.vnode.size == Int64(info.st_size), "open file: fd 255's size is the script's")
    check(stated && file?.vnode.statusChange
            == FileTimestamp(seconds: Int64(info.st_ctimespec.tv_sec), nanoseconds: Int64(info.st_ctimespec.tv_nsec)),
          "open file: fd 255's status-change time is the script's st_ctime")
    check(file?.isOnLocalMounts == true, "open file: a script in the temporary directory is on local mounts")
    check(facts.openFile(of: child, fd: 0) == nil, "open file: a terminal on fd 0 is not a regular file")
    check(facts.openFile(of: child, fd: 200) == nil, "open file: a descriptor that is not open reads as nil")

    // Replacing the script by rename leaves bash reading the old, unlinked
    // file; the path no longer names it, so the read refuses it.
    let replacement = base + "/replacement.sh"
    if FileManager.default.createFile(atPath: replacement, contents: Data("#!/bin/bash\necho other\n".utf8)),
       rename(replacement, script) == 0 {
        check(facts.openFile(of: child, fd: 255) == nil,
              "open file: a script replaced by rename while bash runs it reads as nil")
    } else {
        check(false, "open file: the replacement script is renamed into place")
    }

    // The pin check's change-time rule rests on rename moving st_ctime: a
    // file swapped out and back by rename(2) is not the same as one untouched.
    let swapped = base + "/swapped.sh"
    let aside = base + "/aside.sh"
    var before = stat()
    var after = stat()
    if FileManager.default.createFile(atPath: swapped, contents: Data("x\n".utf8)),
       stat(swapped, &before) == 0 {
        usleep(20_000)
        let moved = rename(swapped, aside) == 0 && rename(aside, swapped) == 0
        check(moved && stat(swapped, &after) == 0
                && (after.st_ctimespec.tv_sec, after.st_ctimespec.tv_nsec)
                    > (before.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec),
              "open file: renaming a file away and back moves its st_ctime")
    } else {
        check(false, "open file: the rename probe file is written")
    }
}

private func liveWorkingDirectoryTests() {
    guard let base = makeProbeDirectory().flatMap(realPath) else { return }
    defer { try? FileManager.default.removeItem(atPath: base) }
    let manager = FileManager.default

    // Entered through a symlink: the kernel reports the target.
    if let tmp = realPath("/tmp"), tmp != "/tmp" {
        withSleeper(in: "/tmp") { facts, child in
            check(facts.cwd(of: child)?.directory.path == tmp,
                  "cwd: a directory entered as /tmp is reported by its target \(tmp)")
        }
    }
    let target = base + "/Target"
    let link = base + "/Link"
    if (try? manager.createDirectory(atPath: target, withIntermediateDirectories: false)) != nil,
       (try? manager.createSymbolicLink(atPath: link, withDestinationPath: target)) != nil {
        withSleeper(in: link) { facts, child in
            let directory = facts.cwd(of: child)?.directory
            var info = stat()
            check(directory?.path == target && stat(target, &info) == 0
                    && directory?.inode == UInt64(info.st_ino),
                  "cwd: a directory entered through a symlink is reported by its real path and inode")
        }
    } else {
        check(false, "cwd: the symlink fixture is created")
    }

    // Entered through the Data volume: the kernel reports the firmlinked
    // path, which realpath does not.
    if let entry = getpwuid(getuid()), let homePointer = entry.pointee.pw_dir {
        let home = String(cString: homePointer)
        let dataPath = "/System/Volumes/Data" + home
        if realPath(home) == home, manager.fileExists(atPath: dataPath) {
            withSleeper(in: dataPath) { facts, child in
                check(facts.cwd(of: child)?.directory.path == home,
                      "cwd: a directory entered through /System/Volumes/Data is reported by its firmlinked path")
            }
            check(realPath(dataPath) == dataPath,
                  "cwd: realpath leaves the Data-volume path as it is, so the kernel path is the more canonical one")
        } else {
            print("skip - cwd: no firmlinked home under /System/Volumes/Data")
        }
    }

    // Entered by a case variant on a case-insensitive volume: the on-disk case.
    let original = base + "/CaseProbe"
    let variant = base + "/CASEPROBE"
    var originalInfo = stat()
    var variantInfo = stat()
    if (try? manager.createDirectory(atPath: original, withIntermediateDirectories: false)) != nil,
       stat(original, &originalInfo) == 0 {
        if stat(variant, &variantInfo) == 0, variantInfo.st_ino == originalInfo.st_ino {
            withSleeper(in: variant) { facts, child in
                check(facts.cwd(of: child)?.directory.path == original,
                      "cwd: a directory entered by a case variant is reported in its on-disk case")
            }
        } else {
            print("skip - cwd: the probe volume is case-sensitive")
        }
    }

    // Renamed after the process entered it: the kernel follows the rename.
    let before = base + "/Before"
    let renamed = base + "/After"
    if (try? manager.createDirectory(atPath: before, withIntermediateDirectories: false)) != nil {
        withSleeper(in: before, after: { _ = rename(before, renamed) }) { facts, child in
            check(facts.cwd(of: child)?.directory.path == renamed,
                  "cwd: a directory renamed after the process entered it is reported by its new path")
        }
    }

    // Removed after the process entered it: the kernel keeps the last path,
    // so the presence check on a local mount is what refuses it.
    let gone = base + "/Gone"
    if (try? manager.createDirectory(atPath: gone, withIntermediateDirectories: false)) != nil {
        withSleeper(in: gone, after: { _ = rmdir(gone) }) { facts, child in
            check(ProcessAncestry.workingDirectoryVnode(of: child.pid)?.path == gone,
                  "cwd: the kernel keeps a removed directory's last path")
            check(facts.cwd(of: child) == nil,
                  "cwd: a directory removed after the process entered it is unavailable")
        }
    }

    // The mount table: cached, local-ness from MNT_LOCAL, matched by f_fsid.
    check(ProcessAncestry.pathIsOnLocalMounts("/") == true, "mounts: / is on local mounts")
    check(ProcessAncestry.pathIsOnLocalMounts("relative/path") == nil, "mounts: a relative path is refused")
    check(ProcessAncestry.mount(of: FileSystemID(0, 0)) == nil, "mounts: an unknown file-system ID has no mount")
    if let rootID = fileSystemID(of: "/") {
        check(ProcessAncestry.mount(of: rootID)?.isLocal == true
                && ProcessAncestry.mount(of: rootID)?.mountPoint == "/",
              "mounts: the root volume is found by its f_fsid and is local")
    }

    // A directory on a non-local mount. autofs's own directory is a
    // non-local mount the kernel serves without any network, so a process can
    // sit in it safely; its cwd is reported without any file-system call.
    var mounts: UnsafeMutablePointer<statfs>?
    let count = Int(getmntinfo(&mounts, MNT_NOWAIT))
    let autofsMountPoint = (0..<count).lazy.compactMap { index -> String? in
        guard var mount = mounts?[index], mount.f_flags & UInt32(MNT_LOCAL) == 0 else { return nil }
        let type = withUnsafeBytes(of: &mount.f_fstypename) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        let point = withUnsafeBytes(of: &mount.f_mntonname) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        return type == "autofs" ? point : nil
    }.first
    if let autofsMountPoint {
        check(ProcessAncestry.pathIsOnLocalMounts(autofsMountPoint + "/csec-selftest") == false,
              "mounts: a path under a non-local mount is not on local mounts")
        withSleeper(in: autofsMountPoint) { facts, child in
            let workingDirectory = facts.cwd(of: child)
            check(workingDirectory?.directory.path == autofsMountPoint
                    && workingDirectory?.isOnLocalMounts == false && workingDirectory?.mount.isLocal == false
                    && workingDirectory?.mount.fileSystemType == "autofs",
                  "cwd: a directory on a non-local mount is reported as such, unverified")
        }
    } else {
        print("skip - cwd: no autofs mount to stand in for a non-local one")
    }
}

// MARK: - Requirements

private func anthropicRequirementTests() {
    var pinned: SecRequirement?
    let created = SecRequirementCreateWithString(
        ForeignCodeIdentity.anthropicClaudeCodeRequirement as CFString, SecCSFlags(rawValue: 0), &pinned
    )
    var pinnedData: CFData?
    var canonical: CFString?
    if created == errSecSuccess, let pinned {
        _ = SecRequirementCopyData(pinned, SecCSFlags(rawValue: 0), &pinnedData)
        _ = SecRequirementCopyString(pinned, SecCSFlags(rawValue: 0), &canonical)
    }
    check(created == errSecSuccess && pinnedData != nil,
          "requirement: Anthropic's pinned designated requirement compiles")
    var recompiled: SecRequirement?
    var recompiledData: CFData?
    if let canonical,
       SecRequirementCreateWithString(canonical, SecCSFlags(rawValue: 0), &recompiled) == errSecSuccess,
       let recompiled {
        _ = SecRequirementCopyData(recompiled, SecCSFlags(rawValue: 0), &recompiledData)
    }
    check(pinnedData != nil && (pinnedData as Data?) == (recompiledData as Data?),
          "requirement: the pinned text round-trips through Security.framework unchanged")
    let text = ForeignCodeIdentity.anthropicClaudeCodeRequirement
    check(text.contains("anchor apple generic") && text.contains("certificate leaf[subject.OU] = Q6L2SF6YDW")
            && text.contains(#"identifier "com.anthropic.claude-code""#),
          "requirement: the pinned text names the identifier, Apple's anchor and Anthropic's team")
}

/// Opt-in (CSEC_SELFTEST_LIVE_CLAUDE=1): check the pinned requirement against
/// the installed Claude Code and every live Claude Code session of this user.
/// Never required: CI has no Claude Code.
private func liveClaudeOptInTests() {
    guard ProcessInfo.processInfo.environment["CSEC_SELFTEST_LIVE_CLAUDE"] == "1" else {
        print("skip - live Claude Code identity (set CSEC_SELFTEST_LIVE_CLAUDE=1)")
        return
    }
    let facts = LiveClaudeSessionFactProvider()
    let versions = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".local/share/claude/versions", isDirectory: true)
    let installed = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".local/bin/claude").resolvingSymlinksInPath()
    var staticCode: SecStaticCode?
    var designated: SecRequirement?
    var designatedText: CFString?
    var pinned: SecRequirement?
    var pinnedText: CFString?
    if SecStaticCodeCreateWithPath(installed as CFURL, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
       let staticCode,
       SecCodeCopyDesignatedRequirement(staticCode, SecCSFlags(rawValue: 0), &designated) == errSecSuccess,
       let designated,
       SecRequirementCreateWithString(
        ForeignCodeIdentity.anthropicClaudeCodeRequirement as CFString, SecCSFlags(rawValue: 0), &pinned
       ) == errSecSuccess, let pinned {
        // The embedded requirement nests its `and`s to the right and the text
        // compiler to the left, so the bytes differ; the canonical text is the
        // comparison that means "the same requirement".
        _ = SecRequirementCopyString(designated, SecCSFlags(rawValue: 0), &designatedText)
        _ = SecRequirementCopyString(pinned, SecCSFlags(rawValue: 0), &pinnedText)
        check(designatedText != nil && (designatedText as String?) == (pinnedText as String?),
              "live Claude: the pinned requirement is \(installed.lastPathComponent)'s designated requirement")
    } else {
        print("skip - live Claude: no signed ~/.local/bin/claude to compare")
    }

    // Every installed version, statically: Anthropic's builds satisfy the pinned
    // requirement; any other build (a locally patched one) does not, and is
    // matched by its own cdhash instead.
    let installedVersions = (try? FileManager.default.contentsOfDirectory(atPath: versions.path)) ?? []
    for version in installedVersions.sorted() {
        let url = versions.appendingPathComponent(version)
        var code: SecStaticCode?
        var information: CFDictionary?
        guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(rawValue: 0), &code) == errSecSuccess,
              let code, let pinned,
              SecCodeCopySigningInformation(
                code, SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)), &information
              ) == errSecSuccess,
              let dictionary = information as? [String: Any] else { continue }
        let strict = SecCSFlags(rawValue: UInt32(kSecCSStrictValidate))
        let satisfiesPinned = SecStaticCodeCheckValidity(code, strict, pinned) == errSecSuccess
        let team = dictionary[kSecCodeInfoTeamIdentifier as String] as? String
        let cdHash = (dictionary[kSecCodeInfoUnique as String] as? Data)?
            .map { String(format: "%02x", $0) }.joined()
        var byHash: SecRequirement?
        let matchesOwnHash = cdHash.map { hash in
            SecRequirementCreateWithString("cdhash H\"\(hash)\"" as CFString, SecCSFlags(rawValue: 0), &byHash)
                == errSecSuccess && byHash.map { SecStaticCodeCheckValidity(code, strict, $0) } == errSecSuccess
        } ?? false
        print("info - installed Claude \(version): team \(team ?? "none"), pinned requirement \(satisfiesPinned)")
        if team == "Q6L2SF6YDW" {
            check(satisfiesPinned, "live Claude: Anthropic-signed \(version) satisfies the pinned requirement statically")
        } else {
            check(!satisfiesPinned && matchesOwnHash,
                  "live Claude: \(version), not signed by Anthropic, fails the pinned requirement and matches its own cdhash")
        }
    }

    let sessions = (facts.liveProcesses() ?? []).filter { process in
        facts.executablePath(of: process)?.hasPrefix(versions.path + "/") == true
    }
    if sessions.isEmpty { print("skip - live Claude: no live Claude Code session") }
    for session in sessions {
        guard let identity = facts.codeIdentity(of: session, parentOf: nil, trustedCDHashes: []) else { continue }
        let version = facts.executablePath(of: session).map { ($0 as NSString).lastPathComponent } ?? "?"
        var collection: [Double] = []
        var resolution: [Double] = []
        for _ in 0..<10 {
            collection.append(milliseconds {
                _ = facts.jobFacts(of: session)
                _ = facts.fdCharDevice(of: session, fd: 0)
                _ = facts.cwd(of: session)
                _ = facts.argv(of: session)
                _ = facts.envPresence(of: session, names: ["BUN_OPTIONS", "CLAUDECODE"], prefixes: ["DYLD_"])
                _ = facts.envValues(of: session, allowlistedKeys: ["NODE_OPTIONS", "CLAUDE_CONFIG_DIR"])
            })
            resolution.append(milliseconds {
                _ = facts.codeIdentity(of: session, parentOf: nil, trustedCDHashes: [])
            })
        }
        let timing = String(
            format: "facts median %.3f ms, identity median %.3f ms", median(collection), median(resolution)
        )
        print("info - live Claude \(version) (pid \(session.pid)) via \(identity.lookup.logDescription): "
              + "anthropic=\(identity.satisfiesAnthropicRequirement) runtime=\(identity.hardenedRuntime) "
              + "interactive=\(facts.interactivity(of: session).isInteractive) \(timing)")
        // The facts the gates read must be readable on a real session: its
        // argv (counted, never shown), its environment names, and its cwd.
        let argumentCount = facts.argv(of: session)?.count
        let environmentReadable = facts.envPresence(of: session, names: ["CLAUDECODE"], prefixes: ["DYLD_"]) != nil
        check(argumentCount != nil && environmentReadable && facts.cwd(of: session) != nil
                && facts.envValues(of: session, allowlistedKeys: ["NODE_OPTIONS", "CLAUDE_CONFIG_DIR"]) != nil,
              "live Claude: \(version) (pid \(session.pid)) has readable argv (\(argumentCount ?? -1) entries), environment and cwd")
        if identity.teamIdentifier != nil {
            check(identity.satisfiesAnthropicRequirement && identity.isClaudeCode,
                  "live Claude: Anthropic-signed \(version) satisfies the pinned requirement")
        } else if let cdHash = identity.cdHash {
            check(!identity.satisfiesAnthropicRequirement
                    && facts.codeIdentity(of: session, parentOf: nil, trustedCDHashes: [cdHash])?.isClaudeCode == true,
                  "live Claude: unsigned-by-Anthropic \(version) fails the requirement and passes when its cdhash is trusted")
        }
    }
}
