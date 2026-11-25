import ConvenientSecurity
import Darwin
import Foundation

/// A job a coding agent's tool shell detached stays linked to the agent's
/// process tree through its session (`SessionLineage`), and only while the
/// kernel's facts prove it.

/// A synthetic kernel: processes with a parent, a session and a unique ID,
/// where exiting re-parents children to launchd and every spawn takes the next
/// unique ID, as xnu does.
final class FakeLineageKernel: @unchecked Sendable {
    struct Process {
        var parent: pid_t
        var session: pid_t
        let uniqueID: UInt64
        let startTime: UInt64
        /// False for another user's process (login is root's).
        var readable: Bool
    }

    private let lock = NSLock()
    private var processes: [pid_t: Process] = [:]
    private var lastUniqueID: UInt64 = 5_000_000
    private var maximumProcessesValue: Int? = 16_000
    private var afterLineageRead: (@Sendable (pid_t) -> Void)?

    /// Start `pid` as a child of `parent`, in the parent's session unless it
    /// starts its own. Launchd's children share launchd's session, 1.
    @discardableResult
    func spawn(_ pid: pid_t, parent: pid_t, leadsSession: Bool = false, readable: Bool = true) -> pid_t {
        lock.withLock {
            lastUniqueID += 1
            let session = leadsSession ? pid : (processes[parent]?.session ?? 1)
            processes[pid] = Process(
                parent: parent, session: session, uniqueID: lastUniqueID,
                startTime: 1_790_000_000_000_000 + lastUniqueID, readable: readable
            )
        }
        return pid
    }

    /// Other processes forked elsewhere on the machine meanwhile.
    func forkElsewhere(_ count: UInt64) {
        lock.withLock { lastUniqueID += count }
    }

    /// The process exits and is reaped; its children are re-parented to launchd.
    func exit(_ pid: pid_t) {
        lock.withLock {
            processes.removeValue(forKey: pid)
            for (child, process) in processes where process.parent == pid {
                processes[child]?.parent = 1
            }
        }
    }

    func setMaximumProcesses(_ value: Int?) {
        lock.withLock { maximumProcessesValue = value }
    }

    func afterReading(_ hook: (@Sendable (pid_t) -> Void)?) {
        lock.withLock { afterLineageRead = hook }
    }

    func uniqueID(_ pid: pid_t) -> UInt64 { lock.withLock { processes[pid]?.uniqueID ?? 0 } }
    func startTime(_ pid: pid_t) -> UInt64? { lock.withLock { processes[pid]?.startTime } }
    func kernelParent(_ pid: pid_t) -> pid_t? { lock.withLock { processes[pid]?.parent } }

    var facts: SessionLineage.Facts {
        SessionLineage.Facts(
            kernelParent: { [self] in kernelParent($0) },
            lineage: { [self] pid in
                let read: ProcessLineageFacts? = lock.withLock {
                    guard let process = processes[pid], process.readable else { return nil }
                    return ProcessLineageFacts(
                        pid: pid, parent: process.parent, session: process.session,
                        uniqueID: process.uniqueID, startTime: process.startTime
                    )
                }
                let hook = lock.withLock { afterLineageRead }
                hook?(pid)
                return read
            },
            maximumProcesses: { [self] in lock.withLock { maximumProcessesValue } }
        )
    }

    func inspection(
        lineage: SessionLineage?,
        names: [pid_t: String] = [:],
        paths: [pid_t: String] = [:],
        terminals: Set<pid_t> = []
    ) -> ProcessInspection {
        ProcessInspection(
            startTime: { [self] in startTime($0) },
            parent: { [self] in kernelParent($0) },
            name: { names[$0] },
            executablePath: { paths[$0] ?? "/usr/bin/\(names[$0] ?? "unknown")" },
            hasControllingTerminal: { terminals.contains($0) },
            lineageParent: lineage.map { lineage in { @Sendable pid in lineage.parent(of: pid) } }
        )
    }
}

/// The measured Claude-under-iTerm shape: every tool shell leads its own
/// session, a child of Claude; login is root's and unreadable.
struct FakeClaudeSession {
    static let iTerm: pid_t = 1_602
    static let iTermServer: pid_t = 1_642
    static let login: pid_t = 2_584
    static let fish: pid_t = 2_589
    static let claude: pid_t = 31_163
    static let toolShell: pid_t = 65_048
    static let csecAI: pid_t = 65_051
    static let command: pid_t = 65_054
    static let subshell: pid_t = 65_055
    static let job: pid_t = 65_056
    /// An `ssh` the tool call runs itself, inside the tree.
    static let inTreeSSH: pid_t = 65_060
    /// An `ssh` the detached job runs.
    static let ssh: pid_t = 65_070

    static let names: [pid_t: String] = [
        iTerm: "iTerm2", iTermServer: "iTermServer", login: "login", fish: "fish",
        claude: "2.1.257", toolShell: "zsh", csecAI: "csec", command: "zsh",
        subshell: "zsh", job: "bash", inTreeSSH: "ssh", ssh: "ssh",
    ]
    static let paths: [pid_t: String] = [
        claude: "/Users/tester/.local/share/claude/versions/2.1.257",
    ]
    static let terminals: Set<pid_t> = [login, fish, claude]

    let kernel = FakeLineageKernel()

    /// Claude runs `csec ai -- '( job & ); …'`: the subshell forks the job and
    /// exits at once, detaching it while the tool shell still runs.
    init() {
        kernel.spawn(Self.iTerm, parent: 1)
        kernel.spawn(Self.iTermServer, parent: Self.iTerm)
        kernel.spawn(Self.login, parent: Self.iTermServer, leadsSession: true, readable: false)
        kernel.spawn(Self.fish, parent: Self.login)
        kernel.spawn(Self.claude, parent: Self.fish)
        kernel.spawn(Self.toolShell, parent: Self.claude, leadsSession: true)
        kernel.spawn(Self.csecAI, parent: Self.toolShell)
        kernel.spawn(Self.command, parent: Self.csecAI)
        kernel.spawn(Self.subshell, parent: Self.command)
        kernel.spawn(Self.job, parent: Self.subshell)
        kernel.exit(Self.subshell)
    }

    /// The tool call ends: its shell, csec ai and the command exit.
    func endToolCall() {
        kernel.exit(Self.command)
        kernel.exit(Self.csecAI)
        kernel.exit(Self.toolShell)
    }

    func inspection(_ lineage: SessionLineage?) -> ProcessInspection {
        kernel.inspection(lineage: lineage, names: Self.names, paths: Self.paths, terminals: Self.terminals)
    }
}

func sessionLineageTests() async {
    print("\n# Session lineage (a detached job stays in the tree that started it)")

    check(SessionLineage.reuseMargin(maximumProcesses: 16_000) == 25_950,
          "the reuse margin is half of 99,900 − 3 × kern.maxproc allocations")
    check(SessionLineage.reuseMargin(maximumProcesses: 33_300) == nil
            && SessionLineage.reuseMargin(maximumProcesses: 33_299) == 1,
          "a kern.maxproc that leaves no margin disables the session link")

    // While the tool shell still runs, the detached job's session leader is
    // its ancestor by session membership: no record needed.
    do {
        let session = FakeClaudeSession()
        let lineage = SessionLineage(facts: session.kernel.facts)
        session.kernel.spawn(FakeClaudeSession.ssh, parent: FakeClaudeSession.job)
        check(session.kernel.kernelParent(FakeClaudeSession.job) == 1,
              "the detached job's kernel parent is launchd")
        check(lineage.parent(of: FakeClaudeSession.job) == FakeClaudeSession.toolShell,
              "while the tool shell runs, a job it detached has the tool shell as lineage parent")
        let inspection = session.inspection(lineage)
        check(inspection.descends(
            FakeClaudeSession.ssh, from: FakeClaudeSession.claude,
            rootStartTime: session.kernel.startTime(FakeClaudeSession.claude)!
        ), "an ssh the detached job runs descends from Claude while the tool shell runs")
        check(lineage.parent(of: FakeClaudeSession.ssh) == FakeClaudeSession.job,
              "a process whose kernel parent is not launchd keeps its kernel parent")
    }

    // The tool call ends. Only the record csec ai's call made links the job.
    do {
        let session = FakeClaudeSession()
        let lineage = SessionLineage(facts: session.kernel.facts)
        lineage.record(from: FakeClaudeSession.csecAI)
        let record = lineage.recorded(session: FakeClaudeSession.toolShell)
        check(record?.leaderUniqueID == session.kernel.uniqueID(FakeClaudeSession.toolShell)
                && record?.parent == SessionLineage.Incarnation(
                    pid: FakeClaudeSession.claude, uniqueID: session.kernel.uniqueID(FakeClaudeSession.claude)),
              "a csec call records its tool shell and the shell's parent, Claude")
        session.endToolCall()
        session.kernel.spawn(FakeClaudeSession.ssh, parent: FakeClaudeSession.job)

        check(lineage.parent(of: FakeClaudeSession.job) == FakeClaudeSession.claude,
              "after the tool shell exits, a recorded session links its detached job to Claude")
        let inspection = session.inspection(lineage)
        let claudeStart = session.kernel.startTime(FakeClaudeSession.claude)!
        check(inspection.descends(FakeClaudeSession.ssh, from: FakeClaudeSession.claude, rootStartTime: claudeStart)
                && inspection.descends(
                    FakeClaudeSession.ssh, from: FakeClaudeSession.fish,
                    rootStartTime: session.kernel.startTime(FakeClaudeSession.fish)!
                ),
              "an ssh the detached job runs later descends from Claude and from the terminal's shell")
        check(!inspection.descends(FakeClaudeSession.ssh, from: FakeClaudeSession.claude, rootStartTime: claudeStart + 1),
              "the link never matches another incarnation of Claude's pid")

        let choices = GrantScopeInspector.choices(
            planRootPID: FakeClaudeSession.ssh,
            planRootStartTime: session.kernel.startTime(FakeClaudeSession.ssh)!,
            requestingLabel: "ssh", inspection: inspection
        )
        check(choices.options.map(\.kind) == [.requestingCommand, .codingAgent, .terminalSession]
                && choices.defaultOption.kind == .codingAgent
                && choices.defaultOption.pid == FakeClaudeSession.claude,
              "a detached job's ssh is offered Claude's session, pre-selected, and the terminal session")

        let kernelOnly = GrantScopeInspector.choices(
            planRootPID: FakeClaudeSession.ssh,
            planRootStartTime: session.kernel.startTime(FakeClaudeSession.ssh)!,
            requestingLabel: "ssh", inspection: session.inspection(nil)
        )
        check(kernelOnly.options.map(\.kind) == [.requestingCommand],
              "by kernel parents alone the detached job's ssh can only be approved per command")

        let unrecorded = SessionLineage(facts: session.kernel.facts)
        check(unrecorded.parent(of: FakeClaudeSession.job) == 1
                && !session.inspection(unrecorded).descends(
                    FakeClaudeSession.ssh, from: FakeClaudeSession.claude, rootStartTime: claudeStart),
              "an unrecorded session leaves the job unlinked once its tool shell has exited")

        // The terminal line follows the same link.
        let terminal = TerminalSessionInspector(
            environment: { pid in
                pid == FakeClaudeSession.claude || pid == FakeClaudeSession.fish
                    ? ["TERM_PROGRAM": "iTerm.app", "ITERM_SESSION_ID": "w0t6p0:LINEAGE"] : [:]
            },
            parent: { lineage.parent(of: $0) },
            terminalName: { $0 == FakeClaudeSession.claude ? "ttys000" : nil },
            titleQuery: { _ in nil }
        ).identity(forCallerPID: FakeClaudeSession.ssh)
        check(terminal.application == .iTerm2 && terminal.tty == "ttys000",
              "the review names the terminal of the Claude session that started the detached job")
    }

    // Only while the leader's recorded parent still runs: when Claude exits,
    // the kernel orphans the tree's own survivors, and the detached job with
    // them.
    do {
        let session = FakeClaudeSession()
        let lineage = SessionLineage(facts: session.kernel.facts)
        lineage.record(from: FakeClaudeSession.csecAI)
        session.endToolCall()
        session.kernel.spawn(FakeClaudeSession.ssh, parent: FakeClaudeSession.job)
        session.kernel.exit(FakeClaudeSession.claude)
        check(lineage.parent(of: FakeClaudeSession.job) == 1,
              "once Claude exits, its detached job is unlinked, not handed to the terminal's shell")
        let afterClaude = GrantScopeInspector.choices(
            planRootPID: FakeClaudeSession.ssh,
            planRootStartTime: session.kernel.startTime(FakeClaudeSession.ssh)!,
            requestingLabel: "ssh", inspection: session.inspection(lineage)
        )
        check(afterClaude.options.map(\.kind) == [.requestingCommand],
              "a job that outlived Claude is offered its own command only, never the terminal session")
        session.kernel.spawn(FakeClaudeSession.claude, parent: FakeClaudeSession.fish)
        check(lineage.parent(of: FakeClaudeSession.job) == 1,
              "a new process under Claude's old pid is not taken for Claude")
    }

    // The races the unique IDs close. The job's session dies right after the
    // job is read, and the leader's pid goes to a new session's leader.
    do {
        let session = FakeClaudeSession()
        let lineage = SessionLineage(facts: session.kernel.facts)
        lineage.record(from: FakeClaudeSession.csecAI)
        session.endToolCall()
        let kernel = session.kernel
        kernel.afterReading { pid in
            guard pid == FakeClaudeSession.job else { return }
            kernel.afterReading(nil)
            kernel.exit(FakeClaudeSession.job)
            kernel.spawn(FakeClaudeSession.toolShell, parent: FakeClaudeSession.fish, leadsSession: true)
        }
        check(lineage.parent(of: FakeClaudeSession.job) == 1,
              "a leader newer than the job it is asked about is not that job's leader")
    }
    do {
        let session = FakeClaudeSession()
        let lineage = SessionLineage(facts: session.kernel.facts)
        lineage.record(from: FakeClaudeSession.csecAI)
        session.endToolCall()
        let kernel = session.kernel
        kernel.afterReading { pid in
            guard pid == FakeClaudeSession.job else { return }
            kernel.afterReading(nil)
            kernel.exit(FakeClaudeSession.job)
            kernel.spawn(FakeClaudeSession.toolShell, parent: FakeClaudeSession.fish, leadsSession: true)
            lineage.record(from: FakeClaudeSession.toolShell)
            kernel.exit(FakeClaudeSession.toolShell)
        }
        check(lineage.parent(of: FakeClaudeSession.job) == 1
                && lineage.recorded(session: FakeClaudeSession.toolShell)?.parent.pid == FakeClaudeSession.fish,
              "a record newer than the job it is asked about links nothing (and cannot underflow)")
    }

    // Reuse of the session's ID. The pid comes back only after the allocator
    // has gone round the ring, so a job in the new session is far above the
    // recorded leader's unique ID.
    func reusedSession() -> (session: FakeClaudeSession, lineage: SessionLineage, stranger: pid_t, job: pid_t) {
        let session = FakeClaudeSession()
        let lineage = SessionLineage(facts: session.kernel.facts)
        lineage.record(from: FakeClaudeSession.csecAI)
        session.endToolCall()
        session.kernel.exit(FakeClaudeSession.job)
        session.kernel.forkElsewhere(90_000)
        let stranger: pid_t = 70_001
        session.kernel.spawn(stranger, parent: 1)
        session.kernel.spawn(FakeClaudeSession.toolShell, parent: stranger, leadsSession: true)
        session.kernel.spawn(70_002, parent: FakeClaudeSession.toolShell)
        session.kernel.spawn(70_003, parent: 70_002)
        session.kernel.exit(70_002)
        return (session, lineage, stranger, 70_003)
    }
    do {
        let reused = reusedSession()
        let claudeStart = reused.session.kernel.startTime(FakeClaudeSession.claude)!
        check(reused.lineage.parent(of: reused.job) == FakeClaudeSession.toolShell,
              "a job in a new session under a reused ID links to that session's own running leader")
        check(!reused.session.inspection(reused.lineage).descends(
            reused.job, from: FakeClaudeSession.claude, rootStartTime: claudeStart
        ), "a job in a new session under a reused ID never descends from the recorded Claude")
        reused.session.kernel.exit(FakeClaudeSession.toolShell)
        check(reused.lineage.parent(of: reused.job) == 1,
              "once the new leader exits too, the margin keeps the old record from linking the new job")
    }
    do {
        let reused = reusedSession()
        reused.lineage.record(from: FakeClaudeSession.toolShell)
        check(reused.lineage.recorded(session: FakeClaudeSession.toolShell)?.parent.pid
                == reused.stranger,
              "a running leader under a reused ID replaces the old session's record")
        reused.session.kernel.exit(FakeClaudeSession.toolShell)
        check(reused.lineage.parent(of: reused.job) == reused.stranger
                && !reused.session.inspection(reused.lineage).descends(
                    reused.job, from: FakeClaudeSession.claude,
                    rootStartTime: reused.session.kernel.startTime(FakeClaudeSession.claude)!),
              "the replaced record links the new session's job to its own tree, not Claude's")
    }

    // The margin, exactly.
    do {
        let session = FakeClaudeSession()
        let lineage = SessionLineage(facts: session.kernel.facts)
        lineage.record(from: FakeClaudeSession.csecAI)
        let leaderID = session.kernel.uniqueID(FakeClaudeSession.toolShell)
        let inside: pid_t = 65_100
        let outside: pid_t = 65_101
        // The fixture spawned four processes after the tool shell; the next
        // spawn is the jobs' parent, then the two jobs.
        session.kernel.forkElsewhere(25_948 - 4 - 1)
        session.kernel.spawn(65_099, parent: FakeClaudeSession.command)
        session.kernel.spawn(inside, parent: 65_099)
        session.kernel.spawn(outside, parent: 65_099)
        session.kernel.exit(65_099)
        session.endToolCall()
        check(session.kernel.uniqueID(inside) - leaderID == 25_949
                && session.kernel.uniqueID(outside) - leaderID == 25_950,
              "fixture: one job one allocation inside the margin and one at it")
        check(lineage.parent(of: inside) == FakeClaudeSession.claude,
              "a job forked within the reuse margin of its recorded leader is linked")
        check(lineage.parent(of: outside) == 1,
              "a job forked beyond the reuse margin is not linked")
        session.kernel.setMaximumProcesses(nil)
        check(lineage.parent(of: inside) == 1,
              "without kern.maxproc there is no margin and nothing is linked")
        session.kernel.setMaximumProcesses(40_000)
        check(lineage.parent(of: inside) == 1,
              "a kern.maxproc that leaves no margin links nothing")
    }

    // Processes that are not detached session members.
    do {
        let session = FakeClaudeSession()
        let lineage = SessionLineage(facts: session.kernel.facts)
        lineage.record(from: FakeClaudeSession.csecAI)
        let daemon: pid_t = 65_300
        session.kernel.spawn(65_299, parent: FakeClaudeSession.command)
        session.kernel.spawn(daemon, parent: 65_299, leadsSession: true)
        session.kernel.exit(65_299)
        session.endToolCall()
        check(lineage.parent(of: daemon) == 1,
              "a job that started its own session (setsid, a daemon) is not linked")
        check(lineage.parent(of: FakeClaudeSession.iTerm) == 1,
              "an application launchd started, in launchd's session, is not linked")

        let unlinked = FakeClaudeSession()
        let before = SessionLineage(facts: unlinked.kernel.facts)
        before.record(from: FakeClaudeSession.job)
        check(before.recorded(session: FakeClaudeSession.toolShell) == nil,
              "a call from an already detached job records nothing: its session leader is not above it")
    }

    // Recording reads each ancestor while its child still names it as parent.
    do {
        let session = FakeClaudeSession()
        let lineage = SessionLineage(facts: session.kernel.facts)
        let kernel = session.kernel
        kernel.afterReading { pid in
            if pid == FakeClaudeSession.claude {
                kernel.afterReading(nil)
                kernel.exit(FakeClaudeSession.claude)
            }
        }
        lineage.record(from: FakeClaudeSession.csecAI)
        check(lineage.recorded(session: FakeClaudeSession.toolShell) == nil,
              "a parent that exits while it is being read is not recorded as an ancestor")
    }

    // Bounded memory: the least recently recorded or used session goes first.
    do {
        let kernel = FakeLineageKernel()
        kernel.spawn(500, parent: 1)
        let lineage = SessionLineage(facts: kernel.facts)
        let first: pid_t = 1_000
        for index in 0...SessionLineage.capacity {
            let leader = first + pid_t(index)
            kernel.spawn(leader, parent: 500, leadsSession: true)
            lineage.record(from: leader)
        }
        check(lineage.recorded(session: first) == nil
                && lineage.recorded(session: first + 1) != nil
                && lineage.recorded(session: first + pid_t(SessionLineage.capacity)) != nil,
              "past capacity, the oldest recorded session is forgotten")
    }
    do {
        let kernel = FakeLineageKernel()
        kernel.spawn(500, parent: 1)
        let lineage = SessionLineage(facts: kernel.facts)
        let first: pid_t = 1_000
        let job: pid_t = 99_000
        kernel.spawn(first, parent: 500, leadsSession: true)
        kernel.spawn(job, parent: first)
        lineage.record(from: job)
        kernel.exit(first)
        for index in 1..<SessionLineage.capacity {
            let leader = first + pid_t(index)
            kernel.spawn(leader, parent: 500, leadsSession: true)
            lineage.record(from: leader)
        }
        check(lineage.parent(of: job) == 500,
              "fixture: the first session's detached job is linked")
        let overflow = first + pid_t(SessionLineage.capacity)
        kernel.spawn(overflow, parent: 500, leadsSession: true)
        lineage.record(from: overflow)
        check(lineage.recorded(session: first) != nil && lineage.recorded(session: first + 1) == nil,
              "a session whose record a job keeps using outlives newer ones nobody used")
    }

    await liveDetachedJobTests()
}

/// Real processes: a session leader started as Claude Code starts a tool
/// shell detaches a job and exits, and the job is linked back only through
/// the record.
private func liveDetachedJobTests() async {
    struct Leader {
        let pid: pid_t
        let job: pid_t
        let input: Int32
    }

    func startDetachingLeader() -> Leader? {
        var input: [Int32] = [-1, -1]
        var output: [Int32] = [-1, -1]
        guard pipe(&input) == 0, pipe(&output) == 0 else { return nil }
        // Nothing but the dup2'd ends reaches a child: another leader holding
        // this leader's input open would keep its `read` from ever ending.
        for fd in [input[0], input[1], output[0], output[1]] {
            _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        }
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_adddup2(&actions, input[0], 0)
        posix_spawn_file_actions_adddup2(&actions, output[1], 1)
        for fd in [input[0], input[1], output[0], output[1]] {
            posix_spawn_file_actions_addclose(&actions, fd)
        }
        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        // A new session, as Claude Code starts each tool shell, with nothing
        // blocked (this runs on a Swift-concurrency thread, whose mask blocks
        // SIGTERM and would pass to the job).
        var unblocked = sigset_t()
        sigemptyset(&unblocked)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSID | POSIX_SPAWN_SETSIGMASK))
        posix_spawnattr_setsigmask(&attributes, &unblocked)
        let arguments = ["/bin/sh", "-c", "(sleep 120 & echo $!); read line"]
        var argv: [UnsafeMutablePointer<CChar>?] = arguments.map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) } }
        var pid: pid_t = 0
        let spawned = posix_spawn(&pid, "/bin/sh", &actions, &attributes, &argv, environ)
        close(input[0])
        close(output[1])
        guard spawned == 0 else {
            close(input[1]); close(output[0])
            return nil
        }
        var line = Data()
        var byte: UInt8 = 0
        while read(output[0], &byte, 1) == 1, byte != 0x0A { line.append(byte) }
        close(output[0])
        guard let job = pid_t(String(decoding: line, as: UTF8.self)) else {
            close(input[1])
            return nil
        }
        // The subshell that forked the job exits at once.
        for _ in 0..<200 where ProcessAncestry.parent(of: job) != 1 { usleep(10_000) }
        return Leader(pid: pid, job: job, input: input[1])
    }

    func finish(_ leader: Leader) {
        close(leader.input)
        var status: Int32 = 0
        while waitpid(leader.pid, &status, 0) < 0, errno == EINTR {}
    }

    let me = getpid()
    guard let myStart = ProcessAncestry.startTime(of: me),
          let recorded = startDetachingLeader(),
          let unrecorded = startDetachingLeader() else {
        check(false, "live: could not start the detaching session leaders")
        return
    }
    defer {
        kill(recorded.job, SIGKILL)
        kill(unrecorded.job, SIGKILL)
    }

    let jobFacts = ProcessAncestry.lineageFacts(of: recorded.job)
    check(ProcessAncestry.parent(of: recorded.job) == 1
            && jobFacts?.session == recorded.pid
            && ProcessAncestry.lineageFacts(of: recorded.pid)?.leadsSession == true,
          "live: a detached job's parent is launchd and its session is the leader that started it")
    let lineage = SessionLineage()
    check(lineage.parent(of: recorded.job) == recorded.pid,
          "live: while its session leader runs, the job's lineage parent is that leader")

    lineage.record(from: recorded.pid)
    SessionLineage.shared.record(from: recorded.pid)
    check(lineage.recorded(session: recorded.pid)?.parent
            == ProcessAncestry.lineageFacts(of: me).map { SessionLineage.Incarnation(pid: me, uniqueID: $0.uniqueID) },
          "live: recording the leader records this process as its parent")

    finish(recorded)
    finish(unrecorded)
    let after = ProcessAncestry.lineageFacts(of: recorded.job)
    check(ProcessAncestry.lineageFacts(of: recorded.pid) == nil
            && after?.session == recorded.pid
            && (after?.uniqueID ?? 0) > (lineage.recorded(session: recorded.pid)?.leaderUniqueID ?? .max),
          "live: after its leader exits, the job keeps the leader's session ID and a later unique ID")
    check(lineage.parent(of: recorded.job) == me,
          "live: a recorded session links its detached job back to the leader's parent")
    check(SessionLineage().parent(of: recorded.job) == 1,
          "live: without the record the detached job stays unlinked")

    // The production wiring: coverage and scope checks read the shared lineage.
    check(ProcessInspection.live.descends(recorded.job, from: me, rootStartTime: myStart),
          "live: ProcessInspection.live follows the shared lineage to the job's tree")
    check(!ProcessInspection.live.descends(unrecorded.job, from: me, rootStartTime: myStart),
          "live: a job from an unrecorded session is outside the tree")
    let reference = "csec://lineage-selftest/value"
    let table = GrantTable()
    await table.add(Grant(
        rootPID: me, rootStartTime: myStart, references: [reference],
        reason: "session lineage selftest", scopeKind: .codingAgent
    ))
    let covered = await table.accessibleReferences(for: recorded.job, now: Date())
    let uncovered = await table.accessibleReferences(for: unrecorded.job, now: Date())
    check(covered == [reference] && uncovered.isEmpty,
          "live: a grant rooted in the tree covers its recorded detached job and nothing else")
}
