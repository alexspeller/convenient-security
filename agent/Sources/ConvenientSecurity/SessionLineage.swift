import Foundation

/// Links a job detached from its process tree back to the tree it was
/// started in.
///
/// csec binds a grant to a process tree and checks coverage by walking kernel
/// parents from the requester up to the grant's root. A job that a coding
/// agent's tool shell detaches — `( job & )`, `nohup job &`, `disown` — loses
/// that path: when the process that forked it exits, the kernel re-parents it
/// to launchd, and a walk from anything it starts stops there. So every `ssh`
/// such a job ran raised its own panel, although the human had approved that
/// connection for the agent's session.
///
/// The job keeps its session, and the session proves where it came from. From
/// xnu (`setsid`, `forkproc`) and measured on macOS 26:
/// - A process is in a session only by being forked from a member of it:
///   `setsid` starts a new session named by the caller's own pid, and nothing
///   joins an existing one. So every member descends from the session's
///   leader, the process that started it.
/// - The kernel never allocates a pid still in use as a process, process group
///   or session ID, so a session's ID names only that session while it has a
///   member.
/// - Once its last member exits the ID can name a new session, but only after
///   the pid allocator has gone all the way round the pid ring (100…99,998)
///   and handed the leader's pid out again. Every value in the ring is
///   allocated on the way except those in use as a pid, group or session ID
///   from the leader's fork until the allocator passes them: at most three per
///   process then alive, plus the sessions and groups a terminal still holds
///   (two per tty) and the few forks in flight past fork's process-count
///   check. Each allocation advances the kernel's unique process ID by exactly
///   one, so a member of a newer session sits at least
///   `99,900 − 3 × kern.maxproc` (less those small terms) above the old
///   leader's unique ID. csec accepts only half that, which absorbs them many
///   times over. On a busy Mac the ring comes round every few minutes, so the
///   margin is what keeps a reused ID from linking anything.
///
/// Claude Code starts every tool shell as a session leader, a child of Claude.
/// csecd records a session when a csec client in it calls csecd — `csec ai`
/// does before every command it runs — while the leader still runs: the
/// nearest session leader on the caller's kernel-parent path, and that
/// leader's parent, each by unique ID. The lineage parent of a process whose
/// kernel parent is launchd and which does not lead its own session is:
/// - its session's leader, while that is still running; or
/// - once the leader has exited, if the session was recorded and the process's
///   unique ID shows it was forked after the leader and within the margin, the
///   leader's recorded parent, while that is still the same process.
/// That is the answer the kernel would give if the leader were still running:
/// when the leader's parent exits, the tree's own survivors are orphaned too,
/// and so is the detached job.
///
/// Every other process's lineage parent is its kernel parent. Unlinked: a job
/// that leaves its session (`setsid`, a daemon), one forked beyond the margin,
/// and any job whose session was not recorded or has been forgotten. Records
/// live in memory only, at most `capacity` of them, least recently used first
/// out, so a csecd restart forgets them all, and a flood of csec calls from
/// fresh sessions can push one out; both leave a job unlinked, never linked.
///
/// The link is not specific to coding agents: any terminal whose shell leads
/// its own session and runs as the user (tmux panes, VS Code) keeps a job it
/// detached inside that shell's tree while the shell runs. iTerm2 and
/// Terminal.app sessions are led by root's `login`, which csec cannot read, so
/// their shells' detached jobs stay unlinked. Like the kernel-parent walk, this
/// assumes no debugger re-parents a process (ptrace attach, or a detach that
/// looks the original parent up by pid), and the reads of one hop are not bound
/// to the next.
public final class SessionLineage: @unchecked Sendable {
    /// csecd's lineage, fed by its control socket and read wherever csecd
    /// decides whether a request is inside a granted process tree.
    public static let shared = SessionLineage()

    /// The kernel reads the lineage uses; injectable so tests can build
    /// sessions, exits and pid reuse that a live system cannot stage on demand.
    public struct Facts: Sendable {
        let kernelParent: @Sendable (pid_t) -> pid_t?
        let lineage: @Sendable (pid_t) -> ProcessLineageFacts?
        let maximumProcesses: @Sendable () -> Int?

        public init(
            kernelParent: @escaping @Sendable (pid_t) -> pid_t?,
            lineage: @escaping @Sendable (pid_t) -> ProcessLineageFacts?,
            maximumProcesses: @escaping @Sendable () -> Int?
        ) {
            self.kernelParent = kernelParent
            self.lineage = lineage
            self.maximumProcesses = maximumProcesses
        }

        public static let live = Facts(
            kernelParent: { ProcessAncestry.parent(of: $0) },
            lineage: { ProcessAncestry.lineageFacts(of: $0) },
            maximumProcesses: { ProcessAncestry.maximumProcesses() }
        )
    }

    /// A process incarnation, by pid and the kernel's unique ID.
    public struct Incarnation: Sendable, Equatable {
        public let pid: pid_t
        public let uniqueID: UInt64

        public init(pid: pid_t, uniqueID: UInt64) {
            self.pid = pid
            self.uniqueID = uniqueID
        }
    }

    /// What was recorded about one session while its leader was running.
    public struct Record: Sendable, Equatable {
        public let leaderUniqueID: UInt64
        /// The leader's parent when it was recorded.
        public let parent: Incarnation
    }

    /// Sessions remembered at once. csec ai records one per tool call; the
    /// least recently recorded or used goes first, and a job in a forgotten
    /// session is only unlinked.
    public static let capacity = 4_096
    static let maximumHops = 64

    private let facts: Facts
    private let lock = NSLock()
    private var records: [pid_t: (record: Record, sequence: UInt64)] = [:]
    private var nextSequence: UInt64 = 0

    public init(facts: Facts = .live) {
        self.facts = facts
    }

    /// How far above a recorded leader's unique ID a member of its session can
    /// be and still be known to belong to that session and not to a newer one
    /// under the same ID: half the proven `99,900 − 3 × kern.maxproc`, so the
    /// terms that count leaves out (terminals' sessions and groups, forks in
    /// flight) fit many times over. Nil when `kern.maxproc` leaves no margin.
    public static func reuseMargin(maximumProcesses: Int) -> UInt64? {
        let margin = (99_900 - 3 * maximumProcesses) / 2
        return margin > 0 ? UInt64(margin) : nil
    }

    // MARK: - Recording

    /// Record the session of `callerPID`: the nearest session leader on its
    /// kernel-parent path, and that leader's parent. Only a leader still
    /// running, found by walking up from a live caller, is recorded, so the
    /// record states what the kernel reported at that moment.
    public func record(from callerPID: pid_t) {
        var current = callerPID
        for _ in 0..<Self.maximumHops {
            guard current > 1, let process = facts.lineage(current) else { return }
            if process.leadsSession {
                recordLeader(process)
                return
            }
            current = process.parent
        }
    }

    private func recordLeader(_ leader: ProcessLineageFacts) {
        // The leader still has this parent after the parent was read, so the
        // parent did not exit in between (which re-parents the leader to
        // launchd): the facts are that parent's.
        guard leader.parent > 1,
              let parent = facts.lineage(leader.parent),
              let again = facts.lineage(leader.pid),
              again.uniqueID == leader.uniqueID,
              again.parent == parent.pid else { return }
        let record = Record(
            leaderUniqueID: leader.uniqueID,
            parent: Incarnation(pid: parent.pid, uniqueID: parent.uniqueID)
        )
        lock.withLock {
            // A later call from the same session keeps the record; a new
            // session under a reused ID replaces the old one.
            if let existing = records[leader.pid], existing.record.leaderUniqueID == leader.uniqueID {
                return
            }
            nextSequence += 1
            records[leader.pid] = (record, nextSequence)
            if records.count > Self.capacity,
               let oldest = records.min(by: { $0.value.sequence < $1.value.sequence })?.key {
                records.removeValue(forKey: oldest)
            }
        }
    }

    /// The record for session `sessionID`, for tests and diagnostics.
    public func recorded(session sessionID: pid_t) -> Record? {
        lock.withLock { records[sessionID]?.record }
    }

    // MARK: - Lineage

    /// The process `pid` is proven to descend from next: its kernel parent, or
    /// for a job detached from its session, what the session links it to (see
    /// the type's documentation). Nil when the process is gone.
    public func parent(of pid: pid_t) -> pid_t? {
        guard let parent = facts.kernelParent(pid) else { return nil }
        guard parent == 1, pid > 1 else { return parent }
        return sessionParent(ofDetached: pid) ?? parent
    }

    private func sessionParent(ofDetached pid: pid_t) -> pid_t? {
        guard let detached = facts.lineage(pid),
              detached.parent == 1,
              !detached.leadsSession,
              detached.session > 1 else { return nil }
        let leaderPID = detached.session

        // The pid still names a process that leads a session: only this
        // session's own leader can, because the pid is not handed out again
        // while the session has a member.
        if let leader = facts.lineage(leaderPID), leader.leadsSession {
            return leader.uniqueID < detached.uniqueID ? leaderPID : nil
        }

        // The leader has exited (or can no longer be read, e.g. it exec'd a
        // setuid program). Only the record and the margin can link the job,
        // and only to the leader's parent while that is the same process.
        guard let record = recorded(session: leaderPID),
              detached.uniqueID > record.leaderUniqueID,
              let maximumProcesses = facts.maximumProcesses(),
              let margin = Self.reuseMargin(maximumProcesses: maximumProcesses),
              detached.uniqueID - record.leaderUniqueID < margin,
              facts.lineage(record.parent.pid)?.uniqueID == record.parent.uniqueID else { return nil }
        // Used: a long-running job keeps its session's record.
        lock.withLock {
            guard records[leaderPID]?.record == record else { return }
            nextSequence += 1
            records[leaderPID]?.sequence = nextSequence
        }
        return record.parent.pid
    }
}
