import Foundation

/// Value-free process metadata used to bind grants to live process trees.
/// Production always uses the kernel-backed `live` implementation. The
/// injectable form keeps root selection deterministic in synthetic tests
/// without weakening the release caller checks.
public struct ProcessInspection: Sendable {
    private let startTimeLookup: @Sendable (pid_t) -> UInt64?
    private let parentLookup: @Sendable (pid_t) -> pid_t?
    private let nameLookup: @Sendable (pid_t) -> String?
    private let executablePathLookup: @Sendable (pid_t) -> String?
    private let controllingTerminalLookup: @Sendable (pid_t) -> Bool
    private let lineageParentLookup: @Sendable (pid_t) -> pid_t?
    private let argumentsLookup: @Sendable (pid_t) -> [String]?

    /// `lineageParent` defaults to `parent`: a synthetic tree has no detached
    /// jobs unless a test models one. `arguments` defaults to none, so a
    /// synthetic tree never reads a real process's argv by a made-up pid.
    public init(
        startTime: @escaping @Sendable (pid_t) -> UInt64?,
        parent: @escaping @Sendable (pid_t) -> pid_t?,
        name: @escaping @Sendable (pid_t) -> String?,
        executablePath: @escaping @Sendable (pid_t) -> String?,
        hasControllingTerminal: @escaping @Sendable (pid_t) -> Bool = { _ in false },
        lineageParent: (@Sendable (pid_t) -> pid_t?)? = nil,
        arguments: @escaping @Sendable (pid_t) -> [String]? = { _ in nil }
    ) {
        startTimeLookup = startTime
        parentLookup = parent
        nameLookup = name
        executablePathLookup = executablePath
        controllingTerminalLookup = hasControllingTerminal
        lineageParentLookup = lineageParent ?? parent
        argumentsLookup = arguments
    }

    public static let live = ProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) },
        parent: { ProcessAncestry.parent(of: $0) },
        name: { ProcessAncestry.name(of: $0) },
        executablePath: { ProcessAncestry.executablePath(of: $0) },
        hasControllingTerminal: { ProcessAncestry.hasControllingTerminal($0) },
        lineageParent: { SessionLineage.shared.parent(of: $0) },
        arguments: { ProcessAncestry.arguments(of: $0) }
    )

    public func startTime(of pid: pid_t) -> UInt64? {
        startTimeLookup(pid)
    }

    /// The kernel parent: launchd (1) once the original parent has exited.
    public func parent(of pid: pid_t) -> pid_t? {
        parentLookup(pid)
    }

    /// The process `pid` is proven to descend from next: the kernel parent,
    /// or for a job detached from its session, what `SessionLineage` links it
    /// to. Grant coverage and scope roots walk this; a check that means "the
    /// direct parent right now" uses `parent(of:)`.
    public func lineageParent(of pid: pid_t) -> pid_t? {
        lineageParentLookup(pid)
    }

    public func name(of pid: pid_t) -> String? {
        nameLookup(pid)
    }

    public func executablePath(of pid: pid_t) -> String? {
        executablePathLookup(pid)
    }

    public func hasControllingTerminal(_ pid: pid_t) -> Bool {
        controllingTerminalLookup(pid)
    }

    /// The exec-time argv of the process that started at `startTime` as
    /// `pid`, or nil when it is gone, unreadable, empty, or the pid now names
    /// another process. The start time is read before and after the argv, so
    /// a pid reused in between yields nothing rather than a stranger's
    /// command. argv is whatever the process was started with: untrusted
    /// display metadata, never identity or policy input.
    public func arguments(of pid: pid_t, startedAt startTime: UInt64) -> [String]? {
        guard pid > 1, startTime > 0, startTimeLookup(pid) == startTime,
              let arguments = argumentsLookup(pid), !arguments.isEmpty,
              startTimeLookup(pid) == startTime else { return nil }
        return arguments
    }

    /// Whether `pid` is `root` or descends from it, with `root`'s start time
    /// still matching `rootStartTime`. The walk follows lineage parents, so a
    /// job its tree detached is still inside it (`SessionLineage`); otherwise
    /// it is the walk `ProcessAncestry.descends` performs against the kernel.
    /// The seam exists only so synthetic trees can exercise selection logic.
    public func descends(
        _ pid: pid_t,
        from root: pid_t,
        rootStartTime: UInt64
    ) -> Bool {
        guard startTime(of: root) == rootStartTime else { return false }

        var current = pid
        var hops = 0
        while hops < 128 {
            if current == root { return true }
            if current <= 1 { return false }
            guard let next = lineageParent(of: current), next != current else { return false }
            current = next
            hops += 1
        }
        return false
    }
}
