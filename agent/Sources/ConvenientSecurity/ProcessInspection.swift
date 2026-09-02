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

    public init(
        startTime: @escaping @Sendable (pid_t) -> UInt64?,
        parent: @escaping @Sendable (pid_t) -> pid_t?,
        name: @escaping @Sendable (pid_t) -> String?,
        executablePath: @escaping @Sendable (pid_t) -> String?,
        hasControllingTerminal: @escaping @Sendable (pid_t) -> Bool = { _ in false }
    ) {
        startTimeLookup = startTime
        parentLookup = parent
        nameLookup = name
        executablePathLookup = executablePath
        controllingTerminalLookup = hasControllingTerminal
    }

    public static let live = ProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) },
        parent: { ProcessAncestry.parent(of: $0) },
        name: { ProcessAncestry.name(of: $0) },
        executablePath: { ProcessAncestry.executablePath(of: $0) },
        hasControllingTerminal: { ProcessAncestry.hasControllingTerminal($0) }
    )

    public func startTime(of pid: pid_t) -> UInt64? {
        startTimeLookup(pid)
    }

    public func parent(of pid: pid_t) -> pid_t? {
        parentLookup(pid)
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

    /// Whether `pid` is `root` or descends from it, with `root`'s start time
    /// still matching `rootStartTime`. This is the same walk `ProcessAncestry`
    /// performs against the kernel; the seam exists only so synthetic trees can
    /// exercise selection logic.
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
            guard let next = parent(of: current), next != current else { return false }
            current = next
            hops += 1
        }
        return false
    }
}
