import Foundation

/// Arrival-time process facts for a request that may wait on a human. Kernel
/// parentage catches an orphan even when SessionLineage still links it to its
/// session; the default scope catches a session that no longer contains it.
/// This bounds an unanswered request, never an already-delivered grant.
public struct RequestAnchor: Sendable {
    public struct Process: Sendable {
        public let pid: pid_t
        public let startTime: UInt64
        public let label: String

        init(pid: pid_t, startTime: UInt64, label: String) {
            self.pid = pid
            self.startTime = startTime
            self.label = ReviewDisplay.bounded(ReviewDisplay.sanitized(label), maxBytes: 128)
        }
    }

    public struct Parent: Sendable {
        public let pid: pid_t
        /// A root-owned/setuid parent may be unreadable. Its kernel pid is
        /// still known from the requester, and reparenting still withdraws it.
        public let startTime: UInt64?
        public let label: String

        func stillParents(_ requester: pid_t, using inspection: ProcessInspection) -> Bool {
            inspection.parent(of: requester) == pid
                && (startTime.map { inspection.startTime(of: pid) == $0 } ?? true)
        }
    }

    public let requester: Process
    public let parent: Parent?
    public let scope: Process
    /// Carry the same live process source through restore tasks that clear
    /// HumanWait.current. Production captures .live; synthetic kernels remain
    /// consistent across the service, queue and panel liveness predicates.
    let inspection: ProcessInspection
    private let capturedIntact: Bool

    public static func capture(
        _ caller: CallerInfo, inspection: ProcessInspection = .live,
        scopeRoot: (pid: pid_t, startTime: UInt64)? = nil
    ) -> RequestAnchor {
        let requesterWasAlive = inspection.startTime(of: caller.pid) == caller.startTime
        let parentPID = inspection.parent(of: caller.pid)
        let parent: Parent?
        if let parentPID, parentPID > 1 {
            parent = Parent(
                pid: parentPID, startTime: inspection.startTime(of: parentPID),
                label: ReviewDisplay.bounded(ReviewDisplay.sanitized(inspection.name(of: parentPID) ?? "parent"), maxBytes: 128)
            )
        } else {
            parent = nil
        }
        let choices = GrantScopeInspector.choices(
            planRootPID: scopeRoot?.pid ?? caller.pid,
            planRootStartTime: scopeRoot?.startTime ?? caller.startTime,
            requestingLabel: inspection.name(of: scopeRoot?.pid ?? caller.pid) ?? "requester", inspection: inspection
        )
        let root = choices.defaultOption
        return RequestAnchor(
            requester: Process(pid: caller.pid, startTime: caller.startTime, label: caller.description),
            parent: parent,
            scope: Process(pid: root.pid, startTime: root.startTime, label: root.processLabel),
            inspection: inspection,
            capturedIntact: caller.startTime > 0 && requesterWasAlive
                && inspection.startTime(of: caller.pid) == caller.startTime
                && parentPID != nil
                && inspection.parent(of: caller.pid) == parentPID
                && (parent.map { $0.stillParents(caller.pid, using: inspection) } ?? true)
        )
    }

    public func abandonment(using override: ProcessInspection? = nil) -> RequestAbandonment? {
        let inspection = override ?? self.inspection
        guard capturedIntact,
              inspection.startTime(of: requester.pid) == requester.startTime else {
            return RequestAbandonment(detail: "its requester exited or changed")
        }
        if let parent, !parent.stillParents(requester.pid, using: inspection) {
            return RequestAbandonment(
                detail: "abandoned: \(parent.label) (pid \(parent.pid)), which started it, exited or changed"
            )
        }
        if scope.pid != requester.pid,
           !inspection.descends(requester.pid, from: scope.pid, rootStartTime: scope.startTime) {
            return RequestAbandonment(
                detail: "abandoned: its original scope \(scope.label) (pid \(scope.pid)) exited or no longer contains it"
            )
        }
        return nil
    }
}

public struct RequestAbandonment: Sendable, Equatable {
    public let detail: String

    public var message: String {
        "approval was not given: the process that started this request exited or its original scope changed; "
            + "csec withdrew the request and released nothing"
    }
}

public extension CallerInfo {
    /// Preserve the first snapshot through queue re-entry and display copies.
    func anchored(
        using inspection: ProcessInspection = .live,
        scopeRoot: (pid: pid_t, startTime: UInt64)? = nil
    ) -> CallerInfo {
        var caller = self
        if caller.requestAnchor == nil {
            caller.requestAnchor = RequestAnchor.capture(caller, inspection: inspection, scopeRoot: scopeRoot)
        }
        return caller
    }
}
