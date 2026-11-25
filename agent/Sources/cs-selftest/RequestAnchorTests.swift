import ConvenientSecurity
import Foundation

/// Kernel parentage can change while the lineage link deliberately survives.
final class AnchorFixtureTree: @unchecked Sendable {
    private let lock = NSLock()
    private var starts: [pid_t: UInt64]
    private var parents: [pid_t: pid_t]
    private let lineage: [pid_t: pid_t]
    private let terminal: pid_t

    init(starts: [pid_t: UInt64], parents: [pid_t: pid_t], terminal: pid_t) {
        self.starts = starts
        self.parents = parents
        self.lineage = parents
        self.terminal = terminal
    }

    func reparent(_ pid: pid_t, to parent: pid_t = 1) {
        lock.withLock { parents[pid] = parent }
    }

    func recycle(_ pid: pid_t) {
        lock.withLock { starts[pid] = (starts[pid] ?? 0) + 1 }
    }

    var inspection: ProcessInspection {
        ProcessInspection(
            startTime: { pid in self.lock.withLock { self.starts[pid] } },
            parent: { pid in self.lock.withLock { self.parents[pid] } },
            name: { $0 == self.terminal ? "fish" : "fixture" },
            executablePath: { _ in "/usr/bin/fixture" },
            hasControllingTerminal: { $0 == self.terminal },
            lineageParent: { self.lineage[$0] }
        )
    }
}

func requestAnchorTests() async {
    print("\n# Pending request parent and scope anchors")
    func tree() -> AnchorFixtureTree {
        AnchorFixtureTree(starts: [300: 30, 200: 20, 100: 10],
                          parents: [300: 200, 200: 100, 100: 1], terminal: 100)
    }
    let caller = CallerInfo(pid: 300, startTime: 30, description: "fixture requester")
    let intact = tree()
    let anchored = caller.anchored(using: intact.inspection)
    check(anchored.requestAnchor?.parent?.pid == 200 && anchored.requestAnchor?.scope.pid == 100,
          "anchor: captures the kernel parent incarnation and original default scope")
    check(AccessReviewRequester.isAlive(anchored, using: intact.inspection),
          "anchor: a live requester under the original parent and scope remains reviewable")
    check(AccessReviewRequester.isAlive(anchored),
          "anchor: a queued or restore review keeps the process source its request captured")
    intact.reparent(300)
    check(intact.inspection.descends(300, from: 100, rootStartTime: 10)
          && !AccessReviewRequester.isAlive(anchored, using: intact.inspection),
          "anchor: orphaning cancels even when recorded lineage still contains the requester")
    check(anchored.anchored(using: intact.inspection).requestAnchor?.parent?.pid == 200,
          "anchor: queue re-entry never replaces the original parent with launchd")

    for pid: pid_t in [300, 200, 100] {
        let fixture = tree()
        let anchor = RequestAnchor.capture(caller, inspection: fixture.inspection)
        fixture.recycle(pid)
        check(anchor.abandonment(using: fixture.inspection) != nil,
              "anchor: a reused requester, parent or scope pid (\(pid)) is gone")
    }
    let registered = AnchorFixtureTree(starts: [300: 30, 200: 20, 100: 10],
                                      parents: [300: 200, 200: 100, 100: 1], terminal: 0)
    let sessionAnchor = RequestAnchor.capture(caller, inspection: registered.inspection,
                                             scopeRoot: (pid: 100, startTime: 10))
    check(sessionAnchor.scope.pid == 100 && sessionAnchor.parent?.pid == 200,
          "anchor: a verified delivery root is retained without a terminal or coding-agent ancestor")
    registered.recycle(100)
    check(sessionAnchor.abandonment(using: registered.inspection) != nil,
          "anchor: loss of a registered delivery scope withdraws the request while its direct parent lives")
    let unreadable = tree(), original = unreadable.inspection
    let inspection = ProcessInspection(
        startTime: { $0 == 200 ? nil : original.startTime(of: $0) },
        parent: { original.parent(of: $0) }, name: { original.name(of: $0) },
        executablePath: { original.executablePath(of: $0) },
        hasControllingTerminal: { original.hasControllingTerminal($0) },
        lineageParent: { original.lineageParent(of: $0) }
    )
    let unknownParent = RequestAnchor.capture(caller, inspection: inspection)
    check(unknownParent.parent?.pid == 200 && unknownParent.parent?.startTime == nil
          && unknownParent.abandonment(using: inspection) == nil,
          "anchor: an unreadable setuid parent retains the existing human-review fallback")
    unreadable.reparent(300)
    check(unknownParent.abandonment(using: inspection)?.detail.contains("pid 200") == true,
          "anchor: reparenting still detects an orphan when its parent's start time was unreadable")
    let detached = tree()
    detached.reparent(300)
    let detachedAnchor = RequestAnchor.capture(caller, inspection: detached.inspection)
    check(detachedAnchor.parent == nil && detachedAnchor.abandonment(using: detached.inspection) == nil,
          "anchor: a requester already parented by launchd at arrival gets no parent watch")
    detached.recycle(100)
    check(detachedAnchor.abandonment(using: detached.inspection) != nil,
          "anchor: a detached request still watches its recorded wider scope")

    let watched = tree()
    let wait = HumanWait(
        requester: .init(pid: 300, startTime: 30), summary: "fixture", limit: nil,
        requestAnchor: RequestAnchor.capture(caller, inspection: watched.inspection),
        processInspection: watched.inspection, requesterPollInterval: .milliseconds(10)
    )
    let pending = Task {
        await wait.bounding {
            try? await Task.sleep(for: .seconds(10))
            return Task.isCancelled
        }
    }
    watched.reparent(300)
    check(await pending.value && !wait.isExpired && wait.abandonment != nil,
          "anchor: losing the parent cancels an unbounded wait without calling it a timeout")
    check(!wait.expire() && !wait.decide() && wait.currentState == .abandoned,
          "anchor: a later deadline or decision cannot relabel an abandoned request")
    check(wait.withdrawnDetail().contains("never shown; abandoned:")
          && wait.withdrawnDetail().contains("pid 200")
          && wait.effectiveReason(.requesterGone) == .withdrawn,
          "anchor: a never-shown withdrawal carries the original parent and wait detail")
    wait.markShown()
    check(wait.effectiveReason(.requesterGone) == .requesterGone,
          "anchor: an already-shown review retains its requester_gone panel outcome")

    // A restore panel belongs to all its waiters, so it deliberately clears
    // HumanWait.current. Its displayed caller must still be checked when it
    // reaches the UI turn; another waiter can then get a fresh presentation.
    // The lost scope is a process this test started and reaped: a fixed pid
    // can be live, and the inspector then walks its real ancestors, which may
    // also contain this test, so the scope looks intact.
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    if let start = ProcessAncestry.startTime(of: me), let lostScope = exitedProcess() {
        let staleCaller = CallerInfo(pid: me, startTime: start, description: "restore fixture")
            .anchored(scopeRoot: (pid: lostScope.pid, startTime: lostScope.start))
        let queue = ConsentQueue(), gate = GatedPolicyReview(automatic: .deny(.authenticationFailed))
        let held = try! await queue.acquire()
        let reviewer = QueuedPolicyReview(underlying: gate, queue: queue)
        let review = AccessPolicyReview.restoreOnly(caller: staleCaller, restore: RestoreReviewDetails(
            cause: .upgrade,
            rows: [RestoreReviewRow(kind: .secretGrant, title: "fixture", detail: "fixture",
                                    references: ["op://orphan/restore/token"])],
            storeCount: 1
        ))
        let pending = HumanWait.$current.withValue(nil) {
            Task { await reviewer.reviewAccess(review) }
        }
        check(await eventuallyTrue { await queue.waitingCount == 1 },
              "anchor restore: a shared restore waits on the UI queue without a HumanWait")
        await held.release()
        let outcome = await pending.value
        if case .denied(.withdrawn) = outcome {
            check(true, "anchor restore: a lost original scope withdraws the shared panel at presentation")
        } else {
            check(false, "anchor restore: a lost original scope must withdraw before presentation")
        }
        check(await gate.reviews == 0, "anchor restore: the stale queued restore caller is never presented")
    } else {
        check(false, "anchor restore: the fixture has a live process incarnation and an exited scope")
    }
}
