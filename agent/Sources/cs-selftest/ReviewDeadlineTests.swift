import ConvenientSecurity
import Foundation
#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  import AppKit
#endif

// The deadline an unanswered approval panel closes at, shown on the panel
// (csec-kua.4): the sudo review's PAM limit, which the helper closes just
// before, and a coding agent's request wait. `csec-sudo-review
// --deadline-probe` and `CSEC_PREVIEW_DEADLINE` with `cs-review-preview` show
// the live panels doing it.

func reviewDeadlineTests() async {
    print("\n# Review deadline: a panel nobody answers says when it closes, then counts down")
    reviewDeadlineLineTests()
    sudoReviewDeadlineLatchTests()
    await sudoReviewDeadlineWatchTests()
    sudoReviewWireTimeLimitTests()
    reviewDeadlineHumanWaitTests()
    await phoneDeadlineTests()
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await MainActor.run { reviewDeadlinePanelTests() }
    #endif
}

private func reviewDeadlineLineTests() {
    let utc = TimeZone(identifier: "UTC")!
    let now = Date(timeIntervalSince1970: 1_792_000_000)  // 2026-10-14 17:46:40 UTC
    let deadline = ReviewDeadline(
        remaining: .seconds(300), now: .now, nowDate: now)
    let quiet = deadline.line(remaining: .seconds(300), now: now, timeZone: utc)
    check(quiet == .init(text: "If nobody answers by 17:51, this closes without approving anything.", isCountdown: false),
          "review deadline: with time left the line names the closing time, quietly (\(quiet.text))")
    check(!deadline.line(remaining: .milliseconds(30_001), now: now, timeZone: utc).isCountdown,
          "review deadline: just over 30 s left is still the quiet line")
    check(deadline.line(remaining: .seconds(30), now: now, timeZone: utc)
            == .init(text: "Closes in 30 seconds if nobody answers, without approving anything.", isCountdown: true),
          "review deadline: the countdown starts at 30 seconds")
    check(deadline.line(remaining: .milliseconds(29_200), now: now, timeZone: utc).text.hasPrefix("Closes in 30 seconds"),
          "review deadline: the countdown rounds up, so it never reads a second early")
    check(deadline.line(remaining: .milliseconds(400), now: now, timeZone: utc).text
            == "Closes in 1 second if nobody answers, without approving anything.",
          "review deadline: its final second is singular")
    check(deadline.line(remaining: .zero, now: now, timeZone: utc)
            == .init(text: "Closing: nobody answered in time. Nothing was approved.", isCountdown: true),
          "review deadline: at the deadline it says why the panel is closing")
    let late = ReviewDeadline(remaining: .seconds(12 * 3_600), now: .now, nowDate: now)
    check(late.line(remaining: .seconds(12 * 3_600), now: now, timeZone: utc).text
            == "If nobody answers by tomorrow at 05:46, this closes without approving anything.",
          "review deadline: a close on a later day says so")

    check(ReviewDeadline.nextChange(after: .seconds(300)) == .seconds(270),
          "review deadline: the quiet line next changes when the countdown starts")
    check(ReviewDeadline.nextChange(after: .milliseconds(29_200)) == .milliseconds(200),
          "review deadline: the countdown next changes when its number drops")
    check(ReviewDeadline.nextChange(after: .seconds(30)) == .seconds(1),
          "review deadline: from a whole second the countdown changes a second later")
    check(ReviewDeadline.nextChange(after: .zero) == nil && ReviewDeadline.nextChange(after: .seconds(-1)) == nil,
          "review deadline: once it has passed nothing is scheduled; the owner closes the panel")
}

private func sudoReviewDeadlineLatchTests() {
    let start = ContinuousClock.now
    let deadline = SudoReviewDeadline(timeLimit: .seconds(300), now: start, nowDate: Date(timeIntervalSince1970: 0))
    check(deadline.closing.instant == start + .seconds(297)
            && deadline.closing.date == Date(timeIntervalSince1970: 297),
          "sudo deadline: the helper closes the review 3 s before the PAM module's deadline")
    check(deadline.fitsBeforeModuleDeadline(SudoDelegationClient.deadline, now: start + .seconds(297))
            && !deadline.fitsBeforeModuleDeadline(SudoDelegationClient.deadline, now: start + .seconds(298)),
          "sudo deadline: an approval at the close still has time to pair; one later skips it rather than overrun")
    check(SudoReviewDeadline(timeLimit: .seconds(1), now: start).closing.instant == start,
          "sudo deadline: with less than the margin left it closes at once")
    check(deadline.decide() && !deadline.expire() && deadline.decide(),
          "sudo deadline: a decision made first stands; the deadline cannot overrule it")
    let expired = SudoReviewDeadline(timeLimit: .seconds(300))
    check(expired.expire() && !expired.decide() && !expired.expire(),
          "sudo deadline: once the deadline closed the review, a late decision is too late")
    check(SudoReviewDeadline.expiredExitStatus == 75
            && SudoReviewDeadline.expiredExitStatus != SudoReviewOutcome.approved(on: .mac).exitStatus
            && SudoReviewDeadline.expiredExitStatus != SudoReviewOutcome.usePassword(deniedOnPhone: false).exitStatus,
          "sudo deadline: expiry is its own exit status, CSEC_REVIEW_EXPIRED_EXIT_STATUS")
}

private final class Expiries: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.lock(); count += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
}

private func sudoReviewDeadlineWatchTests() async {
    // 3.15 s limit, 3 s margin: closes 150 ms from now.
    let undecided = SudoReviewDeadline(timeLimit: .milliseconds(3_150))
    let fired = Expiries()
    undecided.watch { fired.increment() }
    try? await Task.sleep(for: .milliseconds(80))
    let early = fired.value
    try? await Task.sleep(for: .milliseconds(400))
    check(early == 0 && fired.value == 1 && !undecided.decide(),
          "sudo deadline: the watch closes an undecided review at its deadline, once, and not before")

    let decided = SudoReviewDeadline(timeLimit: .milliseconds(3_100))
    let notFired = Expiries()
    decided.watch { notFired.increment() }
    check(decided.decide(), "sudo deadline: a review decided before its deadline is decided")
    try? await Task.sleep(for: .milliseconds(400))
    check(notFired.value == 0, "sudo deadline: the watch leaves a decided review alone")
}

private func sudoReviewWireTimeLimitTests() {
    let request = SudoAuthorizationReviewRequest(
        submittedCommand: "sudo id", workingDirectory: "/Users/example", terminal: "/dev/ttys001",
        timeLimit: .milliseconds(287_431))
    guard let frame = SudoAuthorizationReviewWire.encode(request) else {
        check(false, "sudo wire v2: a review with a time limit encodes")
        return
    }
    check(SudoAuthorizationReviewWire.decode(frame)?.timeLimit == .milliseconds(287_431),
          "sudo wire v2: the time left crosses to the helper to the millisecond")
    check(Array(frame[8..<16]) == [0, 0, 0, 2, 0, 0x04, 0x62, 0xc7],
          "sudo wire v2: version 2, then the time limit, as the PAM module writes them")
    check(request.withDelegation(note: "n", pairingLine: nil).timeLimit == request.timeLimit,
          "sudo wire v2: csecd's note leaves the time limit alone")
    check(SudoAuthorizationReviewRequest(
        submittedCommand: "sudo id", workingDirectory: "/", terminal: "no tty").timeLimit == .seconds(300),
          "sudo wire v2: a review made here defaults to the PAM module's limit")

    func patched(_ frame: Data, at offset: Int, _ bytes: [UInt8]) -> Data {
        var copy = frame
        copy.replaceSubrange(offset..<(offset + bytes.count), with: bytes)
        return copy
    }
    check(SudoAuthorizationReviewWire.decode(patched(frame, at: 12, [0, 0, 0, 0])) == nil,
          "sudo wire v2: a frame with no time left is refused")
    check(SudoAuthorizationReviewWire.decode(patched(frame, at: 12, [0, 0x09, 0x27, 0xc1])) == nil,
          "sudo wire v2: a time limit past 600 s is refused")
    check(SudoAuthorizationReviewWire.decode(patched(frame, at: 12, [0, 0x09, 0x27, 0xc0]))?.timeLimit
            == .seconds(600),
          "sudo wire v2: 600 s is the longest accepted")
    check(SudoAuthorizationReviewWire.decode(patched(frame, at: 8, [0, 0, 0, 1])) == nil,
          "sudo wire v2: a version 1 frame, which carries no time limit, is refused")
    for limit: Duration in [.zero, .seconds(601)] {
        check(SudoAuthorizationReviewWire.encode(SudoAuthorizationReviewRequest(
            submittedCommand: "sudo id", workingDirectory: "/", terminal: "no tty", timeLimit: limit)) == nil,
              "sudo wire v2: a time limit the module never sends does not encode (\(limit))")
    }
}

private func reviewDeadlineHumanWaitTests() {
    let requester = HumanWait.Requester(pid: 51, startTime: 9)
    let arrived = ContinuousClock.now
    let agent = HumanWait(
        requester: requester, summary: "fixture", limit: .seconds(1_200),
        arrivedAt: arrived, arrivedAtDate: Date(timeIntervalSince1970: 0))
    check(ReviewDeadline(agent) == ReviewDeadline(instant: arrived + .seconds(1_200), date: Date(timeIntervalSince1970: 1_200)),
          "review deadline: a coding agent's request shows the moment csecd withdraws it")
    let decidedWait = HumanWait(requester: requester, summary: "fixture", limit: .seconds(1_200))
    decidedWait.decide()
    check(ReviewDeadline(decidedWait) == nil,
          "review deadline: a request already decided shows no deadline nobody enforces")
    check(ReviewDeadline(HumanWait(requester: requester, summary: "fixture", limit: nil)) == nil
            && ReviewDeadline(nil) == nil,
          "review deadline: a terminal's request, and a panel with no request wait, show no deadline")
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @MainActor
  private func reviewDeadlinePanelTests() {
    NSApplication.shared.setActivationPolicy(.accessory)
    func clipped(_ field: NSTextField) -> Bool {
        guard let cell = field.cell else { return true }
        let needed = cell.cellSize(forBounds: NSRect(x: 0, y: 0, width: field.bounds.width, height: .greatestFiniteMagnitude))
        return needed.height > field.bounds.height + 0.5
    }
    func line(_ panel: ApprovalPanelInspection) -> NSTextField? {
        panel.window.contentView?.layoutSubtreeIfNeeded()
        func find(_ view: NSView) -> NSTextField? {
            if let field = view as? NSTextField, field.identifier == ReviewDeadlineCountdown.lineIdentifier {
                return field
            }
            return view.subviews.lazy.compactMap(find).first
        }
        return panel.window.contentView.flatMap(find)
    }
    let caller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
        descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: nil, operationContext: "run migrations"
    )
    let credentials = [PolicyReviewCredential(references: [try! SecretRef("csec://dev/API_TOKEN")])]
    let access = AccessPolicyReview(
        caller: caller, reason: "run migrations", plan: plan, commandLine: "bin/rails db:migrate",
        credentials: credentials)
    let ssh = SSHAccessReviewDetails(
        hostNames: ["nimbus.local"], remoteUser: "root", keyLabel: "id_rsa", keyAlgorithm: "ssh-rsa")
    let sshReview = AccessPolicyReview(
        caller: caller, reason: ssh.reason,
        plan: DeliveryPlan(
            mechanism: .credentialProtocol,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
            descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
        ),
        credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/id_rsa")])],
        ssh: ssh)
    let sudoRequest = SudoAuthorizationReviewRequest(
        submittedCommand: "sudo id", workingDirectory: "/Users/example", terminal: "/dev/ttys009")
    let terminal = TerminalSessionContext(application: "iTerm2", title: "agent", location: "window 1, tab 1", tty: "ttys009")

    let later = ReviewDeadline(remaining: .seconds(1_200))
    // A counting panel takes its number from the clock when it is built, so
    // each is built just before it is read, from its own deadline, and the
    // number it may show runs from 12 down to what was left once it was
    // built: on a loaded Mac building panels can take more than a second.
    let panels: [(String, ApprovalPanelInspection, (ReviewDeadline) -> ApprovalPanelInspection, ApprovalPanelInspection)] = [
        ("secret-access", .access(access, deadline: later), { .access(access, deadline: $0) }, .access(access)),
        ("SSH", .access(sshReview, deadline: later), { .access(sshReview, deadline: $0) }, .access(sshReview)),
        ("sudo", .sudo(sudoRequest, terminal: terminal, deadline: later),
         { .sudo(sudoRequest, terminal: terminal, deadline: $0) }, .sudo(sudoRequest, terminal: terminal)),
    ]
    var countingPanels: [ApprovalPanelInspection] = []
    for (name, quiet, makeCounting, none) in panels {
        let quietLine = line(quiet)
        check(quietLine.map { $0.stringValue.hasPrefix("If nobody answers by") && !$0.isHidden && !clipped($0) } == true,
              "review deadline: the real \(name) panel shows the closing time whole")
        let soon = ReviewDeadline(remaining: .seconds(12))
        let counting = makeCounting(soon)
        countingPanels.append(counting)
        let left = soon.remaining
        let leftOnceBuilt = (0...12).first { Duration.seconds($0) >= left } ?? 12
        let countdown = line(counting)
        check(countdown.map { field in
            (max(leftOnceBuilt, 2)...12).contains { field.stringValue.hasPrefix("Closes in \($0) seconds if") }
                && field.textColor == .systemOrange && !clipped(field)
        } == true, "review deadline: the real \(name) panel counts down its last 30 s, drawn to be noticed "
            + "(\(countdown?.stringValue ?? "no line"))")
        check(quiet.window.frame.height == counting.window.frame.height,
              "review deadline: the \(name) panel is the same height counting down, so nothing moves")
        check(line(none) == nil && none.deadlineLine == nil,
              "review deadline: the \(name) panel shows no line without a deadline")
        check(counting.deadlineLine == countdown?.stringValue,
              "review deadline: the inspection reads the \(name) panel's line")
    }
    let restore = ApprovalPanelInspection.access(.restoreOnly(
        caller: caller, restore: RestoreReviewDetails(cause: .restart, rows: [RestoreReviewRow(
            kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
            references: ["csec://dev/API_TOKEN"])], storeCount: 1)))
    check(restore.deadlineLine == nil, "review deadline: the restore panel has no deadline")
    withExtendedLifetime((panels, countingPanels, restore)) {}
  }
#endif
