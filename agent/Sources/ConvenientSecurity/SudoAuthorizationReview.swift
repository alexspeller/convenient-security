import Foundation

public struct SudoAuthorizationReviewRequest: Sendable, Equatable {
  public let submittedCommand: String
  public let workingDirectory: String
  public let terminal: String
  /// Why Claude Code auto mode did not approve this sudo, from csecd's answer
  /// to `sudo_delegation` ("Auto mode didn't approve this: …"). Never part of
  /// the root→helper frame.
  public let delegationNote: String?
  /// The line saying that approving also lets auto mode run sudo in the
  /// project (`SudoPairingOffer`), from the same answer. The panel shows it
  /// whole whenever it is set: a sudo panel offers no scope or lifetime.
  public let pairingLine: String?
  /// How long was left of the PAM module's review deadline when it wrote the
  /// frame. The helper's own deadline starts from it (`SudoReviewDeadline`).
  public let timeLimit: Duration

  public init(
    submittedCommand: String,
    workingDirectory: String,
    terminal: String,
    delegationNote: String? = nil,
    pairingLine: String? = nil,
    timeLimit: Duration = SudoReviewDeadline.pamTimeLimit
  ) {
    self.timeLimit = timeLimit
    self.submittedCommand = ReviewDisplay.sanitized(submittedCommand)
    self.workingDirectory = ReviewDisplay.sanitized(workingDirectory)
    self.terminal = ReviewDisplay.sanitized(terminal)
    self.delegationNote = delegationNote.map {
      ReviewDisplay.bounded(ReviewDisplay.sanitized($0), maxBytes: SudoDelegationAnswer.maximumNoteBytes)
    }
    // Never shortened: approving agrees to all of it. An over-long line is
    // dropped, and the approval then pairs nothing (the helper reports only
    // an approval whose panel showed the line).
    self.pairingLine = pairingLine.map { ReviewDisplay.sanitized($0) }.flatMap {
      $0.isEmpty || $0.utf8.count > SudoDelegationAnswer.maximumPairingLineBytes ? nil : $0
    }
  }

  /// The same review, with csecd's note and pairing line.
  public func withDelegation(note: String?, pairingLine: String?) -> SudoAuthorizationReviewRequest {
    SudoAuthorizationReviewRequest(
      submittedCommand: submittedCommand, workingDirectory: workingDirectory, terminal: terminal,
      delegationNote: note, pairingLine: pairingLine, timeLimit: timeLimit
    )
  }
}

/// The sudo review's deadline, as the helper keeps it.
///
/// The PAM module ends the authentication `pamTimeLimit` after it launched
/// the helper, whatever the helper is doing (packaging/sudo/pam_csec_sudo.c),
/// and tells it how much of that is left in the frame. The helper closes the
/// review `closingMargin` before then, wherever it is — asking csecd about
/// delegation, waiting for another review's turn, or showing the panel, whose
/// deadline line (`ReviewDeadline`) counts down to this moment — and exits
/// `expiredExitStatus`, which the module turns into the same end of sudo its
/// own deadline gives, so the panel closes explained instead of being
/// SIGKILLed. The module still kills a helper that is late.
///
/// The latch is `HumanWait`'s: a human who answers at 4:56.9 is not overruled
/// by a close at 4:57. Whichever of `decide` and `expire` comes first wins.
/// What it cannot see is the moment between a touch and the race returning,
/// while the losing leg closes (milliseconds): an approval lost there ends
/// sudo as the deadline does and approves nothing.
public final class SudoReviewDeadline: @unchecked Sendable {
  /// `CSEC_REVIEW_TIMEOUT_MILLISECONDS`.
  public static let pamTimeLimit: Duration = .seconds(300)
  /// The longest time limit a frame may carry.
  public static let maximumTimeLimit: Duration = .seconds(600)
  /// How long before the module's deadline the helper closes the review:
  /// enough to close the window and withdraw the phone copy first, and to
  /// absorb the helper's own start, which the frame's time limit already
  /// counts against it. It is also longer than the pairing call a last-moment
  /// approval may still make (`fitsBeforeModuleDeadline`).
  public static let closingMargin: Duration = .seconds(3)
  /// `CSEC_REVIEW_EXPIRED_EXIT_STATUS`. The module believes it only within
  /// 10 s of its own deadline (`CSEC_REVIEW_EXPIRY_CLAIM_MILLISECONDS`), so a
  /// helper that exits with it early falls back to the password prompt.
  public static let expiredExitStatus: Int32 = 75

  private enum State {
    case pending
    case decided
    case expired
  }

  /// When the helper closes the review.
  public let closing: ReviewDeadline
  /// When the module ends the authentication, by the helper's reckoning.
  private let moduleDeadline: ContinuousClock.Instant
  private let lock = NSLock()
  private var state = State.pending

  /// `timeLimit` from the frame, measured from `now`, the moment the frame was
  /// read: the module wrote it just before.
  public init(timeLimit: Duration, now: ContinuousClock.Instant = .now, nowDate: Date = Date()) {
    let closesIn = max(.zero, timeLimit - Self.closingMargin)
    closing = ReviewDeadline(remaining: closesIn, now: now, nowDate: nowDate)
    moduleDeadline = now + timeLimit
  }

  /// Whether work bounded by `duration` (and a moment to exit) still ends
  /// before the module's own deadline. An approval made just before the close
  /// must not be turned into the module's expiry by what follows it.
  public func fitsBeforeModuleDeadline(_ duration: Duration, now: ContinuousClock.Instant = .now) -> Bool {
    now + duration + .milliseconds(250) < moduleDeadline
  }

  /// A decision ended the review. True unless the deadline came first.
  @discardableResult
  public func decide() -> Bool {
    lock.withLock {
      switch state {
      case .pending, .decided:
        state = .decided
        return true
      case .expired:
        return false
      }
    }
  }

  /// The deadline passed. True only if nothing had decided the review.
  public func expire() -> Bool {
    lock.withLock {
      guard state == .pending else { return false }
      state = .expired
      return true
    }
  }

  /// At the deadline, unless something decided the review first, run
  /// `onExpire`, once, off the main thread; the helper cancels the review
  /// with it.
  public func watch(onExpire: @escaping @Sendable () -> Void) {
    let instant = closing.instant
    Task.detached { [self] in
      // An explicit tolerance: by default a sleep this long may fire seconds
      // late (measured 2 s on a 32 s sleep), eating the closing margin.
      try? await Task.sleep(until: instant, tolerance: .milliseconds(50), clock: .continuous)
      if self.expire() { onExpire() }
    }
  }
}

public enum SudoAuthorizationReviewOutcome: Sendable, Equatable {
  case approved
  case usePassword
}

/// What a failed biometric evaluation means on the sudo review surface, given
/// whether the screen was locked at the moment it failed.
///
/// A cancellation behind the lock screen cannot be the human choosing Use
/// Password: the panel is not reachable, so the cancel is system-initiated. The
/// review is therefore held open and Touch ID re-presented after unlock, rather
/// than failing a sudo the human never saw over to the password prompt.
/// Unlocked, the failure goes on to `ReviewTouchIDUnavailable.afterFailure`,
/// which keeps the panel up for a system cancel and otherwise ends it with
/// the password. The live lock/unlock cycle can only be exercised on-device;
/// this decision is the part `cs-selftest` can check. See `ScreenLockState`.
public enum SudoAuthorizationReviewFailure {
  public enum Response: Sendable, Equatable {
    /// Hold the panel open and re-present Touch ID once the Mac is unlocked.
    case waitForUnlock
    /// Finish the review and let sudo ask for a password.
    case usePassword
  }

  public static func response(screenLocked: Bool) -> Response {
    switch ScreenLockState.action(screenLocked: screenLocked) {
    case .waitForUnlock: return .waitForUnlock
    case .deny: return .usePassword
    }
  }
}

/// What the sudo review does with Touch ID unavailable on this Mac: no
/// fingerprint enrolled, Touch ID locked out after failed attempts, or the
/// lid closed with no Touch ID keyboard.
///
/// The panel cannot approve then; only the paired phone can. While the phone
/// may still decide, the panel stays up, so the person at the Mac sees what
/// is waiting and can still choose Use Password. Once the phone cannot
/// decide either, nobody can approve, and a panel left up would only hold
/// sudo until someone clicks Use Password or PAM's deadline passes. So the
/// review ends at once, unsuccessful, and sudo falls back to Apple's own
/// prompt, which takes the password. The live panel can only be exercised
/// on-device (`csec-sudo-review --no-touch-id-probe`); this decision is the
/// part `cs-selftest` can check.
public enum SudoReviewWithoutTouchID {
  public enum Response: Sendable, Equatable {
    /// Touch ID works: arm it as usual.
    case armTouchID
    /// Keep the panel up for the phone, closing it if the phone cannot decide.
    case waitForPhone
    /// End the review now, before anything is drawn.
    case usePassword
  }

  public static func response(touchIDAvailable: Bool, phoneCanDecide: Bool) -> Response {
    if touchIDAvailable { return .armTouchID }
    return phoneCanDecide ? .waitForPhone : .usePassword
  }
}

/// Closes the sudo review when the sudo that asked for it is gone.
///
/// The PAM module spawns the helper in a process group of its own, so no
/// terminal signal reaches it, and the module kills and reaps it on every exit
/// path it controls — an approval, a timeout, a Ctrl-C or Ctrl-\ it finds
/// pending, or the terminal hanging up (packaging/sudo/pam_csec_sudo.c). What
/// the module cannot cover is its own process dying: a SIGKILLed or crashed
/// sudo leaves the helper orphaned with its panel, and a live Touch ID, up for
/// nobody. So the helper watches its original parent with a kqueue
/// `EVFILT_PROC`/`NOTE_EXIT` filter and closes as unsuccessful when it exits.
public enum SudoReviewParentWatch {
  /// Arm the watch on `originalParent`, the helper's parent pid read as early
  /// as possible at startup. `onExit` runs once, off the main thread, when that
  /// process exits. Returns false — and never calls `onExit` — when the parent
  /// is already gone, which the caller must treat the same way.
  public static func start(
    originalParent: pid_t,
    onExit: @escaping @Sendable () -> Void
  ) -> Bool {
    // A helper whose parent had already exited was reparented to launchd.
    guard originalParent > 1 else { return false }
    let queue = kqueue()
    guard queue >= 0 else { return false }
    var change = kevent(
      ident: UInt(originalParent),
      filter: Int16(EVFILT_PROC),
      flags: UInt16(EV_ADD | EV_ONESHOT),
      fflags: UInt32(NOTE_EXIT),
      data: 0,
      udata: nil
    )
    // ESRCH: the parent exited before the filter could attach.
    guard kevent(queue, &change, 1, nil, 0, nil) == 0 else {
      close(queue)
      return false
    }
    // The parent can exit between the caller reading its pid and the filter
    // attaching. Exit reparents this process first, so a parent that is still
    // ours now is one whose exit the filter will report.
    guard getppid() == originalParent else {
      close(queue)
      return false
    }
    Thread.detachNewThread {
      var event = kevent()
      while kevent(queue, nil, 0, &event, 1, nil) < 0 && errno == EINTR {}
      // The exit itself, or a watch that can no longer report one: either
      // way nothing is left to answer this review.
      close(queue)
      onExit()
    }
    return true
  }
}

/// Narrow binary handoff from the root PAM process to the unprivileged review
/// helper. The command is already escaped and redacted before it enters this
/// frame; no raw argv or secret catalog crosses this boundary.
public enum SudoAuthorizationReviewWire {
  public static let maximumCommandBytes = 8_191
  public static let maximumContextBytes = 255

  private static let magic = Data("CSECSUDO".utf8)
  /// 2 added the time limit, in milliseconds, after the version.
  private static let version = 2
  private static let headerBytes = 8 + 4 + 4 + 4 + 4 + 4

  public static func encode(_ request: SudoAuthorizationReviewRequest) -> Data? {
    let command = Data(request.submittedCommand.utf8)
    let directory = Data(request.workingDirectory.utf8)
    let terminal = Data(request.terminal.utf8)
    guard let timeLimit = milliseconds(request.timeLimit),
      !command.isEmpty,
      command.count <= maximumCommandBytes,
      directory.count <= maximumContextBytes,
      terminal.count <= maximumContextBytes,
      !command.contains(0),
      !directory.contains(0),
      !terminal.contains(0)
    else { return nil }

    var frame = Data()
    frame.reserveCapacity(headerBytes + command.count + directory.count + terminal.count)
    frame.append(magic)
    appendUInt32(UInt32(version), to: &frame)
    appendUInt32(timeLimit, to: &frame)
    appendUInt32(UInt32(command.count), to: &frame)
    appendUInt32(UInt32(directory.count), to: &frame)
    appendUInt32(UInt32(terminal.count), to: &frame)
    frame.append(command)
    frame.append(directory)
    frame.append(terminal)
    return frame
  }

  public static func decode(_ frame: Data) -> SudoAuthorizationReviewRequest? {
    guard frame.count >= headerBytes,
      frame.prefix(magic.count) == magic
    else { return nil }

    var offset = magic.count
    guard let decodedVersion = readUInt32(frame, offset: &offset),
      decodedVersion == version,
      let timeLimit = readUInt32(frame, offset: &offset),
      timeLimit > 0,
      timeLimit <= Int(SudoReviewDeadline.maximumTimeLimit.components.seconds) * 1_000,
      let commandLength = readUInt32(frame, offset: &offset),
      let directoryLength = readUInt32(frame, offset: &offset),
      let terminalLength = readUInt32(frame, offset: &offset),
      commandLength > 0,
      commandLength <= maximumCommandBytes,
      directoryLength <= maximumContextBytes,
      terminalLength <= maximumContextBytes
    else { return nil }

    let lengths = [commandLength, directoryLength, terminalLength]
    guard lengths.allSatisfy({ $0 <= Int.max - offset }) else { return nil }
    let expectedPayload = lengths.reduce(0, +)
    guard expectedPayload == frame.count - offset else { return nil }

    func readString(length: Int) -> String? {
      guard length <= frame.count - offset else { return nil }
      let bytes = frame[offset..<(offset + length)]
      offset += length
      guard !bytes.contains(0) else { return nil }
      return String(data: bytes, encoding: .utf8)
    }

    guard let command = readString(length: commandLength),
      let directory = readString(length: directoryLength),
      let terminal = readString(length: terminalLength),
      offset == frame.count
    else { return nil }
    return SudoAuthorizationReviewRequest(
      submittedCommand: command,
      workingDirectory: directory,
      terminal: terminal,
      timeLimit: .milliseconds(timeLimit)
    )
  }

  /// A time limit the frame can carry, in whole milliseconds.
  private static func milliseconds(_ duration: Duration) -> UInt32? {
    guard duration > .zero, duration <= SudoReviewDeadline.maximumTimeLimit else { return nil }
    let parts = duration.components
    return UInt32(parts.seconds * 1_000 + parts.attoseconds / 1_000_000_000_000_000)
  }

  private static func appendUInt32(_ value: UInt32, to data: inout Data) {
    data.append(UInt8((value >> 24) & 0xff))
    data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
  }

  private static func readUInt32(_ data: Data, offset: inout Int) -> Int? {
    guard data.count - offset >= 4 else { return nil }
    let value =
      (UInt32(data[offset]) << 24)
      | (UInt32(data[offset + 1]) << 16)
      | (UInt32(data[offset + 2]) << 8)
      | UInt32(data[offset + 3])
    offset += 4
    return Int(value)
  }
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @preconcurrency import AppKit
  @preconcurrency import LocalAuthentication
  @preconcurrency import LocalAuthenticationEmbeddedUI

  @MainActor
  public final class TrustedSudoAuthorizationReviewSession: NSObject, NSWindowDelegate {
    private enum State {
      case ready
      case authenticating
      // The prompt was cancelled while the screen was locked. The review is
      // held open — not failed over to sudo's password prompt — until the Mac
      // is unlocked and Touch ID can be re-presented. See ScreenLockState.
      case waitingForUnlock
      case finished
    }

    /// The note's accessibility identifier, for `ApprovalPanelInspection`.
    static let delegationNoteIdentifier = "delegation-note"

    private static let contentWidth: CGFloat = 640
    private static let horizontalMargin: CGFloat = 28
    private static var innerWidth: CGFloat { contentWidth - horizontalMargin * 2 }

    private let review: SudoAuthorizationReviewRequest
    /// Which terminal tab is running sudo, resolved by the helper from the PAM
    /// tty before the window is built. Never part of the root→helper frame.
    private let terminal: TerminalSessionContext
    /// Whether the paired phone may still decide, from the helper's race. It
    /// matters only when this Mac cannot take a touch
    /// (`SudoReviewWithoutTouchID`).
    private let phone: ReviewPhoneStatus
    /// When the helper closes this review unanswered (`SudoReviewDeadline`),
    /// shown by the deadline line under the status line.
    private let deadline: ReviewDeadline?
    private var deadlineCountdown: ReviewDeadlineCountdown?
    // Not `let`: a prompt cancelled behind the lock screen spends its context,
    // and another prompt can strand it (`ReviewFocusRecovery`), so the unlock
    // retry and the focus re-arm evaluate a fresh one (and re-bind the
    // embedded view).
    // Both come from `ReviewAuthenticationContext`, which is where the
    // Touch-ID-reuse and button-title invariants live for all three surfaces.
    private var context = ReviewAuthenticationContext.make(for: .sudo)
    private var state = State.ready
    private var continuation: CheckedContinuation<SudoAuthorizationReviewOutcome, Never>?
    private var biometricsAvailable = false
    /// A dev-only stand-in for a Mac with no Touch ID; nil for every review.
    private let touchIDOverride: ReviewTouchIDOverride?
    /// When the panel was built, which the override's intervals count from.
    private let builtAt = ContinuousClock.now
    /// Polls for Touch ID coming back while the panel is up without it.
    private var touchIDWatch: TouchIDAvailabilityWatch?
    /// Drives the wait for the Mac to unlock while `state == .waitingForUnlock`.
    /// Polling (not the `com.apple.screenIsUnlocked` notification) so a dropped
    /// notification cannot strand a held-open review. Runs only while waiting.
    private var unlockPollTimer: Timer?
    /// Counts Touch ID evaluations. A re-arm invalidates a still-pending
    /// evaluation, whose late cancellation must not be read as this panel's
    /// answer, so each callback carries the generation it was started as.
    private var authenticationGeneration = 0
    /// Whether the window resigned key while the current evaluation was armed,
    /// and whether that evaluation started while the window was not key and it
    /// has not been key since. See `ReviewFocusRecovery`.
    private var lostKeyWhileArmed = false
    private var armedWhileNotKey = false
    /// Whether the panel renewed Touch ID after a system cancel since it last
    /// became or resigned key (`ReviewFocusRecovery.onSystemCancel`).
    private var renewedAfterSystemCancelWhileKey = false

    private var window: NSPanel!
    private var authenticationView: LAAuthenticationView!
    /// The vertical stack holding `authenticationView` + `statusLabel`, retained
    /// so the embedded Touch ID view can be swapped for a fresh-context one on an
    /// unlock retry or a focus re-arm.
    private var authenticationArea: NSStackView!
    private var statusLabel: NSTextField!
    private var fallbackButton: NSButton!
    /// The submitted command, sized to the screen once the window is built.
    private var commandText: ReviewCommandText!
    /// Every control a keystroke or click can act on, registered as it is
    /// built, so the grace period can hold all of them back together.
    private(set) var interactiveControls: [NSControl] = []
    private var interactionGrace: PromptInteractionGrace?

    private init(
      review: SudoAuthorizationReviewRequest,
      terminal: TerminalSessionContext,
      phone: ReviewPhoneStatus,
      deadline: ReviewDeadline?,
      touchID: ReviewTouchIDOverride? = nil
    ) {
      self.review = review
      self.terminal = terminal
      self.phone = phone
      self.deadline = deadline
      self.touchIDOverride = touchID
      super.init()
      configureAuthentication()
      configureWindow()
    }

    /// Cancelling the calling task closes the panel as unsuccessful: the
    /// window closes and its LAContext is invalidated, so the losing side can
    /// never produce a second decision. The helper cancels it when the sudo
    /// that asked has exited (`SudoReviewParentWatch`): the panel, and its live
    /// Touch ID, must not stay up for nobody. It also cancels it when the
    /// paired phone answered first (`SudoReviewRace`), exactly as a phone
    /// decision closes the access and SSH panels; the helper then reports the
    /// phone's answer, never this panel's.
    ///
    /// `phone` is the race's word on whether the phone may still decide. With
    /// no Touch ID on this Mac the panel is shown only while it may, and
    /// returns `.usePassword` the moment it cannot (`SudoReviewWithoutTouchID`).
    /// If Touch ID comes back while the panel is up (the lid opened), the
    /// panel arms it (`TouchIDAvailabilityWatch`). `touchID` treats Touch ID
    /// as unavailable whatever this Mac says, for the dev probes; it can never
    /// make Touch ID available.
    ///
    /// `deadline` is when the helper will close the review unanswered
    /// (`SudoReviewDeadline.closing`); the panel shows it and counts down to
    /// it, and the helper's cancellation closes it.
    public static func present(
      _ review: SudoAuthorizationReviewRequest,
      terminal: TerminalSessionContext,
      phone: ReviewPhoneStatus,
      deadline: ReviewDeadline?,
      touchID: ReviewTouchIDOverride? = nil
    ) async -> SudoAuthorizationReviewOutcome {
      guard !Task.isCancelled else { return .usePassword }
      let session = TrustedSudoAuthorizationReviewSession(
        review: review, terminal: terminal, phone: phone, deadline: deadline,
        touchID: touchID)
      return await withTaskCancellationHandler {
        await session.run()
      } onCancel: {
        Task { @MainActor in
          session.requesterGone()
        }
      }
    }

    /// The real panel, never ordered onscreen and with no Touch ID evaluation
    /// started (`ApprovalPanelInspection`).
    static func unpresented(
      _ review: SudoAuthorizationReviewRequest,
      terminal: TerminalSessionContext,
      deadline: ReviewDeadline?,
      touchID: ReviewTouchIDOverride? = nil
    ) -> (window: NSPanel, owner: AnyObject) {
      let session = TrustedSudoAuthorizationReviewSession(
        review: review, terminal: terminal, phone: ReviewPhoneStatus(),
        deadline: deadline, touchID: touchID)
      return (session.window, session)
    }

    /// Dev-only, value-free design harness. It renders the real panel without
    /// ordering it onscreen or starting LocalAuthentication. With no
    /// `deadline` it shows the one a fresh review has.
    public static func previewPNG(
      _ review: SudoAuthorizationReviewRequest,
      terminal: TerminalSessionContext,
      deadline: ReviewDeadline? = nil,
      touchID: ReviewTouchIDOverride? = nil
    ) -> Data? {
      let session = TrustedSudoAuthorizationReviewSession(
        review: review, terminal: terminal, phone: ReviewPhoneStatus(),
        deadline: deadline ?? SudoReviewDeadline(timeLimit: review.timeLimit).closing,
        touchID: touchID)
      guard let content = session.window.contentView else { return nil }
      let target = content.superview ?? content
      target.layoutSubtreeIfNeeded()
      session.window.displayIfNeeded()
      guard let bitmap = target.bitmapImageRepForCachingDisplay(in: target.bounds) else {
        return nil
      }
      target.cacheDisplay(in: target.bounds, to: bitmap)
      return bitmap.representation(using: .png, properties: [:])
    }

    private func configureAuthentication() {
      biometricsAvailable =
        touchIDOverride?.holdsUnavailable(builtAt: builtAt) != true
        && ReviewTouchIDUnavailable.isAvailable(context)
    }

    private func configureWindow() {
      window = NSPanel(
        contentRect: NSRect(x: 0, y: 0, width: Self.contentWidth, height: 400),
        styleMask: [.titled, .closable],
        backing: .buffered,
        defer: false
      )
      window.title = ReviewTestBanner.title("Convenient Security")
      window.isRestorable = false
      window.isReleasedWhenClosed = false
      window.hidesOnDeactivate = false
      window.level = .modalPanel
      window.delegate = self

      // Keyboard focus rests on the content view itself, never on Use
      // Password…: see PromptKeyboardSink.
      let contentView = PromptKeyboardSink.install(in: window)

      let root = NSStackView()
      root.orientation = .vertical
      root.alignment = .leading
      root.spacing = 16
      root.translatesAutoresizingMaskIntoConstraints = false
      contentView.addSubview(root)

      // A panel a developer check put on screen says so before anything else,
      // in every variant (ReviewTestBanner); a real request never has it.
      if let testBanner = ReviewTestBanner.view(width: Self.innerWidth) {
        root.addArrangedSubview(testBanner)
      }
      root.addArrangedSubview(makeHeader())
      root.addArrangedSubview(
        Self.makeBanner(
          text: "ADMINISTRATOR ACCESS: An approved sudo command can modify any local "
            + "account or system file. Verify every displayed argument before touching "
            + "the sensor.",
          tint: .systemOrange,
          width: Self.innerWidth
        ))

      // Which tab is asking leads, at the weight the secret-access panel gives
      // it, ahead of the command it ran.
      root.addArrangedSubview(makeTerminalFact())

      root.addArrangedSubview(Self.makeSectionLabel("Submitted command"))
      root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
      root.addArrangedSubview(makeCommandCard(width: Self.innerWidth))

      root.addArrangedSubview(Self.makeSectionLabel("Request"))
      root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
      root.addArrangedSubview(makeDetailsGrid())

      let footnote = NSTextField(
        wrappingLabelWithString:
          "This is the frozen, redacted submitted argv received before Touch ID starts. "
          + "Touch ID verifies the current user; it does not attest the window pixels. "
          + "Sudo policy resolves the executable after authentication."
      )
      footnote.font = .systemFont(ofSize: 11)
      footnote.textColor = .tertiaryLabelColor
      footnote.maximumNumberOfLines = 4
      footnote.preferredMaxLayoutWidth = Self.innerWidth
      root.addArrangedSubview(footnote)
      // Why Claude Code auto mode did not approve this sudo on its own, as the
      // secret-access and SSH panels say it below their footnotes.
      if let delegationNote = review.delegationNote, !delegationNote.isEmpty {
        root.setCustomSpacing(6, after: footnote)
        let note = NSTextField(wrappingLabelWithString: delegationNote)
        note.font = .systemFont(ofSize: 11)
        note.textColor = .tertiaryLabelColor
        note.maximumNumberOfLines = 3
        note.preferredMaxLayoutWidth = Self.innerWidth
        note.identifier = NSUserInterfaceItemIdentifier(Self.delegationNoteIdentifier)
        root.addArrangedSubview(note)
      }
      // What approving also allows: the access and SSH panels' pairing line,
      // shown whenever it is offered, since nothing here selects a scope.
      if let pairingLine = review.pairingLine {
        let line = NSTextField(wrappingLabelWithString: pairingLine)
        line.font = .systemFont(ofSize: 12, weight: .medium)
        line.textColor = .secondaryLabelColor
        line.maximumNumberOfLines = 0
        line.preferredMaxLayoutWidth = Self.innerWidth
        line.identifier = PromptInteractionGraceProbe.pairingLineIdentifier
        root.addArrangedSubview(line)
      }

      let separator = NSBox()
      separator.boxType = .separator
      root.addArrangedSubview(separator)
      root.addArrangedSubview(makeAuthenticationArea())
      root.addArrangedSubview(makeFooter())

      NSLayoutConstraint.activate([
        root.leadingAnchor.constraint(
          equalTo: contentView.leadingAnchor, constant: Self.horizontalMargin),
        root.trailingAnchor.constraint(
          equalTo: contentView.trailingAnchor, constant: -Self.horizontalMargin),
        root.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 22),
        root.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -18),
        root.widthAnchor.constraint(equalToConstant: Self.innerWidth),
        separator.widthAnchor.constraint(equalTo: root.widthAnchor),
      ])

      // The whole command, scrolling only in what the screen leaves. It is
      // this panel's one such view; the access panel fits its lists and
      // commands through the same call (`ReviewScreenFit`).
      ReviewScreenFit.fit([commandText], in: window)
      contentView.layoutSubtreeIfNeeded()
      window.setContentSize(contentView.fittingSize)
    }

    private func makeHeader() -> NSView {
      let icon = NSImageView()
      icon.image = NSImage(
        systemSymbolName: "lock.shield.fill",
        accessibilityDescription: "Convenient Security"
      )
      icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 30, weight: .medium)
        .applying(.init(hierarchicalColor: .controlAccentColor))
      icon.setContentHuggingPriority(.required, for: .horizontal)
      NSLayoutConstraint.activate([
        icon.widthAnchor.constraint(equalToConstant: 44),
        icon.heightAnchor.constraint(equalToConstant: 44),
      ])

      let title = NSTextField(labelWithString: "Administrator Access Requested")
      title.font = .systemFont(ofSize: 19, weight: .semibold)

      let purpose = NSTextField(
        wrappingLabelWithString:
          "sudo wants to run the submitted command with administrator privileges."
      )
      purpose.font = .systemFont(ofSize: 13)
      purpose.textColor = .labelColor
      purpose.maximumNumberOfLines = 3
      purpose.preferredMaxLayoutWidth = Self.innerWidth - 58

      let labels = NSStackView(views: [title, purpose])
      labels.orientation = .vertical
      labels.alignment = .leading
      labels.spacing = 3

      let header = NSStackView(views: [icon, labels])
      header.orientation = .horizontal
      header.alignment = .centerY
      header.spacing = 14
      return header
    }

    /// The submitted command in its card, whole: see `ReviewCommandText`.
    private func makeCommandCard(width: CGFloat) -> NSView {
      let text = ReviewCommandText(
        review.submittedCommand, font: .monospacedSystemFont(ofSize: 12.5, weight: .regular),
        // Inside the card's 12-point padding and 1-point border.
        width: width - 26, inset: .zero, borderType: .noBorder)
      commandText = text
      let card = Self.card(
        wrapping: text.scrollView,
        fill: NSColor.labelColor.withAlphaComponent(0.045),
        border: NSColor.separatorColor,
        width: width
      )
      let stack = NSStackView(views: [card, text.overflowCue])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 6
      return stack
    }

    /// The tab's displayed title as the headline; the parts a process in the
    /// tab cannot forge, and sudo's own tty where it differs, below it
    /// (`SudoAuthorizationReviewRequest.terminalFact`).
    private func makeTerminalFact() -> NSView {
      let fact = review.terminalFact(terminal)
      let title = NSTextField(wrappingLabelWithString: ReviewDisplay.sanitized(fact.title))
      title.font = .systemFont(ofSize: 22, weight: .semibold)
      title.textColor = .labelColor
      // Wraps rather than truncates: the title is the tab's own, so nothing
      // of it may be elided.
      title.maximumNumberOfLines = 4
      title.preferredMaxLayoutWidth = Self.innerWidth
      title.identifier = NSUserInterfaceItemIdentifier(Self.terminalTitleIdentifier)

      let detail = NSTextField(wrappingLabelWithString: ReviewDisplay.sanitized(fact.detail))
      detail.font = .systemFont(ofSize: 12)
      detail.textColor = .secondaryLabelColor
      detail.maximumNumberOfLines = 3
      detail.preferredMaxLayoutWidth = Self.innerWidth
      detail.identifier = NSUserInterfaceItemIdentifier(Self.terminalDetailIdentifier)

      let stack = NSStackView(views: [Self.makeSectionLabel("Terminal tab"), title, detail])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 3
      stack.setCustomSpacing(5, after: stack.arrangedSubviews[0])
      stack.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
      return stack
    }

    /// Mark the terminal fact's two lines, so a test can find them.
    public static let terminalTitleIdentifier = "csec.sudo-review.terminal-title"
    public static let terminalDetailIdentifier = "csec.sudo-review.terminal-detail"

    private func makeDetailsGrid() -> NSView {
      // The terminal leads the panel (`makeTerminalFact`), so it has no row here.
      let rows: [(String, String)] = [
        ("Requested by", "sudo"),
        ("Privilege", "Administrator (root)"),
        ("Working directory", review.workingDirectory),
        ("Argument filtering", "Active csec catalog + secret-like heuristics"),
      ]
      let grid = NSGridView(
        views: rows.map { [Self.gridLabel($0.0), Self.gridValue($0.1)] }
      )
      grid.columnSpacing = 14
      grid.rowSpacing = 6
      grid.rowAlignment = .none
      grid.column(at: 0).xPlacement = .trailing
      grid.translatesAutoresizingMaskIntoConstraints = false
      // The panel's full width, labels right-aligned against the values.
      grid.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
      return grid
    }

    /// The status line while Touch ID is armed. `beginAuthentication` restores
    /// it, so an unlock retry replaces the waiting-for-unlock copy.
    private var authenticationStatusText: String {
      biometricsAvailable
        ? "Touch ID is active. Touch the sensor to authorize, or use your password."
        : Self.touchIDUnavailableText
    }

    /// The status line when this Mac cannot take a touch. The panel is up
    /// only while the phone may still decide (`SudoReviewWithoutTouchID`).
    public static let touchIDUnavailableText =
      ReviewTouchIDUnavailable.statusText(for: .sudo, phoneCanDecide: true)

    private func makeAuthenticationArea() -> NSView {
      authenticationView = LAAuthenticationView(context: context, controlSize: .large)
      authenticationView.setContentHuggingPriority(.required, for: .horizontal)
      authenticationView.setContentCompressionResistancePriority(.required, for: .horizontal)
      // With no Touch ID the embedded view draws nothing and is never armed;
      // the stack collapses it, so the status line says what to do instead.
      authenticationView.isHidden = !biometricsAvailable

      statusLabel = NSTextField(wrappingLabelWithString: authenticationStatusText)
      statusLabel.font = .systemFont(ofSize: 12)
      statusLabel.textColor = biometricsAvailable ? .secondaryLabelColor : .systemRed
      statusLabel.alignment = .center
      statusLabel.maximumNumberOfLines = 3
      statusLabel.preferredMaxLayoutWidth = Self.innerWidth - 80

      var views: [NSView] = [authenticationView, statusLabel]
      // Under the status line, whose messages (click to resume, waiting for
      // unlock) it never replaces. Present from the start, so the countdown
      // moves nothing.
      if let deadline {
        let countdown = ReviewDeadlineCountdown(
          deadline: deadline, width: Self.innerWidth - 80, alignment: .center)
        deadlineCountdown = countdown
        views.append(countdown.label)
      }
      let area = NSStackView(views: views)
      area.orientation = .vertical
      area.alignment = .centerX
      area.spacing = 8
      area.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
      authenticationArea = area
      return area
    }

    private func makeFooter() -> NSView {
      let spacer = NSView()
      spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
      spacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

      fallbackButton = NSButton(
        title: "Use Password…",
        target: self,
        action: #selector(usePasswordPressed(_:))
      )
      fallbackButton.keyEquivalent = "\u{1b}"
      fallbackButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 112).isActive = true
      interactiveControls.append(fallbackButton)

      let footer = NSStackView(views: [spacer, fallbackButton])
      footer.orientation = .horizontal
      footer.alignment = .centerY
      footer.spacing = 10
      footer.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
      return footer
    }

    private func run() async -> SudoAuthorizationReviewOutcome {
      guard state == .ready else { return .usePassword }
      let withoutTouchID = SudoReviewWithoutTouchID.response(
        touchIDAvailable: biometricsAvailable, phoneCanDecide: phone.canDecide)
      // Nobody can approve: no window, no grace, and sudo goes straight on to
      // Apple's prompt.
      if withoutTouchID == .usePassword {
        SudoReviewLog.record(.touchIDUnavailable(.noPhone))
        finish(.usePassword)
        return .usePassword
      }
      return await withCheckedContinuation { continuation in
        self.continuation = continuation
        NSApplication.shared.setActivationPolicy(.accessory)
        window.center()
        // Visible at once, but neither key nor interactive until the grace
        // period passes, so the tail of a typed sentence cannot press Use
        // Password. Touch ID below starts now, not after the grace, though
        // macOS hands it a touch only once the panel is key.
        let grace = PromptInteractionGrace(window: window, controls: interactiveControls)
        interactionGrace = grace
        grace.begin()
        window.displayIfNeeded()
        beginAuthentication()
        deadlineCountdown?.start()
        // With no Touch ID, `beginAuthentication` armed nothing: the panel is
        // up for the phone alone, and closes once the phone cannot decide.
        if withoutTouchID == .waitForPhone {
          waitForPhone()
        }
      }
    }

    /// Up for the phone alone, with no Touch ID to arm: on first
    /// presentation, or once Touch ID went away under an armed evaluation
    /// (`touchIDLost`).
    private func waitForPhone() {
      SudoReviewLog.record(.touchIDUnavailable(.waitingForPhone))
      phone.whenUnavailable { [weak self] in
        DispatchQueue.main.async { self?.phoneCannotDecide() }
      }
      // If Touch ID comes back first (the lid opened), arm it.
      let watch = TouchIDAvailabilityWatch(surface: .sudo, override: touchIDOverride, builtAt: builtAt)
      touchIDWatch = watch
      watch.start { [weak self] available in self?.touchIDPolled(available: available) }
    }

    /// One poll of `touchIDWatch`: arm Touch ID once it is back with the
    /// screen unlocked. The parent watch already closes this helper when its
    /// sudo is gone, so the requester counts as alive here.
    private func touchIDPolled(available: Bool) {
      guard state == .ready, !biometricsAvailable else {
        stopTouchIDWatch()
        return
      }
      switch ReviewTouchIDUnavailable.onPoll(
        touchIDAvailable: available,
        screenLocked: available && ScreenLockState.isScreenLocked,
        requesterAlive: true
      ) {
      case .keepWaiting, .requesterGone:
        return
      case .arm:
        stopTouchIDWatch()
        SudoReviewLog.record(.touchIDUnavailable(.returned))
        biometricsAvailable = true
        // A fresh context from the factory, with its Touch ID view shown in
        // place of the hidden one, armed the way the first presentation arms.
        rebuildAuthenticationContext()
        beginAuthentication()
      }
    }

    private func stopTouchIDWatch() {
      touchIDWatch?.stop()
      touchIDWatch = nil
    }

    /// The phone turned out unable to decide while this panel, with no Touch
    /// ID to arm, was up for it: nobody is left to approve.
    private func phoneCannotDecide() {
      guard !biometricsAvailable, state != .finished else { return }
      SudoReviewLog.record(.touchIDUnavailable(.phoneCannotDecide))
      finish(.usePassword)
    }

    private func beginAuthentication() {
      guard state == .ready, biometricsAvailable else { return }
      state = .authenticating
      authenticationGeneration += 1
      let generation = authenticationGeneration
      lostKeyWhileArmed = false
      armedWhileNotKey = !window.isKeyWindow
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = authenticationStatusText
      context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason:
          "Confirm administrator access after reviewing the submitted sudo invocation."
      ) { [weak self] success, error in
        DispatchQueue.main.async {
          self?.authenticationFinished(success: success, error: error, generation: generation)
        }
      }
      // Dev-only (`ReviewTouchIDOverride.lostAfter`): the lid closes under
      // this evaluation, which ends the way the system would end it.
      if let delay = touchIDOverride?.endsArmedEvaluation(builtAt: builtAt) {
        Task { @MainActor [weak self] in
          try? await Task.sleep(for: delay)
          guard let self, self.state == .authenticating, self.authenticationGeneration == generation
          else { return }
          self.context.invalidate()
        }
      }
    }

    /// Key status left the panel while Touch ID was armed. Touches reach only
    /// the window in front, and whatever took the focus may have taken the
    /// sensor too, so say what brings Touch ID back.
    public func windowDidResignKey(_ notification: Notification) {
      renewedAfterSystemCancelWhileKey = false
      guard ReviewFocusRecovery.onResignKey(authenticating: state == .authenticating)
        == .showClickToResume
      else { return }
      lostKeyWhileArmed = true
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = ReviewFocusRecovery.clickToResumeText
    }

    /// The panel is key, and Touch ID was armed while it could not take a
    /// touch: another prompt may have stranded that evaluation, which then
    /// never answers (`ReviewFocusRecovery`). After losing key, Use Password is
    /// held back at once — the click or keystrokes that made the panel key are
    /// still being delivered — behind a guard that never takes the focus back:
    /// the human made this panel key, and if they have left it again by the
    /// time the guard ends, the focus is theirs (another armed panel doing the
    /// same would otherwise trade the focus with this one forever). The
    /// evaluation itself is renewed one run-loop turn later, so the Touch ID
    /// view that click may be landing on is not swapped out from under it.
    public func windowDidBecomeKey(_ notification: Notification) {
      renewedAfterSystemCancelWhileKey = false
      let recovery = ReviewFocusRecovery.onBecomeKey(
        authenticating: state == .authenticating, lostKeyWhileArmed: lostKeyWhileArmed,
        armedWhileNotKey: armedWhileNotKey)
      guard recovery != .none else { return }
      if recovery == .rearm {
        let grace = PromptInteractionGrace(
          window: window, controls: interactiveControls,
          focus: { [weak self] in
            guard let self else { return }
            PromptInteractionGrace.refocusIfStillKey(self.window)
          })
        interactionGrace = grace
        grace.begin()
      }
      DispatchQueue.main.async { [weak self] in self?.renewAfterBecomingKey() }
    }

    /// The same re-present the unlock path does, on a panel that is still key
    /// and still waiting on Touch ID. The parent watch already closes this
    /// helper when its sudo is gone.
    private func renewAfterBecomingKey() {
      guard ReviewFocusRecovery.onBecomeKey(
        authenticating: state == .authenticating, lostKeyWhileArmed: lostKeyWhileArmed,
        armedWhileNotKey: armedWhileNotKey) != .none,
        window.isKeyWindow
      else { return }
      state = .ready
      rebuildAuthenticationContext()
      beginAuthentication()
    }

    private func authenticationFinished(success: Bool, error: (any Error)?, generation: Int) {
      guard ReviewFocusRecovery.isCurrent(
        generation: generation, currentGeneration: authenticationGeneration,
        authenticating: state == .authenticating
      ) else { return }
      if success {
        finish(.approved)
        return
      }
      // A cancellation while the screen is locked cannot be the human choosing
      // Use Password: this panel is behind the lock screen, so the cancel is
      // system-initiated. Hold the review open and re-present Touch ID once the
      // Mac is unlocked, rather than failing a sudo the human never saw over to
      // the password prompt.
      if SudoAuthorizationReviewFailure.response(screenLocked: ScreenLockState.isScreenLocked)
        == .waitForUnlock
      {
        SudoReviewLog.record(.lockedCancel(errorCode: (error as NSError?)?.code))
        waitForUnlockThenRetry()
        return
      }
      // Touch ID may have gone under the evaluation (the lid closed with an
      // external display): ask again rather than trust the error code, and if
      // it has, stay up for the phone while it may decide instead of falling
      // to the password.
      let errorCode = (error as NSError?)?.code
      let touchIDAvailable = ReviewTouchIDUnavailable.isAvailableNow(
        for: .sudo, override: touchIDOverride, builtAt: builtAt)
      SudoReviewLog.record(.armedFailure(errorCode: errorCode, touchIDLost: !touchIDAvailable))
      switch ReviewTouchIDUnavailable.afterFailure(errorCode: errorCode, touchIDAvailable: touchIDAvailable) {
      case .touchIDLost:
        touchIDLost()
      case .systemCancelled:
        systemCancelled()
      case .failed:
        finish(.usePassword)
      }
    }

    /// macOS ended the armed evaluation itself with Touch ID still here:
    /// another app came forward, or another prompt took the sensor. That is
    /// not the human choosing Use Password, so the panel stays up waiting on
    /// Touch ID, renewing it at once while key or when it next becomes key
    /// (`ReviewFocusRecovery.onSystemCancel`).
    private func systemCancelled() {
      guard state == .authenticating else { return }
      let recovery = ReviewFocusRecovery.onSystemCancel(
        windowIsKey: window.isKeyWindow, renewedWhileKey: renewedAfterSystemCancelWhileKey)
      SudoReviewLog.record(.systemCancel(renewed: recovery == .renew))
      guard recovery == .renew else {
        lostKeyWhileArmed = true
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.stringValue = ReviewFocusRecovery.clickToResumeText
        return
      }
      renewedAfterSystemCancelWhileKey = true
      DispatchQueue.main.async { [weak self] in self?.renewAfterSystemCancel() }
    }

    /// The renewal `renewAfterBecomingKey` does, for a panel still key after
    /// a system cancel. The parent watch already closes this helper when its
    /// sudo is gone.
    private func renewAfterSystemCancel() {
      guard state == .authenticating, window.isKeyWindow else { return }
      state = .ready
      rebuildAuthenticationContext()
      beginAuthentication()
    }

    /// Touch ID went away under the armed evaluation: what a panel opened
    /// without it does (`run`). Up for the phone while it may decide; once
    /// nobody can approve, sudo goes on to the password.
    private func touchIDLost() {
      guard state == .authenticating else { return }
      state = .ready
      biometricsAvailable = false
      lostKeyWhileArmed = false
      armedWhileNotKey = false
      guard SudoReviewWithoutTouchID.response(touchIDAvailable: false, phoneCanDecide: phone.canDecide)
        == .waitForPhone
      else {
        SudoReviewLog.record(.touchIDUnavailable(.phoneCannotDecide))
        finish(.usePassword)
        return
      }
      authenticationView.isHidden = true
      statusLabel.textColor = .systemRed
      statusLabel.stringValue = authenticationStatusText
      waitForPhone()
    }

    /// Enter the held-open wait: replace the spent context so the retry presents
    /// a clean prompt, tell the user what is happening, and poll for unlock.
    ///
    /// Nothing here needs its own give-up timer. The PAM module caps the whole
    /// review at `CSEC_REVIEW_TIMEOUT_MILLISECONDS` (five minutes,
    /// packaging/sudo/pam_csec_sudo.c) and the helper closes it just before
    /// that (`SudoReviewDeadline`), ending sudo without another prompt, so a
    /// Mac left locked cannot hold a terminal forever.
    private func waitForUnlockThenRetry() {
      guard state == .authenticating else { return }
      state = .waitingForUnlock
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = ScreenLockState.waitingForUnlockText
      // The grace still pending from the first presentation (the Mac may have
      // locked inside it) is left to the retry's grace, which supersedes it
      // when it begins (see PromptInteractionGrace).
      rebuildAuthenticationContext()
      startUnlockWatch()
    }

    private func startUnlockWatch() {
      guard unlockPollTimer == nil else { return }
      let timer = Timer(
        timeInterval: ScreenLockState.pollInterval, repeats: true
      ) { [weak self] _ in
        DispatchQueue.main.async { self?.handleUnlockSignal() }
      }
      // `.common` so the poll keeps firing even during window/menu tracking.
      RunLoop.main.add(timer, forMode: .common)
      unlockPollTimer = timer
    }

    private func stopUnlockWatch() {
      unlockPollTimer?.invalidate()
      unlockPollTimer = nil
    }

    private func handleUnlockSignal() {
      guard state == .waitingForUnlock, !ScreenLockState.isScreenLocked else { return }
      stopUnlockWatch()
      state = .ready
      // The human has just been typing at the lock screen and this panel is
      // still the key window, so the re-presented prompt gets the same typing
      // guard the first one had: controls held back until the keyboard has
      // been quiet, while Touch ID starts again at once.
      let grace = PromptInteractionGrace(window: window, controls: interactiveControls)
      interactionGrace = grace
      grace.begin()
      beginAuthentication()
    }

    /// Invalidate the spent or stranded context and swap the embedded Touch ID
    /// view for one bound to a fresh context, so the unlock retry or the focus
    /// re-arm evaluates cleanly.
    private func rebuildAuthenticationContext() {
      context.invalidate()
      let fresh = ReviewAuthenticationContext.make(for: .sudo)
      context = fresh

      let replacement = LAAuthenticationView(context: fresh, controlSize: .large)
      replacement.setContentHuggingPriority(.required, for: .horizontal)
      replacement.setContentCompressionResistancePriority(.required, for: .horizontal)
      replacement.isHidden = !biometricsAvailable
      if let area = authenticationArea, let previous = authenticationView {
        area.removeArrangedSubview(previous)
        previous.removeFromSuperview()
        area.insertArrangedSubview(replacement, at: 0)
      }
      authenticationView = replacement
    }

    @objc private func usePasswordPressed(_ sender: Any?) {
      finish(.usePassword)
    }

    /// The sudo that asked is gone, or the paired phone answered first: close
    /// without a decision. Nothing reads the outcome, but it is the
    /// unsuccessful one, never an approval.
    private func requesterGone() {
      finish(.usePassword)
    }

    private func finish(_ outcome: SudoAuthorizationReviewOutcome) {
      guard state != .finished else { return }
      state = .finished
      stopUnlockWatch()
      stopTouchIDWatch()
      interactionGrace?.cancel()
      deadlineCountdown?.stop()
      context.invalidate()
      let pending = continuation
      continuation = nil
      closeWindow()
      pending?.resume(returning: outcome)
    }

    private func closeWindow() {
      stopUnlockWatch()
      stopTouchIDWatch()
      window.delegate = nil
      window.orderOut(nil)
      window.close()
    }

    public func windowWillClose(_ notification: Notification) {
      finish(.usePassword)
    }

    private static func makeSectionLabel(_ text: String) -> NSTextField {
      let label = NSTextField(labelWithString: text.uppercased())
      label.font = .systemFont(ofSize: 11, weight: .semibold)
      label.textColor = .secondaryLabelColor
      return label
    }

    private static func makeBanner(text: String, tint: NSColor, width: CGFloat) -> NSView {
      let icon = NSImageView()
      icon.image = NSImage(
        systemSymbolName: "exclamationmark.triangle.fill",
        accessibilityDescription: "Warning"
      )
      icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 16, weight: .semibold)
      icon.contentTintColor = tint
      icon.setContentHuggingPriority(.required, for: .horizontal)
      icon.setContentCompressionResistancePriority(.required, for: .horizontal)

      let label = NSTextField(wrappingLabelWithString: text)
      label.font = .systemFont(ofSize: 12, weight: .semibold)
      label.textColor = tint
      label.maximumNumberOfLines = 14
      label.preferredMaxLayoutWidth = width - 60

      let content = NSStackView(views: [icon, label])
      content.orientation = .horizontal
      content.alignment = .top
      content.spacing = 10
      return card(
        wrapping: content,
        fill: tint.withAlphaComponent(0.09),
        border: tint.withAlphaComponent(0.35),
        width: width
      )
    }

    private static func paddedBox(
      content: NSView,
      cornerRadius: CGFloat,
      fill: NSColor,
      border: NSColor?,
      horizontalPadding: CGFloat,
      verticalPadding: CGFloat,
      width: CGFloat? = nil
    ) -> NSView {
      let box = NSBox()
      box.boxType = .custom
      box.titlePosition = .noTitle
      box.cornerRadius = cornerRadius
      box.fillColor = fill
      box.borderColor = border ?? .clear
      box.borderWidth = border == nil ? 0 : 1
      box.contentViewMargins = .zero
      box.translatesAutoresizingMaskIntoConstraints = false

      let host: NSView
      if let existing = box.contentView {
        host = existing
      } else {
        host = NSView()
        box.contentView = host
      }
      // Pinned inside the border rather than left to the box's autoresizing:
      // a box whose content view keeps its autoresizing constraints measures
      // a few points off from how it lays out, so a column of cards was
      // fitted to one height and drawn at another (csec-lz39).
      host.translatesAutoresizingMaskIntoConstraints = false
      content.translatesAutoresizingMaskIntoConstraints = false
      host.addSubview(content)
      NSLayoutConstraint.activate([
        host.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: box.borderWidth),
        host.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -box.borderWidth),
        host.topAnchor.constraint(equalTo: box.topAnchor, constant: box.borderWidth),
        host.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -box.borderWidth),
        content.leadingAnchor.constraint(equalTo: host.leadingAnchor, constant: horizontalPadding),
        content.trailingAnchor.constraint(
          equalTo: host.trailingAnchor, constant: -horizontalPadding),
        content.topAnchor.constraint(equalTo: host.topAnchor, constant: verticalPadding),
        content.bottomAnchor.constraint(equalTo: host.bottomAnchor, constant: -verticalPadding),
      ])
      if let width {
        box.widthAnchor.constraint(equalToConstant: width).isActive = true
      }
      return box
    }

    private static func card(
      wrapping content: NSView,
      fill: NSColor,
      border: NSColor,
      width: CGFloat?
    ) -> NSView {
      paddedBox(
        content: content,
        cornerRadius: 9,
        fill: fill,
        border: border,
        horizontalPadding: 12,
        verticalPadding: 10,
        width: width
      )
    }

    private static func gridLabel(_ text: String) -> NSTextField {
      let label = NSTextField(labelWithString: text)
      label.font = .systemFont(ofSize: 13)
      label.textColor = .secondaryLabelColor
      return label
    }

    private static func gridValue(_ text: String) -> NSTextField {
      let font = NSFont.systemFont(ofSize: 13)
      let availableWidth = innerWidth - 124
      let measured = (text as NSString).size(withAttributes: [.font: font]).width
      if measured <= availableWidth {
        let label = NSTextField(labelWithString: text)
        label.font = font
        label.textColor = .labelColor
        return label
      }
      let label = NSTextField(wrappingLabelWithString: text)
      label.font = font
      label.textColor = .labelColor
      label.maximumNumberOfLines = 4
      label.preferredMaxLayoutWidth = availableWidth
      return label
    }
  }
#else
  public enum TrustedSudoAuthorizationReviewSession {
    public static func present(
      _ review: SudoAuthorizationReviewRequest,
      terminal: TerminalSessionContext,
      phone: ReviewPhoneStatus,
      deadline: ReviewDeadline?,
      touchID: ReviewTouchIDOverride? = nil
    ) async -> SudoAuthorizationReviewOutcome {
      .usePassword
    }

    public static func previewPNG(
      _ review: SudoAuthorizationReviewRequest,
      terminal: TerminalSessionContext,
      deadline: ReviewDeadline? = nil,
      touchID: ReviewTouchIDOverride? = nil
    ) -> Data? {
      nil
    }
  }
#endif
