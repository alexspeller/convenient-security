import CSECRemoteApproval
import Foundation

/// When an approval panel nobody answers will close on its own, and the line
/// every panel with such a deadline shows about it.
///
/// Two clocks close an unanswered panel. The sudo review lives inside a PAM
/// authentication that the module ends after five minutes
/// (`CSEC_REVIEW_TIMEOUT_MILLISECONDS`, packaging/sudo/pam_csec_sudo.c); the
/// helper closes its panel just before that (`SudoReviewDeadline`). A coding
/// agent's secret-access or SSH request is withdrawn once it has waited
/// `ApprovalWaitLimit` (`HumanWait`). Either way the panel used to vanish from
/// under the human with no warning, possibly mid-touch. So a panel with a
/// deadline says so from the moment it appears — a quiet line while there is
/// time, a countdown for the last `warningWindow` — and a close is never a
/// surprise. The line is there from the start so nothing moves under the
/// pointer when the countdown begins. A panel with no deadline (a terminal's
/// own request, the restore panel, setup) shows no line. The phone's copy of
/// the review carries the same moment and shows the same line.
///
/// This adds no clock: it only shows one that already ends the wait.
public struct ReviewDeadline: Sendable, Equatable {
  /// When the panel closes, on the clock its owner enforces it with.
  public let instant: ContinuousClock.Instant
  /// The same moment on the wall clock, for the quiet line.
  public let date: Date

  /// How long before the close the line turns into a countdown.
  public static let warningWindow: Duration = ReviewDeadlineText.warningWindow

  public init(instant: ContinuousClock.Instant, date: Date) {
    self.instant = instant
    self.date = date
  }

  /// The deadline `remaining` from now.
  public init(
    remaining: Duration, now: ContinuousClock.Instant = .now, nowDate: Date = Date()
  ) {
    self.init(instant: now + remaining, date: nowDate.addingTimeInterval(Self.seconds(remaining)))
  }

  /// A coding agent's request's withdrawal, or nil for a request that waits
  /// as long as it takes.
  public init?(_ wait: HumanWait?) {
    guard let wait, wait.currentState == .pending,
      let instant = wait.deadline, let date = wait.deadlineDate
    else { return nil }
    self.init(instant: instant, date: date)
  }

  public var remaining: Duration { ContinuousClock.now.duration(to: instant) }

  /// What the line says `remaining` before the close.
  public struct Line: Sendable, Equatable {
    public let text: String
    /// The last `warningWindow`: drawn so it is noticed.
    public let isCountdown: Bool

    public init(text: String, isCountdown: Bool) {
      self.text = text
      self.isCountdown = isCountdown
    }
  }

  /// The words are `ReviewDeadlineText`'s, which the phone's card uses too.
  public func line(
    remaining: Duration, now: Date = Date(), timeZone: TimeZone = .current
  ) -> Line {
    let line = ReviewDeadlineText.line(closesAt: date, remaining: remaining, now: now, timeZone: timeZone)
    return Line(text: line.text, isCountdown: line.isCountdown)
  }

  /// How long until the line next reads differently: until the countdown
  /// starts, then until its number drops. Nil once the deadline has passed,
  /// when the closing line stays until the owner closes the panel.
  public static func nextChange(after remaining: Duration) -> Duration? {
    ReviewDeadlineText.nextChange(after: remaining)
  }

  /// The close in Unix milliseconds, as the phone's copy of the review
  /// carries it (`RemoteApprovalReview.closesAtMilliseconds`).
  public var unixMilliseconds: UInt64 {
    let milliseconds = (date.timeIntervalSince1970 * 1_000).rounded(.down)
    return milliseconds > 0 ? UInt64(milliseconds) : 0
  }

  static func seconds(_ duration: Duration) -> TimeInterval {
    ReviewDeadlineText.seconds(duration)
  }
}

#if canImport(AppKit)
  import AppKit

  /// The deadline line itself, shared by every approval panel so the three
  /// surfaces cannot drift apart: built with the window, refreshed by a timer
  /// that fires only when its text changes, and stopped when the panel
  /// finishes. It never closes the panel; the deadline's owner does that.
  @MainActor
  public final class ReviewDeadlineCountdown {
    /// The line's accessibility identifier, for `ApprovalPanelInspection`.
    public static let lineIdentifier = NSUserInterfaceItemIdentifier("review-deadline")

    public let label: NSTextField
    private let deadline: ReviewDeadline
    private var timer: Timer?

    /// `width` is the label's wrapping width. The text is set at once, so a
    /// panel built but never presented (the previews) shows it too.
    public init(deadline: ReviewDeadline, width: CGFloat, alignment: NSTextAlignment) {
      self.deadline = deadline
      label = NSTextField(wrappingLabelWithString: "")
      label.font = .systemFont(ofSize: 11)
      label.alignment = alignment
      label.maximumNumberOfLines = 2
      label.preferredMaxLayoutWidth = width
      label.identifier = Self.lineIdentifier
      refresh(scheduling: false)
    }

    /// Starts following the clock. Called when the panel is presented.
    public func start() {
      guard timer == nil else { return }
      refresh(scheduling: true)
    }

    /// Stops the timer. Called when the panel finishes, however it ends.
    public func stop() {
      timer?.invalidate()
      timer = nil
    }

    /// Stops the timer and blanks the line, keeping its space so nothing
    /// moves: the request was decided, and the deadline no longer applies.
    public func retire() {
      stop()
      label.alphaValue = 0
    }

    private func refresh(scheduling: Bool) {
      let remaining = deadline.remaining
      let line = deadline.line(remaining: remaining)
      label.stringValue = line.text
      label.textColor = line.isCountdown ? .systemOrange : .tertiaryLabelColor
      label.font = .systemFont(ofSize: 11, weight: line.isCountdown ? .semibold : .regular)
      guard scheduling, let next = ReviewDeadline.nextChange(after: remaining) else {
        timer = nil
        return
      }
      // A few milliseconds late, so the number has dropped when it fires.
      let interval = ReviewDeadline.seconds(next) + 0.005
      let timer = Timer(timeInterval: interval, repeats: false) { [weak self] _ in
        MainActor.assumeIsolated { self?.refresh(scheduling: true) }
      }
      // `.common`, as the unlock poll: it keeps firing during tracking.
      RunLoop.main.add(timer, forMode: .common)
      self.timer = timer
    }
  }
#endif
