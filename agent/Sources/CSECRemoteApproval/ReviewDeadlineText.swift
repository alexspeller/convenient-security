import Foundation

/// What an approval nobody answers says about when it closes: the one wording
/// and timing the Mac panels (`ReviewDeadline`) and the phone's card share, so
/// the surfaces cannot drift apart. A quiet line names the closing time while
/// there is time, a countdown runs for the last `warningWindow`, and at the
/// deadline the line says why it is closing.
///
/// This adds no clock: it only words one that already ends the wait (the sudo
/// review's PAM limit, a coding agent's request wait).
public enum ReviewDeadlineText {
    /// How long before the close the line turns into a countdown.
    public static let warningWindow: Duration = .seconds(30)

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

    /// The line for a close at `closesAt`, `remaining` from `now`.
    public static func line(
        closesAt: Date, remaining: Duration, now: Date = Date(), timeZone: TimeZone = .current
    ) -> Line {
        if remaining <= .zero {
            return Line(text: "Closing: nobody answered in time. Nothing was approved.", isCountdown: true)
        }
        if remaining <= warningWindow {
            let seconds = wholeSecondsLeft(remaining)
            let unit = seconds == 1 ? "second" : "seconds"
            return Line(
                text: "Closes in \(seconds) \(unit) if nobody answers, without approving anything.",
                isCountdown: true)
        }
        return Line(
            text: "If nobody answers by \(closingTime(closesAt, now: now, timeZone: timeZone)), "
                + "this closes without approving anything.",
            isCountdown: false)
    }

    /// The line for a close at `closesAt`, measured on the wall clock: the
    /// phone's, whose only clock for a Mac's deadline is the date it was sent.
    public static func line(closesAt: Date, now: Date, timeZone: TimeZone = .current) -> Line {
        line(closesAt: closesAt, remaining: .seconds(closesAt.timeIntervalSince(now)), now: now, timeZone: timeZone)
    }

    /// How long until the line next reads differently: until the countdown
    /// starts, then until its number drops. Nil once the deadline has passed,
    /// when the closing line stays until the owner closes the review.
    public static func nextChange(after remaining: Duration) -> Duration? {
        guard remaining > .zero else { return nil }
        if remaining > warningWindow { return remaining - warningWindow }
        let shown = wholeSecondsLeft(remaining)
        return remaining - .seconds(shown - 1)
    }

    /// Every moment after `now` at which the line for a close at `closesAt`
    /// reads differently, the deadline itself last: a schedule for a view
    /// that redraws only when its text changes. Each is a few milliseconds
    /// late, so the number has dropped when the line is drawn for it. At most
    /// the countdown's seconds plus one.
    public static func changes(closesAt: Date, from now: Date) -> [Date] {
        var dates: [Date] = []
        var remaining = Duration.seconds(closesAt.timeIntervalSince(now))
        var at = now
        while let next = nextChange(after: remaining) {
            at = at.addingTimeInterval(seconds(next))
            dates.append(at.addingTimeInterval(0.005))
            remaining -= next
        }
        return dates
    }

    /// The countdown rounds up, so it reads 30 the moment it starts and 1 in
    /// its final second.
    public static func wholeSecondsLeft(_ remaining: Duration) -> Int {
        Int(seconds(remaining).rounded(.up))
    }

    /// `14:37`, as `HumanWait`'s notice gives it, or `tomorrow at 14:37`.
    private static func closingTime(_ date: Date, now: Date, timeZone: TimeZone) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = "HH:mm"
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let time = formatter.string(from: date)
        return calendar.isDate(date, inSameDayAs: now) ? time : "tomorrow at \(time)"
    }

    public static func seconds(_ duration: Duration) -> TimeInterval {
        let parts = duration.components
        return TimeInterval(parts.seconds) + TimeInterval(parts.attoseconds) / 1e18
    }
}
