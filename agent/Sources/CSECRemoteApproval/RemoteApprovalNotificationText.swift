import Foundation

/// The words the phone shows for a request: the card's heading, and the
/// notification the notification service extension writes once the request's
/// Mac signature has verified. One builder, so the alert says what the card
/// says.
public enum RemoteApprovalNotificationText {
    /// What the alert shows.
    public struct Content: Equatable, Sendable {
        public let title: String
        public let subtitle: String
        public let body: String

        public init(title: String, subtitle: String, body: String) {
            self.title = title
            self.subtitle = subtitle
            self.body = body
        }
    }

    /// The card's heading for each kind of request.
    public static func kindTitle(_ kind: RemoteApprovalReview.Kind) -> String {
        switch kind {
        case .access: return "Secret access requested"
        case .ssh: return "SSH sign-in requested"
        case .sudo: return "sudo requested"
        case .restore: return "Reopen approvals after csecd restarted"
        case .settings: return "Settings change requested"
        }
    }

    /// What the push itself says, and what stays when the request cannot be
    /// read or verified in time: nothing from the request, so nothing
    /// unverified reaches the lock screen.
    public static let unverified = Content(
        title: "Convenient Security",
        subtitle: "",
        body: "A Mac is asking for your approval."
    )

    /// The alert for a request the Mac stopped waiting on before it arrived.
    public static let noLongerWaiting = Content(
        title: "Convenient Security",
        subtitle: "",
        body: "A request from your Mac is no longer waiting."
    )

    static let maximumTitleCharacters = 80
    static let maximumSubtitleCharacters = 80
    static let maximumLineCharacters = 160

    /// The alert for a request whose Mac signature has verified. `macName` is
    /// the pinned Mac's name, not the one the request claims. Every part is
    /// sanitized for display and cut to a bound with the ellipsis inside it.
    public static func content(
        for review: RemoteApprovalReview,
        macName: String
    ) -> Content {
        let headline = fitted(review.headline, maximumLineCharacters - 2)
        var lines = ["“\(headline)”"]
        // The requester's own command line, under the reason it wrote.
        if let command = review.requesterCommand.map({ fitted($0, maximumLineCharacters) }), !command.isEmpty {
            lines.append(command)
        }
        let caller = fitted(review.callerDescription, maximumLineCharacters)
        if !caller.isEmpty {
            lines.append(caller)
        }
        return Content(
            title: fitted(kindTitle(review.kind), maximumTitleCharacters),
            subtitle: fitted("From \(macName)", maximumSubtitleCharacters),
            body: lines.joined(separator: "\n")
        )
    }

    static func fitted(_ value: String, _ maximum: Int) -> String {
        let clean = RemoteApprovalDisplayText.sanitized(value)
        guard clean.count > maximum else { return clean }
        return String(clean.prefix(max(0, maximum - 1))) + "…"
    }
}
