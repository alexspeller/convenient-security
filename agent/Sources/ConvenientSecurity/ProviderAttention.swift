import Foundation

/// Something a provider's own app needs from a person at the Mac, for csecd to
/// tell them about in a notification. Value-free: the provider's name and an
/// account label it made display-safe, never a reference or a value.
///
/// Why csecd says anything at all: a provider such as 1Password asks for its
/// own authorization in its own window, which csec neither draws nor sees. On
/// the author's Mac that window went unanswered after 4 of 6 installs (csec-0.64.17),
/// with the person at the Mac, so the paired values stayed cold until their
/// next approval there and nothing said so.
public struct ProviderAttention: Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        /// The provider's app has been asking a while for authorization and
        /// has not been answered yet.
        case awaitingAuthorization
        /// The request it asked about has ended without a refusal: whatever
        /// `awaitingAuthorization` said is over.
        case settled
        /// The provider will not be asked again for this account until a
        /// person approves a csec panel at this Mac: its app refused, or its
        /// prompt went unanswered (`unanswered`).
        case notAuthorized(unanswered: Bool)
    }

    public let provider: String
    public let account: String
    public let kind: Kind

    public init(provider: String, account: String, kind: Kind) {
        self.provider = provider
        self.account = account
        self.kind = kind
    }

    /// One notification per provider account, so each new state replaces the
    /// last instead of piling up.
    public var notificationIdentifier: String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-"))
        let slug = "\(provider)-\(account)".unicodeScalars
            .map { allowed.contains($0) ? Character($0) : "-" }
        return "csec-provider-attention-" + String(slug).lowercased()
    }

    /// The notification's words, or nil when it should be withdrawn.
    public var notification: (title: String, body: String)? {
        let provider = ReviewDisplay.sanitized(String(provider.prefix(32)))
        let account = ReviewDisplay.sanitized(String(account.prefix(64)))
        switch kind {
        case .awaitingAuthorization:
            return ("\(provider) is asking to allow csec",
                    "Answer \(provider)'s prompt for \(account) now, so auto mode can use its values. "
                        + "csec stops waiting for it within the minute.")
        case .settled:
            return nil
        case .notAuthorized(let unanswered):
            return (unanswered ? "\(provider)'s prompt went unanswered" : "\(provider) did not allow csec",
                    "csec won't ask \(provider) for \(account) again until you approve a csec panel at this Mac. "
                        + "Until then auto mode can't use its values.")
        }
    }
}
