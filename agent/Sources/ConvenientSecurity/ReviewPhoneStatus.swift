import Foundation

/// Whether the paired phone can still decide a review, as the race between
/// the Mac panel and the phone learns it, for the Mac panel.
///
/// A panel on a Mac that cannot take a touch (no fingerprint enrolled, Touch
/// ID locked out after failed attempts, the lid closed) cannot approve; only
/// the phone can. What the panel does then differs by surface, but each one
/// needs this answer (`ReviewTouchIDUnavailable`):
/// - the sudo panel stays up while the phone may still decide, and closes the
///   moment the race hears the phone cannot, so sudo falls back to Apple's own
///   prompt instead of a panel nobody can approve (`SudoReviewWithoutTouchID`;
///   `SudoReviewRace` marks it);
/// - the secret-access and SSH panels, which have no fallback prompt to hand
///   over to, stay up either way and say whether the phone can still approve
///   (`MirroredPolicyReview` binds it as `current` for its local leg and
///   marks it).
///
/// Only ever goes from undecided to unavailable, once.
public final class ReviewPhoneStatus: @unchecked Sendable {
    private let lock = NSLock()
    private var unavailable: Bool
    private var observers: [@Sendable () -> Void] = []

    /// A phone leg that has not answered yet: it may still decide.
    public init() {
        unavailable = false
    }

    private init(unavailable: Bool) {
        self.unavailable = unavailable
    }

    /// No phone leg at all: nothing but the Mac panel can decide.
    public static var none: ReviewPhoneStatus { ReviewPhoneStatus(unavailable: true) }

    /// The phone leg racing the secret-access or SSH panel this task presents,
    /// bound by `MirroredPolicyReview` around its local leg only. Nil when the
    /// review was not mirrored (automation, setup at this Mac, no phone ready,
    /// a review the phone format cannot carry): the panel alone decides.
    @TaskLocal public static var current: ReviewPhoneStatus?

    /// Whether the phone may still decide this review.
    public var canDecide: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !unavailable
    }

    /// The phone leg answered `.unavailable`: it will not decide.
    public func markUnavailable() {
        lock.lock()
        guard !unavailable else {
            lock.unlock()
            return
        }
        unavailable = true
        let pending = observers
        observers = []
        lock.unlock()
        // Outside the lock: an observer may read `canDecide`.
        for observer in pending { observer() }
    }

    /// Run `body` once the phone cannot decide: at once, on the calling
    /// thread, if that is already known, otherwise on the thread that learns
    /// it.
    public func whenUnavailable(_ body: @escaping @Sendable () -> Void) {
        lock.lock()
        guard unavailable else {
            observers.append(body)
            lock.unlock()
            return
        }
        lock.unlock()
        body()
    }
}
