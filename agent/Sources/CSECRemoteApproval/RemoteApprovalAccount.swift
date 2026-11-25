import Foundation

/// Why the relay's account cannot carry approvals right now. These mirror the
/// classes CloudKit reports for the current iCloud account, without making the
/// protocol module depend on CloudKit, so the Mac can say which one applies
/// instead of collapsing them into one "unavailable".
public enum RemoteApprovalAccountProblem: String, Equatable, Sendable, CaseIterable {
    /// No iCloud account is signed in on this device.
    case noAccount = "no_account"
    /// Screen Time or device management denies access to the account.
    case restricted
    /// The account status could not be read. Usually a blip in the system's
    /// account service; asking again can succeed.
    case couldNotDetermine = "could_not_determine"
    /// An account is signed in but not ready, e.g. it needs the user to verify
    /// their Apple Account. It becomes available without re-pairing.
    case temporarilyUnavailable = "temporarily_unavailable"

    /// Whether the condition can clear on its own, so a caller should simply
    /// ask again rather than wait for the user to change something.
    public var isTransient: Bool {
        self == .couldNotDetermine || self == .temporarilyUnavailable
    }
}

/// The current relay account, as the Mac checks it before trusting that a
/// paired phone can actually be reached.
public enum RemoteApprovalAccountStatus: Equatable, Sendable {
    case available
    case unavailable(RemoteApprovalAccountProblem)
}
