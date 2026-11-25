import CSECRemoteApproval
import CSECRemoteApprovalCloudKit
import Foundation

/// What the app reads from and writes to the mailbox. The private iCloud
/// database, through `CloudKitRemoteApprovalRelay`, is the one real mailbox;
/// the Simulator test mode can stand an in-memory one in its place
/// (`SimulatedMailbox`), so the UI tests drive the same refresh, decision and
/// confirmation code the installed app runs. Nothing read here is trusted:
/// every request is verified against a pinned Mac before it is shown.
protocol PhoneMailbox: Sendable {
    /// The requests the mailbox query returns, each stored under its own
    /// `request-<requestID>`, with when the mailbox last saved it: a waiting
    /// Mac saves its request again every minute, so one not saved for longer
    /// than `RemoteApprovalLiveness.quietAfterSeconds` is from a Mac that has
    /// gone quiet. The query reads a bounded number of records in no promised
    /// order.
    func pendingRequestRecords() async throws -> [RemoteApprovalMailboxRequest]
    /// One request, read by its record name; nil once the Mac has deleted it.
    func requestRecord(requestID: String) async throws -> RemoteApprovalMailboxRequest?
    /// Whether the request record is still there, and when it was last saved.
    func requestPresence(requestID: String) async throws -> RemoteApprovalRequestPresence
    func requestIsPending(requestID: String) async throws -> Bool
    func publishResponse(
        _ response: SignedRemoteApprovalResponse,
        keepingEarlierAnswer isEarlierAnswer: @Sendable (SignedRemoteApprovalResponse) -> Bool
    ) async throws -> SignedRemoteApprovalResponse?
    /// What this iPhone's slot for a request holds,
    /// `response-<requestID>-<phoneDeviceID>`; nil when it is empty.
    func response(
        for requestID: String,
        phoneDeviceID: String
    ) async throws -> SignedRemoteApprovalResponse?
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer?
    func pairingConfirmation(
        macDeviceID: String
    ) async throws -> SignedRemoteApprovalPairingConfirmation?
    func publishPairingConfirmation(
        _ confirmation: SignedRemoteApprovalPairingConfirmation
    ) async throws
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws
    func ensureSubscriptions() async throws
    /// Saved apart from the other two: its refusal must not cost the alerts.
    func ensureSettledSubscription() async throws
    /// Whether the iCloud account can carry requests at all, bounded: a read
    /// that fails or takes too long is "could not determine".
    func approvalAccountStatus() async -> RemoteApprovalAccountStatus
}

extension CloudKitRemoteApprovalRelay: PhoneMailbox {}
