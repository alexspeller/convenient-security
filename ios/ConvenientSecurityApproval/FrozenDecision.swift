import CSECRemoteApproval
import Foundation

/// What the reader had selected on a card when they tapped Approve or Deny.
struct RemoteApprovalChoice: Equatable {
    var scopeID: String?
    var durationIndex: UInt16?

    init(scopeID: String?, durationIndex: UInt16?) {
        self.scopeID = scopeID
        self.durationIndex = durationIndex
    }

    /// What a card shows before the reader touches a picker: the review's own
    /// defaults, which are the Mac panel's defaults.
    init(defaultsOf review: RemoteApprovalReview) {
        self.init(scopeID: review.defaultScopeID, durationIndex: review.defaultDurationIndex)
    }
}

/// The private-key operations one decision needs. `PhoneAuthorization` puts a
/// single evaluated Face ID behind both.
protocol PhoneDecisionKeys {
    /// An ECDSA P-256 signature (DER) by the phone's signing key.
    func sign(_ data: Data) async throws -> Data
    /// x(p·B) for the request's blinded point, by the phone's key-agreement key.
    func unlockAnswer(blindedPoint: Data) async throws -> Data
}

enum FrozenDecisionError: Error, Equatable {
    /// The card's selection is not one the verified request offers.
    case selectionNotOffered
}

/// One decision, frozen when the reader tapped — before Face ID. It holds the
/// exact verified request that was on screen and the selection the card showed
/// at that moment, so nothing that happens while Face ID is up (a refresh, a
/// picker, a second tap) can change what Face ID authorizes.
struct FrozenDecision {
    let request: RemoteApprovalRequest
    let decision: RemoteApprovalDecision
    let selectedScopeID: String?
    let selectedDurationIndex: UInt16?
    /// Whether the card showed the request's pairing line for the frozen
    /// selection: nil unless an approval answers a request that carries one.
    /// The card draws the line by the same rule (`pairingLineApplies`), and
    /// csecd accepts the answer only when it agrees.
    let pairingLineShown: Bool?
    let decidedAtMilliseconds: UInt64

    /// An approval carries exactly the choices the review offers — the card
    /// always shows one, the default until the reader changes it — and a
    /// denial selects nothing. A choice the request did not offer is refused
    /// here rather than signed and then refused by the Mac.
    init(
        request: RemoteApprovalRequest,
        decision: RemoteApprovalDecision,
        choice: RemoteApprovalChoice,
        decidedAtMilliseconds: UInt64
    ) throws {
        self.request = request
        self.decision = decision
        self.decidedAtMilliseconds = decidedAtMilliseconds
        guard decision == .approve else {
            selectedScopeID = nil
            selectedDurationIndex = nil
            pairingLineShown = nil
            return
        }
        let review = request.review
        if review.scopeOptions.isEmpty {
            selectedScopeID = nil
        } else {
            guard let scopeID = choice.scopeID,
                  review.scopeOptions.contains(where: { $0.id == scopeID }) else {
                throw FrozenDecisionError.selectionNotOffered
            }
            selectedScopeID = scopeID
        }
        if review.durationOptions.isEmpty {
            selectedDurationIndex = nil
        } else {
            guard let index = choice.durationIndex,
                  Int(index) < review.durationOptions.count else {
                throw FrozenDecisionError.selectionNotOffered
            }
            selectedDurationIndex = index
        }
        pairingLineShown = review.delegation?.pairing == nil
            ? nil
            : review.pairingLineApplies(scopeID: selectedScopeID, durationIndex: selectedDurationIndex)
    }

    /// Only an approval of a request that carries a blinded point is answered.
    /// A denial never computes a key agreement.
    var answersUnlockChallenge: Bool {
        decision == .approve && request.unlockChallenge != nil
    }

    /// Answer the unlock challenge (an approval that carries one), then sign
    /// the response, with the keys one Face ID unlocked. The result is checked
    /// with the Mac's own acceptance rule before anything leaves the phone: the
    /// same request and digest, this phone, a selection the request offered,
    /// an unlock answer exactly when it asked for one, a pairing-line answer
    /// exactly when the review carries a line, and a valid signature.
    func signed(
        phoneDeviceID: String,
        phonePublicKeyX963: Data,
        phoneAppVersion: String,
        keys: some PhoneDecisionKeys
    ) async throws -> SignedRemoteApprovalResponse {
        var unlockAnswer: Data?
        if decision == .approve, let challenge = request.unlockChallenge {
            unlockAnswer = try await keys.unlockAnswer(blindedPoint: challenge.blindedPoint)
        }
        let response = RemoteApprovalResponse(
            requestID: request.requestID,
            requestDigest: try request.digest(),
            phoneDeviceID: phoneDeviceID,
            decision: decision,
            decidedAtMilliseconds: decidedAtMilliseconds,
            selectedScopeID: selectedScopeID,
            selectedDurationIndex: selectedDurationIndex,
            unlockAnswer: unlockAnswer,
            phoneAppVersion: phoneAppVersion,
            pairingLineShown: pairingLineShown
        )
        let signature = try await keys.sign(try response.signingData())
        let envelope = SignedRemoteApprovalResponse(response: response, signatureDER: signature)
        try envelope.verify(
            for: request,
            pinnedPhoneDeviceID: phoneDeviceID,
            phonePublicKeyX963: phonePublicKeyX963
        )
        return envelope
    }
}
