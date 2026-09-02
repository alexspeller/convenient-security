import CryptoKit
import CSECRemoteApproval
import Foundation

/// Adapter seam between the agent's immutable local review and a remote
/// requester. Returning unavailable never suppresses or denies the local prompt.
public protocol RemoteAccessPolicyReviewProvider: Sendable {
    func reviewRemoteAccess(
        _ review: RemoteApprovalReview
    ) async -> RemoteApprovalRequesterResult
}

public struct RequesterRemoteAccessPolicyReviewProvider: RemoteAccessPolicyReviewProvider {
    private let requester: RemoteApprovalRequester

    public init(requester: RemoteApprovalRequester) {
        self.requester = requester
    }

    public func reviewRemoteAccess(
        _ review: RemoteApprovalReview
    ) async -> RemoteApprovalRequesterResult {
        await requester.requestApproval(for: review)
    }
}

/// Opt-in policy reviewer that presents the ordinary local Touch ID prompt and
/// mirrors the exact frozen, value-free transaction to one pinned phone. The
/// first authenticated decision wins. Host remediation remains local-only.
public struct MirroredPolicyReview: PolicyReviewProvider {
    private let local: any PolicyReviewProvider
    private let remote: any RemoteAccessPolicyReviewProvider

    public init(
        local: any PolicyReviewProvider = TrustedPolicyReview(),
        remote: any RemoteAccessPolicyReviewProvider
    ) {
        self.local = local
        self.remote = remote
    }

    public func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        // A remote approval cannot produce a Mac LAContext. For this first
        // release it is therefore limited to 1Password, whose proactively-held
        // desktop connection can resolve without unlocking a cold csec Keychain
        // cache or native-store key. Mixed/native requests stay local.
        let references = review.credentials.flatMap(\.references)
        guard review.automation == nil,
              !references.isEmpty,
              references.allSatisfy({ $0.scheme == "op" }),
              let frozen = try? RemoteApprovalReview(accessPolicyReview: review) else {
            return await local.reviewAccess(review)
        }

        return await withTaskGroup(of: PolicyReviewRaceResult.self) { group in
            group.addTask {
                .local(await local.reviewAccess(review))
            }
            group.addTask {
                .remote(await remote.reviewRemoteAccess(frozen))
            }

            while let result = await group.next() {
                switch result {
                case let .local(outcome):
                    group.cancelAll()
                    return outcome
                case .remote(.approved):
                    group.cancelAll()
                    return .approved(
                        AccessPolicyApproval(
                            authenticationSession: RemoteApprovedAuthenticationSession()
                        )
                    )
                case .remote(.denied):
                    group.cancelAll()
                    return .denied
                case .remote(.unavailable):
                    // CloudKit/account/network trouble is not a decision. Leave
                    // the ordinary local prompt running unchanged.
                    continue
                }
            }
            return .denied
        }
    }

    public func reviewHostRemediation(
        _ review: HostRemediationReview
    ) async -> HostRemediationOutcome {
        await local.reviewHostRemediation(review)
    }
}

private enum PolicyReviewRaceResult: Sendable {
    case local(AccessPolicyReviewOutcome)
    case remote(RemoteApprovalRequesterResult)
}

/// Converts the phone's already-verified, single-request signature into the
/// existing agent completion seam. It deliberately supplies no Mac Keychain
/// unlock context and can be consumed only once.
public actor RemoteApprovedAuthenticationSession: AccessPolicyAuthenticationSession {
    private var available = true

    public init() {}

    public func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        guard available else { return .denied }
        available = false
        return .approved(unlock: nil)
    }

    public func cancel() async {
        available = false
    }
}

public extension RemoteApprovalReview {
    /// Freeze every string the phone will render before either biometric path
    /// begins. The raw reference-set digest and full delivery-plan digest bind
    /// this presentation to the agent's immutable authorization transaction.
    init(accessPolicyReview review: AccessPolicyReview) throws {
        let groups = review.credentials.map { credential -> Credential in
            let group = ReviewDisplay.referenceGroup(for: credential)
            // The phone renders a fixed set of fields, so provider context joins
            // the subtitle rather than adding a wire field. The strings are the
            // same bounded, sanitized ones the Mac window shows, so both
            // surfaces describe the same resolution.
            let subtitle = ReviewDisplay.bounded(
                ([group.subtitle].compactMap { $0 } + group.noteLines).joined(separator: " · "),
                maxBytes: 1_024
            )
            return Credential(
                title: group.title,
                subtitle: subtitle.isEmpty ? nil : subtitle,
                fields: group.fields,
                rawReferences: group.rawReferences
            )
        }
        let plan = review.plan
        let emitterPath = ReviewDisplay.sanitized(plan.executable.canonicalPath)
        let emitterName = ReviewDisplay.sanitized(
            URL(fileURLWithPath: plan.executable.canonicalPath).lastPathComponent
        )
        self.init(
            reason: ReviewDisplay.sanitized(review.reason),
            callerDescription: ReviewDisplay.sanitized(review.caller.description),
            credentials: groups,
            referenceSetDigest: Self.referenceSetDigest(
                review.credentials.flatMap(\.references).map(\.uri)
            ),
            emitterName: emitterName,
            emitterPath: emitterPath,
            emitterAssurance: ReviewDisplay.assurance(plan.executable.assurance),
            recipientDescription: DeliveryReviewCopy.recipientDescription(for: plan),
            deliveryDescription:
                "\(ReviewDisplay.mechanism(plan.mechanism)) · "
                + ReviewDisplay.scope(plan.descendantScope),
            // The phone has no scope selector, so it renders — and approving on
            // it applies — exactly the default scope the Mac window pre-selects.
            // `MirroredPolicyReview` returns no `selectedScopeOptionID`, which
            // the agent resolves to that same default.
            grantRootDescription: ReviewDisplay.bounded(
                review.scopeChoices.map {
                    ReviewDisplay.scopeSummary($0.defaultOption)
                } ?? ReviewDisplay.root(plan.root),
                maxBytes: 512
            ),
            destinationDescription: ReviewDisplay.destination(plan.destination),
            requestedDurationDescription: ReviewDisplay.duration(
                seconds: plan.requestedTTLSeconds
            ),
            warning: DeliveryReviewCopy.warning(for: review),
            deliveryPlanDigest: try Self.decodeSHA256(try plan.digest())
        )
        try validate()
    }

    private static func referenceSetDigest(_ references: [String]) -> Data {
        var bytes = Data("csec.remote-approval.references.v1".utf8)
        for reference in references.sorted() {
            let value = Data(reference.utf8)
            let count = UInt32(value.count)
            bytes.append(UInt8((count >> 24) & 0xff))
            bytes.append(UInt8((count >> 16) & 0xff))
            bytes.append(UInt8((count >> 8) & 0xff))
            bytes.append(UInt8(count & 0xff))
            bytes.append(value)
        }
        return Data(SHA256.hash(data: bytes))
    }

    private static func decodeSHA256(_ value: String) throws -> Data {
        guard value.utf8.count == SHA256.byteCount * 2 else {
            throw RemoteApprovalValidationError.invalidDigest
        }
        var result = Data()
        result.reserveCapacity(SHA256.byteCount)
        var index = value.startIndex
        while index < value.endIndex {
            let end = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<end], radix: 16) else {
                throw RemoteApprovalValidationError.invalidDigest
            }
            result.append(byte)
            index = end
        }
        return result
    }
}
