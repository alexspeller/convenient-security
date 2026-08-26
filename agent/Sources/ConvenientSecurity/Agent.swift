import Foundation

/// The policy core: matches callers against subtree grants, gates newly-seen
/// references through consent, then resolves the approved references.
public actor Agent {
    private struct CredentialPolicyState {
        let descriptor: CredentialGroupDescriptor
        var identity: CredentialIdentity
        let judgment: RiskJudgment?
        var acceptance: DeliveryAcceptance?
        var storedLevel: RiskLevel
        var decision: PolicyDecision
        let scopeExpanded: Bool
        var acceptanceWasAdded = false
    }

    private struct RiskContext {
        let descriptor: CredentialGroupDescriptor
        let identity: CredentialIdentity
        let judgment: RiskJudgment?
        let acceptances: [DeliveryAcceptance]
        let referenceInKnownScope: Bool
    }

    private struct NativeEditAuthorization {
        let callerPID: pid_t
        let callerStartTime: UInt64
        let reference: SecretRef
        let plan: DeliveryPlan
        let policyBinding: PolicyGrantBinding
        let expiresAt: Date
    }

    private struct RedactionCaller: Sendable {
        let pid: pid_t
        let startTime: UInt64

        func matches(_ caller: CallerInfo) -> Bool {
            caller.pid == pid && caller.startTime == startTime
        }
    }

    private struct RedactionSession: Sendable {
        let caller: RedactionCaller
        let destination: DestinationClass
        var redactors: [OutputRedactionStream: StreamingOutputRedactor]
        var finishedStreams: Set<OutputRedactionStream>
        var registryGeneration: UInt64
        let includeShortValues: Bool
        var lastUsedAt: Date
    }

    private struct RegisteredSession: Sendable {
        let rootPID: pid_t
        let rootStartTime: UInt64
        let auditSessionID: UInt32?
    }

    private static let maximumOutputChunkBytes = 64 * 1024
    private static let maximumRedactionSessions = 32
    private static let redactionSessionIdleSeconds: TimeInterval = 5 * 60
    private static let maximumRegisteredSessions = 64

    private let resolver: SecretResolver
    private let grants: GrantTable
    private let consent: ConsentProvider
    private let riskJudgments: RiskJudgmentStore
    private let policyReview: PolicyReviewProvider
    private let nativeStore: NativeEncryptedFileProvider?
    private let allowLegacyAccessForTesting: Bool
    private let allowUnverifiedPlansForTesting: Bool
    private var activeSecrets = ActiveSecretRegistry()
    private var redactionSessions: [String: RedactionSession] = [:]
    private var knownReferencesByCredentialKey: [String: Set<String>] = [:]
    private var nativeEditAuthorizations: [String: NativeEditAuthorization] = [:]
    private var registeredSessions: [String: RegisteredSession] = [:]

    public init(
        resolver: SecretResolver,
        grants: GrantTable,
        consent: ConsentProvider,
        riskJudgments: RiskJudgmentStore,
        policyReview: PolicyReviewProvider,
        nativeStore: NativeEncryptedFileProvider? = nil,
        allowLegacyAccessForTesting: Bool = false,
        allowUnverifiedPlansForTesting: Bool = false
    ) {
        self.resolver = resolver
        self.grants = grants
        self.consent = consent
        self.riskJudgments = riskJudgments
        self.policyReview = policyReview
        self.nativeStore = nativeStore
        self.allowLegacyAccessForTesting = allowLegacyAccessForTesting
        self.allowUnverifiedPlansForTesting = allowUnverifiedPlansForTesting
    }

    public func handle(request: AccessRequest, caller: CallerInfo) async -> Response {
        let requestID = request.requestID
        let rootPID: pid_t
        let rootStartTime: UInt64
        let planDigest: String?
        let plan: DeliveryPlan?

        if request.isLegacy {
            guard allowLegacyAccessForTesting else {
                return .failed(
                    .upgradeRequired,
                    message: "client must use protocol v2 with a delivery plan"
                )
            }
            rootPID = caller.pid
            rootStartTime = caller.startTime
            planDigest = nil
            plan = nil
        } else {
            guard request.protocolVersion == WireProtocol.version else {
                return .failed(
                    .upgradeRequired,
                    message: "unsupported protocol version",
                    requestID: requestID
                )
            }
            guard let requestID,
                  UUID(uuidString: requestID) != nil,
                  let deliveryPlan = request.deliveryPlan,
                  let claimedDigest = request.deliveryPlanDigest,
                  Self.isSHA256Digest(claimedDigest),
                  (try? deliveryPlan.digest()) == claimedDigest,
                  deliveryPlan.requestedTTLSeconds == request.ttlSeconds,
                  Self.hasValidMetadata(deliveryPlan) else {
                return .failed(
                    .invalidRequest,
                    message: "invalid or incomplete delivery-plan binding",
                    requestID: requestID
                )
            }
            guard allowUnverifiedPlansForTesting
                    || caller.peerIdentity?.code.role == .launcher else {
                return .failed(
                    .unverifiedPeer,
                    message: "a verified launcher is required for delivery plans",
                    requestID: requestID
                )
            }
            pruneRegisteredSessions()
            guard let verifiedRoot = verifyDeliveryRoot(deliveryPlan, caller: caller) else {
                return .failed(
                    .invalidRequest,
                    message: "the requested grant root does not match process ancestry",
                    requestID: requestID
                )
            }
            if deliveryPlan.mechanism == .credentialProtocol {
                guard let parentPID = ProcessAncestry.parent(of: caller.pid),
                      parentPID > 1,
                      ProcessAncestry.executablePath(of: parentPID)
                        == URL(fileURLWithPath: deliveryPlan.executable.canonicalPath)
                            .standardizedFileURL.resolvingSymlinksInPath().path else {
                    return .failed(
                        .invalidRequest,
                        message: "the credential consumer does not match the verified parent",
                        requestID: requestID
                    )
                }
            }
            rootPID = verifiedRoot.pid
            rootStartTime = verifiedRoot.startTime
            planDigest = claimedDigest
            plan = deliveryPlan
        }

        guard !request.references.isEmpty,
              request.references.count <= 64,
              request.references.allSatisfy({
                  !$0.isEmpty && $0.utf8.count <= 4_096 && !$0.utf8.contains(0)
              }),
              request.ttlSeconds > 0,
              request.ttlSeconds <= 24 * 60 * 60,
              !request.reason.isEmpty,
              request.reason.utf8.count <= 512,
              plan?.operationContext.utf8.count ?? 0 <= 512 else {
            return .failed(
                .invalidRequest,
                message: "request fields are outside supported bounds",
                requestID: requestID
            )
        }

        var refs: [SecretRef] = []
        for raw in request.references {
            guard let ref = try? SecretRef(raw) else {
                return .failed(
                    .invalidRequest,
                    message: "one or more references are invalid",
                    requestID: requestID
                )
            }
            refs.append(ref)
        }

        let now = Date()
        guard let plan, let planDigest else {
            return await handleLegacyAccess(
                refs: refs,
                request: request,
                caller: caller,
                rootPID: rootPID,
                rootStartTime: rootStartTime,
                now: now
            )
        }

        return await handlePolicyAccess(
            refs: refs,
            request: request,
            caller: caller,
            rootPID: rootPID,
            rootStartTime: rootStartTime,
            plan: plan,
            planDigest: planDigest,
            now: now
        )
    }

    private func handlePolicyAccess(
        refs: [SecretRef],
        request: AccessRequest,
        caller: CallerInfo,
        rootPID: pid_t,
        rootStartTime: UInt64,
        plan: DeliveryPlan,
        planDigest: String,
        now: Date
    ) async -> Response {
        let invalidated = await grants.revalidate(policyVersion: RiskPolicyV2.version)
        await resolver.invalidate(references: invalidated)

        var states: [CredentialPolicyState] = []
        do {
            for descriptor in CredentialGrouping.groups(for: refs) {
                let identity = try await riskJudgments.credentialIdentity(
                    provider: descriptor.provider,
                    providerAccount: descriptor.providerAccount,
                    group: descriptor.group,
                    memberReferences: descriptor.references.map(\.uri)
                )
                let judgment = try await riskJudgments.load(
                    credentialKey: identity.credentialKey,
                    policyVersion: RiskPolicyV2.version,
                    at: now
                )
                let acceptance = try await riskJudgments.loadAcceptance(
                    credentialKey: identity.credentialKey,
                    plan: plan,
                    policyVersion: RiskPolicyV2.version,
                    at: now
                )
                let storedLevel = judgment?.level ?? .unknown
                let decision = RiskPolicyV2.evaluate(RiskPolicyInput(
                    credentialKey: identity.credentialKey,
                    storedLevel: storedLevel,
                    evidence: judgment?.evidence ?? [],
                    plan: plan,
                    acceptance: acceptance,
                    now: now
                ))
                let requestedMembers = Set(identity.memberReferenceKeys)
                let knownMembers = Set(judgment?.credential.memberReferenceKeys ?? [])
                states.append(CredentialPolicyState(
                    descriptor: descriptor,
                    identity: identity,
                    judgment: judgment,
                    acceptance: acceptance,
                    storedLevel: storedLevel,
                    decision: decision,
                    scopeExpanded: judgment != nil && !requestedMembers.isSubset(of: knownMembers)
                ))
                knownReferencesByCredentialKey[identity.credentialKey, default: []]
                    .formUnion(descriptor.references.map(\.uri))
            }
        } catch {
            return .failed(
                .internalError,
                message: "risk metadata is unavailable; no secret was resolved",
                requestID: request.requestID
            )
        }

        let currentBindings = policyBindingsByReference(states)
        // Every protected regular-file launch is a fresh two-party rendezvous.
        // Reusing a csec-side grant would let a new root launch outlive the
        // authorization that originally created it, so this mechanism always
        // repeats trusted review and biometric consent before resolving bytes.
        let accessible: Set<String>
        if plan.mechanism == .capabilityGIDFile {
            accessible = []
        } else {
            accessible = await grants.accessibleReferences(
                for: caller.pid,
                now: now,
                deliveryPlanDigest: planDigest,
                policyBindingsByReference: currentBindings
            )
        }
        let newReferenceURIs = Set(refs.map(\.uri)).subtracting(accessible)

        if !newReferenceURIs.isEmpty {
            // A stored classification cannot be silently lowered during an
            // ordinary access. Denials other than missing classification or a
            // separately reviewable compatibility acceptance are immutable in
            // this flow and happen before cache/provider lookup.
            if let denied = states.first(where: {
                $0.storedLevel != .unknown
                    && !$0.decision.allowed
                    && $0.decision.denialReason != .compatibilityAcceptanceRequired
            }) {
                return policyDenied(denied.decision, plan: plan, requestID: request.requestID)
            }

            let reviewCredentials = states.filter { state in
                state.descriptor.references.contains { newReferenceURIs.contains($0.uri) }
            }.map { state in
                PolicyReviewCredential(
                    identity: state.identity,
                    references: state.descriptor.references,
                    storedLevel: state.storedLevel,
                    scopeExpanded: state.scopeExpanded,
                    compatibilityReviewOffered: plan.mechanism.isWeakCompatibility
                        && (state.storedLevel == .unknown
                            || state.decision.denialReason == .compatibilityAcceptanceRequired
                            || state.acceptance != nil),
                    compatibilityAccepted: state.acceptance != nil
                )
            }
            let review = AccessPolicyReview(
                caller: displayedCaller(caller, plan: plan, rootPID: rootPID),
                reason: request.reason,
                plan: plan,
                credentials: reviewCredentials
            )
            guard case let .approved(approval) = await policyReview.reviewAccess(review) else {
                return .failed(
                    .consentDenied,
                    message: "policy review denied",
                    requestID: request.requestID
                )
            }

            for index in states.indices {
                if states[index].storedLevel == .unknown {
                    guard let selected = approval.classifications[
                        states[index].identity.credentialKey
                    ], selected != .unknown else {
                        await approval.authenticationSession?.cancel()
                        return .failed(
                            .policyDenied,
                            message: "an explicit risk classification is required",
                            requestID: request.requestID
                        )
                    }
                    states[index].storedLevel = selected
                }

                states[index].decision = RiskPolicyV2.evaluate(RiskPolicyInput(
                    credentialKey: states[index].identity.credentialKey,
                    storedLevel: states[index].storedLevel,
                    evidence: states[index].judgment?.evidence ?? [],
                    plan: plan,
                    acceptance: states[index].acceptance,
                    now: now
                ))

                if states[index].acceptance == nil,
                   states[index].decision.denialReason == .compatibilityAcceptanceRequired,
                   approval.acceptedCompatibilityCredentialKeys.contains(
                       states[index].identity.credentialKey
                   ) {
                    let newAcceptance = compatibilityAcceptance(
                        credentialKey: states[index].identity.credentialKey,
                        plan: plan,
                        decision: states[index].decision,
                        now: now
                    )
                    states[index].acceptance = newAcceptance.acceptance
                    states[index].acceptanceWasAdded = newAcceptance.shouldPersist
                    states[index].decision = RiskPolicyV2.evaluate(RiskPolicyInput(
                        credentialKey: states[index].identity.credentialKey,
                        storedLevel: states[index].storedLevel,
                        evidence: states[index].judgment?.evidence ?? [],
                        plan: plan,
                        acceptance: states[index].acceptance,
                        now: now
                    ))
                }
            }

            if let denied = states.first(where: { state in
                guard !state.decision.allowed else { return false }

                // High/critical compatibility acceptance deliberately lives
                // only for the risk-capped live grant. When a mixed request
                // adds another credential, do not make an already-accessible
                // reference recreate a persisted acceptance merely because
                // its policy evaluation once again reports the review gate.
                // Any credential that needs a new grant must still be
                // explicitly accepted in this review.
                if state.decision.denialReason == .compatibilityAcceptanceRequired {
                    return state.descriptor.references.contains {
                        newReferenceURIs.contains($0.uri)
                    }
                }
                return true
            }) {
                await approval.authenticationSession?.cancel()
                return policyDenied(denied.decision, plan: plan, requestID: request.requestID)
            }

            let grantedTTL = states.map(\.decision.grantedTTLSeconds).min() ?? 0
            guard grantedTTL > 0 else {
                await approval.authenticationSession?.cancel()
                return .failed(
                    .policyDenied,
                    message: "risk policy did not grant a positive duration",
                    requestID: request.requestID
                )
            }
            let newReferences = refs.filter { newReferenceURIs.contains($0.uri) }
            let policySummary = biometricPolicySummary(states, plan: plan)
            let outcome = await authenticateReviewedAccess(
                approval: approval,
                caller: displayedCaller(caller, plan: plan, rootPID: rootPID),
                newReferences: newReferences,
                reason: request.reason,
                ttl: TimeInterval(grantedTTL),
                policySummary: policySummary
            )
            guard case let .approved(approvedUnlock) = outcome else {
                return .failed(
                    .consentDenied,
                    message: "consent denied",
                    requestID: request.requestID
                )
            }

            guard let releaseRoot = verifyDeliveryRoot(plan, caller: caller),
                  releaseRoot.pid == rootPID,
                  releaseRoot.startTime == rootStartTime else {
                return .failed(
                    .invalidRequest,
                    message: "the approved requester changed before release",
                    requestID: request.requestID
                )
            }

            // Classification/scope/compatibility choices become durable only
            // after the fresh OS authentication succeeds.
            do {
                for index in states.indices {
                    let state = states[index]
                    if state.judgment == nil || state.scopeExpanded {
                        let combinedMembers = Set(
                            state.judgment?.credential.memberReferenceKeys ?? []
                        ).union(state.identity.memberReferenceKeys)
                        let combinedIdentity = CredentialIdentity(
                            provider: state.identity.provider,
                            providerAccountKey: state.identity.providerAccountKey,
                            credentialKey: state.identity.credentialKey,
                            memberReferenceKeys: Array(combinedMembers)
                        )
                        let judgment = RiskJudgment(
                            credential: combinedIdentity,
                            level: state.storedLevel,
                            evidence: state.judgment?.evidence ?? [],
                            source: .explicitUser,
                            decidedAt: now,
                            reviewAfter: now.addingTimeInterval(
                                TimeInterval(RiskPolicyV2.judgmentReviewSeconds)
                            ),
                            policyVersion: RiskPolicyV2.version,
                            providerRevision: state.judgment?.providerRevision,
                            observedScopeDigest: state.judgment?.observedScopeDigest
                        )
                        try await riskJudgments.save(judgment)
                        states[index].identity = combinedIdentity
                    }
                    if state.acceptanceWasAdded, let acceptance = state.acceptance {
                        try await riskJudgments.save(acceptance)
                    }
                }
            } catch {
                return .failed(
                    .internalError,
                    message: "risk decision could not be stored; no secret was resolved",
                    requestID: request.requestID
                )
            }

            for state in states {
                let references = Set(state.descriptor.references.compactMap {
                    newReferenceURIs.contains($0.uri) ? $0.uri : nil
                })
                guard !references.isEmpty else { continue }
                await grants.add(Grant(
                    rootPID: rootPID,
                    rootStartTime: rootStartTime,
                    references: references,
                    reason: request.reason,
                    expiresAt: now.addingTimeInterval(TimeInterval(grantedTTL)),
                    requestID: request.requestID,
                    deliveryPlanDigest: planDigest,
                    peerPIDVersion: caller.peerIdentity?.audit.pidVersion,
                    peerCDHash: caller.peerIdentity?.code.cdHash,
                    plannedExecutable: plan.executable,
                    policyBinding: policyBinding(for: state)
                ))
            }

            let response = await resolve(
                refs: refs,
                requestID: request.requestID,
                unlock: approvedUnlock,
                activeUntil: now.addingTimeInterval(TimeInterval(grantedTTL))
            )
            guard let finalRoot = verifyDeliveryRoot(plan, caller: caller),
                  finalRoot.pid == rootPID,
                  finalRoot.startTime == rootStartTime else {
                return .failed(
                    .invalidRequest,
                    message: "the approved requester changed during release",
                    requestID: request.requestID
                )
            }
            return response
        }

        guard let grantedTTL = states.map(\.decision.grantedTTLSeconds).min(),
              grantedTTL > 0,
              states.allSatisfy({
                  $0.decision.allowed
                    || $0.decision.denialReason == .compatibilityAcceptanceRequired
              }) else {
            let denied = states.first(where: { !$0.decision.allowed })?.decision
            return denied.map {
                policyDenied($0, plan: plan, requestID: request.requestID)
            } ?? .failed(
                .policyDenied,
                message: "risk policy denied access",
                requestID: request.requestID
            )
        }
        guard let releaseRoot = verifyDeliveryRoot(plan, caller: caller),
              releaseRoot.pid == rootPID,
              releaseRoot.startTime == rootStartTime else {
            return .failed(
                .invalidRequest,
                message: "the granted requester changed before release",
                requestID: request.requestID
            )
        }
        let response = await resolve(
            refs: refs,
            requestID: request.requestID,
            unlock: nil,
            activeUntil: now.addingTimeInterval(TimeInterval(grantedTTL))
        )
        guard let finalRoot = verifyDeliveryRoot(plan, caller: caller),
              finalRoot.pid == rootPID,
              finalRoot.startTime == rootStartTime else {
            return .failed(
                .invalidRequest,
                message: "the granted requester changed during release",
                requestID: request.requestID
            )
        }
        return response
    }

    private func handleLegacyAccess(
        refs: [SecretRef],
        request: AccessRequest,
        caller: CallerInfo,
        rootPID: pid_t,
        rootStartTime: UInt64,
        now: Date
    ) async -> Response {
        let accessible = await grants.accessibleReferences(for: caller.pid, now: now)
        let newReferences = refs.filter { !accessible.contains($0.uri) }
        var unlock: CacheUnlock?
        if !newReferences.isEmpty {
            let outcome = await consent.requestConsent(
                caller: caller,
                newReferences: newReferences,
                reason: request.reason,
                ttl: TimeInterval(request.ttlSeconds),
                policySummary: nil
            )
            guard case let .approved(approvedUnlock) = outcome else {
                return .failed(.consentDenied, message: "consent denied")
            }
            unlock = approvedUnlock
            await grants.add(Grant(
                rootPID: rootPID,
                rootStartTime: rootStartTime,
                references: Set(newReferences.map(\.uri)),
                reason: request.reason,
                expiresAt: now.addingTimeInterval(TimeInterval(request.ttlSeconds))
            ))
        }
        return await resolve(
            refs: refs,
            requestID: request.requestID,
            unlock: unlock,
            activeUntil: nil
        )
    }

    private func resolve(
        refs: [SecretRef],
        requestID: String?,
        unlock: CacheUnlock?,
        activeUntil: Date?
    ) async -> Response {
        var values: [String: String] = [:]
        for ref in refs {
            do {
                values[ref.uri] = try await resolver.resolve(ref, unlock: unlock)
            } catch {
                return .failed(
                    .resolutionFailed,
                    message: "the provider could not resolve one or more references",
                    requestID: requestID
                )
            }
        }
        if let activeUntil {
            activeSecrets.register(values: Array(values.values), expiresAt: activeUntil)
        }
        return Response(
            requestID: requestID,
            values: values,
            accessExpiresAt: activeUntil
        )
    }

    private func policyBindingsByReference(
        _ states: [CredentialPolicyState]
    ) -> [String: PolicyGrantBinding] {
        var bindings: [String: PolicyGrantBinding] = [:]
        for state in states {
            let binding = policyBinding(for: state)
            for reference in state.descriptor.references {
                bindings[reference.uri] = binding
            }
        }
        return bindings
    }

    private func policyBinding(for state: CredentialPolicyState) -> PolicyGrantBinding {
        PolicyGrantBinding(
            credentialKey: state.identity.credentialKey,
            riskLevel: state.decision.effectiveLevel,
            policyVersion: state.decision.policyVersion,
            policyDigest: state.decision.policyDigest,
            outputPolicy: state.decision.outputPolicy
        )
    }

    private func compatibilityAcceptance(
        credentialKey: String,
        plan: DeliveryPlan,
        decision: PolicyDecision,
        now: Date
    ) -> (acceptance: DeliveryAcceptance, shouldPersist: Bool) {
        let shouldPersist = decision.effectiveLevel == .standard
        let lifetime = shouldPersist
            ? RiskPolicyV2.compatibilityAcceptanceReviewSeconds
            : decision.grantedTTLSeconds
        return (
            DeliveryAcceptance(
                credentialKey: credentialKey,
                shape: CompatibilityDeliveryShape(plan: plan),
                policyVersion: RiskPolicyV2.version,
                acceptedAt: now,
                reviewAfter: now.addingTimeInterval(TimeInterval(lifetime))
            ),
            shouldPersist
        )
    }

    private func displayedCaller(
        _ caller: CallerInfo,
        plan: DeliveryPlan,
        rootPID: pid_t
    ) -> CallerInfo {
        var displayed = caller
        let executableName = URL(fileURLWithPath: plan.executable.canonicalPath).lastPathComponent
        if case .directParent = plan.root {
            let requester = plan.requestingExecutable ?? plan.executable
            // Derive the label from the independently checked executable path,
            // not the process's mutable display name.
            let requesterName = URL(fileURLWithPath: requester.canonicalPath).lastPathComponent
            displayed.description = "\(requesterName) [\(requester.assurance.rawValue)] "
                + "(pid \(rootPID)) via \(caller.description)"
        } else {
            displayed.description = "\(caller.description) for \(executableName) "
                + "[\(plan.executable.assurance.rawValue)] (grant root pid \(rootPID))"
        }
        return displayed
    }

    private func policyDenied(
        _ decision: PolicyDecision,
        plan: DeliveryPlan,
        requestID: String?
    ) -> Response {
        let reason = decision.denialReason?.rawValue ?? "denied"
        return .failed(
            .policyDenied,
            message: "risk policy denied \(plan.mechanism.rawValue) delivery (\(reason))",
            requestID: requestID
        )
    }

    public func handleRiskOperation(
        request: RiskOperationRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              !request.reference.isEmpty,
              request.reference.utf8.count <= 4_096,
              !request.reference.utf8.contains(0),
              let reference = try? SecretRef(request.reference),
              ((request.operation == .inspect || request.operation == .forget)
                    ? request.level == nil
                    : request.level != nil && request.level != .unknown) else {
            return .failed(
                .invalidRequest,
                message: "the risk operation is invalid",
                requestID: request.requestID
            )
        }

        let now = Date()
        let context: RiskContext
        do {
            context = try await riskContext(for: reference, now: now)
        } catch {
            return .failed(
                .internalError,
                message: "risk metadata is unavailable; no secret was resolved",
                requestID: request.requestID
            )
        }
        knownReferencesByCredentialKey[context.identity.credentialKey, default: []]
            .insert(reference.uri)

        if request.operation == .inspect {
            return Response(
                requestID: request.requestID,
                riskInspection: riskInspection(context)
            )
        }

        let currentLevel = context.judgment?.level ?? .unknown
        if request.operation == .raise,
           let requestedLevel = request.level,
           !requestedLevel.isAtLeastAsRestrictive(as: currentLevel) {
            return .failed(
                .policyDenied,
                message: "raise cannot lower the current effective risk level",
                requestID: request.requestID
            )
        }

        let resultingLevel = request.operation == .forget ? nil : request.level
        let requiresBiometric = request.operation == .forget
            || (resultingLevel?.effectiveFloor.severityRank ?? Int.max)
                < currentLevel.effectiveFloor.severityRank
        let review = RiskChangeReview(
            caller: caller,
            operation: request.operation,
            reference: reference,
            currentLevel: currentLevel,
            requestedLevel: resultingLevel,
            knownMemberCount: context.judgment?.credential.memberReferenceKeys.count ?? 0,
            scopeExpanded: context.judgment != nil && !context.referenceInKnownScope,
            requiresBiometric: requiresBiometric
        )
        guard await policyReview.reviewRiskChange(review) else {
            return .failed(
                .consentDenied,
                message: "risk change review denied",
                requestID: request.requestID
            )
        }
        if requiresBiometric {
            let result = resultingLevel?.rawValue ?? "unknown"
            let outcome = await consent.authenticate(reason:
                "confirm \(request.operation.rawValue) risk change from "
                    + "\(currentLevel.rawValue) to \(result) for \(reference.safeInlineURI)"
            )
            guard outcome.isApproved else {
                return .failed(
                    .consentDenied,
                    message: "risk change authentication denied",
                    requestID: request.requestID
                )
            }
        }

        do {
            if request.operation == .forget {
                try await riskJudgments.forget(
                    credentialKey: context.identity.credentialKey
                )
                try await riskJudgments.forgetAcceptances(
                    credentialKey: context.identity.credentialKey
                )
            } else if let resultingLevel {
                if context.judgment?.level != resultingLevel {
                    try await riskJudgments.forgetAcceptances(
                        credentialKey: context.identity.credentialKey
                    )
                }
                let members = Set(
                    context.judgment?.credential.memberReferenceKeys ?? []
                ).union(context.identity.memberReferenceKeys)
                try await riskJudgments.save(RiskJudgment(
                    credential: CredentialIdentity(
                        provider: context.identity.provider,
                        providerAccountKey: context.identity.providerAccountKey,
                        credentialKey: context.identity.credentialKey,
                        memberReferenceKeys: Array(members)
                    ),
                    level: resultingLevel,
                    evidence: context.judgment?.evidence ?? [],
                    source: .explicitUser,
                    decidedAt: now,
                    reviewAfter: now.addingTimeInterval(
                        TimeInterval(RiskPolicyV2.judgmentReviewSeconds)
                    ),
                    policyVersion: RiskPolicyV2.version,
                    providerRevision: context.judgment?.providerRevision,
                    observedScopeDigest: context.judgment?.observedScopeDigest
                ))
            }
        } catch {
            return .failed(
                .internalError,
                message: "risk change could not be stored; existing grants were left unchanged",
                requestID: request.requestID
            )
        }

        var invalidated = await grants.revoke(
            credentialKey: context.identity.credentialKey
        )
        invalidated.formUnion(
            knownReferencesByCredentialKey.removeValue(
                forKey: context.identity.credentialKey
            ) ?? []
        )
        invalidated.insert(reference.uri)
        await resolver.invalidate(references: invalidated)
        await revokeNativeEdits(credentialKey: context.identity.credentialKey)

        do {
            let updated = try await riskContext(for: reference, now: Date())
            return Response(
                requestID: request.requestID,
                riskInspection: riskInspection(updated)
            )
        } catch {
            return .failed(
                .internalError,
                message: "risk changed but its updated metadata could not be inspected",
                requestID: request.requestID
            )
        }
    }

    private func riskContext(for reference: SecretRef, now: Date) async throws -> RiskContext {
        guard let descriptor = CredentialGrouping.groups(for: [reference]).first else {
            throw RiskJudgmentStoreError.invalidOpaqueMetadata
        }
        let identity = try await riskJudgments.credentialIdentity(
            provider: descriptor.provider,
            providerAccount: descriptor.providerAccount,
            group: descriptor.group,
            memberReferences: descriptor.references.map(\.uri)
        )
        let judgment = try await riskJudgments.load(
            credentialKey: identity.credentialKey,
            policyVersion: RiskPolicyV2.version,
            at: now
        )
        let acceptances = try await riskJudgments.loadAcceptances(
            credentialKey: identity.credentialKey,
            policyVersion: RiskPolicyV2.version,
            at: now
        )
        let knownMembers = Set(judgment?.credential.memberReferenceKeys ?? [])
        return RiskContext(
            descriptor: descriptor,
            identity: identity,
            judgment: judgment,
            acceptances: acceptances,
            referenceInKnownScope: Set(identity.memberReferenceKeys).isSubset(of: knownMembers)
        )
    }

    private func riskInspection(_ context: RiskContext) -> RiskInspection {
        let level = context.judgment?.level ?? .unknown
        return RiskInspection(
            provider: context.descriptor.provider,
            level: level,
            effectiveLevel: level.effectiveFloor,
            decidedAt: context.judgment?.decidedAt,
            reviewAfter: context.judgment?.reviewAfter,
            policyVersion: RiskPolicyV2.version,
            knownMemberCount: context.judgment?.credential.memberReferenceKeys.count ?? 0,
            referenceInKnownScope: context.referenceInKnownScope,
            acceptances: context.acceptances.map {
                RiskAcceptanceInspection(
                    mechanism: $0.shape.mechanism,
                    destination: $0.shape.destination,
                    descendantScope: $0.shape.descendantScope,
                    emitterAssurance: $0.shape.emitterAssurance,
                    requesterAssurance: $0.shape.requesterAssurance,
                    recipientAssurance: $0.shape.recipientAssurance,
                    reviewAfter: $0.reviewAfter
                )
            }
        )
    }

    private func biometricPolicySummary(
        _ states: [CredentialPolicyState],
        plan: DeliveryPlan
    ) -> String {
        let counts = Dictionary(grouping: states, by: { $0.decision.effectiveLevel })
        let levels = [RiskLevel.low, .standard, .high, .critical].compactMap { level in
            counts[level].map { "\(level.rawValue) × \($0.count)" }
        }.joined(separator: ", ")
        let weak = plan.mechanism.isWeakCompatibility
            ? "; weak compatibility accepted"
            : ""
        let root = if case .registeredSession = plan.root {
            "registered session"
        } else {
            "per-command"
        }
        return "risk \(levels); delivery \(plan.mechanism.rawValue); "
            + "root \(root); scope \(plan.descendantScope.rawValue); "
            + "destination \(plan.destination.rawValue); recipient "
            + "\(plan.recipientAssurance?.rawValue ?? "planned_consumer")\(weak)"
    }

    /// Production policy review freezes its visible choices at biometric
    /// success and keeps the trusted window and evaluated LAContext alive while
    /// this actor validates that snapshot. Test/headless reviewers have no
    /// embedded session and continue through the injected consent seam.
    private func authenticateReviewedAccess(
        approval: AccessPolicyApproval,
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval,
        policySummary: String
    ) async -> ConsentOutcome {
        if let session = approval.authenticationSession {
            let displaySummary = policySummary
                + "; duration \(BiometricConsent.formatDuration(ttl))"
            return await session.completeAfterPolicyApproval(
                policySummary: displaySummary
            )
        }
        return await consent.requestConsent(
            caller: caller,
            newReferences: newReferences,
            reason: reason,
            ttl: ttl,
            policySummary: policySummary
        )
    }

    public func beginOutputRedaction(
        request: BeginOutputRedactionRequest,
        caller: CallerInfo
    ) -> Response {
        let now = Date()
        pruneRedactionSessions(now: now)
        guard UUID(uuidString: request.requestID) != nil,
              request.destination == .aiTool || request.destination == .localDevelopment,
              !request.streams.isEmpty,
              request.streams.count <= OutputRedactionStream.allCases.count,
              Set(request.streams).count == request.streams.count,
              redactionSessions.count < Self.maximumRedactionSessions else {
            return .failed(
                .invalidRequest,
                message: "output-redaction request is outside supported bounds",
                requestID: request.requestID
            )
        }

        let snapshot = activeSecrets.snapshot(now: now)
        let catalog = OutputRedactionCatalog(
            valuesByReference: snapshot.valuesByOpaqueID,
            includeShortValues: request.includeShortValues
        )
        let sessionID = UUID().uuidString.lowercased()
        redactionSessions[sessionID] = RedactionSession(
            caller: RedactionCaller(pid: caller.pid, startTime: caller.startTime),
            destination: request.destination,
            redactors: Dictionary(uniqueKeysWithValues: request.streams.map {
                ($0, StreamingOutputRedactor(patterns: catalog.patterns))
            }),
            finishedStreams: [],
            registryGeneration: snapshot.generation,
            includeShortValues: request.includeShortValues,
            lastUsedAt: now
        )
        return Response(
            requestID: request.requestID,
            outputRedactionSessionID: sessionID,
            protectedValueCount: catalog.protectedValueCount,
            skippedShortValueCount: catalog.skippedShortValueCount
        )
    }

    public func redactOutputChunk(
        request: RedactOutputChunkRequest,
        caller: CallerInfo
    ) -> Response {
        let now = Date()
        pruneRedactionSessions(now: now)
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.sessionID) != nil,
              request.data.count <= Self.maximumOutputChunkBytes,
              var session = redactionSessions[request.sessionID],
              session.destination == .aiTool || session.destination == .localDevelopment,
              session.caller.matches(caller),
              !session.finishedStreams.contains(request.stream),
              var redactor = session.redactors[request.stream] else {
            return .failed(
                .invalidRequest,
                message: "invalid or expired output-redaction session",
                requestID: request.requestID
            )
        }

        // Values released while the command is running join the matcher before
        // the next output chunk. Existing patterns are never removed mid-stream,
        // preserving any prefix already withheld by this session.
        let snapshot = activeSecrets.snapshot(now: now)
        if snapshot.generation != session.registryGeneration {
            let catalog = OutputRedactionCatalog(
                valuesByReference: snapshot.valuesByOpaqueID,
                includeShortValues: session.includeShortValues
            )
            for stream in Array(session.redactors.keys) {
                session.redactors[stream]?.add(patterns: catalog.patterns)
            }
            session.registryGeneration = snapshot.generation
            redactor = session.redactors[request.stream]!
        }

        var result = redactor.process(request.data)
        if request.finish {
            let final = redactor.finish()
            result = OutputRedactionResult(
                data: result.data + final.data,
                matches: result.matches + final.matches
            )
            session.finishedStreams.insert(request.stream)
        }
        session.redactors[request.stream] = redactor
        session.lastUsedAt = now
        redactionSessions[request.sessionID] = session

        return Response(
            requestID: request.requestID,
            redactedData: result.data,
            redactionMatches: result.matches
        )
    }

    public func endOutputRedaction(
        request: EndOutputRedactionRequest,
        caller: CallerInfo
    ) -> Response {
        pruneRedactionSessions(now: Date())
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.sessionID) != nil,
              let session = redactionSessions[request.sessionID],
              session.caller.matches(caller) else {
            return .failed(
                .invalidRequest,
                message: "invalid or expired output-redaction session",
                requestID: request.requestID
            )
        }
        redactionSessions.removeValue(forKey: request.sessionID)
        return Response(requestID: request.requestID, redactedData: Data())
    }

    public func beginNativeStoreEdit(
        request: BeginNativeStoreEditRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              request.store.utf8.count <= 64,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              Self.hasValidNativeEditorMetadata(request) else {
            return .failed(
                .invalidRequest,
                message: "the native-store edit request is invalid",
                requestID: request.requestID
            )
        }
        guard let nativeStore else {
            return .failed(
                .nativeStoreUnavailable,
                message: "the native encrypted store is unavailable",
                requestID: request.requestID
            )
        }
        let store: NativeStoreName
        do {
            store = try NativeStoreName(request.store)
        } catch {
            return .failed(
                .invalidRequest,
                message: "the native store name is invalid",
                requestID: request.requestID
            )
        }

        let plannedExecutable: PlannedExecutable
        switch request.mode {
        case .builtInMemory, .onboardingImport:
            guard let executablePath = ProcessAncestry.executablePath(of: caller.pid) else {
                return .failed(
                    .unverifiedPeer,
                    message: "the native-store editor process is unavailable",
                    requestID: request.requestID
                )
            }
            plannedExecutable = PlannedExecutable(
                canonicalPath: executablePath,
                signingIdentifier: ProductCodeIdentity.launcherIdentifier,
                teamIdentifier: ProductCodeIdentity.teamIdentifier,
                assurance: .verifiedProduct
            )
        case .externalTemporaryFile:
            plannedExecutable = PlannedExecutable(
                canonicalPath: request.externalEditorPath!,
                assurance: .unverified
            )
        }
        let consentReference = NativeSecretReference.editConsentReference(for: store)
        let operationContext: String
        switch request.mode {
        case .builtInMemory:
            operationContext = "built-in native-store editor"
        case .onboardingImport:
            operationContext = "explicit onboarding import into the native encrypted store"
        case .externalTemporaryFile:
            operationContext = "external native-store editor using a named plaintext file"
        }
        let plan = DeliveryPlan(
            mechanism: request.mode == .externalTemporaryFile
                ? .namedPlaintextFile
                : .directHeap,
            executable: plannedExecutable,
            root: .caller,
            descendantScope: .exactProcess,
            destination: .localDevelopment,
            requestedTTLSeconds: 30 * 60,
            operationContext: operationContext
        )

        do {
            let now = Date()
            let context = try await riskContext(for: consentReference, now: now)
            knownReferencesByCredentialKey[context.identity.credentialKey, default: []]
                .insert(consentReference.uri)
            var storedLevel = context.judgment?.level ?? .unknown
            var acceptance = context.acceptances.first {
                $0.permits(
                    credentialKey: context.identity.credentialKey,
                    plan: plan,
                    policyVersion: RiskPolicyV2.version,
                    at: now
                )
            }
            var decision = RiskPolicyV2.evaluate(RiskPolicyInput(
                credentialKey: context.identity.credentialKey,
                storedLevel: storedLevel,
                evidence: context.judgment?.evidence ?? [],
                plan: plan,
                acceptance: acceptance,
                now: now
            ))
            let scopeExpanded = context.judgment != nil && !context.referenceInKnownScope

            if storedLevel != .unknown,
               !decision.allowed,
               decision.denialReason != .compatibilityAcceptanceRequired {
                return policyDenied(decision, plan: plan, requestID: request.requestID)
            }

            let reviewCredential = PolicyReviewCredential(
                identity: context.identity,
                references: [consentReference],
                storedLevel: storedLevel,
                scopeExpanded: scopeExpanded,
                compatibilityReviewOffered: plan.mechanism.isWeakCompatibility
                    && (storedLevel == .unknown
                        || decision.denialReason == .compatibilityAcceptanceRequired
                        || acceptance != nil),
                compatibilityAccepted: acceptance != nil
            )
            let review = AccessPolicyReview(
                caller: caller,
                reason: plan.operationContext,
                plan: plan,
                credentials: [reviewCredential]
            )
            guard case let .approved(approval) = await policyReview.reviewAccess(review) else {
                return .failed(
                    .consentDenied,
                    message: "native-store policy review denied",
                    requestID: request.requestID
                )
            }
            if storedLevel == .unknown {
                guard let selected = approval.classifications[context.identity.credentialKey],
                      selected != .unknown else {
                    await approval.authenticationSession?.cancel()
                    return .failed(
                        .policyDenied,
                        message: "an explicit native-store risk classification is required",
                        requestID: request.requestID
                    )
                }
                storedLevel = selected
            }
            decision = RiskPolicyV2.evaluate(RiskPolicyInput(
                credentialKey: context.identity.credentialKey,
                storedLevel: storedLevel,
                evidence: context.judgment?.evidence ?? [],
                plan: plan,
                acceptance: acceptance,
                now: now
            ))
            var acceptanceWasAdded = false
            if acceptance == nil,
               decision.denialReason == .compatibilityAcceptanceRequired,
               approval.acceptedCompatibilityCredentialKeys.contains(
                   context.identity.credentialKey
               ) {
                let newAcceptance = compatibilityAcceptance(
                    credentialKey: context.identity.credentialKey,
                    plan: plan,
                    decision: decision,
                    now: now
                )
                acceptance = newAcceptance.acceptance
                acceptanceWasAdded = newAcceptance.shouldPersist
                decision = RiskPolicyV2.evaluate(RiskPolicyInput(
                    credentialKey: context.identity.credentialKey,
                    storedLevel: storedLevel,
                    evidence: context.judgment?.evidence ?? [],
                    plan: plan,
                    acceptance: acceptance,
                    now: now
                ))
            }
            guard decision.allowed, decision.grantedTTLSeconds > 0 else {
                await approval.authenticationSession?.cancel()
                return policyDenied(decision, plan: plan, requestID: request.requestID)
            }

            let policySummary = "risk \(decision.effectiveLevel.rawValue) × 1; "
                + "delivery \(plan.mechanism.rawValue); scope exact_process; "
                + "destination local_development"
                + (plan.mechanism.isWeakCompatibility ? "; weak compatibility accepted" : "")
            let outcome = await authenticateReviewedAccess(
                approval: approval,
                caller: caller,
                newReferences: [consentReference],
                reason: plan.operationContext,
                ttl: TimeInterval(decision.grantedTTLSeconds),
                policySummary: policySummary
            )
            guard case let .approved(unlock) = outcome else {
                return .failed(
                    .consentDenied,
                    message: "consent denied",
                    requestID: request.requestID
                )
            }

            if context.judgment == nil || scopeExpanded {
                let members = Set(
                    context.judgment?.credential.memberReferenceKeys ?? []
                ).union(context.identity.memberReferenceKeys)
                try await riskJudgments.save(RiskJudgment(
                    credential: CredentialIdentity(
                        provider: context.identity.provider,
                        providerAccountKey: context.identity.providerAccountKey,
                        credentialKey: context.identity.credentialKey,
                        memberReferenceKeys: Array(members)
                    ),
                    level: storedLevel,
                    evidence: context.judgment?.evidence ?? [],
                    source: .explicitUser,
                    decidedAt: now,
                    reviewAfter: now.addingTimeInterval(
                        TimeInterval(RiskPolicyV2.judgmentReviewSeconds)
                    ),
                    policyVersion: RiskPolicyV2.version,
                    providerRevision: context.judgment?.providerRevision,
                    observedScopeDigest: context.judgment?.observedScopeDigest
                ))
            }
            if acceptanceWasAdded, let acceptance {
                try await riskJudgments.save(acceptance)
            }

            let edit = try await nativeStore.beginEdit(
                store: store,
                callerPID: caller.pid,
                callerStartTime: caller.startTime,
                unlock: unlock,
                authorizedTTL: TimeInterval(decision.grantedTTLSeconds),
                now: now
            )
            nativeEditAuthorizations[edit.sessionID] = NativeEditAuthorization(
                callerPID: caller.pid,
                callerStartTime: caller.startTime,
                reference: consentReference,
                plan: plan,
                policyBinding: PolicyGrantBinding(
                    credentialKey: context.identity.credentialKey,
                    riskLevel: decision.effectiveLevel,
                    policyVersion: decision.policyVersion,
                    policyDigest: decision.policyDigest,
                    outputPolicy: decision.outputPolicy
                ),
                expiresAt: now.addingTimeInterval(TimeInterval(decision.grantedTTLSeconds))
            )
            return Response(
                requestID: request.requestID,
                editSessionID: edit.sessionID,
                document: edit.document
            )
        } catch {
            return nativeStoreFailure(error, requestID: request.requestID)
        }
    }

    public func commitNativeStoreEdit(
        request: CommitNativeStoreEditRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.editSessionID) != nil,
              request.document.count <= NativeStoreDocument.maximumBytes,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              let nativeStore,
              let authorization = nativeEditAuthorizations[request.editSessionID],
              authorization.callerPID == caller.pid,
              authorization.callerStartTime == caller.startTime else {
            return .failed(
                .invalidRequest,
                message: "the native-store edit request is invalid",
                requestID: request.requestID
            )
        }
        do {
            guard Date() < authorization.expiresAt,
                  try await nativeEditPolicyIsCurrent(authorization) else {
                await nativeStore.cancelEdit(
                    sessionID: request.editSessionID,
                    callerPID: caller.pid,
                    callerStartTime: caller.startTime
                )
                nativeEditAuthorizations[request.editSessionID] = nil
                return .failed(
                    .policyDenied,
                    message: "native-store edit authorization changed or expired",
                    requestID: request.requestID
                )
            }
        } catch {
            await nativeStore.cancelEdit(
                sessionID: request.editSessionID,
                callerPID: caller.pid,
                callerStartTime: caller.startTime
            )
            nativeEditAuthorizations[request.editSessionID] = nil
            return .failed(
                .internalError,
                message: "native-store risk metadata is unavailable; edit cancelled",
                requestID: request.requestID
            )
        }
        do {
            let result = try await nativeStore.commitEdit(
                sessionID: request.editSessionID,
                document: request.document,
                callerPID: caller.pid,
                callerStartTime: caller.startTime
            )
            nativeEditAuthorizations[request.editSessionID] = nil
            return Response(
                requestID: request.requestID,
                generation: result.generation,
                secretCount: result.secretCount
            )
        } catch {
            return nativeStoreFailure(error, requestID: request.requestID)
        }
    }

    public func cancelNativeStoreEdit(
        request: CancelNativeStoreEditRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.editSessionID) != nil,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              let nativeStore else {
            return .failed(
                .invalidRequest,
                message: "the native-store edit request is invalid",
                requestID: request.requestID
            )
        }
        await nativeStore.cancelEdit(
            sessionID: request.editSessionID,
            callerPID: caller.pid,
            callerStartTime: caller.startTime
        )
        nativeEditAuthorizations[request.editSessionID] = nil
        return Response(requestID: request.requestID)
    }

    private func nativeEditPolicyIsCurrent(
        _ authorization: NativeEditAuthorization
    ) async throws -> Bool {
        let now = Date()
        let context = try await riskContext(for: authorization.reference, now: now)
        let acceptance = context.acceptances.first {
            $0.permits(
                credentialKey: context.identity.credentialKey,
                plan: authorization.plan,
                policyVersion: RiskPolicyV2.version,
                at: now
            )
        }
        let decision = RiskPolicyV2.evaluate(RiskPolicyInput(
            credentialKey: context.identity.credentialKey,
            storedLevel: context.judgment?.level ?? .unknown,
            evidence: context.judgment?.evidence ?? [],
            plan: authorization.plan,
            acceptance: acceptance,
            now: now
        ))
        let current = PolicyGrantBinding(
            credentialKey: context.identity.credentialKey,
            riskLevel: decision.effectiveLevel,
            policyVersion: decision.policyVersion,
            policyDigest: decision.policyDigest,
            outputPolicy: decision.outputPolicy
        )
        return decision.allowed && current == authorization.policyBinding
    }

    private func revokeNativeEdits(credentialKey: String) async {
        guard let nativeStore else { return }
        let affected = nativeEditAuthorizations.filter {
            $0.value.policyBinding.credentialKey == credentialKey
        }
        for (sessionID, authorization) in affected {
            await nativeStore.cancelEdit(
                sessionID: sessionID,
                callerPID: authorization.callerPID,
                callerStartTime: authorization.callerStartTime
            )
            nativeEditAuthorizations[sessionID] = nil
        }
    }

    /// Advertise the URI schemes the agent can resolve. A capability query — no
    /// consent, no grant, no secret material — so a client can detect which
    /// environment values are secret references.
    public func schemes() async -> Response {
        Response(schemes: await resolver.registeredSchemes())
    }

    public func capabilities() -> Response {
        let features = WireCapability.allCases.filter {
            switch $0 {
            case .nativeEncryptedStore, .nativeEditorPolicy:
                return nativeStore != nil
            default:
                return true
            }
        }
        return Response(capabilities: ProtocolCapabilities(features: features))
    }

    /// Batched host remediation: run the audit, present the fixable set as a
    /// single deselectable checklist under one Touch ID, then apply the selected
    /// changes (`.auto` in-process, `.autoPrivileged` via the agent-role root
    /// helper). Implemented by `HostRemediationCoordinator` + the trusted review.
    public func runHostRemediation(
        request: HostRemediationRequest,
        caller: CallerInfo
    ) async -> Response {
        guard isVerifiedLauncher(caller) else {
            return .failed(
                .consentDenied,
                message: "host remediation requires the verified csec launcher",
                requestID: request.requestID
            )
        }
        let summary = await HostRemediationCoordinator.run(
            request: request,
            review: policyReview
        )
        return Response(requestID: request.requestID, hostRemediation: summary)
    }

    /// Register the authenticated launcher's current process incarnation. A
    /// descendant can later name the opaque ID, but access succeeds only when
    /// a fresh kernel ancestry walk reaches this exact PID/start-time pair.
    public func beginSession(
        request: BeginSessionRequest,
        caller: CallerInfo
    ) -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              caller.pid > 1,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              ProcessAncestry.startTime(of: caller.pid) == caller.startTime else {
            return .failed(
                .unverifiedPeer,
                message: "a live verified launcher is required to register a session",
                requestID: request.requestID
            )
        }

        pruneRegisteredSessions()
        registeredSessions = registeredSessions.filter {
            $0.value.rootPID != caller.pid || $0.value.rootStartTime != caller.startTime
        }
        guard registeredSessions.count < Self.maximumRegisteredSessions else {
            return .failed(
                .policyDenied,
                message: "too many registered sessions are active",
                requestID: request.requestID
            )
        }

        let sessionID = UUID().uuidString.lowercased()
        registeredSessions[sessionID] = RegisteredSession(
            rootPID: caller.pid,
            rootStartTime: caller.startTime,
            auditSessionID: caller.peerIdentity?.audit.auditSessionID
        )
        return Response(requestID: request.requestID, registeredSessionID: sessionID)
    }

    private func isVerifiedLauncher(_ caller: CallerInfo) -> Bool {
        allowUnverifiedPlansForTesting || caller.peerIdentity?.code.role == .launcher
    }

    private func nativeStoreFailure(_ error: Error, requestID: String) -> Response {
        guard let error = error as? NativeStoreError else {
            return .failed(
                .internalError,
                message: "the native-store operation failed",
                requestID: requestID
            )
        }
        switch error {
        case .invalidStoreName, .invalidReference:
            return .failed(
                .invalidRequest,
                message: "the native-store request is invalid",
                requestID: requestID
            )
        case .invalidDocument, .documentTooLarge, .tooManySecrets:
            return .failed(
                .invalidStoreDocument,
                message: "the store must be a JSON object with unique valid keys and string values",
                requestID: requestID
            )
        case .editSessionExpired:
            return .failed(
                .editSessionExpired,
                message: "the native-store edit session is invalid or expired",
                requestID: requestID
            )
        case .editConflict:
            return .failed(
                .editConflict,
                message: "the native store changed after this edit began",
                requestID: requestID
            )
        case .tooManyEditSessions:
            return .failed(
                .policyDenied,
                message: "too many native-store edit sessions are active",
                requestID: requestID
            )
        case .authenticationRequired, .keyUnavailable, .storeNotFound,
             .secretNotFound, .integrityFailure, .filesystemFailure,
             .randomGenerationFailed:
            return .failed(
                .nativeStoreUnavailable,
                message: "the native encrypted store is unavailable or failed integrity validation",
                requestID: requestID
            )
        }
    }

    private func pruneRedactionSessions(now: Date) {
        let cutoff = now.addingTimeInterval(-Self.redactionSessionIdleSeconds)
        redactionSessions = redactionSessions.filter { $0.value.lastUsedAt > cutoff }
    }

    private func verifyRoot(
        _ root: DeliveryRoot,
        caller: CallerInfo
    ) -> (pid: pid_t, startTime: UInt64)? {
        switch root {
        case .caller:
            guard caller.startTime > 0 else { return nil }
            return (caller.pid, caller.startTime)
        case let .directParent(pid, startTime):
            guard pid > 1,
                  startTime > 0,
                  ProcessAncestry.parent(of: caller.pid) == pid,
                  ProcessAncestry.startTime(of: pid) == startTime else { return nil }
            return (pid, startTime)
        case let .registeredSession(id):
            guard let canonicalID = UUID(uuidString: id)?.uuidString.lowercased(),
                  canonicalID == id.lowercased(),
                  let session = registeredSessions[canonicalID],
                  session.auditSessionID == nil
                    || caller.peerIdentity?.audit.auditSessionID == session.auditSessionID,
                  ProcessAncestry.descends(
                    caller.pid,
                    from: session.rootPID,
                    rootStartTime: session.rootStartTime
                  ) else { return nil }
            return (session.rootPID, session.rootStartTime)
        }
    }

    private func verifyDeliveryRoot(
        _ plan: DeliveryPlan,
        caller: CallerInfo
    ) -> (pid: pid_t, startTime: UInt64)? {
        guard let root = verifyRoot(plan.root, caller: caller) else { return nil }
        guard case let .directParent(pid, _) = plan.root else { return root }

        let requester = plan.requestingExecutable ?? plan.executable
        let claimedPath = URL(fileURLWithPath: requester.canonicalPath)
            .standardizedFileURL.resolvingSymlinksInPath().path
        guard ProcessAncestry.executablePath(of: pid) == claimedPath else { return nil }

        // A separate requester identity is a signed-launcher assertion, but
        // csecd independently recomputes it and then rechecks the live image.
        if plan.requestingExecutable != nil {
            guard let inspected = try? ExecutableInspection.plannedExecutable(
                command: claimedPath
            ), inspected == requester,
            ProcessAncestry.startTime(of: pid) == root.startTime,
            ProcessAncestry.executablePath(of: pid) == claimedPath else { return nil }
        }
        return root
    }

    private func pruneRegisteredSessions() {
        registeredSessions = registeredSessions.filter {
            ProcessAncestry.startTime(of: $0.value.rootPID) == $0.value.rootStartTime
        }
    }

    private static func hasValidMetadata(_ plan: DeliveryPlan) -> Bool {
        let executable = plan.executable
        return hasValidExecutableMetadata(executable)
            && hasValidRequesterMetadata(plan)
            && hasValidRecipientMetadata(plan)
            && !plan.operationContext.isEmpty
            && plan.operationContext.utf8.count <= 512
            && !plan.operationContext.utf8.contains(0)
            && hasValidRootScope(plan)
            && (plan.commandDigest.map(isSHA256Digest) ?? true)
            && hasValidOutputGuard(plan)
    }

    private static func hasValidRequesterMetadata(_ plan: DeliveryPlan) -> Bool {
        switch (plan.root, plan.requestingExecutable) {
        case (.directParent, .none):
            // Existing direct-parent consumers use `executable` for both roles.
            return true
        case let (.directParent, .some(requester)):
            return hasValidExecutableMetadata(requester)
        case (_, .none):
            return true
        case (_, .some):
            return false
        }
    }

    private static func hasValidExecutableMetadata(_ executable: PlannedExecutable) -> Bool {
        executable.canonicalPath.hasPrefix("/")
            && executable.canonicalPath.utf8.count <= 4_096
            && !executable.canonicalPath.utf8.contains(0)
            && (executable.signingIdentifier.map {
                !$0.isEmpty && $0.utf8.count <= 512 && !$0.utf8.contains(0)
            } ?? true)
            && (executable.teamIdentifier.map {
                !$0.isEmpty && $0.utf8.count <= 128 && !$0.utf8.contains(0)
            } ?? true)
            && (executable.cdHash.map {
                !$0.isEmpty && $0.utf8.count <= 128 && $0.utf8.allSatisfy(isLowerHex)
            } ?? true)
    }

    private static func hasValidRecipientMetadata(_ plan: DeliveryPlan) -> Bool {
        switch (plan.mechanism, plan.destination, plan.recipientAssurance) {
        case (.rawStandardOutput, .humanOutput, .interactiveTerminal),
             (.rawStandardOutput, .shellDelegatedPipe, .unverifiedPipeReader),
             (.namedPlaintextFile, .persistentPlaintextFile, .ordinaryPersistentFile):
            guard plan.executable.assurance == .verifiedProduct,
                  plan.executable.signingIdentifier == ProductCodeIdentity.launcherIdentifier,
                  plan.executable.teamIdentifier == ProductCodeIdentity.teamIdentifier,
                  plan.requestingExecutable != nil,
                  plan.descendantScope == .subtree,
                  case .directParent = plan.root else { return false }
            return true
        case (.rawStandardOutput, _, _):
            // Raw stdout is exposed only through the fully described csec-get
            // shapes above. In particular, omitting the requester/recipient or
            // relabelling a pipe as terminal output is malformed metadata.
            return false
        case (_, .shellDelegatedPipe, _), (_, .persistentPlaintextFile, _):
            return false
        case (_, _, .some):
            return false
        case (_, _, .none):
            return true
        }
    }

    private static func hasValidRootScope(_ plan: DeliveryPlan) -> Bool {
        switch plan.root {
        case .registeredSession:
            return plan.descendantScope == .broadSession
        case .caller, .directParent:
            return plan.descendantScope != .broadSession
        }
    }

    private static func hasValidNativeEditorMetadata(
        _ request: BeginNativeStoreEditRequest
    ) -> Bool {
        switch request.mode {
        case .builtInMemory, .onboardingImport:
            return request.externalEditorPath == nil
        case .externalTemporaryFile:
            guard let path = request.externalEditorPath else { return false }
            return path.hasPrefix("/")
                && path.utf8.count <= 4_096
                && !path.utf8.contains(0)
        }
    }

    private static func isSHA256Digest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy(isLowerHex)
    }

    private static func hasValidOutputGuard(_ plan: DeliveryPlan) -> Bool {
        if plan.mechanism == .unrestrictedInitialEnvironment {
            guard let outputGuard = plan.outputGuard else { return false }
            return outputGuard.matcherVersion == OutputGuardPlan.currentMatcherVersion
        }
        return plan.outputGuard?.matcherVersion == OutputGuardPlan.currentMatcherVersion
            || plan.outputGuard == nil
    }

    private static func isLowerHex(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}
