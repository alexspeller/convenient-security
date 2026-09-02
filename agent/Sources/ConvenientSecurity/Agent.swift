import Foundation

/// The policy core: matches callers against subtree grants, gates newly-seen
/// references through consent, then resolves the approved references.
public actor Agent {
    private struct NativeEditAuthorization {
        let callerPID: pid_t
        let callerStartTime: UInt64
        let expiresAt: Date
        let store: NativeStoreName
        let mode: NativeStoreEditorMode
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
        let labelStyle: OutputRedactionLabelStyle
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
    // Whole-file import batch bounds. A single csec exec/import call carries the
    // files' bytes over the socket; hundreds of small dotenv files or a handful
    // of large ones fit, and larger sets are imported in successive batches.
    private static let maximumImportBlobs = 256
    private static let maximumImportTotalBytes = 16 * 1024 * 1024

    private let resolver: SecretResolver
    private let grants: GrantTable
    private let consent: ConsentProvider
    private let policyReview: PolicyReviewProvider
    private let nativeStore: NativeEncryptedFileProvider?
    private let sshSigningService: SSHSigningService?
    private let automationService: AutomationService?
    private let allowLegacyAccessForTesting: Bool
    private let allowUnverifiedPlansForTesting: Bool
    private let allowUnverifiedAutomationCallersForTesting: Bool
    /// Kernel process metadata used to resolve and re-verify grant scopes.
    /// Production always uses `.live`; the seam keeps synthetic-ancestry tests
    /// possible without weakening any release check.
    private let processInspection: ProcessInspection
    private var activeSecrets = ActiveSecretRegistry()
    private var redactionSessions: [String: RedactionSession] = [:]
    private var nativeEditAuthorizations: [String: NativeEditAuthorization] = [:]
    private var registeredSessions: [String: RegisteredSession] = [:]

    public init(
        resolver: SecretResolver,
        grants: GrantTable,
        consent: ConsentProvider,
        policyReview: PolicyReviewProvider,
        nativeStore: NativeEncryptedFileProvider? = nil,
        sshSigningService: SSHSigningService? = nil,
        automationService: AutomationService? = nil,
        allowLegacyAccessForTesting: Bool = false,
        allowUnverifiedPlansForTesting: Bool = false,
        allowUnverifiedAutomationCallersForTesting: Bool = false,
        processInspection: ProcessInspection = .live
    ) {
        self.processInspection = processInspection
        self.resolver = resolver
        self.grants = grants
        self.consent = consent
        self.policyReview = policyReview
        self.nativeStore = nativeStore
        self.sshSigningService = sshSigningService
        self.automationService = automationService
        self.allowLegacyAccessForTesting = allowLegacyAccessForTesting
        self.allowUnverifiedPlansForTesting = allowUnverifiedPlansForTesting
        self.allowUnverifiedAutomationCallersForTesting =
            allowUnverifiedAutomationCallersForTesting
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

        if let automationService {
            switch await automationService.authorizeAccess(
                references: refs,
                plan: plan,
                caller: caller,
                now: now
            ) {
            case .notApplicable:
                break
            case let .allowed(values, expiresAt):
                activeSecrets.register(valuesByReference: values, expiresAt: expiresAt)
                return Response(
                    requestID: request.requestID,
                    values: values,
                    accessExpiresAt: expiresAt
                )
            case let .denied(error):
                return automationFailure(error, requestID: request.requestID)
            }
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
        // The value-free release decision depends only on the plan: a bounded
        // grant lifetime, a mechanism-derived output policy, and the csec-get
        // plaintext-exposure gate. There is no risk classification, no
        // compatibility-acceptance ledger, and no per-credential policy.
        let decision = ReleasePolicy.evaluate(plan: plan)
        guard decision.allowed, decision.grantedTTLSeconds > 0 else {
            return policyDenied(decision, plan: plan, requestID: request.requestID)
        }
        let grantedTTL = decision.grantedTTLSeconds

        // Grant reuse: a live grant rooted at the caller or an ancestor covers
        // these references without another prompt. A per-command grant needs this
        // exact delivery-plan digest; a grant the human widened to an agent or
        // terminal session needs the same release shape (see
        // `DeliveryPlan.releaseShapeDigest`). Capability-GID launches never reuse
        // — each is a fresh two-party rendezvous whose new root must not outlive
        // its authorization.
        let releaseShapeDigest = try? plan.releaseShapeDigest()
        let accessible: Set<String>
        if plan.mechanism == .capabilityGIDFile {
            accessible = []
        } else {
            accessible = await grants.accessibleReferences(
                for: caller.pid,
                now: now,
                deliveryPlanDigest: planDigest,
                releaseShapeDigest: releaseShapeDigest,
                callerAuditSessionID: caller.peerIdentity?.audit.auditSessionID
            )
        }
        let newReferenceURIs = Set(refs.map(\.uri)).subtracting(accessible)

        if newReferenceURIs.isEmpty {
            // Everything is covered by a live grant — resolve without a prompt.
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

        // New references → one display-only trusted review + Touch ID. The
        // window shows the references, destination, and any inspectable-shape
        // warning; a successful biometric is itself the authorization.
        // Providers get to say where each value will come from before the window
        // asks for Touch ID — an `op://` reference names no account, so this is
        // where the chosen one becomes visible.
        let reviewCredentials = await resolver.reviewCredentials(
            for: CredentialGrouping.groups(for: refs)
                .filter { group in
                    group.references.contains { newReferenceURIs.contains($0.uri) }
                }
                .map(\.references)
        )
        // csecd — not the launcher — resolves which roots may be offered, by
        // walking kernel ancestry above the already-verified plan root. A
        // capability-GID rendezvous is deliberately single-use, so it is never
        // offered a wider root.
        let scopeChoices: GrantScopeChoices? =
            plan.mechanism == .capabilityGIDFile
            ? nil
            : GrantScopeInspector.choices(
                planRootPID: rootPID,
                planRootStartTime: rootStartTime,
                requestingLabel: scopeRequestingLabel(plan: plan, rootPID: rootPID),
                inspection: processInspection
            )
        let offersScopeChoice = (scopeChoices?.options.count ?? 0) > 1
        let review = AccessPolicyReview(
            caller: displayedCaller(
                caller, plan: plan, rootPID: rootPID,
                statesGrantRoot: !offersScopeChoice
            ),
            reason: request.reason,
            plan: plan,
            credentials: reviewCredentials,
            scopeChoices: scopeChoices
        )
        guard case let .approved(approval) = await policyReview.reviewAccess(review) else {
            return .failed(
                .consentDenied,
                message: "policy review denied",
                requestID: request.requestID
            )
        }

        // Resolve the reviewer's selection against the list csecd itself built,
        // then prove the chosen root is still the same live process and still
        // contains the plan root. An unknown identifier resolves to the displayed
        // default and can never widen the grant.
        let selectedScope = scopeChoices.map {
            $0.resolved(selectedID: approval.selectedScopeOptionID)
        }
        if let selectedScope, selectedScope.kind != .requestingCommand {
            guard verifiedScopeRoot(selectedScope, planRootPID: rootPID) else {
                return .failed(
                    .invalidRequest,
                    message: "the selected grant scope changed before release",
                    requestID: request.requestID
                )
            }
        }

        let newReferences = refs.filter { newReferenceURIs.contains($0.uri) }
        let outcome = await authenticateReviewedAccess(
            approval: approval,
            caller: displayedCaller(
                caller, plan: plan, rootPID: rootPID,
                statesGrantRoot: !offersScopeChoice
            ),
            newReferences: newReferences,
            reason: request.reason,
            ttl: TimeInterval(grantedTTL),
            policySummary: releasePolicySummary(plan: plan, scope: selectedScope)
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

        // The chosen root must still be live and still contain the plan root at
        // the moment the grant is minted, not only when the window was shown.
        let scope = selectedScope ?? GrantScopeOption(
            kind: .requestingCommand,
            pid: rootPID,
            startTime: rootStartTime,
            processLabel: ReviewDisplay.sanitized(
                scopeRequestingLabel(plan: plan, rootPID: rootPID)
            )
        )
        guard scope.kind == .requestingCommand
                || verifiedScopeRoot(scope, planRootPID: rootPID) else {
            return .failed(
                .invalidRequest,
                message: "the selected grant scope changed before release",
                requestID: request.requestID
            )
        }

        // Mint one subtree-bound grant per credential group for the newly
        // approved references, valid for the bounded lifetime.
        for group in CredentialGrouping.groups(for: refs) {
            let references = Set(group.references.compactMap {
                newReferenceURIs.contains($0.uri) ? $0.uri : nil
            })
            guard !references.isEmpty else { continue }
            await grants.add(Grant(
                rootPID: scope.pid,
                rootStartTime: scope.startTime,
                references: references,
                reason: request.reason,
                expiresAt: now.addingTimeInterval(TimeInterval(grantedTTL)),
                requestID: request.requestID,
                deliveryPlanDigest: planDigest,
                peerPIDVersion: caller.peerIdentity?.audit.pidVersion,
                peerCDHash: caller.peerIdentity?.code.cdHash,
                plannedExecutable: plan.executable,
                scopeKind: scope.kind,
                // A per-command root keeps the original exact-digest binding; a
                // widened one is reusable by any command of the same shape.
                scopeReuseDigest: scope.kind.reusesAcrossCommands
                    ? releaseShapeDigest : nil,
                auditSessionID: caller.peerIdentity?.audit.auditSessionID,
                rootProcessLabel: scope.processLabel
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
        var values: [String: Data] = [:]
        for ref in refs {
            do {
                values[ref.uri] = try await resolver.resolve(ref, unlock: unlock)
            } catch {
                // The reference URI is value-free metadata the consent window
                // already displayed; naming it turns an opaque failure into an
                // actionable one. A provider may add a reason only through
                // `ProviderDiagnosableError`, which is csec-authored and
                // bounded; a tool's own error output never reaches a client.
                var message = "the provider could not resolve \(ref.safeInlineURI)"
                if let diagnosable = error as? ProviderDiagnosableError {
                    message += ": " + ReviewDisplay.bounded(
                        ReviewDisplay.sanitized(diagnosable.boundedReason),
                        maxBytes: 512
                    )
                }
                return .failed(.resolutionFailed, message: message, requestID: requestID)
            }
        }
        if let activeUntil {
            activeSecrets.register(valuesByReference: values, expiresAt: activeUntil)
        }
        return Response(
            requestID: requestID,
            values: values,
            accessExpiresAt: activeUntil
        )
    }

    /// Planted-sidecar defense for symlink-delivered (`*.csec`) bindings that name
    /// a native `csec://` blob: the value must come from a blob whose recorded
    /// `csec protect` path equals the sidecar's own project location, so a sidecar
    /// dropped or moved by same-uid malware cannot redirect a native value to a
    /// path it was never protected at. It reuses the store key record cached by the
    /// just-completed resolution, so it adds no second Touch ID, and fails closed:
    /// a native binding whose recorded path differs (or is absent) is rejected.
    ///
    /// A sidecar is source-neutral, so a non-native reference (`op://`, …) has no
    /// recorded protect-path and cannot be path-bound; it is allowed here and, like
    /// `op://` everywhere else in csec, relies on the Touch ID review that shows the
    /// reference before release. Environment-delivered bindings are unaffected.
    public func protectedFilePathsAreBound(_ bindings: [ProtectedFileBinding]) async -> Bool {
        for binding in bindings {
            guard let target = binding.symlinkTarget else { continue }
            guard let reference = try? SecretRef(binding.reference) else { return false }
            // Only native references carry a recorded protect-path to bind against.
            guard reference.scheme == "csec" else { continue }
            guard let nativeStore,
                  let nativeReference = try? NativeSecretReference(reference),
                  let recordedPath = await nativeStore.recordedBlobPath(
                      store: nativeReference.store, key: nativeReference.key),
                  recordedPath == target else {
                return false
            }
        }
        return true
    }

    private func displayedCaller(
        _ caller: CallerInfo,
        plan: DeliveryPlan,
        rootPID: pid_t,
        // When the review offers a scope selector, that selector is the
        // authoritative statement of the grant root; naming a root here too
        // would contradict a live selection.
        statesGrantRoot: Bool = true
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
            let root = statesGrantRoot ? " (grant root pid \(rootPID))" : ""
            displayed.description = "\(caller.description) for \(executableName) "
                + "[\(plan.executable.assurance.rawValue)]\(root)"
        }
        return displayed
    }

    private func policyDenied(
        _ decision: ReleaseDecision,
        plan: DeliveryPlan,
        requestID: String?
    ) -> Response {
        let reason = decision.denialReason?.rawValue ?? "denied"
        return .failed(
            .policyDenied,
            message: "release policy denied \(plan.mechanism.rawValue) delivery (\(reason))",
            requestID: requestID
        )
    }

    /// Label for the plan's own root, which is not always the emitter. For a
    /// direct-parent root (an interactive `csec get`) the root process is the
    /// requester — the shell — not the signed csec that emits the bytes; for a
    /// registered session it is neither, so the live kernel name is the only
    /// honest description of that pid.
    private func scopeRequestingLabel(plan: DeliveryPlan, rootPID: pid_t) -> String {
        if case .registeredSession = plan.root {
            return processInspection.name(of: rootPID)
                ?? URL(fileURLWithPath: plan.executable.canonicalPath).lastPathComponent
        }
        let requester = plan.requestingExecutable ?? plan.executable
        return URL(fileURLWithPath: requester.canonicalPath).lastPathComponent
    }

    /// A widened root is honored only while it is the same live process it was
    /// when the window was drawn, and only while it still contains the plan root.
    /// Both are fresh kernel checks; nothing the reviewer returns is trusted.
    private func verifiedScopeRoot(
        _ scope: GrantScopeOption,
        planRootPID: pid_t
    ) -> Bool {
        scope.pid > 1
            && processInspection.startTime(of: scope.pid) == scope.startTime
            && processInspection.descends(
                planRootPID, from: scope.pid, rootStartTime: scope.startTime
            )
    }

    /// A value-free one-line summary of the delivery shown in the Touch ID
    /// reason string. It names the mechanism, root, scope, destination, and
    /// recipient — there is no risk level, because there no longer is one. When
    /// the review offered a scope selector, the root is the option that was
    /// actually selected.
    private func releasePolicySummary(
        plan: DeliveryPlan,
        scope: GrantScopeOption? = nil
    ) -> String {
        let root: String
        if let scope {
            root = ReviewDisplay.scopeSummary(scope)
        } else if case .registeredSession = plan.root {
            root = "registered session"
        } else {
            root = "per-command"
        }
        return "delivery \(plan.mechanism.rawValue); root \(root); "
            + "scope \(plan.descendantScope.rawValue); "
            + "destination \(plan.destination.rawValue); recipient "
            + "\(plan.recipientAssurance?.rawValue ?? "planned_consumer")"
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
            valuesByReference: snapshot.valuesByReference,
            labelStyle: request.labelStyle,
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
            labelStyle: request.labelStyle,
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
                valuesByReference: snapshot.valuesByReference,
                labelStyle: session.labelStyle,
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
        case .builtInMemory, .onboardingImport, .sshKeyImport:
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
        case .sshKeyImport:
            operationContext = "protect and register private SSH keys for signature-only use"
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
            operationContext: operationContext,
            // Choosing `csec edit --editor` (the only path that uses the
            // named-plaintext-file mechanism here) is itself the explicit
            // acknowledgment of the temporary plaintext file it warns about.
            plaintextExposureAcknowledged: request.mode == .externalTemporaryFile
        )

        do {
            let now = Date()
            // A native-store edit is authorized by one display-only review +
            // Touch ID, exactly like a secret release: no classification, no
            // acceptance. The bounded edit lifetime comes from the plan's TTL.
            let decision = ReleasePolicy.evaluate(plan: plan)
            guard decision.allowed, decision.grantedTTLSeconds > 0 else {
                return policyDenied(decision, plan: plan, requestID: request.requestID)
            }
            let review = AccessPolicyReview(
                caller: caller,
                reason: plan.operationContext,
                plan: plan,
                credentials: [PolicyReviewCredential(references: [consentReference])]
            )
            guard case let .approved(approval) = await policyReview.reviewAccess(review) else {
                return .failed(
                    .consentDenied,
                    message: "native-store policy review denied",
                    requestID: request.requestID
                )
            }
            let outcome = await authenticateReviewedAccess(
                approval: approval,
                caller: caller,
                newReferences: [consentReference],
                reason: plan.operationContext,
                ttl: TimeInterval(decision.grantedTTLSeconds),
                policySummary: releasePolicySummary(plan: plan)
            )
            guard case let .approved(unlock) = outcome else {
                return .failed(
                    .consentDenied,
                    message: "consent denied",
                    requestID: request.requestID
                )
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
                expiresAt: now.addingTimeInterval(TimeInterval(decision.grantedTTLSeconds)),
                store: store,
                mode: request.mode
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
        guard Date() < authorization.expiresAt else {
            await nativeStore.cancelEdit(
                sessionID: request.editSessionID,
                callerPID: caller.pid,
                callerStartTime: caller.startTime
            )
            nativeEditAuthorizations[request.editSessionID] = nil
            return .failed(
                .editSessionExpired,
                message: "the native-store edit session expired",
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

    public func commitNativeStoreBlobs(
        request: CommitNativeStoreBlobsRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.editSessionID) != nil,
              !request.blobs.isEmpty,
              request.blobs.count <= Self.maximumImportBlobs,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              let nativeStore,
              let authorization = nativeEditAuthorizations[request.editSessionID],
              authorization.callerPID == caller.pid,
              authorization.callerStartTime == caller.startTime,
              request.sshKeyRegistrations.isEmpty || (
                authorization.mode == .sshKeyImport && sshSigningService != nil
              ) else {
            return .failed(
                .invalidRequest,
                message: "the native-store blob import request is invalid",
                requestID: request.requestID
            )
        }
        var totalBytes = 0
        var keys = Set<String>()
        for blob in request.blobs {
            totalBytes += blob.data.count
            guard keys.insert(blob.key).inserted else {
                return .failed(
                    .invalidRequest,
                    message: "the blob import batch contains a duplicate key",
                    requestID: request.requestID
                )
            }
        }
        guard totalBytes <= Self.maximumImportTotalBytes else {
            return .failed(
                .invalidRequest,
                message: "the blob import batch exceeds the per-request size limit",
                requestID: request.requestID
            )
        }
        if !request.sshKeyRegistrations.isEmpty {
            let expected = Set(request.blobs.compactMap {
                try? NativeSecretReference(store: authorization.store, key: $0.key).uri
            })
            let requested = Set(request.sshKeyRegistrations.map(\.reference))
            guard expected.count == request.blobs.count,
                  requested.count == request.sshKeyRegistrations.count,
                  requested == expected else {
                return .failed(
                    .invalidRequest,
                    message: "SSH registrations must exactly match the imported canonical references",
                    requestID: request.requestID
                )
            }
        }
        guard Date() < authorization.expiresAt else {
            await nativeStore.cancelEdit(
                sessionID: request.editSessionID,
                callerPID: caller.pid,
                callerStartTime: caller.startTime
            )
            nativeEditAuthorizations[request.editSessionID] = nil
            return .failed(
                .editSessionExpired,
                message: "the native-store edit session expired",
                requestID: request.requestID
            )
        }
        do {
            let requests = request.blobs.map {
                NativeBlobStore.PutRequest(key: $0.key, data: $0.data, mode: $0.mode, path: $0.path)
            }
            let result = try await nativeStore.commitBlobs(
                sessionID: request.editSessionID,
                requests: requests,
                callerPID: caller.pid,
                callerStartTime: caller.startTime
            )
            nativeEditAuthorizations[request.editSessionID] = nil
            var sshKeys: [SSHKeyMetadata]?
            if !request.sshKeyRegistrations.isEmpty {
                guard let sshSigningService else {
                    return .failed(
                        .sshAgentUnavailable,
                        message: "the SSH signing service is unavailable",
                        requestID: request.requestID
                    )
                }
                do {
                    sshKeys = try await sshSigningService.registerAlreadyAuthorized(
                        request.sshKeyRegistrations,
                        caller: caller
                    )
                } catch {
                    // The encrypted import is already durable. Returning failure
                    // keeps csec from writing sidecars or unlinking plaintext.
                    return sshFailure(error, requestID: request.requestID)
                }
            }
            return Response(
                requestID: request.requestID,
                generation: result.generation,
                secretCount: result.secretCount,
                sshKeys: sshKeys
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

    /// Advertise the URI schemes the agent can resolve. A capability query — no
    /// consent, no grant, no secret material — so a client can detect which
    /// environment values are secret references.
    public func schemes() async -> Response {
        Response(
            schemes: await resolver.registeredSchemes(),
            providerStatus: await resolver.providerStatuses()
        )
    }

    public func capabilities() -> Response {
        let features = WireCapability.allCases.filter {
            switch $0 {
            case .nativeEncryptedStore, .nativeEditorPolicy:
                return nativeStore != nil
            case .unattendedAutomation:
                return automationService != nil
            default:
                return true
            }
        }
        return Response(capabilities: ProtocolCapabilities(features: features))
    }

    public func configureSSH(
        request: SSHKeyCatalogRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              isVerifiedLauncher(caller),
              let sshSigningService else {
            return .failed(
                .sshAgentUnavailable,
                message: "the SSH signing service is unavailable",
                requestID: request.requestID
            )
        }
        do {
            switch request.action {
            case .list:
                guard request.registrations.isEmpty, request.fingerprint == nil else {
                    throw SSHProtectionError.malformedMessage
                }
                return Response(
                    requestID: request.requestID,
                    sshKeys: try await sshSigningService.listedSSHKeys()
                )
            case .register:
                guard request.fingerprint == nil else {
                    throw SSHProtectionError.malformedMessage
                }
                return Response(
                    requestID: request.requestID,
                    sshKeys: try await sshSigningService.register(
                        request.registrations,
                        caller: caller
                    )
                )
            case .remove:
                guard request.registrations.isEmpty,
                      let fingerprint = request.fingerprint else {
                    throw SSHProtectionError.malformedMessage
                }
                guard try await sshSigningService.remove(
                    fingerprint: fingerprint,
                    caller: caller
                ) else { throw SSHProtectionError.keyNotRegistered }
                return Response(
                    requestID: request.requestID,
                    sshKeys: try await sshSigningService.listedSSHKeys()
                )
            }
        } catch {
            return sshFailure(error, requestID: request.requestID)
        }
    }

    public func configureAutomation(
        request: AutomationRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID)?.uuidString.lowercased()
                == request.requestID else {
            return .failed(
                .invalidRequest,
                message: "the automation request is invalid",
                requestID: request.requestID
            )
        }
        guard allowUnverifiedAutomationCallersForTesting || isVerifiedLauncher(caller) else {
            return .failed(
                .unverifiedPeer,
                message: "unattended automation requires the verified csec launcher",
                requestID: request.requestID
            )
        }
        guard let automationService else {
            return .failed(
                .automationUnavailable,
                message: "unattended automation is unavailable",
                requestID: request.requestID
            )
        }

        do {
            switch request.action {
            case .enroll:
                guard let enrollment = request.enrollment,
                      request.name == nil,
                      request.runID == nil else {
                    throw AutomationServiceError.invalidRequest
                }
                let job = try await automationService.enroll(enrollment, caller: caller)
                return Response(requestID: request.requestID, automationJobs: [job])
            case .list:
                guard request.enrollment == nil,
                      request.name == nil,
                      request.runID == nil else {
                    throw AutomationServiceError.invalidRequest
                }
                return Response(
                    requestID: request.requestID,
                    automationJobs: try await automationService.list()
                )
            case .beginRun:
                guard request.enrollment == nil,
                      let name = request.name,
                      request.runID == nil else {
                    throw AutomationServiceError.invalidRequest
                }
                switch try await automationService.beginRun(name: name, caller: caller) {
                case let .started(run):
                    return Response(requestID: request.requestID, automationRun: run)
                case let .skipped(nextEligibleAt):
                    return Response(
                        requestID: request.requestID,
                        automationNextEligibleAt: nextEligibleAt
                    )
                }
            case .finishRun:
                guard request.enrollment == nil,
                      request.name == nil,
                      let runID = request.runID,
                      await automationService.finishRun(runID: runID, caller: caller) else {
                    throw AutomationServiceError.invalidRequest
                }
                return Response(requestID: request.requestID)
            case .revoke:
                guard request.enrollment == nil,
                      let name = request.name,
                      request.runID == nil else {
                    throw AutomationServiceError.invalidRequest
                }
                let job = try await automationService.revoke(name: name, caller: caller)
                return Response(requestID: request.requestID, automationJobs: [job])
            }
        } catch let error as AutomationServiceError {
            return automationFailure(error, requestID: request.requestID)
        } catch {
            return automationFailure(.unavailable, requestID: request.requestID)
        }
    }

    private func automationFailure(
        _ error: AutomationServiceError,
        requestID: String?
    ) -> Response {
        let code: WireErrorCode
        switch error {
        case .invalidRequest, .notFound:
            code = .invalidRequest
        case .consentDenied:
            code = .consentDenied
        case .resolutionFailed:
            code = .resolutionFailed
        case .alreadyRunning:
            code = .automationAlreadyRunning
        case .unavailable, .materializationUnavailable:
            code = .automationUnavailable
        case .executableChanged:
            code = .policyDenied
        }
        return .failed(
            code,
            message: error.localizedDescription,
            requestID: requestID
        )
    }

    private func sshFailure(_ error: Error, requestID: String) -> Response {
        guard let error = error as? SSHProtectionError else {
            return .failed(
                .internalError,
                message: "the SSH signing operation failed",
                requestID: requestID
            )
        }
        switch error {
        case .authorizationDenied:
            return .failed(.consentDenied, message: error.localizedDescription, requestID: requestID)
        case .providerResolutionFailed:
            return .failed(.resolutionFailed, message: error.localizedDescription, requestID: requestID)
        case .catalogUnavailable:
            return .failed(.sshAgentUnavailable, message: error.localizedDescription, requestID: requestID)
        default:
            return .failed(.invalidSSHKey, message: error.localizedDescription, requestID: requestID)
        }
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

    /// Persist the user's value-free triage decisions (exemptions/TODOs/cleared)
    /// into the accepted baseline. Verified-launcher gated like remediation; the
    /// store is csecd-owned so there is a single writer. Returns a plain success.
    public func recordHostTriage(
        request: HostTriageRequest,
        caller: CallerInfo
    ) async -> Response {
        guard isVerifiedLauncher(caller) else {
            return .failed(
                .consentDenied,
                message: "host triage requires the verified csec launcher",
                requestID: request.requestID
            )
        }
        HostAuditService.recordTriage(
            request, recordedAtHint: ISO8601DateFormatter().string(from: Date()))
        return Response(requestID: request.requestID)
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

    /// Inspect or drop live grants.
    ///
    /// Neither action releases a value: listing returns the same value-free
    /// metadata the review window already showed, and revocation only removes
    /// access, so it fails safe and needs no Touch ID of its own. Both still
    /// require an authenticated signed launcher.
    public func handleGrants(
        request: GrantsRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil, isVerifiedLauncher(caller) else {
            return .failed(
                .unverifiedPeer,
                message: "a verified launcher is required to inspect or revoke grants",
                requestID: request.requestID
            )
        }
        let now = Date()
        switch request.action {
        case .list:
            return Response(
                requestID: request.requestID,
                grants: await grants.summaries(now: now)
            )
        case .revoke:
            if request.all {
                await grants.sweep(now: now)
                return Response(
                    requestID: request.requestID,
                    revokedGrantCount: await grants.revokeAll()
                )
            }
            guard let grantID = request.grantID,
                  !grantID.isEmpty,
                  grantID.utf8.count <= 64,
                  grantID.allSatisfy({ $0.isHexDigit || $0 == "-" }) else {
                return .failed(
                    .invalidRequest,
                    message: "a grant id (or --all) is required",
                    requestID: request.requestID
                )
            }
            await grants.sweep(now: now)
            return Response(
                requestID: request.requestID,
                revokedGrantCount: await grants.revoke(idPrefix: grantID)
            )
        }
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
        case .crossTierKeyConflict:
            return .failed(
                .invalidStoreDocument,
                message: "a key cannot exist in both the editable-document and file tiers of one store",
                requestID: requestID
            )
        case .authenticationRequired, .keyUnavailable, .storeNotFound,
             .secretNotFound, .integrityFailure, .filesystemFailure,
             .randomGenerationFailed, .blobTierUnavailable:
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
        case .builtInMemory, .onboardingImport, .sshKeyImport:
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
