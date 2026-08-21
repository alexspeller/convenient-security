import Foundation

/// The policy core: matches callers against subtree grants, gates newly-seen
/// references through consent, then resolves the approved references.
public actor Agent {
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
        var lastUsedAt: Date
    }

    private static let maximumOutputChunkBytes = 64 * 1024
    private static let maximumRedactionSessions = 32
    private static let redactionSessionIdleSeconds: TimeInterval = 5 * 60

    private let resolver: SecretResolver
    private let grants: GrantTable
    private let consent: ConsentProvider
    private let nativeStore: NativeEncryptedFileProvider?
    private let allowLegacyAccessForTesting: Bool
    private let allowUnverifiedPlansForTesting: Bool
    private var activeSecrets = ActiveSecretRegistry()
    private var redactionSessions: [String: RedactionSession] = [:]

    public init(
        resolver: SecretResolver,
        grants: GrantTable,
        consent: ConsentProvider,
        nativeStore: NativeEncryptedFileProvider? = nil,
        allowLegacyAccessForTesting: Bool = false,
        allowUnverifiedPlansForTesting: Bool = false
    ) {
        self.resolver = resolver
        self.grants = grants
        self.consent = consent
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
            guard let verifiedRoot = Self.verifyRoot(deliveryPlan.root, caller: caller) else {
                return .failed(
                    .invalidRequest,
                    message: "the requested grant root does not match process ancestry",
                    requestID: requestID
                )
            }
            if case let .directParent(pid, _) = deliveryPlan.root {
                let claimedPath = URL(fileURLWithPath: deliveryPlan.executable.canonicalPath)
                    .standardizedFileURL.resolvingSymlinksInPath().path
                guard ProcessAncestry.executablePath(of: pid) == claimedPath else {
                    return .failed(
                        .invalidRequest,
                        message: "the planned executable does not match the verified parent",
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
        let accessible = await grants.accessibleReferences(
            for: caller.pid,
            now: now,
            deliveryPlanDigest: planDigest
        )
        let newReferences = refs.filter { !accessible.contains($0.uri) }

        // New references require fresh consent; already-granted ones don't. The
        // consent touch also yields the unlock for a cold cache value or native
        // store key after an agent restart.
        var unlock: CacheUnlock?
        if !newReferences.isEmpty {
            var displayedCaller = caller
            if let plan {
                let executableName = URL(fileURLWithPath: plan.executable.canonicalPath).lastPathComponent
                displayedCaller.description = "\(caller.description) for \(executableName) "
                    + "[\(plan.executable.assurance.rawValue)] (grant root pid \(rootPID))"
            }
            let outcome = await consent.requestConsent(
                caller: displayedCaller,
                newReferences: newReferences,
                reason: request.reason,
                ttl: TimeInterval(request.ttlSeconds)
            )
            guard case let .approved(approvedUnlock) = outcome else {
                return .failed(
                    .consentDenied,
                    message: "consent denied",
                    requestID: requestID
                )
            }
            unlock = approvedUnlock
            let grant = Grant(
                rootPID: rootPID,
                rootStartTime: rootStartTime,
                references: Set(newReferences.map(\.uri)),
                reason: request.reason,
                expiresAt: now.addingTimeInterval(TimeInterval(request.ttlSeconds)),
                requestID: requestID,
                deliveryPlanDigest: planDigest,
                peerPIDVersion: caller.peerIdentity?.audit.pidVersion,
                peerCDHash: caller.peerIdentity?.code.cdHash,
                plannedExecutable: plan?.executable
            )
            await grants.add(grant)
        }

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
        // Keep only values that were genuinely released. This is an in-memory
        // egress dictionary for the current agent lifetime, never a reason to
        // unlock dormant cache/provider entries. The delivery TTL is the first
        // conservative lease; longer-lived consumers must renew it.
        if plan != nil {
            activeSecrets.register(
                values: Array(values.values),
                expiresAt: now.addingTimeInterval(TimeInterval(request.ttlSeconds))
            )
        }
        return Response(requestID: requestID, values: values)
    }

    public func beginOutputRedaction(
        request: BeginOutputRedactionRequest,
        caller: CallerInfo
    ) -> Response {
        let now = Date()
        pruneRedactionSessions(now: now)
        guard UUID(uuidString: request.requestID) != nil,
              request.destination == .aiTool,
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
        let catalog = OutputRedactionCatalog(valuesByReference: snapshot.valuesByOpaqueID)
        let sessionID = UUID().uuidString.lowercased()
        redactionSessions[sessionID] = RedactionSession(
            caller: RedactionCaller(pid: caller.pid, startTime: caller.startTime),
            destination: request.destination,
            redactors: Dictionary(uniqueKeysWithValues: request.streams.map {
                ($0, StreamingOutputRedactor(patterns: catalog.patterns))
            }),
            finishedStreams: [],
            registryGeneration: snapshot.generation,
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
              session.destination == .aiTool,
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
            let catalog = OutputRedactionCatalog(valuesByReference: snapshot.valuesByOpaqueID)
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
              let nativeStore else {
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

        let consentReference = NativeSecretReference.editConsentReference(for: store)
        let outcome = await consent.requestConsent(
            caller: caller,
            newReferences: [consentReference],
            reason: "edit native encrypted store",
            ttl: 30 * 60
        )
        guard case let .approved(unlock) = outcome else {
            return .failed(
                .consentDenied,
                message: "consent denied",
                requestID: request.requestID
            )
        }

        do {
            let edit = try await nativeStore.beginEdit(
                store: store,
                callerPID: caller.pid,
                callerStartTime: caller.startTime,
                unlock: unlock
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
              let nativeStore else {
            return .failed(
                .invalidRequest,
                message: "the native-store edit request is invalid",
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
        return Response(requestID: request.requestID)
    }

    /// Advertise the URI schemes the agent can resolve. A capability query — no
    /// consent, no grant, no secret material — so a client can detect which
    /// environment values are secret references.
    public func schemes() async -> Response {
        Response(schemes: await resolver.registeredSchemes())
    }

    public func capabilities() -> Response {
        let features = WireCapability.allCases.filter {
            $0 != .nativeEncryptedStore || nativeStore != nil
        }
        return Response(capabilities: ProtocolCapabilities(features: features))
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

    private static func verifyRoot(
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
        }
    }

    private static func hasValidMetadata(_ plan: DeliveryPlan) -> Bool {
        let executable = plan.executable
        return executable.canonicalPath.hasPrefix("/")
            && executable.canonicalPath.utf8.count <= 4_096
            && !executable.canonicalPath.utf8.contains(0)
            && !plan.operationContext.isEmpty
            && plan.operationContext.utf8.count <= 512
            && !plan.operationContext.utf8.contains(0)
            && (plan.commandDigest.map(isSHA256Digest) ?? true)
            && hasValidOutputGuard(plan)
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
