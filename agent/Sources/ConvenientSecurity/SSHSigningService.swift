import Foundation

public protocol SSHAgentKeyProvider: Sendable {
    func listedSSHKeys() async throws -> [SSHKeyMetadata]
    func signSSHAuthentication(
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        binding: SSHDestinationBinding,
        caller: CallerInfo
    ) async throws -> Data
}

/// Provider-neutral SSH consumer. Catalog entries retain only SecretRef URIs and
/// public metadata. Private key bytes enter this actor only after a complete,
/// destination-bound request is authorized, and leave only as an SSH signature.
public actor SSHSigningService: SSHAgentKeyProvider {
    private struct Grant: Sendable {
        let fingerprint: String
        let hostKeyFingerprint: String
        let remoteUser: String
        let rootPID: pid_t
        let rootStartTime: UInt64
        let auditSessionID: UInt32?
        let clientCDHash: String?
        let expiresAt: Date

        func covers(
            key: SSHKeyMetadata,
            binding: SSHDestinationBinding,
            authentication: SSHBoundUserAuthentication,
            caller: CallerInfo,
            now: Date
        ) -> Bool {
            guard now < expiresAt,
                  key.fingerprint == fingerprint,
                  binding.hostKeyFingerprint == hostKeyFingerprint,
                  authentication.remoteUser == remoteUser,
                  caller.peerIdentity?.audit.auditSessionID == auditSessionID,
                  caller.peerIdentity?.code.cdHash == clientCDHash,
                  ProcessAncestry.startTime(of: rootPID) == rootStartTime else { return false }
            return ProcessAncestry.descends(
                caller.pid, from: rootPID, rootStartTime: rootStartTime
            )
        }
    }

    private struct Root: Sendable {
        let pid: pid_t
        let startTime: UInt64
    }

    public static let grantTTLSeconds = ReleasePolicy.defaultTTLSeconds
    private static let maximumGrants = 256

    private let resolver: SecretResolver
    private let catalog: SSHKeyCatalog
    private let consent: any ConsentProvider
    private let policyReview: any PolicyReviewProvider
    private let allowUnverifiedCallersForTesting: Bool
    private var grants: [Grant] = []

    public init(
        resolver: SecretResolver,
        catalog: SSHKeyCatalog,
        consent: any ConsentProvider,
        policyReview: any PolicyReviewProvider,
        allowUnverifiedCallersForTesting: Bool = false
    ) {
        self.resolver = resolver
        self.catalog = catalog
        self.consent = consent
        self.policyReview = policyReview
        self.allowUnverifiedCallersForTesting = allowUnverifiedCallersForTesting
    }

    public func listedSSHKeys() async throws -> [SSHKeyMetadata] {
        try await catalog.list()
    }

    public func register(
        _ registrations: [SSHKeyRegistrationIntent],
        caller: CallerInfo
    ) async throws -> [SSHKeyMetadata] {
        guard verifiedLauncher(caller),
              let references = Self.validatedRegistrations(registrations) else {
            throw SSHProtectionError.authorizationDenied
        }

        let executablePath = caller.peerIdentity?.code.executablePath
            ?? ProcessAncestry.executablePath(of: caller.pid)
            ?? "/usr/local/bin/csec"
        let plan = DeliveryPlan(
            mechanism: .credentialProtocol,
            executable: PlannedExecutable(
                canonicalPath: executablePath,
                signingIdentifier: caller.peerIdentity?.code.identifier,
                teamIdentifier: caller.peerIdentity?.code.teamIdentifier,
                cdHash: caller.peerIdentity?.code.cdHash,
                assurance: caller.peerIdentity?.code.role == .launcher
                    ? .verifiedProduct : .unverified
            ),
            root: .caller,
            descendantScope: .exactProcess,
            destination: .credentialConsumer,
            requestedTTLSeconds: 5 * 60,
            operationContext: "register public metadata for protected SSH keys"
        )
        let review = AccessPolicyReview(
            caller: caller,
            reason: plan.operationContext,
            plan: plan,
            credentials: references.map { PolicyReviewCredential(references: [$0]) }
        )
        guard case let .approved(approval) = await policyReview.reviewAccess(review) else {
            throw SSHProtectionError.authorizationDenied
        }
        let authentication = await completeReview(
            approval,
            caller: caller,
            references: references,
            reason: plan.operationContext,
            ttl: TimeInterval(plan.requestedTTLSeconds),
            summary: "register SSH signer metadata; no private key leaves csecd"
        )
        guard case let .approved(unlock) = authentication,
              verifiedLauncher(caller) else {
            throw SSHProtectionError.authorizationDenied
        }
        return try await resolveAndRegister(
            registrations, references: references, unlock: unlock
        )
    }

    /// Used by `csec protect --ssh` after a native blob import that was already
    /// shown and authenticated as an SSH-key import. The caller supplies canonical
    /// references only; this path does not know or retain native blob identifiers.
    public func registerAlreadyAuthorized(
        _ registrations: [SSHKeyRegistrationIntent],
        caller: CallerInfo,
        unlock: CacheUnlock? = nil
    ) async throws -> [SSHKeyMetadata] {
        guard verifiedLauncher(caller),
              let references = Self.validatedRegistrations(registrations) else {
            throw SSHProtectionError.authorizationDenied
        }
        return try await resolveAndRegister(
            registrations, references: references, unlock: unlock
        )
    }

    public func remove(fingerprint: String, caller: CallerInfo) async throws -> Bool {
        guard verifiedLauncher(caller), Self.validFingerprint(fingerprint) else {
            throw SSHProtectionError.authorizationDenied
        }
        let outcome = await consent.authenticate(
            reason: "Remove protected SSH key \(ReviewDisplay.sanitized(fingerprint))"
        )
        guard outcome.isApproved, verifiedLauncher(caller) else {
            throw SSHProtectionError.authorizationDenied
        }
        let removed = try await catalog.remove(fingerprint: fingerprint)
        if removed { grants.removeAll { $0.fingerprint == fingerprint } }
        return removed
    }

    public func signSSHAuthentication(
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        binding: SSHDestinationBinding,
        caller: CallerInfo
    ) async throws -> Data {
        guard verifiedSSHClient(caller),
              let key = try await catalog.key(publicKeyBlob: publicKeyBlob) else {
            throw SSHProtectionError.keyNotRegistered
        }
        let authentication = try SSHBoundUserAuthentication.parse(
            signedData: signedData,
            binding: binding,
            requestedKeyBlob: publicKeyBlob,
            flags: flags
        )
        let root = try grantRoot(for: caller.pid)
        let now = Date()
        pruneGrants(now: now)

        var unlock: CacheUnlock?
        var shouldMintGrant = false
        if !grants.contains(where: {
            $0.covers(
                key: key,
                binding: binding,
                authentication: authentication,
                caller: caller,
                now: now
            )
        }) {
            let displayUser = ReviewDisplay.sanitized(authentication.remoteUser)
            let operation = "SSH authentication with key \(key.fingerprint) as "
                + "\(displayUser) to host key \(binding.hostKeyFingerprint)"
            let reviewedCaller = CallerInfo(
                pid: caller.pid,
                startTime: caller.startTime,
                description: Self.callerDescription(caller: caller, root: root),
                peerIdentity: caller.peerIdentity
            )
            let plan = DeliveryPlan(
                mechanism: .credentialProtocol,
                executable: PlannedExecutable(
                    canonicalPath: "/usr/bin/ssh",
                    signingIdentifier: "com.apple.ssh",
                    cdHash: caller.peerIdentity?.code.cdHash,
                    assurance: .independentlyProtected
                ),
                root: .caller,
                descendantScope: .subtree,
                destination: .credentialConsumer,
                requestedTTLSeconds: Self.grantTTLSeconds,
                operationContext: operation
            )
            let review = AccessPolicyReview(
                caller: reviewedCaller,
                reason: operation,
                plan: plan,
                credentials: [PolicyReviewCredential(references: [try SecretRef(key.reference)])]
            )
            guard case let .approved(approval) = await policyReview.reviewAccess(review) else {
                throw SSHProtectionError.authorizationDenied
            }
            let outcome = await completeReview(
                approval,
                caller: reviewedCaller,
                references: [try SecretRef(key.reference)],
                reason: operation,
                ttl: TimeInterval(Self.grantTTLSeconds),
                summary: "SSH signature only; key \(key.fingerprint); host key "
                    + "\(binding.hostKeyFingerprint); remote user \(displayUser); process subtree"
            )
            guard case let .approved(approvedUnlock) = outcome,
                  verifiedSSHClient(caller),
                  ProcessAncestry.startTime(of: root.pid) == root.startTime,
                  ProcessAncestry.descends(
                    caller.pid, from: root.pid, rootStartTime: root.startTime
                  ) else {
                throw SSHProtectionError.authorizationDenied
            }
            unlock = approvedUnlock
            shouldMintGrant = true
        }

        let reference = try SecretRef(key.reference)
        let bytes: Data
        do {
            bytes = try await resolver.resolve(reference, unlock: unlock)
        } catch {
            throw SSHProtectionError.providerResolutionFailed
        }
        let privateKey = try SSHPrivateKey.parse(bytes)
        guard privateKey.publicKeyBlob == publicKeyBlob else {
            throw SSHProtectionError.invalidPrivateKey
        }
        let signature = try privateKey.sign(signedData, flags: flags)
        guard verifiedSSHClient(caller),
              ProcessAncestry.startTime(of: root.pid) == root.startTime,
              ProcessAncestry.descends(
                caller.pid, from: root.pid, rootStartTime: root.startTime
              ) else {
            throw SSHProtectionError.authorizationDenied
        }

        if shouldMintGrant {
            grants.append(Grant(
                fingerprint: key.fingerprint,
                hostKeyFingerprint: binding.hostKeyFingerprint,
                remoteUser: authentication.remoteUser,
                rootPID: root.pid,
                rootStartTime: root.startTime,
                auditSessionID: caller.peerIdentity?.audit.auditSessionID,
                clientCDHash: caller.peerIdentity?.code.cdHash,
                expiresAt: now.addingTimeInterval(TimeInterval(Self.grantTTLSeconds))
            ))
            if grants.count > Self.maximumGrants {
                grants.removeFirst(grants.count - Self.maximumGrants)
            }
        }
        return signature
    }

    private func resolveAndRegister(
        _ registrations: [SSHKeyRegistrationIntent],
        references: [SecretRef],
        unlock: CacheUnlock?
    ) async throws -> [SSHKeyMetadata] {
        var metadata: [SSHKeyMetadata] = []
        metadata.reserveCapacity(registrations.count)
        for (registration, reference) in zip(registrations, references) {
            let bytes: Data
            do {
                bytes = try await resolver.resolve(reference, unlock: unlock)
            } catch {
                throw SSHProtectionError.providerResolutionFailed
            }
            let key = try SSHPrivateKey.parse(bytes)
            let publicKey = try SSHPublicKey.parse(key.publicKeyBlob)
            let label = Self.safeLabel(registration.label)
            metadata.append(SSHKeyMetadata(
                reference: reference.uri,
                fingerprint: publicKey.fingerprint,
                algorithm: publicKey.algorithm,
                publicKeyBlob: publicKey.blob,
                label: label
            ))
        }
        return try await catalog.register(metadata)
    }

    private func completeReview(
        _ approval: AccessPolicyApproval,
        caller: CallerInfo,
        references: [SecretRef],
        reason: String,
        ttl: TimeInterval,
        summary: String
    ) async -> ConsentOutcome {
        if let session = approval.authenticationSession {
            return await session.completeAfterPolicyApproval(
                policySummary: summary + "; duration \(BiometricConsent.formatDuration(ttl))"
            )
        }
        return await consent.requestConsent(
            caller: caller,
            newReferences: references,
            reason: reason,
            ttl: ttl,
            policySummary: summary
        )
    }

    private func verifiedLauncher(_ caller: CallerInfo) -> Bool {
        if allowUnverifiedCallersForTesting { return true }
        guard caller.startTime > 0,
              ProcessAncestry.startTime(of: caller.pid) == caller.startTime else { return false }
        return caller.peerIdentity?.code.signatureValid == true
            && caller.peerIdentity?.code.role == .launcher
    }

    private func verifiedSSHClient(_ caller: CallerInfo) -> Bool {
        if allowUnverifiedCallersForTesting { return true }
        guard caller.startTime > 0,
              ProcessAncestry.startTime(of: caller.pid) == caller.startTime,
              let peer = caller.peerIdentity else { return false }
        return SSHClientCodeIdentity.accepts(peer)
    }

    private func grantRoot(for sshPID: pid_t) throws -> Root {
        if allowUnverifiedCallersForTesting {
            let start = ProcessAncestry.startTime(of: sshPID) ?? 1
            return Root(pid: sshPID, startTime: start)
        }
        guard var candidate = ProcessAncestry.parent(of: sshPID), candidate > 1 else {
            throw SSHProtectionError.authorizationDenied
        }
        // Git and file-transfer wrappers are short-lived. Rooting one level above
        // them lets a shell/IDE reuse the exact host+user grant without widening a
        // direct `ssh` invocation beyond its immediate parent.
        var hops = 0
        while hops < 4, Self.isTransientSSHParent(candidate),
              let parent = ProcessAncestry.parent(of: candidate), parent > 1 {
            candidate = parent
            hops += 1
        }
        guard let startTime = ProcessAncestry.startTime(of: candidate) else {
            throw SSHProtectionError.authorizationDenied
        }
        return Root(pid: candidate, startTime: startTime)
    }

    private func pruneGrants(now: Date) {
        grants.removeAll {
            now >= $0.expiresAt
                || ProcessAncestry.startTime(of: $0.rootPID) != $0.rootStartTime
        }
    }

    private static func validatedRegistrations(
        _ registrations: [SSHKeyRegistrationIntent]
    ) -> [SecretRef]? {
        guard !registrations.isEmpty,
              registrations.count <= SSHKeyCatalog.maximumKeys else { return nil }
        var references: [SecretRef] = []
        var seen = Set<String>()
        for registration in registrations {
            guard registration.reference.utf8.count <= 4_096,
                  let reference = try? SecretRef(registration.reference),
                  reference.uri == registration.reference,
                  seen.insert(reference.uri).inserted,
                  registration.label?.utf8.count ?? 0 <= 256,
                  !(registration.label?.utf8.contains(0) ?? false) else { return nil }
            references.append(reference)
        }
        return references
    }

    private static func safeLabel(_ value: String?) -> String {
        let sanitized = ReviewDisplay.sanitized(value ?? "csec protected key")
        return String(sanitized.prefix(256))
    }

    private static func validFingerprint(_ value: String) -> Bool {
        value.hasPrefix("SHA256:")
            && value.utf8.count <= 128
            && !value.utf8.contains(0)
    }

    private static func isTransientSSHParent(_ pid: pid_t) -> Bool {
        let name = (ProcessAncestry.name(of: pid) ?? "").lowercased()
        return name == "git" || name.hasPrefix("git-")
            || name == "scp" || name == "sftp" || name == "rsync"
    }

    private static func callerDescription(caller: CallerInfo, root: Root) -> String {
        let rootName = ReviewDisplay.sanitized(
            ProcessAncestry.name(of: root.pid) ?? "requesting process"
        )
        return "Apple SSH [verified] (pid \(caller.pid)); grant root \(rootName) (pid \(root.pid))"
    }
}
