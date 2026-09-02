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

/// Value-free process metadata used to bind SSH grants to live process trees.
/// Production always uses the kernel-backed `live` implementation. The
/// injectable form keeps session-root selection deterministic in synthetic
/// tests without weakening the release caller checks.
public struct SSHProcessInspection: Sendable {
    private let startTimeLookup: @Sendable (pid_t) -> UInt64?
    private let parentLookup: @Sendable (pid_t) -> pid_t?
    private let nameLookup: @Sendable (pid_t) -> String?
    private let executablePathLookup: @Sendable (pid_t) -> String?

    public init(
        startTime: @escaping @Sendable (pid_t) -> UInt64?,
        parent: @escaping @Sendable (pid_t) -> pid_t?,
        name: @escaping @Sendable (pid_t) -> String?,
        executablePath: @escaping @Sendable (pid_t) -> String?
    ) {
        startTimeLookup = startTime
        parentLookup = parent
        nameLookup = name
        executablePathLookup = executablePath
    }

    public static let live = SSHProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) },
        parent: { ProcessAncestry.parent(of: $0) },
        name: { ProcessAncestry.name(of: $0) },
        executablePath: { ProcessAncestry.executablePath(of: $0) }
    )

    fileprivate func startTime(of pid: pid_t) -> UInt64? {
        startTimeLookup(pid)
    }

    fileprivate func parent(of pid: pid_t) -> pid_t? {
        parentLookup(pid)
    }

    fileprivate func name(of pid: pid_t) -> String? {
        nameLookup(pid)
    }

    fileprivate func executablePath(of pid: pid_t) -> String? {
        executablePathLookup(pid)
    }

    fileprivate func descends(
        _ pid: pid_t,
        from root: pid_t,
        rootStartTime: UInt64
    ) -> Bool {
        guard startTime(of: root) == rootStartTime else { return false }

        var current = pid
        var hops = 0
        while hops < 128 {
            if current == root { return true }
            if current <= 1 { return false }
            guard let next = parent(of: current), next != current else { return false }
            current = next
            hops += 1
        }
        return false
    }
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
            now: Date,
            processInspection: SSHProcessInspection
        ) -> Bool {
            guard now < expiresAt,
                  key.fingerprint == fingerprint,
                  binding.hostKeyFingerprint == hostKeyFingerprint,
                  authentication.remoteUser == remoteUser,
                  caller.peerIdentity?.audit.auditSessionID == auditSessionID,
                  caller.peerIdentity?.code.cdHash == clientCDHash,
                  processInspection.startTime(of: rootPID) == rootStartTime else { return false }
            return processInspection.descends(
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
    private static let maximumCodingAgentAncestorHops = 32

    private let resolver: SecretResolver
    private let catalog: SSHKeyCatalog
    private let consent: any ConsentProvider
    private let policyReview: any PolicyReviewProvider
    private let allowUnverifiedCallersForTesting: Bool
    private let processInspection: SSHProcessInspection
    private var grants: [Grant] = []

    public init(
        resolver: SecretResolver,
        catalog: SSHKeyCatalog,
        consent: any ConsentProvider,
        policyReview: any PolicyReviewProvider,
        allowUnverifiedCallersForTesting: Bool = false,
        processInspection: SSHProcessInspection = .live
    ) {
        self.resolver = resolver
        self.catalog = catalog
        self.consent = consent
        self.policyReview = policyReview
        self.allowUnverifiedCallersForTesting = allowUnverifiedCallersForTesting
        self.processInspection = processInspection
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
            credentials: await resolver.reviewCredentials(for: references.map { [$0] })
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
                now: now,
                processInspection: processInspection
            )
        }) {
            let displayUser = ReviewDisplay.sanitized(authentication.remoteUser)
            let operation = "SSH authentication with key \(key.fingerprint) as "
                + "\(displayUser) to host key \(binding.hostKeyFingerprint)"
            let reviewedCaller = CallerInfo(
                pid: caller.pid,
                startTime: caller.startTime,
                description: callerDescription(caller: caller, root: root),
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
                  processInspection.startTime(of: root.pid) == root.startTime,
                  processInspection.descends(
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
              processInspection.startTime(of: root.pid) == root.startTime,
              processInspection.descends(
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
              processInspection.startTime(of: caller.pid) == caller.startTime else { return false }
        return caller.peerIdentity?.code.signatureValid == true
            && caller.peerIdentity?.code.role == .launcher
    }

    private func verifiedSSHClient(_ caller: CallerInfo) -> Bool {
        if allowUnverifiedCallersForTesting { return true }
        guard caller.startTime > 0,
              processInspection.startTime(of: caller.pid) == caller.startTime,
              let peer = caller.peerIdentity else { return false }
        return SSHClientCodeIdentity.accepts(peer)
    }

    private func grantRoot(for sshPID: pid_t) throws -> Root {
        guard let immediateParent = processInspection.parent(of: sshPID),
              immediateParent > 1 else {
            throw SSHProtectionError.authorizationDenied
        }

        // Claude Code and Codex create a fresh non-interactive shell (and often
        // another project wrapper) for each tool call. The nearest live coding-
        // agent ancestor is the stable security boundary the user is approving;
        // binding its exact PID/start time lets sibling tool calls reuse only the
        // same key + host-key + remote-user grant. The process name/path only
        // selects this bounded session root; it is not an authentication claim.
        // Kernel ancestry, Apple ssh identity, the audit session, and the human
        // review remain the authority checks.
        if let codingAgentRoot = codingAgentRoot(
            for: sshPID,
            startingAt: immediateParent
        ) {
            return codingAgentRoot
        }

        var candidate = immediateParent
        // Git and file-transfer wrappers are short-lived. Rooting one level above
        // them lets a shell/IDE reuse the exact host+user grant without widening a
        // direct `ssh` invocation beyond its immediate parent.
        var hops = 0
        while hops < 4, isTransientSSHParent(candidate),
              let parent = processInspection.parent(of: candidate), parent > 1 {
            candidate = parent
            hops += 1
        }
        guard let startTime = processInspection.startTime(of: candidate),
              processInspection.descends(
                sshPID, from: candidate, rootStartTime: startTime
              ) else {
            throw SSHProtectionError.authorizationDenied
        }
        return Root(pid: candidate, startTime: startTime)
    }

    private func codingAgentRoot(for sshPID: pid_t, startingAt firstPID: pid_t) -> Root? {
        var candidate = firstPID
        var visited = Set<pid_t>()

        for _ in 0..<Self.maximumCodingAgentAncestorHops {
            guard candidate > 1,
                  visited.insert(candidate).inserted,
                  let startTime = processInspection.startTime(of: candidate) else {
                return nil
            }
            let name = processInspection.name(of: candidate)
            let executablePath = processInspection.executablePath(of: candidate)
            let parent = processInspection.parent(of: candidate)
            guard processInspection.startTime(of: candidate) == startTime else {
                return nil
            }

            if Self.codingAgentClient(name: name, executablePath: executablePath) != nil,
               processInspection.descends(
                 sshPID, from: candidate, rootStartTime: startTime
               ) {
                return Root(pid: candidate, startTime: startTime)
            }

            guard let parent, parent > 1, parent != candidate else { return nil }
            candidate = parent
        }
        return nil
    }

    private static func codingAgentClient(
        name: String?,
        executablePath: String?
    ) -> AICommandHookClient? {
        if let name, let client = AICommandHookClient(rawValue: name) { return client }
        guard let executablePath, executablePath.hasPrefix("/") else { return nil }

        let basename = (executablePath as NSString).lastPathComponent
        if let client = AICommandHookClient(rawValue: basename) { return client }

        // Anthropic's native installer currently execs a version-named binary,
        // so proc_name and the basename are both the version. Match only its
        // dedicated CLI versions directory; do not collapse Claude.app or an
        // arbitrary process whose argv happens to call itself "claude".
        let marker = "/.local/share/claude/versions/"
        guard !executablePath.contains(".app/Contents/"),
              let markerRange = executablePath.range(of: marker) else { return nil }
        let version = executablePath[markerRange.upperBound...]
        return !version.isEmpty && !version.contains("/") ? .claude : nil
    }

    private func pruneGrants(now: Date) {
        grants.removeAll {
            now >= $0.expiresAt
                || processInspection.startTime(of: $0.rootPID) != $0.rootStartTime
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

    private func isTransientSSHParent(_ pid: pid_t) -> Bool {
        let name = (processInspection.name(of: pid) ?? "").lowercased()
        return name == "git" || name.hasPrefix("git-")
            || name == "scp" || name == "sftp" || name == "rsync"
    }

    private func callerDescription(caller: CallerInfo, root: Root) -> String {
        let processName = processInspection.name(of: root.pid)
        let executablePath = processInspection.executablePath(of: root.pid)
        let rootName: String
        switch Self.codingAgentClient(name: processName, executablePath: executablePath) {
        case .claude: rootName = "Claude Code"
        case .codex: rootName = "Codex"
        case nil:
            rootName = ReviewDisplay.sanitized(processName ?? "requesting process")
        }
        return "Apple SSH [verified] (pid \(caller.pid)); grant root \(rootName) (pid \(root.pid))"
    }
}
