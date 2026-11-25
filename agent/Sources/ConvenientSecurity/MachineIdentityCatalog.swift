import CSECRemoteApproval
import CryptoKit
import Foundation

// The machine identity catalog and its provider. An identity is a Secure
// Enclave key with the issuer and subject its tokens carry; a target is one
// audience that identity signs in to. `csec-identity://<identity>/<target>` is
// an ordinary secret reference: resolving it mints a fresh token, so the
// review, grants, delegation, restore, decision log, phone mirror and every
// delivery adapter treat a sign-in exactly as they treat a stored secret, and
// none of them knows the value was made rather than read.

// MARK: - Persisted catalog

/// One key of an identity. `handle` is the Secure Enclave's wrapped handle for
/// the private key: any process running as this user that held it could have
/// the enclave sign, so it lives only in this csecd-only document.
public struct StoredMachineIdentityKey: Codable, Sendable, Equatable {
    public let handle: Data
    public let jwk: MachineIdentityJWK
    public let created: Date

    public init(handle: Data, jwk: MachineIdentityJWK, created: Date) {
        self.handle = handle
        self.jwk = jwk
        self.created = created
    }
}

public struct StoredMachineIdentity: Codable, Sendable, Equatable {
    /// Bounded: the current key, plus the previous one while a rotation's new
    /// key reaches every provider.
    public static let maximumKeys = 2

    public let name: String
    public let issuer: String
    public static let maximumAcceptedKids = 16

    public let subject: String
    /// Newest first; the first key signs.
    public var keys: [StoredMachineIdentityKey]
    /// Other keys the human accepted in the published key set, such as their
    /// other Macs'. The issuer check flags any published key that is neither
    /// this identity's nor one of these.
    public var acceptedKids: [String]

    public init(
        name: String, issuer: String, subject: String, keys: [StoredMachineIdentityKey], acceptedKids: [String] = []
    ) {
        self.name = name
        self.issuer = issuer
        self.subject = subject
        self.keys = keys
        self.acceptedKids = acceptedKids
    }

    var isWellFormed: Bool {
        MachineIdentityName.isValid(name)
            && MachineIdentityIssuer.isValid(issuer)
            && MachineIdentityClaims.isPrintable(subject, maxBytes: MachineIdentityClaims.maximumSubjectBytes)
            && (1...Self.maximumKeys).contains(keys.count)
            && keys.allSatisfy { !$0.handle.isEmpty && $0.handle.count <= 4_096 && (try? $0.jwk.publicKey()) != nil }
            && Set(keys.map(\.jwk.kid)).count == keys.count
            && acceptedKids.count <= Self.maximumAcceptedKids
            && acceptedKids.allSatisfy { MachineIdentityClaims.isPrintable($0, maxBytes: 64) }
            && Set(acceptedKids).count == acceptedKids.count
    }
}

/// One audience an identity signs in to. A `token` target resolves to the
/// signed token itself, for anything that takes an OIDC token (Google Cloud,
/// Vault, Databricks and the rest). An `aws` target resolves to temporary
/// credentials for one IAM role: csecd exchanges the token with STS itself, so
/// the token never leaves csecd and a grant for one role yields only that
/// role's credentials. A `google` target similarly returns an access token
/// for the pinned provider and optional service account, for the gcloud wrapper.
public struct MachineIdentityTarget: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        case token
        case aws
        case google
    }

    /// What an IAM OIDC provider lists as its client ID by convention.
    public static let defaultAWSAudience = "sts.amazonaws.com"
    public static let defaultAWSRegion = "us-east-1"

    public let name: String
    public let identity: String
    public let kind: Kind
    public let audience: String
    /// Seconds: the token's life for a `token` target, the credentials' for
    /// an exchange target (whose assertion lives only for the exchange).
    public let lifetime: Int
    /// `aws` only: the role to assume and the region whose STS endpoint
    /// exchanges the token.
    public let roleARN: String?
    public let region: String?
    /// `google` only; nil uses the federated principal directly. Sealed with
    /// the target, so a grant cannot be redirected to another service account.
    public let googleServiceAccount: String?

    public init(
        name: String,
        identity: String,
        kind: Kind = .token,
        audience: String,
        lifetime: Int = MachineIdentityToken.defaultLifetime,
        roleARN: String? = nil,
        region: String? = nil,
        googleServiceAccount: String? = nil
    ) {
        self.name = name
        self.identity = identity
        self.kind = kind
        self.audience = audience
        self.lifetime = lifetime
        self.roleARN = roleARN
        self.region = region
        self.googleServiceAccount = googleServiceAccount
    }

    public var reference: String { "\(MachineIdentityProvider.scheme)://\(identity)/\(name)" }

    /// What is wrong with this target, or nil when it can be stored.
    public var validationError: MachineIdentityError? {
        guard MachineIdentityName.isValid(name), MachineIdentityName.isValid(identity) else { return .invalidName }
        guard MachineIdentityClaims.isPrintable(audience, maxBytes: 512) else { return .invalidAudience }
        switch kind {
        case .token:
            guard roleARN == nil, region == nil, googleServiceAccount == nil else { return .invalidRoleARN }
            guard (MachineIdentityToken.minimumLifetime...MachineIdentityToken.maximumLifetime).contains(lifetime) else {
                return .invalidLifetime
            }
        case .aws:
            guard googleServiceAccount == nil else { return .invalidGoogleTarget }
            guard let roleARN, AWSWebIdentity.isValidRoleARN(roleARN) else { return .invalidRoleARN }
            guard let region, MachineIdentityS3Issuer.isValidRegion(region) else { return .invalidRegion }
            guard (AWSWebIdentity.minimumDuration...AWSWebIdentity.maximumDuration).contains(lifetime) else {
                return .invalidDuration
            }
        case .google:
            guard roleARN == nil, region == nil,
                  (try? GoogleWorkloadIdentityProvider(audience)) != nil,
                  googleServiceAccount.map(MachineIdentityGoogleSetup.isServiceAccount) ?? true,
                  lifetime == GoogleWebIdentity.lifetime else { return .invalidGoogleTarget }
        }
        return nil
    }

    var isWellFormed: Bool { validationError == nil }
}

public enum MachineIdentityName {
    /// Lower-case letters, digits, `-`, `_` and `.`, starting with a letter or
    /// digit: a name is a path segment of a reference and a file name in
    /// guidance, so nothing in it needs quoting or escaping.
    public static func isValid(_ name: String) -> Bool {
        guard let first = name.utf8.first, name.utf8.count <= 64 else { return false }
        func allowed(_ byte: UInt8) -> Bool {
            (byte >= 0x61 && byte <= 0x7a) || (byte >= 0x30 && byte <= 0x39) || byte == 0x2d || byte == 0x5f || byte == 0x2e
        }
        return allowed(first) && first != 0x2d && first != 0x5f && first != 0x2e && name.utf8.allSatisfy(allowed)
    }
}

/// The `machine-identity`/`catalog-v1` document. csecd-only (`ProtectedItem`),
/// so a same-user process can neither read a key handle nor add a target.
public struct MachineIdentityDocument: ProtectedDocument, Equatable {
    public static let protectedItem: ProtectedItem = .machineIdentity
    public static let formatVersion = 1
    public static let maximumIdentities = 8
    public static let maximumTargets = 64

    public var identities: [StoredMachineIdentity]
    public var targets: [MachineIdentityTarget]

    public init(identities: [StoredMachineIdentity] = [], targets: [MachineIdentityTarget] = []) {
        self.identities = identities
        self.targets = targets
    }

    public var isWellFormed: Bool {
        identities.count <= Self.maximumIdentities
            && targets.count <= Self.maximumTargets
            && identities.allSatisfy(\.isWellFormed)
            && targets.allSatisfy(\.isWellFormed)
            && Set(identities.map(\.name)).count == identities.count
            && Set(targets.map { "\($0.identity)/\($0.name)" }).count == targets.count
            && targets.allSatisfy { target in identities.contains { $0.name == target.identity } }
    }
}

// MARK: - Catalog

public enum MachineIdentityCatalogError: Error, Equatable, Sendable {
    case identityExists(String)
    case identityNotFound(String)
    case targetExists(String)
    case targetNotFound(String)
    case tooMany
    case invalid(MachineIdentityError)
    case persistenceFailed(String)

    public var message: String {
        switch self {
        case let .identityExists(name): return "a machine identity named \(name) already exists"
        case let .identityNotFound(name): return "no machine identity is named \(name)"
        case let .targetExists(name): return "the identity already has a target named \(name)"
        case let .targetNotFound(name): return "no target is named \(name)"
        case .tooMany:
            return "at most \(MachineIdentityDocument.maximumIdentities) identities and \(MachineIdentityDocument.maximumTargets) targets"
        case let .invalid(error): return error.message
        case let .persistenceFailed(detail): return "the machine identity catalog could not be saved: \(detail)"
        }
    }
}

/// Makes and opens identity keys. Production uses the Secure Enclave; tests
/// and unsigned development builds inject software keys.
public struct MachineIdentityKeyFactory: Sendable {
    public let create: @Sendable () throws -> (signer: IdentitySigner, handle: Data)
    public let open: @Sendable (Data) throws -> IdentitySigner

    public init(
        create: @escaping @Sendable () throws -> (signer: IdentitySigner, handle: Data),
        open: @escaping @Sendable (Data) throws -> IdentitySigner
    ) {
        self.create = create
        self.open = open
    }

    public static let secureEnclave = MachineIdentityKeyFactory(
        create: {
            let (signer, handle) = try SecureEnclaveIdentitySigner.create()
            return (signer, handle)
        },
        open: { try SecureEnclaveIdentitySigner(dataRepresentation: $0) }
    )

    #if DEBUG
    /// Exportable software keys whose handle is the private key itself: only
    /// for a development build's process-local catalog on a Mac without a
    /// Secure Enclave, never for a catalog that persists.
    public static let processLocalSoftware = MachineIdentityKeyFactory(
        create: {
            let key = P256.Signing.PrivateKey()
            return (SoftwareIdentitySigner(key: key), key.rawRepresentation)
        },
        open: { SoftwareIdentitySigner(key: try P256.Signing.PrivateKey(rawRepresentation: $0)) }
    )
    #endif
}

/// One minted token and what it was minted for.
public struct MachineIdentityMinted: Sendable {
    public let token: String
    public let expiresAt: Date
    public let target: MachineIdentityTarget
    public let subject: String
    /// The signing key's id, so credentials obtained with it are never reused
    /// after the key changes.
    public let kid: String
}

/// The identities and targets, and the one place that mints. It answers only
/// to csecd: whoever calls `mint` has already had the reference authorized.
public actor MachineIdentityCatalog {
    private let store: ProtectedStore<MachineIdentityDocument>?
    private let keys: MachineIdentityKeyFactory
    private let clock: @Sendable () -> Date
    private var document = MachineIdentityDocument()
    /// Opened signers by kid, so a token costs one enclave signature rather
    /// than reopening the handle each time.
    private var signers: [String: IdentitySigner] = [:]
    /// Why the persisted catalog could not be read this run, or nil.
    private(set) var unreadable: ProtectedUnreadableReason?
    /// Counts prepared changes, so a failed commit rolls back only when no
    /// later change was prepared on top of it.
    private var generation: UInt64 = 0

    /// `store` nil keeps the catalog in this process only (tests and unsigned
    /// development builds).
    public init(
        store: ProtectedStore<MachineIdentityDocument>?,
        keys: MachineIdentityKeyFactory = .secureEnclave,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.store = store
        self.keys = keys
        self.clock = clock
    }

    /// Reads the persisted catalog. An unreadable item leaves the catalog
    /// empty for this run, and held, so nothing writes over it.
    public func load() async {
        guard let store else { return }
        switch await store.load() {
        case let .document(stored):
            document = stored
        case .absent:
            break
        case let .unreadable(reason):
            unreadable = reason
        }
    }

    public var snapshot: MachineIdentityDocument { document }

    public func identity(named name: String) -> StoredMachineIdentity? {
        document.identities.first { $0.name == name }
    }

    public func target(identity: String, name: String) -> MachineIdentityTarget? {
        document.targets.first { $0.identity == identity && $0.name == name }
    }

    /// Makes a new key and records the identity. The caller has had the
    /// creation approved.
    @discardableResult
    public func createIdentity(name: String, issuer: String, subject: String) async throws -> StoredMachineIdentity {
        guard MachineIdentityName.isValid(name) else { throw MachineIdentityCatalogError.invalid(.invalidName) }
        guard MachineIdentityIssuer.isValid(issuer) else { throw MachineIdentityCatalogError.invalid(.invalidIssuer) }
        guard MachineIdentityClaims.isPrintable(subject, maxBytes: MachineIdentityClaims.maximumSubjectBytes) else {
            throw MachineIdentityCatalogError.invalid(.invalidSubject)
        }
        guard identity(named: name) == nil else { throw MachineIdentityCatalogError.identityExists(name) }
        guard document.identities.count < MachineIdentityDocument.maximumIdentities else {
            throw MachineIdentityCatalogError.tooMany
        }
        let made: (signer: IdentitySigner, handle: Data)
        do {
            made = try keys.create()
        } catch let error as MachineIdentityError {
            throw MachineIdentityCatalogError.invalid(error)
        }
        let key = StoredMachineIdentityKey(
            handle: made.handle, jwk: MachineIdentityJWK(publicKey: made.signer.publicKey), created: clock()
        )
        let identity = StoredMachineIdentity(name: name, issuer: issuer, subject: subject, keys: [key])
        var next = document
        next.identities.append(identity)
        try await persist(next)
        signers[key.jwk.kid] = made.signer
        return identity
    }

    public func addTarget(_ target: MachineIdentityTarget) async throws {
        if let error = target.validationError { throw MachineIdentityCatalogError.invalid(error) }
        guard identity(named: target.identity) != nil else {
            throw MachineIdentityCatalogError.identityNotFound(target.identity)
        }
        guard self.target(identity: target.identity, name: target.name) == nil else {
            throw MachineIdentityCatalogError.targetExists(target.name)
        }
        guard document.targets.count < MachineIdentityDocument.maximumTargets else {
            throw MachineIdentityCatalogError.tooMany
        }
        var next = document
        next.targets.append(target)
        try await persist(next)
    }

    public func removeTarget(identity: String, name: String) async throws {
        guard target(identity: identity, name: name) != nil else { throw MachineIdentityCatalogError.targetNotFound(name) }
        var next = document
        next.targets.removeAll { $0.identity == identity && $0.name == name }
        try await persist(next)
    }

    /// Forgets an identity, its targets and its key handles. The enclave key
    /// becomes unreachable: nothing can sign with it again. Returns the
    /// references of the targets removed with it.
    @discardableResult
    public func removeIdentity(named name: String) async throws -> Set<String> {
        guard let removed = identity(named: name) else { throw MachineIdentityCatalogError.identityNotFound(name) }
        var next = document
        let targets = Set(next.targets.filter { $0.identity == name }.map(\.reference))
        next.identities.removeAll { $0.name == name }
        next.targets.removeAll { $0.identity == name }
        try await persist(next)
        for key in removed.keys { signers[key.jwk.kid] = nil }
        return targets
    }

    /// The target and the current key's id, for a caller that may already
    /// hold what a mint would be exchanged for.
    public func signingKey(identity name: String, target targetName: String) -> (target: MachineIdentityTarget, kid: String)? {
        guard let target = target(identity: name, name: targetName),
              let kid = identity(named: name)?.keys.first?.jwk.kid else { return nil }
        return (target, kid)
    }

    /// Records the published keys `kids` as accepted for `name`, so the
    /// issuer check stops flagging them. The caller has had the acceptance
    /// approved: an accepted key can sign in as this identity's clouds.
    public func acceptKeys(identity name: String, kids: [String]) async throws {
        guard let index = document.identities.firstIndex(where: { $0.name == name }) else {
            throw MachineIdentityCatalogError.identityNotFound(name)
        }
        var next = document
        let own = Set(next.identities[index].keys.map(\.jwk.kid))
        for kid in kids where !own.contains(kid) && !next.identities[index].acceptedKids.contains(kid) {
            next.identities[index].acceptedKids.append(kid)
        }
        guard next.identities[index].acceptedKids.count <= StoredMachineIdentity.maximumAcceptedKids else {
            throw MachineIdentityCatalogError.tooMany
        }
        try await persist(next)
    }

    /// Checks what `name`'s issuer publishes against its keys and the keys
    /// the human accepted.
    public func checkIssuer(
        identity name: String,
        fetch: @Sendable (URL) async throws -> Data = MachineIdentityIssuerCheck.fetchAnonymously
    ) async throws -> MachineIdentityIssuerFinding {
        guard let identity = identity(named: name) else { throw MachineIdentityCatalogError.identityNotFound(name) }
        return await MachineIdentityIssuerCheck.check(
            issuer: identity.issuer, ownKeys: identity.keys.map(\.jwk),
            acceptedKids: Set(identity.acceptedKids), fetch: fetch
        )
    }

    /// The public keys of every identity, for the issuer's key set.
    public func publicKeys(identity name: String) throws -> [MachineIdentityJWK] {
        guard let identity = identity(named: name) else { throw MachineIdentityCatalogError.identityNotFound(name) }
        return identity.keys.map(\.jwk)
    }

    /// A fresh token for `target`, with what the caller needs to use it.
    /// Authorization happened before this call. An exchange target's token lives
    /// only long enough to be exchanged.
    public func mint(identity identityName: String, target targetName: String) throws -> MachineIdentityMinted {
        guard let target = target(identity: identityName, name: targetName) else {
            throw MachineIdentityCatalogError.targetNotFound(targetName)
        }
        guard let identity = identity(named: identityName), let key = identity.keys.first else {
            throw MachineIdentityCatalogError.identityNotFound(identityName)
        }
        let signer: IdentitySigner
        if let open = signers[key.jwk.kid] {
            signer = open
        } else {
            do {
                signer = try keys.open(key.handle)
            } catch let error as MachineIdentityError {
                throw MachineIdentityCatalogError.invalid(error)
            }
            // A handle that opens to some other key is not this identity's.
            guard MachineIdentityJWK(publicKey: signer.publicKey).kid == key.jwk.kid else {
                throw MachineIdentityCatalogError.invalid(.keyUnusable)
            }
            signers[key.jwk.kid] = signer
        }
        do {
            let claims = try MachineIdentityClaims(
                issuer: identity.issuer, subject: identity.subject, audience: target.audience,
                issuedAt: clock(), lifetime: target.kind == .token ? target.lifetime : AWSWebIdentity.tokenLifetime
            )
            return MachineIdentityMinted(
                token: try MachineIdentityToken.mint(claims, signer: signer), expiresAt: claims.expiresAt,
                target: target, subject: identity.subject, kid: key.jwk.kid
            )
        } catch let error as MachineIdentityError {
            throw MachineIdentityCatalogError.invalid(error)
        }
    }

    /// The change becomes this actor's state in the same turn it is
    /// prepared, so a second change made while the first commits starts from
    /// it rather than from what was there before (the store applies changes
    /// in the order they were prepared).
    private func persist(_ next: MachineIdentityDocument) async throws {
        guard next.isWellFormed else { throw MachineIdentityCatalogError.invalid(.invalidName) }
        guard unreadable == nil else {
            throw MachineIdentityCatalogError.persistenceFailed("the saved catalog cannot be read by this csecd, so it is kept as found")
        }
        guard let store else {
            document = next
            return
        }
        let change: ProtectedChange
        do {
            change = try store.prepare(next)
        } catch {
            throw MachineIdentityCatalogError.persistenceFailed(String(describing: error))
        }
        let previous = document
        document = next
        generation += 1
        let mine = generation
        do {
            try await change.commit()
        } catch {
            if generation == mine { document = previous }
            throw MachineIdentityCatalogError.persistenceFailed(String(describing: error))
        }
    }
}

// MARK: - Provider

/// `csec-identity://<identity>/<target>`: resolving mints a token, and for an
/// `aws` or `google` target exchanges it for that target's credentials. The value
/// is made fresh and never cached at rest. A token needs no unlock and no
/// network; an exchange uses the cloud's token services, with no authorization of its
/// own, so the reference resolves the same whether a human or a delegated
/// approval authorized the request.
public struct MachineIdentityProvider: SecretProvider {
    public static let scheme = "csec-identity"

    public typealias Exchange = @Sendable (URLRequest) async throws -> (Data, Int)

    private let catalog: MachineIdentityCatalog
    private let exchange: Exchange
    private let sessions: AWSWebIdentitySessions
    private let googleExchange: Exchange
    private let googleSessions: GoogleWebIdentitySessions
    private let clock: @Sendable () -> Date

    public init(
        catalog: MachineIdentityCatalog,
        exchange: @escaping Exchange = AWSWebIdentity.send,
        googleExchange: @escaping Exchange = GoogleWebIdentity.send,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.catalog = catalog
        self.exchange = exchange
        self.sessions = AWSWebIdentitySessions()
        self.googleExchange = googleExchange
        self.googleSessions = GoogleWebIdentitySessions()
        self.clock = clock
    }

    public var schemes: Set<String> { [Self.scheme] }

    /// The identity and target a reference names, or nil for anything else.
    /// Only the canonical spelling (a lower-case scheme) names a sign-in: a
    /// grant or pairing is keyed on the reference as written, so a second
    /// spelling of the same target would escape its revocation.
    public static func parse(_ ref: SecretRef) -> (identity: String, target: String)? {
        guard ref.scheme == scheme, ref.uri == "\(scheme)://\(ref.path)" else { return nil }
        let parts = ref.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2, MachineIdentityName.isValid(parts[0]), MachineIdentityName.isValid(parts[1]) else {
            return nil
        }
        return (parts[0], parts[1])
    }

    public func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let (identity, target) = Self.parse(ref) else {
            throw ProviderError.referenceNotFound(ref.uri)
        }
        // Credentials csecd already holds for an AWS target cost no signature.
        if let known = await catalog.signingKey(identity: identity, target: target), known.target.kind == .aws,
           let held = await sessions.credentials(for: Self.sessionKey(known.target, kid: known.kid), now: clock()) {
            return ResolvedSecret(value: try held.bundle(), cacheHint: .noCache)
        }
        if let known = await catalog.signingKey(identity: identity, target: target), known.target.kind == .google,
           let held = await googleSessions.token(for: Self.sessionKey(known.target, kid: known.kid), now: clock()) {
            return ResolvedSecret(value: held.value, cacheHint: .noCache)
        }
        let minted: MachineIdentityMinted
        do {
            minted = try await catalog.mint(identity: identity, target: target)
        } catch let error as MachineIdentityCatalogError {
            switch error {
            case .identityNotFound, .targetNotFound:
                throw ProviderError.referenceNotFound(ref.uri)
            default:
                throw MachineIdentityProviderError(boundedReason: error.message)
            }
        }
        switch minted.target.kind {
        case .token:
            return ResolvedSecret(value: Data(minted.token.utf8), cacheHint: .noCache)
        case .aws:
            return ResolvedSecret(value: try await awsCredentials(for: minted).bundle(), cacheHint: .noCache)
        case .google:
            return ResolvedSecret(value: try await googleToken(for: minted).value, cacheHint: .noCache)
        }
    }

    private func googleToken(for minted: MachineIdentityMinted) async throws -> GoogleAccessToken {
        let target = minted.target
        let key = Self.sessionKey(target, kid: minted.kid)
        if let held = await googleSessions.token(for: key, now: clock()) { return held }
        do {
            let request = try GoogleWebIdentity.request(audience: target.audience, token: minted.token)
            let (data, status) = try await googleExchange(request)
            var token = try GoogleWebIdentity.parse(data, status: status, now: clock())
            if let serviceAccount = target.googleServiceAccount {
                let request = try GoogleWebIdentity.impersonationRequest(
                    serviceAccount: serviceAccount, token: String(decoding: token.value, as: UTF8.self)
                )
                let (data, status) = try await googleExchange(request)
                token = try GoogleWebIdentity.parse(data, status: status, now: clock(), impersonated: true)
            }
            await googleSessions.keep(token, for: key)
            return token
        } catch let error as GoogleWebIdentityError {
            throw MachineIdentityProviderError(boundedReason: error.message)
        } catch {
            throw MachineIdentityProviderError(boundedReason: GoogleWebIdentityError.unreachable.message)
        }
    }

    private func awsCredentials(for minted: MachineIdentityMinted) async throws -> AWSTemporaryCredentials {
        let target = minted.target
        guard let roleARN = target.roleARN, let region = target.region else {
            throw MachineIdentityProviderError(boundedReason: AWSWebIdentityError.invalidTarget.message)
        }
        let key = Self.sessionKey(target, kid: minted.kid)
        if let held = await sessions.credentials(for: key, now: clock()) {
            return held
        }
        let credentials: AWSTemporaryCredentials
        do {
            let request = try AWSWebIdentity.request(
                roleARN: roleARN, region: region, token: minted.token,
                sessionName: AWSWebIdentity.sessionName(forSubject: minted.subject), duration: target.lifetime
            )
            let (data, status) = try await exchange(request)
            credentials = try AWSWebIdentity.parse(data, status: status)
        } catch let error as AWSWebIdentityError {
            throw MachineIdentityProviderError(boundedReason: error.message)
        } catch {
            throw MachineIdentityProviderError(boundedReason: AWSWebIdentityError.unreachable.message)
        }
        await sessions.keep(credentials, for: key)
        return credentials
    }

    static func sessionKey(_ target: MachineIdentityTarget, kid: String) -> String {
        [target.identity, target.name, target.kind.rawValue, target.audience, target.roleARN ?? "",
         target.region ?? "", target.googleServiceAccount ?? "", String(target.lifetime), kid]
            .joined(separator: "\u{0}")
    }

    public func authenticate() async throws {}

    public func isAvailable() async -> Bool { await catalog.unreadable == nil }

    /// A sign-in is made per use and lasts at most an hour, so a copy kept
    /// for later runs (an automation job's materialization) would expire.
    public func valuesExpireSoon(_ ref: SecretRef) async -> Bool { true }

    /// Minting needs no unlock and the exchange no authorization, so a
    /// delegated release resolves a sign-in as a reviewed one does.
    public func resolveWithoutInteraction(_ ref: SecretRef) async -> ResolvedSecret? {
        try? await resolve(ref, unlock: nil)
    }

    public func presence(of ref: SecretRef) async -> ReferencePresence {
        guard let (identity, target) = Self.parse(ref) else {
            return .absent(reason: "not a machine identity reference (csec-identity://<identity>/<target>, in lower case)")
        }
        // A catalog this csecd cannot read is not known to lack anything.
        guard await catalog.unreadable == nil else { return .unknown }
        guard await catalog.identity(named: identity) != nil else {
            return .absent(reason: "this Mac has no machine identity named \(identity)")
        }
        guard await catalog.target(identity: identity, name: target) != nil else {
            return .absent(reason: "machine identity \(identity) has no target named \(target)")
        }
        return .present
    }

    public func reviewDescription(for ref: SecretRef) async -> ReviewSecret? {
        guard let (identityName, targetName) = Self.parse(ref),
              let identity = await catalog.identity(named: identityName),
              let target = await catalog.target(identity: identityName, name: targetName) else {
            return nil
        }
        return ReviewSecret(
            provider: "Machine identity", tint: .indigo, account: "this Mac",
            container: identityName, item: targetName, field: nil, itemIsIdentifier: true,
            notes: Self.reviewNotes(identity: identity, target: target)
        )
    }

    /// What the review says a sign-in is: who it signs in as, to what, and
    /// for how long a copy would be good.
    static func reviewNotes(identity: StoredMachineIdentity, target: MachineIdentityTarget) -> [String] {
        let minutes = target.lifetime / 60
        let duration = "\(minutes) minute\(minutes == 1 ? "" : "s")"
        switch target.kind {
        case .token:
            return [
                "A sign-in token signed by this Mac's Secure Enclave as \(identity.subject), for \(target.audience).",
                "It lasts \(duration); whoever holds it can sign in as this Mac until then.",
            ]
        case .aws:
            let role = target.roleARN.flatMap(AWSWebIdentity.roleName(ofRole:)) ?? "?"
            let account = target.roleARN.flatMap(AWSWebIdentity.accountID(ofRole:)) ?? "?"
            return [
                "AWS credentials for the role \(role) in account \(account), signed in as this Mac (\(identity.subject)).",
                "They last up to \(duration); whoever holds them can act as that role until then.",
            ]
        case .google:
            return [
                "A Google Cloud access token for \(target.googleServiceAccount ?? identity.subject), through \(target.audience).",
                "It lasts up to an hour; whoever holds it can use that Google identity until then.",
            ]
        }
    }

    public func statusSummary() async -> ProviderStatusSummary? {
        let snapshot = await catalog.snapshot
        guard !snapshot.identities.isEmpty else { return nil }
        let identities = snapshot.identities.count
        let targets = snapshot.targets.count
        return ProviderStatusSummary(
            label: "Machine identity",
            detail: "\(identities) identit\(identities == 1 ? "y" : "ies"), \(targets) target\(targets == 1 ? "" : "s")",
            healthy: true
        )
    }
}

public struct MachineIdentityProviderError: ProviderDiagnosableError {
    public let boundedReason: String
}
