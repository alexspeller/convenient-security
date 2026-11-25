import Foundation

// `csec identity …` over the authenticated socket. Managing identities is
// setup at this Mac: each change that adds what csecd can sign for (a new
// identity, a new sign-in target, accepting another key in the published key
// set) or destroys a key takes one Touch ID in csecd's settings panel, as
// backups do, and goes in the decision log. Using an identity is not managed
// here at all: a sign-in is an ordinary `csec-identity://` reference, reviewed
// and granted like any secret. Everything this service returns is public metadata: names, issuer
// URLs, key ids and public keys.

public enum MachineIdentityAction: String, Codable, Sendable {
    case status
    case create
    case remove
    case addTarget = "add_target"
    case removeTarget = "remove_target"
    case acceptKeys = "accept_keys"
    /// Fetch the published issuer files and compare them with this Mac's keys.
    case check
    /// The discovery document and key set to publish.
    case publicFiles = "public_files"
}

public struct MachineIdentityRequest: Codable, Sendable {
    public let requestID: String
    public let action: MachineIdentityAction
    public let identity: String?
    /// `create` only.
    public let issuer: String?
    public let subject: String?
    /// `add_target` only.
    public let target: MachineIdentityTarget?
    /// `remove_target` only.
    public let targetName: String?
    /// `accept_keys` only.
    public let kids: [String]?

    public init(
        action: MachineIdentityAction,
        identity: String? = nil,
        issuer: String? = nil,
        subject: String? = nil,
        target: MachineIdentityTarget? = nil,
        targetName: String? = nil,
        kids: [String]? = nil,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.action = action
        self.identity = identity
        self.issuer = issuer
        self.subject = subject
        self.target = target
        self.targetName = targetName
        self.kids = kids
    }

    /// Each action carries exactly the fields it uses. Values are checked
    /// again where they are used; this bounds what the decoder accepts.
    public var isWellFormed: Bool {
        let names = [identity, targetName].compactMap { $0 }
        guard names.allSatisfy(MachineIdentityName.isValid),
              (issuer.map { $0.utf8.count <= 512 } ?? true),
              (subject.map { $0.utf8.count <= 256 } ?? true),
              (kids.map { $0.count <= StoredMachineIdentity.maximumAcceptedKids && $0.allSatisfy { $0.utf8.count <= 64 } } ?? true)
        else { return false }
        switch action {
        case .status:
            return identity == nil && issuer == nil && subject == nil && target == nil && targetName == nil && kids == nil
        case .create:
            return identity != nil && issuer != nil && subject != nil && target == nil && targetName == nil && kids == nil
        case .remove, .check, .publicFiles:
            return identity != nil && issuer == nil && subject == nil && target == nil && targetName == nil && kids == nil
        case .addTarget:
            return identity == nil && issuer == nil && subject == nil && target != nil && targetName == nil && kids == nil
        case .removeTarget:
            return identity != nil && issuer == nil && subject == nil && target == nil && targetName != nil && kids == nil
        case .acceptKeys:
            return identity != nil && issuer == nil && subject == nil && target == nil && targetName == nil
                && !(kids ?? []).isEmpty
        }
    }
}

/// One identity as `csec identity status` lists it. Public metadata only: the
/// key handle never leaves csecd.
public struct MachineIdentitySummary: Codable, Sendable, Equatable {
    public let name: String
    public let issuer: String
    public let subject: String
    /// This Mac's keys, current first.
    public let keys: [MachineIdentityJWK]
    public let acceptedKids: [String]
    public let created: Date
}

public struct MachineIdentityStatus: Codable, Sendable, Equatable {
    public let identities: [MachineIdentitySummary]
    public let targets: [MachineIdentityTarget]
    /// Whether new keys go in the Secure Enclave. False only in unsigned
    /// development builds on a Mac without one.
    public let hardwareKeys: Bool
    /// Whether the catalog survives csecd restarting.
    public let persistent: Bool
}

/// What the issuer check found, value-free.
public struct MachineIdentityIssuerReport: Codable, Sendable, Equatable {
    public let identity: String
    public let issuer: String
    public let clear: Bool
    /// A key this Mac never accepted is published, or the discovery document
    /// points elsewhere: someone may be able to sign in as this identity.
    public let compromiseSuspected: Bool
    public let summary: String
    public let unexpectedKids: [String]

    public init(identity: String, issuer: String, finding: MachineIdentityIssuerFinding) {
        self.identity = identity
        self.issuer = issuer
        self.clear = finding.isClear
        self.summary = finding.summary
        switch finding {
        case let .unexpectedKeys(kids):
            compromiseSuspected = true
            unexpectedKids = kids
        case .discoveryMismatch:
            compromiseSuspected = true
            unexpectedKids = []
        case .clear, .ownKeyMissing, .unreachable:
            compromiseSuspected = false
            unexpectedKids = []
        }
    }
}

public struct MachineIdentityReply: Codable, Sendable, Equatable {
    public let status: MachineIdentityStatus?
    public let issuerReport: MachineIdentityIssuerReport?
    public let discoveryDocument: Data?
    public let keySet: Data?
    /// `remove` and `remove_target`: grants dropped because they covered a
    /// sign-in that no longer exists.
    public let revokedGrants: Int?

    public init(
        status: MachineIdentityStatus? = nil,
        issuerReport: MachineIdentityIssuerReport? = nil,
        discoveryDocument: Data? = nil,
        keySet: Data? = nil,
        revokedGrants: Int? = nil
    ) {
        self.status = status
        self.issuerReport = issuerReport
        self.discoveryDocument = discoveryDocument
        self.keySet = keySet
        self.revokedGrants = revokedGrants
    }
}

public actor MachineIdentityService {
    private let catalog: MachineIdentityCatalog
    private let consent: ConsentProvider
    private let terminalInspection: TerminalSessionInspector
    private let hardwareKeys: Bool
    private let persistent: Bool
    /// Drops every grant and pairing that names the references, returning
    /// how many grants went: a sign-in removed may come back under the same
    /// name for something else.
    private let revokeReferences: @Sendable (Set<String>) async -> Int
    /// The detail, and whether a Touch ID approved the change.
    private let record: @Sendable (String, Bool) async -> Void
    private let fetch: @Sendable (URL) async throws -> Data

    public init(
        catalog: MachineIdentityCatalog,
        consent: ConsentProvider,
        hardwareKeys: Bool,
        persistent: Bool,
        revokeReferences: @escaping @Sendable (Set<String>) async -> Int = { _ in 0 },
        record: @escaping @Sendable (String, Bool) async -> Void = { _, _ in },
        terminalInspection: TerminalSessionInspector,
        fetch: @escaping @Sendable (URL) async throws -> Data = MachineIdentityIssuerCheck.fetchAnonymously
    ) {
        self.catalog = catalog
        self.consent = consent
        self.terminalInspection = terminalInspection
        self.hardwareKeys = hardwareKeys
        self.persistent = persistent
        self.revokeReferences = revokeReferences
        self.record = record
        self.fetch = fetch
    }

    public func handle(_ request: MachineIdentityRequest, caller: CallerInfo) async -> Response {
        let id = request.requestID
        guard request.isWellFormed else {
            return .failed(.invalidRequest, message: "the machine identity request is malformed", requestID: id)
        }
        do {
            switch request.action {
            case .status:
                return reply(id, MachineIdentityReply(status: await status()))
            case .create:
                return try await create(request, caller: caller, id: id)
            case .remove:
                return try await remove(identity: request.identity!, caller: caller, id: id)
            case .addTarget:
                return try await addTarget(request.target!, caller: caller, id: id)
            case .removeTarget:
                return try await removeTarget(identity: request.identity!, name: request.targetName!, id: id)
            case .acceptKeys:
                return try await acceptKeys(identity: request.identity!, kids: request.kids ?? [], caller: caller, id: id)
            case .check:
                let name = request.identity!
                guard let identity = await catalog.identity(named: name) else {
                    throw MachineIdentityCatalogError.identityNotFound(name)
                }
                let finding = try await catalog.checkIssuer(identity: name, fetch: fetch)
                return reply(id, MachineIdentityReply(
                    issuerReport: MachineIdentityIssuerReport(identity: name, issuer: identity.issuer, finding: finding)
                ))
            case .publicFiles:
                let name = request.identity!
                guard let identity = await catalog.identity(named: name) else {
                    throw MachineIdentityCatalogError.identityNotFound(name)
                }
                return reply(id, MachineIdentityReply(
                    discoveryDocument: try MachineIdentityIssuer.discoveryDocument(issuer: identity.issuer),
                    keySet: try MachineIdentityIssuer.keySet(identity.keys.map(\.jwk))
                ))
            }
        } catch let error as MachineIdentityCatalogError {
            return .failed(code(for: error), message: error.message, requestID: id)
        } catch let error as MachineIdentityError {
            return .failed(.invalidRequest, message: error.message, requestID: id)
        } catch let denied as Denied {
            return .failed(.consentDenied, message: denied.message, requestID: id)
        } catch {
            return .failed(.internalError, message: "the machine identity catalog could not be changed", requestID: id)
        }
    }

    /// Every identity and target, for `csec identity status` and the issuer
    /// check that csecd runs with its daily audit.
    public func status() async -> MachineIdentityStatus {
        let snapshot = await catalog.snapshot
        return MachineIdentityStatus(
            identities: snapshot.identities.map {
                MachineIdentitySummary(
                    name: $0.name, issuer: $0.issuer, subject: $0.subject, keys: $0.keys.map(\.jwk),
                    acceptedKids: $0.acceptedKids, created: $0.keys.last?.created ?? Date(timeIntervalSince1970: 0)
                )
            },
            targets: snapshot.targets,
            hardwareKeys: hardwareKeys,
            persistent: persistent
        )
    }

    /// The issuer check for every identity whose issuer is published, as
    /// the daily audit runs it: only findings that suggest someone else can
    /// sign in are returned.
    public func suspectedIssuerCompromises() async -> [MachineIdentityIssuerReport] {
        var reports: [MachineIdentityIssuerReport] = []
        for identity in await catalog.snapshot.identities {
            guard let finding = try? await catalog.checkIssuer(identity: identity.name, fetch: fetch) else { continue }
            let report = MachineIdentityIssuerReport(identity: identity.name, issuer: identity.issuer, finding: finding)
            if report.compromiseSuspected { reports.append(report) }
        }
        return reports
    }

    // MARK: - Changes

    private struct Denied: Error {
        let message: String
    }

    /// One touch in csecd's settings panel, naming the tab `caller` runs in.
    private func approve(_ title: String, _ change: String, caller: CallerInfo) async throws {
        var shown = caller
        shown.terminal = await terminalInspection.context(forCallerPID: caller.pid)
        let outcome = await consent.approveSettingsChange(
            SettingsChangeReviewDetails(title: title, changes: [change]), caller: shown
        )
        outcome.unlock?.invalidate()
        guard outcome.isApproved else { throw Denied(message: "denied at Touch ID") }
    }

    private func create(_ request: MachineIdentityRequest, caller: CallerInfo, id: String) async throws -> Response {
        let name = request.identity!, issuer = request.issuer!, subject = request.subject!
        // Checked before the touch, so a mistake costs no prompt.
        guard MachineIdentityIssuer.isValid(issuer) else { throw MachineIdentityError.invalidIssuer }
        guard MachineIdentityClaims.isPrintable(subject, maxBytes: MachineIdentityClaims.maximumSubjectBytes) else {
            throw MachineIdentityError.invalidSubject
        }
        guard await catalog.identity(named: name) == nil else { throw MachineIdentityCatalogError.identityExists(name) }
        try await approve(
            "Create a Machine Identity",
            "Create the machine identity \(name), signing in as this Mac (\(subject)) with issuer \(issuer)",
            caller: caller
        )
        let identity = try await catalog.createIdentity(name: name, issuer: issuer, subject: subject)
        await record("machine identity \(name) created (issuer \(issuer), subject \(subject), key \(identity.keys[0].jwk.kid))", true)
        return reply(id, MachineIdentityReply(status: await status()))
    }

    private func remove(identity name: String, caller: CallerInfo, id: String) async throws -> Response {
        guard await catalog.identity(named: name) != nil else { throw MachineIdentityCatalogError.identityNotFound(name) }
        try await approve(
            "Remove a Machine Identity",
            "Remove the machine identity \(name) and its key for good, with every grant for its sign-ins",
            caller: caller
        )
        // What was removed, not what was there before the touch: a target
        // added meanwhile goes with the identity and its grants with it.
        let references = try await catalog.removeIdentity(named: name)
        let revoked = await revokeReferences(references)
        await record("machine identity \(name) removed with its key; \(revoked) grant(s) revoked", true)
        return reply(id, MachineIdentityReply(status: await status(), revokedGrants: revoked))
    }

    private func addTarget(_ target: MachineIdentityTarget, caller: CallerInfo, id: String) async throws -> Response {
        if let error = target.validationError { throw error }
        guard let identity = await catalog.identity(named: target.identity) else {
            throw MachineIdentityCatalogError.identityNotFound(target.identity)
        }
        guard await catalog.target(identity: target.identity, name: target.name) == nil else {
            throw MachineIdentityCatalogError.targetExists(target.name)
        }
        let what = Self.describe(target)
        try await approve(
            "Add a Machine Identity Sign-In",
            "Add the sign-in \(target.identity)/\(target.name): \(what), as \(identity.subject)",
            caller: caller
        )
        try await catalog.addTarget(target)
        await record("machine identity target \(target.identity)/\(target.name) added: \(what)", true)
        return reply(id, MachineIdentityReply(status: await status()))
    }

    /// Removing only takes access away, so it needs no touch, as removing the
    /// GitHub proxy's registration needs none. Grants that covered the
    /// sign-in go with it: a target added later under the same name may sign
    /// in somewhere else, and nothing approved for this one may carry over.
    private func removeTarget(identity: String, name: String, id: String) async throws -> Response {
        guard let target = await catalog.target(identity: identity, name: name) else {
            throw MachineIdentityCatalogError.targetNotFound(name)
        }
        try await catalog.removeTarget(identity: identity, name: name)
        let revoked = await revokeReferences([target.reference])
        await record("machine identity target \(identity)/\(name) removed; \(revoked) grant(s) revoked", false)
        return reply(id, MachineIdentityReply(status: await status(), revokedGrants: revoked))
    }

    private func acceptKeys(
        identity name: String, kids: [String], caller: CallerInfo, id: String
    ) async throws -> Response {
        guard let identity = await catalog.identity(named: name) else { throw MachineIdentityCatalogError.identityNotFound(name) }
        let own = Set(identity.keys.map(\.jwk.kid))
        let new = kids.filter { !own.contains($0) && !identity.acceptedKids.contains($0) }
        guard !new.isEmpty else { return reply(id, MachineIdentityReply(status: await status())) }
        guard new.allSatisfy(MachineIdentityJWK.isThumbprint) else { throw MachineIdentityError.invalidKeyID }
        try await approve(
            "Accept Published Keys",
            "Accept \(new.count) other key\(new.count == 1 ? "" : "s") in \(name)'s published key set, "
                + "each able to sign in as anyone its clouds trust",
            caller: caller
        )
        try await catalog.acceptKeys(identity: name, kids: new)
        await record("machine identity \(name): accepted published key(s) \(new.joined(separator: ", "))", true)
        return reply(id, MachineIdentityReply(status: await status()))
    }

    static func describe(_ target: MachineIdentityTarget) -> String {
        switch target.kind {
        case .token:
            return "a token for \(target.audience)"
        case .aws:
            let role = target.roleARN.flatMap(AWSWebIdentity.roleName(ofRole:)) ?? "?"
            let account = target.roleARN.flatMap(AWSWebIdentity.accountID(ofRole:)) ?? "?"
            return "AWS role \(role) in account \(account)"
        case .google:
            return "Google access through \(target.audience)\(target.googleServiceAccount.map { ", as \($0)" } ?? ", as this Mac")"
        }
    }

    private func reply(_ id: String, _ reply: MachineIdentityReply) -> Response {
        Response(requestID: id, machineIdentity: reply)
    }

    private func code(for error: MachineIdentityCatalogError) -> WireErrorCode {
        switch error {
        case .identityNotFound, .targetNotFound, .identityExists, .targetExists, .tooMany, .invalid:
            return .invalidRequest
        case .persistenceFailed:
            return .internalError
        }
    }
}
