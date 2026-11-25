import CryptoKit
import CSECRemoteApproval
import ConvenientSecurity
import Foundation
import LocalAuthentication
import CSECBuildIdentity

// Remote approval protocol v3, the Mac's request path: the signed wire and its
// acceptance rules, the review the phone renders, which reviews reach the phone
// (provider-neutral readiness), and end to end the phone-held unlock factor
// opening cold storage for a phone approval, with the grant it selected. Every
// key is a synthetic software P-256 key and every backend is in memory.

// MARK: - Shared fixtures

/// A phone approval that selects nothing, for fakes of reviews that offer no
/// choice.
let remoteApprovalNoSelection = RemoteApprovalSelection(scopeOptionID: nil, durationIndex: nil, unlockAnswer: nil)

/// A review's fields, so a test can rebuild it with one of them changed.
struct RemoteReviewParts {
    var kind: RemoteApprovalReview.Kind
    var headline: String
    var callerDescription: String
    var terminalDescription: String?
    var secrets: [ReviewSecret]
    var referenceSetDigest: Data
    var delivery: RemoteApprovalReview.Delivery?
    var warnings: [String]
    var footnote: String?
    var ssh: RemoteApprovalReview.SSH?
    var sudo: RemoteApprovalReview.Sudo?
    var restore: RemoteApprovalReview.Restore?
    var settings: RemoteApprovalReview.Settings?
    var scopeOptions: [RemoteApprovalReview.ScopeOption]
    var defaultScopeID: String?
    var durationOptions: [String]
    var defaultDurationIndex: UInt16?
    var delegation: RemoteApprovalReview.Delegation?
    var requesterCommand: String?
    var closesAtMilliseconds: UInt64?
    var operationDigest: Data

    init(_ review: RemoteApprovalReview) {
        kind = review.kind
        headline = review.headline
        callerDescription = review.callerDescription
        terminalDescription = review.terminalDescription
        secrets = review.secrets
        referenceSetDigest = review.referenceSetDigest
        delivery = review.delivery
        warnings = review.warnings
        footnote = review.footnote
        ssh = review.ssh
        sudo = review.sudo
        restore = review.restore
        settings = review.settings
        scopeOptions = review.scopeOptions
        defaultScopeID = review.defaultScopeID
        durationOptions = review.durationOptions
        defaultDurationIndex = review.defaultDurationIndex
        delegation = review.delegation
        requesterCommand = review.requesterCommand
        closesAtMilliseconds = review.closesAtMilliseconds
        operationDigest = review.operationDigest
    }

    var review: RemoteApprovalReview {
        RemoteApprovalReview(
            kind: kind, headline: headline, callerDescription: callerDescription,
            terminalDescription: terminalDescription, secrets: secrets,
            referenceSetDigest: referenceSetDigest, delivery: delivery, warnings: warnings,
            footnote: footnote, ssh: ssh, sudo: sudo, restore: restore, settings: settings,
            scopeOptions: scopeOptions,
            defaultScopeID: defaultScopeID, durationOptions: durationOptions,
            defaultDurationIndex: defaultDurationIndex, delegation: delegation,
            requesterCommand: requesterCommand, closesAtMilliseconds: closesAtMilliseconds,
            operationDigest: operationDigest
        )
    }

    static func changing(
        _ review: RemoteApprovalReview, _ change: (inout RemoteReviewParts) -> Void
    ) -> RemoteApprovalReview {
        var parts = RemoteReviewParts(review)
        change(&parts)
        return parts.review
    }
}

extension ReviewSecret {
    func with(
        provider: String?? = .none, tint: ReviewSecretTint? = nil, account: String?? = .none,
        container: String?? = .none, item: String? = nil, field: String?? = .none,
        itemIsIdentifier: Bool? = nil, notes: [String]? = nil, warnings: [String]? = nil
    ) -> ReviewSecret {
        ReviewSecret(
            provider: provider ?? self.provider, tint: tint ?? self.tint,
            account: account ?? self.account, container: container ?? self.container,
            item: item ?? self.item, field: field ?? self.field,
            itemIsIdentifier: itemIsIdentifier ?? self.itemIsIdentifier,
            notes: notes ?? self.notes, warnings: warnings ?? self.warnings
        )
    }
}

/// What the providers say about the fixtures' references.
func v3OnePasswordSecret(
    _ vault: String, _ item: String, _ field: String,
    account: String? = "example.1password.com", warnings: [String] = []
) -> ReviewSecret {
    ReviewSecret(
        provider: "1Password", tint: .teal, account: account, container: vault,
        item: item, field: field, warnings: warnings
    )
}

func v3NativeSecret(_ store: String, _ key: String) -> ReviewSecret {
    ReviewSecret(
        provider: "csec", tint: .purple, account: "this Mac", container: store,
        item: key, field: nil, itemIsIdentifier: true
    )
}

extension RemoteApprovalReview.Delivery {
    func with(_ index: Int, _ value: String) -> RemoteApprovalReview.Delivery {
        var fields = [emitterName, emitterPath, emitterAssurance, recipientDescription,
                      deliveryDescription, destinationDescription]
        fields[index] = value
        return RemoteApprovalReview.Delivery(
            emitterName: fields[0], emitterPath: fields[1], emitterAssurance: fields[2],
            recipientDescription: fields[3], deliveryDescription: fields[4], destinationDescription: fields[5]
        )
    }
}

extension RemoteApprovalReview.SSH {
    func with(
        hostNames: [String]? = nil, hostContext: String? = nil, unknownHost: Bool? = nil,
        remoteUser: String? = nil, keyLabel: String? = nil, keyAlgorithm: String? = nil
    ) -> RemoteApprovalReview.SSH {
        RemoteApprovalReview.SSH(
            hostNames: hostNames ?? self.hostNames, hostContext: hostContext ?? self.hostContext,
            unknownHost: unknownHost ?? self.unknownHost, remoteUser: remoteUser ?? self.remoteUser,
            keyLabel: keyLabel ?? self.keyLabel, keyAlgorithm: keyAlgorithm ?? self.keyAlgorithm
        )
    }
}

extension RemoteApprovalReview.Restore {
    func with(
        header: String? = nil, footnote: String? = nil, storeCount: UInt16? = nil,
        rows: [RemoteApprovalReview.RestoreRow]? = nil
    ) -> RemoteApprovalReview.Restore {
        RemoteApprovalReview.Restore(
            header: header ?? self.header, footnote: footnote ?? self.footnote,
            storeCount: storeCount ?? self.storeCount, rows: rows ?? self.rows
        )
    }
}

extension RemoteApprovalReview.RestoreRow {
    func with(
        kind: String? = nil, title: String? = nil, detail: String? = nil,
        secrets: [ReviewSecret]? = nil, ssh: RemoteApprovalReview.SSH?? = .none
    ) -> RemoteApprovalReview.RestoreRow {
        RemoteApprovalReview.RestoreRow(
            kind: kind ?? self.kind, title: title ?? self.title, detail: detail ?? self.detail,
            secrets: secrets ?? self.secrets, ssh: ssh ?? self.ssh
        )
    }
}

private let v3SSHFacts = RemoteApprovalReview.SSH(
    hostNames: ["github.com"], hostContext: "Recognized from known_hosts.", unknownHost: false,
    remoteUser: "git", keyLabel: "work laptop", keyAlgorithm: "Ed25519"
)

/// An access review carrying every field an access review can: provider notes
/// and warnings, a banner warning, a restore section with an SSH row, and the
/// scope and lifetime choices.
func v3AccessReviewFixture(withRestore: Bool = true) -> RemoteApprovalReview {
    RemoteApprovalReview(
        kind: .access,
        headline: "bin/rails db:migrate",
        callerDescription: "ruby [protected] (pid 42)",
        terminalDescription: "iTerm2 · tab 1 · ttys003",
        secrets: [
            v3OnePasswordSecret("Development", "Database", "password", warnings: ["two accounts are signed in"])
                .with(notes: ["read through the 1Password desktop app"]),
            ReviewDisplay.undescribedSecret(try! SecretRef("vault://kv/app/token")),
        ],
        referenceSetDigest: Data(repeating: 0x11, count: SHA256.byteCount),
        delivery: .init(
            emitterName: "ruby", emitterPath: "/usr/bin/ruby", emitterAssurance: "Protected path",
            recipientDescription: "planned executable consumer",
            deliveryDescription: "Direct to process memory · process and its descendants",
            destinationDescription: "Local development"
        ),
        warnings: ["TERMINAL PLAINTEXT: synthetic banner.\n\nSecond paragraph."],
        footnote: DeliveryReviewCopy.releaseFootnote,
        restore: withRestore ? .init(
            header: "csecd restarted (restart): reopen what you approved",
            footnote: "Touch ID also reopens 2 stores for approvals you already made.",
            storeCount: 2,
            rows: [
                .init(kind: "secret_grant", title: "fish", detail: "This terminal session · pid 7",
                      secrets: [v3NativeSecret("dev", "API_TOKEN")], ssh: nil),
                .init(kind: "ssh_grant", title: "ssh", detail: "This SSH command · pid 8",
                      secrets: [v3NativeSecret("dev", "id_ed25519")], ssh: v3SSHFacts),
            ]
        ) : nil,
        scopeOptions: [
            .init(id: "requesting_command-42-7", title: "Requesting process only",
                  detail: "ruby (pid 42) and its descendants — this command only"),
            .init(id: "terminal_session-7-1", title: "This terminal session",
                  detail: "fish (pid 7) — everything started in this terminal, until the grant expires"),
        ],
        defaultScopeID: "terminal_session-7-1",
        durationOptions: ["Until it exits", "1 hour", "12 hours"],
        defaultDurationIndex: 0,
        operationDigest: Data(repeating: 0x22, count: SHA256.byteCount)
    )
}

func v3SSHReviewFixture() -> RemoteApprovalReview {
    RemoteApprovalReview(
        kind: .ssh,
        headline: "SSH to github.com as git using work laptop",
        callerDescription: "Apple SSH [verified] (pid 51)",
        terminalDescription: nil,
        secrets: [v3NativeSecret("dev", "id_ed25519")],
        referenceSetDigest: Data(repeating: 0x33, count: SHA256.byteCount),
        delivery: .init(
            emitterName: "ssh", emitterPath: "/usr/bin/ssh", emitterAssurance: "Protected path",
            recipientDescription: "planned executable consumer",
            deliveryDescription: "Credential helper protocol · process and its descendants",
            destinationDescription: "Credential consumer"
        ),
        warnings: [],
        footnote: DeliveryReviewCopy.sshFootnote,
        ssh: v3SSHFacts,
        scopeOptions: [.init(id: "requesting_command-51-9", title: "This SSH command",
                             detail: "ssh (pid 51) — only this command and its descendants")],
        defaultScopeID: "requesting_command-51-9",
        durationOptions: ["Until it exits", "1 hour"],
        defaultDurationIndex: 0,
        operationDigest: Data(repeating: 0x44, count: SHA256.byteCount)
    )
}

func v3SudoReviewFixture() -> RemoteApprovalReview {
    RemoteApprovalReview(
        kind: .sudo,
        headline: "sudo ls /var/root",
        callerDescription: "sudo (pid 60)",
        terminalDescription: "Terminal · tab 2",
        secrets: [],
        referenceSetDigest: Data(repeating: 0x55, count: SHA256.byteCount),
        delivery: nil,
        warnings: [],
        footnote: "Touch ID authorizes this one sudo command.",
        sudo: .init(command: "ls /var/root", workingDirectory: "/Users/alex", targetUser: "root"),
        operationDigest: Data(repeating: 0x66, count: SHA256.byteCount)
    )
}

/// A synthetic iPhone: its signing identity, its key-agreement key, and what
/// its app would sign.
struct SyntheticPhone: Sendable {
    let deviceID: String
    let signingKey: P256.Signing.PrivateKey
    let keyAgreementKey: P256.KeyAgreement.PrivateKey
    var name = "Alex’s iPhone"

    init(
        deviceID: String = UUID().uuidString.lowercased(),
        signingKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
        keyAgreementKey: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey()
    ) {
        self.deviceID = deviceID
        self.signingKey = signingKey
        self.keyAgreementKey = keyAgreementKey
    }

    func pairing(vouchedBy voucher: P256.Signing.PrivateKey? = nil,
                 keyAgreementKey claimed: P256.KeyAgreement.PublicKey? = nil) throws -> RemoteApprovalPhonePairing {
        let keyAgreement = claimed ?? keyAgreementKey.publicKey
        let signed = RemoteApprovalPhonePairing.keyAgreementBindingData(
            phoneDeviceID: deviceID,
            phoneKeyAgreementPublicKeyX963: keyAgreementKey.publicKey.x963Representation
        )
        return RemoteApprovalPhonePairing(
            phoneDeviceID: deviceID,
            phoneDeviceName: name,
            phonePublicKeyX963: signingKey.publicKey.x963Representation,
            phoneKeyAgreementPublicKeyX963: keyAgreement.x963Representation,
            keyAgreementSignatureDER: try (voucher ?? signingKey).signature(for: signed).derRepresentation,
            appVersion: "1.0 (7)"
        )
    }

    var pairingCode: String {
        get throws { try RemoteApprovalPairingCode.encodePhone(try pairing()) }
    }

    /// A response with exactly these fields, signed by this phone.
    func respond(
        to envelope: SignedRemoteApprovalRequest,
        _ decision: RemoteApprovalDecision,
        scopeID: String? = nil,
        durationIndex: UInt16? = nil,
        unlockAnswer: Data? = nil,
        pairingLineShown: Bool? = nil,
        signer: P256.Signing.PrivateKey? = nil
    ) throws -> SignedRemoteApprovalResponse {
        try .signed(
            RemoteApprovalResponse(
                requestID: envelope.request.requestID,
                requestDigest: try envelope.request.digest(),
                phoneDeviceID: deviceID,
                decision: decision,
                decidedAtMilliseconds: currentTimeMilliseconds(),
                selectedScopeID: scopeID,
                selectedDurationIndex: durationIndex,
                unlockAnswer: unlockAnswer,
                phoneAppVersion: "1.0 (7)",
                pairingLineShown: pairingLineShown
            ),
            by: signer ?? signingKey
        )
    }

    /// Approve as the app would: the offered defaults unless told otherwise,
    /// and the answer to the request's unlock challenge computed with
    /// `answeringWith` (this phone's own key by default).
    func approve(
        _ envelope: SignedRemoteApprovalRequest,
        scopeID: String? = nil,
        durationIndex: UInt16? = nil,
        answeringWith key: P256.KeyAgreement.PrivateKey? = nil
    ) throws -> SignedRemoteApprovalResponse {
        let review = envelope.request.review
        let scope = scopeID ?? review.defaultScopeID
        let duration = durationIndex ?? review.defaultDurationIndex
        // As the app signs it: whether its card drew the pairing line.
        return try respond(
            to: envelope, .approve,
            scopeID: scope,
            durationIndex: duration,
            unlockAnswer: try envelope.request.unlockChallenge.map {
                try Self.answer($0, with: key ?? keyAgreementKey)
            },
            pairingLineShown: review.delegation?.pairing == nil
                ? nil : review.pairingLineApplies(scopeID: scope, durationIndex: duration)
        )
    }

    static func answer(_ challenge: RemoteApprovalUnlockChallenge, with key: P256.KeyAgreement.PrivateKey) throws -> Data {
        try RemoteUnlockCrypto.answer(blindedPoint: challenge.blindedPoint) {
            try key.sharedSecretFromKeyAgreement(with: $0)
        }
    }
}

/// The phone code a phone app would produce, without the encoder's own
/// validation, so a code a real app could never produce can be tried.
private func unvalidatedPhoneCode(_ pairing: RemoteApprovalPhonePairing) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let base64 = try encoder.encode(pairing).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return RemoteApprovalPairingCode.phonePrefix + base64
}

actor V3SoftwareSigner: RemoteApprovalRequestSigner {
    let key: P256.Signing.PrivateKey
    init(key: P256.Signing.PrivateKey) { self.key = key }
    func publicKeyX963Representation() async throws -> Data { key.publicKey.x963Representation }
    func sign(_ data: Data) async throws -> Data { try key.signature(for: data).derRepresentation }
}

func v3SoftwareMacKeys() -> RemoteApprovalMacKeys {
    RemoteApprovalMacKeys(
        create: {
            let key = P256.Signing.PrivateKey()
            return (V3SoftwareSigner(key: key), key.rawRepresentation, key.publicKey.x963Representation)
        },
        load: { V3SoftwareSigner(key: try P256.Signing.PrivateKey(rawRepresentation: $0)) }
    )
}

/// The CloudKit mailbox's shape in memory: request and response records, the
/// phone's pairing confirmation and status. Nothing here decides anything.
actor V3MailboxRelay: RemoteApprovalRelay {
    private var requests: [String: SignedRemoteApprovalRequest] = [:]
    private var responses: [String: SignedRemoteApprovalResponse] = [:]
    private var confirmations: [String: SignedRemoteApprovalPairingConfirmation] = [:]
    private var statuses: [String: SignedRemoteApprovalPhoneStatus] = [:]
    private(set) var published: [String] = []
    private(set) var deleted: [String] = []
    private(set) var polls = 0
    /// Alert records in the mailbox, and every alert publish that landed.
    private(set) var alerts: Set<String> = []
    private(set) var alertsPublished: [String] = []
    private(set) var alertAttempts = 0
    /// Thrown, in order, by the next alert publishes.
    private var alertFailures: [Error] = []

    func failNextAlerts(_ failures: [Error]) { alertFailures = failures }

    func publishAlert(requestID: String, macDeviceID: String) async throws {
        alertAttempts += 1
        if !alertFailures.isEmpty { throw alertFailures.removeFirst() }
        alerts.insert(requestID)
        alertsPublished.append(requestID)
    }

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        requests[request.request.requestID] = request
        published.append(request.request.requestID)
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        polls += 1
        return RemoteApprovalMailboxName.response(requestID: requestID, phoneDeviceID: phoneDeviceID)
            .flatMap { responses[$0] }
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async {
        if let name = RemoteApprovalMailboxName.response(requestID: requestID, phoneDeviceID: phoneDeviceID) {
            responses[name] = nil
        }
    }

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] { Array(requests.values) }
    func requestIsPending(requestID: String) async throws -> Bool { requests[requestID] != nil }

    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        if let name = RemoteApprovalMailboxName.response(
            requestID: response.response.requestID,
            phoneDeviceID: response.response.phoneDeviceID
        ) {
            responses[name] = response
        }
    }

    func deleteExchange(requestID: String, phoneDeviceID: String?) async {
        requests[requestID] = nil
        alerts.remove(requestID)
        if let phoneDeviceID,
           let name = RemoteApprovalMailboxName.response(requestID: requestID, phoneDeviceID: phoneDeviceID) {
            responses[name] = nil
        }
        deleted.append(requestID)
    }

    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? {
        confirmations[macDeviceID.lowercased()]
    }

    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {
        confirmations[confirmation.confirmation.macDeviceID] = confirmation
    }

    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? {
        statuses[phoneDeviceID.lowercased()]
    }

    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {
        statuses[status.status.phoneDeviceID] = status
    }

    /// Offer records by phone, and every offer publish that landed.
    private(set) var offers: [String: SignedRemoteApprovalPairingOffer] = [:]
    private(set) var offersPublished = 0
    private(set) var offerWithdrawals: [(phoneDeviceID: String, macDeviceID: String)] = []
    private var failOfferPublishes = false
    private var offerWithdrawalFailuresLeft = 0

    func failOfferPublishes(_ fail: Bool) { failOfferPublishes = fail }
    /// The next `count` offer withdrawals fail, as with no network.
    func failNextOfferWithdrawals(_ count: Int) { offerWithdrawalFailuresLeft = count }

    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {
        if failOfferPublishes { throw RemoteApprovalRelayFailure.transient }
        offers[offer.offer.phoneDeviceID] = offer
        offersPublished += 1
    }

    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? {
        offers[phoneDeviceID.lowercased()]
    }

    /// Like the CloudKit relay: removes the offer only when that Mac made it.
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async throws {
        offerWithdrawals.append((phoneDeviceID.lowercased(), macDeviceID.lowercased()))
        if offerWithdrawalFailuresLeft > 0 {
            offerWithdrawalFailuresLeft -= 1
            throw RemoteApprovalRelayFailure.transient
        }
        if offers[phoneDeviceID.lowercased()]?.offer.mac.macDeviceID == macDeviceID.lowercased() {
            offers[phoneDeviceID.lowercased()] = nil
        }
    }

    /// Plant an offer as any writer could.
    func plantOffer(_ offer: SignedRemoteApprovalPairingOffer) {
        offers[offer.offer.phoneDeviceID] = offer
    }

    func liveRequests() -> [SignedRemoteApprovalRequest] { Array(requests.values) }

    /// The next request published after `count` earlier ones, once it lands.
    func request(number index: Int) -> SignedRemoteApprovalRequest? {
        guard published.indices.contains(index) else { return nil }
        return requests[published[index]]
    }
}

func v3WaitForRequest(
    _ relay: V3MailboxRelay, number index: Int = 0
) async -> SignedRemoteApprovalRequest? {
    for _ in 0..<600 {
        if let envelope = await relay.request(number: index) { return envelope }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return nil
}

/// Pairing records in memory, stored as the bytes the Keychain would hold
/// and decoded the way the Keychain store decodes them.
actor V3MemoryConfigurationStore: RemoteApprovalConfigurationStore {
    private var bytes: Data?
    private(set) var deletes = 0

    init(record: StoredRemoteApprovalConfiguration? = nil, raw: Data? = nil) {
        bytes = raw ?? record.flatMap { try? JSONEncoder().encode($0) }
    }

    func current() -> StoredRemoteApprovalConfiguration? {
        bytes.flatMap { try? StoredRemoteApprovalConfiguration.decodeStored($0) }
    }

    func load() async throws -> StoredRemoteApprovalConfiguration? {
        guard let bytes else { return nil }
        return try StoredRemoteApprovalConfiguration.decodeStored(bytes)
    }

    func store(_ configuration: StoredRemoteApprovalConfiguration) async throws {
        try configuration.validate()
        bytes = try JSONEncoder().encode(configuration)
    }

    func delete() async throws {
        deletes += 1
        bytes = nil
    }
}

actor V3CountingConsent: ConsentProvider {
    private(set) var requests = 0
    private(set) var authentications = 0

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        requests += 1
        return .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        authentications += 1
        return .approved(unlock: nil)
    }
}

final class V3LogLines: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    func append(_ line: String) { lock.lock(); lines.append(line); lock.unlock() }
    var all: [String] { lock.lock(); defer { lock.unlock() }; return lines }
}

/// A pairing made directly with software keys, as `enable` would store it.
func v3StoredPairing(
    phone: SyntheticPhone, macKey: P256.Signing.PrivateKey
) -> StoredRemoteApprovalConfiguration {
    StoredRemoteApprovalConfiguration(
        macDeviceID: UUID().uuidString.lowercased(),
        macDeviceName: "Alex’s Mac",
        macSigningKeyRepresentation: macKey.rawRepresentation,
        macPublicKeyX963: macKey.publicKey.x963Representation,
        phoneDeviceID: phone.deviceID,
        phoneDeviceName: phone.name,
        phonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
        phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
        cloudKitContainerIdentifier: CSECBuildIdentity.cloudKitContainer
    )
}

func v3Manager(
    store: V3MemoryConfigurationStore,
    relay: V3MailboxRelay,
    consent: V3CountingConsent = V3CountingConsent(),
    remoteUnlock: RemoteUnlockStore? = nil,
    resolver: SecretResolver? = nil,
    log: V3LogLines = V3LogLines()
) -> RemoteApprovalManager {
    RemoteApprovalManager(
        store: store,
        relay: relay,
        consent: consent,
        cloudKitContainerIdentifier: CSECBuildIdentity.cloudKitContainer,
        accountStatus: { .available },
        macKeys: v3SoftwareMacKeys(),
        remoteUnlock: remoteUnlock,
        coverage: resolver.map { resolver in
            { @Sendable references in await resolver.remoteUnlockCoverage(references) }
        },
        log: { log.append($0) }
    )
}

// MARK: - Suite

func remoteApprovalV3Tests() async {
    print("\n# Remote approval v3 wire (canonical binding, kinds, selection and unlock rules)")
    v3CanonicalBindingTests()
    v3KindConsistencyTests()
    await v3AcceptanceRuleTests()
    print("\n# Remote approval v3 pairing (the phone's key-agreement key, vouched for)")
    await v3PairingTests()
    print("\n# Remote approval v3 review (what the phone renders, from the Mac panel's copy)")
    v3ReviewBuilderTests()
    v3DelegationTests()
    print("\n# Remote approval v3 readiness and the phone-held unlock factor, end to end")
    await v3UnlockEndToEndTests()
    print("\n# Remote approval v3: a cached copy is read before a provider that may be locked")
    await v3CachedCopyEndToEndTests()
    await settingsAcknowledgementPhoneTests()
    await remoteStatusReadinessTests()
}

// MARK: - Wire

private func v3CanonicalBindingTests() {
    func request(
        _ review: RemoteApprovalReview,
        challenge: RemoteApprovalUnlockChallenge? = nil,
        requestID: String = "0b8f5f1e-1111-4222-8333-944455556666",
        macDeviceID: String = "1c9f5f1e-1111-4222-8333-944455556666",
        macDeviceName: String = "Alex’s Mac",
        createdAt: UInt64 = 1_700_000_000_000
    ) -> RemoteApprovalRequest {
        RemoteApprovalRequest(
            requestID: requestID, macDeviceID: macDeviceID, macDeviceName: macDeviceName,
            createdAtMilliseconds: createdAt, review: review, unlockChallenge: challenge
        )
    }
    func digest(_ request: RemoteApprovalRequest) -> Data? { try? request.digest() }

    let access = v3AccessReviewFixture()
    let ssh = v3SSHReviewFixture()
    let sudo = v3SudoReviewFixture()
    let challenge = RemoteApprovalUnlockChallenge(
        enrollmentID: UUID().uuidString,
        blindedPoint: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
    )
    check(digest(request(access)) != nil && digest(request(access)) == digest(request(RemoteReviewParts(access).review)),
          "v3 wire: an access review with every field validates, and rebuilding it gives the same digest")

    typealias Mutation = (String, (inout RemoteReviewParts) -> Void)
    let accessMutations: [Mutation] = [
        ("headline", { $0.headline = "bin/rails db:drop" }),
        ("caller", { $0.callerDescription = "node (pid 43)" }),
        ("terminal", { $0.terminalDescription = "Terminal · tab 9" }),
        ("terminal removed", { $0.terminalDescription = nil }),
        ("secret provider", { $0.secrets[0] = $0.secrets[0].with(provider: .some("Other")) }),
        ("secret provider removed", { $0.secrets[0] = $0.secrets[0].with(provider: .some(nil)) }),
        ("secret tint", { $0.secrets[0] = $0.secrets[0].with(tint: .purple) }),
        ("secret account", { $0.secrets[0] = $0.secrets[0].with(account: .some("other.1password.com")) }),
        ("secret account removed", { $0.secrets[0] = $0.secrets[0].with(account: .some(nil)) }),
        ("secret vault", { $0.secrets[0] = $0.secrets[0].with(container: .some("Prod")) }),
        ("secret item", { $0.secrets[0] = $0.secrets[0].with(item: "Other") }),
        ("secret field", { $0.secrets[0] = $0.secrets[0].with(field: .some("username")) }),
        ("secret field removed", { $0.secrets[0] = $0.secrets[0].with(field: .some(nil)) }),
        ("secret identifier style", { $0.secrets[0] = $0.secrets[0].with(itemIsIdentifier: true) }),
        ("secret notes", { $0.secrets[0] = $0.secrets[0].with(notes: []) }),
        ("secret warnings", { $0.secrets[0] = $0.secrets[0].with(warnings: []) }),
        ("whole reference", { $0.secrets[1] = $0.secrets[1].with(item: "vault://kv/app/other") }),
        ("secrets reordered", { $0.secrets.reverse() }),
        ("reference set", { $0.referenceSetDigest = Data(repeating: 0x12, count: SHA256.byteCount) }),
        ("emitter name", { $0.delivery = $0.delivery?.with(0, "rubyx") }),
        ("emitter path", { $0.delivery = $0.delivery?.with(1, "/opt/ruby") }),
        ("emitter assurance", { $0.delivery = $0.delivery?.with(2, "Unverified") }),
        ("recipient", { $0.delivery = $0.delivery?.with(3, "requesting terminal") }),
        ("delivery", { $0.delivery = $0.delivery?.with(4, "Injected at launch") }),
        ("destination", { $0.delivery = $0.delivery?.with(5, "Production") }),
        ("warning text", { $0.warnings = ["TERMINAL PLAINTEXT: synthetic banner."] }),
        ("warning removed", { $0.warnings = [] }),
        ("footnote", { $0.footnote = "Other footnote." }),
        ("footnote removed", { $0.footnote = nil }),
        ("restore header", { $0.restore = $0.restore?.with(header: "csecd restarted: reopen what you approved") }),
        ("restore footnote", { $0.restore = $0.restore?.with(footnote: "Touch ID reopens 2 stores.") }),
        ("restore store count", { $0.restore = $0.restore?.with(storeCount: 3) }),
        ("restore row kind", {
            guard let rows = $0.restore?.rows else { return }
            $0.restore = $0.restore?.with(rows: [rows[0].with(kind: "paired_project"), rows[1]])
        }),
        ("restore row title", {
            guard let rows = $0.restore?.rows else { return }
            $0.restore = $0.restore?.with(rows: [rows[0].with(title: "zsh"), rows[1]])
        }),
        ("restore row detail", {
            guard let rows = $0.restore?.rows else { return }
            $0.restore = $0.restore?.with(rows: [rows[0].with(detail: "Requesting process only · pid 7"), rows[1]])
        }),
        ("restore row secrets", {
            guard let rows = $0.restore?.rows else { return }
            $0.restore = $0.restore?.with(rows: [rows[0].with(secrets: [v3NativeSecret("dev", "OTHER")]), rows[1]])
        }),
        ("restore row SSH user", {
            guard let rows = $0.restore?.rows else { return }
            $0.restore = $0.restore?.with(rows: [rows[0], rows[1].with(ssh: .some(v3SSHFacts.with(remoteUser: "root")))])
        }),
        ("restore row SSH removed", {
            guard let rows = $0.restore?.rows else { return }
            $0.restore = $0.restore?.with(rows: [rows[0], rows[1].with(ssh: .some(nil))])
        }),
        ("restore row dropped", {
            guard let rows = $0.restore?.rows else { return }
            $0.restore = $0.restore?.with(rows: [rows[0]])
        }),
        ("restore section removed", { $0.restore = nil }),
        ("scope option id", {
            $0.scopeOptions[0] = .init(id: "requesting_command-42-8", title: $0.scopeOptions[0].title,
                                       detail: $0.scopeOptions[0].detail)
        }),
        ("scope option title", {
            $0.scopeOptions[0] = .init(id: $0.scopeOptions[0].id, title: "Other title", detail: $0.scopeOptions[0].detail)
        }),
        ("scope option detail", {
            $0.scopeOptions[1] = .init(id: $0.scopeOptions[1].id, title: $0.scopeOptions[1].title, detail: "other detail")
        }),
        ("default scope", { $0.defaultScopeID = "requesting_command-42-7" }),
        ("scope options removed", { $0.scopeOptions = []; $0.defaultScopeID = nil }),
        ("duration title", { $0.durationOptions[1] = "2 hours" }),
        ("duration dropped", { $0.durationOptions = ["Until it exits", "1 hour"] }),
        ("default duration", { $0.defaultDurationIndex = 1 }),
        ("durations removed", { $0.durationOptions = []; $0.defaultDurationIndex = nil }),
        ("operation", { $0.operationDigest = Data(repeating: 0x23, count: SHA256.byteCount) }),
    ]
    let sshMutations: [Mutation] = [
        ("SSH host names", { $0.ssh = $0.ssh?.with(hostNames: ["gitlab.com"]) }),
        ("SSH second host name", { $0.ssh = $0.ssh?.with(hostNames: ["github.com", "gh"]) }),
        ("SSH unknown host", { $0.ssh = $0.ssh?.with(hostNames: [], unknownHost: true) }),
        ("SSH host context", { $0.ssh = $0.ssh?.with(hostContext: "These known hosts share the same server identity.") }),
        ("SSH remote user", { $0.ssh = $0.ssh?.with(remoteUser: "root") }),
        ("SSH key label", { $0.ssh = $0.ssh?.with(keyLabel: "other key") }),
        ("SSH key algorithm", { $0.ssh = $0.ssh?.with(keyAlgorithm: "RSA") }),
    ]
    let sudoMutations: [Mutation] = [
        ("sudo command", { $0.sudo = .init(command: "ls /", workingDirectory: "/Users/alex", targetUser: "root") }),
        ("sudo directory", { $0.sudo = .init(command: "ls /var/root", workingDirectory: "/tmp", targetUser: "root") }),
        ("sudo target user", { $0.sudo = .init(command: "ls /var/root", workingDirectory: "/Users/alex", targetUser: nil) }),
    ]
    var unbound: [String] = []
    for (base, mutations) in [(access, accessMutations), (ssh, sshMutations), (sudo, sudoMutations)] {
        let baseDigest = digest(request(base))
        for (name, mutate) in mutations {
            let changed = RemoteReviewParts.changing(base, mutate)
            let changedDigest = digest(request(changed))
            if changedDigest == nil || changedDigest == baseDigest { unbound.append(name) }
        }
    }
    check(unbound.isEmpty && accessMutations.count + sshMutations.count + sudoMutations.count == 60,
          "v3 wire: changing any review field (60 flips across access, SSH and sudo) still validates and changes "
            + "the signed digest (unbound: \(unbound))")

    let requestLevel: [(String, RemoteApprovalRequest)] = [
        ("request ID", request(access, requestID: "0b8f5f1e-1111-4222-8333-944455556667")),
        ("Mac ID", request(access, macDeviceID: "1c9f5f1e-1111-4222-8333-944455556667")),
        ("Mac name", request(access, macDeviceName: "Other Mac")),
        ("created at", request(access, createdAt: 1_700_000_000_001)),
        ("challenge added", request(access, challenge: challenge)),
    ]
    let base = digest(request(access))
    let withChallenge = digest(request(access, challenge: challenge))
    let otherEnrollment = digest(request(access, challenge: RemoteApprovalUnlockChallenge(
        enrollmentID: UUID().uuidString, blindedPoint: challenge.blindedPoint
    )))
    let otherPoint = digest(request(access, challenge: RemoteApprovalUnlockChallenge(
        enrollmentID: challenge.enrollmentID,
        blindedPoint: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
    )))
    check(requestLevel.allSatisfy { digest($0.1) != base }
            && otherEnrollment != withChallenge && otherPoint != withChallenge,
          "v3 wire: the request ID, Mac, time, and the unlock challenge's enrollment and blinded point are all signed")

    // The response signs the selection and the unlock answer: a relay that
    // edits either breaks the phone's signature.
    do {
        let phone = SyntheticPhone()
        let macKey = P256.Signing.PrivateKey()
        let envelope = try SignedRemoteApprovalRequest.signed(request(access, challenge: challenge), by: macKey)
        let answer = P256.KeyAgreement.PrivateKey().publicKey.rawRepresentation.prefix(32)
        let signed = try phone.respond(
            to: envelope, .approve, scopeID: "requesting_command-42-7", durationIndex: 1, unlockAnswer: Data(answer)
        )
        let original = signed.response
        func tampered(scope: String?, duration: UInt16?, answer: Data?) -> SignedRemoteApprovalResponse {
            SignedRemoteApprovalResponse(
                response: RemoteApprovalResponse(
                    requestID: original.requestID, requestDigest: original.requestDigest,
                    phoneDeviceID: original.phoneDeviceID, decision: original.decision,
                    decidedAtMilliseconds: original.decidedAtMilliseconds, selectedScopeID: scope,
                    selectedDurationIndex: duration, unlockAnswer: answer, phoneAppVersion: original.phoneAppVersion
                ),
                signatureDER: signed.signatureDER
            )
        }
        func rejects(_ envelope: SignedRemoteApprovalResponse) -> Bool {
            do {
                try envelope.verify(
                    for: request(access, challenge: challenge),
                    pinnedPhoneDeviceID: phone.deviceID,
                    phonePublicKeyX963: phone.signingKey.publicKey.x963Representation
                )
                return false
            } catch {
                return error as? RemoteApprovalValidationError == .invalidSignature
            }
        }
        let honest = (try? signed.verify(
            for: request(access, challenge: challenge),
            pinnedPhoneDeviceID: phone.deviceID,
            phonePublicKeyX963: phone.signingKey.publicKey.x963Representation
        )) ?? nil
        check(honest == RemoteApprovalSelection(
            scopeOptionID: "requesting_command-42-7", durationIndex: 1, unlockAnswer: Data(answer)
        ), "v3 wire: an untampered approval verifies with exactly its signed selection and answer")
        let otherAnswer = Data(P256.KeyAgreement.PrivateKey().publicKey.rawRepresentation.prefix(32))
        check(rejects(tampered(scope: "terminal_session-7-1", duration: 1, answer: Data(answer)))
                && rejects(tampered(scope: "requesting_command-42-7", duration: 2, answer: Data(answer)))
                && rejects(tampered(scope: "requesting_command-42-7", duration: 1, answer: otherAnswer)),
              "v3 wire: the phone's signature covers its scope, its lifetime and its unlock answer")
    } catch {
        check(false, "v3 wire: response binding fixtures (\(error))")
    }
}

private func v3KindConsistencyTests() {
    func error(_ review: RemoteApprovalReview) -> RemoteApprovalValidationError? {
        do {
            try review.validate()
            return nil
        } catch {
            return error as? RemoteApprovalValidationError
        }
    }
    let access = v3AccessReviewFixture()
    let ssh = v3SSHReviewFixture()
    let sudo = v3SudoReviewFixture()
    let restoreOnly = RemoteReviewParts.changing(access) {
        $0.kind = .restore; $0.secrets = []; $0.delivery = nil
        $0.scopeOptions = []; $0.defaultScopeID = nil; $0.durationOptions = []; $0.defaultDurationIndex = nil
    }
    check(error(access) == nil && error(ssh) == nil && error(sudo) == nil && error(restoreOnly) == nil,
          "v3 kinds: an access, SSH, sudo and restore-only review each validate with exactly their own facts")
    let inconsistent: [(String, RemoteApprovalReview)] = [
        ("access without delivery", RemoteReviewParts.changing(access) { $0.delivery = nil }),
        ("access without secrets", RemoteReviewParts.changing(access) { $0.secrets = [] }),
        ("access with SSH facts", RemoteReviewParts.changing(access) { $0.ssh = v3SSHFacts }),
        ("access with sudo facts", RemoteReviewParts.changing(access) { $0.sudo = sudo.sudo }),
        ("SSH without SSH facts", RemoteReviewParts.changing(ssh) { $0.ssh = nil }),
        ("SSH with a restore section", RemoteReviewParts.changing(ssh) { $0.restore = access.restore }),
        ("sudo with secrets", RemoteReviewParts.changing(sudo) { $0.secrets = access.secrets }),
        ("sudo with scope options", RemoteReviewParts.changing(sudo) {
            $0.scopeOptions = access.scopeOptions; $0.defaultScopeID = access.defaultScopeID
        }),
        ("sudo without sudo facts", RemoteReviewParts.changing(sudo) { $0.sudo = nil }),
        ("restore with delivery", RemoteReviewParts.changing(restoreOnly) { $0.delivery = access.delivery }),
        ("restore with durations", RemoteReviewParts.changing(restoreOnly) {
            $0.durationOptions = ["1 hour"]; $0.defaultDurationIndex = 0
        }),
        ("restore without its section", RemoteReviewParts.changing(restoreOnly) { $0.restore = nil }),
    ]
    let wrong = inconsistent.filter { error($0.1) != .inconsistentKind }.map(\.0)
    check(wrong.isEmpty, "v3 kinds: each kind carrying another kind's facts is inconsistentKind (not: \(wrong))")
    check(error(RemoteReviewParts.changing(ssh) { $0.ssh = v3SSHFacts.with(unknownHost: true) }) == .fieldOutOfBounds
            && error(RemoteReviewParts.changing(ssh) { $0.ssh = v3SSHFacts.with(hostNames: []) }) == .fieldOutOfBounds,
          "v3 kinds: an unknown-host flag that disagrees with the host names is refused")
    check(error(RemoteReviewParts.changing(access) { $0.defaultScopeID = "unknown" }) == .invalidSelection
            && error(RemoteReviewParts.changing(access) { $0.defaultDurationIndex = 3 }) == .invalidSelection
            && error(RemoteReviewParts.changing(access) { $0.defaultScopeID = nil }) == .invalidSelection,
          "v3 kinds: a default scope or lifetime the review does not offer is refused")
}

/// Every malformed decision is `.rejected`, never a denial, and the request
/// stays pending until a well-formed one arrives.
private func v3AcceptanceRuleTests() async {
    let phone = SyntheticPhone()
    let macKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()
    func makeRequester(_ relay: V3MailboxRelay) throws -> RemoteApprovalRequester {
        try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: macDeviceID, macDeviceName: "Alex’s Mac",
                pinnedPhoneDeviceID: phone.deviceID,
                pinnedPhonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: V3SoftwareSigner(key: macKey),
            relay: relay
        )
    }
    let validAnswer = Data(P256.KeyAgreement.PrivateKey().publicKey.rawRepresentation.prefix(32))

    // A review offering a scope and a lifetime, with no unlock challenge.
    do {
        let relay = V3MailboxRelay()
        let requester = try makeRequester(relay)
        let pending = Task { await requester.requestApproval(for: v3AccessReviewFixture(withRestore: false)) }
        guard let envelope = await v3WaitForRequest(relay) else {
            pending.cancel()
            check(false, "v3 acceptance: the request reaches the mailbox")
            return
        }
        let offered = envelope.request.review
        let rules: [(String, SignedRemoteApprovalResponse, RemoteApprovalValidationError)] = [
            ("an unknown scope ID", try phone.respond(to: envelope, .approve, scopeID: "terminal_session-1-1",
                                                     durationIndex: 0), .invalidSelection),
            ("an out-of-range lifetime", try phone.respond(to: envelope, .approve, scopeID: offered.defaultScopeID,
                                                          durationIndex: 3), .invalidSelection),
            ("a missing scope", try phone.respond(to: envelope, .approve, durationIndex: 0), .invalidSelection),
            ("a missing lifetime", try phone.respond(to: envelope, .approve, scopeID: offered.defaultScopeID),
             .invalidSelection),
            ("a denial with a scope", try phone.respond(to: envelope, .deny, scopeID: offered.defaultScopeID),
             .invalidSelection),
            ("a denial with a lifetime", try phone.respond(to: envelope, .deny, durationIndex: 0), .invalidSelection),
            ("an unlock answer nobody asked for", try phone.respond(
                to: envelope, .approve, scopeID: offered.defaultScopeID, durationIndex: 0, unlockAnswer: validAnswer
            ), .invalidUnlockAnswer),
            ("a denial with an unlock answer", try phone.respond(to: envelope, .deny, unlockAnswer: validAnswer),
             .invalidUnlockAnswer),
        ]
        var wrong: [String] = []
        for (name, response, expected) in rules where await requester.accept(response) != .rejected(expected) {
            wrong.append(name)
        }
        let stillPending = await requester.isPending(requestID: envelope.request.requestID)
        check(wrong.isEmpty && stillPending,
              "v3 acceptance: an unknown scope, an out-of-range lifetime, a missing selection, a selection on a "
                + "denial and an unasked unlock answer are each rejected, and the request stays pending (\(wrong))")

        // Through the mailbox: a bad decision is waited through, not treated
        // as an answer, and the phone's corrected approval then counts.
        try await relay.publishResponse(try phone.respond(
            to: envelope, .approve, scopeID: "unknown-scope", durationIndex: 0
        ))
        let pollsBefore = await relay.polls
        _ = await eventuallyTrue { await relay.polls >= pollsBefore + 3 }
        let waitedThrough = await requester.isPending(requestID: envelope.request.requestID)
        try await relay.publishResponse(try phone.respond(
            to: envelope, .approve, scopeID: "requesting_command-42-7", durationIndex: 2
        ))
        let result = await pending.value
        check(waitedThrough && result == .approved(RemoteApprovalSelection(
            scopeOptionID: "requesting_command-42-7", durationIndex: 2, unlockAnswer: nil
        )), "v3 acceptance: a rejected mailbox decision is waited through; the phone's valid selection is what is returned")
    } catch {
        check(false, "v3 acceptance: selection rules (\(error))")
    }

    // A review that offers no choice: any selection is refused.
    do {
        let relay = V3MailboxRelay()
        let requester = try makeRequester(relay)
        let pending = Task { await requester.requestApproval(for: v3SudoReviewFixture()) }
        guard let envelope = await v3WaitForRequest(relay) else {
            pending.cancel()
            check(false, "v3 acceptance: the choiceless request reaches the mailbox")
            return
        }
        let scoped = await requester.accept(try phone.respond(to: envelope, .approve, scopeID: "requesting_command-1-1"))
        let timed = await requester.accept(try phone.respond(to: envelope, .approve, durationIndex: 0))
        try await relay.publishResponse(try phone.respond(to: envelope, .approve))
        let result = await pending.value
        check(scoped == .rejected(.invalidSelection) && timed == .rejected(.invalidSelection)
                && result == .approved(remoteApprovalNoSelection),
              "v3 acceptance: a selection on a review that offered none is rejected; a plain approval is accepted")
    } catch {
        check(false, "v3 acceptance: choiceless rules (\(error))")
    }

    // A request carrying an unlock challenge.
    do {
        let relay = V3MailboxRelay()
        let requester = try makeRequester(relay)
        let challenge = RemoteApprovalUnlockChallenge(
            enrollmentID: UUID().uuidString,
            blindedPoint: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
        )
        let pending = Task {
            await requester.requestApproval(for: v3SudoReviewFixture(), unlockChallenge: challenge)
        }
        guard let envelope = await v3WaitForRequest(relay) else {
            pending.cancel()
            check(false, "v3 acceptance: the challenged request reaches the mailbox")
            return
        }
        let notOnCurve = Data(repeating: 0xff, count: 32)
        let unanswered = await requester.accept(try phone.respond(to: envelope, .approve))
        let offCurve = await requester.accept(try phone.respond(to: envelope, .approve, unlockAnswer: notOnCurve))
        let deniedWithAnswer = await requester.accept(try phone.respond(to: envelope, .deny, unlockAnswer: validAnswer))
        // A short answer cannot even be signed; offered unsigned it is still
        // refused as an answer, before the signature is looked at.
        let honest = try phone.respond(to: envelope, .approve, unlockAnswer: validAnswer)
        let truncated = SignedRemoteApprovalResponse(
            response: RemoteApprovalResponse(
                requestID: honest.response.requestID, requestDigest: honest.response.requestDigest,
                phoneDeviceID: honest.response.phoneDeviceID, decision: .approve,
                decidedAtMilliseconds: honest.response.decidedAtMilliseconds,
                unlockAnswer: validAnswer.prefix(31), phoneAppVersion: "1.0 (7)"
            ),
            signatureDER: honest.signatureDER
        )
        let short = await requester.accept(truncated)
        let stillPending = await requester.isPending(requestID: envelope.request.requestID)
        check(unanswered == .rejected(.invalidUnlockAnswer) && offCurve == .rejected(.invalidUnlockAnswer)
                && deniedWithAnswer == .rejected(.invalidUnlockAnswer) && short == .rejected(.invalidUnlockAnswer)
                && stillPending,
              "v3 acceptance: a missing, off-curve or short unlock answer, or one on a denial, is rejected and the "
                + "request stays pending")
        try await relay.publishResponse(honest)
        let result = await pending.value
        check(result == .approved(RemoteApprovalSelection(scopeOptionID: nil, durationIndex: nil, unlockAnswer: validAnswer)),
              "v3 acceptance: the challenged request is approved with exactly the phone's signed answer")
        // A denial is a denial: it stays distinct from every rejection above.
        let denyRelay = V3MailboxRelay()
        let denyRequester = try makeRequester(denyRelay)
        let denied = Task { await denyRequester.requestApproval(for: v3SudoReviewFixture(), unlockChallenge: challenge) }
        if let denyEnvelope = await v3WaitForRequest(denyRelay) {
            try await denyRelay.publishResponse(try phone.respond(to: denyEnvelope, .deny))
            if case .denied = await denied.value {
                check(true, "v3 acceptance: a plain phone Deny of a challenged request is a denial")
            } else {
                check(false, "v3 acceptance: a plain phone Deny of a challenged request is a denial")
            }
        } else {
            denied.cancel()
            check(false, "v3 acceptance: the denied request reaches the mailbox")
        }
    } catch {
        check(false, "v3 acceptance: unlock rules (\(error))")
    }
}

// MARK: - Pairing

private func v3PairingTests() async {
    let phone = SyntheticPhone()
    let stranger = P256.Signing.PrivateKey()
    do {
        let pairing = try phone.pairing()
        try pairing.validate()
        let code = try RemoteApprovalPairingCode.encodePhone(pairing)
        let decoded = try RemoteApprovalPairingCode.decodePhone(code)
        check(code.hasPrefix("csec-phone-v2:") && decoded == pairing,
              "pairing v2: a phone code vouching for its key-agreement key round-trips")

        let wrongSigner = try phone.pairing(vouchedBy: stranger)
        var refusedSigner = false
        do { _ = try RemoteApprovalPairingCode.decodePhone(try unvalidatedPhoneCode(wrongSigner)) } catch {
            refusedSigner = error as? RemoteApprovalValidationError == .invalidSignature
        }
        let swapped = try phone.pairing(keyAgreementKey: P256.KeyAgreement.PrivateKey().publicKey)
        var refusedSwap = false
        do { _ = try RemoteApprovalPairingCode.decodePhone(try unvalidatedPhoneCode(swapped)) } catch {
            refusedSwap = error as? RemoteApprovalValidationError == .invalidSignature
        }
        check(refusedSigner && refusedSwap,
              "pairing v2: a key-agreement key vouched for by another key, or not the key that was vouched for, is refused")
        var refusedV1 = false
        do { _ = try RemoteApprovalPairingCode.decodePhone("csec-phone-v1:e30") } catch { refusedV1 = true }
        check(refusedV1, "pairing v2: a v1 phone code is refused rather than read")

        // The Mac pins the key-agreement key from a vouched-for code only.
        let consent = V3CountingConsent()
        let store = V3MemoryConfigurationStore()
        let manager = v3Manager(store: store, relay: V3MailboxRelay(), consent: consent)
        do {
            _ = try await manager.enable(phonePairingCode: try unvalidatedPhoneCode(wrongSigner), caller: setupCaller)
            check(false, "pairing v2: enable refuses a code whose key-agreement key is not vouched for")
        } catch {
            let touched = await consent.authentications
            let pinned = await store.current()
            check(touched == 0 && pinned == nil,
                  "pairing v2: enable refuses a code whose key-agreement key is not vouched for, before the Touch ID")
        }
        _ = try await manager.enable(phonePairingCode: try phone.pairingCode, caller: setupCaller)
        let stored = await store.current()
        check(stored?.phoneKeyAgreementPublicKeyX963 == phone.keyAgreementKey.publicKey.x963Representation
                && stored?.version == RemoteApprovalProtocolV3.pairingVersion,
              "pairing v2: enabling pins the phone's key-agreement key in a v2 record")

        // Confirmation and status: signed by the pinned phone, bound to this pairing.
        guard let stored else { return }
        let confirmation = RemoteApprovalPairingConfirmation(
            macDeviceID: stored.macDeviceID, macPublicKeyX963: stored.macPublicKeyX963,
            phoneDeviceID: phone.deviceID,
            phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
            phoneAppVersion: "1.0 (7)", createdAtMilliseconds: currentTimeMilliseconds()
        )
        func verify(_ confirmation: RemoteApprovalPairingConfirmation, by key: P256.Signing.PrivateKey) -> RemoteApprovalValidationError? {
            do {
                try SignedRemoteApprovalPairingConfirmation(
                    confirmation: confirmation,
                    signatureDER: try key.signature(for: confirmation.signingData()).derRepresentation
                ).verify(
                    macDeviceID: stored.macDeviceID, macPublicKeyX963: stored.macPublicKeyX963,
                    phoneDeviceID: phone.deviceID, phonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
                    phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation
                )
                return nil
            } catch {
                return error as? RemoteApprovalValidationError ?? .invalidSignature
            }
        }
        let otherKeyAgreement = RemoteApprovalPairingConfirmation(
            macDeviceID: stored.macDeviceID, macPublicKeyX963: stored.macPublicKeyX963,
            phoneDeviceID: phone.deviceID,
            phoneKeyAgreementPublicKeyX963: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
            phoneAppVersion: "1.0 (7)", createdAtMilliseconds: currentTimeMilliseconds()
        )
        check(verify(confirmation, by: phone.signingKey) == nil
                && verify(confirmation, by: stranger) == .invalidSignature
                && verify(otherKeyAgreement, by: phone.signingKey) == .wrongRequest,
              "pairing v2: the confirmation verifies only from the pinned phone, for the key-agreement key the Mac enrolled")
        let status = RemoteApprovalPhoneStatus(
            phoneDeviceID: phone.deviceID, appVersion: "1.0 (7)", notificationsAuthorized: true,
            updatedAtMilliseconds: currentTimeMilliseconds()
        )
        let signedStatus = SignedRemoteApprovalPhoneStatus(
            status: status, signatureDER: try phone.signingKey.signature(for: status.signingData()).derRepresentation
        )
        let forgedStatus = SignedRemoteApprovalPhoneStatus(
            status: status, signatureDER: try stranger.signature(for: status.signingData()).derRepresentation
        )
        var forgedRefused = false
        do {
            try forgedStatus.verify(phoneDeviceID: phone.deviceID, phonePublicKeyX963: phone.signingKey.publicKey.x963Representation)
        } catch { forgedRefused = true }
        try signedStatus.verify(phoneDeviceID: phone.deviceID, phonePublicKeyX963: phone.signingKey.publicKey.x963Representation)
        check(forgedRefused, "pairing v2: the phone status verifies only with the pinned phone's signature")
    } catch {
        check(false, "pairing v2 fixtures (\(error))")
    }

    // A pairing an older build stored reads as outdated, never as corrupt,
    // and never crashes; disable removes it behind one Touch ID.
    do {
        let macDeviceID = UUID().uuidString.lowercased()
        let v1: [String: Any] = [
            "version": 1, "macDeviceID": macDeviceID, "macDeviceName": "Mac",
            "macSigningKeyRepresentation": Data([1, 2, 3]).base64EncodedString(),
            "macPublicKeyX963": P256.Signing.PrivateKey().publicKey.x963Representation.base64EncodedString(),
            "phoneDeviceID": phone.deviceID, "phoneDeviceName": "iPhone",
            "phonePublicKeyX963": phone.signingKey.publicKey.x963Representation.base64EncodedString(),
            "cloudKitContainerIdentifier": CSECBuildIdentity.cloudKitContainer,
        ]
        let raw = try JSONSerialization.data(withJSONObject: v1)
        var outdatedID: String??
        do { _ = try StoredRemoteApprovalConfiguration.decodeStored(raw) } catch let
            RemoteApprovalConfigurationStoreError.outdated(identifier) { outdatedID = .some(identifier) }
        check(outdatedID == .some(macDeviceID),
              "pairing v2: a stored v1 record decodes as outdated, naming its Mac ID")
        let consent = V3CountingConsent()
        let store = V3MemoryConfigurationStore(raw: raw)
        let log = V3LogLines()
        let manager = v3Manager(store: store, relay: V3MailboxRelay(), consent: consent, log: log)
        await manager.prepare()
        check(await manager.status() == .pairingInvalid(.outdated)
                && log.all.contains { $0.contains("(outdated)") && $0.contains("csec remote disable") },
              "pairing v2: a v1 pairing surfaces as pairingInvalid(outdated) with its fix")
        check(await manager.remoteReadiness(for: [try SecretRef("op://v/i/f")]) == .unavailable,
              "pairing v2: an outdated pairing mirrors nothing")
        try await manager.disable(caller: setupCaller)
        let touches = await consent.authentications
        let deletes = await store.deletes
        let afterDisable = await manager.status()
        check(touches == 1 && deletes == 1 && afterDisable == .disabled,
              "pairing v2: disable removes an outdated pairing behind one Touch ID")
    } catch {
        check(false, "pairing v2: outdated record (\(error))")
    }
}

// MARK: - Review builder

func v3AutomationDetails() -> AutomationReviewDetails {
    AutomationReviewDetails(job: AutomationJob(
        id: UUID().uuidString.lowercased(), revision: UUID().uuidString.lowercased(),
        name: "backup", reason: "nightly backup", references: ["csec://dev/X"],
        command: AutomationCommand(
            executable: PlannedExecutable(canonicalPath: "/usr/bin/true", assurance: .unverified),
            commandLine: ["/usr/bin/true"], workingDirectory: "/tmp",
            commandDigest: String(repeating: "0", count: 64)
        ),
        minimumIntervalSeconds: 60, maximumRuntimeSeconds: 60, consumerTrust: .mutableInterpreted,
        createdAt: Date(), updatedAt: Date()
    ))
}

private func v3BuilderPlan(
    mechanism: DeliveryMechanism = .directHeap,
    recipient: RecipientAssurance? = nil,
    interactive: Bool = false
) -> DeliveryPlan {
    DeliveryPlan(
        mechanism: mechanism,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
        descendantScope: .subtree,
        destination: .localDevelopment,
        recipientAssurance: recipient,
        requestedTTLSeconds: nil,
        operationContext: "run migrations",
        interactive: interactive
    )
}

private func v3ReviewBuilderTests() {
    typealias Limit = RemoteApprovalReview.FieldLimit
    let caller = CallerInfo(pid: 42, startTime: 7, description: "ruby [protected] (pid 42)")
    let scopeChoices = GrantScopeChoices(
        options: [
            GrantScopeOption(kind: .requestingCommand, pid: 42, startTime: 7, processLabel: "ruby"),
            GrantScopeOption(kind: .codingAgent, pid: 30, startTime: 3, processLabel: "Claude Code"),
            GrantScopeOption(kind: .terminalSession, pid: 20, startTime: 2, processLabel: "fish"),
        ],
        defaultOptionID: "coding_agent-30-3"
    )
    let durations = GrantDurationChoices.offered(requestedTTLSeconds: nil)
    let described = v3OnePasswordSecret(
        "Development", "Database", "password", warnings: ["two accounts are signed in"]
    )
    let access = AccessPolicyReview(
        caller: caller, reason: "run migrations",
        plan: v3BuilderPlan(mechanism: .rawStandardOutput, recipient: .interactiveTerminal, interactive: false),
        commandLine: "bin/rails db:migrate",
        credentials: [PolicyReviewCredential(
            described: [(try! SecretRef("op://Development/Database/password"), described)]
        )],
        scopeChoices: scopeChoices, durationChoices: durations
    )
    do {
        let frozen = try RemoteApprovalReview(accessPolicyReview: access)
        let planDigest = try access.plan.digest()
        check(frozen.kind == .access && frozen.secrets == access.credentials[0].secrets
                && frozen.secrets == [described],
              "v3 review: each secret carries what the Mac tree draws: account, vault, item, field, tint and warnings")
        let banner = DeliveryReviewCopy.warning(for: access)
        check(banner != nil && frozen.warnings == [banner!] && frozen.warnings[0].contains("\n\n"),
              "v3 review: the Mac panel's banner warning is the phone's, paragraph break kept")
        check(frozen.footnote == DeliveryReviewCopy.releaseFootnote
                && frozen.footnote == DeliveryReviewCopy.footnote(for: access),
              "v3 review: the footnote is the Mac release panel's footnote")
        check(frozen.headline == "bin/rails db:migrate" && frozen.callerDescription == caller.description,
              "v3 review: the headline is the redacted command line")
        check(frozen.scopeOptions.map(\.id) == scopeChoices.options.map(\.id)
                && frozen.scopeOptions.map(\.title) == scopeChoices.options.map(ReviewDisplay.scopeTitle)
                && frozen.scopeOptions.map(\.detail) == scopeChoices.options.map(ReviewDisplay.scopeDetail)
                && frozen.defaultScopeID == "coding_agent-30-3",
              "v3 review: scope options carry exactly the Mac panel's radio titles and details, default included")
        check(frozen.durationOptions == durations.options.map(ReviewDisplay.durationTitle(for:))
                && frozen.durationOptions == ["Until it exits", "1 hour", "12 hours"]
                && frozen.defaultDurationIndex == UInt16(durations.defaultIndex),
              "v3 review: lifetimes are the Mac popup's titles in its order, default included")
        check(frozen.delivery?.emitterName == "ruby" && frozen.delivery?.emitterPath == "/usr/bin/ruby"
                && frozen.delivery?.deliveryDescription == "Raw standard output · process and its descendants"
                && frozen.delivery?.recipientDescription == DeliveryReviewCopy.recipientDescription(for: access.plan),
              "v3 review: delivery facts are the Mac panel's")
        check(frozen.operationDigest.count == SHA256.byteCount
                && frozen.operationDigest.map { String(format: "%02x", $0) }.joined() == planDigest,
              "v3 review: an access review's operation digest is its delivery plan digest")
    } catch {
        check(false, "v3 review: access review builds (\(error))")
    }

    // SSH: unknown and known hosts.
    let sshPlan = DeliveryPlan(
        mechanism: .credentialProtocol,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
        descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
    )
    let sshChoices = GrantScopeChoices(
        options: [
            GrantScopeOption(kind: .requestingCommand, pid: 51, startTime: 9, processLabel: "ssh"),
            GrantScopeOption(kind: .terminalSession, pid: 20, startTime: 2, processLabel: "fish"),
        ],
        defaultOptionID: "terminal_session-20-2"
    )
    func sshReview(_ hosts: [String]) -> AccessPolicyReview {
        let details = SSHAccessReviewDetails(hostNames: hosts, remoteUser: "git", keyLabel: "work", keyAlgorithm: "ssh-ed25519")
        return AccessPolicyReview(
            caller: CallerInfo(pid: 51, startTime: 9, description: "Apple SSH [verified] (pid 51)"),
            reason: details.reason, plan: sshPlan,
            credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/id_ed25519")])],
            scopeChoices: sshChoices, durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil),
            ssh: details
        )
    }
    do {
        let unknown = try RemoteApprovalReview(accessPolicyReview: sshReview([]))
        check(unknown.kind == .ssh && unknown.ssh?.hostNames == [] && unknown.ssh?.unknownHost == true
                && unknown.warnings == [DeliveryReviewCopy.unknownHostWarning]
                && unknown.footnote == DeliveryReviewCopy.sshFootnote
                && unknown.ssh?.hostContext == "No hostname found in known_hosts."
                && unknown.ssh?.keyAlgorithm == "Ed25519" && unknown.ssh?.remoteUser == "git",
              "v3 review: an unknown SSH host has no names, the UNKNOWN HOST warning, and the signature-only footnote")
        let known = try RemoteApprovalReview(accessPolicyReview: sshReview(["github.com"]))
        check(known.ssh?.hostNames == ["github.com"] && known.ssh?.unknownHost == false && known.warnings.isEmpty
                && known.headline == "SSH to github.com as git using work",
              "v3 review: a known SSH host names it, with no warning")
        check(known.scopeOptions.map(\.title) == sshChoices.options.map(ReviewDisplay.sshScopeTitle)
                && known.scopeOptions.map(\.detail) == sshChoices.options.map(ReviewDisplay.sshScopeDetail)
                && known.defaultScopeID == "terminal_session-20-2",
              "v3 review: SSH scope options use the SSH panel's vocabulary")
    } catch {
        check(false, "v3 review: SSH review builds (\(error))")
    }

    // Restore-only and mixed.
    let details = SSHAccessReviewDetails(hostNames: ["github.com"], remoteUser: "git", keyLabel: "work", keyAlgorithm: "ssh-ed25519")
    let rows = [
        RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
                         references: ["csec://dev/API_TOKEN"]),
        RestoreReviewRow(kind: .sshGrant, title: "ssh", detail: "This SSH command · pid 51",
                         references: ["csec://dev/id_ed25519"], ssh: RestoreReviewRow.SSH(details)),
        RestoreReviewRow(kind: .pairedProject, title: "app", detail: "Claude Code auto mode in ~/app",
                         references: ["op://Development/Database/password"]),
    ]
    let restore = RestoreReviewDetails(cause: .restart, rows: rows, storeCount: 2)
    do {
        let only = try RemoteApprovalReview(accessPolicyReview: .restoreOnly(caller: caller, restore: restore))
        check(only.kind == .restore && only.secrets.isEmpty && only.delivery == nil
                && only.scopeOptions.isEmpty && only.durationOptions.isEmpty
                && only.footnote == restore.footnote && only.restore?.footnote == restore.footnote
                && only.headline == restore.header && only.restore?.header == restore.header
                && only.restore?.storeCount == 2,
              "v3 review: a restore-only review carries its header, its footnote and no choice")
        check(only.restore?.rows.map(\.kind) == ["secret_grant", "ssh_grant", "paired_project"]
                && only.restore?.rows[1].ssh?.hostNames == ["github.com"]
                && only.restore?.rows[1].ssh?.keyAlgorithm == "Ed25519"
                && only.restore?.rows[0].secrets == [ReviewDisplay.undescribedSecret(try! SecretRef("csec://dev/API_TOKEN"))],
              "v3 review: restore rows keep their kind, secrets and SSH facts")
        let reordered = try RemoteApprovalReview(accessPolicyReview: .restoreOnly(
            caller: caller,
            restore: RestoreReviewDetails(cause: .restart, rows: [rows[0], rows[1]], storeCount: 2)
        ))
        check(only.operationDigest == RemoteApprovalReview.restoreOperationDigest(rows)
                && only.operationDigest != reordered.operationDigest,
              "v3 review: a restore's operation digest is over exactly the rows it reopens")
        let mixed = try RemoteApprovalReview(accessPolicyReview: AccessPolicyReview(
            caller: caller, reason: "run", plan: v3BuilderPlan(),
            credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/NEW")])],
            scopeChoices: scopeChoices, durationChoices: durations, restore: restore
        ))
        let plain = try RemoteApprovalReview(accessPolicyReview: AccessPolicyReview(
            caller: caller, reason: "run", plan: v3BuilderPlan(),
            credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/NEW")])],
            scopeChoices: scopeChoices, durationChoices: durations
        ))
        check(mixed.kind == .access && mixed.restore?.footnote == restore.mixedFootnote
                && mixed.footnote == DeliveryReviewCopy.releaseFootnote && !mixed.scopeOptions.isEmpty
                && mixed.referenceSetDigest != plain.referenceSetDigest,
              "v3 review: a release with a restore section keeps its choices, uses the mixed note, and binds the rows' references")
    } catch {
        check(false, "v3 review: restore reviews build (\(error))")
    }

    // Length never keeps a review off the phone.
    let long = (0..<200).map { "echo line \($0) \(String(repeating: "x", count: 12))" }.joined(separator: "\n")
    do {
        check(long.utf8.count > 5_000, "v3 review: fixture is a multi-line command over 5,000 bytes (\(long.utf8.count))")
        let frozen = try RemoteApprovalReview(accessPolicyReview: AccessPolicyReview(
            caller: CallerInfo(pid: 42, startTime: 7, description: String(repeating: "c", count: 3_000)),
            reason: "run", plan: v3BuilderPlan(), commandLine: long,
            credentials: [PolicyReviewCredential(described: [(
                try! SecretRef("op://" + String(repeating: "V", count: 900) + "/Item/password"),
                v3OnePasswordSecret(
                    String(repeating: "V", count: 900), "Item", "password",
                    account: String(repeating: "界", count: 400)
                )
            )])]
        ))
        try frozen.validate()
        check(frozen.headline.utf8.count <= Limit.headline && frozen.headline.hasSuffix("…")
                && frozen.headline.contains("\n") && frozen.headline.hasPrefix("echo line 0")
                && frozen.callerDescription.utf8.count <= Limit.callerDescription,
              "v3 review: a 5,000-byte multi-line command is fitted to the 2 KiB headline, newlines kept, and validates")
    } catch {
        check(false, "v3 review: a long multi-line command still builds (\(error))")
    }
    do {
        _ = try RemoteApprovalReview(accessPolicyReview: AccessPolicyReview(
            caller: caller, reason: "enroll", plan: v3BuilderPlan(),
            credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/X")])],
            automation: v3AutomationDetails()
        ))
        check(false, "v3 review: an automation enrollment is never frozen for the phone")
    } catch {
        check(true, "v3 review: an automation enrollment is never frozen for the phone")
    }
}

// MARK: - Readiness and the phone-held unlock factor, end to end

/// What survives a simulated csecd restart: every backend. Each boot builds
/// fresh actors over them, so native storage starts cold, as after a restart.
private struct V3World {
    let docKeys = InMemoryNativeStoreKeyBackend()
    let docFiles = InMemoryNativeStoreFileBackend()
    let cacheItems = RemoteUnlockFakeKeychain()
    let items = InMemoryRemoteUnlockItemBackend()
    /// Like 1Password: resolves behind its own authorization, needs no unlock.
    let remoteLike = RemoteCoverageFixtureProvider(
        scheme: "op", needsUnlock: false, opensRemotely: false, value: "synthetic-op-value"
    )
    /// A sealed provider with no remote-unlock mirrors: needs an unlock no
    /// phone approval can open.
    let sealed = RemoteCoverageFixtureProvider(
        scheme: "vault", needsUnlock: true, opensRemotely: false, value: "synthetic-vault-value"
    )
    /// A sealed provider that keeps its own remote-unlock mirrors.
    let mirrored = RemoteCoverageFixtureProvider(
        scheme: "keyring", needsUnlock: true, opensRemotely: true, value: "synthetic-keyring-value"
    )
}

private struct V3Run {
    let store: RemoteUnlockStore
    let provider: NativeEncryptedFileProvider
    let resolver: SecretResolver
}

private let v3LastRun = CsecdLastRun(
    bootSessionUUID: "synthetic-boot", pid: 4242, startTimeMicros: 1, cdHash: "build-v3", version: nil
)

private func v3Boot(_ world: V3World, previous: CsecdLastRun?) async -> V3Run {
    let store = RemoteUnlockStore(backend: world.items, buildIdentity: "build-v3")
    _ = await store.reconcileEpoch(previousRun: previous)
    let provider = NativeEncryptedFileProvider(
        keyBackend: world.docKeys, fileBackend: world.docFiles, remoteUnlock: store
    )
    let resolver = SecretResolver(cache: KeychainSecretCache(backend: world.cacheItems, remoteUnlock: store))
    await resolver.register(provider)
    await resolver.register(world.remoteLike)
    await resolver.register(world.sealed)
    await resolver.register(world.mirrored)
    return V3Run(store: store, provider: provider, resolver: resolver)
}

/// Records what the phone leg returned, so a test can check an unlock was
/// dropped once its request was done with it.
actor V3SpyRemote: RemoteAccessPolicyReviewProvider {
    let inner: any RemoteAccessPolicyReviewProvider
    private(set) var readinessCalls = 0
    private(set) var reviews = 0
    private(set) var unlocks: [CacheUnlock] = []

    init(_ inner: any RemoteAccessPolicyReviewProvider) { self.inner = inner }

    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        readinessCalls += 1
        return await inner.remoteReadiness(for: references, restoring: restoring)
    }

    func remoteSettingsReadiness() async -> RemoteReviewReadiness {
        readinessCalls += 1
        return await inner.remoteSettingsReadiness()
    }

    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        reviews += 1
        let result = await inner.reviewRemoteAccess(review, unlock: unlock)
        if case let .approved(_, unlock?) = result { unlocks.append(unlock) }
        return result
    }
}

/// The Mac panel left up: it answers only by being cancelled.
actor V3UnansweredLocal: PolicyReviewProvider {
    private(set) var reviews = 0
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews += 1
        while !Task.isCancelled { try? await Task.sleep(nanoseconds: 10_000_000) }
        return .denied(.requesterGone)
    }
}

/// A local panel that fails after a short delay.
private struct V3QuickFailure: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        try? await Task.sleep(nanoseconds: 50_000_000)
        return .denied(.authenticationFailed)
    }
}

private actor V3RestoreSource: RestoredGrantSource {
    let entries: [RestoreEntry]
    private(set) var settled: [Set<UUID>] = []
    init(_ entries: [RestoreEntry]) { self.entries = entries }
    func restoreEntries() async -> [RestoreEntry] { settled.isEmpty ? entries : [] }
    func settleRestore(forgetting: Set<UUID>) async -> Int {
        settled.append(forgetting)
        return forgetting.count
    }
}

/// Live ancestry, except that this process's parent reads as the terminal
/// session's shell and nothing above it is a coding agent, so the scope
/// options are exactly [this command, the terminal session].
func v3Inspection() -> ProcessInspection {
    let me = getpid()
    let parent = ProcessAncestry.parent(of: me)
    return ProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) },
        parent: { ProcessAncestry.parent(of: $0) },
        name: { pid in pid == parent ? "zsh" : (pid == me ? ProcessAncestry.name(of: pid) : nil) },
        executablePath: { pid in
            pid == parent ? "/bin/zsh" : (pid == me ? ProcessAncestry.executablePath(of: pid) : nil)
        },
        hasControllingTerminal: { $0 == parent },
        lineageParent: { ProcessAncestry.parent(of: $0) }
    )
}

let v3SilentTerminal = TerminalSessionInspector(
    environment: { _ in nil }, parent: { _ in nil }, terminalName: { _ in nil }, titleQuery: { _ in nil }
)

func v3AccessPlan() -> DeliveryPlan {
    DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/phone-e2e", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: nil, operationContext: "synthetic phone e2e",
        outputGuard: OutputGuardPlan(mode: .tty)
    )
}

private func v3UnlockEndToEndTests() async {
    let world = V3World()
    let local = CacheUnlock(LAContext()) // in-memory backends only; never prompts
    let phone = SyntheticPhone()
    let pairing = v3StoredPairing(phone: phone, macKey: P256.Signing.PrivateKey())
    let storeName = try! NativeStoreName("phone-store")
    let nativeURI = "csec://phone-store/API_TOKEN"
    let nativeRef = try! SecretRef(nativeURI)
    let nativeValue = Data("synthetic-native-value".utf8)
    let opRef = try! SecretRef("op://Vault/Item/password")
    let vaultRef = try! SecretRef("vault://kv/app/token")
    let keyringRef = try! SecretRef("keyring://login/app")
    let me = getpid()
    guard let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "v3 e2e: the fixture reads its own start time")
        return
    }
    let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic phone e2e")

    do {
        // Run 1 writes the native store with this Mac's own touch.
        let run1 = await v3Boot(world, previous: nil)
        let session = try await run1.provider.beginEdit(
            store: storeName, callerPID: 4242, callerStartTime: 1, unlock: local
        )
        _ = try await run1.provider.commitEdit(
            sessionID: session.sessionID,
            document: try NativeStoreDocument(values: ["API_TOKEN": String(decoding: nativeValue, as: UTF8.self)]).encoded(),
            callerPID: 4242, callerStartTime: 1
        )

        // Run 2: restarted, the store is cold and nothing is enrolled yet.
        let run2 = await v3Boot(world, previous: v3LastRun)
        let manager2 = v3Manager(
            store: V3MemoryConfigurationStore(record: pairing), relay: V3MailboxRelay(),
            remoteUnlock: run2.store, resolver: run2.resolver
        )
        await manager2.prepare()
        func ready(_ refs: [SecretRef]) async -> RemoteReviewReadiness { await manager2.remoteReadiness(for: refs) }
        let unenrolled = [await ready([opRef]), await ready([nativeRef]), await ready([keyringRef]), await ready([vaultRef])]
        check(unenrolled == [.ready(unlock: .notNeeded), .unavailable, .unavailable, .unavailable],
              "v3 readiness: before enrollment only what needs no unlock can reach the phone (\(unenrolled))")

        // An enrollment for another phone opens nothing for this pairing.
        _ = try await run2.store.enroll(
            phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
            macDeviceID: pairing.macDeviceID, phoneDeviceID: UUID().uuidString.lowercased()
        )
        _ = await run2.resolver.backfillRemoteUnlockMirrors(localUnlock: local)
        check(await ready([nativeRef]) == .unavailable,
              "v3 readiness: an enrollment belonging to another pairing does not make cold storage phone-servable")

        _ = try await run2.store.enroll(
            phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
            macDeviceID: pairing.macDeviceID, phoneDeviceID: phone.deviceID
        )
        let backfill = await run2.resolver.backfillRemoteUnlockMirrors(localUnlock: local)
        check(backfill.mirrored >= 1 && backfill.failed == 0, "v3 readiness: enrollment backfills the store's mirror")
        let answers = [
            await ready([opRef]), await ready([nativeRef]), await ready([vaultRef]), await ready([keyringRef]),
            await ready([opRef, nativeRef]), await ready([opRef, vaultRef]),
            await ready([nativeRef, keyringRef]), await ready([nativeRef, vaultRef]),
        ]
        let expected: [RemoteReviewReadiness] = [
            .ready(unlock: .notNeeded), .ready(unlock: .required), .unavailable, .ready(unlock: .required),
            .ready(unlock: .required), .unavailable, .ready(unlock: .required), .unavailable,
        ]
        check(answers == expected,
              "v3 readiness is provider-neutral: a remote provider needs no unlock, native storage and a mirrored "
                + "provider are covered, an uncovered sealed provider keeps any set it is in on the Mac (\(answers))")
        let blind = v3Manager(
            store: V3MemoryConfigurationStore(record: pairing), relay: V3MailboxRelay(), remoteUnlock: run2.store
        )
        await blind.prepare()
        check(await blind.remoteReadiness(for: [opRef]) == .unavailable,
              "v3 readiness: without the providers' coverage nothing is judged phone-servable")

        // Automation and setup at this Mac never reach the phone, even when
        // every reference could.
        let spy2 = V3SpyRemote(manager2)
        let gate = MirroredPolicyReview(local: V3QuickFailure(), remote: spy2, log: { _ in })
        let plan = v3AccessPlan()
        _ = await gate.reviewAccess(AccessPolicyReview(
            caller: caller, reason: "enroll", plan: plan,
            credentials: [PolicyReviewCredential(references: [opRef])], automation: v3AutomationDetails()
        ))
        _ = await gate.reviewAccess(AccessPolicyReview(
            caller: caller, reason: "edit", plan: plan,
            credentials: [PolicyReviewCredential(references: [opRef])], macOnly: true
        ))
        let macOnlyAsked = await spy2.readinessCalls
        _ = await gate.reviewAccess(AccessPolicyReview(
            caller: caller, reason: "release", plan: plan, credentials: [PolicyReviewCredential(references: [opRef])]
        ))
        let releaseAsked = await spy2.readinessCalls
        let releaseMirrored = await spy2.reviews
        check(macOnlyAsked == 0 && releaseAsked == 1 && releaseMirrored == 1,
              "v3 mirroring: automation enrollment and Mac-only setup stay on the Mac; an ordinary release is mirrored")
    } catch {
        check(false, "v3 readiness fixtures (\(error))")
    }

    // End to end: a cold native value after a restart, approved on the phone
    // with no local context, delivered, with the scope and lifetime the phone chose.
    do {
        let run = await v3Boot(world, previous: v3LastRun)
        let relay = V3MailboxRelay()
        let manager = v3Manager(
            store: V3MemoryConfigurationStore(record: pairing), relay: relay,
            remoteUnlock: run.store, resolver: run.resolver
        )
        await manager.prepare()
        check(await run.provider.requiresUnlockToResolve(nativeRef),
              "v3 e2e: after the restart the native store is cold")
        let spy = V3SpyRemote(manager)
        let localPanel = V3UnansweredLocal()
        let consent = V3CountingConsent()
        let grants = GrantTable()
        let agent = Agent(
            resolver: run.resolver, grants: grants, consent: consent,
            policyReview: MirroredPolicyReview(local: localPanel, remote: spy, log: { _ in }),
            allowUnverifiedPlansForTesting: true, processInspection: v3Inspection(),
            terminalInspection: v3SilentTerminal
        )
        let keyLoads = await world.docKeys.loadCount
        let request = try AccessRequest(references: [nativeURI], reason: "phone e2e", deliveryPlan: v3AccessPlan())
        let asked = Task { await agent.handle(request: request, caller: caller) }
        guard let envelope = await v3WaitForRequest(relay) else {
            asked.cancel()
            check(false, "v3 e2e: the request reaches the phone")
            return
        }
        try envelope.verify(macPublicKeyX963: pairing.macPublicKeyX963, at: currentTimeMilliseconds())
        let offered = envelope.request.review
        let requesting = offered.scopeOptions.first
        check(envelope.request.unlockChallenge != nil && offered.kind == .access && offered.scopeOptions.count == 2
                && requesting?.title == "Requesting process only" && offered.defaultScopeID != requesting?.id
                && offered.durationOptions == ["Until it exits", "1 hour", "12 hours"],
              "v3 e2e: the signed request carries an unlock challenge and the Mac panel's scope and lifetime choices")
        try await relay.publishResponse(try phone.approve(envelope, scopeID: requesting?.id, durationIndex: 1))
        let response = await asked.value
        check(response.values?[nativeURI] == nativeValue,
              "v3 e2e: the phone's approval opens the cold native value and it is delivered")
        let consentAsked = await consent.requests
        let localReviews = await localPanel.reviews
        let keyLoadsAfter = await world.docKeys.loadCount
        check(consentAsked == 0 && localReviews == 1 && keyLoadsAfter == keyLoads,
              "v3 e2e: no local context was used: no consent sheet, and the key record's biometric item was never read")
        let minted = await grants.summaries(now: Date())
        let expiry = minted.first?.expiresAt?.timeIntervalSinceNow ?? 0
        check(minted.count == 1 && minted[0].scopeKind == .requestingCommand && expiry > 3_500 && expiry <= 3_600,
              "v3 e2e: the grant has the phone's selected scope (not the default) and its 1-hour lifetime")
        let unlocks = await spy.unlocks
        check(unlocks.count == 1 && unlocks[0].remote?.isInvalidated == true,
              "v3 e2e: the phone's remote unlock is dropped once the release is done")
        check(await eventuallyTrue { await relay.deleted.contains(envelope.request.requestID) },
              "v3 e2e: the answered request is withdrawn from the mailbox")
    } catch {
        check(false, "v3 e2e: phone-approved cold release (\(error))")
    }

    // A phone answer computed with another key-agreement key opens nothing:
    // no delivery, and the local prompt still decides.
    do {
        let run = await v3Boot(world, previous: v3LastRun)
        let relay = V3MailboxRelay()
        let log = V3LogLines()
        let manager = v3Manager(
            store: V3MemoryConfigurationStore(record: pairing), relay: relay,
            remoteUnlock: run.store, resolver: run.resolver, log: log
        )
        await manager.prepare()
        let localGate = GatedPolicyReview()
        let grants = GrantTable()
        let agent = Agent(
            resolver: run.resolver, grants: grants, consent: V3CountingConsent(),
            policyReview: MirroredPolicyReview(local: localGate, remote: manager, log: { _ in }),
            allowUnverifiedPlansForTesting: true, processInspection: v3Inspection(),
            terminalInspection: v3SilentTerminal
        )
        let request = try AccessRequest(references: [nativeURI], reason: "phone wrong key", deliveryPlan: v3AccessPlan())
        let asked = Task { await agent.handle(request: request, caller: caller) }
        guard let envelope = await v3WaitForRequest(relay) else {
            asked.cancel()
            check(false, "v3 e2e: the wrong-key request reaches the phone")
            return
        }
        try await relay.publishResponse(try phone.approve(envelope, answeringWith: P256.KeyAgreement.PrivateKey()))
        let refused = await eventuallyTrue { log.all.contains { $0.contains("did not open") } }
        let panelUp = await localGate.pendingCount == 1
        await localGate.decide(.deny(.human(decidedAt: .now)))
        let response = await asked.value
        check(refused && panelUp && response.values == nil && response.failure?.code == .consentDenied,
              "v3 e2e: an answer from another key-agreement key opens nothing and the local prompt still decides")
        let minted = await grants.summaries(now: Date())
        let stillCold = await run.provider.requiresUnlockToResolve(nativeRef)
        check(minted.isEmpty && stillCold,
              "v3 e2e: nothing was minted and the store stays cold")
        check(!log.all.joined().contains(String(decoding: nativeValue, as: UTF8.self)),
              "v3 e2e: the failure is logged value-free")
    } catch {
        check(false, "v3 e2e: wrong phone key (\(error))")
    }

    // Restore via the phone: the restore panel reaches the phone, and a phone
    // approval reopens the restored grant rather than dropping it.
    do {
        let run = await v3Boot(world, previous: v3LastRun)
        let relay = V3MailboxRelay()
        let manager = v3Manager(
            store: V3MemoryConfigurationStore(record: pairing), relay: relay,
            remoteUnlock: run.store, resolver: run.resolver
        )
        await manager.prepare()
        let source = V3RestoreSource([RestoreEntry(
            grantID: UUID(),
            row: RestoreReviewRow(kind: .secretGrant, title: "zsh", detail: "This terminal session · pid 1",
                                  references: [nativeURI]),
            references: [nativeRef]
        )])
        let localGate = GatedPolicyReview()
        let restoration = GrantRestoration(
            resolver: run.resolver,
            policyReview: MirroredPolicyReview(local: localGate, remote: manager, log: { _ in }),
            consent: V3CountingConsent(), terminalInspection: v3SilentTerminal
        )
        await restoration.addGrantSource(source)
        let waiting = Task { await restoration.ensureWarm(for: [nativeRef], requester: caller) }
        guard let envelope = await v3WaitForRequest(relay) else {
            waiting.cancel()
            check(false, "v3 restore: the restore reaches the phone")
            return
        }
        let offered = envelope.request.review
        check(offered.kind == .restore && envelope.request.unlockChallenge != nil && offered.scopeOptions.isEmpty
                && offered.restore?.rows.first?.secrets == [v3NativeSecret("phone-store", "API_TOKEN")],
              "v3 restore: the restore-only panel reaches the phone with an unlock challenge, no choices, "
                + "and each row's secrets named by their provider")
        try await relay.publishResponse(try phone.approve(envelope))
        let outcome = await waiting.value
        let settled = await source.settled
        check(outcome == .warmed && settled == [[]],
              "v3 restore: a phone approval reopens the restored grant; nothing is dropped")
        check(!(await run.provider.requiresUnlockToResolve(nativeRef)),
              "v3 restore: the store is open for the rest of the run")
        check(await eventuallyTrue { await localGate.cancelledReviews == 1 },
              "v3 restore: the Mac's restore panel closes when the phone decides")
    } catch {
        check(false, "v3 restore: phone restore (\(error))")
    }

    // A restore listing a reference no phone approval could reopen stays on the Mac.
    do {
        let run = await v3Boot(world, previous: v3LastRun)
        let relay = V3MailboxRelay()
        let manager = v3Manager(
            store: V3MemoryConfigurationStore(record: pairing), relay: relay,
            remoteUnlock: run.store, resolver: run.resolver
        )
        await manager.prepare()
        let source = V3RestoreSource([
            RestoreEntry(
                grantID: UUID(),
                row: RestoreReviewRow(kind: .secretGrant, title: "zsh", detail: "d", references: [nativeURI]),
                references: [nativeRef]
            ),
            RestoreEntry(
                grantID: UUID(),
                row: RestoreReviewRow(kind: .secretGrant, title: "zsh", detail: "d", references: [vaultRef.uri]),
                references: [vaultRef]
            ),
        ])
        let localGate = GatedPolicyReview()
        let restoration = GrantRestoration(
            resolver: run.resolver,
            policyReview: MirroredPolicyReview(local: localGate, remote: manager, log: { _ in }),
            consent: V3CountingConsent(), terminalInspection: v3SilentTerminal
        )
        await restoration.addGrantSource(source)
        let waiting = Task { await restoration.ensureWarm(for: [nativeRef, vaultRef], requester: caller) }
        let panelUp = await eventuallyTrue { await localGate.pendingCount == 1 }
        let publishedWhileUp = await relay.published
        await localGate.decide(.deny(.human(decidedAt: .now)))
        let outcome = await waiting.value
        check(panelUp && publishedWhileUp.isEmpty && outcome == .forgotten,
              "v3 restore: a restore whose rows are not all covered stays on the Mac panel")
    }
}

/// A phone approval of a value a fetchable provider serves (1Password, say)
/// reads csec's cached copy first, as a Mac approval does, so a provider
/// locked along with the Mac does not fail the release. With no copy, or an
/// unlock answer that does not open, the approval still stands and the
/// provider is asked, as it would be with no unlock at all.
private func v3CachedCopyEndToEndTests() async {
    let world = V3World()
    let local = CacheUnlock(LAContext()) // in-memory backends only; never prompts
    let phone = SyntheticPhone()
    let pairing = v3StoredPairing(phone: phone, macKey: P256.Signing.PrivateKey())
    let cachedURI = "op://Vault/Cached/password"
    let uncachedURI = "op://Vault/Uncached/password"
    let opValue = Data("synthetic-op-value".utf8)
    let me = getpid()
    guard let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "v3 cached copy: the fixture reads its own start time")
        return
    }
    let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic cached-copy e2e")

    func agent(_ run: V3Run, remote: any RemoteAccessPolicyReviewProvider, consent: V3CountingConsent,
               grants: GrantTable, local: any PolicyReviewProvider = V3UnansweredLocal()) -> Agent {
        Agent(
            resolver: run.resolver, grants: grants, consent: consent,
            policyReview: MirroredPolicyReview(local: local, remote: remote, log: { _ in }),
            allowUnverifiedPlansForTesting: true, processInspection: v3Inspection(),
            terminalInspection: v3SilentTerminal
        )
    }

    // Run 1: this pairing's factor is enrolled, and a value fetched at the Mac
    // is cached together with its remote-unlock mirror.
    do {
        let run1 = await v3Boot(world, previous: nil)
        _ = try await run1.store.enroll(
            phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
            macDeviceID: pairing.macDeviceID, phoneDeviceID: phone.deviceID
        )
        let fetched = try await run1.resolver.resolve(try SecretRef(cachedURI), unlock: local)
        let mirrored = await run1.store.exists(.cache(uri: cachedURI))
        check(fetched == opValue && mirrored,
              "v3 cached copy: a value fetched at the Mac is cached with a remote-unlock mirror")
    } catch {
        check(false, "v3 cached copy: the value is cached at the Mac (\(error))")
        return
    }

    // The provider is locked, as 1Password is while the Mac is: after a
    // restart nothing is warm, and the phone approval reads the cached copy.
    await world.remoteLike.setLocked(true)
    do {
        let run = await v3Boot(world, previous: v3LastRun)
        let relay = V3MailboxRelay()
        let manager = v3Manager(
            store: V3MemoryConfigurationStore(record: pairing), relay: relay,
            remoteUnlock: run.store, resolver: run.resolver
        )
        await manager.prepare()
        let readiness = await manager.remoteReadiness(for: [try SecretRef(cachedURI)])
        check(readiness == .ready(unlock: .preferred),
              "v3 cached copy: a cached value the provider could fetch prefers the phone-held unlock (\(readiness))")
        let spy = V3SpyRemote(manager)
        let consent = V3CountingConsent()
        let grants = GrantTable()
        let fetchesBefore = await world.remoteLike.resolveCount
        let request = try AccessRequest(references: [cachedURI], reason: "phone cached copy", deliveryPlan: v3AccessPlan())
        let asked = Task { await agent(run, remote: spy, consent: consent, grants: grants).handle(request: request, caller: caller) }
        guard let envelope = await v3WaitForRequest(relay) else {
            asked.cancel()
            check(false, "v3 cached copy: the request reaches the phone")
            return
        }
        try envelope.verify(macPublicKeyX963: pairing.macPublicKeyX963, at: currentTimeMilliseconds())
        check(envelope.request.unlockChallenge != nil,
              "v3 cached copy: the signed request carries an unlock challenge for the cached copy")
        try await relay.publishResponse(try phone.approve(envelope))
        let response = await asked.value
        let fetchesAfter = await world.remoteLike.resolveCount
        let consentAsked = await consent.requests
        check(response.values?[cachedURI] == opValue && fetchesAfter == fetchesBefore && consentAsked == 0,
              "v3 cached copy: with the provider locked, the phone approval delivers the cached copy, asking "
                + "neither the provider nor this Mac's Touch ID")
        let unlocks = await spy.unlocks
        check(unlocks.count == 1 && unlocks[0].remote?.isInvalidated == true,
              "v3 cached copy: the remote unlock is dropped once the release is done")
        let minted = await grants.summaries(now: Date())
        check(minted.count == 1, "v3 cached copy: the phone approval mints its grant")
    } catch {
        check(false, "v3 cached copy: phone release with the provider locked (\(error))")
    }

    // With the provider locked and nothing cached, the approval reaches the
    // provider, which refuses: a bounded failure, nothing delivered or minted.
    do {
        let run = await v3Boot(world, previous: v3LastRun)
        let relay = V3MailboxRelay()
        let log = V3LogLines()
        let manager = v3Manager(
            store: V3MemoryConfigurationStore(record: pairing), relay: relay,
            remoteUnlock: run.store, resolver: run.resolver, log: log
        )
        await manager.prepare()
        let readiness = await manager.remoteReadiness(for: [try SecretRef(uncachedURI)])
        check(readiness == .ready(unlock: .notNeeded),
              "v3 cached copy: a value with no cached copy reaches the phone with no unlock (\(readiness))")
        let grants = GrantTable()
        let request = try AccessRequest(references: [uncachedURI], reason: "phone locked provider", deliveryPlan: v3AccessPlan())
        let asked = Task {
            await agent(run, remote: manager, consent: V3CountingConsent(), grants: grants).handle(request: request, caller: caller)
        }
        guard let envelope = await v3WaitForRequest(relay) else {
            asked.cancel()
            check(false, "v3 cached copy: the uncached request reaches the phone")
            return
        }
        check(envelope.request.unlockChallenge == nil,
              "v3 cached copy: with nothing cached, the request carries no unlock challenge")
        try await relay.publishResponse(try phone.approve(envelope))
        let response = await asked.value
        let minted = await grants.summaries(now: Date())
        check(response.values == nil && response.failure?.code == .resolutionFailed && minted.isEmpty,
              "v3 cached copy: a locked provider with no cached copy fails the phone-approved release, "
                + "and nothing is delivered or minted")
    } catch {
        check(false, "v3 cached copy: phone release with the provider locked and nothing cached (\(error))")
    }
    await world.remoteLike.setLocked(false)

    // An unlock answer from another key opens nothing; with every value
    // fetchable the approval still stands and the provider is asked.
    do {
        let run = await v3Boot(world, previous: v3LastRun)
        let relay = V3MailboxRelay()
        let log = V3LogLines()
        let manager = v3Manager(
            store: V3MemoryConfigurationStore(record: pairing), relay: relay,
            remoteUnlock: run.store, resolver: run.resolver, log: log
        )
        await manager.prepare()
        let grants = GrantTable()
        // A panel this test can close, so a phone approval that did not stand
        // fails the check below instead of waiting on the Mac forever.
        let localGate = GatedPolicyReview()
        let fetchesBefore = await world.remoteLike.resolveCount
        let request = try AccessRequest(references: [cachedURI], reason: "phone cached wrong key", deliveryPlan: v3AccessPlan())
        let asked = Task {
            await agent(run, remote: manager, consent: V3CountingConsent(), grants: grants, local: localGate)
                .handle(request: request, caller: caller)
        }
        guard let envelope = await v3WaitForRequest(relay) else {
            asked.cancel()
            check(false, "v3 cached copy: the wrong-key request reaches the phone")
            return
        }
        let panelUp = await eventuallyTrue { await localGate.pendingCount == 1 }
        try await relay.publishResponse(try phone.approve(envelope, answeringWith: P256.KeyAgreement.PrivateKey()))
        // A standing phone approval ends the race and closes the Mac panel.
        let phoneWon = await eventuallyTrue { await localGate.pendingCount == 0 }
        if !phoneWon { await localGate.decide(.deny(.human(decidedAt: .now))) }
        let response = await asked.value
        let stood = panelUp && phoneWon && log.all.contains { $0.contains("the approval stands") }
        let fetchesAfter = await world.remoteLike.resolveCount
        check(response.values?[cachedURI] == opValue && fetchesAfter == fetchesBefore + 1 && stood,
              "v3 cached copy: an unlock answer that does not open leaves the phone approval standing, "
                + "and the provider is asked for the value")
        let minted = await grants.summaries(now: Date())
        check(minted.count == 1 && !log.all.joined().contains(String(decoding: opValue, as: UTF8.self)),
              "v3 cached copy: that approval mints its grant, and the log stays value-free")
    } catch {
        check(false, "v3 cached copy: wrong-key answer to a preferred unlock (\(error))")
    }
}

// MARK: - The delegation block and the pairing-line acknowledgement

/// A request Claude Code auto mode declined, carrying the note and pairing
/// line: requests and responses without the block sign exactly as they did
/// before it existed (an older phone app keeps verifying them), the block and
/// the acknowledgement are bound by their own signing domains, and csecd
/// accepts an approval only when its acknowledgement says what the shared
/// rule says for the signed selection.
private func v3DelegationTests() {
    let base = v3DelegationGoldenReview()
    let request = RemoteApprovalRequest(
        requestID: "00000000-0000-4000-8000-0000000000a1", macDeviceID: "00000000-0000-4000-8000-0000000000a2",
        macDeviceName: "Alex’s Mac", createdAtMilliseconds: 1_760_000_000_000, review: base
    )
    let response = RemoteApprovalResponse(
        requestID: request.requestID, requestDigest: (try? request.digest()) ?? Data(),
        phoneDeviceID: "00000000-0000-4000-8000-0000000000a3", decision: .approve,
        decidedAtMilliseconds: 1_760_000_000_500, selectedScopeID: "coding_agent-5-5", selectedDurationIndex: 0,
        phoneAppVersion: "1.0 (7)"
    )
    // Computed with the protocol code as it was before the delegation block
    // (commit 3947b69), from this exact fixture.
    check(v3Hex(try? request.digest()) == "34061580ba80df83c560f03e31279b09f7a90771dccf49f01eed2224dad9cd6f",
          "delegation block: a request without it signs exactly as before the block existed")
    check(v3Hex((try? response.signingData()).map { Data(SHA256.hash(data: $0)) })
            == "7a0454ceb876b80ff66ca76c7cebfac1fbd2872437fe1f2ef1cd01a3df33088a",
          "delegation block: a response without an acknowledgement signs exactly as before")

    let pairing = RemoteApprovalReview.Delegation.Pairing(
        line: "Approving also lets Claude Code auto mode start SSH from bin/deploy in app until you revoke them or they change",
        scopeID: "coding_agent-5-5", processLifetimeIndex: 0
    )
    let delegation = RemoteApprovalReview.Delegation(
        note: DelegationDecline.uncheckedBuild("new release").panelText,
        pairing: pairing
    )
    let declined = RemoteReviewParts.changing(base) { $0.delegation = delegation }
    func digest(_ review: RemoteApprovalReview) -> Data? {
        try? RemoteApprovalRequest(
            requestID: request.requestID, macDeviceID: request.macDeviceID, macDeviceName: request.macDeviceName,
            createdAtMilliseconds: request.createdAtMilliseconds, review: review
        ).digest()
    }
    let declinedDigest = digest(declined)
    check(declinedDigest != nil && declinedDigest != digest(base), "delegation block: adding it changes what is signed")
    for (label, changed) in [
        ("the note", RemoteApprovalReview.Delegation(note: "other", pairing: pairing)),
        ("no note", RemoteApprovalReview.Delegation(note: nil, pairing: pairing)),
        ("the line", RemoteApprovalReview.Delegation(note: delegation.note, pairing: .init(
            line: pairing.line + ".", scopeID: pairing.scopeID, processLifetimeIndex: 0))),
        ("the lifetime index", RemoteApprovalReview.Delegation(note: delegation.note, pairing: .init(
            line: pairing.line, scopeID: pairing.scopeID, processLifetimeIndex: 1))),
        ("no line", RemoteApprovalReview.Delegation(note: delegation.note, pairing: nil)),
    ] {
        let other = digest(RemoteReviewParts.changing(base) { $0.delegation = changed })
        check(other != nil && other != declinedDigest, "delegation block: \(label) is bound by the signature")
    }

    // What a review may carry. A sudo review offers no scope or lifetime, so
    // its line is unscoped and applies to the one approval there is.
    let sudoNote = RemoteReviewParts.changing(v3SudoReviewFixture()) {
        $0.delegation = .init(note: DelegationDecline.uncheckedBuild("new release").panelText, pairing: nil)
    }
    let sudoLine = RemoteReviewParts.changing(v3SudoReviewFixture()) {
        $0.delegation = .init(note: DelegationDecline.uncheckedBuild("new release").panelText,
                             pairing: .unscoped(line: "Approving also lets …"))
    }
    check((try? sudoNote.validate()) != nil && (try? sudoLine.validate()) != nil,
          "delegation block: a sudo review may carry the note, and an unscoped pairing line")
    let generatedPolicyNote = DelegationDecline.settingsUnreadable(
        "/Library/Application Support/ClaudeCode/managed-settings.json").panelText
    for (label, original) in [("secret", base), ("SSH", v3SSHReviewFixture()), ("sudo", v3SudoReviewFixture())] {
        let review = RemoteReviewParts.changing(original) {
            $0.delegation = .init(note: generatedPolicyNote, pairing: nil)
        }
        let decoded = try? JSONDecoder().decode(RemoteApprovalReview.self, from: JSONEncoder().encode(review))
        check((try? review.validate()) != nil && digest(review) != nil && digest(review) != digest(original)
                && decoded?.delegation?.note == generatedPolicyNote,
              "delegation block: the \(label) generated-policy note is preserved and bound to the signed phone request")
    }
    check(sudoLine.pairingLineApplies(scopeID: nil, durationIndex: nil)
            && !sudoLine.pairingLineApplies(scopeID: "coding_agent-5-5", durationIndex: 0)
            && !sudoNote.pairingLineApplies(scopeID: nil, durationIndex: nil),
          "delegation block: an unscoped line applies exactly to an approval that selects nothing")
    for (label, review, expected) in [
        ("on sudo with a scoped line", RemoteReviewParts.changing(v3SudoReviewFixture()) {
            $0.delegation = .init(note: "x", pairing: .init(line: "x", scopeID: "coding_agent-5-5", processLifetimeIndex: 0))
        }, RemoteApprovalValidationError.invalidSelection),
        ("an unscoped line on a review that offers a scope", RemoteReviewParts.changing(base) {
            $0.delegation = .init(note: nil, pairing: .unscoped(line: "x"))
        }, .invalidSelection),
        ("an unscoped line with a lifetime index", RemoteReviewParts.changing(v3SudoReviewFixture()) {
            $0.delegation = .init(note: nil, pairing: .init(line: "x", scopeID: "", processLifetimeIndex: 1))
        }, .invalidSelection),
        ("empty", RemoteReviewParts.changing(base) { $0.delegation = .init(note: nil, pairing: nil) }, .fieldOutOfBounds),
        ("a scope the review does not offer", RemoteReviewParts.changing(base) {
            $0.delegation = .init(note: nil, pairing: .init(line: "x", scopeID: "terminal_session-1-1", processLifetimeIndex: 0))
        }, .invalidSelection),
        ("a lifetime index out of range", RemoteReviewParts.changing(base) {
            $0.delegation = .init(note: nil, pairing: .init(line: "x", scopeID: pairing.scopeID, processLifetimeIndex: 2))
        }, .invalidSelection),
        ("a line over its bound", RemoteReviewParts.changing(base) {
            $0.delegation = .init(note: nil, pairing: .init(
                line: String(repeating: "x", count: RemoteApprovalReview.FieldLimit.pairingLine + 1),
                scopeID: pairing.scopeID, processLifetimeIndex: 0))
        }, .fieldOutOfBounds),
    ] {
        var thrown: RemoteApprovalValidationError?
        do { try review.validate() } catch let error as RemoteApprovalValidationError { thrown = error } catch {}
        check(thrown == expected, "delegation block: one \(label) is refused (\(String(describing: thrown)))")
    }
    check(declined.pairingLineApplies(scopeID: "coding_agent-5-5", durationIndex: 0)
            && !declined.pairingLineApplies(scopeID: "coding_agent-5-5", durationIndex: 1)
            && !declined.pairingLineApplies(scopeID: "connection", durationIndex: 0)
            && !base.pairingLineApplies(scopeID: "coding_agent-5-5", durationIndex: 0),
          "delegation block: the line applies exactly at its scope and the process lifetime")

    // What csecd accepts from the phone.
    let mac = P256.Signing.PrivateKey()
    let phone = SyntheticPhone()
    guard let envelope = try? SignedRemoteApprovalRequest.signed(
        RemoteApprovalRequest(macDeviceID: request.macDeviceID, macDeviceName: "Mac",
                              createdAtMilliseconds: currentTimeMilliseconds(), review: RemoteReviewParts.changing(base) {
                                  $0.scopeOptions.append(.init(id: "connection", title: "This SSH command", detail: "ssh"))
                                  $0.delegation = delegation
                              }),
        by: mac
    ) else {
        check(false, "delegation block: the request signs")
        return
    }
    func accepted(_ response: SignedRemoteApprovalResponse?) -> Result<RemoteApprovalSelection?, RemoteApprovalValidationError>? {
        guard let response else { return nil }
        do {
            return .success(try response.verify(
                for: envelope.request, pinnedPhoneDeviceID: phone.deviceID,
                phonePublicKeyX963: phone.signingKey.publicKey.x963Representation
            ))
        } catch let error as RemoteApprovalValidationError {
            return .failure(error)
        } catch {
            return nil
        }
    }
    let defaults = accepted(try? phone.approve(envelope))
    check(defaults == .success(RemoteApprovalSelection(
        scopeOptionID: "coding_agent-5-5", durationIndex: 0, unlockAnswer: nil, pairingLineShown: true
    )), "acknowledgement: an approval of the defaults that showed the line is accepted as showing it")
    let capped = accepted(try? phone.approve(envelope, durationIndex: 1))
    check(capped == .success(RemoteApprovalSelection(
        scopeOptionID: "coding_agent-5-5", durationIndex: 1, unlockAnswer: nil, pairingLineShown: false
    )), "acknowledgement: an approval with a lifetime cap says the line was hidden, and is accepted as hidden")
    for (label, response) in [
        ("claiming a line a cap hid", try? phone.respond(
            to: envelope, .approve, scopeID: "coding_agent-5-5", durationIndex: 1, pairingLineShown: true)),
        ("claiming the line hidden at the defaults", try? phone.respond(
            to: envelope, .approve, scopeID: "coding_agent-5-5", durationIndex: 0, pairingLineShown: false)),
        ("saying nothing about a line the review carries", try? phone.respond(
            to: envelope, .approve, scopeID: "coding_agent-5-5", durationIndex: 0)),
        ("acknowledging a line on a denial", try? phone.respond(to: envelope, .deny, pairingLineShown: true)),
    ] {
        check(accepted(response) == .failure(.invalidSelection), "acknowledgement: \(label) is refused")
    }
    if let plain = try? SignedRemoteApprovalRequest.signed(
        RemoteApprovalRequest(macDeviceID: request.macDeviceID, macDeviceName: "Mac",
                              createdAtMilliseconds: currentTimeMilliseconds(), review: base),
        by: mac
    ), let response = try? phone.respond(
        to: plain, .approve, scopeID: "coding_agent-5-5", durationIndex: 0, pairingLineShown: true
    ) {
        var thrown: RemoteApprovalValidationError?
        do {
            try response.verify(for: plain.request, pinnedPhoneDeviceID: phone.deviceID,
                                phonePublicKeyX963: phone.signingKey.publicKey.x963Representation)
        } catch let error as RemoteApprovalValidationError { thrown = error } catch {}
        check(thrown == .invalidSelection, "acknowledgement: one on a request with no line is refused")
    }
    if let signed = try? phone.approve(envelope) {
        let flipped = SignedRemoteApprovalResponse(
            response: RemoteApprovalResponse(
                requestID: signed.response.requestID, requestDigest: signed.response.requestDigest,
                phoneDeviceID: signed.response.phoneDeviceID, decision: .approve,
                decidedAtMilliseconds: signed.response.decidedAtMilliseconds,
                selectedScopeID: "coding_agent-5-5", selectedDurationIndex: 1,
                phoneAppVersion: signed.response.phoneAppVersion, pairingLineShown: false
            ),
            signatureDER: signed.signatureDER
        )
        check(accepted(flipped) == .failure(.invalidSignature),
              "acknowledgement: changing a signed answer's selection and acknowledgement breaks its signature")
    }
}

/// The fixture `v3DelegationTests` pins byte for byte (do not change it: its
/// digests were computed with the protocol code before the delegation block).
private func v3DelegationGoldenReview() -> RemoteApprovalReview {
    RemoteApprovalReview(
        kind: .ssh, headline: "bin/deploy", callerDescription: "ssh (pid 7) ← bash ← zsh ← Claude Code",
        terminalDescription: "iTerm2 · “app” · window 1, tab 1", secrets: [
            ReviewSecret(provider: "csec", tint: .purple, account: "this Mac", container: "ssh-keys", item: "deploy", field: nil),
        ],
        referenceSetDigest: Data(repeating: 0x11, count: 32),
        delivery: .init(
            emitterName: "ssh", emitterPath: "/usr/bin/ssh", emitterAssurance: "Apple",
            recipientDescription: "SSH server github.com", deliveryDescription: "One signature",
            destinationDescription: "SSH authentication"
        ),
        warnings: [], footnote: "SSH receives only a signature.",
        ssh: .init(hostNames: ["github.com"], hostContext: "known_hosts", unknownHost: false,
                   remoteUser: "git", keyLabel: "deploy", keyAlgorithm: "Ed25519"),
        scopeOptions: [.init(id: "coding_agent-5-5", title: "This Claude Code session", detail: "Claude Code (pid 5)")],
        defaultScopeID: "coding_agent-5-5", durationOptions: ["Until it exits", "1 hour"], defaultDurationIndex: 0,
        operationDigest: Data(repeating: 0x22, count: 32)
    )
}

private func v3Hex(_ data: Data?) -> String {
    data.map { $0.map { String(format: "%02x", $0) }.joined() } ?? "(none)"
}
