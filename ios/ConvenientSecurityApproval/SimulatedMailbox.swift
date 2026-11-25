#if DEBUG && targetEnvironment(simulator)
import CloudKit
import CSECRemoteApproval
import CSECRemoteApprovalCloudKit
import CryptoKit
import Foundation

/// The simulated mailbox's iCloud account, as CloudKit would report it.
enum SimulatedICloud: String, CaseIterable, Identifiable {
    case available
    case signedOut
    case restricted
    case notReady
    /// Signed in, but no request reaches iCloud: the network is down.
    case unreachable
    /// Signed in, but iCloud does not answer: every call waits until the
    /// account is set to something else, as a CloudKit operation waits on a
    /// server that never replies. A call the app has stopped waiting for
    /// still finishes then, a save included: cancelling the task that awaits
    /// a CloudKit call does not end it.
    case notAnswering

    var id: String { rawValue }

    var menuTitle: String {
        switch self {
        case .available: return "Available"
        case .signedOut: return "Signed out"
        case .restricted: return "Restricted"
        case .notReady: return "Not ready"
        case .unreachable: return "Network down"
        case .notAnswering: return "Not answering"
        }
    }
}

/// The Simulator's stand-in for the private iCloud database, on only when the
/// app is launched with `--csec-simulator-mailbox`. It holds what simulated
/// Macs and this app leave in the mailbox — requests, this iPhone's answers,
/// the pairing offer and confirmations — in a file in the app's container, so
/// a relaunch finds what the last run left. A simulated Mac here never
/// withdraws anything on its own: it is the Mac whose delete failed, which is
/// what lets the UI tests see what the app does with a request it already
/// answered. It verifies nothing; the app verifies every request as it would
/// one from iCloud.
@MainActor
final class SimulatedMailbox: ObservableObject, PhoneMailbox {
    static let shared: SimulatedMailbox? = {
        let arguments = ProcessInfo.processInfo.arguments
        guard arguments.contains(SimulatorLaunchArgument.mailbox) else { return nil }
        return SimulatedMailbox(iCloud: SimulatorLaunchArgument.iCloud(arguments))
    }()

    private struct StoredMac: Codable {
        let deviceID: String
        let deviceName: String
        /// The simulated Mac's software key, so it signs as itself again
        /// after a relaunch.
        let signingKey: Data
    }

    private struct State: Codable {
        var macs: [StoredMac] = []
        /// In the order they were posted.
        var requests: [SignedRemoteApprovalRequest] = []
        /// Requests the mailbox query does not return, as a backlog larger
        /// than the query reads can leave one out; read by ID, they are there.
        var leftOutOfQuery: [String] = []
        /// Requests whose Mac has stopped saving them again, as a Mac that
        /// crashed for good leaves its record: their save time stays behind
        /// the phone's quiet threshold. Every other request reads as just
        /// saved, as a waiting Mac keeps it.
        var quiet: [String] = []
        /// By record name, `response-<requestID>-<phoneDeviceID>`.
        var responses: [String: SignedRemoteApprovalResponse] = [:]
        var offer: SignedRemoteApprovalPairingOffer?
        /// By Mac ID, as `pairing-confirmation-<macDeviceID>` names them.
        var confirmations: [String: SignedRemoteApprovalPairingConfirmation] = [:]
        /// Every save of a confirmation, a republication included.
        var confirmationSaves = 0
    }

    @Published var iCloud: SimulatedICloud
    @Published private var state: State
    /// The next answer is saved, and then its reply lost: the save reports a
    /// failure though the answer is in the mailbox.
    @Published private(set) var losesNextReply = false
    /// How many of the menu's actions have run since launch, each counted
    /// before it does anything. The UI tests read it, as the mailbox line's
    /// accessibility value, to tell a menu tap that ran its action from one a
    /// loaded Simulator dropped, so a dropped tap is made again and a tap
    /// that did run never is.
    @Published private(set) var actionsRun = 0

    private init(iCloud: SimulatedICloud) {
        self.iCloud = iCloud
        self.state = Self.loadState()
    }

    var summary: String {
        "Simulated mailbox: \(state.requests.count) requests "
            + "(\(state.leftOutOfQuery.count) left out of the list), "
            + "\(state.responses.count) answers, "
            + "\(state.confirmations.count) pairing confirmations, "
            + "\(state.confirmationSaves) confirmation saves"
    }

    /// The newest request the query leaves out, for the launch argument that
    /// opens the app from its alert.
    var lastRequestLeftOutOfQuery: String? { state.leftOutOfQuery.last }

    // MARK: - The mailbox

    func pendingRequestRecords() async throws -> [RemoteApprovalMailboxRequest] {
        try await reachRelay()
        return state.requests
            .filter { !state.leftOutOfQuery.contains($0.request.requestID) }
            .map(record)
    }

    func requestRecord(requestID: String) async throws -> RemoteApprovalMailboxRequest? {
        try await reachRelay()
        return state.requests.first { $0.request.requestID == requestID }.map(record)
    }

    func requestPresence(requestID: String) async throws -> RemoteApprovalRequestPresence {
        guard let record = try await requestRecord(requestID: requestID) else { return .gone }
        return .present(savedAt: record.savedAt)
    }

    func requestIsPending(requestID: String) async throws -> Bool {
        try await reachRelay()
        return state.requests.contains { $0.request.requestID == requestID }
    }

    private func record(_ envelope: SignedRemoteApprovalRequest) -> RemoteApprovalMailboxRequest {
        let quiet = state.quiet.contains(envelope.request.requestID)
        return RemoteApprovalMailboxRequest(
            envelope: envelope,
            savedAt: quiet
                ? Date(timeIntervalSinceNow: -(RemoteApprovalLiveness.quietAfterSeconds + 60))
                : Date()
        )
    }

    func publishResponse(
        _ response: SignedRemoteApprovalResponse,
        keepingEarlierAnswer isEarlierAnswer: @Sendable (SignedRemoteApprovalResponse) -> Bool
    ) async throws -> SignedRemoteApprovalResponse? {
        try await reachRelay()
        guard let name = RemoteApprovalMailboxName.response(
            requestID: response.response.requestID,
            phoneDeviceID: response.response.phoneDeviceID
        ) else { throw RemoteApprovalRelayFailure.permanentlyUnavailable }
        if let earlier = state.responses[name], isEarlierAnswer(earlier) {
            return earlier
        }
        state.responses[name] = response
        save()
        if losesNextReply {
            losesNextReply = false
            throw RemoteApprovalRelayFailure.transient
        }
        return nil
    }

    func response(
        for requestID: String,
        phoneDeviceID: String
    ) async throws -> SignedRemoteApprovalResponse? {
        try await reachRelay()
        guard let name = RemoteApprovalMailboxName.response(
            requestID: requestID,
            phoneDeviceID: phoneDeviceID
        ) else { throw RemoteApprovalRelayFailure.permanentlyUnavailable }
        return state.responses[name]
    }

    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? {
        try await reachRelay()
        guard let offer = state.offer,
              offer.offer.phoneDeviceID == phoneDeviceID.lowercased() else { return nil }
        return offer
    }

    func pairingConfirmation(
        macDeviceID: String
    ) async throws -> SignedRemoteApprovalPairingConfirmation? {
        try await reachRelay()
        return state.confirmations[macDeviceID.lowercased()]
    }

    func publishPairingConfirmation(
        _ confirmation: SignedRemoteApprovalPairingConfirmation
    ) async throws {
        try await reachRelay()
        let macDeviceID = confirmation.confirmation.macDeviceID
        state.confirmations[macDeviceID] = confirmation
        state.confirmationSaves += 1
        // The Mac withdraws its offer once the phone confirms it.
        if state.offer?.offer.mac.macDeviceID == macDeviceID {
            state.offer = nil
        }
        save()
    }

    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {
        try await reachRelay()
    }

    /// CloudKit's own error, unclassified, as the real relay throws it here.
    func ensureSubscriptions() async throws {
        try await reach()
    }

    /// Refused as a Production container refuses a subscription its schema
    /// was never given, when launched with
    /// `--csec-simulator-refuse-settled-subscription`.
    func ensureSettledSubscription() async throws {
        try await reach()
        if ProcessInfo.processInfo.arguments.contains(SimulatorLaunchArgument.refuseSettledSubscription) {
            throw CKError(
                .invalidArguments,
                userInfo: [NSLocalizedDescriptionKey: "attempting to create a subscription in a production container"]
            )
        }
    }

    /// The relay's own bound on its account read, as it plays out when iCloud
    /// does not answer that either.
    func approvalAccountStatus() async -> RemoteApprovalAccountStatus {
        if iCloud == .notAnswering {
            await Self.sleepIgnoringCancellation(
                nanoseconds: CloudKitRemoteApprovalRelay.accountStatusBoundNanoseconds
            )
            if iCloud == .notAnswering { return .unavailable(.couldNotDetermine) }
        }
        switch iCloud {
        case .available, .unreachable, .notAnswering: return .available
        case .signedOut: return .unavailable(.noAccount)
        case .restricted: return .unavailable(.restricted)
        case .notReady: return .unavailable(.temporarilyUnavailable)
        }
    }

    /// What CloudKit answers an account that cannot carry requests, or a
    /// device with no network, once it answers at all.
    private func reach() async throws {
        while iCloud == .notAnswering {
            await Self.sleepIgnoringCancellation(nanoseconds: 100_000_000)
        }
        switch iCloud {
        case .available, .notAnswering: return
        case .signedOut: throw CKError(.notAuthenticated)
        case .restricted: throw CKError(.managedAccountRestricted)
        case .notReady: throw CKError(.accountTemporarilyUnavailable)
        case .unreachable: throw CKError(.networkUnavailable)
        }
    }

    /// A CloudKit call does not end when the task awaiting it is cancelled,
    /// so neither does a simulated one.
    private static func sleepIgnoringCancellation(nanoseconds: UInt64) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            DispatchQueue.main.asyncAfter(deadline: .now() + .nanoseconds(Int(nanoseconds))) {
                continuation.resume()
            }
        }
    }

    /// The same, classified the way the real relay classifies it.
    private func reachRelay() async throws {
        do {
            try await reach()
        } catch {
            throw CloudKitRemoteApprovalRelay.relayFailure(for: error)
        }
    }

    // MARK: - The simulated Macs

    /// Play `csec remote enable` with this iPhone's code: a new Mac, named as
    /// the Simulator's other Macs are, leaves its signed offer here. With
    /// `sameMacNewKey`, the last Mac offers again under its ID and name with
    /// a new key, and signs as that key from then on.
    func offerPairing(to identity: PhoneApprovalIdentity, sameMacNewKey: Bool = false) throws {
        let mac: SimulatedMac
        if sameMacNewKey, let last = state.macs.last {
            mac = SimulatedMac(deviceName: last.deviceName, deviceID: last.deviceID)
        } else {
            mac = SimulatedMac()
        }
        state.offer = try mac.offer(
            to: identity.deviceID,
            phonePublicKeyX963: identity.publicKeyX963,
            phoneKeyAgreementPublicKeyX963: identity.keyAgreementPublicKeyX963
        )
        state.macs.append(StoredMac(
            deviceID: mac.deviceID,
            deviceName: mac.deviceName,
            signingKey: mac.keyRawRepresentation
        ))
        save()
    }

    /// A request signed by the newest of this mailbox's Macs that the iPhone
    /// pinned, or nil when it pinned none of them. `leftOutOfQuery` keeps it
    /// out of `pendingRequests()` while `request(requestID:)` still finds it.
    func postRequest(
        _ fixture: SimulatorFixture,
        pinnedMacIDs: Set<String>,
        identity: PhoneApprovalIdentity,
        leftOutOfQuery: Bool
    ) throws -> String? {
        guard let stored = state.macs.last(where: { pinnedMacIDs.contains($0.deviceID) }) else {
            return nil
        }
        let mac = SimulatedMac(
            deviceName: stored.deviceName,
            deviceID: stored.deviceID,
            key: try P256.Signing.PrivateKey(rawRepresentation: stored.signingKey)
        )
        let made = try mac.request(
            fixture,
            phoneDeviceID: identity.deviceID,
            phoneKeyAgreementPublicKeyX963: identity.keyAgreementPublicKeyX963,
            at: currentTimeMilliseconds()
        )
        let requestID = made.envelope.request.requestID
        state.requests.append(made.envelope)
        if leftOutOfQuery {
            state.leftOutOfQuery.append(requestID)
        }
        save()
        return requestID
    }

    /// As if the confirmation records went missing from iCloud.
    func deletePairingConfirmations() {
        state.confirmations = [:]
        save()
    }

    /// The Mac refuses every answer here — as csecd refuses one whose clock
    /// is too far from its own — and deletes only the answer, still waiting
    /// on the request.
    func refuseAnswers() {
        state.responses = [:]
        save()
    }

    func noteActionRun() {
        actionsRun += 1
    }

    func loseNextReply() {
        losesNextReply = true
    }

    /// The Mac takes every answer here: it deletes each answered request with
    /// its answer, as `deleteExchange` does once csecd accepts one.
    func takeAnswers() {
        let answered = Set(state.responses.values.map(\.response.requestID))
        state.requests.removeAll { answered.contains($0.request.requestID) }
        state.leftOutOfQuery.removeAll { answered.contains($0) }
        state.responses = [:]
        save()
    }

    /// The Macs stop saving their requests again, as a Mac that crashed and
    /// never runs csecd again: every request here goes quiet.
    func goQuiet() {
        state.quiet = state.requests.map(\.request.requestID)
        save()
    }

    /// The Macs save their requests again, as a Mac back from sleep does.
    func comeBack() {
        state.quiet = []
        save()
    }

    /// The Mac's own panel answers every request nobody answered here: csecd
    /// withdraws each, deleting it from the mailbox.
    func answerAtTheMac() {
        let answered = Set(state.responses.values.map(\.response.requestID))
        state.requests.removeAll { !answered.contains($0.request.requestID) }
        state.leftOutOfQuery.removeAll { !answered.contains($0) }
        save()
    }

    // MARK: - Storage

    nonisolated private static var fileURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("csec-simulated-mailbox.json")
    }

    /// Part of erasing the Simulator's approval records: a new setup starts
    /// with an empty mailbox.
    nonisolated static func eraseStoredState() {
        try? FileManager.default.removeItem(at: fileURL)
    }

    private static func loadState() -> State {
        guard let data = try? Data(contentsOf: fileURL),
              let state = try? JSONDecoder().decode(State.self, from: data) else {
            return State()
        }
        return state
    }

    private func save() {
        let url = Self.fileURL
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        if let data = try? JSONEncoder().encode(state) {
            try? data.write(to: url, options: .atomic)
        }
    }
}
#endif
