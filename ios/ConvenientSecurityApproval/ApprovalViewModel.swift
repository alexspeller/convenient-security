import CloudKit
import CSECRemoteApproval
import CSECRemoteApprovalCloudKit
import Foundation
import LocalAuthentication
import SwiftUI
import UIKit
import UserNotifications

struct PendingRemoteApproval: Identifiable, Equatable {
    let envelope: SignedRemoteApprovalRequest
    let mac: PinnedMac

    var id: String { envelope.request.requestID }
    var request: RemoteApprovalRequest { envelope.request }
    var review: RemoteApprovalReview { envelope.request.review }
    /// A restore-only review approves nothing new; its refusing button forgets
    /// the approvals instead of denying a request.
    var isRestoreOnly: Bool { review.kind == .restore }
    /// When the Mac opened this prompt. It does not run out: the Mac waits for
    /// whichever screen answers first and withdraws the request when it stops
    /// waiting, so the age is context for the reader, never a deadline.
    var createdAt: Date {
        Date(
            timeIntervalSince1970:
                TimeInterval(envelope.request.createdAtMilliseconds) / 1_000
        )
    }
    /// When the Mac closes this review if nobody answers (a coding agent's
    /// request, a sudo), or nil for one that waits as long as it takes. The
    /// card shows it as the Mac panel does; the card itself goes only when
    /// the Mac withdraws the request, as any other withdrawal.
    var closesAt: Date? {
        review.closesAtMilliseconds.map {
            Date(timeIntervalSince1970: TimeInterval($0) / 1_000)
        }
    }
}

/// A line the app shows at the top of the list after an action.
struct ApprovalOutcome: Equatable {
    enum Tone: Equatable {
        case success
        case info
        case failure
    }

    let tone: Tone
    let text: String
}

/// Whether a Mac's request can reach this iPhone while the app is closed.
enum NotificationState: Equatable {
    case unknown
    case notDetermined
    case enabled
    /// Notifications are refused, or allowed without alerts.
    case off

    var isEnabled: Bool { self == .enabled }
}

/// The Mac deleted its request record, which is how it says it is no longer
/// waiting: the local window answered first, the requesting command went away,
/// or csecd restarted and swept what it left behind.
private struct RemoteApprovalWithdrawnError: Error {}

/// A mailbox call iCloud did not answer within its bound (`mailboxCall`).
private struct MailboxNotAnswering: Error {}

/// One refresh, as its own mailbox calls see it (`RefreshRun.current`): once
/// one of them has not answered, the rest fail at once, since each would wait
/// out its bound too. A watch or a decision running beside the refresh is not
/// in it, so its calls neither stop the refresh nor are stopped by it.
@MainActor
private final class RefreshRun {
    var iCloudDidNotAnswer = false
}

private enum RefreshScope {
    @TaskLocal static var run: RefreshRun?
}

/// A Mac pairing code that decoded and passed every check, waiting for the
/// reader to look at which Mac it is before Face ID pins it.
struct MacPairingCandidate: Equatable {
    let pairing: RemoteApprovalMacPairing
    /// The pinned entry for this very Mac (same device ID), which pairing
    /// replaces.
    let replacing: PinnedMac?
    /// Other pinned Macs with the same name, told apart by their keys.
    let sameNamed: [PinnedMac]
    /// The Mac's own offer from the mailbox, not a pasted code.
    var offered = false

    var displayName: String { RemoteApprovalDisplayText.sanitized(pairing.macDeviceName) }

    var fingerprint: String {
        RemoteApprovalPairingCode.publicKeyFingerprint(pairing.macPublicKeyX963)
    }
}

@MainActor
final class ApprovalViewModel: ObservableObject {
    enum Setup: Equatable {
        case loading
        case notSetUp
        /// Set up by a build without the key-agreement key.
        case outdated
        /// The approval records could not be read just now (the iPhone may be
        /// locked). Read again on the next activation, push, or "Try again";
        /// never a reason to set up again.
        case temporarilyUnavailable(Int32)
        case unusable
        case ready
    }

    @Published private(set) var setup: Setup = .loading
    @Published private(set) var phonePairingCode: String?
    @Published private(set) var phoneFingerprint: String?
    @Published private(set) var pinnedMacs: [PinnedMac] = []
    /// Verified requests, oldest first. A card whose decision was sent stays,
    /// marked as sent, until its request leaves the mailbox.
    @Published private(set) var pending: [PendingRemoteApproval] = []
    @Published private(set) var sentDecisions: [String: RemoteApprovalDecision] = [:]
    /// Requests whose sent answer the Mac did not take: it is still waiting,
    /// but deleted this iPhone's answer, as csecd does with one it refuses.
    /// Their cards can be decided again, and say so.
    @Published private(set) var answersNotTaken: Set<String> = []
    @Published private(set) var decidingRequestID: String?
    /// Setup, pairing or unpairing is waiting on Face ID or iCloud.
    @Published private(set) var isBusy = false
    @Published private(set) var isRefreshing = false
    @Published private(set) var notifications: NotificationState = .unknown
    @Published private(set) var pushRegistrationFailed = false
    /// Why iCloud refused the subscription that raises request alerts, when it
    /// did with a failure retrying cannot fix. Cleared by a later save that
    /// works, which each refresh tries.
    @Published private(set) var subscriptionProblem: String?
    /// Why iCloud refused the subscription that tells this iPhone a request
    /// is over, when it did with a failure retrying cannot fix. Alerts still
    /// work without it; a settled request's alert and badge count then stay
    /// until the app runs or the next alert arrives. Each refresh tries again.
    @Published private(set) var settledSubscriptionProblem: String?
    /// Set when the mailbox could not be read; the list then shows the last
    /// requests this iPhone verified.
    @Published private(set) var mailboxUnreachable = false
    /// Why the iCloud account cannot carry requests, as iCloud last said: read
    /// at each activation and after a mailbox read or a decision fails. Nil
    /// while it can, or until it was asked.
    @Published private(set) var iCloudAccountProblem: RemoteApprovalAccountProblem?
    @Published private(set) var outcome: ApprovalOutcome?
    /// Bumped when the reader opens the app from an approval notification.
    @Published private(set) var pendingFocusRequest = 0
    /// The request whose alert the reader tapped, once it is on the list.
    @Published private(set) var focusedRequestID: String?
    @Published var macPairingCode = ""
    /// The Mac a pasted code or the Mac's offer names, shown before Face ID
    /// pins it.
    @Published private(set) var pairingCandidate: MacPairingCandidate?

    private let identityStore = PhoneIdentityStore()
    /// Created on first use: once a real Mac is pinned, or once the app looks
    /// for a Mac's offer or its iCloud account while it is on screen.
    private var relayInstance: (any PhoneMailbox)?
    /// Looks for a Mac's offer while the app is on screen.
    private var offerWatch: Task<Void, Never>?
    private var requestWatch: Task<Void, Never>?
    /// Offers turned down or refused in this run, by Mac ID and key, so the
    /// watch does not show the same one again every two seconds. The same Mac
    /// paired again has a new key, so its new offer still shows.
    private var declinedOffers: Set<String> = []
    private var identity: PhoneApprovalIdentity?
    private var statusPublication = PhoneStatusPublication()
    private var subscriptionEnsured = false
    private var settledSubscriptionEnsured = false
    /// `.ready` once the subscription is saved, `.subscriptionRefused` after a
    /// failure no retry fixes; nil until either is known.
    private var subscriptionState: RemoteApprovalPhoneAlertState?
    private var started = false
    private var refreshTask: Task<Bool, Never>?
    private var refreshAgain = false
    /// Requests this iPhone answered, or found withdrawn while answering,
    /// kept across runs of the app (`PhoneIdentityStore.loadDecidedRequestIDs`).
    /// The Mac never publishes a request ID twice, so one of these still or
    /// again in the mailbox — a delete the Mac could not make, or an old
    /// signed request saved again — is never shown as live. Bounded; the
    /// oldest are forgotten first.
    private var decidedRequestIDs: [String] = []
    private var decidedRequestIDSet: Set<String> = []
    /// Requests an alert named, read by their ID on every refresh the mailbox
    /// query does not return them, until they leave the mailbox: the query
    /// reads a bounded number of records in no promised order, so a large
    /// backlog could otherwise keep an alerted request off the list. Bounded;
    /// the oldest are forgotten first.
    private var alertedRequestIDs: [String] = []
    private static let maximumAlertedRequestIDs = 16
    /// Requests whose answer may be in the mailbox although its save reported
    /// a failure — a save whose reply was lost — until the card goes or an
    /// answer is sent.
    private var possiblySentRequestIDs: Set<String> = []
    /// Pinned Macs whose pairing confirmation was looked for since the app
    /// last became active, so a missing one is published again at most once
    /// per activation.
    private var confirmationsCheckedThisActivation: Set<String> = []
    #if DEBUG && targetEnvironment(simulator)
    /// The mailbox's offer, in the Simulator: one from a simulated Mac.
    private var simulatorOffer: SignedRemoteApprovalPairingOffer?
    /// The Mac that made it, so it can offer again with a new key.
    private var simulatorOfferMac: SimulatedMac?
    private let simulatedMac = SimulatedMac()
    private let lookalikeMac = SimulatedMac(deviceName: SimulatedMac.lookalikeName)
    private var simulatorRequests: [String: PendingRemoteApproval] = [:]
    private var simulatorUnlockChecks: [String: SimulatorUnlockCheck] = [:]
    #endif

    /// Face ID is up, or an action it started has not finished.
    var faceIDActionInProgress: Bool { isBusy || decidingRequestID != nil }

    /// The mailbox itself. Every call that can wait on iCloud goes through
    /// `mailboxCall`; only the account status, which the relay bounds itself,
    /// is asked here directly.
    private var relay: any PhoneMailbox {
        if let relayInstance { return relayInstance }
        #if DEBUG && targetEnvironment(simulator)
        if let simulated = SimulatedMailbox.shared {
            relayInstance = simulated
            return simulated
        }
        #endif
        let created = CloudKitRemoteApprovalRelay()
        relayInstance = created
        return created
    }

    /// How long a decision's save may take. Longer than a read's bound: a save
    /// cut off by it costs the reader another Face ID, so a slow save that
    /// works must not be. One cut off can still land; the next attempt then
    /// finds this iPhone's earlier answer in its slot and reports that one
    /// (`publishResponse`'s `keepingEarlierAnswer`), and a request withdrawn
    /// meanwhile says the earlier answer may have counted
    /// (`possiblySentRequestIDs`).
    static let decisionSaveNanoseconds: UInt64 = 15_000_000_000

    /// One mailbox call, within `bound`. A CloudKit call waits on an iCloud
    /// that does not answer with no end the app can count on: cancelling the
    /// task that awaits it does not end it, and neither do the operation's
    /// own request and resource timeouts. A decision, a pairing or a refresh
    /// that waited on one would hold Face ID, or every later refresh, until
    /// the app was relaunched. A call that does not answer in time throws
    /// `MailboxNotAnswering`, which every caller treats as the transient
    /// failure it is; within a refresh, the refresh's later calls then fail
    /// at once (`RefreshRun`). It is not awaited past the bound, and it goes
    /// on: a save given up on can still land.
    private func mailboxCall<Value: Sendable>(
        within bound: UInt64 = RemoteApprovalBound.readNanoseconds,
        _ call: @escaping @Sendable (any PhoneMailbox) async throws -> Value
    ) async throws -> Value {
        let run = RefreshScope.run
        if run?.iCloudDidNotAnswer == true { throw MailboxNotAnswering() }
        let relay = self.relay
        let answer = await RemoteApprovalBound.firstAnswer(
            within: bound,
            otherwise: Result<Value, any Error>?.none
        ) {
            do {
                return .success(try await call(relay))
            } catch {
                return .failure(error)
            }
        }
        guard let answer else {
            run?.iCloudDidNotAnswer = true
            throw MailboxNotAnswering()
        }
        return try answer.get()
    }

    /// Whether anything here talks to iCloud yet. On the iPhone, as soon as
    /// it is set up: the offer watch reads iCloud too. The Simulator test mode
    /// reads offers from its fixtures and makes no CloudKit call until a Mac
    /// is pinned, unless the simulated mailbox stands in for iCloud.
    private var usesICloud: Bool {
        guard setup == .ready else { return false }
        #if DEBUG && targetEnvironment(simulator)
        return SimulatedMailbox.shared != nil || !pinnedMacs.isEmpty
        #else
        return true
        #endif
    }

    // MARK: - Lifecycle

    func start() async {
        guard !started else { return }
        started = true
        loadIdentityState()
        watchForPairingOffers()
        watchPendingRequests()
        await refreshNotificationState()
        await checkICloudAccount()
        _ = await refresh()
    }

    func sceneBecameActive() async {
        await start()
        // A new activation: each pinned Mac's confirmation is looked for
        // once more.
        confirmationsCheckedThisActivation = []
        watchForPairingOffers()
        watchPendingRequests()
        reloadIdentityIfUnavailable()
        await refreshNotificationState()
        if setup == .ready, notifications == .notDetermined {
            await requestNotificationAuthorization()
        }
        await checkICloudAccount()
        _ = await refresh()
    }

    /// A push: silent (content-available) or the visible alert while the app
    /// is in the foreground. Neither carries a request field; an alert's
    /// record name says which request it is for, which is then read by its ID
    /// if the mailbox query leaves it out. The mailbox is fetched and every
    /// Mac signature verified as always.
    func handleRemoteNotification(alertRequestID: String? = nil) async -> Bool {
        await start()
        reloadIdentityIfUnavailable()
        if let alertRequestID {
            rememberAlerted(alertRequestID)
        }
        return await refresh()
    }

    /// The reader tapped the alert for `requestID` (nil if the alert named
    /// none): read it by its ID along with the mailbox, verify it like any
    /// other request, and bring its card up.
    func handleNotificationTap(requestID: String?) async {
        await start()
        reloadIdentityIfUnavailable()
        if let requestID {
            rememberAlerted(requestID)
        }
        _ = await refresh()
        if let requestID {
            await focus(onAlerted: requestID)
        } else {
            focusedRequestID = nil
        }
        pendingFocusRequest += 1
    }

    /// The card to bring up when the reader taps an alert: its request's, or
    /// the first one waiting.
    var pendingFocusTarget: String? {
        if let focusedRequestID, pending.contains(where: { $0.id == focusedRequestID }) {
            return focusedRequestID
        }
        return pending.first?.id
    }

    private func focus(onAlerted requestID: String) async {
        if pending.contains(where: { $0.id == requestID }) {
            focusedRequestID = requestID
            return
        }
        focusedRequestID = nil
        if decidedRequestIDSet.contains(requestID) {
            outcome = ApprovalOutcome(
                tone: .info,
                text: "This iPhone has already answered that request."
            )
        } else if usesICloud,
                  let presence = try? await mailboxCall({ try await $0.requestPresence(requestID: requestID) }) {
            switch presence {
            case .gone:
                outcome = ApprovalOutcome(
                    tone: .info,
                    text: "That request from your Mac is no longer waiting."
                )
            case .present where !presence.isWaiting(at: Date()):
                outcome = ApprovalOutcome(
                    tone: .info,
                    text: Self.quietRequestText
                )
            case .present:
                break
            }
        }
    }

    /// What a tapped alert says when its request's Mac has gone quiet
    /// (`RemoteApprovalLiveness`).
    static let quietRequestText =
        "Your Mac has not been in touch about that request for over ten minutes. "
        + "It may be asleep, offline or no longer running csec; the request shows here again if it comes back to it."

    private func rememberAlerted(_ requestID: String) {
        guard RemoteApprovalMailboxName.isCanonicalID(requestID),
              !alertedRequestIDs.contains(requestID) else { return }
        alertedRequestIDs.append(requestID)
        if alertedRequestIDs.count > Self.maximumAlertedRequestIDs {
            alertedRequestIDs.removeFirst()
        }
    }

    /// "Try again" on the records-unavailable screen.
    func retryLoadingIdentity() async {
        reloadIdentityIfUnavailable()
        _ = await refresh()
    }

    /// A read the Keychain refused (usually: not unlocked since restart) is
    /// simply read again; nothing is ever re-created because of one.
    private func reloadIdentityIfUnavailable() {
        guard case .temporarilyUnavailable = setup, !faceIDActionInProgress else { return }
        loadIdentityState()
    }

    func pushRegistration(succeeded: Bool) {
        pushRegistrationFailed = !succeeded
    }

    func dismissOutcome() {
        outcome = nil
    }

    private func loadIdentityState() {
        let protectedDataAvailable = UIApplication.shared.isProtectedDataAvailable
        switch identityStore.loadState(protectedDataAvailable: protectedDataAvailable) {
        case let .ready(loaded):
            let macs: [PinnedMac]
            do {
                macs = try identityStore.loadPinnedMacs()
            } catch let PhoneIdentityError.keychain(status) {
                // Not readable right now. Going on with an empty list would
                // let the next pairing overwrite every Mac pinned here.
                identity = nil
                setup = .temporarilyUnavailable(status)
                return
            } catch {
                macs = []
                outcome = ApprovalOutcome(
                    tone: .failure,
                    text: "The list of paired Macs could not be read. Pair your Mac again."
                )
            }
            let decided: [String]
            do {
                decided = try identityStore.loadDecidedRequestIDs()
            } catch let PhoneIdentityError.keychain(status) {
                // Going on without it would show requests already answered
                // as live, and the next answer would overwrite the list.
                identity = nil
                setup = .temporarilyUnavailable(status)
                return
            } catch {
                decided = []
            }
            restoreDecided(decided)
            identity = loaded
            pinnedMacs = macs
            statusPublication = identityStore.loadStatusPublication()
            if let code = try? RemoteApprovalPairingCode.encodePhone(
                loaded.pairing(appVersion: AppVersion.current)
            ) {
                phonePairingCode = code
                phoneFingerprint = loaded.fingerprint
                setup = .ready
            } else {
                identity = nil
                setup = .unusable
            }
        case .notSetUp:
            setup = .notSetUp
        case .outdated:
            setup = .outdated
        case let .temporarilyUnavailable(status):
            identity = nil
            setup = .temporarilyUnavailable(status)
        case .unusable:
            setup = .unusable
        }
    }

    // MARK: - Setup

    /// One Face ID creates both Secure Enclave keys and binds them.
    func setUpPhone() async {
        guard await createIdentity() else { return }
        // Outside the busy window, as after a pairing: neither the permission
        // prompt nor the refresh needs Face ID, and while the window is open
        // a Mac's offer is not shown, so one made as soon as setup has
        // finished would wait for both.
        await requestNotificationAuthorization()
        _ = await refresh()
    }

    /// `setUpPhone` up to its outcome: true once this iPhone is set up.
    private func createIdentity() async -> Bool {
        guard !faceIDActionInProgress else { return false }
        isBusy = true
        defer { isBusy = false }
        do {
            let created = try await identityStore.createIdentity(
                deviceName: UIDevice.current.name,
                reason: "Set up this iPhone to approve requests from your Mac"
            )
            identity = created
            pinnedMacs = []
            pending = []
            sentDecisions = [:]
            // A new identity has no Macs; what the old one answered went
            // with its records.
            decidedRequestIDs = []
            decidedRequestIDSet = []
            alertedRequestIDs = []
            statusPublication = PhoneStatusPublication()
            phonePairingCode = try RemoteApprovalPairingCode.encodePhone(
                created.pairing(appVersion: AppVersion.current)
            )
            phoneFingerprint = created.fingerprint
            setup = .ready
            outcome = ApprovalOutcome(
                tone: .success,
                text: "This iPhone is set up. Under Pair a Mac, copy the command and run it on your Mac."
            )
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "This iPhone was not set up: " + problemDescription(error)
            )
            return false
        }
        #if DEBUG && targetEnvironment(simulator)
        simulatorRequests = [:]
        simulatorUnlockChecks = [:]
        #endif
        return true
    }

    // MARK: - Pairing

    /// Decode and check a pasted Mac code, then show which Mac it names — its
    /// name and key — before anything asks for Face ID.
    func reviewMacPairingCode() {
        guard identity != nil, !faceIDActionInProgress else { return }
        pairingCandidate = nil
        let code = macPairingCode.trimmingCharacters(in: .whitespacesAndNewlines)
        if code.hasPrefix("csec-mac-v1:") {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "That code is from an older csec. Update csec on the Mac, run csec remote enable with this iPhone's code, and paste the csec-mac-v2: code it prints."
            )
            return
        }
        let pairing: RemoteApprovalMacPairing
        do {
            pairing = try RemoteApprovalPairingCode.decodeMac(code)
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "The Mac pairing code was not accepted. Paste the whole csec-mac-v2: code that csec remote enable printed."
            )
            return
        }
        outcome = nil
        review(pairing, offered: false)
    }

    /// Make `pairing` the candidate, unless it cannot be paired here: another
    /// iCloud container, or no room for it whatever the reader chooses.
    /// Returns whether it became the candidate.
    @discardableResult
    private func review(_ pairing: RemoteApprovalMacPairing, offered: Bool) -> Bool {
        guard pairing.cloudKitContainerIdentifier == PhoneIdentityStore.containerIdentifier else {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "That Mac uses a different iCloud container than this app, so the two cannot exchange approvals."
            )
            return false
        }
        let name = RemoteApprovalDisplayText.sanitized(pairing.macDeviceName)
        let replacing = pinnedMacs.first { $0.deviceID == pairing.macDeviceID }
        let sameNamed = pinnedMacs.filter {
            $0.deviceID != pairing.macDeviceID && $0.displayName == name
        }
        // Refused here only when no choice could fit it: replacing the
        // same-named Macs frees their places. `confirmPairing` checks the
        // choice actually made.
        guard pinnedMacs.count - (replacing == nil ? 0 : 1) - sameNamed.count
                < PhoneIdentityStore.maximumPinnedMacs else {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "This iPhone is paired with \(PhoneIdentityStore.maximumPinnedMacs) Macs already. Unpair one first."
            )
            return false
        }
        pairingCandidate = MacPairingCandidate(
            pairing: pairing,
            replacing: replacing,
            sameNamed: sameNamed,
            offered: offered
        )
        return true
    }

    func cancelPairing() {
        guard !faceIDActionInProgress else { return }
        if let candidate = pairingCandidate, candidate.offered {
            declinedOffers.insert(Self.offerKey(candidate.pairing))
        }
        pairingCandidate = nil
    }

    /// The pasted code changed: a candidate from a pasted code always
    /// describes the code on screen. A Mac's offer is not the pasted code, so
    /// typing leaves it.
    func pastedCodeChanged() {
        guard pairingCandidate?.offered == false else { return }
        cancelPairing()
    }

    // MARK: - Pairing offers

    static let offerPollNanoseconds: UInt64 = 2_000_000_000

    private static func offerKey(_ pairing: RemoteApprovalMacPairing) -> String {
        pairing.macDeviceID + "/" + RemoteApprovalPairingCode.publicKeyFingerprint(pairing.macPublicKeyX963)
    }

    /// While the app is on screen, look every two seconds for a Mac's offer
    /// to this iPhone: `csec remote enable` leaves one in the private iCloud
    /// database, so the Mac code need not be copied back by hand. The person
    /// is at the phone when they pair, so nothing alerts it; the watch lasts
    /// until the app leaves the screen.
    func watchForPairingOffers() {
        guard offerWatch == nil else { return }
        offerWatch = Task { [weak self] in
            while !Task.isCancelled {
                await self?.checkPairingOffer()
                try? await Task.sleep(nanoseconds: Self.offerPollNanoseconds)
            }
        }
    }

    func stopWatchingForPairingOffers() {
        offerWatch?.cancel()
        offerWatch = nil
        requestWatch?.cancel()
        requestWatch = nil
    }

    /// While the app is on screen, look every two seconds for cards whose
    /// request the Mac stopped waiting on — answered at the Mac, the command
    /// gone — or whose Mac has gone quiet, and take them, and their alerts,
    /// off the phone. The settled
    /// subscription's wake-up does the same through `refresh()`, but iOS
    /// delivers a content-available push only when it chooses to.
    func watchPendingRequests() {
        guard requestWatch == nil else { return }
        requestWatch = Task { [weak self] in
            while !Task.isCancelled {
                await self?.dropWithdrawnCards()
                try? await Task.sleep(nanoseconds: Self.offerPollNanoseconds)
            }
        }
    }

    /// Each unanswered card's request, read by its ID: one no longer in the
    /// mailbox leaves the list, and so does one whose Mac has gone quiet
    /// (`RemoteApprovalLiveness`), which the next refresh brings back once
    /// that Mac saves it again. A card being decided, or already answered
    /// (its follow-up decides), is left alone, as is anything not from the
    /// mailbox.
    func dropWithdrawnCards() async {
        guard UIApplication.shared.applicationState == .active,
              usesICloud, setup == .ready, !faceIDActionInProgress else { return }
        var dropped = false
        for item in pending where isUnansweredMailboxCard(item) {
            let requestID = item.id
            let presence: RemoteApprovalRequestPresence
            do {
                presence = try await mailboxCall { try await $0.requestPresence(requestID: requestID) }
            } catch is MailboxNotAnswering {
                // The next card's read would wait out its bound too.
                break
            } catch {
                continue
            }
            // What changed while it was read wins.
            guard !presence.isWaiting(at: Date()), isUnansweredMailboxCard(item), !faceIDActionInProgress,
                  pending.contains(where: { $0.id == item.id }) else { continue }
            guard presence == .gone else {
                // Quiet, not withdrawn: nothing was decided, so nothing is
                // remembered, and the card can come back.
                removeCard(item.id)
                dropped = true
                continue
            }
            // After a save that reported a failure, the Mac may have taken
            // that answer and stopped waiting because of it.
            if possiblySentRequestIDs.contains(item.id) {
                outcome = ApprovalOutcome(
                    tone: .info,
                    text: "\(item.mac.displayName) is no longer waiting. Your earlier answer may have been applied."
                )
                rememberDecided(item.id)
            }
            removeCard(item.id)
            dropped = true
        }
        if dropped { clearStaleAlerts() }
    }

    private func isUnansweredMailboxCard(_ item: PendingRemoteApproval) -> Bool {
        guard sentDecisions[item.id] == nil, decidingRequestID != item.id else { return false }
        #if DEBUG && targetEnvironment(simulator)
        if simulatorRequests[item.id] != nil { return false }
        #endif
        return true
    }

    /// Delivered alerts for requests this iPhone can no longer answer come
    /// off the lock screen and Notification Center. Run only after a mailbox
    /// read that succeeded, so a request missing only because iCloud was
    /// unreachable keeps its alert. Nothing waits for it: on a loaded iPhone
    /// Notification Center can take many seconds to list what it delivered,
    /// and a refresh that waited would hold every refresh asked for
    /// meanwhile, and the cards they bring, behind it.
    private func clearStaleAlerts() {
        let answerable = Set(pending.filter { sentDecisions[$0.id] == nil }.map(\.id))
        Task {
            let center = UNUserNotificationCenter.current()
            let delivered = await center.deliveredNotifications()
            let stale = RemoteApprovalDeliveredAlerts.stale(
                delivered.map {
                    (
                        identifier: $0.request.identifier,
                        requestID: CloudKitRemoteApprovalRelay.alertRequestID(
                            fromRemoteNotification: $0.request.content.userInfo
                        )
                    )
                },
                answerable: answerable
            )
            if !stale.isEmpty { center.removeDeliveredNotifications(withIdentifiers: stale) }
        }
    }

    /// Show the Mac's offer to this iPhone, once it verifies: made to this
    /// phone's ID and keys, and signed by the Mac key it offers. It is then
    /// exactly a pasted code's candidate — the reader checks the Mac's name
    /// and key, and Face ID pins it. An offer of a Mac already pinned with
    /// that key, or one turned down in this run, is not shown.
    func checkPairingOffer() async {
        guard UIApplication.shared.applicationState == .active,
              setup == .ready, let identity,
              pairingCandidate == nil, !faceIDActionInProgress else { return }
        guard let signed = await fetchPairingOffer(phoneDeviceID: identity.deviceID),
              let mac = try? signed.verifiedMac(
                  phoneDeviceID: identity.deviceID,
                  phonePublicKeyX963: identity.publicKeyX963,
                  phoneKeyAgreementPublicKeyX963: identity.keyAgreementPublicKeyX963
              ) else { return }
        let key = Self.offerKey(mac)
        // What changed while the offer was read wins.
        guard !declinedOffers.contains(key),
              !pinnedMacs.contains(where: {
                  $0.deviceID == mac.macDeviceID && $0.publicKeyX963 == mac.macPublicKeyX963
              }),
              setup == .ready, self.identity == identity,
              pairingCandidate == nil, !faceIDActionInProgress else { return }
        if !review(mac, offered: true) {
            declinedOffers.insert(key)
        }
    }

    private func fetchPairingOffer(phoneDeviceID: String) async -> SignedRemoteApprovalPairingOffer? {
        #if DEBUG && targetEnvironment(simulator)
        if SimulatedMailbox.shared == nil {
            return simulatorOffer
        }
        #endif
        return (try? await mailboxCall { try await $0.pairingOffer(phoneDeviceID: phoneDeviceID) }) ?? nil
    }

    /// Pin the reviewed Mac under Face ID and, with the same Face ID, sign the
    /// confirmation the Mac waits for before it reports the pairing ready.
    /// `replacingSameNamed` also unpairs the other Macs with the same name —
    /// the reader's answer to "is this the same Mac, paired again?".
    func confirmPairing(replacingSameNamed: Bool) async {
        guard await pinCandidate(replacingSameNamed: replacingSameNamed) else { return }
        // Outside the busy window: the refresh waits on iCloud, not on Face
        // ID, so the next Face ID action need not wait for it.
        _ = await refresh()
    }

    /// `confirmPairing` up to its outcome: true once the Mac is pinned.
    private func pinCandidate(replacingSameNamed: Bool) async -> Bool {
        guard let identity, let candidate = pairingCandidate, !faceIDActionInProgress else { return false }
        let pairing = candidate.pairing
        let name = candidate.displayName
        let removed = Set([pairing.macDeviceID]
            + (replacingSameNamed ? candidate.sameNamed.map(\.deviceID) : []))
        var macs = pinnedMacs.filter { !removed.contains($0.deviceID) }
        guard macs.count < PhoneIdentityStore.maximumPinnedMacs else {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "This iPhone is paired with \(PhoneIdentityStore.maximumPinnedMacs) Macs already. Unpair one first."
            )
            return false
        }

        isBusy = true
        defer { isBusy = false }
        let authorization: PhoneAuthorization
        do {
            authorization = try await identityStore.authorize(
                identity,
                reason: "Pair with \(name), key \(candidate.fingerprint), for remote approvals"
            )
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "\(name) was not paired: " + problemDescription(error)
            )
            return false
        }
        defer { authorization.invalidate() }
        let now = currentTimeMilliseconds()
        do {
            let confirmation = RemoteApprovalPairingConfirmation(
                macDeviceID: pairing.macDeviceID,
                macPublicKeyX963: pairing.macPublicKeyX963,
                phoneDeviceID: identity.deviceID,
                phoneKeyAgreementPublicKeyX963: identity.keyAgreementPublicKeyX963,
                phoneAppVersion: AppVersion.current,
                createdAtMilliseconds: now
            )
            let signed = SignedRemoteApprovalPairingConfirmation(
                confirmation: confirmation,
                signatureDER: try await authorization.sign(try confirmation.signingData())
            )
            try signed.verify(
                macDeviceID: pairing.macDeviceID,
                macPublicKeyX963: pairing.macPublicKeyX963,
                phoneDeviceID: identity.deviceID,
                phonePublicKeyX963: identity.publicKeyX963,
                phoneKeyAgreementPublicKeyX963: identity.keyAgreementPublicKeyX963
            )
            macs.append(PinnedMac(pairing, confirmation: signed, pairedAtMilliseconds: now))
            macs.sort {
                $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending
            }
            try identityStore.savePinnedMacs(macs)
            pinnedMacs = macs
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "\(name) was not paired: " + problemDescription(error)
            )
            return false
        }
        await signStatusIfDue(with: authorization)
        authorization.invalidate()
        pairingCandidate = nil
        macPairingCode = ""
        pending.removeAll { removed.contains($0.mac.deviceID) }

        let delivered = await deliverConfirmation(forMac: pairing.macDeviceID)
        outcome = delivered
            ? ApprovalOutcome(
                tone: .success,
                text: "Paired with \(name) (key \(candidate.fingerprint)). The Mac finishes pairing when it sees this iPhone's confirmation; its requests then appear here."
            )
            : ApprovalOutcome(
                tone: .info,
                text: "Paired with \(name) (key \(candidate.fingerprint)) on this iPhone, but iCloud could not be reached. The confirmation the Mac is waiting for is sent automatically once it can be."
            )
        return true
    }

    /// Stop showing a Mac's requests on this iPhone. Only this side changes:
    /// the Mac keeps its pairing until `csec remote disable`.
    func unpair(_ mac: PinnedMac) async {
        guard let identity, !faceIDActionInProgress,
              pinnedMacs.contains(where: { $0.deviceID == mac.deviceID }) else { return }
        isBusy = true
        defer { isBusy = false }
        let authorization: PhoneAuthorization
        do {
            authorization = try await identityStore.authorize(
                identity,
                reason: "Unpair \(mac.displayName), key \(mac.fingerprint)"
            )
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "\(mac.displayName) is still paired: " + problemDescription(error)
            )
            return
        }
        authorization.invalidate()
        let remaining = pinnedMacs.filter { $0.deviceID != mac.deviceID }
        do {
            try identityStore.savePinnedMacs(remaining)
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "\(mac.displayName) is still paired: the paired-Mac list could not be saved."
            )
            return
        }
        pinnedMacs = remaining
        pending.removeAll { $0.mac.deviceID == mac.deviceID }
        updateBadge()
        outcome = ApprovalOutcome(
            tone: .info,
            text: "Unpaired \(mac.displayName) on this iPhone. Run csec remote disable on the Mac as well: until then it keeps sending requests here, which this iPhone now ignores. Its own prompt still works."
        )
    }

    // MARK: - Mailbox

    /// Refresh the mailbox. Calls that arrive while one is running wait for it
    /// and make it run once more, so a push that lands mid-refresh is not lost.
    @discardableResult
    func refresh() async -> Bool {
        if let running = refreshTask {
            refreshAgain = true
            return await running.value
        }
        let task = Task { () -> Bool in
            var changed = false
            repeat {
                refreshAgain = false
                if await performRefresh() { changed = true }
            } while refreshAgain
            // Cleared in the same main-actor turn as the last check above, so
            // a caller can never wait on a task that will not run again.
            refreshTask = nil
            isRefreshing = false
            return changed
        }
        refreshTask = task
        isRefreshing = true
        return await task.value
    }

    private func performRefresh() async -> Bool {
        await RefreshScope.$run.withValue(RefreshRun()) {
            await performRefreshRun()
        }
    }

    private func performRefreshRun() async -> Bool {
        guard setup == .ready, identity != nil else { return false }
        let before = pending
        var cards: [PendingRemoteApproval] = []
        let macs = pinnedMacs.filter {
            $0.cloudKitContainerIdentifier == CloudKitRemoteApprovalRelay.defaultContainerIdentifier
        }
        if macs.isEmpty {
            mailboxUnreachable = false
            sentDecisions = [:]
        } else {
            await deliverPendingPublications()
            await ensureSubscription()
            do {
                var records = try await mailboxCall { try await $0.pendingRequestRecords() }
                records += await alertedRequestsLeftOut(of: records)
                let now = currentTimeMilliseconds()
                let nowDate = Date()
                // A request whose Mac has stopped saving it again has gone
                // quiet: a Mac that crashed, or was lost, leaves its record
                // behind with nothing listening for an answer. It is not
                // shown, and not forgotten either, so a Mac that wakes or
                // reconnects and saves it again brings it back.
                let waiting = records.filter { !$0.isQuiet(at: nowDate) }
                // The relay has already dropped every record not stored under
                // `request-<its requestID>`, so a signed request copied under
                // another name never gets this far.
                for envelope in waiting.map(\.envelope) {
                    let request = envelope.request
                    guard let mac = macs.first(where: { $0.deviceID == request.macDeviceID })
                    else { continue }
                    // Answered (or withdrawn) earlier, in this run or an
                    // earlier one, and no longer shown as sent: its record is
                    // still there or back — a delete the Mac could not make,
                    // or a replay — and the Mac's prompt has its answer.
                    if decidedRequestIDSet.contains(request.requestID),
                       sentDecisions[request.requestID] == nil {
                        continue
                    }
                    do {
                        try envelope.verify(macPublicKeyX963: mac.publicKeyX963, at: now)
                        cards.append(PendingRemoteApproval(envelope: envelope, mac: mac))
                    } catch {
                        // An unverifiable mailbox record is never rendered as
                        // actionable and never converted into a decision.
                    }
                }
                let inMailbox = Set(waiting.map(\.requestID))
                sentDecisions = sentDecisions.filter { inMailbox.contains($0.key) }
                mailboxUnreachable = false
                iCloudAccountProblem = nil
            } catch {
                mailboxUnreachable = true
                cards = before.filter { item in
                    macs.contains(where: { $0.deviceID == item.mac.deviceID })
                }
                // Signed out, restricted and not ready each say so under the
                // list; anything else is the network. An iCloud that did not
                // answer the read would not answer this either.
                if !(error is MailboxNotAnswering) { await checkICloudAccount() }
            }
        }
        // The card being decided stays until its decision finishes, even if
        // its request left meanwhile: the decision reports what happened.
        if let deciding = decidingRequestID,
           !cards.contains(where: { $0.id == deciding }),
           let item = before.first(where: { $0.id == deciding }) {
            cards.append(item)
        }
        #if DEBUG && targetEnvironment(simulator)
        appendValidSimulatorRequests(to: &cards)
        #endif
        cards.sort(by: Self.oldestFirst)
        var changed = cards != before
        pending = cards
        updateBadge()
        // A Mac that was asleep or offline reads a sent answer later than the
        // follow-up after sending looks; each refresh looks again. Only the
        // cards still in the mailbox are left marked as sent here.
        if !mailboxUnreachable {
            for requestID in sentDecisions.keys.sorted() {
                _ = await followUp(onSent: requestID, knownPending: true)
                if sentDecisions[requestID] == nil { changed = true }
            }
            clearStaleAlerts()
        }
        return changed
    }

    private static func oldestFirst(
        _ lhs: PendingRemoteApproval,
        _ rhs: PendingRemoteApproval
    ) -> Bool {
        if lhs.request.createdAtMilliseconds != rhs.request.createdAtMilliseconds {
            return lhs.request.createdAtMilliseconds < rhs.request.createdAtMilliseconds
        }
        return lhs.id < rhs.id
    }

    /// The alerted requests the query did not return, read by their ID. One
    /// the mailbox no longer holds is forgotten; one that cannot be read just
    /// now is asked for again on the next refresh. Each is verified with the
    /// rest, by the caller.
    private func alertedRequestsLeftOut(
        of listed: [RemoteApprovalMailboxRequest]
    ) async -> [RemoteApprovalMailboxRequest] {
        let listedIDs = Set(listed.map(\.requestID))
        var found: [RemoteApprovalMailboxRequest] = []
        for requestID in alertedRequestIDs where !listedIDs.contains(requestID) {
            do {
                if let record = try await mailboxCall({ try await $0.requestRecord(requestID: requestID) }) {
                    if record.requestID == requestID {
                        found.append(record)
                    }
                } else {
                    alertedRequestIDs.removeAll { $0 == requestID }
                }
            } catch {
                // Not readable just now.
            }
        }
        return found
    }

    /// The subscription carries the visible "approval requested" alert and the
    /// content-available wake-up. It is saved once; a failure is retried on the
    /// next refresh, and one no retry fixes is shown here and reported to the
    /// Mac rather than dropped. The settled subscription follows once the
    /// alert's is in place.
    private func ensureSubscription() async {
        if !subscriptionEnsured {
            do {
                try await mailboxCall { try await $0.ensureSubscriptions() }
                subscriptionEnsured = true
                subscriptionState = .ready
                subscriptionProblem = nil
            } catch is MailboxNotAnswering {
                // A delay, not a refusal; the refresh names it once.
                return
            } catch {
                subscriptionEnsured = false
                // An account that cannot carry anything refuses every save.
                // That is the account's problem, named under the list, not a
                // refusal of the subscription; the save is tried again once
                // it can.
                await checkICloudAccount()
                guard iCloudAccountProblem == nil else { return }
                recordSubscriptionFailure(error)
                return
            }
        }
        await ensureSettledSubscription()
    }

    /// Saved apart from the alert's, so its refusal — a Production schema not
    /// yet given it — leaves alerts working. A refusal no retry fixes is
    /// shown on its own line; a delay changes nothing. Each refresh tries
    /// again until it is saved.
    private func ensureSettledSubscription() async {
        guard !settledSubscriptionEnsured else { return }
        do {
            try await mailboxCall { try await $0.ensureSettledSubscription() }
            settledSubscriptionEnsured = true
            settledSubscriptionProblem = nil
        } catch {
            guard CloudKitRemoteApprovalRelay.alertState(afterSubscriptionFailure: error) != nil else {
                return
            }
            settledSubscriptionProblem = CloudKitRemoteApprovalRelay.failureSummary(error)
        }
    }

    // MARK: - iCloud account

    /// Ask iCloud whether its account can carry requests, so the line under
    /// the list names the cause — signed out, restricted, not ready — rather
    /// than calling every failure the network. Bounded by
    /// `CloudKitRemoteApprovalRelay.accountStatusBoundNanoseconds`; "could not
    /// determine" names nothing.
    private func checkICloudAccount() async {
        guard usesICloud else { return }
        switch await relay.approvalAccountStatus() {
        case .available:
            iCloudAccountProblem = nil
        case let .unavailable(problem):
            iCloudAccountProblem = problem
        }
    }

    /// What keeps iCloud from carrying requests, as a reason that fits after
    /// "No decision was sent: ", or nil when no account problem is known.
    private static func accountReason(_ problem: RemoteApprovalAccountProblem?) -> String? {
        switch problem {
        case .noAccount?:
            return "this iPhone is not signed in to iCloud. In Settings, sign in to the Apple Account your Mac uses."
        case .restricted?:
            return "iCloud is restricted on this iPhone by Screen Time or device management."
        case .temporarilyUnavailable?:
            return "this iPhone's iCloud account is not ready yet. Settings may ask you to verify your Apple Account."
        case .couldNotDetermine?, nil:
            return nil
        }
    }

    /// The line under the list when iCloud cannot carry requests: the
    /// account's problem when iCloud named one, the network otherwise.
    var relayProblem: String? {
        let cause: String
        if let reason = Self.accountReason(iCloudAccountProblem) {
            cause = "Requests from your Mac cannot reach this iPhone: " + reason
        } else if mailboxUnreachable {
            cause = "Could not reach iCloud."
        } else {
            return nil
        }
        return mailboxUnreachable
            ? cause + " Showing the requests this iPhone last verified."
            : cause
    }

    #if DEBUG && targetEnvironment(simulator)
    /// The UI tests' stand-in for a Production container that refuses the
    /// subscription: the refusal CloudKit returns, through the same path.
    func simulateRefusedSubscriptionForTests() {
        recordSubscriptionFailure(CKError(
            .invalidArguments,
            userInfo: [NSLocalizedDescriptionKey: "attempting to create a subscription in a production container"]
        ))
    }
    #endif

    private func recordSubscriptionFailure(_ error: Error) {
        // A delay worth retrying leaves what was known as it was.
        guard let state = CloudKitRemoteApprovalRelay.alertState(afterSubscriptionFailure: error) else {
            return
        }
        subscriptionState = state
        subscriptionProblem = CloudKitRemoteApprovalRelay.failureSummary(error)
    }

    /// Whether a request alerts this iPhone, as far as it knows: nil until the
    /// subscription has been saved or refused.
    var requestAlerts: RemoteApprovalPhoneAlertState? {
        if pushRegistrationFailed { return .pushRegistrationFailed }
        return subscriptionState
    }

    private func removeCard(_ requestID: String) {
        pending.removeAll { $0.id == requestID }
        sentDecisions.removeValue(forKey: requestID)
        answersNotTaken.remove(requestID)
        possiblySentRequestIDs.remove(requestID)
        updateBadge()
    }

    private func forgetDecided(_ requestID: String) {
        guard decidedRequestIDSet.remove(requestID) != nil else { return }
        decidedRequestIDs.removeAll { $0 == requestID }
        identityStore.saveDecidedRequestIDs(decidedRequestIDs)
    }

    private func rememberDecided(_ requestID: String) {
        guard decidedRequestIDSet.insert(requestID).inserted else { return }
        decidedRequestIDs.append(requestID)
        if decidedRequestIDs.count > PhoneIdentityStore.maximumDecidedRequestIDs {
            decidedRequestIDSet.remove(decidedRequestIDs.removeFirst())
        }
        identityStore.saveDecidedRequestIDs(decidedRequestIDs)
    }

    /// The stored list, then anything this run remembered that it lacks.
    private func restoreDecided(_ stored: [String]) {
        let remembered = decidedRequestIDs
        decidedRequestIDs = []
        decidedRequestIDSet = []
        for requestID in stored + remembered where decidedRequestIDSet.insert(requestID).inserted {
            decidedRequestIDs.append(requestID)
        }
        let excess = decidedRequestIDs.count - PhoneIdentityStore.maximumDecidedRequestIDs
        if excess > 0 {
            decidedRequestIDs.prefix(excess).forEach { decidedRequestIDSet.remove($0) }
            decidedRequestIDs.removeFirst(excess)
        }
    }

    private func updateBadge() {
        let count = pending.filter { sentDecisions[$0.id] == nil }.count
        if #available(iOS 17.0, *) {
            UNUserNotificationCenter.current().setBadgeCount(count, withCompletionHandler: nil)
        } else {
            UIApplication.shared.applicationIconBadgeNumber = count
        }
    }

    // MARK: - Deciding

    /// Freeze the card, collect one Face ID, answer the unlock challenge (an
    /// approval that carries one) and sign, verify with the Mac's own rule, and
    /// publish. One decision at a time.
    func decide(
        _ item: PendingRemoteApproval,
        decision: RemoteApprovalDecision,
        choice: RemoteApprovalChoice
    ) async {
        guard let identity, !faceIDActionInProgress,
              sentDecisions[item.id] == nil,
              pending.contains(where: { $0.id == item.id }) else { return }
        decidingRequestID = item.id
        defer { decidingRequestID = nil }
        let macName = item.mac.displayName

        // Freeze: the exact verified request and the selection on screen now.
        let frozen: FrozenDecision
        do {
            let now = currentTimeMilliseconds()
            try item.envelope.verify(macPublicKeyX963: item.mac.publicKeyX963, at: now)
            frozen = try FrozenDecision(
                request: item.request,
                decision: decision,
                choice: choice,
                decidedAtMilliseconds: now
            )
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "No decision was sent: this request did not verify."
            )
            return
        }

        let authorization: PhoneAuthorization
        do {
            authorization = try await identityStore.authorize(
                identity,
                reason: faceIDReason(for: item, decision: decision)
            )
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "No decision was sent: " + problemDescription(error)
            )
            return
        }
        defer { authorization.invalidate() }
        let envelope: SignedRemoteApprovalResponse
        do {
            envelope = try await frozen.signed(
                phoneDeviceID: identity.deviceID,
                phonePublicKeyX963: identity.publicKeyX963,
                phoneAppVersion: AppVersion.current,
                keys: authorization
            )
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "No decision was sent: " + problemDescription(error)
            )
            return
        }
        await signStatusIfDue(with: authorization)
        authorization.invalidate()

        #if DEBUG && targetEnvironment(simulator)
        if simulatorRequests[item.id] != nil {
            completeSimulatorDecision(item, envelope: envelope, identity: identity)
            return
        }
        #endif

        var iCloudAnswered = true
        do {
            if let earlier = try await publishDecision(envelope, for: item, identity: identity) {
                // This iPhone's own earlier answer is already in its slot (a
                // save whose reply was lost): that is the one the Mac reads,
                // so report exactly what it decided, not this tap.
                sentDecisions[item.id] = earlier.response.decision
                outcome = ApprovalOutcome(
                    tone: .info,
                    text: earlierText(for: item, decision: earlier.response.decision)
                )
            } else {
                sentDecisions[item.id] = decision
                outcome = ApprovalOutcome(
                    tone: .success,
                    text: sentText(for: item, decision: decision)
                )
            }
            answersNotTaken.remove(item.id)
            possiblySentRequestIDs.remove(item.id)
            rememberDecided(item.id)
            updateBadge()
            followSentRequest(item.id)
        } catch is RemoteApprovalWithdrawnError {
            // After a save that reported a failure, the Mac may have taken
            // that answer and then stopped waiting because of it.
            outcome = ApprovalOutcome(
                tone: .info,
                text: possiblySentRequestIDs.contains(item.id)
                    ? "\(macName) is no longer waiting. Your earlier answer may have been applied."
                    : "No decision was sent: \(macName) is no longer waiting."
            )
            rememberDecided(item.id)
            removeCard(item.id)
        } catch {
            // A save iCloud did not answer goes on and can still land, so
            // whatever the account says, the Mac may have this answer.
            iCloudAnswered = !(error is MailboxNotAnswering)
            if iCloudAnswered { await checkICloudAccount() }
            if iCloudAnswered, let reason = Self.accountReason(iCloudAccountProblem) {
                // An account that cannot carry anything saved nothing.
                outcome = ApprovalOutcome(
                    tone: .failure,
                    text: "No decision was sent: " + reason
                )
            } else {
                // The save may have landed with its reply lost, or, one
                // iCloud did not answer, may land yet.
                possiblySentRequestIDs.insert(item.id)
                outcome = ApprovalOutcome(
                    tone: .failure,
                    text: "Could not reach iCloud, so \(macName) may not have received this decision. Try again."
                )
            }
        }
        // After a save iCloud did not answer, the status's would wait out its
        // bound too, with this card still held; the next refresh sends it.
        if iCloudAnswered { await deliverStatusIfPending() }
    }

    /// Deleting the request record is how the Mac says it stopped waiting, so
    /// check for that before sending a decision nobody will read — Face ID may
    /// have been open for a while. Only a definite "withdrawn" stops the send:
    /// if the check itself fails, the Mac's pending table is still the
    /// authority on whether a decision counts, so the answer is worth sending.
    ///
    /// The answer goes to this iPhone's own slot for the request. If the slot
    /// already holds this iPhone's valid answer to the same request, that
    /// earlier answer is returned and nothing is overwritten; anything else in
    /// the slot is overwritten.
    ///
    /// The check gets a read's bound, and one that does not answer is no
    /// answer: the decision is sent. The save gets `decisionSaveNanoseconds`.
    private func publishDecision(
        _ envelope: SignedRemoteApprovalResponse,
        for item: PendingRemoteApproval,
        identity: PhoneApprovalIdentity
    ) async throws -> SignedRemoteApprovalResponse? {
        let requestID = item.id
        if let stillPending = try? await mailboxCall({ try await $0.requestIsPending(requestID: requestID) }),
           !stillPending {
            throw RemoteApprovalWithdrawnError()
        }
        let request = item.request
        let phoneDeviceID = identity.deviceID
        let phonePublicKeyX963 = identity.publicKeyX963
        return try await mailboxCall(within: Self.decisionSaveNanoseconds) { relay in
            try await relay.publishResponse(envelope) { existing in
                Self.isOwnAnswer(
                    existing,
                    to: request,
                    phoneDeviceID: phoneDeviceID,
                    phonePublicKeyX963: phonePublicKeyX963
                )
            }
        }
    }

    /// Whether `existing` is this iPhone's valid, signed answer to `request`,
    /// checked by the Mac's own acceptance rule.
    nonisolated private static func isOwnAnswer(
        _ existing: SignedRemoteApprovalResponse,
        to request: RemoteApprovalRequest,
        phoneDeviceID: String,
        phonePublicKeyX963: Data
    ) -> Bool {
        do {
            try existing.verify(
                for: request,
                pinnedPhoneDeviceID: phoneDeviceID,
                phonePublicKeyX963: phonePublicKeyX963
            )
            return true
        } catch {
            return false
        }
    }

    /// The Mac deletes the exchange — the request, then this iPhone's answer —
    /// as soon as it accepts the decision (or stops waiting), and deletes only
    /// the answer when it refuses it. Look a few times so a sent card leaves
    /// promptly, or opens again if the Mac refused the answer; each refresh
    /// looks too, for a Mac that reads the answer later.
    private func followSentRequest(_ requestID: String) {
        Task { [weak self] in
            for _ in 0..<6 {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                guard let self, self.sentDecisions[requestID] != nil else { return }
                if await self.followUp(onSent: requestID, knownPending: false) { return }
            }
        }
    }

    /// One look at a sent answer. Returns true once there is nothing left to
    /// follow: the request left the mailbox (its card goes), or the Mac is
    /// still waiting but the answer is no longer in this iPhone's slot (the
    /// card can be decided again). A read that fails changes nothing.
    private func followUp(onSent requestID: String, knownPending: Bool) async -> Bool {
        guard let identity else { return true }
        if !knownPending {
            guard let stillPending = try? await mailboxCall({ try await $0.requestIsPending(requestID: requestID) }) else {
                return false
            }
            guard sentDecisions[requestID] != nil else { return true }
            if !stillPending {
                removeCard(requestID)
                return true
            }
        }
        let inSlot: SignedRemoteApprovalResponse?
        do {
            let phoneDeviceID = identity.deviceID
            inSlot = try await mailboxCall { try await $0.response(for: requestID, phoneDeviceID: phoneDeviceID) }
        } catch RemoteApprovalRelayFailure.unreadableRecord {
            // Something that is not an answer took the slot.
            inSlot = nil
        } catch is DecodingError {
            inSlot = nil
        } catch is CloudKitRemoteApprovalError {
            inSlot = nil
        } catch {
            return false
        }
        guard sentDecisions[requestID] != nil,
              let item = pending.first(where: { $0.id == requestID }) else { return true }
        if let inSlot, Self.isOwnAnswer(
            inSlot,
            to: item.request,
            phoneDeviceID: identity.deviceID,
            phonePublicKeyX963: identity.publicKeyX963
        ) {
            // Still there: the Mac has not read it yet.
            return false
        }
        // csecd deletes an accepted exchange's request before its answer, so
        // the answer can be gone a moment before the request is: only a
        // request still pending after the answer went was refused.
        guard let stillPending = try? await mailboxCall({ try await $0.requestIsPending(requestID: requestID) }) else {
            return false
        }
        guard sentDecisions[requestID] != nil else { return true }
        if !stillPending {
            removeCard(requestID)
            return true
        }
        sentDecisions.removeValue(forKey: requestID)
        forgetDecided(requestID)
        answersNotTaken.insert(requestID)
        updateBadge()
        outcome = ApprovalOutcome(
            tone: .failure,
            text: "\(item.mac.displayName) did not accept this iPhone's answer and is still waiting. Decide again."
        )
        return true
    }

    private func faceIDReason(
        for item: PendingRemoteApproval,
        decision: RemoteApprovalDecision
    ) -> String {
        switch (decision, item.isRestoreOnly) {
        case (.approve, true): return "Reopen these approvals on \(item.mac.displayName)"
        case (.deny, true): return "Forget these approvals on \(item.mac.displayName)"
        case (.approve, false): return "Approve this request from \(item.mac.displayName)"
        case (.deny, false): return "Deny this request from \(item.mac.displayName)"
        }
    }

    private func earlierText(for item: PendingRemoteApproval, decision: RemoteApprovalDecision) -> String {
        let earlier: String
        switch (decision, item.isRestoreOnly) {
        case (.approve, true): earlier = "Reopen"
        case (.deny, true): earlier = "Forget"
        case (.approve, false): earlier = "Approve"
        case (.deny, false): earlier = "Deny"
        }
        return "This tap was not sent: this iPhone had already answered this request with \(earlier), and that answer reached iCloud. \(item.mac.displayName) acts on that one."
    }

    private func sentText(for item: PendingRemoteApproval, decision: RemoteApprovalDecision) -> String {
        switch (decision, item.isRestoreOnly) {
        case (.approve, true): return "Reopened. Sent to \(item.mac.displayName)."
        case (.deny, true): return "Forgotten. Sent to \(item.mac.displayName)."
        case (.approve, false): return "Approved. Sent to \(item.mac.displayName)."
        case (.deny, false): return "Denied. Sent to \(item.mac.displayName)."
        }
    }

    // MARK: - Confirmations and phone status

    /// Save a record that is already signed and kept until it is delivered,
    /// within a read's bound, the bound the Mac gives its own offer. Pairing
    /// waits for its confirmation's save before it shows the outcome and
    /// frees Face ID for the next action. A save that does not answer in time
    /// counts as not delivered, which every refresh retries; if it lands
    /// anyway, the retry saves the same record again.
    private func publishWithinBound(
        _ publish: @escaping @Sendable (any PhoneMailbox) async throws -> Void
    ) async -> Bool {
        (try? await mailboxCall(publish)) != nil
    }

    /// Publish a signed pairing confirmation that has not reached iCloud yet.
    /// It is public and already signed, so this needs no Face ID.
    @discardableResult
    private func deliverConfirmation(forMac macDeviceID: String) async -> Bool {
        guard let index = pinnedMacs.firstIndex(where: { $0.deviceID == macDeviceID }) else {
            return false
        }
        let mac = pinnedMacs[index]
        guard !mac.confirmationDelivered, let confirmation = mac.confirmation else { return true }
        guard await publishWithinBound({ try await $0.publishPairingConfirmation(confirmation) }) else {
            return false
        }
        guard let current = pinnedMacs.firstIndex(where: { $0.deviceID == macDeviceID }) else {
            return true
        }
        var updated = pinnedMacs
        updated[current].confirmationDelivered = true
        if (try? identityStore.savePinnedMacs(updated)) != nil {
            pinnedMacs = updated
        }
        await deliverStatusIfPending()
        return true
    }

    private func deliverPendingPublications() async {
        for mac in pinnedMacs where !mac.confirmationDelivered {
            await deliverConfirmation(forMac: mac.deviceID)
        }
        for mac in pinnedMacs where mac.confirmationDelivered
            && !confirmationsCheckedThisActivation.contains(mac.deviceID) {
            await recheckConfirmation(forMac: mac.deviceID)
        }
        await deliverStatusIfPending()
    }

    /// A delivered confirmation can later go missing — nothing in csec
    /// deletes it, but iCloud data can be reset or removed — and a csecd that
    /// restarts then reports the pairing unconfirmed until the phone pairs
    /// again. Once per activation, look for it, and publish it again if it is
    /// gone or the record holds something the Mac would not accept as this
    /// phone's confirmation of this pairing. It is public and already signed,
    /// so this needs no Face ID. A read that fails is tried again on the next
    /// refresh; a publication that fails marks the confirmation undelivered,
    /// which every refresh retries.
    private func recheckConfirmation(forMac macDeviceID: String) async {
        guard let identity,
              let mac = pinnedMacs.first(where: { $0.deviceID == macDeviceID }),
              let confirmation = mac.confirmation else { return }
        let found: SignedRemoteApprovalPairingConfirmation?
        do {
            found = try await mailboxCall { try await $0.pairingConfirmation(macDeviceID: macDeviceID) }
        } catch is DecodingError {
            found = nil
        } catch is CloudKitRemoteApprovalError {
            // A record that is not a confirmation at all.
            found = nil
        } catch {
            return
        }
        confirmationsCheckedThisActivation.insert(macDeviceID)
        if let found, (try? found.verify(
            macDeviceID: mac.deviceID,
            macPublicKeyX963: mac.publicKeyX963,
            phoneDeviceID: identity.deviceID,
            phonePublicKeyX963: identity.publicKeyX963,
            phoneKeyAgreementPublicKeyX963: identity.keyAgreementPublicKeyX963
        )) != nil {
            return
        }
        do {
            try await mailboxCall { try await $0.publishPairingConfirmation(confirmation) }
        } catch {
            guard let current = pinnedMacs.firstIndex(where: { $0.deviceID == macDeviceID }) else {
                return
            }
            var updated = pinnedMacs
            updated[current].confirmationDelivered = false
            if (try? identityStore.savePinnedMacs(updated)) != nil {
                pinnedMacs = updated
            }
        }
    }

    private var currentStatusFacts: PhoneStatusFacts? {
        // Never sign a guess about notifications.
        guard notifications != .unknown else { return nil }
        return PhoneStatusFacts(
            appVersion: AppVersion.current,
            protocolVersion: RemoteApprovalProtocolV3.version,
            notificationsAuthorized: notifications.isEnabled,
            requestAlerts: requestAlerts,
            // The card's switch over the kinds is exhaustive, so every kind
            // this build knows is one it shows.
            reviewKinds: RemoteApprovalReview.Kind.allCases.map(\.rawValue)
        )
    }

    /// Whether the Mac's view of this phone is out of date and no signed status
    /// already waits to correct it. Only a paired phone reports.
    private var statusNeedsSigning: Bool {
        guard let facts = currentStatusFacts, !pinnedMacs.isEmpty else { return false }
        if statusPublication.published == facts { return false }
        if let unpublished = statusPublication.unpublished,
           PhoneStatusFacts(unpublished.status) == facts {
            return false
        }
        return true
    }

    /// The status record is signed by the Face-ID-gated signing key, so it is
    /// signed only with a Face ID the reader has just given for something else
    /// — pairing, a decision — and never with a prompt of its own. A change
    /// noticed at launch or in the foreground waits for that Face ID.
    private func signStatusIfDue(with authorization: PhoneAuthorization) async {
        guard statusNeedsSigning, let facts = currentStatusFacts else { return }
        let identity = authorization.identity
        let status = RemoteApprovalPhoneStatus(
            phoneDeviceID: identity.deviceID,
            appVersion: facts.appVersion,
            protocolVersion: facts.protocolVersion,
            notificationsAuthorized: facts.notificationsAuthorized,
            requestAlerts: facts.requestAlerts,
            reviewKinds: facts.reviewKinds,
            updatedAtMilliseconds: currentTimeMilliseconds()
        )
        guard let data = try? status.signingData(),
              let signature = try? await authorization.sign(data) else { return }
        let signed = SignedRemoteApprovalPhoneStatus(status: status, signatureDER: signature)
        guard (try? signed.verify(
            phoneDeviceID: identity.deviceID,
            phonePublicKeyX963: identity.publicKeyX963
        )) != nil else { return }
        statusPublication.unpublished = signed
        identityStore.saveStatusPublication(statusPublication)
    }

    private func deliverStatusIfPending() async {
        guard let unpublished = statusPublication.unpublished, !pinnedMacs.isEmpty,
              await publishWithinBound({ try await $0.publishPhoneStatus(unpublished) })
        else { return }
        statusPublication.published = PhoneStatusFacts(unpublished.status)
        if statusPublication.unpublished == unpublished {
            statusPublication.unpublished = nil
        }
        identityStore.saveStatusPublication(statusPublication)
    }

    // MARK: - Notifications

    func requestNotificationAuthorization() async {
        let center = UNUserNotificationCenter.current()
        _ = try? await center.requestAuthorization(options: [.alert, .sound, .badge])
        await refreshNotificationState()
        UIApplication.shared.registerForRemoteNotifications()
    }

    func refreshNotificationState() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        switch settings.authorizationStatus {
        case .notDetermined:
            notifications = .notDetermined
        case .authorized, .ephemeral:
            notifications = settings.alertSetting == .enabled ? .enabled : .off
        case .denied, .provisional:
            notifications = .off
        @unknown default:
            notifications = .off
        }
    }

    // MARK: - Messages

    private func problemDescription(_ error: Error) -> String {
        switch error {
        case let PhoneIdentityError.biometrics(code):
            switch code {
            case .userCancel, .systemCancel, .appCancel, .userFallback:
                return "Face ID was cancelled."
            case .authenticationFailed:
                return "Face ID did not recognize you."
            case .biometryLockout:
                return "Face ID is locked after too many attempts. Unlock this iPhone with its passcode, then try again."
            case .biometryNotEnrolled, .passcodeNotSet:
                return "Face ID and a passcode must be set up on this iPhone."
            case .biometryNotAvailable:
                return "Face ID is not available to this app. Allow it in Settings › Convenient Security."
            default:
                return "Face ID did not complete."
            }
        case PhoneIdentityError.keyUnusable:
            return "this iPhone's approval key could not be used. If that keeps happening — for example after a change to Face ID — set up this iPhone again and pair your Mac again."
        case PhoneIdentityError.secureEnclaveUnavailable:
            return "this iPhone's Secure Enclave is not available."
        case PhoneIdentityError.keychain, PhoneIdentityError.invalidState:
            return "this iPhone's approval records could not be saved or read."
        case FrozenDecisionError.selectionNotOffered:
            return "the selected choice is not one this request offers."
        default:
            return "it did not complete."
        }
    }

    // MARK: - Simulator test mode

    #if DEBUG && targetEnvironment(simulator)
    func injectSimulatorRequest(_ fixture: SimulatorFixture) {
        guard let identity else {
            outcome = ApprovalOutcome(tone: .failure, text: "Set up the Simulator identity first.")
            return
        }
        do {
            let now = currentTimeMilliseconds()
            let mac = fixture.fromLookalikeMac ? lookalikeMac : simulatedMac
            let made = try mac.request(
                fixture,
                phoneDeviceID: identity.deviceID,
                phoneKeyAgreementPublicKeyX963: identity.keyAgreementPublicKeyX963,
                at: now
            )
            let item = PendingRemoteApproval(
                envelope: made.envelope,
                mac: PinnedMac(mac.pairing, confirmation: nil, pairedAtMilliseconds: now)
            )
            simulatorRequests[item.id] = item
            simulatorUnlockChecks[item.id] = made.unlock
            pending.append(item)
            pending.sort(by: Self.oldestFirst)
            updateBadge()
            outcome = ApprovalOutcome(
                tone: .info,
                text: "Injected a signed \(fixture.menuTitle.lowercased()) request. Decide it with simulated Face ID."
            )
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "The signed Simulator request could not be created."
            )
        }
    }

    /// Play a Mac running `csec remote enable` with this iPhone's code: a new
    /// simulated Mac, with its own ID and key, leaves its signed offer where
    /// the offer watch reads it — the simulated mailbox, when it is on.
    /// `sameMacNewKey` offers again as the last Mac offered, under its ID and
    /// name but with a new key.
    func offerSimulatorPairing(sameMacNewKey: Bool = false) async {
        guard let identity else {
            outcome = ApprovalOutcome(tone: .failure, text: "Set up the Simulator identity first.")
            return
        }
        do {
            if let mailbox = SimulatedMailbox.shared {
                try mailbox.offerPairing(to: identity, sameMacNewKey: sameMacNewKey)
            } else {
                let mac: SimulatedMac
                if sameMacNewKey, let last = simulatorOfferMac {
                    mac = SimulatedMac(deviceName: last.deviceName, deviceID: last.deviceID)
                } else {
                    mac = SimulatedMac()
                }
                simulatorOffer = try mac.offer(
                    to: identity.deviceID,
                    phonePublicKeyX963: identity.publicKeyX963,
                    phoneKeyAgreementPublicKeyX963: identity.keyAgreementPublicKeyX963
                )
                simulatorOfferMac = mac
            }
        } catch {
            outcome = ApprovalOutcome(tone: .failure, text: "The simulated Mac's offer could not be signed.")
            return
        }
        await checkPairingOffer()
    }

    /// Play the simulated mailbox's paired Mac leaving a request for this
    /// iPhone, then refresh as its push would. `leftOutOfList` keeps it out
    /// of the mailbox query, as a backlog larger than the query reads can.
    func postSimulatedMailboxRequest(_ fixture: SimulatorFixture, leftOutOfList: Bool = false) async {
        guard let mailbox = SimulatedMailbox.shared, let identity else { return }
        do {
            guard try mailbox.postRequest(
                fixture,
                pinnedMacIDs: Set(pinnedMacs.map(\.deviceID)),
                identity: identity,
                leftOutOfQuery: leftOutOfList
            ) != nil else {
                outcome = ApprovalOutcome(
                    tone: .failure,
                    text: "Pair a Mac from the simulated mailbox first."
                )
                return
            }
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "The simulated Mac's request could not be signed."
            )
            return
        }
        outcome = ApprovalOutcome(
            tone: .info,
            text: "Posted a signed \(fixture.menuTitle.lowercased()) request to the simulated mailbox."
        )
        _ = await refresh()
    }

    /// As if the pairing confirmations went missing from iCloud.
    func deleteSimulatedMailboxConfirmations() {
        SimulatedMailbox.shared?.deletePairingConfirmations()
        outcome = ApprovalOutcome(
            tone: .info,
            text: "Deleted the pairing confirmations from the simulated mailbox."
        )
    }

    /// Switch the simulated mailbox's iCloud account, then look again as an
    /// activation does.
    func setSimulatedICloud(_ account: SimulatedICloud) async {
        guard let mailbox = SimulatedMailbox.shared else { return }
        mailbox.iCloud = account
        await checkICloudAccount()
        _ = await refresh()
    }

    /// The launch argument's stand-in for a tap on the alert for the
    /// simulated mailbox's latest request its query leaves out: what the
    /// notification delegate does with the alert's request ID.
    func openAlertForSimulatedHiddenRequest() async {
        await handleNotificationTap(requestID: SimulatedMailbox.shared?.lastRequestLeftOutOfQuery)
    }

    func injectAllSimulatorRequests() {
        for fixture in SimulatorFixture.allCases {
            injectSimulatorRequest(fixture)
        }
        outcome = ApprovalOutcome(
            tone: .info,
            text: "Injected one signed request of each kind. Decide them with simulated Face ID."
        )
    }

    /// Play the simulated Mac: accept the decision with the Mac's own check,
    /// and for a cold-unlock approval open the remote key with the answer.
    private func completeSimulatorDecision(
        _ item: PendingRemoteApproval,
        envelope: SignedRemoteApprovalResponse,
        identity: PhoneApprovalIdentity
    ) {
        let check = simulatorUnlockChecks[item.id]
        simulatorRequests.removeValue(forKey: item.id)
        simulatorUnlockChecks.removeValue(forKey: item.id)
        removeCard(item.id)
        do {
            let selection = try envelope.verify(
                for: item.request,
                pinnedPhoneDeviceID: identity.deviceID,
                phonePublicKeyX963: identity.publicKeyX963
            )
            guard let selection else {
                outcome = ApprovalOutcome(
                    tone: .success,
                    text: "Denied (Simulator). The simulated Mac accepted the signed denial; no key agreement was computed."
                )
                return
            }
            var parts = ["Approved (Simulator). The simulated Mac accepted it"]
            if let scopeID = selection.scopeOptionID,
               let option = item.review.scopeOptions.first(where: { $0.id == scopeID }) {
                parts.append("scope “\(option.title)”")
            }
            if let index = selection.durationIndex, index < item.review.durationOptions.count {
                parts.append("for “\(item.review.durationOptions[index])”")
            }
            if item.review.delegation?.pairing != nil {
                parts.append(selection.pairingLineShown ? "and pairs it for auto mode" : "without pairing")
            }
            var text = parts.joined(separator: ", ") + "."
            if let check {
                guard let answer = selection.unlockAnswer else {
                    outcome = ApprovalOutcome(
                        tone: .failure,
                        text: "The approval carried no unlock answer."
                    )
                    return
                }
                try SimulatedMac.checkUnlock(check, answer: answer)
                text += " The unlock answer opened the simulated Mac's remote key and the storage sealed to it."
            }
            outcome = ApprovalOutcome(tone: .success, text: text)
        } catch {
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "The simulated Mac rejected this decision: \(error)"
            )
        }
    }

    private func appendValidSimulatorRequests(to cards: inout [PendingRemoteApproval]) {
        let now = currentTimeMilliseconds()
        for (requestID, item) in simulatorRequests {
            do {
                try item.envelope.verify(macPublicKeyX963: item.mac.publicKeyX963, at: now)
                if !cards.contains(where: { $0.id == requestID }) {
                    cards.append(item)
                }
            } catch {
                simulatorRequests.removeValue(forKey: requestID)
                simulatorUnlockChecks.removeValue(forKey: requestID)
            }
        }
    }
    #endif
}

/// The paired list's cards decide through the model: Face ID, the phone's
/// signing key, the mailbox.
extension ApprovalViewModel: ApprovalCardHost {
    var decisionsReachAMac: Bool { true }
}
