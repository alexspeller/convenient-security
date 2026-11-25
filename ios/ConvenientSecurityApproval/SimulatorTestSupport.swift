#if DEBUG && targetEnvironment(simulator)
import Foundation
import SwiftUI

/// What the simulated Face ID and keys did since launch, for the UI tests in
/// `ConvenientSecurityApprovalUITests`: that one action costs exactly one Face
/// ID, and that only an approval of a request carrying an unlock challenge
/// computes a key agreement. Every recording is awaited before the action
/// goes on, so the counts are final by the time its outcome is on screen.
@MainActor
final class SimulatorInstrumentation: ObservableObject {
    static let shared = SimulatorInstrumentation()

    /// `evaluatePolicy` calls, each one Face ID sheet. The Simulator's keys
    /// are software keys, so no key use raises a sheet of its own.
    @Published private(set) var faceIDPrompts = 0
    /// Of those, the ones a matching face passed.
    @Published private(set) var faceIDMatches = 0
    /// Key agreements with the key-agreement key to answer an unlock
    /// challenge (the throwaway one at setup is not counted).
    @Published private(set) var unlockKeyAgreements = 0
    /// Signatures the phone's signing key made after setup: decisions,
    /// pairing confirmations and statuses. The demo must never add one.
    @Published private(set) var phoneKeySignatures = 0

    func recordFaceIDPrompt() {
        faceIDPrompts += 1
    }

    func recordFaceIDMatch() {
        faceIDMatches += 1
    }

    func recordUnlockKeyAgreement() {
        unlockKeyAgreements += 1
    }

    func recordPhoneKeySignature() {
        phoneKeySignatures += 1
    }
}

/// The counts, in a strip under the list so they are on screen however far
/// it is scrolled. Shown in full: the label VoiceOver reads is what is drawn. The
/// strip is instrumentation, so it stays small at any text size.
///
/// Its accessibility value says whether notifications are still undecided,
/// as the app last read them from the system. The system asks for permission
/// only while they are, so that, not anything a test runner remembers, is
/// when setup must raise the prompt: xcodebuild relaunches the runner after a
/// test times out or crashes, and a relaunched runner has forgotten the
/// earlier setups. It is a value rather than drawn text so the strip stays one
/// line on the smallest iPhone: a second line covers the list's last control.
struct SimulatorCountersView: View {
    @ObservedObject var instrumentation: SimulatorInstrumentation
    let notifications: NotificationState
    /// Whether the app is active: a Face ID sheet makes it inactive until the
    /// sheet has gone, and the tests wait for that before going on.
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Text(
            "Simulator counters: Face ID prompts \(instrumentation.faceIDPrompts), "
                + "matched \(instrumentation.faceIDMatches), "
                + "key agreements \(instrumentation.unlockKeyAgreements), "
                + "signatures \(instrumentation.phoneKeySignatures)"
        )
        .font(.caption2.monospacedDigit())
        .dynamicTypeSize(...DynamicTypeSize.large)
        // Still one line on the smallest iPhone, scaled down rather than cut.
        .lineLimit(1)
        .minimumScaleFactor(0.5)
        .foregroundStyle(.orange)
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(.bar)
        .accessibilityIdentifier("simulator-counters")
        .accessibilityValue("notifications \(notificationsWord); scene \(sceneWord)")
    }

    private var sceneWord: String {
        switch scenePhase {
        case .active: "active"
        case .inactive: "inactive"
        case .background: "background"
        @unknown default: "unknown"
        }
    }

    private var notificationsWord: String {
        switch notifications {
        case .unknown: "unread"
        case .notDetermined: "undecided"
        case .enabled: "on"
        case .off: "off"
        }
    }
}

/// Launch arguments the UI tests pass so each test starts from a known
/// state. The Simulator keeps Keychain items across app reinstalls, so
/// without them a test would find whatever the last one left.
enum SimulatorLaunchArgument {
    /// Delete this Simulator's approval records, and the simulated mailbox,
    /// before anything reads them: the app starts not set up.
    static let eraseIdentity = "--csec-simulator-erase-identity"
    /// After erasing, store a protocol v2 (format 1) identity, so the app
    /// finds a setup made by an earlier version.
    static let seedLegacyIdentity = "--csec-simulator-seed-legacy-identity"
    /// After erasing, store an identity record that does not decode.
    static let seedUndecodableIdentity = "--csec-simulator-seed-undecodable-identity"
    /// After erasing, store an identity whose keys do not match it.
    static let seedMismatchedIdentity = "--csec-simulator-seed-mismatched-identity"
    /// Refuse every Keychain read, as a locked iPhone refuses them before its
    /// first unlock, until the Simulator button on the unavailable screen
    /// lifts it.
    static let refuseKeychainReads = "--csec-simulator-refuse-keychain-reads"
    /// Start as if iCloud refused the request subscription.
    static let refuseSubscription = "--csec-simulator-refuse-subscription"
    /// Have the simulated mailbox refuse the settled subscription, as a
    /// Production container whose schema was never given it does.
    static let refuseSettledSubscription = "--csec-simulator-refuse-settled-subscription"
    /// Use `SimulatedMailbox` in place of the private iCloud database.
    static let mailbox = "--csec-simulator-mailbox"
    /// The simulated mailbox's iCloud account, from launch; available
    /// otherwise.
    static let iCloudSignedOut = "--csec-simulator-icloud-signed-out"
    static let iCloudRestricted = "--csec-simulator-icloud-restricted"
    static let iCloudNotReady = "--csec-simulator-icloud-not-ready"
    static let iCloudUnreachable = "--csec-simulator-icloud-unreachable"
    /// Open the app as a tap on the alert for the simulated mailbox's latest
    /// request that its query leaves out.
    static let openAlertForHiddenRequest = "--csec-simulator-open-alert-for-hidden-request"

    @MainActor
    static func apply(_ arguments: [String]) {
        let store = PhoneIdentityStore()
        let seeds = [seedLegacyIdentity, seedUndecodableIdentity, seedMismatchedIdentity]
        if arguments.contains(eraseIdentity) || seeds.contains(where: arguments.contains) {
            store.eraseForSimulatorTests()
            SimulatedMailbox.eraseStoredState()
        }
        if arguments.contains(seedLegacyIdentity) {
            store.seedLegacyIdentityForSimulatorTests()
        }
        if arguments.contains(seedUndecodableIdentity) {
            store.seedUndecodableIdentityForSimulatorTests()
        }
        if arguments.contains(seedMismatchedIdentity) {
            store.seedMismatchedIdentityForSimulatorTests()
        }
        if arguments.contains(refuseKeychainReads) {
            SimulatorKeychainRefusal.shared.isOn = true
        }
    }

    /// The simulated mailbox's account as the launch arguments set it.
    static func iCloud(_ arguments: [String]) -> SimulatedICloud {
        if arguments.contains(iCloudSignedOut) { return .signedOut }
        if arguments.contains(iCloudRestricted) { return .restricted }
        if arguments.contains(iCloudNotReady) { return .notReady }
        if arguments.contains(iCloudUnreachable) { return .unreachable }
        return .available
    }
}

/// Whether the Simulator refuses Keychain reads the way a locked iPhone does
/// (`errSecInteractionNotAllowed`). Writes are not refused, so a bug that set
/// up again while the records were unreadable would replace them, and the UI
/// test that checks the identity survives would see it.
final class SimulatorKeychainRefusal: @unchecked Sendable {
    static let shared = SimulatorKeychainRefusal()

    private let lock = NSLock()
    private var refusing = false

    var isOn: Bool {
        get { lock.withLock { refusing } }
        set { lock.withLock { refusing = newValue } }
    }
}
#endif
