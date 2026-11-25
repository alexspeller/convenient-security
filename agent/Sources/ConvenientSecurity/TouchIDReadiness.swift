import Foundation
import LocalAuthentication

/// Whether this Mac can take the Touch ID touch every csec approval asks for,
/// as `csec setup` reports it before anything else. Consent is biometric only
/// (`BiometricConsent`), and a panel that cannot take a touch waits for a
/// paired iPhone, so a Mac without a usable sensor and an enrolled finger can
/// approve nothing on its own. The probe never prompts.
public enum TouchIDReadiness: Sendable, Equatable {
    case ready
    /// No sensor csec can use now: none built in, the lid closed, or no Magic
    /// Keyboard with Touch ID connected.
    case noSensor
    /// A sensor, but no finger enrolled for this user.
    case noEnrolledFinger
    /// Too many failed attempts; macOS asks for the password before Touch ID
    /// works again.
    case lockedOut
    /// The account has no login password, which Touch ID requires.
    case noPassword
    /// macOS refused for a reason csec does not recognise (its LAError code).
    case unrecognised(code: Int)

    /// What `canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`
    /// answered: `available`, or the LAError code it failed with.
    public static func classify(available: Bool, errorCode: Int?) -> TouchIDReadiness {
        if available { return .ready }
        switch errorCode.flatMap(LAError.Code.init(rawValue:)) {
        case .biometryNotAvailable?, .biometryDisconnected?, .biometryNotPaired?: return .noSensor
        case .biometryNotEnrolled?: return .noEnrolledFinger
        case .biometryLockout?: return .lockedOut
        case .passcodeNotSet?: return .noPassword
        default: return .unrecognised(code: errorCode ?? 0)
        }
    }

    /// This Mac, now, on a fresh context.
    public static func current() -> TouchIDReadiness {
        var error: NSError?
        let available = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        return classify(available: available, errorCode: error?.code)
    }

    public var canApprove: Bool { self == .ready }

    /// One plain sentence on what is wrong.
    public var problem: String {
        switch self {
        case .ready: return "Touch ID is ready."
        case .noSensor:
            return "This Mac has no Touch ID sensor csec can use right now: there is none built in, "
                + "the lid is closed, or no Magic Keyboard with Touch ID is connected."
        case .noEnrolledFinger: return "Touch ID has no fingerprint enrolled for this account."
        case .lockedOut: return "Touch ID is locked after too many failed attempts."
        case .noPassword: return "This account has no login password, and Touch ID needs one."
        case let .unrecognised(code): return "macOS says Touch ID cannot be used now (LocalAuthentication error \(code))."
        }
    }

    /// What the user can do about it.
    public var remedy: String {
        switch self {
        case .ready: return ""
        case .noSensor:
            return "Open the lid, or connect a Magic Keyboard with Touch ID, then run `csec setup` again."
        case .noEnrolledFinger:
            return "Add a fingerprint in System Settings → Touch ID & Password, then run `csec setup` again."
        case .lockedOut:
            return "Lock the screen and unlock it with your password, then run `csec setup` again."
        case .noPassword:
            return "Set a login password in System Settings → Users & Groups, add a fingerprint, "
                + "then run `csec setup` again."
        case .unrecognised:
            return "Check System Settings → Touch ID & Password, then run `csec setup` again."
        }
    }

    /// What does not work until Touch ID does.
    public static let consequence =
        "csec asks for a touch to approve every secret, SSH signature and sudo review, so until Touch ID "
        + "works no request can be approved on this Mac and secrets stay locked. Setup still configures "
        + "everything else, but leaves the sudo review off: it would have nothing to approve with."
}
