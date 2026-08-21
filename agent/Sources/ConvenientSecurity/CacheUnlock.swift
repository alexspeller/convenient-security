import Foundation
import LocalAuthentication

/// A biometric authorization, produced by the consent step, that the SE-cache can
/// present when reading a `.biometryCurrentSet` keychain item so the cold read
/// folds into the consent touch instead of prompting again.
///
/// It wraps the `LAContext` the consent provider already evaluated. Whether a
/// keychain read with an already-evaluated context skips a second prompt is an OS
/// behaviour we verify on hardware (see `packaging/spike`); the cache is correct
/// either way — a second prompt only ever costs a touch on a cold start.
///
/// `@unchecked Sendable`: the context is *handed off* from consent to the cache,
/// used serially, never shared across tasks. `LAContext` itself is not `Sendable`,
/// so this box is how it crosses the actor hop without weakening the type system
/// elsewhere.
public struct CacheUnlock: @unchecked Sendable {
    /// The evaluated context to present as `kSecUseAuthenticationContext`.
    public let context: LAContext

    public init(_ context: LAContext) {
        self.context = context
    }
}
