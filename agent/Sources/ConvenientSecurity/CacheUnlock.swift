import Foundation
import LocalAuthentication

/// A biometric authorization produced by consent. The SE-cache presents it when
/// reading a `.biometryCurrentSet` item, and the native provider presents it for
/// its `.biometryAny` key/pointer record, so cold Keychain access can fold into
/// the consent touch instead of prompting again.
///
/// It wraps the `LAContext` the consent provider already evaluated. Whether a
/// Keychain operation with that context skips a second prompt is an OS behavior
/// verified on signed hardware (see `packaging/spike`).
///
/// `@unchecked Sendable`: the context is handed from consent to serial cache or
/// provider operations, never used concurrently. `LAContext` itself is not
/// `Sendable`, so this box is how it crosses actor hops without weakening the
/// type system elsewhere.
public struct CacheUnlock: @unchecked Sendable {
    /// The evaluated context to present as `kSecUseAuthenticationContext`.
    public let context: LAContext

    public init(_ context: LAContext) {
        self.context = context
    }
}
