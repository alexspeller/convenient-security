import Foundation
import LocalAuthentication

/// A biometric authorization produced by consent. The SE-cache presents it when
/// reading a `.biometryCurrentSet` item, and the native provider presents it for
/// its `.biometryAny` key/pointer record, so cold Keychain access can fold into
/// the consent touch instead of prompting again.
///
/// It is one of two things:
///
/// - **Local** — the `LAContext` the consent provider already evaluated.
///   Whether a Keychain operation with that context skips a second prompt is an
///   OS behavior verified on signed hardware (see `packaging/spike`). Only a
///   local unlock opens the biometric Keychain items themselves, so only a local
///   unlock can write native storage.
/// - **Remote** — the remote-unlock key a verified phone approval opened
///   (`RemoteUnlockKey`). It opens only the remote-unlock mirrors
///   (`RemoteUnlockStore`), so it reads cold storage and never writes it.
///
/// `@unchecked Sendable`: the context is handed from consent to serial cache or
/// provider operations, never used concurrently. `LAContext` itself is not
/// `Sendable`, so this box is how it crosses actor hops without weakening the
/// type system elsewhere. The remote key is `Sendable` on its own.
public struct CacheUnlock: @unchecked Sendable {
    private enum Source {
        case local(LAContext)
        case remote(RemoteUnlockKey)
    }

    private let source: Source

    public init(_ context: LAContext) {
        self.source = .local(context)
    }

    public init(remote: RemoteUnlockKey) {
        self.source = .remote(remote)
    }

    /// The evaluated context to present as `kSecUseAuthenticationContext`, or
    /// nil for a remote unlock, which has none and must never reach a query
    /// for a biometric item (without a context that query would raise its own
    /// Touch ID sheet).
    public var context: LAContext? {
        if case let .local(context) = source { return context }
        return nil
    }

    /// The opened remote-unlock key, or nil for a local unlock.
    public var remote: RemoteUnlockKey? {
        if case let .remote(key) = source { return key }
        return nil
    }

    /// Whether this is a local, evaluated `LAContext`: the only kind of unlock
    /// that opens (and so can update) a biometric Keychain item.
    public var isLocal: Bool { context != nil }

    /// Ends the authorization: a local context is invalidated, a remote key is
    /// dropped, so nothing holding a copy of this unlock can use it again.
    public func invalidate() {
        switch source {
        case let .local(context): context.invalidate()
        case let .remote(key): key.invalidate()
        }
    }
}
