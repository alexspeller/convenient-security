import Foundation

/// At-rest cache for resolved secrets. The production implementation
/// (`KeychainSecretCache`) keeps a warm in-heap tier for zero-touch in-grant
/// fetches and a cold tier that stores each value in the data-protection keychain
/// under a `.biometryCurrentSet` ACL, so the on-disk ciphertext is useless without
/// the Secure Enclave and a live biometric. See DESIGN.md (Resolution + cache).
public protocol SecretCache: Sendable {
    /// The cached value, or nil on miss / expiry.
    ///
    /// A warm-tier hit returns with no biometric. A cold-tier (keychain) read is
    /// only attempted when `unlock` is present — the consent context that just
    /// authorized the grant — so the cache never raises a biometric prompt the
    /// caller didn't already consent to. With no `unlock`, a warm miss is a miss.
    func get(_ uri: String, unlock: CacheUnlock?) async throws -> String?
    /// Persist a value for at most `maxAge`. Writing the keychain item needs no
    /// biometric; only reading it back does.
    func put(_ uri: String, value: String, maxAge: TimeInterval) async throws
    /// Drop a cached value from both tiers (e.g. on rotation).
    func invalidate(_ uri: String) async
}

/// A cache that never persists — used by the local/e2e agents that have no
/// entitlement to the data-protection keychain. Every `get` is a miss.
public struct NullSecretCache: SecretCache {
    public init() {}
    public func get(_ uri: String, unlock: CacheUnlock?) async throws -> String? { nil }
    public func put(_ uri: String, value: String, maxAge: TimeInterval) async throws {}
    public func invalidate(_ uri: String) async {}
}
