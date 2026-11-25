import Foundation

/// At-rest cache for resolved secrets. The production implementation
/// (`KeychainSecretCache`) keeps a warm in-heap tier for zero-touch in-grant
/// fetches and a cold tier that stores each value in the data-protection keychain
/// under a `.biometryCurrentSet` ACL, so the on-disk ciphertext is useless without
/// the Secure Enclave and a live biometric. See DESIGN.md (Resolution + cache).
public protocol SecretCache: Sendable {
    /// The cached value, or nil on a miss.
    ///
    /// A warm-tier hit returns with no biometric. A cold-tier read is only
    /// attempted when `unlock` is present — the consent context that just
    /// authorized the grant, or the remote unlock a verified phone approval
    /// opened, which reads the entry's remote-unlock mirror instead of the
    /// biometric item — so the cache never raises a biometric prompt the
    /// caller didn't already consent to. With no `unlock`, a warm miss is a
    /// miss.
    func get(_ uri: String, unlock: CacheUnlock?) async throws -> Data?
    /// Persist a value, replacing any held for `uri`. It is kept until
    /// `invalidate` removes it (e.g. on rotation) or a later `put` replaces
    /// it, never dropped on a clock. Writing the keychain item needs no
    /// biometric; only reading it back does.
    func put(_ uri: String, value: Data) async throws
    /// Drop a cached value from every tier (e.g. on rotation). False when an
    /// at-rest copy may remain that a later unlock could still read; the
    /// failure is also logged, value-free.
    @discardableResult
    func invalidate(_ uri: String) async -> Bool
    /// Whether a value for `uri` is held in any tier, so a consent
    /// context could read it back. Reads neither the value nor anything that
    /// needs a biometric, and never prompts.
    func holds(_ uri: String) async -> Bool
    /// Whether a remote unlock could read `uri` back: a current remote-unlock
    /// mirror of its entry exists. Attributes only; never prompts.
    func holdsRemoteUnlockMirror(_ uri: String) async -> Bool
    /// Mirror every cold entry, reading each with `localUnlock`, the one
    /// evaluated context remote-unlock enrollment spent. The warm tier is left
    /// as it was.
    func backfillRemoteUnlockMirrors(localUnlock: CacheUnlock) async -> RemoteUnlockBackfillReport
}

public extension SecretCache {
    func holdsRemoteUnlockMirror(_ uri: String) async -> Bool { false }
    func backfillRemoteUnlockMirrors(localUnlock: CacheUnlock) async -> RemoteUnlockBackfillReport {
        RemoteUnlockBackfillReport()
    }
}

/// A cache that never persists — used by the local/e2e agents that have no
/// entitlement to the data-protection keychain. Every `get` is a miss.
public struct NullSecretCache: SecretCache {
    public init() {}
    public func get(_ uri: String, unlock: CacheUnlock?) async throws -> Data? { nil }
    public func put(_ uri: String, value: Data) async throws {}
    @discardableResult
    public func invalidate(_ uri: String) async -> Bool { true }
    public func holds(_ uri: String) async -> Bool { false }
}
