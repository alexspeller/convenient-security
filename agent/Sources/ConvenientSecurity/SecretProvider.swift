import Foundation

/// A resolved secret plus a hint about how long it may be cached at rest.
public struct ResolvedSecret: Sendable {
    public let value: String
    public let cacheHint: CacheHint

    public init(value: String, cacheHint: CacheHint) {
        self.value = value
        self.cacheHint = cacheHint
    }
}

public enum CacheHint: Sendable, Equatable {
    /// Safe to cache at rest (SE-gated) for at most `maxAge`.
    case cacheable(maxAge: TimeInterval)
    /// Never persist; resolve live every time.
    case noCache
}

/// A secret backend. All provider-specific logic — SDKs, auth flows, and the
/// parsing of `SecretRef.path` — lives behind this interface. The agent core
/// (grants, consent, cache, socket, delivery) is provider-agnostic.
public protocol SecretProvider: Sendable {
    /// URI scheme(s) this provider claims, e.g. `["op"]`.
    var schemes: Set<String> { get }

    /// Resolve a reference to its value. Implementations may call
    /// `authenticate()` internally on demand (e.g. 1Password DesktopAuth).
    func resolve(_ ref: SecretRef) async throws -> ResolvedSecret

    /// Establish or refresh provider auth (DesktopAuth, token, SSO…). Idempotent.
    func authenticate() async throws

    /// Whether the provider can currently serve without an interactive step.
    func isAvailable() async -> Bool
}

public enum ProviderError: Error {
    case unsupportedScheme(String)
    case notAuthenticated
    case referenceNotFound(String)
    case notImplemented
}
