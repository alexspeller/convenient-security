import Foundation

/// A resolved secret plus a hint about how long it may be cached at rest.
///
/// The value is raw *bytes*, not a `String`: a reference resolves to a value and
/// a value is bytes, whether that is a short token or a whole binary file. Text
/// is a *delivery constraint* (an environment variable must be a NUL-free UTF-8
/// C string), applied at the delivery boundary — never a property of the value
/// itself. Providers that natively yield text seal it with `Data(text.utf8)`.
public struct ResolvedSecret: Sendable {
    public let value: Data
    public let cacheHint: CacheHint

    public init(value: Data, cacheHint: CacheHint) {
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

/// One line of value-free, provider-supplied context for the trusted review
/// window: where a value will actually come from, and whether that resolution is
/// ambiguous enough to warrant a warning. The core never interprets these — it
/// only renders them — so the consent path stays provider-agnostic.
///
/// A note is a *commitment*: a provider that reports one must resolve exactly
/// what it described, so the window can never name one source and deliver
/// another.
public struct ProviderReviewNote: Sendable, Equatable {
    /// Short lowercase label, e.g. `account`.
    public let label: String
    /// Bounded value-free detail, e.g. a 1Password sign-in URL.
    public let detail: String
    /// Render as a warning rather than ordinary context.
    public let isWarning: Bool

    public init(label: String, detail: String, isWarning: Bool = false) {
        self.label = label
        self.detail = detail
        self.isWarning = isWarning
    }
}

/// A provider's one-line health summary for `csec status`. Value-free.
public struct ProviderStatusSummary: Codable, Sendable, Equatable {
    public let label: String
    public let detail: String
    public let healthy: Bool

    public init(label: String, detail: String, healthy: Bool) {
        self.label = label
        self.detail = detail
        self.healthy = healthy
    }
}

/// A provider error that can name its own cause in text csec itself authored.
///
/// The agent may repeat `boundedReason` to the client; it must therefore be a
/// fixed, short, value-free string built by the adapter — never a tool's raw
/// stderr, which is unbounded and attacker-influenced.
public protocol ProviderDiagnosableError: Error {
    var boundedReason: String { get }
}

/// A secret backend. All provider-specific logic — SDKs, auth flows, and the
/// parsing of `SecretRef.path` — lives behind this interface. The agent core
/// (grants, consent, cache, socket, delivery) is provider-agnostic.
public protocol SecretProvider: Sendable {
    /// URI scheme(s) this provider claims, e.g. `["op"]`.
    var schemes: Set<String> { get }

    /// Resolve a reference to its value. Implementations may call
    /// `authenticate()` internally on demand (e.g. 1Password DesktopAuth).
    /// `unlock` is the fresh biometric context produced by the agent's consent
    /// step. Providers whose own source material is biometrically sealed may
    /// consume it; remote providers can ignore it.
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret

    /// Establish or refresh provider auth (DesktopAuth, token, SSO…). Idempotent.
    func authenticate() async throws

    /// Whether the provider can currently serve without an interactive step.
    func isAvailable() async -> Bool

    /// Value-free context to display before this reference is authorized.
    /// Called while the review window is being built, so it must answer from
    /// warm state and never start an interactive or unbounded operation.
    func reviewNotes(for ref: SecretRef) async -> [ProviderReviewNote]

    /// One-line health summary for `csec status`, or nil to stay unlisted.
    func statusSummary() async -> ProviderStatusSummary?
}

public extension SecretProvider {
    func reviewNotes(for ref: SecretRef) async -> [ProviderReviewNote] { [] }
    func statusSummary() async -> ProviderStatusSummary? { nil }
}

public enum ProviderError: Error {
    case unsupportedScheme(String)
    case notAuthenticated
    case referenceNotFound(String)
    case notImplemented
}
