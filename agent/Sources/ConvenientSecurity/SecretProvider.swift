import CSECRemoteApproval
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
    /// Safe to cache at rest (SE-gated). Kept until it is explicitly invalidated
    /// (e.g. on rotation, via `invalidate`) or replaced by a newer value its
    /// provider serves from an open session (`resolveFromOpenSession`), never
    /// dropped on a wall clock — a re-fetch that only re-verifies a
    /// still-authorized value would cost a prompt for no security gain.
    case cacheable
    /// Never persist; resolve live every time.
    case noCache
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

/// Whether a reference exists, as a provider can tell from state it already
/// holds. `absent` is a certainty, never a guess: resolving the reference now,
/// with any unlock, would fail for `reason`, a fixed value-free sentence the
/// provider authored (it may name the store and key, which are metadata).
/// Anything a provider cannot settle without an unlock, a prompt or the
/// network is `unknown`.
public enum ReferencePresence: Sendable, Equatable {
    case present
    case unknown
    case absent(reason: String)
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

    /// How a review names this reference before it is authorized: where the
    /// value resolves from (an account, this Mac), the vault or store, the
    /// item and the field, the colour this provider's secrets are drawn in,
    /// and any note or warning about that choice. Value-free. The core never
    /// parses a reference to show it; it draws what this returns, made
    /// display-safe, or the whole reference when this returns nil.
    ///
    /// A description is a *commitment*: a provider that names a source must
    /// resolve exactly that source, so the window can never name one account
    /// and deliver from another.
    ///
    /// Called while the review window is being built, so it must answer from
    /// warm state and never start an interactive or unbounded operation.
    func reviewDescription(for ref: SecretRef) async -> ReviewSecret?

    /// One-line health summary for `csec status`, or nil to stay unlisted.
    func statusSummary() async -> ProviderStatusSummary?

    /// Whether resolving `ref` now, with no `unlock`, would need the biometric
    /// context of a fresh touch: its source material is sealed behind a
    /// Keychain item this provider has not opened in this daemon lifetime.
    /// Answered from warm state only; it never prompts and never contacts a
    /// remote service. A provider that can serve without such a context (a
    /// remote provider behind its own authorization) keeps the default, false.
    func requiresUnlockToResolve(_ ref: SecretRef) async -> Bool

    /// Open what `refs` need with `unlock`, a context a touch just evaluated,
    /// so later resolutions of them need none. Reads local sealed state only
    /// and never contacts a provider over the network. A failure leaves the
    /// reference cold; the caller asks `requiresUnlockToResolve` again.
    func warm(_ refs: [SecretRef], unlock: CacheUnlock) async

    /// Resolve `ref` only from state this provider already holds open: no
    /// unlock, no prompt, no interactive step, no network. Nil when it cannot.
    /// The one exception is a provider that makes its value rather than
    /// reading it (`MachineIdentityProvider`): its bounded exchange with a
    /// token service raises no authorization of its own and holds nothing a
    /// human would have to open, so it may make the value here too.
    /// This is how a delegated release (one no human approved on a panel)
    /// resolves a reference the request is new to, so a provider whose
    /// resolution may raise its own authorization or reach a remote service
    /// keeps the default, nil: its values then qualify only while csecd holds
    /// them warm in its cache.
    func resolveWithoutInteraction(_ ref: SecretRef) async -> ResolvedSecret?

    /// `ref`'s current value, read only over a session this provider already
    /// holds open and has recently proven, for a provider whose values can
    /// change outside csec (edited in the provider's own app): the resolver
    /// asks this before it serves a cached copy, so an edit there is never
    /// hidden behind csecd's cache while the session that would show it is
    /// open. It never opens or restarts a session, never authorizes and never
    /// prompts; nil whenever it cannot answer that way, and the cached copy is
    /// served as before. A provider whose values change only through csec, or
    /// are never cached, keeps the default, nil.
    func resolveFromOpenSession(_ ref: SecretRef) async -> ResolvedSecret?

    /// Whether `ref`'s value can change outside csec (edited in the
    /// provider's own app), so a person approving its release at the Mac is
    /// worth asking the provider for, ahead of csecd's cached copy, when no
    /// open session could confirm it (`resolveFromOpenSession`). That read may
    /// raise the provider's own authorization, which is why only a local
    /// approval, a person at the Mac, makes it. Providers whose values change
    /// only through csec, or are never cached, keep the default, false.
    func valuesChangeOutsideCsec(_ ref: SecretRef) async -> Bool

    /// Whether a remote unlock (`CacheUnlock(remote:)`, the key a verified
    /// phone approval opened) would open what resolving `ref` needs: every
    /// sealed item this provider would have to open for it has a current
    /// remote-unlock mirror, or is known not to exist. Asked only for a
    /// reference `requiresUnlockToResolve` reports. Value-free: it reads
    /// attributes at most, never opens a mirror, never prompts and never
    /// contacts a remote service. A provider with no remote-unlock mirrors
    /// keeps the default, false, so its references stay Mac-only.
    func canResolveWithRemoteUnlock(_ ref: SecretRef) async -> Bool

    /// Whether resolving `ref` now may raise this provider's own
    /// authorization at this Mac (its app's prompt), which only a person at
    /// the Mac can answer: a phone approval could not carry it out, since the
    /// value would wait on that prompt. A provider that authorizes per
    /// session says false only while it holds a session for `ref` open and
    /// recently proven. Answered from warm state only: never prompts, never
    /// starts or contacts a session, never reads a value. A provider whose
    /// resolution raises no authorization of its own keeps the default, false.
    func requiresAttendanceToResolve(_ ref: SecretRef) async -> Bool

    /// Write a remote-unlock mirror for every sealed item this provider holds,
    /// reading each with `localUnlock`, the one evaluated context remote-unlock
    /// enrollment spent. It must leave this provider's warm state exactly as
    /// it was: that touch approved enrolling, not opening storage for use.
    func backfillRemoteUnlockMirrors(localUnlock: CacheUnlock) async -> RemoteUnlockBackfillReport

    /// Whether `ref` exists, answered before any review so a request that can
    /// never be delivered is refused instead of costing a prompt. Value-free
    /// and warm-state only: no unlock, no prompt, no network, no unbounded
    /// work, and nothing opened or retained. A provider may read sealed state
    /// it already holds open to answer, but no value, nor anything derived
    /// from one, may leave it. A provider that cannot answer that way keeps
    /// the default, `unknown`, and its requests are reviewed as before.
    func presence(of ref: SecretRef) async -> ReferencePresence

    /// Whether each value resolved for `ref` is made for that use and good
    /// only briefly (a minted sign-in), so a copy stored for later, such as
    /// an automation job's materialization, would stop working. Providers of
    /// stored values keep the default, false.
    func valuesExpireSoon(_ ref: SecretRef) async -> Bool

    /// Whether this provider works out the current one-time code for a
    /// one-time-code reference (`SecretRef.isOneTimeCode`) itself, so its
    /// seed never reaches csecd. A provider that keeps the default, false, is
    /// only ever asked for the seed reference
    /// (`SecretRef.oneTimeCodeSeedReference`), and csecd makes the code from
    /// the `otpauth://` value it returns.
    func makesOneTimeCodes(_ ref: SecretRef) async -> Bool

    /// Resolve `refs` now, ahead of any request for them, because a person is
    /// at the Mac to answer whatever authorization the provider's own app
    /// raises (the attended restore after csecd restarted). Asked only for
    /// references whose provider needs no csec unlock. A provider whose source
    /// can refuse asks each source at most once per call: after one refusal it
    /// fails that source's remaining references without contacting it, so a
    /// declined prompt is one prompt, not one per reference. One result per
    /// reference, in order. The default resolves each in turn.
    func fetchAhead(_ refs: [SecretRef]) async -> [FetchAheadResult]

    /// A person has just approved a csec panel at this Mac, before the
    /// approved request resolves. A provider whose source can refuse its own
    /// app's authorization stops asking a source that refused, for every
    /// request, attended or not, since each new ask is another prompt and an
    /// unanswered or declined one is no reason to ask again. This is what
    /// lets it ask once more: someone is there to answer. A phone approval is
    /// not one, as nobody need be at the Mac. Providers whose sources never
    /// refuse keep the default, which does nothing.
    func personApprovedAtMac() async
}

/// What `SecretProvider.fetchAhead` got for one reference. Value-free apart
/// from the resolved secret itself, which only the resolver's cache keeps.
public struct FetchAheadResult: Sendable {
    public enum Outcome: Sendable {
        case fetched(ResolvedSecret)
        /// The provider's value-free reason, when it gave one
        /// (`ProviderDiagnosableError`).
        case failed(reason: String?)
    }

    public let reference: SecretRef
    public let outcome: Outcome

    public init(reference: SecretRef, outcome: Outcome) {
        self.reference = reference
        self.outcome = outcome
    }

    /// `ref` resolved with no unlock, or the reason it was not.
    public static func resolving(_ ref: SecretRef, with provider: some SecretProvider) async -> FetchAheadResult {
        do {
            return FetchAheadResult(reference: ref, outcome: .fetched(try await provider.resolve(ref, unlock: nil)))
        } catch {
            return FetchAheadResult(
                reference: ref, outcome: .failed(reason: (error as? any ProviderDiagnosableError)?.boundedReason)
            )
        }
    }
}

public extension SecretProvider {
    func reviewDescription(for ref: SecretRef) async -> ReviewSecret? { nil }
    func statusSummary() async -> ProviderStatusSummary? { nil }
    func requiresUnlockToResolve(_ ref: SecretRef) async -> Bool { false }
    func warm(_ refs: [SecretRef], unlock: CacheUnlock) async {}
    func resolveWithoutInteraction(_ ref: SecretRef) async -> ResolvedSecret? { nil }
    func resolveFromOpenSession(_ ref: SecretRef) async -> ResolvedSecret? { nil }
    func valuesChangeOutsideCsec(_ ref: SecretRef) async -> Bool { false }
    func canResolveWithRemoteUnlock(_ ref: SecretRef) async -> Bool { false }
    func requiresAttendanceToResolve(_ ref: SecretRef) async -> Bool { false }
    func backfillRemoteUnlockMirrors(localUnlock: CacheUnlock) async -> RemoteUnlockBackfillReport {
        RemoteUnlockBackfillReport()
    }
    func presence(of ref: SecretRef) async -> ReferencePresence { .unknown }
    func valuesExpireSoon(_ ref: SecretRef) async -> Bool { false }
    func makesOneTimeCodes(_ ref: SecretRef) async -> Bool { false }
    func fetchAhead(_ refs: [SecretRef]) async -> [FetchAheadResult] {
        var results: [FetchAheadResult] = []
        for ref in refs {
            results.append(await FetchAheadResult.resolving(ref, with: self))
        }
        return results
    }
    func personApprovedAtMac() async {}
}

public enum ProviderError: Error {
    case unsupportedScheme(String)
    case notAuthenticated
    case referenceNotFound(String)
    case notImplemented
}
