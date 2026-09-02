import Foundation

/// Dispatches a `SecretRef` to the provider that owns its scheme, with the
/// SE-gated cache layered above (provider-agnostic, keyed by the canonical URI).
public actor SecretResolver {
    private var providers: [String: SecretProvider] = [:]
    private let cache: SecretCache

    public init(cache: SecretCache) {
        self.cache = cache
    }

    public func register(_ provider: SecretProvider) {
        for scheme in provider.schemes {
            providers[scheme] = provider
        }
    }

    /// The URI schemes currently resolvable, sorted for a stable wire order.
    public func registeredSchemes() -> [String] {
        providers.keys.sorted()
    }

    /// Value-free context the owning provider wants shown before this reference
    /// is authorized (e.g. which 1Password account it resolves from). Never
    /// consults the cache: a note describes the resolution the review is about
    /// to authorize, not a value already held.
    public func reviewNotes(for ref: SecretRef) async -> [ProviderReviewNote] {
        guard let provider = providers[ref.scheme] else { return [] }
        return await provider.reviewNotes(for: ref)
    }

    /// Reviewable credentials, one per group, each carrying its providers'
    /// value-free context. Use this everywhere a review is built so every
    /// consent surface describes resolution the same way.
    public func reviewCredentials(
        for groups: [[SecretRef]]
    ) async -> [PolicyReviewCredential] {
        var credentials: [PolicyReviewCredential] = []
        for group in groups {
            credentials.append(await reviewCredential(for: group))
        }
        return credentials
    }

    /// One reviewable credential with its providers' context attached. Notes
    /// repeat across the fields of one item, so identical lines are shown once.
    public func reviewCredential(for references: [SecretRef]) async -> PolicyReviewCredential {
        var notes: [ProviderReviewNote] = []
        var seen = Set<String>()
        for reference in references {
            for note in await reviewNotes(for: reference)
            where seen.insert("\(note.label)\u{0}\(note.detail)").inserted {
                notes.append(note)
            }
        }
        return PolicyReviewCredential(references: references, providerNotes: notes)
    }

    /// Per-provider health lines for `csec status`, in stable scheme order.
    public func providerStatuses() async -> [ProviderStatusSummary] {
        var summaries: [ProviderStatusSummary] = []
        for scheme in providers.keys.sorted() {
            guard let provider = providers[scheme] else { continue }
            if let summary = await provider.statusSummary() {
                summaries.append(summary)
            }
        }
        return summaries
    }

    public func invalidate(references: some Sequence<String>) async {
        for reference in Set(references) {
            await cache.invalidate(reference)
        }
    }

    /// Resolve to a plaintext value: SE-cache first (a warm hit is free; a cold
    /// read folds into `unlock`, the consent touch), then the owning provider on a
    /// miss, persisting per the provider's cache hint.
    ///
    /// The cache is strictly an optimization: a read or write failure is logged and
    /// treated as a miss / no-op, never propagated — a keychain hiccup must not
    /// break resolution when the provider can still serve the value.
    public func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> Data {
        if let cached = await cachedValue(for: ref.uri, unlock: unlock) {
            return cached
        }
        guard let provider = providers[ref.scheme] else {
            throw ProviderError.unsupportedScheme(ref.scheme)
        }
        let resolved = try await provider.resolve(ref, unlock: unlock)
        if case let .cacheable(maxAge) = resolved.cacheHint {
            do {
                try await cache.put(ref.uri, value: resolved.value, maxAge: maxAge)
            } catch {
                logCache("write", error)
            }
        }
        return resolved.value
    }

    private func cachedValue(for uri: String, unlock: CacheUnlock?) async -> Data? {
        do {
            return try await cache.get(uri, unlock: unlock)
        } catch {
            logCache("read", error)
            return nil
        }
    }

    private func logCache(_ operation: String, _ error: Error) {
        FileHandle.standardError.write(Data(
            "csecd: cache \(operation) failed, continuing (\(error))\n".utf8
        ))
    }
}
