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
