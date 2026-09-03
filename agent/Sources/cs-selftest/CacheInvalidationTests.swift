import ConvenientSecurity
import Foundation
import LocalAuthentication

/// A provider whose value can rotate under a fixed reference, so a test can prove
/// that a cached resolution goes stale after rotation and that invalidation
/// restores freshness. Resolutions are `.cacheable`, mirroring the op:// provider.
actor RotatingCacheableProvider: SecretProvider {
    nonisolated let schemes: Set<String>
    private let reference: String
    private var value: String
    private(set) var resolveCount = 0

    init(scheme: String, reference: String, value: String) {
        self.schemes = [scheme]
        self.reference = reference
        self.value = value
    }

    func setValue(_ newValue: String) {
        value = newValue
    }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        resolveCount += 1
        guard ref.uri == reference else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: Data(value.utf8), cacheHint: .cacheable(maxAge: 24 * 3600))
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

/// The post-rotation freshness guarantee: after a value rotates, a cached
/// resolution must be dropped so the next resolve re-reads the new value. Also
/// covers the wire contract for the `invalidate_cached_references` verb.
func cacheInvalidationTests() async {
    print("\n# Cache invalidation (post-rotation freshness)")

    let unlock = CacheUnlock(LAContext())
    let uri = "op://vault/rotated/field"
    let ref = try! SecretRef(uri)

    let provider = RotatingCacheableProvider(scheme: "op", reference: uri, value: "BEFORE")
    let backend = FakeKeychainBackend()
    let cache = KeychainSecretCache(backend: backend)
    let resolver = SecretResolver(cache: cache)
    await resolver.register(provider)

    do {
        let first = try await resolver.resolve(ref, unlock: unlock)
        check(first == Data("BEFORE".utf8), "first resolve returns the live value")
        check(await provider.resolveCount == 1, "first resolve consults the provider")

        // Rotate the underlying value. Without invalidation the cache still wins —
        // this is precisely the stale-after-rotation bug.
        await provider.setValue("AFTER")
        let cached = try await resolver.resolve(ref, unlock: unlock)
        check(cached == Data("BEFORE".utf8),
              "a cacheable resolution is served from the cache after rotation (the bug)")
        check(await provider.resolveCount == 1,
              "the cached resolve never re-consults the provider")

        // Invalidate, then the next resolve must re-read the rotated value.
        await resolver.invalidate(references: [uri])
        check(!(await backend.has(uri)), "invalidate drops the cold cache entry")
        let fresh = try await resolver.resolve(ref, unlock: unlock)
        check(fresh == Data("AFTER".utf8),
              "after invalidation the resolver serves the rotated value")
        check(await provider.resolveCount == 2,
              "the post-invalidation resolve re-consults the provider")

        // Invalidating an uncached / unknown reference is a harmless no-op.
        await resolver.invalidate(references: ["op://vault/never/cached"])
        check(true, "invalidating an unknown reference does not throw")
    } catch {
        check(false, "cache invalidation checks threw unexpectedly: \(error)")
    }

    // Wire contract: the new verb round-trips its references and requestID.
    do {
        let request = InvalidateCachedReferencesRequest(
            references: ["op://v/i/f", "csec://store/KEY"])
        let encoded = try JSONEncoder().encode(Request.invalidateCachedReferences(request))
        let decoded = try JSONDecoder().decode(Request.self, from: encoded)
        if case let .invalidateCachedReferences(roundTrip) = decoded {
            check(roundTrip.references == request.references,
                  "invalidate request round-trips its references")
            check(roundTrip.requestID == request.requestID,
                  "invalidate request round-trips its requestID")
        } else {
            check(false, "invalidate request decodes to the invalidateCachedReferences case")
        }
    } catch {
        check(false, "invalidate request wire round-trip threw: \(error)")
    }

    // The decoder rejects an over-long reference list rather than accepting an
    // unbounded batch from a misbehaving peer.
    let tooMany = (0...InvalidateCachedReferencesRequest.maximumReferences)
        .map { "op://v/i/f\($0)" }
    let overlongJSON: [String: Any] = [
        "type": "invalidate_cached_references",
        "version": WireProtocol.version,
        "requestID": UUID().uuidString.lowercased(),
        "references": tooMany,
    ]
    checkThrows("the decoder rejects too many references to invalidate") {
        let data = try JSONSerialization.data(withJSONObject: overlongJSON)
        _ = try JSONDecoder().decode(Request.self, from: data)
    }
}
