import Foundation

/// Plaintext values that this agent actually released during its current
/// lifetime. Entries are memory-only: one released under a bounded grant
/// lapses with that grant's lifetime, and one released for a process's
/// lifetime (a process-lifetime grant, a delegated release) stays until csecd
/// restarts or the value is invalidated. The registry never unlocks dormant
/// cache or provider values to populate itself.
struct ActiveSecretRegistry: Sendable {
    struct Snapshot: Sendable {
        /// Every currently-active value → the real reference URI that resolved
        /// to it, so an output-redaction catalog built from this can label a
        /// redaction with the reference the user already holds in their sidecar
        /// or environment. When several references resolve to one value the
        /// lexically-first is kept. One reference can name several values: a
        /// rotated secret's old value and its new one were both released, so
        /// both are here and both are masked.
        let referenceByValue: [Data: String]
        let generation: UInt64
    }

    private struct Entry: Sendable {
        let sequence: UInt64
        let value: Data
        var reference: String
        /// Wall-clock expiry, or nil for a value released under a process-lifetime
        /// grant: it stays available for redaction until the daemon restarts or
        /// the value is invalidated, mirroring the grant it was released under.
        var expiresAt: Date?
    }

    private var entriesByValue: [Data: Entry] = [:]
    private var nextSequence: UInt64 = 1
    private(set) var generation: UInt64 = 0

    /// Register the values released for one delivery, each keyed by the reference
    /// it resolved from. The reference is value-free metadata csecd already holds;
    /// keeping it lets redaction name what leaked instead of an opaque ordinal.
    mutating func register(valuesByReference: [String: Data], expiresAt: Date?) {
        var changed = false
        // Deterministic order so re-registration keeps the lexically-first
        // reference for a value shared by several references.
        for reference in valuesByReference.keys.sorted() {
            guard let bytes = valuesByReference[reference], !bytes.isEmpty else { continue }
            if var existing = entriesByValue[bytes] {
                var mutated = false
                if reference < existing.reference {
                    existing.reference = reference
                    mutated = true
                }
                // Keep the longest-lived expiry for a value released more than
                // once; a nil (process-lifetime) expiry outlives any dated one.
                if Self.expiryIsLater(expiresAt, than: existing.expiresAt) {
                    existing.expiresAt = expiresAt
                    mutated = true
                }
                if mutated {
                    entriesByValue[bytes] = existing
                    changed = true
                }
            } else {
                entriesByValue[bytes] = Entry(
                    sequence: nextSequence,
                    value: bytes,
                    reference: reference,
                    expiresAt: expiresAt
                )
                nextSequence &+= 1
                changed = true
            }
        }
        if changed { generation &+= 1 }
    }

    /// True when `candidate` outlives `current`, treating nil as "never expires"
    /// (the latest possible instant).
    private static func expiryIsLater(_ candidate: Date?, than current: Date?) -> Bool {
        switch (candidate, current) {
        case (nil, nil): return false
        case (nil, _?): return true
        case (_?, nil): return false
        case let (c?, cur?): return c > cur
        }
    }

    mutating func snapshot(now: Date = Date()) -> Snapshot {
        let expired = entriesByValue.filter { entry in
            guard let expiresAt = entry.value.expiresAt else { return false }
            return expiresAt <= now
        }.map(\.key)
        if !expired.isEmpty {
            for key in expired { entriesByValue.removeValue(forKey: key) }
            generation &+= 1
        }
        return Snapshot(
            referenceByValue: entriesByValue.mapValues(\.reference),
            generation: generation
        )
    }
}
