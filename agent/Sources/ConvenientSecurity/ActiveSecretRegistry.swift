import Foundation

/// Plaintext values that this agent actually released during its current
/// lifetime. Entries are memory-only and expire with their delivery grant; the
/// registry never unlocks dormant cache or provider values to populate itself.
struct ActiveSecretRegistry: Sendable {
    struct Snapshot: Sendable {
        /// Real reference URI → value for every currently-active secret. The key
        /// is the reference that resolved to the value, so an output-redaction
        /// catalog built from this can label a redaction with the reference the
        /// user already holds in their sidecar or environment. When several
        /// references resolve to one value the lexically-first is kept.
        let valuesByReference: [String: Data]
        let generation: UInt64
    }

    private struct Entry: Sendable {
        let sequence: UInt64
        let value: Data
        var reference: String
        var expiresAt: Date
    }

    private var entriesByValue: [Data: Entry] = [:]
    private var nextSequence: UInt64 = 1
    private(set) var generation: UInt64 = 0

    /// Register the values released for one delivery, each keyed by the reference
    /// it resolved from. The reference is value-free metadata csecd already holds;
    /// keeping it lets redaction name what leaked instead of an opaque ordinal.
    mutating func register(valuesByReference: [String: Data], expiresAt: Date) {
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
                if expiresAt > existing.expiresAt {
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

    mutating func snapshot(now: Date = Date()) -> Snapshot {
        let expired = entriesByValue.filter { $0.value.expiresAt <= now }.map(\.key)
        if !expired.isEmpty {
            for key in expired { entriesByValue.removeValue(forKey: key) }
            generation &+= 1
        }
        // A value shared by several references is stored once (lexically-first
        // reference), so keys are unique. On the theoretically impossible tie
        // (two distinct values, same reference) keep the earliest registered.
        var values: [String: Data] = [:]
        for entry in entriesByValue.values.sorted(by: { $0.sequence < $1.sequence }) {
            if values[entry.reference] == nil { values[entry.reference] = entry.value }
        }
        return Snapshot(valuesByReference: values, generation: generation)
    }
}
