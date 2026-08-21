import Foundation

/// Plaintext values that this agent actually released during its current
/// lifetime. Entries are memory-only and expire with their delivery grant; the
/// registry never unlocks dormant cache or provider values to populate itself.
struct ActiveSecretRegistry: Sendable {
    struct Snapshot: Sendable {
        let valuesByOpaqueID: [String: String]
        let generation: UInt64
    }

    private struct Entry: Sendable {
        let sequence: UInt64
        let value: String
        var expiresAt: Date
    }

    private var entriesByValue: [Data: Entry] = [:]
    private var nextSequence: UInt64 = 1
    private(set) var generation: UInt64 = 0

    mutating func register(values: some Sequence<String>, expiresAt: Date) {
        var changed = false
        for value in values {
            let bytes = Data(value.utf8)
            guard !bytes.isEmpty else { continue }
            if var existing = entriesByValue[bytes] {
                if expiresAt > existing.expiresAt {
                    existing.expiresAt = expiresAt
                    entriesByValue[bytes] = existing
                    changed = true
                }
            } else {
                entriesByValue[bytes] = Entry(
                    sequence: nextSequence,
                    value: value,
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
        let values = Dictionary(uniqueKeysWithValues: entriesByValue.values.map { entry in
            (String(format: "registry://%020llu", entry.sequence), entry.value)
        })
        return Snapshot(valuesByOpaqueID: values, generation: generation)
    }
}
