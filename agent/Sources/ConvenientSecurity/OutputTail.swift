import Foundation

/// The last `limit` bytes of a stream, in storage that stays within about
/// twice that however much passes through. Trimming a `Data` from the front
/// only moves its start index and keeps the whole buffer alive, so this moves
/// its own start and copies the kept bytes down once per `limit` dropped.
public struct OutputTail: Sendable {
    public let limit: Int
    private var storage = Data()
    private var start = 0

    public init(limit: Int) {
        precondition(limit > 0)
        self.limit = limit
    }

    public var count: Int { storage.count - start }
    public var isEmpty: Bool { count == 0 }
    /// Bytes held, kept bytes and not yet compacted ones together.
    public var storageCount: Int { storage.count }

    /// The kept bytes, indexed from zero.
    public var bytes: Data {
        storage.subdata(in: (storage.startIndex + start)..<storage.endIndex)
    }

    /// Appends `data` and returns, oldest first, what no longer fits.
    @discardableResult
    public mutating func append(_ data: Data) -> Data {
        storage.append(data)
        let excess = count - limit
        guard excess > 0 else { return Data() }
        let first = storage.startIndex + start
        let dropped = storage.subdata(in: first..<(first + excess))
        start += excess
        if start >= limit {
            storage = storage.subdata(in: (storage.startIndex + start)..<storage.endIndex)
            start = 0
        }
        return dropped
    }

    public mutating func removeAll() {
        storage = Data()
        start = 0
    }
}
