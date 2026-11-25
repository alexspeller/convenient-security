import Foundation

/// Plaintext-free request sent from a language client to the signed `csec
/// bridge` child over private stdin/stdout pipes.
public struct BridgeRequest: Codable, Sendable {
    public let version: Int
    public let references: [String]
    public let reason: String
    /// An explicit wall-clock lifetime for the grant, in seconds. Absent (and
    /// omitted on the wire) means no clock: like `csec exec`, the grant lives as
    /// long as the root the human approves, the requesting process by default.
    public let ttlSeconds: Int?

    public init(references: [String], reason: String, ttlSeconds: Int? = nil) {
        self.version = 1
        self.references = references
        self.reason = reason
        self.ttlSeconds = ttlSeconds
    }

    /// Whether the request is inside the bridge's bounds. An explicit lifetime
    /// must be positive and is otherwise passed through as given, as csecd and
    /// `csec exec` honour it; the language clients keep their own upper bound.
    public var isWellFormed: Bool {
        version == 1
            && !references.isEmpty
            && references.count <= 64
            && !reason.isEmpty
            && reason.utf8.count <= 512
            && (ttlSeconds.map { $0 > 0 } ?? true)
    }
}

/// One-shot bridge response. `failure` is value-free; values exist only on the
/// private pipe to the requesting parent process.
public struct BridgeResponse: Codable, Sendable {
    public let version: Int
    public let values: [String: String]?
    public let failure: ProtocolFailure?

    public init(values: [String: String]? = nil, failure: ProtocolFailure? = nil) {
        self.version = 1
        self.values = values
        self.failure = failure
    }
}
