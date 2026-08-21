import Foundation

/// Plaintext-free request sent from a language client to the signed `csec
/// bridge` child over private stdin/stdout pipes.
public struct BridgeRequest: Codable, Sendable {
    public let version: Int
    public let references: [String]
    public let reason: String
    public let ttlSeconds: Int

    public init(references: [String], reason: String, ttlSeconds: Int) {
        self.version = 1
        self.references = references
        self.reason = reason
        self.ttlSeconds = ttlSeconds
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
