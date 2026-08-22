import Foundation

public enum SecureDeliveryError: Error, LocalizedError, Equatable {
    case invalidSessionHint
    case invalidAWSCredentialDocument
    case invalidGitCredentialRequest
    case invalidGitCredentialValue
    case invalidInheritedFile

    public var errorDescription: String? {
        switch self {
        case .invalidSessionHint:
            return "the inherited csec session is invalid; relaunch it with csec session"
        case .invalidAWSCredentialDocument:
            return "the AWS credential document is incomplete or invalid"
        case .invalidGitCredentialRequest:
            return "Git supplied an invalid or oversized credential request"
        case .invalidGitCredentialValue:
            return "a Git credential cannot be represented by the helper protocol"
        case .invalidInheritedFile:
            return "an inherited secret file is empty, oversized, or contains a NUL byte"
        }
    }
}

/// Non-secret environment hint installed by `csec session`. Possession of this
/// UUID is not authorization; csecd resolves it to a live PID/start-time record
/// and independently walks kernel ancestry for every access.
public enum RegisteredSessionHint {
    public static let environmentKey = "CSEC_SESSION_ID"

    public static func sessionID(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws -> String? {
        guard let raw = environment[environmentKey] else { return nil }
        guard let id = UUID(uuidString: raw)?.uuidString.lowercased(),
              id == raw.lowercased() else {
            throw SecureDeliveryError.invalidSessionHint
        }
        return id
    }
}

/// Strict renderer for AWS `credential_process` version 1 output.
public enum AWSCredentialProcess {
    public static let accessKeyID = "AccessKeyId"
    public static let secretAccessKey = "SecretAccessKey"
    public static let sessionToken = "SessionToken"
    public static let expiration = "Expiration"

    private static let allowedKeys: Set<String> = [
        accessKeyID, secretAccessKey, sessionToken, expiration,
    ]
    private static let maximumFieldBytes = 256 * 1024

    private struct Document: Encodable {
        let version = 1
        let accessKeyID: String
        let secretAccessKey: String
        let sessionToken: String?
        let expiration: String?

        private enum CodingKeys: String, CodingKey {
            case version = "Version"
            case accessKeyID = "AccessKeyId"
            case secretAccessKey = "SecretAccessKey"
            case sessionToken = "SessionToken"
            case expiration = "Expiration"
        }
    }

    /// Parse a strict flat JSON bundle, suitable for a single native-store or
    /// 1Password field containing all of the AWS process credentials.
    public static func fields(fromBundle value: String) throws -> [String: String] {
        guard let document = try? NativeStoreDocument(data: Data(value.utf8)),
              Set(document.values.keys).isSubset(of: allowedKeys) else {
            throw SecureDeliveryError.invalidAWSCredentialDocument
        }
        return document.values
    }

    public static func render(fields: [String: String]) throws -> Data {
        guard Set(fields.keys).isSubset(of: allowedKeys),
              let accessKeyID = fields[accessKeyID],
              let secretAccessKey = fields[secretAccessKey],
              validField(accessKeyID),
              validField(secretAccessKey),
              fields[sessionToken].map(validField) ?? true,
              fields[expiration].map(validExpiration) ?? true else {
            throw SecureDeliveryError.invalidAWSCredentialDocument
        }

        let document = Document(
            accessKeyID: accessKeyID,
            secretAccessKey: secretAccessKey,
            sessionToken: fields[sessionToken],
            expiration: fields[expiration]
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(document)
        data.append(0x0a)
        return data
    }

    private static func validField(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= maximumFieldBytes
            && !value.unicodeScalars.contains(where: {
                $0.value == 0 || CharacterSet.newlines.contains($0)
            })
    }

    private static func validExpiration(_ value: String) -> Bool {
        guard validField(value) else { return false }
        let formatter = ISO8601DateFormatter()
        if formatter.date(from: value) != nil { return true }
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value) != nil
    }
}

/// Bounded parser for Git's line-oriented credential-helper request. Secret
/// input attributes (such as `password`) are deliberately discarded.
public struct GitCredentialRequest: Sendable, Equatable {
    public static let maximumBytes = 64 * 1024

    public let protocolValue: String?
    public let host: String?
    public let path: String?
    public let username: String?

    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes,
              let text = String(data: data, encoding: .utf8),
              !text.unicodeScalars.contains(where: { $0.value == 0 }) else {
            throw SecureDeliveryError.invalidGitCredentialRequest
        }

        var selected: [String: String] = [:]
        var terminated = false
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = String(rawLine)
            if line.last == "\r" { line.removeLast() }
            if line.isEmpty {
                terminated = true
                continue
            }
            guard !terminated,
                  let separator = line.firstIndex(of: "="),
                  separator != line.startIndex else {
                throw SecureDeliveryError.invalidGitCredentialRequest
            }
            let key = String(line[..<separator])
            let value = String(line[line.index(after: separator)...])
            guard key.utf8.count <= 128, value.utf8.count <= 16 * 1024 else {
                throw SecureDeliveryError.invalidGitCredentialRequest
            }
            if ["protocol", "host", "path", "username"].contains(key) {
                guard selected[key] == nil else {
                    throw SecureDeliveryError.invalidGitCredentialRequest
                }
                selected[key] = value
            }
        }

        protocolValue = selected["protocol"]
        host = selected["host"]
        path = selected["path"]
        username = selected["username"]
    }

    public func matches(protocol expectedProtocol: String, host expectedHost: String, path expectedPath: String?) -> Bool {
        guard protocolValue?.lowercased() == expectedProtocol.lowercased(),
              host?.lowercased() == expectedHost.lowercased() else { return false }
        if let expectedPath { return path == expectedPath }
        return true
    }

    public static func render(username: String?, password: String) throws -> Data {
        guard validOutputValue(password),
              username.map(validOutputValue) ?? true else {
            throw SecureDeliveryError.invalidGitCredentialValue
        }
        var output = ""
        if let username { output += "username=\(username)\n" }
        output += "password=\(password)\n\n"
        return Data(output.utf8)
    }

    private static func validOutputValue(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 256 * 1024
            && !value.unicodeScalars.contains(where: {
                $0.value == 0 || CharacterSet.newlines.contains($0)
            })
    }
}

/// File-shaped adapters known to accept a configurable path. Each preset only
/// installs its non-secret `/dev/fd/N` variable; the bytes remain in an
/// anonymous, single-open pipe.
public enum InheritedFilePreset: String, CaseIterable, Sendable {
    case pgpass
    case kubeconfig
    case awsSharedCredentials = "aws-shared-credentials"
    case googleServiceAccount = "google-service-account"

    public var environmentName: String {
        switch self {
        case .pgpass: return "PGPASSFILE"
        case .kubeconfig: return "KUBECONFIG"
        case .awsSharedCredentials: return "AWS_SHARED_CREDENTIALS_FILE"
        case .googleServiceAccount: return "GOOGLE_APPLICATION_CREDENTIALS"
        }
    }

    public static let maximumFileBytes = 1024 * 1024

    public func render(_ value: String) throws -> Data {
        let data = Data(value.utf8)
        guard !data.isEmpty,
              data.count <= Self.maximumFileBytes,
              !data.contains(0) else {
            throw SecureDeliveryError.invalidInheritedFile
        }
        return data
    }
}
