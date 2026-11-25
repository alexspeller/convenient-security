import Foundation

/// Bounded reader for `~/.aws/credentials`-style ini files, feeding the
/// creds-aws import: each static-key profile becomes one
/// `AWSCredentialProcess.renderBundle` string ready for the store. Profiles
/// whose credentials are *derived* — SSO, `credential_process`, assumed roles
/// — hold no importable static secret and are reported as skipped, never
/// silently dropped and never guessed at.
public struct AWSSharedCredentialsFile: Sendable, Equatable {
    public static let maximumBytes = 1024 * 1024
    public static let maximumProfiles = 256

    public struct Profile: Sendable, Equatable {
        public let name: String
        public let accessKeyID: String?
        public let secretAccessKey: String?
        public let sessionToken: String?
        /// Keys that mark the profile's credentials as derived elsewhere.
        public let derivedCredentialKeys: [String]

        public var isImportable: Bool {
            accessKeyID != nil && secretAccessKey != nil && derivedCredentialKeys.isEmpty
        }
    }

    public enum SkipReason: Error, Sendable, Equatable {
        case derivedCredentials(keys: [String])
        case missingStaticKeys
    }

    public let profiles: [Profile]

    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes,
              !data.contains(0),
              let text = String(data: data, encoding: .utf8) else {
            throw SecureDeliveryError.invalidAWSCredentialDocument
        }

        let derivedMarkers: Set<String> = [
            "credential_process", "sso_start_url", "sso_session", "sso_account_id",
            "role_arn", "source_profile", "credential_source", "web_identity_token_file",
        ]

        var profiles: [Profile] = []
        var order: [String] = []
        var sections: [String: [String: String]] = [:]
        var current: String?

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = String(rawLine)
            if line.last == "\r" { line.removeLast() }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") {
                continue
            }
            if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
                var name = String(trimmed.dropFirst().dropLast())
                    .trimmingCharacters(in: .whitespaces)
                // The credentials file uses bare names; a config-style
                // `profile foo` heading is tolerated and normalized.
                if name.lowercased().hasPrefix("profile ") {
                    name = String(name.dropFirst("profile ".count))
                        .trimmingCharacters(in: .whitespaces)
                }
                guard !name.isEmpty else {
                    throw SecureDeliveryError.invalidAWSCredentialDocument
                }
                if sections[name] == nil {
                    order.append(name)
                    sections[name] = [:]
                    guard order.count <= Self.maximumProfiles else {
                        throw SecureDeliveryError.invalidAWSCredentialDocument
                    }
                }
                current = name
                continue
            }
            guard let current else {
                // Content before any section heading is not a credentials file.
                throw SecureDeliveryError.invalidAWSCredentialDocument
            }
            guard let equals = trimmed.firstIndex(of: "=") else { continue }
            // AWS parses keys case-insensitively; values are verbatim.
            let key = trimmed[..<equals].trimmingCharacters(in: .whitespaces).lowercased()
            let value = trimmed[trimmed.index(after: equals)...]
                .trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { continue }
            if sections[current]?[key] == nil {
                sections[current]?[key] = value
            }
        }

        for name in order {
            let keys = sections[name] ?? [:]
            let derived = derivedMarkers.intersection(keys.keys).sorted()
            profiles.append(Profile(
                name: name,
                accessKeyID: keys["aws_access_key_id"].flatMap { $0.isEmpty ? nil : $0 },
                secretAccessKey: keys["aws_secret_access_key"].flatMap { $0.isEmpty ? nil : $0 },
                sessionToken: keys["aws_session_token"].flatMap { $0.isEmpty ? nil : $0 },
                derivedCredentialKeys: derived
            ))
        }
        self.profiles = profiles
    }

    /// Every profile resolved to either a store-ready bundle string or a skip
    /// reason. The bundle is the only place a secret value flows, and it flows
    /// straight into the caller's import batch.
    public func importOutcomes() -> [(profile: String, result: Result<String, SkipReason>)] {
        profiles.map { profile in
            if !profile.derivedCredentialKeys.isEmpty {
                return (profile.name, .failure(.derivedCredentials(
                    keys: profile.derivedCredentialKeys)))
            }
            guard let accessKeyID = profile.accessKeyID,
                  let secretAccessKey = profile.secretAccessKey else {
                return (profile.name, .failure(.missingStaticKeys))
            }
            var fields = [
                AWSCredentialProcess.accessKeyID: accessKeyID,
                AWSCredentialProcess.secretAccessKey: secretAccessKey,
            ]
            if let sessionToken = profile.sessionToken {
                fields[AWSCredentialProcess.sessionToken] = sessionToken
            }
            guard let bundle = try? AWSCredentialProcess.renderBundle(fields: fields) else {
                return (profile.name, .failure(.missingStaticKeys))
            }
            return (profile.name, .success(bundle))
        }
    }
}
