import Foundation

// Where an identity's issuer files live is the user's choice: any HTTPS host
// that serves the two public files works (Alex, csec-0.39.6.1). csec makes the
// files, suggests hosts, writes the exact commands for a locked-down S3
// bucket, and checks what the host actually publishes. Whoever can change the
// published key set can sign as any subject the cloud trusts, so the check
// treats a key this Mac did not expect as a possible compromise.

// MARK: - S3 bucket guidance

/// The commands that publish an issuer from an S3 bucket the user owns, run
/// with the user's own AWS administrator credentials. csec prints them; it
/// never holds cloud administrator credentials itself.
///
/// The policy follows av-0.360.15: anyone may read exactly the two issuer
/// files, and every action other than reads and listing is denied on the
/// bucket and its objects to every principal but one named administrator. An
/// account's other powerful principals (a PowerUser role, a CI role) could
/// otherwise rewrite the key set and become every role that trusts it.
/// Versioning keeps a replaced key set visible.
public struct MachineIdentityS3Issuer: Sendable, Equatable {
    public let bucket: String
    public let region: String
    /// The only principal that may change the bucket: the ARN of the role or
    /// user the human publishes keys as.
    public let administratorARN: String

    public enum SetupError: Error, Equatable, Sendable {
        case invalidBucket
        case invalidRegion
        case invalidAdministrator

        public var message: String {
            switch self {
            case .invalidBucket:
                return "an S3 bucket name is 3 to 63 lower-case letters, digits and '-', with no dots (the issuer URL must match the bucket's TLS certificate)"
            case .invalidRegion: return "an AWS region looks like eu-west-2"
            case .invalidAdministrator:
                return "the administrator must be an IAM role or user ARN (arn:aws:iam::<account>:role/... or :user/...)"
            }
        }
    }

    public init(bucket: String, region: String, administratorARN: String) throws {
        guard Self.isValidBucket(bucket) else { throw SetupError.invalidBucket }
        guard Self.isValidRegion(region) else { throw SetupError.invalidRegion }
        guard Self.isValidAdministrator(administratorARN) else { throw SetupError.invalidAdministrator }
        self.bucket = bucket
        self.region = region
        self.administratorARN = administratorARN
    }

    /// The virtual-hosted URL, which AWS serves under its own public
    /// certificate for any bucket name without dots.
    public var issuer: String { "https://\(bucket).s3.\(region).amazonaws.com" }

    public func bucketPolicy() throws -> Data {
        let objects = ["arn:aws:s3:::\(bucket)/.well-known/openid-configuration", "arn:aws:s3:::\(bucket)/jwks.json"]
        let policy: [String: Any] = [
            "Version": "2012-10-17",
            "Statement": [
                [
                    "Sid": "PublicIssuerFiles",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": objects,
                ],
                [
                    "Sid": "OnlyTheAdministratorChangesTheIssuer",
                    "Effect": "Deny",
                    "Principal": "*",
                    "NotAction": ["s3:Get*", "s3:List*"],
                    "Resource": ["arn:aws:s3:::\(bucket)", "arn:aws:s3:::\(bucket)/*"],
                    "Condition": ["ArnNotEquals": ["aws:PrincipalArn": administratorARN]],
                ],
            ],
        ]
        return try JSONSerialization.data(
            withJSONObject: policy, options: [.sortedKeys, .withoutEscapingSlashes, .prettyPrinted]
        )
    }

    /// The commands, in order, for files written as `openid-configuration`,
    /// `jwks.json` and `bucket-policy.json` in the current directory. Versioning
    /// goes on before the policy, which then denies changing it to everyone
    /// but the administrator.
    public func setupCommands() -> [String] {
        let location = region == "us-east-1" ? [] : ["--create-bucket-configuration", "LocationConstraint=\(region)"]
        return [
            ["aws", "s3api", "create-bucket", "--bucket", bucket, "--region", region] + location,
            ["aws", "s3api", "put-public-access-block", "--bucket", bucket, "--public-access-block-configuration",
             "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=false"],
            // Quoted when printed: zsh would glob the brackets and fish would
            // expand the braces.
            ["aws", "s3api", "put-bucket-ownership-controls", "--bucket", bucket,
             "--ownership-controls", "Rules=[{ObjectOwnership=BucketOwnerEnforced}]"],
            ["aws", "s3api", "put-bucket-versioning", "--bucket", bucket, "--versioning-configuration", "Status=Enabled"],
            ["aws", "s3api", "put-bucket-policy", "--bucket", bucket, "--policy", "file://bucket-policy.json"],
        ].map(MachineIdentityShell.command) + publishCommands()
    }

    /// The commands that publish the files again after a key change.
    public func publishCommands() -> [String] {
        [
            ["aws", "s3api", "put-object", "--bucket", bucket, "--key", ".well-known/openid-configuration",
             "--body", "openid-configuration", "--content-type", "application/json"],
            ["aws", "s3api", "put-object", "--bucket", bucket, "--key", "jwks.json",
             "--body", "jwks.json", "--content-type", "application/json"],
        ].map(MachineIdentityShell.command)
    }

    static func isValidBucket(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        guard (3...63).contains(bytes.count),
              bytes.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2d }),
              bytes.first != 0x2d, bytes.last != 0x2d,
              !name.hasPrefix("xn--"), !name.hasPrefix("sthree-"),
              !name.hasSuffix("-s3alias"), !name.hasSuffix("--ol-s3") else { return false }
        return true
    }

    static func isValidRegion(_ region: String) -> Bool {
        let parts = region.split(separator: "-", omittingEmptySubsequences: false)
        guard (3...4).contains(parts.count), region.utf8.count <= 32,
              let last = parts.last, !last.isEmpty, last.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return false }
        return parts.dropLast().allSatisfy { !$0.isEmpty && $0.utf8.allSatisfy { $0 >= 0x61 && $0 <= 0x7a } }
    }

    static func isValidAdministrator(_ arn: String) -> Bool {
        let parts = arn.split(separator: ":", maxSplits: 5, omittingEmptySubsequences: false)
        guard parts.count == 6, parts[0] == "arn", parts[1].hasPrefix("aws"), parts[2] == "iam", parts[3].isEmpty,
              parts[4].utf8.count == 12, parts[4].utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
              parts[5].hasPrefix("role/") || parts[5].hasPrefix("user/"),
              arn.utf8.count <= 2_048, arn.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f && $0 != 0x22 && $0 != 0x5c }) else {
            return false
        }
        return true
    }
}

// MARK: - What the issuer publishes

/// The result of comparing what an issuer publishes with what this Mac
/// expects. Value-free: key ids and URLs are public metadata.
public enum MachineIdentityIssuerFinding: Equatable, Sendable {
    /// The discovery document names this issuer and its own key set, which
    /// holds this Mac's key and no key this Mac has not accepted.
    case clear(publishedKeys: Int)
    /// This Mac's current key is not published: clouds that fetch keys will
    /// refuse its tokens. Not a compromise, but nothing signs in until it is.
    case ownKeyMissing(kid: String)
    /// Keys this Mac has never accepted are published. Each one can sign as
    /// any subject the issuer's clouds trust: a new Mac of the user's, or
    /// someone else's key in the key set.
    case unexpectedKeys([String])
    /// The discovery document names another issuer or points its key set
    /// somewhere else, so the clouds would read keys from a place this Mac
    /// does not check.
    case discoveryMismatch(String)
    /// The files could not be fetched or read; nothing is known.
    case unreachable(String)

    public var isClear: Bool {
        if case .clear = self { return true }
        return false
    }

    public var summary: String {
        switch self {
        case let .clear(count):
            return "the issuer publishes this Mac's key and \(count - 1) other accepted key\(count == 2 ? "" : "s")"
        case let .ownKeyMissing(kid):
            return "this Mac's key (\(kid)) is not published yet, so clouds that fetch the issuer's keys will refuse its tokens"
        case let .unexpectedKeys(kids):
            return "the issuer publishes \(kids.count) key\(kids.count == 1 ? "" : "s") this Mac never accepted (\(kids.joined(separator: ", "))): each can sign in as any subject the issuer's clouds trust"
        case let .discoveryMismatch(detail):
            return "the issuer's discovery document does not match: \(detail)"
        case let .unreachable(detail):
            return "the issuer's files could not be checked: \(detail)"
        }
    }
}

public enum MachineIdentityIssuerCheck {
    /// The most either file may be: a key set of 100 EC keys (AWS's limit) is
    /// well under it.
    public static let maximumDocumentBytes = 64 * 1_024

    /// Compares the published discovery document and key set with
    /// `ownKeys` (this identity's keys, current first) and `acceptedKids`
    /// (other keys the human has accepted, such as another Mac's). The key
    /// set comes from the discovery document's `jwks_uri`, which must be the
    /// issuer's own `/jwks.json`.
    public static func evaluate(
        issuer: String,
        discovery: Data,
        keySet: Data,
        ownKeys: [MachineIdentityJWK],
        acceptedKids: Set<String>
    ) -> MachineIdentityIssuerFinding {
        guard discovery.count <= maximumDocumentBytes, keySet.count <= maximumDocumentBytes,
              let document = try? JSONSerialization.jsonObject(with: discovery) as? [String: Any] else {
            return .unreachable("the discovery document is not a JSON object")
        }
        guard document["issuer"] as? String == issuer else {
            return .discoveryMismatch("it names another issuer")
        }
        guard document["jwks_uri"] as? String == issuer + MachineIdentityIssuer.keySetPath else {
            return .discoveryMismatch("its jwks_uri is not \(issuer + MachineIdentityIssuer.keySetPath)")
        }
        guard let set = try? JSONSerialization.jsonObject(with: keySet) as? [String: Any],
              let entries = set["keys"] as? [[String: Any]] else {
            return .unreachable("the key set is not a JWKS")
        }
        // Every entry counts, whatever its type or algorithm: a relying party
        // may accept an RSA key as readily as an EC one. Keys are compared by
        // the RFC 7638 thumbprint of what is published, never by the `kid`
        // the file claims, so a key swapped in under an accepted or own kid
        // is still a key this Mac never accepted. An entry that is not an EC
        // P-256 key has no thumbprint csec accepts, so it is always reported.
        let trusted = Set(ownKeys.map(\.kid)).union(acceptedKids)
        var thumbprints: [String] = []
        var unexpected: [String] = []
        for (index, entry) in entries.enumerated() {
            let claimed = (entry["kid"] as? String).map { ReviewDisplay.bounded(ReviewDisplay.sanitized($0), maxBytes: 64) }
            guard let thumbprint = MachineIdentityJWK.thumbprint(ofEntry: entry) else {
                unexpected.append("\(claimed.map { "kid \($0)" } ?? "key #\(index + 1)") (not an EC P-256 key)")
                continue
            }
            thumbprints.append(thumbprint)
            if !trusted.contains(thumbprint) { unexpected.append(thumbprint) }
        }
        if !unexpected.isEmpty { return .unexpectedKeys(unexpected) }
        if let current = ownKeys.first, !thumbprints.contains(current.kid) {
            return .ownKeyMissing(kid: current.kid)
        }
        return .clear(publishedKeys: entries.count)
    }

    /// Fetches both files anonymously over HTTPS, as a cloud would, and
    /// evaluates them. `fetch` is injected for tests; production uses
    /// `URLSession` with no cookies, cache or credentials.
    public static func check(
        issuer: String,
        ownKeys: [MachineIdentityJWK],
        acceptedKids: Set<String>,
        fetch: @Sendable (URL) async throws -> Data = MachineIdentityIssuerCheck.fetchAnonymously
    ) async -> MachineIdentityIssuerFinding {
        guard MachineIdentityIssuer.isValid(issuer),
              let discoveryURL = URL(string: issuer + MachineIdentityIssuer.discoveryPath),
              let keySetURL = URL(string: issuer + MachineIdentityIssuer.keySetPath) else {
            return .unreachable("the issuer URL is not valid")
        }
        let discovery: Data
        let keySet: Data
        do {
            discovery = try await fetch(discoveryURL)
            keySet = try await fetch(keySetURL)
        } catch {
            return .unreachable(ReviewDisplay.bounded(ReviewDisplay.sanitized(String(describing: error)), maxBytes: 200))
        }
        return evaluate(issuer: issuer, discovery: discovery, keySet: keySet, ownKeys: ownKeys, acceptedKids: acceptedKids)
    }

    public enum FetchError: Error, CustomStringConvertible {
        case status(Int)
        case tooLarge
        case notHTTP

        public var description: String {
            switch self {
            case let .status(code): return "HTTP \(code)"
            case .tooLarge: return "a file is larger than \(MachineIdentityIssuerCheck.maximumDocumentBytes) bytes"
            case .notHTTP: return "not an HTTP response"
            }
        }
    }

    @Sendable
    public static func fetchAnonymously(_ url: URL) async throws -> Data {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = 20
        configuration.httpAdditionalHeaders = ["User-Agent": "csec-identity-check"]
        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse else { throw FetchError.notHTTP }
        guard http.statusCode == 200 else { throw FetchError.status(http.statusCode) }
        guard data.count <= maximumDocumentBytes else { throw FetchError.tooLarge }
        return data
    }
}
