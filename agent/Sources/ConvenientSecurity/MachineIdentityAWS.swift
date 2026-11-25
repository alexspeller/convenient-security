import Foundation

// An `aws` target's sign-in: csecd mints a short token for the target's
// audience and exchanges it with AWS STS (`AssumeRoleWithWebIdentity`) for
// temporary credentials of one role. The call is unsigned, as AWS allows for
// this action, so csecd holds no AWS credentials of its own; the token goes in
// the request body, never the URL. What comes back is the `credential_process`
// bundle `csec creds aws --item` already serves, so the AWS adapter needs no
// change for a minted sign-in.

public enum AWSWebIdentity {
    /// Half an hour. STS itself allows 900 seconds, but botocore refreshes
    /// `credential_process` output once fewer than 15 minutes remain, so a
    /// session that short would have it run csec on every request.
    public static let minimumDuration = 1_800
    /// An hour, as for tokens: `credential_process` refreshes on its own, so a
    /// longer session would only lengthen what a stolen copy is good for.
    public static let maximumDuration = 3_600
    /// The token only has to survive the exchange.
    public static let tokenLifetime = 300
    /// csecd reuses credentials it already holds while more than this is left.
    /// botocore refreshes `credential_process` output once fewer than 15
    /// minutes remain (`_DEFAULT_ADVISORY_REFRESH_TIMEOUT`), so anything
    /// shorter would have it ask again on every request.
    public static let reuseMargin: TimeInterval = 20 * 60
    public static let maximumResponseBytes = 64 * 1_024

    /// `arn:<partition>:iam::<12 digits>:role/<optional path/><name>`.
    public static func isValidRoleARN(_ arn: String) -> Bool {
        let parts = arn.split(separator: ":", maxSplits: 5, omittingEmptySubsequences: false)
        guard parts.count == 6, parts[0] == "arn", ["aws", "aws-cn", "aws-us-gov"].contains(String(parts[1])),
              parts[2] == "iam", parts[3].isEmpty,
              parts[4].utf8.count == 12, parts[4].utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
              parts[5].hasPrefix("role/"), arn.utf8.count <= 2_048 else { return false }
        let path = parts[5].dropFirst("role/".count)
        guard let name = path.split(separator: "/", omittingEmptySubsequences: false).last,
              (1...64).contains(name.utf8.count) else { return false }
        return path.utf8.allSatisfy { byte in
            (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) || (byte >= 0x30 && byte <= 0x39)
                || Array("+=,.@_-/".utf8).contains(byte)
        }
    }

    public static func accountID(ofRole arn: String) -> String? {
        let parts = arn.split(separator: ":", maxSplits: 5, omittingEmptySubsequences: false)
        return parts.count == 6 ? String(parts[4]) : nil
    }

    public static func roleName(ofRole arn: String) -> String? {
        let parts = arn.split(separator: ":", maxSplits: 5, omittingEmptySubsequences: false)
        guard parts.count == 6 else { return nil }
        return parts[5].split(separator: "/").last.map(String.init)
    }

    /// `RoleSessionName` names the session in CloudTrail: the identity's
    /// subject, in the characters STS accepts, 2 to 64 of them.
    public static func sessionName(forSubject subject: String) -> String {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+=,.@_-")
        let mapped = String(subject.map { allowed.contains($0) ? $0 : "-" }.prefix(64))
        return mapped.count >= 2 ? mapped : "csec-machine-identity"
    }

    /// The regional STS endpoint: AWS recommends it over the global one, and
    /// it keeps the exchange in the region the human chose.
    public static func endpoint(region: String) -> URL? {
        guard MachineIdentityS3Issuer.isValidRegion(region) else { return nil }
        let suffix = region.hasPrefix("cn-") ? "amazonaws.com.cn" : "amazonaws.com"
        return URL(string: "https://sts.\(region).\(suffix)/")
    }

    /// The exchange as an HTTP request: a form-encoded POST, so the token is in
    /// the body and never in a URL a proxy or log might keep.
    public static func request(roleARN: String, region: String, token: String, sessionName: String, duration: Int) throws -> URLRequest {
        guard let url = endpoint(region: region) else { throw AWSWebIdentityError.invalidTarget }
        var form = URLComponents()
        form.queryItems = [
            URLQueryItem(name: "Action", value: "AssumeRoleWithWebIdentity"),
            URLQueryItem(name: "Version", value: "2011-06-15"),
            URLQueryItem(name: "RoleArn", value: roleARN),
            URLQueryItem(name: "RoleSessionName", value: sessionName),
            URLQueryItem(name: "DurationSeconds", value: String(duration)),
            URLQueryItem(name: "WebIdentityToken", value: token),
        ]
        // URLComponents leaves `+` and `=` alone in a query; a form body must
        // escape them or STS reads `+` as a space.
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "+=&")
        let body = (form.queryItems ?? []).map { item in
            let name = item.name.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
            let value = (item.value ?? "").addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
            return name + "=" + value
        }.joined(separator: "&")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("csec-machine-identity", forHTTPHeaderField: "User-Agent")
        request.httpBody = Data(body.utf8)
        request.timeoutInterval = 15
        return request
    }

    /// Reads STS's XML reply. A refusal is reported by its error code alone,
    /// and only a code AWS documents for this action: the message can quote
    /// the request, and the reply is not csec's text.
    public static func parse(_ data: Data, status: Int) throws -> AWSTemporaryCredentials {
        guard data.count <= maximumResponseBytes else { throw AWSWebIdentityError.unexpectedResponse(status) }
        let fields = STSReplyReader.read(data)
        guard (200..<300).contains(status) else {
            let code = fields["Code"].flatMap { documentedErrorCodes.contains($0) ? $0 : nil }
            throw AWSWebIdentityError.refused(code: code, status: status)
        }
        guard let accessKeyID = fields["AccessKeyId"], let secretAccessKey = fields["SecretAccessKey"],
              let sessionToken = fields["SessionToken"], let expirationText = fields["Expiration"],
              let expiration = parseDate(expirationText) else {
            throw AWSWebIdentityError.unexpectedResponse(status)
        }
        return AWSTemporaryCredentials(
            accessKeyID: accessKeyID, secretAccessKey: secretAccessKey,
            sessionToken: sessionToken, expiration: expiration
        )
    }

    static let documentedErrorCodes: Set<String> = [
        "AccessDenied", "ExpiredTokenException", "IDPCommunicationError", "IDPRejectedClaim",
        "InvalidIdentityToken", "MalformedPolicyDocument", "PackedPolicyTooLarge", "RegionDisabledException",
        "InvalidParameterValue", "ValidationError", "Throttling",
    ]

    static func parseDate(_ text: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: text) { return date }
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: text)
    }

    /// The live exchange: an ephemeral session with no cookies, cache or
    /// credentials. Tests inject their own.
    @Sendable
    public static func send(_ request: URLRequest) async throws -> (Data, Int) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw AWSWebIdentityError.unexpectedResponse(0) }
        return (data, http.statusCode)
    }
}

public enum AWSWebIdentityError: Error, Equatable, Sendable {
    case invalidTarget
    case refused(code: String?, status: Int)
    case unexpectedResponse(Int)
    case unreachable

    /// Value-free and csec-authored.
    public var message: String {
        switch self {
        case .invalidTarget:
            return "the AWS target is not complete"
        case let .refused(code?, status):
            return "AWS STS refused the sign-in (\(code), HTTP \(status))\(Self.hint(code))"
        case let .refused(nil, status):
            return "AWS STS refused the sign-in (HTTP \(status))"
        case let .unexpectedResponse(status):
            return "AWS STS sent a reply csec could not read (HTTP \(status))"
        case .unreachable:
            return "AWS STS could not be reached"
        }
    }

    private static func hint(_ code: String) -> String {
        switch code {
        case "InvalidIdentityToken":
            return ": check the issuer is published and its IAM OIDC provider exists (csec identity check)"
        case "AccessDenied":
            return ": the role's trust policy does not admit this Mac's subject and audience"
        case "IDPCommunicationError":
            return ": AWS could not fetch the issuer's keys"
        default:
            return ""
        }
    }
}

/// Temporary credentials for one role. Held only by csecd.
public struct AWSTemporaryCredentials: Sendable, Equatable {
    public let accessKeyID: String
    public let secretAccessKey: String
    public let sessionToken: String
    public let expiration: Date

    public init(accessKeyID: String, secretAccessKey: String, sessionToken: String, expiration: Date) {
        self.accessKeyID = accessKeyID
        self.secretAccessKey = secretAccessKey
        self.sessionToken = sessionToken
        self.expiration = expiration
    }

    /// The flat bundle `AWSCredentialProcess.fields(fromBundle:)` reads, with
    /// the expiry `credential_process` needs to refresh on its own.
    public func bundle() throws -> Data {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return try NativeStoreDocument(values: [
            AWSCredentialProcess.accessKeyID: accessKeyID,
            AWSCredentialProcess.secretAccessKey: secretAccessKey,
            AWSCredentialProcess.sessionToken: sessionToken,
            AWSCredentialProcess.expiration: formatter.string(from: expiration),
        ]).encoded()
    }
}

/// The text of the few elements an STS reply carries that csec reads.
private final class STSReplyReader: NSObject, XMLParserDelegate {
    private static let wanted: Set<String> = ["AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration", "Code"]
    private var fields: [String: String] = [:]
    private var current: String?
    private var text = ""

    static func read(_ data: Data) -> [String: String] {
        let reader = STSReplyReader()
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = reader
        guard parser.parse() else { return [:] }
        return reader.fields
    }

    func parser(
        _ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
        qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]
    ) {
        current = Self.wanted.contains(elementName) && fields[elementName] == nil ? elementName : nil
        text = ""
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if current != nil { text += string }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if let current, current == elementName {
            let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !value.isEmpty { fields[current] = value }
        }
        current = nil
    }
}

/// The credentials csecd already holds for each AWS target, reused while
/// more than `AWSWebIdentity.reuseMargin` is left. The expiry is the only
/// invalidation; the key names the role, region, duration and signing key, so
/// a changed target never reuses another's credentials.
actor AWSWebIdentitySessions {
    private var held: [String: AWSTemporaryCredentials] = [:]

    func credentials(for key: String, now: Date) -> AWSTemporaryCredentials? {
        guard let credentials = held[key] else { return nil }
        guard credentials.expiration.timeIntervalSince(now) > AWSWebIdentity.reuseMargin else {
            held[key] = nil
            return nil
        }
        return credentials
    }

    func keep(_ credentials: AWSTemporaryCredentials, for key: String) {
        held[key] = credentials
    }
}
