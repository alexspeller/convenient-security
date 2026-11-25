import Foundation

/// Google's fixed workload identity provider resource, never a caller-supplied
/// token endpoint. Shared by setup and the sealed target's validation.
public struct GoogleWorkloadIdentityProvider: Sendable {
    public let projectNumber: String
    public let pool: String
    public let provider: String

    public init(_ audience: String) throws {
        var path = audience
        for prefix in ["//iam.googleapis.com/", "https://iam.googleapis.com/"] where path.hasPrefix(prefix) {
            path = String(path.dropFirst(prefix.count))
        }
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        func isID(_ value: String) -> Bool {
            (4...32).contains(value.utf8.count)
                && value.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2d }
        }
        guard path != audience, parts.count == 8, parts[0] == "projects",
              !parts[1].isEmpty, parts[1].utf8.count <= 20,
              parts[1].utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
              parts[2] == "locations", parts[3] == "global", parts[4] == "workloadIdentityPools",
              isID(parts[5]), parts[6] == "providers", isID(parts[7]) else {
            throw MachineIdentitySetupError.notGoogleAudience
        }
        projectNumber = parts[1]
        pool = parts[5]
        provider = parts[7]
    }

    public var audience: String {
        "//iam.googleapis.com/projects/\(projectNumber)/locations/global/workloadIdentityPools/\(pool)/providers/\(provider)"
    }
}

/// Exchanges only after SecretResolver has authorized a canonical reference.
/// No JWT, access token, response body or provider error text is diagnostic.
public enum GoogleWebIdentity {
    public static let lifetime = 3_600
    public static let reuseMargin: TimeInterval = 300
    public static let maximumResponseBytes = 64 * 1_024
    public static let scope = "https://www.googleapis.com/auth/cloud-platform"
    public static let accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

    public static func request(audience: String, token: String) throws -> URLRequest {
        let provider = try GoogleWorkloadIdentityProvider(audience)
        return try post(URL(string: MachineIdentityGoogleSetup.tokenURL)!, fields: [
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": accessTokenType,
            "subject_token_type": MachineIdentityGoogleSetup.subjectTokenType,
            "audience": provider.audience, "subject_token": token, "scope": scope,
        ])
    }

    public static func impersonationRequest(serviceAccount: String, token: String) throws -> URLRequest {
        guard MachineIdentityGoogleSetup.isServiceAccount(serviceAccount) else { throw GoogleWebIdentityError.invalidTarget }
        var request = try post(URL(string:
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/\(serviceAccount):generateAccessToken"
        )!, fields: ["scope": [scope], "lifetime": "\(lifetime)s"])
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        return request
    }

    private static func post(_ url: URL, fields: [String: Any]) throws -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("csec-machine-identity", forHTTPHeaderField: "User-Agent")
        request.httpBody = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
        request.timeoutInterval = 15
        return request
    }

    public static func parse(_ data: Data, status: Int, now: Date, impersonated: Bool = false) throws -> GoogleAccessToken {
        guard data.count <= maximumResponseBytes else { throw GoogleWebIdentityError.unexpectedResponse(status) }
        guard (200..<300).contains(status) else { throw GoogleWebIdentityError.refused(status) }
        guard let fields = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = fields[impersonated ? "accessToken" : "access_token"] as? String,
              !token.isEmpty, token.utf8.count <= GoogleExecutableCredential.maximumTokenBytes,
              token.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) else {
            throw GoogleWebIdentityError.unexpectedResponse(status)
        }
        let expiration: Date
        if impersonated {
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            guard let text = fields["expireTime"] as? String,
                  let date = ISO8601DateFormatter().date(from: text) ?? formatter.date(from: text),
                  date > now, date.timeIntervalSince(now) <= Double(lifetime) + 60 else {
                throw GoogleWebIdentityError.unexpectedResponse(status)
            }
            expiration = date
        } else {
            guard fields["token_type"] as? String == "Bearer", fields["issued_token_type"] as? String == accessTokenType,
                  let seconds = fields["expires_in"] as? Int, (1...lifetime).contains(seconds),
                  !(fields["expires_in"] is Bool) else {
                throw GoogleWebIdentityError.unexpectedResponse(status)
            }
            expiration = now.addingTimeInterval(Double(seconds))
        }
        return GoogleAccessToken(value: Data(token.utf8), expiration: expiration)
    }

    /// Ephemeral, bounded, with redirects refused so neither a JWT body nor a
    /// bearer header can be forwarded to another destination.
    @Sendable
    public static func send(_ request: URLRequest) async throws -> (Data, Int) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        let session = URLSession(configuration: configuration, delegate: GoogleTokenRedirectGuard(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (bytes, response) = try await session.bytes(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        var data = Data()
        for try await byte in bytes {
            guard data.count < maximumResponseBytes else { throw GoogleWebIdentityError.unexpectedResponse(status) }
            data.append(byte)
        }
        return (data, status)
    }
}

private final class GoogleTokenRedirectGuard: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

public enum GoogleWebIdentityError: Error, Equatable, Sendable {
    case invalidTarget
    case refused(Int)
    case unexpectedResponse(Int)
    case unreachable

    public var message: String {
        switch self {
        case .invalidTarget: return "the Google sign-in target is not complete"
        case let .refused(status): return "Google refused the sign-in (HTTP \(status)); check the provider and its IAM bindings"
        case let .unexpectedResponse(status): return "Google sent a sign-in reply csec could not read (HTTP \(status))"
        case .unreachable: return "Google's sign-in service could not be reached"
        }
    }
}

public struct GoogleAccessToken: Sendable {
    public let value: Data
    public let expiration: Date
}

actor GoogleWebIdentitySessions {
    private var held: [String: GoogleAccessToken] = [:]

    func token(for key: String, now: Date) -> GoogleAccessToken? {
        held = held.filter { $0.value.expiration.timeIntervalSince(now) > GoogleWebIdentity.reuseMargin }
        return held[key]
    }

    func keep(_ token: GoogleAccessToken, for key: String) {
        // Catalog limits bound live targets; also bound entries left by removals
        // or key changes until their natural expiry.
        if held.count >= MachineIdentityDocument.maximumTargets { held.removeAll() }
        held[key] = token
    }
}
