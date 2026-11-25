import CryptoKit
import Foundation
import Security

// Dev-machine OIDC: this Mac as its own OpenID Connect issuer. A P-256 key in
// the Secure Enclave signs short-lived ES256 JSON Web Tokens, and a cloud's
// workload identity federation (an AWS IAM OIDC provider, a Google Cloud
// workload identity pool) trusts the key's public half. Nothing here talks to
// a cloud or to the socket: this file is the key, the token and the two public
// issuer documents, with no authorization of its own. Whoever calls `mint`
// has already been authorized for that identity and audience.

// MARK: - Signers

/// The private half of an identity key. Production keys live in the Secure
/// Enclave and never leave it; `SoftwareIdentitySigner` exists for tests and
/// unsigned development builds, which cannot reach csecd's keychain group.
public protocol IdentitySigner: Sendable {
    var publicKey: P256.Signing.PublicKey { get }
    func signature(for data: Data) throws -> P256.Signing.ECDSASignature
}

public enum MachineIdentityError: Error, Equatable, Sendable {
    case secureEnclaveUnavailable
    case keyUnusable
    case invalidName
    case invalidIssuer
    case invalidSubject
    case invalidAudience
    case invalidLifetime
    case invalidDuration
    case invalidRoleARN
    case invalidRegion
    case invalidGoogleTarget
    case invalidKeyID
    case invalidToken(String)

    public var message: String {
        switch self {
        case .secureEnclaveUnavailable:
            return "this Mac has no Secure Enclave, so it cannot hold a machine identity key"
        case .keyUnusable:
            return "the machine identity key cannot sign on this Mac (erased, or made on another Mac)"
        case .invalidName:
            return "an identity name is 1 to 64 lower-case letters, digits, '-', '_' or '.'"
        case .invalidIssuer:
            return "the issuer must be an https URL with a host and no query, fragment or credentials"
        case .invalidSubject:
            return "the subject must be 1 to \(MachineIdentityClaims.maximumSubjectBytes) printable ASCII characters"
        case .invalidAudience:
            return "each audience must be 1 to 512 printable ASCII characters"
        case .invalidLifetime:
            return "a token lasts between \(MachineIdentityToken.minimumLifetime) and \(MachineIdentityToken.maximumLifetime) seconds"
        case .invalidDuration:
            return "AWS credentials last between \(AWSWebIdentity.minimumDuration) and \(AWSWebIdentity.maximumDuration) seconds"
        case .invalidRoleARN:
            return "an AWS target needs an IAM role ARN (arn:aws:iam::<account>:role/<name>); a token target takes none"
        case .invalidRegion:
            return "an AWS region looks like eu-west-2"
        case .invalidGoogleTarget:
            return "a Google target needs a workload identity provider, an optional service-account email, and a one-hour lifetime"
        case .invalidKeyID:
            return "an accepted key is named by its RFC 7638 thumbprint: 43 base64url characters, as csec identity check prints it"
        case let .invalidToken(detail):
            return "not a valid machine identity token: \(detail)"
        }
    }
}

/// A key held by the Secure Enclave. `dataRepresentation` is the enclave's
/// wrapped handle for it: not key material, but any process running as this
/// user that holds the handle can have the enclave sign with it, measured
/// across two differently signed binaries. It must therefore live only where
/// csecd alone can read it, never in a file.
public struct SecureEnclaveIdentitySigner: IdentitySigner {
    private let key: SecureEnclave.P256.Signing.PrivateKey

    public init(dataRepresentation: Data) throws {
        guard SecureEnclave.isAvailable else { throw MachineIdentityError.secureEnclaveUnavailable }
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
        } catch {
            throw MachineIdentityError.keyUnusable
        }
    }

    /// Makes a new key. Usable from the first unlock after boot, with no
    /// biometric ACL on the key: consent lives in csecd's authorization of
    /// each use, so a token can be minted at the lock screen for a grant a
    /// human already approved.
    public static func create() throws -> (signer: SecureEnclaveIdentitySigner, dataRepresentation: Data) {
        guard SecureEnclave.isAvailable else { throw MachineIdentityError.secureEnclaveUnavailable }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            &accessError
        ) else {
            throw MachineIdentityError.secureEnclaveUnavailable
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        return (SecureEnclaveIdentitySigner(key: key), key.dataRepresentation)
    }

    private init(key: SecureEnclave.P256.Signing.PrivateKey) {
        self.key = key
    }

    public var publicKey: P256.Signing.PublicKey { key.publicKey }

    public func signature(for data: Data) throws -> P256.Signing.ECDSASignature {
        do {
            return try key.signature(for: data)
        } catch {
            throw MachineIdentityError.keyUnusable
        }
    }
}

/// An exportable software key, for tests and unsigned development builds only.
public struct SoftwareIdentitySigner: IdentitySigner {
    private let key: P256.Signing.PrivateKey

    public init(key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.key = key
    }

    public var publicKey: P256.Signing.PublicKey { key.publicKey }

    public func signature(for data: Data) throws -> P256.Signing.ECDSASignature {
        try key.signature(for: data)
    }
}

// MARK: - Public key as a JWK

/// The public half of an identity key as an RFC 7517 JSON Web Key, with the
/// RFC 7638 thumbprint as its `kid`.
public struct MachineIdentityJWK: Codable, Sendable, Equatable {
    public let kty: String
    public let crv: String
    public let x: String
    public let y: String
    public let kid: String
    public let alg: String
    public let use: String

    public init(publicKey: P256.Signing.PublicKey) {
        // x963 is 0x04 || X || Y, each coordinate 32 bytes for P-256.
        let point = publicKey.x963Representation
        let x = Base64URL.encode(point.subdata(in: 1..<33))
        let y = Base64URL.encode(point.subdata(in: 33..<65))
        self.kty = "EC"
        self.crv = "P-256"
        self.x = x
        self.y = y
        self.kid = Self.thumbprint(x: x, y: y)
        self.alg = "ES256"
        self.use = "sig"
    }

    /// Whether `value` has the shape of a P-256 key's RFC 7638 thumbprint:
    /// a SHA-256 digest in unpadded base64url.
    public static func isThumbprint(_ value: String) -> Bool {
        value.utf8.count == 43 && Base64URL.decode(value)?.count == 32
    }

    /// The thumbprint of a published key-set entry, or nil when it is not an
    /// EC P-256 key with well-formed coordinates.
    static func thumbprint(ofEntry entry: [String: Any]) -> String? {
        guard entry["kty"] as? String == "EC", entry["crv"] as? String == "P-256",
              let x = entry["x"] as? String, Base64URL.decode(x)?.count == 32,
              let y = entry["y"] as? String, Base64URL.decode(y)?.count == 32 else { return nil }
        return thumbprint(x: x, y: y)
    }

    /// RFC 7638 §3: SHA-256 over the required members only, in lexicographic
    /// order, with no whitespace. The base64url alphabet needs no JSON
    /// escaping, so the string is built directly.
    static func thumbprint(x: String, y: String) -> String {
        let canonical = #"{"crv":"P-256","kty":"EC","x":"\#(x)","y":"\#(y)"}"#
        return Base64URL.encode(Data(SHA256.hash(data: Data(canonical.utf8))))
    }

    /// The public key this JWK describes, refusing one whose `kid` is not its
    /// own thumbprint.
    public func publicKey() throws -> P256.Signing.PublicKey {
        guard kty == "EC", crv == "P-256",
              let xBytes = Base64URL.decode(x), xBytes.count == 32,
              let yBytes = Base64URL.decode(y), yBytes.count == 32,
              kid == Self.thumbprint(x: x, y: y) else {
            throw MachineIdentityError.invalidToken("malformed public key")
        }
        return try P256.Signing.PublicKey(x963Representation: Data([0x04]) + xBytes + yBytes)
    }
}

// MARK: - Claims and tokens

/// What one identity token asserts. `issuer` is the URL the cloud looks the
/// keys up under (or, for an uploaded JWKS, only a name it matches), `subject`
/// names this Mac, and `audience` is the provider the token is for.
public struct MachineIdentityClaims: Sendable, Equatable {
    /// Google Cloud maps `sub` to `google.subject`, which holds at most 127
    /// bytes; a longer subject would mint tokens Google refuses.
    public static let maximumSubjectBytes = 127

    public let issuer: String
    public let subject: String
    public let audience: String
    public let issuedAt: Date
    public let lifetime: Int
    public let tokenID: String

    public init(
        issuer: String,
        subject: String,
        audience: String,
        issuedAt: Date,
        lifetime: Int = MachineIdentityToken.defaultLifetime,
        tokenID: String = UUID().uuidString.lowercased()
    ) throws {
        guard MachineIdentityIssuer.isValid(issuer) else { throw MachineIdentityError.invalidIssuer }
        guard Self.isPrintable(subject, maxBytes: MachineIdentityClaims.maximumSubjectBytes) else { throw MachineIdentityError.invalidSubject }
        guard Self.isPrintable(audience, maxBytes: 512) else { throw MachineIdentityError.invalidAudience }
        guard (MachineIdentityToken.minimumLifetime...MachineIdentityToken.maximumLifetime).contains(lifetime) else {
            throw MachineIdentityError.invalidLifetime
        }
        self.issuer = issuer
        self.subject = subject
        self.audience = audience
        // Whole seconds: NumericDate is seconds, and a fraction would make
        // `expiresAt` disagree with what the token says.
        self.issuedAt = Date(timeIntervalSince1970: issuedAt.timeIntervalSince1970.rounded(.down))
        self.lifetime = lifetime
        self.tokenID = tokenID
    }

    public var expiresAt: Date { issuedAt.addingTimeInterval(TimeInterval(lifetime)) }

    static func isPrintable(_ value: String, maxBytes: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maxBytes && value.utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7f }
    }
}

public enum MachineIdentityToken {
    /// An hour: the longest an AWS web-identity session can be asked to
    /// outlive its token by default, and well inside Google's 24-hour limit.
    /// A stolen token is good until it expires, so it is kept short.
    public static let defaultLifetime = 3_600
    public static let minimumLifetime = 60
    public static let maximumLifetime = 3_600

    /// A compact JWS (`header.payload.signature`) for `claims`, signed ES256
    /// with `signer`, whose public key's thumbprint goes in the header's `kid`.
    public static func mint(_ claims: MachineIdentityClaims, signer: IdentitySigner) throws -> String {
        let kid = MachineIdentityJWK(publicKey: signer.publicKey).kid
        let header: [String: Any] = ["alg": "ES256", "typ": "JWT", "kid": kid]
        let issued = Int(claims.issuedAt.timeIntervalSince1970)
        let payload: [String: Any] = [
            "iss": claims.issuer,
            "sub": claims.subject,
            "aud": claims.audience,
            "iat": issued,
            "nbf": issued,
            "exp": issued + claims.lifetime,
            "jti": claims.tokenID,
        ]
        let signingInput = try encodeSegment(header) + "." + encodeSegment(payload)
        // JWS ES256 (RFC 7518 §3.4) is the raw 64-byte R || S, not DER.
        let signature = try signer.signature(for: Data(signingInput.utf8)).rawRepresentation
        return signingInput + "." + Base64URL.encode(signature)
    }

    private static func encodeSegment(_ object: [String: Any]) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        return Base64URL.encode(data)
    }

    /// What `verify` found in a token whose signature checked out.
    public struct Verified: Sendable, Equatable {
        public let kid: String
        public let issuer: String
        public let subject: String
        public let audience: String
        public let issuedAt: Int
        public let notBefore: Int
        public let expiresAt: Int
        public let tokenID: String
    }

    /// Checks a token's shape and its ES256 signature against `keys`, as a
    /// relying party would, without judging its times or claims: that is the
    /// caller's policy. For tests, `csec identity` self-checks and diagnosis.
    public static func verify(_ token: String, keys: [MachineIdentityJWK]) throws -> Verified {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let headerData = Base64URL.decode(String(parts[0])),
              let payloadData = Base64URL.decode(String(parts[1])),
              let signatureData = Base64URL.decode(String(parts[2])),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              let payload = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw MachineIdentityError.invalidToken("not a compact JWS")
        }
        guard header["alg"] as? String == "ES256", let kid = header["kid"] as? String else {
            throw MachineIdentityError.invalidToken("not an ES256 token with a key id")
        }
        guard let jwk = keys.first(where: { $0.kid == kid }) else {
            throw MachineIdentityError.invalidToken("signed by a key not in the key set")
        }
        let signature: P256.Signing.ECDSASignature
        do {
            signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
        } catch {
            throw MachineIdentityError.invalidToken("malformed signature")
        }
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        guard try jwk.publicKey().isValidSignature(signature, for: signingInput) else {
            throw MachineIdentityError.invalidToken("bad signature")
        }
        guard let issuer = payload["iss"] as? String,
              let subject = payload["sub"] as? String,
              let audience = payload["aud"] as? String,
              let issuedAt = payload["iat"] as? Int,
              let notBefore = payload["nbf"] as? Int,
              let expiresAt = payload["exp"] as? Int,
              let tokenID = payload["jti"] as? String else {
            throw MachineIdentityError.invalidToken("missing claims")
        }
        return Verified(
            kid: kid, issuer: issuer, subject: subject, audience: audience,
            issuedAt: issuedAt, notBefore: notBefore, expiresAt: expiresAt, tokenID: tokenID
        )
    }
}

// MARK: - Issuer documents

/// The two public files an issuer serves for a relying party that fetches its
/// keys (AWS IAM, Microsoft Entra): the OpenID discovery document at
/// `<issuer>/.well-known/openid-configuration`, and the key set at
/// `<issuer>/jwks.json`. A provider that takes an uploaded key set (Google
/// Cloud) needs only the second. Whoever can change the published key set can
/// sign as any subject the cloud trusts, so where these files live is the
/// trust root of every role that trusts the issuer.
public enum MachineIdentityIssuer {
    public static let discoveryPath = "/.well-known/openid-configuration"
    public static let keySetPath = "/jwks.json"

    /// An `https` URL with a host, and no query, fragment, credentials or
    /// trailing slash, so `issuer + discoveryPath` is the URL a relying party
    /// derives (OpenID Connect Discovery §4).
    public static func isValid(_ issuer: String) -> Bool {
        guard issuer.utf8.count <= 512, !issuer.hasSuffix("/"),
              let components = URLComponents(string: issuer),
              components.scheme == "https",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              issuer.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) else {
            return false
        }
        return true
    }

    public static func discoveryDocument(issuer: String) throws -> Data {
        guard isValid(issuer) else { throw MachineIdentityError.invalidIssuer }
        let document: [String: Any] = [
            "issuer": issuer,
            "jwks_uri": issuer + keySetPath,
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "claims_supported": ["iss", "sub", "aud", "iat", "nbf", "exp", "jti"],
        ]
        return try JSONSerialization.data(
            withJSONObject: document, options: [.sortedKeys, .withoutEscapingSlashes, .prettyPrinted]
        )
    }

    /// The key set for `keys`, one entry per distinct `kid`, sorted by `kid` so
    /// the same keys always produce the same bytes.
    public static func keySet(_ keys: [MachineIdentityJWK]) throws -> Data {
        var seen = Set<String>()
        let unique = keys.sorted { $0.kid < $1.kid }.filter { seen.insert($0.kid).inserted }
        struct KeySet: Encodable { let keys: [MachineIdentityJWK] }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes, .prettyPrinted]
        return try encoder.encode(KeySet(keys: unique))
    }
}

// MARK: - base64url

enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Strict: the unpadded base64url alphabet only.
    static func decode(_ text: String) -> Data? {
        guard text.utf8.allSatisfy({ byte in
            (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a)
                || (byte >= 0x30 && byte <= 0x39) || byte == 0x2d || byte == 0x5f
        }), text.utf8.count % 4 != 1 else { return nil }
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.utf8.count % 4) % 4)
        return Data(base64Encoded: base64)
    }
}
