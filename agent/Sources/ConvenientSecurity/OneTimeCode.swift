import CryptoKit
import Foundation

/// One-time codes (TOTP, RFC 6238) and the seeds they are made from.
///
/// A reference ending in `?attribute=otp` (`SecretRef.isOneTimeCode`) asks for
/// the current code. A provider that makes codes itself (1Password) returns
/// one; for any other, csecd resolves the seed reference and works the code
/// out here, so the seed stays inside csecd. A seed is a standing second
/// factor, so csecd never releases one: `isSeed` is checked on every value an
/// ordinary reference resolves to.
public enum OneTimeCode {
    /// Whether `value` is a one-time-code seed: an `otpauth://` URI, or an
    /// authenticator export (`otpauth-migration://`, which carries many).
    /// Leading whitespace is ignored and the scheme compared without case, as
    /// an authenticator app would read it.
    public static func isSeed(_ value: Data) -> Bool {
        let prefixes = ["otpauth://", "otpauth-migration://"]
        let start = value.prefix(64).drop { $0 == 0x20 || $0 == 0x09 || $0 == 0x0a || $0 == 0x0d }
        guard let head = String(bytes: start.prefix(24), encoding: .ascii)?.lowercased() else { return false }
        return prefixes.contains { head.hasPrefix($0) }
    }

    /// The code `seed` (an `otpauth://totp/…` URI) gives at `date`, as ASCII
    /// digits. Only time-based seeds qualify: a counter-based (`hotp`) one
    /// needs a counter csecd would have to keep in step with the service.
    public static func code(fromSeed seed: Data, at date: Date = Date()) throws -> Data {
        let parameters = try TOTPParameters(seed: seed)
        return Data(parameters.code(at: date).utf8)
    }
}

/// Why csecd would not release a value for a one-time-code reference, or for
/// an ordinary reference whose value is a seed. Every reason is csec's own,
/// value-free sentence.
public enum OneTimeCodeError: Error, Equatable, ProviderDiagnosableError {
    /// An ordinary reference resolved to a seed.
    case seedRefused
    /// A one-time-code reference's seed is not an `otpauth://totp` URI csecd
    /// can work a code out from.
    case unusableSeed(String)

    public var boundedReason: String {
        switch self {
        case .seedRefused:
            return "this value is a 2FA seed, which csec never releases; "
                + "add ?attribute=otp to the reference to get a one-time code from it"
        case let .unusableSeed(why):
            return "csec could not work out a one-time code: \(why)"
        }
    }
}

/// The parts of an `otpauth://totp/LABEL?secret=…` URI a code needs, with the
/// defaults authenticator apps use: SHA-1, six digits, thirty seconds.
struct TOTPParameters: Equatable {
    enum Algorithm: Equatable {
        case sha1, sha256, sha512
    }

    let key: Data
    let algorithm: Algorithm
    let digits: Int
    let period: Int

    init(seed: Data) throws {
        guard let text = String(data: seed, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              let components = URLComponents(string: text),
              components.scheme?.lowercased() == "otpauth" else {
            throw OneTimeCodeError.unusableSeed("the stored value is not an otpauth:// URI")
        }
        guard components.host?.lowercased() == "totp" else {
            throw OneTimeCodeError.unusableSeed("only time-based (totp) seeds are supported")
        }
        var query: [String: String] = [:]
        for item in components.queryItems ?? [] {
            let name = item.name.lowercased()
            // A repeated parameter is ambiguous; refuse it rather than pick one.
            guard query[name] == nil else {
                throw OneTimeCodeError.unusableSeed("the otpauth:// URI repeats \(Self.parameterName(name))")
            }
            query[name] = item.value ?? ""
        }
        guard let secret = query["secret"], let key = Base32.decode(secret), !key.isEmpty else {
            throw OneTimeCodeError.unusableSeed("the otpauth:// URI has no valid base32 secret")
        }
        switch query["algorithm"]?.uppercased() ?? "SHA1" {
        case "SHA1": algorithm = .sha1
        case "SHA256": algorithm = .sha256
        case "SHA512": algorithm = .sha512
        default: throw OneTimeCodeError.unusableSeed("the otpauth:// URI names an unsupported algorithm")
        }
        guard let digits = Int(query["digits"] ?? "6"), (6...8).contains(digits) else {
            throw OneTimeCodeError.unusableSeed("the otpauth:// URI asks for other than 6 to 8 digits")
        }
        guard let period = Int(query["period"] ?? "30"), (1...3_600).contains(period) else {
            throw OneTimeCodeError.unusableSeed("the otpauth:// URI has an unusable period")
        }
        self.key = key
        self.digits = digits
        self.period = period
    }

    /// RFC 6238: HOTP (RFC 4226) over the count of whole periods since the
    /// Unix epoch.
    func code(at date: Date) -> String {
        let counter = UInt64(max(0, date.timeIntervalSince1970) / Double(period))
        var bigEndian = counter.bigEndian
        let message = Data(bytes: &bigEndian, count: MemoryLayout<UInt64>.size)
        let symmetricKey = SymmetricKey(data: key)
        let mac: [UInt8]
        switch algorithm {
        case .sha1: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetricKey))
        case .sha256: mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey))
        case .sha512: mac = Array(HMAC<SHA512>.authenticationCode(for: message, using: symmetricKey))
        }
        let offset = Int(mac[mac.count - 1] & 0x0f)
        let truncated = (UInt32(mac[offset] & 0x7f) << 24)
            | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8)
            | UInt32(mac[offset + 3])
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        let number = String(truncated % modulus)
        return String(repeating: "0", count: digits - number.count) + number
    }

    /// A parameter name fit to repeat in a reason: only the ones csecd reads.
    private static func parameterName(_ name: String) -> String {
        ["secret", "algorithm", "digits", "period", "issuer"].contains(name) ? name : "a parameter"
    }
}

/// RFC 4648 base32, as authenticator seeds spell it: any case, optional
/// padding, and the spaces or hyphens some services group the secret with.
enum Base32 {
    static func decode(_ text: String) -> Data? {
        var bits: UInt64 = 0
        var bitCount = 0
        var bytes: [UInt8] = []
        var padding = false
        for scalar in text.unicodeScalars {
            switch scalar {
            case " ", "-":
                continue
            case "=":
                padding = true
                continue
            default:
                break
            }
            guard !padding else { return nil }
            let value: UInt64
            switch scalar.value {
            case 65...90: value = UInt64(scalar.value - 65)
            case 97...122: value = UInt64(scalar.value - 97)
            case 50...55: value = UInt64(scalar.value - 50 + 26)
            default: return nil
            }
            bits = (bits << 5) | value
            bitCount += 5
            if bitCount >= 8 {
                bitCount -= 8
                bytes.append(UInt8((bits >> UInt64(bitCount)) & 0xff))
                bits &= (1 << UInt64(bitCount)) - 1
            }
        }
        return Data(bytes)
    }
}
