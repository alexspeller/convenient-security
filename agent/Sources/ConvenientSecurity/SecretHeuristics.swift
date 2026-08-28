import Foundation

/// Pure heuristics for deciding whether an environment variable *name* or a
/// candidate *value* looks like credential material. Callers use the verdict
/// to choose defaults (e.g. which vars a picker pre-selects); nothing here
/// logs, stores, or emits the inspected value.
public enum SecretHeuristics {
    public static func nameLooksSecretLike(_ name: String) -> Bool {
        let upper = name.uppercased()
        let markers = [
            "TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "PRIVATE_KEY",
            "ACCESS_KEY", "CREDENTIAL", "AUTH", "SIGNING_KEY", "ENCRYPTION_KEY",
            "COOKIE", "WEBHOOK", "DATABASE_URL", "REDIS_URL", "DSN",
        ]
        return markers.contains { upper.contains($0) }
    }

    public static func isEnvironmentName(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count <= 128 else { return false }
        guard (bytes[0] >= 65 && bytes[0] <= 90)
                || (bytes[0] >= 97 && bytes[0] <= 122)
                || bytes[0] == 95 else { return false }
        return bytes.allSatisfy {
            ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                || ($0 >= 48 && $0 <= 57) || $0 == 95
        }
    }

    /// Shannon entropy of the UTF-8 byte distribution, in bits per byte.
    /// A short string cannot exceed log2(length) even if every byte is
    /// distinct, so thresholds only make sense alongside a length floor.
    public static func shannonEntropyBitsPerChar(_ value: String) -> Double {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty else { return 0 }
        var counts = [Int](repeating: 0, count: 256)
        for byte in bytes { counts[Int(byte)] += 1 }
        let total = Double(bytes.count)
        var entropy = 0.0
        for count in counts where count > 0 {
            let probability = Double(count) / total
            entropy -= probability * log2(probability)
        }
        return entropy
    }

    /// Whether a value looks like a key/secret independent of its name:
    /// a well-known token prefix, PEM key material, or a long high-entropy
    /// machine-generated string. Deliberately conservative for short or
    /// dictionary-like values — callers typically OR this with the name
    /// heuristic, so misses are recoverable and false alarms are cheap.
    public static func valueLooksSecretLike(_ value: String) -> Bool {
        if value.contains("-----BEGIN"), value.contains("PRIVATE KEY") { return true }
        guard value.utf8.count >= 8 else { return false }
        if hasKnownSecretPrefix(value) { return true }

        let bytes = Array(value.utf8)
        guard bytes.count >= 20 else { return false }
        guard !bytes.contains(where: { $0 == 32 || $0 == 9 }) else { return false }
        let tokenByteCount = bytes.filter(isTokenByte).count
        guard Double(tokenByteCount) >= 0.9 * Double(bytes.count) else { return false }

        if bytes.count >= 32, bytes.allSatisfy(isHexByte) { return true }

        let hasLetter = bytes.contains {
            ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
        }
        let hasDigit = bytes.contains { $0 >= 48 && $0 <= 57 }
        guard hasLetter, hasDigit else { return false }

        if bytes.count >= 24, bytes.allSatisfy(isBase64Byte) { return true }
        return shannonEntropyBitsPerChar(value) >= 3.5
    }

    private static func hasKnownSecretPrefix(_ value: String) -> Bool {
        let prefixes = [
            "sk-", "sk_live_", "sk_test_", "rk_live_",
            "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
            "glpat-", "npm_", "dop_v1_", "shpat_", "shpss_",
            "AKIA", "ASIA", "AIza", "eyJ",
        ]
        if prefixes.contains(where: { value.hasPrefix($0) }) { return true }
        // Slack token families: xoxb-, xoxp-, xoxa-, xoxs-, xoxr-, xoxe- …
        let bytes = Array(value.utf8)
        if bytes.count >= 5, bytes[0] == 120, bytes[1] == 111, bytes[2] == 120,
           bytes[4] == 45 {
            return true
        }
        return false
    }

    private static func isTokenByte(_ byte: UInt8) -> Bool {
        (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
            || (byte >= 48 && byte <= 57)
            || byte == 43 || byte == 47 || byte == 61 // + / =
            || byte == 95 || byte == 45 || byte == 46 // _ - .
            || byte == 58 // :
    }

    private static func isHexByte(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
            || (byte >= 65 && byte <= 70)
    }

    private static func isBase64Byte(_ byte: UInt8) -> Bool {
        (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
            || (byte >= 48 && byte <= 57)
            || byte == 43 || byte == 47 || byte == 61 // + / =
            || byte == 95 || byte == 45 // _ - (url-safe alphabet)
    }
}
