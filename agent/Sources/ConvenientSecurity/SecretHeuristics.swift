import CSECSecretHeuristics

/// Pure heuristics for deciding whether an environment variable *name* or a
/// candidate *value* looks like credential material. Callers use the verdict
/// to choose defaults (e.g. which vars a picker pre-selects); nothing here
/// logs, stores, or emits the inspected value.
public enum SecretHeuristics {
    public static func nameLooksSecretLike(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        return bytes.withUnsafeBufferPointer {
            cs_secret_name_looks_secret_like($0.baseAddress, $0.count) != 0
        }
    }

    /// The one combined name/value verdict used for env-file candidates. A
    /// value may be omitted when it could not be parsed safely.
    public static func environmentVariableLooksSecretLike(
        name: String,
        value: String?
    ) -> Bool {
        nameLooksSecretLike(name) || value.map(valueLooksSecretLike) == true
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
        return bytes.withUnsafeBufferPointer {
            cs_secret_shannon_entropy_bits_per_byte($0.baseAddress, $0.count)
        }
    }

    /// Whether a value looks like a key/secret independent of its name:
    /// a credential-bearing URL, well-known token prefix, PEM key material, or
    /// a long high-entropy machine-generated string. Hierarchical URLs without
    /// a userinfo password are ordinary configuration, regardless of their
    /// punctuation/entropy. Deliberately conservative for short or
    /// dictionary-like values — callers typically combine this with the name
    /// heuristic, so misses are recoverable and false alarms are cheap.
    public static func valueLooksSecretLike(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return bytes.withUnsafeBufferPointer {
            cs_secret_value_looks_secret_like($0.baseAddress, $0.count) != 0
        }
    }
}
