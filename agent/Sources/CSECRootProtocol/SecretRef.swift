import Foundation

/// A canonical secret reference: a URI whose scheme selects the provider.
///
/// The scheme is the adapter selector. The shipping daemon may register the
/// 1Password `op://…` adapter, the native `csec://…` provider, or both. The core
/// understands only `scheme` and an opaque, provider-specific `path`; parsing
/// that path is the provider's job.
public struct SecretRef: Hashable, Sendable, CustomStringConvertible {
    /// The full canonical URI, e.g. `op://vault/item/field`. This is the identity.
    public let uri: String
    /// The URI scheme, lowercased, e.g. `op`.
    public let scheme: String
    /// Everything after `://`, opaque to the core, e.g. `vault/item/field`.
    public let path: String

    public enum ParseError: Error, Equatable {
        case missingSchemeSeparator
        case emptyScheme
        case emptyPath
        case invalidScheme(String)
    }

    public init(_ uri: String) throws {
        guard let separator = uri.range(of: "://") else {
            throw ParseError.missingSchemeSeparator
        }
        let scheme = String(uri[uri.startIndex..<separator.lowerBound])
        let path = String(uri[separator.upperBound...])
        guard !scheme.isEmpty else { throw ParseError.emptyScheme }
        guard !path.isEmpty else { throw ParseError.emptyPath }

        // Scheme grammar (RFC 3986): ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
        let first = scheme.unicodeScalars.first!
        guard CharacterSet.letters.contains(first) else {
            throw ParseError.invalidScheme(scheme)
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "+-."))
        guard scheme.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw ParseError.invalidScheme(scheme)
        }

        self.uri = uri
        self.scheme = scheme.lowercased()
        self.path = path
    }

    public var description: String { uri }

    /// Whether this reference asks for a current one-time code (TOTP) rather
    /// than a stored value: its path ends in a query whose `attribute` is
    /// `otp` or `totp`, 1Password's own spelling, on any scheme. A code is
    /// never cached, never covered by a grant and never released by auto
    /// mode, so the match is deliberately wider than any provider's grammar:
    /// key and value are compared case-insensitively after percent-decoding,
    /// and any parameter of the query counts. 1Password's parser accepts only
    /// the lowercase single-parameter forms, so no spelling it resolves to a
    /// code can read here as an ordinary secret.
    public var isOneTimeCode: Bool { Self.oneTimeCodeQuery(in: path) != nil }

    /// The reference to the code's seed: this one with its one-time-code query
    /// removed. A provider that cannot make codes itself resolves this, and
    /// csecd works the code out from the stored `otpauth://` value. Nil when
    /// this is not a one-time-code reference.
    public var oneTimeCodeSeedReference: SecretRef? {
        guard let query = Self.oneTimeCodeQuery(in: path) else { return nil }
        let seedURI = scheme + "://" + String(path[..<query.lowerBound])
        return try? SecretRef(seedURI)
    }

    /// The range of the query, `?` included, when it asks for a one-time code.
    private static func oneTimeCodeQuery(in path: String) -> Range<String.Index>? {
        guard let mark = path.lastIndex(of: "?") else { return nil }
        let query = path[path.index(after: mark)...]
        let asksForCode = query.split(separator: "&", omittingEmptySubsequences: true).contains { parameter in
            guard let equals = parameter.firstIndex(of: "=") else { return false }
            let key = normalizedQueryPart(parameter[..<equals])
            let value = normalizedQueryPart(parameter[parameter.index(after: equals)...])
            return key == "attribute" && (value == "otp" || value == "totp")
        }
        return asksForCode ? mark..<path.endIndex : nil
    }

    private static func normalizedQueryPart(_ part: Substring) -> String {
        let decoded = String(part).removingPercentEncoding ?? String(part)
        return decoded.trimmingCharacters(in: .whitespaces).lowercased()
    }

    /// Single-line form for an explicitly requested metadata-bearing output
    /// label. It preserves ordinary canonical references while neutralizing
    /// terminal controls, newlines, and bidirectional text controls.
    public var safeInlineURI: String { Self.promptSafe(uri) }

    /// Human-readable display for consent prompts.
    /// For known providers this breaks the path into labeled components; for
    /// other schemes it falls back to the raw URI.
    public var displayString: String {
        if scheme == "csec", let slash = path.firstIndex(of: "/") {
            let store = Self.promptSafe(String(path[..<slash]))
            let key = Self.promptSafe(String(path[path.index(after: slash)...]))
            if key == "*" {
                return "native store: \(store)\nkeys: all (edit access)"
            }
            return "native store: \(store)\nkey: \(key)"
        }
        guard scheme == "op" else { return Self.promptSafe(uri) }
        // op://vault/item/field
        if let range = path.range(of: "/") {
            let vault = Self.promptSafe(String(path[..<range.lowerBound]))
            let rest = String(path[range.upperBound...])
            if let slash2 = rest.range(of: "/") {
                let item = Self.promptSafe(String(rest[..<slash2.lowerBound]))
                let field = Self.promptSafe(String(rest[slash2.upperBound...]))
                return "vault: \(vault)\nitem: \(item)\nfield: \(field)"
            }
            // op://vault/item (no field)
            return "vault: \(vault)\nitem: \(Self.promptSafe(rest))"
        }
        // op://b4bqchaderdmfawqcznscaozeq (UUID-only, no slashes)
        return "item: \(Self.promptSafe(path))"
    }

    // Intentionally duplicates `ReviewDisplay.sanitized` (default mode). This is
    // the lowest module in the stack and cannot import ConvenientSecurity, so the
    // ~12-line copy is the correct layering tradeoff rather than a shared dep.
    private static func promptSafe(_ value: String) -> String {
        let bidiControls: Set<UInt32> = [
            0x061c, 0x200e, 0x200f,
            0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
            0x2066, 0x2067, 0x2068, 0x2069,
        ]
        return value.unicodeScalars.map { scalar in
            if CharacterSet.controlCharacters.contains(scalar)
                || CharacterSet.newlines.contains(scalar)
                || bidiControls.contains(scalar.value) {
                return "�"
            }
            return String(scalar)
        }.joined()
    }
}
