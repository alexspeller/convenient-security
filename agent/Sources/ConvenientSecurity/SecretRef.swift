import Foundation

/// A canonical secret reference: a URI whose scheme selects the provider.
///
/// The scheme is the adapter selector. The shipping daemon registers `op://…`
/// for the 1Password adapter. The core understands only `scheme` and an opaque,
/// provider-specific `path`; parsing the path (for example into
/// vault/item/field) is the adapter's job.
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

    /// Single-line form for an explicitly requested metadata-bearing output
    /// label. It preserves ordinary canonical references while neutralizing
    /// terminal controls, newlines, and bidirectional text controls.
    public var safeInlineURI: String { Self.promptSafe(uri) }

    /// Human-readable display for consent prompts.
    /// For `op://` references this breaks the path into vault / item / field
    /// on separate lines; for other schemes it falls back to the raw URI.
    public var displayString: String {
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
