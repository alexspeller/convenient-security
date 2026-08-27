import Foundation

/// Pure derivation for `csec protect`: turning a project directory and the files
/// under it into a native store name and per-file keys. Kept side-effect-free so
/// the naming rules are unit-testable without touching the filesystem, the
/// daemon, or the keychain. The importer records the human-readable relative path
/// separately (in the blob's `path` metadata and the sidecar location); the key
/// only has to be valid, stable, and collision-free.
public enum ProtectedFileImportPlanner {
    /// A store name derived from a project directory's absolute path: the
    /// directory's own name for legibility, plus a digest suffix so two projects
    /// that happen to share a base name never share an encryption key. Always a
    /// valid `NativeStoreName` (ASCII alnum/`-`/`_`, alnum-initial, ≤64).
    public static func storeName(forProjectDirectory absolutePath: String) throws -> NativeStoreName {
        let base = (absolutePath as NSString).lastPathComponent
        var legible = String(String(base.unicodeScalars.map {
            isStoreNameByte(UInt8(exactly: $0.value) ?? 0) ? Character($0) : "-"
        }).prefix(40))
        // A store name must start with an alphanumeric; guarantee one.
        if legible.first.map({ !$0.isLetter && !$0.isNumber }) ?? true {
            legible = "p" + legible
        }
        let suffix = String(NativeStoreEnvelope.digest(Data(absolutePath.utf8)).prefix(12))
        return try NativeStoreName("\(legible.prefix(48))-\(suffix)")
    }

    /// A store key derived from a project-relative file path. Invalid runs collapse
    /// to `_`, a leading non-key byte is prefixed, and a digest suffix guarantees
    /// distinct paths never collide onto one key. Always passes `isValidKey`.
    public static func storeKey(forRelativePath relativePath: String) -> String {
        var sanitized = ""
        var lastWasUnderscore = false
        for scalar in relativePath.unicodeScalars {
            let byte = UInt8(exactly: scalar.value) ?? 0
            if isKeyByte(byte), byte != UInt8(ascii: "_") {
                sanitized.unicodeScalars.append(scalar)
                lastWasUnderscore = false
            } else if !lastWasUnderscore {
                sanitized.append("_")
                lastWasUnderscore = true
            }
        }
        if let first = sanitized.first, first.isLetter || first.isNumber || first == "_" {
            // keep
        } else {
            sanitized = "f_" + sanitized
        }
        let suffix = String(NativeStoreEnvelope.digest(Data(relativePath.utf8)).prefix(12))
        // Leave room for the "_" + 12-hex suffix within the 128-byte key bound.
        return "\(sanitized.prefix(100))_\(suffix)"
    }

    private static func isStoreNameByte(_ byte: UInt8) -> Bool {
        isAlphaNumeric(byte) || byte == UInt8(ascii: "-") || byte == UInt8(ascii: "_")
    }

    private static func isKeyByte(_ byte: UInt8) -> Bool {
        isAlphaNumeric(byte)
            || byte == UInt8(ascii: "-")
            || byte == UInt8(ascii: ".")
            || byte == UInt8(ascii: "_")
    }

    private static func isAlphaNumeric(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
    }
}
