import Foundation

/// How default-store resolution answers "does a store with this name already
/// exist, and which project root claimed it?". The production implementation
/// reads the store directories (`NativeStoreDirectoryIndex`); tests substitute
/// a fixed map. `origin(forStore:)` returns the *unverified* cleartext origin —
/// good enough to propose a default the user reviews, while the daemon
/// re-verifies the marker under the store key before any store mutation.
public protocol NativeStoreNameIndexing {
    func storeExists(_ name: String) -> Bool
    func origin(forStore name: String) -> String?
}

public enum StoreNameResolutionError: Error, LocalizedError, Equatable {
    /// Both the clean legible name and its deterministic suffixed variant are
    /// claimed by other project roots. Practically unreachable (requires a
    /// 32-bit digest collision on top of a name collision); never resolved
    /// silently.
    case unresolvableCollision(cleanName: String, suffixedName: String)

    public var errorDescription: String? {
        switch self {
        case let .unresolvableCollision(cleanName, suffixedName):
            return "store names \(cleanName) and \(suffixedName) are both claimed by "
                + "other project directories; pass --store to choose a name explicitly"
        }
    }
}

/// Pure derivation for `csec protect`: turning a project directory and the files
/// under it into a native store name and per-file keys. Kept side-effect-free so
/// the naming rules are unit-testable without touching the filesystem, the
/// daemon, or the keychain. The importer records the human-readable relative path
/// separately (in the blob's `path` metadata and the sidecar location); the key
/// only has to be valid, stable, and collision-free.
public enum ProtectedFileImportPlanner {
    /// The legible part of a default store name is capped below the 64-byte
    /// `NativeStoreName` bound so a `-8hex` conflict suffix always fits.
    public static let maximumLegibleStoreNameBytes = 55

    /// The legible default store name for a project directory: its home-relative
    /// path with `/` and every byte outside `[A-Za-z0-9_-]` mapped to `-`, runs
    /// collapsed, and an alphanumeric initial guaranteed. `~/work/WebApp`
    /// becomes `work-WebApp`. Purely lexical — no filesystem access; the
    /// caller passes `homeDirectory` explicitly. The result is *not* yet a
    /// unique store name: `resolveDefaultStore` adds a digest suffix only when a
    /// different project has actually claimed the same name.
    public static func legibleStoreName(
        forProjectDirectory absolutePath: String,
        homeDirectory: String
    ) -> String {
        var relative = absolutePath
        var home = homeDirectory
        while home.count > 1, home.hasSuffix("/") { home.removeLast() }
        if !home.isEmpty, home != "/" {
            if absolutePath == home {
                relative = ""
            } else if absolutePath.hasPrefix(home + "/") {
                relative = String(absolutePath.dropFirst(home.count + 1))
            }
        }
        while relative.hasPrefix("/") { relative.removeFirst() }

        var legible = ""
        var lastWasDash = false
        for scalar in relative.unicodeScalars {
            let byte = UInt8(exactly: scalar.value)
            if let byte, isStoreNameByte(byte), byte != UInt8(ascii: "-") {
                legible.unicodeScalars.append(scalar)
                lastWasDash = false
            } else if !lastWasDash {
                legible.append("-")
                lastWasDash = true
            }
        }
        while legible.hasPrefix("-") { legible.removeFirst() }
        while legible.hasSuffix("-") { legible.removeLast() }
        if legible.isEmpty { legible = "home" }
        if legible.first.map({ !$0.isLetter && !$0.isNumber }) ?? true {
            legible = "p" + legible
        }
        return legible
    }

    /// The deterministic fallback name a project resolves to when its clean
    /// legible name is claimed by a different root: the (byte-capped) legible
    /// part plus an 8-hex digest of the absolute project directory, so the same
    /// colliding project always lands on the same suffixed name.
    public static func conflictStoreName(
        forProjectDirectory absolutePath: String,
        homeDirectory: String
    ) throws -> NativeStoreName {
        let legible = cappedLegible(legibleStoreName(
            forProjectDirectory: absolutePath, homeDirectory: homeDirectory))
        let suffix = String(NativeStoreEnvelope.digest(Data(absolutePath.utf8)).prefix(8))
        return try NativeStoreName("\(legible)-\(suffix)")
    }

    /// The default store for a project directory, collision-checked against the
    /// stores that already exist. Read-only — origin stamping happens in the
    /// daemon when the store is actually created or adopted under Touch ID.
    ///
    /// - No store under the clean name → the clean name.
    /// - Store exists and its origin is this root → reuse (append to it).
    /// - Store exists with no origin marker (legacy) → adopt it; the next edit
    ///   stamps this root as its origin.
    /// - Store exists under a *different* root → the deterministic suffixed
    ///   name (unless that too is claimed by a third root, which is an error).
    /// - A legible part over the byte cap always takes the suffix: silent
    ///   byte-truncation is itself a uniqueness hazard.
    public static func resolveDefaultStore(
        projectRoot: String,
        homeDirectory: String,
        index: NativeStoreNameIndexing
    ) throws -> NativeStoreName {
        let legible = legibleStoreName(
            forProjectDirectory: projectRoot, homeDirectory: homeDirectory)
        let suffixed = try conflictStoreName(
            forProjectDirectory: projectRoot, homeDirectory: homeDirectory)
        guard legible.utf8.count <= maximumLegibleStoreNameBytes else {
            return suffixed
        }
        if !index.storeExists(legible) { return try NativeStoreName(legible) }
        let claimedBy = index.origin(forStore: legible)
        if claimedBy == nil || claimedBy == projectRoot {
            return try NativeStoreName(legible)
        }
        if index.storeExists(suffixed.value),
           let suffixedClaim = index.origin(forStore: suffixed.value),
           suffixedClaim != projectRoot {
            throw StoreNameResolutionError.unresolvableCollision(
                cleanName: legible, suffixedName: suffixed.value)
        }
        return suffixed
    }

    private static func cappedLegible(_ legible: String) -> String {
        // The legible part is ASCII by construction, so a character prefix is a
        // byte prefix; trim any dash the cut may have exposed.
        var capped = String(legible.prefix(maximumLegibleStoreNameBytes))
        while capped.hasSuffix("-") { capped.removeLast() }
        if capped.isEmpty { capped = "p" }
        return capped
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
