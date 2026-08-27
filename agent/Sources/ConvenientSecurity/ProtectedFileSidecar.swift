import Foundation

public enum ProtectedFileSidecarError: Error, Equatable, LocalizedError {
    case notASidecar
    case tooLarge
    case malformed
    case unsupportedVersion
    case invalidTargetName

    public var errorDescription: String? {
        switch self {
        case .notASidecar: return "not a csec protected-file sidecar"
        case .tooLarge: return "the sidecar is larger than a protected-file descriptor may be"
        case .malformed:
            return "not a valid sidecar: expected a secret reference (e.g. op://… or "
                + "csec://…), optionally quoted, or the JSON that `csec protect` writes"
        case .unsupportedVersion: return "the sidecar uses an unsupported descriptor version"
        case .invalidTargetName: return "the sidecar does not name a valid target file"
        }
    }
}

/// The on-disk `<name>.csec` marker that replaces a plaintext secret file: a
/// tiny *pointer* to a secret reference — never a value. It is **source-neutral**,
/// naming any secret reference (`op://…`, `csec://…`, …) exactly as every other
/// csec surface does. Two on-disk forms are accepted, both parsed as untrusted
/// metadata under a bounded size:
///   1. the strict JSON envelope `csec protect` writes (fixed magic, version, and
///      an exact key set), and
///   2. a bare reference — a single secret URL on its own, tolerant of surrounding
///      whitespace and one layer of quotes (the shape a `csec get` / 1Password
///      value naturally has), so a hand-written sidecar just works.
/// A native `csec://` reference additionally gets the planted-sidecar defense:
/// materialization matches the blob's own recorded protect-path against the
/// sidecar's location (`Agent.protectedFilePathsAreBound`), so a moved or planted
/// native sidecar fails closed. A non-native reference has no such recorded path,
/// so — like `op://` everywhere else in csec — it relies on the Touch ID review
/// that shows the reference before any value is released.
public struct ProtectedFileSidecar: Sendable, Equatable {
    public static let suffix = ".csec"
    public static let magic = "convenient-security/protected-file"
    public static let currentVersion = 1
    public static let maximumBytes = 4096

    public let reference: SecretRef

    public init(reference: SecretRef) {
        self.reference = reference
    }

    public func encoded() throws -> Data {
        let object: [String: Any] = [
            "csec": Self.magic,
            "version": Self.currentVersion,
            "reference": reference.uri,
        ]
        let data = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .prettyPrinted]
        )
        return data + Data("\n".utf8)
    }

    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes else { throw ProtectedFileSidecarError.tooLarge }
        // Prefer the strict JSON envelope (what `csec protect` writes). Only a JSON
        // object is treated as the envelope; a bare quoted string is a fragment
        // JSONSerialization rejects by default, so it falls through to the bare form.
        if let any = try? JSONSerialization.jsonObject(with: data, options: []),
           let object = any as? [String: Any] {
            self.reference = try Self.reference(fromEnvelope: object)
            return
        }
        // Fall back to a bare reference: a single secret URL on its own line,
        // tolerant of surrounding whitespace and one layer of quotes.
        if let text = String(data: data, encoding: .utf8),
           let reference = try? SecretRef(Self.unwrapBareReference(text)) {
            self.reference = reference
            return
        }
        throw ProtectedFileSidecarError.malformed
    }

    private static func reference(fromEnvelope object: [String: Any]) throws -> SecretRef {
        guard Set(object.keys) == ["csec", "version", "reference"] else {
            throw ProtectedFileSidecarError.malformed
        }
        guard let magic = object["csec"] as? String, magic == Self.magic else {
            throw ProtectedFileSidecarError.malformed
        }
        // Reject a Bool masquerading as a number (NSNumber bridging is lenient).
        guard let versionNumber = object["version"] as? NSNumber,
              !(versionNumber === kCFBooleanTrue) && !(versionNumber === kCFBooleanFalse),
              versionNumber.intValue == Self.currentVersion,
              Double(versionNumber.intValue) == versionNumber.doubleValue else {
            throw ProtectedFileSidecarError.unsupportedVersion
        }
        guard let referenceString = object["reference"] as? String,
              let secretRef = try? SecretRef(referenceString) else {
            throw ProtectedFileSidecarError.malformed
        }
        return secretRef
    }

    /// Trim surrounding whitespace and a single layer of matching quotes so a
    /// hand-written or `csec get`-piped reference (which 1Password prints quoted)
    /// parses. Inner content is never altered, so a reference's own path — which
    /// may legitimately contain spaces — is preserved.
    static func unwrapBareReference(_ text: String) -> String {
        var trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        for quote in ["\"", "'"] where trimmed.count >= 2
            && trimmed.hasPrefix(quote) && trimmed.hasSuffix(quote) {
            trimmed = String(trimmed.dropFirst().dropLast())
                .trimmingCharacters(in: .whitespacesAndNewlines)
            break
        }
        return trimmed
    }

    /// The base name of the sidecar file for a given target file name.
    public static func sidecarName(forTargetNamed target: String) -> String {
        target + suffix
    }

    /// The target file a sidecar materializes, derived from the sidecar's own
    /// base name. `.envrc.csec -> .envrc`, `config.json.csec -> config.json`.
    /// Returns nil for names that are not sidecars or would not name a real file.
    public static func targetName(forSidecarNamed name: String) throws -> String {
        guard name.hasSuffix(suffix), name.utf8.count > suffix.utf8.count else {
            throw ProtectedFileSidecarError.notASidecar
        }
        let target = String(name.dropLast(suffix.count))
        guard !target.isEmpty,
              target != ".",
              target != "..",
              !target.contains("/"),
              !target.utf8.contains(0) else {
            throw ProtectedFileSidecarError.invalidTargetName
        }
        return target
    }
}
