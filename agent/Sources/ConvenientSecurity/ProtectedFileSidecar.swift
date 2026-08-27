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
        case .malformed: return "the sidecar is not a well-formed protected-file descriptor"
        case .unsupportedVersion: return "the sidecar uses an unsupported descriptor version"
        case .invalidTargetName: return "the sidecar does not name a valid target file"
        }
    }
}

/// The on-disk `<name>.csec` marker that replaces a plaintext secret file. It is
/// a tiny, strict-JSON *pointer* to a native `csec://<store>/<key>` value — never
/// a value — and it lives in a user-writable, possibly hostile directory, so it
/// is parsed as untrusted metadata: exact key set, fixed magic, bounded size, and
/// a reference that must use the native `csec://` scheme (never `op://` or any
/// remote provider). Materialization resolves the reference against the store's
/// file/blob tier and matches that blob's own recorded path against the sidecar's
/// location (Stage 4), so a planted sidecar cannot redirect another store's value
/// here.
public struct ProtectedFileSidecar: Sendable, Equatable {
    public static let suffix = ".csec"
    public static let magic = "convenient-security/protected-file"
    public static let currentVersion = 1
    public static let maximumBytes = 4096

    public let reference: NativeSecretReference

    public init(reference: NativeSecretReference) {
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
        guard let any = try? JSONSerialization.jsonObject(with: data, options: []),
              let object = any as? [String: Any] else {
            throw ProtectedFileSidecarError.malformed
        }
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
        guard let referenceString = object["reference"] as? String else {
            throw ProtectedFileSidecarError.malformed
        }
        guard let secretRef = try? SecretRef(referenceString),
              let nativeRef = try? NativeSecretReference(secretRef) else {
            throw ProtectedFileSidecarError.malformed
        }
        self.reference = nativeRef
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
