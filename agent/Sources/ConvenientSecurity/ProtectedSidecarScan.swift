import Foundation
import CSECRootProtocol
#if canImport(Darwin)
import Darwin
#endif

/// One protected file discovered by scanning a project subtree for `*.csec`
/// sidecars. `targetRelativePath` is where the plaintext used to live — and where
/// the value must reappear for an unmodified tool — while `sidecarRelativePath`
/// is the `*.csec` pointer that replaced it. Both are project-relative.
public struct DiscoveredProtectedFile: Equatable, Sendable {
    public let targetRelativePath: String
    public let sidecarRelativePath: String
    public let reference: SecretRef

    public init(
        targetRelativePath: String,
        sidecarRelativePath: String,
        reference: SecretRef
    ) {
        self.targetRelativePath = targetRelativePath
        self.sidecarRelativePath = sidecarRelativePath
        self.reference = reference
    }
}

/// A file that looks like a sidecar (its name ends in `.csec`) but could not be
/// used, surfaced so `csec exec` can warn about it rather than silently skipping —
/// a broken sidecar otherwise looks exactly like "the secret just wasn't there".
/// Value-free: it carries the project-relative path and a human-readable reason.
public struct ProtectedSidecarIssue: Equatable, Sendable {
    public let sidecarRelativePath: String
    public let reason: String

    public init(sidecarRelativePath: String, reason: String) {
        self.sidecarRelativePath = sidecarRelativePath
        self.reason = reason
    }
}

/// The outcome of a scan: the usable sidecars plus any `.csec` files that could
/// not be parsed into one. Overflow past the per-launch bound is still a thrown
/// error, not an issue, because it aborts the launch rather than degrading it.
public struct ProtectedSidecarScanResult: Equatable, Sendable {
    public let discoveries: [DiscoveredProtectedFile]
    public let issues: [ProtectedSidecarIssue]

    public init(discoveries: [DiscoveredProtectedFile], issues: [ProtectedSidecarIssue]) {
        self.discoveries = discoveries
        self.issues = issues
    }
}

public enum ProtectedSidecarScanError: Error, LocalizedError, Equatable {
    case tooManySidecars(limit: Int)

    public var errorDescription: String? {
        switch self {
        case let .tooManySidecars(limit):
            return "the project has more than \(limit) protected-file sidecars, the per-launch maximum"
        }
    }
}

/// Filename-agnostic discovery of `*.csec` sidecars beneath a project directory.
///
/// Deliberately filesystem-only — no daemon, no resolution — so the walk and its
/// bounds are unit-testable against a real temporary tree. A sidecar lives in a
/// user-writable, possibly hostile directory, so the scan treats every discovery
/// as untrusted metadata: it follows no symlink (neither directories nor the
/// sidecars themselves), bounds the read of each descriptor, and parses via the
/// strict `ProtectedFileSidecar` validator. Overflow past `maximumSidecars` is a
/// hard error, never a silent truncation, so a project that outgrows a single
/// launch fails loudly instead of materializing an arbitrary subset.
public enum ProtectedSidecarScanner {
    /// Matches the onboarding dotenv discovery so both walks agree on how deep a
    /// project is and which build/vendor subtrees are never secret sources.
    public static let maximumDepth = 4
    public static let maximumVisitedEntries = 20_000
    public static var maximumSidecars: Int { ProtectedLaunchPlan.maximumFiles }

    static let excludedDirectories: Set<String> = [
        ".git", ".build", ".swiftpm", "node_modules", "vendor", "Pods",
        "DerivedData", "build", "dist", "coverage", "tmp",
    ]

    public static func scan(projectDirectory: String) throws -> ProtectedSidecarScanResult {
        let root = URL(fileURLWithPath: projectDirectory, isDirectory: true)
        let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey]
        var discoveries: [DiscoveredProtectedFile] = []
        var issues: [ProtectedSidecarIssue] = []
        var visited = 0
        // Carry each directory's path relative to the root through the walk rather
        // than reconstructing it from absolute paths afterward: on macOS a temp
        // dir resolves through the /var -> /private/var firmlink, so comparing an
        // entry's standardized absolute path against the root's would spuriously
        // fail and drop every sidecar.
        var pending: [(url: URL, depth: Int, relativePath: String)] = [(root, 0, "")]
        var next = 0

        scan: while next < pending.count {
            let directory = pending[next]
            next += 1
            let entries: [URL]
            do {
                entries = try FileManager.default.contentsOfDirectory(
                    at: directory.url,
                    includingPropertiesForKeys: keys,
                    options: []
                ).sorted { $0.lastPathComponent < $1.lastPathComponent }
            } catch {
                // A directory we cannot list contributes no sidecars; a hostile or
                // transient subtree must not abort the whole launch.
                continue
            }
            for url in entries {
                visited += 1
                if visited > Self.maximumVisitedEntries { break scan }
                let name = url.lastPathComponent
                let relative = directory.relativePath.isEmpty
                    ? name
                    : directory.relativePath + "/" + name
                let values = try? url.resourceValues(forKeys: Set(keys))
                if values?.isDirectory == true {
                    if values?.isSymbolicLink != true,
                       !Self.excludedDirectories.contains(name),
                       directory.depth < Self.maximumDepth {
                        pending.append((url, directory.depth + 1, relative))
                    }
                    continue
                }
                // Only names that look like a sidecar are considered; anything else
                // is unrelated and never warned about.
                guard name.hasSuffix(ProtectedFileSidecar.suffix) else { continue }

                // From here the entry claims to be a sidecar, so every failure is a
                // reported issue (`csec exec` warns) rather than a silent skip — a
                // broken sidecar otherwise looks identical to "the file just wasn't
                // there". A `.csec` symlink or special file is refused, not followed.
                guard values?.isRegularFile == true, values?.isSymbolicLink != true else {
                    issues.append(ProtectedSidecarIssue(
                        sidecarRelativePath: relative,
                        reason: "not a regular file (a sidecar must be a plain file, "
                            + "not a symlink or special file)"
                    ))
                    continue
                }
                let targetName: String
                do {
                    targetName = try ProtectedFileSidecar.targetName(forSidecarNamed: name)
                } catch {
                    issues.append(ProtectedSidecarIssue(
                        sidecarRelativePath: relative,
                        reason: (error as? LocalizedError)?.errorDescription
                            ?? "does not name a target file"
                    ))
                    continue
                }
                guard let bytes = Self.readBounded(
                    url: url,
                    maximum: ProtectedFileSidecar.maximumBytes
                ) else {
                    issues.append(ProtectedSidecarIssue(
                        sidecarRelativePath: relative,
                        reason: "could not be read, or is larger than a sidecar may be "
                            + "(max \(ProtectedFileSidecar.maximumBytes) bytes)"
                    ))
                    continue
                }
                let sidecar: ProtectedFileSidecar
                do {
                    sidecar = try ProtectedFileSidecar(data: bytes)
                } catch {
                    issues.append(ProtectedSidecarIssue(
                        sidecarRelativePath: relative,
                        reason: (error as? LocalizedError)?.errorDescription
                            ?? "is not a valid protected-file sidecar"
                    ))
                    continue
                }

                let targetRelative = directory.relativePath.isEmpty
                    ? targetName
                    : directory.relativePath + "/" + targetName
                discoveries.append(DiscoveredProtectedFile(
                    targetRelativePath: targetRelative,
                    sidecarRelativePath: relative,
                    reference: sidecar.reference
                ))
                if discoveries.count > Self.maximumSidecars {
                    throw ProtectedSidecarScanError.tooManySidecars(limit: Self.maximumSidecars)
                }
            }
        }
        return ProtectedSidecarScanResult(
            discoveries: discoveries.sorted { $0.targetRelativePath < $1.targetRelativePath },
            issues: issues.sorted { $0.sidecarRelativePath < $1.sidecarRelativePath }
        )
    }

    /// Read at most `maximum` bytes from a regular file without following a
    /// symlink. Returns nil on any error or if the descriptor is not a regular
    /// file, so a FIFO or device that ends in `.csec` cannot block or mislead.
    private static func readBounded(url: URL, maximum: Int) -> Data? {
        let fd = url.path.withCString { open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG else { return nil }
        var buffer = [UInt8](repeating: 0, count: maximum + 1)
        var total = 0
        while total <= maximum {
            let count = buffer.withUnsafeMutableBytes { raw in
                Darwin.read(fd, raw.baseAddress!.advanced(by: total), (maximum + 1) - total)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { break }
            total += count
        }
        // A file larger than the sidecar bound is not a sidecar; the strict parser
        // would reject it anyway, but bounding the read avoids slurping a large
        // unrelated file that merely ends in `.csec`.
        guard total <= maximum else { return nil }
        return Data(buffer.prefix(total))
    }
}
