import Foundation

/// Settings-loader compatibility is independent of publisher/custom-build trust.
/// The compiled catalog ships inside signed csecd. The only other source is
/// the signed release manifest's `claude_code` list (`current(store:)`),
/// verified against a pinned release key on every read, which can add images
/// but never withdraw a compiled one; no other file can extend it.
/// A version label, pathname, signature or passing settings probe is not proof
/// that a new image still loads only the sources the gate inspects.
public struct ClaudeBuildVerification: Sendable {
    public struct Record: Sendable {
        public let cdHash: String
        public let version: String
        public let evidence: String

        public init(cdHash: String, version: String, evidence: String) {
            self.cdHash = cdHash
            self.version = version
            self.evidence = evidence
        }
    }

    public let records: [Record]

    public init(records: [Record]) {
        self.records = records
    }

    public func checkedVersion(cdHash: String?) -> String? {
        guard let cdHash, WireField.isLowercaseHex(cdHash, length: 40) else { return nil }
        return records.first { $0.cdHash == cdHash }?.version
    }

    /// These records plus the manifest's images not already among them. A
    /// compiled record always wins, label included.
    public func adding(_ manifest: ReleaseManifest) -> ClaudeBuildVerification {
        let known = Set(records.map(\.cdHash))
        let added = manifest.claudeCode.filter { !known.contains($0.cdHash) }.map {
            Record(cdHash: $0.cdHash, version: $0.version,
                   evidence: "signed release manifest, number \(manifest.sequence)")
        }
        return ClaudeBuildVerification(records: records + added)
    }

    /// `compiled` plus the held signed manifest's list, read and verified
    /// again now. With no verified manifest (none fetched yet, no pinned
    /// key, or a file someone replaced) this is `compiled` alone.
    public static func current(
        compiled: ClaudeBuildVerification = .shipped, store: ReleaseManifestStore
    ) -> ClaudeBuildVerification {
        guard let held = store.load() else { return compiled }
        return compiled.adding(held.manifest)
    }

    /// Advisory discovery only. Actual authorization always uses live code.
    public static func isInventoryCandidate(_ path: String) -> Bool {
        CodingAgentIdentity.client(name: nil, executablePath: path) == .claude
    }

    /// Installation labels are useful copy, never compatibility evidence.
    public static func versionLabel(executablePath path: String) -> String {
        for marker in [ClaudeInstallLayout.miseVersionsMarker, ClaudeInstallLayout.homebrewVersionsMarker] {
            if let range = path.range(of: marker),
               let label = path[range.upperBound...].split(separator: "/").first {
                return String(label)
            }
        }
        // npm's path names no version; its package.json is not read for a label.
        if path.hasSuffix(ClaudeInstallLayout.npmExecutableSuffix) { return ClaudeInstallLayout.npmLabel }
        let name = (path as NSString).lastPathComponent
        return name.isEmpty ? "unknown build" : name
    }

    public static let shipped = ClaudeBuildVerification(records: [
        Record(
            cdHash: "21209468e54034262a7f049c21983dca5f06ed09", version: "2.1.267",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "af5e0f66b9fd8fdc7e615959dc602cd6386d8d11", version: "2.1.278",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "a2a0746b3c279794afb4eb104aaa6bb88a252a34", version: "2.1.280",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "aec6b146f0cd2378b1489dd316f69d16e11591aa", version: "2.1.282",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "7bfc0b1005fbcb70382ca4e4dd3ae9f7ff2f119b", version: "2.1.295",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "c17da5ef4bfdb3894ec64fee484b9de17127def8", version: "2.1.301",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "3759f6c69569d1685ffcd6eea1c7e20539c2d4b5", version: "2.1.302",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "78d6b9ed85da6de5b0847587570cb3ae268a5c96", version: "2.1.305",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "62f3298fb35e54f02451657e7bfbcd0b795657c7", version: "2.1.310",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "a9faecb664dd8b01e19cdfc12af95da1b267f10e", version: "2.1.311",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "9d4c442a850897e6cf0e68c0d022b98859161d2e", version: "2.1.312",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "33bc52834785912c4ff7dd9e2b9e8c1dd38ef9fd", version: "2.1.314",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "0be2f7d3dad265d1ef590ee83623569caab5fcdd", version: "2.1.315",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "e49e58a1feeb798a46fcdd8d07bcac4ee5ad1428", version: "2.1.316",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "9fd02acbf815f7259d78c4f779c2930ad33ca9aa", version: "2.1.317",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "f9106e5a4887c4904a64d3b9dd15e7154f6120d7", version: "2.1.318",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "c3fca2f1fef791c80f93c36ca7b029950614005b", version: "2.1.319",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
        Record(
            cdHash: "cb0b92a2ee6314aeadf4303ca2b503a181ad9f7f", version: "2.1.325",
            evidence: "docs/claude-release-verification.md#verified-images"
        ),
    ])
}

/// Where Claude Code's installers put its one native image on Apple Silicon.
/// The native installer, Homebrew's cask and npm's package all ship the same
/// Anthropic-signed image with the same code directory hash, so one audit
/// covers every route; these paths only find images and label them.
public enum ClaudeInstallLayout {
    /// `~/.local/share/mise/installs/npm-anthropic-ai-claude-code/VERSION/…`
    public static let miseVersionsMarker = "/.local/share/mise/installs/npm-anthropic-ai-claude-code/"
    /// `/opt/homebrew/Caskroom/claude-code/VERSION/claude`
    public static let homebrewVersionsMarker = "/Caskroom/claude-code/"
    public static let homebrewVersionsDirectory = "/opt/homebrew/Caskroom/claude-code"
    /// `PREFIX/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe`
    public static let npmExecutableSuffix = "/@anthropic-ai/claude-code/bin/claude.exe"
    /// Global npm installs under Homebrew's Node and the nodejs.org installer.
    /// Per-user Node managers are not searched; their running images are
    /// still found and checked wherever they run.
    public static let npmGlobalExecutables = [
        "/opt/homebrew/lib/node_modules" + npmExecutableSuffix,
        "/usr/local/lib/node_modules" + npmExecutableSuffix,
    ]
    public static let npmLabel = "npm install"
}

/// Value-free, daemon-authored inventory consumed by status and the release
/// watchdog. Missing code identity is unknown, never a checked build.
public struct ClaudeBuildVerificationReport: Codable, Sendable, Equatable {
    public static let schemaVersion = 1
    public static let maximumCheckedReleases = 1_024
    public let schemaVersion: Int
    public let builds: [Build]
    public let unreadablePaths: [String]
    /// Scheduling hints from all shipped records, including images not installed
    /// here. These labels never authorize a live process.
    public let checkedReleases: [String]

    public struct Build: Codable, Sendable, Equatable {
        public let path: String
        public let versionLabel: String
        public let cdHash: String?
        public let checkedVersion: String?
        public let running: Bool

        public init(path: String, versionLabel: String, cdHash: String?, checkedVersion: String?, running: Bool) {
            self.path = path
            self.versionLabel = versionLabel
            self.cdHash = cdHash
            self.checkedVersion = checkedVersion
            self.running = running
        }

        public var isWellFormed: Bool {
            WireField.isAbsolutePath(path, maximumBytes: ClaudeBuildSummary.maximumPathBytes)
                && WireField.isBoundedText(versionLabel, maximumBytes: ClaudeBuildSummary.maximumVersionLabelBytes)
                && (cdHash.map { WireField.isLowercaseHex($0, length: 40) } ?? true)
                && (checkedVersion.map {
                    cdHash != nil && WireField.isBoundedText($0, maximumBytes: ClaudeBuildSummary.maximumVersionLabelBytes)
                } ?? true)
        }
    }

    public init(builds: [Build], unreadablePaths: [String] = [], checkedReleases: [String] = [],
                schemaVersion: Int = Self.schemaVersion) {
        self.schemaVersion = schemaVersion
        self.builds = builds
        self.unreadablePaths = unreadablePaths
        self.checkedReleases = checkedReleases
    }

    public var uncheckedBuilds: [Build] { builds.filter { $0.checkedVersion == nil } }

    public var isWellFormed: Bool {
        schemaVersion == Self.schemaVersion
            && builds.count <= DelegationStatus.maximumDiscoveredBuilds
            && builds.allSatisfy(\.isWellFormed)
            && unreadablePaths.count <= DelegationStatus.maximumDiscoveredBuilds
            && unreadablePaths.allSatisfy { WireField.isAbsolutePath($0) }
            && checkedReleases.count <= Self.maximumCheckedReleases
            && checkedReleases.allSatisfy { WireField.isBoundedText($0, maximumBytes: ClaudeBuildSummary.maximumVersionLabelBytes) }
    }
}
