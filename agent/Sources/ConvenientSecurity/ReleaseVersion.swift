import Foundation
#if canImport(MachO)
import MachO
#endif

/// A csec release number: `MAJOR.MINOR.PATCH`, digits only. The repository's
/// `VERSION` file holds it, `build-agent.sh` stamps it into every binary and
/// the app, and the package refuses to install over a higher one.
public struct ReleaseVersion: Sendable, Equatable, Hashable, Comparable, CustomStringConvertible {
    public let major: Int
    public let minor: Int
    public let patch: Int

    public init(major: Int, minor: Int, patch: Int) {
        self.major = major
        self.minor = minor
        self.patch = patch
    }

    /// Exactly three dot-separated decimal numbers with no leading zeros
    /// (`0` itself is allowed), as semantic versioning writes a release. A
    /// pre-release or build suffix is refused: csec numbers builds separately.
    public init?(_ text: String) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }
        var numbers: [Int] = []
        for part in parts {
            guard !part.isEmpty, part.count <= 9,
                  part.allSatisfy({ $0.isASCII && $0.isNumber }),
                  part == "0" || part.first != "0",
                  let number = Int(part) else { return nil }
            numbers.append(number)
        }
        self.init(major: numbers[0], minor: numbers[1], patch: numbers[2])
    }

    public var description: String { "\(major).\(minor).\(patch)" }

    public static func < (lhs: ReleaseVersion, rhs: ReleaseVersion) -> Bool {
        (lhs.major, lhs.minor, lhs.patch) < (rhs.major, rhs.minor, rhs.patch)
    }
}

/// What a csec binary was built as: its release version, its build number
/// (the commit count of the history it was built from, so a later commit on
/// the same line always numbers higher) and that commit.
///
/// `build-agent.sh` links the stamp into every release binary as the Mach-O
/// section `__TEXT,__csec_stamp`, rather than as an embedded `__info_plist`:
/// an embedded Info.plist would replace the app's own for `csec` inside the
/// bundle (dropping its bundle identifier), while this section changes
/// nothing else. A development build (`swift build`, the tests) has none.
public struct ReleaseStamp: Sendable, Equatable, Codable {
    public let version: String
    public let build: Int
    public let commit: String

    public init(version: String, build: Int, commit: String) {
        self.version = version
        self.build = build
        self.commit = commit
    }

    public static let sectionSegment = "__TEXT"
    public static let sectionName = "__csec_stamp"

    /// The parsed release version, nil when the stamp's text is not one.
    public var releaseVersion: ReleaseVersion? { ReleaseVersion(version) }

    /// `0.9.0 (build 4567, commit ace53c8)`.
    public var display: String {
        "\(version) (build \(build), commit \(commit.prefix(7)))"
    }

    /// Decodes the section's JSON, refusing anything that is not a whole,
    /// well-formed stamp: a release version, a positive build and a full
    /// lowercase commit id.
    public static func decode(_ data: Data) -> ReleaseStamp? {
        guard let stamp = try? JSONDecoder().decode(ReleaseStamp.self, from: data),
              stamp.releaseVersion != nil,
              stamp.build > 0,
              stamp.commit.count == 40,
              stamp.commit.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) })
        else { return nil }
        return stamp
    }

    /// The running executable's own stamp; nil for a development build.
    /// Read once: the section is part of the mapped image and cannot change.
    public static let current: ReleaseStamp? = readExecutableSection().flatMap(decode)

    private static func readExecutableSection() -> Data? {
        #if canImport(MachO)
        // Image 0 is the main executable, whichever binary links this library.
        guard let header = _dyld_get_image_header(0) else { return nil }
        var size: UInt = 0
        let bytes = header.withMemoryRebound(to: mach_header_64.self, capacity: 1) {
            getsectiondata($0, sectionSegment, sectionName, &size)
        }
        guard let bytes, size > 0, size <= 4096 else { return nil }
        return Data(bytes: bytes, count: Int(size))
        #else
        return nil
        #endif
    }

    /// `csec --version`'s line for this binary.
    public static func versionLine(program: String, stamp: ReleaseStamp? = current) -> String {
        guard let stamp else { return "\(program) development build (no release stamp)" }
        return "\(program) \(stamp.display)"
    }
}

/// A version and build together, the order the package's downgrade check
/// and the update notice use: the release version first, then the build.
public struct ReleaseBuild: Sendable, Equatable, Comparable, CustomStringConvertible {
    public let version: ReleaseVersion
    public let build: Int

    public init(version: ReleaseVersion, build: Int) {
        self.version = version
        self.build = build
    }

    public init?(_ stamp: ReleaseStamp) {
        guard let version = stamp.releaseVersion else { return nil }
        self.init(version: version, build: stamp.build)
    }

    public var description: String { "\(version) (build \(build))" }

    public static func < (lhs: ReleaseBuild, rhs: ReleaseBuild) -> Bool {
        if lhs.version != rhs.version { return lhs.version < rhs.version }
        return lhs.build < rhs.build
    }
}
