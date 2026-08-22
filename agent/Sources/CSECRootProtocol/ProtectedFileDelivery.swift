import Foundation
import CryptoKit
import Darwin

public enum ProtectedFileDeliveryError: Error, LocalizedError, Equatable {
    case invalidLaunchPlan
    case invalidFileBinding
    case invalidFilePayload
    case invalidGitHubProfile
    case unavailableRootHelper
    case untrustedRootHelper
    case rootHelperFailure(String)
    case launchExpired

    public var errorDescription: String? {
        switch self {
        case .invalidLaunchPlan:
            return "the protected-file launch plan is invalid"
        case .invalidFileBinding:
            return "a protected-file binding is invalid or duplicated"
        case .invalidFilePayload:
            return "a protected file is empty, oversized, or does not match the reviewed plan"
        case .invalidGitHubProfile:
            return "the protected GitHub profile is invalid"
        case .unavailableRootHelper:
            return "the protected-file root helper is unavailable"
        case .untrustedRootHelper:
            return "the protected-file root helper has an unexpected identity"
        case let .rootHelperFailure(message):
            return "the protected-file root helper refused the launch: \(message)"
        case .launchExpired:
            return "the protected-file launch expired before it started"
        }
    }
}

/// Rendering is selected by signed product code and digest-bound before any
/// value is resolved. The root helper receives only final bytes and a relative
/// path; it never interprets a credential or accepts an arbitrary destination.
public enum ProtectedFileRendering: Codable, Sendable, Equatable {
    case raw
    case githubHosts(host: String, user: String?, gitProtocol: String)

    private enum CodingKeys: String, CodingKey { case kind, host, user, gitProtocol }
    private enum Kind: String, Codable { case raw, githubHosts = "github_hosts" }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .kind) {
        case .raw:
            self = .raw
        case .githubHosts:
            self = .githubHosts(
                host: try container.decode(String.self, forKey: .host),
                user: try container.decodeIfPresent(String.self, forKey: .user),
                gitProtocol: try container.decode(String.self, forKey: .gitProtocol)
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .raw:
            try container.encode(Kind.raw, forKey: .kind)
        case let .githubHosts(host, user, gitProtocol):
            try container.encode(Kind.githubHosts, forKey: .kind)
            try container.encode(host, forKey: .host)
            try container.encodeIfPresent(user, forKey: .user)
            try container.encode(gitProtocol, forKey: .gitProtocol)
        }
    }
}

/// One value-to-file mapping. `relativePath` and `environmentRelativePath` are
/// interpreted only beneath the already-open tmpfs launch directory.
public struct ProtectedFileBinding: Codable, Sendable, Equatable {
    public let relativePath: String
    public let environmentName: String
    public let environmentRelativePath: String
    public let reference: String
    public let rendering: ProtectedFileRendering

    public init(
        relativePath: String,
        environmentName: String,
        environmentRelativePath: String? = nil,
        reference: String,
        rendering: ProtectedFileRendering = .raw
    ) {
        self.relativePath = relativePath
        self.environmentName = environmentName
        self.environmentRelativePath = environmentRelativePath ?? relativePath
        self.reference = reference
        self.rendering = rendering
    }

    public static func raw(
        environmentName: String,
        reference: String,
        index: Int
    ) -> ProtectedFileBinding {
        ProtectedFileBinding(
            relativePath: "files/credential-\(index)",
            environmentName: environmentName,
            reference: reference
        )
    }

    public static func github(
        reference: String,
        host: String = "github.com",
        user: String? = nil,
        gitProtocol: String = "https"
    ) -> ProtectedFileBinding {
        ProtectedFileBinding(
            relativePath: "github/hosts.yml",
            environmentName: "GH_CONFIG_DIR",
            environmentRelativePath: "github",
            reference: reference,
            rendering: .githubHosts(host: host, user: user, gitProtocol: gitProtocol)
        )
    }
}

/// Complete, bounded, plaintext-free root launch request. Both signed parties
/// see this exact object. Its digest is the rendezvous capability; a nonce is
/// still required so an approval can be consumed only by one prepared launch.
public struct ProtectedLaunchPlan: Codable, Sendable, Equatable {
    public static let maximumArguments = 256
    public static let maximumEnvironmentEntries = 512
    public static let maximumMetadataBytes = 1024 * 1024
    public static let maximumFiles = 16

    public let protocolVersion: Int
    public let launcherPID: pid_t
    public let launcherStartTime: UInt64
    public let uid: uid_t
    public let auditSessionID: UInt32
    public let executable: PlannedExecutable
    public let commandLine: [String]
    public let environment: [String: String]
    public let files: [ProtectedFileBinding]
    public let deliveryPlan: DeliveryPlan
    public let hardTTL: Bool
    public let usesPTY: Bool

    public init(
        launcherPID: pid_t,
        launcherStartTime: UInt64,
        uid: uid_t,
        auditSessionID: UInt32,
        executable: PlannedExecutable,
        commandLine: [String],
        environment: [String: String],
        files: [ProtectedFileBinding],
        deliveryPlan: DeliveryPlan,
        hardTTL: Bool = false,
        usesPTY: Bool = false
    ) {
        self.protocolVersion = RootHelperWireProtocol.version
        self.launcherPID = launcherPID
        self.launcherStartTime = launcherStartTime
        self.uid = uid
        self.auditSessionID = auditSessionID
        self.executable = executable
        self.commandLine = commandLine
        self.environment = environment
        self.files = files
        self.deliveryPlan = deliveryPlan
        self.hardTTL = hardTTL
        self.usesPTY = usesPTY
    }

    public var references: [String] {
        var seen = Set<String>()
        return files.map(\.reference).filter { seen.insert($0).inserted }
    }

    public func digest() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return SHA256.hash(data: try encoder.encode(self)).map {
            String(format: "%02x", $0)
        }.joined()
    }

    /// Structural validation shared by csec, csecd, and csec-rootd. Every
    /// privileged endpoint reruns it; a signed caller is not trusted to have
    /// remembered a bound or path rule.
    public func validate() throws {
        guard protocolVersion == RootHelperWireProtocol.version,
              launcherPID > 1,
              launcherStartTime > 0,
              uid != UInt32.max,
              auditSessionID != UInt32.max,
              !executable.canonicalPath.isEmpty,
              executable.canonicalPath.hasPrefix("/"),
              executable.canonicalPath.utf8.count <= 4_096,
              !executable.canonicalPath.utf8.contains(0),
              commandLine.count > 0,
              commandLine.count <= Self.maximumArguments,
              environment.count <= Self.maximumEnvironmentEntries,
              files.count > 0,
              files.count <= Self.maximumFiles,
              deliveryPlan.mechanism == .capabilityGIDFile,
              deliveryPlan.executable == executable,
              deliveryPlan.root == .caller,
              deliveryPlan.requestedTTLSeconds > 0,
              deliveryPlan.requestedTTLSeconds <= 24 * 60 * 60,
              !deliveryPlan.operationContext.isEmpty,
              deliveryPlan.operationContext.utf8.count <= 512,
              !deliveryPlan.operationContext.utf8.contains(0),
              deliveryPlan.commandDigest == (try? ExecutableInspection.commandDigest(commandLine)),
              deliveryPlan.outputGuard != nil else {
            throw ProtectedFileDeliveryError.invalidLaunchPlan
        }

        var metadataBytes = executable.canonicalPath.utf8.count
        for argument in commandLine {
            guard !argument.utf8.contains(0), argument.utf8.count <= 64 * 1024 else {
                throw ProtectedFileDeliveryError.invalidLaunchPlan
            }
            metadataBytes += argument.utf8.count
        }
        for (name, value) in environment {
            guard Self.validEnvironmentName(name),
                  !name.hasPrefix("CSEC_"),
                  !Self.isLoaderControl(name),
                  !value.utf8.contains(0),
                  value.utf8.count <= 256 * 1024 else {
                throw ProtectedFileDeliveryError.invalidLaunchPlan
            }
            metadataBytes += name.utf8.count + value.utf8.count
        }
        guard metadataBytes <= Self.maximumMetadataBytes else {
            throw ProtectedFileDeliveryError.invalidLaunchPlan
        }

        var paths = Set<String>()
        var environmentNames = Set<String>()
        for binding in files {
            guard Self.validRelativePath(binding.relativePath, allowDirectory: false),
                  Self.validRelativePath(binding.environmentRelativePath, allowDirectory: true),
                  binding.relativePath == binding.environmentRelativePath
                    || binding.relativePath.hasPrefix(binding.environmentRelativePath + "/"),
                  Self.validEnvironmentName(binding.environmentName),
                  !binding.environmentName.hasPrefix("CSEC_"),
                  environment[binding.environmentName] == nil,
                  paths.insert(binding.relativePath).inserted,
                  environmentNames.insert(binding.environmentName).inserted,
                  binding.reference.utf8.count <= 4_096,
                  !binding.reference.utf8.contains(0),
                  (try? SecretRef(binding.reference)) != nil else {
                throw ProtectedFileDeliveryError.invalidFileBinding
            }
            metadataBytes += binding.relativePath.utf8.count
                + binding.environmentName.utf8.count
                + binding.environmentRelativePath.utf8.count
                + binding.reference.utf8.count
            switch binding.rendering {
            case .raw:
                guard binding.environmentRelativePath == binding.relativePath else {
                    throw ProtectedFileDeliveryError.invalidFileBinding
                }
            case let .githubHosts(host, user, gitProtocol):
                guard binding.relativePath == "github/hosts.yml",
                      binding.environmentName == "GH_CONFIG_DIR",
                      binding.environmentRelativePath == "github",
                      Self.validGitHubHost(host),
                      user.map(Self.validGitHubUser) ?? true,
                      gitProtocol == "https" || gitProtocol == "ssh" else {
                    throw ProtectedFileDeliveryError.invalidGitHubProfile
                }
            }
        }
        let orderedPaths = paths.sorted()
        for path in orderedPaths {
            guard !orderedPaths.contains(where: {
                $0 != path && ($0.hasPrefix(path + "/") || path.hasPrefix($0 + "/"))
            }) else {
                throw ProtectedFileDeliveryError.invalidFileBinding
            }
        }
        guard metadataBytes <= Self.maximumMetadataBytes else {
            throw ProtectedFileDeliveryError.invalidLaunchPlan
        }
    }

    public static func sanitizedEnvironment(
        _ environment: [String: String]
    ) -> [String: String] {
        environment.filter { name, value in
            validEnvironmentName(name)
                && !name.hasPrefix("CSEC_")
                && !isLoaderControl(name)
                && !value.utf8.contains(0)
                && value.utf8.count <= 256 * 1024
        }
    }

    public static func validEnvironmentName(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count <= 128,
              asciiAlpha(bytes[0]) || bytes[0] == 95 else { return false }
        return bytes.allSatisfy { asciiAlpha($0) || (48...57).contains($0) || $0 == 95 }
    }

    public static func validRelativePath(_ value: String, allowDirectory: Bool) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 512, !value.hasPrefix("/") else { return false }
        let components = value.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty, components.count <= 4,
              allowDirectory || components.count >= 2 else { return false }
        return components.allSatisfy { component in
            !component.isEmpty && component != "." && component != ".."
                && component.utf8.count <= 128
                && component.utf8.allSatisfy {
                    asciiAlpha($0) || (48...57).contains($0)
                        || $0 == 45 || $0 == 46 || $0 == 95
                }
        }
    }

    private static func isLoaderControl(_ name: String) -> Bool {
        name.hasPrefix("DYLD_") || name.hasPrefix("LD_") || name.hasPrefix("_RLD_")
            || name.hasPrefix("Malloc") || name == "NSUnbufferedIO"
    }

    private static func validGitHubHost(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253,
              !value.hasPrefix("."), !value.hasSuffix(".") else { return false }
        return value.utf8.allSatisfy {
            asciiAlpha($0) || (48...57).contains($0) || $0 == 45 || $0 == 46
        }
    }

    private static func validGitHubUser(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128
            && value.utf8.allSatisfy {
                asciiAlpha($0) || (48...57).contains($0) || $0 == 45 || $0 == 95
            }
    }

    private static func asciiAlpha(_ byte: UInt8) -> Bool {
        (65...90).contains(byte) || (97...122).contains(byte)
    }
}

public struct ProtectedFilePayload: Codable, Sendable, Equatable {
    public let relativePath: String
    public let data: Data

    public init(relativePath: String, data: Data) {
        self.relativePath = relativePath
        self.data = data
    }
}

public enum ProtectedFilePayloadRenderer {
    public static let maximumFileBytes = 1024 * 1024
    public static let maximumTotalBytes = 4 * 1024 * 1024

    public static func render(
        bindings: [ProtectedFileBinding],
        values: [String: String]
    ) throws -> [ProtectedFilePayload] {
        guard Set(values.keys) == Set(bindings.map(\.reference)) else {
            throw ProtectedFileDeliveryError.invalidFilePayload
        }
        var payloads: [ProtectedFilePayload] = []
        var total = 0
        for binding in bindings {
            guard let value = values[binding.reference] else {
                throw ProtectedFileDeliveryError.invalidFilePayload
            }
            let data: Data
            switch binding.rendering {
            case .raw:
                data = Data(value.utf8)
            case let .githubHosts(host, user, gitProtocol):
                guard !value.isEmpty,
                      !value.unicodeScalars.contains(where: {
                          $0.value == 0 || CharacterSet.newlines.contains($0)
                      }) else {
                    throw ProtectedFileDeliveryError.invalidGitHubProfile
                }
                var lines = [
                    "\(host):",
                    "    oauth_token: \(yamlSingleQuoted(value))",
                    "    git_protocol: \(gitProtocol)",
                ]
                if let user {
                    lines.append("    user: \(yamlSingleQuoted(user))")
                }
                data = Data((lines.joined(separator: "\n") + "\n").utf8)
            }
            guard !data.isEmpty, data.count <= maximumFileBytes else {
                throw ProtectedFileDeliveryError.invalidFilePayload
            }
            total += data.count
            guard total <= maximumTotalBytes else {
                throw ProtectedFileDeliveryError.invalidFilePayload
            }
            payloads.append(ProtectedFilePayload(relativePath: binding.relativePath, data: data))
        }
        return payloads
    }

    private static func yamlSingleQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "''") + "'"
    }
}

public enum RootHelperWireProtocol {
    public static let version = 1
}

public enum RootHelperSocket {
    public static let canonicalDirectory = "/private/var/run/convenient-security"
    public static let canonicalPath = canonicalDirectory + "/rootd.sock"
    public static let canonicalMountPath = canonicalDirectory + "/files"

    public static var isUsingDebugOverride: Bool {
        #if DEBUG
        return ProcessInfo.processInfo.environment["CSEC_ROOT_SOCKET"]?.isEmpty == false
        #else
        return false
        #endif
    }

    public static func defaultPath() -> String {
        if isUsingDebugOverride {
            return ProcessInfo.processInfo.environment["CSEC_ROOT_SOCKET"]!
        }
        return canonicalPath
    }
}

public enum RootLaunchState: String, Codable, Sendable {
    case prepared
    case ready
    case running
    case finished
    case cancelled
}

public enum RootHelperRequest: Codable, Sendable {
    case prepare(requestID: String, plan: ProtectedLaunchPlan, planDigest: String)
    case approve(
        requestID: String,
        nonce: String,
        planDigest: String,
        payloads: [ProtectedFilePayload],
        expiresAt: Date
    )
    case start(requestID: String, nonce: String, planDigest: String)
    case status(requestID: String, nonce: String, planDigest: String)
    case signal(requestID: String, nonce: String, planDigest: String, signal: Int32)
    case cancel(requestID: String, nonce: String, planDigest: String)
    case health(requestID: String)

    private enum CodingKeys: String, CodingKey {
        case version, type, requestID, plan, planDigest, nonce, payloads, expiresAt, signal
    }

    private enum Kind: String, Codable {
        case prepare, approve, start, status, signal, cancel, health
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(Int.self, forKey: .version) == RootHelperWireProtocol.version else {
            throw ProtectedFileDeliveryError.invalidLaunchPlan
        }
        let kind = try container.decode(Kind.self, forKey: .type)
        let requestID = try container.decode(String.self, forKey: .requestID)
        switch kind {
        case .prepare:
            self = .prepare(
                requestID: requestID,
                plan: try container.decode(ProtectedLaunchPlan.self, forKey: .plan),
                planDigest: try container.decode(String.self, forKey: .planDigest)
            )
        case .approve:
            self = .approve(
                requestID: requestID,
                nonce: try container.decode(String.self, forKey: .nonce),
                planDigest: try container.decode(String.self, forKey: .planDigest),
                payloads: try container.decode([ProtectedFilePayload].self, forKey: .payloads),
                expiresAt: try container.decode(Date.self, forKey: .expiresAt)
            )
        case .start:
            self = .start(
                requestID: requestID,
                nonce: try container.decode(String.self, forKey: .nonce),
                planDigest: try container.decode(String.self, forKey: .planDigest)
            )
        case .status:
            self = .status(
                requestID: requestID,
                nonce: try container.decode(String.self, forKey: .nonce),
                planDigest: try container.decode(String.self, forKey: .planDigest)
            )
        case .signal:
            self = .signal(
                requestID: requestID,
                nonce: try container.decode(String.self, forKey: .nonce),
                planDigest: try container.decode(String.self, forKey: .planDigest),
                signal: try container.decode(Int32.self, forKey: .signal)
            )
        case .cancel:
            self = .cancel(
                requestID: requestID,
                nonce: try container.decode(String.self, forKey: .nonce),
                planDigest: try container.decode(String.self, forKey: .planDigest)
            )
        case .health:
            self = .health(requestID: requestID)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(RootHelperWireProtocol.version, forKey: .version)
        switch self {
        case let .prepare(requestID, plan, digest):
            try container.encode(Kind.prepare, forKey: .type)
            try container.encode(requestID, forKey: .requestID)
            try container.encode(plan, forKey: .plan)
            try container.encode(digest, forKey: .planDigest)
        case let .approve(requestID, nonce, digest, payloads, expiresAt):
            try container.encode(Kind.approve, forKey: .type)
            try container.encode(requestID, forKey: .requestID)
            try container.encode(nonce, forKey: .nonce)
            try container.encode(digest, forKey: .planDigest)
            try container.encode(payloads, forKey: .payloads)
            try container.encode(expiresAt, forKey: .expiresAt)
        case let .start(requestID, nonce, digest):
            try container.encode(Kind.start, forKey: .type)
            try container.encode(requestID, forKey: .requestID)
            try container.encode(nonce, forKey: .nonce)
            try container.encode(digest, forKey: .planDigest)
        case let .status(requestID, nonce, digest):
            try container.encode(Kind.status, forKey: .type)
            try container.encode(requestID, forKey: .requestID)
            try container.encode(nonce, forKey: .nonce)
            try container.encode(digest, forKey: .planDigest)
        case let .signal(requestID, nonce, digest, signal):
            try container.encode(Kind.signal, forKey: .type)
            try container.encode(requestID, forKey: .requestID)
            try container.encode(nonce, forKey: .nonce)
            try container.encode(digest, forKey: .planDigest)
            try container.encode(signal, forKey: .signal)
        case let .cancel(requestID, nonce, digest):
            try container.encode(Kind.cancel, forKey: .type)
            try container.encode(requestID, forKey: .requestID)
            try container.encode(nonce, forKey: .nonce)
            try container.encode(digest, forKey: .planDigest)
        case let .health(requestID):
            try container.encode(Kind.health, forKey: .type)
            try container.encode(requestID, forKey: .requestID)
        }
    }
}

public enum RootHelperWireErrorCode: String, Codable, Sendable {
    case invalidRequest = "invalid_request"
}

public struct RootHelperWireFailure: Codable, Sendable, Equatable {
    public let code: RootHelperWireErrorCode
    public let message: String

    public init(_ code: RootHelperWireErrorCode, message: String) {
        self.code = code
        self.message = message
    }
}

public struct RootHelperResponse: Codable, Sendable {
    public let version: Int
    public let requestID: String
    public let nonce: String?
    public let planDigest: String?
    public let state: RootLaunchState?
    public let childPID: pid_t?
    public let childStartTime: UInt64?
    public let waitStatus: Int32?
    public let failure: RootHelperWireFailure?

    public init(
        requestID: String,
        nonce: String? = nil,
        planDigest: String? = nil,
        state: RootLaunchState? = nil,
        childPID: pid_t? = nil,
        childStartTime: UInt64? = nil,
        waitStatus: Int32? = nil,
        failure: RootHelperWireFailure? = nil
    ) {
        self.version = RootHelperWireProtocol.version
        self.requestID = requestID
        self.nonce = nonce
        self.planDigest = planDigest
        self.state = state
        self.childPID = childPID
        self.childStartTime = childStartTime
        self.waitStatus = waitStatus
        self.failure = failure
    }

    public static func failed(
        requestID: String,
        _ code: RootHelperWireErrorCode,
        _ message: String
    ) -> RootHelperResponse {
        RootHelperResponse(
            requestID: requestID,
            failure: RootHelperWireFailure(code, message: message)
        )
    }
}
