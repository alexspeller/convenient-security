import Foundation
import Security
import CSecuritySupport

/// The kernel-authenticated identity attached to one end of a local socket.
///
/// `rawAuditToken` is intentionally retained in full. A PID is reusable; the
/// complete audit token also carries the PID version and is the input used by
/// Security.framework to resolve the *live* code object for this connection.
public struct AuditIdentity: Sendable {
    public let rawAuditToken: Data
    public let pid: pid_t
    public let pidVersion: Int32
    public let effectiveUID: uid_t
    public let auditSessionID: UInt32
    public let executablePath: String?
    public let startTime: UInt64

    /// Read the peer token supplied by the kernel for a connected local socket.
    /// Nothing in this value is accepted from protocol JSON or process argv.
    public static func socketPeer(fd: Int32) -> AuditIdentity? {
        // audit_token_t is currently 32 bytes. Use a deliberately larger buffer
        // and trust the C bridge's returned length so Swift never depends on the
        // private representation or field ordering.
        var tokenBuffer = [UInt8](repeating: 0, count: 64)
        let tokenLength = tokenBuffer.withUnsafeMutableBytes { bytes in
            cs_peer_audit_token(fd, bytes.baseAddress, Int32(bytes.count))
        }
        guard tokenLength > 0, tokenLength <= tokenBuffer.count else { return nil }

        let token = Data(tokenBuffer.prefix(Int(tokenLength)))
        let pid = token.withUnsafeBytes {
            cs_audit_token_pid($0.baseAddress, Int32($0.count))
        }
        let pidVersion = token.withUnsafeBytes {
            cs_audit_token_pidversion($0.baseAddress, Int32($0.count))
        }
        let effectiveUID = token.withUnsafeBytes {
            cs_audit_token_euid($0.baseAddress, Int32($0.count))
        }
        let auditSessionID = token.withUnsafeBytes {
            cs_audit_token_asid($0.baseAddress, Int32($0.count))
        }
        guard pid > 0, pidVersion >= 0, effectiveUID != UInt32.max,
              auditSessionID != UInt32.max else { return nil }

        // libproc's maximum is currently 4 * MAXPATHLEN; the macro itself is
        // unavailable to Swift because it is an arithmetic C macro.
        var pathBuffer = [CChar](repeating: 0, count: 4 * 1_024)
        let pathLength = token.withUnsafeBytes { tokenBytes in
            pathBuffer.withUnsafeMutableBufferPointer { pathBytes in
                cs_proc_path_audit_token(
                    tokenBytes.baseAddress,
                    Int32(tokenBytes.count),
                    pathBytes.baseAddress,
                    Int32(pathBytes.count)
                )
            }
        }
        let path = pathLength > 0 ? String(cString: pathBuffer) : nil

        return AuditIdentity(
            rawAuditToken: token,
            pid: pid,
            pidVersion: pidVersion,
            effectiveUID: effectiveUID,
            auditSessionID: auditSessionID,
            executablePath: path,
            startTime: cs_proc_start_time(pid)
        )
    }
}

/// Product roles have separate, exact signing identifiers. A matching Team ID
/// alone is insufficient: another binary signed by the same developer must not
/// be accepted as either endpoint.
public enum ProductCodeRole: String, Sendable {
    case agent
    case launcher
    case rootHelper = "root_helper"
    case other
}

/// Value-only result of resolving and validating a live process's code object.
/// It deliberately does not retain a `SecCode` reference across concurrency
/// boundaries.
public struct CodeIdentity: Sendable {
    public let identifier: String?
    public let teamIdentifier: String?
    public let cdHash: String?
    public let executablePath: String?
    public let signatureValid: Bool
    public let hardenedRuntime: Bool
    public let dangerousEntitlements: [String]
    public let role: ProductCodeRole
    public let status: Int32

    public var isVerifiedProduct: Bool {
        signatureValid && hardenedRuntime && dangerousEntitlements.isEmpty && role != .other
    }

    public static let unverified = CodeIdentity(
        identifier: nil,
        teamIdentifier: nil,
        cdHash: nil,
        executablePath: nil,
        signatureValid: false,
        hardenedRuntime: false,
        dangerousEntitlements: [],
        role: .other,
        status: Int32(errSecCSUnsigned)
    )

    public init(
        identifier: String?,
        teamIdentifier: String?,
        cdHash: String?,
        executablePath: String?,
        signatureValid: Bool,
        hardenedRuntime: Bool,
        dangerousEntitlements: [String],
        role: ProductCodeRole,
        status: Int32
    ) {
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.cdHash = cdHash
        self.executablePath = executablePath
        self.signatureValid = signatureValid
        self.hardenedRuntime = hardenedRuntime
        self.dangerousEntitlements = dangerousEntitlements
        self.role = role
        self.status = status
    }
}

/// The only code-signing policy accepted for shipping endpoints.
public enum ProductCodeIdentity {
    public static let teamIdentifier = "8RS6GD89Y7"
    public static let agentIdentifier = "com.alexspeller.convenient-security"
    public static let launcherIdentifier = "com.alexspeller.convenient-security.csec"
    public static let rootHelperIdentifier = "com.alexspeller.convenient-security.rootd"
    public static let forbiddenEntitlements = [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.debugger",
    ]

    /// Resolve a dynamic `SecCode` from the complete socket audit token, check
    /// its live validity, and then evaluate the exact product requirement.
    public static func resolve(_ audit: AuditIdentity) -> CodeIdentity {
        let attributes = [kSecGuestAttributeAudit: audit.rawAuditToken as CFData] as CFDictionary
        var code: SecCode?
        let lookupStatus = SecCodeCopyGuestWithAttributes(
            nil,
            attributes,
            SecCSFlags(rawValue: 0),
            &code
        )
        guard lookupStatus == errSecSuccess, let code else {
            return CodeIdentity(
                identifier: nil,
                teamIdentifier: nil,
                cdHash: nil,
                executablePath: audit.executablePath,
                signatureValid: false,
                hardenedRuntime: false,
                dangerousEntitlements: [],
                role: .other,
                status: lookupStatus
            )
        }

        let validationFlags = SecCSFlags(rawValue: UInt32(kSecCSStrictValidate))
        let validityStatus = SecCodeCheckValidity(code, validationFlags, nil)

        var staticCode: SecStaticCode?
        let staticCodeStatus = SecCodeCopyStaticCode(
            code,
            SecCSFlags(rawValue: 0),
            &staticCode
        )

        var information: CFDictionary?
        let informationStatus: OSStatus
        if staticCodeStatus == errSecSuccess, let staticCode {
            informationStatus = SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)),
                &information
            )
        } else {
            informationStatus = staticCodeStatus
        }
        let dictionary = information as? [String: Any]
        let identifier = dictionary?[kSecCodeInfoIdentifier as String] as? String
        let teamIdentifier = dictionary?[kSecCodeInfoTeamIdentifier as String] as? String
        let cdHash = (dictionary?[kSecCodeInfoUnique as String] as? Data)?.hexString
        let flags = (dictionary?[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let hardenedRuntime = flags & 0x0001_0000 != 0 // CS_RUNTIME
        let entitlements = dictionary?[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        let dangerousEntitlements = forbiddenEntitlements.filter {
            (entitlements[$0] as? Bool) == true
        }

        var codePath: CFURL?
        let pathStatus: OSStatus
        if let staticCode {
            pathStatus = SecCodeCopyPath(
                staticCode,
                SecCSFlags(rawValue: 0),
                &codePath
            )
        } else {
            pathStatus = staticCodeStatus
        }
        let resolvedPath = pathStatus == errSecSuccess ? (codePath as URL?)?.path : audit.executablePath

        let signatureValid = validityStatus == errSecSuccess && informationStatus == errSecSuccess
        let role: ProductCodeRole
        if signatureValid, hardenedRuntime, dangerousEntitlements.isEmpty,
           identifier == agentIdentifier,
           teamIdentifier == self.teamIdentifier,
           satisfiesRequirement(code, identifier: agentIdentifier) {
            role = .agent
        } else if signatureValid, hardenedRuntime, dangerousEntitlements.isEmpty,
                  identifier == launcherIdentifier,
                  teamIdentifier == self.teamIdentifier,
                  satisfiesRequirement(code, identifier: launcherIdentifier) {
            role = .launcher
        } else if signatureValid, hardenedRuntime, dangerousEntitlements.isEmpty,
                  identifier == rootHelperIdentifier,
                  teamIdentifier == self.teamIdentifier,
                  satisfiesRequirement(code, identifier: rootHelperIdentifier) {
            role = .rootHelper
        } else {
            role = .other
        }

        return CodeIdentity(
            identifier: identifier,
            teamIdentifier: teamIdentifier,
            cdHash: cdHash,
            executablePath: resolvedPath,
            signatureValid: signatureValid,
            hardenedRuntime: hardenedRuntime,
            dangerousEntitlements: dangerousEntitlements,
            role: role,
            status: signatureValid ? Int32(errSecSuccess) : Int32(validityStatus)
        )
    }

    /// Pure metadata classifier for regression tests and display. Production
    /// trust does not use this helper; `resolve` additionally evaluates the
    /// compiled Security.framework requirement against the live code object.
    public static func metadataRole(
        identifier: String?,
        teamIdentifier: String?,
        signatureValid: Bool,
        hardenedRuntime: Bool = true,
        dangerousEntitlements: [String] = []
    ) -> ProductCodeRole {
        guard signatureValid,
              hardenedRuntime,
              dangerousEntitlements.isEmpty,
              teamIdentifier == self.teamIdentifier else { return .other }
        switch identifier {
        case agentIdentifier: return .agent
        case launcherIdentifier: return .launcher
        case rootHelperIdentifier: return .rootHelper
        default: return .other
        }
    }

    private static func satisfiesRequirement(_ code: SecCode, identifier: String) -> Bool {
        // `anchor apple generic` plus the leaf OU makes this a Developer ID
        // requirement for this exact team and signing identifier. This is more
        // than a metadata comparison: Security.framework evaluates it against
        // the live, kernel-selected code object.
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamIdentifier)\" and identifier \"\(identifier)\""
        var requirement: SecRequirement?
        let creationStatus = SecRequirementCreateWithString(
            text as CFString,
            SecCSFlags(rawValue: 0),
            &requirement
        )
        guard creationStatus == errSecSuccess, let requirement else { return false }
        return SecCodeCheckValidity(
            code,
            SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)),
            requirement
        ) == errSecSuccess
    }
}

/// Kernel identity and validated code identity for a connected peer.
public struct PeerIdentity: Sendable {
    public let audit: AuditIdentity
    public let code: CodeIdentity

    public static func socketPeer(fd: Int32) -> PeerIdentity? {
        guard let audit = AuditIdentity.socketPeer(fd: fd) else { return nil }
        return PeerIdentity(audit: audit, code: ProductCodeIdentity.resolve(audit))
    }

    public var isCurrentUser: Bool { audit.effectiveUID == getuid() }

    public var displayDescription: String {
        if code.isVerifiedProduct {
            return "\(code.role.rawValue) [verified] (pid \(audit.pid))"
        }
        let name = ProcessAncestry.name(of: audit.pid)
            ?? audit.executablePath.map { URL(fileURLWithPath: $0).lastPathComponent }
            ?? "process"
        return "\(name) [unverified] (pid \(audit.pid))"
    }
}

private extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
