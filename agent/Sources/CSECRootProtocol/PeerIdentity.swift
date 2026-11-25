import Foundation
import Security
import CSecuritySupport
import CSECBuildIdentity

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

    /// The audit token of an arbitrary same-user process, read from its task
    /// name port rather than from a socket. Its PID version changes on exec,
    /// so a code identity resolved from it names exactly one image. The kernel
    /// may refuse the name port (another real UID, a MAC policy, or no such
    /// process); that refusal is returned with its kern_return_t so the caller
    /// can fall back and say why. A failure after the port was granted is
    /// `.changed`, never a refusal: the process it named is gone or replaced.
    public static func task(pid: pid_t) -> TaskAuditTokenLookup {
        var tokenBuffer = [UInt8](repeating: 0, count: 64)
        var kernelStatus: Int32 = 0
        let tokenLength = tokenBuffer.withUnsafeMutableBytes { bytes in
            cs_task_audit_token(pid, bytes.baseAddress, Int32(bytes.count), &kernelStatus)
        }
        let failureStatus = kernelStatus == 0 ? KERN_FAILURE : kernelStatus
        if tokenLength == -1 { return .refused(kernelStatus: failureStatus) }
        guard tokenLength > 0, tokenLength <= tokenBuffer.count else {
            return .changed(kernelStatus: failureStatus)
        }
        let token = Data(tokenBuffer.prefix(Int(tokenLength)))
        let tokenPID = token.withUnsafeBytes {
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
        guard tokenPID == pid, pidVersion >= 0, effectiveUID != UInt32.max,
              auditSessionID != UInt32.max else {
            return .changed(kernelStatus: KERN_FAILURE)
        }
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
        return .token(AuditIdentity(
            rawAuditToken: token,
            pid: pid,
            pidVersion: pidVersion,
            effectiveUID: effectiveUID,
            auditSessionID: auditSessionID,
            executablePath: pathLength > 0 ? String(cString: pathBuffer) : nil,
            startTime: cs_proc_start_time(pid)
        ))
    }
}

/// The result of asking the kernel for another process's audit token.
public enum TaskAuditTokenLookup: Sendable {
    case token(AuditIdentity)
    /// `task_name_for_pid` refused the name port with this kern_return_t. The
    /// only case in which a PID-based lookup may stand in for the token.
    case refused(kernelStatus: Int32)
    /// The name port was granted, but the token could not be read or did not
    /// name the PID: the task exited or the PID was reused in between. Nothing
    /// may stand in for the token; the process is not the one asked about.
    case changed(kernelStatus: Int32)
}

/// Product roles have separate, exact signing identifiers. A matching Team ID
/// alone is insufficient: another binary signed by the same developer must not
/// be accepted as either endpoint.
public enum ProductCodeRole: String, Sendable, CaseIterable {
    case agent
    case launcher
    case rootHelper = "root_helper"
    /// `csec-sudo-review`, the helper the sudo PAM module spawns. csecd takes
    /// exactly one request from it: mirroring its sudo review to the paired
    /// phone (`sudo_remote_review`).
    case sudoReviewHelper = "sudo_review_helper"
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
    public static let teamIdentifier = CSECBuildIdentity.teamIdentifier
    public static let agentIdentifier = CSECBuildIdentity.identifier
    public static let launcherIdentifier = CSECBuildIdentity.named("csec")
    public static let rootHelperIdentifier = CSECBuildIdentity.named("rootd")
    /// As `packaging/bin/build-sudo-review.sh` signs the helper, and as the PAM
    /// module checks it before handing it a review.
    public static let sudoReviewHelperIdentifier = CSECBuildIdentity.named("sudo-review")
    public static let forbiddenEntitlements = [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.debugger",
    ]

    /// Static verdicts of `evaluate`, kept for the life of this process; see
    /// `CodeSignatureVerdictCache` for why, and for the revocation trade-off.
    public static let staticVerdicts = CodeSignatureVerdictCache<CodeIdentity>(capacity: 64)

    /// What a product verdict answers: strict validation, the forbidden
    /// entitlements, and every role's requirement. Part of each verdict's key.
    public static let verdictPolicy: String = {
        let requirements = [
            agentIdentifier, launcherIdentifier, rootHelperIdentifier, sudoReviewHelperIdentifier,
        ].map(requirement(identifier:))
        return "strict-validate; roles: \(requirements.joined(separator: "; ")); "
            + "forbidden entitlements: \(forbiddenEntitlements.joined(separator: ", "))"
    }()

    /// The product identity of the live code the complete audit token names.
    ///
    /// The kernel is asked first, for this connection: the image the token
    /// names must still be valid (CS_VALID), and its cdhash, identifier, Team
    /// ID and path select a static verdict. A verdict csecd already holds is
    /// returned as it stands; it was produced by `evaluate` for that exact
    /// code directory, and the kernel has just proved the running image is
    /// that code directory. Only a binary not yet seen pays for `evaluate`,
    /// whose certificate-chain evaluation waits on trustd. When the kernel
    /// facts cannot be read (the process exited or exec'd, or reports no
    /// signature), `evaluate` alone decides, exactly as before the cache.
    public static func resolve(_ audit: AuditIdentity) -> CodeIdentity {
        resolve(audit, verdicts: staticVerdicts)
    }

    /// `resolve` with its parts injectable for tests: the cache, the kernel
    /// read, and the full Security.framework evaluation.
    public static func resolve(
        _ audit: AuditIdentity,
        verdicts: CodeSignatureVerdictCache<CodeIdentity>,
        kernelFacts: (AuditIdentity) -> KernelCodeFacts? = KernelCodeFacts.read,
        evaluate: (AuditIdentity) -> CodeIdentity = ProductCodeIdentity.evaluate
    ) -> CodeIdentity {
        guard let facts = kernelFacts(audit), facts.isDynamicallyValid,
              let path = audit.executablePath else { return evaluate(audit) }
        let key = CodeSignatureVerdictKey(facts: facts, executablePath: path, policy: verdictPolicy)
        // The hardened runtime is sealed in the code directory, so the kernel
        // reports it for every image of a cached cdhash; a disagreement is
        // never resolved in the cache's favour.
        if let cached = verdicts.verdict(for: key),
           !cached.hardenedRuntime || facts.hasHardenedRuntime {
            return cached
        }
        let identity = evaluate(audit)
        if isCacheable(identity, for: facts) {
            verdicts.store(identity, for: key)
        }
        return identity
    }

    /// Whether a fresh `evaluate` result may answer later connections from
    /// the same code. Only a valid signature, for exactly the code directory
    /// the kernel reported, qualifies. Its role must also be the one its
    /// metadata implies: a product-shaped identity that still came back
    /// `.other` failed its requirement, either because the signature is not
    /// the product's (which the next full check will find again) or because
    /// the process went away between the two Security.framework calls, and
    /// neither may be filed as the binary's verdict.
    public static func isCacheable(_ identity: CodeIdentity, for facts: KernelCodeFacts) -> Bool {
        identity.signatureValid
            && identity.cdHash == facts.cdHash
            && identity.identifier == facts.identifier
            && identity.teamIdentifier == facts.teamIdentifier
            && identity.role == metadataRole(
                identifier: identity.identifier,
                teamIdentifier: identity.teamIdentifier,
                signatureValid: identity.signatureValid,
                hardenedRuntime: identity.hardenedRuntime,
                dangerousEntitlements: identity.dangerousEntitlements
            )
    }

    /// The full check, with no cache: resolve a dynamic `SecCode` from the
    /// complete audit token, check its live validity, and then evaluate the
    /// exact product requirement. Its certificate-chain evaluation is a
    /// trustd round trip.
    public static func evaluate(_ audit: AuditIdentity) -> CodeIdentity {
        evaluate(
            attributes: [kSecGuestAttributeAudit: audit.rawAuditToken as CFData] as CFDictionary,
            kernelPath: audit.executablePath
        )
    }

    /// The product identity of another live process, which must still be the
    /// incarnation that started at `startTime`: SSH lazy binding's `csec ai`,
    /// which is no socket peer. The audit-token path comes first; only when
    /// `task_name_for_pid` itself refuses does the lookup fall back to the PID,
    /// exactly as `ForeignCodeIdentity.resolve` does, and `lookup` says which
    /// path ran. A token that could not be read after the name port was
    /// granted (`.changed`) returns nil. The start time is re-read before and
    /// after the Security.framework work, so a reused PID returns nil.
    /// `taskAuditToken` is a seam for tests that must drive the fallback.
    public static func resolve(
        pid: pid_t,
        startTime: UInt64,
        taskAuditToken: (pid_t) -> TaskAuditTokenLookup = { AuditIdentity.task(pid: $0) }
    ) -> (identity: CodeIdentity, lookup: ForeignCodeIdentity.Lookup)? {
        guard pid > 1, startTime > 0, cs_proc_start_time(pid) == startTime else { return nil }
        let identity: CodeIdentity
        let lookup: ForeignCodeIdentity.Lookup
        switch taskAuditToken(pid) {
        case let .token(audit):
            guard audit.pid == pid, audit.startTime == startTime else { return nil }
            identity = resolve(audit)
            lookup = .auditToken(pidVersion: audit.pidVersion)
        case .changed:
            return nil
        case let .refused(status):
            // No token, so nothing exec-exact to key a verdict on: the PID
            // fallback always takes the full check.
            identity = evaluate(
                attributes: [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary,
                kernelPath: ProcessAncestry.executablePath(of: pid)
            )
            lookup = .processID(taskNameStatus: status)
        }
        guard cs_proc_start_time(pid) == startTime else { return nil }
        return (identity, lookup)
    }

    private static func evaluate(attributes: CFDictionary, kernelPath: String?) -> CodeIdentity {
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
                executablePath: kernelPath,
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
        let resolvedPath = pathStatus == errSecSuccess ? (codePath as URL?)?.path : kernelPath

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
        } else if signatureValid, hardenedRuntime, dangerousEntitlements.isEmpty,
                  identifier == sudoReviewHelperIdentifier,
                  teamIdentifier == self.teamIdentifier,
                  satisfiesRequirement(code, identifier: sudoReviewHelperIdentifier) {
            role = .sudoReviewHelper
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
        case sudoReviewHelperIdentifier: return .sudoReviewHelper
        default: return .other
        }
    }

    /// `anchor apple generic` plus the leaf OU makes this a Developer ID
    /// requirement for this exact team and signing identifier.
    static func requirement(identifier: String) -> String {
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamIdentifier)\" and identifier \"\(identifier)\""
    }

    private static func satisfiesRequirement(_ code: SecCode, identifier: String) -> Bool {
        // This is more than a metadata comparison: Security.framework
        // evaluates the requirement against the live, kernel-selected code
        // object.
        let text = Self.requirement(identifier: identifier)
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

/// The validated code identity of another live process: one that is neither a
/// socket peer nor one of csec's own products, such as the coding agent a
/// request descends from.
///
/// `ProductCodeIdentity.resolve` is deliberately not reused. It classifies any
/// binary holding disable-library-validation, allow-jit or
/// allow-unsigned-executable-memory as `.other`, and Anthropic's Claude Code
/// holds all three. This type reports what the live signature is and which
/// requirements it satisfies; the caller decides what to trust. Like
/// `CodeIdentity`, it retains no `SecCode` across concurrency boundaries.
public struct ForeignCodeIdentity: Sendable, Equatable {
    /// Anthropic's designated requirement for Claude Code, verbatim from
    /// `codesign -d -r-` on 2.1.280 without codesign's `/* exists */`
    /// annotations, which compile to the same requirement. It is unchanged
    /// across auto-updates. bin/ci requires this literal to appear exactly
    /// once, here, so it cannot be weakened or shadowed silently.
    public static let anthropicClaudeCodeRequirement = #"identifier "com.anthropic.claude-code" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = Q6L2SF6YDW"#

    /// How the live code object was located.
    public enum Lookup: Sendable, Equatable {
        /// `task_name_for_pid` → `TASK_AUDIT_TOKEN` → `kSecGuestAttributeAudit`.
        /// Exec-exact: the token's PID version names one image, so an exec
        /// between the lookup and the checks fails validation.
        case auditToken(pidVersion: Int32)
        /// `kSecGuestAttributePid`, used only when the kernel refused the task
        /// name port; `taskNameStatus` is the kern_return_t it gave. PID reuse
        /// is still closed by the start-time and parent re-reads around the
        /// checks, but an exec by the same process in between is not.
        case processID(taskNameStatus: Int32)

        public var isExecExact: Bool {
            if case .auditToken = self { return true }
            return false
        }

        /// Value-free text for logs and diagnostics: which path ran and
        /// whether it is exec-exact. Delegation records it on every decision
        /// that resolved Claude Code's identity, and `csec status` shows the
        /// latest, so whether the signed csecd is refused the task name port
        /// can be read on the device.
        public var logDescription: String {
            switch self {
            case .auditToken: return "audit-token (exec-exact)"
            case let .processID(status):
                return "pid fallback (not exec-exact; task_name_for_pid refused: kern_return \(status))"
            }
        }
    }

    public let pid: pid_t
    public let startTime: UInt64
    public let lookup: Lookup
    public let identifier: String?
    public let teamIdentifier: String?
    /// Lowercase hex of the code directory hash (`kSecCodeInfoUnique`).
    public let cdHash: String?
    public let executablePath: String?
    /// Strict dynamic validity (`kSecCSStrictValidate`) with readable signing
    /// information. Every requirement below is false unless this holds.
    public let signatureValid: Bool
    public let hardenedRuntime: Bool
    /// The OS release identifier for code signed as part of macOS, else nil.
    public let platformIdentifier: Int?
    /// Sorted entitlement keys. Values are never retained.
    public let entitlementKeys: [String]
    /// Satisfies `anchor apple`: signed by Apple itself, as OS binaries are.
    public let appleAnchored: Bool
    /// Satisfies `anthropicClaudeCodeRequirement`.
    public let satisfiesAnthropicRequirement: Bool
    /// The caller-trusted cdhash the live code satisfied as `cdhash H"…"`.
    public let trustedCDHash: String?
    /// errSecSuccess, or the first Security.framework failure.
    public let status: Int32

    /// Genuine Claude Code, or a build the user trusted by cdhash.
    public var isClaudeCode: Bool {
        signatureValid && (satisfiesAnthropicRequirement || trustedCDHash != nil)
    }

    /// An Apple-signed binary shipped as part of macOS.
    public var isApplePlatformBinary: Bool {
        signatureValid && appleAnchored && platformIdentifier != nil
    }

    /// Resolve and validate the live code of `pid`, which must still be the
    /// incarnation that started at `startTime`.
    ///
    /// The audit-token path is tried first. Only if `task_name_for_pid` itself
    /// refuses does the lookup fall back to the PID, and `lookup` says so; a
    /// failure after the name port was granted (`.changed`) returns nil.
    /// Before and after the Security.framework work the start time is re-read,
    /// and when `child` is given, `ppid(child) == pid` is re-read too: a walk
    /// that found this process as `child`'s parent stays valid only if the
    /// parent never died in between. Any failed re-read returns nil; a
    /// signature that does not validate returns an identity whose
    /// `signatureValid` is false.
    ///
    /// `trustedCDHashes` are 40 lowercase hex digits; anything else is ignored,
    /// so no caller-supplied text reaches the requirement compiler.
    /// `taskAuditToken` is a seam for tests that must drive the fallback.
    public static func resolve(
        pid: pid_t,
        startTime: UInt64,
        parentOf child: pid_t? = nil,
        trustedCDHashes: Set<String> = [],
        taskAuditToken: (pid_t) -> TaskAuditTokenLookup = { AuditIdentity.task(pid: $0) }
    ) -> ForeignCodeIdentity? {
        guard pid > 1, startTime > 0,
              incarnationHolds(pid: pid, startTime: startTime, child: child) else { return nil }

        let lookup: Lookup
        let attributes: CFDictionary
        let kernelPath: String?
        switch taskAuditToken(pid) {
        case let .token(audit):
            guard audit.pid == pid, audit.startTime == startTime else { return nil }
            lookup = .auditToken(pidVersion: audit.pidVersion)
            attributes = [kSecGuestAttributeAudit: audit.rawAuditToken as CFData] as CFDictionary
            kernelPath = audit.executablePath
        case .changed:
            return nil
        case let .refused(status):
            lookup = .processID(taskNameStatus: status)
            attributes = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
            kernelPath = ProcessAncestry.executablePath(of: pid)
        }

        let identity = evaluate(
            attributes: attributes,
            pid: pid,
            startTime: startTime,
            lookup: lookup,
            kernelPath: kernelPath,
            trustedCDHashes: trustedCDHashes
        )
        guard incarnationHolds(pid: pid, startTime: startTime, child: child) else { return nil }
        return identity
    }

    public init(
        pid: pid_t,
        startTime: UInt64,
        lookup: Lookup,
        identifier: String?,
        teamIdentifier: String?,
        cdHash: String?,
        executablePath: String?,
        signatureValid: Bool,
        hardenedRuntime: Bool,
        platformIdentifier: Int?,
        entitlementKeys: [String],
        appleAnchored: Bool,
        satisfiesAnthropicRequirement: Bool,
        trustedCDHash: String?,
        status: Int32
    ) {
        self.pid = pid
        self.startTime = startTime
        self.lookup = lookup
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.cdHash = cdHash
        self.executablePath = executablePath
        self.signatureValid = signatureValid
        self.hardenedRuntime = hardenedRuntime
        self.platformIdentifier = platformIdentifier
        self.entitlementKeys = entitlementKeys
        self.appleAnchored = appleAnchored
        self.satisfiesAnthropicRequirement = satisfiesAnthropicRequirement
        self.trustedCDHash = trustedCDHash
        self.status = status
    }

    /// Whether `text` is a cdhash this type will put into a requirement.
    public static func isWellFormedCDHash(_ text: String) -> Bool {
        text.utf8.count == 40 && text.utf8.allSatisfy { byte in
            (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
        }
    }

    private static func incarnationHolds(pid: pid_t, startTime: UInt64, child: pid_t?) -> Bool {
        guard cs_proc_start_time(pid) == startTime else { return false }
        if let child, cs_proc_ppid(child) != pid { return false }
        return true
    }

    private static func evaluate(
        attributes: CFDictionary,
        pid: pid_t,
        startTime: UInt64,
        lookup: Lookup,
        kernelPath: String?,
        trustedCDHashes: Set<String>
    ) -> ForeignCodeIdentity {
        var code: SecCode?
        let lookupStatus = SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(rawValue: 0), &code)
        guard lookupStatus == errSecSuccess, let code else {
            return ForeignCodeIdentity(
                pid: pid, startTime: startTime, lookup: lookup,
                identifier: nil, teamIdentifier: nil, cdHash: nil, executablePath: kernelPath,
                signatureValid: false, hardenedRuntime: false, platformIdentifier: nil,
                entitlementKeys: [], appleAnchored: false, satisfiesAnthropicRequirement: false,
                trustedCDHash: nil, status: lookupStatus
            )
        }

        let strict = SecCSFlags(rawValue: UInt32(kSecCSStrictValidate))
        let validityStatus = SecCodeCheckValidity(code, strict, nil)

        var staticCode: SecStaticCode?
        let staticCodeStatus = SecCodeCopyStaticCode(code, SecCSFlags(rawValue: 0), &staticCode)
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
        let platform = (dictionary?[kSecCodeInfoPlatformIdentifier as String] as? NSNumber)?.intValue
        let entitlements = dictionary?[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]

        var codePath: CFURL?
        let pathStatus = staticCode.map { SecCodeCopyPath($0, SecCSFlags(rawValue: 0), &codePath) }
            ?? staticCodeStatus
        let resolvedPath = pathStatus == errSecSuccess ? (codePath as URL?)?.path : kernelPath

        let signatureValid = validityStatus == errSecSuccess && informationStatus == errSecSuccess
        func satisfies(_ text: String) -> Bool {
            guard signatureValid else { return false }
            var requirement: SecRequirement?
            guard SecRequirementCreateWithString(
                text as CFString, SecCSFlags(rawValue: 0), &requirement
            ) == errSecSuccess, let requirement else { return false }
            return SecCodeCheckValidity(code, strict, requirement) == errSecSuccess
        }
        // A cdhash that is not in the trusted set cannot satisfy any of its
        // requirements, so only a candidate the signature names is compiled.
        let trustedCDHash = cdHash.flatMap { candidate in
            trustedCDHashes.contains(candidate) && isWellFormedCDHash(candidate)
                && satisfies("cdhash H\"\(candidate)\"") ? candidate : nil
        }

        return ForeignCodeIdentity(
            pid: pid,
            startTime: startTime,
            lookup: lookup,
            identifier: identifier,
            teamIdentifier: teamIdentifier,
            cdHash: cdHash,
            executablePath: resolvedPath,
            signatureValid: signatureValid,
            hardenedRuntime: flags & 0x0001_0000 != 0, // CS_RUNTIME
            platformIdentifier: platform.flatMap { $0 > 0 ? $0 : nil },
            entitlementKeys: entitlements.keys.sorted(),
            appleAnchored: satisfies("anchor apple"),
            satisfiesAnthropicRequirement: satisfies(anthropicClaudeCodeRequirement),
            trustedCDHash: trustedCDHash,
            status: signatureValid ? Int32(errSecSuccess) : Int32(validityStatus != errSecSuccess ? validityStatus : informationStatus)
        )
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
