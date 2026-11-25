import Foundation
import Security
import CSecuritySupport

/// What the kernel itself says about the code an audit token names: the code
/// directory hash of the running main executable, the signing identifier and
/// Team ID recorded in that code directory, and the live code-signing status
/// flags. Every field is read with `csops_audittoken` on the complete token,
/// which the kernel refuses (ESRCH) once the token's PID version is not the
/// process's current one, so the facts describe exactly the image the token
/// named and never one exec'd after it. Nothing here reads the disk or asks
/// trustd, so it costs a few system calls however loaded the Mac is.
///
/// These are the dynamic half of `SecCodeCheckValidity`: Security.framework
/// itself asks the kernel for the same CS_OPS_STATUS and CS_OPS_CDHASH
/// (`KernelCode::getGuestStatus` / `identifyGuest`) and requires CS_VALID and
/// a kernel cdhash equal to the validated on-disk one. The static half, the
/// CMS signature and its certificate chain, is what trustd evaluates and what
/// `CodeSignatureVerdictCache` keeps per cdhash.
public struct KernelCodeFacts: Sendable, Equatable {
    /// CS_VALID (xnu `cs_blobs.h`): every page the process has loaded matched
    /// its code directory. The kernel only ever clears it within one image.
    public static let validFlag: UInt32 = 0x0000_0001
    /// CS_RUNTIME: the hardened runtime applies to the process.
    public static let hardenedRuntimeFlag: UInt32 = 0x0001_0000

    /// The CS_OPS_STATUS flags, read after every other field.
    public let statusFlags: UInt32
    /// Lowercase hex of the 20-byte cdhash, as `kSecCodeInfoUnique` reports it.
    public let cdHash: String
    public let identifier: String
    public let teamIdentifier: String?

    public init(statusFlags: UInt32, cdHash: String, identifier: String, teamIdentifier: String?) {
        self.statusFlags = statusFlags
        self.cdHash = cdHash
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
    }

    /// The kernel still considers the running image validly signed.
    public var isDynamicallyValid: Bool { statusFlags & Self.validFlag != 0 }
    public var hasHardenedRuntime: Bool { statusFlags & Self.hardenedRuntimeFlag != 0 }

    /// Nil when the kernel refuses any read: the token no longer names a live
    /// image, or the image has no code signature to report.
    public static func read(_ audit: AuditIdentity) -> KernelCodeFacts? {
        var flags: UInt32 = 0
        var cdHash = [UInt8](repeating: 0, count: 20)
        var identifier = [CChar](repeating: 0, count: 1_024)
        var team = [CChar](repeating: 0, count: 128)
        var hasTeam: Int32 = 0
        let status = audit.rawAuditToken.withUnsafeBytes { token in
            cdHash.withUnsafeMutableBufferPointer { hash in
                identifier.withUnsafeMutableBufferPointer { identifierBytes in
                    team.withUnsafeMutableBufferPointer { teamBytes in
                        cs_audit_token_code_facts(
                            token.baseAddress, Int32(token.count),
                            &flags,
                            hash.baseAddress, Int32(hash.count),
                            identifierBytes.baseAddress, Int32(identifierBytes.count),
                            teamBytes.baseAddress, Int32(teamBytes.count), &hasTeam
                        )
                    }
                }
            }
        }
        guard status == 0 else { return nil }
        let identifierText = String(cString: identifier)
        guard !identifierText.isEmpty else { return nil }
        return KernelCodeFacts(
            statusFlags: flags,
            cdHash: cdHash.map { String(format: "%02x", $0) }.joined(),
            identifier: identifierText,
            teamIdentifier: hasTeam != 0 ? String(cString: team) : nil
        )
    }
}

/// What a cached static verdict is filed under: everything the verdict
/// depends on. The cdhash names one code directory, and with it the code, the
/// entitlements, the flags, the identifier and the Team ID that directory
/// seals; the identifier and Team ID are keyed as well, as the kernel reports
/// them, so a verdict can only be found for code whose kernel-reported
/// identity is the one verified. The executable path is keyed because the
/// verdict carries the code's canonical path (a bundle's main executable
/// resolves to the bundle) and covers that location's sealed resources, such
/// as a bundle's Info.plist; a copy elsewhere is verified afresh. `policy`
/// names the requirement and validation flags the verdict answers, so a
/// verdict for one question is never an answer to another.
public struct CodeSignatureVerdictKey: Hashable, Sendable {
    public let cdHash: String
    public let identifier: String
    public let teamIdentifier: String?
    public let executablePath: String
    public let policy: String

    public init(
        cdHash: String,
        identifier: String,
        teamIdentifier: String?,
        executablePath: String,
        policy: String
    ) {
        self.cdHash = cdHash
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.executablePath = executablePath
        self.policy = policy
    }

    public init(facts: KernelCodeFacts, executablePath: String, policy: String) {
        self.init(
            cdHash: facts.cdHash,
            identifier: facts.identifier,
            teamIdentifier: facts.teamIdentifier,
            executablePath: executablePath,
            policy: policy
        )
    }
}

/// Successful static code-signing verdicts, kept for the life of the process
/// that holds them (csecd, the root helper), so a binary's signature and its
/// certificate chain are evaluated by trustd once per cdhash instead of on
/// every connection.
///
/// Why: every csec, `csec hook claude` and `ssh` connection is a new process
/// running one of a handful of binaries, and trustd answers slowly when the
/// Mac is loaded (seconds at a load average near 100), long enough for
/// `csec hook claude`'s one-second registration bound to expire. The kernel
/// facts (`KernelCodeFacts`) still prove, per connection, that the running
/// image is that cdhash and still valid; only the trustd half is reused.
///
/// The trade-off: a cached verdict outlives a revocation of the signing
/// certificate until the process restarts (every install restarts csecd and
/// the root helper). The full check never requests a revocation check: csec
/// validates with `kSecCSStrictValidate` alone, so Security.framework adds no
/// revocation policy, and trustd consults its local Valid database and OCSP
/// cache, fetching OCSP only when that database flags the certificate. A
/// binary not yet verified, such as one signed with a stolen and
/// since-revoked key, has its own cdhash and gets the full check, revocation
/// database included.
///
/// Only successes are stored: a failure may be transient (trustd timing out,
/// the process exiting mid-check), and caching it would refuse a genuine
/// binary until restart. The cache is bounded and evicts the least recently
/// used verdict; an evicted binary is simply verified again. Verdicts are
/// computed outside the lock, so a slow trustd evaluation never holds up
/// another connection's lookup; two connections that miss at once both
/// evaluate, and the second store replaces the first with the same verdict.
public final class CodeSignatureVerdictCache<Verdict: Sendable>: @unchecked Sendable {
    public let capacity: Int
    private let lock = NSLock()
    /// Read and written only under `lock`.
    private var entries: [CodeSignatureVerdictKey: Verdict] = [:]
    /// Keys from least to most recently used; read and written under `lock`.
    private var recency: [CodeSignatureVerdictKey] = []

    public init(capacity: Int) {
        self.capacity = max(1, capacity)
    }

    /// The verdict filed under `key`, which becomes the most recently used.
    public func verdict(for key: CodeSignatureVerdictKey) -> Verdict? {
        lock.lock()
        defer { lock.unlock() }
        guard let verdict = entries[key] else { return nil }
        touch(key)
        return verdict
    }

    /// File `verdict` under `key`, evicting the least recently used verdict
    /// when the cache is full.
    public func store(_ verdict: Verdict, for key: CodeSignatureVerdictKey) {
        lock.lock()
        defer { lock.unlock() }
        if entries.updateValue(verdict, forKey: key) != nil {
            touch(key)
            return
        }
        recency.append(key)
        while recency.count > capacity {
            entries[recency.removeFirst()] = nil
        }
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }

    /// Caller holds `lock`.
    private func touch(_ key: CodeSignatureVerdictKey) {
        if let index = recency.firstIndex(of: key) { recency.remove(at: index) }
        recency.append(key)
    }
}

/// A Security.framework requirement evaluated against the live code an audit
/// token names, with the static half cached per cdhash
/// (`CodeSignatureVerdictCache`). csecd's SSH agent asks it of every `ssh`
/// connection and again before every reply.
public enum LiveCodeRequirement {
    /// What one full evaluation found: whether the live code satisfied the
    /// requirement, and the cdhash of the code that was validated.
    public struct Evaluation: Sendable, Equatable {
        public let satisfied: Bool
        public let cdHash: String?

        public init(satisfied: Bool, cdHash: String?) {
            self.satisfied = satisfied
            self.cdHash = cdHash
        }
    }

    /// Satisfied requirements, by the code and the requirement text.
    public static let verdicts = CodeSignatureVerdictCache<Bool>(capacity: 64)

    /// Whether the live code `audit` names satisfies `requirement`.
    public static func isSatisfied(by audit: AuditIdentity, requirement: String) -> Bool {
        isSatisfied(by: audit, requirement: requirement, verdicts: verdicts)
    }

    /// The same check with its parts injectable for tests. The kernel facts
    /// are read for every call; a cached verdict is used only while they say
    /// the image is still valid, and a full evaluation is stored only when it
    /// succeeded for exactly the cdhash the kernel reported.
    public static func isSatisfied(
        by audit: AuditIdentity,
        requirement: String,
        verdicts: CodeSignatureVerdictCache<Bool>,
        kernelFacts: (AuditIdentity) -> KernelCodeFacts? = KernelCodeFacts.read,
        evaluate: (AuditIdentity, String) -> Evaluation = LiveCodeRequirement.evaluate
    ) -> Bool {
        guard let facts = kernelFacts(audit), facts.isDynamicallyValid,
              let path = audit.executablePath else {
            return evaluate(audit, requirement).satisfied
        }
        let key = CodeSignatureVerdictKey(
            facts: facts,
            executablePath: path,
            policy: "strict-validate; requirement: \(requirement)"
        )
        if verdicts.verdict(for: key) == true { return true }
        let evaluation = evaluate(audit, requirement)
        if evaluation.satisfied, evaluation.cdHash == facts.cdHash {
            verdicts.store(true, for: key)
        }
        return evaluation.satisfied
    }

    /// The full Security.framework check, with no cache: locate the live code
    /// by the complete audit token and validate it, statically and
    /// dynamically, against `requirement`.
    public static func evaluate(_ audit: AuditIdentity, requirement text: String) -> Evaluation {
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(
            nil,
            [kSecGuestAttributeAudit: audit.rawAuditToken as CFData] as CFDictionary,
            SecCSFlags(rawValue: 0),
            &code
        ) == errSecSuccess, let code else { return Evaluation(satisfied: false, cdHash: nil) }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            text as CFString, SecCSFlags(rawValue: 0), &requirement
        ) == errSecSuccess, let requirement else { return Evaluation(satisfied: false, cdHash: nil) }
        guard SecCodeCheckValidity(
            code, SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)), requirement
        ) == errSecSuccess else { return Evaluation(satisfied: false, cdHash: nil) }
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopyStaticCode(code, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
              let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: 0), &information) == errSecSuccess,
              let unique = (information as? [String: Any])?[kSecCodeInfoUnique as String] as? Data else {
            return Evaluation(satisfied: true, cdHash: nil)
        }
        return Evaluation(satisfied: true, cdHash: unique.map { String(format: "%02x", $0) }.joined())
    }
}
