import Foundation
import Security
import ConvenientSecurity
import Darwin

// The per-cdhash static verdict cache behind every socket peer's code
// identity check (csec-9gj0): the cache itself, the rules for what may be
// filed and when a filed verdict may answer, and the live checks that a
// second process of the same real binary is answered from the kernel's facts
// alone while a stale or exec'd token still fails.

func codeSignatureVerdictTests() {
    print("\n# Code-signature verdict cache (per-cdhash static verdicts)")
    verdictCacheUnitTests()
    productResolveRuleTests()
    liveCodeRequirementRuleTests()
    liveVerdictTests()
}

private let syntheticCDHash = String(repeating: "ab", count: 20)
private let otherCDHash = String(repeating: "cd", count: 20)

private func key(
    cdHash: String = syntheticCDHash,
    identifier: String = "com.example.tool",
    team: String? = "ABCDE12345",
    path: String = "/opt/example/tool",
    policy: String = "policy-a"
) -> CodeSignatureVerdictKey {
    CodeSignatureVerdictKey(
        cdHash: cdHash, identifier: identifier, teamIdentifier: team,
        executablePath: path, policy: policy
    )
}

private func verdictCacheUnitTests() {
    let cache = CodeSignatureVerdictCache<Int>(capacity: 8)
    let base = key()
    check(cache.verdict(for: base) == nil && cache.count == 0,
          "verdict cache: an empty cache answers nothing")
    cache.store(1, for: base)
    check(cache.verdict(for: base) == 1 && cache.count == 1,
          "verdict cache: a stored verdict is found under its key")
    cache.store(2, for: base)
    check(cache.verdict(for: base) == 2 && cache.count == 1,
          "verdict cache: storing under the same key replaces, never duplicates")

    let variants: [(String, CodeSignatureVerdictKey)] = [
        ("cdhash", key(cdHash: otherCDHash)),
        ("identifier", key(identifier: "com.example.other")),
        ("Team ID", key(team: "ZYXWV98765")),
        ("absent Team ID", key(team: nil)),
        ("executable path", key(path: "/tmp/copy/tool")),
        ("policy", key(policy: "policy-b")),
    ]
    for (field, variant) in variants {
        check(cache.verdict(for: variant) == nil,
              "verdict cache: a key differing only in its \(field) finds nothing")
    }

    let bounded = CodeSignatureVerdictCache<Int>(capacity: 3)
    let first = key(cdHash: String(repeating: "01", count: 20))
    let second = key(cdHash: String(repeating: "02", count: 20))
    let third = key(cdHash: String(repeating: "03", count: 20))
    let fourth = key(cdHash: String(repeating: "04", count: 20))
    bounded.store(1, for: first)
    bounded.store(2, for: second)
    bounded.store(3, for: third)
    _ = bounded.verdict(for: first) // the least recently used is now `second`
    bounded.store(4, for: fourth)
    check(bounded.count == 3, "verdict cache: never holds more than its capacity")
    check(bounded.verdict(for: second) == nil,
          "verdict cache: a full cache evicts the least recently used verdict")
    check(bounded.verdict(for: first) == 1 && bounded.verdict(for: third) == 3
            && bounded.verdict(for: fourth) == 4,
          "verdict cache: a recently used verdict survives the eviction")
}

/// The selftest's own audit token: the rule tests below inject the kernel
/// facts and the evaluation, so only the token's path is read.
private func selfAudit() -> AuditIdentity? {
    guard case let .token(audit) = AuditIdentity.task(pid: getpid()), audit.executablePath != nil else {
        return nil
    }
    return audit
}

private func facts(
    cdHash: String = syntheticCDHash,
    identifier: String = ProductCodeIdentity.launcherIdentifier,
    team: String? = ProductCodeIdentity.teamIdentifier,
    valid: Bool = true,
    hardened: Bool = true
) -> KernelCodeFacts {
    var flags: UInt32 = 0
    if valid { flags |= KernelCodeFacts.validFlag }
    if hardened { flags |= KernelCodeFacts.hardenedRuntimeFlag }
    return KernelCodeFacts(statusFlags: flags, cdHash: cdHash, identifier: identifier, teamIdentifier: team)
}

private func launcherIdentity(
    cdHash: String = syntheticCDHash,
    identifier: String = ProductCodeIdentity.launcherIdentifier,
    team: String? = ProductCodeIdentity.teamIdentifier,
    signatureValid: Bool = true,
    role: ProductCodeRole = .launcher
) -> CodeIdentity {
    CodeIdentity(
        identifier: identifier,
        teamIdentifier: team,
        cdHash: cdHash,
        executablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec",
        signatureValid: signatureValid,
        hardenedRuntime: true,
        dangerousEntitlements: [],
        role: role,
        status: signatureValid ? errSecSuccess : errSecCSSignatureFailed
    )
}

private func sameIdentity(_ left: CodeIdentity, _ right: CodeIdentity) -> Bool {
    left.identifier == right.identifier && left.teamIdentifier == right.teamIdentifier
        && left.cdHash == right.cdHash && left.executablePath == right.executablePath
        && left.signatureValid == right.signatureValid && left.hardenedRuntime == right.hardenedRuntime
        && left.dangerousEntitlements == right.dangerousEntitlements && left.role == right.role
        && left.status == right.status
}

private func productResolveRuleTests() {
    guard let audit = selfAudit() else {
        check(false, "product verdicts: this process's own audit token is readable")
        return
    }

    // A valid launcher verdict is evaluated once and then answered from the
    // cache while the kernel keeps reporting the same valid image.
    do {
        let cache = CodeSignatureVerdictCache<CodeIdentity>(capacity: 8)
        var evaluations = 0
        let resolve = {
            ProductCodeIdentity.resolve(audit, verdicts: cache, kernelFacts: { _ in facts() }) { _ in
                evaluations += 1
                return launcherIdentity()
            }
        }
        let first = resolve()
        let second = resolve()
        check(evaluations == 1 && cache.count == 1,
              "product verdicts: a second connection from the same valid image skips the full evaluation")
        check(sameIdentity(first, second) && second.role == .launcher && second.isVerifiedProduct,
              "product verdicts: the cached answer is the evaluated identity, field for field")

        // CS_VALID cleared: the cached verdict must not answer.
        var evaluatedInvalid = false
        let invalid = ProductCodeIdentity.resolve(
            audit, verdicts: cache, kernelFacts: { _ in facts(valid: false) }
        ) { _ in
            evaluatedInvalid = true
            return launcherIdentity(signatureValid: false, role: .other)
        }
        check(evaluatedInvalid && !invalid.signatureValid && invalid.role == .other,
              "product verdicts: an image the kernel no longer calls valid gets the full check, not the cached verdict")

        // No kernel facts at all (process gone, token stale): the full check
        // decides and nothing is filed.
        var evaluatedGone = false
        let gone = ProductCodeIdentity.resolve(audit, verdicts: cache, kernelFacts: { _ in nil }) { _ in
            evaluatedGone = true
            return .unverified
        }
        check(evaluatedGone && !gone.signatureValid && cache.count == 1,
              "product verdicts: unreadable kernel facts mean the full check decides, and nothing is filed")

        // The hardened runtime is sealed in the code directory: a kernel that
        // does not report it for a cached hardened verdict is not trusted.
        var evaluatedRuntime = false
        _ = ProductCodeIdentity.resolve(
            audit, verdicts: cache, kernelFacts: { _ in facts(hardened: false) }
        ) { _ in
            evaluatedRuntime = true
            return launcherIdentity(signatureValid: false, role: .other)
        }
        check(evaluatedRuntime,
              "product verdicts: a cached hardened verdict never answers for an image the kernel reports without CS_RUNTIME")

        // Another cdhash, identifier or Team ID is another key.
        for (label, variant) in [
            ("cdhash", facts(cdHash: otherCDHash)),
            ("identifier", facts(identifier: ProductCodeIdentity.agentIdentifier)),
            ("Team ID", facts(team: "ZYXWV98765")),
        ] {
            var evaluated = false
            _ = ProductCodeIdentity.resolve(audit, verdicts: cache, kernelFacts: { _ in variant }) { _ in
                evaluated = true
                return .unverified
            }
            check(evaluated, "product verdicts: kernel facts with another \(label) are evaluated afresh")
        }
    }

    // What may never be filed as a binary's verdict.
    let uncacheable: [(String, KernelCodeFacts, CodeIdentity)] = [
        ("an invalid signature", facts(), launcherIdentity(signatureValid: false, role: .other)),
        ("a product-shaped identity whose requirement failed", facts(), launcherIdentity(role: .other)),
        ("a verdict for another cdhash than the kernel's", facts(), launcherIdentity(cdHash: otherCDHash)),
        ("a verdict for another identifier than the kernel's",
         facts(identifier: ProductCodeIdentity.agentIdentifier), launcherIdentity()),
        ("a verdict for another Team ID than the kernel's", facts(team: nil), launcherIdentity()),
    ]
    for (label, kernel, evaluated) in uncacheable {
        let cache = CodeSignatureVerdictCache<CodeIdentity>(capacity: 8)
        var evaluations = 0
        for _ in 0..<2 {
            _ = ProductCodeIdentity.resolve(audit, verdicts: cache, kernelFacts: { _ in kernel }) { _ in
                evaluations += 1
                return evaluated
            }
        }
        check(evaluations == 2 && cache.count == 0 && !ProductCodeIdentity.isCacheable(evaluated, for: kernel),
              "product verdicts: \(label) is never filed, so every connection is checked in full")
    }

    // A validly signed non-product (ssh, say) is a static fact like any other.
    let other = CodeIdentity(
        identifier: "com.apple.ssh", teamIdentifier: nil, cdHash: syntheticCDHash,
        executablePath: "/usr/bin/ssh", signatureValid: true, hardenedRuntime: true,
        dangerousEntitlements: [], role: .other, status: errSecSuccess
    )
    check(ProductCodeIdentity.isCacheable(other, for: facts(identifier: "com.apple.ssh", team: nil)),
          "product verdicts: a valid signature whose metadata names no product role is filed as .other")
}

private func liveCodeRequirementRuleTests() {
    guard let audit = selfAudit() else {
        check(false, "requirement verdicts: this process's own audit token is readable")
        return
    }
    let requirement = "anchor apple and identifier \"com.example.tool\""
    let kernel = facts(identifier: "com.example.tool", team: nil)

    let cache = CodeSignatureVerdictCache<Bool>(capacity: 8)
    var evaluations = 0
    for _ in 0..<2 {
        check(LiveCodeRequirement.isSatisfied(
            by: audit, requirement: requirement, verdicts: cache, kernelFacts: { _ in kernel }
        ) { _, _ in
            evaluations += 1
            return .init(satisfied: true, cdHash: syntheticCDHash)
        }, "requirement verdicts: a satisfied requirement is satisfied")
    }
    check(evaluations == 1 && cache.count == 1,
          "requirement verdicts: a satisfied requirement is evaluated once per cdhash")

    var otherRequirementEvaluated = false
    _ = LiveCodeRequirement.isSatisfied(
        by: audit, requirement: "anchor apple and identifier \"com.example.other\"",
        verdicts: cache, kernelFacts: { _ in kernel }
    ) { _, _ in
        otherRequirementEvaluated = true
        return .init(satisfied: false, cdHash: nil)
    }
    check(otherRequirementEvaluated,
          "requirement verdicts: a verdict for one requirement never answers another")

    var invalidEvaluated = false
    let invalid = LiveCodeRequirement.isSatisfied(
        by: audit, requirement: requirement, verdicts: cache,
        kernelFacts: { _ in facts(identifier: "com.example.tool", team: nil, valid: false) }
    ) { _, _ in
        invalidEvaluated = true
        return .init(satisfied: false, cdHash: nil)
    }
    check(invalidEvaluated && !invalid,
          "requirement verdicts: an image the kernel no longer calls valid gets the full check")

    for (label, evaluation) in [
        ("an unsatisfied requirement", LiveCodeRequirement.Evaluation(satisfied: false, cdHash: syntheticCDHash)),
        ("a satisfied requirement for another cdhash",
         LiveCodeRequirement.Evaluation(satisfied: true, cdHash: otherCDHash)),
        ("a satisfied requirement whose cdhash was unreadable",
         LiveCodeRequirement.Evaluation(satisfied: true, cdHash: nil)),
    ] {
        let fresh = CodeSignatureVerdictCache<Bool>(capacity: 8)
        var count = 0
        for _ in 0..<2 {
            _ = LiveCodeRequirement.isSatisfied(
                by: audit, requirement: requirement, verdicts: fresh, kernelFacts: { _ in kernel }
            ) { _, _ in
                count += 1
                return evaluation
            }
        }
        check(count == 2 && fresh.count == 0,
              "requirement verdicts: \(label) is never filed")
    }
}

// MARK: - Live

private func spawn(_ path: String, _ arguments: [String], input: Pipe? = nil) -> Process? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    process.standardInput = input ?? FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
    } catch {
        return nil
    }
    return process
}

private func stop(_ process: Process) {
    if process.isRunning { process.terminate() }
    process.waitUntilExit()
}

private func liveAudit(of process: Process) -> AuditIdentity? {
    guard case let .token(audit) = AuditIdentity.task(pid: process.processIdentifier) else { return nil }
    return audit
}

private func liveVerdictTests() {
    guard let first = spawn("/bin/sleep", ["30"]), let second = spawn("/bin/sleep", ["30"]) else {
        check(false, "live verdicts: two /bin/sleep processes start")
        return
    }
    defer {
        stop(first)
        stop(second)
    }
    guard let firstAudit = liveAudit(of: first), let secondAudit = liveAudit(of: second) else {
        check(false, "live verdicts: both processes' audit tokens are readable")
        return
    }

    let firstFacts = KernelCodeFacts.read(firstAudit)
    let uncached = ProductCodeIdentity.evaluate(firstAudit)
    check(firstFacts?.isDynamicallyValid == true && firstFacts?.identifier == "com.apple.sleep"
            && firstFacts?.teamIdentifier == nil,
          "live verdicts: the kernel reports /bin/sleep as valid, with its identifier and no Team ID")
    check(firstFacts.map { ForeignCodeIdentity.isWellFormedCDHash($0.cdHash) } == true
            && firstFacts?.cdHash == uncached.cdHash,
          "live verdicts: the kernel's cdhash is the one Security.framework validates")
    check(KernelCodeFacts.read(secondAudit)?.cdHash == firstFacts?.cdHash,
          "live verdicts: two processes of one binary report one cdhash")

    // The hook's shape: a new process of the same binary on every call.
    let cache = CodeSignatureVerdictCache<CodeIdentity>(capacity: 8)
    var evaluations = 0
    let counted: (AuditIdentity) -> CodeIdentity = {
        evaluations += 1
        return ProductCodeIdentity.evaluate($0)
    }
    let firstResolved = ProductCodeIdentity.resolve(firstAudit, verdicts: cache, evaluate: counted)
    check(evaluations == 1 && firstResolved.signatureValid && firstResolved.role == .other
            && cache.count == 1,
          "live verdicts: the first process of a binary is evaluated in full and filed")
    let secondResolved = ProductCodeIdentity.resolve(secondAudit, verdicts: cache, evaluate: counted)
    check(evaluations == 1,
          "live verdicts: a second process of the same signed binary is resolved without re-running the static check")
    check(sameIdentity(secondResolved, ProductCodeIdentity.evaluate(secondAudit)),
          "live verdicts: the cached answer equals a full evaluation of the second process")
    check(sameIdentity(ProductCodeIdentity.resolve(secondAudit), ProductCodeIdentity.evaluate(secondAudit)),
          "live verdicts: the shared cache's answer equals a full evaluation")

    // A token whose process has gone: the kernel refuses it, so no cached
    // verdict can answer, and the full check fails.
    stop(second)
    check(KernelCodeFacts.read(secondAudit) == nil,
          "live verdicts: the kernel refuses the facts of a process that has exited")
    let goneResolved = ProductCodeIdentity.resolve(secondAudit, verdicts: cache, evaluate: counted)
    check(evaluations == 2 && !goneResolved.signatureValid,
          "live verdicts: a stale token gets the full check, which fails, never the cached verdict")

    liveExecTest()
    liveRequirementTest(firstAudit: firstAudit)
    liveSSHRequirementTest()
}

/// A token stays bound to the image it named: after the process execs, the
/// old token resolves to nothing, even with the old image's verdict cached.
private func liveExecTest() {
    let input = Pipe()
    guard let shell = spawn("/bin/bash", ["-c", "read line; exec /bin/sleep 30"], input: input) else {
        check(false, "live verdicts: a shell that execs on cue starts")
        return
    }
    defer {
        try? input.fileHandleForWriting.close()
        stop(shell)
    }
    guard let shellAudit = liveAudit(of: shell), shellAudit.executablePath == "/bin/bash" else {
        check(false, "live verdicts: the shell's audit token names /bin/bash")
        return
    }
    let cache = CodeSignatureVerdictCache<CodeIdentity>(capacity: 8)
    var evaluations = 0
    let counted: (AuditIdentity) -> CodeIdentity = {
        evaluations += 1
        return ProductCodeIdentity.evaluate($0)
    }
    let before = ProductCodeIdentity.resolve(shellAudit, verdicts: cache, evaluate: counted)
    check(before.signatureValid && before.identifier == "com.apple.bash" && cache.count == 1,
          "live verdicts: the shell's verdict is filed before it execs")

    input.fileHandleForWriting.write(Data("go\n".utf8))
    let deadline = Date().addingTimeInterval(10)
    while ProcessAncestry.executablePath(of: shell.processIdentifier) != "/bin/sleep", Date() < deadline {
        usleep(20_000)
    }
    guard ProcessAncestry.executablePath(of: shell.processIdentifier) == "/bin/sleep" else {
        check(false, "live verdicts: the shell execs /bin/sleep on cue")
        return
    }
    check(KernelCodeFacts.read(shellAudit) == nil,
          "live verdicts: the kernel refuses the facts of a token from before an exec")
    let after = ProductCodeIdentity.resolve(shellAudit, verdicts: cache, evaluate: counted)
    check(evaluations == 2 && !after.signatureValid,
          "live verdicts: a token from before an exec never gets the old image's cached verdict")
    if let current = liveAudit(of: shell) {
        let resolved = ProductCodeIdentity.resolve(current, verdicts: cache, evaluate: counted)
        check(resolved.identifier == "com.apple.sleep" && resolved.signatureValid,
              "live verdicts: the new image's own token resolves the new image")
    } else {
        check(false, "live verdicts: the exec'd process's new audit token is readable")
    }
}

private func liveRequirementTest(firstAudit: AuditIdentity) {
    guard let another = spawn("/bin/sleep", ["30"]) else {
        check(false, "live requirement: a further /bin/sleep starts")
        return
    }
    defer { stop(another) }
    guard let anotherAudit = liveAudit(of: another) else {
        check(false, "live requirement: its audit token is readable")
        return
    }
    let cache = CodeSignatureVerdictCache<Bool>(capacity: 8)
    var evaluations = 0
    let counted: (AuditIdentity, String) -> LiveCodeRequirement.Evaluation = {
        evaluations += 1
        return LiveCodeRequirement.evaluate($0, requirement: $1)
    }
    let sleepRequirement = "anchor apple and identifier \"com.apple.sleep\""
    check(LiveCodeRequirement.isSatisfied(
            by: firstAudit, requirement: sleepRequirement, verdicts: cache, evaluate: counted)
            && LiveCodeRequirement.isSatisfied(
                by: anotherAudit, requirement: sleepRequirement, verdicts: cache, evaluate: counted)
            && evaluations == 1,
          "live requirement: Apple's requirement is evaluated once for two processes of /bin/sleep")
    let unsatisfied = SSHClientCodeIdentity.requirement
    check(!LiveCodeRequirement.isSatisfied(
            by: firstAudit, requirement: unsatisfied, verdicts: cache, evaluate: counted)
            && !LiveCodeRequirement.isSatisfied(
                by: firstAudit, requirement: unsatisfied, verdicts: cache, evaluate: counted)
            && evaluations == 3 && cache.count == 1,
          "live requirement: /bin/sleep fails the ssh requirement, every time, and nothing is filed for it")
}

/// The production SSH requirement against the real `/usr/bin/ssh`, held open
/// by a proxy command that never answers (no network, no user configuration,
/// no agent).
private func liveSSHRequirementTest() {
    guard let ssh = spawn("/usr/bin/ssh", [
        "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentityAgent=none",
        "-o", "ProxyCommand=/bin/sleep 20", "csec-selftest.invalid",
    ]) else {
        check(false, "live ssh requirement: /usr/bin/ssh starts")
        return
    }
    defer { stop(ssh) }
    guard let audit = liveAudit(of: ssh), audit.executablePath == "/usr/bin/ssh" else {
        check(false, "live ssh requirement: ssh's audit token names /usr/bin/ssh")
        return
    }
    let identity = ProductCodeIdentity.resolve(audit)
    check(identity.identifier == "com.apple.ssh" && identity.executablePath == "/usr/bin/ssh"
            && identity.signatureValid && identity.hardenedRuntime && identity.dangerousEntitlements.isEmpty,
          "live ssh requirement: ssh resolves as the SSH agent's accepted peer shape")
    let cache = CodeSignatureVerdictCache<Bool>(capacity: 8)
    var evaluations = 0
    let counted: (AuditIdentity, String) -> LiveCodeRequirement.Evaluation = {
        evaluations += 1
        return LiveCodeRequirement.evaluate($0, requirement: $1)
    }
    check(LiveCodeRequirement.isSatisfied(
            by: audit, requirement: SSHClientCodeIdentity.requirement, verdicts: cache, evaluate: counted)
            && LiveCodeRequirement.isSatisfied(
                by: audit, requirement: SSHClientCodeIdentity.requirement, verdicts: cache, evaluate: counted)
            && evaluations == 1,
          "live ssh requirement: the real ssh satisfies Apple's requirement, evaluated once")
}
