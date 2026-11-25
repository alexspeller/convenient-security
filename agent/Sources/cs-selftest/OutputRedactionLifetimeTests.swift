import Foundation
import ConvenientSecurity

/// No files, host mutations, or real providers. Explicit dates reproduce days
/// of silence without sleeping or changing the system clock.
func outputRedactionLifetimeTests() async {
    print("\n# Output-redaction process lifetime")
    let pid = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let start = ProcessAncestry.startTime(of: pid) else {
        check(false, "the scanner fixture can identify its own process")
        return
    }
    let owner = CallerInfo(pid: pid, startTime: start, description: "synthetic scanner owner")
    let other = CallerInfo(pid: 50101, startTime: 101, description: "synthetic other owner")
    let processes = RedactionFixtureProcesses([pid: start, other.pid: other.startTime])
    let resolver = SecretResolver(cache: NullSecretCache())
    let resolutions = RedactionResolutionCount()
    let first = "synthetic-op-scanner-token-123456789"
    let second = "synthetic-vault-scanner-token-987654321"
    let references = ["op://synthetic/scanner/token", "vault://synthetic/scanner/token"]
    await resolver.register(RedactionFixtureProvider(
        values: [references[0]: Data(first.utf8), references[1]: Data(second.utf8)],
        resolutions: resolutions
    ))
    func makeAgent() -> Agent {
        Agent(resolver: resolver, grants: GrantTable(), consent: AutoApproveConsent(),
              policyReview: AutoApprovePolicyReview(), allowUnverifiedPlansForTesting: true,
              processInspection: processes.inspection, terminalInspection: .unavailable)
    }
    let agent = makeAgent()
    do {
        let access = try AccessRequest(
            references: references, reason: AICommandExec.operationContext, ttlSeconds: 60,
            deliveryPlan: AICommandExec.deliveryPlan(executablePath: "/usr/bin/true", ttlSeconds: 60)
        )
        let seeded = await agent.handle(request: access, caller: owner)
        check(seeded.failure == nil && seeded.values?.count == 2,
              "only synthetic values from two provider schemes seed the scanner")
    } catch {
        check(false, "synthetic scanner authorization could be constructed")
        return
    }

    let now = Date()
    let daysLater = now.addingTimeInterval(2 * 24 * 60 * 60)
    let begin = BeginOutputRedactionRequest(destination: .aiTool, streams: [.stdout, .stderr])
    let opened = await agent.beginOutputRedaction(request: begin, caller: owner, now: now)
    guard let session = opened.outputRedactionSessionID else {
        check(false, "the synthetic output scanner opens")
        return
    }
    func chunk(_ data: String, stream: OutputRedactionStream = .stdout, finish: Bool = false)
        -> RedactOutputChunkRequest {
        RedactOutputChunkRequest(sessionID: session, stream: stream,
                                 data: Data(data.utf8), finish: finish)
    }
    let prefix = String(first.prefix(15))
    let held = await agent.redactOutputChunk(request: chunk(prefix), caller: owner, now: now)
    check(held.failure == nil && held.redactedData == Data(),
          "a partial secret is withheld before the command becomes idle")

    // Starting another command also runs pruning; it must not retire the quiet
    // server's matcher or lose the prefix it has already withheld.
    let unrelated = await agent.beginOutputRedaction(request: begin, caller: other, now: daysLater)
    check(unrelated.outputRedactionSessionID != nil, "another command can start days later")
    let wrongOwner = await agent.redactOutputChunk(request: chunk("probe"), caller: other, now: daysLater)
    let wrongEnd = await agent.endOutputRedaction(
        request: EndOutputRedactionRequest(sessionID: session), caller: other)
    check(wrongOwner.failure?.code == .invalidRequest && wrongOwner.redactedData == nil
          && wrongEnd.failure?.code == .invalidRequest,
          "another caller cannot use or close the retained scanner")

    let resumed = await agent.redactOutputChunk(
        request: chunk(String(first.dropFirst(prefix.count)) + "\n", finish: true),
        caller: owner, now: daysLater)
    check(resumed.failure == nil && resumed.redactedData == Data("[csec:secret-1]\n".utf8),
          "output resumes after two idle days with the original secret prefix still protected")
    let stderr = await agent.redactOutputChunk(
        request: chunk(second + "\n", stream: .stderr, finish: true), caller: owner, now: daysLater)
    check(stderr.failure == nil && stderr.redactedData == Data("[csec:secret-2]\n".utf8),
          "stderr retains its provider-neutral matcher after delivery registry entries expire")
    let resolutionCount = await resolutions.value
    check(resolutionCount == 2, "retaining a scanner does not resolve secrets again")
    let finished = await agent.redactOutputChunk(request: chunk("late"), caller: owner, now: daysLater)
    check(finished.failure?.code == .invalidRequest && finished.redactedData == nil,
          "a finished stream cannot resume sending output")
    let ended = await agent.endOutputRedaction(
        request: EndOutputRedactionRequest(sessionID: session), caller: owner)
    check(ended.failure == nil, "the owner can explicitly close a long-lived scanner")
    let closed = await agent.redactOutputChunk(request: chunk("closed"), caller: owner, now: daysLater)
    check(closed.failure?.code == .invalidRequest && closed.redactedData == nil,
          "an explicitly closed scanner fails closed")

    // The owner is identified by its process incarnation, not just its PID.
    let stale = await agent.beginOutputRedaction(request: begin, caller: owner)
    processes.set(pid, start: start + 1)
    let reused = CallerInfo(pid: pid, startTime: start + 1, description: "synthetic reused PID")
    let reuse = await agent.redactOutputChunk(request: RedactOutputChunkRequest(
        sessionID: stale.outputRedactionSessionID ?? "", stream: .stdout, data: Data("probe".utf8)
    ), caller: reused)
    check(reuse.failure?.code == .invalidRequest && reuse.redactedData == nil,
          "a reused PID cannot inherit a previous process's scanner")
    let staleOpen = await agent.beginOutputRedaction(request: begin, caller: owner)
    check(staleOpen.failure?.code == .invalidRequest,
          "scanner creation rejects an owner whose process incarnation has changed")
    processes.set(pid, start: nil)
    let deadOpen = await agent.beginOutputRedaction(request: begin, caller: reused)
    check(deadOpen.failure?.code == .invalidRequest, "scanner creation rejects a dead owner")
    processes.set(pid, start: start)

    // Retention must not remove the resource bound or evict live sessions to
    // make room. Dead owners are reclaimed before checking the cap.
    let bounded = makeAgent()
    var liveIDs: [String] = []
    let bound = Agent.maximumRedactionSessions
    check(bound >= 256, "the scanner bound leaves room for every coding agent's long-running commands")
    for _ in 0..<(bound - 1) {
        if let id = await bounded.beginOutputRedaction(request: begin, caller: owner).outputRedactionSessionID {
            liveIDs.append(id)
        }
    }
    let survivor = await bounded.beginOutputRedaction(request: begin, caller: other)
    let full = await bounded.beginOutputRedaction(request: begin, caller: owner, now: daysLater)
    check(liveIDs.count == bound - 1 && survivor.outputRedactionSessionID != nil
          && full.failure?.code == .invalidRequest,
          "the \(bound)-session bound refuses overflow without expiring live idle owners")
    processes.set(pid, start: nil)
    let reclaimed = await bounded.beginOutputRedaction(request: begin, caller: other, now: daysLater)
    check(reclaimed.outputRedactionSessionID != nil, "dead owners free scanner capacity")
    let deadChunk = await bounded.redactOutputChunk(request: RedactOutputChunkRequest(
        sessionID: liveIDs.first ?? "", stream: .stdout, data: Data("dead".utf8)
    ), caller: owner, now: daysLater)
    check(deadChunk.failure?.code == .invalidRequest && deadChunk.redactedData == nil,
          "reclaimed scanners cannot emit unscanned output")
    let liveChunk = await bounded.redactOutputChunk(request: RedactOutputChunkRequest(
        sessionID: survivor.outputRedactionSessionID ?? "", stream: .stdout,
        data: Data("alive\n".utf8), finish: true
    ), caller: other, now: daysLater)
    check(liveChunk.failure == nil && liveChunk.redactedData == Data("alive\n".utf8),
          "reclaiming dead owners preserves other live commands")

    await outputRedactionAfterRotation()
}

/// A rotated reference resolves to a new value while the old one is still
/// registered. Both were released, so both stay masked: in a scanner opened
/// after the rotation, and in one already running when the new value is
/// released.
private func outputRedactionAfterRotation() async {
    let pid = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let start = ProcessAncestry.startTime(of: pid) else {
        check(false, "the rotation fixture can identify its own process")
        return
    }
    let owner = CallerInfo(pid: pid, startTime: start, description: "synthetic rotation owner")
    let processes = RedactionFixtureProcesses([pid: start])
    let reference = "op://synthetic/rotating/token"
    let old = "synthetic-rotation-old-value-1111"
    let new = "synthetic-rotation-new-value-2222"
    let provider = RotatingFixtureProvider(value: Data(old.utf8))
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(provider)
    let agent = Agent(resolver: resolver, grants: GrantTable(), consent: AutoApproveConsent(),
                      policyReview: AutoApprovePolicyReview(), allowUnverifiedPlansForTesting: true,
                      processInspection: processes.inspection, terminalInspection: .unavailable)
    func release() async -> Bool {
        guard let access = try? AccessRequest(
            references: [reference], reason: AICommandExec.operationContext, ttlSeconds: 60,
            deliveryPlan: AICommandExec.deliveryPlan(executablePath: "/usr/bin/true", ttlSeconds: 60)
        ) else { return false }
        let released = await agent.handle(request: access, caller: owner)
        return released.failure == nil && released.values?.count == 1
    }
    let begin = BeginOutputRedactionRequest(destination: .aiTool, streams: [.stdout])
    func scan(_ session: String, _ text: String) async -> String? {
        let result = await agent.redactOutputChunk(
            request: RedactOutputChunkRequest(
                sessionID: session, stream: .stdout, data: Data(text.utf8), finish: true
            ),
            caller: owner
        )
        return result.redactedData.map { String(decoding: $0, as: UTF8.self) }
    }
    func masksBoth(_ output: String?) -> Bool {
        guard let output else { return false }
        return !output.contains(old) && !output.contains(new) && output.contains("[csec:")
    }

    let releasedOld = await release()
    let running = await agent.beginOutputRedaction(request: begin, caller: owner).outputRedactionSessionID
    await provider.rotate(to: Data(new.utf8))
    let releasedNew = await release()
    check(releasedOld && releasedNew && running != nil,
          "the rotation fixture releases the value before and after the rotation")

    let later = await agent.beginOutputRedaction(request: begin, caller: owner).outputRedactionSessionID
    let afterRotation = await scan(later ?? "", "old=\(old) new=\(new)\n")
    check(masksBoth(afterRotation),
          "a scanner opened after a rotation masks the reference's new value and its old one")
    let midStream = await scan(running ?? "", "old=\(old) new=\(new)\n")
    check(masksBoth(midStream),
          "a scanner already running masks a rotated value released after it opened, and the old one")
}

private actor RotatingFixtureProvider: SecretProvider {
    private var value: Data
    init(value: Data) { self.value = value }
    func rotate(to next: Data) { value = next }
    nonisolated var schemes: Set<String> { ["op"] }
    func resolve(_ reference: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        ResolvedSecret(value: value, cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private final class RedactionFixtureProcesses: @unchecked Sendable {
    private let lock = NSLock()
    private var starts: [pid_t: UInt64]
    init(_ starts: [pid_t: UInt64]) { self.starts = starts }
    func set(_ pid: pid_t, start: UInt64?) {
        lock.lock(); defer { lock.unlock() }
        starts[pid] = start
    }
    private func start(_ pid: pid_t) -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        return starts[pid]
    }
    var inspection: ProcessInspection {
        ProcessInspection(startTime: { self.start($0) }, parent: { _ in 1 },
                          name: { _ in "synthetic" }, executablePath: { _ in "/synthetic/csec" })
    }
}

private actor RedactionResolutionCount {
    var value = 0
    func resolved() { value += 1 }
}

private struct RedactionFixtureProvider: SecretProvider {
    let values: [String: Data]
    let resolutions: RedactionResolutionCount
    var schemes: Set<String> { ["op", "vault"] }
    func resolve(_ reference: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let value = values[reference.uri] else { throw ProviderError.referenceNotFound(reference.uri) }
        await resolutions.resolved()
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}
