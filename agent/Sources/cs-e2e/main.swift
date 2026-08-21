import Foundation
import ConvenientSecurity

// End-to-end check: start the agent on a temp socket, connect a client, and
// prove the full path — socket, LOCAL_PEERTOKEN peer identity, subtree grant,
// resolution — round-trips a value. Runs locally with no entitlements, using a
// fake in-memory provider and a counting consent stub.

var failures = 0
let forcedScannerFailureMarker = "csec-synthetic-scanner-failure-trigger"
func check(_ condition: Bool, _ label: String) {
    print(condition ? "ok   - \(label)" : "FAIL - \(label)")
    if !condition { failures += 1 }
}

struct StaticProvider: SecretProvider {
    let values: [String: String]
    var schemes: Set<String> { ["op"] }
    func resolve(_ ref: SecretRef) async throws -> ResolvedSecret {
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

actor ConsentCounter: ConsentProvider {
    private(set) var count = 0
    func requestConsent(caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval) async -> ConsentOutcome {
        count += 1
        return .approved(unlock: nil)
    }
    func calls() -> Int { count }
}

actor RequestCapture {
    private(set) var calls = 0
    private(set) var lastCaller: CallerInfo?

    func record(_ caller: CallerInfo) {
        calls += 1
        lastCaller = caller
    }

    func snapshot() -> (calls: Int, caller: CallerInfo?) { (calls, lastCaller) }
}

let socketPath = NSTemporaryDirectory() + "cs-e2e-\(getpid()).sock"

let resolver = SecretResolver(cache: NullSecretCache())
await resolver.register(StaticProvider(values: [
    "op://demo/db/url": "postgres://s3cr3t",
    "op://demo/db/url-extended": "postgres://s3cr3t/extended",
    "op://demo/api/key": "sk-demo-123",
]))
let grants = GrantTable()
let consent = ConsentCounter()
let capture = RequestCapture()
let agent = Agent(
    resolver: resolver,
    grants: grants,
    consent: consent,
    allowUnverifiedPlansForTesting: true
)

let server = SocketServer(path: socketPath, clientTrustPolicy: .allowUnverifiedForTesting) { request, caller in
    await capture.record(caller)
    if case let .redactOutputChunk(chunk) = request,
       chunk.data.range(of: Data(forcedScannerFailureMarker.utf8)) != nil {
        return .failed(
            .internalError,
            message: "synthetic scanner failure",
            requestID: chunk.requestID
        )
    }
    switch request {
    case let .access(access):
        return await agent.handle(request: access, caller: caller)
    case .schemes:
        return await agent.schemes()
    case .capabilities:
        return await agent.capabilities()
    case let .beginOutputRedaction(begin):
        return await agent.beginOutputRedaction(request: begin, caller: caller)
    case let .redactOutputChunk(chunk):
        return await agent.redactOutputChunk(request: chunk, caller: caller)
    case let .endOutputRedaction(end):
        return await agent.endOutputRedaction(request: end, caller: caller)
    }
}
Thread.detachNewThread { try? server.run() }

// Wait (up to ~2s) for the socket to appear.
var waited = 0
while !FileManager.default.fileExists(atPath: socketPath) && waited < 100 {
    usleep(20_000)
    waited += 1
}
check(FileManager.default.fileExists(atPath: socketPath), "agent socket is listening")

let client = AgentClient(path: socketPath, serverTrustPolicy: .allowUnverifiedForTesting)

// A production client must authenticate the connected process before sending
// even a capability query. This server is the unsigned cs-e2e process.
do {
    _ = try AgentClient(path: socketPath).schemes()
    check(false, "production client rejects an unsigned replacement server")
} catch AgentClient.ClientError.untrustedServer {
    check(true, "production client rejects an unsigned replacement server before request write")
} catch {
    check(false, "replacement server rejection is a typed trust failure (got \(error))")
}
check((await capture.snapshot()).calls == 0,
      "replacement server receives no request metadata before client rejection")

do {
    let capabilities = try client.capabilities()
    check(capabilities.supportedVersions == [2], "client negotiates protocol v2")
    check(capabilities.features.contains(.deliveryPlans)
          && capabilities.features.contains(.typedFailures)
          && capabilities.features.contains(.outputGuardBinding)
          && capabilities.features.contains(.activeOutputRedaction),
          "agent advertises delivery-plan, output-guard, active-redaction, and typed-failure capabilities")
} catch {
    check(false, "protocol capability negotiation succeeds (\(error))")
}

// Old access JSON remains recognizable solely so the production agent can fail
// with an explicit upgrade code; it never infers a secure delivery plan.
let legacyData = Data(#"{"type":"access","references":["op://demo/db/url"],"reason":"legacy","ttlSeconds":60}"#.utf8)
if let legacyWire = try? JSONDecoder().decode(Request.self, from: legacyData),
   case let .access(legacyAccess) = legacyWire {
    let legacyResponse = await agent.handle(
        request: legacyAccess,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "legacy test"
        )
    )
    check(legacyResponse.failure?.code == .upgradeRequired,
          "production agent fails closed on v1 access with upgrade_required")
} else {
    check(false, "legacy access JSON decodes for migration failure")
}

let invalidMetadataPlan = DeliveryPlan(
    mechanism: .directHeap,
    executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .unverified),
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 60,
    operationContext: "metadata bounds test",
    commandDigest: "not-a-sha256-digest"
)
if let invalidMetadataRequest = try? AccessRequest(
    references: ["op://demo/db/url"],
    reason: "invalid metadata must fail before consent",
    ttlSeconds: 60,
    deliveryPlan: invalidMetadataPlan
) {
    let invalidMetadataResponse = await agent.handle(
        request: invalidMetadataRequest,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "metadata test"
        )
    )
    check(invalidMetadataResponse.failure?.code == .invalidRequest,
          "malformed delivery metadata fails before consent or resolution")
} else {
    check(false, "malformed-metadata request can be constructed for rejection testing")
}

let unsupportedMatcherPlan = DeliveryPlan(
    mechanism: .unrestrictedInitialEnvironment,
    executable: PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified),
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 60,
    operationContext: "unsupported matcher test",
    outputGuard: OutputGuardPlan(mode: .always, matcherVersion: 999)
)
if let unsupportedMatcherRequest = try? AccessRequest(
    references: ["op://demo/db/url"],
    reason: "unsupported output matcher must fail before consent",
    ttlSeconds: 60,
    deliveryPlan: unsupportedMatcherPlan
) {
    let consentBefore = await consent.calls()
    let response = await agent.handle(
        request: unsupportedMatcherRequest,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "matcher-version test"
        )
    )
    let consentAfter = await consent.calls()
    check(response.failure?.code == .invalidRequest
          && consentAfter == consentBefore,
          "unsupported output-matcher semantics fail before consent or resolution")
} else {
    check(false, "unsupported-matcher request can be constructed for rejection testing")
}

let unboundOutputPlan = DeliveryPlan(
    mechanism: .unrestrictedInitialEnvironment,
    executable: PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified),
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 60,
    operationContext: "missing output binding test"
)
if let unboundOutputRequest = try? AccessRequest(
    references: ["op://demo/db/url"],
    reason: "unbound output policy must fail before consent",
    ttlSeconds: 60,
    deliveryPlan: unboundOutputPlan
) {
    let consentBefore = await consent.calls()
    let response = await agent.handle(
        request: unboundOutputRequest,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "missing-output-binding test"
        )
    )
    let consentAfter = await consent.calls()
    check(response.failure?.code == .invalidRequest
          && consentAfter == consentBefore,
          "unrestricted env delivery without an output-policy binding fails before consent")
} else {
    check(false, "unbound-output request can be constructed for rejection testing")
}

do {
    let first = try client.access(references: ["op://demo/db/url"], reason: "e2e first", ttlSeconds: 3600)
    check(first["op://demo/db/url"] == "postgres://s3cr3t", "value resolves end-to-end over the socket")

    let second = try client.access(references: ["op://demo/db/url"], reason: "e2e second", ttlSeconds: 3600)
    check(second["op://demo/db/url"] == "postgres://s3cr3t", "second fetch succeeds")

    let consentCalls = await consent.calls()
    check(consentCalls == 1, "consent asked once; the subtree grant covered the second fetch")

    let capturedCaller = (await capture.snapshot()).caller
    check(capturedCaller?.peerIdentity?.audit.pid == getpid(),
          "server caller PID comes from the complete kernel audit token")
    check(capturedCaller?.peerIdentity?.audit.effectiveUID == getuid(),
          "server caller effective uid comes from the kernel audit token")
    check(capturedCaller?.peerIdentity?.audit.pidVersion ?? -1 >= 0,
          "server retains the audit-token PID version")
    check(capturedCaller?.peerIdentity?.audit.rawAuditToken.isEmpty == false,
          "server retains the complete opaque audit token")
    check(capturedCaller?.peerIdentity?.code.role == .other,
          "unsigned/ad-hoc test code is explicitly unverified, not product code")
} catch {
    check(false, "client access failed: \(error)")
}

// Reciprocal gate: a production server rejects this unsigned client before its
// access request reaches the handler. The client relaxes only server checking
// here so the test exercises the daemon-side decision.
let strictSocketPath = NSTemporaryDirectory() + "cs-e2e-strict-\(getpid()).sock"
let strictCapture = RequestCapture()
let strictServer = SocketServer(path: strictSocketPath) { _, caller in
    await strictCapture.record(caller)
    return Response(error: "should not be reached")
}
Thread.detachNewThread { try? strictServer.run() }
waited = 0
while !FileManager.default.fileExists(atPath: strictSocketPath) && waited < 100 {
    usleep(20_000)
    waited += 1
}
do {
    _ = try AgentClient(
        path: strictSocketPath,
        serverTrustPolicy: .allowUnverifiedForTesting
    ).access(references: ["op://demo/db/url"], reason: "must be rejected", ttlSeconds: 60)
    check(false, "production server rejects an unsigned client")
} catch {
    check(true, "production server rejects an unsigned client")
}
usleep(20_000)
check((await strictCapture.snapshot()).calls == 0,
      "unsigned client's access request never reaches the production handler")
unlink(strictSocketPath)

// An unknown reference must surface as an error, not a silent empty result.
do {
    _ = try client.access(references: ["op://demo/missing"], reason: "e2e missing", ttlSeconds: 60)
    check(false, "a missing reference should raise")
} catch {
    check(true, "a missing reference raises (\(error))")
}

// Consent delta: requesting an already-granted reference plus a new one prompts
// only for the new one, and both resolve. This is the core grant-expansion rule.
do {
    let before = await consent.calls()
    let both = try client.access(
        references: ["op://demo/db/url", "op://demo/api/key"],
        reason: "e2e delta", ttlSeconds: 3600
    )
    let after = await consent.calls()
    check(after - before == 1, "adding one new reference consents only for the delta (\(after - before))")
    check(both["op://demo/db/url"] == "postgres://s3cr3t" && both["op://demo/api/key"] == "sk-demo-123",
          "both the already-granted and the newly-granted reference resolve")
} catch {
    check(false, "consent-delta access failed: \(error)")
}

// Full `csec exec` path: run the actual built binary against this agent and
// confirm the (fake) secret lands in the child's environment. CSEC_SOCKET points
// csec at our temp agent; the fake value is safe to print.
let selfURL = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
let csecURL = selfURL.deletingLastPathComponent().appendingPathComponent("csec")
let processTitleFixtureURL = selfURL.deletingLastPathComponent()
    .appendingPathComponent("cs-process-title-fixture")

func runCsec(
    _ arguments: [String],
    extraEnv: [String: String]
) -> (status: Int32, reason: Process.TerminationReason, out: String, err: String) {
    let process = Process()
    process.executableURL = csecURL
    process.arguments = arguments
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    for (key, value) in extraEnv { environment[key] = value }
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, .exit, "", "spawn failed: \(error)")
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        process.terminationReason,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func runProgram(
    executable: String,
    arguments: [String]
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed")
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func runCsecInPTY(
    _ arguments: [String],
    extraEnv: [String: String]
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/script")
    process.arguments = [
        "-q", "/dev/null", "/bin/sh", "-c",
        "stty rows 37 cols 113; exec \"$@\"", "csec-pty", csecURL.path,
    ] + arguments
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    for (key, value) in extraEnv { environment[key] = value }
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed: \(error)")
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func runCsecThroughStopAndContinue() -> (
    status: Int32,
    observedStop: Bool,
    out: String,
    err: String
) {
    let process = Process()
    process.executableURL = csecURL
    process.arguments = [
        "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
        "/bin/sh", "-c",
        "printf '%080d' 0; kill -STOP $$; printf %s \"$TESTVAR\"",
    ]
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, false, "", "spawn failed: \(error)")
    }

    let first = outPipe.fileHandleForReading.readData(ofLength: 1)
    var observedStop = false
    for _ in 0..<200 {
        if ProcessAncestry.isStopped(process.processIdentifier) {
            observedStop = true
            break
        }
        usleep(10_000)
    }
    _ = kill(process.processIdentifier, SIGCONT)
    if !observedStop {
        process.terminate()
        _ = kill(process.processIdentifier, SIGCONT)
    }

    let rest = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        observedStop,
        String(data: first + rest, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func runCsecWithExternalTermination() -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = csecURL
    process.arguments = [
        "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
        "/bin/sh", "-c",
        "trap 'exit 42' TERM; printf '%080d' 0; while :; do :; done",
    ]
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed: \(error)")
    }

    // The guard withholds at most its longest-pattern tail. Reading one byte
    // proves the supervisor and child signal handlers are fully established.
    let first = outPipe.fileHandleForReading.readData(ofLength: 1)
    process.terminate()
    let rest = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: first + rest, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

if FileManager.default.isExecutableFile(atPath: csecURL.path) {
    let fetched = runCsec(
        ["get", "op://demo/db/url", "--reason", "synthetic pipe test", "--for", "60"],
        extraEnv: [:]
    )
    check(fetched.status == 0 && fetched.out == "postgres://s3cr3t\n",
          "piped csec get remains an explicit raw-output path with an exact caller grant")

    // Explicit --set injects a named reference into the child.
    let explicit = runCsec(
        ["exec", "--set", "TESTVAR=op://demo/db/url", "--", "/bin/sh", "-c", "printf %s \"$TESTVAR\""],
        extraEnv: [:]
    )
    check(explicit.status == 0 && explicit.out == "postgres://s3cr3t",
          "csec exec --set injects the resolved value (got status \(explicit.status), out \"\(explicit.out)\", err \"\(explicit.err)\")")

    let guarded = runCsec(
        [
            "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c",
            "printf %s 'postgres://'; printf %s 's3cr3t'; "
                + "printf %s 'postgres://' >&2; printf %s 's3cr3t' >&2",
        ],
        extraEnv: [:]
    )
    check(guarded.status == 0
          && guarded.out == "[csec:secret-1]"
          && guarded.err.contains("[csec:secret-1]")
          && guarded.err.contains("protected output detected and redacted")
          && !guarded.out.contains("postgres://s3cr3t")
          && !guarded.err.contains("postgres://s3cr3t"),
          "always mode redacts split matches on stdout and stderr before forwarding")

    // This launch resolves no values. Its matcher comes from csecd's registry,
    // populated by the earlier independent access/exec launches, which is the
    // property needed when pgrep exposes a RuboCop daemon from another worktree.
    let crossLaunch = runCsec(
        [
            "tool-exec", "--destination", "ai", "--", "/bin/sh", "-c",
            "printf %s 'postgres://'; printf %s 's3cr3t'",
        ],
        extraEnv: [:]
    )
    check(crossLaunch.status == 0
          && crossLaunch.out.hasPrefix("[csec:secret-")
          && crossLaunch.err.contains("protected output detected and redacted")
          && !crossLaunch.out.contains("postgres://s3cr3t")
          && !crossLaunch.err.contains("postgres://s3cr3t"),
          "AI tool broker redacts another launch's active value before returning output "
              + "(status=\(crossLaunch.status), label=\(crossLaunch.out.hasPrefix("[csec:secret-")), "
              + "event=\(crossLaunch.err.contains("protected output detected and redacted")), "
              + "raw=\(crossLaunch.out.contains("postgres://s3cr3t") || crossLaunch.err.contains("postgres://s3cr3t")), "
              + "err=\(crossLaunch.err.contains("postgres://s3cr3t") ? "<contained synthetic marker>" : crossLaunch.err))")

    let quotedShellOutput = "spaces $HOME `uname` \"quotes\"\nsecond line"
    let quotedShellProgram = "printf '%s' '" + quotedShellOutput + "'"
    let encodedShell = runCsec(
        [
            "tool-exec", "--destination", "ai", "--encoded-shell-command",
            AICommandHook.encodeShellCommand(quotedShellProgram),
        ],
        extraEnv: [:]
    )
    check(encodedShell.status == 0 && encodedShell.out == quotedShellOutput,
          "hook transport preserves spaces, metacharacters, quotes, and newlines exactly")

    // Faithful regression for the reported incident: a tiny synthetic daemon
    // rewrites its original argv string area the way modern Ruby does while one
    // already-registered fake value is in its initial environment. First prove
    // raw pgrep exposes the marker, then run the same command through tool-exec.
    let rubocopToken = "csec-rubocop-fixture-\(getpid())"
    let rubocopFixture = Process()
    rubocopFixture.executableURL = processTitleFixtureURL
    rubocopFixture.arguments = [rubocopToken, "padding-one", "padding-two"]
    rubocopFixture.environment = ["CSEC_SYNTHETIC_RUBOCOP_SECRET": "postgres://s3cr3t"]
    let readyPipe = Pipe()
    rubocopFixture.standardOutput = readyPipe
    rubocopFixture.standardError = FileHandle.nullDevice
    do {
        try rubocopFixture.run()
        let ready = readyPipe.fileHandleForReading.readData(ofLength: 6)
        let rawPgrep = runProgram(executable: "/usr/bin/pgrep", arguments: ["-fl", rubocopToken])
        let rawFixtureReproduced = ready == Data("ready\n".utf8)
            && rawPgrep.status == 0
            && rawPgrep.out.contains("postgres://s3cr3t")
        check(rawFixtureReproduced,
              "synthetic RuboCop-title fixture reproduces the raw pgrep environment disclosure "
                  + "(ready=\(ready == Data("ready\n".utf8)), status=\(rawPgrep.status), "
                  + "marker=\(rawPgrep.out.contains("postgres://s3cr3t")))")

        let guardedPgrep = runCsec(
            ["tool-exec", "--destination", "ai", "--", "/usr/bin/pgrep", "-fl", rubocopToken],
            extraEnv: [:]
        )
        check(rawFixtureReproduced
              && guardedPgrep.status == 0
              && guardedPgrep.out.contains("[csec:secret-")
              && !guardedPgrep.out.contains("postgres://s3cr3t")
              && !guardedPgrep.err.contains("postgres://s3cr3t"),
              "synthetic RuboCop/pgrep leak is redacted before the simulated AI recipient "
                  + "(status=\(guardedPgrep.status), label=\(guardedPgrep.out.contains("[csec:secret-")), "
                  + "raw=\(guardedPgrep.out.contains("postgres://s3cr3t") || guardedPgrep.err.contains("postgres://s3cr3t")))")
        rubocopFixture.terminate()
        rubocopFixture.waitUntilExit()
    } catch {
        check(false, "synthetic RuboCop-title fixture starts")
    }

    let unavailableMarker = NSTemporaryDirectory() + "csec-tool-exec-not-run-\(getpid())"
    try? FileManager.default.removeItem(atPath: unavailableMarker)
    let unavailable = runCsec(
        ["tool-exec", "--destination", "ai", "--", "/usr/bin/touch", unavailableMarker],
        extraEnv: ["CSEC_SOCKET": NSTemporaryDirectory() + "csec-missing-\(getpid()).sock"]
    )
    check(unavailable.status == 1
          && !FileManager.default.fileExists(atPath: unavailableMarker)
          && unavailable.err.contains("command not run"),
          "AI tool broker fails closed before launch when the scanner is unavailable")

    let interruptedMarker = NSTemporaryDirectory() + "csec-tool-exec-terminated-\(getpid())"
    try? FileManager.default.removeItem(atPath: interruptedMarker)
    let interrupted = runCsec(
        [
            "tool-exec", "--destination", "ai", "--", "/bin/sh", "-c",
            "printf %s \(forcedScannerFailureMarker); sleep 2; /usr/bin/touch \(interruptedMarker)",
        ],
        extraEnv: [:]
    )
    check(interrupted.status == 1
          && interrupted.out.isEmpty
          && !FileManager.default.fileExists(atPath: interruptedMarker)
          && interrupted.err.contains("command terminated"),
          "AI tool broker forwards no unscanned chunk and terminates the child if scanning fails")

    let longest = runCsec(
        [
            "exec", "--redact-output=always",
            "--set", "SHORT=op://demo/db/url",
            "--set", "LONG=op://demo/db/url-extended", "--",
            "/bin/sh", "-c", "printf %s \"$LONG\"",
        ],
        extraEnv: [:]
    )
    check(longest.status == 0 && longest.out == "[csec:secret-2]"
          && !longest.out.contains("postgres://s3cr3t"),
          "supervised output uses the longest matching protected value")

    let encoded = runCsec(
        [
            "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "printf %s \"$TESTVAR\" | /usr/bin/base64",
        ],
        extraEnv: [:]
    )
    check(encoded.status == 0 && encoded.out == "[csec:secret-1]\n"
          && !encoded.out.contains("cG9zdGdyZXM"),
          "supervised output recognizes canonical base64 secret output")

    let referenceLabel = runCsec(
        [
            "exec", "--redact-output=always", "--redact-output-label=reference",
            "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "printf %s \"$TESTVAR\"",
        ],
        extraEnv: [:]
    )
    check(referenceLabel.status == 0 && referenceLabel.out == "op://demo/db/url"
          && referenceLabel.err.contains("reference metadata"),
          "reference-shaped redaction is explicit and warns about metadata exposure")

    let byteExact = runCsec(
        [
            "exec", "--redact-output=never", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "printf %s \"$TESTVAR\"",
        ],
        extraEnv: [:]
    )
    check(byteExact.status == 0 && byteExact.out == "postgres://s3cr3t"
          && byteExact.err.contains("explicitly disabled"),
          "never mode is an explicit byte-exact bypass with a warning")

    let childExit = runCsec(
        [
            "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "exit 23",
        ],
        extraEnv: [:]
    )
    check(childExit.status == 23, "the output supervisor preserves the child's exit code")

    let childSignal = runCsec(
        [
            "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "kill -TERM $$",
        ],
        extraEnv: [:]
    )
    check(childSignal.reason == .uncaughtSignal && childSignal.status == SIGTERM,
          "the output supervisor preserves a child's terminating signal")

    let externallyTerminated = runCsecWithExternalTermination()
    check(externallyTerminated.status == 42 && externallyTerminated.out.count == 80,
          "signals sent to csec are forwarded to the supervised child process group")

    let stopAndContinue = runCsecThroughStopAndContinue()
    check(stopAndContinue.observedStop
          && stopAndContinue.status == 0
          && stopAndContinue.out.hasSuffix("[csec:secret-1]")
          && !stopAndContinue.out.contains("postgres://s3cr3t"),
          "the supervisor mirrors child stop/continue and resumes guarded output")

    let automaticTTY = runCsecInPTY(
        [
            "exec", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c",
            "test -t 0 && test -t 1 && test -t 2 && stty size && "
                + "printf %s 'postgres://' && printf %s 's3cr3t'",
        ],
        extraEnv: [:]
    )
    let ptyNumbers = automaticTTY.out
        .split(whereSeparator: { !$0.isNumber })
        .compactMap { Int($0) }
    let automaticTTYPassed = automaticTTY.status == 0
        && automaticTTY.out.contains("[csec:secret-1]")
        && automaticTTY.out.contains("37 113")
        && automaticTTY.out.contains("protected output detected and redacted")
        && !automaticTTY.out.contains("postgres://s3cr3t")
    let automaticTTYDiagnostics = automaticTTYPassed ? "" : " "
        + "(status=\(automaticTTY.status), label=\(automaticTTY.out.contains("[csec:secret-1]")), "
        + "size=\(automaticTTY.out.contains("37 113")), numbers=\(ptyNumbers), "
        + "event=\(automaticTTY.out.contains("protected output detected and redacted")), "
        + "raw=\(automaticTTY.out.contains("postgres://s3cr3t")))"
    check(automaticTTYPassed,
          "default tty mode allocates a child PTY and automatically redacts terminal output"
              + automaticTTYDiagnostics)

    // Env-scan: a reference already in the environment is resolved in place.
    let scanned = runCsec(
        ["exec", "--", "/bin/sh", "-c", "printf %s \"$TESTVAR\""],
        extraEnv: ["TESTVAR": "op://demo/db/url"]
    )
    check(scanned.status == 0 && scanned.out == "postgres://s3cr3t",
          "csec exec env-scan resolves an op:// value already in the environment (got status \(scanned.status), out \"\(scanned.out)\", err \"\(scanned.err)\")")

    // A plain URL in the environment must be passed through untouched.
    let untouched = runCsec(
        ["exec", "--", "/bin/sh", "-c", "printf %s \"$SITE_URL\""],
        extraEnv: ["SITE_URL": "https://example.com"]
    )
    check(untouched.status == 0 && untouched.out == "https://example.com",
          "csec exec leaves a non-secret URL untouched (got status \(untouched.status), out \"\(untouched.out)\", err \"\(untouched.err)\")")
} else {
    check(false, "built csec binary is present at \(csecURL.path)")
}

unlink(socketPath)

if failures == 0 {
    print("\nAll end-to-end checks passed.")
    exit(0)
} else {
    FileHandle.standardError.write(Data("\n\(failures) check(s) failed.\n".utf8))
    exit(1)
}
