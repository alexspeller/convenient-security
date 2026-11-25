import Foundation
import ConvenientSecurity
import CSECRootProtocol

/// The review window shows the launcher's full command, not just the executable
/// name: the argv travels with the access request, is bound to the plan's
/// command digest, and is passed through csecd's standard output redaction
/// before a human reads it.
func commandLineReviewTests() async {
    print("\n# Access review shows the full, redacted command line")

    // Display formatting: shell-readable, quoted only where a shell would care.
    let line = ReviewDisplay.commandLine(["bash", "-c", "echo 'hi' | grep h", "--flag=x/y"])
    check(line == "bash -c 'echo '\\''hi'\\'' | grep h' --flag=x/y",
          "arguments are joined shell-style with quoting only where needed")
    check(ReviewDisplay.commandLine(["sh", "-c", "a\nb"]) == "sh -c 'a\nb'",
          "newlines inside an argument survive so multi-line programs stay readable")
    check(ReviewDisplay.commandLine(["x", "a\u{202E}b\u{07}c"]) == "x 'a�b�c'",
          "bidi overrides and other control characters are neutralized")
    let huge = ReviewDisplay.commandLine(["cat"] + Array(repeating: "argument-value", count: 4_000))
    check(huge.utf8.count <= ReviewDisplay.maximumCommandLineDisplayBytes + 64
          && huge.hasSuffix("… command line truncated for display"),
          "a command longer than the display budget is cut with an explicit note")

    // Wire validation: the argv must hash to the digest the grant is keyed on.
    let argv = ["/bin/echo", "hello", "world"]
    let digest = try! ExecutableInspection.commandDigest(argv)
    let plan = DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/bin/echo", assurance: .unverified),
        root: .caller,
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 3_600,
        operationContext: "csec exec echo",
        commandDigest: digest,
        outputGuard: OutputGuardPlan(mode: .always, labelStyle: .opaque)
    )
    func request(_ commandLine: [String]?) -> AccessRequest {
        try! AccessRequest(
            references: ["op://vault/item/field"],
            reason: "csec exec echo",
            ttlSeconds: 3_600,
            deliveryPlan: plan,
            commandLine: commandLine
        )
    }
    check(request(argv).hasValidCommandLine, "an argv matching the plan's command digest is valid")
    check(request(nil).hasValidCommandLine, "a request without argv stays valid (csec get, SSH)")
    check(!request(["/bin/echo", "tampered"]).hasValidCommandLine,
          "an argv that does not hash to the plan's command digest is rejected")
    check(!request(["/bin/echo", "nul\u{0}byte"]).hasValidCommandLine,
          "an argument containing NUL is rejected")

    // The socket carries `Request`, whose hand-written flat codec is what the
    // installed client and daemon actually speak — not AccessRequest's synthesized
    // one — so the round trip has to go through it.
    let encoded = try! JSONEncoder().encode(Request.access(request(argv)))
    if case let .access(decoded) = try! JSONDecoder().decode(Request.self, from: encoded) {
        check(decoded.commandLine == argv, "the argv round-trips through the socket's request encoding")
        check(decoded.hasValidCommandLine, "the decoded argv still matches the plan's digest")
    } else {
        check(false, "an access request decodes as an access request")
    }

    // End to end through Agent: a value csecd released earlier, pasted verbatim
    // into a later command, reaches the review as a redaction label.
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "the command-line review test can read its own start time")
        return
    }
    let inspection = ProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) },
        parent: { ProcessAncestry.parent(of: $0) },
        name: { ProcessAncestry.name(of: $0) },
        executablePath: { ProcessAncestry.executablePath(of: $0) },
        hasControllingTerminal: { _ in false }
    )
    let first = "op://vault/deploy/token"
    let second = "op://vault/deploy/other"
    let releasedValue = "synthetic-released-token-value-0123456789"
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(CommandLineFixtureProvider(values: [
        first: Data(releasedValue.utf8),
        second: Data("another-synthetic-value".utf8),
    ]))
    let review = CommandLineCapturingReview()
    let agent = Agent(
        resolver: resolver,
        grants: GrantTable(),
        consent: CommandLineApprovingConsent(),
        policyReview: review,
        allowUnverifiedPlansForTesting: true,
        processInspection: inspection,
        terminalInspection: .unavailable
    )
    let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic launcher")

    func execRequest(references: [String], argv: [String]) -> AccessRequest {
        let plan = DeliveryPlan(
            mechanism: .unrestrictedInitialEnvironment,
            executable: PlannedExecutable(canonicalPath: argv[0], assurance: .unverified),
            root: .caller,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: 3_600,
            operationContext: "csec exec \(URL(fileURLWithPath: argv[0]).lastPathComponent)",
            commandDigest: try! ExecutableInspection.commandDigest(argv),
            outputGuard: OutputGuardPlan(mode: .always, labelStyle: .opaque)
        )
        return try! AccessRequest(
            references: references,
            reason: plan.operationContext,
            ttlSeconds: 3_600,
            deliveryPlan: plan,
            commandLine: argv
        )
    }

    let firstResponse = await agent.handle(
        request: execRequest(references: [first], argv: ["/bin/echo", "deploy", "--dry-run"]),
        caller: caller
    )
    check(firstResponse.values?[first] != nil, "the first exec releases its value")
    let firstShown = await review.lastCommandLine()
    check(firstShown == "/bin/echo deploy --dry-run",
          "the review receives the first command in full (got \(firstShown ?? "nil"))")

    let pasted = ["/usr/bin/curl", "-H", "Authorization: Bearer \(releasedValue)", "https://example.invalid"]
    let secondResponse = await agent.handle(
        request: execRequest(references: [second], argv: pasted),
        caller: caller
    )
    check(secondResponse.values?[second] != nil, "the second exec releases its value")
    let secondShown = await review.lastCommandLine() ?? ""
    check(!secondShown.contains(releasedValue),
          "a previously released value pasted into argv never reaches the review")
    check(secondShown.contains("[csec:secret-1]"),
          "the pasted value is shown as the standard redaction label (got \(secondShown))")
    check(secondShown.hasPrefix("/usr/bin/curl -H 'Authorization: Bearer "),
          "the rest of the command stays readable around the redaction")

    let tampered = await agent.handle(
        request: try! AccessRequest(
            references: [second],
            reason: "csec exec echo",
            ttlSeconds: 3_600,
            deliveryPlan: execRequest(references: [second], argv: ["/bin/echo", "real"]).deliveryPlan!,
            commandLine: ["/bin/echo", "shown-instead"]
        ),
        caller: caller
    )
    check(tampered.failure?.code == .invalidRequest,
          "csecd refuses an argv that does not match the plan's command digest")
}

private struct CommandLineFixtureProvider: SecretProvider {
    let values: [String: Data]

    var schemes: Set<String> { ["op"] }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let value = values[ref.uri] else {
            throw ProviderError.referenceNotFound(ref.uri)
        }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private struct CommandLineApprovingConsent: ConsentProvider {
    func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval?,
        policySummary: String?
    ) async -> ConsentOutcome {
        .approved(unlock: nil)
    }

    func authenticate(reason: String) async -> ConsentOutcome { .approved(unlock: nil) }
}

private actor CommandLineCapturingReview: PolicyReviewProvider {
    private var last: String?

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        last = review.commandLine
        let scope = review.scopeChoices?.options.first { $0.kind == .requestingCommand }
        return .approved(AccessPolicyApproval(
            selectedScopeOptionID: scope?.id,
            selectedDurationIndex: nil
        ))
    }

    func lastCommandLine() -> String? { last }
}
