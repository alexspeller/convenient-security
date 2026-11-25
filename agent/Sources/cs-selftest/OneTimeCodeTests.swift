import ConvenientSecurity
import CSECRemoteApproval
import Foundation
import LocalAuthentication
#if canImport(AppKit)
  import AppKit
#endif

/// One-time codes (csec-0.65): a reference ending in `?attribute=otp` gets a
/// fresh code after one approval per command, never cached, never covered by
/// a grant and never released by auto mode, and no ordinary reference ever
/// releases a 2FA seed.
func oneTimeCodeTests() async {
    print("\n# One-time codes (csec-0.65)")
    oneTimeCodeReferenceTests()
    oneTimeCodeGenerationTests()
    await oneTimeCodeResolverTests()
    await oneTimeCodeSeedGuardTests()
    oneTimeCodeWordingTests()
    await oneTimeCodeAgentTests()
    await phoneApprovalAttendanceTests()
    oneTimeCodePhoneMirrorTests()
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await MainActor.run { oneTimeCodePanelTests() }
    #endif
}

private func oneTimeCodeReferenceTests() {
    let codes = [
        "op://Private/npm/one-time password?attribute=otp",
        "op://Private/npm/one-time password?attribute=totp",
        "op://v/i/f?attribute=OTP",
        "op://v/i/f?Attribute=Totp",
        "op://v/i/f?attribute=%6Ftp",
        "op://v/i/f?attribute= otp ",
        "op://v/i/f?ssh-format=openssh&attribute=otp",
        "csec://npm/SEED?attribute=otp",
        "example://anything?attribute=otp",
    ]
    for uri in codes {
        check((try? SecretRef(uri))?.isOneTimeCode == true,
              "one-time code: \(uri) is recognised as a code (wider than 1Password's own grammar)")
    }
    let ordinary = [
        "op://Private/npm/one-time password",
        "op://v/i/f?ssh-format=openssh",
        "op://v/i/f?attribute=value",
        "op://v/i/f?attribute=otpx",
        "op://v/i/f?foo=otp",
        "op://v?attribute=otp/i/f",
        "csec://npm/SEED",
    ]
    for uri in ordinary {
        check((try? SecretRef(uri))?.isOneTimeCode == false,
              "one-time code: \(uri) is an ordinary reference")
    }
    check((try? SecretRef("op://Private/npm/one-time password?attribute=otp"))?.oneTimeCodeSeedReference?.uri
            == "op://Private/npm/one-time password"
            && (try? SecretRef("csec://npm/SEED?attribute=TOTP"))?.oneTimeCodeSeedReference?.uri == "csec://npm/SEED"
            && (try? SecretRef("csec://npm/SEED"))?.oneTimeCodeSeedReference == nil,
          "one-time code: the seed reference is the code reference without its query")
}

private func oneTimeCodeGenerationTests() {
    // RFC 6238 appendix B: the ASCII keys "12345678901234567890" (SHA-1),
    // its 32-byte (SHA-256) and 64-byte (SHA-512) repetitions, 8 digits.
    let sha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    let sha256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
    let sha512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="
    func code(_ uri: String, at seconds: TimeInterval) -> String? {
        (try? OneTimeCode.code(fromSeed: Data(uri.utf8), at: Date(timeIntervalSince1970: seconds)))
            .flatMap { String(data: $0, encoding: .utf8) }
    }
    let vectors: [(TimeInterval, String, String, String)] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ]
    for (time, one, two, five) in vectors {
        check(code("otpauth://totp/x?secret=\(sha1)&digits=8", at: time) == one
                && code("otpauth://totp/x?secret=\(sha256)&digits=8&algorithm=SHA256", at: time) == two
                && code("otpauth://totp/x?secret=\(sha512)&digits=8&algorithm=SHA512", at: time) == five,
              "one-time code: RFC 6238 test vectors at T=\(Int(time)) for SHA-1, SHA-256 and SHA-512")
    }
    check(code("otpauth://totp/npm:alex?secret=\(sha1.lowercased())&issuer=npm", at: 59) == "287082"
            && code(" OTPAUTH://TOTP/x?SECRET=GEZD GNBV-GY3T QOJQ GEZD GNBV GY3T QOJQ\n", at: 59) == "287082",
          "one-time code: six digits and thirty seconds by default; any case, spaces and hyphens in the secret")
    for (seed, label) in [
        ("otpauth://hotp/x?secret=\(sha1)&counter=1", "a counter-based seed"),
        ("otpauth://totp/x", "a seed with no secret"),
        ("otpauth://totp/x?secret=not*base32", "a secret that is not base32"),
        ("otpauth://totp/x?secret=\(sha1)&digits=4", "four digits"),
        ("otpauth://totp/x?secret=\(sha1)&algorithm=MD5", "an unknown algorithm"),
        ("otpauth://totp/x?secret=\(sha1)&secret=AAAA", "a repeated secret"),
        ("https://example.test/?secret=\(sha1)", "a URI that is not otpauth"),
        (sha1, "a bare base32 secret"),
    ] {
        check(code(seed, at: 59) == nil, "one-time code: \(label) gives no code")
    }
    check(OneTimeCode.isSeed(Data("otpauth://totp/x?secret=\(sha1)".utf8))
            && OneTimeCode.isSeed(Data("\n  OTPAuth://totp/x".utf8))
            && OneTimeCode.isSeed(Data("otpauth-migration://offline?data=AAAA".utf8))
            && !OneTimeCode.isSeed(Data("ghp_synthetic-token".utf8))
            && !OneTimeCode.isSeed(Data("123456".utf8))
            && !OneTimeCode.isSeed(Data([0xff, 0xfe, 0x00])),
          "one-time code: otpauth:// and otpauth-migration:// values are seeds, nothing else is")
}

/// A provider that records what it is asked for: as 1Password it makes codes
/// itself (a counter, marked cacheable to prove csecd ignores that), and as a
/// store it only holds values, seeds included.
private actor CodeFixtureProvider: SecretProvider {
    nonisolated let schemes: Set<String>
    private let makesCodes: Bool
    private let values: [String: Data]
    private(set) var resolved: [String] = []
    private var counter = 0

    init(scheme: String, makesCodes: Bool, values: [String: Data] = [:]) {
        self.schemes = [scheme]
        self.makesCodes = makesCodes
        self.values = values
    }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        resolved.append(ref.uri)
        if makesCodes, ref.isOneTimeCode {
            counter += 1
            return ResolvedSecret(value: Data(String(format: "%06d", counter).utf8), cacheHint: .cacheable)
        }
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: value, cacheHint: .cacheable)
    }

    func resolveWithoutInteraction(_ ref: SecretRef) async -> ResolvedSecret? {
        try? await resolve(ref, unlock: nil)
    }

    func reviewDescription(for ref: SecretRef) async -> ReviewSecret? {
        resolved.append("describe " + ref.uri)
        return ReviewSecret(
            provider: "fixture", tint: .teal, account: nil, container: "vault", item: "npm", field: "one-time password"
        )
    }

    func presence(of ref: SecretRef) async -> ReferencePresence {
        resolved.append("presence " + ref.uri)
        return .present
    }

    nonisolated func makesOneTimeCodes(_ ref: SecretRef) async -> Bool { makesCodes }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
    func asked() -> [String] { resolved }
}

private let fixtureSeed = "otpauth://totp/npm:alex?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=npm"

private func oneTimeCodeResolverTests() async {
    let unlock = CacheUnlock(LAContext())
    let code = try! SecretRef("op://Private/npm/one-time password?attribute=otp")
    let backend = FakeKeychainBackend()
    let cache = KeychainSecretCache(backend: backend)
    let resolver = SecretResolver(cache: cache)
    let onePassword = CodeFixtureProvider(scheme: "op", makesCodes: true)
    await resolver.register(onePassword)

    // An older csecd cached the first code with no expiry; that copy goes.
    try? await cache.put(code.uri, value: Data("999999".utf8))
    let first = try? await resolver.resolve(code, unlock: unlock)
    let second = try? await resolver.resolve(code, unlock: unlock)
    check(first == Data("000001".utf8) && second == Data("000002".utf8),
          "one-time code: every resolution asks the provider for a fresh code, even one it marks cacheable")
    check(!(await backend.has(code.uri)),
          "one-time code: a code is never written to the cache, and one an older csecd kept is dropped")
    check(await onePassword.asked() == [code.uri, code.uri],
          "one-time code: a provider that makes codes is asked for the code reference itself")

    // Never released with no person: delegation, a restore, a fetch ahead.
    check(await resolver.resolveWithoutInteraction(code) == nil,
          "one-time code: a code is never held for a release with no interaction")
    if case let .notHeld(reason) = await resolver.resolveForDelegation(code) {
        check(reason?.contains("one-time codes always need you") == true,
              "one-time code: auto mode's release says a code always needs a person")
    } else {
        check(false, "one-time code: auto mode's release says a code always needs a person")
    }
    check(await resolver.referencesRestorable([code]).isEmpty,
          "one-time code: a restore has nothing to reopen for a code")
    let fetched = await resolver.fetchAhead([code])
    let askedAfterFetch = await onePassword.asked().count
    check(fetched.summary.fetched == 0 && fetched.summary.failureCount == 0 && askedAfterFetch == 2,
          "one-time code: the attended fetch ahead skips codes without asking the provider")

    // A store that cannot make codes is asked only for the seed, and csecd
    // makes the code; the seed itself never leaves the resolver.
    let store = CodeFixtureProvider(scheme: "csec", makesCodes: false, values: [
        "csec://npm/SEED": Data(fixtureSeed.utf8),
        "csec://npm/TOKEN": Data("synthetic-npm-token".utf8),
    ])
    await resolver.register(store)
    let nativeCode = try! SecretRef("csec://npm/SEED?attribute=otp")
    let made = try? await resolver.resolve(nativeCode, unlock: unlock)
    let expected = try? OneTimeCode.code(fromSeed: Data(fixtureSeed.utf8))
    check(made != nil && made == expected && made != Data(fixtureSeed.utf8) && made?.count == 6,
          "one-time code: csecd works a store's code out from its otpauth:// seed")
    _ = await resolver.referencesKnownAbsent([nativeCode])
    _ = await resolver.reviewSecret(for: nativeCode)
    let storeAsked = await store.asked()
    check(storeAsked == ["csec://npm/SEED", "presence csec://npm/SEED", "describe csec://npm/SEED"],
          "one-time code: a provider that cannot make codes never sees the code suffix")
    let codeCached = await backend.has(nativeCode.uri)
    let seedCached = await backend.has("csec://npm/SEED")
    check(!codeCached && !seedCached, "one-time code: neither the code nor its seed is cached")
    do {
        _ = try await resolver.resolve(try SecretRef("csec://npm/TOKEN?attribute=otp"), unlock: unlock)
        check(false, "one-time code: a stored value that is not a seed gives no code")
    } catch let error as OneTimeCodeError {
        check(error.boundedReason.hasPrefix("csec could not work out a one-time code"),
              "one-time code: a stored value that is not a seed gives no code")
    } catch {
        check(false, "one-time code: a stored value that is not a seed gives no code (\(error))")
    }

    // The review names the code as one, on every surface through its notes.
    let described = await resolver.reviewSecret(for: code)
    check(described.notes.first == ReviewDisplay.oneTimeCodeNote(item: "npm"),
          "one-time code: the review's secret carries csec's one-time-code note first")
    let plain = await resolver.reviewSecret(for: try! SecretRef("csec://npm/TOKEN"))
    check(plain.notes.isEmpty, "one-time code: an ordinary secret carries no such note")
}

private func oneTimeCodeSeedGuardTests() async {
    let unlock = CacheUnlock(LAContext())
    let backend = FakeKeychainBackend()
    let cache = KeychainSecretCache(backend: backend)
    let resolver = SecretResolver(cache: cache)
    let store = CodeFixtureProvider(scheme: "op", makesCodes: false, values: [
        "op://Private/npm/one-time password": Data(fixtureSeed.utf8),
        "op://Private/npm/password": Data("synthetic-password".utf8),
    ])
    await resolver.register(store)
    let seed = try! SecretRef("op://Private/npm/one-time password")
    do {
        _ = try await resolver.resolve(seed, unlock: unlock)
        check(false, "seed guard: an ordinary reference to a seed is refused")
    } catch let error as OneTimeCodeError {
        check(error == .seedRefused && error.boundedReason.contains("?attribute=otp"),
              "seed guard: an ordinary reference to a seed is refused, and the reason names ?attribute=otp")
    } catch {
        check(false, "seed guard: an ordinary reference to a seed is refused (\(error))")
    }
    check(!(await backend.has(seed.uri)), "seed guard: a refused seed is never cached")
    // One an older csecd cached is refused from the cache too.
    try? await cache.put(seed.uri, value: Data(fixtureSeed.utf8))
    let fromCache = try? await resolver.resolve(seed, unlock: unlock)
    let heldSeed = await resolver.resolveWithoutInteraction(seed)
    check(fromCache == nil && heldSeed == nil, "seed guard: a seed already in the cache is never released")
    _ = await resolver.invalidate(references: [seed.uri])
    let fetched = await resolver.fetchAhead([seed])
    let seedKept = await backend.has(seed.uri)
    check(fetched.summary.fetched == 0 && !seedKept
            && fetched.summary.failures.first?.reason == OneTimeCodeError.seedRefused.boundedReason,
          "seed guard: the attended fetch ahead never keeps a seed")
    let password = try? await resolver.resolve(try SecretRef("op://Private/npm/password"), unlock: unlock)
    check(password == Data("synthetic-password".utf8), "seed guard: an ordinary value still resolves")
}

private func oneTimeCodeWordingTests() {
    let code = try! SecretRef("op://Private/npm/one-time password?attribute=otp")
    let token = try! SecretRef("op://Private/npm/token")
    let plan = DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/npm", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        operationContext: "csec exec npm publish"
    )
    func review(_ refs: [SecretRef]) -> AccessPolicyReview {
        AccessPolicyReview(
            caller: CallerInfo(pid: 4_100, startTime: 1, description: "synthetic"),
            reason: "npm publish", plan: plan,
            credentials: [PolicyReviewCredential(references: refs)]
        )
    }
    let only = review([code])
    let mixed = review([code, token])
    check(ReviewDisplay.accessHeadline(for: only) == "One-Time Code Requested"
            && ReviewDisplay.accessHeadline(for: mixed) == "Secret Access Requested",
          "one-time code wording: a code-only panel is headed as one")
    check(ReviewDisplay.secretsHeading(for: only, count: 1) == "One-time code released"
            && ReviewDisplay.secretsHeading(for: mixed, count: 2) == "Secrets released",
          "one-time code wording: the secrets heading names a code-only release")
    let option = GrantScopeOption(kind: .codingAgent, pid: 4_000, startTime: 1, processLabel: "Claude Code")
    check(ReviewDisplay.touchIDReadyText(for: only, scope: nil, duration: .processLifetime)
            == "Touch ID is ready. Touch the sensor to release a one-time code to this command.",
          "one-time code wording: the sensor line says the code is for this command")
    check(ReviewDisplay.touchIDReadyText(for: mixed, scope: option, duration: .processLifetime)
            .hasSuffix("for as long as it runs, and a one-time code to this command only."),
          "one-time code wording: a mixed release says the code alone is for this command")

    var record = DecisionLogRecord(kind: .panel, refs: [code.uri, token.uri], cause: DecisionLogPromptCause.oneTimeCode.rawValue)
    record.wallTime = DecisionLogTime(Date(timeIntervalSince1970: 0))
    let line = record.displayLine(timeZone: TimeZone(identifier: "UTC")!)
    check(line.contains("one_time_code") && line.contains("one-time code"),
          "one-time code wording: csec log lists the release as a one-time code")
}

/// Approves every panel selecting the widest scope it offers, and records
/// what each panel offered.
private actor CodeRecordingReview: PolicyReviewProvider {
    private(set) var reviews: [AccessPolicyReview] = []

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews.append(review)
        return .approved(AccessPolicyApproval(
            selectedScopeOptionID: review.scopeChoices?.options.last?.id,
            selectedDurationIndex: nil
        ))
    }

    func all() -> [AccessPolicyReview] { reviews }
}

private actor CodeApprovingConsent: ConsentProvider {
    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome { .approved(unlock: nil) }

    func authenticate(reason: String) async -> ConsentOutcome { .approved(unlock: nil) }
}

private func oneTimeCodeAgentTests() async {
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let parent = ProcessAncestry.parent(of: me), parent > 1,
          let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "one-time code agent: the test can read its own live ancestry")
        return
    }
    // The real parent reads as an interactive shell, so a terminal-session
    // root is on offer wherever the suite runs.
    let inspection = ProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) },
        parent: { ProcessAncestry.parent(of: $0) },
        name: { $0 == parent ? "zsh" : ProcessAncestry.name(of: $0) },
        executablePath: { ProcessAncestry.executablePath(of: $0) },
        hasControllingTerminal: { $0 == parent }
    )
    let code = "op://Private/npm/one-time password?attribute=otp"
    let token = "op://Private/npm/token"
    let resolver = SecretResolver(cache: NullSecretCache())
    let provider = CodeFixtureProvider(scheme: "op", makesCodes: true, values: [token: Data("synthetic-npm-token".utf8)])
    await resolver.register(provider)
    let review = CodeRecordingReview()
    let grants = GrantTable()
    let agent = Agent(
        resolver: resolver, grants: grants, consent: CodeApprovingConsent(), policyReview: review,
        allowUnverifiedPlansForTesting: true, processInspection: inspection,
        terminalInspection: .unavailable
    )
    let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic launcher")
    func publish(_ references: [String], digest: Character) async -> Response {
        let plan = DeliveryPlan(
            mechanism: .unrestrictedInitialEnvironment,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/npm", assurance: .unverified),
            root: .caller, descendantScope: .subtree, destination: .localDevelopment,
            operationContext: "csec exec npm publish",
            commandDigest: String(repeating: digest, count: 64),
            outputGuard: OutputGuardPlan(mode: .tty)
        )
        return await agent.handle(
            request: try! AccessRequest(references: references, reason: "npm publish", ttlSeconds: nil, deliveryPlan: plan),
            caller: caller
        )
    }

    // The token and the code together: one panel; the token is granted at
    // the scope chosen, the code is not granted at all.
    let first = await publish([token, code], digest: "a")
    let firstReviews = await review.all()
    let afterFirst = await grants.summaries(now: Date())
    check(first.values?[code] == Data("000001".utf8) && first.values?[token] != nil && firstReviews.count == 1,
          "one-time code agent: the first publish gets one panel and both values")
    check(afterFirst.count == 1 && afterFirst.first?.references == [token]
            && afterFirst.first?.scopeKind == .terminalSession,
          "one-time code agent: the token's grant is minted at the chosen scope; no grant names the code")
    check(firstReviews.first?.scopeChoices?.options.count ?? 0 > 1 && firstReviews.first?.durationChoices != nil,
          "one-time code agent: a panel with an ordinary secret still offers its scopes and lifetimes")

    // The next publish, a different command: the token rides its grant, the
    // code asks again, on a panel that offers nothing past this command.
    let second = await publish([token, code], digest: "b")
    let secondReviews = await review.all()
    let codePanel = secondReviews.last
    check(second.values?[code] == Data("000002".utf8) && second.values?[token] != nil && secondReviews.count == 2,
          "one-time code agent: the next publish asks again and gets a fresh code")
    check(codePanel?.credentials.flatMap(\.references).map(\.uri) == [code]
            && codePanel?.scopeChoices?.options.map(\.kind) == [.requestingCommand]
            && codePanel?.durationChoices == nil
            && codePanel.map(ReviewDisplay.releasesOnlyOneTimeCodes) == true,
          "one-time code agent: a code-only panel offers only this command and no lifetime")
    let afterSecond = await grants.summaries(now: Date())
    check(afterSecond.count == 1 && afterSecond.allSatisfy { !$0.references.contains(code) },
          "one-time code agent: approving a code-only panel mints nothing")

    // The same command again: no grant covers a code, even per command.
    _ = await publish([code], digest: "b")
    check(await review.all().count == 3, "one-time code agent: the same command asking again gets another panel")
}

/// The phone's copy of a code-only review, as csecd freezes it for the paired
/// iPhone: the card draws its lifetime menu from `durationOptions` and its
/// scope choices from `scopeOptions`, so a code-only release reaches the phone
/// with this command as its one scope, no lifetime and the one-time-code note,
/// as the Mac panel shows it.
private func oneTimeCodePhoneMirrorTests() {
    let caller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
    let plan = DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/npm", assurance: .unverified),
        descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: nil, operationContext: "csec exec npm publish"
    )
    let code = try! SecretRef("op://Private/npm/one-time password?attribute=otp")
    let token = try! SecretRef("op://Private/npm/token")
    func described(_ ref: SecretRef, field: String) -> ReviewSecret {
        ReviewDisplay.oneTimeCodeSecret(ReviewSecret(
            provider: "1Password", tint: .teal, account: "my.1password.com", container: "Private",
            item: "npm", field: field
        ), for: ref)
    }
    let command = GrantScopeOption(kind: .requestingCommand, pid: 4_100, startTime: 7, processLabel: "npm")
    let agent = GrantScopeOption(kind: .codingAgent, pid: 4_000, startTime: 6, processLabel: "Claude Code")

    let only = AccessPolicyReview(
        caller: caller, reason: "npm publish", plan: plan, commandLine: "npm publish --otp=$NPM_OTP",
        credentials: [PolicyReviewCredential(described: [(code, described(code, field: "one-time password"))])],
        scopeChoices: GrantScopeChoices(options: [command], defaultOptionID: command.id),
        durationChoices: nil
    )
    guard let phone = try? RemoteApprovalReview(accessPolicyReview: only) else {
        check(false, "one-time code phone: a code-only review can be frozen for the phone")
        return
    }
    check(phone.durationOptions.isEmpty && phone.scopeOptions.map(\.id) == [command.id],
          "one-time code phone: a code-only review offers the phone this command only and no lifetime")
    check(phone.secrets.flatMap(\.notes).contains(ReviewDisplay.oneTimeCodeNote(item: "npm")),
          "one-time code phone: the phone's copy carries the one-time-code note")
    let shown: [String] = [phone.headline] + phone.secrets.flatMap { secret -> [String] in
        [secret.item] + (secret.field.map { [$0] } ?? []) + secret.notes
    }
    check(!shown.contains(where: { $0.contains("?attribute=") || $0.contains("op://") }),
          "one-time code phone: the code's reference is never shown raw on the phone")

    let mixed = AccessPolicyReview(
        caller: caller, reason: "npm publish", plan: plan, commandLine: "npm publish --otp=$NPM_OTP",
        credentials: [PolicyReviewCredential(described: [
            (code, described(code, field: "one-time password")), (token, described(token, field: "token")),
        ])],
        scopeChoices: GrantScopeChoices(options: [command, agent], defaultOptionID: agent.id),
        durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil)
    )
    let mixedPhone = try? RemoteApprovalReview(accessPolicyReview: mixed)
    check(mixedPhone.map { !$0.durationOptions.isEmpty && $0.scopeOptions.count == 2 } == true,
          "one-time code phone: a code beside an ordinary secret still offers the phone its scopes and lifetimes")
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  /// The secret-access panel's real window for a code-only release and for a
  /// code beside an ordinary secret, built offscreen with no Touch ID.
  @MainActor
  private func oneTimeCodePanelTests() {
    NSApplication.shared.setActivationPolicy(.accessory)
    let caller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
    let plan = DeliveryPlan(
      mechanism: .unrestrictedInitialEnvironment,
      executable: PlannedExecutable(canonicalPath: "/usr/bin/npm", assurance: .unverified),
      descendantScope: .subtree, destination: .localDevelopment,
      requestedTTLSeconds: nil, operationContext: "csec exec npm publish"
    )
    let code = try! SecretRef("op://Private/npm/one-time password?attribute=otp")
    let token = try! SecretRef("op://Private/npm/token")
    func described(_ ref: SecretRef, field: String) -> ReviewSecret {
      ReviewDisplay.oneTimeCodeSecret(ReviewSecret(
        provider: "1Password", tint: .teal, account: "my.1password.com", container: "Private",
        item: "npm", field: field
      ), for: ref)
    }
    let command = GrantScopeOption(kind: .requestingCommand, pid: 4_100, startTime: 7, processLabel: "npm")
    let agent = GrantScopeOption(kind: .codingAgent, pid: 4_000, startTime: 6, processLabel: "Claude Code")
    func views(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(views) }

    let only = AccessPolicyReview(
      caller: caller, reason: "npm publish", plan: plan, commandLine: "npm publish --otp=$NPM_OTP",
      credentials: [PolicyReviewCredential(described: [(code, described(code, field: "one-time password"))])],
      scopeChoices: GrantScopeChoices(options: [command], defaultOptionID: command.id),
      durationChoices: nil
    )
    let panel = ApprovalPanelInspection.access(only)
    panel.window.contentView?.layoutSubtreeIfNeeded()
    let content = views(panel.window.contentView ?? NSView())
    let texts = content.compactMap { ($0 as? NSTextField)?.stringValue }
    check(texts.contains("One-Time Code Requested") && texts.contains("ONE-TIME CODE RELEASED")
            && texts.contains(ReviewDisplay.oneTimeCodeLifetime)
            && texts.contains(ReviewDisplay.oneTimeCodeLifetimeDetail)
            && texts.contains(ReviewDisplay.oneTimeCodeNote(item: "npm")),
          "one-time code panel: a code-only release is headed as one, says this command only and shows the note")
    check(!content.contains { $0 is NSPopUpButton } && panel.unregisteredControls.isEmpty,
          "one-time code panel: a code-only release offers no lifetime, and every control it draws is guarded")
    check(!texts.contains(where: { $0.contains("?attribute=") || $0.contains("op://") }),
          "one-time code panel: the code's reference is never shown raw")
    let reason = ApprovalPanelInspection.accessAuthenticationReason(only)
    check(reason.hasPrefix("release a one-time code to cs-selftest fixture (pid 51) for this command only")
            && !reason.contains("duration:"),
          "one-time code panel: Touch ID's reason says the code is for this command, with no lifetime")

    let mixed = AccessPolicyReview(
      caller: caller, reason: "npm publish", plan: plan, commandLine: "npm publish --otp=$NPM_OTP",
      credentials: [PolicyReviewCredential(described: [
        (code, described(code, field: "one-time password")), (token, described(token, field: "token")),
      ])],
      scopeChoices: GrantScopeChoices(options: [command, agent], defaultOptionID: agent.id),
      durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil)
    )
    let mixedPanel = ApprovalPanelInspection.access(mixed)
    mixedPanel.window.contentView?.layoutSubtreeIfNeeded()
    let mixedContent = views(mixedPanel.window.contentView ?? NSView())
    let mixedTexts = mixedContent.compactMap { ($0 as? NSTextField)?.stringValue }
    check(mixedTexts.contains("Secret Access Requested") && mixedContent.contains { $0 is NSPopUpButton }
            && mixedTexts.contains(ReviewDisplay.oneTimeCodeNote(item: "npm"))
            && mixedPanel.unregisteredControls.isEmpty,
          "one-time code panel: beside an ordinary secret, the panel keeps its lifetime choice and notes the code")
    withExtendedLifetime([panel, mixedPanel]) {}
  }
#endif
