import ConvenientSecurity
import Foundation
import LocalAuthentication

// A bare Touch ID sheet that ends without approving keeps why (csec-0.51):
// the human's Deny, a sheet macOS dismissed and a finger not recognised are
// distinct reasons, a dismissal with the screen unlocked is shown once more,
// and `csec setup` says which it was.

func consentRefusalTests() async {
    print("\n# Touch ID sheet refusals: why a bare sheet ended")
    refusalCauseTests()
    refusalLogFieldTests()
    showAgainRuleTests()
    await explainingProviderTests()
    setupNotGivenMessageTests()
    print("\n# Secret-access panel refusals: how an unapproved review ended")
    panelDenialWordsTests()
    await panelDenialMessageTests()
}

private func refusalCauseTests() {
    let expected: [(LAError.Code, ConsentRefusal.Cause)] = [
        (.userCancel, .userCancel),
        (.systemCancel, .systemCancel),
        (.appCancel, .appCancel),
        (.authenticationFailed, .authenticationFailed),
        (.userFallback, .userFallback),
        (.biometryLockout, .biometryLockout),
        (.biometryNotAvailable, .touchIDUnavailable),
        (.biometryNotEnrolled, .touchIDUnavailable),
        (.passcodeNotSet, .touchIDUnavailable),
        (.notInteractive, .notInteractive),
        (.invalidContext, .other),
    ]
    for (code, cause) in expected {
        check(ConsentRefusal.cause(errorCode: code.rawValue) == cause,
              "refusal cause: LAError \(code.rawValue) is \(cause.rawValue)")
    }
    check(ConsentRefusal.cause(errorCode: nil) == .other && ConsentRefusal.cause(errorCode: 424_242) == .other,
          "refusal cause: no code, or one LocalAuthentication does not define, is other")
    let whys = Set(ConsentRefusal.Cause.allCases.map { ConsentRefusal(cause: $0, errorCode: -99).why })
    check(whys.count == ConsentRefusal.Cause.allCases.count, "refusal cause: every cause has its own words")
    check(ConsentRefusal(cause: .userCancel).isHumanRefusal
            && ConsentRefusal.Cause.allCases.filter { ConsentRefusal(cause: $0).isHumanRefusal } == [.userCancel],
          "refusal cause: only the sheet's Deny is the human refusing")
}

private func refusalLogFieldTests() {
    let deny = ConsentRefusal(errorCode: LAError.Code.userCancel.rawValue, shownFor: .milliseconds(8_042))
    check(deny.logOutcome == .denied && deny.logDecider == .humanLocal && deny.logCause == "user_cancel"
            && deny.ttdMs == 8_042,
          "refusal log: a Deny is a human_local denial with its time on screen")
    check(deny.summary == "you pressed Deny; the sheet was up 8.0s", "refusal log: a Deny's summary says so plainly")
    let dismissed = ConsentRefusal(errorCode: LAError.Code.systemCancel.rawValue, shownFor: .seconds(2), shownAgain: true)
    check(dismissed.logOutcome == .authenticationFailed && dismissed.logDecider == nil
            && dismissed.logCause == "system_cancel" && dismissed.summary.contains("shown again"),
          "refusal log: a dismissal is no human's denial, and says it was a second showing")
    let gone = ConsentRefusal(cause: .requesterGone)
    check(gone.logOutcome == .requesterGone && gone.ttdMs == nil && gone.summary == "the request went away",
          "refusal log: a requester that left is requester_gone, with no time on screen when no sheet was up")
    let unknown = ConsentRefusal(errorCode: LAError.Code.invalidContext.rawValue)
    check(unknown.logCause == "la_error_\(LAError.Code.invalidContext.rawValue)"
            && unknown.why.contains("\(LAError.Code.invalidContext.rawValue)"),
          "refusal log: an unmapped LAError keeps its code in the cause and the words")
    check(ConsentRefusal.Cause.allCases.allSatisfy { $0.rawValue.count <= 17 } && "la_error_-1004".count <= 17,
          "refusal log: every cause fits csec log's CAUSE column")
}

private func showAgainRuleTests() {
    for cause in ConsentRefusal.Cause.allCases {
        check(BiometricConsent.next(after: cause, screenLocked: true, shownAgain: true) == .waitForUnlock,
              "show again: with the screen locked, \(cause.rawValue) waits for unlock, as before")
    }
    for cause in [ConsentRefusal.Cause.systemCancel, .appCancel] {
        check(BiometricConsent.next(after: cause, screenLocked: false, shownAgain: false) == .showAgain
                && BiometricConsent.next(after: cause, screenLocked: false, shownAgain: true) == .refuse,
              "show again: an unlocked \(cause.rawValue) is shown once more, then refuses")
    }
    let refusing = ConsentRefusal.Cause.allCases.filter { $0 != .systemCancel && $0 != .appCancel }
    check(refusing.allSatisfy { BiometricConsent.next(after: $0, screenLocked: false, shownAgain: false) == .refuse },
          "show again: Deny, a finger not recognised and every other unlocked end refuse at once")
}

/// Answers `authenticate` only, as an injected provider written before
/// `authenticateExplaining` did.
private struct SilentConsent: ConsentProvider {
    let approve: Bool

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        approve ? .approved(unlock: nil) : .denied
    }
}

/// Explains every refusal with `refusal`, after `delay`.
private struct ExplainingConsent: ConsentProvider {
    let refusal: ConsentRefusal
    var delay: Duration = .zero

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        await authenticateExplaining(reason: reason).outcome
    }

    func authenticateExplaining(reason: String) async -> ConsentAnswer {
        if delay > .zero { try? await Task.sleep(for: delay) }
        return .refused(refusal)
    }
}

private func explainingProviderTests() async {
    let silentDenial = await SilentConsent(approve: false).authenticateExplaining(reason: "r")
    let silentApproval = await SilentConsent(approve: true).authenticateExplaining(reason: "r")
    check(silentDenial.refusal == .unexplained && silentApproval.refusal == nil && silentApproval.outcome.isApproved,
          "explaining: a provider that cannot say why refuses as unexplained and approves as before")

    let dismissed = ConsentRefusal(errorCode: LAError.Code.systemCancel.rawValue, shownFor: .seconds(3))
    let queued = QueuedConsentProvider(underlying: ExplainingConsent(refusal: dismissed), queue: ConsentQueue())
    let passed = await queued.authenticateExplaining(reason: "r")
    let plain = await queued.authenticate(reason: "r")
    check(passed.refusal == dismissed && !plain.isApproved,
          "explaining: the shared queue passes the sheet's reason through")

    let held = ConsentQueue()
    let ahead = try? await held.acquire()
    let waiting = Task {
        await QueuedConsentProvider(underlying: ExplainingConsent(refusal: dismissed), queue: held)
            .authenticateExplaining(reason: "r")
    }
    var queuedUp = false
    for _ in 0..<200 where !queuedUp {
        queuedUp = await held.waitingCount == 1
        if !queuedUp { try? await Task.sleep(for: .milliseconds(5)) }
    }
    waiting.cancel()
    let withdrawn = await waiting.value
    await ahead?.release()
    check(queuedUp && withdrawn.refusal?.cause == .requesterGone && withdrawn.refusal?.shownFor == nil,
          "explaining: a request that leaves while queued is requester_gone, with no sheet shown")

    let slow = Task {
        await QueuedConsentProvider(
            underlying: ExplainingConsent(refusal: dismissed, delay: .milliseconds(200)), queue: ConsentQueue()
        ).authenticateExplaining(reason: "r")
    }
    try? await Task.sleep(for: .milliseconds(50))
    slow.cancel()
    let goneWhileUp = await slow.value
    check(goneWhileUp.refusal?.cause == .requesterGone && goneWhileUp.refusal?.shownFor == .seconds(3),
          "explaining: a request that leaves while its sheet is up is requester_gone, keeping the time on screen")
}

private func setupNotGivenMessageTests() {
    let deny = ClaudeDelegationSetup.notGivenMessage("you pressed Deny; the sheet was up 8.0s", unchanged: "nothing changed")
    check(deny == "Touch ID was not given: you pressed Deny; the sheet was up 8.0s; nothing changed.",
          "setup message: csecd's reason follows \"Touch ID was not given\", which scripts match on")
    check(ClaudeDelegationSetup.notGivenMessage("", unchanged: "nothing changed") == "Touch ID was not given; nothing changed.",
          "setup message: no reason reads as before")
    let hostile = ClaudeDelegationSetup.notGivenMessage("Deny\n✓ Acknowledged.", unchanged: "nothing changed")
    check(!hostile.contains("\n"), "setup message: csecd's reason cannot add a line to setup's output")
}

// A secret-access panel that ends unapproved tells its requester how
// (csec-0.73): a bare "policy review denied" read as the human refusing, so a
// failed Touch ID was routed as a refusal instead of being asked again.

private let everyPanelDenial: [(String, AccessPolicyDenialReason)] = [
    ("Mac Deny", .human(decidedAt: .now, on: .mac)),
    ("iPhone Deny", .human(decidedAt: .now, on: .phone)),
    ("reviewer Deny", .human(decidedAt: .now)),
    ("requester gone", .requesterGone),
    ("withdrawn", .withdrawn),
    ("timed out", .timedOut),
    ("Touch ID failed", .authenticationFailed),
]

private func panelDenialWordsTests() {
    let words = everyPanelDenial.map { $0.1.endedText }
    check(Set(words).count == everyPanelDenial.count, "panel denial: every way a review ends has its own words")
    check(everyPanelDenial.allSatisfy { $0.1.deniedMessage().hasPrefix("policy review denied: ") },
          "panel denial: the reason follows \"policy review denied\", which agent tooling matches on")
    let failed = AccessPolicyDenialReason.authenticationFailed.endedText
    check(failed.contains("not a refusal") && failed.contains("csec log") && !failed.contains("refused it"),
          "panel denial: a failed Touch ID says it is not a refusal and where its outcome is")
    check(everyPanelDenial.filter { $0.1.endedText.contains("refused") }.count == 3,
          "panel denial: only the human's Deny reads as a refusal")
}

private struct FixedPanel: PolicyReviewProvider {
    let outcome: AccessPolicyReviewOutcome
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome { outcome }
}

private struct NeverAskedConsent: ConsentProvider {
    func requestConsent(caller: CallerInfo, newReferences: [SecretRef], reason: String,
                        ttl: TimeInterval?, policySummary: String?) async -> ConsentOutcome { .denied }
    func authenticate(reason: String) async -> ConsentOutcome { .denied }
}

private struct PanelDenialProvider: SecretProvider {
    var schemes: Set<String> { ["op"] }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        ResolvedSecret(value: Data("synthetic-panel-denial-value".utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private func panelDenialMessageTests() async {
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let start = ProcessAncestry.startTime(of: me) else {
        check(false, "panel denial: the fixture reads its own start time")
        return
    }
    let caller = CallerInfo(pid: me, startTime: start, description: "synthetic panel-denial caller")
    let inspection = ProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) }, parent: { _ in 1 },
        name: { ProcessAncestry.name(of: $0) }, executablePath: { ProcessAncestry.executablePath(of: $0) },
        hasControllingTerminal: { _ in false }
    )
    // `csec exec` hands its child the environment; `csec get` keeps the value
    // in its own heap. Both reach the same review.
    let plans: [(String, DeliveryPlan)] = [
        ("csec exec", DeliveryPlan(
            mechanism: .unrestrictedInitialEnvironment,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/true", assurance: .unverified),
            root: .caller, descendantScope: .subtree, destination: .localDevelopment,
            operationContext: "synthetic exec", outputGuard: OutputGuardPlan(mode: .tty)
        )),
        ("csec get", DeliveryPlan(
            mechanism: .directHeap,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/true", assurance: .unverified),
            root: .caller, descendantScope: .subtree, destination: .localDevelopment,
            operationContext: "synthetic get"
        )),
    ]
    for (label, reason) in everyPanelDenial {
        for (command, plan) in plans {
            let resolver = SecretResolver(cache: NullSecretCache())
            await resolver.register(PanelDenialProvider())
            let agent = Agent(
                resolver: resolver, grants: GrantTable(), consent: NeverAskedConsent(),
                policyReview: FixedPanel(outcome: .denied(reason)),
                allowUnverifiedPlansForTesting: true, processInspection: inspection,
                terminalInspection: .unavailable
            )
            let request = try! AccessRequest(
                references: ["op://panel-denial/item/password"], reason: plan.operationContext, deliveryPlan: plan
            )
            let response = await agent.handle(request: request, caller: caller)
            let message = response.failure?.message ?? ""
            check(response.values == nil && response.failure?.code == .consentDenied
                  && message == "policy review denied: \(reason.endedText)",
                  "panel denial: \(command) after \(label) says so (\(message))")
        }
    }

    let editor = CallerInfo(pid: 41_730, startTime: 4_173, description: "synthetic editor")
    let editorInspection = ProcessInspection(
        startTime: { $0 == editor.pid ? editor.startTime : nil }, parent: { _ in 1 },
        name: { _ in "synthetic" }, executablePath: { _ in "/synthetic/csec" }
    )
    for (label, reason) in everyPanelDenial {
        let store = NativeEncryptedFileProvider(
            keyBackend: InMemoryNativeStoreKeyBackend(), fileBackend: InMemoryNativeStoreFileBackend()
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(store)
        let agent = Agent(
            resolver: resolver, grants: GrantTable(), consent: NeverAskedConsent(),
            policyReview: FixedPanel(outcome: .denied(reason)), nativeStore: store,
            allowUnverifiedPlansForTesting: true, processInspection: editorInspection,
            terminalInspection: .unavailable
        )
        let response = await agent.beginNativeStoreEdit(
            request: BeginNativeStoreEditRequest(
                store: "paneldenial", mode: .externalTemporaryFile, externalEditorPath: "/usr/bin/true"
            ),
            caller: editor
        )
        let message = response.failure?.message ?? ""
        check(response.failure?.code == .consentDenied
              && message == "native-store policy review denied: \(reason.endedText)",
              "panel denial: a native-store edit after \(label) says so (\(message))")
    }
}
