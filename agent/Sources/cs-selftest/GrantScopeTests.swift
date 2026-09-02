import ConvenientSecurity
import Foundation

/// Selectable grant scopes: which roots csecd offers above a verified plan root,
/// which one it pre-selects, and how a widened grant is reused.
///
/// The synthetic trees mirror the shape measured on a real machine:
///     iTerm2 → iTermServer → login → fish(tty) → claude(tty)
///         → zsh(no tty, one per tool call) → csec tool-exec
///             → zsh(no tty) → csec exec
/// The per-tool-call shells report no controlling terminal, which is what
/// separates them from the terminal session itself.
struct SyntheticTree {
    var parents: [pid_t: pid_t] = [:]
    var names: [pid_t: String] = [:]
    var paths: [pid_t: String] = [:]
    var terminals: Set<pid_t> = []
    var startTimes: [pid_t: UInt64] = [:]

    mutating func add(
        pid: pid_t,
        parent: pid_t,
        name: String,
        path: String? = nil,
        hasTerminal: Bool = false
    ) {
        parents[pid] = parent
        names[pid] = name
        paths[pid] = path ?? "/usr/bin/\(name)"
        startTimes[pid] = UInt64(1_000 + pid)
        if hasTerminal { terminals.insert(pid) }
    }

    var inspection: ProcessInspection {
        let parents = parents, names = names, paths = paths
        let terminals = terminals, startTimes = startTimes
        return ProcessInspection(
            startTime: { startTimes[$0] },
            parent: { parents[$0] },
            name: { names[$0] },
            executablePath: { paths[$0] },
            hasControllingTerminal: { terminals.contains($0) }
        )
    }

    func startTime(_ pid: pid_t) -> UInt64 { startTimes[pid] ?? 0 }
}

/// The measured Claude-under-iTerm shape, ending at a `csec exec` plan root.
private func claudeTree() -> SyntheticTree {
    var tree = SyntheticTree()
    tree.add(pid: 1602, parent: 1, name: "iTerm2", path: "/Applications/iTerm.app/Contents/MacOS/iTerm2")
    tree.add(pid: 1642, parent: 1602, name: "iTermServer")
    tree.add(pid: 2584, parent: 1642, name: "login", hasTerminal: true)
    tree.add(pid: 2589, parent: 2584, name: "fish", hasTerminal: true)
    // proc_name for the native Claude installer is the version, not "claude";
    // only the versions-directory path identifies it. Measured on a live agent.
    tree.add(
        pid: 31163, parent: 2589, name: "2.1.252",
        path: "/Users/tester/.local/share/claude/versions/2.1.252",
        hasTerminal: true
    )
    tree.add(pid: 65048, parent: 31163, name: "zsh", path: "/bin/zsh")
    tree.add(pid: 65051, parent: 65048, name: "csec", path: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec")
    tree.add(pid: 65054, parent: 65051, name: "zsh", path: "/bin/zsh")
    tree.add(pid: 65060, parent: 65054, name: "csec", path: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec")
    return tree
}

private func choices(
    _ tree: SyntheticTree,
    planRoot: pid_t,
    label: String = "csec"
) -> GrantScopeChoices {
    GrantScopeInspector.choices(
        planRootPID: planRoot,
        planRootStartTime: tree.startTime(planRoot),
        requestingLabel: label,
        inspection: tree.inspection
    )
}

func grantScopeTests() async {
    print("\n# GrantScopeInspector (process-tree scope discovery)")

    let tree = claudeTree()
    let agentChoices = choices(tree, planRoot: 65060)

    check(agentChoices.options.map(\.kind) == [.requestingCommand, .codingAgent, .terminalSession],
          "the measured Claude tree offers command, coding agent, and terminal session")
    check(agentChoices.defaultOption.kind == .codingAgent,
          "an agent ancestor is the default scope")
    check(agentChoices.defaultOption.pid == 31163,
          "the default scope is rooted at the agent's pid")
    check(agentChoices.defaultOption.processLabel == "Claude Code",
          "the agent option is labeled with its product name, not its version-named binary")
    check(agentChoices.options.first(where: { $0.kind == .terminalSession })?.pid == 2589,
          "the terminal session is the outermost shell owning a controlling terminal (fish)")
    check(agentChoices.options.allSatisfy { $0.pid != 65048 && $0.pid != 65054 },
          "the per-tool-call shells are never offered: they own no controlling terminal")
    check(agentChoices.options.first(where: { $0.kind == .requestingCommand })?.pid == 65060,
          "the requesting-command option is the verified plan root")

    // No agent: a human typing csec exec straight into their shell.
    var shellTree = SyntheticTree()
    shellTree.add(pid: 1602, parent: 1, name: "iTerm2")
    shellTree.add(pid: 2589, parent: 1602, name: "fish", hasTerminal: true)
    shellTree.add(pid: 4100, parent: 2589, name: "csec")
    let shellChoices = choices(shellTree, planRoot: 4100)
    check(shellChoices.options.map(\.kind) == [.requestingCommand, .terminalSession],
          "a tree with no agent offers only the command and the terminal session")
    check(shellChoices.defaultOption.kind == .terminalSession
            && shellChoices.defaultOption.pid == 2589,
          "with no agent present the terminal session is the default")

    // A daemon/CI context: shells exist but none owns a terminal.
    var daemonTree = SyntheticTree()
    daemonTree.add(pid: 900, parent: 1, name: "sh", path: "/bin/sh")
    daemonTree.add(pid: 901, parent: 900, name: "bash", path: "/bin/bash")
    daemonTree.add(pid: 902, parent: 901, name: "csec")
    let daemonChoices = choices(daemonTree, planRoot: 902)
    check(daemonChoices.options.map(\.kind) == [.requestingCommand],
          "shells with no controlling terminal are not offered as a terminal session")
    check(daemonChoices.defaultOption.kind == .requestingCommand,
          "with no agent and no terminal session the default is today's per-command root")

    // Nested agents: the nearest one is the boundary being approved.
    var nestedTree = claudeTree()
    nestedTree.add(pid: 65055, parent: 65054, name: "codex", path: "/opt/homebrew/bin/codex")
    nestedTree.add(pid: 65061, parent: 65055, name: "csec")
    let nestedChoices = choices(nestedTree, planRoot: 65061)
    check(nestedChoices.defaultOption.pid == 65055,
          "the nearest coding-agent ancestor wins over an outer one")

    // A candidate that is not an ancestor of the plan root is never offered.
    var siblingTree = claudeTree()
    siblingTree.add(pid: 70000, parent: 2589, name: "csec")
    let siblingChoices = choices(siblingTree, planRoot: 70000)
    check(siblingChoices.options.allSatisfy { $0.pid != 31163 },
          "an agent that is not an ancestor of the plan root is not offered")
    check(siblingChoices.defaultOption.kind == .terminalSession,
          "a sibling of the agent still gets its own terminal session")

    // A cycle or a broken chain must terminate rather than spin.
    var cyclicTree = SyntheticTree()
    cyclicTree.add(pid: 500, parent: 501, name: "a")
    cyclicTree.add(pid: 501, parent: 500, name: "b")
    let cyclicChoices = choices(cyclicTree, planRoot: 500)
    check(cyclicChoices.options.map(\.kind) == [.requestingCommand],
          "a cyclic ancestry chain terminates with only the requesting command")

    // Selection resolution never widens on unrecognized input.
    check(agentChoices.resolved(selectedID: nil).kind == .codingAgent,
          "no selection resolves to the displayed default")
    check(agentChoices.resolved(selectedID: "coding_agent-999-999").kind == .codingAgent,
          "a forged option id resolves to the default rather than an invented root")
    let terminalOption = agentChoices.options.first { $0.kind == .terminalSession }!
    check(agentChoices.resolved(selectedID: terminalOption.id).pid == 2589,
          "an offered option id resolves to exactly that option")
    check(agentChoices.resolved(selectedID: agentChoices.options[0].id).kind == .requestingCommand,
          "the narrow option can always be chosen back")

    check(GrantScopeKind.requestingCommand.reusesAcrossCommands == false,
          "a per-command scope keeps the exact delivery-plan-digest binding")
    check(GrantScopeKind.codingAgent.reusesAcrossCommands
            && GrantScopeKind.terminalSession.reusesAcrossCommands,
          "widened scopes reuse across commands of the same release shape")

    await releaseShapeDigestTests()
    await widenedGrantReuseTests()
}

private func plan(
    mechanism: DeliveryMechanism = .unrestrictedInitialEnvironment,
    destination: DestinationClass = .localDevelopment,
    recipientAssurance: RecipientAssurance? = nil,
    ttlSeconds: Int = 3_600,
    operationContext: String = "csec exec rspec",
    commandDigest: String? = String(repeating: "a", count: 64),
    interactive: Bool = false,
    acknowledged: Bool = false,
    executablePath: String = "/usr/bin/rspec"
) -> DeliveryPlan {
    DeliveryPlan(
        mechanism: mechanism,
        executable: PlannedExecutable(canonicalPath: executablePath, assurance: .unverified),
        root: .caller,
        descendantScope: .subtree,
        destination: destination,
        recipientAssurance: recipientAssurance,
        requestedTTLSeconds: ttlSeconds,
        operationContext: operationContext,
        commandDigest: commandDigest,
        interactive: interactive,
        plaintextExposureAcknowledged: acknowledged
    )
}

private func releaseShapeDigestTests() async {
    print("\n# DeliveryPlan.releaseShapeDigest (widened-grant reuse key)")

    let base = plan()
    let differentCommand = plan(
        operationContext: "csec exec rails db:migrate",
        commandDigest: String(repeating: "b", count: 64),
        executablePath: "/usr/bin/rails"
    )
    check((try? base.releaseShapeDigest()) == (try? differentCommand.releaseShapeDigest()),
          "a different command with the same delivery shape shares a release-shape digest")
    check((try? base.digest()) != (try? differentCommand.digest()),
          "…while its exact delivery-plan digest still differs")

    let differentTTL = plan(ttlSeconds: 12 * 60 * 60)
    check((try? base.releaseShapeDigest()) == (try? differentTTL.releaseShapeDigest()),
          "a different requested duration does not change the release shape")

    for (label, other) in [
        ("mechanism", plan(mechanism: .rawStandardOutput)),
        ("destination", plan(destination: .production)),
        ("recipient assurance", plan(recipientAssurance: .interactiveTerminal)),
        ("interactivity", plan(interactive: true)),
        ("plaintext acknowledgement", plan(acknowledged: true)),
    ] {
        check((try? base.releaseShapeDigest()) != (try? other.releaseShapeDigest()),
              "a different \(label) is a different release shape")
    }

    check((try? base.releaseShapeDigest()) != (try? base.digest()),
          "the release-shape digest is domain-separated from the delivery-plan digest")
}

private func widenedGrantReuseTests() async {
    print("\n# GrantTable (widened-scope reuse)")

    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "widened-grant reuse tests can read their root start time")
        return
    }
    let now = Date()
    let table = GrantTable()
    await table.add(Grant(
        rootPID: me,
        rootStartTime: myStart,
        references: ["op://vault/item/password"],
        reason: "synthetic widened",
        expiresAt: now.addingTimeInterval(60),
        deliveryPlanDigest: "plan-a",
        scopeKind: .codingAgent,
        scopeReuseDigest: "shape-1",
        auditSessionID: 4_242,
        rootProcessLabel: "Claude Code"
    ))

    check(await table.accessibleReferences(
        for: me, now: now,
        deliveryPlanDigest: "plan-b",
        releaseShapeDigest: "shape-1",
        callerAuditSessionID: 4_242
    ) == ["op://vault/item/password"],
    "a widened grant is reused by a different command of the same release shape")

    check(await table.accessibleReferences(
        for: me, now: now,
        deliveryPlanDigest: "plan-b",
        releaseShapeDigest: "shape-2",
        callerAuditSessionID: 4_242
    ).isEmpty, "a widened grant is not reused for a different release shape")

    check(await table.accessibleReferences(
        for: me, now: now,
        deliveryPlanDigest: "plan-a",
        releaseShapeDigest: nil,
        callerAuditSessionID: 4_242
    ).isEmpty, "a widened grant is never reused by a request that presents no release shape")

    check(await table.accessibleReferences(
        for: me, now: now,
        deliveryPlanDigest: "plan-b",
        releaseShapeDigest: "shape-1",
        callerAuditSessionID: 9_999
    ).isEmpty, "a widened grant is not reused from a different audit session")

    check(await table.accessibleReferences(
        for: 1, now: now,
        deliveryPlanDigest: "plan-b",
        releaseShapeDigest: "shape-1",
        callerAuditSessionID: 4_242
    ).isEmpty, "a widened grant still requires kernel ancestry to its root")

    // A per-command grant is untouched by the new key.
    let narrow = GrantTable()
    await narrow.add(Grant(
        rootPID: me,
        rootStartTime: myStart,
        references: ["csec://test/TOKEN"],
        reason: "synthetic narrow",
        expiresAt: now.addingTimeInterval(60),
        deliveryPlanDigest: "plan-a"
    ))
    check(await narrow.accessibleReferences(
        for: me, now: now,
        deliveryPlanDigest: "plan-b",
        releaseShapeDigest: "shape-1",
        callerAuditSessionID: 4_242
    ).isEmpty, "a per-command grant is not reused just because the release shape matches")
    check(await narrow.accessibleReferences(
        for: me, now: now,
        deliveryPlanDigest: "plan-a",
        releaseShapeDigest: "shape-1",
        callerAuditSessionID: 4_242
    ) == ["csec://test/TOKEN"],
    "a per-command grant is still reused for its exact delivery-plan digest")

    // Listing and revocation.
    let summaries = await table.summaries(now: now)
    check(summaries.count == 1
            && summaries[0].scopeKind == .codingAgent
            && summaries[0].rootProcessLabel == "Claude Code"
            && summaries[0].reusesAcrossCommands
            && summaries[0].references == ["op://vault/item/password"]
            && summaries[0].isWellFormed,
          "a live grant summarizes its scope, root label, references, and reuse")
    check(await table.revoke(idPrefix: String(summaries[0].id.prefix(8))) == 1,
          "a grant is revocable by an id prefix")
    check(await table.accessibleReferences(
        for: me, now: now,
        deliveryPlanDigest: "plan-b",
        releaseShapeDigest: "shape-1",
        callerAuditSessionID: 4_242
    ).isEmpty, "a revoked grant grants nothing")
    check(await table.revoke(idPrefix: "") == 0,
          "an empty id prefix revokes nothing")
    let revokedAll = await narrow.revokeAll()
    let remaining = await narrow.summaries(now: now)
    check(revokedAll == 1 && remaining.isEmpty,
          "revoke --all drops every live grant")
}

// MARK: - Agent wiring

private struct GrantScopeFixtureProvider: SecretProvider {
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

private actor GrantScopeConsentCounter: ConsentProvider {
    private var count = 0

    func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval,
        policySummary: String?
    ) async -> ConsentOutcome {
        count += 1
        return .approved(unlock: nil)
    }

    func authenticate(reason: String) async -> ConsentOutcome { .approved(unlock: nil) }
    func calls() -> Int { count }
}

/// Approves while selecting the offered scope of a given kind, so the wiring is
/// exercised independently of which kinds the real ancestry happens to contain.
private actor GrantScopeSelectingReview: PolicyReviewProvider {
    private let kind: GrantScopeKind
    private var lastChoices: GrantScopeChoices?

    init(selecting kind: GrantScopeKind) { self.kind = kind }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        lastChoices = review.scopeChoices
        let selected = review.scopeChoices?.options.first { $0.kind == kind }
        return .approved(AccessPolicyApproval(selectedScopeOptionID: selected?.id))
    }

    func offeredChoices() -> GrantScopeChoices? { lastChoices }
}

private func execShapedPlan(
    executablePath: String,
    operationContext: String,
    commandDigest: String
) -> DeliveryPlan {
    DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: executablePath, assurance: .unverified),
        root: .caller,
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 600,
        operationContext: operationContext,
        commandDigest: commandDigest,
        outputGuard: OutputGuardPlan(mode: .tty)
    )
}

private func accessRequest(
    references: [String],
    plan: DeliveryPlan
) throws -> AccessRequest {
    try AccessRequest(
        references: references,
        reason: "grant scope wiring",
        ttlSeconds: plan.requestedTTLSeconds,
        deliveryPlan: plan
    )
}

/// End-to-end through `Agent`: one approval at a widened root covers a *different*
/// later command of the same shape, and does not cover a different shape.
func grantScopeAgentWiringTests() async {
    print("\n# Agent (widened grant scope end to end)")

    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let parent = ProcessAncestry.parent(of: me), parent > 1,
          let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "the agent wiring test can read its own live ancestry")
        return
    }

    // Present the real parent as an interactive shell so a terminal-session
    // option is offered deterministically, wherever the suite runs. Ancestry,
    // start times, and paths stay live, so every kernel check the agent performs
    // — including GrantTable's own ProcessAncestry walk — remains real.
    let inspection = ProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) },
        parent: { ProcessAncestry.parent(of: $0) },
        name: { $0 == parent ? "zsh" : ProcessAncestry.name(of: $0) },
        executablePath: { ProcessAncestry.executablePath(of: $0) },
        hasControllingTerminal: { $0 == parent }
    )

    let reference = "op://vault/grant-scope/password"
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(GrantScopeFixtureProvider(
        values: [reference: Data("synthetic-grant-scope-value".utf8)]
    ))
    let consent = GrantScopeConsentCounter()
    let review = GrantScopeSelectingReview(selecting: .terminalSession)
    let agent = Agent(
        resolver: resolver,
        grants: GrantTable(),
        consent: consent,
        policyReview: review,
        allowUnverifiedPlansForTesting: true,
        processInspection: inspection
    )
    let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic launcher")

    let first = await agent.handle(
        request: try! accessRequest(
            references: [reference],
            plan: execShapedPlan(
                executablePath: "/usr/bin/rspec",
                operationContext: "csec exec rspec",
                commandDigest: String(repeating: "a", count: 64)
            )
        ),
        caller: caller
    )
    let offered = await review.offeredChoices()
    check(offered?.options.contains(where: { $0.kind == .terminalSession }) == true,
          "the agent offers the terminal-session root it resolved from live ancestry")
    check(offered?.options.first?.kind == .requestingCommand,
          "the requesting-command root is always offered first")
    check(offered?.options.first?.processLabel == "rspec",
          "the requesting-command option is labeled with the plan's own root process")
    let callsAfterFirst = await consent.calls()
    check(first.values?[reference] != nil && callsAfterFirst == 1,
          "the first widened-scope release prompts once and returns its value")

    // A different command — different executable, operation context, and command
    // digest, so a different delivery-plan digest — of the same delivery shape.
    let second = await agent.handle(
        request: try! accessRequest(
            references: [reference],
            plan: execShapedPlan(
                executablePath: "/usr/bin/rails",
                operationContext: "csec exec rails db:migrate",
                commandDigest: String(repeating: "b", count: 64)
            )
        ),
        caller: caller
    )
    let callsAfterSecond = await consent.calls()
    check(second.values?[reference] != nil && callsAfterSecond == 1,
          "a different command of the same shape reuses the widened grant without prompting")

    // A different delivery shape must not inherit that approval.
    let differentShape = await agent.handle(
        request: try! accessRequest(
            references: [reference],
            plan: DeliveryPlan(
                mechanism: .directHeap,
                executable: PlannedExecutable(
                    canonicalPath: "/usr/bin/rails", assurance: .unverified
                ),
                root: .caller,
                descendantScope: .subtree,
                destination: .localDevelopment,
                requestedTTLSeconds: 600,
                operationContext: "csec bridge"
            )
        ),
        caller: caller
    )
    let callsAfterDifferentShape = await consent.calls()
    check(differentShape.values?[reference] != nil && callsAfterDifferentShape == 2,
          "a different delivery shape prompts again rather than reusing the widened grant")

    // The narrow option keeps the pre-existing per-command binding.
    let narrowReview = GrantScopeSelectingReview(selecting: .requestingCommand)
    let narrowAgent = Agent(
        resolver: resolver,
        grants: GrantTable(),
        consent: consent,
        policyReview: narrowReview,
        allowUnverifiedPlansForTesting: true,
        processInspection: inspection
    )
    let before = await consent.calls()
    _ = await narrowAgent.handle(
        request: try! accessRequest(
            references: [reference],
            plan: execShapedPlan(
                executablePath: "/usr/bin/rspec",
                operationContext: "csec exec rspec",
                commandDigest: String(repeating: "a", count: 64)
            )
        ),
        caller: caller
    )
    _ = await narrowAgent.handle(
        request: try! accessRequest(
            references: [reference],
            plan: execShapedPlan(
                executablePath: "/usr/bin/rails",
                operationContext: "csec exec rails db:migrate",
                commandDigest: String(repeating: "b", count: 64)
            )
        ),
        caller: caller
    )
    let callsAfterNarrow = await consent.calls()
    check(callsAfterNarrow == before + 2,
          "choosing the requesting-process root still prompts for every distinct command")
}
