import ConvenientSecurity
import CSECRemoteApproval
import CSECRootProtocol
import CryptoKit
import Foundation
#if canImport(AppKit)
  import AppKit
#endif

/// A request with no argv of its own whose plan root is the requester's direct
/// parent — a language client over `csec bridge`, a `csec get` — is described
/// on its panel by the reason that requester wrote. Under that reason csecd
/// shows the requester's own command line, read from the kernel by pid and
/// start time (never claimed by the request), redacted and bounded like a
/// launcher's argv: on the Mac panel, in the phone mirror and its alert, and
/// as the panel's decision-log `command`.
func requesterCommandLineTests() async {
    print("\n# Requester command line under a language client's reason")
    processInspectionArgumentTests()
    await requesterCommandLineAgentTests()
    requesterCommandLineReviewShapeTests()
    requesterCommandLineRemoteTests()
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await MainActor.run {
        requesterCommandLinePanelTests()
      }
    #endif
}

// MARK: - Reading argv by pid and start time

private func processInspectionArgumentTests() {
    let argv = ["/usr/bin/python3", "-m", "pytest", "-q"]
    func inspection(startTimes: [UInt64], arguments: [String]?) -> ProcessInspection {
        let reads = StartTimeSequence(startTimes)
        return ProcessInspection(
            startTime: { _ in reads.next() },
            parent: { _ in nil }, name: { _ in nil }, executablePath: { _ in nil },
            arguments: { _ in arguments }
        )
    }
    check(inspection(startTimes: [7, 7], arguments: argv).arguments(of: 4242, startedAt: 7) == argv,
          "argv: read while the pid is still the process that started at the root's start time")
    check(inspection(startTimes: [7, 8], arguments: argv).arguments(of: 4242, startedAt: 7) == nil,
          "argv: a pid reused while it was read yields nothing, not a stranger's command")
    check(inspection(startTimes: [8, 8], arguments: argv).arguments(of: 4242, startedAt: 7) == nil,
          "argv: a pid that already names another process yields nothing")
    check(inspection(startTimes: [7, 7], arguments: nil).arguments(of: 4242, startedAt: 7) == nil
            && inspection(startTimes: [7, 7], arguments: []).arguments(of: 4242, startedAt: 7) == nil,
          "argv: an unreadable or empty argv yields nothing")
    check(inspection(startTimes: [7, 7], arguments: argv).arguments(of: 1, startedAt: 7) == nil
            && inspection(startTimes: [0, 0], arguments: argv).arguments(of: 4242, startedAt: 0) == nil,
          "argv: launchd and an unknown start time are never read")
    let synthetic = ProcessInspection(
        startTime: { _ in 7 }, parent: { _ in nil }, name: { _ in nil }, executablePath: { _ in nil }
    )
    check(synthetic.arguments(of: getpid(), startedAt: 7) == nil,
          "argv: a synthetic inspection reads no real process's argv unless a test gives it one")

    let me = getpid()
    if let start = ProcessAncestry.startTime(of: me) {
        check(ProcessInspection.live.arguments(of: me, startedAt: start) == CommandLine.arguments,
              "argv: the live inspection reads a real process's argv from the kernel")
        check(ProcessInspection.live.arguments(of: me, startedAt: start &+ 1) == nil,
              "argv: the live inspection refuses a start time that is not the process's")
    } else {
        check(false, "argv: the fixture reads its own start time")
    }
}

/// Start times handed out in order, the last repeated: a pid reused between
/// the two reads that bracket an argv read.
private final class StartTimeSequence: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [UInt64]

    init(_ values: [UInt64]) { self.values = values }

    func next() -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        guard values.count > 1 else { return values.first }
        return values.removeFirst()
    }
}

// MARK: - End to end through Agent, against real processes

private let requesterReleasedValue = "synthetic-requester-argv-token-0123456789"

private func requesterCommandLineAgentTests() async {
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "requester command: the fixture reads its own start time")
        return
    }
    // The requester: a bash that keeps a child (the caller, as `csec bridge`
    // is the language client's child) and whose own argv carries a marker and
    // a value csecd will already have released.
    guard let requester = RequesterFixture.start(extraArguments: [
        "csec-bridge-fixture", "--header", "Bearer \(requesterReleasedValue)",
    ]) else {
        check(false, "requester command: the bash fixture starts with a child")
        return
    }
    defer { requester.stop() }

    let first = "op://requester/deploy/token"
    let second = "op://requester/relay/token"
    let third = "op://requester/other/token"
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(RequesterFixtureProvider(values: [
        first: Data(requesterReleasedValue.utf8),
        second: Data("synthetic-relay-value".utf8),
        third: Data("synthetic-other-value".utf8),
    ]))
    let directory = NSTemporaryDirectory() + "cs-selftest-requester-command-\(UUID().uuidString.lowercased())"
    defer { try? FileManager.default.removeItem(atPath: directory) }
    let log = DecisionLog(
        directory: SealedRecordDirectory(path: directory),
        stores: .processLocal(InMemoryProtectedItemBackend()),
        bootSessionUUID: "00000000-0000-0000-0000-00000000c0de"
    )
    _ = await log.open()
    let review = RequesterCapturingReview()
    func agent(arguments readsArguments: Bool) -> Agent {
        let arguments: @Sendable (pid_t) -> [String]?
        if readsArguments {
            arguments = { pid in ProcessAncestry.arguments(of: pid) }
        } else {
            arguments = { _ in nil }
        }
        return Agent(
            resolver: resolver,
            grants: GrantTable(),
            consent: AutoApproveConsent(),
            policyReview: review,
            allowUnverifiedPlansForTesting: true,
            processInspection: ProcessInspection(
                startTime: { ProcessAncestry.startTime(of: $0) },
                parent: { ProcessAncestry.parent(of: $0) },
                name: { ProcessAncestry.name(of: $0) },
                executablePath: { ProcessAncestry.executablePath(of: $0) },
                arguments: arguments
            ),
            terminalInspection: .unavailable,
            decisionLog: log
        )
    }
    let csecd = agent(arguments: true)

    // A value csecd releases first, so it is live when the requester's argv,
    // which carries it, is shown.
    let exec = ["/bin/echo", "deploy"]
    let execPlan = DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/bin/echo", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: nil, operationContext: "csec exec echo",
        commandDigest: try! ExecutableInspection.commandDigest(exec),
        outputGuard: OutputGuardPlan(mode: .always, labelStyle: .opaque)
    )
    let released = await csecd.handle(
        request: try! AccessRequest(references: [first], reason: "csec exec echo", deliveryPlan: execPlan, commandLine: exec),
        caller: CallerInfo(pid: me, startTime: myStart, description: "synthetic launcher")
    )
    check(released.values?[first] != nil, "requester command: the first value is released")
    let execShown = await review.last()
    check(execShown?.commandLine == "/bin/echo deploy" && execShown?.requesterCommandLine == nil,
          "requester command: a request carrying its own argv shows that, and no second command line")

    let bridgeCaller = CallerInfo(
        pid: requester.child.pid, startTime: requester.child.startTime, description: "csec bridge"
    )
    let reason = "harbor: read the relay on nimbus as harbord (Approve presses)"
    func bridgeRequest(_ reference: String, root: DeliveryRoot) -> AccessRequest {
        try! AccessRequest(
            references: [reference], reason: reason,
            deliveryPlan: DeliveryPlan(
                mechanism: .directHeap,
                executable: PlannedExecutable(canonicalPath: "/bin/bash", assurance: .unverified),
                root: root, descendantScope: .subtree, destination: .localDevelopment,
                requestedTTLSeconds: nil, operationContext: reason
            )
        )
    }
    let bridged = await csecd.handle(
        request: bridgeRequest(second, root: .directParent(pid: requester.parent.pid, startTime: requester.parent.startTime)),
        caller: bridgeCaller
    )
    check(bridged.values?[second] != nil, "requester command: the bridge request is released")
    let shown = await review.last()
    let line = shown?.requesterCommandLine ?? ""
    check(shown?.reason == reason && shown?.commandLine == nil,
          "requester command: the bridge panel's headline is still the reason its program wrote")
    check(line.hasPrefix("/bin/bash -c ") && line.contains("csec-bridge-fixture --header"),
          "requester command: under it, the program's own command line as csecd read it (got \(line))")
    check(!line.contains(requesterReleasedValue) && line.contains("[csec:secret-"),
          "requester command: a released value in that argv is shown as its redaction label")

    let panels = await requesterRecords(log)
    check(panels.count == 2 && panels.last?.command == line && panels.first?.command == "/bin/echo deploy",
          "requester command: the panel's decision record names the same command line as its `command`")
    let encoded = String(decoding: (try? JSONEncoder().encode(panels)) ?? Data(), as: UTF8.self)
    check(!encoded.contains(requesterReleasedValue),
          "requester command: no released value reaches the decision log")

    if let shown, let remote = try? RemoteApprovalReview(accessPolicyReview: shown) {
        check(remote.headline == reason && remote.requesterCommand == line,
              "requester command: the phone mirror carries it under the same headline")
    } else {
        check(false, "requester command: the bridge review mirrors to the phone")
    }

    // Unreadable argv: the panel shows the reason alone, and the request is
    // decided as before.
    let unreadable = await agent(arguments: false).handle(
        request: bridgeRequest(third, root: .directParent(pid: requester.parent.pid, startTime: requester.parent.startTime)),
        caller: bridgeCaller
    )
    let withoutArgv = await review.last()
    check(unreadable.values?[third] != nil && withoutArgv?.requesterCommandLine == nil
            && withoutArgv?.reason == reason,
          "requester command: when argv cannot be read the panel has the reason alone and the request is not failed")

    // A request rooted at its caller has no direct-parent requester to read.
    let rooted = await agent(arguments: true).handle(
        request: bridgeRequest(third, root: .caller),
        caller: CallerInfo(pid: me, startTime: myStart, description: "synthetic caller")
    )
    let rootedShown = await review.last()
    check(rooted.values?[third] != nil && rootedShown?.requesterCommandLine == nil,
          "requester command: a request rooted at its own caller shows no requester command line")
}

/// `/bin/bash -c 'sleep 60 & echo $!; wait' <extra arguments>`: a live parent
/// whose argv the test chooses, with one child to stand as the caller.
private struct RequesterFixture {
    let process: Process
    let parent: (pid: pid_t, startTime: UInt64)
    let child: (pid: pid_t, startTime: UInt64)

    static func start(extraArguments: [String]) -> RequesterFixture? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", "sleep 60 & echo $!; wait"] + extraArguments
        let output = Pipe()
        process.standardOutput = output
        do { try process.run() } catch { return nil }
        let line = output.fileHandleForReading.readLine()
        guard let childPID = line.flatMap({ pid_t($0) }),
              ProcessAncestry.parent(of: childPID) == process.processIdentifier,
              let parentStart = ProcessAncestry.startTime(of: process.processIdentifier),
              let childStart = ProcessAncestry.startTime(of: childPID) else {
            process.terminate()
            return nil
        }
        return RequesterFixture(
            process: process,
            parent: (process.processIdentifier, parentStart),
            child: (childPID, childStart)
        )
    }

    func stop() {
        kill(child.pid, SIGTERM)
        process.terminate()
        process.waitUntilExit()
    }
}

private extension FileHandle {
    /// One line of a child's output, without waiting for it to close.
    func readLine() -> String? {
        var bytes = Data()
        while bytes.count < 64 {
            let byte = readData(ofLength: 1)
            guard let first = byte.first else { break }
            if first == UInt8(ascii: "\n") { break }
            bytes.append(first)
        }
        return String(data: bytes, encoding: .utf8)
    }
}

private func requesterRecords(_ log: DecisionLog) async -> [DecisionLogRecord] {
    var query = DecisionLogQuery(streams: [.decisions], kinds: [.panel])
    var records: [DecisionLogRecord] = []
    for _ in 0..<100 {
        let page = await log.read(query)
        records += page.records
        guard let next = page.next, !page.records.isEmpty else { break }
        query.after = next
    }
    return records
}

private struct RequesterFixtureProvider: SecretProvider {
    let values: [String: Data]

    var schemes: Set<String> { ["op"] }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private actor RequesterCapturingReview: PolicyReviewProvider {
    private var reviews: [AccessPolicyReview] = []

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews.append(review)
        let scope = review.scopeChoices?.options.first { $0.kind == .requestingCommand }
        return .approved(AccessPolicyApproval(selectedScopeOptionID: scope?.id, selectedDurationIndex: nil))
    }

    func last() -> AccessPolicyReview? { reviews.last }
}

// MARK: - Which reviews carry it

private let fixtureCaller = CallerInfo(pid: 51, startTime: 9, description: "python3 [unverified] (pid 51) via csec")
private let fixtureReason = "harbor: read the relay on nimbus as harbord (Approve presses)"
private let fixtureCommand = ReviewDisplay.commandLine(["/usr/bin/python3", "-m", "pytest", "-q"])
private let fixturePlan = DeliveryPlan(
    mechanism: .directHeap,
    executable: PlannedExecutable(canonicalPath: "/usr/bin/python3", assurance: .unverified),
    root: .directParent(pid: 51, startTime: 9), descendantScope: .subtree,
    destination: .localDevelopment, requestedTTLSeconds: nil, operationContext: fixtureReason
)
private let fixtureCredentials = [PolicyReviewCredential(references: [try! SecretRef("csec://harbor/RELAY_TOKEN")])]

private func bridgeReview(
    commandLine: String? = nil,
    automation: AutomationReviewDetails? = nil,
    ssh: SSHAccessReviewDetails? = nil,
    restore: RestoreReviewDetails? = nil,
    credentials: [PolicyReviewCredential] = fixtureCredentials
) -> AccessPolicyReview {
    AccessPolicyReview(
        caller: fixtureCaller, reason: fixtureReason, plan: fixturePlan,
        commandLine: commandLine, requesterCommandLine: fixtureCommand,
        credentials: credentials, automation: automation,
        durationChoices: automation == nil ? GrantDurationChoices.offered(requestedTTLSeconds: nil) : nil,
        ssh: ssh, restore: restore
    )
}

private let fixtureRestore = RestoreReviewDetails(
    cause: .restart,
    rows: [RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
                            references: ["csec://harbor/RELAY_TOKEN"])],
    storeCount: 1
)
private let fixtureSSH = SSHAccessReviewDetails(
    hostNames: ["github.com"], remoteUser: "git", keyLabel: "work", keyAlgorithm: "ssh-ed25519"
)

private func requesterCommandLineReviewShapeTests() {
    check(bridgeReview().requesterCommandLine == fixtureCommand,
          "review shape: a release with no argv of its own carries the requester's command line")
    check(bridgeReview(commandLine: "/bin/echo hi").requesterCommandLine == nil,
          "review shape: a release that carries its own argv shows that alone")
    check(bridgeReview(restore: fixtureRestore).requesterCommandLine == fixtureCommand,
          "review shape: a release with a restore section keeps it")
    check(bridgeReview(restore: fixtureRestore, credentials: []).requesterCommandLine == nil,
          "review shape: a restore-only panel approves nothing new and names no requester's command")
    check(bridgeReview(automation: v3AutomationDetails()).requesterCommandLine == nil,
          "review shape: automation enrollment shows its job's command, never a requester's")
    check(bridgeReview(ssh: fixtureSSH).requesterCommandLine == nil,
          "review shape: SSH signing names its own facts, never a requester's command line")
}

// MARK: - The phone mirror

private func requesterCommandLineRemoteTests() {
    guard let mirrored = try? RemoteApprovalReview(accessPolicyReview: bridgeReview()) else {
        check(false, "phone: a bridge review mirrors")
        return
    }
    check(mirrored.kind == .access && mirrored.headline == fixtureReason && mirrored.requesterCommand == fixtureCommand,
          "phone: the review carries the requester's command line under the reason headline")
    let restoreOnly = try? RemoteApprovalReview(accessPolicyReview: bridgeReview(restore: fixtureRestore, credentials: []))
    check(restoreOnly != nil && restoreOnly?.requesterCommand == nil,
          "phone: a restore-only review carries none")
    let long = AccessPolicyReview(
        caller: fixtureCaller, reason: fixtureReason, plan: fixturePlan,
        requesterCommandLine: ReviewDisplay.commandLine(["/usr/bin/python3"] + Array(repeating: "argument-value", count: 400)),
        credentials: fixtureCredentials
    )
    let longMirrored = try? RemoteApprovalReview(accessPolicyReview: long)
    check((longMirrored?.requesterCommand?.utf8.count ?? .max) <= RemoteApprovalReview.FieldLimit.requesterCommand
            && longMirrored?.requesterCommand?.hasSuffix("…") == true,
          "phone: a long command line is shortened to its bound, not refused")

    let plain = RemoteReviewParts.changing(mirrored) { $0.requesterCommand = nil }
    func request(_ review: RemoteApprovalReview) -> RemoteApprovalRequest {
        RemoteApprovalRequest(
            requestID: "00000000-0000-4000-8000-0000000000c1", macDeviceID: "00000000-0000-4000-8000-0000000000c2",
            macDeviceName: "Alex’s Mac", createdAtMilliseconds: 1_760_000_000_000, review: review
        )
    }
    let withLine = try? request(mirrored).digest()
    check(withLine != nil && withLine != (try? request(plain).digest()),
          "phone: the command line is bound by the request signature")
    check(withLine != (try? request(RemoteReviewParts.changing(mirrored) { $0.requesterCommand = fixtureCommand + " -x" }).digest()),
          "phone: changing the command line changes what is signed")
    check(RemoteApprovalRequest.signingDomain(for: plain) == "csec.remote-approval.request.v3"
            && RemoteApprovalRequest.signingDomain(for: mirrored) == "csec.remote-approval.request.v3+command",
          "phone: a review without it signs under the old domain, one with it under its own")
    let delegated = RemoteReviewParts.changing(mirrored) {
        $0.delegation = .init(note: "Auto mode didn't approve this: x", pairing: nil)
    }
    check(RemoteApprovalRequest.signingDomain(for: delegated) == "csec.remote-approval.request.v3+delegation+command"
            && (try? request(delegated).digest()) != (try? request(RemoteReviewParts.changing(delegated) {
                $0.requesterCommand = nil
            }).digest()),
          "phone: with a delegation block too, both are named by the domain and bound")

    let mac = P256.Signing.PrivateKey()
    if let signed = try? SignedRemoteApprovalRequest.signed(request(mirrored), by: mac) {
        let stripped = SignedRemoteApprovalRequest(request: request(plain), signatureDER: signed.signatureDER)
        var thrown: Error?
        do { try stripped.verify(macPublicKeyX963: mac.publicKey.x963Representation, at: 1_760_000_000_000) } catch {
            thrown = error
        }
        check(thrown != nil, "phone: dropping the command line from a signed request breaks its signature")
        check((try? signed.verify(macPublicKeyX963: mac.publicKey.x963Representation, at: 1_760_000_000_000)) != nil,
              "phone: the signed request with it verifies")
    } else {
        check(false, "phone: a request with the command line signs")
    }

    for (label, review) in [
        ("an SSH review", RemoteReviewParts.changing(v3SSHReviewFixture()) { $0.requesterCommand = "x" }),
        ("a sudo review", RemoteReviewParts.changing(v3SudoReviewFixture()) { $0.requesterCommand = "x" }),
    ] {
        var thrown: RemoteApprovalValidationError?
        do { try review.validate() } catch let error as RemoteApprovalValidationError { thrown = error } catch {}
        check(thrown == .inconsistentKind, "phone: \(label) carrying a requester command line is refused")
    }
    for (label, value) in [
        ("an empty one", ""),
        ("one over its bound", String(repeating: "x", count: RemoteApprovalReview.FieldLimit.requesterCommand + 1)),
    ] {
        var thrown: RemoteApprovalValidationError?
        do { try RemoteReviewParts.changing(mirrored) { $0.requesterCommand = value }.validate() }
        catch let error as RemoteApprovalValidationError { thrown = error } catch {}
        check(thrown == .fieldOutOfBounds, "phone: \(label) is refused")
    }

    let alert = RemoteApprovalNotificationText.content(for: mirrored, macName: "Alex’s Mac")
    let lines = alert.body.components(separatedBy: "\n")
    check(lines.count == 3 && lines[0] == "“\(fixtureReason)”" && lines[1] == fixtureCommand,
          "phone alert: the command line follows the reason it stands under")
    check(!RemoteApprovalNotificationText.content(for: plain, macName: "Mac").body.contains("pytest"),
          "phone alert: a review without it says what it said before")
}

// MARK: - The Mac panel

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @MainActor
  private func requesterCommandLinePanelTests() {
    NSApplication.shared.setActivationPolicy(.accessory)
    func lineView(_ review: AccessPolicyReview) -> (found: Bool, texts: [String], all: [String]) {
      let panel = ApprovalPanelInspection.access(review)
      defer { withExtendedLifetime(panel) {} }
      guard let content = panel.window.contentView else { return (false, [], []) }
      content.layoutSubtreeIfNeeded()
      func views(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(views) }
      let all = views(content)
      let line = all.first { $0.identifier?.rawValue == "csec.requester-command-line" }
      let texts = line.map { views($0).compactMap { ($0 as? NSTextField)?.stringValue } } ?? []
      return (line != nil, texts, all.compactMap { ($0 as? NSTextField)?.stringValue })
    }

    let bridge = lineView(bridgeReview())
    check(bridge.found && bridge.texts.contains("Process command line") && bridge.texts.contains(fixtureCommand),
          "panel: a bridge release shows the program's command line, labelled, under its reason")
    check(bridge.all.contains("“\(fixtureReason)”") || bridge.all.contains(fixtureReason),
          "panel: the reason it wrote is still shown")
    if let reasonIndex = bridge.all.firstIndex(of: fixtureReason),
       let commandIndex = bridge.all.firstIndex(of: fixtureCommand) {
      check(reasonIndex < commandIndex, "panel: the command line comes after the reason")
    }
    let reasonOnly = lineView(AccessPolicyReview(
      caller: fixtureCaller, reason: fixtureReason, plan: fixturePlan, credentials: fixtureCredentials
    ))
    check(!reasonOnly.found && reasonOnly.all.contains(fixtureReason),
          "panel: with no command line read, the reason stands alone as before")
    let launcher = lineView(bridgeReview(commandLine: "/bin/echo hi"))
    check(!launcher.found && launcher.all.contains("/bin/echo hi"),
          "panel: a release carrying its own argv shows that command and no second line")
    let mixed = lineView(bridgeReview(restore: fixtureRestore))
    check(mixed.found, "panel: a release with a restore section shows it too")
    check(!lineView(bridgeReview(restore: fixtureRestore, credentials: [])).found,
          "panel: the restore-only layout has no requester command line")
    check(!lineView(bridgeReview(automation: v3AutomationDetails())).found,
          "panel: the automation layout has no requester command line")
    check(!lineView(bridgeReview(ssh: fixtureSSH)).found,
          "panel: the SSH layout has no requester command line")
  }
#endif
