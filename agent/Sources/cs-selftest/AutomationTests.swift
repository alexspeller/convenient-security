import ConvenientSecurity
import CryptoKit
import Foundation

private struct AutomationFixtureProvider: SecretProvider {
    let scheme: String
    let values: [String: Data]

    var schemes: Set<String> { [scheme] }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let value = values[ref.uri] else {
            throw ProviderError.referenceNotFound(ref.uri)
        }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

/// Manually advanced clock. Awake and wall time move independently so a test
/// can sleep the Mac (wall advances, awake does not) or charge csecd's own
/// interpreter inspection (both advance inside an inspection).
private final class ManualAutomationClock: @unchecked Sendable {
    private let lock = NSLock()
    private var reading: AutomationClock

    init(wall: Date, awake: TimeInterval) {
        reading = AutomationClock(wall: wall, awake: awake)
    }

    func now() -> AutomationClock {
        lock.lock()
        defer { lock.unlock() }
        return reading
    }

    /// The Mac is awake: both clocks advance.
    func tick(_ seconds: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        reading = AutomationClock(
            wall: reading.wall.addingTimeInterval(seconds),
            awake: reading.awake + seconds
        )
    }

    /// The Mac sleeps: wall time advances, awake time does not.
    func sleep(_ seconds: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        reading = AutomationClock(
            wall: reading.wall.addingTimeInterval(seconds),
            awake: reading.awake
        )
    }
}

private actor AutomationFixtureInspector: AutomationProcessInspecting {
    private var starts: [pid_t: UInt64]
    private var parents: [pid_t: pid_t]
    private var paths: [pid_t: String]
    private let executable: PlannedExecutable
    private let clock: ManualAutomationClock
    /// Awake seconds each interpreter inspection costs csecd, so a test can
    /// prove that cost is not charged to the run lease.
    private var inspectionCost: TimeInterval = 0
    private(set) var inspections = 0
    private var pauseNextExecutablePath = false
    private var executablePathPauseReached = false
    private var releaseExecutablePath = false

    init(
        starts: [pid_t: UInt64],
        parents: [pid_t: pid_t],
        paths: [pid_t: String],
        executable: PlannedExecutable,
        clock: ManualAutomationClock
    ) {
        self.starts = starts
        self.parents = parents
        self.paths = paths
        self.executable = executable
        self.clock = clock
    }

    func startTime(of pid: pid_t) async -> UInt64? { starts[pid] }
    func parent(of pid: pid_t) async -> pid_t? { parents[pid] }
    func executablePath(of pid: pid_t) async -> String? {
        if pauseNextExecutablePath {
            pauseNextExecutablePath = false
            executablePathPauseReached = true
            while !releaseExecutablePath { await Task.yield() }
        }
        return paths[pid]
    }

    func inspectedExecutable(path: String) async -> PlannedExecutable? {
        if let aliased = aliases[path] {
            inspections += 1
            return aliased
        }
        guard path == executable.canonicalPath else { return nil }
        inspections += 1
        clock.tick(inspectionCost)
        return executable
    }

    /// A symlink, such as a virtual environment's `bin/python`: inspecting it
    /// resolves to `target`, or to nothing once it is removed.
    private var aliases: [String: PlannedExecutable] = [:]

    func setAlias(_ path: String, to target: PlannedExecutable?) { aliases[path] = target }

    func addProcess(_ pid: pid_t, startTime: UInt64, parent: pid_t?, path: String) {
        starts[pid] = startTime
        parents[pid] = parent
        paths[pid] = path
    }

    func setInspectionCost(_ seconds: TimeInterval) { inspectionCost = seconds }

    func removeProcess(_ pid: pid_t) {
        starts[pid] = nil
        parents[pid] = nil
        paths[pid] = nil
    }

    func pauseNextExecutablePathInspection() {
        pauseNextExecutablePath = true
        executablePathPauseReached = false
        releaseExecutablePath = false
    }

    func waitForExecutablePathPause() async {
        while !executablePathPauseReached { await Task.yield() }
    }

    func resumeExecutablePathInspection() {
        releaseExecutablePath = true
    }
}

private actor AutomationReviewCapture {
    private(set) var jobs: [AutomationJob] = []
    private(set) var reviews = 0

    func record(_ review: AccessPolicyReview) {
        reviews += 1
        if let job = review.automation?.job { jobs.append(job) }
    }
}

private struct AutomationApprovingReview: PolicyReviewProvider {
    let capture: AutomationReviewCapture

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        await capture.record(review)
        return .approved(AccessPolicyApproval())
    }
}

private enum ConcurrentAutomationStart: Sendable {
    case started(String)
    case alreadyRunning
    case failed
}

private func bridgePlan(
    executable: PlannedExecutable,
    consumerPID: pid_t,
    consumerStartTime: UInt64,
    reason: String
) -> DeliveryPlan {
    DeliveryPlan(
        mechanism: .directHeap,
        executable: executable,
        root: .directParent(pid: consumerPID, startTime: consumerStartTime),
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 300,
        operationContext: reason
    )
}

func automationTests() async {
    print("\n# Unattended automation")

    let opRef = "op://automation-fixture/item/token"
    let nativeRef = "csec://automation-fixture/token"
    let opValue = Data("synthetic-op-value".utf8)
    let nativeValue = Data("synthetic-native-value".utf8)
    let executable = PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified)
    let commandLine = ["/bin/sh", "-c", "synthetic mutable script"]
    let command: AutomationCommand
    do {
        command = AutomationCommand(
            executable: executable,
            commandLine: commandLine,
            workingDirectory: "/tmp",
            commandDigest: try ExecutableInspection.commandDigest(commandLine)
        )
    } catch {
        check(false, "automation fixture command digest is constructible")
        return
    }

    check(command.isWellFormed, "automation command accepts an explicit unverified interpreter")
    let sanitized = AutomationCommand.sanitizedEnvironment([
        "PATH": "/usr/bin:/bin",
        "HOME": "/tmp/synthetic-home",
        "NODE_OPTIONS": "--require=/tmp/preload.js",
        "NODE_PATH": "/tmp/modules",
        "PYTHONPATH": "/tmp/python",
        "RUBYOPT": "-r/tmp/preload.rb",
        "DYLD_INSERT_LIBRARIES": "/tmp/inject.dylib",
        "CSEC_SOCKET": "/tmp/alternate-agent.sock",
    ])
    check(sanitized["PATH"] == "/usr/bin:/bin" && sanitized["HOME"] != nil,
          "automation preserves ordinary trigger environment")
    check(sanitized["NODE_OPTIONS"] == nil
            && sanitized["NODE_PATH"] == nil
            && sanitized["PYTHONPATH"] == nil
            && sanitized["RUBYOPT"] == nil
            && sanitized["DYLD_INSERT_LIBRARIES"] == nil
            && sanitized["CSEC_SOCKET"] == nil,
          "automation strips loader, interpreter, and csec injection controls")

    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(AutomationFixtureProvider(
        scheme: "op", values: [opRef: opValue]
    ))
    await resolver.register(AutomationFixtureProvider(
        scheme: "csec", values: [nativeRef: nativeValue]
    ))
    let grantStore = InMemoryAutomationGrantStore()
    let materializationStore = InMemoryAutomationMaterializationStore()
    let clock = ManualAutomationClock(wall: Date(timeIntervalSince1970: 1_000), awake: 10_000)
    // Three signed launcher incarnations (700, 710, 720), each supervising one
    // interpreter child (701, 711, 721) that spawns one bridge (702, 712, 722).
    let inspector = AutomationFixtureInspector(
        starts: [
            700: 70, 701: 71, 702: 72,
            710: 80, 711: 81, 712: 82,
            720: 90, 721: 91, 722: 92,
        ],
        parents: [701: 700, 702: 701, 711: 710, 712: 711, 721: 720, 722: 721],
        paths: [
            700: "/synthetic/csec", 701: "/bin/sh", 702: "/synthetic/csec",
            710: "/synthetic/csec", 711: "/bin/sh", 712: "/synthetic/csec",
            720: "/synthetic/csec", 721: "/bin/sh", 722: "/synthetic/csec",
        ],
        executable: executable,
        clock: clock
    )
    let reviewCapture = AutomationReviewCapture()
    let setupTouches = SettingsPanelRecorder()
    let service = AutomationService(
        resolver: resolver,
        grantStore: grantStore,
        materializationStore: materializationStore,
        consent: setupTouches,
        policyReview: AutomationApprovingReview(capture: reviewCapture),
        processInspector: inspector,
        terminalInspection: .unavailable,
        clock: { clock.now() }
    )
    let caller = CallerInfo(pid: 700, startTime: 70, description: "synthetic csec")
    let secondLauncher = CallerInfo(pid: 710, startTime: 80, description: "synthetic csec")
    let thirdLauncher = CallerInfo(pid: 720, startTime: 90, description: "synthetic csec")
    let bridgeCaller = CallerInfo(pid: 702, startTime: 72, description: "synthetic bridge")
    let secondBridge = CallerInfo(pid: 712, startTime: 82, description: "synthetic bridge")
    let thirdBridge = CallerInfo(pid: 722, startTime: 92, description: "synthetic bridge")
    let reason = "Synthetic unattended reminders"
    let plan = bridgePlan(executable: executable, consumerPID: 701, consumerStartTime: 71, reason: reason)
    let secondPlan = bridgePlan(executable: executable, consumerPID: 711, consumerStartTime: 81, reason: reason)
    let thirdPlan = bridgePlan(executable: executable, consumerPID: 721, consumerStartTime: 91, reason: reason)
    let enrollment = AutomationEnrollment(
        name: "youtube-reminders",
        reason: reason,
        references: [nativeRef, opRef],
        command: command,
        minimumIntervalSeconds: 60,
        maximumRuntimeSeconds: 300
    )

    // A job with a reference that cannot resolve is refused before its
    // review: here a scheme no provider claims.
    do {
        _ = try await service.enroll(AutomationEnrollment(
            name: "absent-reference",
            reason: reason,
            references: [nativeRef, "nope://absent/item"],
            command: command,
            minimumIntervalSeconds: 60,
            maximumRuntimeSeconds: 300
        ), caller: caller)
        check(false, "automation refuses a job with a reference that cannot resolve before its review")
    } catch let AutomationServiceError.referenceNotFound(summary) {
        let reviews = await reviewCapture.jobs.count
        let stored = (try? await service.list())?.count ?? -1
        check(summary.contains("nope://absent/item") && reviews == 0 && stored == 0,
              "automation refuses a job with a reference that cannot resolve before its review")
    } catch {
        check(false, "automation refuses a job with a reference that cannot resolve before its review (\(error))")
    }

    // A minted sign-in lasts at most an hour, so a job's stored copy would be
    // expired by a later run: refused before its review, whatever provider
    // says its values expire.
    let identities = MachineIdentityCatalog(store: nil, keys: MachineIdentityKeyFactory(
        create: {
            let key = P256.Signing.PrivateKey()
            return (SoftwareIdentitySigner(key: key), key.rawRepresentation)
        },
        open: { SoftwareIdentitySigner(key: try P256.Signing.PrivateKey(rawRepresentation: $0)) }
    ))
    _ = try? await identities.createIdentity(name: "default", issuer: "https://issuer.example.test", subject: "dev-mac")
    try? await identities.addTarget(MachineIdentityTarget(name: "vault", identity: "default", audience: "vault"))
    await resolver.register(MachineIdentityProvider(catalog: identities))
    do {
        _ = try await service.enroll(AutomationEnrollment(
            name: "minted-sign-in",
            reason: reason,
            references: [nativeRef, "csec-identity://default/vault"],
            command: command,
            minimumIntervalSeconds: 60,
            maximumRuntimeSeconds: 300
        ), caller: caller)
        check(false, "automation refuses a job with a sign-in made per use before its review")
    } catch let AutomationServiceError.expiringValues(references) {
        let reviews = await reviewCapture.jobs.count
        let stored = (try? await service.list())?.count ?? -1
        check(references == ["csec-identity://default/vault"] && reviews == 0 && stored == 0,
              "automation refuses a job with a sign-in made per use before its review")
    } catch {
        check(false, "automation refuses a job with a sign-in made per use before its review (\(error))")
    }

    // A person approves each one-time code, so no unattended job may hold
    // one: refused before its review, on any scheme.
    let code = "csec://automation/NPM_SEED?attribute=otp"
    do {
        _ = try await service.enroll(AutomationEnrollment(
            name: "one-time-code",
            reason: reason,
            references: [nativeRef, code],
            command: command,
            minimumIntervalSeconds: 60,
            maximumRuntimeSeconds: 300
        ), caller: caller)
        check(false, "automation refuses a job with a one-time code before its review")
    } catch let AutomationServiceError.oneTimeCodes(references) {
        let reviews = await reviewCapture.jobs.count
        let stored = (try? await service.list())?.count ?? -1
        check(references == [code] && reviews == 0 && stored == 0,
              "automation refuses a job with a one-time code before its review")
    } catch {
        check(false, "automation refuses a job with a one-time code before its review (\(error))")
    }

    do {
        let enrolled = try await service.enroll(enrollment, caller: caller)
        check(enrolled.references == [nativeRef, opRef].sorted(),
              "automation persists sorted canonical references across provider schemes")
        check(await reviewCapture.jobs.count == 1,
              "automation requires one explicit value-free attended review")
        check(DeliveryReviewCopy.warning(for: AccessPolicyReview(
            caller: caller,
            reason: enrolled.reason,
            plan: DeliveryPlan(
                mechanism: .directHeap,
                executable: executable,
                root: .caller,
                descendantScope: .subtree,
                destination: .localDevelopment,
                requestedTTLSeconds: 300,
                operationContext: enrolled.reason
            ),
            credentials: [],
            automation: AutomationReviewDetails(job: enrolled)
        ))?.contains("until you revoke it") == true,
              "automation review explicitly warns that mutable code is trusted until revoke")

        let materialized = await materializationStore.load(
            jobID: enrolled.id,
            revision: enrolled.revision
        )
        check(materialized?.matches(enrolled) == true,
              "enrollment materializes the exact backend-neutral reference set")

        // csecd's own strict validation of a large interpreter can take real
        // time; charge five awake seconds per inspection and prove the lease
        // still gets the full registered runtime.
        await inspector.setInspectionCost(5)
        let inspectionsBeforeStart = await inspector.inspections
        let run: AutomationRunAuthorization
        switch try await service.beginRun(name: enrolled.name, caller: caller) {
        case let .started(authorization):
            run = authorization
            check(authorization.remainingRuntimeSeconds == 300,
                  "automation run lease is bounded by maximum runtime, in awake seconds")
        case .skipped:
            check(false, "first automation trigger starts")
            return
        }
        check(await inspector.inspections == inspectionsBeforeStart + 1,
              "csecd inspects the interpreter once per run start")
        let firstStart = clock.now()

        switch await service.authorizeAccess(
            references: [try SecretRef(opRef)],
            plan: plan,
            caller: bridgeCaller
        ) {
        case let .allowed(values, expiresAt):
            check(values[opRef] == opValue && values.count == 1,
                  "only the requested registered materialization reaches the exact child")
            check(expiresAt == firstStart.wall.addingTimeInterval(300),
                  "the lease clock starts after csecd's own interpreter inspection")
        default:
            check(false, "exact direct child receives unattended access")
        }

        switch await service.authorizeAccess(
            references: [try SecretRef("op://automation-fixture/item/unregistered")],
            plan: plan,
            caller: bridgeCaller
        ) {
        case .denied(.invalidRequest):
            check(true, "automation fails closed for an unregistered reference")
        default:
            check(false, "automation fails closed for an unregistered reference")
        }

        await inspector.pauseNextExecutablePathInspection()
        let invalidatedAccess = Task {
            await service.authorizeAccess(
                references: [try! SecretRef(opRef)],
                plan: plan,
                caller: bridgeCaller
            )
        }
        await inspector.waitForExecutablePathPause()
        check(await service.finishRun(runID: run.runID, caller: caller),
              "only the exact launcher incarnation can finish its run")
        await inspector.resumeExecutablePathInspection()
        switch await invalidatedAccess.value {
        case .denied(.materializationUnavailable):
            check(true, "a concurrent finish invalidates an in-flight access decision")
        default:
            check(false, "a concurrent finish invalidates an in-flight access decision")
        }

        clock.tick(1)
        switch try await service.beginRun(name: enrolled.name, caller: caller) {
        case let .skipped(nextEligibleAt):
            check(nextEligibleAt == firstStart.wall.addingTimeInterval(60),
                  "minimum interval suppresses rapid cron retries")
        case .started:
            check(false, "minimum interval suppresses rapid cron retries")
        }

        clock.tick(60)
        let concurrentStarts = await withTaskGroup(
            of: ConcurrentAutomationStart.self,
            returning: [ConcurrentAutomationStart].self
        ) { group in
            for _ in 0..<2 {
                group.addTask {
                    do {
                        switch try await service.beginRun(name: enrolled.name, caller: caller) {
                        case let .started(authorization):
                            return .started(authorization.runID)
                        case .skipped:
                            return .failed
                        }
                    } catch AutomationServiceError.alreadyRunning {
                        return .alreadyRunning
                    } catch {
                        return .failed
                    }
                }
            }
            var results: [ConcurrentAutomationStart] = []
            for await result in group { results.append(result) }
            return results
        }
        let concurrentRunIDs = concurrentStarts.compactMap { result -> String? in
            guard case let .started(runID) = result else { return nil }
            return runID
        }
        check(concurrentRunIDs.count == 1
                && concurrentStarts.filter {
                    if case .alreadyRunning = $0 { return true }
                    return false
                }.count == 1,
              "concurrent cron triggers create only one run lease")
        for runID in concurrentRunIDs {
            _ = await service.finishRun(runID: runID, caller: caller)
        }

        // The trigger interval is how cron thinks: wall time. A Mac that slept
        // through the interval runs on the next trigger after waking.
        clock.sleep(120)
        let secondRun: AutomationRunAuthorization
        switch try await service.beginRun(name: enrolled.name, caller: caller) {
        case let .started(authorization):
            secondRun = authorization
            check(true, "the trigger interval follows wall time, so a sleep does not defer the next run")
        case .skipped:
            check(false, "the trigger interval follows wall time, so a sleep does not defer the next run")
            return
        }

        // The lease is awake time: sleeping for hours mid-run costs nothing,
        // exactly as the runner's own cap sees it.
        clock.sleep(3 * 60 * 60)
        switch await service.authorizeAccess(
            references: [try SecretRef(opRef)], plan: plan, caller: bridgeCaller
        ) {
        case .allowed:
            check(true, "a sleeping Mac does not expire a run lease")
        default:
            check(false, "a sleeping Mac does not expire a run lease")
        }
        clock.tick(299)
        switch await service.authorizeAccess(
            references: [try SecretRef(opRef)], plan: plan, caller: bridgeCaller
        ) {
        case .allowed:
            check(true, "the lease is releasable through the last awake second of its runtime")
        default:
            check(false, "the lease is releasable through the last awake second of its runtime")
        }

        // Past its maximum runtime the job is still an automation job. Its
        // bridge gets a typed automation denial, never a fall-through to the
        // attended review, which would prompt for an explicitly unattended run.
        clock.tick(1)
        switch await service.authorizeAccess(
            references: [try SecretRef(opRef)], plan: plan, caller: bridgeCaller
        ) {
        case .denied(.runExpired):
            check(true, "an expired run lease fails closed with an automation denial")
        case .notApplicable:
            check(false, "an expired run lease fails closed with an automation denial (fell through to attended review)")
        default:
            check(false, "an expired run lease fails closed with an automation denial")
        }

        // The expired launcher may still be winding its child down. Its
        // tombstone answers that child's late bridge but does not block the
        // job's next trigger from a fresh launcher.
        let thirdRun: AutomationRunAuthorization
        switch try await service.beginRun(name: enrolled.name, caller: secondLauncher) {
        case let .started(authorization):
            thirdRun = authorization
            check(true, "an expired lease's tombstone does not block the job's next trigger")
        case .skipped:
            check(false, "an expired lease's tombstone does not block the job's next trigger")
            return
        }
        switch await service.authorizeAccess(
            references: [try SecretRef(opRef)], plan: secondPlan, caller: secondBridge
        ) {
        case let .allowed(values, _):
            check(values[opRef] == opValue, "the fresh launcher's exact child is released")
        default:
            check(false, "the fresh launcher's exact child is released")
        }
        switch await service.authorizeAccess(
            references: [try SecretRef(opRef)], plan: plan, caller: bridgeCaller
        ) {
        case .denied(.runExpired):
            check(true, "the expired launcher's late bridge is still answered as automation")
        default:
            check(false, "the expired launcher's late bridge is still answered as automation")
        }
        do {
            _ = try await service.beginRun(name: enrolled.name, caller: caller)
            check(false, "a launcher incarnation holds one lease, tombstone included")
        } catch AutomationServiceError.alreadyRunning {
            check(true, "a launcher incarnation holds one lease, tombstone included")
        }
        await inspector.removeProcess(700)
        switch await service.authorizeAccess(
            references: [try SecretRef(opRef)], plan: plan, caller: bridgeCaller
        ) {
        case .notApplicable:
            check(true, "a tombstone is released once its launcher has exited")
        default:
            check(false, "a tombstone is released once its launcher has exited")
        }
        check(secondRun.runID != thirdRun.runID, "each trigger gets its own run lease")

        let afterRestart = AutomationService(
            resolver: resolver,
            grantStore: grantStore,
            materializationStore: materializationStore,
            consent: AutoApproveConsent(),
            policyReview: AutomationApprovingReview(capture: reviewCapture),
            processInspector: inspector,
            terminalInspection: .unavailable,
            clock: { clock.now() }
        )
        check(try await afterRestart.list().map(\.name) == [enrolled.name],
              "until-revoked authorization survives daemon restart")

        // Re-enrollment and revocation mid-run leave the in-flight child a
        // typed reason too; its launcher can still finish the tombstoned run.
        let reenrolled = try await service.enroll(enrollment, caller: thirdLauncher)
        check(reenrolled.id == enrolled.id && reenrolled.revision != enrolled.revision,
              "re-enrollment installs a new revision of the same job")
        switch await service.authorizeAccess(
            references: [try SecretRef(opRef)], plan: secondPlan, caller: secondBridge
        ) {
        case .denied(.runInvalidated):
            check(true, "re-enrollment invalidates the in-flight run with a typed denial")
        default:
            check(false, "re-enrollment invalidates the in-flight run with a typed denial")
        }
        check(await service.finishRun(runID: thirdRun.runID, caller: secondLauncher),
              "a launcher can finish its tombstoned run")

        switch try await service.beginRun(name: enrolled.name, caller: thirdLauncher) {
        case .started:
            check(true, "the new revision runs on the next trigger")
        case .skipped:
            check(false, "the new revision runs on the next trigger")
            return
        }
        _ = try await service.revoke(name: enrolled.name, caller: thirdLauncher)
        let revokePanel = await setupTouches.panels.last
        let bareSheets = await setupTouches.bareSheets
        check(revokePanel?.change.title == "Revoke an Unattended Automation Job"
                && revokePanel?.change.changes.first?.hasPrefix("Revoke unattended automation job \(enrolled.name):") == true
                && revokePanel?.caller.pid == thirdLauncher.pid && bareSheets == 0,
              "revoking a job is csecd's settings panel for the launcher that asked, never the bare sheet (csec-0.60)")
        switch await service.authorizeAccess(
            references: [try SecretRef(opRef)], plan: thirdPlan, caller: thirdBridge
        ) {
        case .denied(.runInvalidated):
            check(true, "revocation invalidates the in-flight run with a typed denial")
        default:
            check(false, "revocation invalidates the in-flight run with a typed denial")
        }
        check(try await service.list().isEmpty,
              "revocation removes persistent authorization metadata")
        let oldCopy = await materializationStore.load(
            jobID: enrolled.id, revision: enrolled.revision
        )
        let newCopy = await materializationStore.load(
            jobID: reenrolled.id, revision: reenrolled.revision
        )
        check(oldCopy == nil && newCopy == nil,
              "revocation removes the automation-only value copy")
    } catch {
        check(false, "automation lifecycle completed without an unexpected error (\(error))")
    }

    do {
        let request = AutomationRequest(action: .list)
        let encoded = try JSONEncoder().encode(Request.configureAutomation(request))
        let decoded = try JSONDecoder().decode(Request.self, from: encoded)
        guard case let .configureAutomation(roundTrip) = decoded else {
            check(false, "automation request retains its wire discriminator")
            return
        }
        check(roundTrip.requestID == request.requestID && roundTrip.action == .list,
              "automation request round-trips with its bound nonce")
    } catch {
        check(false, "automation request wire round-trip succeeds (\(error))")
    }

    await automationAgentWiringTests()
    await automationDaemonTests()
    await automationRestartTests()
    await automationRestartKeychainFailureTests()
    await automationInvokedPathTests()
    await automationFrameworkPythonTests()
    automationPythonSignatureTests()
    automationOutputTailTests()
}

/// The launcher keeps the tail of each stream for every automation run, so
/// the tail must stay bounded however much the job prints, and hand back its
/// bytes indexed from zero: a slice of a trimmed `Data` keeps every byte ever
/// appended alive and starts at a large index.
private func automationOutputTailTests() {
    let limit = 64 * 1_024
    var tail = OutputTail(limit: limit)
    check(tail.isEmpty && tail.bytes.isEmpty, "output tail starts empty")
    var input = Data()
    var overflow = Data()
    var largestStorage = 0
    var chunkNumber: UInt8 = 0
    for _ in 0..<640 {
        chunkNumber &+= 1
        let chunk = Data((0..<(16 * 1_024)).map { UInt8(truncatingIfNeeded: $0) &+ chunkNumber })
        input.append(chunk)
        overflow.append(tail.append(chunk))
        largestStorage = max(largestStorage, tail.storageCount)
    }
    let kept = tail.bytes
    check(tail.count == limit && kept.count == limit && kept.startIndex == 0,
          "output tail keeps exactly its limit, indexed from zero (count \(tail.count), start \(kept.startIndex))")
    check(kept == input.suffix(limit), "output tail keeps the last bytes appended, in order")
    check(overflow == input.prefix(input.count - limit),
          "output tail hands back, in order, every byte that fell off its front")
    check(largestStorage <= 2 * limit + 16 * 1_024,
          "output tail storage stays within twice its limit after 10 MiB (largest \(largestStorage))")

    var small = OutputTail(limit: 8)
    check(small.append(Data("abc".utf8)).isEmpty && small.bytes == Data("abc".utf8),
          "output tail under its limit drops nothing")
    check(small.append(Data("defghijkl".utf8)) == Data("abcd".utf8) && small.bytes == Data("efghijkl".utf8),
          "output tail drops only the oldest bytes past its limit")
    check(small.append(Data(repeating: 0x7a, count: 20)) == Data("efghijkl".utf8) + Data(repeating: 0x7a, count: 12),
          "output tail given more than its limit at once keeps the newest")
    small.removeAll()
    check(small.isEmpty && small.storageCount == 0, "output tail empties")
}

/// Through `Agent`, with this process standing in for the signed bridge and
/// its real parent for the leased interpreter: kernel ancestry is live, only
/// the launcher above the parent is synthetic. An expired lease must come back
/// as a typed automation failure without the policy review ever being asked.
private func automationAgentWiringTests() async {
    let me = getpid()
    let parent = getppid()
    guard let myStart = ProcessAncestry.startTime(of: me),
          let parentStart = ProcessAncestry.startTime(of: parent),
          let parentPath = ProcessAncestry.executablePath(of: parent) else {
        check(false, "the self-test process has an inspectable parent")
        return
    }
    let executable = PlannedExecutable(canonicalPath: parentPath, assurance: .unverified)
    let commandLine = [parentPath, "-c", "synthetic mutable script"]
    let opRef = "op://automation-fixture/item/token"
    let opValue = Data("synthetic-op-value".utf8)
    let reason = "Synthetic late bridge"
    do {
        let command = AutomationCommand(
            executable: executable,
            commandLine: commandLine,
            workingDirectory: "/tmp",
            commandDigest: try ExecutableInspection.commandDigest(commandLine)
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(AutomationFixtureProvider(scheme: "op", values: [opRef: opValue]))
        let clock = ManualAutomationClock(wall: Date(), awake: 20_000)
        let inspector = AutomationFixtureInspector(
            starts: [800: 80, parent: parentStart],
            parents: [parent: 800],
            paths: [800: "/synthetic/csec", parent: parentPath],
            executable: executable,
            clock: clock
        )
        let reviewCapture = AutomationReviewCapture()
        let review = AutomationApprovingReview(capture: reviewCapture)
        let service = AutomationService(
            resolver: resolver,
            grantStore: InMemoryAutomationGrantStore(),
            materializationStore: InMemoryAutomationMaterializationStore(),
            consent: AutoApproveConsent(),
            policyReview: review,
            processInspector: inspector,
            terminalInspection: .unavailable,
            clock: { clock.now() }
        )
        let launcher = CallerInfo(pid: 800, startTime: 80, description: "synthetic csec")
        _ = try await service.enroll(AutomationEnrollment(
            name: "late-bridge",
            reason: reason,
            references: [opRef],
            command: command,
            maximumRuntimeSeconds: 300
        ), caller: launcher)
        guard case .started = try await service.beginRun(name: "late-bridge", caller: launcher) else {
            check(false, "the synthetic launcher starts its run")
            return
        }
        let reviewsAfterEnrollment = await reviewCapture.reviews

        let agent = Agent(
            resolver: resolver,
            grants: GrantTable(),
            consent: AutoApproveConsent(),
            policyReview: review,
            automationService: service,
            allowUnverifiedPlansForTesting: true,
            terminalInspection: .unavailable
        )
        let request = try AccessRequest(
            references: [opRef],
            reason: reason,
            ttlSeconds: 300,
            deliveryPlan: bridgePlan(
                executable: executable,
                consumerPID: parent,
                consumerStartTime: parentStart,
                reason: reason
            )
        )
        let bridge = CallerInfo(pid: me, startTime: myStart, description: "synthetic bridge")

        let live = await agent.handle(request: request, caller: bridge)
        let reviewsAfterLive = await reviewCapture.reviews
        check(live.values?[opRef] == opValue && reviewsAfterLive == reviewsAfterEnrollment,
              "a live automation lease releases through csecd without an attended review")

        clock.tick(300)
        let late = await agent.handle(request: request, caller: bridge)
        let reviewsAfterLate = await reviewCapture.reviews
        check(late.values == nil
                && late.failure?.code == .automationRunExpired
                && reviewsAfterLate == reviewsAfterEnrollment,
              "an expired automation lease is a typed failure that never reaches the attended review"
                + " (got \(late.failure.map { "\($0.code.rawValue): \($0.message)" } ?? "values"))")
    } catch {
        check(false, "automation agent wiring checks run (\(error))")
    }
}

/// csec-1xv.10: a daemon job (no maximum runtime) gets a process-lifetime lease —
/// auth once at enrollment, secrets stay releasable for as long as the daemon
/// process lives, with no wall-clock expiry. The launcher-exit prune that ends it
/// is the same one the bounded tests exercise.
private func automationDaemonTests() async {
    let me = getpid()
    let parent = getppid()
    guard let myStart = ProcessAncestry.startTime(of: me),
          let parentStart = ProcessAncestry.startTime(of: parent),
          let parentPath = ProcessAncestry.executablePath(of: parent) else {
        check(false, "the self-test process has an inspectable parent")
        return
    }
    let executable = PlannedExecutable(canonicalPath: parentPath, assurance: .unverified)
    let commandLine = [parentPath, "-c", "synthetic daemon script"]
    let opRef = "op://automation-daemon/item/token"
    let opValue = Data("synthetic-daemon-value".utf8)
    let reason = "Synthetic auth-once daemon"
    do {
        let command = AutomationCommand(
            executable: executable,
            commandLine: commandLine,
            workingDirectory: "/tmp",
            commandDigest: try ExecutableInspection.commandDigest(commandLine)
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(AutomationFixtureProvider(scheme: "op", values: [opRef: opValue]))
        let clock = ManualAutomationClock(wall: Date(), awake: 20_000)
        let inspector = AutomationFixtureInspector(
            starts: [800: 80, parent: parentStart],
            parents: [parent: 800],
            paths: [800: "/synthetic/csec", parent: parentPath],
            executable: executable,
            clock: clock
        )
        let review = AutomationApprovingReview(capture: AutomationReviewCapture())
        let service = AutomationService(
            resolver: resolver,
            grantStore: InMemoryAutomationGrantStore(),
            materializationStore: InMemoryAutomationMaterializationStore(),
            consent: AutoApproveConsent(),
            policyReview: review,
            processInspector: inspector,
            terminalInspection: .unavailable,
            clock: { clock.now() }
        )
        let launcher = CallerInfo(pid: 800, startTime: 80, description: "synthetic csec")
        let daemon = try await service.enroll(AutomationEnrollment(
            name: "auth-once-daemon",
            reason: reason,
            references: [opRef],
            command: command,
            maximumRuntimeSeconds: nil
        ), caller: launcher)
        check(daemon.maximumRuntimeSeconds == nil,
              "a daemon job enrolls with no maximum runtime (process lifetime)")
        guard case let .started(run) = try await service.beginRun(name: "auth-once-daemon", caller: launcher)
        else {
            check(false, "the daemon launcher starts its run")
            return
        }
        check(run.remainingRuntimeSeconds == nil,
              "a daemon run lease carries no runtime cap")

        let plan = bridgePlan(
            executable: executable, consumerPID: parent, consumerStartTime: parentStart, reason: reason
        )
        let bridge = CallerInfo(pid: me, startTime: myStart, description: "synthetic bridge")
        switch await service.authorizeAccess(references: [try SecretRef(opRef)], plan: plan, caller: bridge) {
        case let .allowed(values, expiresAt):
            check(values[opRef] == opValue && expiresAt == nil,
                  "a daemon lease releases the exact child's value with no wall-clock expiry")
        default:
            check(false, "a daemon lease releases the exact child's value")
        }

        // The lease never lapses by clock: a month of awake time later it still
        // releases (contrast the bounded run, which becomes .runExpired).
        clock.tick(30 * 24 * 60 * 60)
        switch await service.authorizeAccess(references: [try SecretRef(opRef)], plan: plan, caller: bridge) {
        case let .allowed(values, expiresAt):
            check(values[opRef] == opValue && expiresAt == nil,
                  "a daemon lease still releases a month later — it never expires on a clock")
        default:
            check(false, "a daemon lease still releases after a long awake interval")
        }

        // Only the daemon process exiting ends the lease (same prune as bounded).
        await inspector.removeProcess(800)
        switch await service.authorizeAccess(references: [try SecretRef(opRef)], plan: plan, caller: bridge) {
        case .allowed:
            check(false, "a daemon lease ends once its process exits")
        default:
            check(true, "a daemon lease ends once its process exits")
        }
    } catch {
        check(false, "automation daemon checks run (\(error))")
    }
}

/// A csecd restart (an update restarts it) must not strand a job whose
/// launcher outlives it: the restarted csecd restores the lease from the
/// `automation`/`runs-v1` item and keeps serving the launcher's child as
/// automation, never through an attended panel nobody is there to answer.
private func automationRestartTests() async {
    let opRef = "op://automation-restart/item/token"
    let nativeRef = "csec://automation-restart/token"
    let opValue = Data("synthetic-restart-op-value".utf8)
    let nativeValue = Data("synthetic-restart-native-value".utf8)
    let executable = PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified)
    let commandLine = ["/bin/sh", "-c", "synthetic restart script"]
    let reason = "Synthetic restart-surviving daemon"
    do {
        let command = AutomationCommand(
            executable: executable,
            commandLine: commandLine,
            workingDirectory: "/tmp",
            commandDigest: try ExecutableInspection.commandDigest(commandLine)
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(AutomationFixtureProvider(scheme: "op", values: [opRef: opValue]))
        await resolver.register(AutomationFixtureProvider(
            scheme: "csec", values: [nativeRef: nativeValue]
        ))
        let clock = ManualAutomationClock(wall: Date(timeIntervalSince1970: 5_000), awake: 40_000)
        // Launchers 900 (daemon job), 910 (bounded job), 920 (a job whose
        // launcher exits before the restart), 930 (a later daemon run), 940 (a
        // run over an unreadable item), each supervising one interpreter (9x1).
        let inspector = AutomationFixtureInspector(
            starts: [
                900: 90, 901: 91, 910: 100, 911: 101, 920: 110, 921: 111, 930: 120, 931: 121,
                940: 130, 941: 131,
            ],
            parents: [901: 900, 911: 910, 921: 920, 931: 930, 941: 940],
            paths: [
                900: "/synthetic/csec", 901: "/bin/sh", 910: "/synthetic/csec", 911: "/bin/sh",
                920: "/synthetic/csec", 921: "/bin/sh", 930: "/synthetic/csec", 931: "/bin/sh",
                940: "/synthetic/csec", 941: "/bin/sh",
            ],
            executable: executable,
            clock: clock
        )
        let grantStore = InMemoryAutomationGrantStore()
        let materializationStore = InMemoryAutomationMaterializationStore()
        let backend = InMemoryProtectedItemBackend()
        func csecd(boot: String? = "boot-a", runs: Bool = true) -> AutomationService {
            AutomationService(
                resolver: resolver,
                grantStore: grantStore,
                materializationStore: materializationStore,
                consent: AutoApproveConsent(),
                policyReview: AutomationApprovingReview(capture: AutomationReviewCapture()),
                processInspector: inspector,
                terminalInspection: .unavailable,
                clock: { clock.now() },
                runStore: runs
                    ? ProtectedStores.processLocal(backend).store(for: AutomationRunsDocument.self)
                    : nil,
                bootSessionUUID: boot
            )
        }
        func launcher(_ pid: pid_t, _ start: UInt64) -> CallerInfo {
            CallerInfo(pid: pid, startTime: start, description: "synthetic csec")
        }
        func plan(_ pid: pid_t, _ start: UInt64) -> DeliveryPlan {
            bridgePlan(executable: executable, consumerPID: pid, consumerStartTime: start, reason: reason)
        }
        let bridge = CallerInfo(pid: 9_999, startTime: 999, description: "synthetic bridge")
        func enrollment(_ name: String, runtime: Int?) -> AutomationEnrollment {
            AutomationEnrollment(
                name: name, reason: reason, references: [nativeRef, opRef], command: command,
                maximumRuntimeSeconds: runtime
            )
        }
        func started(_ decision: AutomationRunDecision) -> AutomationRunAuthorization? {
            if case let .started(run) = decision { return run }
            return nil
        }

        // Before its first restore, a csecd never writes the item, so a fresh
        // csecd cannot overwrite the leases it is about to restore.
        let unrestored = csecd()
        _ = try await unrestored.enroll(enrollment("restart-unrestored", runtime: nil), caller: launcher(930, 120))
        _ = try await unrestored.beginRun(name: "restart-unrestored", caller: launcher(930, 120))
        await unrestored.flushPersistedRuns()
        check(await backend.rawBytes(for: .automationRuns) == nil,
              "automation restart: nothing is persisted before the first restore")
        _ = try await unrestored.revoke(name: "restart-unrestored", caller: launcher(930, 120))

        let first = csecd()
        check(await first.restoreRuns() == AutomationRunRestoration(),
              "automation restart: a first start with no item restores nothing")
        _ = try await first.enroll(enrollment("restart-daemon", runtime: nil), caller: launcher(900, 90))
        _ = try await first.enroll(enrollment("restart-bounded", runtime: 300), caller: launcher(910, 100))
        _ = try await first.enroll(enrollment("restart-gone", runtime: nil), caller: launcher(920, 110))
        guard let daemonRun = started(try await first.beginRun(name: "restart-daemon", caller: launcher(900, 90))),
              let boundedRun = started(try await first.beginRun(name: "restart-bounded", caller: launcher(910, 100))),
              started(try await first.beginRun(name: "restart-gone", caller: launcher(920, 110))) != nil else {
            check(false, "automation restart: the three runs start")
            return
        }
        guard case .allowed = await first.authorizeAccess(
            references: [try SecretRef(opRef)], plan: plan(901, 91), caller: bridge
        ) else {
            check(false, "automation restart: the daemon's child is served before the restart")
            return
        }
        await first.flushPersistedRuns()
        let persisted = await backend.rawBytes(for: .automationRuns)
        let persistedText = persisted.map { String(decoding: $0, as: UTF8.self) } ?? ""
        check(persisted != nil
                && !persistedText.contains("synthetic-restart")
                && persistedText.contains(daemonRun.runID),
              "automation restart: each run lease is persisted, value-free")

        // csecd stops. While it is down the bounded run passes its deadline
        // and launcher 920 exits.
        clock.tick(301)
        await inspector.removeProcess(920)
        await inspector.removeProcess(921)

        let restarted = csecd()
        let restoration = await restarted.restoreRuns()
        check(restoration.live == 1 && restoration.tombstones == 1 && restoration.dropped == 1
                && restoration.unreadable == nil,
              "automation restart: the live daemon run is restored, the expired one is a tombstone, "
                + "the exited launcher's is dropped (\(restoration))")
        check(restoration.releases == [AutomationRunRestoration.Release(
                valuesByReference: [nativeRef: nativeValue, opRef: opValue], expiresAt: nil
              )],
              "automation restart: the restored run's values go to the output redactor, "
                + "with no clock expiry for a daemon")
        check(await restarted.restoreRuns() == AutomationRunRestoration(),
              "automation restart: the item is restored once per csecd")
        switch await restarted.authorizeAccess(
            references: [try SecretRef(opRef)], plan: plan(901, 91), caller: bridge
        ) {
        case let .allowed(values, expiresAt):
            check(values == [opRef: opValue] && expiresAt == nil,
                  "automation restart: the daemon's child is still served as automation, with no panel")
        default:
            check(false, "automation restart: the daemon's child is still served as automation, with no panel")
        }
        switch await restarted.authorizeAccess(
            references: [try SecretRef(opRef)], plan: plan(911, 101), caller: bridge
        ) {
        case .denied(.runExpired):
            check(true, "automation restart: the expired bounded run's child gets the typed expiry")
        default:
            check(false, "automation restart: the expired bounded run's child gets the typed expiry")
        }
        check(await restarted.resumeRun(runID: daemonRun.runID, caller: launcher(900, 90))
                == AutomationRunRestoration.Release(
                    valuesByReference: [nativeRef: nativeValue, opRef: opValue], expiresAt: nil
                ),
              "automation restart: the daemon's launcher can resume its run on the restarted csecd")
        check(await restarted.resumeRun(runID: daemonRun.runID, caller: launcher(910, 100)) == nil,
              "automation restart: another launcher cannot resume a run it does not hold")
        check(await restarted.resumeRun(runID: boundedRun.runID, caller: launcher(910, 100)) == nil,
              "automation restart: an expired run cannot be resumed")
        do {
            _ = try await restarted.beginRun(name: "restart-daemon", caller: launcher(930, 120))
            check(false, "automation restart: a restored run still blocks an overlapping trigger")
        } catch AutomationServiceError.alreadyRunning {
            check(true, "automation restart: a restored run still blocks an overlapping trigger")
        }
        check(await restarted.finishRun(runID: daemonRun.runID, caller: launcher(900, 90)),
              "automation restart: the launcher finishes its run on the restarted csecd")
        check(await restarted.finishRun(runID: boundedRun.runID, caller: launcher(910, 100)),
              "automation restart: the launcher finishes its tombstoned run too")

        // A lease whose write said "live" while the job was re-enrolled
        // elsewhere comes back as a tombstone for the old revision.
        guard let laterRun = started(try await restarted.beginRun(name: "restart-daemon", caller: launcher(930, 120))) else {
            check(false, "automation restart: the next daemon trigger starts")
            return
        }
        await restarted.flushPersistedRuns()
        _ = try await csecd(runs: false).enroll(enrollment("restart-daemon", runtime: nil), caller: launcher(930, 120))
        let afterReenroll = csecd()
        let reenrolled = await afterReenroll.restoreRuns()
        check(reenrolled.live == 0 && reenrolled.tombstones == 1 && reenrolled.releases.isEmpty,
              "automation restart: a run of a since-re-enrolled revision is restored as a tombstone")
        switch await afterReenroll.authorizeAccess(
            references: [try SecretRef(opRef)], plan: plan(931, 121), caller: bridge
        ) {
        case .denied(.runInvalidated):
            check(true, "automation restart: its child gets the typed invalidation, never a panel")
        default:
            check(false, "automation restart: its child gets the typed invalidation, never a panel")
        }
        check(await afterReenroll.resumeRun(runID: laterRun.runID, caller: launcher(930, 120)) == nil,
              "automation restart: a tombstoned run cannot be resumed, so its launcher stops scanning")
        await afterReenroll.flushPersistedRuns()

        // A revoked job's run comes back as a tombstone too.
        _ = try await csecd(runs: false).revoke(name: "restart-daemon", caller: launcher(930, 120))
        let afterRevoke = csecd()
        let revoked = await afterRevoke.restoreRuns()
        check(revoked.tombstones == 1 && revoked.live == 0,
              "automation restart: a run of a revoked job is restored as a tombstone")
        switch await afterRevoke.authorizeAccess(
            references: [try SecretRef(opRef)], plan: plan(931, 121), caller: bridge
        ) {
        case .denied(.runInvalidated):
            check(true, "automation restart: a revoked job's child gets the typed invalidation")
        default:
            check(false, "automation restart: a revoked job's child gets the typed invalidation")
        }
        await afterRevoke.flushPersistedRuns()

        // An unknown boot session restores nothing either.
        let beforeUnknownBoot = await backend.rawBytes(for: .automationRuns)
        let unknownBootCsecd = csecd(boot: nil)
        let unknownBoot = await unknownBootCsecd.restoreRuns()
        await unknownBootCsecd.flushPersistedRuns()
        check(unknownBoot.live == 0 && unknownBoot.tombstones == 0 && unknownBoot.dropped == 1,
              "automation restart: nothing is restored when the boot session cannot be read")
        await backend.setRawBytes(beforeUnknownBoot, for: .automationRuns)

        // A later boot restores nothing, whatever the launcher table says.
        let nextBootCsecd = csecd(boot: "boot-b")
        let nextBoot = await nextBootCsecd.restoreRuns()
        await nextBootCsecd.flushPersistedRuns()
        check(nextBoot.live == 0 && nextBoot.tombstones == 0 && nextBoot.dropped == 1,
              "automation restart: nothing is restored from an earlier boot")

        // An item this build cannot read restores nothing and is left as found.
        let garbage = Data("{\"formatVersion\":99,\"document\":{}}".utf8)
        await backend.setRawBytes(garbage, for: .automationRuns)
        let unreadable = await csecd().restoreRuns()
        let leftAsFound = await backend.rawBytes(for: .automationRuns) == garbage
        check(unreadable.unreadable != nil && unreadable.live == 0 && leftAsFound,
              "automation restart: an unreadable item restores nothing and is not rewritten")

        // The leases record no human decision, so an unreadable item is not
        // held: the csecd that could not read it persists its own leases over
        // it, and revoking a job, which must write its tombstone first, works.
        let overUnreadable = csecd()
        _ = await overUnreadable.restoreRuns()
        _ = try await overUnreadable.enroll(enrollment("restart-over-unreadable", runtime: nil),
                                            caller: launcher(940, 130))
        let overRun = started(try await overUnreadable.beginRun(name: "restart-over-unreadable",
                                                                caller: launcher(940, 130)))
        await overUnreadable.flushPersistedRuns()
        let replaced = await ProtectedStores.processLocal(backend).store(for: AutomationRunsDocument.self).load()
        guard case let .document(replacedRuns) = replaced else {
            check(false, "automation restart: a lease change replaces an unreadable item (\(replaced))")
            return
        }
        check(overRun != nil && replacedRuns.runs.map(\.jobName) == ["restart-over-unreadable"],
              "automation restart: a lease change replaces an unreadable item")
        let revokedOverUnreadable = try? await overUnreadable.revoke(name: "restart-over-unreadable",
                                                                    caller: launcher(940, 130))
        check(revokedOverUnreadable != nil,
              "automation restart: a job revokes after an unreadable item was found at start")
    } catch {
        check(false, "automation restart checks run (\(error))")
    }
}

/// The catalog and materialization stores, with reads that fail on demand, standing in for a Keychain that cannot be read for a moment.
private actor FlakyAutomationStores: AutomationGrantStore, AutomationMaterializationStore {
    private let jobs = InMemoryAutomationGrantStore()
    private let values = InMemoryAutomationMaterializationStore()
    var catalogUnreadable = false
    var materializationUnreadable = false

    struct Unreadable: Error {}

    func set(catalogUnreadable: Bool = false, materializationUnreadable: Bool = false) {
        self.catalogUnreadable = catalogUnreadable
        self.materializationUnreadable = materializationUnreadable
    }

    func load() async throws -> [AutomationJob] {
        if catalogUnreadable { throw Unreadable() }
        return await jobs.load()
    }

    func store(_ jobs: [AutomationJob]) async throws { await self.jobs.store(jobs) }

    func store(_ materialization: AutomationMaterialization) async throws {
        await values.store(materialization)
    }

    func load(jobID: String, revision: String) async throws -> AutomationMaterialization? {
        if materializationUnreadable { throw Unreadable() }
        return await values.load(jobID: jobID, revision: revision)
    }

    func delete(jobID: String, revision: String) async throws {
        await values.delete(jobID: jobID, revision: revision)
    }
}

/// A Keychain that can't be read for a moment at csecd's start must not end
/// a daemon's run for good: its child is refused this time, and the record is
/// kept as it was for the next csecd to check. And a revoke whose tombstone
/// cannot be written keeps the values and fails, so no restart can find the
/// revoked run live with its values gone or present.
private func automationRestartKeychainFailureTests() async {
    let opRef = "op://automation-keychain/item/token"
    let opValue = Data("synthetic-keychain-op-value".utf8)
    let executable = PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified)
    let commandLine = ["/bin/sh", "-c", "synthetic keychain script"]
    let reason = "Synthetic daemon across a Keychain hiccup"
    do {
        let command = AutomationCommand(
            executable: executable,
            commandLine: commandLine,
            workingDirectory: "/tmp",
            commandDigest: try ExecutableInspection.commandDigest(commandLine)
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(AutomationFixtureProvider(scheme: "op", values: [opRef: opValue]))
        let clock = ManualAutomationClock(wall: Date(timeIntervalSince1970: 5_000), awake: 40_000)
        let inspector = AutomationFixtureInspector(
            starts: [950: 150, 951: 151],
            parents: [951: 950],
            paths: [950: "/synthetic/csec", 951: "/bin/sh"],
            executable: executable,
            clock: clock
        )
        let stores = FlakyAutomationStores()
        let backend = InMemoryProtectedItemBackend()
        func csecd() -> AutomationService {
            AutomationService(
                resolver: resolver,
                grantStore: stores,
                materializationStore: stores,
                consent: AutoApproveConsent(),
                policyReview: AutomationApprovingReview(capture: AutomationReviewCapture()),
                processInspector: inspector,
                terminalInspection: .unavailable,
                clock: { clock.now() },
                runStore: ProtectedStores.processLocal(backend).store(for: AutomationRunsDocument.self),
                bootSessionUUID: "boot-a"
            )
        }
        let launcher = CallerInfo(pid: 950, startTime: 150, description: "synthetic csec")
        let bridge = CallerInfo(pid: 9_999, startTime: 999, description: "synthetic bridge")
        let plan = bridgePlan(executable: executable, consumerPID: 951, consumerStartTime: 151, reason: reason)
        func served(_ service: AutomationService) async throws -> Bool {
            if case .allowed = await service.authorizeAccess(
                references: [try SecretRef(opRef)], plan: plan, caller: bridge
            ) { return true }
            return false
        }

        let first = csecd()
        _ = await first.restoreRuns()
        _ = try await first.enroll(AutomationEnrollment(
            name: "keychain-daemon", reason: reason, references: [opRef], command: command,
            maximumRuntimeSeconds: nil
        ), caller: launcher)
        guard case .started = try await first.beginRun(name: "keychain-daemon", caller: launcher) else {
            check(false, "automation keychain: the daemon run starts")
            return
        }
        await first.flushPersistedRuns()

        for (label, unreadableCatalog) in [("materialization", false), ("catalog", true)] {
            await stores.set(catalogUnreadable: unreadableCatalog, materializationUnreadable: !unreadableCatalog)
            let hiccup = csecd()
            let restored = await hiccup.restoreRuns()
            let refused = try await !served(hiccup)
            await hiccup.flushPersistedRuns()
            check(restored.live == 0 && restored.tombstones == 1 && refused,
                  "automation keychain: an unreadable \(label) at start refuses the child (\(restored))")
            await stores.set()
            let healthy = csecd()
            let again = await healthy.restoreRuns()
            let servedAgain = try await served(healthy)
            check(again.live == 1 && servedAgain,
                  "automation keychain: the next csecd that can read the \(label) restores the run live (\(again))")
            await healthy.flushPersistedRuns()
        }

        // The tombstone can't be written: the revoke fails and keeps the values.
        let revoking = csecd()
        _ = await revoking.restoreRuns()
        await backend.inject(.failingWrites(errSecIO, delete: errSecIO), for: .automationRuns)
        do {
            _ = try await revoking.revoke(name: "keychain-daemon", caller: launcher)
            check(false, "automation keychain: a revoke whose tombstone can't be written fails")
        } catch {
            check(true, "automation keychain: a revoke whose tombstone can't be written fails")
        }
        guard let job = try await stores.load().first else {
            check(false, "automation keychain: the failed revoke left the job enrolled")
            return
        }
        let kept = try await stores.load(jobID: job.id, revision: job.revision)
        check(kept != nil, "automation keychain: the failed revoke left the values in place")
        let servedAfterFailedRevoke = try await served(revoking)
        check(!servedAfterFailedRevoke,
              "automation keychain: the run is refused in memory at once all the same")
        await backend.inject(InMemoryProtectedItemBackend.Failures(), for: .automationRuns)
        _ = try await revoking.revoke(name: "keychain-daemon", caller: launcher)
        await revoking.flushPersistedRuns()
        let afterRevoke = csecd()
        let revoked = await afterRevoke.restoreRuns()
        let servedAfterRevoke = try await served(afterRevoke)
        check(revoked.live == 0 && revoked.tombstones == 1 && !servedAfterRevoke,
              "automation keychain: the retried revoke's run is restored only as a tombstone (\(revoked))")
    } catch {
        check(false, "automation keychain checks run (\(error))")
    }
}

/// A virtual environment's `bin/python` is a symlink, and Python finds the
/// environment only from argv[0]. The job keeps that path as argv[0] and runs
/// only while it still leads to the enrolled interpreter.
private func automationInvokedPathTests() async {
    let interpreter = PlannedExecutable(
        canonicalPath: "/synthetic/python/bin/python3.12", assurance: .unverified
    )
    let venvPython = "/synthetic/project/.venv/bin/python"
    let commandLine = [venvPython, "-m", "synthetic.daemon"]
    let opRef = "op://automation-venv/item/token"
    do {
        let command = AutomationCommand(
            executable: interpreter,
            commandLine: commandLine,
            workingDirectory: "/tmp",
            commandDigest: try ExecutableInspection.commandDigest(commandLine)
        )
        check(command.isWellFormed,
              "automation command keeps a symlinked interpreter path as argv[0]")
        let relative = ["python", "-m", "synthetic.daemon"]
        check(!AutomationCommand(
            executable: interpreter,
            commandLine: relative,
            workingDirectory: "/tmp",
            commandDigest: try ExecutableInspection.commandDigest(relative)
        ).isWellFormed, "automation command refuses a relative argv[0]")

        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(AutomationFixtureProvider(
            scheme: "op", values: [opRef: Data("synthetic-venv-value".utf8)]
        ))
        let clock = ManualAutomationClock(wall: Date(timeIntervalSince1970: 7_000), awake: 50_000)
        let inspector = AutomationFixtureInspector(
            starts: [940: 130, 950: 140],
            parents: [:],
            paths: [940: "/synthetic/csec", 950: "/synthetic/csec"],
            executable: PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified),
            clock: clock
        )
        await inspector.setAlias(venvPython, to: interpreter)
        let service = AutomationService(
            resolver: resolver,
            grantStore: InMemoryAutomationGrantStore(),
            materializationStore: InMemoryAutomationMaterializationStore(),
            consent: AutoApproveConsent(),
            policyReview: AutomationApprovingReview(capture: AutomationReviewCapture()),
            processInspector: inspector,
            terminalInspection: .unavailable,
            clock: { clock.now() }
        )
        let job = try await service.enroll(AutomationEnrollment(
            name: "venv-daemon", reason: "Synthetic venv daemon", references: [opRef],
            command: command, maximumRuntimeSeconds: nil
        ), caller: CallerInfo(pid: 940, startTime: 130, description: "synthetic csec"))
        check(job.command.commandLine[0] == venvPython
                && job.command.executable.canonicalPath == interpreter.canonicalPath,
              "automation enrolls the venv path as argv[0] and the resolved interpreter as its identity")
        guard case let .started(run) = try await service.beginRun(
            name: "venv-daemon", caller: CallerInfo(pid: 940, startTime: 130, description: "synthetic csec")
        ) else {
            check(false, "automation runs a job whose argv[0] leads to the enrolled interpreter")
            return
        }
        check(run.job.command.commandLine[0] == venvPython,
              "automation hands the runner the venv path as argv[0]")
        _ = await service.finishRun(
            runID: run.runID, caller: CallerInfo(pid: 940, startTime: 130, description: "synthetic csec")
        )

        // The venv was rebuilt over another interpreter.
        await inspector.setAlias(
            venvPython,
            to: PlannedExecutable(canonicalPath: "/synthetic/python/bin/python3.13", assurance: .unverified)
        )
        do {
            _ = try await service.beginRun(
                name: "venv-daemon", caller: CallerInfo(pid: 950, startTime: 140, description: "synthetic csec")
            )
            check(false, "automation refuses a run once argv[0] leads to another interpreter")
        } catch AutomationServiceError.executableChanged {
            check(true, "automation refuses a run once argv[0] leads to another interpreter")
        }
    } catch {
        check(false, "automation invoked-path checks run (\(error))")
    }
}

/// A framework Python replaces its launcher with Python.app in the same PID.
/// The wire fixture keeps this regression executable against the old catalog
/// decoder too: it used to discard launcherExecutable and refuse enrollment.
private func automationFrameworkPythonTests() async {
    let root = "/synthetic/Python.framework/Versions/3.14"
    let launcher = PlannedExecutable(
        canonicalPath: root + "/bin/python3.14", cdHash: String(repeating: "a", count: 40),
        assurance: .unverified
    )
    let consumer = PlannedExecutable(
        canonicalPath: root + "/Resources/Python.app/Contents/MacOS/Python",
        cdHash: String(repeating: "b", count: 40), assurance: .unverified
    )
    let ref = "op://framework-python/item/token"
    let nativeRef = "csec://framework-python/token"
    do {
        let invoked = "/synthetic/project/.venv/bin/python"
        let argv = [invoked, "-m", "synthetic.job"]
        let original = AutomationCommand(
            executable: consumer, commandLine: argv, workingDirectory: "/tmp",
            commandDigest: try ExecutableInspection.commandDigest(argv)
        )
        var wire = try JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as! [String: Any]
        wire["launcherExecutable"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(launcher))
        let command = try JSONDecoder().decode(
            AutomationCommand.self, from: JSONSerialization.data(withJSONObject: wire)
        )
        let clock = ManualAutomationClock(wall: Date(timeIntervalSince1970: 8_000), awake: 100)
        let inspector = AutomationFixtureInspector(
            starts: [960: 150, 961: 151, 962: 152],
            parents: [961: 960, 962: 961],
            paths: [960: "/synthetic/csec", 961: consumer.canonicalPath, 962: "/synthetic/csec"],
            executable: launcher, clock: clock
        )
        await inspector.setAlias(consumer.canonicalPath, to: consumer)
        await inspector.setAlias(invoked, to: launcher)
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(AutomationFixtureProvider(
            scheme: "op", values: [ref: Data("synthetic-framework-value".utf8)]
        ))
        await resolver.register(AutomationFixtureProvider(
            scheme: "csec", values: [nativeRef: Data("synthetic-framework-native-value".utf8)]
        ))
        let service = AutomationService(
            resolver: resolver, grantStore: InMemoryAutomationGrantStore(),
            materializationStore: InMemoryAutomationMaterializationStore(), consent: AutoApproveConsent(),
            policyReview: AutomationApprovingReview(capture: AutomationReviewCapture()),
            processInspector: inspector, terminalInspection: .unavailable, clock: { clock.now() }
        )
        let caller = CallerInfo(pid: 960, startTime: 150, description: "synthetic csec")
        _ = try await service.enroll(AutomationEnrollment(
            name: "framework-python", reason: "Synthetic framework Python", references: [ref, nativeRef],
            command: command
        ), caller: caller)
        guard case let .started(run) = try await service.beginRun(name: "framework-python", caller: caller) else {
            check(false, "automation framework Python starts its pinned launcher")
            return
        }
        let access = await service.authorizeAccess(
            references: [try SecretRef(ref), try SecretRef(nativeRef)],
            plan: bridgePlan(executable: consumer, consumerPID: 961, consumerStartTime: 151,
                             reason: "Synthetic framework Python"),
            caller: CallerInfo(pid: 962, startTime: 152, description: "synthetic bridge")
        )
        if case let .allowed(values, _) = access {
            check(Set(values.keys) == Set([ref, nativeRef]),
                  "automation serves both provider schemes to the pinned Python.app direct child")
        } else {
            check(false, "automation serves the pinned Python.app direct child after framework re-exec")
        }

        check(command.launcherExecutable == launcher && command.executionPath == argv[0],
              "automation framework recipe pins both images and executes the invoked launcher path")
        check(try JSONDecoder().decode(AutomationCommand.self, from: JSONEncoder().encode(command)) == command,
              "automation framework identities survive the value-free catalog round-trip")
        let legacy = AutomationCommand(
            executable: launcher, commandLine: argv, workingDirectory: "/tmp",
            commandDigest: command.commandDigest
        )
        let legacyWire = try JSONEncoder().encode(legacy)
        check(try JSONDecoder().decode(AutomationCommand.self, from: legacyWire).launcherExecutable == nil
                && !String(decoding: legacyWire, as: UTF8.self).contains("launcherExecutable")
                && legacy.executionPath == launcher.canonicalPath,
              "automation legacy recipes keep one identity and their original execution path")

        func recipe(_ consumerImage: PlannedExecutable, _ launcherImage: PlannedExecutable) -> AutomationCommand {
            AutomationCommand(
                executable: consumerImage, commandLine: argv, workingDirectory: "/tmp",
                commandDigest: command.commandDigest, launcherExecutable: launcherImage
            )
        }
        let unrelated = PlannedExecutable(
            canonicalPath: "/synthetic/Other.app/Contents/MacOS/Python",
            cdHash: consumer.cdHash, assurance: .unverified
        )
        check(!recipe(unrelated, launcher).isWellFormed,
              "automation refuses an unrelated app as a framework consumer")
        check(!recipe(PlannedExecutable(
            canonicalPath: consumer.canonicalPath, assurance: .unverified
        ), launcher).isWellFormed && !recipe(consumer, PlannedExecutable(
            canonicalPath: launcher.canonicalPath, assurance: .unverified
        )).isWellFormed, "automation requires both framework image cdhashes")
        let changedConsumer = PlannedExecutable(
            canonicalPath: consumer.canonicalPath, cdHash: String(repeating: "c", count: 40),
            assurance: .unverified
        )
        let changedAccess = await service.authorizeAccess(
            references: [try SecretRef(ref)],
            plan: bridgePlan(executable: changedConsumer, consumerPID: 961, consumerStartTime: 151,
                             reason: "Synthetic changed framework image"),
            caller: CallerInfo(pid: 962, startTime: 152, description: "synthetic bridge")
        )
        if case .denied(.executableChanged) = changedAccess {
            check(true, "automation refuses a bridge whose Python.app cdhash changed")
        } else {
            check(false, "automation refuses a bridge whose Python.app cdhash changed")
        }
        _ = await service.finishRun(runID: run.runID, caller: caller)
        let changedLauncher = PlannedExecutable(
            canonicalPath: launcher.canonicalPath, cdHash: String(repeating: "d", count: 40),
            assurance: .unverified
        )
        for (label, path, originalImage, replacement) in [
            ("launcher", invoked, launcher, changedLauncher),
            ("consumer", consumer.canonicalPath, consumer, changedConsumer),
            ("venv target", invoked, launcher, unrelated),
        ] {
            await inspector.setAlias(path, to: replacement)
            do {
                _ = try await service.beginRun(name: "framework-python", caller: caller)
                check(false, "automation refuses a framework run after its \(label) changes")
            } catch AutomationServiceError.executableChanged {
                check(true, "automation refuses a framework run after its \(label) changes")
            }
            await inspector.setAlias(path, to: originalImage)
        }
    } catch {
        check(false, "automation framework Python enrollment and bridge access succeed (\(error))")
    }
}
