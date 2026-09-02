import ConvenientSecurity
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

private actor AutomationFixtureInspector: AutomationProcessInspecting {
    private var starts: [pid_t: UInt64]
    private var parents: [pid_t: pid_t]
    private var paths: [pid_t: String]
    private let executable: PlannedExecutable
    private var pauseNextExecutablePath = false
    private var executablePathPauseReached = false
    private var releaseExecutablePath = false

    init(
        starts: [pid_t: UInt64],
        parents: [pid_t: pid_t],
        paths: [pid_t: String],
        executable: PlannedExecutable
    ) {
        self.starts = starts
        self.parents = parents
        self.paths = paths
        self.executable = executable
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
        path == executable.canonicalPath ? executable : nil
    }

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

    func record(_ review: AccessPolicyReview) {
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
    let inspector = AutomationFixtureInspector(
        starts: [700: 70, 701: 71, 702: 72],
        parents: [701: 700, 702: 701],
        paths: [700: "/synthetic/csec", 701: "/bin/sh", 702: "/synthetic/csec"],
        executable: executable
    )
    let reviewCapture = AutomationReviewCapture()
    let service = AutomationService(
        resolver: resolver,
        grantStore: grantStore,
        materializationStore: materializationStore,
        consent: AutoApproveConsent(),
        policyReview: AutomationApprovingReview(capture: reviewCapture),
        processInspector: inspector
    )
    let caller = CallerInfo(pid: 700, startTime: 70, description: "synthetic csec")
    let enrollment = AutomationEnrollment(
        name: "youtube-reminders",
        reason: "Synthetic unattended reminders",
        references: [nativeRef, opRef],
        command: command,
        minimumIntervalSeconds: 60,
        maximumRuntimeSeconds: 300
    )

    do {
        let enrolled = try await service.enroll(
            enrollment,
            caller: caller,
            now: Date(timeIntervalSince1970: 1_000)
        )
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

        let startedAt = Date(timeIntervalSince1970: 1_010)
        let run: AutomationRunAuthorization
        switch try await service.beginRun(name: enrolled.name, caller: caller, now: startedAt) {
        case let .started(authorization):
            run = authorization
            check(authorization.expiresAt == startedAt.addingTimeInterval(300),
                  "automation run lease is bounded by maximum runtime")
        case .skipped:
            check(false, "first automation trigger starts")
            return
        }

        let plan = DeliveryPlan(
            mechanism: .directHeap,
            executable: executable,
            root: .directParent(pid: 701, startTime: 71),
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: 300,
            operationContext: "Synthetic unattended reminders"
        )
        let bridgeCaller = CallerInfo(pid: 702, startTime: 72, description: "synthetic bridge")
        switch await service.authorizeAccess(
            references: [try SecretRef(opRef)],
            plan: plan,
            caller: bridgeCaller,
            now: startedAt.addingTimeInterval(1)
        ) {
        case let .allowed(values, expiresAt):
            check(values[opRef] == opValue && values.count == 1 && expiresAt == run.expiresAt,
                  "only the requested registered materialization reaches the exact child")
        default:
            check(false, "exact direct child receives unattended access")
        }

        switch await service.authorizeAccess(
            references: [try SecretRef("op://automation-fixture/item/unregistered")],
            plan: plan,
            caller: bridgeCaller,
            now: startedAt.addingTimeInterval(1)
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
                caller: bridgeCaller,
                now: startedAt.addingTimeInterval(2)
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
        switch try await service.beginRun(
            name: enrolled.name,
            caller: caller,
            now: startedAt.addingTimeInterval(5)
        ) {
        case let .skipped(nextEligibleAt):
            check(nextEligibleAt == startedAt.addingTimeInterval(60),
                  "minimum interval suppresses rapid cron retries")
        case .started:
            check(false, "minimum interval suppresses rapid cron retries")
        }

        let concurrentStarts = await withTaskGroup(
            of: ConcurrentAutomationStart.self,
            returning: [ConcurrentAutomationStart].self
        ) { group in
            for _ in 0..<2 {
                group.addTask {
                    do {
                        switch try await service.beginRun(
                            name: enrolled.name,
                            caller: caller,
                            now: startedAt.addingTimeInterval(61)
                        ) {
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

        let afterRestart = AutomationService(
            resolver: resolver,
            grantStore: grantStore,
            materializationStore: materializationStore,
            consent: AutoApproveConsent(),
            policyReview: AutomationApprovingReview(capture: reviewCapture),
            processInspector: inspector
        )
        check(try await afterRestart.list().map(\.name) == [enrolled.name],
              "until-revoked authorization survives daemon restart")

        _ = try await service.revoke(name: enrolled.name, caller: caller)
        check(try await service.list().isEmpty,
              "revocation removes persistent authorization metadata")
        check(await materializationStore.load(
            jobID: enrolled.id,
            revision: enrolled.revision
        ) == nil, "revocation removes the automation-only value copy")
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
}
