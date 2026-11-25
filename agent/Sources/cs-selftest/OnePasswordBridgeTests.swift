import Foundation
import Darwin
import ConvenientSecurity
import OnePasswordAdapter

/// Stands in for one `csec-op-bridge` process. Records what the provider asked
/// for, so a test can prove not only what csec did but what it never did — the
/// property that matters here is the absence of unrequested 1Password contact.
actor FakeOnePasswordBackend: OnePasswordBackend {
    enum Call: Equatable {
        case resolve(String)
        /// A read over the running process only (`resolveOverRunningSession`).
        case resolveOpen(String)
        case vaults
        case items(String)
        case shutdown
    }

    private(set) var calls: [Call] = []
    private var vaultList: [OnePasswordVault]
    private var itemsByVault: [String: [OnePasswordItemIdentity]]
    private var values: [String: String]
    private var vaultsFailure: Error?
    /// What every read throws instead of answering: 1Password refusing.
    private var resolveFailure: Error?
    private var vaultsDelay: TimeInterval = 0
    /// How long a read takes before it answers or fails: 1Password's prompt
    /// on screen, waiting for a person.
    private var resolveDelay: TimeInterval = 0
    /// How many upcoming resolves report "not found" before the values table
    /// is consulted — the SDK's answer from an account still loading.
    private var pendingMisses = 0
    /// Whether the process is up: a stopped one answers no running-session
    /// read, and only `resolve` would start it again.
    private var running = true
    /// How long a running-session read takes to answer.
    private var openReadDelay: TimeInterval = 0

    init(
        vaults: [OnePasswordVault] = [],
        items: [String: [OnePasswordItemIdentity]] = [:],
        values: [String: String] = [:],
        vaultsError: Error? = nil,
        vaultsDelay: TimeInterval = 0,
        resolveError: Error? = nil,
        resolveDelay: TimeInterval = 0
    ) {
        self.vaultList = vaults
        self.itemsByVault = items
        self.values = values
        self.vaultsFailure = vaultsError
        self.vaultsDelay = vaultsDelay
        self.resolveFailure = resolveError
        self.resolveDelay = resolveDelay
    }

    func failVaults(with error: Error?) { vaultsFailure = error }
    func failResolves(with error: Error?) { resolveFailure = error }
    func delayVaults(by seconds: TimeInterval) { vaultsDelay = seconds }
    func delayResolves(by seconds: TimeInterval) { resolveDelay = seconds }
    func missNextResolves(_ count: Int) { pendingMisses = count }
    func setVaults(_ vaults: [OnePasswordVault]) { vaultList = vaults }
    func setItems(_ items: [OnePasswordItemIdentity], inVault vaultID: String) {
        itemsByVault[vaultID] = items
    }
    func recordedCalls() -> [Call] { calls }
    /// The value changes in 1Password, outside csec.
    func setValue(_ value: String, for reference: String) { values[reference] = value }
    func stopRunning() { running = false }
    func delayOpenReads(by seconds: TimeInterval) { openReadDelay = seconds }

    func resolve(_ reference: String) async throws -> Data {
        calls.append(.resolve(reference))
        running = true
        if resolveDelay > 0 {
            try await Task.sleep(nanoseconds: UInt64(resolveDelay * 1_000_000_000))
        }
        if let resolveFailure { throw resolveFailure }
        if pendingMisses > 0 {
            pendingMisses -= 1
            throw OnePasswordBridgeError.remote(kind: "not_found", message: "itemNotFound")
        }
        guard let value = values[reference] else {
            throw OnePasswordBridgeError.remote(kind: "not_found", message: "vaultNotFound")
        }
        return Data(value.utf8)
    }

    func resolveOverRunningSession(_ reference: String) async throws -> Data {
        calls.append(.resolveOpen(reference))
        guard running else { throw OnePasswordBridgeError.bridgeExited }
        if openReadDelay > 0 {
            try await Task.sleep(nanoseconds: UInt64(openReadDelay * 1_000_000_000))
        }
        if let resolveFailure { throw resolveFailure }
        guard let value = values[reference] else {
            throw OnePasswordBridgeError.remote(kind: "not_found", message: "itemNotFound")
        }
        return Data(value.utf8)
    }

    func vaults() async throws -> [OnePasswordVault] {
        calls.append(.vaults)
        if vaultsDelay > 0 {
            try await Task.sleep(nanoseconds: UInt64(vaultsDelay * 1_000_000_000))
        }
        if let vaultsFailure { throw vaultsFailure }
        return vaultList
    }

    func items(inVault vaultID: String) async throws -> [OnePasswordItemIdentity] {
        calls.append(.items(vaultID))
        return itemsByVault[vaultID] ?? []
    }

    func shutdown() async { calls.append(.shutdown) }
}

/// Hands out fake backends and records which accounts were ever authorized.
/// Creating a backend is the moment a real deployment would raise a Touch ID
/// prompt, so "was a backend created" is the test-visible stand-in for "was the
/// user interrupted".
final class FakeBackendRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var backends: [String: FakeOnePasswordBackend] = [:]
    private var created: [String] = []
    private let make: @Sendable (OnePasswordAccount) -> FakeOnePasswordBackend

    init(make: @escaping @Sendable (OnePasswordAccount) -> FakeOnePasswordBackend) {
        self.make = make
    }

    func factory() -> OnePasswordProvider.BackendFactory {
        { [self] account in
            lock.lock()
            defer { lock.unlock() }
            if let existing = backends[account.userID] { return existing }
            let backend = make(account)
            backends[account.userID] = backend
            created.append(account.userID)
            return backend
        }
    }

    func createdAccounts() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return created
    }

    func backend(_ userID: String) -> FakeOnePasswordBackend? {
        lock.lock()
        defer { lock.unlock() }
        return backends[userID]
    }
}

private func account(_ id: String, url: String) -> OnePasswordAccount {
    OnePasswordAccount(
        userID: id,
        accountID: "acct-\(id)",
        url: url,
        email: "\(id)@example.invalid"
    )
}

func onePasswordBridgeTests() async {
    print("\n# OnePasswordProvider over the bridge (no 1Password, no prompts)")

    let personal = account("user-personal", url: "my.1password.com")
    let work = account("user-work", url: "acme-work.1password.eu")

    #if DEBUG
    await onePasswordSessionRecoveryTests()
    await onePasswordBridgeOutputOrderTests()
    await onePasswordBridgeStalledShutdownTests()

    // Exercise the actual subprocess boundary. A backend fake would miss the
    // distinction between the CLI's user_uuid and the SDK's account_uuid.
    do {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("csec-bridge-selector-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("bridge-fixture")
        let script = """
        #!/bin/sh
        IFS= read -r request || exit 1
        if [ "$1" = "acct-user-work" ]; then
          printf '%s\\n' '{"id":1,"ok":true,"vaults":[{"id":"fixture-vault","title":"Fixture"}]}'
        else
          printf '%s\\n' '{"id":1,"ok":false,"kind":"not_found","message":"Account not found"}'
        fi
        IFS= read -r request || exit 1
        printf '%s\\n' '{"id":2,"ok":true}'
        """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: executable.path
        )
        let previous = ProcessInfo.processInfo.environment["CSEC_OP_BRIDGE_PATH"]
        setenv("CSEC_OP_BRIDGE_PATH", executable.path, 1)
        defer {
            if let previous {
                setenv("CSEC_OP_BRIDGE_PATH", previous, 1)
            } else {
                unsetenv("CSEC_OP_BRIDGE_PATH")
            }
        }
        let session = OnePasswordBridgeSession(
            account: work, executablePath: executable.path, requestTimeout: 3
        )
        do {
            let vaults = try await session.vaults()
            check(vaults == [OnePasswordVault(id: "fixture-vault", name: "Fixture")],
                  "the real bridge subprocess receives the SDK account UUID, not the CLI user UUID")
        } catch {
            check(false, "the bridge account selector reaches the SDK fixture (\(error))")
        }
        await session.shutdown()
    } catch {
        check(false, "the bridge account selector fixture starts (\(error))")
    }

    // The bridge's stderr and its exit are the only record of why a 1Password
    // prompt appeared, so both must reach the diagnostic sink — including an
    // exit that leaves a request unanswered.
    do {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("csec-bridge-diagnostics-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("bridge-fixture")
        let script = """
        #!/bin/sh
        IFS= read -r request || exit 1
        printf 'fixture: authorizing account=%s\\n' "$1" >&2
        printf 'fixture: giving up\\n' >&2
        exit 3
        """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: executable.path
        )
        let previous = ProcessInfo.processInfo.environment["CSEC_OP_BRIDGE_PATH"]
        setenv("CSEC_OP_BRIDGE_PATH", executable.path, 1)
        defer {
            if let previous {
                setenv("CSEC_OP_BRIDGE_PATH", previous, 1)
            } else {
                unsetenv("CSEC_OP_BRIDGE_PATH")
            }
        }
        final class Recorder: @unchecked Sendable {
            private let lock = NSLock()
            private var recorded: [OnePasswordBridgeDiagnostic] = []
            func record(_ entry: OnePasswordBridgeDiagnostic) { lock.lock(); recorded.append(entry); lock.unlock() }
            func entries() -> [OnePasswordBridgeDiagnostic] { lock.lock(); defer { lock.unlock() }; return recorded }
            func snapshot() -> [String] { entries().map(bridgeDiagnosticText) }
        }
        let recorder = Recorder()
        // The drain grace is far longer than this fixture needs, so only a
        // lost line, never the grace running out, can fail the checks below.
        let session = OnePasswordBridgeSession(
            account: work, executablePath: executable.path, requestTimeout: 30,
            outputDrainTimeout: 30,
            diagnostics: { recorder.record($0) }
        )
        do {
            _ = try await session.vaults()
            check(false, "a bridge that exits without answering fails the request")
        } catch let error as OnePasswordBridgeError {
            check(error == .bridgeExited,
                  "a bridge that exits without answering fails the request as bridgeExited (\(error))")
        } catch {
            check(false, "a bridge that exits without answering fails with a bridge error (\(error))")
        }
        // The request fails only once the exit is handled, and the exit waits
        // for stderr's EOF: no polling, every line is already recorded.
        let lines = recorder.snapshot()
        check(lines.contains { $0.hasPrefix("bridge process #1 started pid=") },
              "the bridge start is reported with its pid: \(lines)")
        check(lines.contains { $0 == "fixture: authorizing account=acct-user-work" },
              "each bridge stderr line is forwarded verbatim: \(lines)")
        check(recorder.entries().contains(OnePasswordBridgeDiagnostic(
                  event: OnePasswordBridgeDiagnostic.stderr,
                  detail: "fixture: authorizing account=acct-user-work"
              )),
              "a bridge stderr line is the detail of a stderr event, never csec's own words: \(lines)")
        check(lines.contains { $0.contains("exited (exit status 3) with 1 request(s) pending") },
              "the bridge exit is reported with its status and the requests it stranded: \(lines)")
        check(bridgeLine("fixture: giving up", precedesExitIn: lines),
              "the bridge's stderr lines are all reported before its exit: \(lines)")
    } catch {
        check(false, "the bridge diagnostics fixture starts (\(error))")
    }
    #endif

    // A clock the test drives, so lease expiry is exercised rather than waited for.
    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var now = Date(timeIntervalSince1970: 1_700_000_000)
        func date() -> Date { lock.lock(); defer { lock.unlock() }; return now }
        func advance(_ seconds: TimeInterval) {
            lock.lock(); defer { lock.unlock() }; now = now.addingTimeInterval(seconds)
        }
    }

    let configuration = OnePasswordConnectionConfiguration(
        keepaliveInterval: 4,
        sessionIdleWindow: 10,
        authenticationTimeout: 7
    )

    // MARK: One signed-in account: a read must not build an index

    do {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts([(personal.userID, personal.url)], vaults: [:])
        let registry = FakeBackendRegistry { _ in
            FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "v1", name: "Private")],
                values: ["op://Private/item/field": "single-account-value"]
            )
        }
        let clock = Clock()
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            },
            currentDate: { clock.date() }
        )

        // Nothing may touch 1Password before a request does.
        await provider.keepaliveTick()
        check(registry.createdAccounts().isEmpty,
              "the keepalive authorizes nothing before a real request")

        do {
            let resolved = try await provider.resolve(
                try SecretRef("op://Private/item/field"), unlock: nil
            )
            check(resolved.value == Data("single-account-value".utf8),
                  "a single-account read resolves over the bridge")
            check(registry.createdAccounts() == ["user-personal"],
                  "a single-account read authorizes exactly one account")
            let calls = await registry.backend("user-personal")?.recordedCalls() ?? []
            check(calls == [.resolve("op://Private/item/field")],
                  "the optimistic read costs no vault listing: one call, no index build")
        } catch {
            check(false, "single-account bridge read succeeds (\(error))")
        }

        // The keepalive follows real use.
        await provider.keepaliveTick()
        let afterTick = await registry.backend("user-personal")?.recordedCalls() ?? []
        check(afterTick.contains(.vaults),
              "after a real request the keepalive holds the session open")

        // ...and keeps holding it however long ago the last request was: there is
        // no activity lease, so an unlocked Mac keeps its session warm.
        clock.advance(60 * 60)
        let beforeIdle = (await registry.backend("user-personal")?.recordedCalls() ?? []).count
        await provider.keepaliveTick()
        let afterIdle = (await registry.backend("user-personal")?.recordedCalls() ?? []).count
        check(afterIdle > beforeIdle,
              "the keepalive keeps holding the session open regardless of how long ago the last request was")
    }

    // MARK: Screen lock suspends the keepalive

    do {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts([(personal.userID, personal.url)], vaults: [:])
        let registry = FakeBackendRegistry { _ in
            FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "v1", name: "Private")],
                values: ["op://Private/item/field": "value"]
            )
        }
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            }
        )
        _ = try? await provider.resolve(try SecretRef("op://Private/item/field"), unlock: nil)

        await provider.suspendKeepalive()
        let before = (await registry.backend("user-personal")?.recordedCalls() ?? []).count
        await provider.keepaliveTick()
        let after = (await registry.backend("user-personal")?.recordedCalls() ?? []).count
        check(before == after,
              "a locked screen suspends the keepalive: 1Password revokes on lock, so a ping could only re-prompt")

        // Only a real request re-arms it — never the screen unlocking.
        _ = try? await provider.resolve(try SecretRef("op://Private/item/field"), unlock: nil)
        await provider.keepaliveTick()
        let resumed = (await registry.backend("user-personal")?.recordedCalls() ?? []).count
        check(resumed > after, "a real request re-arms the keepalive")
    }

    // MARK: Screen lock is gated on 1Password's onDeviceLock setting

    do {
        // onDeviceLock = false: the session survives a screen lock, so csec must
        // NOT suspend — it keeps pinging and the next request costs no prompt.
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts([(personal.userID, personal.url)], vaults: [:])
        let registry = FakeBackendRegistry { _ in
            FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "v1", name: "Private")],
                values: ["op://Private/item/field": "value"]
            )
        }
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            },
            locksOnDeviceLock: { false }
        )
        _ = try? await provider.resolve(try SecretRef("op://Private/item/field"), unlock: nil)
        await provider.handleScreenLock()
        let before = (await registry.backend("user-personal")?.recordedCalls() ?? []).count
        await provider.keepaliveTick()
        let after = (await registry.backend("user-personal")?.recordedCalls() ?? []).count
        check(after > before,
              "when 1Password does not lock on device lock, a screen lock holds the session open (keepalive keeps pinging)")
    }

    do {
        // onDeviceLock = true: a screen lock revokes the session, so csec suspends
        // exactly as before — a ping could only re-prompt.
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts([(personal.userID, personal.url)], vaults: [:])
        let registry = FakeBackendRegistry { _ in
            FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "v1", name: "Private")],
                values: ["op://Private/item/field": "value"]
            )
        }
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            },
            locksOnDeviceLock: { true }
        )
        _ = try? await provider.resolve(try SecretRef("op://Private/item/field"), unlock: nil)
        await provider.handleScreenLock()
        let before = (await registry.backend("user-personal")?.recordedCalls() ?? []).count
        await provider.keepaliveTick()
        let after = (await registry.backend("user-personal")?.recordedCalls() ?? []).count
        check(before == after,
              "when 1Password locks on device lock, a screen lock suspends the keepalive")
    }

    // OnePasswordAppSettings reads the value-free onDeviceLock setting and
    // defaults to locking (suspend) whenever it cannot be read.
    do {
        let dir = NSTemporaryDirectory()
            + "csec-1p-settings-\(getpid())-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        func write(_ name: String, _ json: String) -> String {
            let path = (dir as NSString).appendingPathComponent(name)
            try? json.write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        let onPath = write("on.json", #"{"security.autolock.onDeviceLock": true, "x": 1}"#)
        let offPath = write("off.json", #"{"security.autolock.onDeviceLock": false}"#)
        let absentPath = write("absent.json", #"{"security.autolock.minutes": 60}"#)
        let malformedPath = write("bad.json", "not json{")
        check(OnePasswordAppSettings.locksOnDeviceLock(settingsPath: onPath) == true,
              "onDeviceLock=true parses as locking with the device")
        check(OnePasswordAppSettings.locksOnDeviceLock(settingsPath: offPath) == false,
              "onDeviceLock=false parses as not locking with the device")
        check(OnePasswordAppSettings.locksOnDeviceLock(settingsPath: absentPath) == true,
              "a missing onDeviceLock key defaults to locking (suspend)")
        check(OnePasswordAppSettings.locksOnDeviceLock(settingsPath: malformedPath) == true,
              "malformed settings default to locking (suspend)")
        check(OnePasswordAppSettings.locksOnDeviceLock(
                settingsPath: (dir as NSString).appendingPathComponent("nope.json")) == true,
              "an absent settings file defaults to locking (suspend)")
    }

    // MARK: A lapsed session is dropped, not silently re-authorized

    do {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts([(personal.userID, personal.url)], vaults: [:])
        let registry = FakeBackendRegistry { _ in
            FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "v1", name: "Private")],
                values: ["op://Private/item/field": "value"]
            )
        }
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            }
        )
        _ = try? await provider.resolve(try SecretRef("op://Private/item/field"), unlock: nil)
        await registry.backend("user-personal")?.failVaults(
            with: OnePasswordBridgeError.remote(kind: "session_expired", message: "expired")
        )
        await provider.keepaliveTick()
        let calls = await registry.backend("user-personal")?.recordedCalls() ?? []
        check(calls.contains(.shutdown),
              "a keepalive ping that cannot be served stops the bridge instead of re-authorizing")
        check(await provider.connectionStatus() == .disconnected,
              "a lapsed session is reported, not papered over")
    }

    // MARK: Two accounts — a miss pays for the index, and then selects correctly

    do {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts(
            [(personal.userID, personal.url), (work.userID, work.url)], vaults: [:])
        let registry = FakeBackendRegistry { requested in
            if requested.userID == "user-work" {
                return FakeOnePasswordBackend(
                    vaults: [OnePasswordVault(id: "w1", name: "Employee")],
                    values: ["op://Employee/Slack/password": "work-value"]
                )
            }
            return FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "p1", name: "Private")]
            )
        }
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            }
        )
        do {
            let resolved = try await provider.resolve(
                try SecretRef("op://Employee/Slack/password"), unlock: nil
            )
            check(resolved.value == Data("work-value".utf8),
                  "a vault that exists in only one account resolves from that account")
            check(Set(registry.createdAccounts()) == Set(["user-personal", "user-work"]),
                  "with several accounts and no warm session, the index is built to decide")
            let personalCalls = await registry.backend("user-personal")?.recordedCalls() ?? []
            check(!personalCalls.contains(.resolve("op://Employee/Slack/password")),
                  "the reference is never read from an account that does not hold the vault")
        } catch {
            check(false, "multi-account selection resolves the right account (\(error))")
        }

        // Once decided, the choice is remembered and costs no further listing.
        let workBefore = (await registry.backend("user-work")?.recordedCalls() ?? []).count
        _ = try? await provider.resolve(try SecretRef("op://Employee/Slack/password"), unlock: nil)
        let workAfter = await registry.backend("user-work")?.recordedCalls() ?? []
        check(workAfter.count == workBefore + 1,
              "a remembered account is re-used without rebuilding the index")
    }

    // MARK: A reference no account can serve fails, without reading anywhere

    do {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts(
            [(personal.userID, personal.url), (work.userID, work.url)], vaults: [:])
        let registry = FakeBackendRegistry { _ in
            FakeOnePasswordBackend(vaults: [OnePasswordVault(id: "p1", name: "Private")])
        }
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            }
        )
        do {
            _ = try await provider.resolve(
                try SecretRef("op://Nowhere/item/field"), unlock: nil
            )
            check(false, "a vault no account has should fail")
        } catch let error as OnePasswordError {
            guard case let .vaultNotFoundInAnyAccount(vault, accounts) = error else {
                check(false, "an unknown vault reports which accounts were searched")
                return
            }
            check(vault == "Nowhere" && accounts.count == 2,
                  "an unknown vault names the vault and the accounts searched")
        } catch {
            check(false, "an unknown vault reports a provider error (\(error))")
        }
    }

    // MARK: Failures are reported in csec's own words

    do {
        // op's and the SDK's text never reaches a user-facing surface; only the
        // closed set of csec-authored reasons does.
        let leaky = OnePasswordBridgeError.remote(
            kind: "not_found",
            message: "vaultNotFound: op internal detail 0xdeadbeef"
        )
        check(leaky.boundedReason == "1Password has no such vault, item, or field in this account",
              "a provider failure reaches the client as csec's words, not the SDK's")
        check(!leaky.boundedReason.contains("0xdeadbeef"),
              "upstream error text never rides out on a bounded reason")
        check(OnePasswordBridgeError.remote(kind: "session_expired", message: "")
                .boundedReason.contains("unlock 1Password"),
              "an expired session tells the user what to do about it")

        // A missing bridge is a distinct, actionable state — not "1Password is
        // unauthorized".
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts([(personal.userID, personal.url)], vaults: [:])
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: { _ in throw OnePasswordBridgeError.executableNotFound },
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            }
        )
        do {
            _ = try await provider.resolve(try SecretRef("op://Private/item/field"), unlock: nil)
            check(false, "a missing bridge should fail resolution")
        } catch let error as OnePasswordBridgeError {
            check(error == .executableNotFound, "a missing bridge is reported as such")
        } catch {
            check(false, "a missing bridge reports a bridge error (\(error))")
        }
        let summary = await provider.statusSummary()
        check(summary?.healthy == false
                && summary?.detail.contains("bridge is missing") == true,
              "csec status names a missing bridge instead of blaming 1Password")
    }

    // A cold multi-account request must preserve connection failures from the
    // index probe. Previously try? discarded them and reported "unlock
    // 1Password", including when the bridge itself was missing or unavailable.
    for failure in [
        OnePasswordBridgeError.executableNotFound,
        OnePasswordBridgeError.remote(
            kind: "unavailable", message: "untrusted-upstream-diagnostic"
        ),
    ] {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts(
            [(personal.userID, personal.url), (work.userID, work.url)], vaults: [:]
        )
        let registry = FakeBackendRegistry { _ in
            FakeOnePasswordBackend(vaultsError: failure)
        }
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: { requested in
                if failure == .executableNotFound { throw failure }
                return try registry.factory()(requested)
            },
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            }
        )
        do {
            _ = try await provider.resolve(try SecretRef("op://Employee/Slack/password"), unlock: nil)
            check(false, "failed multi-account connection should reject the request")
        } catch let error as OnePasswordBridgeError {
            check(error == failure,
                  "a failed account index preserves the original bridge error")
        } catch {
            check(false, "a failed account index must report its bridge error (\(error))")
        }
        let summary = await provider.statusSummary()
        check(summary?.healthy == false && summary?.detail == failure.boundedReason,
              "status reports the bounded bridge failure without upstream text")
        for id in registry.createdAccounts() {
            let calls = await registry.backend(id)?.recordedCalls() ?? []
            check(calls == [.vaults, .shutdown],
                  "a failed account probe shuts down without reading any secret")
        }
    }

    // MARK: A daemon nobody has used yet is idle, not broken

    do {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts([(personal.userID, personal.url)], vaults: [:])
        let registry = FakeBackendRegistry { _ in
            FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "v1", name: "Private")],
                values: ["op://Private/item/field": "value"]
            )
        }
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            }
        )
        // csecd now sits in this state from launch until it is first used, so
        // it must not read as a fault. Telling the user to unlock 1Password
        // here would invent a problem and train them to ignore the row.
        let idle = await provider.statusSummary()
        check(idle?.healthy == true && idle?.detail.contains("idle") == true,
              "an unused provider reports idle, not an unauthorized account")
        check(registry.createdAccounts().isEmpty,
              "asking for status never authorizes anything")

        _ = try? await provider.resolve(try SecretRef("op://Private/item/field"), unlock: nil)
        await provider.shutdownBackends()
        let lapsed = await provider.statusSummary()
        check(lapsed?.detail.contains("session lapsed") == true,
              "a lapsed session is named rather than implied to be live")
    }
}

#if DEBUG
/// Whether `line` was reported, and reported before the bridge's exit line.
/// A bridge diagnostic as these tests read it: a stderr line as the bridge
/// wrote it, any other event in csec's words with its detail after a colon.
private func bridgeDiagnosticText(_ entry: OnePasswordBridgeDiagnostic) -> String {
    if entry.event == OnePasswordBridgeDiagnostic.stderr { return entry.detail ?? "" }
    return entry.detail.map { "\(entry.event): \($0)" } ?? entry.event
}

private func bridgeLine(_ line: String, precedesExitIn lines: [String]) -> Bool {
    guard let position = lines.firstIndex(of: line),
          let exit = lines.firstIndex(where: { $0.contains(" exited (") })
    else { return false }
    return position < exit
}

/// A bridge's stdout, stderr and exit reach csecd on three handlers, in no
/// fixed order. Each fixture here makes the exit arrive first, every time: a
/// child the bridge leaves behind writes after the bridge itself has exited,
/// and the pipes reach EOF only once that child is gone too.
private func onePasswordBridgeOutputOrderTests() async {
    final class Recorder: @unchecked Sendable {
        private let lock = NSLock()
        private var lines: [String] = []
        func record(_ line: String) { lock.lock(); lines.append(line); lock.unlock() }
        func snapshot() -> [String] { lock.lock(); defer { lock.unlock() }; return lines }
    }

    for mode in ["late-diagnostic", "late-answer", "shutdown-diagnostic", "held-pipe"] {
        do {
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("csec-bridge-output-\(UUID().uuidString)")
                .resolvingSymlinksInPath()
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: directory) }
            let executable = directory.appendingPathComponent("bridge-fixture")
            let body: String
            switch mode {
            case "late-diagnostic":
                body = """
                IFS= read -r request || exit 1
                ( /bin/sleep 0.5; printf 'fixture: written after the bridge exited\\n' >&2 ) &
                exit 3
                """
            case "late-answer":
                // The child holds the pipes a second past its answer, so the
                // shutdown below finds a bridge that has exited but whose
                // exit is still waiting for its pipes. Every launch is logged
                // to `launches`.
                body = """
                printf 'launch\\n' >> '\(directory.path)/launches'
                IFS= read -r request || exit 1
                ( /bin/sleep 0.5; printf '%s\\n' '{"id":1,"ok":true,"vaults":[{"id":"late-vault","title":"Late"}]}'; /bin/sleep 1 ) &
                exit 0
                """
            case "shutdown-diagnostic":
                // Like the real bridge's "exiting" line, this one follows the
                // last answer; ignoring csecd's SIGTERM keeps the fixture
                // alive past the teardown so the line is always written after it.
                body = """
                trap '' TERM
                IFS= read -r request || exit 1
                printf '%s\\n' '{"id":1,"ok":true,"vaults":[]}'
                IFS= read -r request || exit 1
                printf '%s\\n' '{"id":2,"ok":true}'
                /bin/sleep 0.5
                printf 'fixture: exiting after shutdown\\n' >&2
                printf '%s' "$?" > '\(directory.path)/written'
                exit 0
                """
            default:
                // A child that keeps the bridge's pipes open and never writes.
                body = """
                IFS= read -r request || exit 1
                /bin/sleep 30 &
                printf '%s\\n' "$!" > '\(directory.path)/holder'
                exit 4
                """
            }
            try Data("#!/bin/sh\n\(body)\n".utf8).write(to: executable)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
            let previous = ProcessInfo.processInfo.environment["CSEC_OP_BRIDGE_PATH"]
            setenv("CSEC_OP_BRIDGE_PATH", executable.path, 1)
            defer {
                if let previous { setenv("CSEC_OP_BRIDGE_PATH", previous, 1) }
                else { unsetenv("CSEC_OP_BRIDGE_PATH") }
            }
            let recorder = Recorder()
            let session = OnePasswordBridgeSession(
                account: account("user-work", url: "work.example.invalid"),
                executablePath: executable.path, requestTimeout: 30,
                outputDrainTimeout: mode == "held-pipe" ? 0.5 : 30,
                diagnostics: { recorder.record(bridgeDiagnosticText($0)) }
            )

            switch mode {
            case "late-diagnostic":
                do {
                    _ = try await session.vaults()
                    check(false, "a bridge that exits without answering fails the request (\(mode))")
                } catch {
                    check(error as? OnePasswordBridgeError == .bridgeExited,
                          "a bridge that exits without answering fails as bridgeExited (\(mode): \(error))")
                }
                let lines = recorder.snapshot()
                check(bridgeLine("fixture: written after the bridge exited", precedesExitIn: lines),
                      "stderr still in the bridge's pipe when its exit is observed is reported, before the exit: \(lines)")
                check(lines.contains { $0.contains("exited (exit status 3) with 1 request(s) pending") },
                      "the exit is reported once its pipes are drained, with the request it stranded: \(lines)")
            case "late-answer":
                do {
                    let vaults = try await session.vaults()
                    check(vaults == [OnePasswordVault(id: "late-vault", name: "Late")],
                          "an answer still in the bridge's stdout when its exit is observed answers its request")
                } catch {
                    check(false, "an answer still in the bridge's stdout when its exit is observed is not lost (\(error))")
                }
                await session.shutdown()
                let launches = (try? String(contentsOf: directory.appendingPathComponent("launches"), encoding: .utf8)) ?? ""
                check(launches == "launch\n" && !recorder.snapshot().contains { $0.hasPrefix("bridge process #2 ") },
                      "shutting down a bridge that has exited starts no new bridge to say goodbye to: \(recorder.snapshot())")
            case "shutdown-diagnostic":
                do {
                    _ = try await session.vaults()
                } catch {
                    check(false, "the shutdown fixture answers its first request (\(error))")
                }
                await session.shutdown()
                // Wait for the fixture to have written its line, then for the
                // line to be reported, so a failure says which of the two
                // never happened. The bounds only absorb a stalled machine.
                let written = directory.appendingPathComponent("written").path
                for _ in 0..<300 where !FileManager.default.fileExists(atPath: written) {
                    try await Task.sleep(nanoseconds: 100_000_000)
                }
                var lines = recorder.snapshot()
                for _ in 0..<300 where !lines.contains("fixture: exiting after shutdown") {
                    try await Task.sleep(nanoseconds: 100_000_000)
                    lines = recorder.snapshot()
                }
                let printfStatus = (try? String(contentsOfFile: written, encoding: .utf8)) ?? "never ran"
                check(lines.contains("fixture: exiting after shutdown"),
                      "stderr a bridge writes after csecd has shut it down is still reported"
                      + " (the fixture's printf status: \(printfStatus)): \(lines)")
            default:
                let started = Date()
                do {
                    _ = try await session.vaults()
                    check(false, "a bridge that exits without answering fails the request (\(mode))")
                } catch {
                    check(error as? OnePasswordBridgeError == .bridgeExited,
                          "a bridge that exits without answering fails as bridgeExited (\(mode): \(error))")
                }
                let elapsed = Date().timeIntervalSince(started)
                check(elapsed < 10,
                      "a pipe held open after the bridge exits delays the exit only by the drain grace (\(elapsed)s)")
                let lines = recorder.snapshot()
                check(lines.contains { $0.contains("exited (exit status 4) with 1 request(s) pending") },
                      "the exit is reported when the drain grace ends: \(lines)")
                if let holder = try? String(contentsOf: directory.appendingPathComponent("holder"), encoding: .utf8),
                   let pid = pid_t(holder.trimmingCharacters(in: .whitespacesAndNewlines)) {
                    kill(pid, SIGTERM)
                }
            }
            await session.shutdown()
        } catch {
            check(false, "the bridge output-order fixture runs (\(mode): \(error))")
        }
    }
}

/// A real pipe/process fixture reproduces the poisoned SDK handle without
/// contacting 1Password. Only a new process can serve the synthetic value.
private func onePasswordSessionRecoveryTests() async {
    final class Diagnostics: @unchecked Sendable {
        private let lock = NSLock()
        private var lines: [String] = []
        func record(_ line: String) { lock.lock(); lines.append(line); lock.unlock() }
        func snapshot() -> [String] { lock.lock(); defer { lock.unlock() }; return lines }
    }

    for mode in ["recover", "still-invalid", "keepalive", "unauthorized", "not_found", "session_expired"] {
        do {
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("csec-session-recovery-\(UUID().uuidString)")
                .resolvingSymlinksInPath()
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: directory) }
            let executable = directory.appendingPathComponent("bridge-fixture")
            let kind = ["unauthorized", "not_found", "session_expired"].contains(mode)
                ? mode : "client_invalidated"
            let script = """
            #!/bin/sh
            count=0
            if [ -f '\(directory.path)/launches' ]; then
              IFS= read -r count < '\(directory.path)/launches'
            fi
            count=$((count + 1))
            printf '%s\\n' "$count" > '\(directory.path)/launches'
            printf '%s\\n' "$1" >> '\(directory.path)/accounts'
            while IFS= read -r request; do
              id=$(printf '%s' "$request" | /usr/bin/sed -n 's/.*"id":\\([0-9]*\\).*/\\1/p')
              case "$request" in
                *'"op":"shutdown"'*) printf '{"id":%s,"ok":true}\\n' "$id"; exit 0 ;;
              esac
              printf '%s\\n' "$request" >> '\(directory.path)/requests'
              if [ '\(mode)' = recover ] && [ "$count" -gt 1 ]; then
                printf '{"id":%s,"ok":true,"value":"synthetic-recovered-value"}\\n' "$id"
              else
                printf '{"id":%s,"ok":false,"kind":"\(kind)","message":"fixture upstream error"}\\n' "$id"
              fi
            done
            """
            try Data(script.utf8).write(to: executable)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
            let previous = ProcessInfo.processInfo.environment["CSEC_OP_BRIDGE_PATH"]
            setenv("CSEC_OP_BRIDGE_PATH", executable.path, 1)
            defer {
                if let previous { setenv("CSEC_OP_BRIDGE_PATH", previous, 1) }
                else { unsetenv("CSEC_OP_BRIDGE_PATH") }
            }
            let diagnostics = Diagnostics()
            let session = OnePasswordBridgeSession(
                account: account("user-work", url: "work.example.invalid"),
                executablePath: executable.path, requestTimeout: 3,
                diagnostics: { diagnostics.record(bridgeDiagnosticText($0)) }
            )
            let reference = "op://Employee/Fixture Item/web token"
            do {
                if mode == "keepalive" {
                    _ = try await session.vaults()
                } else {
                    let value = try await session.resolve(reference)
                    check(mode == "recover" && value == Data("synthetic-recovered-value".utf8),
                          "an invalid client is retried on a fresh bridge for the authorized read (\(mode))")
                    if mode == "recover" {
                        let next = try await session.resolve(reference)
                        check(next == value, "the recovered bridge remains usable for the next read")
                    }
                }
                check(mode == "recover", "only the recoverable fixture succeeds (\(mode))")
            } catch let error as OnePasswordBridgeError {
                check(mode != "recover" && error == .remote(kind: kind, message: "fixture upstream error"),
                      "session recovery preserves the final bounded failure (\(mode))")
                if kind == "client_invalidated" {
                    check(error.boundedReason.contains("session")
                          && !error.boundedReason.contains("fixture upstream error"),
                          "an invalid SDK client is reported as a session failure without upstream text")
                    check(!(await session.isRunning()), "a poisoned bridge is discarded even when recovery fails")
                }
            } catch {
                check(false, "session recovery fixture returns a bridge error (\(mode): \(error))")
            }
            await session.shutdown()

            let launches = try String(contentsOf: directory.appendingPathComponent("launches"), encoding: .utf8)
            let expectedLaunches = ["recover", "still-invalid"].contains(mode) ? 2 : 1
            check(Int(launches.trimmingCharacters(in: .whitespacesAndNewlines)) == expectedLaunches,
                  "recovery is bounded to one restart, and keepalive/denials/misses never reconnect (\(mode))")
            let accounts = try String(contentsOf: directory.appendingPathComponent("accounts"), encoding: .utf8)
            check(accounts.split(separator: "\n") == Array(repeating: "acct-user-work", count: expectedLaunches),
                  "every recovery process stays on the approved account (\(mode))")
            let requests = try String(contentsOf: directory.appendingPathComponent("requests"), encoding: .utf8)
            let rows = try requests.split(separator: "\n").map {
                try JSONSerialization.jsonObject(with: Data($0.utf8)) as! [String: Any]
            }
            let expectedRequests = mode == "recover" ? 3 : expectedLaunches
            check(rows.count == expectedRequests && rows.allSatisfy {
                mode == "keepalive" ? $0["op"] as? String == "vaults"
                    : ($0["op"] as? String == "resolve" && $0["reference"] as? String == reference)
            }, "recovery repeats only the same approved operation and reference (\(mode))")
            check(!diagnostics.snapshot().joined().contains("synthetic-recovered-value"),
                  "session recovery diagnostics never contain the resolved value")
        } catch {
            check(false, "session recovery fixture runs (\(mode): \(error))")
        }
    }
}

/// The bridge reads its requests one at a time, so one held in a 1Password
/// prompt nobody answers cannot read csecd's goodbye either. Shutting it down
/// must not wait out a second request timeout for that goodbye (csec-0.65.6):
/// the caller's error and the next account's try are already a timeout late.
///
/// Each fixture `exec`s into a sleep that never answers, so it stands for a
/// bridge blocked inside the SDK and, like the real one, dies on SIGTERM.
private func onePasswordBridgeStalledShutdownTests() async {
    final class Recorder: @unchecked Sendable {
        private let lock = NSLock()
        private var lines: [String] = []
        func record(_ line: String) { lock.lock(); lines.append(line); lock.unlock() }
        func snapshot() -> [String] { lock.lock(); defer { lock.unlock() }; return lines }
    }

    for mode in ["timed-out", "pending", "slow-goodbye", "answered-late"] {
        do {
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("csec-bridge-stalled-\(UUID().uuidString)")
                .resolvingSymlinksInPath()
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: directory) }
            let executable = directory.appendingPathComponent("bridge-fixture")
            let body: String
            switch mode {
            case "slow-goodbye":
                // Answers its one request, then reads the goodbye and never
                // answers that.
                body = """
                IFS= read -r request || exit 1
                printf '%s\\n' '{"id":1,"ok":true,"vaults":[]}'
                IFS= read -r request || exit 1
                exec /bin/sleep 60
                """
            case "answered-late":
                // Answers its first request after csecd gave up on it, then
                // serves the next, and notes the goodbye when it reads one.
                body = """
                IFS= read -r request || exit 1
                /bin/sleep 3
                printf '%s\\n' '{"id":1,"ok":true,"vaults":[]}'
                IFS= read -r request || exit 1
                printf '%s\\n' '{"id":2,"ok":true,"vaults":[]}'
                IFS= read -r request || exit 1
                case "$request" in *'"op":"shutdown"'*) : > '\(directory.path)/goodbye' ;; esac
                printf '%s\\n' '{"id":3,"ok":true}'
                exec /bin/sleep 60
                """
            default:
                // Reads its first request and never answers anything again.
                body = """
                IFS= read -r request || exit 1
                exec /bin/sleep 60
                """
            }
            try Data("#!/bin/sh\n\(body)\n".utf8).write(to: executable)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
            let previous = ProcessInfo.processInfo.environment["CSEC_OP_BRIDGE_PATH"]
            setenv("CSEC_OP_BRIDGE_PATH", executable.path, 1)
            defer {
                if let previous { setenv("CSEC_OP_BRIDGE_PATH", previous, 1) }
                else { unsetenv("CSEC_OP_BRIDGE_PATH") }
            }
            let recorder = Recorder()
            // Where the goodbye must not be sent at all, its bound is at least
            // the request timeout, so only skipping it passes the time checks.
            let requestTimeout: TimeInterval = mode == "timed-out" ? 4 : mode == "answered-late" ? 2 : 30
            let shutdownTimeout: TimeInterval = mode == "slow-goodbye" ? 1 : 30
            let session = OnePasswordBridgeSession(
                account: account("user-work", url: "work.example.invalid"),
                executablePath: executable.path, requestTimeout: requestTimeout,
                shutdownTimeout: shutdownTimeout,
                diagnostics: { recorder.record(bridgeDiagnosticText($0)) }
            )

            switch mode {
            case "timed-out":
                let started = Date()
                do {
                    _ = try await session.vaults()
                    check(false, "a bridge that never answers fails the request")
                } catch {
                    check(error as? OnePasswordBridgeError == .timedOut,
                          "a bridge that never answers fails the request as timedOut (\(error))")
                }
                await session.shutdown()
                let elapsed = Date().timeIntervalSince(started)
                // The provider's own order: the request's error, then shutdown.
                // Waiting for the goodbye would take twice the request timeout.
                check(elapsed < requestTimeout + 2,
                      "a bridge that left a request unanswered is shut down without waiting for its goodbye"
                      + " (request and shutdown took \(elapsed)s; request timeout \(requestTimeout)s)")
            case "pending":
                let request = Task { try await session.vaults() }
                // send registers its waiter in the same actor turn that starts
                // the process, so a running process means a pending request.
                for _ in 0..<300 where !(await session.isRunning()) {
                    try await Task.sleep(nanoseconds: 10_000_000)
                }
                check(await session.isRunning(), "the pending-request fixture starts")
                let started = Date()
                await session.shutdown()
                let elapsed = Date().timeIntervalSince(started)
                check(elapsed < 3,
                      "a bridge still serving a request is shut down without waiting for its goodbye (\(elapsed)s)")
                do {
                    _ = try await request.value
                    check(false, "a request pending at shutdown fails")
                } catch {
                    check(error as? OnePasswordBridgeError == .bridgeExited,
                          "a request pending at shutdown fails as bridgeExited (\(error))")
                }
            case "answered-late":
                do {
                    _ = try await session.vaults()
                    check(false, "the late fixture's first request times out")
                } catch {
                    check(error as? OnePasswordBridgeError == .timedOut,
                          "the late fixture's first request times out (\(error))")
                }
                // Its answer to this one follows the late answer to the first,
                // so both have been delivered when this returns.
                do {
                    _ = try await session.vaults()
                } catch {
                    check(false, "a bridge that answers late serves the next request (\(error))")
                }
                await session.shutdown()
                check(FileManager.default.fileExists(atPath: directory.appendingPathComponent("goodbye").path),
                      "a bridge that has answered again since a request timed out is sent its goodbye")
            default:
                do {
                    _ = try await session.vaults()
                } catch {
                    check(false, "the slow-goodbye fixture answers its first request (\(error))")
                }
                let started = Date()
                await session.shutdown()
                let elapsed = Date().timeIntervalSince(started)
                check(elapsed >= shutdownTimeout - 0.2 && elapsed < shutdownTimeout + 3,
                      "an idle bridge that does not answer its goodbye is stopped after the goodbye's own bound"
                      + " (\(elapsed)s; bound \(shutdownTimeout)s, request timeout \(requestTimeout)s)")
            }
            check(!(await session.isRunning()), "shutdown stops the bridge (\(mode))")
            if mode == "timed-out" || mode == "pending" {
                let lines = recorder.snapshot()
                check(!lines.contains { $0.contains("op=shutdown") }
                      && lines.contains { $0.contains("still busy with a request; stopping it without a goodbye") },
                      "a bridge busy with a request is sent no goodbye (\(mode)): \(lines)")
            }
        } catch {
            check(false, "the stalled-bridge shutdown fixture runs (\(mode): \(error))")
        }
    }
}
#endif

/// A "not found" from the bridge is a claim to be checked, not a verdict.
///
/// The first read after 1Password unlocks (which every read after the Mac
/// sleeps is) reaches an account that is still loading, and the SDK reports
/// what it has not loaded yet as absent. These tests pin the shape of the
/// answer csec gives instead: retry while the account may still be loading,
/// stop as soon as the miss is provably real, and always say which account
/// was asked.
func onePasswordMissConfirmationTests() async {
    print("\n# 1Password miss confirmation (transient not-found after unlock)")

    let personal = account("user-personal", url: "my.1password.com")
    let work = account("user-work", url: "acme-work.1password.eu")
    let reference = try! SecretRef("op://Employee/Slack Token/password")
    let slackItem = OnePasswordItemIdentity(id: "item-slack", title: "Slack Token")
    let schedule: [TimeInterval] = [0.001, 0.002, 0.003]
    let configuration = OnePasswordConnectionConfiguration(
        keepaliveInterval: 4,
        sessionIdleWindow: 10,
        authenticationTimeout: 7,
        missRetryDelays: schedule
    )

    actor RecordingSleeper {
        private var intervals: [TimeInterval] = []
        func sleep(_ seconds: TimeInterval) { intervals.append(seconds) }
        func recorded() -> [TimeInterval] { intervals }
    }

    struct Fixture {
        let provider: OnePasswordProvider
        let registry: FakeBackendRegistry
        let sleeper: RecordingSleeper
    }

    func makeFixture(
        workItems: [OnePasswordItemIdentity],
        workValues: [String: String]
    ) async -> Fixture {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts(
            [(personal.userID, personal.url), (work.userID, work.url)], vaults: [:]
        )
        let registry = FakeBackendRegistry { requested in
            if requested.userID == "user-work" {
                return FakeOnePasswordBackend(
                    vaults: [OnePasswordVault(id: "w1", name: "Employee", isPersonal: true)],
                    items: ["w1": workItems],
                    values: workValues
                )
            }
            return FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "p1", name: "Personal", isPersonal: true)]
            )
        }
        let sleeper = RecordingSleeper()
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            },
            sleep: { seconds in await sleeper.sleep(seconds) }
        )
        return Fixture(provider: provider, registry: registry, sleeper: sleeper)
    }

    // MARK: The race itself: a miss that heals once the account has loaded

    do {
        let fixture = await makeFixture(
            workItems: [slackItem], workValues: [reference.uri: "slack-value"]
        )
        // Decide the account first, the way a review does before Touch ID.
        _ = await fixture.provider.reviewDescription(for: reference)
        _ = try? await fixture.provider.resolve(reference, unlock: nil)
        let workBackend = fixture.registry.backend("user-work")!
        let before = await workBackend.recordedCalls().count

        // Now the session re-authorizes after a lock and answers "not found"
        // twice while the vault is still loading.
        await workBackend.missNextResolves(2)
        do {
            let resolved = try await fixture.provider.resolve(reference, unlock: nil)
            check(resolved.value == Data("slack-value".utf8),
                  "a miss from an account that holds the vault is retried until it resolves")
        } catch {
            check(false, "a transient miss heals on retry (\(error))")
        }
        let calls = Array((await workBackend.recordedCalls()).dropFirst(before))
        check(calls.first == .resolve(reference.uri) && calls.contains(.vaults),
              "the first miss is checked against the account's own vault list before retrying")
        check(calls.filter { $0 == .resolve(reference.uri) }.count == 3,
              "the read is repeated once per schedule entry until it succeeds, then stops")
        check(await fixture.sleeper.recorded() == Array(schedule.prefix(2)),
              "each retry waits its scheduled pause, and no pause is spent after success")
        let personalCalls = await fixture.registry.backend("user-personal")?.recordedCalls() ?? []
        check(!personalCalls.contains(.resolve(reference.uri)),
              "confirming a miss never reads the reference from another account")
        check(await fixture.provider.connectionStatus() == .connected,
              "a miss is not a connection failure and does not mark the provider disconnected")
    }

    // MARK: A genuine typo: the item never appears, the failure names the account

    do {
        let fixture = await makeFixture(workItems: [], workValues: [:])
        do {
            _ = try await fixture.provider.resolve(reference, unlock: nil)
            check(false, "an item no account has should not resolve")
        } catch let error as OnePasswordError {
            guard case let .referenceNotFound(vault, accountLabel, itemListed) = error else {
                check(false, "a confirmed miss is reported as such (got \(error))")
                return
            }
            check(vault == "Employee" && accountLabel == "acme-work.1password.eu" && !itemListed,
                  "a confirmed miss names the vault and the account that was asked")
            check(error.boundedReason.contains("acme-work.1password.eu"),
                  "the bounded reason carries the account label")
            check(error.boundedReason.contains("has no such item in vault “Employee”"),
                  "the bounded reason says the item, not the vault, is what is missing")
        } catch {
            check(false, "a confirmed miss is a provider error (\(error))")
        }
        check(await fixture.sleeper.recorded() == schedule,
              "a genuine miss exhausts the whole retry schedule before it is believed")
        let workCalls = await fixture.registry.backend("user-work")?.recordedCalls() ?? []
        check(workCalls.filter { $0 == .items("w1") }.count == 1
                && workCalls.last == .items("w1"),
              "the vault's items are listed once, after the schedule, only to classify the miss")
    }

    // MARK: The item exists but the field does not: reported as a field miss

    do {
        let fixture = await makeFixture(workItems: [slackItem], workValues: [:])
        do {
            _ = try await fixture.provider.resolve(reference, unlock: nil)
            check(false, "a missing field should not resolve")
        } catch let error as OnePasswordError {
            guard case let .referenceNotFound(_, _, itemListed) = error else {
                check(false, "a missing field is reported as a confirmed miss (got \(error))")
                return
            }
            check(itemListed, "a miss with the item listed is reported as a section or field miss")
            check(error.boundedReason.contains("but not that section or field"),
                  "the bounded reason distinguishes a missing field from a missing item")
        } catch {
            check(false, "a missing field is a provider error (\(error))")
        }
        check(await fixture.sleeper.recorded() == schedule,
              "a listed item does not shorten the schedule: the listing loads from the same store as the read")
    }

    // MARK: The displayed account no longer has the vault: fail closed, forget

    do {
        let fixture = await makeFixture(
            workItems: [slackItem], workValues: [reference.uri: "slack-value"]
        )
        _ = await fixture.provider.reviewDescription(for: reference)
        _ = try? await fixture.provider.resolve(reference, unlock: nil)
        let workBackend = fixture.registry.backend("user-work")!
        await workBackend.setVaults([])
        await workBackend.missNextResolves(1)
        do {
            _ = try await fixture.provider.resolve(reference, unlock: nil)
            check(false, "a vault gone from the displayed account should not resolve elsewhere")
        } catch let error as OnePasswordError {
            guard case let .vaultNoLongerInAccount(vault, accountLabel) = error else {
                check(false, "a vault gone from the chosen account is reported (got \(error))")
                return
            }
            check(vault == "Employee" && accountLabel == "acme-work.1password.eu",
                  "the failure names the account the review displayed and the vault it lost")
            check(error.boundedReason.contains("request it again"),
                  "the user is told to request again so the new account can be displayed")
        } catch {
            check(false, "a vault gone from the chosen account is a provider error (\(error))")
        }
        check(await fixture.sleeper.recorded().isEmpty,
              "a vault the account no longer has is settled without any retry")
        let personalCalls = await fixture.registry.backend("user-personal")?.recordedCalls() ?? []
        check(!personalCalls.contains(.resolve(reference.uri)),
              "the value is never fetched from an account the review did not display")
    }
}

/// A keepalive ping is abandoned, and its bridge stopped, when it cannot be
/// served in time, so a ping that had to re-authorize takes its prompt down
/// with it. On a busy Mac a healthy session answers slowly too, and dropping
/// it costs the next real request a fresh authorization: a prompt. So the
/// short deadline applies only where a re-authorization is plausible, and a
/// session that answered moments ago from a 1Password that cannot have
/// idle-locked is given a longer, still bounded, wait.
func onePasswordSlowKeepaliveTests() async {
    print("\n# 1Password keepalive on a slow Mac (a healthy session is held)")

    let personal = account("user-personal", url: "my.1password.com")
    let reference = try! SecretRef("op://Private/item/field")
    let configuration = OnePasswordConnectionConfiguration(
        keepaliveInterval: 4,
        sessionIdleWindow: 10,
        authenticationTimeout: 7,
        keepalivePingDeadline: 0.2,
        patientKeepalivePingDeadline: 1.5
    )

    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var now = Date(timeIntervalSince1970: 1_700_000_000)
        func date() -> Date { lock.lock(); defer { lock.unlock() }; return now }
        func advance(_ seconds: TimeInterval) {
            lock.lock(); defer { lock.unlock() }; now = now.addingTimeInterval(seconds)
        }
    }

    struct Outcome {
        let calls: [FakeOnePasswordBackend.Call]
        let status: OnePasswordConnectionStatus
        var dropped: Bool { calls.contains(.shutdown) }
    }

    /// One account, one real read, then one keepalive tick whose ping takes
    /// `pingDelay`, `sinceRead` seconds after the read.
    func tick(
        idleLock: OnePasswordAppSettings.IdleLock,
        systemIdle: TimeInterval?,
        pingDelay: TimeInterval,
        sinceRead: TimeInterval = 1
    ) async -> Outcome {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts([(personal.userID, personal.url)], vaults: [:])
        let registry = FakeBackendRegistry { _ in
            FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "v1", name: "Private")],
                values: [reference.uri: "value"]
            )
        }
        let clock = Clock()
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            },
            currentDate: { clock.date() },
            idleLockPolicy: { idleLock },
            systemIdleTime: { systemIdle }
        )
        _ = try? await provider.resolve(reference, unlock: nil)
        clock.advance(sinceRead)
        await registry.backend(personal.userID)?.delayVaults(by: pingDelay)
        await provider.keepaliveTick()
        return Outcome(
            calls: await registry.backend(personal.userID)?.recordedCalls() ?? [],
            status: await provider.connectionStatus()
        )
    }

    // The case seen live: 1Password never idle-locks, the session answered a
    // read moments ago, and the Mac is busy, so the ping is slow but answers.
    let slow = await tick(idleLock: .never, systemIdle: 0, pingDelay: 0.6)
    check(!slow.dropped,
          "a slow ping on a session that just answered, from a 1Password that never idle-locks, keeps its bridge: \(slow.calls)")
    check(slow.status == .connected,
          "a slow but answered keepalive ping reports the session as connected (\(slow.status))")

    // The longer wait is still bounded: a ping that never answers is dropped.
    let stuck = await tick(idleLock: .never, systemIdle: 0, pingDelay: 3)
    check(stuck.dropped,
          "a ping slower than the longer deadline still stops its bridge, withdrawing any prompt: \(stuck.calls)")

    // 1Password idle-locks, and the Mac has been idle long enough for that to
    // have happened: the ping may be an unlock prompt, so it is cut short.
    let idleLocked = await tick(idleLock: .after(minutes: 10), systemIdle: 20 * 60, pingDelay: 0.6)
    check(idleLocked.dropped,
          "when 1Password may have idle-locked, a slow ping is cut short at the short deadline: \(idleLocked.calls)")

    // 1Password idle-locks, but someone used the Mac moments ago, so it has
    // not: the session is as healthy as in the first case.
    let active = await tick(idleLock: .after(minutes: 10), systemIdle: 30, pingDelay: 0.6)
    check(!active.dropped,
          "when 1Password idle-locks but the Mac was used within that window, a slow ping keeps its bridge: \(active.calls)")

    // Unknown idle time with an idle-locking 1Password proves nothing.
    let unknownIdle = await tick(idleLock: .after(minutes: 10), systemIdle: nil, pingDelay: 0.6)
    check(unknownIdle.dropped,
          "an unreadable system idle time keeps the short deadline: \(unknownIdle.calls)")

    // An unreadable 1Password setting is treated as idle-locking.
    let unknownPolicy = await tick(idleLock: .unknown, systemIdle: 0, pingDelay: 0.6)
    check(unknownPolicy.dropped,
          "an unreadable auto-lock setting keeps the short deadline: \(unknownPolicy.calls)")

    // A session that has not answered within 1Password's idle window may have
    // lapsed, so its ping may be re-authorizing.
    let lapsed = await tick(idleLock: .never, systemIdle: 0, pingDelay: 0.6, sinceRead: 11)
    check(lapsed.dropped,
          "a session last answered beyond the idle window keeps the short deadline: \(lapsed.calls)")

    // A real read that answers while a ping waits proves the session alive,
    // so the ping running out afterwards does not drop it.
    do {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts([(personal.userID, personal.url)], vaults: [:])
        let registry = FakeBackendRegistry { _ in
            FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "v1", name: "Private")],
                values: [reference.uri: "value"]
            )
        }
        let clock = Clock()
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            },
            currentDate: { clock.date() },
            idleLockPolicy: { .never },
            systemIdleTime: { 0 }
        )
        _ = try? await provider.resolve(reference, unlock: nil)
        await registry.backend(personal.userID)?.delayVaults(by: 3)
        let ping = Task { await provider.keepaliveTick() }
        try? await Task.sleep(nanoseconds: 300_000_000)
        clock.advance(1)
        let read = try? await provider.resolve(reference, unlock: nil)
        await ping.value
        let calls = await registry.backend(personal.userID)?.recordedCalls() ?? []
        check(read?.value == Data("value".utf8),
              "a read during a slow keepalive ping is served by the running session")
        check(!calls.contains(.shutdown),
              "a ping that runs out after a read proved the session alive keeps its bridge: \(calls)")
    }

    // A fast ping is held under every policy, as before.
    let fast = await tick(idleLock: .unknown, systemIdle: nil, pingDelay: 0)
    check(!fast.dropped && fast.status == .connected,
          "a fast ping holds the session under the strictest policy: \(fast.calls)")

    // The settings reader: value-free, and anything it cannot read as a
    // definite answer is treated as idle-locking.
    do {
        let dir = NSTemporaryDirectory()
            + "csec-1p-idlelock-\(getpid())-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        func write(_ name: String, _ json: String) -> String {
            let path = (dir as NSString).appendingPathComponent(name)
            try? json.write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        let never = write("never.json", #"{"security.autolock.minutes": -1}"#)
        let ten = write("ten.json", #"{"security.autolock.minutes": 10}"#)
        let zero = write("zero.json", #"{"security.autolock.minutes": 0}"#)
        let absent = write("absent.json", #"{"security.autolock.onDeviceLock": false}"#)
        let text = write("text.json", #"{"security.autolock.minutes": "10"}"#)
        let malformed = write("bad.json", "not json{")
        check(OnePasswordAppSettings.idleLock(settingsPath: never) == .never,
              "autolock minutes -1 parses as never idle-locking")
        check(OnePasswordAppSettings.idleLock(settingsPath: ten) == .after(minutes: 10),
              "autolock minutes 10 parses as idle-locking after ten minutes")
        check(OnePasswordAppSettings.idleLock(settingsPath: zero) == .unknown,
              "autolock minutes 0 has no documented meaning, so it is unknown")
        check(OnePasswordAppSettings.idleLock(settingsPath: absent) == .unknown,
              "a missing autolock minutes key is unknown")
        check(OnePasswordAppSettings.idleLock(settingsPath: text) == .unknown,
              "a non-integer autolock minutes value is unknown")
        check(OnePasswordAppSettings.idleLock(settingsPath: malformed) == .unknown,
              "malformed settings are unknown")
        check(OnePasswordAppSettings.idleLock(
                settingsPath: (dir as NSString).appendingPathComponent("nope.json")) == .unknown,
              "an absent settings file is unknown")
    }

    // The shipping idle reader answers on a Mac with a console session.
    if let idle = SystemIdleTime.seconds() {
        check(idle >= 0, "the system idle time reads as a non-negative interval (\(idle))")
    }
}
