import Foundation
import os
import Security
import ConvenientSecurity
import CSECBuildIdentity

/// What the provider needs from 1Password, independent of how it gets there.
///
/// One conforming instance serves exactly one 1Password account: the desktop
/// integration binds an authorization to an account, and the SDK's library core
/// is a per-process singleton keyed by the first account it sees.
public protocol OnePasswordBackend: AnyObject, Sendable {
    /// Resolve one `op://` reference. The value is returned as bytes and is
    /// never logged, echoed, or placed on a command line.
    func resolve(_ reference: String) async throws -> Data
    /// Resolve one reference only over the process already running: never
    /// start one, which is what authorizes (and may prompt), and never retry
    /// with a fresh one. `bridgeExited` when none is running.
    func resolveOverRunningSession(_ reference: String) async throws -> Data
    /// The account's vaults. Also the keepalive: it is the cheapest call that
    /// provably touches the desktop session, so refreshing the vault list and
    /// refreshing the idle window are the same operation.
    func vaults() async throws -> [OnePasswordVault]
    /// Value-free item identities in one vault, used only to decide which of
    /// two same-named vaults in different accounts holds a reference.
    func items(inVault vaultID: String) async throws -> [OnePasswordItemIdentity]
    /// Release the desktop session and stop the backing process.
    func shutdown() async
}

public enum OnePasswordBridgeError: Error, CustomStringConvertible, Equatable,
    ProviderDiagnosableError
{
    case executableNotFound
    case executableUntrusted(reason: String)
    case launchFailed(String)
    case bridgeExited
    case timedOut
    case malformedResponse
    /// A bounded failure reported by the bridge itself.
    case remote(kind: String, message: String)

    /// The kinds csec's bridge reports (`bridge/protocol.go`). A kind outside
    /// this set is untrusted text and never reaches the log in the clear.
    static let knownRemoteKinds: Set<String> = [
        "not_found", "session_expired", "client_invalidated", "unauthorized",
        "unavailable", "invalid_request", "internal", "otp_seed",
    ]

    public var description: String {
        switch self {
        case .executableNotFound:
            return "the csec 1Password bridge is missing from this installation"
        case let .executableUntrusted(reason):
            return "the csec 1Password bridge failed its code-identity check: \(reason)"
        case let .launchFailed(message):
            return "the csec 1Password bridge could not start: \(message)"
        case .bridgeExited:
            return "the csec 1Password bridge stopped unexpectedly"
        case .timedOut:
            return "1Password did not answer in time"
        case .malformedResponse:
            return "the csec 1Password bridge sent an unreadable response"
        case let .remote(kind, message):
            return "1Password reported \(kind): \(message)"
        }
    }

    /// What a client is allowed to be told. `description` keeps the bridge's own
    /// text for the daemon log; this is csec's words only, so a provider failure
    /// can never carry unbounded upstream output to a user-facing surface.
    public var boundedReason: String {
        switch self {
        case .executableNotFound:
            return "the csec 1Password bridge is missing from this installation; reinstall csec"
        case .executableUntrusted:
            return "the csec 1Password bridge failed its code-identity check; reinstall csec"
        case .launchFailed:
            return "the csec 1Password bridge could not start"
        case .bridgeExited:
            return "the 1Password connection stopped before answering"
        case .timedOut:
            return "1Password did not answer in time"
        case .malformedResponse:
            return "the csec 1Password bridge sent an unreadable response"
        case let .remote(kind, _):
            switch kind {
            case "not_found":
                return "1Password has no such vault, item, or field in this account"
            case "session_expired":
                return "the 1Password session expired; unlock 1Password and try again"
            case "client_invalidated":
                return "the 1Password client session is no longer valid; try again to reconnect"
            case "unauthorized":
                return "1Password did not authorize this request"
            case "unavailable":
                return "the 1Password app is not running, or its app integration is turned off"
            case "invalid_request":
                return "csec sent 1Password a request it could not read"
            case "otp_seed":
                return OneTimeCodeError.seedRefused.boundedReason
            default:
                return "1Password could not serve this reference"
            }
        }
    }

    /// The bridge would not send the value because its field holds a 2FA
    /// seed (a TOTP-type field read without `?attribute=otp`).
    public var refusedSeed: Bool {
        guard case let .remote(kind, _) = self else { return false }
        return kind == "otp_seed"
    }

    fileprivate var invalidatesClient: Bool {
        guard case let .remote(kind, _) = self else { return false }
        return kind == "client_invalidated"
    }
}

// MARK: - Locating and trusting the bridge executable

public enum OnePasswordBridgeExecutable {
    public static let identifier = CSECBuildIdentity.named("opbridge")

    /// The bridge ships beside the executable that launches it, inside the
    /// signed bundle. It is deliberately not searched for on `PATH`: a
    /// provider-critical binary must not be selectable by the environment.
    public static func locate() -> String? {
        #if DEBUG
        if let override = ProcessInfo.processInfo.environment["CSEC_OP_BRIDGE_PATH"],
           !override.isEmpty,
           FileManager.default.isExecutableFile(atPath: override) {
            return override
        }
        #endif
        guard let executable = Bundle.main.executableURL?.resolvingSymlinksInPath() else {
            return nil
        }
        let sibling = executable
            .deletingLastPathComponent()
            .appendingPathComponent("csec-op-bridge")
            .path
        return FileManager.default.isExecutableFile(atPath: sibling) ? sibling : nil
    }

    /// The bridge is the one csec binary permitted to disable library
    /// validation, because the 1Password SDK reaches the desktop app by
    /// dlopening a library signed by AgileBits rather than by us. Every other
    /// forbidden entitlement still disqualifies it, and the exemption is
    /// checked against this exact signing identifier so it cannot be inherited
    /// by any other component.
    public static let permittedEntitlement = "com.apple.security.cs.disable-library-validation"

    public static func verifyTrusted(_ path: String) throws {
        let canonicalPath = URL(fileURLWithPath: path)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path

        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            URL(fileURLWithPath: canonicalPath) as CFURL,
            SecCSFlags(rawValue: 0),
            &code
        ) == errSecSuccess, let code else {
            throw OnePasswordBridgeError.executableUntrusted(reason: "unreadable signature")
        }

        #if DEBUG
        // A development build is ad-hoc signed by the Swift toolchain, so the
        // product requirement cannot hold. Release builds have no such path.
        if ProcessInfo.processInfo.environment["CSEC_OP_BRIDGE_PATH"] == canonicalPath {
            return
        }
        #endif

        guard SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)),
            nil
        ) == errSecSuccess else {
            throw OnePasswordBridgeError.executableUntrusted(reason: "invalid signature")
        }

        var information: CFDictionary?
        _ = SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)),
            &information
        )
        let dictionary = information as? [String: Any]
        let flags = (dictionary?[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        guard flags & 0x0001_0000 != 0 else { // CS_RUNTIME
            throw OnePasswordBridgeError.executableUntrusted(reason: "hardened runtime is off")
        }

        let entitlements = dictionary?[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        let disallowed = ProductCodeIdentity.forbiddenEntitlements
            .filter { $0 != permittedEntitlement }
            .filter { (entitlements[$0] as? Bool) == true }
        guard disallowed.isEmpty else {
            throw OnePasswordBridgeError.executableUntrusted(
                reason: "carries \(disallowed.joined(separator: ", "))"
            )
        }

        let requirementText = "identifier \"\(identifier)\" and anchor apple generic"
            + " and certificate leaf[subject.OU] = \"\(ProductCodeIdentity.teamIdentifier)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            requirementText as CFString,
            SecCSFlags(rawValue: 0),
            &requirement
        ) == errSecSuccess, let requirement,
            SecStaticCodeCheckValidity(
                code,
                SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)),
                requirement
            ) == errSecSuccess
        else {
            throw OnePasswordBridgeError.executableUntrusted(reason: "not the csec bridge")
        }
    }

    /// The 1Password library the bridge will load, checked here as well as
    /// inside the bridge: csecd refuses to start a bridge that would have
    /// nothing trustworthy to talk to.
    public static let onePasswordLibraryPath =
        "/Applications/1Password.app/Contents/Frameworks/libop_sdk_ipc_client.dylib"

    public static func onePasswordLibraryIsTrusted(
        at path: String = onePasswordLibraryPath
    ) -> Bool {
        guard let attributes = try? FileManager.default
            .attributesOfItem(atPath: path),
            (attributes[.type] as? FileAttributeType) == .typeRegular
        else { return false }

        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            URL(fileURLWithPath: path) as CFURL,
            SecCSFlags(rawValue: 0),
            &code
        ) == errSecSuccess, let code else { return false }

        var requirement: SecRequirement?
        let requirementText = "anchor apple generic and certificate leaf[subject.OU] = \"2BUA8C4S2C\""
        guard SecRequirementCreateWithString(
            requirementText as CFString,
            SecCSFlags(rawValue: 0),
            &requirement
        ) == errSecSuccess, let requirement else { return false }

        return SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)),
            requirement
        ) == errSecSuccess
    }
}

// MARK: - Wire types

struct OnePasswordBridgeRequest: Encodable {
    let id: UInt64
    let op: String
    var reference: String?
    var vaultID: String?

    enum CodingKeys: String, CodingKey {
        case id, op, reference
        case vaultID = "vault_id"
    }
}

struct OnePasswordBridgeResponse: Decodable {
    let id: UInt64
    let ok: Bool
    let value: String?
    let vaults: [Vault]?
    let items: [Item]?
    let kind: String?
    let message: String?

    struct Vault: Decodable {
        let id: String
        let title: String
        /// The SDK's vault type; "personal" marks the account's own vault.
        let type: String?
    }

    struct Item: Decodable {
        let id: String
        let title: String
    }
}

// MARK: - The session

/// One bridge event for csecd's log. `event` is csec's own fixed words and
/// numbers, logged in the clear; `detail` is whatever the event concerns that
/// could name something in the user's 1Password or on this Mac (a line of the
/// bridge's stderr, an error's text, a path), logged private.
public struct OnePasswordBridgeDiagnostic: Sendable, Equatable {
    /// The event of a line the bridge wrote to its own stderr.
    public static let stderr = "stderr"

    public let event: String
    public let detail: String?

    public init(event: String, detail: String? = nil) {
        self.event = event
        self.detail = detail
    }

    /// One line of the bridge's stderr. The bridge's own lines (`diagf` in
    /// `bridge/main.go`) have a few fixed shapes, and a request's outcome and
    /// duration are how a silent re-authorization shows (a slow request), so
    /// a line in one of those shapes is an event in the clear, without the
    /// account UUID or the SDK's error text, which become its detail. Every
    /// other line is untrusted and wholly private. Each pattern admits only
    /// the bridge's fixed words, numbers, its op and error-kind vocabularies
    /// and Go durations; a line the bridge changes falls back to private.
    public static func fromStderr(_ line: String) -> OnePasswordBridgeDiagnostic {
        if let match = line.wholeMatch(of: requestLine) {
            return OnePasswordBridgeDiagnostic(
                event: String(match.output.event), detail: match.output.detail.map(String.init)
            )
        }
        if let match = line.wholeMatch(of: lifecycleLine) {
            return OnePasswordBridgeDiagnostic(
                event: String(match.output.event), detail: match.output.detail.map(String.init)
            )
        }
        if let match = line.wholeMatch(of: startedLine) {
            return OnePasswordBridgeDiagnostic(event: "\(match.output.time) started pid=\(match.output.pid)")
        }
        if let match = line.wholeMatch(of: authorizingLine) {
            return OnePasswordBridgeDiagnostic(
                event: "\(match.output.time) authorizing: creating the SDK client"
                    + " (1Password will prompt if this account is not already authorized)"
            )
        }
        if let match = line.wholeMatch(of: authorizedLine) {
            return OnePasswordBridgeDiagnostic(event: "\(match.output.time) authorized after \(match.output.took)")
        }
        return OnePasswordBridgeDiagnostic(event: stderr, detail: line)
    }

    // The bridge's timestamp, then a Go duration (`12ms`, `1.5s`, `2m3s`).
    // Multi-line regex literals ignore whitespace, so `\ ` is a space.

    /// `request id=… op=… ok|failed kind=… took=…`, and the shutdown request;
    /// a failure's message is private.
    private static let requestLine = #/
        (?<event>
          \d{2}:\d{2}:\d{2}\.\d{3}
          \ request\ id=\d+\ op=(?:resolve|vaults|items|shutdown)
          (?:
            \ (?:ok|failed\ kind=(?:not_found|session_expired|client_invalidated|unauthorized|unavailable|invalid_request|internal|otp_seed))
            \ took=[0-9][0-9.hmnsuµ]*
            (?:\ \(slower\ than\ a\ warm\ session;\ 1Password\ re-authorized\ or\ prompted\))?
          )?
        )
        (?::\ (?<detail>.*))?
    /#

    /// The bridge's lifecycle lines; an error after the colon is private.
    private static let lifecycleLine = #/
        (?<event>
          \d{2}:\d{2}:\d{2}\.\d{3}
          \ (?:
            authorization\ failed\ after\ [0-9][0-9.hmnsuµ]*
            | exiting
            | refusing\ to\ start
            | resolve:\ the\ batched\ answer\ lacked\ the\ reference;\ reading\ it\ alone
          )
        )
        (?::\ (?<detail>.*))?
    /#

    // The lines that name the account's UUID, which the line's account tag
    // already stands for: the UUID is dropped.
    private static let startedLine = #/
        (?<time>\d{2}:\d{2}:\d{2}\.\d{3})
        \ started\ pid=(?<pid>\d+)\ account=\S+
    /#
    private static let authorizingLine = #/
        (?<time>\d{2}:\d{2}:\d{2}\.\d{3})
        \ authorizing:\ creating\ the\ SDK\ client\ for\ account=\S+
        \ \(1Password\ will\ prompt\ if\ this\ account\ is\ not\ already\ authorized\)
    /#
    private static let authorizedLine = #/
        (?<time>\d{2}:\d{2}:\d{2}\.\d{3})
        \ authorized\ account=\S+\ after\ (?<took>[0-9][0-9.hmnsuµ]*)
    /#
}

/// One long-lived bridge process holding one 1Password desktop session.
///
/// The point of holding it is that the `op` CLI cannot: every CLI invocation
/// re-authorizes, and an authorization attempted while the 1Password app is
/// locked unlocks the app — a Touch ID prompt. Here a single authorization is
/// established on the first request and then kept inside 1Password's ten-minute
/// idle window by the provider's keepalive, so later reads cost no prompt at
/// all.
///
/// The process is started lazily. Starting it is not what authorizes; the first
/// request that needs the SDK client is. Either way nothing happens here except
/// in response to a call the provider chose to make.
public actor OnePasswordBridgeSession: OnePasswordBackend {
    private let account: OnePasswordAccount
    private let executablePath: String
    private let requestTimeout: TimeInterval
    /// How long an exited bridge's pipes may stay open before its exit is
    /// handled anyway. The Go bridge starts no children, so its pipes close
    /// when it exits; this bounds the wait only for something else holding
    /// them, which would otherwise strand the pending requests.
    private let outputDrainTimeout: TimeInterval
    /// How long csecd waits for an idle bridge to answer its goodbye. A warm
    /// bridge answers at once; this bounds only one that has stopped reading.
    private let shutdownTimeout: TimeInterval

    private let diagnostics: DiagnosticSink

    private var process: Process?
    private var input: FileHandle?
    private var waiters: [UInt64: CheckedContinuation<OnePasswordBridgeResponse, Error>] = [:]
    private var nextRequestID: UInt64 = 0
    /// Whether the running process let a request time out. It reads requests
    /// one at a time, so it is still busy with that one, most likely held in
    /// a 1Password prompt, and would not read a goodbye before it ends.
    private var leftRequestUnanswered = false
    /// Counts up across restarts so the log can tell one bridge process from
    /// its successor.
    private var generation = 0

    /// Receives one value-free entry per bridge event: process start and
    /// exit, and every line the bridge writes to its own stderr. The default
    /// sink is the unified log; tests substitute a recorder.
    public typealias DiagnosticSink = @Sendable (_ entry: OnePasswordBridgeDiagnostic) -> Void

    public init(
        account: OnePasswordAccount,
        executablePath: String,
        requestTimeout: TimeInterval = 60,
        outputDrainTimeout: TimeInterval = 5,
        shutdownTimeout: TimeInterval = 2,
        diagnostics: DiagnosticSink? = nil
    ) {
        self.account = account
        self.executablePath = executablePath
        self.requestTimeout = requestTimeout
        self.outputDrainTimeout = outputDrainTimeout
        self.shutdownTimeout = shutdownTimeout
        let tag = OnePasswordDiagnostics.account(account)
        self.diagnostics = diagnostics ?? { entry in
            if let detail = entry.detail {
                OnePasswordDiagnostics.log.notice(
                    "bridge[\(tag, privacy: .public)]: \(entry.event, privacy: .public): \(detail, privacy: .private)"
                )
            } else {
                OnePasswordDiagnostics.log.notice(
                    "bridge[\(tag, privacy: .public)]: \(entry.event, privacy: .public)"
                )
            }
        }
    }

    /// `event` is csec's own words. `detail` is untrusted metadata (the SDK's
    /// error text is shaped by whatever 1Password answered, a path names the
    /// user): neutralize control characters and bound the length before it
    /// reaches a log line, where it is private.
    private nonisolated func report(_ event: String, detail: String? = nil) {
        diagnostics(OnePasswordBridgeDiagnostic(
            event: event,
            detail: detail.map { OnePasswordProvider.displaySafe($0, limit: 400) }
        ))
    }

    public func resolve(_ reference: String) async throws -> Data {
        let response: OnePasswordBridgeResponse
        do {
            response = try await send(op: "resolve", reference: reference)
        } catch let error as OnePasswordBridgeError where error.invalidatesClient {
            // send discarded the poisoned process. Only an authorized read
            // retries: vaults() also serves background keepalive and must not
            // reconnect there. A fresh process resets the SDK's shared core,
            // retaining exactly the same account and reference. Retry once.
            try Task.checkCancellation()
            report("1Password invalidated its client; retrying the requested read once with a fresh bridge")
            response = try await send(op: "resolve", reference: reference)
        }
        guard let value = response.value, let data = value.data(using: .utf8) else {
            throw OnePasswordBridgeError.malformedResponse
        }
        return data
    }

    public func resolveOverRunningSession(_ reference: String) async throws -> Data {
        let response = try await send(op: "resolve", reference: reference, startingIfNeeded: false)
        guard let value = response.value, let data = value.data(using: .utf8) else {
            throw OnePasswordBridgeError.malformedResponse
        }
        return data
    }

    public func vaults() async throws -> [OnePasswordVault] {
        let response = try await send(op: "vaults")
        guard let vaults = response.vaults else {
            throw OnePasswordBridgeError.malformedResponse
        }
        return vaults.map {
            OnePasswordVault(id: $0.id, name: $0.title, isPersonal: $0.type == "personal")
        }
    }

    public func items(inVault vaultID: String) async throws -> [OnePasswordItemIdentity] {
        let response = try await send(op: "items", vaultID: vaultID)
        guard let items = response.items else {
            throw OnePasswordBridgeError.malformedResponse
        }
        return items.map { OnePasswordItemIdentity(id: $0.id, title: $0.title) }
    }

    public func shutdown() async {
        guard process != nil else { return }
        report("shutdown requested by csecd; releasing the desktop session")
        // The goodbye only lets the bridge exit on its own; SIGTERM releases
        // the desktop session just the same. A bridge still busy with a
        // request cannot read it until that request ends, so it gets none.
        guard !leftRequestUnanswered, waiters.isEmpty else {
            report("bridge process #\(generation) is still busy with a request; stopping it without a goodbye")
            teardown(resumeWaitersWith: OnePasswordBridgeError.bridgeExited)
            return
        }
        // Best effort: a bridge that has already died needs no goodbye, and
        // must not be started again to receive one.
        _ = try? await send(op: "shutdown", startingIfNeeded: false, timeout: shutdownTimeout)
        teardown(resumeWaitersWith: OnePasswordBridgeError.bridgeExited)
    }

    /// Whether a process is currently running. The provider uses this to tell
    /// "never connected" from "connected and warm".
    public func isRunning() -> Bool {
        process?.isRunning == true
    }

    // MARK: Request/response

    private func send(
        op: String,
        reference: String? = nil,
        vaultID: String? = nil,
        startingIfNeeded: Bool = true,
        timeout: TimeInterval? = nil
    ) async throws -> OnePasswordBridgeResponse {
        if startingIfNeeded {
            try start()
        } else if process?.isRunning != true {
            throw OnePasswordBridgeError.bridgeExited
        }
        let requestGeneration = generation
        nextRequestID &+= 1
        let id = nextRequestID
        let request = OnePasswordBridgeRequest(
            id: id, op: op, reference: reference, vaultID: vaultID
        )
        var line = try JSONEncoder().encode(request)
        line.append(0x0A)

        let bound = timeout ?? requestTimeout
        let timer = Task {
            try? await Task.sleep(nanoseconds: UInt64(bound * 1_000_000_000))
            guard !Task.isCancelled else { return }
            self.report(
                "request id=\(id) op=\(op) did not answer within \(Int(bound))s; failing it"
            )
            self.timedOut(id: id, generation: requestGeneration)
        }
        defer { timer.cancel() }

        let response: OnePasswordBridgeResponse = try await withCheckedThrowingContinuation { continuation in
            waiters[id] = continuation
            guard let input else {
                waiters.removeValue(forKey: id)
                continuation.resume(throwing: OnePasswordBridgeError.bridgeExited)
                return
            }
            do {
                try input.write(contentsOf: line)
            } catch {
                waiters.removeValue(forKey: id)
                continuation.resume(throwing: OnePasswordBridgeError.bridgeExited)
            }
        }

        guard response.ok else {
            let error = OnePasswordBridgeError.remote(
                kind: response.kind ?? "internal",
                message: response.message ?? ""
            )
            if error.invalidatesClient && generation == requestGeneration {
                report("1Password client is invalid; discarding bridge process #\(requestGeneration)")
                teardown(resumeWaitersWith: error)
            }
            throw error
        }
        return response
    }

    private func timedOut(id: UInt64, generation: Int) {
        guard let waiter = waiters.removeValue(forKey: id) else { return }
        if self.generation == generation { leftRequestUnanswered = true }
        waiter.resume(throwing: OnePasswordBridgeError.timedOut)
    }

    // MARK: Process lifecycle

    private func start() throws {
        if let process, process.isRunning { return }
        if process != nil {
            // A dead process leaves stale handles behind; clear them before
            // respawn. The exit itself was reported when it happened.
            report("previous bridge process is gone; starting a new one (a new process means a new authorization)")
            teardown(resumeWaitersWith: OnePasswordBridgeError.bridgeExited)
        }

        guard FileManager.default.isExecutableFile(atPath: executablePath) else {
            report("bridge executable missing", detail: executablePath)
            throw OnePasswordBridgeError.executableNotFound
        }
        do {
            try OnePasswordBridgeExecutable.verifyTrusted(executablePath)
        } catch {
            report("bridge executable rejected", detail: String(describing: error))
            throw error
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        // Desktop SDK integration accepts account_uuid, whereas the CLI's
        // --account selector uses user_uuid. Both are value-free identifiers.
        process.arguments = [account.accountID]
        process.environment = OnePasswordCLI.sanitizedEnvironment()

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        // The bridge's diagnostics are value-free by contract (see bridge/main.go)
        // and are the only record of what the SDK did: csecd's own stderr is
        // discarded by launchd, so they are forwarded to the unified log.
        process.standardError = stderrPipe

        generation += 1
        let generation = generation

        // Both pipes and the exit yield into one stream, each in the order it
        // happened, and one task consumes the stream, so no chunk overtakes
        // another from its pipe. The exit handler is attached before launch
        // so that even an immediate exit is seen.
        let (events, sink) = AsyncStream.makeStream(of: BridgeProcessEvent.self)
        process.terminationHandler = { process in
            sink.yield(.exited(
                status: process.terminationStatus,
                bySignal: process.terminationReason == .uncaughtSignal
            ))
        }

        do {
            try process.run()
        } catch {
            process.terminationHandler = nil
            sink.finish()
            report("bridge process #\(generation) failed to launch", detail: String(describing: error))
            throw OnePasswordBridgeError.launchFailed(String(describing: error))
        }
        report("bridge process #\(generation) started pid=\(process.processIdentifier)")
        Self.readToEOF(stdoutPipe.fileHandleForReading, into: sink, diagnostics: false)
        Self.readToEOF(stderrPipe.fileHandleForReading, into: sink, diagnostics: true)

        self.process = process
        self.input = stdinPipe.fileHandleForWriting
        // A write to a bridge that has exited must fail with EPIPE, not raise
        // SIGPIPE in csecd.
        _ = fcntl(stdinPipe.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)

        // The consumer keeps the session alive until this process's stream
        // ends, so its exit is still handled and its last words still logged.
        let drainTimeout = outputDrainTimeout
        Task.detached {
            await self.consume(events, sink: sink, generation: generation, drainTimeout: drainTimeout)
        }
    }

    /// Reads one of a bridge's pipes to EOF on a thread of its own, yielding
    /// each chunk and then an empty chunk at EOF.
    ///
    /// A blocking read(2) returns whatever the pipe holds. A FileHandle
    /// readability handler instead waits on a GCD read source, and in
    /// cs-selftest's full run a bridge's stderr source was seen never to fire,
    /// for its data or its EOF, while the line sat in the pipe (csec-93dr).
    /// The thread lives as long as the pipe is open, which for a bridge is as
    /// long as the bridge runs, and owns the handle until then.
    private static func readToEOF(
        _ handle: FileHandle,
        into sink: AsyncStream<BridgeProcessEvent>.Continuation,
        diagnostics: Bool
    ) {
        let thread = Thread {
            let descriptor = handle.fileDescriptor
            var buffer = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let count = buffer.withUnsafeMutableBytes {
                    Darwin.read(descriptor, $0.baseAddress, $0.count)
                }
                if count > 0 {
                    let chunk = Data(buffer[0..<count])
                    sink.yield(diagnostics ? .diagnostics(chunk) : .output(chunk))
                } else if count < 0, errno == EINTR {
                    continue
                } else {
                    // EOF, or an error that ends the pipe just the same.
                    break
                }
            }
            sink.yield(diagnostics ? .diagnostics(Data()) : .output(Data()))
            withExtendedLifetime(handle) {}
        }
        thread.name = diagnostics ? "csec-op-bridge stderr" : "csec-op-bridge stdout"
        thread.start()
    }

    /// Everything one bridge process reports, start to EOF.
    ///
    /// The exit is handled only once both pipes reach EOF, because the exit
    /// can be observed before the output the process wrote ahead of it has
    /// been read: handling it first would discard an answer still in stdout
    /// and the stderr lines that say why the bridge stopped. Stderr is
    /// forwarded to its EOF even after the session has moved on from this
    /// process, since what a discarded bridge says last is still a diagnostic.
    private nonisolated func consume(
        _ events: AsyncStream<BridgeProcessEvent>,
        sink: AsyncStream<BridgeProcessEvent>.Continuation,
        generation: Int,
        drainTimeout: TimeInterval
    ) async {
        var output = LineBuffer()
        var diagnostics = LineBuffer()
        var outputClosed = false
        var diagnosticsClosed = false
        var exit: (status: Int32, bySignal: Bool)?
        var exitHandled = false
        for await event in events {
            var drainExpired = false
            switch event {
            case let .output(chunk):
                if chunk.isEmpty {
                    outputClosed = true
                } else {
                    for line in output.append(chunk) {
                        await deliver(line, generation: generation)
                    }
                }
            case let .diagnostics(chunk):
                if chunk.isEmpty {
                    diagnosticsClosed = true
                    if let tail = diagnostics.remainder() { forward(tail) }
                } else {
                    for line in diagnostics.append(chunk) { forward(line) }
                }
            case let .exited(status, bySignal):
                exit = (status, bySignal)
                if !(outputClosed && diagnosticsClosed) {
                    Task {
                        try? await Task.sleep(nanoseconds: UInt64(drainTimeout * 1_000_000_000))
                        sink.yield(.drainExpired)
                    }
                }
            case .drainExpired:
                drainExpired = true
            }
            if let exit, !exitHandled, drainExpired || (outputClosed && diagnosticsClosed) {
                exitHandled = true
                await handleTermination(generation: generation, status: exit.status, bySignal: exit.bySignal)
            }
            if exitHandled && outputClosed && diagnosticsClosed { sink.finish() }
        }
    }

    private nonisolated func forward(_ line: Data) {
        guard !line.isEmpty, let text = String(data: line, encoding: .utf8) else { return }
        diagnostics(OnePasswordBridgeDiagnostic.fromStderr(
            OnePasswordProvider.displaySafe(text, limit: 400)
        ))
    }

    /// Complete the waiter one stdout line answers. A line from a process
    /// already discarded answers nothing: its waiters were failed then.
    private func deliver(_ line: Data, generation: Int) {
        guard self.generation == generation, process != nil, !line.isEmpty else { return }
        guard let response = try? JSONDecoder().decode(OnePasswordBridgeResponse.self, from: line) else {
            // An unreadable line cannot be correlated to a request, so it
            // cannot fail one; the request's own timeout still applies.
            return
        }
        // Any answer, even one to a request already failed, means the bridge
        // is reading requests again.
        leftRequestUnanswered = false
        waiters.removeValue(forKey: response.id)?.resume(returning: response)
    }

    private func handleTermination(generation: Int, status: Int32, bySignal: Bool) {
        // Only the current process's exit tears the session down. A process
        // csecd discarded, or one already replaced, has nothing left to do.
        guard self.generation == generation, process != nil else { return }
        let how = bySignal ? "killed by signal \(status)" : "exit status \(status)"
        let pending = waiters.count
        report(
            "bridge process #\(generation) exited (\(how)) with \(pending) request(s) pending; its desktop session is gone"
        )
        teardown(resumeWaitersWith: OnePasswordBridgeError.bridgeExited)
    }

    /// Fails the waiters and stops the process. Its pipes are still read to
    /// EOF: the process's own stream ends there, and nothing it reports after
    /// this point touches the session (see `consume`).
    private func teardown(resumeWaitersWith error: Error) {
        if let process, process.isRunning { process.terminate() }
        try? input?.close()
        process = nil
        input = nil
        leftRequestUnanswered = false
        let pending = waiters
        waiters = [:]
        for (_, continuation) in pending {
            continuation.resume(throwing: error)
        }
    }
}

/// What one bridge process reports, each pipe in the order it was read.
private enum BridgeProcessEvent: Sendable {
    /// A stdout chunk; empty at EOF.
    case output(Data)
    /// A stderr chunk; empty at EOF.
    case diagnostics(Data)
    case exited(status: Int32, bySignal: Bool)
    /// The exit's drain grace ran out with a pipe still open.
    case drainExpired
}

/// Splits a pipe's chunks into newline-terminated lines.
private struct LineBuffer {
    private var pending = Data()

    mutating func append(_ chunk: Data) -> [Data] {
        pending.append(chunk)
        var lines: [Data] = []
        while let newline = pending.firstIndex(of: 0x0A) {
            lines.append(Data(pending[pending.startIndex..<newline]))
            pending = Data(pending[pending.index(after: newline)...])
        }
        return lines
    }

    /// An unterminated last line, at EOF.
    mutating func remainder() -> Data? {
        defer { pending = Data() }
        return pending.isEmpty ? nil : pending
    }
}
