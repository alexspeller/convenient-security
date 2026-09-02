import Foundation
import ConvenientSecurity

public enum OnePasswordConnectionStatus: String, Sendable, Equatable {
    case notStarted
    case cliUnavailable
    case connecting
    case connected
    case disconnected
}

public struct OnePasswordConnectionConfiguration: Sendable, Equatable {
    /// 1Password CLI desktop-app authorization expires after ten minutes of
    /// inactivity. Eight minutes leaves room for scheduling delay and wake-up.
    public var heartbeatInterval: TimeInterval
    public var connectionFreshness: TimeInterval
    public var initialRetryDelay: TimeInterval
    public var maximumRetryDelay: TimeInterval
    public var authenticationTimeout: TimeInterval
    public var resolutionTimeout: TimeInterval

    public init(
        heartbeatInterval: TimeInterval = 8 * 60,
        connectionFreshness: TimeInterval = 10 * 60,
        initialRetryDelay: TimeInterval = 5 * 60,
        maximumRetryDelay: TimeInterval = 30 * 60,
        authenticationTimeout: TimeInterval = 60,
        resolutionTimeout: TimeInterval = OnePasswordCLI.defaultTimeout
    ) {
        self.heartbeatInterval = max(0.001, heartbeatInterval)
        self.connectionFreshness = max(0.001, connectionFreshness)
        self.initialRetryDelay = max(0.001, initialRetryDelay)
        self.maximumRetryDelay = max(self.initialRetryDelay, maximumRetryDelay)
        self.authenticationTimeout = max(0.001, authenticationTimeout)
        self.resolutionTimeout = max(0.001, resolutionTimeout)
    }
}

/// 1Password provider backed by the official `op` CLI. The actor owns the CLI
/// authorization lifecycle as well as resolution: it attempts a metadata-only
/// connection at daemon launch, keeps that connection active, coalesces
/// simultaneous reconnects, and serializes commands so background maintenance
/// can never race a real read into a second authorization prompt.
public actor OnePasswordProvider: SecretProvider {
    public typealias CommandRunner = @Sendable (
        _ path: String,
        _ arguments: [String],
        _ timeout: TimeInterval
    ) async throws -> OnePasswordCLI.Result
    public typealias CLILocator = @Sendable () -> String?
    public typealias DateProvider = @Sendable () -> Date
    public typealias Sleeper = @Sendable (_ seconds: TimeInterval) async throws -> Void
    public typealias StatusObserver = @Sendable (_ status: OnePasswordConnectionStatus) -> Void

    public nonisolated let schemes: Set<String> = ["op"]

    private let configuredCLIPath: String?
    private let cacheMaxAge: TimeInterval
    private let configuration: OnePasswordConnectionConfiguration
    private let locateCLI: CLILocator
    private let runCommand: CommandRunner
    private let currentDate: DateProvider
    private let sleep: Sleeper
    private let statusObserver: StatusObserver

    private var status: OnePasswordConnectionStatus = .notStarted
    private var lastConfirmedAt: Date?
    private var connectionAttempt: (id: UInt64, task: Task<Void, Error>)?
    private var nextConnectionAttemptID: UInt64 = 0
    private var commandRunning = false
    private var commandWaiters: [CheckedContinuation<Void, Never>] = []
    private var maintenanceRunning = false

    /// Which signed-in account owns which vault. Rebuilt by every connection
    /// probe, held in memory only, and never written to disk — see
    /// `OnePasswordAccountIndex`.
    private var accountIndex: OnePasswordAccountIndex?
    /// Item identities per `userID/vaultID`, populated only when a vault name is
    /// ambiguous across accounts and item presence has to break the tie.
    private var itemIdentities: [String: [OnePasswordItemIdentity]] = [:]
    /// The account each reference resolved from, keyed by canonical URI. Once a
    /// review has displayed an account, later resolutions of that reference stay
    /// on it rather than drifting when 1Password's own default moves.
    private var accountSelections: [String: AccountSelection] = [:]
    /// `op`'s own current default account, read only to break a tie.
    private var defaultAccountID: String?

    /// The account a reference resolves from, plus whether that answer required
    /// choosing between accounts.
    private enum AccountSelection: Sendable, Equatable {
        /// Exactly one signed-in account has this vault (and item).
        case unique(OnePasswordAccount)
        /// Several accounts qualified. `chosen` is the stable pick; `others` are
        /// the accounts a review must warn about.
        case ambiguous(chosen: OnePasswordAccount, others: [OnePasswordAccount])
        /// At least one account could not be listed, so the vault's absence is
        /// unproven: fall back to the account-less read, exactly as before this
        /// adapter became account-aware.
        case unindexed
        /// Every account answered and none has this vault.
        case notFound(searched: [OnePasswordAccount])

        /// The account to pass to `--account`, or nil to let `op` choose.
        var account: OnePasswordAccount? {
            switch self {
            case .unique(let account): return account
            case .ambiguous(let chosen, _): return chosen
            case .unindexed, .notFound: return nil
            }
        }

        /// Only a settled choice is worth remembering; the other two are states
        /// of the index, not decisions about the reference.
        var isDecision: Bool {
            switch self {
            case .unique, .ambiguous: return true
            case .unindexed, .notFound: return false
            }
        }
    }

    public init(
        cliPath: String? = nil,
        cacheMaxAge: TimeInterval = 24 * 3600,
        configuration: OnePasswordConnectionConfiguration = .init(),
        locateCLI: @escaping CLILocator = { OnePasswordCLI.locate() },
        runCommand: @escaping CommandRunner = { path, arguments, timeout in
            try await OnePasswordCLI.run(path, arguments, timeout: timeout)
        },
        currentDate: @escaping DateProvider = { Date() },
        sleep: @escaping Sleeper = { seconds in
            let nanoseconds = UInt64(min(seconds * 1_000_000_000, Double(UInt64.max)))
            try await Task.sleep(nanoseconds: nanoseconds)
        },
        statusObserver: @escaping StatusObserver = { _ in }
    ) {
        self.configuredCLIPath = cliPath
        self.cacheMaxAge = cacheMaxAge
        self.configuration = configuration
        self.locateCLI = locateCLI
        self.runCommand = runCommand
        self.currentDate = currentDate
        self.sleep = sleep
        self.statusObserver = statusObserver
    }

    /// Starts one resident maintenance loop. The first authentication attempt is
    /// immediate; subsequent successful probes stay inside 1Password's ten-minute
    /// inactivity window. Failed probes back off, while a real request can still
    /// trigger an immediate coalesced reconnect.
    public func maintainConnection() async {
        guard !maintenanceRunning else { return }
        maintenanceRunning = true
        defer { maintenanceRunning = false }

        var retryDelay = configuration.initialRetryDelay
        while !Task.isCancelled {
            do {
                try await establishConnection(forceProbe: true)
                retryDelay = configuration.initialRetryDelay
                try await sleep(configuration.heartbeatInterval)
            } catch is CancellationError {
                return
            } catch {
                if Task.isCancelled { return }
                do {
                    try await sleep(retryDelay)
                } catch {
                    return
                }
                retryDelay = min(configuration.maximumRetryDelay, retryDelay * 3)
            }
        }
    }

    public func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        try await authenticate()

        let account = try await resolvedAccount(for: ref)
        var arguments = ["read"]
        if let account {
            // `op://` references carry no account, so the account this reference
            // resolves from is decided here and stated on argv. An account id is
            // metadata; values still travel only by stdin/stdout.
            arguments += ["--account", account.userID]
        }
        arguments += ["--no-newline", ref.uri]

        let result: OnePasswordCLI.Result
        do {
            result = try await execute(
                arguments: arguments,
                timeout: configuration.resolutionTimeout
            )
        } catch {
            markConnectionFailure(error)
            throw error
        }

        guard result.status == 0 else {
            let stderr = String(data: result.stderr, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let message = (stderr?.isEmpty == false) ? stderr! : "op exited \(result.status)"
            let error = OnePasswordError.readFailed(
                reference: ref.uri,
                status: result.status,
                message: message
            )
            markConnectionFailure(error)
            throw error
        }
        markConnected()

        // `op read` addresses a single field, which is text; a non-UTF-8 result
        // signals a wrong reference (e.g. a document) rather than a real value.
        // The validated bytes are sealed verbatim — a value is bytes.
        guard String(data: result.stdout, encoding: .utf8) != nil else {
            throw OnePasswordError.notUTF8(ref.uri)
        }
        return ResolvedSecret(value: result.stdout, cacheHint: .cacheable(maxAge: cacheMaxAge))
    }

    /// Establish or refresh the desktop-app authorization. Idempotent and
    /// single-flight: concurrent callers share one metadata-only probe.
    public func authenticate() async throws {
        try await establishConnection(forceProbe: false)
    }

    /// Value-free context for the trusted review window: the account this
    /// reference will resolve from, and a warning when more than one signed-in
    /// account could serve it.
    ///
    /// Answers from the warm index only — the review window is being built, so
    /// this never starts a connection probe. The decision is remembered, so the
    /// account displayed here is the account `resolve` then reads from; the
    /// window cannot name one source and deliver another.
    public func reviewNotes(for ref: SecretRef) async -> [ProviderReviewNote] {
        guard accountIndex?.isUsable == true,
              let path = OnePasswordReferencePath(path: ref.path),
              let selection = try? await selectAccount(for: ref, allowRefresh: false)
        else { return [] }
        if selection.isDecision { accountSelections[ref.uri] = selection }

        let vault = Self.displaySafe(path.vault)
        switch selection {
        case .unique(let account):
            return [ProviderReviewNote(label: "account", detail: Self.displaySafe(account.label))]
        case let .ambiguous(chosen, others):
            let alternatives = others.map { Self.displaySafe($0.label) }
                .joined(separator: ", ")
            return [
                ProviderReviewNote(label: "account", detail: Self.displaySafe(chosen.label)),
                ProviderReviewNote(
                    // The card already says 1Password and names the vault; the
                    // warning only has to say what is unusual about it.
                    label: "",
                    detail: "More than one signed-in account has a vault named “\(vault)”"
                        + " (also \(alternatives)). This value will come from"
                        + " \(Self.displaySafe(chosen.label)). To name one account exactly,"
                        + " use the vault's unique id in the reference.",
                    isWarning: true
                ),
            ]
        case .notFound(let searched):
            let accounts = searched.map { Self.displaySafe($0.label) }.joined(separator: ", ")
            return [
                ProviderReviewNote(
                    label: "",
                    detail: "No signed-in 1Password account has a vault named “\(vault)”"
                        + " (searched \(accounts)), so this request will fail.",
                    isWarning: true
                ),
            ]
        case .unindexed:
            return []
        }
    }

    public func statusSummary() async -> ProviderStatusSummary? {
        let label = "1Password"
        if status == .cliUnavailable {
            return ProviderStatusSummary(
                label: label,
                detail: "CLI not found or not the official signed binary",
                healthy: false
            )
        }
        guard let index = accountIndex, index.isUsable else {
            return ProviderStatusSummary(
                label: label,
                detail: "no authorized account; unlock 1Password and retry",
                healthy: false
            )
        }
        let authorized = index.entries.filter(\.listingSucceeded).count
        var detail = "\(Self.count(authorized, "account")),"
            + " \(Self.count(index.indexedVaultCount, "vault")) indexed"
        let lapsed = index.entries.count - authorized
        if lapsed > 0 {
            detail += "; \(Self.count(lapsed, "account")) not authorized"
        }
        return ProviderStatusSummary(label: label, detail: detail, healthy: index.isComplete)
    }

    // MARK: - Account selection

    /// The account `op read` must be pointed at, or nil to let `op` choose.
    /// A remembered decision wins: once a review has displayed the account for a
    /// reference, that reference stays on it.
    private func resolvedAccount(for ref: SecretRef) async throws -> OnePasswordAccount? {
        if let remembered = accountSelections[ref.uri] {
            return remembered.account
        }
        let vault = OnePasswordReferencePath(path: ref.path)?.vault ?? ref.path
        let selection = try await selectAccount(for: ref, allowRefresh: true)
        switch selection {
        case .unique(let account):
            accountSelections[ref.uri] = selection
            return account
        case let .ambiguous(chosen, others):
            // Nothing displayed this choice to the user, so refuse rather than
            // silently pick one account's copy of the vault over another's.
            throw OnePasswordError.vaultAmbiguous(
                vault: vault,
                accounts: ([chosen] + others).map(\.label)
            )
        case .unindexed:
            return nil
        case .notFound(let searched):
            throw OnePasswordError.vaultNotFoundInAnyAccount(
                vault: vault,
                accounts: searched.map(\.label)
            )
        }
    }

    /// Walk the selection ladder: unique vault id, unique vault name, then the
    /// account whose vault actually holds the item. `allowRefresh` is false on
    /// the consent path, where a cold index must yield no answer instead of a
    /// slow one.
    private func selectAccount(
        for ref: SecretRef,
        allowRefresh: Bool
    ) async throws -> AccountSelection {
        guard let path = OnePasswordReferencePath(path: ref.path) else { return .unindexed }

        var refreshed = false
        if accountIndex == nil {
            guard allowRefresh else { return .unindexed }
            try await establishConnection(forceProbe: true)
            refreshed = true
        }
        guard var index = accountIndex else { return .unindexed }

        var candidates = index.candidates(forVault: path.vault)
        if candidates.isEmpty, allowRefresh, !refreshed {
            // A vault created since the last probe is worth one rebuild before
            // reporting it missing.
            try await establishConnection(forceProbe: true)
            guard let rebuilt = accountIndex else { return .unindexed }
            index = rebuilt
            candidates = index.candidates(forVault: path.vault)
        }

        if candidates.isEmpty {
            return index.isComplete ? .notFound(searched: index.accounts) : .unindexed
        }
        if candidates.count == 1 {
            return .unique(candidates[0].account)
        }

        let narrowed = await narrow(candidates, toItem: path.item)
        if narrowed.count == 1 {
            return .unique(narrowed[0].account)
        }
        let ordered = OnePasswordAccountIndex.stableOrder(
            narrowed,
            vaultQuery: path.vault,
            defaultAccountID: await currentDefaultAccountID()
        )
        return .ambiguous(
            chosen: ordered[0].account,
            others: ordered.dropFirst().map(\.account)
        )
    }

    /// Keep only the candidates whose vault actually contains the item. A
    /// candidate whose item listing fails is kept: an unlistable vault is
    /// unknown, not empty, and dropping it would turn a warning into a wrong
    /// answer.
    private func narrow(
        _ candidates: [OnePasswordVaultCandidate],
        toItem item: String?
    ) async -> [OnePasswordVaultCandidate] {
        guard let item else { return candidates }
        var narrowed: [OnePasswordVaultCandidate] = []
        for candidate in candidates {
            guard let identities = await identities(in: candidate) else {
                narrowed.append(candidate)
                continue
            }
            if identities.contains(where: { $0.matches(item) }) {
                narrowed.append(candidate)
            }
        }
        return narrowed.isEmpty ? candidates : narrowed
    }

    /// Item titles and ids for one vault — never field values. Cached for the
    /// life of the index, and requested only to break a tie between accounts.
    private func identities(
        in candidate: OnePasswordVaultCandidate
    ) async -> [OnePasswordItemIdentity]? {
        let key = "\(candidate.account.userID)/\(candidate.vault.id)"
        if let cached = itemIdentities[key] { return cached }
        guard let result = try? await execute(
            arguments: [
                "item", "list",
                "--account", candidate.account.userID,
                "--vault", candidate.vault.id,
                "--format=json",
            ],
            timeout: configuration.authenticationTimeout
        ), result.status == 0 else { return nil }
        let identities = OnePasswordAccountIndex.decodeItemIdentities(result.stdout)
        itemIdentities[key] = identities
        return identities
    }

    /// The account plain `op` would use. Consulted only to break a tie, so an
    /// unreadable default costs nothing.
    private func currentDefaultAccountID() async -> String? {
        if let defaultAccountID { return defaultAccountID }
        guard let result = try? await execute(
            arguments: ["account", "get", "--format=json"],
            timeout: configuration.authenticationTimeout
        ), result.status == 0 else { return nil }
        defaultAccountID = OnePasswordAccountIndex.decodeDefaultAccountID(result.stdout)
        return defaultAccountID
    }

    /// Vault names and account labels are untrusted metadata that reach a
    /// window and an error string: neutralize terminal/bidi controls and bound
    /// the length before either.
    static func displaySafe(_ text: String, limit: Int = 96) -> String {
        let sanitized = ReviewDisplay.sanitized(text)
        guard sanitized.count > limit else { return sanitized }
        return String(sanitized.prefix(limit)) + "…"
    }

    private static func count(_ value: Int, _ noun: String) -> String {
        "\(value) \(noun)\(value == 1 ? "" : "s")"
    }

    /// True only while a recent authenticated command proves the provider can
    /// serve without beginning another interactive authorization ceremony.
    public func isAvailable() async -> Bool {
        guard connectionIsFresh else {
            if status == .connected { setStatus(.disconnected) }
            return false
        }
        return true
    }

    public func connectionStatus() -> OnePasswordConnectionStatus {
        status
    }

    private var connectionIsFresh: Bool {
        guard status == .connected, let lastConfirmedAt else { return false }
        let age = max(0, currentDate().timeIntervalSince(lastConfirmedAt))
        return age < configuration.connectionFreshness
    }

    private func establishConnection(forceProbe: Bool) async throws {
        if !forceProbe, connectionIsFresh { return }

        if let attempt = connectionAttempt {
            try await attempt.task.value
            return
        }

        nextConnectionAttemptID &+= 1
        let attemptID = nextConnectionAttemptID
        if status != .connected { setStatus(.connecting) }
        let task = Task { try await self.performAuthenticationProbe() }
        connectionAttempt = (attemptID, task)

        do {
            try await task.value
            if connectionAttempt?.id == attemptID {
                connectionAttempt = nil
            }
        } catch {
            if connectionAttempt?.id == attemptID {
                connectionAttempt = nil
            }
            throw error
        }
    }

    /// The probe is the account-index build: `op account list` (local, and true
    /// even while locked) followed by one `op vault list --account …` per
    /// account, which succeeds only for an account whose desktop authorization
    /// is live. `op whoami` cannot serve here — it reports an `op signin`
    /// session and fails with "account is not signed in" under desktop-app
    /// authorization, which is how csec is meant to be used.
    ///
    /// 1Password's ten-minute inactivity window is per account, so listing every
    /// account is also what keeps a second account's authorization alive.
    /// Vault names and ids are metadata; no item, field, or value is read.
    private func performAuthenticationProbe() async throws {
        do {
            let accountsResult = try await execute(
                arguments: ["account", "list", "--format=json"],
                timeout: configuration.authenticationTimeout
            )
            guard accountsResult.status == 0 else {
                throw OnePasswordError.authenticationFailed(status: accountsResult.status)
            }
            let accounts = OnePasswordAccountIndex.decodeAccounts(accountsResult.stdout)
            guard !accounts.isEmpty else {
                throw OnePasswordError.noSignedInAccounts
            }

            var entries: [OnePasswordAccountIndex.Entry] = []
            for account in accounts {
                let vaults = try await listVaults(for: account)
                entries.append(
                    OnePasswordAccountIndex.Entry(
                        account: account,
                        vaults: vaults ?? [],
                        listingSucceeded: vaults != nil
                    )
                )
            }
            let index = OnePasswordAccountIndex(entries: entries, builtAt: currentDate())
            guard index.isUsable else {
                throw OnePasswordError.notAuthorized
            }
            adopt(index)
            markConnected()
        } catch {
            markConnectionFailure(error)
            throw error
        }
    }

    /// Vaults for one account, or nil when that account could not be listed
    /// (locked, expired, or never authorized). A CLI that cannot run at all is
    /// rethrown: that is not a per-account condition.
    private func listVaults(
        for account: OnePasswordAccount
    ) async throws -> [OnePasswordVault]? {
        let result: OnePasswordCLI.Result
        do {
            result = try await execute(
                arguments: ["vault", "list", "--account", account.userID, "--format=json"],
                timeout: configuration.authenticationTimeout
            )
        } catch let error as OnePasswordError {
            if case .cliNotFound = error { throw error }
            return nil
        } catch let error as OnePasswordCLIError {
            if case .untrustedExecutable = error { throw error }
            return nil
        }
        guard result.status == 0 else { return nil }
        return OnePasswordAccountIndex.decodeVaults(result.stdout)
    }

    /// Install a freshly built index and drop everything derived from the old
    /// one. A remembered account survives only while it is still signed in and
    /// still holds the vault it was chosen for; anything else is re-decided (and
    /// so re-displayed) rather than silently reused.
    private func adopt(_ index: OnePasswordAccountIndex) {
        accountIndex = index
        itemIdentities.removeAll()
        defaultAccountID = nil
        accountSelections = accountSelections.filter { uri, selection in
            guard let account = selection.account,
                  let path = referencePath(forURI: uri),
                  let entry = index.entries.first(where: { $0.account == account }),
                  entry.listingSucceeded
            else { return false }
            return index.candidates(forVault: path.vault)
                .contains { $0.account == account }
        }
    }

    private func referencePath(forURI uri: String) -> OnePasswordReferencePath? {
        guard let ref = try? SecretRef(uri) else { return nil }
        return OnePasswordReferencePath(path: ref.path)
    }

    private func execute(
        arguments: [String],
        timeout: TimeInterval
    ) async throws -> OnePasswordCLI.Result {
        await acquireCommandSlot()
        defer { releaseCommandSlot() }
        try Task.checkCancellation()

        guard let cliPath = configuredCLIPath ?? locateCLI() else {
            throw OnePasswordError.cliNotFound
        }
        return try await runCommand(cliPath, arguments, timeout)
    }

    private func acquireCommandSlot() async {
        if !commandRunning {
            commandRunning = true
            return
        }
        await withCheckedContinuation { continuation in
            commandWaiters.append(continuation)
        }
    }

    private func releaseCommandSlot() {
        if commandWaiters.isEmpty {
            commandRunning = false
            return
        }
        commandWaiters.removeFirst().resume()
    }

    private func markConnected() {
        lastConfirmedAt = currentDate()
        setStatus(.connected)
    }

    private func markConnectionFailure(_ error: Error) {
        if let onePasswordError = error as? OnePasswordError,
           case .cliNotFound = onePasswordError {
            setStatus(.cliUnavailable)
        } else {
            setStatus(.disconnected)
        }
    }

    private func setStatus(_ next: OnePasswordConnectionStatus) {
        guard status != next else { return }
        status = next
        statusObserver(next)
    }
}

public enum OnePasswordError: Error, CustomStringConvertible, ProviderDiagnosableError {
    case cliNotFound
    case authenticationFailed(status: Int32)
    case readFailed(reference: String, status: Int32, message: String)
    case notUTF8(String)
    /// `op account list` returned nothing: no account is set up on this device.
    case noSignedInAccounts
    /// Accounts exist, but not one of them could be listed.
    case notAuthorized
    /// Every signed-in account answered, and none has this vault.
    case vaultNotFoundInAnyAccount(vault: String, accounts: [String])
    /// Several accounts hold this vault and item, and no review has displayed
    /// which one would be used.
    case vaultAmbiguous(vault: String, accounts: [String])

    /// Internal detail, `op`'s own stderr included. For csecd's log — never for
    /// a client, which gets `boundedReason`.
    public var description: String {
        switch self {
        case .cliNotFound:
            return "the verified official 1Password CLI (op) was not found"
        case .authenticationFailed(let status):
            return "1Password desktop authorization failed (exit \(status))"
        case let .readFailed(reference, status, message):
            return "op read \(reference) failed (exit \(status)): \(message)"
        case let .notUTF8(reference):
            return "op returned non-UTF-8 data for \(reference)"
        case .noSignedInAccounts:
            return "no 1Password account is signed in on this device"
        case .notAuthorized:
            return "no signed-in 1Password account is currently authorized"
        case let .vaultNotFoundInAnyAccount(vault, accounts):
            return "no signed-in 1Password account has vault \(vault) (searched \(accounts))"
        case let .vaultAmbiguous(vault, accounts):
            return "vault \(vault) exists in more than one 1Password account \(accounts)"
        }
    }

    /// Text csec itself authored, safe to repeat to a client: fixed wording plus
    /// bounded, sanitized metadata. `op`'s stderr is deliberately excluded — it
    /// is unbounded and shaped by whatever the reference names.
    public var boundedReason: String {
        switch self {
        case .cliNotFound:
            return "the official 1Password CLI (op) was not found, or is not the signed binary"
        case .authenticationFailed, .notAuthorized:
            return "the 1Password CLI is not authorized; unlock 1Password and try again"
        case .noSignedInAccounts:
            return "no 1Password account is signed in on this device"
        case .readFailed:
            return "1Password rejected the read; check the vault, item, and field names"
        case .notUTF8:
            return "1Password returned data that is not a single text field"
        case let .vaultNotFoundInAnyAccount(vault, accounts):
            return "no signed-in 1Password account has vault “\(Self.safe(vault))”"
                + " (searched \(Self.safeList(accounts)))"
        case let .vaultAmbiguous(vault, accounts):
            return "vault “\(Self.safe(vault))” exists in more than one signed-in 1Password"
                + " account (\(Self.safeList(accounts))); request it again so the account can"
                + " be shown for approval, or name one account exactly by using the vault's"
                + " unique id in the reference"
        }
    }

    private static func safe(_ text: String) -> String {
        OnePasswordProvider.displaySafe(text)
    }

    private static func safeList(_ values: [String]) -> String {
        values.prefix(8).map { safe($0) }.joined(separator: ", ")
    }
}
