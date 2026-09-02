import Foundation

/// One signed-in 1Password identity, as reported by `op account list`.
///
/// `userID` (`user_uuid`) is the selector passed to `--account`: it stays unique
/// even when one organization account is signed in under two different users,
/// which `account_uuid` does not.
public struct OnePasswordAccount: Sendable, Equatable, Hashable, Codable {
    public let userID: String
    public let accountID: String
    public let url: String
    public let email: String

    public init(userID: String, accountID: String, url: String, email: String) {
        self.userID = userID
        self.accountID = accountID
        self.url = url
        self.email = email
    }

    /// Value-free label for prompts, warnings, and status rows. The sign-in URL
    /// identifies the account without printing the user's address.
    public var label: String { url.isEmpty ? accountID : url }

    private enum CodingKeys: String, CodingKey {
        case userID = "user_uuid"
        case accountID = "account_uuid"
        case url
        case email
    }
}

public struct OnePasswordVault: Sendable, Equatable, Hashable, Codable {
    public let id: String
    public let name: String

    public init(id: String, name: String) {
        self.id = id
        self.name = name
    }
}

/// A vault in a specific account: the unit `--account` selection resolves to.
public struct OnePasswordVaultCandidate: Sendable, Equatable, Hashable {
    public let account: OnePasswordAccount
    public let vault: OnePasswordVault

    public init(account: OnePasswordAccount, vault: OnePasswordVault) {
        self.account = account
        self.vault = vault
    }
}

/// Which account owns the vault named by an `op://` reference.
///
/// Built from `op account list` plus one `op vault list --account <user_uuid>`
/// per account. The vault listing doubles as the authorization probe: it exits
/// non-zero for an account whose desktop authorization has lapsed, which is
/// recorded per entry so an incomplete index never produces a definitive
/// "no account has this vault" answer.
///
/// This index is derived state, held in memory by the provider actor and thrown
/// away when csecd exits. It is deliberately never written to disk: a
/// same-uid-writable vault-to-account map would let ordinary malware redirect a
/// reference at an attacker-controlled account and substitute the value.
public struct OnePasswordAccountIndex: Sendable, Equatable {
    public struct Entry: Sendable, Equatable {
        public let account: OnePasswordAccount
        public let vaults: [OnePasswordVault]
        /// False when `op vault list` failed for this account (locked, expired,
        /// or never authorized). Its vaults are unknown, not absent.
        public let listingSucceeded: Bool

        public init(
            account: OnePasswordAccount,
            vaults: [OnePasswordVault],
            listingSucceeded: Bool
        ) {
            self.account = account
            self.vaults = vaults
            self.listingSucceeded = listingSucceeded
        }
    }

    public let entries: [Entry]
    public let builtAt: Date

    public init(entries: [Entry], builtAt: Date) {
        self.entries = entries
        self.builtAt = builtAt
    }

    public var accounts: [OnePasswordAccount] { entries.map(\.account) }

    /// True when every signed-in account answered its vault listing. Only then
    /// can "no account has this vault" be reported as fact rather than guessed.
    public var isComplete: Bool {
        !entries.isEmpty && entries.allSatisfy(\.listingSucceeded)
    }

    /// True when at least one account is authorized, i.e. the provider can serve.
    public var isUsable: Bool { entries.contains(where: \.listingSucceeded) }

    public var indexedVaultCount: Int {
        entries.reduce(0) { $0 + $1.vaults.count }
    }

    /// Every account whose vaults contain `vault`, matched exactly as `op` does:
    /// an exact vault id, or an exact name compared case-insensitively (`op`
    /// accepts `employee` for `Employee` but rejects the prefix `Emplo`).
    ///
    /// An id match wins outright — vault ids are globally unique, so a name that
    /// happens to equal another vault's id cannot widen the result.
    public func candidates(forVault vault: String) -> [OnePasswordVaultCandidate] {
        let byID = matches(forVault: vault) { $0.id == vault }
        if !byID.isEmpty { return byID }
        return matches(forVault: vault) {
            $0.name.compare(vault, options: [.caseInsensitive]) == .orderedSame
        }
    }

    private func matches(
        forVault vault: String,
        _ isMatch: (OnePasswordVault) -> Bool
    ) -> [OnePasswordVaultCandidate] {
        entries.flatMap { entry in
            entry.vaults.filter(isMatch).map {
                OnePasswordVaultCandidate(account: entry.account, vault: $0)
            }
        }
    }

    /// Deterministic order for candidates that survive every narrowing step, so
    /// the account named in the approval dialog is stable across daemon
    /// restarts: an exactly-cased vault name first, then `op`'s own current
    /// default account (matching what plain `op read` would have done), then the
    /// lowest user id. `defaultAccountID` is an `account_uuid` as reported by
    /// `op account get`.
    public static func stableOrder(
        _ candidates: [OnePasswordVaultCandidate],
        vaultQuery: String,
        defaultAccountID: String?
    ) -> [OnePasswordVaultCandidate] {
        candidates.sorted { lhs, rhs in
            let lhsExact = lhs.vault.name == vaultQuery
            let rhsExact = rhs.vault.name == vaultQuery
            if lhsExact != rhsExact { return lhsExact }
            if let defaultAccountID {
                let lhsDefault = lhs.account.accountID == defaultAccountID
                let rhsDefault = rhs.account.accountID == defaultAccountID
                if lhsDefault != rhsDefault { return lhsDefault }
            }
            if lhs.account.userID != rhs.account.userID {
                return lhs.account.userID < rhs.account.userID
            }
            return lhs.vault.id < rhs.vault.id
        }
    }

    // MARK: - CLI output decoding

    /// `op account list --format=json`. Entries missing the fields this adapter
    /// needs are dropped rather than failing the whole listing.
    public static func decodeAccounts(_ data: Data) -> [OnePasswordAccount] {
        guard let rows = try? JSONDecoder().decode([OnePasswordAccount].self, from: data)
        else { return [] }
        return rows.filter { !$0.userID.isEmpty }
    }

    /// `op vault list --format=json`.
    public static func decodeVaults(_ data: Data) -> [OnePasswordVault] {
        guard let rows = try? JSONDecoder().decode([OnePasswordVault].self, from: data)
        else { return [] }
        return rows.filter { !$0.id.isEmpty }
    }

    /// `op account get --format=json` — the account `op` would use with no
    /// `--account`. Only consulted to break a tie.
    public static func decodeDefaultAccountID(_ data: Data) -> String? {
        struct Account: Decodable { let id: String }
        guard let account = try? JSONDecoder().decode(Account.self, from: data),
              !account.id.isEmpty
        else { return nil }
        return account.id
    }

    /// `op item list --format=json`, reduced to the identity fields. Item field
    /// *values* are never requested, so this stays metadata-only.
    public static func decodeItemIdentities(_ data: Data) -> [OnePasswordItemIdentity] {
        (try? JSONDecoder().decode([OnePasswordItemIdentity].self, from: data)) ?? []
    }
}

/// An item's identity within one vault. `op item list` returns this without any
/// field values.
public struct OnePasswordItemIdentity: Sendable, Equatable, Hashable, Decodable {
    public let id: String
    public let title: String

    public init(id: String, title: String) {
        self.id = id
        self.title = title
    }

    /// Matches `item` the way `op` addresses an item: exact id, or an exact
    /// title compared case-insensitively.
    public func matches(_ item: String) -> Bool {
        if id == item { return true }
        return title.compare(item, options: [.caseInsensitive]) == .orderedSame
    }
}

/// The parts of an `op://` reference this adapter needs to choose an account.
/// The rest of the path (section, field) is passed to `op` untouched.
public struct OnePasswordReferencePath: Sendable, Equatable {
    public let vault: String
    public let item: String?

    public init?(path: String) {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard let vault = parts.first, !vault.isEmpty else { return nil }
        self.vault = vault
        let item = parts.count > 1 ? parts[1] : ""
        self.item = item.isEmpty ? nil : item
    }
}

/// Synchronous account lookup for the CLI's own 1Password writes
/// (`csec protect --env`, `csec edit op://…`). csecd keeps a warm index inside
/// its provider actor; a short-lived `csec` process cannot reach it, so it
/// builds its own from the same metadata-only commands and applies the same
/// ladder. Reads and writes therefore agree about which account owns a vault.
public enum OnePasswordAccountDirectory {
    public enum Selection: Sendable, Equatable {
        case unique(OnePasswordVaultCandidate)
        /// Several accounts hold this vault (and item). The caller must ask
        /// rather than choose: a write goes somewhere permanent.
        case ambiguous([OnePasswordVaultCandidate])
        case notFound(searched: [OnePasswordAccount])
        /// At least one account could not be listed, so nothing is proven.
        case indeterminate(searched: [OnePasswordAccount])
    }

    /// Build the index from `run`, which invokes `op` and returns its result.
    /// Injectable so the ladder can be tested without a CLI.
    public static func buildIndex(
        now: Date = Date(),
        run: (_ arguments: [String]) throws -> OnePasswordCLI.Result
    ) throws -> OnePasswordAccountIndex {
        let accountsResult = try run(["account", "list", "--format=json"])
        guard accountsResult.status == 0 else { throw OnePasswordError.notAuthorized }
        let accounts = OnePasswordAccountIndex.decodeAccounts(accountsResult.stdout)
        guard !accounts.isEmpty else { throw OnePasswordError.noSignedInAccounts }

        let entries = accounts.map { account -> OnePasswordAccountIndex.Entry in
            let result = try? run(
                ["vault", "list", "--account", account.userID, "--format=json"]
            )
            guard let result, result.status == 0 else {
                return OnePasswordAccountIndex.Entry(
                    account: account, vaults: [], listingSucceeded: false
                )
            }
            return OnePasswordAccountIndex.Entry(
                account: account,
                vaults: OnePasswordAccountIndex.decodeVaults(result.stdout),
                listingSucceeded: true
            )
        }
        return OnePasswordAccountIndex(entries: entries, builtAt: now)
    }

    /// Build the index by running the trust-gated `op` at `cliPath`. Every
    /// invocation re-verifies its code identity, exactly like the daemon's.
    public static func buildIndex(cliPath: String) throws -> OnePasswordAccountIndex {
        try buildIndex { arguments in try OnePasswordCLI.runSync(cliPath, arguments) }
    }

    /// Which account owns `vault`, narrowed by `item` when more than one does.
    /// An item that does not exist yet cannot narrow anything — that case stays
    /// ambiguous so the caller asks before creating it in the wrong account.
    public static func select(
        vault: String,
        item: String?,
        in index: OnePasswordAccountIndex,
        itemIdentities: (OnePasswordVaultCandidate) -> [OnePasswordItemIdentity]?
    ) -> Selection {
        let candidates = index.candidates(forVault: vault)
        if candidates.isEmpty {
            return index.isComplete
                ? .notFound(searched: index.accounts)
                : .indeterminate(searched: index.accounts)
        }
        if candidates.count == 1 { return .unique(candidates[0]) }
        guard let item else { return .ambiguous(candidates) }

        let narrowed = candidates.filter { candidate in
            guard let identities = itemIdentities(candidate) else { return true }
            return identities.contains { $0.matches(item) }
        }
        if narrowed.count == 1 { return .unique(narrowed[0]) }
        return .ambiguous(narrowed.isEmpty ? candidates : narrowed)
    }

    /// Item identities in one vault — titles and ids, never field values.
    public static func itemIdentities(
        cliPath: String,
        candidate: OnePasswordVaultCandidate
    ) -> [OnePasswordItemIdentity]? {
        guard let result = try? OnePasswordCLI.runSync(cliPath, [
            "item", "list",
            "--account", candidate.account.userID,
            "--vault", candidate.vault.id,
            "--format=json",
        ]), result.status == 0 else { return nil }
        return OnePasswordAccountIndex.decodeItemIdentities(result.stdout)
    }
}
