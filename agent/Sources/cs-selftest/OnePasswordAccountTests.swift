import ConvenientSecurity
import CSECRemoteApproval
import Foundation
import OnePasswordAdapter

// Multi-account 1Password resolution. An `op://VAULT/ITEM/FIELD` reference
// carries no account, so with more than one signed in, csec decides which one
// owns the vault instead of inheriting whatever `op`'s own config last recorded
// — a default that moves whenever a different account is unlocked.
//
// Every listing used here is metadata: account ids, vault names, item titles.
// No field value is requested at any point.

private func account(_ id: String, _ url: String) -> OnePasswordAccount {
    OnePasswordAccount(
        userID: id,
        accountID: "account-\(id)",
        url: url,
        email: "\(id)@example.invalid"
    )
}

private func entry(
    _ account: OnePasswordAccount,
    _ vaults: [(String, String)],
    listed: Bool = true,
    personal: Bool = false
) -> OnePasswordAccountIndex.Entry {
    OnePasswordAccountIndex.Entry(
        account: account,
        vaults: vaults.map { OnePasswordVault(id: $0.0, name: $0.1, isPersonal: personal) },
        listingSucceeded: listed
    )
}

private let personal = account("user-personal", "my.1password.com")
private let work = account("user-work", "acme.1password.eu")

func onePasswordAccountIndexTests() {
    print("\n# 1Password account index (vault -> account)")

    let index = OnePasswordAccountIndex(
        entries: [
            entry(personal, [("vault-personal", "Personal")]),
            entry(work, [("vault-employee", "Employee"), ("vault-shared", "Personal")]),
        ],
        builtAt: Date(timeIntervalSince1970: 0)
    )

    // A vault that exists in exactly one account needs no tie-break at all.
    let employee = index.candidates(forVault: "Employee")
    check(employee.map(\.account) == [work],
          "a vault held by one account selects that account")

    // op matches a vault name case-insensitively (`employee` resolves,
    // `Emplo` does not). The index must match exactly the same set, or csec
    // would refuse references op itself accepts.
    check(index.candidates(forVault: "employee").map(\.account) == [work],
          "vault names match case-insensitively, as op does")
    check(index.candidates(forVault: "EMPLOYEE").map(\.account) == [work],
          "vault name matching ignores case in both directions")
    check(index.candidates(forVault: "Emplo").isEmpty,
          "a vault name prefix does not match, as op does not")

    // Vault ids are globally unique, which is what makes them the escape hatch
    // an ambiguity warning can point at.
    check(index.candidates(forVault: "vault-shared").map(\.account) == [work],
          "a vault id selects one account outright")
    check(index.candidates(forVault: "Personal").map(\.account) == [personal, work],
          "a name held by two accounts yields both as candidates")
    check(index.candidates(forVault: "Marketing").isEmpty,
          "an unknown vault yields no candidate")

    // A member's personal vault is titled "Employee" or "Private" depending on
    // when the account was provisioned, and op shows one spelling while the
    // SDK shows the other. The bridge already reads either spelling as the
    // account's personal vault; the index must agree, or it would declare a
    // vault absent that a read would have found. An exact title still wins.
    let renamed = OnePasswordAccountIndex(
        entries: [
            entry(personal, [("vault-personal", "Personal")]),
            entry(work, [("vault-private", "Private")]),
        ],
        builtAt: Date(timeIntervalSince1970: 0)
    )
    check(renamed.candidates(forVault: "Employee").map(\.vault.id) == ["vault-private"],
          "op://Employee/… finds an account whose personal vault the SDK titles Private")
    check(renamed.candidates(forVault: "private").map(\.vault.id) == ["vault-private"],
          "the personal-vault alias does not displace an exact name match")
    let typed = OnePasswordAccountIndex(
        entries: [
            entry(personal, [("vault-personal", "Personal")], personal: true),
            entry(work, [("vault-employee", "Employee"), ("vault-shared", "Personal")]),
        ],
        builtAt: Date(timeIntervalSince1970: 0)
    )
    check(typed.candidates(forVault: "Employee").map(\.vault.id) == ["vault-employee"],
          "an exact vault name outranks another account's personal-type vault")
    check(typed.candidates(forVault: "Private").map(\.vault.id) == ["vault-personal", "vault-employee"],
          "with no exact match, every personal vault answers, by type or by the other spelling, and the item breaks the tie")
    check(typed.candidates(forVault: "Shared").isEmpty,
          "the alias applies only to the two personal-vault spellings")
    // The CLI-built directory (csec edit, protect --env) sees op's spelling and
    // no vault type, and must land on the same account as csecd's read path.
    let cliSelection = OnePasswordAccountDirectory.select(
        vault: "Employee", item: nil, in: renamed, itemIdentities: { _ in nil }
    )
    check(cliSelection == .unique(renamed.candidates(forVault: "Private")[0]),
          "the CLI-side lookup and the daemon's index agree about a personal vault")

    check(index.isComplete && index.isUsable,
          "an index whose accounts all answered is complete")
    check(index.indexedVaultCount == 3, "the index counts every listed vault")

    // An account that could not be listed has unknown vaults, not none — so the
    // absence of a vault is never reported as fact.
    let partial = OnePasswordAccountIndex(
        entries: [entry(personal, [("vault-personal", "Personal")]),
                  entry(work, [], listed: false)],
        builtAt: Date(timeIntervalSince1970: 0)
    )
    check(!partial.isComplete && partial.isUsable,
          "an unlistable account leaves the index usable but incomplete")

    let unusable = OnePasswordAccountIndex(
        entries: [entry(personal, [], listed: false)],
        builtAt: Date(timeIntervalSince1970: 0)
    )
    check(!unusable.isUsable, "an index with no listed account is unusable")

    // Stable order decides only genuine ties, and must not move between daemon
    // restarts: exact case first, then op's own default, then the lowest id.
    let tied = index.candidates(forVault: "personal")
    let ordered = OnePasswordAccountIndex.stableOrder(
        tied, vaultQuery: "personal", defaultAccountID: nil
    )
    check(ordered.map(\.account) == [personal, work],
          "with no exact case or default account, the lowest user id wins")
    check(
        OnePasswordAccountIndex.stableOrder(
            tied, vaultQuery: "personal", defaultAccountID: "account-user-work"
        ).map(\.account) == [work, personal],
        "op's own current default account breaks a tie before the user id")
    // Exact case outranks even op's own default: the reference names the vault
    // the way its owner spelled it.
    let mixedCase = OnePasswordAccountIndex(
        entries: [
            entry(personal, [("vault-lower", "personal")]),
            entry(work, [("vault-exact", "Personal")]),
        ],
        builtAt: Date(timeIntervalSince1970: 0)
    )
    check(
        OnePasswordAccountIndex.stableOrder(
            mixedCase.candidates(forVault: "Personal"),
            vaultQuery: "Personal",
            defaultAccountID: "account-user-personal"
        ).first?.account == work,
        "an exactly-cased vault name outranks op's default account")

    // Reference parsing: the adapter needs the vault and item only; sections and
    // fields are passed to op untouched.
    check(OnePasswordReferencePath(path: "Employee/Token/password")?.vault == "Employee",
          "the first path segment is the vault")
    check(OnePasswordReferencePath(path: "Employee/Token/password")?.item == "Token",
          "the second path segment is the item")
    check(OnePasswordReferencePath(path: "Employee/Token/Section/password")?.item == "Token",
          "a sectioned reference still names the item second")
    check(OnePasswordReferencePath(path: "Employee")?.item == nil,
          "a reference with no item segment has no item to narrow by")

    // Item identity matching mirrors op: exact id, case-insensitive title.
    let identity = OnePasswordItemIdentity(id: "item-1", title: "Slack Token")
    check(identity.matches("item-1"), "an item id matches exactly")
    check(identity.matches("slack token"), "an item title matches case-insensitively")
    check(!identity.matches("Slack"), "a partial item title does not match")

    print("\n# 1Password account directory (CLI-side write selection)")

    // Writes must never assume: one candidate is used, several are reported as a
    // choice for the caller to ask about, and an incomplete index stays
    // indeterminate rather than claiming a vault is missing.
    let noItems: (OnePasswordVaultCandidate) -> [OnePasswordItemIdentity]? = { _ in [] }
    check(
        OnePasswordAccountDirectory.select(
            vault: "Employee", item: "Token", in: index, itemIdentities: noItems
        ) == .unique(
            OnePasswordVaultCandidate(
                account: work, vault: OnePasswordVault(id: "vault-employee", name: "Employee")
            )),
        "a uniquely held vault selects its account for a write")
    check(
        OnePasswordAccountDirectory.select(
            vault: "Marketing", item: "Token", in: index, itemIdentities: noItems
        ) == .notFound(searched: [personal, work]),
        "a complete index reports an unknown vault as missing, naming what it searched")
    check(
        OnePasswordAccountDirectory.select(
            vault: "Marketing", item: "Token", in: partial, itemIdentities: noItems
        ) == .indeterminate(searched: [personal, work]),
        "an incomplete index reports an unknown vault as indeterminate, not missing")

    // The item narrows the tie: only the account whose vault actually holds it.
    let holder: (OnePasswordVaultCandidate) -> [OnePasswordItemIdentity]? = { candidate in
        candidate.account == work
            ? [OnePasswordItemIdentity(id: "item-1", title: "Deploy Key")]
            : []
    }
    check(
        OnePasswordAccountDirectory.select(
            vault: "Personal", item: "Deploy Key", in: index, itemIdentities: holder
        ) == .unique(
            OnePasswordVaultCandidate(
                account: work, vault: OnePasswordVault(id: "vault-shared", name: "Personal")
            )),
        "the account whose vault holds the item wins a same-name tie")

    if case .ambiguous(let candidates) = OnePasswordAccountDirectory.select(
        vault: "Personal", item: nil, in: index, itemIdentities: noItems
    ) {
        check(candidates.count == 2,
              "a new item in a same-named vault stays ambiguous, so a write asks")
    } else {
        check(false, "a new item in a same-named vault stays ambiguous, so a write asks")
    }

    if case .ambiguous = OnePasswordAccountDirectory.select(
        vault: "Personal", item: "Missing", in: index, itemIdentities: noItems
    ) {
        check(true, "an item in neither vault stays ambiguous rather than guessing")
    } else {
        check(false, "an item in neither vault stays ambiguous rather than guessing")
    }

    // A candidate whose item listing fails is unknown, not empty: keeping it
    // turns a wrong answer into a warning.
    let unlistable: (OnePasswordVaultCandidate) -> [OnePasswordItemIdentity]? = { candidate in
        candidate.account == work ? nil : []
    }
    if case .unique(let candidate) = OnePasswordAccountDirectory.select(
        vault: "Personal", item: "Deploy Key", in: index, itemIdentities: unlistable
    ) {
        check(candidate.account == work,
              "a vault whose items cannot be listed is kept as a candidate")
    } else {
        check(false, "a vault whose items cannot be listed is kept as a candidate")
    }

    // Write argv carries the account and never a value.
    let writeArguments = OnePasswordItemWrite.getItemArguments(
        title: "Project", vault: "Employee", account: work
    )
    check(writeArguments == [
        "item", "get", "Project", "--vault", "Employee",
        "--account", "user-work", "--format", "json",
    ], "a write names the account it targets")
    check(
        OnePasswordItemWrite.createArguments(vault: "Employee", account: work)
            == ["item", "create", "--vault", "Employee",
                "--account", "user-work", "--format", "json", "-"],
        "item creation names the account it targets")
    check(
        OnePasswordItemWrite.editArguments(itemID: "item-1", account: work)
            == ["item", "edit", "item-1", "--account", "user-work", "--format", "json"],
        "item edits name the account they target")
    check(
        OnePasswordItemWrite.getItemArguments(title: "Project", vault: "Employee")
            == ["item", "get", "Project", "--vault", "Employee", "--format", "json"],
        "with no decided account the argv is unchanged, leaving the choice to op")

    // Decoding the three metadata listings.
    let accountsJSON = Data("""
    [{"url":"my.1password.com","email":"user-personal@example.invalid",
      "user_uuid":"user-personal","account_uuid":"account-user-personal"}]
    """.utf8)
    check(OnePasswordAccountIndex.decodeAccounts(accountsJSON) == [personal],
          "op account list output decodes to accounts keyed by user id")
    check(
        OnePasswordAccountIndex.decodeVaults(
            Data("""
            [{"id":"vault-employee","name":"Employee","items":7}]
            """.utf8)
        ) == [OnePasswordVault(id: "vault-employee", name: "Employee")],
        "op vault list output decodes to vault ids and names")
    check(
        OnePasswordAccountIndex.decodeDefaultAccountID(
            Data(#"{"id":"account-user-personal","name":"A","domain":"my"}"#.utf8)
        ) == "account-user-personal",
        "op account get output decodes to the current default account id")
    check(
        OnePasswordAccountIndex.decodeItemIdentities(
            Data("""
            [{"id":"item-1","title":"Slack Token","version":2,
              "vault":{"id":"vault-employee","name":"Employee"}}]
            """.utf8)
        ) == [OnePasswordItemIdentity(id: "item-1", title: "Slack Token")],
        "op item list output decodes to item ids and titles only")
    check(OnePasswordAccountIndex.decodeAccounts(Data("not json".utf8)).isEmpty,
          "unparseable account output yields no accounts rather than throwing")
}

func onePasswordProviderAccountTests() async {
    print("\n# 1Password provider account selection")

    let configuration = OnePasswordConnectionConfiguration(
        keepaliveInterval: 4,
        sessionIdleWindow: 10,
        authenticationTimeout: 7
    )

    // Two accounts: only the work one has "Employee". This is the originally
    // reported bug — an account-less read resolves against op's own default
    // (personal) and fails, while the vault sits in the other account all along.
    // Both accounts also have a vault named "Personal", which is the ambiguity
    // the ladder has to refuse to guess at.
    let runner = FakeOnePasswordCommandRunner()
    await runner.setAccounts(
        [("user-personal", "my.1password.com"), ("user-work", "acme.1password.eu")],
        vaults: [:]
    )
    let registry = FakeBackendRegistry { requested in
        if requested.userID == "user-work" {
            return FakeOnePasswordBackend(
                vaults: [
                    OnePasswordVault(id: "vault-employee", name: "Employee"),
                    OnePasswordVault(id: "vault-shared", name: "Personal"),
                ],
                items: ["vault-shared": [OnePasswordItemIdentity(id: "item-w", title: "Deploy Key")]],
                values: [
                    "op://Employee/Token/password": "work-token",
                    "op://Personal/Shared/password": "work-shared",
                ]
            )
        }
        return FakeOnePasswordBackend(
            vaults: [OnePasswordVault(id: "vault-personal", name: "Personal")],
            items: ["vault-personal": [OnePasswordItemIdentity(id: "item-p", title: "Home Router")]],
            values: ["op://Personal/Shared/password": "personal-shared"]
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
            try SecretRef("op://Employee/Token/password"), unlock: nil
        )
        check(resolved.value == Data("work-token".utf8),
              "a vault held by one account resolves from that account")
        let personalCalls = await registry.backend("user-personal")?.recordedCalls() ?? []
        check(!personalCalls.contains(.resolve("op://Employee/Token/password")),
              "the reference is never read from the account that lacks the vault")
    } catch {
        check(false, "a vault in a non-default account resolves (\(error))")
    }

    // Once decided, the reference stays on that account: a second read does not
    // re-derive it, so the answer cannot drift when op's default moves.
    do {
        let before = (await registry.backend("user-work")?.recordedCalls() ?? []).count
        _ = try await provider.resolve(try SecretRef("op://Employee/Token/password"), unlock: nil)
        let after = await registry.backend("user-work")?.recordedCalls() ?? []
        check(after.count == before + 1 && after.last == .resolve("op://Employee/Token/password"),
              "a decided reference resolves without re-deriving its account")
    } catch {
        check(false, "a remembered account resolves (\(error))")
    }

    // Ambiguity with no review to display it must fail closed rather than pick.
    do {
        _ = try await provider.resolve(try SecretRef("op://Personal/Shared/password"), unlock: nil)
        check(false, "an undisplayed ambiguous vault should not resolve")
    } catch let error as OnePasswordError {
        guard case let .vaultAmbiguous(vault, accounts) = error else {
            check(false, "an ambiguous vault fails with the ambiguity error (got \(error))")
            return
        }
        check(vault == "Personal" && accounts.count == 2,
              "an ambiguous vault fails closed, naming every account that has it")
        check(error.boundedReason.contains("more than one")
                && !error.boundedReason.contains("op exited"),
              "the ambiguity reason is csec's own words, not op's output")
    } catch {
        check(false, "an ambiguous vault fails with the ambiguity error (got \(error))")
    }

    // The review window is where that choice becomes visible. The description
    // answers from the warm index, and resolution then follows exactly what
    // was displayed.
    let ambiguous = try! SecretRef("op://Personal/Shared/password")
    let described = await provider.reviewDescription(for: ambiguous)
    check(described?.provider == "1Password" && described?.tint == .teal
            && described?.container == "Personal" && described?.item == "Shared"
            && described?.field == "password",
          "the review names account › vault › item › field from the reference")
    check(described?.account != nil,
          "the review is told which account the value will come from")
    check(described?.warnings.contains { $0.contains("More than one") } == true,
          "an ambiguous vault warns in the review before Touch ID")
    let displayedAccount = described?.account
    do {
        let resolved = try await provider.resolve(ambiguous, unlock: nil)
        let expected = displayedAccount == "my.1password.com" ? "personal-shared" : "work-shared"
        check(resolved.value == Data(expected.utf8),
              "resolution reads from exactly the account the review displayed")
    } catch {
        check(false, "an ambiguous reference resolves once a review displayed it (\(error))")
    }

    // The item breaks the tie before anything is called ambiguous: "Deploy Key"
    // exists only in the work account's same-named vault.
    let narrowed = await provider.reviewDescription(
        for: try! SecretRef("op://Personal/Deploy Key/password")
    )
    check(narrowed?.account == "acme.1password.eu" && narrowed?.warnings.isEmpty == true,
          "the account whose vault holds the item is chosen without a warning")

    // Everything after the item is the field, so a sectioned reference keeps
    // its item as the name; a reference with no field is not one 1Password
    // can serve, and is shown whole.
    let sectioned = await provider.reviewDescription(
        for: try! SecretRef("op://Personal/Deploy Key/Production/password")
    )
    check(sectioned?.item == "Deploy Key" && sectioned?.field == "Production/password",
          "a sectioned reference names its item, with section/field as the field")
    check(await provider.reviewDescription(for: try! SecretRef("op://Personal/Deploy Key")) == nil,
          "a reference without a field is left for the review to show whole")

    // A vault no account has is a definite answer once every account answered.
    do {
        _ = try await provider.resolve(try SecretRef("op://Missing/Item/field"), unlock: nil)
        check(false, "a vault held by no account should not resolve")
    } catch let error as OnePasswordError {
        guard case .vaultNotFoundInAnyAccount = error else {
            check(false, "an unknown vault reports that no account has it (got \(error))")
            return
        }
        check(error.boundedReason.contains("no signed-in 1Password account has vault"),
              "the missing-vault reason names the vault and the accounts searched")
    } catch {
        check(false, "an unknown vault reports that no account has it (got \(error))")
    }

    let missing = await provider.reviewDescription(for: try! SecretRef("op://Missing/Item/field"))
    check(missing?.warnings.contains { $0.contains("No signed-in 1Password account") } == true
            && missing?.account == nil && missing?.container == "Missing",
          "a vault no account has is flagged in the review, before Touch ID, with no account named")

    let summary = await provider.statusSummary()
    check(summary?.label == "1Password" && summary?.healthy == true,
          "csec status reports the 1Password provider as healthy")
    check(summary?.detail == "2 accounts, 3 vaults indexed",
          "csec status counts authorized accounts and indexed vaults")

    // An account whose authorization has lapsed leaves its vaults unknown. There
    // is no account-less read to fall back to any more — a session is per
    // account — so a reference that might live in the unreachable account is
    // refused rather than answered from the wrong one.
    let partialRunner = FakeOnePasswordCommandRunner()
    await partialRunner.setAccounts(
        [("user-personal", "my.1password.com"), ("user-work", "acme.1password.eu")],
        vaults: [:]
    )
    let partialRegistry = FakeBackendRegistry { requested in
        guard requested.userID == "user-personal" else {
            return FakeOnePasswordBackend(
                vaultsError: OnePasswordBridgeError.remote(kind: "unauthorized", message: "locked")
            )
        }
        return FakeOnePasswordBackend(
            vaults: [OnePasswordVault(id: "vault-personal", name: "Personal")]
        )
    }
    let partialProvider = OnePasswordProvider(
        cliPath: "/synthetic/op",
        configuration: configuration,
        makeBackend: partialRegistry.factory(),
        runCommand: { path, arguments, timeout in
            try await partialRunner.run(path: path, arguments: arguments, timeout: timeout)
        }
    )
    do {
        _ = try await partialProvider.resolve(
            try SecretRef("op://Employee/Token/password"), unlock: nil
        )
        check(false, "a vault that may live in an unreachable account should not resolve")
    } catch let error as OnePasswordError {
        guard case .notAuthorized = error else {
            check(false, "an unreachable account is reported as such (got \(error))")
            return
        }
        check(true, "a reference that may live in an unreachable account is refused")
    } catch {
        check(false, "an unreachable account is reported as such (got \(error))")
    }
    let partialSummary = await partialProvider.statusSummary()
    check(partialSummary?.healthy == false
            && partialSummary?.detail.contains("1 account not authorized") == true,
          "csec status shows an account whose authorization has lapsed")

    // No account at all is a distinct, actionable state.
    let emptyRunner = FakeOnePasswordCommandRunner()
    await emptyRunner.setAccounts([], vaults: [:])
    let emptyRegistry = FakeBackendRegistry { _ in FakeOnePasswordBackend() }
    let emptyProvider = OnePasswordProvider(
        cliPath: "/synthetic/op",
        configuration: configuration,
        makeBackend: emptyRegistry.factory(),
        runCommand: { path, arguments, timeout in
            try await emptyRunner.run(path: path, arguments: arguments, timeout: timeout)
        }
    )
    do {
        _ = try await emptyProvider.resolve(try SecretRef("op://Any/Item/field"), unlock: nil)
        check(false, "resolution with no signed-in account should throw")
    } catch let error as OnePasswordError {
        check(error.boundedReason.contains("no 1Password account is signed in"),
              "no signed-in account is reported as such, not as a missing vault")
    } catch {
        check(false, "no signed-in account is reported as such (got \(error))")
    }
}

/// Counts backend factory calls: making a backend is where a real bridge
/// would start authorizing.
private final class BridgeFactoryCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    func increment() {
        lock.lock()
        defer { lock.unlock() }
        count += 1
    }

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }
}

/// The review is built before anyone has approved anything, so a tie between
/// two accounts' same-named vaults is broken there only from item listings
/// already held. The usual way to arrive with none: the index was built by an
/// earlier read, then 1Password locked with the Mac and the bridges went away.
/// Listing a vault's items now would open a bridge and raise 1Password's own
/// unlock prompt ahead of csec's panel.
func onePasswordColdTieBreakReviewTests() async {
    print("\n# 1Password review of a shared vault name with no item listings held")

    let configuration = OnePasswordConnectionConfiguration(
        keepaliveInterval: 4,
        sessionIdleWindow: 10,
        authenticationTimeout: 7
    )

    /// A provider whose index is built and whose bridges have gone, with no
    /// item listing held. Both accounts have a vault named "Shared"; "Deploy
    /// Key" is only in the work one, "Router" is in both.
    func lockedProvider() async -> (OnePasswordProvider, FakeBackendRegistry, BridgeFactoryCounter) {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts(
            [("user-personal", "my.1password.com"), ("user-work", "acme.1password.eu")],
            vaults: [:]
        )
        let registry = FakeBackendRegistry { requested in
            if requested.userID == "user-work" {
                return FakeOnePasswordBackend(
                    vaults: [
                        OnePasswordVault(id: "vault-employee", name: "Employee"),
                        OnePasswordVault(id: "vault-work-shared", name: "Shared"),
                    ],
                    items: ["vault-work-shared": [
                        OnePasswordItemIdentity(id: "item-deploy", title: "Deploy Key"),
                        OnePasswordItemIdentity(id: "item-router-w", title: "Router"),
                    ]],
                    values: [
                        "op://Employee/Token/password": "work-token",
                        "op://Shared/Deploy Key/password": "work-deploy",
                        "op://Shared/Router/password": "work-router",
                    ]
                )
            }
            return FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "vault-personal-shared", name: "Shared")],
                items: ["vault-personal-shared": [
                    OnePasswordItemIdentity(id: "item-router-p", title: "Router"),
                ]],
                values: ["op://Shared/Router/password": "personal-router"]
            )
        }
        let factoryCalls = BridgeFactoryCounter()
        let factory = registry.factory()
        let provider = OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: { account in
                factoryCalls.increment()
                return try factory(account)
            },
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            }
        )
        // A read from a vault only one account has builds the index, listing
        // vaults but no items. Then 1Password locks.
        do {
            _ = try await provider.resolve(try SecretRef("op://Employee/Token/password"), unlock: nil)
        } catch {
            check(false, "a vault held by one account resolves and builds the index (\(error))")
        }
        await provider.shutdownBackends()
        return (provider, registry, factoryCalls)
    }

    func contact(_ registry: FakeBackendRegistry) async -> [FakeOnePasswordBackend.Call] {
        var calls: [FakeOnePasswordBackend.Call] = []
        for id in ["user-personal", "user-work"] {
            calls += (await registry.backend(id)?.recordedCalls() ?? []).filter { $0 != .shutdown }
        }
        return calls
    }

    let (provider, registry, factoryCalls) = await lockedProvider()
    let callsBefore = await contact(registry)
    let bridgesBefore = factoryCalls.value
    let deploy = try! SecretRef("op://Shared/Deploy Key/password")
    let described = await provider.reviewDescription(for: deploy)
    check(await contact(registry) == callsBefore && factoryCalls.value == bridgesBefore,
          "the review of a shared vault name opens no bridge and asks 1Password nothing")
    check(described?.container == "Shared" && described?.item == "Deploy Key"
            && described?.field == "password",
          "the review still names vault › item › field")
    check(described?.account == nil,
          "the review names no account it has not decided on")
    check(described?.warnings.count == 1
            && described?.warnings.first?.contains("More than one signed-in account has a vault named “Shared”") == true
            && described?.warnings.first?.contains("my.1password.com") == true
            && described?.warnings.first?.contains("acme.1password.eu") == true
            && described?.warnings.first?.contains("whichever of them holds “Deploy Key”") == true,
          "the review warns which accounts share the vault and how one will be chosen")

    // Approved, the read settles the tie by listing items, now that a person
    // has asked for it, and reads from the one account that holds the item.
    do {
        let resolved = try await provider.resolve(deploy, unlock: nil)
        check(resolved.value == Data("work-deploy".utf8),
              "the approved read comes from the one account whose vault holds the item")
    } catch {
        check(false, "the approved read of an item one account holds resolves (\(error))")
    }

    // An item both vaults hold is a tie no listing can break, and nothing
    // displayed a choice of account, so the read fails closed.
    let (bothProvider, bothRegistry, bothFactoryCalls) = await lockedProvider()
    let router = try! SecretRef("op://Shared/Router/password")
    let undecided = await bothProvider.reviewDescription(for: router)
    check(undecided?.account == nil
            && undecided?.warnings.first?.contains("whichever of them holds “Router”") == true,
          "an item both same-named vaults hold is left undecided while no listing is held")
    do {
        _ = try await bothProvider.resolve(router, unlock: nil)
        check(false, "an item in both same-named vaults should not resolve from an undecided review")
    } catch let error as OnePasswordError {
        if case let .vaultAmbiguous(vault, accounts) = error {
            check(vault == "Shared" && accounts.count == 2,
                  "an item in both same-named vaults fails closed, naming both accounts")
        } else {
            check(false, "an item in both same-named vaults fails with the ambiguity error (got \(error))")
        }
    } catch {
        check(false, "an item in both same-named vaults fails with the ambiguity error (got \(error))")
    }

    // The listings that read took are held now, so the next review decides
    // from them without contacting 1Password, and names the account it will
    // read from.
    let warmCalls = await contact(bothRegistry)
    let warmBridges = bothFactoryCalls.value
    let decided = await bothProvider.reviewDescription(for: router)
    check(await contact(bothRegistry) == warmCalls && bothFactoryCalls.value == warmBridges,
          "a review with the listings held still asks 1Password nothing")
    check(decided?.account != nil
            && decided?.warnings.first?.contains("This value will come from") == true,
          "with the listings held, the review names the account the value will come from")
    let decidedValue = decided?.account == "my.1password.com" ? "personal-router" : "work-router"
    do {
        let resolved = try await bothProvider.resolve(router, unlock: nil)
        check(resolved.value == Data(decidedValue.utf8),
              "the read then follows the account that review displayed")
    } catch {
        check(false, "a displayed ambiguous choice resolves (\(error))")
    }
}

// The provider's description must survive the whole way to what a person
// reads, on the Mac window and on the phone.
func onePasswordReviewDescriptionTests() {
    print("\n# provider review descriptions in the trusted surfaces")

    let warning = "More than one signed-in account has a vault named “Employee”."
    let credential = PolicyReviewCredential(described: [(
        try! SecretRef("op://Employee/Slack/password"),
        ReviewDisplay.displaySafe(ReviewSecret(
            provider: "1Password", tint: .teal, account: "acme.1password.eu",
            container: "Employee", item: "Slack", field: "password", warnings: [warning]
        ))
    )])
    let tree = ReviewSecretTree(credential.secrets)
    check(tree.sources.first?.title == "1Password · acme.1password.eu"
            && tree.sources.first?.containers.first?.name == "Employee",
          "the account is the source line and the vault folds onto it")
    check(tree.sources.first?.containers.first?.warnings == [warning],
          "a provider warning is kept separate from the names, under its vault")

    // A description is attacker-influenced metadata (a vault name reaches it),
    // so the window sanitizes it exactly like every other dynamic review string.
    let hostile = ReviewDisplay.displaySafe(ReviewSecret(
        provider: "1Password", tint: .teal, account: "evil\u{202E}corp\nnew",
        container: "Employee", item: "Slack", field: "password"
    ))
    check(hostile.account?.contains("\u{202E}") == false && hostile.account?.contains("\n") == false,
          "account text is stripped of bidi and newline controls before display")

    check(ReviewDisplay.bounded("abcdef", maxBytes: 4) == "abc…",
          "bounded trims to the byte budget")
    check(ReviewDisplay.bounded("ab", maxBytes: 64) == "ab",
          "bounded leaves text inside the budget untouched")
}

/// Live check against the machine's real 1Password accounts. Off by default so
/// `bin/ci` can never block on a locked 1Password app; opt in with
/// `CSEC_OP_LIVE_ACCOUNTS=1`. It reads only the account and vault listings, and
/// deliberately prints no account, vault, or item name — the suite must never
/// enumerate the developer's real environment.
func onePasswordLiveAccountTests() {
    #if DEBUG
    guard ProcessInfo.processInfo.environment["CSEC_OP_LIVE_ACCOUNTS"] == "1" else { return }
    print("\n# 1Password live account index (metadata only)")
    guard let cliPath = OnePasswordCLI.locate() else {
        print("skip - op CLI not installed")
        return
    }
    guard let index = try? OnePasswordAccountDirectory.buildIndex(cliPath: cliPath) else {
        print("skip - no authorized 1Password account")
        return
    }
    check(index.isUsable, "the live index has at least one authorized account")
    check(index.entries.count >= 1, "the live index lists the signed-in accounts")

    // The invariant the fix rests on: every vault the machine can see resolves
    // to exactly one account when addressed by its globally unique id.
    for entry in index.entries where entry.listingSucceeded {
        for vault in entry.vaults {
            let candidates = index.candidates(forVault: vault.id)
            guard candidates.count == 1, candidates[0].account == entry.account else {
                check(false, "a live vault id resolves to exactly one account")
                return
            }
        }
    }
    check(true, "every live vault id resolves to exactly one account")

    // Name collisions across accounts are exactly the case the approval dialog
    // has to warn about; report only how many there are.
    var accountsByVaultName: [String: Set<String>] = [:]
    for entry in index.entries where entry.listingSucceeded {
        for vault in entry.vaults {
            accountsByVaultName[vault.name.lowercased(), default: []].insert(entry.account.userID)
        }
    }
    let collisions = accountsByVaultName.values.filter { $0.count > 1 }.count
    print("info - live vault names held by more than one account: \(collisions)")
    #endif
}

/// csec-0.64.6: the attended restore fetches every paired value ahead. A
/// person at the Mac who declines 1Password's prompt, or misses it, must see
/// it once per account, not once per paired reference: every new contact
/// with an account that has not authorized csec is another prompt, or
/// another wait for one to time out.
func onePasswordFetchAheadTests() async {
    print("\n# 1Password fetch ahead asks each account at most once")

    let configuration = OnePasswordConnectionConfiguration(
        keepaliveInterval: 4,
        sessionIdleWindow: 10,
        authenticationTimeout: 7
    )
    let unauthorized = OnePasswordBridgeError.remote(kind: "unauthorized", message: "synthetic")

    // One account, which refuses: the first read is its only contact.
    let soloRunner = FakeOnePasswordCommandRunner()
    await soloRunner.setAccounts([("user-work", "acme.1password.eu")], vaults: [:])
    let soloRegistry = FakeBackendRegistry { _ in
        FakeOnePasswordBackend(
            vaults: [OnePasswordVault(id: "vault-employee", name: "Employee")],
            values: ["op://Employee/A/password": "a", "op://Employee/B/password": "b"]
        )
    }
    let solo = OnePasswordProvider(
        cliPath: "/synthetic/op",
        configuration: configuration,
        makeBackend: soloRegistry.factory(),
        runCommand: { path, arguments, timeout in
            try await soloRunner.run(path: path, arguments: arguments, timeout: timeout)
        }
    )
    let soloRefs = ["op://Employee/A/password", "op://Employee/B/password", "op://Employee/C/password"]
        .map { try! SecretRef($0) }
    // The first read creates the backend, so it is refused from the start.
    _ = try? await solo.resolve(soloRefs[0], unlock: nil)
    await soloRegistry.backend("user-work")?.failResolves(with: unauthorized)
    let before = (await soloRegistry.backend("user-work")?.recordedCalls() ?? []).count
    let soloResults = await solo.fetchAhead(soloRefs)
    let soloCalls = (await soloRegistry.backend("user-work")?.recordedCalls() ?? []).dropFirst(before)
    check(soloCalls.filter({ if case .resolve = $0 { return true } else { return false } }).count == 1,
          "fetch ahead: an account that refused is contacted once in the batch, not once per reference")
    let soloReasons = soloResults.compactMap { result -> String? in
        if case let .failed(reason) = result.outcome { return reason }
        return nil
    }
    check(soloResults.count == 3 && soloReasons.count == 3
            && soloReasons[0] == "1Password did not authorize this request"
            && soloReasons.dropFirst().allSatisfy { $0.contains("did not ask it again") },
          "fetch ahead: every reference is answered, the skipped ones saying the account was not asked again")
    // The batch is over, but the refusal is not: a request nobody approved at
    // the Mac does not ask again (csec-0.84). A person's approval there does.
    _ = try? await solo.resolve(soloRefs[1], unlock: nil)
    let unattendedCalls = (await soloRegistry.backend("user-work")?.recordedCalls() ?? []).dropFirst(before)
    check(unattendedCalls.filter({ if case .resolve = $0 { return true } else { return false } }).count == 1,
          "fetch ahead: the refusal outlasts the batch until a person approves at the Mac")
    await solo.personApprovedAtMac()
    _ = try? await solo.resolve(soloRefs[1], unlock: nil)
    let afterCalls = (await soloRegistry.backend("user-work")?.recordedCalls() ?? []).dropFirst(before)
    check(afterCalls.filter({ if case .resolve = $0 { return true } else { return false } }).count == 2,
          "fetch ahead: an approval at the Mac lets the next request ask the account once more")

    // Two accounts: the work one refuses to list its vaults; the personal one
    // serves. Personal values are still fetched, and the work account is
    // listed once, however many of its references follow.
    let pairRunner = FakeOnePasswordCommandRunner()
    await pairRunner.setAccounts(
        [("user-personal", "my.1password.com"), ("user-work", "acme.1password.eu")],
        vaults: [:]
    )
    let pairRegistry = FakeBackendRegistry { requested in
        guard requested.userID == "user-personal" else {
            return FakeOnePasswordBackend(vaultsError: unauthorized)
        }
        return FakeOnePasswordBackend(
            vaults: [OnePasswordVault(id: "vault-personal", name: "Personal")],
            values: ["op://Personal/A/password": "pa", "op://Personal/B/password": "pb"]
        )
    }
    let pair = OnePasswordProvider(
        cliPath: "/synthetic/op",
        configuration: configuration,
        makeBackend: pairRegistry.factory(),
        runCommand: { path, arguments, timeout in
            try await pairRunner.run(path: path, arguments: arguments, timeout: timeout)
        }
    )
    let pairRefs = [
        "op://Personal/A/password", "op://Employee/X/password",
        "op://Personal/B/password", "op://Employee/Y/password",
    ].map { try! SecretRef($0) }
    let pairResults = await pair.fetchAhead(pairRefs)
    let fetched = pairResults.compactMap { result -> String? in
        if case let .fetched(resolved) = result.outcome { return String(decoding: resolved.value, as: UTF8.self) }
        return nil
    }
    let workListings = (await pairRegistry.backend("user-work")?.recordedCalls() ?? []).filter { $0 == .vaults }
    check(fetched == ["pa", "pb"],
          "fetch ahead: the account that serves is fetched from although another refused")
    check(workListings.count == 1,
          "fetch ahead: a refusing account is listed once in the batch, not again for each of its references")
}

/// csec-0.84: on 7 Nov, with two accounts signed in and no index, 1Password
/// refused csec's authorization and csecd asked again for every reference of
/// every request: seven pairs of authorizations in four seconds from two
/// three-reference panels, six pairs in two seconds from an agent's
/// unattended retries, each one a prompt or a refusal. An account that
/// refused is not asked again by anything until a person approves a csec
/// panel at the Mac, and then once.
func onePasswordRefusalHeldUntilApprovalTests() async {
    print("\n# 1Password: an account that refused is not asked again until an approval at the Mac")

    let configuration = OnePasswordConnectionConfiguration(
        keepaliveInterval: 4,
        sessionIdleWindow: 10,
        authenticationTimeout: 7,
        missRetryDelays: []
    )
    let unauthorized = OnePasswordBridgeError.remote(kind: "unauthorized", message: "synthetic")

    let runner = FakeOnePasswordCommandRunner()
    await runner.setAccounts(
        [("user-personal", "my.1password.com"), ("user-work", "acme.1password.eu")],
        vaults: [:]
    )
    let registry = FakeBackendRegistry { requested in
        FakeOnePasswordBackend(
            vaults: requested.userID == "user-personal"
                ? [OnePasswordVault(id: "vault-personal", name: "Personal")]
                : [OnePasswordVault(id: "vault-employee", name: "Employee")],
            values: [
                "op://Personal/Key/issuer_id": "p1", "op://Personal/Key/key": "p2",
                "op://Employee/Slack/token": "w1", "op://Employee/Slack/cookie": "w2",
            ],
            vaultsError: unauthorized
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
    func listings(_ userID: String) async -> Int {
        (await registry.backend(userID)?.recordedCalls() ?? []).filter { $0 == .vaults }.count
    }

    // Two approved requests of several references each, then an agent's
    // unattended retries of the same references.
    let refs = [
        "op://Employee/Slack/token", "op://Employee/Slack/cookie", "op://Employee/Slack/password",
        "op://Personal/Key/issuer_id", "op://Personal/Key/key", "op://Personal/Key/key_id",
        "op://Employee/Slack/token", "op://Employee/Slack/token", "op://Personal/Key/key",
    ].map { try! SecretRef($0) }
    var reasons: [String] = []
    for ref in refs {
        do {
            _ = try await provider.resolve(ref, unlock: nil)
            reasons.append("resolved")
        } catch {
            reasons.append((error as? any ProviderDiagnosableError)?.boundedReason ?? "\(error)")
        }
    }
    let personalListed = await listings("user-personal")
    let workListed = await listings("user-work")
    check(personalListed == 1 && workListed == 1,
          "refusal: each refusing account is asked once, not once per reference, request or retry")
    check(!reasons.contains("resolved")
            && reasons.dropFirst().allSatisfy { $0.contains("approve a csec panel at this Mac") },
          "refusal: the references not asked say why and what asks again")

    // A person approves at the Mac and 1Password now authorizes: one more
    // listing per account, and the values are served.
    await registry.backend("user-personal")?.failVaults(with: nil)
    await registry.backend("user-work")?.failVaults(with: nil)
    await provider.personApprovedAtMac()
    let token = try? await provider.resolve(try! SecretRef("op://Employee/Slack/token"), unlock: nil)
    let key = try? await provider.resolve(try! SecretRef("op://Personal/Key/key"), unlock: nil)
    check(token.map { String(decoding: $0.value, as: UTF8.self) } == "w1"
            && key.map { String(decoding: $0.value, as: UTF8.self) } == "p2",
          "refusal: after an approval at the Mac the accounts are asked again and serve")
    let personalRelisted = await listings("user-personal")
    let workRelisted = await listings("user-work")
    check(personalRelisted == 2 && workRelisted == 2,
          "refusal: an approval at the Mac costs each account one more authorization, no more")

    // A live session that 1Password stops authorizing mid-way (expired, or a
    // prompt nobody answered) is held the same way.
    for kind in [OnePasswordBridgeError.remote(kind: "session_expired", message: "synthetic"), .timedOut] {
        await registry.backend("user-work")?.failResolves(with: kind)
        let before = (await registry.backend("user-work")?.recordedCalls() ?? [])
            .filter { if case .resolve = $0 { return true } else { return false } }.count
        for _ in 0..<3 {
            _ = try? await provider.resolve(try! SecretRef("op://Employee/Slack/cookie"), unlock: nil)
        }
        let after = (await registry.backend("user-work")?.recordedCalls() ?? [])
            .filter { if case .resolve = $0 { return true } else { return false } }.count
        check(after - before == 1, "refusal: a live session's \(kind) is asked once, then held")
        await registry.backend("user-work")?.failResolves(with: nil)
        await provider.personApprovedAtMac()
    }

    // The approval sites tell providers through the resolver, scheme-blind.
    await registry.backend("user-work")?.failResolves(with: unauthorized)
    _ = try? await provider.resolve(try! SecretRef("op://Employee/Slack/cookie"), unlock: nil)
    await registry.backend("user-work")?.failResolves(with: nil)
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(provider)
    await resolver.personApprovedAtMac()
    let viaResolver = try? await provider.resolve(try! SecretRef("op://Employee/Slack/cookie"), unlock: nil)
    check(viaResolver.map { String(decoding: $0.value, as: UTF8.self) } == "w2",
          "refusal: an approval at the Mac reaches the provider through the resolver")

    // A reference miss is the account answering, not refusing.
    _ = try? await provider.resolve(try! SecretRef("op://Employee/Slack/missing"), unlock: nil)
    let served = try? await provider.resolve(try! SecretRef("op://Employee/Slack/cookie"), unlock: nil)
    check(served.map { String(decoding: $0.value, as: UTF8.self) } == "w2",
          "refusal: a reference 1Password does not have is not held as a refusal")
}

/// Collects what a provider asks csecd to tell a person.
private actor AttentionRecorder {
    private(set) var events: [ProviderAttention] = []
    func record(_ event: ProviderAttention) { events.append(event) }
    func kinds(_ account: String) -> [ProviderAttention.Kind] {
        events.filter { $0.account == account }.map(\.kind)
    }
}

/// csec-0.64.17: after 4 of 6 installs from 7 Nov, 1Password's own prompt
/// went unanswered for 60 s with the person at the Mac, the account was held
/// refused (csec-0.84), and the paired values stayed cold until their next
/// approval there. Nothing told anyone: `csec restore` printed it into the
/// install worker's log. csecd now says when 1Password has been asking a
/// while, withdraws that when it is answered, and says once when an account
/// is held. A session that already answered, or a first contact that answers
/// at once, says nothing.
func onePasswordAttentionTests() async {
    print("\n# 1Password: a person hears when its prompt waits, and when an account is held")

    let configuration = OnePasswordConnectionConfiguration(
        keepaliveInterval: 60,
        sessionIdleWindow: 600,
        authenticationTimeout: 7,
        missRetryDelays: [],
        authorizationNoticeDelay: 0.2
    )
    func provider(
        accounts: [(String, String)], registry: FakeBackendRegistry, recorder: AttentionRecorder
    ) async -> OnePasswordProvider {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts(accounts, vaults: [:])
        return OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            },
            attentionObserver: { event in Task { await recorder.record(event) } }
        )
    }
    func settle() async { try? await Task.sleep(nanoseconds: 100_000_000) }
    let personal = "my.1password.com"
    let ref = try! SecretRef("op://Personal/Key/credential")

    // A first contact that 1Password answers after a while, as a person
    // answering its prompt does: told, then withdrawn.
    let slowRecorder = AttentionRecorder()
    let slowRegistry = FakeBackendRegistry { _ in
        FakeOnePasswordBackend(values: ["op://Personal/Key/credential": "v"], resolveDelay: 0.6)
    }
    let slow = await provider(accounts: [("user-personal", personal)], registry: slowRegistry, recorder: slowRecorder)
    let slowValue = try? await slow.resolve(ref, unlock: nil)
    await settle()
    let slowKinds = await slowRecorder.kinds(personal)
    check(slowValue.map { String(decoding: $0.value, as: UTF8.self) } == "v"
            && slowKinds == [.awaitingAuthorization, .settled],
          "attention: a first contact 1Password answers late is announced, then withdrawn")

    // The same session, now answered, reads slowly again: no prompt can be
    // up, so nothing is said.
    _ = try? await slow.resolve(ref, unlock: nil)
    await settle()
    check((await slowRecorder.events).count == 2,
          "attention: a slow read over a session that already answered says nothing")

    // A first contact that answers at once says nothing.
    let quickRecorder = AttentionRecorder()
    let quickRegistry = FakeBackendRegistry { _ in
        FakeOnePasswordBackend(values: ["op://Personal/Key/credential": "v"])
    }
    let quick = await provider(accounts: [("user-personal", personal)], registry: quickRegistry, recorder: quickRecorder)
    _ = try? await quick.resolve(ref, unlock: nil)
    await settle()
    check((await quickRecorder.events).isEmpty, "attention: an authorized first contact says nothing")

    // The prompt nobody answers: told while it waits, then told once that
    // the account is held, however many requests follow.
    let missedRecorder = AttentionRecorder()
    let missedRegistry = FakeBackendRegistry { _ in
        FakeOnePasswordBackend(
            values: ["op://Personal/Key/credential": "v"],
            resolveError: OnePasswordBridgeError.timedOut, resolveDelay: 0.6
        )
    }
    let missed = await provider(accounts: [("user-personal", personal)], registry: missedRegistry, recorder: missedRecorder)
    for _ in 0..<3 { _ = try? await missed.resolve(ref, unlock: nil) }
    await settle()
    check((await missedRecorder.kinds(personal)) == [.awaitingAuthorization, .notAuthorized(unanswered: true)],
          "attention: an unanswered prompt is announced while it waits, then the hold is told once")
    let heldStatus = await missed.statusSummary()
    check(heldStatus?.healthy == false
            && heldStatus?.detail.contains("approve a csec panel at this Mac") == true
            && heldStatus?.detail.contains(personal) == true,
          "attention: csec status names the held account and what asks it again")

    // After an approval at the Mac, 1Password declines outright: told once,
    // as a refusal, with nothing to announce first.
    await missedRegistry.backend("user-personal")?.delayResolves(by: 0)
    await missedRegistry.backend("user-personal")?.failResolves(
        with: OnePasswordBridgeError.remote(kind: "unauthorized", message: "synthetic"))
    await missed.personApprovedAtMac()
    for _ in 0..<2 { _ = try? await missed.resolve(ref, unlock: nil) }
    await settle()
    check((await missedRecorder.kinds(personal)) == [
            .awaitingAuthorization, .notAuthorized(unanswered: true), .notAuthorized(unanswered: false),
          ],
          "attention: a refusal after an approval at the Mac is told once, as declined")

    // Two accounts, no index: both are asked for their vaults and neither
    // answers. Each is announced and held on its own.
    let work = "acme.1password.eu"
    let pairRecorder = AttentionRecorder()
    let pairRegistry = FakeBackendRegistry { _ in
        FakeOnePasswordBackend(vaultsError: OnePasswordBridgeError.timedOut, vaultsDelay: 0.6)
    }
    let pair = await provider(
        accounts: [("user-personal", personal), ("user-work", work)],
        registry: pairRegistry, recorder: pairRecorder
    )
    _ = try? await pair.resolve(try! SecretRef("op://Employee/Slack/token"), unlock: nil)
    await settle()
    let pairExpected: [ProviderAttention.Kind] = [.awaitingAuthorization, .notAuthorized(unanswered: true)]
    let personalKinds = await pairRecorder.kinds(personal)
    let workKinds = await pairRecorder.kinds(work)
    check(personalKinds == pairExpected && workKinds == pairExpected,
          "attention: with two accounts each unanswered prompt is announced and held for its own account")

    // The words: one notification per account, replaced as it changes, and
    // withdrawn once settled.
    let waiting = ProviderAttention(provider: "1Password", account: personal, kind: .awaitingAuthorization)
    let held = ProviderAttention(provider: "1Password", account: personal, kind: .notAuthorized(unanswered: true))
    let declined = ProviderAttention(provider: "1Password", account: personal, kind: .notAuthorized(unanswered: false))
    let other = ProviderAttention(provider: "1Password", account: work, kind: .awaitingAuthorization)
    check(waiting.notificationIdentifier == held.notificationIdentifier
            && waiting.notificationIdentifier != other.notificationIdentifier,
          "attention: each account has one notification, which each new state replaces")
    check(waiting.notification?.body.contains("Answer 1Password's prompt for \(personal)") == true
            && held.notification?.title == "1Password's prompt went unanswered"
            && declined.notification?.title == "1Password did not allow csec"
            && held.notification?.body.contains("until you approve a csec panel at this Mac") == true
            && ProviderAttention(provider: "1Password", account: personal, kind: .settled).notification == nil,
          "attention: the notification says what to answer, or what is held and what asks again")
    let hostile = ProviderAttention(provider: "1Password", account: "evil\u{1B}[2J\nlabel", kind: .awaitingAuthorization)
    check(hostile.notification?.body.contains("\u{1B}") == false
            && hostile.notification?.body.contains("\n") == false,
          "attention: an account label cannot put control characters into the notification")
}
