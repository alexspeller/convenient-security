import ConvenientSecurity
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
    listed: Bool = true
) -> OnePasswordAccountIndex.Entry {
    OnePasswordAccountIndex.Entry(
        account: account,
        vaults: vaults.map { OnePasswordVault(id: $0.0, name: $0.1) },
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
        heartbeatInterval: 8,
        connectionFreshness: 10,
        initialRetryDelay: 5,
        maximumRetryDelay: 30,
        authenticationTimeout: 7,
        resolutionTimeout: 11
    )

    // Two accounts: only the work one has "Employee". This is the reported bug —
    // op's account-less read resolves against its own default (personal) and
    // fails, while the vault sits in the other account the whole time.
    let runner = FakeOnePasswordCommandRunner()
    await runner.setAccounts(
        [("user-personal", "my.1password.com"), ("user-work", "acme.1password.eu")],
        vaults: [
            "user-personal": [(id: "vault-personal", name: "Personal")],
            "user-work": [
                (id: "vault-employee", name: "Employee"),
                (id: "vault-shared", name: "Personal"),
            ],
        ],
        items: [
            "user-personal/vault-personal": [(id: "item-p", title: "Home Router")],
            "user-work/vault-shared": [(id: "item-w", title: "Deploy Key")],
        ]
    )
    let provider = OnePasswordProvider(
        cliPath: "/synthetic/op",
        configuration: configuration,
        runCommand: { path, arguments, timeout in
            try await runner.run(path: path, arguments: arguments, timeout: timeout)
        }
    )

    do {
        _ = try await provider.resolve(try SecretRef("op://Employee/Token/password"), unlock: nil)
        let read = await runner.invocations().last?.arguments
        check(read == [
            "read", "--account", "user-work", "--no-newline", "op://Employee/Token/password",
        ], "a vault held by one account resolves from that account")
    } catch {
        check(false, "a vault in a non-default account resolves (\(error))")
    }

    // Once decided, the reference stays on that account: a second read does not
    // re-derive it, so the answer cannot drift when op's default moves.
    await runner.resetInvocations()
    do {
        _ = try await provider.resolve(try SecretRef("op://Employee/Token/password"), unlock: nil)
        let arguments = await runner.invocations().map(\.arguments)
        check(arguments == [[
            "read", "--account", "user-work", "--no-newline", "op://Employee/Token/password",
        ]], "a decided reference resolves without re-deriving its account")
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

    // The review window is where that choice becomes visible. Notes answer from
    // the warm index, and resolution then follows exactly what was displayed.
    let ambiguous = try! SecretRef("op://Personal/Shared/password")
    let notes = await provider.reviewNotes(for: ambiguous)
    check(notes.first?.label == "account",
          "the review is told which account the value will come from")
    check(notes.contains { $0.isWarning && $0.detail.contains("More than one") },
          "an ambiguous vault warns in the review before Touch ID")
    let displayedAccount = notes.first?.detail
    await runner.resetInvocations()
    do {
        _ = try await provider.resolve(ambiguous, unlock: nil)
        let read = await runner.invocations().last?.arguments ?? []
        let expected = displayedAccount == "my.1password.com" ? "user-personal" : "user-work"
        check(read.contains("--account") && read.contains(expected),
              "resolution reads from exactly the account the review displayed")
    } catch {
        check(false, "an ambiguous reference resolves once a review displayed it (\(error))")
    }

    // The item breaks the tie before anything is called ambiguous: "Deploy Key"
    // exists only in the work account's same-named vault.
    let narrowed = await provider.reviewNotes(
        for: try! SecretRef("op://Personal/Deploy Key/password")
    )
    check(narrowed.count == 1 && narrowed.first?.detail == "acme.1password.eu",
          "the account whose vault holds the item is chosen without a warning")

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

    let missingNotes = await provider.reviewNotes(for: try! SecretRef("op://Missing/Item/field"))
    check(missingNotes.contains { $0.isWarning },
          "a vault no account has is flagged in the review, before Touch ID")

    let summary = await provider.statusSummary()
    check(summary?.label == "1Password" && summary?.healthy == true,
          "csec status reports the 1Password provider as healthy")
    check(summary?.detail == "2 accounts, 3 vaults indexed",
          "csec status counts authorized accounts and indexed vaults")

    // An account whose authorization has lapsed leaves its vaults unknown, so
    // csec keeps today's behavior — let op resolve the reference itself —
    // instead of claiming the vault does not exist.
    let partialRunner = FakeOnePasswordCommandRunner()
    await partialRunner.setAccounts(
        [("user-personal", "my.1password.com"), ("user-work", "acme.1password.eu")],
        vaults: ["user-personal": [(id: "vault-personal", name: "Personal")]],
        unauthorized: ["user-work"]
    )
    let partialProvider = OnePasswordProvider(
        cliPath: "/synthetic/op",
        configuration: configuration,
        runCommand: { path, arguments, timeout in
            try await partialRunner.run(path: path, arguments: arguments, timeout: timeout)
        }
    )
    do {
        _ = try await partialProvider.resolve(
            try SecretRef("op://Employee/Token/password"), unlock: nil
        )
        check(await partialRunner.invocations().last?.arguments == [
            "read", "--no-newline", "op://Employee/Token/password",
        ], "an incomplete index falls back to the account-less read, never worse than before")
    } catch {
        check(false, "an unlistable account does not break resolution (\(error))")
    }
    let partialSummary = await partialProvider.statusSummary()
    check(partialSummary?.healthy == false
            && partialSummary?.detail.contains("1 account not authorized") == true,
          "csec status shows an account whose authorization has lapsed")

    // No account at all is a distinct, actionable state.
    let emptyRunner = FakeOnePasswordCommandRunner()
    await emptyRunner.setAccounts([], vaults: [:])
    let emptyProvider = OnePasswordProvider(
        cliPath: "/synthetic/op",
        configuration: configuration,
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

// The provider's notes must survive the whole way to what a person reads, on
// the Mac window and on the phone.
func onePasswordReviewNoteTests() {
    print("\n# provider review notes in the trusted surfaces")

    let references = [try! SecretRef("op://Employee/Slack/password")]
    let credential = PolicyReviewCredential(
        references: references,
        providerNotes: [
            ProviderReviewNote(label: "account", detail: "acme.1password.eu"),
            ProviderReviewNote(
                label: "",
                detail: "More than one signed-in account has a vault named “Employee”.",
                isWarning: true
            ),
        ]
    )
    let group = ReviewDisplay.referenceGroup(for: credential)
    check(group.subtitle == "1Password · vault “Employee”",
          "the vault subtitle is unchanged by provider notes")
    check(group.notes == ["account: acme.1password.eu"],
          "an ordinary note renders as a labeled line")
    check(group.warnings == ["More than one signed-in account has a vault named “Employee”."],
          "a provider warning is kept separate from ordinary context, and unlabeled")

    // Notes are attacker-influenced metadata (a vault name reaches them), so the
    // window sanitizes them exactly like every other dynamic review string.
    let hostile = ReviewDisplay.referenceGroup(
        for: references,
        providerNotes: [ProviderReviewNote(label: "account", detail: "evil\u{202E}corp\nnew")]
    )
    check(hostile.notes.first?.contains("\u{202E}") == false
            && hostile.notes.first?.contains("\n") == false,
          "note text is stripped of bidi and newline controls before display")

    check(ReviewDisplay.bounded("abcdef", maxBytes: 4) == "abc…",
          "bounded trims to the byte budget")
    check(ReviewDisplay.bounded("ab", maxBytes: 64) == "ab",
          "bounded leaves text inside the budget untouched")

    // Without notes the group is exactly what it was before, so every existing
    // review surface is unaffected.
    check(ReviewDisplay.referenceGroup(for: references).notes.isEmpty,
          "a credential with no provider notes renders no extra lines")
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
