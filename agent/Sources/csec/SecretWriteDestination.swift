import ConvenientSecurity
import Foundation
import OnePasswordAdapter

/// Where `csec protect --env` and `csec edit <reference>` write secret values.
/// `commit` is the safety gate for in-place env rewrites: it returns only once
/// every value is durably stored at the destination, and a throw means the
/// caller must leave the plaintext file untouched.
protocol SecretWriteDestination {
    /// Write `values` (variable name -> plaintext) to the destination and
    /// return variable name -> reference URI for every written value.
    func commit(values: [String: String]) throws -> [String: String]
    /// Value-free one-line description for prompts and reports.
    var summaryLine: String { get }
}

enum SecretWriteDestinationError: Error, LocalizedError {
    case onePasswordCLIUnavailable
    case onePasswordFailed(operation: String, detail: String)
    case onePasswordVaultNotFound(vault: String, accounts: [String])
    case onePasswordAccountUndecidable(vault: String, accounts: [String])

    var errorDescription: String? {
        switch self {
        case .onePasswordCLIUnavailable:
            return "the 1Password CLI (op) was not found or does not satisfy the signing requirement"
        case .onePasswordFailed(let operation, let detail):
            return "op \(operation) failed: \(detail)"
        case let .onePasswordVaultNotFound(vault, accounts):
            return "no signed-in 1Password account has vault \"\(vault)\""
                + " (searched \(accounts.joined(separator: ", ")))"
        case let .onePasswordAccountUndecidable(vault, accounts):
            return "vault \"\(vault)\" exists in more than one signed-in 1Password account"
                + " (\(accounts.joined(separator: ", "))); rerun on a terminal to choose one,"
                + " or name the vault by its unique id in --dest"
        }
    }
}

/// Builds the concrete destination for a parsed spec. The 1Password CLI is
/// located (and signature-verified) only when the user actually chose op.
func makeSecretWriteDestination(
    spec: SecretDestinationSpec, client: @autoclosure () -> AgentClient
) throws -> SecretWriteDestination {
    switch spec {
    case .native(let store):
        return NativeStoreWriteDestination(client: client(), store: store)
    case .onePassword(let vault, let item):
        guard let cliPath = OnePasswordCLI.locate() else {
            throw SecretWriteDestinationError.onePasswordCLIUnavailable
        }
        return OnePasswordWriteDestination(
            cliPath: cliPath,
            account: try selectOnePasswordAccount(cliPath: cliPath, vault: vault, item: item),
            vault: vault,
            itemTitle: item,
            client: client()
        )
    }
}

/// After a value is (re)written, ask csecd to drop any cached resolution for the
/// affected references so a later resolve returns the new value instead of a
/// stale cache hit. A 1Password rotation done through `op` never reaches csecd,
/// which would otherwise serve the pre-rotation value for up to 24h. Best-effort:
/// the value is already durably stored, so a failure here is only a convenience
/// regression (possible staleness until the cache entry expires), never a reason
/// to fail the write. Reveals no value and raises no Touch ID.
func invalidateResolvedCache(for references: [String], client: AgentClient) {
    guard !references.isEmpty else { return }
    do {
        try client.invalidateCachedReferences(references)
    } catch {
        FileHandle.standardError.write(Data(
            ("csec: note: could not refresh the agent's resolution cache; a running "
             + "agent may serve the previous value until it expires "
             + "(\(error.localizedDescription))\n").utf8))
    }
}

/// Which 1Password account a write goes to. A vault name is unique only inside
/// one account, so with several signed in this must be decided before anything
/// is written — `op`'s own default can point at a different organization
/// entirely, and an item created there is a real secret in the wrong place.
///
/// One candidate is not a choice, so it is used (and shown in the confirmation).
/// More than one is a choice, so it is asked, never assumed; without a terminal
/// to ask on, the write fails instead.
private func selectOnePasswordAccount(
    cliPath: String, vault: String, item: String
) throws -> OnePasswordAccount? {
    Prompt.note("Checking which 1Password account owns vault “\(vault)”…")
    let index = try OnePasswordAccountDirectory.buildIndex(cliPath: cliPath)
    let selection = OnePasswordAccountDirectory.select(
        vault: vault,
        item: item,
        in: index,
        itemIdentities: {
            OnePasswordAccountDirectory.itemIdentities(cliPath: cliPath, candidate: $0)
        }
    )
    switch selection {
    case .unique(let candidate):
        return candidate.account
    case .notFound(let searched):
        throw SecretWriteDestinationError.onePasswordVaultNotFound(
            vault: vault, accounts: searched.map(\.label)
        )
    case .indeterminate:
        // An account could not be listed, so its vaults are unknown. Let `op`
        // resolve the vault itself rather than claiming knowledge we lack.
        return nil
    case .ambiguous(let candidates):
        guard let chosen = promptForOnePasswordAccount(vault: vault, candidates: candidates)
        else {
            throw SecretWriteDestinationError.onePasswordAccountUndecidable(
                vault: vault, accounts: candidates.map(\.account.label)
            )
        }
        return chosen.account
    }
}

/// Numbered cooked-mode prompt on stderr, matching the other `csec protect`
/// prompts. Returns nil when there is no terminal to ask on.
private func promptForOnePasswordAccount(
    vault: String, candidates: [OnePasswordVaultCandidate]
) -> OnePasswordVaultCandidate? {
    guard isatty(STDIN_FILENO) == 1, isatty(STDERR_FILENO) == 1 else { return nil }
    Prompt.warn("More than one signed-in 1Password account has a vault named “\(vault)”.")
    for (offset, candidate) in candidates.enumerated() {
        let row = "  \(offset + 1)) \(candidate.account.label) · \(candidate.account.email)"
            + " · vault id \(candidate.vault.id)\n"
        FileHandle.standardError.write(Data(row.utf8))
    }
    for _ in 0..<3 {
        FileHandle.standardError.write(Data(
            "Write to which account? [1-\(candidates.count)]: ".utf8))
        guard let line = readLine(strippingNewline: true) else { return nil }
        if let choice = Int(line.trimmingCharacters(in: .whitespaces)),
           choice >= 1, choice <= candidates.count {
            return candidates[choice - 1]
        }
        FileHandle.standardError.write(Data("  enter a number from the list\n".utf8))
    }
    return nil
}

/// Document-tier import into the native encrypted store: one Touch ID for the
/// whole batch (the begin/merge/commit session pattern proven by `csec setup
/// --import`). Existing keys are overwritten — the user explicitly selected
/// each variable.
struct NativeStoreWriteDestination: SecretWriteDestination {
    let client: AgentClient
    let store: NativeStoreName

    var summaryLine: String { "the csec native store (csec://\(store.value))" }

    func commit(values: [String: String]) throws -> [String: String] {
        let edit = try client.beginNativeStoreEdit(store: store.value, mode: .onboardingImport)
        do {
            let document = try NativeStoreImport.merge(
                existingDocument: edit.document,
                selectedValues: values,
                replaceExisting: true
            )
            _ = try client.commitNativeStoreEdit(sessionID: edit.sessionID, document: document)
        } catch {
            client.cancelNativeStoreEdit(sessionID: edit.sessionID)
            throw error
        }
        var references: [String: String] = [:]
        for name in values.keys {
            references[name] = try NativeSecretReference(store: store, key: name).uri
        }
        invalidateResolvedCache(for: Array(references.values), client: client)
        return references
    }
}

/// One item per project in 1Password, one concealed field per variable.
/// CLI-direct: the trust-gated `op` binary is invoked from this process, and
/// 1Password's own desktop-app authorization gates the write. Values travel
/// exclusively via stdin JSON templates — never argv.
struct OnePasswordWriteDestination: SecretWriteDestination {
    let cliPath: String
    /// The account this write lands in, chosen before anything is written. Nil
    /// only when the account index was incomplete, leaving the choice to `op`.
    let account: OnePasswordAccount?
    let vault: String
    let itemTitle: String
    let client: AgentClient

    var summaryLine: String {
        let target = "1Password (op://\(vault)/\(itemTitle))"
        guard let account else { return target }
        return "\(target) in \(account.label)"
    }

    func commit(values: [String: String]) throws -> [String: String] {
        let fields = values.sorted { $0.key < $1.key }
            .map { OnePasswordItemWrite.Field(label: $0.key, value: $0.value) }

        let existing = try OnePasswordCLI.runSync(
            cliPath,
            OnePasswordItemWrite.getItemArguments(
                title: itemTitle, vault: vault, account: account
            ))
        if existing.status == 0 {
            let updated = try OnePasswordItemWrite.updatedItemJSON(
                existingItem: existing.stdout, fields: fields)
            // Edit by the item's unique id so a rename between get and edit
            // can't retarget the write.
            let itemID = (try? JSONSerialization.jsonObject(with: existing.stdout)
                as? [String: Any])?["id"] as? String ?? itemTitle
            let edit = try OnePasswordCLI.runSync(
                cliPath,
                OnePasswordItemWrite.editArguments(itemID: itemID, account: account),
                stdin: updated)
            guard edit.status == 0 else {
                throw SecretWriteDestinationError.onePasswordFailed(
                    operation: "item edit", detail: Self.detailLine(edit.stderr))
            }
        } else {
            let template = try OnePasswordItemWrite.createTemplate(title: itemTitle, fields: fields)
            let create = try OnePasswordCLI.runSync(
                cliPath,
                OnePasswordItemWrite.createArguments(vault: vault, account: account),
                stdin: template)
            guard create.status == 0 else {
                throw SecretWriteDestinationError.onePasswordFailed(
                    operation: "item create", detail: Self.detailLine(create.stderr))
            }
        }

        var references: [String: String] = [:]
        for name in values.keys {
            references[name] = OnePasswordItemWrite.reference(
                vault: vault, title: itemTitle, field: name)
        }
        invalidateResolvedCache(for: Array(references.values), client: client)
        return references
    }

    /// op's stderr is an error message (metadata), but neutralize terminal
    /// controls and bound the length before echoing it.
    private static func detailLine(_ stderr: Data) -> String {
        let text = String(data: stderr, encoding: .utf8) ?? "unreadable op error"
        let firstLine = text.split(separator: "\n").first.map(String.init) ?? "no error output"
        return ReviewDisplay.sanitized(String(firstLine.prefix(200)))
    }
}
