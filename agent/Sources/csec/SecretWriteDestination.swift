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

    var errorDescription: String? {
        switch self {
        case .onePasswordCLIUnavailable:
            return "the 1Password CLI (op) was not found or does not satisfy the signing requirement"
        case .onePasswordFailed(let operation, let detail):
            return "op \(operation) failed: \(detail)"
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
            cliPath: cliPath, vault: vault, itemTitle: item, client: client())
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
    let vault: String
    let itemTitle: String
    let client: AgentClient

    var summaryLine: String { "1Password (op://\(vault)/\(itemTitle))" }

    func commit(values: [String: String]) throws -> [String: String] {
        let fields = values.sorted { $0.key < $1.key }
            .map { OnePasswordItemWrite.Field(label: $0.key, value: $0.value) }

        let existing = try OnePasswordCLI.runSync(
            cliPath, OnePasswordItemWrite.getItemArguments(title: itemTitle, vault: vault))
        if existing.status == 0 {
            let updated = try OnePasswordItemWrite.updatedItemJSON(
                existingItem: existing.stdout, fields: fields)
            // Edit by the item's unique id so a rename between get and edit
            // can't retarget the write.
            let itemID = (try? JSONSerialization.jsonObject(with: existing.stdout)
                as? [String: Any])?["id"] as? String ?? itemTitle
            let edit = try OnePasswordCLI.runSync(
                cliPath, OnePasswordItemWrite.editArguments(itemID: itemID), stdin: updated)
            guard edit.status == 0 else {
                throw SecretWriteDestinationError.onePasswordFailed(
                    operation: "item edit", detail: Self.detailLine(edit.stderr))
            }
        } else {
            let template = try OnePasswordItemWrite.createTemplate(title: itemTitle, fields: fields)
            let create = try OnePasswordCLI.runSync(
                cliPath, OnePasswordItemWrite.createArguments(vault: vault), stdin: template)
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
