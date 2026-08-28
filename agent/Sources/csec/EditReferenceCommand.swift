import ConvenientSecurity
import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// `csec edit <reference>` — set one secret's value after import, without
/// opening the whole store document.
///
/// The new value is captured either from a hidden terminal prompt (nothing is
/// echoed; entered twice to catch typos) or, when stdin is not a terminal,
/// read from stdin to EOF with exactly one trailing newline stripped — so
/// `printf %s new-value | csec edit csec://store/KEY` and
/// `csec edit op://Vault/item/FIELD < value.txt` both work. The value never
/// appears in argv, on screen, or in any output.
///
/// `csec://store/KEY` commits through the native-store edit session (one Touch
/// ID); a key that does not exist yet is created. `op://VAULT/ITEM/FIELD`
/// writes through the trust-gated `op` CLI (1Password's own authorization
/// gates it), with the value travelling via a stdin JSON template.
func runEditReference(_ uri: String) -> Never {
    let reference: SecretRef
    do {
        reference = try SecretRef(uri)
    } catch {
        editReferenceFail("invalid reference: \(error)")
    }

    let spec: SecretDestinationSpec
    let key: String
    switch reference.scheme {
    case "csec":
        let native: NativeSecretReference
        do {
            native = try NativeSecretReference(reference)
        } catch {
            editReferenceFail("invalid csec reference (expected csec://STORE/KEY): \(error.localizedDescription)")
        }
        spec = .native(native.store)
        key = native.key
    case "op":
        let components = reference.path
            .split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard components.count == 3,
              SecretDestinationSpec.isValidOnePasswordComponent(components[0]),
              SecretDestinationSpec.isValidOnePasswordComponent(components[1]),
              SecretDestinationSpec.isValidOnePasswordComponent(components[2]) else {
            editReferenceFail("an op reference needs the form op://VAULT/ITEM/FIELD")
        }
        spec = .onePassword(vault: components[0], item: components[1])
        key = components[2]
    default:
        editReferenceFail("unsupported reference scheme \"\(reference.scheme)\" (use csec:// or op://)")
    }

    if case .native = spec {
        let client = makeAgentClient()
        do {
            guard try client.capabilities().features.contains(.nativeEncryptedStore) else {
                editReferenceFail("the running agent does not provide the native encrypted store")
            }
        } catch {
            editReferenceFail("cannot reach the trusted agent")
        }
    }

    let maximumValueBytes = NativeStoreDocument.maximumBytes
    let value: String
    if isatty(STDIN_FILENO) == 1 {
        guard isatty(STDERR_FILENO) == 1 else {
            editReferenceFail("needs an interactive terminal (or pipe the new value on stdin)")
        }
        // Raw mode (echo off) before the prompt, so nothing typed can be
        // echoed even if input starts arriving the moment the prompt shows.
        guard let raw = TerminalRawMode() else {
            editReferenceFail("could not configure the terminal")
        }
        FileHandle.standardError.write(Data(
            "New value for \(reference.safeInlineURI) (input hidden): ".utf8))
        guard let first = raw.readHiddenLine(maxBytes: maximumValueBytes) else {
            raw.restore()
            editReferenceFail("cancelled; nothing changed")
        }
        FileHandle.standardError.write(Data("Confirm value (input hidden): ".utf8))
        guard let second = raw.readHiddenLine(maxBytes: maximumValueBytes) else {
            raw.restore()
            editReferenceFail("cancelled; nothing changed")
        }
        raw.restore()
        guard first == second else {
            editReferenceFail("the two entries did not match; nothing changed")
        }
        guard let text = String(data: first, encoding: .utf8) else {
            editReferenceFail("the value is not UTF-8 text")
        }
        value = text
    } else {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard data.count <= maximumValueBytes else {
            editReferenceFail("the value exceeds \(maximumValueBytes) bytes")
        }
        var bytes = [UInt8](data)
        if bytes.last == 0x0A {
            bytes.removeLast()
            if bytes.last == 0x0D { bytes.removeLast() }
        }
        guard !bytes.contains(0), let text = String(bytes: bytes, encoding: .utf8) else {
            editReferenceFail("the value on stdin is not UTF-8 text")
        }
        value = text
    }
    guard !value.isEmpty else {
        editReferenceFail("the new value is empty; nothing changed (use `csec edit <store>` to remove keys)")
    }

    let destination: SecretWriteDestination
    do {
        destination = try makeSecretWriteDestination(spec: spec, client: makeAgentClient())
    } catch {
        editReferenceFail(error.localizedDescription)
    }

    do {
        let references = try destination.commit(values: [key: value])
        print("csec edit: updated \(references[key] ?? reference.safeInlineURI)")
        exit(0)
    } catch {
        editReferenceFail("\(error.localizedDescription); nothing changed")
    }
}

private func editReferenceFail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("csec edit: \(message)\n".utf8))
    exit(1)
}
