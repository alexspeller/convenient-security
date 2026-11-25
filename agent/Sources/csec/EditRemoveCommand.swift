import ConvenientSecurity
import Foundation

// MARK: - csec edit --remove

/// `csec edit --remove <csec://STORE/KEY>…`: delete whole-file values from one
/// native store behind one Touch ID in csecd's settings panel, which names
/// each of them. csecd refuses a value its SSH agent, GitHub socket or an
/// automation job uses, or whose sidecar is still where the file was
/// protected from; the panel is the one confirmation.
func runEditRemove(_ arguments: [String]) -> Never {
    guard !arguments.isEmpty, !arguments.contains(where: { $0.hasPrefix("-") }) else { usage("edit") }
    var references: [NativeSecretReference] = []
    for argument in arguments {
        let reference: SecretRef
        do {
            reference = try SecretRef(argument)
        } catch {
            editRemoveFail("invalid reference: \(error)")
        }
        guard reference.scheme == "csec", let native = try? NativeSecretReference(reference) else {
            editRemoveFail("\(reference.safeInlineURI) is not a csec://STORE/KEY reference; "
                + "--remove deletes only values csec stores itself")
        }
        if !references.contains(native) { references.append(native) }
    }
    guard Set(references.map(\.store.value)).count == 1 else {
        editRemoveFail("name values in one store at a time; nothing was removed")
    }
    guard references.count <= NativeStoreRemovalRequest.maximumReferences else {
        editRemoveFail("remove at most \(NativeStoreRemovalRequest.maximumReferences) values at a time, "
            + "so the Touch ID panel can name each one; nothing was removed")
    }

    let client = makeAgentClient()
    do {
        guard try client.capabilities().features.contains(.nativeEncryptedStore) else {
            editRemoveFail("the running agent does not provide the native encrypted store")
        }
    } catch {
        editRemoveFail("cannot reach the trusted agent")
    }

    let reply: NativeStoreRemovalReply
    do {
        reply = try client.removeNativeValues(NativeStoreRemovalRequest(references: references.map(\.uri)))
    } catch AgentClient.ClientError.protocolFailure(_, let message) {
        editRemoveFail(message)
    } catch {
        editRemoveFail(error.localizedDescription)
    }
    for removed in reply.removed {
        let reference = (try? SecretRef(removed.reference))?.safeInlineURI ?? "a stored value"
        print("csec edit: deleted \(reference) (protected from \(ReviewDisplay.sanitized(removed.path)))")
    }
    if reply.revokedGrants > 0 {
        print("csec edit: revoked \(reply.revokedGrants) grant\(reply.revokedGrants == 1 ? "" : "s") that covered "
            + (reply.removed.count == 1 ? "it" : "them"))
    }
    exit(0)
}

private func editRemoveFail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("csec edit: \(message)\n".utf8))
    exit(1)
}
