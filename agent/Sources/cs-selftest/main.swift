import Foundation
import ConvenientSecurity
import OnePasswordAdapter
import LocalAuthentication
import CSecuritySupport
import CSECRootServer
import Darwin

// Framework-free self-checks for the provider-agnostic core, runnable anywhere
// (`swift run cs-selftest`) without XCTest or full Xcode. Exits non-zero on any
// failure. Richer suites can move to swift-testing once a full toolchain is
// standard across dev + CI.

var failures = 0

func check(_ condition: Bool, _ label: String) {
    if condition {
        print("ok   - \(label)")
    } else {
        print("FAIL - \(label)")
        failures += 1
    }
}

func checkThrows(_ label: String, _ body: () throws -> Void) {
    do {
        try body()
        print("FAIL - \(label) (expected a throw)")
        failures += 1
    } catch {
        print("ok   - \(label) (threw \(error))")
    }
}

func syntheticProtectedLaunchPlan(
    files: [ProtectedFileBinding],
    environment: [String: String] = ["PATH": "/usr/bin:/bin"],
    commandLine: [String] = ["/bin/sh", "-c", "exit 0"],
    hardTTL: Bool = false
) throws -> ProtectedLaunchPlan {
    let executable = PlannedExecutable(
        canonicalPath: "/bin/sh",
        assurance: .independentlyProtected
    )
    let delivery = DeliveryPlan(
        mechanism: .capabilityGIDFile,
        executable: executable,
        root: .caller,
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 300,
        operationContext: "synthetic protected-file self-test",
        commandDigest: try ExecutableInspection.commandDigest(commandLine),
        outputGuard: OutputGuardPlan(mode: .always)
    )
    return ProtectedLaunchPlan(
        launcherPID: getpid(),
        launcherStartTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
        uid: getuid(),
        auditSessionID: cs_self_audit_session_id(),
        executable: executable,
        commandLine: commandLine,
        environment: environment,
        files: files,
        deliveryPlan: delivery,
        hardTTL: hardTTL
    )
}

/// In-memory stand-in for the data-protection keychain. Shared between two
/// `KeychainSecretCache` instances it models the keychain surviving an agent
/// restart (persistent store, empty warm tier). Counts backend touches so a test
/// can assert the cache never consults it — i.e. never raises a biometric —
/// without a consent context.
actor FakeKeychainBackend: KeychainBackend {
    private var items: [String: Data] = [:]
    private(set) var loadCount = 0

    func store(account: String, data: Data) async throws {
        items[account] = data
    }

    func load(account: String, unlock: CacheUnlock?) async throws -> Data? {
        loadCount += 1
        return items[account]
    }

    func delete(account: String) async {
        items[account] = nil
    }

    func has(_ account: String) -> Bool {
        items[account] != nil
    }
}

print("# SecretRef")

// SecretRef: canonical URI parsing + scheme dispatch.
if let ref = try? SecretRef("op://Private/Database Server/credential") {
    check(ref.scheme == "op", "op scheme parsed")
    check(ref.path == "Private/Database Server/credential", "path is the opaque remainder")
    check(ref.uri == "op://Private/Database Server/credential", "canonical uri preserved")
} else {
    check(false, "a valid op:// reference parses")
}

check((try? SecretRef("OP://vault/item/field"))?.scheme == "op", "scheme is lowercased")
check((try? SecretRef("op://vault/item/section/field"))?.path == "vault/item/section/field",
      "multi-segment path stays opaque to the core")

checkThrows("missing :// is rejected") { _ = try SecretRef("op:/vault/item") }
checkThrows("empty scheme is rejected") { _ = try SecretRef("://vault/item") }
checkThrows("empty path is rejected") { _ = try SecretRef("op://") }
checkThrows("scheme starting with a digit is rejected") { _ = try SecretRef("1password://vault/item") }
if let spoofed = try? SecretRef("op://vault/item/field\nforged prompt\u{202e}") {
    let display = spoofed.displayString
    check(display.filter { $0 == "\n" }.count == 2
          && display.contains("field�forged prompt�"),
          "reference control and bidi characters cannot add or reorder consent lines")
} else {
    check(false, "synthetic control-character reference parses for display sanitization test")
}

print("\n# NativeEncryptedFileProvider (strict JSON + authenticated ciphertext)")

check((try? NativeStoreName("development_1"))?.value == "development_1",
      "native store names use one path-safe component")
checkThrows("native store traversal is rejected") { _ = try NativeStoreName("../private") }
checkThrows("native reference requires exactly store/key") {
    _ = try NativeSecretReference(try SecretRef("csec://development/nested/key"))
}
if let nativeRef = try? SecretRef("csec://development/DATABASE_URL"),
   let parsed = try? NativeSecretReference(nativeRef) {
    check(parsed.store.value == "development" && parsed.key == "DATABASE_URL",
          "csec reference selects one store and key")
    check(nativeRef.displayString == "native store: development\nkey: DATABASE_URL",
          "native references have an explicit consent display")
} else {
    check(false, "valid csec reference parses")
}

do {
    let document = try NativeStoreDocument(data: Data(#"{"TOKEN":"line\nvalue","URL":"https://example.test"}"#.utf8))
    check(document.values["TOKEN"] == "line\nvalue",
          "strict JSON decodes explicit string escapes")
    check(document.values["URL"] == "https://example.test",
          "strict JSON preserves explicit string values")
    let canonical = String(data: try document.encoded(), encoding: .utf8) ?? ""
    check(canonical.hasSuffix("\n")
          && canonical.range(of: "\"TOKEN\"")!.lowerBound
             < canonical.range(of: "\"URL\"")!.lowerBound,
          "native store JSON is normalized with sorted keys")
} catch {
    check(false, "valid native-store JSON parses (\(error))")
}
checkThrows("duplicate JSON keys are rejected before dictionary collapse") {
    _ = try NativeStoreDocument(data: Data(#"{"TOKEN":"one","TOKEN":"two"}"#.utf8))
}
checkThrows("escaped duplicate JSON keys are rejected after decoding") {
    _ = try NativeStoreDocument(data: Data(#"{"TOKEN":"one","\u0054OKEN":"two"}"#.utf8))
}
checkThrows("non-string JSON values are rejected") {
    _ = try NativeStoreDocument(data: Data(#"{"TOKEN":123}"#.utf8))
}
checkThrows("nested JSON values are rejected") {
    _ = try NativeStoreDocument(data: Data(#"{"TOKEN":{"nested":"value"}}"#.utf8))
}
checkThrows("reference-unsafe JSON keys are rejected") {
    _ = try NativeStoreDocument(data: Data(#"{"nested/key":"value"}"#.utf8))
}
checkThrows("native store documents enforce the 1024-secret bound") {
    _ = try NativeStoreDocument(values: Dictionary(uniqueKeysWithValues: (0...1024).map {
        ("KEY_\($0)", "value")
    }))
}
checkThrows("native store documents enforce the 1 MiB canonical bound") {
    _ = try NativeStoreDocument(values: ["TOKEN": String(repeating: "x", count: 1024 * 1024)])
}

print("\n# ExternalEditorCommand")

do {
    let command = try ExternalEditorCommand(
        editorValue: #"/bin/cp --force 'path with spaces' escaped\ value "$HOME" '$(touch /tmp/not-run)'"#,
        environment: ["PATH": "/usr/bin:/bin"]
    )
    check(command.executablePath.hasSuffix("/cp"),
          "$EDITOR resolves its executable without a shell")
    check(command.arguments == [
        "--force", "path with spaces", "escaped value", "$HOME", "$(touch /tmp/not-run)",
    ], "$EDITOR supports quoted argv while preserving expansion syntax literally")
} catch {
    check(false, "a bounded quoted $EDITOR command parses (\(error))")
}

let editorExpansionMarker = NSTemporaryDirectory()
    + "csec-editor-command-substitution-\(getpid())"
try? FileManager.default.removeItem(atPath: editorExpansionMarker)
do {
    _ = try ExternalEditorCommand(
        editorValue: "/bin/echo $(/usr/bin/touch \(editorExpansionMarker))",
        environment: ["PATH": "/usr/bin:/bin"]
    )
    check(!FileManager.default.fileExists(atPath: editorExpansionMarker),
          "$EDITOR parsing never evaluates command substitutions")
} catch {
    check(false, "$EDITOR metacharacters remain inert during parsing (\(error))")
}
checkThrows("an unset $EDITOR is rejected before editing") {
    _ = try ExternalEditorCommand(environment: ["PATH": "/usr/bin:/bin"])
}
checkThrows("an unterminated $EDITOR quote is rejected") {
    _ = try ExternalEditorCommand(
        editorValue: #"/bin/echo 'unterminated"#,
        environment: ["PATH": "/usr/bin:/bin"]
    )
}

let nativeUnlock = CacheUnlock(LAContext()) // in-memory backend only; never prompts
do {
    let keyBackend = InMemoryNativeStoreKeyBackend()
    let fileBackend = InMemoryNativeStoreFileBackend()
    let provider = NativeEncryptedFileProvider(
        keyBackend: keyBackend,
        fileBackend: fileBackend
    )
    let store = try NativeStoreName("development")
    let callerPID = getpid()
    let callerStart = ProcessAncestry.startTime(of: callerPID) ?? 1

    do {
        _ = try await provider.beginEdit(
            store: store,
            callerPID: callerPID,
            callerStartTime: callerStart,
            unlock: nil
        )
        check(false, "a cold native-store edit without biometric context is rejected")
    } catch NativeStoreError.authenticationRequired {
        check(true, "a cold native-store edit without biometric context is rejected")
    }

    let edit = try await provider.beginEdit(
        store: store,
        callerPID: callerPID,
        callerStartTime: callerStart,
        unlock: nativeUnlock
    )
    check((try? NativeStoreDocument(data: edit.document).values.isEmpty) == true,
          "first edit opens a new empty store")
    let firstDocument = Data(#"{"DATABASE_URL":"native-postgres-secret","TOKEN":"native-token-value"}"#.utf8)
    do {
        _ = try await provider.commitEdit(
            sessionID: edit.sessionID,
            document: firstDocument,
            callerPID: callerPID,
            callerStartTime: callerStart + 1
        )
        check(false, "a native edit session rejects a different process incarnation")
    } catch NativeStoreError.editSessionExpired {
        check(true, "a native edit session rejects a different process incarnation")
    }
    let firstCommit = try await provider.commitEdit(
        sessionID: edit.sessionID,
        document: firstDocument,
        callerPID: callerPID,
        callerStartTime: callerStart
    )
    check(firstCommit.generation == 1 && firstCommit.secretCount == 2,
          "first save commits one version with the validated secret count")

    let firstFiles = await fileBackend.snapshot()
    let firstCiphertext = firstFiles.values.first ?? Data()
    check(firstFiles.count == 1 && firstFiles.keys.first?.hasSuffix(".csec") == true,
          "one opaque versioned ciphertext file backs the logical store")
    check(firstCiphertext.starts(with: Data("CSECSTR1".utf8))
          && firstCiphertext.range(of: Data("native-postgres-secret".utf8)) == nil
          && firstCiphertext.range(of: Data("native-token-value".utf8)) == nil,
          "AES-GCM envelope contains no plaintext secret bytes")
    let firstRecord = await keyBackend.record(for: store.value)
    check(firstRecord?.generation == 1
          && firstRecord?.keyData.count == 32
          && firstRecord?.ciphertextDigest?.count == 64,
          "biometric key record binds the active generation and ciphertext digest")

    let expiryOrigin = Date(timeIntervalSince1970: 1_000)
    let expiringEdit = try await provider.beginEdit(
        store: store,
        callerPID: callerPID,
        callerStartTime: callerStart,
        unlock: nativeUnlock,
        authorizedTTL: 60,
        now: expiryOrigin
    )
    do {
        _ = try await provider.commitEdit(
            sessionID: expiringEdit.sessionID,
            document: firstDocument,
            callerPID: callerPID,
            callerStartTime: callerStart,
            now: expiryOrigin.addingTimeInterval(61)
        )
        check(false, "a native edit session expires at its shorter policy authorization")
    } catch NativeStoreError.editSessionExpired {
        check(true, "a native edit session expires at its shorter policy authorization")
    }

    let ref = try SecretRef("csec://development/DATABASE_URL")
    let warm = try await provider.resolve(ref, unlock: nil)
    check(warm.value == Data("native-postgres-secret".utf8) && warm.cacheHint == .noCache,
          "a warmed provider serves an already-granted reference without persistent value caching")

    let afterRestart = NativeEncryptedFileProvider(
        keyBackend: keyBackend,
        fileBackend: fileBackend
    )
    do {
        _ = try await afterRestart.resolve(ref, unlock: nil)
        check(false, "a restarted provider cannot cold-decrypt without biometric context")
    } catch NativeStoreError.authenticationRequired {
        check(true, "a restarted provider cannot cold-decrypt without biometric context")
    }
    check(try await afterRestart.resolve(ref, unlock: nativeUnlock).value == Data("native-postgres-secret".utf8),
          "a biometric context unlocks the durable per-store key after restart")

    let concurrentA = try await afterRestart.beginEdit(
        store: store,
        callerPID: callerPID,
        callerStartTime: callerStart,
        unlock: nativeUnlock
    )
    let concurrentB = try await afterRestart.beginEdit(
        store: store,
        callerPID: callerPID,
        callerStartTime: callerStart,
        unlock: nativeUnlock
    )
    let rotatedDocument = Data(#"{"DATABASE_URL":"rotated-native-secret","TOKEN":"native-token-value"}"#.utf8)
    let secondCommit = try await afterRestart.commitEdit(
        sessionID: concurrentA.sessionID,
        document: rotatedDocument,
        callerPID: callerPID,
        callerStartTime: callerStart
    )
    check(secondCommit.generation == 2, "an edit advances the authenticated generation")
    do {
        _ = try await afterRestart.commitEdit(
            sessionID: concurrentB.sessionID,
            document: rotatedDocument,
            callerPID: callerPID,
            callerStartTime: callerStart
        )
        check(false, "a concurrent stale editor cannot overwrite a newer generation")
    } catch NativeStoreError.editConflict {
        check(true, "a concurrent stale editor cannot overwrite a newer generation")
    }

    let secondFiles = await fileBackend.snapshot()
    check(secondFiles.count == 1 && Set(secondFiles.keys) != Set(firstFiles.keys),
          "committing switches to a fresh immutable file and removes the old version")
    if let activeName = secondFiles.keys.first, var tampered = secondFiles[activeName] {
        tampered[tampered.index(before: tampered.endIndex)] ^= 0x01
        await fileBackend.replace(named: activeName, data: tampered)
        do {
            _ = try await afterRestart.resolve(ref, unlock: nil)
            check(false, "ciphertext modification is rejected before a value is returned")
        } catch NativeStoreError.integrityFailure {
            check(true, "ciphertext modification is rejected before a value is returned")
        }
        // Replacing the active filename with a previously valid older envelope
        // also fails because the keychain record pins its digest/generation.
        await fileBackend.replace(named: activeName, data: firstCiphertext)
        do {
            _ = try await afterRestart.resolve(ref, unlock: nil)
            check(false, "an older valid ciphertext cannot be replayed as the active store")
        } catch NativeStoreError.integrityFailure {
            check(true, "an older valid ciphertext cannot be replayed as the active store")
        }
    } else {
        check(false, "active ciphertext is available for tamper tests")
    }
} catch {
    check(false, "native encrypted-store checks succeed (\(error))")
}

print("\n# NativeBlobStore (per-blob envelopes + pinned index)")
do {
    check((try? NativeSecretReference(try SecretRef("csec://project/env_home")))?.key == "env_home",
          "a csec:// reference parses into store/key for either storage tier")
    checkThrows("a nested key is rejected") {
        _ = try NativeSecretReference(try SecretRef("csec://project/dir/key"))
    }

    let keyBackend = InMemoryNativeStoreKeyBackend()
    let fileBackend = InMemoryNativeStoreFileBackend()
    let blobs = NativeBlobStore(keyBackend: keyBackend, fileBackend: fileBackend)
    let store = try NativeStoreName("projectblobs")

    // Arbitrary-shell .envrc bytes plus a binary payload (NULs, high bytes) to
    // prove full-fidelity, format-agnostic storage.
    let envrc = "export FOO=bar\nPATH_add ./bin\nuse_flake\n"
    let envrcData = Data(envrc.utf8)
    let binaryData = Data([0x00, 0x01, 0xff, 0xfe, 0x0a, 0x00, 0x7f, 0x80])

    do {
        _ = try await blobs.putBlobs(
            store: store,
            requests: [.init(key: "envrc", data: envrcData, mode: 0o600, path: ".envrc")],
            unlock: nil
        )
        check(false, "a blob write without biometric context is rejected")
    } catch NativeStoreError.authenticationRequired {
        check(true, "a blob write without biometric context is rejected")
    }

    let firstGeneration = try await blobs.putBlobs(
        store: store,
        requests: [
            .init(key: "envrc", data: envrcData, mode: 0o600, path: ".envrc"),
            .init(key: "keyfile", data: binaryData, mode: 0o400, path: "config/master.key"),
        ],
        unlock: nativeUnlock
    )
    check(firstGeneration == 1, "the first batch commits one authenticated generation")

    let firstSnapshot = await fileBackend.snapshot()
    check(firstSnapshot.count == 3,
          "two blobs plus one index back the store as separate ciphertext files")
    check(firstSnapshot.values.allSatisfy { $0.range(of: envrcData) == nil && $0.range(of: binaryData) == nil },
          "no blob ciphertext contains plaintext bytes")

    let loadedEnvrc = try await blobs.loadBlob(
        store: store, key: "envrc", unlock: nativeUnlock)
    check(loadedEnvrc.data == envrcData && loadedEnvrc.mode == 0o600 && loadedEnvrc.path == ".envrc",
          "an .envrc blob round-trips with its exact bytes, mode, and path")
    let loadedBinary = try await blobs.loadBlob(
        store: store, key: "keyfile", unlock: nativeUnlock)
    check(loadedBinary.data == binaryData && loadedBinary.mode == 0o400,
          "a binary blob round-trips byte-for-byte")

    let listing = try await blobs.list(store: store, unlock: nativeUnlock)
    check(Set(listing.keys) == ["envrc", "keyfile"] && listing["keyfile"]?.size == binaryData.count,
          "the metadata-only listing exposes keys/size/path without values")

    // Capture the generation-1 index so a rollback replay can be attempted.
    let firstIndexName = firstSnapshot.keys.first { $0.hasSuffix(".index.csec") }!
    let firstIndexCiphertext = firstSnapshot[firstIndexName]!

    // Replacing one blob advances the generation and swaps immutable files.
    let secondGeneration = try await blobs.putBlobs(
        store: store,
        requests: [.init(key: "envrc", data: Data("export FOO=rotated\n".utf8), mode: 0o600, path: ".envrc")],
        unlock: nativeUnlock
    )
    check(secondGeneration == 2, "replacing a blob advances the authenticated generation")
    let secondSnapshot = await fileBackend.snapshot()
    check(secondSnapshot.count == 3 && !secondSnapshot.keys.contains(firstIndexName),
          "a replace removes the superseded index and blob file")
    check(try await blobs.loadBlob(store: store, key: "envrc", unlock: nativeUnlock)
            .data == Data("export FOO=rotated\n".utf8),
          "the rotated blob is served after replacement")

    // Restart: a fresh store instance over the same backends still serves.
    let afterRestart = NativeBlobStore(keyBackend: keyBackend, fileBackend: fileBackend)
    do {
        _ = try await afterRestart.loadBlob(store: store, key: "keyfile", unlock: nil)
        check(false, "a restarted blob store cannot cold-decrypt without biometric context")
    } catch NativeStoreError.authenticationRequired {
        check(true, "a restarted blob store cannot cold-decrypt without biometric context")
    }
    check(try await afterRestart.loadBlob(store: store, key: "keyfile", unlock: nativeUnlock)
            .data == binaryData,
          "a biometric context unlocks durable blobs after restart")

    // Tamper: flip a byte in a blob ciphertext -> integrity failure, never a value.
    let liveSnapshot = await fileBackend.snapshot()
    let blobFileName = liveSnapshot.keys.first { $0.hasSuffix(".blob.csec") }!
    var tamperedBlob = liveSnapshot[blobFileName]!
    tamperedBlob[tamperedBlob.index(before: tamperedBlob.endIndex)] ^= 0x01
    await fileBackend.replace(named: blobFileName, data: tamperedBlob)
    var tamperedKey = "envrc"
    // Determine which key the tampered blob belongs to by trying both.
    for candidate in ["envrc", "keyfile"] {
        if (try? await afterRestart.loadBlob(store: store, key: candidate, unlock: nativeUnlock)) == nil {
            tamperedKey = candidate
        }
    }
    do {
        _ = try await afterRestart.loadBlob(store: store, key: tamperedKey, unlock: nativeUnlock)
        check(false, "blob ciphertext modification is rejected before any bytes are returned")
    } catch NativeStoreError.integrityFailure {
        check(true, "blob ciphertext modification is rejected before any bytes are returned")
    }

    // Rollback: replace the active index with the older valid generation-1 index;
    // the keychain record pins the current digest/generation, so it fails closed.
    let activeIndexName = liveSnapshot.keys.first { $0.hasSuffix(".index.csec") }!
    await fileBackend.replace(named: activeIndexName, data: firstIndexCiphertext)
    let rollbackStore = NativeBlobStore(keyBackend: keyBackend, fileBackend: fileBackend)
    do {
        _ = try await rollbackStore.loadBlob(store: store, key: "keyfile", unlock: nativeUnlock)
        check(false, "an older valid index cannot be replayed as the active generation")
    } catch NativeStoreError.integrityFailure {
        check(true, "an older valid index cannot be replayed as the active generation")
    }
} catch {
    check(false, "native blob-store checks succeed (\(error))")
}

// A production filesystem backend with a raised cap round-trips a blob larger
// than the 1 MiB whole-document store limit, proving per-blob sizing.
do {
    let testDirectory = NSTemporaryDirectory()
        + "csec-blob-files-\(UUID().uuidString.lowercased())"
    defer { try? FileManager.default.removeItem(atPath: testDirectory) }
    let files = try SecureNativeStoreFileBackend(
        directoryPath: testDirectory,
        maximumCiphertextBytes: NativeBlobIndex.maximumIndexBytes + 1024
    )
    let blobs = NativeBlobStore(keyBackend: InMemoryNativeStoreKeyBackend(), fileBackend: files)
    let store = try NativeStoreName("bigblobs")
    let large = Data((0..<(1_500_000)).map { UInt8($0 & 0xff) })
    _ = try await blobs.putBlobs(
        store: store,
        requests: [.init(key: "cert", data: large, mode: 0o444, path: "certs/server.pem")],
        unlock: nativeUnlock
    )
    check(try await blobs.loadBlob(store: store, key: "cert", unlock: nativeUnlock).data == large,
          "a >1 MiB blob round-trips through the production ciphertext backend")
} catch {
    check(false, "large-blob filesystem backend check succeeds (\(error))")
}

// Unification: the `csec://` provider resolves a blob-tier value through the
// generic SecretProvider.resolve path. A path leads to a value — the storage
// tier is invisible at the reference, and binary bytes survive with full
// fidelity because the value primitive is Data.
do {
    let blobs = NativeBlobStore(
        keyBackend: InMemoryNativeStoreKeyBackend(),
        fileBackend: InMemoryNativeStoreFileBackend()
    )
    let provider = NativeEncryptedFileProvider(
        keyBackend: InMemoryNativeStoreKeyBackend(),
        fileBackend: InMemoryNativeStoreFileBackend(),
        blobStore: blobs
    )
    let store = try NativeStoreName("unified")
    let binary = Data([0x00, 0x01, 0xff, 0xfe, 0x0a, 0x7f, 0x80])
    _ = try await blobs.putBlobs(
        store: store,
        requests: [.init(key: "keyfile", data: binary, mode: 0o400, path: "config/master.key")],
        unlock: nativeUnlock
    )
    let resolved = try await provider.resolve(
        try SecretRef("csec://unified/keyfile"), unlock: nativeUnlock
    )
    check(resolved.value == binary && resolved.cacheHint == .noCache,
          "the csec:// provider resolves a blob-tier value to its exact bytes")
    do {
        _ = try await provider.resolve(try SecretRef("csec://unified/absent"), unlock: nativeUnlock)
        check(false, "a missing key in a store that exists is secretNotFound across both tiers")
    } catch NativeStoreError.secretNotFound {
        check(true, "a missing key in a store that exists is secretNotFound across both tiers")
    }
    do {
        _ = try await provider.resolve(try SecretRef("csec://nostore/key"), unlock: nativeUnlock)
        check(false, "an unknown store is storeNotFound across both tiers")
    } catch NativeStoreError.storeNotFound {
        check(true, "an unknown store is storeNotFound across both tiers")
    }
} catch {
    check(false, "unified csec:// provider blob resolution succeeds (\(error))")
}

// Whole-file import: a blob commits against an authorized edit session's unlock
// (one consent covers the batch), and cross-tier uniqueness holds both ways so a
// csec://store/key resolves to exactly one value.
do {
    let blobs = NativeBlobStore(
        keyBackend: InMemoryNativeStoreKeyBackend(),
        fileBackend: InMemoryNativeStoreFileBackend()
    )
    let provider = NativeEncryptedFileProvider(
        keyBackend: InMemoryNativeStoreKeyBackend(),
        fileBackend: InMemoryNativeStoreFileBackend(),
        blobStore: blobs
    )
    let store = try NativeStoreName("importtier")
    let callerPID: pid_t = 4242
    let callerStart: UInt64 = 999

    let importSession = try await provider.beginEdit(
        store: store, callerPID: callerPID, callerStartTime: callerStart, unlock: nativeUnlock)
    let envrc = Data("export A=1\nuse_flake\n".utf8)
    let commit = try await provider.commitBlobs(
        sessionID: importSession.sessionID,
        requests: [.init(key: "envrc", data: envrc, mode: 0o600, path: ".envrc")],
        callerPID: callerPID, callerStartTime: callerStart
    )
    check(commit.generation == 1 && commit.secretCount == 1,
          "a blob import through an authorized edit session commits one generation")
    let resolved = try await provider.resolve(
        try SecretRef("csec://importtier/envrc"), unlock: nativeUnlock)
    check(resolved.value == envrc,
          "an imported blob resolves via csec:// with exact bytes")

    // The blob-path binding for `*.csec` sidecars: after resolution unlocked the
    // store record, the recorded protect path is readable with no second unlock.
    check(await provider.recordedBlobPath(store: store, key: "envrc") == ".envrc",
          "a resolved blob's recorded protect path is readable (reusing the unlocked record)")
    check(await provider.recordedBlobPath(store: store, key: "absent") == nil,
          "an unknown blob key has no recorded path")

    // A document commit may not shadow an existing blob key.
    let shadowSession = try await provider.beginEdit(
        store: store, callerPID: callerPID, callerStartTime: callerStart, unlock: nativeUnlock)
    do {
        _ = try await provider.commitEdit(
            sessionID: shadowSession.sessionID,
            document: Data(#"{"envrc":"shadow"}"#.utf8),
            callerPID: callerPID, callerStartTime: callerStart)
        check(false, "a document key cannot shadow an existing blob key")
    } catch NativeStoreError.crossTierKeyConflict {
        check(true, "a document key cannot shadow an existing blob key")
    }

    // And a blob import may not shadow an existing document key.
    let docSession = try await provider.beginEdit(
        store: store, callerPID: callerPID, callerStartTime: callerStart, unlock: nativeUnlock)
    _ = try await provider.commitEdit(
        sessionID: docSession.sessionID,
        document: Data(#"{"TOKEN":"abc"}"#.utf8),
        callerPID: callerPID, callerStartTime: callerStart)
    check(await provider.recordedBlobPath(store: store, key: "TOKEN") == nil,
          "a document-tier value has no recorded blob path (a sidecar cannot bind to it)")
    let clashSession = try await provider.beginEdit(
        store: store, callerPID: callerPID, callerStartTime: callerStart, unlock: nativeUnlock)
    do {
        _ = try await provider.commitBlobs(
            sessionID: clashSession.sessionID,
            requests: [.init(key: "TOKEN", data: Data("x".utf8), mode: 0o600, path: "t")],
            callerPID: callerPID, callerStartTime: callerStart)
        check(false, "a blob key cannot shadow an existing document key")
    } catch NativeStoreError.crossTierKeyConflict {
        check(true, "a blob key cannot shadow an existing document key")
    }
} catch {
    check(false, "whole-file import + cross-tier uniqueness checks succeed (\(error))")
}

print("\n# ProtectedFileImportPlanner (csec protect naming)")
do {
    let storeA = try ProtectedFileImportPlanner.storeName(
        forProjectDirectory: "/Users/alex/projects/my-app")
    let storeAagain = try ProtectedFileImportPlanner.storeName(
        forProjectDirectory: "/Users/alex/projects/my-app")
    let storeB = try ProtectedFileImportPlanner.storeName(
        forProjectDirectory: "/Users/bob/work/my-app")
    check(storeA == storeAagain, "a project directory derives a stable store name")
    check(storeA != storeB,
          "different directories with the same base name derive different stores")
    check(storeA.value.contains("my-app"),
          "the store name keeps the directory name for legibility")
    for dir in ["/", "/Users/alex/.config", "/tmp/weird name!@#", "/a", "/123"] {
        check((try? ProtectedFileImportPlanner.storeName(forProjectDirectory: dir)) != nil,
              "a store name is always valid for '\(dir)'")
    }

    for path in [".envrc", ".env", "config/master.key", "deep/a b/c!d.json", "-x", "..y", "café/x"] {
        let key = ProtectedFileImportPlanner.storeKey(forRelativePath: path)
        check(NativeStoreDocument.isValidKey(key),
              "a store key is always valid for '\(path)'")
        check((try? NativeSecretReference(store: storeA, key: key)) != nil,
              "the derived csec://store/key parses for '\(path)'")
    }
    check(ProtectedFileImportPlanner.storeKey(forRelativePath: ".envrc")
            == ProtectedFileImportPlanner.storeKey(forRelativePath: ".envrc"),
          "a relative path derives a stable key")
    check(ProtectedFileImportPlanner.storeKey(forRelativePath: "a/x")
            != ProtectedFileImportPlanner.storeKey(forRelativePath: "b/x"),
          "distinct relative paths derive distinct keys")
} catch {
    check(false, "protected-file import planner checks succeed (\(error))")
}

print("\n# ProtectedFileSidecar (untrusted *.csec pointer, source-neutral)")
do {
    let good = "convenient-security/protected-file"
    let ref = try SecretRef("csec://project/env_home")
    let encoded = try ProtectedFileSidecar(reference: ref).encoded()
    check(try ProtectedFileSidecar(data: encoded).reference == ref,
          "a sidecar round-trips its reference through the JSON envelope")
    // Source-neutral: any provider scheme is accepted in the JSON envelope, not
    // only native csec://. (This corrects the old csec://-only restriction.)
    let opEnvelope = #"{"csec":"\#(good)","version":1,"reference":"op://vault/item/field"}"#
    check(try ProtectedFileSidecar(data: Data(opEnvelope.utf8)).reference
            == (try SecretRef("op://vault/item/field")),
          "a 1Password reference in the envelope is accepted (source-neutral)")
    // Bare-reference forms: a lone secret URL, tolerant of whitespace and one
    // layer of quotes (the shape a piped `csec get`/1Password value has).
    for (label, text) in [
        ("bare op:// with trailing newline", "op://Personal/foo/bar\n"),
        ("bare csec://", "csec://project/env_home"),
        ("single-quoted", "'op://vault/item'"),
        ("surrounded by whitespace", "   op://vault/item\t\n"),
    ] {
        check((try? ProtectedFileSidecar(data: Data(text.utf8)))?.reference.uri != nil,
              "a bare reference is accepted: \(label)")
    }
    check(try ProtectedFileSidecar(data: Data("\"op://Employee/My Item/password\"\n".utf8))
            .reference == (try SecretRef("op://Employee/My Item/password")),
          "surrounding quotes and whitespace are stripped without altering the reference path")
    let derivedDotEnvrc = try ProtectedFileSidecar.targetName(forSidecarNamed: ".envrc.csec")
    let derivedConfig = try ProtectedFileSidecar.targetName(forSidecarNamed: "config.json.csec")
    check(derivedDotEnvrc == ".envrc" && derivedConfig == "config.json",
          "the target file name is derived from the sidecar name")
    for bad in [".csec", "foo", "..csec", "a/b.csec"] {
        checkThrows("a non-target sidecar name '\(bad)' is rejected") {
            _ = try ProtectedFileSidecar.targetName(forSidecarNamed: bad)
        }
    }
    func rejects(_ label: String, _ content: String) {
        checkThrows(label) { _ = try ProtectedFileSidecar(data: Data(content.utf8)) }
    }
    // A JSON object is only ever read as the strict envelope; it never falls back
    // to the bare form, so a malformed envelope is still rejected.
    rejects("an unknown envelope key is rejected",
            #"{"csec":"\#(good)","version":1,"reference":"csec://project/env_home","x":1}"#)
    rejects("a wrong envelope magic is rejected",
            #"{"csec":"evil","version":1,"reference":"csec://project/env_home"}"#)
    rejects("an unsupported envelope version is rejected",
            #"{"csec":"\#(good)","version":2,"reference":"csec://project/env_home"}"#)
    rejects("content that is neither JSON nor a reference is rejected", "not a reference at all\n")
    rejects("an empty file is rejected", "")
    checkThrows("an opaque ciphertext file is not a sidecar") {
        _ = try ProtectedFileSidecar(data: Data("CSECBLB1".utf8) + Data((0..<64).map { UInt8($0) }))
    }
    checkThrows("an oversize sidecar is rejected") {
        _ = try ProtectedFileSidecar(data: Data(count: ProtectedFileSidecar.maximumBytes + 1))
    }
} catch {
    check(false, "protected-file sidecar checks succeed (\(error))")
}

print("\n# ProtectedSidecarScanner (bounded *.csec discovery)")
do {
    let fm = FileManager.default
    let projectDirectory = NSTemporaryDirectory()
        + "csec-sidecar-scan-\(UUID().uuidString.lowercased())"
    try fm.createDirectory(atPath: projectDirectory, withIntermediateDirectories: true)
    defer { try? fm.removeItem(atPath: projectDirectory) }

    let store = try NativeStoreName("project")
    func writeSidecar(_ base: String, _ relativePath: String, key: String) throws -> SecretRef {
        let ref = try SecretRef("csec://\(store.value)/\(key)")
        let full = (base as NSString).appendingPathComponent(relativePath)
        try fm.createDirectory(
            atPath: (full as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true
        )
        try ProtectedFileSidecar(reference: ref).encoded().write(to: URL(fileURLWithPath: full))
        return ref
    }
    func writeRaw(_ relativePath: String, _ content: String) throws {
        let full = (projectDirectory as NSString).appendingPathComponent(relativePath)
        try fm.createDirectory(
            atPath: (full as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try Data(content.utf8).write(to: URL(fileURLWithPath: full))
    }

    let envRef = try writeSidecar(projectDirectory, ".envrc.csec", key: "env_home")
    let configRef = try writeSidecar(projectDirectory, "config/prod.json.csec", key: "config_prod")
    // A bare-reference sidecar (source-neutral, hand-written) is discovered too.
    try writeRaw("api.key.csec", "op://Personal/api/key\n")
    // A sidecar under an excluded build directory is never reached.
    _ = try writeSidecar(projectDirectory, "node_modules/pkg/.env.csec", key: "vendored")
    // A plain file and a name that is only the suffix are not sidecars.
    try writeRaw("README.md", "noise")
    // A *.csec file that cannot be parsed is reported as an issue, not skipped.
    try writeRaw("broken.env.csec", "this is not a reference")
    // A symlink ending in .csec is not followed — and is reported as an issue.
    try fm.createSymbolicLink(
        atPath: (projectDirectory as NSString).appendingPathComponent("link.csec"),
        withDestinationPath: "/etc/passwd"
    )

    let scan = try ProtectedSidecarScanner.scan(projectDirectory: projectDirectory)
    check(scan.discoveries.map(\.targetRelativePath) == [".envrc", "api.key", "config/prod.json"],
          "the scan finds every in-tree *.csec (JSON and bare), sorted, skipping excluded/non-sidecar")
    check(scan.discoveries.first(where: { $0.sidecarRelativePath == ".envrc.csec" })?.reference == envRef
            && scan.discoveries.first(where: { $0.targetRelativePath == "config/prod.json" })?
                .reference == configRef,
          "a discovery pairs its target with the sidecar path and reference")
    check(scan.discoveries.first(where: { $0.targetRelativePath == "api.key" })?.reference
            == (try SecretRef("op://Personal/api/key")),
          "a bare-reference sidecar resolves its source-neutral reference")
    check(scan.issues.map(\.sidecarRelativePath) == ["broken.env.csec", "link.csec"],
          "an unparseable *.csec and a *.csec symlink are reported as issues, not silently skipped")

    // Overflow past the per-launch maximum is a hard error, not truncation.
    let overflowDirectory = NSTemporaryDirectory()
        + "csec-sidecar-overflow-\(UUID().uuidString.lowercased())"
    try fm.createDirectory(atPath: overflowDirectory, withIntermediateDirectories: true)
    defer { try? fm.removeItem(atPath: overflowDirectory) }
    for index in 0...ProtectedSidecarScanner.maximumSidecars {
        _ = try writeSidecar(overflowDirectory, "file\(index).csec", key: "k\(index)")
    }
    checkThrows("more sidecars than a launch allows is a hard error") {
        _ = try ProtectedSidecarScanner.scan(projectDirectory: overflowDirectory)
    }
} catch {
    check(false, "protected-file sidecar scan checks succeed (\(error))")
}

print("\n# ProtectedSymlinkMaterialization (launcher-installed sidecar links)")
do {
    let fm = FileManager.default
    let project = NSTemporaryDirectory() + "csec-symlink-project-\(UUID().uuidString.lowercased())"
    let mount = NSTemporaryDirectory() + "csec-symlink-mount-\(UUID().uuidString.lowercased())"
    try fm.createDirectory(
        atPath: (project as NSString).appendingPathComponent("config"),
        withIntermediateDirectories: true)
    try fm.createDirectory(atPath: mount, withIntermediateDirectories: true)
    defer { try? fm.removeItem(atPath: project); try? fm.removeItem(atPath: mount) }

    let envTmpfs = (mount as NSString).appendingPathComponent("files-envrc")
    let keyTmpfs = (mount as NSString).appendingPathComponent("files-key")
    try Data("SECRET=1\n".utf8).write(to: URL(fileURLWithPath: envTmpfs))
    try Data("masterkey".utf8).write(to: URL(fileURLWithPath: keyTmpfs))

    let materialization = try ProtectedSymlinkMaterialization(projectDirectory: project, mountRoot: mount)
    try materialization.install([
        .init(projectRelativePath: ".envrc", tmpfsPath: envTmpfs),
        .init(projectRelativePath: "config/master.key", tmpfsPath: keyTmpfs),
    ])
    let envLink = (project as NSString).appendingPathComponent(".envrc")
    let keyLink = (project as NSString).appendingPathComponent("config/master.key")
    check((try? fm.destinationOfSymbolicLink(atPath: envLink)) == envTmpfs
          && (try? Data(contentsOf: URL(fileURLWithPath: envLink))) == Data("SECRET=1\n".utf8),
          "materialization links a project path to its tmpfs file and reads through it")
    check((try? fm.destinationOfSymbolicLink(atPath: keyLink)) == keyTmpfs,
          "materialization creates a nested symlink at its project path")

    let occupied = try ProtectedSymlinkMaterialization(projectDirectory: project, mountRoot: mount)
    try Data("real".utf8).write(
        to: URL(fileURLWithPath: (project as NSString).appendingPathComponent("existing")))
    checkThrows("materialization refuses to clobber an existing target file") {
        try occupied.install([.init(projectRelativePath: "existing", tmpfsPath: envTmpfs)])
    }

    materialization.removeAll()
    check(!fm.fileExists(atPath: envLink) && !fm.fileExists(atPath: keyLink)
          && fm.fileExists(atPath: envTmpfs),
          "teardown removes the launcher's symlinks but leaves their tmpfs targets")

    // A real file that usurped a materialized link must survive teardown.
    let guarded = try ProtectedSymlinkMaterialization(projectDirectory: project, mountRoot: mount)
    try guarded.install([.init(projectRelativePath: "usurped", tmpfsPath: envTmpfs)])
    let usurpedLink = (project as NSString).appendingPathComponent("usurped")
    try fm.removeItem(atPath: usurpedLink)
    try Data("attacker".utf8).write(to: URL(fileURLWithPath: usurpedLink))
    guarded.removeAll()
    check((try? Data(contentsOf: URL(fileURLWithPath: usurpedLink))) == Data("attacker".utf8),
          "teardown never removes a real file that replaced a materialized link")

    // Stale-link reclamation (F3): a hard-killed prior launch skips teardown and
    // leaves a dangling protected link into our mount. A fresh launch uses a new
    // nonce, so the leftover link points at an old, now-gone tmpfs path and would
    // otherwise block the launch with EEXIST. It is reclaimed — but ONLY when it is
    // a dangling symlink into our own mount.
    let staleOldTmpfs = (mount as NSString).appendingPathComponent("old-session-gone")
    let staleNewTmpfs = (mount as NSString).appendingPathComponent("new-session-file")
    try Data("REBORN=1\n".utf8).write(to: URL(fileURLWithPath: staleNewTmpfs))
    let stalePath = (project as NSString).appendingPathComponent("stale.env")
    try fm.createSymbolicLink(atPath: stalePath, withDestinationPath: staleOldTmpfs)
    check(!fm.fileExists(atPath: staleOldTmpfs),
          "stale-link fixture: the leftover link dangles (its old tmpfs target is gone)")
    let reclaimer = try ProtectedSymlinkMaterialization(projectDirectory: project, mountRoot: mount)
    try reclaimer.install([.init(projectRelativePath: "stale.env", tmpfsPath: staleNewTmpfs)])
    check((try? fm.destinationOfSymbolicLink(atPath: stalePath)) == staleNewTmpfs
          && (try? Data(contentsOf: URL(fileURLWithPath: stalePath))) == Data("REBORN=1\n".utf8),
          "a dangling protected link into our mount is reclaimed so the launch proceeds")
    reclaimer.removeAll()

    // Safety 1: a LIVE link into the mount (a concurrent launch's, target still
    // present) is never reclaimed — install refuses rather than break it.
    let liveTmpfs = (mount as NSString).appendingPathComponent("live-session-file")
    try Data("LIVE=1\n".utf8).write(to: URL(fileURLWithPath: liveTmpfs))
    let livePath = (project as NSString).appendingPathComponent("live.env")
    try fm.createSymbolicLink(atPath: livePath, withDestinationPath: liveTmpfs)
    let liveClasher = try ProtectedSymlinkMaterialization(projectDirectory: project, mountRoot: mount)
    checkThrows("a live link into our mount is never reclaimed (concurrent-launch safety)") {
        try liveClasher.install([.init(projectRelativePath: "live.env", tmpfsPath: liveTmpfs)])
    }
    check((try? fm.destinationOfSymbolicLink(atPath: livePath)) == liveTmpfs
          && fm.fileExists(atPath: liveTmpfs),
          "the live link and its target both survive the refused launch")

    // Safety 2: a dangling symlink pointing OUTSIDE our mount (a user's own broken
    // link) is never reclaimed, even though it dangles.
    let foreignPath = (project as NSString).appendingPathComponent("foreign.env")
    try fm.createSymbolicLink(atPath: foreignPath, withDestinationPath: "/nonexistent/user/target")
    let foreignClasher = try ProtectedSymlinkMaterialization(projectDirectory: project, mountRoot: mount)
    checkThrows("a dangling link outside our mount is never reclaimed") {
        try foreignClasher.install([.init(projectRelativePath: "foreign.env", tmpfsPath: envTmpfs)])
    }
    check((try? fm.destinationOfSymbolicLink(atPath: foreignPath)) == "/nonexistent/user/target",
          "the foreign dangling link is left untouched")

    // Safety 3: an empty mount root disables reclamation entirely, so a dangling
    // link is never treated as ours when we cannot prove ownership.
    let noRootPath = (project as NSString).appendingPathComponent("noroot.env")
    try fm.createSymbolicLink(atPath: noRootPath, withDestinationPath: staleOldTmpfs)
    let noRoot = try ProtectedSymlinkMaterialization(projectDirectory: project, mountRoot: "")
    checkThrows("an empty mount root never reclaims any link") {
        try noRoot.install([.init(projectRelativePath: "noroot.env", tmpfsPath: staleNewTmpfs)])
    }
    check((try? fm.destinationOfSymbolicLink(atPath: noRootPath)) == staleOldTmpfs,
          "with no provable mount ownership the dangling link is left untouched")
} catch {
    check(false, "protected symlink materialization checks succeed (\(error))")
}

do {
    let testDirectory = NSTemporaryDirectory()
        + "csec-native-files-\(UUID().uuidString.lowercased())"
    defer { try? FileManager.default.removeItem(atPath: testDirectory) }
    let files = try SecureNativeStoreFileBackend(directoryPath: testDirectory)
    let syntheticCiphertext = Data("synthetic-ciphertext-only".utf8)
    try await files.writeAtomically(named: "demo.0123456789abcdef0123456789abcdef.csec", data: syntheticCiphertext)
    check(try await files.read(named: "demo.0123456789abcdef0123456789abcdef.csec") == syntheticCiphertext,
          "production ciphertext backend round-trips through atomic openat writes")
    do {
        try await files.writeAtomically(
            named: "demo.0123456789abcdef0123456789abcdef.csec",
            data: Data("replacement".utf8)
        )
        check(false, "immutable ciphertext versions cannot be overwritten")
    } catch NativeStoreError.filesystemFailure {
        check(try await files.read(named: "demo.0123456789abcdef0123456789abcdef.csec") == syntheticCiphertext,
              "immutable ciphertext versions cannot be overwritten")
    }
    let attributes = try FileManager.default.attributesOfItem(
        atPath: testDirectory + "/demo.0123456789abcdef0123456789abcdef.csec"
    )
    check((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,
          "encrypted store files are mode 0600")
    let directoryAttributes = try FileManager.default.attributesOfItem(atPath: testDirectory)
    check((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700,
          "encrypted store directory is mode 0700")
    try FileManager.default.createSymbolicLink(
        atPath: testDirectory + "/symlink.csec",
        withDestinationPath: "/etc/passwd"
    )
    do {
        _ = try await files.read(named: "symlink.csec")
        check(false, "ciphertext reads refuse symbolic links")
    } catch NativeStoreError.filesystemFailure {
        check(true, "ciphertext reads refuse symbolic links")
    }
} catch {
    check(false, "production ciphertext filesystem checks succeed (\(error))")
}

print("\n# ProcessAncestry (against the live process tree)")

let me = getpid()
let myParent = getppid()

if let myStart = ProcessAncestry.startTime(of: me) {
    check(myStart > 0, "own start time is readable")
    check(ProcessAncestry.descends(me, from: me, rootStartTime: myStart),
          "a process descends from itself")
    check(!ProcessAncestry.descends(me, from: me, rootStartTime: myStart &+ 1),
          "a mismatched root start time is rejected (PID-reuse guard)")
} else {
    check(false, "own start time is readable")
}

check(ProcessAncestry.parent(of: me) == myParent, "ppid matches getppid()")

if let parentStart = ProcessAncestry.startTime(of: myParent) {
    check(ProcessAncestry.descends(me, from: myParent, rootStartTime: parentStart),
          "a process descends from its parent")
    if let myStart = ProcessAncestry.startTime(of: me) {
        check(!ProcessAncestry.descends(myParent, from: me, rootStartTime: myStart),
              "a parent does NOT descend from its child")
    }
} else {
    check(false, "parent start time is readable")
}

print("\n# GrantTable (plan-digest-bound subtree reuse)")

if let myStart = ProcessAncestry.startTime(of: me) {
    let table = GrantTable()
    await table.add(Grant(
        rootPID: me,
        rootStartTime: myStart,
        references: ["op://vault/item/password"],
        reason: "synthetic",
        expiresAt: Date().addingTimeInterval(60),
        deliveryPlanDigest: "plan-a"
    ))
    check(await table.accessibleReferences(
        for: me,
        now: Date(),
        deliveryPlanDigest: "plan-a"
    ) == ["op://vault/item/password"],
    "a live grant rooted at the caller is reusable for its exact plan digest")

    check(await table.accessibleReferences(
        for: me,
        now: Date(),
        deliveryPlanDigest: "plan-b"
    ).isEmpty, "a different delivery-plan digest cannot reuse an existing grant")

    // A non-descendant PID (init, pid 1) never inherits the caller's grant.
    check(await table.accessibleReferences(
        for: 1,
        now: Date(),
        deliveryPlanDigest: "plan-a"
    ).isEmpty, "a non-descendant process is not covered by the caller's grant")

    // An expired grant is not reused even for its own plan digest.
    await table.add(Grant(
        rootPID: me,
        rootStartTime: myStart,
        references: ["csec://test/TOKEN"],
        reason: "synthetic expired",
        expiresAt: Date().addingTimeInterval(-1),
        deliveryPlanDigest: "plan-expired"
    ))
    check(await table.accessibleReferences(
        for: me,
        now: Date(),
        deliveryPlanDigest: "plan-expired"
    ).isEmpty, "an expired grant is never reused")
} else {
    check(false, "plan-digest-bound grant tests can read their root start time")
}

print("\n# AgentSocket")

let socketDir = AgentSocket.directory()
check(socketDir.contains("convenient-security-"), "socket directory is namespaced by uid")
check(AgentSocket.defaultPath().hasSuffix("/agent.sock"), "default socket path ends in agent.sock")

do {
    try AgentSocket.ensureDirectory()
    var isDirectory: ObjCBool = false
    let exists = FileManager.default.fileExists(atPath: socketDir, isDirectory: &isDirectory)
    check(exists && isDirectory.boolValue, "ensureDirectory creates the directory")
    if let attributes = try? FileManager.default.attributesOfItem(atPath: socketDir),
       let permissions = attributes[.posixPermissions] as? NSNumber {
        check(permissions.intValue == 0o700, "socket directory is private (0700)")
    } else {
        check(false, "socket directory permissions are readable")
    }
} catch {
    check(false, "ensureDirectory succeeds (\(error))")
}

#if DEBUG
check(true, "debug build permits only compile-time test endpoint/provider seams")
#else
let releaseSocketOverride = "/tmp/csec-release-must-ignore.sock"
let originalSocketOverride = ProcessInfo.processInfo.environment["CSEC_SOCKET"]
setenv("CSEC_SOCKET", releaseSocketOverride, 1)
check(!AgentSocket.isUsingDebugOverride && AgentSocket.defaultPath() != releaseSocketOverride,
      "release build ignores CSEC_SOCKET")
if let originalSocketOverride {
    setenv("CSEC_SOCKET", originalSocketOverride, 1)
} else {
    unsetenv("CSEC_SOCKET")
}

let originalProviderOverride = ProcessInfo.processInfo.environment["OP_CLI_PATH"]
setenv("OP_CLI_PATH", "/bin/false", 1)
check(OnePasswordCLI.locate() != "/bin/false", "release build ignores OP_CLI_PATH")
if let originalProviderOverride {
    setenv("OP_CLI_PATH", originalProviderOverride, 1)
} else {
    unsetenv("OP_CLI_PATH")
}

let releaseRootSocketOverride = "/tmp/csec-root-release-must-ignore.sock"
let originalRootSocketOverride = ProcessInfo.processInfo.environment["CSEC_ROOT_SOCKET"]
setenv("CSEC_ROOT_SOCKET", releaseRootSocketOverride, 1)
check(!RootHelperSocket.isUsingDebugOverride
      && RootHelperSocket.defaultPath() == RootHelperSocket.canonicalPath,
      "release build ignores CSEC_ROOT_SOCKET")
if let originalRootSocketOverride {
    setenv("CSEC_ROOT_SOCKET", originalRootSocketOverride, 1)
} else {
    unsetenv("CSEC_ROOT_SOCKET")
}
#endif

print("\n# ProductCodeIdentity (pure trust classification)")

check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.agentIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true
) == .agent, "exact valid agent identity is classified as agent")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.launcherIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true
) == .launcher, "exact valid launcher identity is classified as launcher")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.rootHelperIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true
) == .rootHelper, "exact valid root-helper identity is classified as root helper")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.rootHelperIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true,
    hardenedRuntime: false
) == .other, "root-helper identity without hardened runtime is rejected")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.launcherIdentifier,
    teamIdentifier: "ATTACKERTEAM",
    signatureValid: true
) == .other, "matching identifier signed by another team is rejected")
check(ProductCodeIdentity.metadataRole(
    identifier: "com.example.unrelated",
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true
) == .other, "another binary from the product team is rejected")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.agentIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: false
) == .other, "invalid or unsigned code is rejected even with matching metadata")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.agentIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true,
    hardenedRuntime: false
) == .other, "matching product code without hardened runtime is rejected")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.agentIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true,
    dangerousEntitlements: ["com.apple.security.get-task-allow"]
) == .other, "matching product code with a dangerous entitlement is rejected")

let selfStartupReport = StartupSecurityReport.currentAgent()
check(selfStartupReport.sipStatus != .unknown,
      "startup self-audit obtains a definite SIP status")
check(!selfStartupReport.productionReady,
      "an ad-hoc self-test binary cannot pass the production agent startup gate")

print("\n# Secure regular-file delivery")

do {
    let rawBinding = ProtectedFileBinding.raw(
        environmentName: "PROTECTED_FILE",
        reference: "op://regular-file/config/content",
        index: 0
    )
    let plan = try syntheticProtectedLaunchPlan(files: [rawBinding])
    try plan.validate()
    check(try plan.digest() == plan.digest(),
          "protected launch-plan digest is deterministic")

    let changedCommand = try syntheticProtectedLaunchPlan(
        files: [rawBinding],
        commandLine: ["/bin/sh", "-c", "exit 7"]
    )
    try changedCommand.validate()
    check(try changedCommand.digest() != plan.digest(),
          "command argv changes the two-party launch digest")
    let hardTTLPlan = try syntheticProtectedLaunchPlan(files: [rawBinding], hardTTL: true)
    try hardTTLPlan.validate()
    check(try hardTTLPlan.digest() != plan.digest(),
          "hard-TTL process-tree semantics are digest-bound")

    let duplicateEnvironment = try syntheticProtectedLaunchPlan(files: [
        rawBinding,
        ProtectedFileBinding.raw(
            environmentName: "PROTECTED_FILE",
            reference: "op://regular-file/other/content",
            index: 1
        ),
    ])
    checkThrows("duplicate protected-file environment names are rejected") {
        try duplicateEnvironment.validate()
    }
    let traversal = try syntheticProtectedLaunchPlan(files: [ProtectedFileBinding(
        relativePath: "../escape",
        environmentName: "PROTECTED_FILE",
        reference: "op://regular-file/config/content"
    )])
    checkThrows("protected-file traversal paths are rejected") {
        try traversal.validate()
    }
    let oversizedReference = try syntheticProtectedLaunchPlan(files: [ProtectedFileBinding(
        relativePath: "files/credential-0",
        environmentName: "PROTECTED_FILE",
        reference: "op://regular-file/" + String(repeating: "x", count: 4_096)
    )])
    checkThrows("protected-file references retain the agent protocol byte bound") {
        try oversizedReference.validate()
    }
    let prefixCollision = try syntheticProtectedLaunchPlan(files: [
        ProtectedFileBinding(
            relativePath: "files/item",
            environmentName: "PROTECTED_FILE_A",
            reference: "op://regular-file/a/content"
        ),
        ProtectedFileBinding(
            relativePath: "files/item/nested",
            environmentName: "PROTECTED_FILE_B",
            reference: "op://regular-file/b/content"
        ),
    ])
    checkThrows("file/directory prefix collisions are rejected") {
        try prefixCollision.validate()
    }
    let loaderEnvironment = try syntheticProtectedLaunchPlan(
        files: [rawBinding],
        environment: ["DYLD_INSERT_LIBRARIES": "/tmp/not-loaded"]
    )
    checkThrows("dynamic-loader controls cannot cross the root launch boundary") {
        try loaderEnvironment.validate()
    }
    let sanitized = ProtectedLaunchPlan.sanitizedEnvironment([
        "PATH": "/usr/bin:/bin",
        "CSEC_SOCKET": "/tmp/not-forwarded",
        "DYLD_LIBRARY_PATH": "/tmp/not-forwarded",
        "VALID_NAME": "kept",
    ])
    check(sanitized == ["PATH": "/usr/bin:/bin", "VALID_NAME": "kept"],
          "protected launches strip product and loader control variables")

    let rawPayloads = try ProtectedFilePayloadRenderer.render(
        bindings: [rawBinding],
        values: [rawBinding.reference: Data("regular-file-synthetic-value".utf8)]
    )
    check(rawPayloads.count == 1
          && rawPayloads[0].relativePath == "files/credential-0"
          && rawPayloads[0].data == Data("regular-file-synthetic-value".utf8),
          "raw regular-file rendering preserves exact UTF-8 bytes")
    checkThrows("regular-file rendering rejects an empty payload") {
        _ = try ProtectedFilePayloadRenderer.render(
            bindings: [rawBinding],
            values: [rawBinding.reference: Data("".utf8)]
        )
    }
    checkThrows("regular-file rendering rejects unbound extra values") {
        _ = try ProtectedFilePayloadRenderer.render(
            bindings: [rawBinding],
            values: [
                rawBinding.reference: Data("synthetic".utf8),
                "op://regular-file/unbound/content": Data("synthetic-extra".utf8),
            ]
        )
    }

    let githubBinding = ProtectedFileBinding.github(
        reference: "op://github/profile/token",
        host: "github.example.test",
        user: "synthetic-user",
        gitProtocol: "ssh"
    )
    let githubPlan = try syntheticProtectedLaunchPlan(files: [githubBinding])
    try githubPlan.validate()
    let githubPayload = try ProtectedFilePayloadRenderer.render(
        bindings: [githubBinding],
        values: [githubBinding.reference: Data("synthetic-'github-token".utf8)]
    )
    let githubText = String(data: githubPayload[0].data, encoding: .utf8) ?? ""
    check(githubPayload[0].relativePath == "github/hosts.yml"
          && githubText.contains("github.example.test:")
          && githubText.contains("oauth_token: 'synthetic-''github-token'")
          && githubText.contains("git_protocol: ssh")
          && githubText.contains("user: 'synthetic-user'"),
          "GH_CONFIG_DIR rendering quotes a bounded hosts.yml profile")
    checkThrows("GH_CONFIG_DIR rendering rejects line injection in a token") {
        _ = try ProtectedFilePayloadRenderer.render(
            bindings: [githubBinding],
            values: [githubBinding.reference: Data("synthetic\nforged: true".utf8)]
        )
    }

    // Symlink-delivered bindings — the *.csec sidecar whole-file materialization
    // path. rootd materializes the tmpfs file; the launcher installs the symlink.
    let symlinkBinding = ProtectedFileBinding.symlink(
        projectRelativePath: ".envrc",
        reference: "csec://project/env_home",
        index: 0
    )
    let symlinkPlan = try syntheticProtectedLaunchPlan(files: [symlinkBinding])
    try symlinkPlan.validate()
    check(symlinkBinding.environmentName == nil && symlinkBinding.symlinkTarget == ".envrc",
          "a symlink binding carries a project target and sets no environment name")
    check(try symlinkPlan.digest() != plan.digest(),
          "symlink delivery is digest-bound distinctly from environment delivery")
    let symlinkPayloads = try ProtectedFilePayloadRenderer.render(
        bindings: [symlinkBinding],
        values: [symlinkBinding.reference: Data("SECRET=1\n".utf8)]
    )
    check(symlinkPayloads.count == 1
          && symlinkPayloads[0].relativePath == symlinkBinding.relativePath
          && symlinkPayloads[0].data == Data("SECRET=1\n".utf8),
          "a symlink binding renders its whole file byte-for-byte")
    let nestedSymlink = try syntheticProtectedLaunchPlan(files: [
        ProtectedFileBinding.symlink(
            projectRelativePath: "config/master.key",
            reference: "csec://project/master_key",
            index: 0
        ),
    ])
    try nestedSymlink.validate()
    for badTarget in ["../escape", "/etc/passwd", "a//b", "with\u{0}nul", "a/../b", "."] {
        let bad = try syntheticProtectedLaunchPlan(files: [
            ProtectedFileBinding.symlink(
                projectRelativePath: badTarget,
                reference: "csec://project/env_home",
                index: 0
            ),
        ])
        checkThrows("a symlink target '\(badTarget)' is rejected") { try bad.validate() }
    }
    let symlinkProfile = try syntheticProtectedLaunchPlan(files: [ProtectedFileBinding(
        relativePath: "files/protected-0",
        reference: "csec://project/env_home",
        rendering: .githubHosts(host: "github.com", user: nil, gitProtocol: "https"),
        delivery: .symlink(projectRelativePath: ".envrc")
    )])
    checkThrows("a symlink binding must render raw, never a profile") {
        try symlinkProfile.validate()
    }
    let duplicateSymlink = try syntheticProtectedLaunchPlan(files: [
        ProtectedFileBinding.symlink(projectRelativePath: ".envrc", reference: "csec://project/a", index: 0),
        ProtectedFileBinding.symlink(projectRelativePath: ".envrc", reference: "csec://project/b", index: 1),
    ])
    checkThrows("duplicate symlink targets are rejected") { try duplicateSymlink.validate() }

    // Value-in-environment bindings — folding `csec exec`'s `--set`/env-scan
    // injection into a sidecar launch. rootd places the resolved value directly in
    // the child environment; no file is surfaced and no path binding applies.
    let valueBinding = ProtectedFileBinding.value(
        environmentName: "DATABASE_URL",
        reference: "op://vault/db/url",
        index: 0
    )
    check(valueBinding.environmentName == "DATABASE_URL"
          && valueBinding.symlinkTarget == nil
          && valueBinding.environmentRelativePath == nil
          && valueBinding.relativePath == "env/value-0",
          "a value binding claims an environment name, no file path, and no symlink target")
    if case .environmentValue = valueBinding.delivery {} else {
        check(false, "a value binding uses value-in-environment delivery")
    }
    let mixedPlan = try syntheticProtectedLaunchPlan(files: [symlinkBinding, valueBinding])
    try mixedPlan.validate()
    let mixedDigest = try mixedPlan.digest()
    let symlinkDigest = try symlinkPlan.digest()
    check(mixedPlan.references.sorted() == ["csec://project/env_home", "op://vault/db/url"],
          "a mixed launch resolves both the sidecar and the value reference")
    check(mixedDigest != symlinkDigest,
          "adding a value binding changes the digest a signed party is bound to")
    let valuePayload = try ProtectedFilePayloadRenderer.render(
        bindings: [valueBinding],
        values: [valueBinding.reference: Data("postgres://synthetic".utf8)]
    )
    check(valuePayload.count == 1
          && valuePayload[0].relativePath == "env/value-0"
          && valuePayload[0].data == Data("postgres://synthetic".utf8),
          "a value binding renders its raw value as the routed payload")
    let encodedMixed = try JSONEncoder().encode(mixedPlan)
    let decodedMixed = try JSONDecoder().decode(ProtectedLaunchPlan.self, from: encodedMixed)
    let decodedDigest = try decodedMixed.digest()
    check(decodedMixed == mixedPlan && decodedDigest == mixedDigest,
          "value-in-environment delivery round-trips through Codable and the plan digest")
    // Unlike a symlink binding, a value binding is not path-bound to a stored blob,
    // so any resolvable scheme is accepted.
    try syntheticProtectedLaunchPlan(files: [
        symlinkBinding,
        ProtectedFileBinding.value(environmentName: "API_KEY", reference: "op://vault/api/key", index: 1),
    ]).validate()
    let valueCollidesEnv = try syntheticProtectedLaunchPlan(
        files: [valueBinding],
        environment: ["PATH": "/usr/bin:/bin", "DATABASE_URL": "already-set"]
    )
    checkThrows("a value name cannot duplicate a plan environment entry") {
        try valueCollidesEnv.validate()
    }
    for badName in ["CSEC_SNEAK", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD"] {
        let bad = try syntheticProtectedLaunchPlan(files: [
            symlinkBinding,
            ProtectedFileBinding.value(environmentName: badName, reference: "op://vault/x", index: 1),
        ])
        checkThrows("a value binding rejects the reserved name '\(badName)'") { try bad.validate() }
    }
    let duplicateValueName = try syntheticProtectedLaunchPlan(files: [
        ProtectedFileBinding.value(environmentName: "TOKEN", reference: "op://vault/a", index: 0),
        ProtectedFileBinding.value(environmentName: "TOKEN", reference: "op://vault/b", index: 1),
    ])
    checkThrows("duplicate value environment names are rejected") { try duplicateValueName.validate() }
    let valueClashesRaw = try syntheticProtectedLaunchPlan(files: [
        ProtectedFileBinding.raw(environmentName: "SHARED", reference: "op://vault/a", index: 0),
        ProtectedFileBinding.value(environmentName: "SHARED", reference: "op://vault/b", index: 1),
    ])
    checkThrows("a value name cannot collide with a path-in-environment name") {
        try valueClashesRaw.validate()
    }
    let valueProfile = try syntheticProtectedLaunchPlan(files: [ProtectedFileBinding(
        relativePath: "env/value-0",
        reference: "op://vault/db/url",
        rendering: .githubHosts(host: "github.com", user: nil, gitProtocol: "https"),
        delivery: .environmentValue(name: "DATABASE_URL")
    )])
    checkThrows("a value binding must render raw, never a profile") { try valueProfile.validate() }

    let rootRequestID = UUID().uuidString.lowercased()
    let rootRequest = RootHelperRequest.prepare(
        requestID: rootRequestID,
        plan: plan,
        planDigest: try plan.digest()
    )
    let rootRequestData = try JSONEncoder().encode(rootRequest)
    let decodedRootRequest = try JSONDecoder().decode(
        RootHelperRequest.self,
        from: rootRequestData
    )
    if case let .prepare(decodedID, decodedPlan, decodedDigest) = decodedRootRequest {
        check(decodedID == rootRequestID
              && decodedPlan == plan
              && decodedDigest == (try? plan.digest()),
              "root-helper prepare wire data round-trips its nonce and full plan binding")
    } else {
        check(false, "root-helper prepare wire data decodes as prepare")
    }
    var invalidRootWire = try JSONSerialization.jsonObject(
        with: rootRequestData
    ) as! [String: Any]
    invalidRootWire["version"] = RootHelperWireProtocol.version + 1
    checkThrows("root-helper wire rejects an unsupported protocol version") {
        _ = try JSONDecoder().decode(
            RootHelperRequest.self,
            from: try JSONSerialization.data(withJSONObject: invalidRootWire)
        )
    }

    var sockets: [Int32] = [-1, -1]
    let socketResult = sockets.withUnsafeMutableBufferPointer {
        socketpair(AF_UNIX, SOCK_STREAM, 0, $0.baseAddress)
    }
    if socketResult == 0, let peer = PeerIdentity.socketPeer(fd: sockets[0]) {
        defer { close(sockets[0]); close(sockets[1]) }
        let caller = CallerInfo(
            pid: peer.audit.pid,
            startTime: peer.audit.startTime,
            description: "protected launch self-test",
            peerIdentity: peer
        )
        let approval = try ProtectedLaunchApprovalRequest(
            rendezvousNonce: UUID().uuidString.lowercased(),
            launchPlan: plan,
            launchPlanDigest: try plan.digest()
        )
        check(approval.validate(caller: caller),
              "agent approval binds the launcher audit token, plan digest, and rendezvous nonce")
        let approvalWire = try JSONEncoder().encode(Request.approveProtectedLaunch(approval))
        var mismatchedOuterID = try JSONSerialization.jsonObject(
            with: approvalWire
        ) as! [String: Any]
        mismatchedOuterID["requestID"] = UUID().uuidString.lowercased()
        checkThrows("agent wire rejects a protected approval with mismatched outer request ID") {
            _ = try JSONDecoder().decode(
                Request.self,
                from: try JSONSerialization.data(withJSONObject: mismatchedOuterID)
            )
        }
        var tamperedApprovalWire = try JSONSerialization.jsonObject(
            with: approvalWire
        ) as! [String: Any]
        var nestedApproval = tamperedApprovalWire["protectedLaunchApproval"] as! [String: Any]
        var nestedPlan = nestedApproval["launchPlan"] as! [String: Any]
        nestedPlan["hardTTL"] = true
        nestedApproval["launchPlan"] = nestedPlan
        tamperedApprovalWire["protectedLaunchApproval"] = nestedApproval
        let tamperedRequest = try JSONDecoder().decode(
            Request.self,
            from: try JSONSerialization.data(withJSONObject: tamperedApprovalWire)
        )
        if case let .approveProtectedLaunch(tamperedApproval) = tamperedRequest {
            check(!tamperedApproval.validate(caller: caller),
                  "agent rejects a plan changed after the launcher supplied its digest")
        } else {
            check(false, "tampered protected approval remains type-decodable for validation")
        }
    } else {
        for fd in sockets where fd >= 0 { close(fd) }
        check(false, "local audit-token fixture can create a socket pair")
    }

    var groups = [UInt32](repeating: 0, count: 32)
    let groupCount = groups.withUnsafeMutableBufferPointer {
        cs_proc_groups(getpid(), $0.baseAddress, Int32($0.count))
    }
    check(groupCount > 0
          && groups.prefix(Int(max(0, groupCount))).contains(UInt32(getgid())),
          "kernel process credentials enumerate the launcher's current GID")
    check(cs_gid_is_assigned(getgid()) == 1,
          "the allocator detects a directory-service-assigned GID")
    check(cs_gid_has_live_holder(getgid()) == 1,
          "the process-tree tracker detects a live primary-GID holder")
    check(cs_pid_has_gid(getpid(), getgid()) == 1,
          "tree termination can recheck one stopped PID's capability credential")
    check(cs_boot_time() > 0 && cs_self_audit_session_id() != UInt32.max,
          "boot scope and audit-session identifiers are available")
} catch {
    check(false, "protected-file plan and protocol checks succeed (\(error))")
}

do {
    let baseURL = FileManager.default.temporaryDirectory.appendingPathComponent(
        "csec-protected-store-\(UUID().uuidString)",
        isDirectory: true
    )
    defer { try? FileManager.default.removeItem(at: baseURL) }
    let mountURL = baseURL.appendingPathComponent("files", isDirectory: true)
    let mount = ProtectedTmpFS(
        mode: .syntheticTesting,
        basePath: baseURL.path,
        mountPath: mountURL.path
    )
    try mount.prepare()
    let store = try ProtectedFileStore(
        mountPath: mountURL.path,
        mode: .syntheticTesting
    )
    let binding = ProtectedFileBinding.raw(
        environmentName: "PROTECTED_FILE",
        reference: "op://regular-file/store/content",
        index: 0
    )
    let payload = ProtectedFilePayload(
        relativePath: binding.relativePath,
        data: Data("synthetic-store-value".utf8)
    )
    let nonce = UUID().uuidString.lowercased()
    let session = try store.create(
        nonce: nonce,
        gid: getgid(),
        bindings: [binding],
        payloads: [payload]
    )
    let filePath = session.environment["PROTECTED_FILE"] ?? ""
    let sessionPath = mountURL.appendingPathComponent(nonce).path
    let fileAttributes = try FileManager.default.attributesOfItem(atPath: filePath)
    let directoryAttributes = try FileManager.default.attributesOfItem(atPath: sessionPath)
    let storedData = try Data(contentsOf: URL(fileURLWithPath: filePath))
    check((fileAttributes[.type] as? FileAttributeType) == .typeRegular
          && (fileAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o400
          && (directoryAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700
          && storedData == payload.data,
          "synthetic file store creates an exact regular file beneath a private session")
    try store.cleanup(nonce: nonce)
    check(!FileManager.default.fileExists(atPath: sessionPath),
          "protected file-store cleanup removes the complete session")

    // A symlink-delivered binding still materializes an isolated tmpfs file but
    // contributes no child environment entry — the launcher reaches it by symlink.
    let symlinkStoreNonce = UUID().uuidString.lowercased()
    let symlinkStoreBinding = ProtectedFileBinding.symlink(
        projectRelativePath: ".envrc",
        reference: "csec://project/env_home",
        index: 0
    )
    let symlinkStorePayload = ProtectedFilePayload(
        relativePath: symlinkStoreBinding.relativePath,
        data: Data("SECRET=materialized\n".utf8)
    )
    let symlinkStoreSession = try store.create(
        nonce: symlinkStoreNonce,
        gid: getgid(),
        bindings: [symlinkStoreBinding],
        payloads: [symlinkStorePayload]
    )
    let symlinkFilePath = mountURL.appendingPathComponent(symlinkStoreNonce)
        .appendingPathComponent(symlinkStoreBinding.relativePath).path
    check(symlinkStoreSession.environment.isEmpty
          && FileManager.default.fileExists(atPath: symlinkFilePath)
          && (try? Data(contentsOf: URL(fileURLWithPath: symlinkFilePath))) == symlinkStorePayload.data,
          "a symlink binding materializes its tmpfs file and sets no environment entry")
    try store.cleanup(nonce: symlinkStoreNonce)

    // A value-in-environment binding surfaces no tmpfs file at all — its value goes
    // straight into the child environment. Mixed with a sidecar it proves both:
    // the sidecar file is materialized while the value binding writes nothing.
    let valueStoreNonce = UUID().uuidString.lowercased()
    let valueStoreSidecar = ProtectedFileBinding.symlink(
        projectRelativePath: ".envrc",
        reference: "csec://project/env_home",
        index: 0
    )
    let valueStoreValue = ProtectedFileBinding.value(
        environmentName: "DATABASE_URL",
        reference: "op://vault/db/url",
        index: 0
    )
    let valueStoreSession = try store.create(
        nonce: valueStoreNonce,
        gid: getgid(),
        bindings: [valueStoreSidecar, valueStoreValue],
        payloads: [
            ProtectedFilePayload(
                relativePath: valueStoreSidecar.relativePath, data: Data("SECRET=1\n".utf8)),
            ProtectedFilePayload(
                relativePath: valueStoreValue.relativePath, data: Data("postgres://synthetic".utf8)),
        ]
    )
    let valueStoreSidecarPath = mountURL.appendingPathComponent(valueStoreNonce)
        .appendingPathComponent(valueStoreSidecar.relativePath).path
    let valueStoreValuePath = mountURL.appendingPathComponent(valueStoreNonce)
        .appendingPathComponent(valueStoreValue.relativePath).path
    check(valueStoreSession.environment == ["DATABASE_URL": "postgres://synthetic"]
          && FileManager.default.fileExists(atPath: valueStoreSidecarPath)
          && !FileManager.default.fileExists(atPath: valueStoreValuePath),
          "a value binding injects its value into the environment and materializes no file")
    try store.cleanup(nonce: valueStoreNonce)
    checkThrows("the file store rejects a non-UTF-8 value-in-environment payload") {
        _ = try store.create(
            nonce: UUID().uuidString.lowercased(),
            gid: getgid(),
            bindings: [ProtectedFileBinding.value(
                environmentName: "TOKEN", reference: "op://vault/x", index: 0)],
            payloads: [ProtectedFilePayload(
                relativePath: "env/value-0", data: Data([0xFF, 0xFE, 0xFD]))]
        )
    }

    let traversalNonce = UUID().uuidString.lowercased()
    let traversalBinding = ProtectedFileBinding(
        relativePath: "../outside",
        environmentName: "PROTECTED_FILE",
        reference: binding.reference
    )
    checkThrows("file store independently rejects traversal even without plan validation") {
        _ = try store.create(
            nonce: traversalNonce,
            gid: getgid(),
            bindings: [traversalBinding],
            payloads: [ProtectedFilePayload(
                relativePath: traversalBinding.relativePath,
                data: Data("synthetic".utf8)
            )]
        )
    }
    check(!FileManager.default.fileExists(
        atPath: baseURL.appendingPathComponent("outside").path
    ), "rejected traversal creates nothing outside the mount")

    let duplicateEnvironmentNonce = UUID().uuidString.lowercased()
    let secondBinding = ProtectedFileBinding.raw(
        environmentName: "PROTECTED_FILE",
        reference: "op://regular-file/store/other",
        index: 1
    )
    checkThrows("file store independently rejects duplicate environment mappings") {
        _ = try store.create(
            nonce: duplicateEnvironmentNonce,
            gid: getgid(),
            bindings: [binding, secondBinding],
            payloads: [
                payload,
                ProtectedFilePayload(
                    relativePath: secondBinding.relativePath,
                    data: Data("synthetic-other".utf8)
                ),
            ]
        )
    }
    check(!FileManager.default.fileExists(
        atPath: mountURL.appendingPathComponent(duplicateEnvironmentNonce).path
    ), "rejected environment mappings create no session")

    let symlinkNonce = UUID().uuidString.lowercased()
    let symlinkPath = mountURL.appendingPathComponent(symlinkNonce).path
    try FileManager.default.createSymbolicLink(
        atPath: symlinkPath,
        withDestinationPath: baseURL.path
    )
    checkThrows("file store refuses a pre-existing symlink session") {
        _ = try store.create(
            nonce: symlinkNonce,
            gid: getgid(),
            bindings: [binding],
            payloads: [payload]
        )
    }
    try FileManager.default.removeItem(atPath: symlinkPath)

    let restartNonce = UUID().uuidString.lowercased()
    _ = try store.create(
        nonce: restartNonce,
        gid: getgid(),
        bindings: [binding],
        payloads: [payload]
    )
    try store.recoverAfterDaemonRestart()
    check((try FileManager.default.contentsOfDirectory(atPath: mountURL.path)).isEmpty,
          "daemon-restart recovery unlinks every stale UUID session")

    let unexpectedPath = mountURL.appendingPathComponent("not-a-session").path
    FileManager.default.createFile(atPath: unexpectedPath, contents: Data("x".utf8))
    checkThrows("daemon-restart recovery fails closed on an unexpected mount entry") {
        try store.recoverAfterDaemonRestart()
    }
    try FileManager.default.removeItem(atPath: unexpectedPath)
} catch {
    check(false, "protected file-store checks succeed (\(error))")
}

print("\n# DeliveryPlan + protocol v2")

let baseExecutable = PlannedExecutable(
    canonicalPath: "/usr/bin/ruby",
    assurance: .userWritable
)
let basePlan = DeliveryPlan(
    mechanism: .directHeap,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 3600,
    operationContext: "boot application",
    commandDigest: String(repeating: "a", count: 64)
)
check((try? basePlan.digest()) == (try? basePlan.digest()),
      "delivery plan digest is deterministic")
let envPlan = DeliveryPlan(
    mechanism: .unrestrictedInitialEnvironment,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 3600,
    operationContext: "boot application",
    commandDigest: String(repeating: "a", count: 64)
)
check((try? basePlan.digest()) != (try? envPlan.digest()),
      "delivery mechanism changes the bound plan digest")
let shellRequester = PlannedExecutable(
    canonicalPath: "/bin/fish",
    assurance: .independentlyProtected
)
let shellRootedPlan = DeliveryPlan(
    mechanism: .rawStandardOutput,
    executable: PlannedExecutable(
        canonicalPath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec",
        assurance: .verifiedProduct
    ),
    requestingExecutable: shellRequester,
    root: .directParent(pid: 4242, startTime: 999_999),
    descendantScope: .subtree,
    destination: .humanOutput,
    recipientAssurance: .interactiveTerminal,
    requestedTTLSeconds: 3600,
    operationContext: "interactive get"
)
let otherShellRootedPlan = DeliveryPlan(
    mechanism: .rawStandardOutput,
    executable: shellRootedPlan.executable,
    requestingExecutable: PlannedExecutable(
        canonicalPath: "/bin/zsh",
        assurance: .independentlyProtected
    ),
    root: shellRootedPlan.root,
    descendantScope: .subtree,
    destination: .humanOutput,
    recipientAssurance: .interactiveTerminal,
    requestedTTLSeconds: 3600,
    operationContext: "interactive get"
)
check((try? shellRootedPlan.digest()) != (try? otherShellRootedPlan.digest()),
      "direct-parent requester identity changes the bound plan digest")
let shellPipePlan = DeliveryPlan(
    mechanism: .rawStandardOutput,
    executable: shellRootedPlan.executable,
    requestingExecutable: shellRequester,
    root: shellRootedPlan.root,
    descendantScope: .subtree,
    destination: .shellDelegatedPipe,
    recipientAssurance: .unverifiedPipeReader,
    requestedTTLSeconds: 3600,
    operationContext: "interactive get"
)
let persistentGetPlan = DeliveryPlan(
    mechanism: .namedPlaintextFile,
    executable: shellRootedPlan.executable,
    requestingExecutable: shellRequester,
    root: shellRootedPlan.root,
    descendantScope: .subtree,
    destination: .persistentPlaintextFile,
    recipientAssurance: .ordinaryPersistentFile,
    requestedTTLSeconds: 3600,
    operationContext: "interactive get"
)
check((try? shellRootedPlan.digest()) != (try? shellPipePlan.digest())
      && (try? shellPipePlan.digest()) != (try? persistentGetPlan.digest()),
      "terminal, shell-pipe, and persistent-file delivery shapes have distinct plan digests")
if let encodedShellPlan = try? JSONEncoder().encode(shellRootedPlan),
   let decodedShellPlan = try? JSONDecoder().decode(
    DeliveryPlan.self,
    from: encodedShellPlan
   ) {
    check(decodedShellPlan.requestingExecutable == shellRequester,
          "direct-parent requester identity round-trips")
} else {
    check(false, "direct-parent requester identity round-trips")
}
let guardedEnvPlan = DeliveryPlan(
    mechanism: .unrestrictedInitialEnvironment,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 3600,
    operationContext: "boot application",
    commandDigest: String(repeating: "a", count: 64),
    outputGuard: OutputGuardPlan(mode: .always)
)
let unguardedEnvPlan = DeliveryPlan(
    mechanism: .unrestrictedInitialEnvironment,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 3600,
    operationContext: "boot application",
    commandDigest: String(repeating: "a", count: 64),
    outputGuard: OutputGuardPlan(mode: .never)
)
check((try? guardedEnvPlan.digest()) != (try? unguardedEnvPlan.digest()),
      "output masking versus byte-exact bypass changes the bound plan digest")

do {
    let access = try AccessRequest(
        references: ["op://demo/db/url"],
        reason: "self-test",
        ttlSeconds: 3600,
        deliveryPlan: basePlan,
        requestID: UUID(uuidString: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")!
    )
    let data = try JSONEncoder().encode(Request.access(access))
    let decoded = try JSONDecoder().decode(Request.self, from: data)
    if case let .access(roundTrip) = decoded {
        check(roundTrip.protocolVersion == 2, "v2 access version round-trips")
        check(roundTrip.requestID == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
              "v2 request nonce round-trips")
        check(roundTrip.deliveryPlanDigest == (try? basePlan.digest()),
              "v2 plan digest round-trips")
    } else {
        check(false, "v2 access request decodes as access")
    }
} catch {
    check(false, "v2 access request round-trip succeeds (\(error))")
}

do {
    let begin = BeginSessionRequest(
        requestID: UUID(uuidString: "12345678-1234-5678-9abc-def012345678")!
    )
    let encoded = try JSONEncoder().encode(Request.beginSession(begin))
    let decoded = try JSONDecoder().decode(Request.self, from: encoded)
    if case let .beginSession(roundTrip) = decoded {
        check(roundTrip.requestID == begin.requestID,
              "registered-session request round-trips with its nonce")
    } else {
        check(false, "registered-session request decodes as the correct request")
    }

    let sessionPlan = DeliveryPlan(
        mechanism: .inheritedFileDescriptor,
        executable: baseExecutable,
        root: .registeredSession(id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        descendantScope: .broadSession,
        destination: .localDevelopment,
        requestedTTLSeconds: 300,
        operationContext: "registered session round trip"
    )
    let sessionData = try JSONEncoder().encode(sessionPlan)
    let sessionRoundTrip = try JSONDecoder().decode(DeliveryPlan.self, from: sessionData)
    check(sessionRoundTrip == sessionPlan,
          "registered session IDs are digest-bound delivery roots")
} catch {
    check(false, "registered-session protocol round trips succeed (\(error))")
}

do {
    let begin = BeginNativeStoreEditRequest(
        store: "development",
        mode: .externalTemporaryFile,
        externalEditorPath: "/usr/bin/vi",
        requestID: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
    )
    let beginData = try JSONEncoder().encode(Request.beginNativeStoreEdit(begin))
    let beginDecoded = try JSONDecoder().decode(Request.self, from: beginData)
    if case let .beginNativeStoreEdit(roundTrip) = beginDecoded {
        check(roundTrip.store == "development"
              && roundTrip.mode == .externalTemporaryFile
              && roundTrip.externalEditorPath == "/usr/bin/vi"
              && roundTrip.requestID == "11111111-2222-3333-4444-555555555555",
              "native-store edit begin round-trips with its mode and nonce")
    } else {
        check(false, "native-store edit begin decodes as the correct request")
    }
    let onboardingBegin = BeginNativeStoreEditRequest(
        store: "onboarding",
        mode: .onboardingImport,
        requestID: UUID(uuidString: "22222222-3333-4444-5555-666666666666")!
    )
    let onboardingData = try JSONEncoder().encode(
        Request.beginNativeStoreEdit(onboardingBegin)
    )
    let onboardingDecoded = try JSONDecoder().decode(Request.self, from: onboardingData)
    if case let .beginNativeStoreEdit(roundTrip) = onboardingDecoded {
        check(roundTrip.mode == .onboardingImport
              && roundTrip.externalEditorPath == nil,
              "native-store onboarding import is an explicit shell-free wire mode")
    } else {
        check(false, "native-store onboarding import decodes as the correct request")
    }
    let commit = CommitNativeStoreEditRequest(
        editSessionID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        document: Data(#"{"TOKEN":"synthetic"}"#.utf8),
        requestID: UUID(uuidString: "66666666-7777-8888-9999-aaaaaaaaaaaa")!
    )
    let commitData = try JSONEncoder().encode(Request.commitNativeStoreEdit(commit))
    let commitDecoded = try JSONDecoder().decode(Request.self, from: commitData)
    if case let .commitNativeStoreEdit(roundTrip) = commitDecoded {
        check(roundTrip.editSessionID == commit.editSessionID
              && roundTrip.document == commit.document,
              "native-store plaintext uses bounded Data inside the authenticated edit protocol")
    } else {
        check(false, "native-store edit commit decodes as the correct request")
    }
} catch {
    check(false, "native-store protocol requests round-trip (\(error))")
}

let legacyJSON = Data(#"{"type":"access","references":["op://demo/key"],"reason":"old","ttlSeconds":60}"#.utf8)
if let legacy = try? JSONDecoder().decode(Request.self, from: legacyJSON),
   case let .access(access) = legacy {
    check(access.isLegacy && access.deliveryPlan == nil,
          "v1 access is recognized explicitly and never gains an inferred plan")
} else {
    check(false, "v1 access remains decodable for a typed upgrade failure")
}

check((try? ExecutableInspection.resolve(command: "sh"))?.hasPrefix("/") == true,
      "launcher resolves PATH commands to an absolute executable")
do {
    _ = try ExecutableInspection.resolve(command: "/bin/echo $NAME")
    check(false, "a quoted shell command line used as one program name is rejected")
} catch let error as ExecutableInspectionError {
    if case .notFoundLooksLikeShellCommand = error {
        check(error.localizedDescription.contains("like env"),
              "a missing program name containing whitespace explains the argv model")
    } else {
        check(false, "a missing whitespace program name raises the shell-command guidance, got \(error)")
    }
}
check(ExecutableInspection.independentlyProtected(path: "/bin/sh"),
      "root-owned system executable is independently protected")
check(!ExecutableInspection.independentlyProtected(
    path: Bundle.main.executableURL?.path ?? CommandLine.arguments[0]
), "a user-owned development binary is not mislabeled independently protected")

print("\n# Secure no-root delivery formats")

let sessionHint = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
check((try? RegisteredSessionHint.sessionID(environment: [
    RegisteredSessionHint.environmentKey: sessionHint,
])) == sessionHint, "an opaque registered-session hint parses without carrying authority")
check((try? RegisteredSessionHint.sessionID(environment: [:])) == nil,
      "absence of a session hint keeps per-command delivery")
checkThrows("malformed inherited session hints fail closed") {
    _ = try RegisteredSessionHint.sessionID(environment: [
        RegisteredSessionHint.environmentKey: "not-a-session",
    ])
}

do {
    let aws = try AWSCredentialProcess.render(fields: [
        AWSCredentialProcess.accessKeyID: "AKIA-SYNTHETIC",
        AWSCredentialProcess.secretAccessKey: "aws-synthetic-secret",
        AWSCredentialProcess.sessionToken: "aws-synthetic-session",
        AWSCredentialProcess.expiration: "2033-05-18T03:33:20Z",
    ])
    let object = try JSONSerialization.jsonObject(with: aws) as? [String: Any]
    check(object?["Version"] as? Int == 1
          && object?["AccessKeyId"] as? String == "AKIA-SYNTHETIC"
          && object?["SecretAccessKey"] as? String == "aws-synthetic-secret"
          && object?["SessionToken"] as? String == "aws-synthetic-session",
          "AWS credential_process rendering emits the required versioned JSON fields")

    let bundle = #"{"AccessKeyId":"AKIA-BUNDLE","SecretAccessKey":"bundle-secret"}"#
    let bundleFields = try AWSCredentialProcess.fields(fromBundle: bundle)
    check(bundleFields[AWSCredentialProcess.accessKeyID] == "AKIA-BUNDLE",
          "AWS credentials can be read from one strict JSON bundle reference")
    checkThrows("AWS bundles reject duplicate fields before rendering") {
        _ = try AWSCredentialProcess.fields(
            fromBundle: #"{"AccessKeyId":"first","AccessKeyId":"second","SecretAccessKey":"secret"}"#
        )
    }
    checkThrows("AWS credential_process rejects malformed expiration metadata") {
        _ = try AWSCredentialProcess.render(fields: [
            AWSCredentialProcess.accessKeyID: "AKIA-SYNTHETIC",
            AWSCredentialProcess.secretAccessKey: "aws-synthetic-secret",
            AWSCredentialProcess.expiration: "not-a-time",
        ])
    }
} catch {
    check(false, "AWS credential_process format checks succeed (\(error))")
}

do {
    let gitInput = Data("protocol=https\nhost=example.test\npath=org/repo.git\nusername=hint\n\n".utf8)
    let request = try GitCredentialRequest(data: gitInput)
    check(request.matches(protocol: "HTTPS", host: "EXAMPLE.TEST", path: "org/repo.git"),
          "Git credential constraints bind protocol, host, and repository path")
    check(!request.matches(protocol: "https", host: "other.test", path: "org/repo.git"),
          "a Git credential request for another host does not match")
    let output = try GitCredentialRequest.render(
        username: "synthetic-user",
        password: "synthetic-password"
    )
    check(String(data: output, encoding: .utf8)
          == "username=synthetic-user\npassword=synthetic-password\n\n",
          "Git helper output uses the exact line-oriented get response")
    checkThrows("Git helper values cannot inject protocol attributes") {
        _ = try GitCredentialRequest.render(username: nil, password: "secret\nquit=1")
    }
    checkThrows("ambiguous duplicate Git constraints are rejected") {
        _ = try GitCredentialRequest(data: Data(
            "protocol=https\nhost=one.test\nhost=two.test\n\n".utf8
        ))
    }
} catch {
    check(false, "Git credential-helper format checks succeed (\(error))")
}

check(InheritedFilePreset.pgpass.environmentName == "PGPASSFILE"
      && InheritedFilePreset.kubeconfig.environmentName == "KUBECONFIG"
      && InheritedFilePreset.awsSharedCredentials.environmentName
        == "AWS_SHARED_CREDENTIALS_FILE"
      && InheritedFilePreset.googleServiceAccount.environmentName
        == "GOOGLE_APPLICATION_CREDENTIALS",
      "inherited-fd presets map to the four tool-native path variables")
check((try? InheritedFilePreset.kubeconfig.render("synthetic-kubeconfig"))
      == Data("synthetic-kubeconfig".utf8),
      "fd presets preserve the secret file bytes exactly")
checkThrows("fd presets reject NUL-bearing file content") {
    _ = try InheritedFilePreset.googleServiceAccount.render("{\"key\":\"bad\0value\"}")
}

print("\n# ReleasePolicy (value-free release decision)")

// TTL cap constants match the centralized policy.
check(ReleasePolicy.defaultTTLSeconds == 12 * 60 * 60
      && ReleasePolicy.maxTTLSeconds == 24 * 60 * 60,
      "release policy exposes the 12h default and 24h hard cap")

// (a) A normal protected directHeap plan is allowed, honors its requested TTL,
// and derives the in-band redact-and-warn output policy.
let heapPlan = DeliveryPlan.directHeap(
    executablePath: "/usr/bin/ruby",
    ttlSeconds: ReleasePolicy.defaultTTLSeconds,
    operationContext: "boot application"
)
let heapDecision = ReleasePolicy.evaluate(plan: heapPlan)
check(heapDecision.allowed
      && heapDecision.denialReason == nil
      && heapDecision.grantedTTLSeconds == ReleasePolicy.defaultTTLSeconds
      && heapDecision.outputPolicy == .exactMatchRedactAndWarn
      && !heapDecision.requiresPlaintextAcknowledgement,
      "a protected directHeap plan is allowed with its 12h TTL and redact-and-warn output")

// The granted TTL is clamped to the 24h hard cap regardless of the request.
let overlongPlan = DeliveryPlan.directHeap(
    executablePath: "/usr/bin/ruby",
    ttlSeconds: 999_999,
    operationContext: "boot application"
)
let overlongDecision = ReleasePolicy.evaluate(plan: overlongPlan)
check(overlongDecision.allowed
      && overlongDecision.grantedTTLSeconds == ReleasePolicy.maxTTLSeconds,
      "an overlong requested TTL is capped at the 24h backstop")

// (b) A non-positive requested TTL is refused as an invalid TTL.
let zeroTTLPlan = DeliveryPlan.directHeap(
    executablePath: "/usr/bin/ruby",
    ttlSeconds: 0,
    operationContext: "boot application"
)
let zeroTTLDecision = ReleasePolicy.evaluate(plan: zeroTTLPlan)
check(!zeroTTLDecision.allowed
      && zeroTTLDecision.denialReason == .invalidTTL
      && zeroTTLDecision.grantedTTLSeconds == 0,
      "a non-positive requested TTL is refused as an invalid TTL")

// Shared csec-get shapes for the plaintext-acknowledgement gate. Only the
// mechanism/recipient/interactive/ack fields drive the decision.
func getPlan(
    mechanism: DeliveryMechanism,
    destination: DestinationClass,
    recipient: RecipientAssurance?,
    interactive: Bool,
    acknowledged: Bool,
    ttlSeconds: Int = 3600
) -> DeliveryPlan {
    DeliveryPlan(
        mechanism: mechanism,
        executable: PlannedExecutable(
            canonicalPath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec",
            assurance: .verifiedProduct
        ),
        root: .caller,
        descendantScope: .subtree,
        destination: destination,
        recipientAssurance: recipient,
        requestedTTLSeconds: ttlSeconds,
        operationContext: "interactive get",
        interactive: interactive,
        plaintextExposureAcknowledged: acknowledged
    )
}

// (c) rawStandardOutput to an interactive terminal always needs an
// acknowledgement (terminal scrollback), regardless of interactivity.
let terminalNoAck = getPlan(
    mechanism: .rawStandardOutput, destination: .humanOutput,
    recipient: .interactiveTerminal, interactive: true, acknowledged: false
)
let terminalNoAckDecision = ReleasePolicy.evaluate(plan: terminalNoAck)
check(!terminalNoAckDecision.allowed
      && terminalNoAckDecision.denialReason == .plaintextExposureNotAcknowledged
      && terminalNoAckDecision.requiresPlaintextAcknowledgement,
      "raw terminal output without an acknowledgement is refused")
let terminalWithAck = getPlan(
    mechanism: .rawStandardOutput, destination: .humanOutput,
    recipient: .interactiveTerminal, interactive: true, acknowledged: true
)
let terminalWithAckDecision = ReleasePolicy.evaluate(plan: terminalWithAck)
check(terminalWithAckDecision.allowed
      && terminalWithAckDecision.denialReason == nil
      && terminalWithAckDecision.requiresPlaintextAcknowledgement
      && terminalWithAckDecision.outputPolicy == .exactMatchRedactAndWarn,
      "raw terminal output with the acknowledgement is allowed")

// (d) rawStandardOutput to an unverified pipe reader: an interactive human
// piping to a command needs no acknowledgement; a non-interactive capture does.
let interactivePipe = getPlan(
    mechanism: .rawStandardOutput, destination: .shellDelegatedPipe,
    recipient: .unverifiedPipeReader, interactive: true, acknowledged: false
)
let interactivePipeDecision = ReleasePolicy.evaluate(plan: interactivePipe)
check(interactivePipeDecision.allowed
      && interactivePipeDecision.denialReason == nil
      && !interactivePipeDecision.requiresPlaintextAcknowledgement,
      "an interactive human piping raw output needs no acknowledgement")
let capturedPipe = getPlan(
    mechanism: .rawStandardOutput, destination: .shellDelegatedPipe,
    recipient: .unverifiedPipeReader, interactive: false, acknowledged: false
)
let capturedPipeDecision = ReleasePolicy.evaluate(plan: capturedPipe)
check(!capturedPipeDecision.allowed
      && capturedPipeDecision.denialReason == .plaintextExposureNotAcknowledged
      && capturedPipeDecision.requiresPlaintextAcknowledgement,
      "a non-interactive pipe capture without an acknowledgement is refused")

// (e) A named plaintext file always requires an acknowledgement, even when a
// human is interactively present.
let fileNoAck = getPlan(
    mechanism: .namedPlaintextFile, destination: .persistentPlaintextFile,
    recipient: .ordinaryPersistentFile, interactive: true, acknowledged: false
)
let fileNoAckDecision = ReleasePolicy.evaluate(plan: fileNoAck)
check(!fileNoAckDecision.allowed
      && fileNoAckDecision.denialReason == .plaintextExposureNotAcknowledged
      && fileNoAckDecision.requiresPlaintextAcknowledgement,
      "a persistent plaintext file without an acknowledgement is refused")
let fileWithAck = getPlan(
    mechanism: .namedPlaintextFile, destination: .persistentPlaintextFile,
    recipient: .ordinaryPersistentFile, interactive: true, acknowledged: true
)
let fileWithAckDecision = ReleasePolicy.evaluate(plan: fileWithAck)
check(fileWithAckDecision.allowed && fileWithAckDecision.denialReason == nil,
      "a persistent plaintext file with the acknowledgement is allowed")

// (f) The credential-protocol mechanism is an intentional credential channel.
let credentialPlan = DeliveryPlan(
    mechanism: .credentialProtocol,
    executable: PlannedExecutable(canonicalPath: "/usr/bin/git", assurance: .independentlyProtected),
    root: .caller,
    descendantScope: .exactProcess,
    destination: .credentialConsumer,
    requestedTTLSeconds: 3600,
    operationContext: "git credential helper"
)
let credentialDecision = ReleasePolicy.evaluate(plan: credentialPlan)
check(credentialDecision.allowed
      && credentialDecision.outputPolicy == .intentionalCredentialChannel
      && !credentialDecision.requiresPlaintextAcknowledgement,
      "a credential-protocol delivery uses the intentional credential channel output policy")

// plaintextAcknowledgementRequired truth table: only the two raw csec-get
// exposure shapes above require an override; every protected mechanism does not.
check(ReleasePolicy.plaintextAcknowledgementRequired(fileNoAck)
      && ReleasePolicy.plaintextAcknowledgementRequired(getPlan(
          mechanism: .namedPlaintextFile, destination: .persistentPlaintextFile,
          recipient: .ordinaryPersistentFile, interactive: false, acknowledged: false)),
      "a named plaintext file always requires an acknowledgement, interactive or not")
check(ReleasePolicy.plaintextAcknowledgementRequired(terminalNoAck)
      && ReleasePolicy.plaintextAcknowledgementRequired(getPlan(
          mechanism: .rawStandardOutput, destination: .humanOutput,
          recipient: .interactiveTerminal, interactive: false, acknowledged: false)),
      "raw output to an interactive terminal always requires an acknowledgement")
check(!ReleasePolicy.plaintextAcknowledgementRequired(interactivePipe)
      && ReleasePolicy.plaintextAcknowledgementRequired(capturedPipe),
      "a raw pipe requires an acknowledgement only for a non-interactive capture")
for protectedMechanism: DeliveryMechanism in [
    .directHeap, .capabilityGIDFile, .inheritedFileDescriptor, .credentialProtocol,
    .sealedEnvironment, .restrictedLateEnvironment, .execHook,
    .unrestrictedInitialEnvironment,
] {
    let protectedPlan = DeliveryPlan(
        mechanism: protectedMechanism,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
        root: .caller,
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 3600,
        operationContext: "protected mechanism"
    )
    check(!ReleasePolicy.plaintextAcknowledgementRequired(protectedPlan),
          "protected mechanism \(protectedMechanism.rawValue) never requires an acknowledgement")
}

// The value-free review copy derives the destination-appropriate warning and
// recipient description purely from the plan; it carries no value or path.
let fileReview = AccessPolicyReview(
    caller: CallerInfo(pid: 4242, startTime: 999_999, description: "fish [user_writable]"),
    reason: "review persistent delivery",
    plan: persistentGetPlan,
    credentials: [PolicyReviewCredential(
        references: [try! SecretRef("op://Synthetic/Item/token")]
    )]
)
let fileWarning = DeliveryReviewCopy.warning(for: fileReview) ?? ""
check(fileWarning.contains("Plaintext will persist in an ordinary file")
      && fileWarning.contains("processes running as you")
      && fileWarning.contains("copying, backups")
      && fileWarning.contains("csec exec, exec-file, or a credential helper")
      && !fileWarning.contains("secret-output.txt")
      && !fileWarning.contains("synthetic-secret-value"),
      "persistent-file review gives the complete value-free warning steering toward injection")
let pipeReview = AccessPolicyReview(
    caller: fileReview.caller,
    reason: "review delegated pipe",
    plan: shellPipePlan,
    credentials: fileReview.credentials
)
let pipeWarning = DeliveryReviewCopy.warning(for: pipeReview) ?? ""
check(DeliveryReviewCopy.recipientDescription(for: shellPipePlan)
        .contains("unverified pipe reader")
      && pipeWarning.contains("generic Unix pipelines do not reveal or authenticate"),
      "pipe review distinguishes the shell grant owner, csec emitter, and unverified reader")

print("\n# ReviewDisplay (trusted-window presentation copy)")

let groupedOp = ReviewDisplay.referenceGroup(for: [
    try! SecretRef("op://Employee/Dexory Slack User Token/password"),
    try! SecretRef("op://Employee/Dexory Slack User Token/web token"),
])
check(groupedOp.title == "Dexory Slack User Token"
      && groupedOp.subtitle == "1Password · vault “Employee”"
      && groupedOp.fields == ["password", "web token"]
      && groupedOp.rawReferences.isEmpty,
      "same-item 1Password references group into item, vault, and field list")

let mixedVaults = ReviewDisplay.referenceGroup(for: [
    try! SecretRef("op://Employee/Item A/password"),
    try! SecretRef("op://Infrastructure/Item B/password"),
])
check(mixedVaults.title == nil
      && mixedVaults.rawReferences == [
          "op://Employee/Item A/password",
          "op://Infrastructure/Item B/password",
      ],
      "cross-item 1Password references fall back to complete canonical URIs")

let sectionedOp = ReviewDisplay.referenceGroup(for: [
    try! SecretRef("op://Employee/Item/section/field")
])
check(sectionedOp.title == nil
      && sectionedOp.rawReferences == ["op://Employee/Item/section/field"],
      "sectioned 1Password references are shown as complete URIs, never partially grouped")

let mixedSchemes = ReviewDisplay.referenceGroup(for: [
    try! SecretRef("op://Employee/Item/field"),
    try! SecretRef("csec://dev/DATABASE_URL"),
])
check(mixedSchemes.title == nil && mixedSchemes.rawReferences.count == 2,
      "mixed-provider references fall back to complete canonical URIs")

let nativeGroup = ReviewDisplay.referenceGroup(for: [
    try! SecretRef("csec://dexory-dev/DATABASE_URL"),
    try! SecretRef("csec://dexory-dev/*"),
])
check(nativeGroup.title == "dexory-dev"
      && nativeGroup.subtitle == "Native encrypted store"
      && nativeGroup.fields == ["DATABASE_URL", "all keys (edit access)"],
      "native-store references group by store and label edit access")

let bidiGroup = ReviewDisplay.referenceGroup(for: [
    try! SecretRef("op://Emp\u{202e}loyee/Item/fie\u{0007}ld")
])
check(bidiGroup.title == "Item"
      && bidiGroup.subtitle?.contains("\u{202e}") == false
      && bidiGroup.fields == ["fie�ld"],
      "grouped reference components neutralize bidi and control characters")
check(ReviewDisplay.sanitized("a\u{202e}b\nc") == "a�b�c",
      "sanitized neutralizes bidi overrides and newlines")

check(ReviewDisplay.duration(seconds: 45) == "45 seconds"
      && ReviewDisplay.duration(seconds: 300) == "5 minutes"
      && ReviewDisplay.duration(seconds: 3600) == "1 hour"
      && ReviewDisplay.duration(seconds: 5400) == "1 hour 30 minutes"
      && ReviewDisplay.duration(seconds: 90) == "1 minute 30 seconds",
      "requested durations render in plain units")

print("\n# CredentialGrouping (display + grant shaping)")

check(CredentialGrouping.onePasswordGroup(
    for: try! SecretRef("op://Vault Name/Item Name/section/password")
) == "Vault Name/Item Name", "1Password fields group initially by vault/item capability")

let groupedReferences = CredentialGrouping.groups(for: [
    try! SecretRef("op://Vault/Item/password"),
    try! SecretRef("op://Vault/Item/username"),
    try! SecretRef("csec://production/API_TOKEN"),
    try! SecretRef("csec://production/DATABASE_URL"),
])
check(groupedReferences.count == 2
      && groupedReferences.map(\.references.count).sorted() == [2, 2],
      "provider grouping combines 1Password fields and native keys by logical capability")
check(CredentialGrouping.nativeStoreGroup(
    for: try! SecretRef("csec://production/*")
) == "production", "native edit access and native keys share the store-level grouping")

print("\n# OnePasswordProvider (op CLI plumbing, no account access)")

check(OnePasswordCLI.sanitizedEnvironment()["GITHUB_TOKEN"] == nil
      && OnePasswordCLI.sanitizedEnvironment()["DATABASE_URL"] == nil,
      "provider child receives a minimal allowlisted environment")

if let opPath = OnePasswordCLI.locate() {
    check(FileManager.default.isExecutableFile(atPath: opPath), "op CLI located at \(opPath)")
    if let result = try? await OnePasswordCLI.run(opPath, ["--version"]) {
        check(result.status == 0, "op --version exits 0 via the runner")
        let version = String(data: result.stdout, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        check(!version.isEmpty, "op --version prints a version (\(version))")
    } else {
        check(false, "op --version runs via the runner")
    }
} else {
    print("skip - op CLI not installed; skipping live op checks")
}

// A provider pointed at a missing binary must fail fast, never hang.
let brokenProvider = OnePasswordProvider(cliPath: "/nonexistent/op")
do {
    _ = try await brokenProvider.resolve(try! SecretRef("op://demo/db/url"), unlock: nil)
    check(false, "resolve with a missing CLI should throw")
} catch {
    check(true, "resolve with a missing CLI throws (\(error))")
}

print("\n# ExecPlanner (env-injection planning, no agent)")

// Env-scan resolves references in place; ordinary values pass through untouched.
if let scan = try? ExecPlanner.plan(
    environment: ["DATABASE_URL": "op://vault/db/url", "PATH": "/usr/bin", "HOME": "/Users/x"],
    explicit: [],
    knownSchemes: ["op"]
) {
    check(scan.assignments == ["DATABASE_URL": "op://vault/db/url"],
          "env value that is an op:// reference is detected; plain values are not")
    check(scan.references == ["op://vault/db/url"], "references list is just the detected ref")
} else {
    check(false, "env-scan plan builds")
}

// An ordinary URL must not be mistaken for a secret: https isn't a known scheme.
check((try? ExecPlanner.plan(
    environment: ["SITE": "https://example.com"], explicit: [], knownSchemes: ["op"]
))?.assignments.isEmpty == true, "https:// is left untouched (scheme not resolvable)")

// A reference whose scheme the agent doesn't handle is ignored in env-scan.
check((try? ExecPlanner.plan(
    environment: ["X": "vault://a/b"], explicit: [], knownSchemes: ["op"]
))?.assignments.isEmpty == true, "unknown resolvable-looking scheme is skipped in env-scan")

// Explicit --set overrides an env-scan match for the same variable.
if let overridden = try? ExecPlanner.plan(
    environment: ["DATABASE_URL": "op://vault/db/url"],
    explicit: [(name: "DATABASE_URL", reference: "op://vault/other/url")],
    knownSchemes: ["op"]
) {
    check(overridden.assignments["DATABASE_URL"] == "op://vault/other/url",
          "explicit --set wins over an env-scan match")
} else {
    check(false, "explicit-override plan builds")
}

// references are deduped and sorted for a stable single access() call.
if let many = try? ExecPlanner.plan(
    environment: ["A": "op://x", "B": "op://x", "C": "op://y"],
    explicit: [],
    knownSchemes: ["op"]
) {
    check(many.references == ["op://x", "op://y"], "references are deduped and sorted")
} else {
    check(false, "multi-ref plan builds")
}

if let mixedProviders = try? ExecPlanner.plan(
    environment: [
        "REMOTE_TOKEN": "op://vault/item/token",
        "LOCAL_TOKEN": "csec://development/TOKEN",
    ],
    explicit: [],
    knownSchemes: ["op", "csec"]
) {
    check(mixedProviders.references == [
        "csec://development/TOKEN",
        "op://vault/item/token",
    ], "environment planning resolves native and 1Password references together")
} else {
    check(false, "mixed-provider environment plan builds")
}

checkThrows("--set with a non-reference value throws") {
    _ = try ExecPlanner.plan(
        environment: [:], explicit: [(name: "X", reference: "not a uri")], knownSchemes: ["op"]
    )
}
checkThrows("--set with an unresolvable scheme throws") {
    _ = try ExecPlanner.plan(
        environment: [:], explicit: [(name: "X", reference: "vault://a/b")], knownSchemes: ["op"]
    )
}

// resolvedEnvironment injects values and preserves everything else.
let injectPlan = ExecPlanner.Plan(assignments: ["DATABASE_URL": "op://vault/db/url"])
if let env = try? ExecPlanner.resolvedEnvironment(
    base: ["PATH": "/usr/bin", "DATABASE_URL": "placeholder"],
    plan: injectPlan,
    values: ["op://vault/db/url": Data("postgres://resolved".utf8)]
) {
    check(env["DATABASE_URL"] == "postgres://resolved", "resolved value replaces the placeholder")
    check(env["PATH"] == "/usr/bin", "unrelated variables are preserved")
} else {
    check(false, "resolvedEnvironment succeeds")
}

// With an empty base it yields exactly the injected subset (the exec code path).
check((try? ExecPlanner.resolvedEnvironment(
    base: [:], plan: injectPlan, values: ["op://vault/db/url": Data("postgres://resolved".utf8)]
)) == ["DATABASE_URL": "postgres://resolved"], "empty base yields only the injected variables")

checkThrows("resolvedEnvironment throws when the agent returned no value") {
    _ = try ExecPlanner.resolvedEnvironment(base: [:], plan: injectPlan, values: [:])
}

checkThrows("--set rejects an ambiguous environment name") {
    _ = try ExecPlanner.plan(
        environment: [:],
        explicit: [(name: "BAD=NAME", reference: "op://vault/db/url")],
        knownSchemes: ["op"]
    )
}
checkThrows("environment delivery rejects a protected value containing NUL") {
    _ = try ExecPlanner.resolvedEnvironment(
        base: [:],
        plan: injectPlan,
        values: ["op://vault/db/url": Data("synthetic\0value".utf8)]
    )
}

print("\n# OutputGuard (binary-safe streaming redaction)")

func redact(
    patterns: [OutputRedactionPattern],
    chunks: [Data]
) -> (data: Data, matches: [OutputRedactionMatch], firstChunk: Data) {
    var redactor = StreamingOutputRedactor(patterns: patterns)
    var output = Data()
    var matches: [OutputRedactionMatch] = []
    var firstChunk = Data()
    for (index, chunk) in chunks.enumerated() {
        let result = redactor.process(chunk)
        if index == 0 { firstChunk = result.data }
        output.append(result.data)
        matches.append(contentsOf: result.matches)
    }
    let final = redactor.finish()
    output.append(final.data)
    matches.append(contentsOf: final.matches)
    return (output, matches, firstChunk)
}

let prefixPattern = OutputRedactionPattern(
    opaqueID: "secret-prefix",
    representation: .exact,
    bytes: Data("abcdefgh".utf8),
    replacement: Data("[prefix]".utf8)
)
let longestPattern = OutputRedactionPattern(
    opaqueID: "secret-long",
    representation: .exact,
    bytes: Data("abcdefghijk".utf8),
    replacement: Data("[long]".utf8)
)
let splitRedaction = redact(
    patterns: [prefixPattern, longestPattern],
    chunks: [Data("before:abc".utf8), Data("def".utf8), Data("ghijk:after".utf8)]
)
check(splitRedaction.firstChunk.range(of: Data("abc".utf8)) == nil,
      "a possible secret prefix is withheld rather than forwarded")
check(splitRedaction.data == Data("before:[long]:after".utf8),
      "a secret split across writes is replaced using longest-match semantics")
check(splitRedaction.matches == [OutputRedactionMatch(opaqueID: "secret-long", representation: .exact)],
      "redaction emits only value-free match metadata")

let splitFixture = Data("prefix-abcdefghijk-suffix".utf8)
let splitExpected = Data("prefix-[long]-suffix".utf8)
let everyTwoChunkBoundaryIsSafe = (0...splitFixture.count).allSatisfy { boundary in
    let result = redact(
        patterns: [prefixPattern, longestPattern],
        chunks: [
            splitFixture.subdata(in: 0..<boundary),
            splitFixture.subdata(in: boundary..<splitFixture.count),
        ]
    )
    return result.data == splitExpected
}
let byteAtATime = redact(
    patterns: [prefixPattern, longestPattern],
    chunks: splitFixture.map { Data([$0]) }
)
check(everyTwoChunkBoundaryIsSafe && byteAtATime.data == splitExpected,
      "every split boundary, including byte-at-a-time writes, produces the same safe output")

let binaryRedaction = redact(
    patterns: [longestPattern],
    chunks: [Data([0x00, 0xff, 0x61, 0x62]), Data("cdefghijk".utf8) + Data([0x80])]
)
check(binaryRedaction.data == Data([0x00, 0xff]) + Data("[long]".utf8) + Data([0x80]),
      "matching and replacement preserve unrelated non-UTF8 bytes")

let unmatchedFlush = redact(
    patterns: [longestPattern],
    chunks: [Data("trailing-abcd".utf8)]
)
check(unmatchedFlush.data == Data("trailing-abcd".utf8) && unmatchedFlush.matches.isEmpty,
      "an unmatched trailing prefix is forwarded intact at EOF")

// Interactive streams live on immediacy: a chunk whose tail cannot begin any
// protected value must be forwarded in full without waiting for more input,
// or a supervised shell never shows its prompt.
var promptRedactor = StreamingOutputRedactor(patterns: [prefixPattern, longestPattern])
let promptResult = promptRedactor.process(Data("bash-5.2$ ".utf8))
check(promptResult.data == Data("bash-5.2$ ".utf8) && promptResult.matches.isEmpty,
      "a chunk with no viable secret prefix is forwarded immediately, not withheld")

var echoRedactor = StreamingOutputRedactor(patterns: [prefixPattern, longestPattern])
let echoedImmediately = Data("ls -l\r".utf8).allSatisfy { byte in
    echoRedactor.process(Data([byte])).data == Data([byte])
}
check(echoedImmediately,
      "byte-at-a-time echo of ordinary characters is emitted keystroke by keystroke")

// Withholding stays precise: only the tail that tracks a candidate's leading
// bytes is held back, and a diverging byte releases it verbatim.
var divergeRedactor = StreamingOutputRedactor(patterns: [prefixPattern, longestPattern])
let heldPrefix = divergeRedactor.process(Data("cmd: abcde".utf8))
let released = divergeRedactor.process(Data("X".utf8))
check(heldPrefix.data == Data("cmd: ".utf8) && released.data == Data("abcdeX".utf8),
      "a viable prefix is withheld from its own first byte and released on divergence")

let encodedCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/Output/token": Data("alpha:/\"beta-token".utf8)]
)
let base64Text = Data("alpha:/\"beta-token".utf8).base64EncodedData()
let encodedRedaction = redact(patterns: encodedCatalog.patterns, chunks: [base64Text])
check(encodedRedaction.data == Data("[csec:secret-1]".utf8)
      && encodedRedaction.matches.first?.representation == .base64,
      "canonical base64 output is detected without exposing its source value")

let percentText = Data("alpha%3A%2F%22beta-token".utf8)
let percentRedaction = redact(patterns: encodedCatalog.patterns, chunks: [percentText])
check(percentRedaction.data == Data("[csec:secret-1]".utf8)
      && percentRedaction.matches.first?.representation == .percentEncoded,
      "canonical percent-encoded output is detected")

let encodedJSONText = try! JSONEncoder().encode("alpha:/\"beta-token")
let jsonText = encodedJSONText.subdata(in: 1..<(encodedJSONText.count - 1))
let jsonRedaction = redact(patterns: encodedCatalog.patterns, chunks: [jsonText])
check(jsonRedaction.data == Data("[csec:secret-1]".utf8)
      && jsonRedaction.matches.first?.representation == .jsonEscaped,
      "JSON-escaped output is detected")

let shortCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/short": Data("tiny".utf8)]
)
check(shortCatalog.patterns.isEmpty && shortCatalog.skippedShortValueCount == 1,
      "short common values are excluded from automatic destructive matching")
let optedInShortCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/short": Data("tiny".utf8)],
    includeShortValues: true
)
check(!optedInShortCatalog.patterns.isEmpty,
      "short-value matching requires an explicit opt-in")

let referenceCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/Output/token": Data("synthetic-output-token".utf8)],
    labelStyle: .reference
)
let referenceRedaction = redact(
    patterns: referenceCatalog.patterns,
    chunks: [Data("synthetic-output-token".utf8)]
)
check(referenceRedaction.data == Data("[redacted: op://Synthetic/Output/token]".utf8),
      "the default reference-shaped label names the redacted reference in-band")
check(referenceRedaction.matches.first?.reference == "op://Synthetic/Output/token",
      "a reference-styled match carries the reference so an opt-in warning can name it")

let unsafeReferenceCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/item/field\nforged\u{202e}": Data("synthetic-control-token".utf8)],
    labelStyle: .reference
)
let unsafeReferenceRedaction = redact(
    patterns: unsafeReferenceCatalog.patterns,
    chunks: [Data("synthetic-control-token".utf8)]
)
check(unsafeReferenceRedaction.data == Data("[redacted: op://Synthetic/item/field�forged�]".utf8),
      "reference-shaped output cannot inject lines or bidirectional controls")

// An opaque label never carries the reference into the output stream, even
// though the match metadata still knows it for an opt-in warning.
let opaqueLabelCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/Output/token": Data("synthetic-output-token".utf8)],
    labelStyle: .opaque
)
let opaqueLabelRedaction = redact(
    patterns: opaqueLabelCatalog.patterns,
    chunks: [Data("synthetic-output-token".utf8)]
)
check(opaqueLabelRedaction.data == Data("[csec:secret-1]".utf8)
      && opaqueLabelRedaction.matches.first?.reference == "op://Synthetic/Output/token",
      "an opaque label keeps the reference out of output but still in the match metadata")

let collisionSource = "synthetic-collision-source"
let collisionExact = Data(collisionSource.utf8).base64EncodedString()
let collisionCatalog = OutputRedactionCatalog(
    valuesByReference: [
        "op://Synthetic/a-derived": Data(collisionSource.utf8),
        "op://Synthetic/b-exact": Data(collisionExact.utf8),
    ],
    labelStyle: .reference
)
let collisionRedaction = redact(
    patterns: collisionCatalog.patterns,
    chunks: [Data(collisionExact.utf8)]
)
check(collisionRedaction.data == Data("[redacted: op://Synthetic/b-exact]".utf8)
      && collisionRedaction.matches.first?.representation == .exact,
      "an exact credential wins over another credential's colliding encoded form")

print("\n# AICommandHook (Claude Code / Codex PreToolUse rewriting)")

let complexHookCommand = "printf '%s\\n' \"a b\"; echo `uname` && printf '$HOME'\ntrue"
let hookInputObject: [String: Any] = [
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": [
        "command": complexHookCommand,
        "description": "synthetic quoting test",
        "timeout": 12_345,
        "run_in_background": true,
    ],
]
let hookInputData = try! JSONSerialization.data(withJSONObject: hookInputObject)
for client in AICommandHookClient.allCases {
    do {
        let outputData = try AICommandHook.rewrite(
            input: hookInputData,
            client: client,
            csecExecutablePath: "/opt/Convenient Security/it's/csec"
        )
        let output = try JSONSerialization.jsonObject(with: outputData) as? [String: Any]
        let specific = output?["hookSpecificOutput"] as? [String: Any]
        let updated = specific?["updatedInput"] as? [String: Any]
        let rewritten = updated?["command"] as? String ?? ""
        let encoded = rewritten.split(separator: " ").last.map(String.init) ?? ""
        let decoded = try AICommandHook.decodeShellCommand(encoded)
        check(specific?["hookEventName"] as? String == "PreToolUse"
              && specific?["permissionDecision"] as? String == "allow"
              && decoded == complexHookCommand,
              "\(client.rawValue) hook rewrites the exact multiline shell program through tool-exec")
        check(updated?["description"] as? String == "synthetic quoting test"
              && updated?["timeout"] as? Int == 12_345
              && updated?["run_in_background"] as? Bool == true,
              "\(client.rawValue) hook preserves every unchanged Bash input field")
    } catch {
        check(false, "\(client.rawValue) hook rewrite succeeds")
    }
}

do {
    let claudeData = try AICommandHook.hookConfiguration(
        client: .claude,
        csecExecutablePath: "/opt/Convenient Security/csec"
    )
    let codexData = try AICommandHook.hookConfiguration(
        client: .codex,
        csecExecutablePath: "/opt/Convenient Security/csec"
    )
    let claudeObject = try JSONSerialization.jsonObject(with: claudeData) as? [String: Any]
    let claudeHooks = claudeObject?["hooks"] as? [String: Any]
    let claudeGroups = claudeHooks?["PreToolUse"] as? [[String: Any]]
    let claudeHandlers = claudeGroups?.first?["hooks"] as? [[String: Any]]
    let claudeHandler = claudeHandlers?.first
    let codexObject = try JSONSerialization.jsonObject(with: codexData) as? [String: Any]
    let codexHooks = codexObject?["hooks"] as? [String: Any]
    let codexGroups = codexHooks?["PreToolUse"] as? [[String: Any]]
    let codexHandlers = codexGroups?.first?["hooks"] as? [[String: Any]]
    let codexCommand = codexHandlers?.first?["command"] as? String
    let claudeArguments = claudeHandler?["args"] as? [String]
    check(claudeHandler?["command"] as? String == "/bin/sh"
          && claudeArguments?.first == "-c"
          && claudeArguments?.suffix(3) == [
              "csec-ai-hook", "/opt/Convenient Security/csec", "claude",
          ],
          "Claude hook configuration enters through a fixed fail-closed shell wrapper")
    check(codexCommand?.hasPrefix("/bin/sh -c ") == true
          && codexCommand?.contains("csec-ai-hook") == true
          && codexCommand?.contains("codex") == true,
          "Codex hook configuration safely carries the absolute path through the fail-closed wrapper")
    check(claudeHandler?["statusMessage"] as? String == AICommandHook.managedStatusMessage
          && codexHandlers?.first?["statusMessage"] as? String
              == AICommandHook.managedStatusMessage,
          "generated hook handlers carry a stable csec ownership marker")

    if let claudeArguments, let codexCommand {
        let missingClaude = Process()
        missingClaude.executableURL = URL(fileURLWithPath: "/bin/sh")
        missingClaude.arguments = Array(claudeArguments.dropLast(2))
            + ["/definitely/missing/csec", "claude"]
        missingClaude.standardOutput = Pipe()
        missingClaude.standardError = Pipe()
        try missingClaude.run()
        missingClaude.waitUntilExit()
        check(missingClaude.terminationStatus == 2,
              "Claude hook wrapper denies when the configured csec executable is unavailable")

        let missingCodexCommand = codexCommand.replacingOccurrences(
            of: "'/opt/Convenient Security/csec'",
            with: "'/definitely/missing/csec'"
        )
        let missingCodex = Process()
        missingCodex.executableURL = URL(fileURLWithPath: "/bin/sh")
        missingCodex.arguments = ["-c", missingCodexCommand]
        missingCodex.standardOutput = Pipe()
        missingCodex.standardError = Pipe()
        try missingCodex.run()
        missingCodex.waitUntilExit()
        check(missingCodex.terminationStatus == 2,
              "Codex hook wrapper denies when the configured csec executable is unavailable")
    }
} catch {
    check(false, "hook configurations serialize")
}

checkThrows("hook adapter rejects a non-Bash tool instead of silently passing it through") {
    let invalid = try JSONSerialization.data(withJSONObject: [
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": ["command": "true"],
    ])
    _ = try AICommandHook.rewrite(
        input: invalid,
        client: .claude,
        csecExecutablePath: "/usr/local/bin/csec"
    )
}
checkThrows("encoded hook command rejects malformed base64url") {
    _ = try AICommandHook.decodeShellCommand("not+base64")
}

print("\n# SetupOnboarding (dry-run planning, discovery, import, and audit prompt)")

do {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "csec-onboarding-selftest-\(UUID().uuidString)",
        isDirectory: true
    )
    let home = root.appendingPathComponent("home", isDirectory: true)
    let project = root.appendingPathComponent("project", isDirectory: true)
    let fakeBin = root.appendingPathComponent("bin", isDirectory: true)
    let codexDirectory = home.appendingPathComponent(".codex", isDirectory: true)
    let claudeDirectory = home.appendingPathComponent(".claude", isDirectory: true)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: fakeBin, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: codexDirectory, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: claudeDirectory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let freshHome = root.appendingPathComponent("fresh-home", isDirectory: true)
    try FileManager.default.createDirectory(
        at: freshHome,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: NSNumber(value: Int16(0o700))]
    )
    let freshClaudeDetection = try CodingAgentSetup.detect(
        homeDirectory: freshHome.path,
        pathEnvironment: ""
    ).first { $0.client == .claude }!
    let createPlan = try CodingAgentSetup.plan(
        detection: freshClaudeDetection,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    )
    check(createPlan.action == .create,
          "setup plans creation when a selected client's user configuration is absent")
    try CodingAgentSetup.apply(createPlan)
    var freshDirectoryInfo = stat()
    var freshConfigurationInfo = stat()
    _ = lstat(
        freshHome.appendingPathComponent(".claude", isDirectory: true).path,
        &freshDirectoryInfo
    )
    _ = lstat(freshClaudeDetection.configurationPath, &freshConfigurationInfo)
    check(freshDirectoryInfo.st_mode & 0o777 == 0o700
          && freshConfigurationInfo.st_mode & 0o777 == 0o600,
          "setup creates a private client directory and atomically installs a mode-0600 configuration")
    let createdPlan = try CodingAgentSetup.plan(
        detection: freshClaudeDetection,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    )
    check(createdPlan.action == .unchanged,
          "repeating setup after configuration creation is idempotent")

    let fakeCodex = fakeBin.appendingPathComponent("codex")
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: fakeCodex)
    try FileManager.default.setAttributes(
        [.posixPermissions: NSNumber(value: Int16(0o700))],
        ofItemAtPath: fakeCodex.path
    )
    let codexConfiguration = codexDirectory.appendingPathComponent("hooks.json")
    try Data(#"{"keep":{"theme":"dark"},"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"true"}]}]}}"#.utf8)
        .write(to: codexConfiguration)
    try FileManager.default.setAttributes(
        [.posixPermissions: NSNumber(value: Int16(0o640))],
        ofItemAtPath: codexConfiguration.path
    )

    var detections = try CodingAgentSetup.detect(
        homeDirectory: home.path,
        pathEnvironment: fakeBin.path
    )
    let codexDetection = detections.first { $0.client == .codex }!
    check(codexDetection.detected && codexDetection.executablePath == fakeCodex.path,
          "setup detects a supported coding agent without executing it")
    let mergePlan = try CodingAgentSetup.plan(
        detection: codexDetection,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    )
    check(mergePlan.action == .merge,
          "setup plans an additive merge for an existing user-owned Codex configuration")
    try CodingAgentSetup.apply(mergePlan)
    let mergedObject = try JSONSerialization.jsonObject(
        with: Data(contentsOf: codexConfiguration)
    ) as? [String: Any]
    let mergedKeep = mergedObject?["keep"] as? [String: Any]
    let mergedHooks = mergedObject?["hooks"] as? [String: Any]
    let mergedGroups = mergedHooks?["PreToolUse"] as? [[String: Any]]
    var mergedInfo = stat()
    _ = lstat(codexConfiguration.path, &mergedInfo)
    check(mergedKeep?["theme"] as? String == "dark"
          && mergedGroups?.count == 2,
          "setup preserves unrelated settings and hooks while appending its own handler")
    check(mergedInfo.st_mode & 0o777 == 0o640,
          "setup preserves an existing configuration file's mode")
    let unchangedPlan = try CodingAgentSetup.plan(
        detection: codexDetection,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    )
    check(unchangedPlan.action == .unchanged,
          "repeating setup with the same executable is idempotent")

    let legacyConfiguration = Data(#"{"keep":true,"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"'/old/csec' hook codex","timeout":5,"statusMessage":"Enabling protected output scanning"}]}]}}"#.utf8)
    try legacyConfiguration.write(to: codexConfiguration)
    let blockedPlan = try CodingAgentSetup.plan(
        detection: codexDetection,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    )
    check(blockedPlan.action == .blocked,
          "setup refuses to silently replace an older recognized csec hook")
    let replacementPlan = try CodingAgentSetup.plan(
        detection: codexDetection,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec",
        replaceExistingCSECHook: true
    )
    try CodingAgentSetup.apply(replacementPlan)
    let replacementObject = try JSONSerialization.jsonObject(
        with: Data(contentsOf: codexConfiguration)
    ) as? [String: Any]
    check(replacementObject?["keep"] as? Bool == true,
          "explicit csec-hook replacement still preserves unrelated user configuration")

    let desiredCodexData = try AICommandHook.hookConfiguration(
        client: .codex,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    )
    var wrongMatcherObject = try JSONSerialization.jsonObject(
        with: desiredCodexData
    ) as! [String: Any]
    var wrongMatcherHooks = wrongMatcherObject["hooks"] as! [String: Any]
    var wrongMatcherGroups = wrongMatcherHooks["PreToolUse"] as! [[String: Any]]
    wrongMatcherGroups[0]["matcher"] = "Write"
    wrongMatcherHooks["PreToolUse"] = wrongMatcherGroups
    wrongMatcherObject["hooks"] = wrongMatcherHooks
    try JSONSerialization.data(withJSONObject: wrongMatcherObject).write(to: codexConfiguration)
    let wrongMatcherPlan = try CodingAgentSetup.plan(
        detection: codexDetection,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    )
    check(wrongMatcherPlan.action == .blocked,
          "an exact csec handler under a non-Bash matcher is never mistaken for coverage")

    try Data(#"{"keep":1,"\u006beep":2,"keep":3}"#.utf8).write(to: codexConfiguration)
    checkThrows("setup rejects duplicate decoded JSON keys before a merge can collapse them") {
        _ = try CodingAgentSetup.plan(
            detection: codexDetection,
            csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
        )
    }

    try FileManager.default.removeItem(at: codexConfiguration)
    try FileManager.default.createSymbolicLink(
        atPath: codexConfiguration.path,
        withDestinationPath: codexDirectory.appendingPathComponent("missing-hooks.json").path
    )
    let symlinkDetection = try CodingAgentSetup.detect(
        homeDirectory: home.path,
        pathEnvironment: fakeBin.path
    ).first { $0.client == .codex }!
    check(symlinkDetection.configurationExists,
          "setup reports a dangling configuration symlink instead of treating its path as empty")
    checkThrows("setup refuses a dangling coding-agent configuration symlink") {
        _ = try CodingAgentSetup.plan(
            detection: symlinkDetection,
            csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
        )
    }

    let claudeConfiguration = claudeDirectory.appendingPathComponent("settings.json")
    try Data(#"{"disableAllHooks":true}"#.utf8).write(to: claudeConfiguration)
    detections = try CodingAgentSetup.detect(
        homeDirectory: home.path,
        pathEnvironment: fakeBin.path
    )
    let claudeDetection = detections.first { $0.client == .claude }!
    let disabledPlan = try CodingAgentSetup.plan(
        detection: claudeDetection,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    )
    check(disabledPlan.action == .blocked,
          "setup surfaces Claude's disableAllHooks policy instead of silently overriding it")

    try Data(#"{"theme":"one"}"#.utf8).write(to: claudeConfiguration)
    let racePlan = try CodingAgentSetup.plan(
        detection: claudeDetection,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    )
    let concurrentlyEdited = Data(#"{"theme":"changed-by-user"}"#.utf8)
    try concurrentlyEdited.write(to: claudeConfiguration)
    checkThrows("setup never overwrites a coding-agent config changed after planning") {
        try CodingAgentSetup.apply(racePlan)
    }
    check(try Data(contentsOf: claudeConfiguration) == concurrentlyEdited,
          "a concurrent user edit remains byte-for-byte intact")

    let sameBytes = Data(#"{"theme":"same-bytes-new-file"}"#.utf8)
    try sameBytes.write(to: claudeConfiguration)
    let replacementRacePlan = try CodingAgentSetup.plan(
        detection: claudeDetection,
        csecExecutablePath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    )
    try FileManager.default.removeItem(at: claudeConfiguration)
    try sameBytes.write(to: claudeConfiguration)
    checkThrows("setup detects a same-byte configuration replacement by file identity") {
        try CodingAgentSetup.apply(replacementRacePlan)
    }

    let dotenvMarker = "dotenv-synthetic-value-never-in-audit"
    let environmentMarker = "environment-synthetic-value-never-in-audit"
    try Data("""
    PORT=3000
    API_TOKEN='\(dotenvMarker)'
    DATABASE_URL=op://Synthetic/Database/url
    EXPANDED_SECRET="$TOKEN"
    """.utf8).write(to: project.appendingPathComponent(".env.local"))
    let linkedDotenv = root.appendingPathComponent("external.env")
    try Data("LINKED_SECRET=must-not-be-followed\n".utf8).write(to: linkedDotenv)
    try FileManager.default.createSymbolicLink(
        atPath: project.appendingPathComponent(".env.symlink").path,
        withDestinationPath: linkedDotenv.path
    )
    let environment = [
        "SESSION_SECRET": environmentMarker,
        "CSEC_REFERENCE": "csec://development/EXISTING_TOKEN",
        "PORT": "4000",
    ]
    let discovery = try LocalSecretDiscoveryEngine.discover(
        projectDirectory: project.path,
        environment: environment
    )
    check(discovery.candidates.contains {
        $0.locator.identifier == "env:SESSION_SECRET" && $0.kind == .plaintextCandidate
    }, "setup detects a secret-named environment candidate without reporting its value")
    check(discovery.candidates.contains {
        $0.locator.identifier == "dotenv:.env.local:DATABASE_URL"
            && $0.kind == .reference
            && $0.reference == "op://Synthetic/Database/url"
    }, "setup detects supported logical references as value-safe metadata")
    check(discovery.candidates.contains {
        $0.locator.identifier == "dotenv:.env.local:EXPANDED_SECRET"
            && $0.kind == .unsupported
    }, "setup flags ambiguous dotenv interpolation instead of guessing its value")
    check(!discovery.candidates.contains { $0.locator.identifier == "env:PORT" },
          "setup omits ordinary non-secret-looking environment entries")
    // The walker now accumulates each directory's path relative to the root
    // instead of slicing an entry's standardized absolute path (which the macOS
    // /var firmlink normalizes, silently dropping every match). Cover the nested
    // case that the relative accumulation must get right.
    try FileManager.default.createDirectory(
        at: project.appendingPathComponent("config"), withIntermediateDirectories: true)
    try Data("NESTED_TOKEN='nested-synthetic-never-in-audit'\n".utf8).write(
        to: project.appendingPathComponent("config/.env"))
    let nestedDiscovery = try LocalSecretDiscoveryEngine.discover(
        projectDirectory: project.path,
        environment: [:]
    )
    check(nestedDiscovery.candidates.contains {
        $0.locator.identifier == "dotenv:config/.env:NESTED_TOKEN"
    }, "the relative-path walk resolves a nested dotenv file's project path")
    check(!discovery.candidates.contains {
        $0.locator.identifier == "dotenv:.env.symlink:LINKED_SECRET"
    }, "setup never follows a discovered dotenv symlink")
    checkThrows("an explicitly selected dotenv symlink is refused") {
        _ = try LocalSecretDiscoveryEngine.load(
            .dotenv(relativePath: ".env.symlink", name: "LINKED_SECRET"),
            projectDirectory: project.path,
            environment: environment
        )
    }
    let selectedDotenvCandidate = discovery.candidates.first {
        $0.locator.identifier == "dotenv:.env.local:API_TOKEN"
    }!
    let loadedDotenv = try LocalSecretDiscoveryEngine.load(
        selectedDotenvCandidate,
        projectDirectory: project.path,
        environment: environment
    )
    check(loadedDotenv == dotenvMarker,
          "an explicitly selected supported dotenv entry can be loaded for import")
    try Data("API_TOKEN='changed-after-discovery'\n".utf8)
        .write(to: project.appendingPathComponent(".env.local"))
    checkThrows("apply rejects a dotenv file changed after its in-process review") {
        _ = try LocalSecretDiscoveryEngine.load(
            selectedDotenvCandidate,
            projectDirectory: project.path,
            environment: environment
        )
    }
    try Data("API_TOKEN=csec://development/CHANGED_REFERENCE\n".utf8)
        .write(to: project.appendingPathComponent(".env.local"))
    checkThrows("apply refuses a plaintext candidate that changed into a logical reference") {
        _ = try LocalSecretDiscoveryEngine.load(
            .dotenv(relativePath: ".env.local", name: "API_TOKEN"),
            projectDirectory: project.path,
            environment: environment
        )
    }
    try Data("API_TOKEN='\(dotenvMarker)'\n".utf8)
        .write(to: project.appendingPathComponent(".env.local"))

    let initialStore = try NativeStoreDocument(values: ["EXISTING": "preserved"])
    let importedStoreData = try NativeStoreImport.merge(
        existingDocument: initialStore.encoded(),
        selectedValues: ["API_TOKEN": loadedDotenv],
        replaceExisting: false
    )
    let importedStore = try NativeStoreDocument(data: importedStoreData)
    check(importedStore.values["EXISTING"] == "preserved"
          && importedStore.values["API_TOKEN"] == dotenvMarker,
          "selected import merges into the strict native document without replacing other keys")
    checkThrows("native import protects an existing destination key by default") {
        _ = try NativeStoreImport.merge(
            existingDocument: initialStore.encoded(),
            selectedValues: ["EXISTING": "replacement"],
            replaceExisting: false
        )
    }

    let auditPrompt = try OnboardingAuditPrompt.generate(facts: OnboardingAuditFacts(
        projectDirectory: project.path + "/```untrusted-fence",
        launchAgentStatus: "not registered",
        productAgentReachable: false,
        providerSchemes: [],
        rootHelperReachable: false,
        sipStatus: .enabled,
        codingAgentPlans: [unchangedPlan],
        discovery: discovery
    ))
    check(auditPrompt.utf8.count <= OnboardingAuditPrompt.maximumBytes
          && auditPrompt.contains("Start read-only and remain value-free")
          && auditPrompt.contains("ship/hold recommendation"),
          "setup generates a bounded audit prompt with concrete evidence and decision requirements")
    check(!auditPrompt.contains(dotenvMarker) && !auditPrompt.contains(environmentMarker),
          "the generated audit prompt contains no discovered plaintext values")
    check(auditPrompt.components(separatedBy: "```").count == 3
          && !auditPrompt.contains("```untrusted-fence"),
          "untrusted metadata cannot terminate the audit prompt's JSON fence")

    let longMetadata = String(repeating: "bounded-metadata-", count: 96)
    let crowdedDiscovery = LocalSecretDiscovery(
        candidates: (0..<LocalSecretDiscoveryEngine.maximumCandidateCount).map {
            LocalSecretCandidate(
                locator: .dotenv(
                    relativePath: "\(longMetadata)-\($0)/.env.local",
                    name: "TOKEN_\($0)"
                ),
                kind: .plaintextCandidate
            )
        },
        sources: (0..<32).map {
            LocalSecretSourceSummary(
                source: "\(longMetadata)-\($0)",
                protection: longMetadata,
                candidateCount: 8,
                unsupportedEntryCount: 0
            )
        },
        warnings: (0..<32).map { "\(longMetadata)-warning-\($0)" },
        omittedCandidateCount: 10
    )
    let crowdedPrompt = try OnboardingAuditPrompt.generate(facts: OnboardingAuditFacts(
        projectDirectory: "/" + longMetadata,
        launchAgentStatus: longMetadata,
        productAgentReachable: true,
        providerSchemes: (0..<32).map { "scheme-\($0)-\(longMetadata)" },
        rootHelperReachable: true,
        sipStatus: .enabled,
        codingAgentPlans: [],
        discovery: crowdedDiscovery
    ))
    check(crowdedPrompt.utf8.count <= OnboardingAuditPrompt.maximumBytes
          && crowdedPrompt.contains("\"omitted_candidates\"")
          && crowdedPrompt.contains("\"omitted_sources\""),
          "the audit prompt trims crowded metadata deterministically instead of exceeding its byte bound")
} catch {
    check(false, "setup onboarding checks succeed (\(error))")
}

print("\n# BiometricConsent (prompt formatting + availability, no actual prompt)")

// The consent prompt must state exactly what is granted, to whom, and for how long.
let promptRef = try! SecretRef("op://vault/db/url")
let promptText = BiometricConsent.prompt(
    caller: CallerInfo(pid: 4242, startTime: 1, description: "ruby (pid 4242)"),
    references: [promptRef],
    reason: "run migrations",
    ttl: 8 * 3600
)
check(promptText.contains("vault: vault"), "prompt identifies the vault")
check(promptText.contains("item: db"), "prompt identifies the item")
check(promptText.contains("field: url"), "prompt identifies the field")
check(promptText.contains("ruby (pid 4242)"), "prompt names the requesting process")
check(promptText.contains("run migrations"), "prompt states the caller's reason")
check(promptText.contains("8h"), "prompt states the grant duration")

let policyPrompt = BiometricConsent.prompt(
    caller: CallerInfo(pid: 4242, startTime: 1, description: "ruby"),
    references: [promptRef],
    reason: "run migrations",
    ttl: 15 * 60,
    policySummary: "delivery direct_heap; root per-command; scope subtree"
)
check(policyPrompt.contains("policy: delivery direct_heap; root per-command; scope subtree"),
      "the OS authentication prompt binds the value-free delivery policy summary")

let spoofedPrompt = BiometricConsent.prompt(
    caller: CallerInfo(pid: 4242, startTime: 1, description: "ruby\nverified launcher"),
    references: [promptRef],
    reason: "run tests\ncritical approved",
    ttl: 60
)
check(!spoofedPrompt.contains("ruby\nverified launcher")
      && !spoofedPrompt.contains("run tests\ncritical approved"),
      "caller and reason cannot inject consent-prompt lines")

check(BiometricConsent.formatDuration(45) == "45s", "duration under a minute renders as seconds")
check(BiometricConsent.formatDuration(600) == "10 min", "duration under an hour renders as minutes")
check(BiometricConsent.formatDuration(8 * 3600) == "8h", "whole-hour duration renders as hours")
check(BiometricConsent.formatDuration(3 * 3600 + 30 * 60) == "3h 30m", "mixed duration renders hours and minutes")

// canEvaluatePolicy is a non-interactive capability probe — it never prompts, so
// it's safe to call here. Availability varies by machine; just report it.
let laContext = LAContext()
var laError: NSError?
let biometricsAvailable = laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laError)
print("info - Touch ID available on this machine: \(biometricsAvailable)" +
      (laError.map { " (\($0.localizedDescription))" } ?? ""))
check(true, "LocalAuthentication links and canEvaluatePolicy runs without prompting")

// The advisory process name should resolve for the running self-test process.
check(ProcessAncestry.name(of: getpid()) != nil, "own process name resolves (advisory consent label)")

print("\n# KeychainSecretCache (warm/cold tiers, in-memory backend — no keychain, no biometrics)")

// A CacheUnlock just needs a context object; constructing one never prompts.
let unlock = CacheUnlock(LAContext())

do {
    let backend = FakeKeychainBackend()
    let cache = KeychainSecretCache(backend: backend)

    try await cache.put("op://vault/db/url", value: Data("postgres://s3cr3t".utf8), maxAge: 3600)
    check(try await cache.get("op://vault/db/url", unlock: nil) == Data("postgres://s3cr3t".utf8),
          "warm hit serves an in-grant fetch with no unlock (zero touches)")
    check(await backend.loadCount == 0, "a warm hit never consults the keychain backend")

    // A fresh cache over the same backend = the keychain surviving a restart.
    let afterRestart = KeychainSecretCache(backend: backend)
    check(try await afterRestart.get("op://vault/db/url", unlock: unlock) == Data("postgres://s3cr3t".utf8),
          "cold keychain read serves after a restart when the consent context is supplied")
    check(await backend.loadCount == 1, "the cold read consults the backend exactly once")
    check(try await afterRestart.get("op://vault/db/url", unlock: nil) == Data("postgres://s3cr3t".utf8),
          "a cold hit is promoted to the warm tier and served free thereafter")
    check(await backend.loadCount == 1, "the promoted value is not re-read from the backend")

    // The security-critical invariant: no consent context ⇒ the cache never
    // reaches for the keychain, so it can't raise a prompt nobody consented to.
    let unconsented = KeychainSecretCache(backend: backend)
    check(try await unconsented.get("op://vault/db/url", unlock: nil) == nil,
          "a cold value is NOT served without a consent context")
    check(await backend.loadCount == 1, "no consent context ⇒ the backend/biometric is never consulted")

    // An expired warm entry with no unlock is a plain miss (falls through to the
    // provider), not a surprise biometric.
    let warmExpiry = FakeKeychainBackend()
    let warmExpiryCache = KeychainSecretCache(backend: warmExpiry)
    try await warmExpiryCache.put("op://vault/short/lived", value: Data("STALE".utf8), maxAge: -1)
    check(try await warmExpiryCache.get("op://vault/short/lived", unlock: nil) == nil,
          "an expired warm entry with no unlock is a miss, not a prompt")
    check(await warmExpiry.loadCount == 0, "expired warm + no unlock never consults the backend")

    // A cold entry past its maxAge is dropped on read, not served.
    let coldExpiry = FakeKeychainBackend()
    let coldWriter = KeychainSecretCache(backend: coldExpiry)
    try await coldWriter.put("op://vault/expired", value: Data("OLD".utf8), maxAge: -1)
    let coldReader = KeychainSecretCache(backend: coldExpiry)
    check(try await coldReader.get("op://vault/expired", unlock: unlock) == nil,
          "an expired cold entry is not served")
    check(!(await coldExpiry.has("op://vault/expired")), "an expired cold entry is deleted on read")

    // invalidate clears both tiers.
    let invBackend = FakeKeychainBackend()
    let invCache = KeychainSecretCache(backend: invBackend)
    try await invCache.put("op://vault/rotated", value: Data("V".utf8), maxAge: 3600)
    await invCache.invalidate("op://vault/rotated")
    check(try await invCache.get("op://vault/rotated", unlock: unlock) == nil,
          "invalidate removes the value from the warm tier")
    check(!(await invBackend.has("op://vault/rotated")), "invalidate deletes the keychain item")
} catch {
    check(false, "KeychainSecretCache checks threw unexpectedly: \(error)")
}

// Host posture audit — core guarantees + per-domain check coverage.
await hostAuditCoreTests()
await hostAuditTests_A()
await hostAuditTests_B()
await hostAuditTests_C()
await hostAuditTests_D()
await hostAuditTests_E()
await hostAuditTests_F()
await hostAuditTests_G()
await hostAuditTests_H()
await hostAuditTests_I()
await hostAuditTests_J()
await hostAuditTests_K()
await hostAuditStreamingTests()
hostAuditStreamingSocketTests()
hostAuditRootProtocolTests()
hostAuditTriageTests()
secretHeuristicsTests()
envFileDocumentTests()
envSelectModelTests()
secretDestinationSpecTests()
onePasswordItemWriteTests()

if failures == 0 {
    print("\nAll checks passed.")
    exit(0)
} else {
    FileHandle.standardError.write(Data("\n\(failures) check(s) failed.\n".utf8))
    exit(1)
}
