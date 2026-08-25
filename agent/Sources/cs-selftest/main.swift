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

actor FakeRiskJudgmentBackend: RiskJudgmentBackend {
    private var items: [String: Data] = [:]

    func load(service: String, account: String) async throws -> Data? {
        items["\(service)|\(account)"]
    }

    func store(service: String, account: String, data: Data) async throws {
        items["\(service)|\(account)"] = data
    }

    func delete(service: String, account: String) async throws {
        items["\(service)|\(account)"] = nil
    }

    func snapshot() -> [String: Data] { items }
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
    check(warm.value == "native-postgres-secret" && warm.cacheHint == .noCache,
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
    check(try await afterRestart.resolve(ref, unlock: nativeUnlock).value == "native-postgres-secret",
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

print("\n# GrantTable (policy-bound reuse and revocation)")

if let myStart = ProcessAncestry.startTime(of: me) {
    let table = GrantTable()
    let binding = PolicyGrantBinding(
        credentialKey: "opaque-credential",
        riskLevel: .standard,
        policyVersion: RiskPolicyV1.version,
        policyDigest: "policy-a",
        outputPolicy: .exactMatchRedactAndWarn
    )
    await table.add(Grant(
        rootPID: me,
        rootStartTime: myStart,
        references: ["op://vault/item/password"],
        reason: "synthetic",
        expiresAt: Date().addingTimeInterval(60),
        deliveryPlanDigest: "plan-a",
        policyBinding: binding
    ))
    check(await table.accessibleReferences(
        for: me,
        now: Date(),
        deliveryPlanDigest: "plan-a",
        policyBindingsByReference: ["op://vault/item/password": binding]
    ) == ["op://vault/item/password"],
    "a live grant is reusable only with its exact plan and policy binding")

    let changedBinding = PolicyGrantBinding(
        credentialKey: binding.credentialKey,
        riskLevel: .high,
        policyVersion: binding.policyVersion,
        policyDigest: "policy-b",
        outputPolicy: .stopAndSuppressOnMatch
    )
    check(await table.accessibleReferences(
        for: me,
        now: Date(),
        deliveryPlanDigest: "plan-a",
        policyBindingsByReference: ["op://vault/item/password": changedBinding]
    ).isEmpty, "a changed risk/policy snapshot cannot reuse an old grant")

    check(await table.revoke(credentialKey: binding.credentialKey)
          == ["op://vault/item/password"],
          "targeted risk revocation returns affected in-memory cache identities")
    check(await table.accessibleReferences(
        for: me,
        now: Date(),
        deliveryPlanDigest: "plan-a",
        policyBindingsByReference: ["op://vault/item/password": binding]
    ).isEmpty, "targeted risk revocation removes the live grant")

    let oldVersion = PolicyGrantBinding(
        credentialKey: "old-policy-credential",
        riskLevel: .low,
        policyVersion: RiskPolicyV1.version - 1,
        policyDigest: "old-policy",
        outputPolicy: .exactMatchRedactAndWarn
    )
    await table.add(Grant(
        rootPID: me,
        rootStartTime: myStart,
        references: ["csec://test/TOKEN"],
        reason: "synthetic old policy",
        expiresAt: Date().addingTimeInterval(60),
        policyBinding: oldVersion
    ))
    check(await table.revalidate(policyVersion: RiskPolicyV1.version)
          == ["csec://test/TOKEN"],
          "a policy-version change revokes grants created by older policy code")
} else {
    check(false, "policy-bound grant tests can read their root start time")
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
        values: [rawBinding.reference: "regular-file-synthetic-value"]
    )
    check(rawPayloads.count == 1
          && rawPayloads[0].relativePath == "files/credential-0"
          && rawPayloads[0].data == Data("regular-file-synthetic-value".utf8),
          "raw regular-file rendering preserves exact UTF-8 bytes")
    checkThrows("regular-file rendering rejects an empty payload") {
        _ = try ProtectedFilePayloadRenderer.render(
            bindings: [rawBinding],
            values: [rawBinding.reference: ""]
        )
    }
    checkThrows("regular-file rendering rejects unbound extra values") {
        _ = try ProtectedFilePayloadRenderer.render(
            bindings: [rawBinding],
            values: [
                rawBinding.reference: "synthetic",
                "op://regular-file/unbound/content": "synthetic-extra",
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
        values: [githubBinding.reference: "synthetic-'github-token"]
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
            values: [githubBinding.reference: "synthetic\nforged: true"]
        )
    }

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
        environmentName: binding.environmentName,
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
    requestedTTLSeconds: 3600,
    operationContext: "interactive get"
)
check((try? shellRootedPlan.digest()) != (try? otherShellRootedPlan.digest()),
      "direct-parent requester identity changes the bound plan digest")
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
let guardedOutputDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-output-binding",
    storedLevel: .low,
    evidence: [],
    plan: guardedEnvPlan,
    now: Date(timeIntervalSince1970: 2_000_000_000)
))
let unguardedOutputDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-output-binding",
    storedLevel: .low,
    evidence: [],
    plan: unguardedEnvPlan,
    now: Date(timeIntervalSince1970: 2_000_000_000)
))
check(guardedOutputDecision.policyDigest != unguardedOutputDecision.policyDigest,
      "output-guard configuration changes the policy decision digest")

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
    let risk = RiskOperationRequest(
        operation: .classify,
        reference: "csec://development/TOKEN",
        level: .high,
        requestID: UUID(uuidString: "bbbbbbbb-cccc-dddd-eeee-ffffffffffff")!
    )
    let riskData = try JSONEncoder().encode(Request.risk(risk))
    let riskDecoded = try JSONDecoder().decode(Request.self, from: riskData)
    if case let .risk(roundTrip) = riskDecoded {
        check(roundTrip.operation == .classify
              && roundTrip.reference == "csec://development/TOKEN"
              && roundTrip.level == .high,
              "value-free risk operations round-trip with explicit level semantics")
    } else {
        check(false, "risk operation decodes as the correct request")
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

print("\n# RiskPolicyV1 (preview, pure decisions)")

let policyNow = Date(timeIntervalSince1970: 2_000_000_000)
let unknownDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-credential",
    storedLevel: .unknown,
    evidence: [],
    plan: basePlan,
    now: policyNow
))
check(unknownDecision.effectiveLevel == .high,
      "unknown credentials are enforced at the high floor")
check(!unknownDecision.allowed && unknownDecision.denialReason == .classificationRequired,
      "unknown credentials fail closed pending classification")

let lowEnvDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-low",
    storedLevel: .low,
    evidence: [],
    plan: envPlan,
    now: policyNow
))
check(lowEnvDecision.allowed, "low-risk policy permits labeled compatibility env delivery")
check(lowEnvDecision.ttlCapSeconds == 12 * 3600,
      "low-risk TTL cap comes from the centralized table")

let standardWithoutAcceptance = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-standard",
    storedLevel: .standard,
    evidence: [],
    plan: envPlan,
    now: policyNow
))
check(!standardWithoutAcceptance.allowed
      && standardWithoutAcceptance.denialReason == .compatibilityAcceptanceRequired,
      "standard-risk env delivery requires a separate cached acceptance")

let acceptance = DeliveryAcceptance(
    credentialKey: "opaque-standard",
    mechanism: .unrestrictedInitialEnvironment,
    consumerAssurance: .userWritable,
    policyVersion: RiskPolicyV1.version,
    acceptedAt: policyNow.addingTimeInterval(-60),
    reviewAfter: policyNow.addingTimeInterval(3600)
)
let standardWithAcceptance = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-standard",
    storedLevel: .standard,
    evidence: [],
    plan: envPlan,
    acceptance: acceptance,
    now: policyNow
))
check(standardWithAcceptance.allowed,
      "matching unexpired delivery acceptance permits standard compatibility env")

let aiSubtreePlan = DeliveryPlan(
    mechanism: .directHeap,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .subtree,
    destination: .aiTool,
    requestedTTLSeconds: 300,
    operationContext: "AI-assisted development"
)
let aiSubtreeDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-standard",
    storedLevel: .standard,
    evidence: [],
    plan: aiSubtreePlan,
    now: policyNow
))
check(!aiSubtreeDecision.allowed
      && aiSubtreeDecision.denialReason == .descendantScopeTooBroad,
      "standard-risk access does not implicitly grant an AI process subtree")

let criticalEvidence = RiskEvidence(
    category: .authority,
    floor: .critical,
    source: .providerMetadata,
    evidenceDigest: "opaque-evidence",
    observedAt: policyNow
)
let raisedDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-low",
    storedLevel: .low,
    evidence: [criticalEvidence],
    plan: basePlan,
    now: policyNow
))
check(raisedDecision.effectiveLevel == .critical,
      "provider evidence raises a cached low judgment")
check(!raisedDecision.allowed && raisedDecision.denialReason == .consumerAssuranceInsufficient,
      "critical policy rejects a user-writable consumer")

let protectedHighPlan = DeliveryPlan(
    mechanism: .directHeap,
    executable: PlannedExecutable(
        canonicalPath: "/usr/bin/security",
        assurance: .independentlyProtected
    ),
    root: .caller,
    descendantScope: .exactProcess,
    destination: .production,
    requestedTTLSeconds: 3600,
    operationContext: "bounded production read"
)
let highDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-high",
    storedLevel: .high,
    evidence: [],
    plan: protectedHighPlan,
    now: policyNow
))
check(highDecision.allowed && highDecision.grantedTTLSeconds == 15 * 60,
      "high-risk protected exact-process delivery is allowed with a 15-minute cap")
check(highDecision.outputPolicy == .stopAndSuppressOnMatch,
      "high-risk output matches fail closed")
check(highDecision.policyDigest == RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-high",
    storedLevel: .high,
    evidence: [],
    plan: protectedHighPlan,
    now: policyNow
)).policyDigest, "identical policy inputs yield a stable policy digest")

let highSessionPlan = DeliveryPlan(
    mechanism: .inheritedFileDescriptor,
    executable: PlannedExecutable(
        canonicalPath: "/usr/bin/security",
        assurance: .independentlyProtected
    ),
    root: .registeredSession(id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
    descendantScope: .broadSession,
    destination: .localDevelopment,
    requestedTTLSeconds: 300,
    operationContext: "broad high-risk session"
)
let highSessionDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-high-session",
    storedLevel: .high,
    evidence: [],
    plan: highSessionPlan,
    now: policyNow
))
check(!highSessionDecision.allowed
      && highSessionDecision.denialReason == .descendantScopeTooBroad,
      "high-risk credentials retain per-command roots instead of broad sessions")

print("\n# RiskJudgmentStore (opaque metadata, in-memory backend)")

do {
    let backend = FakeRiskJudgmentBackend()
    let store = RiskJudgmentStore(backend: backend)
    let rawAccount = "synthetic-account-name"
    let rawGroup = "Synthetic Vault/Synthetic Item"
    let rawMember = "op://Synthetic Vault/Synthetic Item/password"
    let identity = try await store.credentialIdentity(
        provider: "op",
        providerAccount: rawAccount,
        group: rawGroup,
        memberReferences: [rawMember]
    )
    check(identity.credentialKey.count == 64 && identity.memberReferenceKeys.first?.count == 64,
          "credential and member identities are keyed opaque hashes")
    check(identity.credentialKey != identity.memberReferenceKeys.first,
          "logical credential and member use domain-separated opaque IDs")

    let sameIdentity = try await RiskJudgmentStore(backend: backend).credentialIdentity(
        provider: "op",
        providerAccount: rawAccount,
        group: rawGroup,
        memberReferences: [rawMember]
    )
    check(sameIdentity == identity, "device-key identity remains stable across store restarts")

    let judgment = RiskJudgment(
        credential: identity,
        level: .standard,
        evidence: [],
        source: .explicitUser,
        decidedAt: policyNow,
        reviewAfter: policyNow.addingTimeInterval(3600),
        policyVersion: RiskPolicyV1.version
    )
    try await store.save(judgment)
    check(try await store.load(
        credentialKey: identity.credentialKey,
        policyVersion: RiskPolicyV1.version,
        at: policyNow
    ) == judgment, "current judgment round-trips separately from grants and values")

    let storedAcceptance = DeliveryAcceptance(
        credentialKey: identity.credentialKey,
        mechanism: .unrestrictedInitialEnvironment,
        consumerAssurance: .unverified,
        policyVersion: RiskPolicyV1.version,
        acceptedAt: policyNow,
        reviewAfter: policyNow.addingTimeInterval(3600)
    )
    try await store.save(storedAcceptance)
    check(try await store.loadAcceptance(
        credentialKey: identity.credentialKey,
        mechanism: .unrestrictedInitialEnvironment,
        assurance: .unverified,
        policyVersion: RiskPolicyV1.version,
        at: policyNow
    ) == storedAcceptance, "weaker-delivery acceptance is stored separately from risk judgment")

    let storedText = await backend.snapshot().reduce(into: "") { partial, item in
        partial += item.key
        partial += String(data: item.value, encoding: .utf8) ?? ""
    }
    check(!storedText.contains(rawAccount)
          && !storedText.contains(rawGroup)
          && !storedText.contains(rawMember),
          "persisted judgment records contain no raw account, item, or reference")

    check(try await store.load(
        credentialKey: identity.credentialKey,
        policyVersion: RiskPolicyV1.version + 1,
        at: policyNow
    ) == nil, "policy-version change invalidates and removes a cached judgment")
} catch {
    check(false, "risk judgment store checks succeed (\(error))")
}

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
) == "production", "native edit access and native keys share the store-level judgment")

let namedFilePlan = DeliveryPlan(
    mechanism: .namedPlaintextFile,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .exactProcess,
    destination: .localDevelopment,
    requestedTTLSeconds: 300,
    operationContext: "external editor"
)
let namedFileDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-standard",
    storedLevel: .standard,
    evidence: [],
    plan: namedFilePlan,
    now: policyNow
))
check(!namedFileDecision.allowed
      && namedFileDecision.denialReason == .compatibilityAcceptanceRequired,
      "named plaintext files require separate acceptance at standard risk")

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
    values: ["op://vault/db/url": "postgres://resolved"]
) {
    check(env["DATABASE_URL"] == "postgres://resolved", "resolved value replaces the placeholder")
    check(env["PATH"] == "/usr/bin", "unrelated variables are preserved")
} else {
    check(false, "resolvedEnvironment succeeds")
}

// With an empty base it yields exactly the injected subset (the exec code path).
check((try? ExecPlanner.resolvedEnvironment(
    base: [:], plan: injectPlan, values: ["op://vault/db/url": "postgres://resolved"]
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
        values: ["op://vault/db/url": "synthetic\0value"]
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

let encodedCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/Output/token": "alpha:/\"beta-token"]
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
    valuesByReference: ["op://Synthetic/short": "tiny"]
)
check(shortCatalog.patterns.isEmpty && shortCatalog.skippedShortValueCount == 1,
      "short common values are excluded from automatic destructive matching")
let optedInShortCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/short": "tiny"],
    includeShortValues: true
)
check(!optedInShortCatalog.patterns.isEmpty,
      "short-value matching requires an explicit opt-in")

let referenceCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/Output/token": "synthetic-output-token"],
    labelStyle: .reference
)
let referenceRedaction = redact(
    patterns: referenceCatalog.patterns,
    chunks: [Data("synthetic-output-token".utf8)]
)
check(referenceRedaction.data == Data("op://Synthetic/Output/token".utf8),
      "reference-shaped replacement is available only through the opt-in catalog style")

let unsafeReferenceCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/item/field\nforged\u{202e}": "synthetic-control-token"],
    labelStyle: .reference
)
let unsafeReferenceRedaction = redact(
    patterns: unsafeReferenceCatalog.patterns,
    chunks: [Data("synthetic-control-token".utf8)]
)
check(unsafeReferenceRedaction.data == Data("op://Synthetic/item/field�forged�".utf8),
      "reference-shaped output cannot inject lines or bidirectional controls")

let collisionSource = "synthetic-collision-source"
let collisionExact = Data(collisionSource.utf8).base64EncodedString()
let collisionCatalog = OutputRedactionCatalog(
    valuesByReference: [
        "op://Synthetic/a-derived": collisionSource,
        "op://Synthetic/b-exact": collisionExact,
    ],
    labelStyle: .reference
)
let collisionRedaction = redact(
    patterns: collisionCatalog.patterns,
    chunks: [Data(collisionExact.utf8)]
)
check(collisionRedaction.data == Data("op://Synthetic/b-exact".utf8)
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
    policySummary: "risk high × 1; delivery direct_heap"
)
check(policyPrompt.contains("policy: risk high × 1; delivery direct_heap"),
      "the OS authentication prompt binds the selected risk and delivery policy")

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

    try await cache.put("op://vault/db/url", value: "postgres://s3cr3t", maxAge: 3600)
    check(try await cache.get("op://vault/db/url", unlock: nil) == "postgres://s3cr3t",
          "warm hit serves an in-grant fetch with no unlock (zero touches)")
    check(await backend.loadCount == 0, "a warm hit never consults the keychain backend")

    // A fresh cache over the same backend = the keychain surviving a restart.
    let afterRestart = KeychainSecretCache(backend: backend)
    check(try await afterRestart.get("op://vault/db/url", unlock: unlock) == "postgres://s3cr3t",
          "cold keychain read serves after a restart when the consent context is supplied")
    check(await backend.loadCount == 1, "the cold read consults the backend exactly once")
    check(try await afterRestart.get("op://vault/db/url", unlock: nil) == "postgres://s3cr3t",
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
    try await warmExpiryCache.put("op://vault/short/lived", value: "STALE", maxAge: -1)
    check(try await warmExpiryCache.get("op://vault/short/lived", unlock: nil) == nil,
          "an expired warm entry with no unlock is a miss, not a prompt")
    check(await warmExpiry.loadCount == 0, "expired warm + no unlock never consults the backend")

    // A cold entry past its maxAge is dropped on read, not served.
    let coldExpiry = FakeKeychainBackend()
    let coldWriter = KeychainSecretCache(backend: coldExpiry)
    try await coldWriter.put("op://vault/expired", value: "OLD", maxAge: -1)
    let coldReader = KeychainSecretCache(backend: coldExpiry)
    check(try await coldReader.get("op://vault/expired", unlock: unlock) == nil,
          "an expired cold entry is not served")
    check(!(await coldExpiry.has("op://vault/expired")), "an expired cold entry is deleted on read")

    // invalidate clears both tiers.
    let invBackend = FakeKeychainBackend()
    let invCache = KeychainSecretCache(backend: invBackend)
    try await invCache.put("op://vault/rotated", value: "V", maxAge: 3600)
    await invCache.invalidate("op://vault/rotated")
    check(try await invCache.get("op://vault/rotated", unlock: unlock) == nil,
          "invalidate removes the value from the warm tier")
    check(!(await invBackend.has("op://vault/rotated")), "invalidate deletes the keychain item")
} catch {
    check(false, "KeychainSecretCache checks threw unexpectedly: \(error)")
}

if failures == 0 {
    print("\nAll checks passed.")
    exit(0)
} else {
    FileHandle.standardError.write(Data("\n\(failures) check(s) failed.\n".utf8))
    exit(1)
}
