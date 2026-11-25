import ConvenientSecurity
import Foundation

actor BulkProtectionReviewMutation {
    private var action: (@Sendable () throws -> Void)?
    private var succeeded = false

    func arm(_ action: @escaping @Sendable () throws -> Void) {
        self.action = action
        succeeded = false
    }

    func run() {
        guard let action else { return }
        self.action = nil
        do { try action(); succeeded = true } catch { succeeded = false }
    }

    func didRun() -> Bool { succeeded }
}

let bulkProtectionReviewMutation = BulkProtectionReviewMutation()

/// Every invocation has its own synthetic home, explicit scan root and scrubbed
/// environment. No host credential location or installed daemon is consulted.
@MainActor func bulkProtectionHardlinkTests() async {
    print("\n# Bulk protection hardlinks")
    let fm = FileManager.default
    let root = NSTemporaryDirectory() + "csec-hardlinks-e2e-\(UUID().uuidString.lowercased())"
    defer { try? fm.removeItem(atPath: root) }
    do {
        let keyPath = root + "/synthetic-key"
        try fm.createDirectory(atPath: root, withIntermediateDirectories: true)
        let keygen = Process()
        keygen.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        keygen.arguments = ["-q", "-t", "ed25519", "-N", "", "-f", keyPath]
        keygen.standardInput = FileHandle.nullDevice
        keygen.standardOutput = FileHandle.nullDevice
        keygen.standardError = FileHandle.nullDevice
        try keygen.run()
        keygen.waitUntilExit()
        guard keygen.terminationStatus == 0 else { throw SSHProtectionError.invalidPrivateKey }
        let privateKey = try Data(contentsOf: URL(fileURLWithPath: keyPath))
        let fixtures: [(approach: String, path: String, alias: String, data: Data, supported: Bool)] = [
            ("per-var", ".envrc", "alias/.env", Data("HARDLINK_TOKEN=hardlink-synthetic-token\n".utf8), false),
            ("ssh", ".ssh/id_ed25519", "alias/backup.pem", privateKey, false),
            ("creds-aws", ".aws/credentials", "alias/.env",
             Data("[default]\naws_access_key_id=SYNTHETIC\naws_secret_access_key=hardlink-synthetic-token\n".utf8), false),
            ("env-token:HF_TOKEN", ".cache/huggingface/token", ".vault-token",
             Data("hardlink-synthetic-token\n".utf8), true),
            ("whole-file", ".envrc", "alias/.env", Data("HARDLINK_TOKEN=hardlink-synthetic-token\n".utf8), true),
            // The npm split rewrites the config in place, so like creds-aws it
            // refuses a link group rather than leave the token in an alias.
            ("preset:npm", ".npmrc", "alias/.env",
             Data("//registry.npmjs.org/:_authToken=hardlink-synthetic-token\n".utf8), false),
            ("skip", ".envrc", "alias/.env", Data("HARDLINK_TOKEN=hardlink-synthetic-token\n".utf8), false),
        ]
        for (index, fixture) in fixtures.enumerated() {
            for keep in [false, true] {
                let home = root + "/case-\(index)-\(keep)/home"
                let path = home + "/" + fixture.path
                let alias = home + "/" + fixture.alias
                for directory in [(path as NSString).deletingLastPathComponent,
                                  (alias as NSString).deletingLastPathComponent] {
                    try fm.createDirectory(atPath: directory, withIntermediateDirectories: true)
                }
                try fixture.data.write(to: URL(fileURLWithPath: path))
                try fm.linkItem(atPath: path, toPath: alias)
                let store = "hardlinks-\(index)-\(keep)"
                let environment = ["HOME": home, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": root + "/"]
                func run(_ arguments: [String]) -> (status: Int32, out: String, err: String) {
                    runCsecPipedAt(
                        cwd: home, ["setup", "--protect-files", "--scan-root", home] + arguments,
                        input: Data(), baseEnvironment: environment)
                }
                let rule = fixture.approach == "skip" ? "**=skip" : "**=\(fixture.approach):csec://\(store)"
                let dry = run(["--glob", rule, "--dry-run"])
                // Refuse to apply unless both exact fixture paths are present
                // and discovery has collapsed them into one unique file.
                let expectedCount = fixture.approach == "skip" ? 0 : 1
                guard dry.status == 0, dry.out.contains("plan: \(expectedCount) unique file(s)"),
                      dry.out.contains("~/" + fixture.path), dry.out.contains("~/" + fixture.alias),
                      dry.out.contains("Hardlink") else {
                    check(false, "\(fixture.approach): isolated hardlink discovery interlock (\(dry.err))")
                    continue
                }
                let reviewsBefore = await accessReviewCapture.snapshot().count
                let keysBefore = try client.listSSHKeys()
                let applied = run(["--glob", rule, "--apply"] + (keep ? ["--keep-plaintext"] : []))
                let label = "\(fixture.approach), keep=\(keep)"
                check(!applied.out.contains("hardlink-synthetic-token")
                      && !applied.err.contains("hardlink-synthetic-token")
                      && !applied.out.contains("BEGIN OPENSSH PRIVATE KEY")
                      && !applied.err.contains("BEGIN OPENSSH PRIVATE KEY"),
                      "\(label): reports contain metadata only")
                if fixture.supported {
                    check(applied.status == 0, "\(label): supports the complete hardlink group (\(applied.err))")
                    let first = try ProtectedFileSidecar(data: Data(contentsOf: URL(fileURLWithPath: path + ".csec")))
                    let second = try ProtectedFileSidecar(data: Data(contentsOf: URL(fileURLWithPath: alias + ".csec")))
                    check(first.reference == second.reference, "\(label): each alias has the same canonical reference")
                    if keep {
                        check(try Data(contentsOf: URL(fileURLWithPath: path)) == fixture.data
                              && Data(contentsOf: URL(fileURLWithPath: alias)) == fixture.data,
                              "\(label): keeps every plaintext alias when requested")
                    } else {
                        check(!fm.fileExists(atPath: path) && !fm.fileExists(atPath: alias),
                              "\(label): removes every plaintext alias")
                    }
                } else {
                    let skipped = fixture.approach == "skip"
                    check(skipped ? applied.status == 0 : applied.status != 0 && applied.err.contains("hardlink"),
                          "\(label): \(skipped ? "skips without mutation" : "refuses before import")")
                    check(await accessReviewCapture.snapshot().count == reviewsBefore,
                          "\(label): requires no consent for a refused/skipped file")
                    check(await !nativeFileBackend.hasFiles(for: store),
                          "\(label): writes no native store")
                    check(try client.listSSHKeys() == keysBefore,
                          "\(label): adds no SSH registration")
                    check((try? Data(contentsOf: URL(fileURLWithPath: path))) == fixture.data
                          && (try? Data(contentsOf: URL(fileURLWithPath: alias))) == fixture.data
                          && !fm.fileExists(atPath: path + ".csec") && !fm.fileExists(atPath: alias + ".csec"),
                          "\(label): leaves both plaintext paths and sidecars untouched")
                }
            }
        }

        for mode in ["--env", "--ssh"] {
            let home = root + "/explicit-\(mode)/home"
            try fm.createDirectory(atPath: home, withIntermediateDirectories: true)
            let path = home + "/.env"
            let alias = home + "/alias"
            let data = mode == "--ssh" ? privateKey : Data("HARDLINK_TOKEN=hardlink-synthetic-token\n".utf8)
            try data.write(to: URL(fileURLWithPath: path))
            try fm.linkItem(atPath: path, toPath: alias)
            let result = runCsecPipedAt(
                cwd: home, ["protect", mode, "--dry-run", path], input: Data(),
                baseEnvironment: ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"])
            check(result.status != 0 && result.err.contains("hardlink"),
                  "explicit protect \(mode): shares the hardlink planning guard")
        }

        // Refusal belongs to the file rewrite, independent of its provider.
        // /bin/false also prevents a regression from reaching a real op CLI.
        let opHome = root + "/op/home"
        try fm.createDirectory(atPath: opHome, withIntermediateDirectories: true)
        let opPath = opHome + "/.env"
        let opAlias = opHome + "/.envrc"
        let opData = Data("HARDLINK_TOKEN=hardlink-synthetic-token\n".utf8)
        try opData.write(to: URL(fileURLWithPath: opPath))
        try fm.linkItem(atPath: opPath, toPath: opAlias)
        let opResult = runCsecPipedAt(
            cwd: opHome, ["setup", "--protect-files", "--scan-root", opHome,
                         "--glob", "**=per-var:op://synthetic-vault/hardlinks", "--apply"], input: Data(),
            baseEnvironment: ["HOME": opHome, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/", "OP_CLI_PATH": "/bin/false"])
        check(opResult.status != 0 && opResult.err.contains("hardlink")
              && (try? Data(contentsOf: URL(fileURLWithPath: opPath))) == opData
              && (try? Data(contentsOf: URL(fileURLWithPath: opAlias))) == opData,
              "op:// per-var: rejects hardlinks before provider access")

        for keep in [false, true] {
            let home = root + "/single-token-\(keep)/home"
            try fm.createDirectory(atPath: home, withIntermediateDirectories: true)
            let path = home + "/.vault-token"
            let data = Data("  hardlink-synthetic-token\n".utf8)
            try data.write(to: URL(fileURLWithPath: path))
            let result = runCsecPipedAt(
                cwd: home, ["setup", "--protect-files", "--scan-root", home,
                           "--glob", "**=env-token:VAULT_TOKEN:csec://hardlinks-single-\(keep)", "--apply"]
                    + (keep ? ["--keep-plaintext"] : []), input: Data(),
                baseEnvironment: ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"])
            check(result.status == 0 && fm.fileExists(atPath: path + ".csec")
                  && fm.fileExists(atPath: path) == keep,
                  "single-link env-token, keep=\(keep): still imports and cleans up normally")
            guard !keep else { continue }
            // The sidecar must be one `csec exec` accepts: a path-bound blob
            // that materializes the token file where its tool reads it.
            let materialized = runCsecPipedAt(
                cwd: home, ["exec", "--", "/bin/sh", "-c",
                            "test \"$(cat .vault-token)\" = '  hardlink-synthetic-token' && printf token-ok"],
                input: Data(), extraEnv: ["CSEC_ROOT_SOCKET": rootSocketPath],
                baseEnvironment: ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"])
            check(materialized.status == 0 && materialized.out == "token-ok",
                  "single-link env-token: csec exec materializes the protected token file "
                    + "(status \(materialized.status), err \(materialized.err))")
            check(!result.out.contains("--set"),
                  "single-link env-token: no recipe injects a token file's content as a variable")
        }

        // SSH keys default to the shared `ssh-keys` store, as `csec protect
        // --ssh` does, never to the home store their location would pick.
        do {
            let home = root + "/ssh-default-store/home"
            try fm.createDirectory(atPath: home + "/.ssh", withIntermediateDirectories: true)
            let keyPath = home + "/.ssh/plex_key"
            try privateKey.write(to: URL(fileURLWithPath: keyPath))
            let result = runCsecPipedAt(
                cwd: home, ["setup", "--protect-files", "--scan-root", home, "--apply"], input: Data(),
                extraEnv: ["CSEC_SSH_SOCKET": sshSocketPath],
                baseEnvironment: ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"])
            // SSH protection registers the key with the agent and leaves no
            // sidecar; the report names the reference it was stored under.
            let registered = try client.listSSHKeys().contains { $0.reference.hasPrefix("csec://ssh-keys/") }
            check(result.status == 0
                  && result.out.contains("~/.ssh/plex_key  ->  csec://ssh-keys/") && registered,
                  "bulk SSH protection uses the shared ssh-keys store by default "
                    + "(status \(result.status), out \(result.out), err \(result.err))")
        }

        // A key csec's SSH agent cannot use must not fail the SSH batch, which
        // csecd registers only if every key in it parses. Discovery encrypts a
        // DSA key whole and leaves a passphrase-protected key alone; forcing
        // the SSH approach onto the DSA key refuses it before any review.
        do {
            func generatedKey(_ path: String, passphrase: String) throws {
                let keygen = Process()
                keygen.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
                keygen.arguments = ["-q", "-t", "ed25519", "-a", "1", "-N", passphrase, "-f", path]
                keygen.standardInput = FileHandle.nullDevice
                keygen.standardOutput = FileHandle.nullDevice
                keygen.standardError = FileHandle.nullDevice
                try keygen.run()
                keygen.waitUntilExit()
                guard keygen.terminationStatus == 0 else { throw SSHProtectionError.invalidPrivateKey }
                try fm.removeItem(atPath: path + ".pub")
            }
            let dsaKey = Data(
                "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKBgQ==\n-----END DSA PRIVATE KEY-----\n".utf8)

            let home = root + "/ssh-mixed/home"
            try fm.createDirectory(atPath: home + "/.ssh", withIntermediateDirectories: true)
            try generatedKey(home + "/.ssh/usable_key", passphrase: "")
            try generatedKey(home + "/.ssh/id_encrypted", passphrase: "synthetic-e2e-passphrase")
            try dsaKey.write(to: URL(fileURLWithPath: home + "/.ssh/id_dsa"))
            let encryptedBefore = try Data(contentsOf: URL(fileURLWithPath: home + "/.ssh/id_encrypted"))
            let result = runCsecPipedAt(
                cwd: home, ["setup", "--protect-files", "--scan-root", home, "--apply"], input: Data(),
                extraEnv: ["CSEC_SSH_SOCKET": sshSocketPath],
                baseEnvironment: ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"])
            check(result.status == 0
                  && result.out.contains("~/.ssh/usable_key  ->  csec://ssh-keys/")
                  && !fm.fileExists(atPath: home + "/.ssh/usable_key")
                  && fm.fileExists(atPath: home + "/.ssh/usable_key.pub"),
                  "bulk SSH protection imports the usable key beside keys it cannot use "
                    + "(status \(result.status), out \(result.out), err \(result.err))")
            check(fm.fileExists(atPath: home + "/.ssh/id_dsa.csec")
                  && !fm.fileExists(atPath: home + "/.ssh/id_dsa"),
                  "a DSA key in ~/.ssh is encrypted whole instead of failing the SSH batch")
            check((try? Data(contentsOf: URL(fileURLWithPath: home + "/.ssh/id_encrypted"))) == encryptedBefore
                  && !fm.fileExists(atPath: home + "/.ssh/id_encrypted.csec")
                  && result.err.contains("id_encrypted") && result.err.contains("passphrase-protected"),
                  "a passphrase-protected key is left as it is, with a warning")

            let forcedHome = root + "/ssh-forced/home"
            try fm.createDirectory(atPath: forcedHome + "/.ssh", withIntermediateDirectories: true)
            try dsaKey.write(to: URL(fileURLWithPath: forcedHome + "/.ssh/id_dsa"))
            let reviewsBefore = await accessReviewCapture.snapshot().count
            let keysBefore = try client.listSSHKeys()
            let forced = runCsecPipedAt(
                cwd: forcedHome,
                ["setup", "--protect-files", "--scan-root", forcedHome, "--glob", "**=ssh", "--apply"],
                input: Data(), extraEnv: ["CSEC_SSH_SOCKET": sshSocketPath],
                baseEnvironment: ["HOME": forcedHome, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"])
            let reviewsAfter = await accessReviewCapture.snapshot().count
            let keysAfter = try client.listSSHKeys()
            check(forced.status != 0 && forced.err.contains("DSA key")
                  && (try? Data(contentsOf: URL(fileURLWithPath: forcedHome + "/.ssh/id_dsa"))) == dsaKey
                  && reviewsAfter == reviewsBefore && keysAfter == keysBefore,
                  "an SSH approach forced onto a DSA key is refused before any review "
                    + "(status \(forced.status), err \(forced.err))")

            // The same key under two names (a copy kept as `id_rsa.old`, say)
            // is imported and registered once: the catalog refuses a batch
            // naming a key twice, which used to fail every key in it.
            let copiesHome = root + "/ssh-copies/home"
            try fm.createDirectory(atPath: copiesHome + "/.ssh", withIntermediateDirectories: true)
            try generatedKey(copiesHome + "/.ssh/id_original", passphrase: "")
            try generatedKey(copiesHome + "/.ssh/other_key", passphrase: "")
            try fm.copyItem(atPath: copiesHome + "/.ssh/id_original", toPath: copiesHome + "/.ssh/id_copy")
            let catalogBefore = try client.listSSHKeys().count
            let copies = runCsecPipedAt(
                cwd: copiesHome, ["setup", "--protect-files", "--scan-root", copiesHome, "--apply"],
                input: Data(), extraEnv: ["CSEC_SSH_SOCKET": sshSocketPath],
                baseEnvironment: ["HOME": copiesHome, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"])
            func reportedReference(_ name: String) -> String? {
                copies.out.split(separator: "\n").first { $0.contains("~/.ssh/\(name)  ->  ") }
                    .flatMap { $0.components(separatedBy: "  ->  ").last?.split(separator: " ").first }
                    .map(String.init)
            }
            let sharedReference = reportedReference("id_original")
            let catalog = try client.listSSHKeys()
            check(copies.status == 0
                  && sharedReference != nil && reportedReference("id_copy") == sharedReference
                  && reportedReference("other_key") != nil && reportedReference("other_key") != sharedReference
                  && catalog.count == catalogBefore + 2
                  && catalog.contains { $0.reference == sharedReference },
                  "two files holding one key are registered once, under one reference "
                    + "(status \(copies.status), out \(copies.out), err \(copies.err))")
            check(["id_original", "id_copy", "other_key"].allSatisfy {
                      !fm.fileExists(atPath: copiesHome + "/.ssh/\($0)")
                          && fm.fileExists(atPath: copiesHome + "/.ssh/\($0).pub")
                  }
                  && (try? Data(contentsOf: URL(fileURLWithPath: copiesHome + "/.ssh/id_copy.pub")))
                      == (try? Data(contentsOf: URL(fileURLWithPath: copiesHome + "/.ssh/id_original.pub"))),
                  "every copy loses its plaintext and keeps a .pub naming the registered key")

            // csecd itself refuses a batch naming one key twice before it
            // writes anything, so a client that does not deduplicate leaves no
            // unregistered blobs behind.
            try generatedKey(root + "/dup-direct-key", passphrase: "")
            let directKey = try Data(contentsOf: URL(fileURLWithPath: root + "/dup-direct-key"))
            let directStore = try NativeStoreName("dup-direct")
            let directReferences = try ["DUP_A", "DUP_B"].map {
                try NativeSecretReference(store: directStore, key: $0).secretRef
            }
            let directEdit = try client.beginNativeStoreEdit(store: directStore.value, mode: .sshKeyImport)
            let keysBeforeDirect = try client.listSSHKeys()
            do {
                _ = try client.commitNativeStoreBlobsAndRegisterSSH(
                    sessionID: directEdit.sessionID,
                    blobs: ["DUP_A", "DUP_B"].map {
                        ProtectedBlobImport(key: $0, data: directKey, mode: 0o600, path: "ssh-keys/\($0)")
                    },
                    registrations: directReferences.map {
                        SSHKeyRegistrationIntent(reference: $0.uri, label: $0.uri)
                    }
                )
                check(false, "csecd refuses an SSH import batch that names one key twice")
            } catch AgentClient.ClientError.protocolFailure(.invalidRequest, let message) {
                check(message.contains("same key"), "csecd refuses an SSH import batch that names one key twice")
            }
            var directBlobWritten = true
            do {
                _ = try client.access(
                    references: directReferences.map(\.uri), reason: "duplicate batch e2e", ttlSeconds: 60)
            } catch {
                directBlobWritten = false
            }
            check(try !directBlobWritten && client.listSSHKeys() == keysBeforeDirect,
                  "a refused duplicate SSH batch writes no blob and registers no key")

            // A key ~/.ssh/config uses with `IdentityAgent none` works only as
            // a file: ssh never asks csec's agent for it. Bulk protect skips it
            // (dry run and apply) and protects the rest; explicit protect
            // refuses it before any review.
            let pinnedHome = root + "/ssh-pinned/home"
            try fm.createDirectory(atPath: pinnedHome + "/.ssh", withIntermediateDirectories: true)
            try generatedKey(pinnedHome + "/.ssh/pinned_key", passphrase: "")
            try generatedKey(pinnedHome + "/.ssh/agent_key", passphrase: "")
            try Data("Host pinned\n  IdentityFile ~/.ssh/pinned_key\n  IdentitiesOnly yes\n  IdentityAgent none\n"
                .utf8).write(to: URL(fileURLWithPath: pinnedHome + "/.ssh/config"))
            let pinnedKeyData = try Data(contentsOf: URL(fileURLWithPath: pinnedHome + "/.ssh/pinned_key"))
            let pinnedEnvironment = ["HOME": pinnedHome, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"]
            let skipLine = "skipping ~/.ssh/pinned_key: used with IdentityAgent none at ~/.ssh/config:2"
            let pinnedDryRun = runCsecPipedAt(
                cwd: pinnedHome, ["setup", "--protect-files", "--scan-root", pinnedHome, "--dry-run"],
                input: Data(), extraEnv: ["CSEC_SSH_SOCKET": sshSocketPath], baseEnvironment: pinnedEnvironment)
            check(pinnedDryRun.status == 0 && pinnedDryRun.err.contains(skipLine)
                  && pinnedDryRun.out.split(separator: "\n").contains {
                      $0.contains("~/.ssh/pinned_key") && $0.contains("skip") },
                  "the dry run shows a key pinned to no agent as skipped, and why "
                    + "(out \(pinnedDryRun.out), err \(pinnedDryRun.err))")
            let reviewsBeforeExplicit = await accessReviewCapture.snapshot().count
            let explicitPinned = runCsecPipedAt(
                cwd: pinnedHome, ["protect", "--ssh", pinnedHome + "/.ssh/pinned_key"],
                input: Data(), extraEnv: ["CSEC_SSH_SOCKET": sshSocketPath], baseEnvironment: pinnedEnvironment)
            let reviewsAfterExplicit = await accessReviewCapture.snapshot().count
            check(explicitPinned.status != 0
                  && explicitPinned.err.contains("IdentityAgent none at ~/.ssh/config:2")
                  && reviewsAfterExplicit == reviewsBeforeExplicit,
                  "explicit protect --ssh refuses a pinned key before any review "
                    + "(status \(explicitPinned.status), err \(explicitPinned.err))")
            let catalogBeforePinned = try client.listSSHKeys().count
            let pinnedApply = runCsecPipedAt(
                cwd: pinnedHome, ["setup", "--protect-files", "--scan-root", pinnedHome, "--apply"],
                input: Data(), extraEnv: ["CSEC_SSH_SOCKET": sshSocketPath], baseEnvironment: pinnedEnvironment)
            let catalogAfterPinned = try client.listSSHKeys().count
            check(pinnedApply.status == 0 && pinnedApply.err.contains(skipLine)
                  && (try? Data(contentsOf: URL(fileURLWithPath: pinnedHome + "/.ssh/pinned_key"))) == pinnedKeyData
                  && !fm.fileExists(atPath: pinnedHome + "/.ssh/agent_key")
                  && fm.fileExists(atPath: pinnedHome + "/.ssh/agent_key.pub")
                  && catalogAfterPinned == catalogBeforePinned + 1,
                  "apply leaves the pinned key as it was and protects the other "
                    + "(status \(pinnedApply.status), out \(pinnedApply.out), err \(pinnedApply.err))")
        }

        // A later import of a name the store already holds with a different
        // value must not repoint the file protected earlier.
        do {
            let home = root + "/store-collision/home"
            let environment = ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"]
            for (directory, value) in [("first", "collision-first-synthetic-value"),
                                       ("second", "collision-second-synthetic-value")] {
                try fm.createDirectory(atPath: home + "/" + directory, withIntermediateDirectories: true)
                try Data("COLLIDE_TOKEN=\(value)\n".utf8)
                    .write(to: URL(fileURLWithPath: home + "/\(directory)/.env"))
                let applied = runCsecPipedAt(
                    cwd: home, ["setup", "--protect-files", "--scan-root", home + "/" + directory,
                                "--glob", "**=per-var:csec://collide", "--apply"],
                    input: Data(), baseEnvironment: environment)
                check(applied.status == 0, "store collision: \(directory) import applies (\(applied.err))")
            }
            let first = (try? String(contentsOfFile: home + "/first/.env", encoding: .utf8)) ?? ""
            let second = (try? String(contentsOfFile: home + "/second/.env", encoding: .utf8)) ?? ""
            check(first.contains("csec://collide/COLLIDE_TOKEN") && !first.contains("COLLIDE_TOKEN_2")
                  && second.contains("csec://collide/COLLIDE_TOKEN_2"),
                  "store collision: the second, different value gets its own suffixed name")
            for (key, value) in [("COLLIDE_TOKEN", "collision-first-synthetic-value"),
                                 ("COLLIDE_TOKEN_2", "collision-second-synthetic-value")] {
                let resolved = runCsecPipedAt(
                    cwd: home, ["exec", "--set", "VALUE=csec://collide/\(key)", "--", "/bin/sh", "-c",
                                "test \"$VALUE\" = '\(value)' && printf value-ok"],
                    input: Data(), baseEnvironment: environment)
                check(resolved.status == 0 && resolved.out == "value-ok",
                      "store collision: csec://collide/\(key) still resolves to its own file's value "
                        + "(err \(resolved.err))")
            }
        }

        // An alias outside the scan remains unknown to discovery. st_nlink
        // must prevent claiming whole-file protection, or an npm split, of
        // only one name.
        for approach in ["whole-file", "preset:npm"] {
            let home = root + "/incomplete-\(approach.replacingOccurrences(of: ":", with: "-"))/home"
            try fm.createDirectory(atPath: home, withIntermediateDirectories: true)
            let path = home + "/.env"
            let alias = (home as NSString).deletingLastPathComponent + "/outside"
            let data = Data("HARDLINK_TOKEN=hardlink-synthetic-token\n".utf8)
            try data.write(to: URL(fileURLWithPath: path))
            try fm.linkItem(atPath: path, toPath: alias)
            let reviewsBefore = await accessReviewCapture.snapshot().count
            let result = runCsecPipedAt(
                cwd: home, ["setup", "--protect-files", "--scan-root", home,
                           "--glob", "**=\(approach):csec://hardlinks-incomplete", "--apply"],
                input: Data(), baseEnvironment: ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"])
            let reviewsAfter = await accessReviewCapture.snapshot().count
            check(result.status != 0 && result.err.contains("hardlink")
                  && reviewsAfter == reviewsBefore,
                  "\(approach): refuses an incomplete discovered link group before consent")
            check((try? Data(contentsOf: URL(fileURLWithPath: path))) == data
                  && (try? Data(contentsOf: URL(fileURLWithPath: alias))) == data
                  && !fm.fileExists(atPath: path + ".csec"),
                  "\(approach): leaves the incomplete group unchanged")
        }

        // Change the filesystem while the fake review is open, after planning
        // but before import returns. Cleanup must retain and report the change.
        for mutation in ["replace-alias", "edit-alias", "add-alias", "edit-token"] {
            let home = root + "/\(mutation)/home"
            try fm.createDirectory(atPath: home, withIntermediateDirectories: true)
            let token = mutation == "edit-token"
            let path = home + (token ? "/.vault-token" : "/.env")
            let alias = token ? path : home + "/.envrc"
            let original = Data("HARDLINK_TOKEN=hardlink-synthetic-token\n".utf8)
            let changed = Data("HARDLINK_TOKEN=changed-synthetic-token\n".utf8)
            try original.write(to: URL(fileURLWithPath: path))
            if !token { try fm.linkItem(atPath: path, toPath: alias) }
            await bulkProtectionReviewMutation.arm {
                if mutation == "add-alias" {
                    try FileManager.default.linkItem(atPath: path, toPath: home + "/unknown")
                    return
                }
                if mutation == "replace-alias" { try FileManager.default.removeItem(atPath: alias) }
                try changed.write(to: URL(fileURLWithPath: alias))
            }
            let approach = token ? "env-token:VAULT_TOKEN" : "whole-file"
            let result = runCsecPipedAt(
                cwd: home, ["setup", "--protect-files", "--scan-root", home,
                           "--glob", "**=\(approach):csec://hardlinks-\(mutation)", "--apply"],
                input: Data(), baseEnvironment: ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"])
            check(await bulkProtectionReviewMutation.didRun(), "\(mutation): changes the fixture during consent")
            check(result.status != 0 && (result.err.contains("changed") || result.err.contains("remains")),
                  "\(mutation): reports incomplete plaintext cleanup")
            check((try? Data(contentsOf: URL(fileURLWithPath: alias))) == (mutation == "add-alias" ? original : changed),
                  "\(mutation): retains the changed plaintext path")
            if !token {
                check((try? Data(contentsOf: URL(fileURLWithPath: path)))
                      == (["replace-alias", "add-alias"].contains(mutation) ? original : changed),
                      "\(mutation): leaves the changed group intact")
            }
        }
    } catch {
        check(false, "bulk hardlink checks succeed (\(error))")
    }
}
