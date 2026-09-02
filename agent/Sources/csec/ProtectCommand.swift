import Foundation
import ConvenientSecurity
#if canImport(Darwin)
import Darwin
#endif

/// `csec protect [--store NAME] [--keep-plaintext] [--dry-run] <path>...`
/// `csec protect --ssh [--store NAME] [--keep-plaintext] [--dry-run] <private-key>...`
/// `csec protect --env [--store NAME | --dest DEST] [--dry-run] <file>`
///
/// Imports whole plaintext secret files under the current project directory into
/// the native store's encrypted file/blob tier, replaces each with a tiny
/// `<name>.csec` sidecar pointing at its `csec://store/key` value, and removes the
/// now-redundant plaintext.
///
/// `--ssh` instead registers the imported backend reference in the SSH catalog,
/// preserves or creates the public-key file, removes the unchanged private-key
/// plaintext, and deliberately leaves no sidecar that could drift from the
/// catalog.
///
/// `--env` instead treats the file as an env file (direnv/.envrc semantics):
/// an interactive picker chooses which variables to import into a selectable
/// destination (the native store or 1Password), and the file is rewritten in
/// place with `csec://`/`op://` references where the plaintext values were.
/// The file stays a normal non-secret file — no sidecar, nothing unlinked.
///
/// Safe by construction: the batch is committed to the destination store
/// (durable, biometric-gated) *before* anything on disk is touched, so the value
/// always exists in the store before its plaintext is unlinked or rewritten.
/// Sidecars and rewrites are written atomically. A failure at any point leaves
/// the imported values intact and the plaintext recoverable.
func runProtect(_ arguments: [String]) -> Never {
    var storeOverride: String?
    var destOverride: String?
    var envMode = false
    var sshMode = false
    var keepPlaintext = false
    var dryRun = false
    var paths: [String] = []

    var index = 0
    while index < arguments.count {
        switch arguments[index] {
        case "--store":
            index += 1
            guard index < arguments.count else { usage("protect") }
            storeOverride = arguments[index]
        case "--dest":
            index += 1
            guard index < arguments.count else { usage("protect") }
            destOverride = arguments[index]
        case "--env":
            envMode = true
        case "--ssh":
            sshMode = true
        case "--keep-plaintext":
            keepPlaintext = true
        case "--dry-run":
            dryRun = true
        case let token where token.hasPrefix("-"):
            usage("protect")
        default:
            paths.append(arguments[index])
        }
        index += 1
    }
    guard !(envMode && sshMode) else { protectFail("use either --env or --ssh, not both") }
    if envMode {
        guard paths.count == 1 else {
            protectFail("--env takes exactly one env file")
        }
        guard !keepPlaintext else {
            protectFail("--keep-plaintext does not apply to --env (the file is rewritten in place, never removed)")
        }
        guard storeOverride == nil || destOverride == nil else {
            protectFail("use either --store or --dest, not both")
        }
        runProtectEnv(
            rawPath: paths[0], storeOverride: storeOverride,
            destOverride: destOverride, dryRun: dryRun)
    }
    if sshMode {
        guard destOverride == nil else { protectFail("--dest does not apply to --ssh") }
        guard !paths.isEmpty else { usage("protect") }
        runProtectSSH(
            rawPaths: paths,
            storeOverride: storeOverride,
            keepPlaintext: keepPlaintext,
            dryRun: dryRun
        )
    }
    guard destOverride == nil else {
        protectFail("--dest requires --env")
    }
    guard !paths.isEmpty else { usage("protect") }

    // Canonicalize the project directory (resolving symlinks such as macOS's
    // /var -> /private/var) so containment checks and relative paths are computed
    // in the same namespace the files themselves resolve into.
    guard let projectDirectory = canonicalPath(FileManager.default.currentDirectoryPath),
          projectDirectory.hasPrefix("/") else {
        protectFail("the current directory could not be determined")
    }

    let store: NativeStoreName
    do {
        store = try storeOverride.map { try NativeStoreName($0) }
            ?? ProtectedFileImportPlanner.storeName(forProjectDirectory: projectDirectory)
    } catch {
        protectFail("invalid store name (\(error.localizedDescription))")
    }

    var planned: [ProtectPlannedFile] = []
    var seenKeys = Set<String>()
    for rawPath in paths {
        let planItem: ProtectPlannedFile
        do {
            planItem = try planProtectedFile(
                rawPath: rawPath, projectDirectory: projectDirectory, store: store)
        } catch let error as ProtectError {
            protectFail("\(rawPath): \(error.message)")
        } catch {
            protectFail("\(rawPath): \(error.localizedDescription)")
        }
        guard seenKeys.insert(planItem.key).inserted else {
            protectFail("\(rawPath): the same file was listed more than once")
        }
        planned.append(planItem)
    }

    if dryRun {
        FileHandle.standardOutput.write(Data(
            "csec protect (dry run): store \(store.value)\n".utf8))
        for item in planned {
            FileHandle.standardOutput.write(Data((
                "  \(item.relativePath)  ->  csec://\(store.value)/\(item.key)"
                    + "  (mode \(String(item.mode, radix: 8)), \(item.data.count) bytes)\n").utf8))
        }
        exit(0)
    }

    let client = makeAgentClient()
    do {
        // 1. Durable, biometric-gated import. After this returns, every value is
        //    in the encrypted store; nothing on disk has changed yet.
        let session = try client.beginNativeStoreEdit(store: store.value, mode: .onboardingImport)
        let blobs = planned.map {
            ProtectedBlobImport(key: $0.key, data: $0.data, mode: $0.mode, path: $0.relativePath)
        }
        _ = try client.commitNativeStoreBlobs(sessionID: session.sessionID, blobs: blobs)

        // 2. Write every sidecar atomically. If any fails we stop before removing
        //    any plaintext — the values are safely imported regardless.
        for item in planned {
            let reference = try NativeSecretReference(store: store, key: item.key)
            let sidecar = try ProtectedFileSidecar(reference: SecretRef(reference.uri)).encoded()
            try writeFileAtomically(path: item.sidecarPath, data: sidecar, mode: 0o600)
        }

        // 3. Only now remove the redundant plaintext.
        var removed = 0
        if !keepPlaintext {
            for item in planned where unlinkIfUnchanged(item) { removed += 1 }
        }

        FileHandle.standardOutput.write(Data((
            "csec protect: imported \(planned.count) file(s) into csec://\(store.value); "
                + (keepPlaintext
                    ? "plaintext left in place (--keep-plaintext)"
                    : "removed \(removed) plaintext file(s)") + "\n").utf8))
        for item in planned {
            FileHandle.standardOutput.write(Data(
                "  \(item.relativePath)  ->  \((item.sidecarPath as NSString).lastPathComponent)\n".utf8))
        }
        exit(0)
    } catch {
        protectFail(error.localizedDescription)
    }
}

/// Manual SSH protection deliberately accepts explicit keys outside the current
/// project (normally ~/.ssh). Import remains native-destination convenience; the
/// resulting catalog registration is a canonical SecretRef and the separate
/// `csec ssh register` command accepts op:// and future provider references.
private func runProtectSSH(
    rawPaths: [String],
    storeOverride: String?,
    keepPlaintext: Bool,
    dryRun: Bool
) -> Never {
    let store: NativeStoreName
    do {
        store = try NativeStoreName(storeOverride ?? "ssh-keys")
    } catch {
        protectFail("invalid SSH key store name (\(error.localizedDescription))")
    }

    var planned: [ProtectPlannedFile] = []
    var seenPaths = Set<String>()
    var seenKeys = Set<String>()
    for rawPath in rawPaths {
        let item: ProtectPlannedFile
        do {
            item = try planSSHPrivateKey(rawPath: rawPath)
        } catch let error as ProtectError {
            protectFail("\(rawPath): \(error.message)")
        } catch {
            protectFail("\(rawPath): \(error.localizedDescription)")
        }
        guard seenPaths.insert(item.originalPath).inserted,
              seenKeys.insert(item.key).inserted else {
            protectFail("\(rawPath): the same private key was listed more than once")
        }
        planned.append(item)
    }

    let references: [SecretRef]
    do {
        references = try planned.map {
            try NativeSecretReference(store: store, key: $0.key).secretRef
        }
    } catch {
        protectFail("could not construct canonical SSH key references")
    }
    let registrations = zip(planned, references).map {
        SSHKeyRegistrationIntent(
            reference: $0.1.uri,
            label: ($0.0.originalPath as NSString).lastPathComponent
        )
    }

    if dryRun {
        var output = "csec protect --ssh (dry run): store \(store.value)\n"
        for (item, reference) in zip(planned, references) {
            output += "  \(ReviewDisplay.sanitized(item.originalPath))  ->  "
                + "\(reference.uri)  (protect + register)\n"
        }
        output += "  private keys unchanged; no SSH catalog entries added (dry run)\n"
        FileHandle.standardOutput.write(Data(output.utf8))
        exit(0)
    }

    let client = makeAgentClient()
    do {
        // The SSH-specific edit mode makes the single trusted review explicit.
        // The commit first durably imports every blob, then derives/stores public
        // catalog metadata inside csecd before the CLI touches the originals.
        let session = try client.beginNativeStoreEdit(
            store: store.value,
            mode: .sshKeyImport
        )
        let blobs = planned.map {
            ProtectedBlobImport(
                key: $0.key,
                data: $0.data,
                mode: $0.mode,
                path: $0.relativePath
            )
        }
        let result = try client.commitNativeStoreBlobsAndRegisterSSH(
            sessionID: session.sessionID,
            blobs: blobs,
            registrations: registrations
        )
        let metadataByReference = Dictionary(
            uniqueKeysWithValues: result.keys.map { ($0.reference, $0) }
        )

        // SSH registration itself durably retains the provider-neutral reference,
        // so do not create a second on-disk pointer that can drift from the
        // catalog. A missing .pub is recreated from returned public metadata;
        // existing .pub files are preserved byte-for-byte.
        for (item, reference) in zip(planned, references) {
            if let metadata = metadataByReference[reference.uri] {
                try writePublicKeyIfMissing(
                    path: item.originalPath + ".pub",
                    data: Data(metadata.publicKeyLine.utf8)
                )
            }
        }

        var removed = 0
        var retained: [ProtectPlannedFile] = []
        if !keepPlaintext {
            for item in planned {
                if unlinkIfUnchanged(item) { removed += 1 }
                else { retained.append(item) }
            }
        }

        var output = "csec protect --ssh: protected and registered \(planned.count) key(s); "
        output += keepPlaintext
            ? "private-key plaintext left in place (--keep-plaintext)\n"
            : "removed \(removed) private-key plaintext file(s)\n"
        for (item, reference) in zip(planned, references) {
            let fingerprint = metadataByReference[reference.uri]?.fingerprint ?? "registered"
            let name = ReviewDisplay.sanitized((item.originalPath as NSString).lastPathComponent)
            output += "  \(name)  ->  "
                + "\(reference.uri)  \(fingerprint)\n"
        }
        output += sshActivationGuidanceIfNeeded()
        FileHandle.standardOutput.write(Data(output.utf8))
        if !retained.isEmpty {
            for item in retained {
                let path = ReviewDisplay.sanitized(item.originalPath)
                FileHandle.standardError.write(Data(
                    "csec protect: warning: \(path) changed or could not be removed; plaintext remains\n"
                        .utf8
                ))
            }
            exit(1)
        }
        exit(0)
    } catch {
        protectFail(
            "SSH protection did not complete; original private key files were left in place: "
                + error.localizedDescription
        )
    }
}

/// `csec protect --env`: parse the env file, pick variables interactively,
/// commit them to the chosen destination (Touch ID for the native store,
/// 1Password's own authorization for op), and only then rewrite the file in
/// place with references. Any failure before the commit succeeds leaves the
/// file byte-identical; a failure after it leaves the plaintext file intact
/// with the values already safely imported (re-running finishes the rewrite).
private func runProtectEnv(
    rawPath: String, storeOverride: String?, destOverride: String?, dryRun: Bool
) -> Never {
    guard let projectDirectory = canonicalPath(FileManager.default.currentDirectoryPath),
          projectDirectory.hasPrefix("/") else {
        protectFail("the current directory could not be determined")
    }

    // Same containment discipline as blob protect: canonicalize the parent
    // (never follow a symlinked target), rejoin the base name, require the
    // result inside the project.
    let absolute = (rawPath as NSString).isAbsolutePath
        ? rawPath
        : (projectDirectory as NSString).appendingPathComponent(rawPath)
    let parent = (absolute as NSString).deletingLastPathComponent
    let baseName = (absolute as NSString).lastPathComponent
    guard let canonicalParent = canonicalPath(parent) else {
        protectFail("\(rawPath): could not be located")
    }
    let canonicalFile = (canonicalParent as NSString).appendingPathComponent(baseName)
    guard canonicalFile.hasPrefix(projectDirectory + "/") else {
        protectFail("\(rawPath): must be inside the current project directory")
    }
    let relative = String(canonicalFile.dropFirst(projectDirectory.count).drop(while: { $0 == "/" }))
    guard !relative.isEmpty else {
        protectFail("\(rawPath): is the project directory, not a file")
    }
    guard !relative.hasSuffix(ProtectedFileSidecar.suffix) else {
        protectFail("\(rawPath): is a csec sidecar, not an env file")
    }

    let data: Data
    let original: stat
    do {
        (data, original) = try readRegularFile(atPath: canonicalFile)
    } catch let error as ProtectError {
        protectFail("\(rawPath): \(error.message)")
    } catch {
        protectFail("\(rawPath): \(error.localizedDescription)")
    }
    guard !data.isEmpty else {
        protectFail("\(rawPath): is empty; nothing to protect")
    }

    let document: EnvFileDocument
    do {
        document = try EnvFileDocument(data: data)
    } catch {
        protectFail("\(rawPath): \(error)")
    }
    guard !document.candidates.isEmpty else {
        FileHandle.standardOutput.write(Data(
            "csec protect --env: no env assignments found in \(relative); nothing to do\n".utf8))
        exit(0)
    }

    let projectItemTitle = (projectDirectory as NSString).lastPathComponent
    let defaultSpec: SecretDestinationSpec
    do {
        if let destOverride {
            defaultSpec = try SecretDestinationSpec.parse(
                destOverride, defaultItemTitle: projectItemTitle)
        } else if let storeOverride {
            defaultSpec = .native(try NativeStoreName(storeOverride))
        } else {
            defaultSpec = .native(
                try ProtectedFileImportPlanner.storeName(forProjectDirectory: projectDirectory))
        }
    } catch {
        protectFail("invalid destination (\(error))")
    }

    let (rows, initiallySelected) = EnvSelectModel.rows(for: document.candidates)

    if dryRun {
        var out = "csec protect --env (dry run): \(relative)  ->  \(defaultSpec.displayString)\n"
        for (index, row) in rows.enumerated() {
            let mark = row.selectable
                ? (initiallySelected.contains(index) ? "[x]" : "[ ]")
                : " - "
            out += "  \(mark) \(row.name)  (\(row.annotation))\n"
        }
        out += "  nothing imported, nothing rewritten (dry run)\n"
        FileHandle.standardOutput.write(Data(out.utf8))
        exit(0)
    }

    guard isatty(STDIN_FILENO) == 1, isatty(STDERR_FILENO) == 1 else {
        protectFail("--env needs an interactive terminal for the picker (use --dry-run to preview)")
    }

    guard let selectedNames = EnvSelectView.run(rows: rows, initiallySelected: initiallySelected)
    else {
        protectFail("cancelled; nothing changed")
    }
    guard !selectedNames.isEmpty else {
        FileHandle.standardOutput.write(Data(
            "csec protect --env: nothing selected; \(relative) unchanged\n".utf8))
        exit(0)
    }

    var values: [String: String] = [:]
    let candidatesByName = Dictionary(
        uniqueKeysWithValues: document.candidates.map { ($0.name, $0) })
    for name in selectedNames {
        guard let candidate = candidatesByName[name], candidate.kind == .importable else {
            protectFail("internal error: selected variable \(name) is not importable")
        }
        values[name] = candidate.importValue
    }

    var spec = defaultSpec
    if destOverride == nil, storeOverride == nil {
        spec = promptEnvDestination(default: defaultSpec, projectItemTitle: projectItemTitle)
    }

    let destination: SecretWriteDestination
    do {
        destination = try makeSecretWriteDestination(spec: spec, client: makeAgentClient())
    } catch {
        protectFail(error.localizedDescription)
    }

    let selectedSet = Set(selectedNames)
    let rewriteLineCount = document.assignments.filter {
        selectedSet.contains($0.name) && !($0.value ?? "").isEmpty
    }.count

    FileHandle.standardError.write(Data((
        "\nImport \(values.count) variable(s) into \(destination.summaryLine),\n"
            + "then rewrite \(relative) in place: \(rewriteLineCount) line(s) get references"
            + " and their plaintext values are removed from the file.\n").utf8))
    guard envConfirm("Proceed?") else {
        protectFail("cancelled; nothing changed")
    }

    // Commit first. The file is untouched until every value is durable at the
    // destination.
    let references: [String: String]
    do {
        references = try destination.commit(values: values)
    } catch {
        protectFail("import failed; \(relative) was not modified: \(error.localizedDescription)")
    }

    do {
        try writeFileAtomically(
            path: canonicalFile,
            data: document.rewritten(references: references),
            mode: mode_t(original.st_mode & 0o7777),
            guardAgainst: original)
    } catch let error as ProtectError {
        protectFail(
            "the secrets were imported, but \(relative) was not rewritten: \(error.message)\n"
                + "re-run `csec protect --env \(rawPath)` to finish replacing the plaintext")
    } catch {
        protectFail(
            "the secrets were imported, but \(relative) was not rewritten: "
                + error.localizedDescription)
    }

    var report = "csec protect --env: imported \(values.count) variable(s) into "
        + "\(destination.summaryLine); rewrote \(relative) in place\n"
    for name in selectedNames {
        if let reference = references[name] {
            report += "  \(name)  ->  \(reference)\n"
        }
    }
    FileHandle.standardOutput.write(Data(report.utf8))
    exit(0)
}

/// Cooked-mode destination prompt on stderr; Enter accepts the default.
private func promptEnvDestination(
    default defaultSpec: SecretDestinationSpec, projectItemTitle: String
) -> SecretDestinationSpec {
    for _ in 0..<3 {
        FileHandle.standardError.write(Data(
            "Destination [\(defaultSpec.displayString)] (csec://STORE or op://VAULT[/ITEM]): ".utf8))
        guard let line = readLine(strippingNewline: true) else {
            protectFail("cancelled; nothing changed")
        }
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return defaultSpec }
        do {
            return try SecretDestinationSpec.parse(trimmed, defaultItemTitle: projectItemTitle)
        } catch {
            FileHandle.standardError.write(Data("  \(error)\n".utf8))
        }
    }
    protectFail("no valid destination given; nothing changed")
}

/// y/N confirmation on stderr (stdout stays clean for the report), default No.
private func envConfirm(_ prompt: String) -> Bool {
    FileHandle.standardError.write(Data("\(prompt) [y/N]: ".utf8))
    guard let line = readLine(strippingNewline: true) else { return false }
    return line.lowercased() == "y" || line.lowercased() == "yes"
}

private struct ProtectPlannedFile {
    let originalPath: String
    let relativePath: String
    let sidecarPath: String
    let key: String
    let data: Data
    let mode: UInt16
    let info: stat
}

private struct ProtectError: Error {
    let message: String
}

private func planProtectedFile(
    rawPath: String,
    projectDirectory: String,
    store: NativeStoreName
) throws -> ProtectPlannedFile {
    let absolute = (rawPath as NSString).isAbsolutePath
        ? rawPath
        : (projectDirectory as NSString).appendingPathComponent(rawPath)
    // Canonicalize the file's parent directory (not the file itself, so a
    // symlinked target is not silently followed) and rejoin the base name.
    let parent = (absolute as NSString).deletingLastPathComponent
    let baseName = (absolute as NSString).lastPathComponent
    guard let canonicalParent = canonicalPath(parent) else {
        throw ProtectError(message: "could not be located")
    }
    let canonicalFile = (canonicalParent as NSString).appendingPathComponent(baseName)
    guard canonicalFile.hasPrefix(projectDirectory + "/") else {
        throw ProtectError(message: "must be inside the current project directory")
    }
    let relative = String(canonicalFile.dropFirst(projectDirectory.count).drop(while: { $0 == "/" }))
    guard !relative.isEmpty else {
        throw ProtectError(message: "is the project directory, not a file")
    }
    guard !relative.hasSuffix(ProtectedFileSidecar.suffix) else {
        throw ProtectError(message: "is itself a csec sidecar")
    }

    let (data, info) = try readRegularFile(atPath: canonicalFile)
    let mode = UInt16(info.st_mode & 0o7777)
    guard !data.isEmpty else {
        throw ProtectError(message: "is empty; nothing to protect")
    }
    guard data.count <= NativeBlobStore.maximumBlobBytes else {
        throw ProtectError(message: "is larger than the per-file limit")
    }
    return ProtectPlannedFile(
        originalPath: canonicalFile,
        relativePath: relative,
        sidecarPath: canonicalFile + ProtectedFileSidecar.suffix,
        key: ProtectedFileImportPlanner.storeKey(forRelativePath: relative),
        data: data,
        mode: mode,
        info: info
    )
}

private func planSSHPrivateKey(rawPath: String) throws -> ProtectPlannedFile {
    let current = FileManager.default.currentDirectoryPath
    let absolute = (rawPath as NSString).isAbsolutePath
        ? rawPath
        : (current as NSString).appendingPathComponent(rawPath)
    let parent = (absolute as NSString).deletingLastPathComponent
    let baseName = (absolute as NSString).lastPathComponent
    guard !baseName.isEmpty, baseName != ".", baseName != "..",
          !baseName.hasSuffix(".pub"),
          !baseName.hasSuffix(ProtectedFileSidecar.suffix),
          let canonicalParent = canonicalPath(parent) else {
        throw ProtectError(message: "must name a private-key file, not a public key or sidecar")
    }
    let canonicalFile = (canonicalParent as NSString).appendingPathComponent(baseName)
    let (data, info) = try readRegularFile(atPath: canonicalFile)
    guard !data.isEmpty else { throw ProtectError(message: "is empty; nothing to protect") }
    return ProtectPlannedFile(
        originalPath: canonicalFile,
        relativePath: "ssh-keys/\(baseName)",
        sidecarPath: canonicalFile + ProtectedFileSidecar.suffix,
        key: ProtectedFileImportPlanner.storeKey(forRelativePath: canonicalFile),
        data: data,
        // If this ordinary blob is ever restored through another delivery path,
        // do not carry forward an accidentally permissive private-key mode.
        mode: 0o600,
        info: info
    )
}

/// Read a regular, caller-owned, non-symlink file's bytes and its stat record
/// (mode for re-creation, identity/size/mtime for change detection before an
/// in-place rewrite).
private func readRegularFile(atPath path: String) throws -> (data: Data, info: stat) {
    let fd = path.withCString { open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
    guard fd >= 0 else { throw ProtectError(message: "could not be opened (not a regular file?)") }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0,
          (info.st_mode & S_IFMT) == S_IFREG,
          info.st_uid == getuid() else {
        throw ProtectError(message: "is not a caller-owned regular file")
    }
    guard info.st_size >= 0, info.st_size <= NativeBlobStore.maximumBlobBytes else {
        throw ProtectError(message: "is larger than the per-file limit")
    }
    var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
    var offset = 0
    let total = bytes.count
    while offset < total {
        let count = bytes.withUnsafeMutableBytes { raw in
            Darwin.read(fd, raw.baseAddress!.advanced(by: offset), total - offset)
        }
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { throw ProtectError(message: "could not be read completely") }
        offset += count
    }
    return (Data(bytes), info)
}

/// Write `data` to `path` atomically: a private temp file in the same directory,
/// fsync'd, then renamed over the destination. When `guardAgainst` carries the
/// stat record the content was derived from, the rename is refused if the file
/// at `path` has changed identity, size, or mtime since — a concurrent editor's
/// work must not be silently overwritten.
private func writeFileAtomically(
    path: String, data: Data, mode: mode_t, guardAgainst original: stat? = nil
) throws {
    let directory = (path as NSString).deletingLastPathComponent
    let temporary = (directory as NSString)
        .appendingPathComponent(".csec-protect-\(UUID().uuidString.lowercased())")
    let fd = temporary.withCString {
        open($0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
    }
    guard fd >= 0 else { throw ProtectError(message: "the sidecar could not be created") }
    var keepTemporary = true
    defer {
        close(fd)
        if keepTemporary { temporary.withCString { _ = unlink($0) } }
    }
    var offset = 0
    try data.withUnsafeBytes { raw in
        while offset < raw.count {
            let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw ProtectError(message: "the sidecar could not be written") }
            offset += count
        }
    }
    guard fchmod(fd, mode) == 0, fsync(fd) == 0 else {
        throw ProtectError(message: "the sidecar could not be persisted")
    }
    if let original {
        var current = stat()
        guard path.withCString({ stat($0, &current) }) == 0,
              current.st_dev == original.st_dev,
              current.st_ino == original.st_ino,
              current.st_size == original.st_size,
              current.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec,
              current.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec else {
            throw ProtectError(message: "the file changed while csec was working; it was left untouched")
        }
    }
    let renamed = temporary.withCString { source in
        path.withCString { destination in rename(source, destination) }
    }
    guard renamed == 0 else { throw ProtectError(message: "the sidecar could not replace the file") }
    keepTemporary = false
}

private func writePublicKeyIfMissing(path: String, data: Data) throws {
    let fd = path.withCString {
        open($0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
    }
    if fd < 0, errno == EEXIST { return }
    guard fd >= 0 else { throw ProtectError(message: "the public key could not be created") }
    var complete = false
    defer {
        close(fd)
        if !complete { path.withCString { _ = unlink($0) } }
    }
    var offset = 0
    try data.withUnsafeBytes { raw in
        while offset < raw.count {
            let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw ProtectError(message: "the public key could not be written") }
            offset += count
        }
    }
    guard fchmod(fd, 0o644) == 0, fsync(fd) == 0 else {
        throw ProtectError(message: "the public key could not be persisted")
    }
    complete = true
}

/// Do not unlink a path that changed while the human was reviewing the import.
/// A concurrent replacement remains plaintext, but is never accidentally lost.
private func unlinkIfUnchanged(_ item: ProtectPlannedFile) -> Bool {
    var current = stat()
    guard item.originalPath.withCString({ lstat($0, &current) }) == 0,
          (current.st_mode & S_IFMT) == S_IFREG,
          current.st_dev == item.info.st_dev,
          current.st_ino == item.info.st_ino,
          current.st_size == item.info.st_size,
          current.st_mtimespec.tv_sec == item.info.st_mtimespec.tv_sec,
          current.st_mtimespec.tv_nsec == item.info.st_mtimespec.tv_nsec else {
        return false
    }
    return item.originalPath.withCString { unlink($0) } == 0
}

/// Canonicalize an existing path via realpath(3), resolving symlinks and `..`.
private func canonicalPath(_ path: String) -> String? {
    guard let resolved = path.withCString({ realpath($0, nil) }) else { return nil }
    defer { free(resolved) }
    return String(cString: resolved)
}

private func protectFail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("csec protect: \(message)\n".utf8))
    exit(1)
}
