import Foundation
import ConvenientSecurity
#if canImport(Darwin)
import Darwin
#endif

/// `csec protect [--store NAME] [--keep-plaintext] [--dry-run] <path>...`
/// `csec protect --ssh [--store NAME] [--keep-plaintext] [--dry-run] <private-key>...`
/// `csec protect --env [--store NAME | --dest DEST] [--dry-run] <file>`
/// `csec protect --gh [--store NAME] [--keep-plaintext] [--dry-run]`
/// `csec protect --fly [--store NAME | --dest DEST] [--keep-plaintext] [--dry-run]`
///
/// Selects protection by file type for explicitly named paths anywhere. Unknown
/// files use whole-file protection. Imports plaintext secret files into
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
/// the imported values intact and the plaintext recoverable. The non-interactive
/// halves live in ProtectCores.swift, shared with the bulk setup apply.
func runProtect(_ arguments: [String]) -> Never {
    var storeOverride: String?
    var destOverride: String?
    var envMode = false
    var sshMode = false
    var awsMode = false
    var gitHubMode = false
    var flyMode = false
    var wholeFileMode = false
    var awsConfigOverride: String?
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
        case "--aws":
            awsMode = true
        case "--gh":
            gitHubMode = true
        case "--fly":
            flyMode = true
        case "--whole-file":
            wholeFileMode = true
        case "--aws-config":
            index += 1
            guard index < arguments.count else { usage("protect") }
            awsConfigOverride = arguments[index]
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
    guard [envMode, sshMode, awsMode, wholeFileMode, gitHubMode, flyMode].filter({ $0 }).count <= 1 else {
        protectFail("choose only one of --env, --ssh, --aws, --gh, --fly, or --whole-file")
    }
    if flyMode {
        guard paths.isEmpty else { protectFail("--fly takes no paths; it reads fly's own config (FLY_CONFIG_DIR or ~/.fly)") }
        guard awsConfigOverride == nil else { protectFail("--aws-config does not apply to --fly") }
        guard storeOverride == nil || destOverride == nil else { protectFail("use either --store or --dest, not both") }
        runProtectFly(storeOverride: storeOverride, destOverride: destOverride, keepPlaintext: keepPlaintext, dryRun: dryRun)
    }
    if gitHubMode {
        guard paths.isEmpty else { protectFail("--gh takes no paths; it reads gh's own stored token") }
        guard destOverride == nil, awsConfigOverride == nil else {
            protectFail("--dest and --aws-config do not apply to --gh")
        }
        runProtectGitHub(storeOverride: storeOverride, keepPlaintext: keepPlaintext, dryRun: dryRun)
    }
    guard awsConfigOverride == nil || !(envMode || sshMode || wholeFileMode) else {
        protectFail("--aws-config applies only to AWS protection")
    }
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
        protectFail("--dest requires --env or --fly")
    }
    guard !paths.isEmpty else { usage("protect") }

    let home = canonicalHomeDirectory()
    var assignments: [BulkProtectAssignment] = []
    var identities = Set<String>()
    do {
        let destination = try storeOverride.map { "csec://" + (try NativeStoreName($0)).value }
        for rawPath in paths {
            let path = try explicitProtectPath(rawPath)
            let (data, info) = try readRegularFile(atPath: path)
            guard !data.isEmpty else { throw ProtectError(message: "\(path): is empty; nothing to protect") }
            guard identities.insert("\(info.st_dev):\(info.st_ino)").inserted else {
                throw ProtectError(message: "the same file was listed more than once")
            }
            // Explicit selection cannot discover aliases elsewhere on disk.
            guard info.st_nlink == 1 else {
                throw ProtectError(message: "\(path): has hardlinks; use setup --protect-files to review every alias")
            }
            let file = SecretFileDiscoveryEngine.explicitFile(
                path: path, data: data, mode: UInt16(info.st_mode & 0o7777),
                homeDirectory: home, environment: ProcessInfo.processInfo.environment)
            // Its only file delivery is whole-file, which such a tool defeats;
            // naming the file is not yet the informed choice `--whole-file` is.
            if file.toolRewritesFile, !wholeFileMode, !awsMode, file.suggestedApproach != .flyToken {
                throw ProtectError(message: "\(path): \(file.displayName ?? "its tool") rewrites this "
                    + "file during ordinary commands, so whole-file protection would break it or put "
                    + "the plaintext back; pass --whole-file to protect it anyway")
            }
            let approach: BulkProtectApproach = awsMode ? .credsAws
                : wholeFileMode ? .wholeFile : BulkProtectApproach(delivery: file.suggestedApproach)
            if keepPlaintext, approach == .perVar {
                throw ProtectError(message: "--keep-plaintext cannot be used with per-variable rewriting; use --whole-file or omit it")
            }
            assignments.append(BulkProtectAssignment(file: file, approach: approach, destination: destination))
        }
        if awsConfigOverride != nil, !assignments.contains(where: { $0.approach == .credsAws }) {
            throw ProtectError(message: "--aws-config requires an AWS credentials file (use --aws for a custom filename)")
        }
        // Preflight every AWS input/config before any store mutation. The apply
        // path snapshots them again so a dry run never authorizes stale bytes.
        for assignment in assignments where assignment.approach == .credsAws {
            let root = bulkProjectRoot(for: assignment.file.canonicalPath, homeDirectory: home)
            let store = try storeOverride.map(NativeStoreName.init)
                ?? ProtectedFileImportPlanner.resolveDefaultStore(
                    projectRoot: root, homeDirectory: home, index: NativeStoreDirectoryIndex())
            let plan = try AWSProtectionPlan(
                path: assignment.file.canonicalPath,
                configPath: awsConfigurationPath(override: awsConfigOverride, homeDirectory: home), store: store)
            FileHandle.standardOutput.write(Data((
                "AWS: \(plan.migration.importedProfiles.count) static profile(s); "
                    + "\(plan.migration.skippedProfiles.count) skipped; config \(ReviewDisplay.sanitized(plan.config.path))\n"
                    + (keepPlaintext ? "  plaintext retained (--keep-plaintext)\n"
                        : "  configure credential_process, then remove migrated static fields\n")).utf8))
        }
    } catch let error as ProtectError { protectFail(error.message) }
    catch { protectFail(error.localizedDescription) }

    FileHandle.standardOutput.write(Data(SetupProtectPlanRenderer.render(assignments, homeDirectory: home).utf8))
    if dryRun {
        FileHandle.standardOutput.write(Data("csec protect: nothing changed (dry run)\n".utf8))
        exit(0)
    }
    let outcome = applyBulkAssignments(
        assignments, homeDirectory: home, keepPlaintext: keepPlaintext,
        awsConfigOverride: awsConfigOverride)
    for line in outcome.reportLines { FileHandle.standardOutput.write(Data((line + "\n").utf8)) }
    for recipe in outcome.recipes { FileHandle.standardOutput.write(Data(("  " + recipe + "\n").utf8)) }
    for failure in outcome.failures {
        FileHandle.standardError.write(Data(("csec protect: " + ReviewDisplay.sanitized(failure) + "\n").utf8))
    }
    exit(outcome.failures.isEmpty ? 0 : 1)
}

/// Resolve relative paths against cwd, but choose scope/storage from the target.
/// Resolve parent aliases only: the hardened reader must reject leaf symlinks.
func explicitProtectPath(_ rawPath: String) throws -> String {
    let expanded = (rawPath as NSString).expandingTildeInPath
    let absolute = (expanded as NSString).isAbsolutePath ? expanded
        : (FileManager.default.currentDirectoryPath as NSString).appendingPathComponent(expanded)
    let name = (absolute as NSString).lastPathComponent
    guard !name.isEmpty, name != ".", name != "..", !name.hasSuffix(ProtectedFileSidecar.suffix),
          let parent = canonicalPath((absolute as NSString).deletingLastPathComponent) else {
        throw ProtectError(message: "must name an existing file, not a directory or csec sidecar")
    }
    return (parent as NSString).appendingPathComponent(name)
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
    let currentDirectory = FileManager.default.currentDirectoryPath
    for rawPath in rawPaths {
        let item: ProtectPlannedFile
        do {
            item = try planSSHPrivateKey(rawPath: rawPath, baseDirectory: currentDirectory)
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

    do {
        // The SSH-specific edit mode makes the single trusted review explicit.
        // The commit first durably imports every blob, then derives/stores public
        // catalog metadata inside csecd before the CLI touches the originals.
        let outcome = try commitSSHKeys(
            planned: planned,
            references: references,
            registrations: registrations,
            keepPlaintext: keepPlaintext,
            store: store,
            client: makeAgentClient()
        )
        let metadataByReference = Dictionary(
            uniqueKeysWithValues: outcome.keys.map { ($0.reference, $0) }
        )

        var output = "csec protect --ssh: protected \(planned.count) file(s), "
            + "registered \(outcome.keys.count) key(s); "
        output += keepPlaintext
            ? "private-key plaintext left in place (--keep-plaintext)\n"
            : "removed \(outcome.removedPlaintextCount) private-key plaintext file(s)\n"
        for item in planned {
            guard let reference = outcome.referenceByPath[item.originalPath] else { continue }
            let fingerprint = metadataByReference[reference]?.fingerprint ?? "registered"
            let name = ReviewDisplay.sanitized((item.originalPath as NSString).lastPathComponent)
            output += "  \(name)  ->  "
                + "\(reference)  \(fingerprint)\n"
        }
        output += sshActivationGuidanceIfNeeded()
        FileHandle.standardOutput.write(Data(output.utf8))
        if !outcome.retainedPlaintext.isEmpty {
            for path in outcome.retainedPlaintext {
                let display = ReviewDisplay.sanitized(path)
                FileHandle.standardError.write(Data(
                    "csec protect: warning: \(display) changed or could not be removed; plaintext remains\n"
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
    let plan: EnvFilePlan
    let projectDirectory: String
    do {
        let path = try explicitProtectPath(rawPath)
        projectDirectory = bulkProjectRoot(for: path, homeDirectory: canonicalHomeDirectory())
        plan = try planEnvFile(rawPath: path, baseDirectory: projectDirectory)
    } catch let error as ProtectError { protectFail("\(rawPath): \(error.message)") }
    catch { protectFail("\(rawPath): \(error.localizedDescription)") }
    let document = plan.document
    let relative = plan.relativePath
    guard !document.candidates.isEmpty else {
        FileHandle.standardOutput.write(Data(
            "csec protect --env: no env assignments found in \(relative); nothing to do\n".utf8))
        exit(0)
    }

    let projectItemTitle = (projectDirectory as NSString).lastPathComponent
    let defaultSpec: SecretDestinationSpec
    // Set only when the native default was resolved from the project path, so
    // accepting it binds the store to this root via the origin marker; explicit
    // --store/--dest or a hand-typed destination sends no origin.
    var defaultResolvedStore: NativeStoreName?
    do {
        if let destOverride {
            defaultSpec = try SecretDestinationSpec.parse(
                destOverride, defaultItemTitle: projectItemTitle)
        } else if let storeOverride {
            defaultSpec = .native(try NativeStoreName(storeOverride))
        } else {
            let resolved = try ProtectedFileImportPlanner.resolveDefaultStore(
                projectRoot: projectDirectory,
                homeDirectory: canonicalHomeDirectory(),
                index: NativeStoreDirectoryIndex()
            )
            defaultResolvedStore = resolved
            defaultSpec = .native(resolved)
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
        out += "  selected variables and existing references use csec_NAME after protection\n"
        for name in document.referenceNamesToPrefix.sorted() {
            out += "  rename existing reference: \(name) -> csec_\(name)\n"
        }
        out += "  nothing imported, nothing rewritten (dry run)\n"
        FileHandle.standardOutput.write(Data(out.utf8))
        exit(0)
    }

    guard isatty(STDIN_FILENO) == 1, isatty(STDERR_FILENO) == 1 else {
        protectFail("--env needs an interactive terminal for the picker (use --dry-run to preview)")
    }

    // Rows, selection, reveal, values, and references are all keyed by the
    // candidate's import key (the name, or NAME_commented_N for a commented
    // secret), so distinct values under one variable name import distinctly.
    let valuesByKey = Dictionary(uniqueKeysWithValues: document.candidates.compactMap {
        $0.kind == .importable ? ($0.importKey, $0.importValue) : nil
    })
    guard let selectedKeys = EnvSelectView.run(
        rows: rows,
        initiallySelected: initiallySelected,
        valuesByName: valuesByKey
    )
    else {
        protectFail("cancelled; nothing changed")
    }
    guard !selectedKeys.isEmpty || !document.referenceNamesToPrefix.isEmpty else {
        FileHandle.standardOutput.write(Data(
            "csec protect --env: nothing selected; \(relative) unchanged\n".utf8))
        exit(0)
    }

    do { try document.validateRewrite(selectedKeys: Set(selectedKeys)) }
    catch { protectFail("\(error)") }
    if selectedKeys.isEmpty {
        FileHandle.standardError.write(Data(
            "Rename existing references in \(relative) to csec_NAME; no import is needed.\n".utf8))
        guard envConfirm("Proceed?") else { protectFail("cancelled; nothing changed") }
        do {
            try writeFileAtomically(
                path: plan.canonicalFile, data: document.rewritten(references: [:]),
                mode: mode_t(plan.originalInfo.st_mode & 0o7777), guardAgainst: plan.originalInfo)
        } catch { protectFail("could not rename references: \(error)") }
        FileHandle.standardOutput.write(Data("csec protect --env: renamed references in \(relative) to csec_NAME\n".utf8))
        exit(0)
    }

    var spec = defaultSpec
    if destOverride == nil, storeOverride == nil {
        spec = promptEnvDestination(default: defaultSpec, projectItemTitle: projectItemTitle)
    }

    let nativeOrigin: String?
    if let defaultResolvedStore, case .native(let chosen) = spec, chosen == defaultResolvedStore {
        nativeOrigin = projectDirectory
    } else {
        nativeOrigin = nil
    }

    let destination: SecretWriteDestination
    do {
        destination = try makeSecretWriteDestination(
            spec: spec, client: makeAgentClient(), nativeOrigin: nativeOrigin)
    } catch {
        protectFail(error.localizedDescription)
    }

    let selectedSet = Set(selectedKeys)
    let rewriteLineCount = document.assignments.filter {
        $0.importKey.map(selectedSet.contains) == true && !($0.value ?? "").isEmpty
    }.count

    FileHandle.standardError.write(Data((
        "\nImport \(selectedKeys.count) variable(s) into \(destination.summaryLine),\n"
            + "then rewrite \(relative) in place: \(rewriteLineCount) line(s) get references"
            + " and their plaintext values are removed from the file.\n"
            + "Protected variables and existing references will use csec_NAME.\n").utf8))
    guard envConfirm("Proceed?") else {
        protectFail("cancelled; nothing changed")
    }

    // Commit first. The file is untouched until every value is durable at the
    // destination.
    let references: [String: String]
    do {
        references = try applyEnvProtection(
            plan: plan, selectedKeys: selectedKeys, destination: destination)
    } catch EnvApplyError.importFailed(let error) {
        protectFail("import failed; \(relative) was not modified: "
            + protectFailureDetail(error, projectDirectory: projectDirectory))
    } catch EnvApplyError.rewriteFailed(let error) {
        protectFail(
            "the secrets were imported, but \(relative) was not rewritten: \(error.message)\n"
                + "re-run `csec protect --env \(rawPath)` to finish replacing the plaintext")
    } catch {
        protectFail("import failed; \(relative) was not modified: \(error.localizedDescription)")
    }

    var report = "csec protect --env: imported \(selectedKeys.count) variable(s) into "
        + "\(destination.summaryLine); rewrote \(relative) in place\n"
    for key in selectedKeys {
        if let reference = references[key] {
            report += "  \(key)  ->  \(reference)\n"
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
func envConfirm(_ prompt: String) -> Bool {
    FileHandle.standardError.write(Data("\(prompt) [y/N]: ".utf8))
    guard let line = readLine(strippingNewline: true) else { return false }
    return line.lowercased() == "y" || line.lowercased() == "yes"
}

func protectFail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("csec protect: \(message)\n".utf8))
    exit(1)
}
