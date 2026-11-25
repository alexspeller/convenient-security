import Foundation
import ConvenientSecurity
#if canImport(Darwin)
import Darwin
#endif

// `csec setup --protect-files` — the glob-driven bulk-protect flow: sweep the
// scan roots (default: the whole home directory) with the file-level discovery
// engine, assign each discovered file an approach and destination (per-kind
// defaults, overridable per glob subset), and apply by driving the same
// protect cores the single-file commands use. Non-interactive with
// `--glob 'PATTERN=approach[:dest]'` + `--apply` (or `--dry-run`); an
// interactive checkbox picker otherwise.

func runSetupProtectFiles(_ arguments: [String]) -> Never {
    exit(performSetupProtectFiles(arguments, fromGuidedSetup: false))
}

/// `noticeShown`: guided setup prints the scan notice before its own "scan
/// now?" question, so it is not repeated here.
func performSetupProtectFiles(
    _ arguments: [String], fromGuidedSetup: Bool, noticeShown: Bool = false
) -> Int32 {
    var scanRoots: [String] = []
    var rules: [BulkProtectRule] = []
    var dryRun = false
    var apply = false
    var keepPlaintext = false
    var includeExcluded = false

    var index = 0
    while index < arguments.count {
        switch arguments[index] {
        case "--scan-root":
            index += 1
            guard index < arguments.count else { return protectFilesUsage() }
            scanRoots.append(arguments[index])
        case "--glob":
            index += 1
            guard index < arguments.count,
                  let rule = BulkProtectRule.parse(arguments[index]) else {
                csecError("setup", "invalid --glob rule "
                    + "(expected 'PATTERN=approach[:dest]', approaches: per-var, whole-file, "
                    + "ssh, creds-aws, preset:<name>, env-token:<VAR>, skip)")
                return 2
            }
            rules.append(rule)
        case "--dry-run":
            dryRun = true
        case "--apply":
            apply = true
        case "--keep-plaintext":
            keepPlaintext = true
        case "--include-excluded":
            includeExcluded = true
        default:
            return protectFilesUsage()
        }
        index += 1
    }
    guard !(dryRun && apply) else { return protectFilesUsage() }

    let homeDirectory = canonicalHomeDirectory()
    let environment = ProcessInfo.processInfo.environment

    if !noticeShown {
        printProtectFilesScanNotice(
            scanRoots: scanRoots, homeDirectory: homeDirectory,
            mode: dryRun ? .dryRun : apply ? .apply : .interactive)
    }

    // --- Discovery (progress redrawn in place when stderr is a terminal) ---
    let streamProgress = isatty(STDERR_FILENO) == 1
    let started = Date()
    var lastDrawn: Date?
    var drewProgress = false
    let report = SecretFileDiscoveryEngine.discover(
        roots: scanRoots,
        homeDirectory: homeDirectory,
        environment: environment,
        includeExcluded: includeExcluded
    ) { progress in
        guard streamProgress else { return }
        let now = Date()
        if let lastDrawn, now.timeIntervalSince(lastDrawn) < 0.1 { return }
        lastDrawn = now
        let line = ProtectFilesScanText.progressLine(
            progress, elapsed: now.timeIntervalSince(started),
            width: TerminalStyle.terminalWidth(fd: STDERR_FILENO))
        FileHandle.standardError.write(Data(("\r\u{1B}[K" + line).utf8))
        drewProgress = true
    }
    let scanDuration = ProtectFilesScanText.duration(Date().timeIntervalSince(started))
    if drewProgress {
        FileHandle.standardError.write(Data("\r\u{1B}[K".utf8))
    }

    let hardlinkCount = report.files.reduce(0) { $0 + $1.aliasPaths.count }
    let summary = "csec setup: \(report.files.count) unique file(s) to protect under "
        + ReviewDisplay.sanitized(report.scannedRootLabels.joined(separator: ", "))
    FileHandle.standardError.write(Data(summary.appending("\n").utf8))
    var details = ["\(ProtectFilesScanText.count(report.visitedEntryCount)) entries scanned in \(scanDuration)",
                   "\(report.symlinkCount) candidate symlink(s) omitted; destinations counted once"]
    if hardlinkCount > 0 {
        details.append("\(hardlinkCount) additional hardlink path(s) grouped with their files")
    }
    if report.suppressedSecretFreeEnvFiles > 0 {
        details.append("\(report.suppressedSecretFreeEnvFiles) secret-free env file(s) omitted")
    }
    FileHandle.standardError.write(Data(("csec setup: " + details.joined(separator: " · ") + "\n").utf8))
    if !report.exclusionCounts.isEmpty {
        let exclusions = report.exclusionCounts.sorted { $0.key < $1.key }
            .map { "\($0.key): \($0.value) path(s)" }.joined(separator: "; ")
        FileHandle.standardError.write(Data(
            "csec setup: excluded \(exclusions). Review with --include-excluded.\n".utf8))
    }
    for warning in report.warnings {
        FileHandle.standardError.write(Data(
            "csec setup: warning: \(ReviewDisplay.sanitized(warning))\n".utf8))
    }
    guard !report.files.isEmpty else {
        FileHandle.standardError.write(Data("csec setup: nothing to protect\n".utf8))
        return 0
    }

    var assignments = SetupProtectPlanner.assignments(
        files: report.files, rules: rules, homeDirectory: homeDirectory)
    skipKeysPinnedAwayFromCsecAgent(&assignments, homeDirectory: homeDirectory)

    if dryRun {
        printBulkPlan(assignments, homeDirectory: homeDirectory)
        return 0
    }

    if !apply {
        // Interactive: the filter-and-tree bulk-select picker.
        guard isatty(STDIN_FILENO) == 1, isatty(STDERR_FILENO) == 1 else {
            csecError("setup", "--protect-files is interactive without --dry-run/--apply; "
                + "run it in a terminal or pass --glob … --apply")
            return 2
        }
        guard let chosen = SetupSelectView.run(
            assignments: assignments, homeDirectory: homeDirectory) else {
            FileHandle.standardError.write(Data("csec setup: cancelled; nothing changed\n".utf8))
            return fromGuidedSetup ? 0 : 1
        }
        assignments = chosen
        guard !assignments.isEmpty else {
            FileHandle.standardError.write(Data("csec setup: nothing selected\n".utf8))
            return 0
        }
        printBulkPlan(assignments, homeDirectory: homeDirectory)
        guard envConfirm("Apply this plan? Each store asks for Touch ID once per import kind "
            + "(variables, files, SSH keys, npm auth lines) and once per AWS credentials file.") else {
            FileHandle.standardError.write(Data("csec setup: cancelled; nothing changed\n".utf8))
            return fromGuidedSetup ? 0 : 1
        }
    } else {
        assignments = assignments.filter { $0.approach != .skip }
        printBulkPlan(assignments, homeDirectory: homeDirectory)
    }

    let outcome = applyBulkAssignments(
        assignments,
        homeDirectory: homeDirectory,
        keepPlaintext: keepPlaintext
    )
    for line in outcome.reportLines {
        FileHandle.standardOutput.write(Data(line.appending("\n").utf8))
    }
    if !outcome.recipes.isEmpty {
        FileHandle.standardOutput.write(Data("\nWire-up recipes (nothing auto-executed):\n".utf8))
        for recipe in outcome.recipes {
            FileHandle.standardOutput.write(Data("  \(recipe)\n".utf8))
        }
    }
    for failure in outcome.failures {
        FileHandle.standardError.write(Data(
            "csec setup: \(ReviewDisplay.sanitized(failure))\n".utf8))
    }
    return outcome.failures.isEmpty ? 0 : 1
}

/// Before any scan: which folders, what is read, and that nothing leaves the
/// Mac or is stored without the user's choice (`ProtectFilesScanText`).
func printProtectFilesScanNotice(
    scanRoots: [String], homeDirectory: String, mode: ProtectFilesScanText.Mode
) {
    let lines = ProtectFilesScanText.notice(
        rootLabels: scanRoots.map { homeRelativeDisplay($0, home: homeDirectory) },
        coversHome: SecretFileDiscoveryEngine.scanCoversHome(
            roots: scanRoots, homeDirectory: homeDirectory),
        mode: mode)
    guard let headline = lines.first else { return }
    Prompt.step(headline)
    for line in lines.dropFirst() { Prompt.body(line) }
}

private func protectFilesUsage() -> Int32 {
    csecError("setup", "usage: csec setup --protect-files [--scan-root DIR]… "
        + "[--glob 'PATTERN=approach[:dest]']… [--dry-run | --apply] [--keep-plaintext] [--include-excluded]")
    return 2
}

/// A key `~/.ssh/config` uses with `IdentityAgent none` (or another agent)
/// only works as a file, so its SSH protection becomes a skip, said before the
/// plan, whatever rule chose it.
private func skipKeysPinnedAwayFromCsecAgent(
    _ assignments: inout [BulkProtectAssignment],
    homeDirectory: String
) {
    guard assignments.contains(where: { $0.approach == .sshKey }) else { return }
    let pins = SSHConfigAgentPins.scanLocal(homeDirectory: homeDirectory)
    for index in assignments.indices where assignments[index].approach == .sshKey {
        guard let pin = sshAgentPin(
            forCanonicalPath: assignments[index].file.canonicalPath, in: pins) else { continue }
        assignments[index].approach = .skip
        let line = "csec setup: skipping \(display(assignments[index], home: homeDirectory)): used with "
            + "\(pin.describe(homeDirectory: homeDirectory)), so ssh would not ask csec's agent for it"
        FileHandle.standardError.write(Data((ReviewDisplay.sanitized(line) + "\n").utf8))
    }
}

private func printBulkPlan(_ assignments: [BulkProtectAssignment], homeDirectory: String) {
    let out = SetupProtectPlanRenderer.render(
        assignments, homeDirectory: homeDirectory,
        width: isatty(STDOUT_FILENO) == 1 ? TerminalStyle.terminalWidth(fd: STDOUT_FILENO) : nil)
    FileHandle.standardOutput.write(Data(out.utf8))
    if assignments.contains(where: { $0.approach == .credsAws }) {
        let config = ReviewDisplay.sanitized(awsConfigurationPath(homeDirectory: homeDirectory))
        FileHandle.standardOutput.write(Data(
            "AWS: configure credential_process in \(config) after import, then remove migrated static fields (unless --keep-plaintext).\n".utf8))
    }
}

func homeRelativeDisplay(_ path: String, home: String) -> String {
    let trimmed = home.hasSuffix("/") ? String(home.dropLast()) : home
    if path == trimmed { return "~" }
    if path.hasPrefix(trimmed + "/") { return "~" + path.dropFirst(trimmed.count) }
    return path
}

// MARK: - interactive picker

/// Raw-mode driver for the bulk-protect picker. Owns only I/O: every key goes
/// to the pure `SetupSelectModel` (its filter included), and `p` and `d` open
/// a `SetupSelectPrompt` edited in place under the table. The terminal stays
/// in raw mode throughout, so the filter and prompts have readline's editing
/// keys rather than the tty's bare line discipline. Returns the effective
/// assignments on apply, nil on cancel.
enum SetupSelectView {
    /// Lines the picker draws around its rows: title, two key lines, header,
    /// the cursor row's details, status, filter, footer, the "more" markers
    /// and a two-line prompt.
    private static let chromeLines = 12

    static func run(
        assignments: [BulkProtectAssignment],
        homeDirectory: String
    ) -> [BulkProtectAssignment]? {
        guard !assignments.isEmpty else { return [] }
        guard let raw = TerminalRawMode(captureInterrupt: true) else { return nil }
        var model = SetupSelectModel(
            assignments: assignments, homeDirectory: homeDirectory,
            screenRows: max(5, terminalHeight(fd: STDERR_FILENO) - chromeLines))
        var prompt: SetupSelectPrompt?
        var previousLines = 0
        let color = TerminalStyle.colorEnabled(STDERR_FILENO)

        func redraw() {
            let width = max(20, TerminalStyle.terminalWidth(fd: STDERR_FILENO)) - 1
            let typing = prompt != nil || model.mode == .filtering
            let height = terminalHeight(fd: STDERR_FILENO) - (typing ? 2 : 0)
            model.pageSize = max(1, height - chromeLines + 2)
            var block = model.render(color: color, width: width, height: height)
            var cursorColumn: Int?
            if let prompt {
                let tail = prompt.render(model: model, color: color, width: width)
                block += "\n" + tail.lines.joined(separator: "\n")
                cursorColumn = tail.cursorColumn
            } else if model.mode == .filtering {
                let tail = model.renderFilterPrompt(color: color, width: width)
                block += "\n" + tail.lines.joined(separator: "\n")
                cursorColumn = tail.cursorColumn
            }
            raw.setCursorVisible(typing)
            previousLines = draw(block, previousLines: previousLines, cursorColumn: cursorColumn)
        }
        func finish() {
            clearBlock(previousLines)
            raw.restore()
        }

        redraw()
        while true {
            guard let key = raw.readLineEditKey() else {
                finish()
                return nil
            }
            if var open = prompt {
                prompt = open.handle(key, model: &model) == .stay ? open : nil
                redraw()
                continue
            }
            switch model.handle(key) {
            case .stay:
                break
            case .prompt(let kind):
                prompt = SetupSelectPrompt(kind: kind)
            case .apply:
                finish()
                return model.effectiveAssignments
            case .cancel:
                finish()
                return nil
            }
            redraw()
        }
    }

    private static func terminalHeight(fd: Int32) -> Int {
        var size = winsize()
        if ioctl(fd, UInt(TIOCGWINSZ), &size) == 0, size.ws_row > 0 { return Int(size.ws_row) }
        return 24
    }

    /// Redraw the block over the previous one. The cursor ends on the block's
    /// last line, at `cursorColumn` when a prompt there is being edited.
    private static func draw(_ block: String, previousLines: Int, cursorColumn: Int?) -> Int {
        var out = ""
        if previousLines > 0 { out += "\u{1B}[\(previousLines)A" }
        out += "\r\u{1B}[0J" + block
        if let cursorColumn {
            out += "\r"
            if cursorColumn > 0 { out += "\u{1B}[\(cursorColumn)C" }
        }
        FileHandle.standardError.write(Data(out.utf8))
        return block.reduce(0) { $0 + ($1 == "\n" ? 1 : 0) }
    }

    private static func clearBlock(_ previousLines: Int) {
        var out = ""
        if previousLines > 0 { out += "\u{1B}[\(previousLines)A" }
        out += "\r\u{1B}[0J"
        FileHandle.standardError.write(Data(out.utf8))
    }
}

// MARK: - apply engine

struct BulkApplyOutcome {
    var reportLines: [String] = []
    var recipes: [String] = []
    var failures: [String] = []
}

/// One assignment with its destination decided: a native store (with the
/// origin binding when default-resolved) or an op:// destination string.
private struct ResolvedBulkAssignment {
    let assignment: BulkProtectAssignment
    let store: NativeStoreName?
    let origin: String?
    let opDestination: String?
}

/// Apply the assignments by driving the shared protect cores, batching files
/// that share one native store into a single biometric-gated session per
/// mechanism. Commit-before-touch-disk holds throughout: values are durable
/// in the destination before any sidecar is written, any file rewritten, or
/// any plaintext removed.
func applyBulkAssignments(
    _ assignments: [BulkProtectAssignment],
    homeDirectory: String,
    keepPlaintext: Bool,
    awsConfigOverride: String? = nil
) -> BulkApplyOutcome {
    var outcome = BulkApplyOutcome()
    let client = makeAgentClient()

    // Resolve each assignment's store (or op destination) up front, so store
    // grouping and origin binding are decided before anything runs.
    typealias Resolved = ResolvedBulkAssignment
    var resolved: [Resolved] = []
    var storeCache: [String: (NativeStoreName, String)] = [:]
    var flyWork: [BulkProtectAssignment] = []
    for assignment in assignments where assignment.approach != .skip {
        // Fly picks its own destination (the registered reference, else
        // csec's fly store), not the project-root store.
        if assignment.approach == .fly {
            flyWork.append(assignment)
            continue
        }
        if let destination = assignment.destination {
            if destination.hasPrefix("csec://") {
                let name = String(destination.dropFirst("csec://".count))
                guard let store = try? NativeStoreName(name) else {
                    outcome.failures.append(
                        "\(display(assignment, home: homeDirectory)): invalid store \(destination)")
                    continue
                }
                resolved.append(Resolved(
                    assignment: assignment, store: store, origin: nil, opDestination: nil))
            } else if destination.hasPrefix("op://") {
                guard assignment.approach == .perVar || isNpmSplit(assignment.approach) else {
                    outcome.failures.append(
                        "\(display(assignment, home: homeDirectory)): op:// destinations "
                            + "support per-var imports and npm config splits only")
                    continue
                }
                resolved.append(Resolved(
                    assignment: assignment, store: nil, origin: nil, opDestination: destination))
            } else {
                outcome.failures.append(
                    "\(display(assignment, home: homeDirectory)): unsupported destination "
                        + "\(destination)")
            }
            continue
        }
        // Default store: the legible, collision-checked name for the file's
        // project root (nearest .git ancestor, else home).
        let root = bulkProjectRoot(
            for: assignment.file.canonicalPath, homeDirectory: homeDirectory)
        if let cached = storeCache[root] {
            resolved.append(Resolved(
                assignment: assignment, store: cached.0, origin: cached.1, opDestination: nil))
            continue
        }
        do {
            let store = try ProtectedFileImportPlanner.resolveDefaultStore(
                projectRoot: root,
                homeDirectory: homeDirectory,
                index: NativeStoreDirectoryIndex())
            storeCache[root] = (store, root)
            resolved.append(Resolved(
                assignment: assignment, store: store, origin: root, opDestination: nil))
        } catch {
            outcome.failures.append(
                "\(display(assignment, home: homeDirectory)): \(error.localizedDescription)")
        }
    }

    // Per-var → whole-file fallback happens before grouping so each file's
    // effective approach drives its batch. The fallback is deterministic:
    // ≥1 importable secret-like candidate → per-var; else ≥1 secret-like
    // (necessarily unsupported) → whole-file for dotenv/envrc, but preserve
    // shell startup files for manual migration; else no-op.
    struct EnvWork {
        let resolved: Resolved
        let plan: EnvFilePlan
        let selectedKeys: [String]
    }
    var envWork: [EnvWork] = []
    var wholeFileWork: [Resolved] = []
    var sshWork: [Resolved] = []
    var awsWork: [Resolved] = []
    var tokenWork: [Resolved] = []
    var presetWork: [Resolved] = []
    var npmWork: [Resolved] = []

    for item in resolved {
        let path = display(item.assignment, home: homeDirectory)
        switch item.assignment.approach {
        case .skip, .fly:
            continue
        case .perVar:
            let base = bulkBaseDirectory(
                for: item.assignment.file.canonicalPath, homeDirectory: homeDirectory)
            do {
                let plan = try planEnvFile(
                    rawPath: item.assignment.file.canonicalPath, baseDirectory: base)
                let preselected = plan.document.candidates
                    .filter { $0.preselect }
                    .map(\.importKey)
                let hasUnsupportedSecrets = plan.document.candidates.contains {
                    $0.kind == .unsupported && $0.secretLike
                }
                if !preselected.isEmpty
                    || (!hasUnsupportedSecrets && !plan.document.referenceNamesToPrefix.isEmpty) {
                    try plan.document.validateRewrite(selectedKeys: Set(preselected))
                    envWork.append(EnvWork(
                        resolved: item, plan: plan, selectedKeys: preselected))
                    if hasUnsupportedSecrets, item.assignment.file.kind == .shellRc {
                        outcome.reportLines.append(
                            "  \(path): unsupported assignments left in the startup file; migrate manually")
                    }
                } else if hasUnsupportedSecrets {
                    if item.assignment.file.kind == .shellRc {
                        // Recheck at apply time too: a per-var override, or a
                        // file changed since discovery, cannot silently turn
                        // into whole-file removal of startup configuration.
                        outcome.reportLines.append(
                            "  \(path): \(SecretFileDiscoveryEngine.shellStartupPreservationNote)")
                    } else {
                        outcome.reportLines.append(
                            "  \(path): per-var cannot rewrite its secrets; whole-file fallback")
                        wholeFileWork.append(item)
                    }
                } else {
                    outcome.reportLines.append("  \(path): nothing to protect; skipped")
                }
            } catch let error as ProtectError {
                outcome.failures.append("\(path): \(error.message)")
            } catch {
                outcome.failures.append("\(path): \(error.localizedDescription)")
            }
        case .wholeFile:
            wholeFileWork.append(item)
        case .sshKey:
            sshWork.append(item)
        case .credsAws:
            awsWork.append(item)
        case .envToken:
            tokenWork.append(item)
        case .filePreset where isNpmSplit(item.assignment.approach):
            npmWork.append(item)
        case .filePreset:
            presetWork.append(item)
        }
    }

    applyEnvBatches(
        envWork.map { ($0.resolved.assignment, $0.resolved.store, $0.resolved.origin,
                       $0.resolved.opDestination, $0.plan, $0.selectedKeys) },
        client: client, homeDirectory: homeDirectory, outcome: &outcome)

    // envToken: until a token can be extracted from a structured file, every
    // token file is protected whole-file. The blob's sidecar is bound to the
    // path it was protected at, so `csec exec` materializes the file where its
    // tool reads it. A bare document value would have no recorded path, and
    // `csec exec` refuses an unbound sidecar.
    for item in tokenWork { wholeFileWork.append(item) }

    // Other file presets ride the whole-file mechanism; the recipe names the
    // preset (or the generic --fd variable when no preset exists yet). npm's
    // splits instead, below.
    for item in presetWork { wholeFileWork.append(item) }

    applyWholeFileBatches(
        wholeFileWork, client: client, homeDirectory: homeDirectory,
        keepPlaintext: keepPlaintext, outcome: &outcome)

    applyNpmSplitBatches(
        npmWork, client: client, homeDirectory: homeDirectory,
        keepPlaintext: keepPlaintext, outcome: &outcome)

    applySSHBatches(sshWork, client: client, homeDirectory: homeDirectory,
                  keepPlaintext: keepPlaintext, outcome: &outcome)

    applyAWSImports(
        awsWork, client: client, homeDirectory: homeDirectory,
        keepPlaintext: keepPlaintext, configOverride: awsConfigOverride, outcome: &outcome)

    applyFlyProtection(
        flyWork, client: client, homeDirectory: homeDirectory,
        keepPlaintext: keepPlaintext, outcome: &outcome)

    return outcome
}

/// One import per Fly config (there is normally one): the token moves to its
/// reference and the file keeps every other setting, as `protect --fly` does.
private func applyFlyProtection(
    _ work: [BulkProtectAssignment],
    client: AgentClient,
    homeDirectory: String,
    keepPlaintext: Bool,
    outcome: inout BulkApplyOutcome
) {
    for assignment in work {
        let path = display(assignment, home: homeDirectory)
        do {
            let snapshot = try FlyConfigSnapshot(path: assignment.file.canonicalPath)
            let configDirectory = (snapshot.path as NSString).deletingLastPathComponent
            let destination = assignment.destination
            let target = try flyImportTarget(
                storeOverride: nil, destOverride: destination,
                registered: readFlyRegistration(configDirectory: configDirectory)?.reference)
            guard snapshot.tokens.accessToken != nil else {
                outcome.reportLines.append("  \(path): no Fly token to protect; skipped")
                continue
            }
            let result = try protectFlyToken(
                snapshot: snapshot, target: target, keepPlaintext: keepPlaintext, client: client)
            outcome.reportLines.append("  \(path): Fly token -> \(result.reference)"
                + (result.blanked ? "; emptied in the file" : "; plaintext kept (--keep-plaintext)"))
            outcome.recipes += FlyCLI.aliasLines().map { "run fly through csec, \($0)" }
        } catch let error as FlyProtectionError {
            outcome.failures.append("\(path): \(error.message)")
        } catch let error as ProtectError {
            outcome.failures.append("\(path): \(error.message)")
        } catch {
            outcome.failures.append("\(path): \(error.localizedDescription)")
        }
    }
}

// MARK: - per-mechanism batches

private func applyEnvBatches(
    _ work: [(assignment: BulkProtectAssignment, store: NativeStoreName?, origin: String?,
              opDestination: String?, plan: EnvFilePlan, selectedKeys: [String])],
    client: AgentClient,
    homeDirectory: String,
    outcome: inout BulkApplyOutcome
) {
    // Group per destination so one commit (one Touch ID) covers every env
    // file landing in the same store. Cross-file key collisions inside one
    // batch resolve deterministically: the first file keeps the bare key; a
    // later file whose value differs gets a store key prefixed with its
    // sanitized relative path (equal values share the key).
    struct Group {
        var files: [(plan: EnvFilePlan, assignment: BulkProtectAssignment,
                     keyMap: [String: String])] = []
        var mergedValues: [String: String] = [:]
        var origin: String?
    }
    var groups: [String: Group] = [:]
    var groupStores: [String: NativeStoreName] = [:]
    var groupOpDestinations: [String: String] = [:]

    for item in work {
        let groupKey = item.store.map { "csec://\($0.value)" } ?? (item.opDestination ?? "")
        var group = groups[groupKey] ?? Group()
        if let store = item.store { groupStores[groupKey] = store }
        if let op = item.opDestination { groupOpDestinations[groupKey] = op }
        if group.origin == nil { group.origin = item.origin }

        var keyMap: [String: String] = [:]
        let candidatesByKey = Dictionary(
            uniqueKeysWithValues: item.plan.document.candidates.map { ($0.importKey, $0) })
        for key in item.selectedKeys {
            guard let candidate = candidatesByKey[key] else { continue }
            let value = candidate.importValue
            if let existing = group.mergedValues[key] {
                if existing == value {
                    keyMap[key] = key
                } else {
                    let prefixed = ProtectedFileImportPlanner.storeKey(
                        forRelativePath: item.plan.relativePath) + "_" + key
                    group.mergedValues[prefixed] = value
                    keyMap[key] = prefixed
                }
            } else {
                group.mergedValues[key] = value
                keyMap[key] = key
            }
        }
        group.files.append((item.plan, item.assignment, keyMap))
        groups[groupKey] = group
    }

    for (groupKey, group) in groups.sorted(by: { $0.key < $1.key }) {
        let references: [String: String]
        if group.mergedValues.isEmpty {
            // A reference-only migration must not contact any provider.
            references = [:]
        } else {
            do {
                let destination: SecretWriteDestination
                if let store = groupStores[groupKey] {
                    destination = NativeStoreWriteDestination(
                        client: client, store: store, origin: group.origin)
                } else if let op = groupOpDestinations[groupKey] {
                    let spec = try SecretDestinationSpec.parse(op, defaultItemTitle: "bulk-protect")
                    destination = try makeSecretWriteDestination(
                        spec: spec, client: client, nativeOrigin: nil)
                } else {
                    throw ProtectError(message: "unusable destination")
                }
                references = try destination.commit(values: group.mergedValues)
            } catch {
                for file in group.files {
                    outcome.failures.append(
                        "\(display(file.assignment, home: homeDirectory)): import failed: "
                            + protectFailureDetail(
                                error, projectDirectory: group.origin ?? homeDirectory))
                }
                continue
            }
        }

        for file in group.files {
            let path = display(file.assignment, home: homeDirectory)
            // The file's own import keys point at the (possibly prefixed)
            // store references they were merged under.
            var fileReferences: [String: String] = [:]
            for (fileKey, storeKey) in file.keyMap {
                fileReferences[fileKey] = references[storeKey]
            }
            do {
                try writeFileAtomically(
                    path: file.plan.canonicalFile,
                    data: try file.plan.document.rewritten(references: fileReferences),
                    mode: mode_t(file.plan.originalInfo.st_mode & 0o7777),
                    guardAgainst: file.plan.originalInfo)
                outcome.reportLines.append(
                    "  \(path): rewrote \(fileReferences.count) variable(s) in place -> \(groupKey); references use csec_ names")
            } catch let error as ProtectError {
                outcome.failures.append(
                    "\(path): imported, but the rewrite did not finish: \(error.message); "
                        + "re-run to finish replacing the plaintext")
            } catch {
                outcome.failures.append("\(path): \(error.localizedDescription)")
            }
        }
    }
}

private func applyWholeFileBatches(
    _ work: [ResolvedBulkAssignment],
    client: AgentClient,
    homeDirectory: String,
    keepPlaintext: Bool,
    outcome: inout BulkApplyOutcome
) {
    // One commit session (one Touch ID) per store covers its whole batch.
    var byStore: [String: (store: NativeStoreName, origin: String?, items: [ResolvedBulkAssignment])] = [:]
    for item in work {
        guard let store = item.store else {
            outcome.failures.append(
                "\(display(item.assignment, home: homeDirectory)): whole-file protection "
                    + "needs a csec:// store destination")
            continue
        }
        var entry = byStore[store.value] ?? (store, item.origin, [])
        if entry.origin == nil { entry.origin = item.origin }
        entry.items.append(item)
        byStore[store.value] = entry
    }

    for (_, entry) in byStore.sorted(by: { $0.key < $1.key }) {
        var planned: [ProtectPlannedFile] = []
        var plannedItems: [ResolvedBulkAssignment] = []
        var aliasPaths: [String: [String]] = [:]
        var seenKeys = Set<String>()
        for item in entry.items {
            let path = display(item.assignment, home: homeDirectory)
            let base = bulkProjectRoot(
                for: item.assignment.file.canonicalPath, homeDirectory: homeDirectory)
            do {
                let plan = try planProtectedFile(
                    rawPath: item.assignment.file.canonicalPath,
                    baseDirectory: base,
                    store: entry.store)
                try validateWholeFilePaths(plan, aliases: item.assignment.file.aliasPaths)
                guard seenKeys.insert(plan.key).inserted else {
                    outcome.reportLines.append("  \(path): duplicate of an already-planned file; skipped")
                    continue
                }
                planned.append(plan)
                plannedItems.append(item)
                if !item.assignment.file.aliasPaths.isEmpty {
                    aliasPaths[plan.originalPath] = item.assignment.file.aliasPaths
                }
            } catch let error as ProtectError {
                outcome.failures.append("\(path): \(error.message)")
            } catch {
                outcome.failures.append("\(path): \(error.localizedDescription)")
            }
        }
        guard !planned.isEmpty else { continue }

        do {
            let result = try commitWholeFiles(
                planned: planned,
                aliasPaths: aliasPaths,
                store: entry.store,
                origin: entry.origin,
                keepPlaintext: keepPlaintext,
                client: client
            )
            for (item, protected) in zip(plannedItems, result.items) {
                let path = display(item.assignment, home: homeDirectory)
                var line = "  \(path)  ->  \(protected.reference)"
                if !protected.aliasSidecarPaths.isEmpty {
                    line += "  (+\(protected.aliasSidecarPaths.count) alias sidecar(s))"
                }
                outcome.reportLines.append(line)
                appendDeliveryRecipe(
                    for: item.assignment, reference: protected.reference, outcome: &outcome)
            }
            for retained in result.retainedPlaintext {
                outcome.failures.append(
                    "\(homeRelativeDisplay(retained, home: homeDirectory)): changed while "
                        + "csec was working or cleanup could not finish; check remaining plaintext")
            }
        } catch {
            for item in plannedItems {
                outcome.failures.append(
                    "\(display(item.assignment, home: homeDirectory)): "
                        + protectFailureDetail(
                            error, projectDirectory: entry.origin ?? homeDirectory))
            }
        }
    }
}

/// The npm preset splits its file rather than protecting it whole: plain
/// `npm`, `pnpm` and `yarn` keep reading the cooldown, `ignore-scripts` and
/// registry settings, and only the auth lines move to the store.
private func isNpmSplit(_ approach: BulkProtectApproach) -> Bool {
    if case .filePreset("npm", _) = approach { return true }
    return false
}

/// One commit (one Touch ID, or one 1Password write) per destination covers
/// every npm config landing there. Each file's auth lines are durable before
/// its rewrite, and a file that changed meanwhile is left as it was.
private func applyNpmSplitBatches(
    _ work: [ResolvedBulkAssignment],
    client: AgentClient,
    homeDirectory: String,
    keepPlaintext: Bool,
    outcome: inout BulkApplyOutcome
) {
    struct Group {
        var files: [(item: ResolvedBulkAssignment, file: NpmSplitFile, key: String)] = []
        var values: [String: String] = [:]
        var store: NativeStoreName?
        var origin: String?
        var opDestination: String?
    }
    var groups: [String: Group] = [:]
    for item in work {
        let path = display(item.assignment, home: homeDirectory)
        let groupKey = item.store.map { "csec://\($0.value)" } ?? (item.opDestination ?? "")
        do {
            let file = try NpmSplitFile(
                path: item.assignment.file.canonicalPath,
                aliasPaths: item.assignment.file.aliasPaths)
            var group = groups[groupKey] ?? Group()
            group.store = group.store ?? item.store
            group.origin = group.origin ?? item.origin
            group.opDestination = group.opDestination ?? item.opDestination
            // The home config keeps the legible name; a second config in the
            // same batch is told apart by its path, as env batches do.
            var key = "NPMRC_AUTH"
            if group.values[key] != nil {
                let base = bulkBaseDirectory(
                    for: item.assignment.file.canonicalPath, homeDirectory: homeDirectory)
                let relative = String(file.path.dropFirst(base == "/" ? 1 : base.count + 1))
                key = ProtectedFileImportPlanner.storeKey(forRelativePath: relative) + "_AUTH"
            }
            group.values[key] = file.split.authLines
            group.files.append((item, file, key))
            groups[groupKey] = group
        } catch let error as ProtectError {
            outcome.failures.append("\(path): \(error.message)")
        } catch {
            outcome.failures.append("\(path): \(error.localizedDescription)")
        }
    }

    for (_, group) in groups.sorted(by: { $0.key < $1.key }) {
        let references: [String: String]
        do {
            let destination: SecretWriteDestination
            if let store = group.store {
                destination = NativeStoreWriteDestination(
                    client: client, store: store, origin: group.origin)
            } else if let op = group.opDestination {
                let spec = try SecretDestinationSpec.parse(op, defaultItemTitle: "bulk-protect")
                destination = try makeSecretWriteDestination(
                    spec: spec, client: client, nativeOrigin: nil)
            } else {
                throw ProtectError(message: "unusable destination")
            }
            references = try destination.commit(values: group.values)
        } catch {
            for entry in group.files {
                outcome.failures.append(
                    "\(display(entry.item.assignment, home: homeDirectory)): import failed: "
                        + protectFailureDetail(
                            error, projectDirectory: group.origin ?? homeDirectory))
            }
            continue
        }

        for entry in group.files {
            let path = display(entry.item.assignment, home: homeDirectory)
            guard let reference = references[entry.key] else {
                outcome.failures.append("\(path): the import returned no reference; the file was left untouched")
                continue
            }
            let lines = "\(entry.file.split.authLineCount) auth line(s)"
            if keepPlaintext {
                outcome.reportLines.append(
                    "  \(path): \(lines) -> \(reference); plaintext retained (--keep-plaintext)")
            } else {
                do {
                    try entry.file.rewrite(reference: reference)
                    outcome.reportLines.append(
                        "  \(path): moved \(lines) -> \(reference); other settings kept in place")
                } catch let error as ProtectError {
                    outcome.failures.append(
                        "\(path): imported, but the rewrite did not finish: \(error.message); "
                            + "re-run to finish removing the plaintext")
                    continue
                } catch {
                    outcome.failures.append("\(path): \(error.localizedDescription)")
                    continue
                }
            }
            outcome.recipes.append("csec exec-fd --preset npm=\(reference) -- npm <command>")
        }
    }
}

/// SSH keys share the dedicated `ssh-keys` store, as `csec protect --ssh`
/// does, unless a rule named a store. A default-resolved project or home store
/// (one with an origin) never applies to them. One session per store.
private func applySSHBatches(
    _ work: [ResolvedBulkAssignment],
    client: AgentClient,
    homeDirectory: String,
    keepPlaintext: Bool,
    outcome: inout BulkApplyOutcome
) {
    var byStore: [String: (store: NativeStoreName, items: [ResolvedBulkAssignment])] = [:]
    for item in work {
        guard let store = item.origin == nil ? item.store : try? NativeStoreName("ssh-keys") else {
            outcome.failures.append("\(display(item.assignment, home: homeDirectory)): no SSH key store")
            continue
        }
        byStore[store.value, default: (store, [])].items.append(item)
    }
    for (_, group) in byStore.sorted(by: { $0.key < $1.key }) {
        applySSHBatch(group.items, store: group.store, client: client,
                      homeDirectory: homeDirectory, keepPlaintext: keepPlaintext, outcome: &outcome)
    }
}

private func applySSHBatch(
    _ work: [ResolvedBulkAssignment],
    store: NativeStoreName,
    client: AgentClient,
    homeDirectory: String,
    keepPlaintext: Bool,
    outcome: inout BulkApplyOutcome
) {
    guard !work.isEmpty else { return }

    var planned: [ProtectPlannedFile] = []
    var plannedItems: [ResolvedBulkAssignment] = []
    var seenKeys = Set<String>()
    let agentPins = SSHConfigAgentPins.scanLocal(homeDirectory: homeDirectory)
    for item in work {
        let path = display(item.assignment, home: homeDirectory)
        do {
            let plan = try planSSHPrivateKey(
                rawPath: item.assignment.file.canonicalPath, baseDirectory: homeDirectory,
                agentPins: agentPins)
            guard seenKeys.insert(plan.key).inserted else { continue }
            planned.append(plan)
            plannedItems.append(item)
        } catch let error as ProtectError {
            outcome.failures.append("\(path): \(error.message)")
        } catch {
            outcome.failures.append("\(path): \(error.localizedDescription)")
        }
    }
    guard !planned.isEmpty else { return }

    do {
        let references = try planned.map {
            try NativeSecretReference(store: store, key: $0.key).secretRef
        }
        let registrations = zip(planned, references).map {
            SSHKeyRegistrationIntent(
                reference: $0.1.uri,
                label: ($0.0.originalPath as NSString).lastPathComponent
            )
        }
        let result = try commitSSHKeys(
            planned: planned,
            references: references,
            registrations: registrations,
            keepPlaintext: keepPlaintext,
            store: store,
            client: client
        )
        let metadataByReference = Dictionary(
            uniqueKeysWithValues: result.keys.map { ($0.reference, $0) })
        for (item, plan) in zip(plannedItems, planned) {
            let path = display(item.assignment, home: homeDirectory)
            guard let reference = result.referenceByPath[plan.originalPath] else { continue }
            let fingerprint = metadataByReference[reference]?.fingerprint ?? "registered"
            outcome.reportLines.append("  \(path)  ->  \(reference)  \(fingerprint)")
        }
        for retained in result.retainedPlaintext {
            outcome.failures.append(
                "\(homeRelativeDisplay(retained, home: homeDirectory)): changed while "
                    + "csec was working; private-key plaintext remains")
        }
        outcome.recipes.append(
            "csec ssh status   # the csec SSH agent now serves the registered key(s)")
    } catch {
        for item in plannedItems {
            outcome.failures.append(
                "\(display(item.assignment, home: homeDirectory)): SSH protection did not "
                    + "complete; the private key was left in place: \(error.localizedDescription)")
        }
    }
}

private func applyAWSImports(
    _ work: [ResolvedBulkAssignment],
    client: AgentClient,
    homeDirectory: String,
    keepPlaintext: Bool,
    configOverride: String?,
    outcome: inout BulkApplyOutcome
) {
    for item in work {
        let path = display(item.assignment, home: homeDirectory)
        guard let store = item.store else {
            outcome.failures.append("\(path): creds-aws needs a csec:// store destination")
            continue
        }
        do {
            let plan = try AWSProtectionPlan(
                path: item.assignment.file.canonicalPath,
                configPath: awsConfigurationPath(override: configOverride, homeDirectory: homeDirectory), store: store)
            let destination = NativeStoreWriteDestination(client: client, store: store, origin: item.origin)
            try plan.apply(destination: destination, keepPlaintext: keepPlaintext)
            for profile in plan.migration.importedProfiles {
                let key = AWSCredentialMigration.bundleKey(sourcePath: plan.source.path, profile: profile)
                outcome.reportLines.append("  \(path) [\(profile)] -> \(plan.migration.references[key]!) (credential_process configured)")
            }
            if !plan.migration.skippedProfiles.isEmpty {
                outcome.reportLines.append("  \(path): unchanged profiles without importable static credentials: "
                    + plan.migration.skippedProfiles.joined(separator: ", "))
            }
            if !plan.migration.importedProfiles.isEmpty {
                outcome.reportLines.append(keepPlaintext
                    ? "  \(path): plaintext retained (--keep-plaintext)"
                    : "  \(path): migrated static fields removed; other settings preserved")
            }
        } catch let error as ProtectError {
            outcome.failures.append("\(path): \(error.message)")
        } catch {
            outcome.failures.append("\(path): " + protectFailureDetail(error, projectDirectory: item.origin ?? homeDirectory))
        }
    }
}

private func display(_ assignment: BulkProtectAssignment, home: String) -> String {
    ReviewDisplay.sanitized(homeRelativeDisplay(assignment.file.canonicalPath, home: home))
}

/// The nearest ancestor holding a `.git` (project root) governs the file's
/// default store name; home-global files resolve to the home root itself.
func bulkProjectRoot(for path: String, homeDirectory: String) -> String {
    let home = homeDirectory.hasSuffix("/") ? String(homeDirectory.dropLast()) : homeDirectory
    let parent = (path as NSString).deletingLastPathComponent
    let underHome = path.hasPrefix(home + "/")
    var directory = parent
    while directory != "/", !(underHome && directory == home) {
        var info = stat()
        let marker = (directory as NSString).appendingPathComponent(".git")
        if marker.withCString({ lstat($0, &info) }) == 0 {
            return directory
        }
        directory = (directory as NSString).deletingLastPathComponent
    }
    return underHome ? home : parent
}

/// Containment base for cores: the home directory for anything under it,
/// the filesystem root otherwise. Relative store keys stay unique because
/// they embed the full base-relative path.
func bulkBaseDirectory(for path: String, homeDirectory: String) -> String {
    let home = homeDirectory.hasSuffix("/") ? String(homeDirectory.dropLast()) : homeDirectory
    return path.hasPrefix(home + "/") ? home : "/"
}

/// The wire-up recipe for a whole-file import whose assignment carries a
/// file-preset delivery.
private func appendDeliveryRecipe(
    for assignment: BulkProtectAssignment,
    reference: String,
    outcome: inout BulkApplyOutcome
) {
    switch assignment.approach {
    case .filePreset(let preset, let variable):
        if preset == "gh-config" {
            outcome.recipes.append("csec exec-file --gh-config \(reference) -- gh <command>")
        } else if InheritedFilePreset(rawValue: preset) != nil {
            outcome.recipes.append("csec exec-fd --preset \(preset)=\(reference) -- <command>")
        } else if let variable {
            outcome.recipes.append("csec exec-fd --fd \(variable)=\(reference) -- <command>")
        }
    default:
        break
    }
}
