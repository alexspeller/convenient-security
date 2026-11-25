import ConvenientSecurity
import Foundation

/// `csec setup --protect-files` as the user meets it: the notice before the
/// scan, the scan's progress line and folder positions, the picker's filter,
/// folders and bulk keys on a find of hundreds of files, and its in-place
/// prompts with readline editing keys.
func protectFilesUXTests() {
    print("\n# Bulk-protect UX (scan notice, progress, picker filter and prompts)")
    lineEditorTests()
    lineEditKeyDecoderTests()
    setupSelectFilterTests()
    setupSelectPickerTests()
    setupSelectPromptTests()
    scanNoticeTests()
    scanProgressTests()
}

private func decode(_ bytes: [UInt8]) -> [LineEditKey] {
    var remaining = bytes[...]
    var keys: [LineEditKey] = []
    while let first = remaining.popFirst() {
        keys.append(LineEditKeyDecoder.decode(first: first) { _ in remaining.popFirst() })
    }
    return keys
}

private func edit(_ editor: inout LineEditor, _ bytes: [UInt8]) -> LineEditor.Outcome {
    var outcome = LineEditor.Outcome.editing
    for key in decode(bytes) { outcome = editor.apply(key) }
    return outcome
}

private func lineEditorTests() {
    var editor = LineEditor()
    _ = edit(&editor, Array("work/**".utf8))
    _ = edit(&editor, [0x01] + Array("~/".utf8))
    check(editor.text == "~/work/**" && editor.cursor == 2,
          "ctrl-a moves to the start of the line, and typing inserts there")
    _ = edit(&editor, [0x05] + Array("/.env".utf8))
    check(editor.text == "~/work/**/.env" && editor.cursor == editor.text.count,
          "ctrl-e moves to the end of the line")
    _ = edit(&editor, [0x1B, 0x5B, 0x44, 0x1B, 0x5B, 0x44, 0x1B, 0x5B, 0x44, 0x0B])
    check(editor.text == "~/work/**/.", "left arrow moves back and ctrl-k kills to the end")
    _ = edit(&editor, [0x1B, 0x5B, 0x44, 0x1B, 0x5B, 0x43, 0x7F])
    check(editor.text == "~/work/**/", "right arrow moves forward and backspace deletes behind")
    _ = edit(&editor, [0x01, 0x1B, 0x5B, 0x33, 0x7E])
    check(editor.text == "/work/**/" && editor.cursor == 0, "the Delete key deletes under the cursor")
    _ = edit(&editor, [0x06, 0x02, 0x04])
    check(editor.text == "work/**/" && editor.cursor == 0, "ctrl-f, ctrl-b and ctrl-d move and delete")
    _ = edit(&editor, [0x05, 0x15])
    check(editor.text.isEmpty && editor.cursor == 0, "ctrl-u kills to the start of the line")

    var words = LineEditor(text: "~/work/app/.env other")
    _ = edit(&words, [0x17])
    check(words.text == "~/work/app/.env ", "ctrl-w kills back to whitespace")
    _ = edit(&words, [0x17])
    check(words.text.isEmpty, "ctrl-w takes a whole glob at once")
    var stepping = LineEditor(text: "~/work/app")
    _ = edit(&stepping, [0x1B, UInt8(ascii: "b")])
    check(stepping.cursor == 7, "alt-b moves back one word of a path")
    _ = edit(&stepping, [0x1B, 0x5B, 0x31, 0x3B, 0x35, 0x44])
    check(stepping.cursor == 2, "ctrl-left moves back a word")
    _ = edit(&stepping, [0x1B, UInt8(ascii: "f")])
    check(stepping.cursor == 6, "alt-f moves forward a word")
    _ = edit(&stepping, [0x1B, UInt8(ascii: "d")])
    check(stepping.text == "~/work", "alt-d kills the next word")
    _ = edit(&stepping, [0x1B, 0x7F])
    check(stepping.text == "~/", "alt-backspace kills back a word")
    _ = edit(&stepping, [0x1B, 0x5B, 0x48])
    check(stepping.cursor == 0, "the Home key moves to the start")
    _ = edit(&stepping, [0x1B, 0x4F, 0x46])
    check(stepping.cursor == 2, "the End key moves to the end")

    var submitted = LineEditor(text: "*.env")
    check(edit(&submitted, [0x0D]) == .submitted("*.env"), "enter submits the line")
    var escaped = LineEditor(text: "*.env")
    check(edit(&escaped, [0x1B]) == .cancelled, "a lone esc cancels")
    var interrupted = LineEditor(text: "*.env")
    check(edit(&interrupted, [0x03]) == .cancelled, "ctrl-c cancels the prompt")
    var empty = LineEditor()
    check(edit(&empty, [0x04]) == .cancelled, "ctrl-d on an empty line cancels, as readline's EOF")

    let long = LineEditor(text: String(repeating: "a", count: 100) + "END")
    let shown = long.render(prompt: "glob: ", width: 40)
    check(shown.line.count <= 39 && shown.line.hasSuffix("END") && shown.cursorColumn == 38,
          "a long line scrolls so the cursor stays on screen within the width")
    var home = long
    home.apply(.home)
    let start = home.render(prompt: "glob: ", width: 40)
    check(start.line.hasPrefix("glob: aaa") && start.cursorColumn == 6 && start.line.count <= 39,
          "at the start of a long line the text shows from its first character")
}

private func lineEditKeyDecoderTests() {
    check(decode(Array("é".utf8)) == [.insert("é")], "UTF-8 characters are inserted whole")
    check(decode([0xE2, 0x80, 0xAE]) == [.ignored], "a bidi override is never inserted")
    check(decode([0x1B, 0x5B, 0x32, 0x30, 0x30, 0x7E, 0x61]) == [.ignored, .insert("a")],
          "an unknown CSI sequence is consumed whole, so its tail never lands in the text")
    check(decode([0x1B, 0x5B, 0x41, 0x1B, 0x4F, 0x42, 0x1B, 0x5B, 0x35, 0x7E, 0x1B, 0x5B, 0x36, 0x7E, 0x09])
              == [.up, .down, .pageUp, .pageDown, .tab],
          "arrows, Page Up/Down and Tab decode for the list around a prompt")
    var line = LineEditor(text: "*.env")
    check(edit(&line, [0x1B, 0x5B, 0x41, 0x09]) == .editing && line.text == "*.env",
          "a single line ignores up and Tab")
    check(decode([0x03, 0x07, 0x1B]) == [.interrupt, .cancel, .cancel],
          "ctrl-c is an interrupt, told apart from esc and ctrl-g")
    check(decode([0x00, 0x1C]) == [.ignored, .ignored], "other control bytes are ignored")
}

private func discovered(_ path: String, _ kind: SecretFileKind, _ approach: CredentialDelivery)
    -> DiscoveredSecretFile
{
    DiscoveredSecretFile(
        canonicalPath: path, aliasPaths: [], kind: kind, catalogID: nil,
        displayName: nil, mode: 0o600, byteSize: 32, sizeClass: .small, rootLabel: "~",
        suggestedApproach: approach, keychainFallback: false, notes: [])
}

private func setupSelectFilterTests() {
    func passes(_ query: String, _ paths: [String]) -> Bool { SetupSelectFilter(query).matches(paths) }
    let worktree = "~/globex/worktrees/fix-login/.envrc"
    check(passes("worktrees", [worktree]),
          "a plain word matches anywhere in the path, with no glob needed")
    check(passes("WORKTREES", [worktree]) == false && passes("worktrees", ["~/Worktrees/.env"]),
          "lower-case words ignore case; a capital makes the word case-sensitive")
    check(passes("envrc globex", [worktree]) && !passes("envrc projects", [worktree]),
          "every word must appear")
    check(!passes("envrc !worktrees", [worktree]) && passes("envrc !projects", [worktree]),
          "!word drops paths containing it")
    check(passes(".envrc$", [worktree]) && !passes(".env$", [worktree])
              && !passes(".envrc$", ["~/app/.envrc.local"]),
          "word$ ties the word to the end of the path")
    check(passes("^~/globex", [worktree]) && !passes("^globex", [worktree]),
          "^word ties the word to the start of the path")
    check(passes("globex*login", [worktree]) && passes("fix-l?gin", [worktree])
              && !passes("login*globex", [worktree]),
          "* stands for any characters and ? for one")
    check(passes("alias", ["~/real/.env", "~/aliases/.env.alias"]),
          "a hardlink's path matches too")
    check(SetupSelectFilter("  ").isEmpty && SetupSelectFilter("!").isEmpty,
          "blank words and bare operators filter nothing")
}

/// Alex's find of 14 Nov 2026: 265 files, 200 of them `.envrc` copies in
/// worktrees, from which the step keeps three project `.envrc` files and
/// `~/.npmrc`.
private func largeFind() -> [BulkProtectAssignment] {
    var files: [DiscoveredSecretFile] = []
    for index in 0..<200 {
        files.append(discovered("/Users/alex/globex/worktrees/wt\(index)/.envrc", .envrc, .perVar))
    }
    for name in ["vat", "dashboard", "ical-feed"] + (0..<40).map({ "p\($0)" }) {
        files.append(discovered("/Users/alex/projects/\(name)/.envrc", .envrc, .perVar))
    }
    files.append(discovered("/Users/alex/projects/vat/.env", .dotenv, .perVar))
    for index in 0..<16 {
        files.append(discovered("/Users/alex/old/backup\(index)/.env", .dotenv, .perVar))
    }
    files += [
        discovered("/Users/alex/.npmrc", .toolCredential,
                   .filePreset(preset: "npm", pathEnvironmentVariable: nil)),
        discovered("/Users/alex/.zshrc", .shellRc, .wholeFile),
        discovered("/Users/alex/.ssh/id_ed25519", .sshPrivateKey, .sshKey),
        discovered("/Users/alex/.ssh/id_rsa", .sshPrivateKey, .sshKey),
        discovered("/Users/alex/.aws/credentials", .toolCredential, .credsAws),
    ]
    // Discovery's order is not the display order.
    files.reverse()
    return SetupProtectPlanner.assignments(files: files, rules: [], homeDirectory: "/Users/alex")
}

private func setupSelectPickerTests() {
    let assignments = largeFind()
    check(assignments.count == 265, "the large-find fixture has 265 files")
    var model = SetupSelectModel(assignments: assignments, homeDirectory: "/Users/alex", screenRows: 16)
    check(model.selected.isEmpty && model.status?.contains("265 files found, so none is selected yet") == true,
          "a large find starts with nothing selected and says so")
    check(model.rows.count <= 16 && model.rows.contains { $0.label == "~/globex/worktrees/" }
              && !model.rows.contains { $0.label.contains("wt0") },
          "the first view fits the screen, with 200 worktree copies as one closed folder row")
    check(model.rows.contains { $0.label == "~/.ssh/" }
              && model.rows.contains { $0.label == "id_rsa" && $0.depth == 1 },
          "small folders open while the view still fits")

    // His task, as keystrokes: filter, Tab to pick, Ctrl-U to clear the
    // filter for the next one, then Enter twice.
    let task = Array("/vat/.envrc\t\u{15}dashboard\t\u{15}ical-feed\t\u{15}npmrc\t\r".utf8)
    var step = SetupSelectModel.Step.stay
    for key in decode(task) { step = model.handle(key) }
    check(step == .stay && model.mode == .list && model.selected.count == 4,
          "four filters and four Tabs pick the four files, and Enter returns to the list")
    check(model.render(color: false, width: 120).contains("4 of 265 selected"),
          "the footer counts the picks")
    for key in decode(Array("\r".utf8)) { step = model.handle(key) }
    check(step == .apply && model.effectiveAssignments.map(\.file.canonicalPath) == [
        "/Users/alex/.npmrc", "/Users/alex/projects/dashboard/.envrc",
        "/Users/alex/projects/ical-feed/.envrc", "/Users/alex/projects/vat/.envrc",
    ], "Enter in the list goes to the plan with exactly those four files")
    check(task.count + 1 <= 50, "the task takes under fifty keystrokes, most of them the names typed")

    // Iterative bulk select and deselect by search.
    var bulk = SetupSelectModel(assignments: assignments, homeDirectory: "/Users/alex", screenRows: 16)
    for key in decode(Array("/worktrees\ra".utf8)) { _ = bulk.handle(key) }
    check(bulk.selected.count == 200 && bulk.status == "selected 200 file(s) the filter shows",
          "a selects every row the filter shows")
    for key in decode(Array("/\u{15}wt1\rn".utf8)) { _ = bulk.handle(key) }
    check(bulk.selected.count == 89, "n deselects every row a narrower filter shows (wt1, wt10-19, wt100-199)")
    let filtered = bulk.render(color: false, width: 120)
    check(filtered.contains("filter: wt1 · 111 of 265 files") && filtered.contains("89 of 265 selected · 0 of the 111 shown"),
          "the list says which filter is on, how many rows it shows and how many of them are picked")
    for key in decode(Array("i".utf8)) { _ = bulk.handle(key) }
    check(bulk.selected.count == 200, "i inverts the rows shown")
    for key in decode([0x1B]) { _ = bulk.handle(key) }
    check(bulk.query.text.isEmpty && bulk.rows.contains { $0.label == "~/globex/worktrees/" },
          "esc clears the filter and the tree returns")
    check(bulk.rows[bulk.cursor].label == "~/globex/worktrees/",
          "the cursor lands on the closed folder holding the file it was on")
    check(bulk.render(color: false, width: 120).contains("[x] ▸ ~/globex/worktrees/"),
          "a fully picked folder shows [x]")
    bulk.toggle()
    check(bulk.selected.isEmpty, "space on a fully picked folder unpicks all of it")
    for key in decode(Array("/wt1\ra".utf8) + [0x1B]) { _ = bulk.handle(key) }
    check(bulk.render(color: false, width: 120).contains("[-] ▸ ~/globex/worktrees/"),
          "a partly picked folder shows [-]")
    bulk.toggle()
    check(bulk.selected.count == 200, "space on a partly picked folder picks all of it")

    // Folding.
    var tree = SetupSelectModel(assignments: assignments, homeDirectory: "/Users/alex", screenRows: 16)
    guard let projects = tree.rows.firstIndex(where: { $0.label == "~/projects/" }) else {
        check(false, "the projects folder is a top-level row")
        return
    }
    while tree.cursor < projects { tree.moveDown() }
    _ = tree.handle(.right)
    check(tree.rows.contains { $0.label == "vat/" && $0.depth == 1 }
              && tree.rows.contains { $0.label == "dashboard/.envrc" },
          "→ opens a folder; a subfolder of several files is a row, a one-file one shows as its file")
    _ = tree.handle(.right)
    check(tree.cursor == projects + 1, "→ on an open folder steps into it")
    _ = tree.handle(.left)
    check(tree.cursor == projects, "← on a row inside a folder moves to the folder")
    _ = tree.handle(.left)
    check(!tree.rows.contains { $0.label == "vat/" }, "← on an open folder closes it")
    tree.pageSize = 3
    _ = tree.handle(.pageDown)
    check(tree.cursor == min(projects + 3, tree.rows.count - 1), "Page Down moves a page")

    // Keys that would throw away a long selection do not.
    var keys = SetupSelectModel(assignments: assignments, homeDirectory: "/Users/alex", screenRows: 16)
    check(keys.handle(.cancel) == .stay, "esc with no filter does not cancel the picker")
    check(keys.handle(.insert("q")) == .cancel && keys.handle(.interrupt) == .cancel,
          "q and ctrl-c cancel")
    check(keys.handle(.insert("p")) == .prompt(.approach) && keys.handle(.insert("d")) == .prompt(.destination),
          "p and d open the approach and destination prompts")

    // Typing the filter: readline keys, how matching works, no matches.
    var typing = SetupSelectModel(assignments: assignments, homeDirectory: "/Users/alex", screenRows: 16)
    for key in decode(Array("/envrc".utf8) + [0x01] + Array("!worktrees ".utf8)) { _ = typing.handle(key) }
    check(typing.mode == .filtering && typing.query.text == "!worktrees envrc" && typing.rows.count == 43,
          "ctrl-a moves to the start of the filter, and the rows follow the words as typed")
    let prompt = typing.renderFilterPrompt(color: false, width: 120)
    check(prompt.lines[0].hasPrefix("every word must appear in the path, any case · !word excludes")
              && prompt.lines[1] == "/ !worktrees envrc" && prompt.cursorColumn == "/ !worktrees ".count,
          "the filter line says how matching works, with the cursor where the typing is")
    check(typing.render(color: false, width: 120).contains("type to filter · ↑/↓ move · tab pick and next"),
          "the key line shows the filter's keys while typing")
    for key in decode(Array("zzz".utf8)) { _ = typing.handle(key) }
    check(typing.rows.isEmpty && typing.render(color: false, width: 120).contains("no files match the filter"),
          "a filter that matches nothing says so")
    for key in decode([0x1B]) { _ = typing.handle(key) }
    check(typing.mode == .list && typing.query.text.isEmpty && typing.selected.isEmpty,
          "esc while typing clears the filter, back in the list with the selection as it was")

    let small = SetupSelectModel(
        assignments: Array(assignments.filter { $0.file.canonicalPath.contains("/projects/") }.prefix(5))
            + assignments.filter { $0.file.kind == .shellRc },
        homeDirectory: "/Users/alex")
    check(small.selected.count == 5 && small.status == nil,
          "a find of twenty or fewer starts with its default protections selected, skips left out")
    let narrow = typing.render(color: false, width: 40).split(separator: "\n")
    check(narrow.allSatisfy { $0.count <= 40 }, "the picker's lines fit the width")
    let wrapped = typing.render(color: false, width: 80)
    check(wrapped.contains("q quit") && wrapped.contains("space pick"),
          "the key line wraps rather than cutting keys off")
    var busy = SetupSelectModel(assignments: assignments, homeDirectory: "/Users/alex", screenRows: 16)
    busy.pageSize = 40
    for key in decode(Array("/wt\r".utf8)) + [.pageDown, .insert("a")] { _ = busy.handle(key) }
    check(busy.status != nil && busy.cursor == 40, "the busy picker has a status and rows above and below")
    check([80, 120].allSatisfy { width in
        busy.render(color: false, width: width, height: 20).split(separator: "\n").count <= 20
    }, "with a filter, a status and rows above and below, the picker fits the height it is given")
}

private func setupSelectPromptTests() {
    let home = "/Users/alex"
    func assignment(_ path: String) -> BulkProtectAssignment {
        BulkProtectAssignment(
            file: DiscoveredSecretFile(
                canonicalPath: path, aliasPaths: [], kind: .dotenv, catalogID: nil,
                displayName: nil, mode: 0o600, byteSize: 32, sizeClass: .small, rootLabel: "~",
                suggestedApproach: .perVar, keychainFallback: false, notes: []),
            approach: .perVar)
    }
    var model = SetupSelectModel(
        assignments: [assignment(home + "/app/.env"), assignment(home + "/work/.envrc"),
                      assignment(home + "/work/api/.env")],
        homeDirectory: home)
    for key in decode(Array("n/~/work\ra".utf8)) { _ = model.handle(key) }
    check(model.selected == [1, 2], "the files under ~/work are selected")

    var approach = SetupSelectPrompt(kind: .approach)
    for key in decode(Array("whole-flie".utf8)) { _ = approach.handle(key, model: &model) }
    check(approach.handle(.submit, model: &model) == .stay
              && approach.message?.contains("unknown approach whole-flie") == true
              && model.assignments[1].approach == .perVar,
          "an unknown approach keeps the prompt open and changes nothing")
    for key in decode([0x1B, 0x5B, 0x44, 0x7F, 0x7F] + Array("il".utf8)) {
        _ = approach.handle(key, model: &model)
    }
    check(approach.editor.text == "whole-file" && approach.handle(.submit, model: &model) == .close
              && model.assignments[1].approach == .wholeFile
              && model.assignments[0].approach == .perVar,
          "the typo is fixed in place and the approach applies to the selected files only")

    var destination = SetupSelectPrompt(kind: .destination)
    for key in decode(Array("vault/item".utf8)) { _ = destination.handle(key, model: &model) }
    check(destination.handle(.submit, model: &model) == .stay
              && model.assignments[1].destination == nil,
          "a destination without csec:// or op:// keeps the prompt open")
    for key in decode([0x01] + Array("op://".utf8)) { _ = destination.handle(key, model: &model) }
    check(destination.handle(.submit, model: &model) == .close
              && model.assignments[1].destination == "op://vault/item",
          "a corrected destination applies")

    let narrow = SetupSelectPrompt(kind: .destination).render(model: model, color: false, width: 30)
    check(narrow.lines.allSatisfy { $0.count <= 29 }, "the prompt's lines fit the width")
}

private func scanNoticeTests() {
    let home = ProtectFilesScanText.notice(rootLabels: [], coversHome: true, mode: .interactive)
    let text = home.joined(separator: "\n")
    check(home.first == "csec is about to scan this Mac for files holding secrets.",
          "the notice opens by saying a scan is about to happen")
    check(text.contains("~, your whole home directory") && text.contains("known credential locations"),
          "it names the folders scanned and the known locations probed")
    check(text.contains("sends nothing over the network, copies nothing and changes nothing")
              && text.contains("never saved"),
          "it says the scan sends, copies, changes and saves nothing")
    check(text.contains("Nothing is protected until you do") && text.contains("csec backup setup"),
          "it says protection waits for the user's choice and names the opt-in backup")
    let narrow = ProtectFilesScanText.notice(
        rootLabels: ["~/work/app"], coversHome: false, mode: .dryRun).joined(separator: "\n")
    check(narrow.contains("Where: ~/work/app") && narrow.contains("are not checked")
              && narrow.contains("--dry-run prints the plan and changes nothing"),
          "a narrowed dry run says where, that known locations outside are not checked, and what follows")
    let applied = ProtectFilesScanText.notice(
        rootLabels: ["~/a\u{1B}[31m"], coversHome: false, mode: .apply).joined(separator: "\n")
    check(!applied.contains("\u{1B}") && applied.contains("--apply protects the planned files"),
          "root labels are sanitized and --apply says it will protect without asking")
}

private func scanProgressTests() {
    check(ProtectFilesScanText.duration(45) == "45s" && ProtectFilesScanText.duration(187) == "3m 07s"
              && ProtectFilesScanText.duration(3720) == "1h 02m",
          "durations read as seconds, minutes or hours")
    check(ProtectFilesScanText.count(1_234_567) == "1,234,567" && ProtectFilesScanText.count(999) == "999",
          "counts group thousands")

    let sweep = SecretFileDiscoveryProgress(
        visitedEntries: 183_204, discoveredFiles: 7, currentLocation: "~/projects/harbor",
        phase: .sweep, rootLabel: "~", rootIndex: 1, rootCount: 1,
        folders: [.init(name: "projects", index: 3, total: 25), .init(name: "harbor", index: 12, total: 60)])
    let wide = ProtectFilesScanText.progressLine(sweep, elapsed: 64, width: 200)
    check(wide == "Scanning ~ · folder 3 of 25 (projects) › 12 of 60 (harbor) · 183,204 entries · 7 found · 1m 04s",
          "the progress line says where it is, how many folders of how many, the counts and the time")
    let eighty = ProtectFilesScanText.progressLine(sweep, elapsed: 64, width: 80)
    check(eighty.count <= 79 && eighty.contains("folder 3 of 25 › 12 of 60") && eighty.hasSuffix("1m 04s"),
          "at 80 columns it drops folder names before the counts and time")
    for width in [20, 40, 60] {
        check(ProtectFilesScanText.progressLine(sweep, elapsed: 64, width: width).count <= width - 1,
              "the progress line never wraps at \(width) columns")
    }
    let probes = SecretFileDiscoveryProgress(
        visitedEntries: 120, discoveredFiles: 3, currentLocation: "aws", phase: .knownLocations)
    check(ProtectFilesScanText.progressLine(probes, elapsed: 2, width: 100)
              == "Checking known credential locations · 120 checked · 3 found · 2s",
          "the known-locations phase says what it is checking")
    let roots = SecretFileDiscoveryProgress(
        visitedEntries: 10, discoveredFiles: 0, currentLocation: "~/b", phase: .sweep,
        rootLabel: "~/b", rootIndex: 2, rootCount: 3)
    check(ProtectFilesScanText.progressLine(roots, elapsed: 1, width: 100)
              == "Scanning ~/b (root 2 of 3) · 10 entries · 0 found · 1s",
          "with several roots it says which root of how many")

    // The engine's folder positions over a real tree: three top-level
    // folders with two, zero and one folders inside.
    let fm = FileManager.default
    let base = NSTemporaryDirectory() + "csec-progress-\(UUID().uuidString.lowercased())"
    defer { try? fm.removeItem(atPath: base) }
    for directory in ["root/a/x", "root/a/y", "root/b", "root/c/z", "home"] {
        try? fm.createDirectory(atPath: base + "/" + directory, withIntermediateDirectories: true)
    }
    fm.createFile(atPath: base + "/root/top.txt", contents: Data("x".utf8))
    var seen: [SecretFileDiscoveryProgress] = []
    _ = SecretFileDiscoveryEngine.discover(
        roots: [base + "/root"], homeDirectory: base + "/home") { seen.append($0) }
    let sweeps = seen.filter { $0.phase == .sweep }
    let tops = sweeps.compactMap(\.folders.first)
    check(!tops.isEmpty && tops.allSatisfy { $0.total == 3 }
              && Set(tops.map(\.index)) == [1, 2, 3]
              && zip(tops, tops.dropFirst()).allSatisfy { $0.index <= $1.index },
          "the walk reports each top-level folder in turn, as 1, 2 and 3 of 3")
    let inner = sweeps.filter { $0.folders.count == 2 }
    check(Set(inner.map { "\($0.folders[0].name):\($0.folders[1].index)/\($0.folders[1].total)" })
              == ["a:1/2", "a:2/2", "c:1/1"],
          "inside a top-level folder it reports that folder's own folders, k of n")
    check(sweeps.first?.rootLabel != nil && sweeps.allSatisfy { $0.rootIndex == 1 && $0.rootCount == 1 },
          "every sweep report names its root and its place among the roots")
    check(!seen.contains { $0.phase == .knownLocations },
          "a scan that does not cover home probes no known locations")
}
