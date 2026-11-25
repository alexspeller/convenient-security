import Foundation

/// The bulk-protect picker's filter: words separated by spaces that must all
/// appear in a file's path, as fzf's extended search and most list filters
/// read them. Matching is by substring, never fuzzy: `a`, `n` and `i` act on
/// every row the filter shows, and a fuzzy match would sweep in rows nobody
/// meant. A word ignores case unless it has a capital letter (smart case);
/// `!word` drops paths containing it; `^word` and `word$` tie it to the start
/// or end of the path; `*` stands for any characters and `?` for one.
public struct SetupSelectFilter: Equatable, Sendable {
    struct Term: Equatable, Sendable {
        var pattern: [Character]
        var negated: Bool
        var anchoredStart: Bool
        var anchoredEnd: Bool
        var caseSensitive: Bool
    }

    let terms: [Term]

    public init(_ query: String) {
        terms = query.split(whereSeparator: \.isWhitespace).compactMap { word in
            var text = Substring(word)
            var negated = false
            var anchoredStart = false
            var anchoredEnd = false
            if text.hasPrefix("!") {
                negated = true
                text = text.dropFirst()
            }
            if text.hasPrefix("^") {
                anchoredStart = true
                text = text.dropFirst()
            }
            if text.hasSuffix("$") {
                anchoredEnd = true
                text = text.dropLast()
            }
            guard !text.isEmpty else { return nil }
            let caseSensitive = text.contains { $0.isUppercase }
            return Term(
                pattern: Array(caseSensitive ? String(text) : text.lowercased()),
                negated: negated, anchoredStart: anchoredStart, anchoredEnd: anchoredEnd,
                caseSensitive: caseSensitive)
        }
    }

    public var isEmpty: Bool { terms.isEmpty }

    /// Whether a file whose paths (canonical, then hardlinks) are `paths`
    /// passes: every word appears in one of them and no `!word` in any.
    public func matches(_ paths: [String]) -> Bool {
        let exact = paths.map { Array($0) }
        let lowered = paths.map { Array($0.lowercased()) }
        for term in terms {
            let hit = (term.caseSensitive ? exact : lowered).contains { Self.match(term, $0) }
            if hit == term.negated { return false }
        }
        return true
    }

    /// `*` and `?` wildcards; an unanchored end behaves as a `*` there, so a
    /// plain word is a substring.
    static func match(_ term: Term, _ text: [Character]) -> Bool {
        var pattern = term.pattern
        if !term.anchoredStart { pattern.insert("*", at: 0) }
        if !term.anchoredEnd { pattern.append("*") }
        // Greedy wildcard match that backtracks to the last `*` on a miss.
        var p = 0
        var t = 0
        var star: Int?
        var resume = 0
        while t < text.count {
            if p < pattern.count, pattern[p] == "*" {
                star = p
                resume = t
                p += 1
            } else if p < pattern.count, pattern[p] == "?" || pattern[p] == text[t] {
                p += 1
                t += 1
            } else if let star {
                p = star + 1
                resume += 1
                t = resume
            } else {
                return false
            }
        }
        while p < pattern.count, pattern[p] == "*" { p += 1 }
        return p == pattern.count
    }
}

/// The picker's directory tree over the files' home-relative paths. A
/// directory holding nothing but one subdirectory merges into it
/// (`globex/worktrees/`), as VS Code's compact folders do, and a directory
/// holding a single file shows as that file (`vat/.envrc`), so every folder
/// row stands for at least two files.
struct SetupSelectTree: Equatable {
    struct Directory: Equatable {
        var path: String
        var parent: Int?
        var directories: [Int] = []
        var files: [Int] = []
        /// Every file at or below this directory.
        var descendants: [Int] = []
    }

    enum Entry: Equatable {
        case directory(Int)
        case file(Int)
    }

    struct Labeled: Equatable {
        let entry: Entry
        let label: String
    }

    let directories: [Directory]
    /// The directory whose entries are the top-level rows.
    let top: Int
    /// Each directory's entries as rows under it, sorted by label.
    let entries: [[Labeled]]
    /// File indices in path order.
    let order: [Int]
    let displayPaths: [String]

    init(displayPaths: [String]) {
        self.displayPaths = displayPaths
        order = displayPaths.indices.sorted {
            (displayPaths[$0], $0) < (displayPaths[$1], $1)
        }
        var directories = [Directory(path: "", parent: nil)]
        var byPath: [String: Int] = [:]
        for file in order {
            var components = displayPaths[file]
                .split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            components.removeLast()
            var parent = 0
            var path: String?
            for component in components {
                let next: String
                switch path {
                case nil: next = component.isEmpty ? "/" : component
                case "/": next = "/" + component
                case let some?: next = some + "/" + component
                }
                path = next
                if let existing = byPath[next] {
                    parent = existing
                } else {
                    directories.append(Directory(path: next, parent: parent))
                    let id = directories.count - 1
                    directories[parent].directories.append(id)
                    byPath[next] = id
                    parent = id
                }
            }
            directories[parent].files.append(file)
            var walk: Int? = parent
            while let id = walk {
                directories[id].descendants.append(file)
                walk = directories[id].parent
            }
        }

        // A directory with no files of its own and one subdirectory is
        // replaced by that subdirectory, all the way down.
        var pending = [0]
        while let id = pending.popLast() {
            directories[id].directories = directories[id].directories.map { child in
                var merged = child
                while directories[merged].files.isEmpty, directories[merged].directories.count == 1 {
                    merged = directories[merged].directories[0]
                }
                directories[merged].parent = id
                return merged
            }
            pending.append(contentsOf: directories[id].directories)
        }
        var top = 0
        while directories[top].files.isEmpty, directories[top].directories.count == 1 {
            top = directories[top].directories[0]
        }
        self.directories = directories
        self.top = top

        entries = directories.indices.map { id in
            func label(_ path: String) -> String {
                Self.label(path, under: id, directories, top)
            }
            var list: [Labeled] = directories[id].directories.map { child in
                let only = directories[child].descendants
                return only.count == 1
                    ? Labeled(entry: .file(only[0]), label: label(displayPaths[only[0]]))
                    : Labeled(entry: .directory(child), label: label(directories[child].path + "/"))
            }
            list += directories[id].files.map { Labeled(entry: .file($0), label: label(displayPaths[$0])) }
            return list.sorted { ($0.label.lowercased(), $0.label) < ($1.label.lowercased(), $1.label) }
        }
    }

    /// Top-level rows show the whole path; deeper rows show it from their
    /// folder down.
    private static func label(
        _ path: String, under id: Int, _ directories: [Directory], _ top: Int
    ) -> String {
        guard id != top else { return path }
        let base = directories[id].path
        guard path.hasPrefix(base) else { return path }
        let rest = path.dropFirst(base.count)
        return String(rest.hasPrefix("/") ? rest.dropFirst() : rest)
    }
}

/// Pure state machine for the bulk-protect file picker; the raw-mode driver
/// owns only I/O. Its keys follow the multi-select lists people already know:
/// `/` opens a live filter (less, vim, lazygit, ranger) whose matches show as
/// a flat list, Tab picks a row and moves on (fzf), `a`, `n` and `i` select,
/// deselect or invert every row shown (Midnight Commander's `+`, `-` and `*`,
/// ranger's marks, inquirer's checkboxes), and with no filter the files are a
/// tree of folders that pick and fold as one row (installer checkbox trees).
/// A small find starts with its default protections selected; a large one
/// starts with nothing selected, because nobody can review hundreds of
/// preselected rows, and keeping a few out of hundreds should never mean
/// deselecting the rest.
public struct SetupSelectModel: Equatable {
    public enum Row: Equatable, Sendable {
        case directory(Int)
        case file(Int)
    }

    public struct VisibleRow: Equatable, Sendable {
        public let row: Row
        public let depth: Int
        public let label: String
    }

    public enum Mode: Equatable, Sendable { case list, filtering }

    public enum Step: Equatable, Sendable {
        case stay
        case apply
        case cancel
        case prompt(SetupSelectPrompt.Kind)
    }

    /// The most files that start selected: a find this small fits on one
    /// screen, so its preselection can be read before Enter.
    public static let preselectLimit = 20

    public private(set) var assignments: [BulkProtectAssignment]
    /// Assignment indices.
    public private(set) var selected: Set<Int>
    /// Index into `rows`.
    public private(set) var cursor: Int = 0
    public private(set) var mode: Mode = .list
    public private(set) var query = LineEditor()
    public private(set) var expanded: Set<Int>
    public private(set) var rows: [VisibleRow] = []
    /// One line under the table saying what the last key did; the next key
    /// clears it.
    public var status: String?
    /// Rows Page Up and Page Down move by; the driver sets it from the
    /// terminal's height.
    public var pageSize = 10
    private let tree: SetupSelectTree
    private let homeDirectory: String

    /// `screenRows`: how many rows the first view may fill. Folders open
    /// smallest first while they fit, so a folder of hundreds of copies stays
    /// one closed row.
    public init(assignments: [BulkProtectAssignment], homeDirectory: String, screenRows: Int = 16) {
        self.assignments = assignments
        self.homeDirectory = homeDirectory
        let large = assignments.count > Self.preselectLimit
        selected = large ? [] : Set(assignments.indices.filter { assignments[$0].approach != .skip })
        tree = SetupSelectTree(displayPaths: assignments.map {
            Self.displayPath($0.file.canonicalPath, home: homeDirectory)
        })
        expanded = Self.initialExpansion(tree, budget: max(1, screenRows))
        rows = computeRows()
        if large {
            status = "\(assignments.count) files found, so none is selected yet: "
                + "/ filters, space picks a row or folder, a picks all shown"
        }
    }

    public var filter: SetupSelectFilter { SetupSelectFilter(query.text) }

    /// The files the rows stand for: the filter's matches, or every file.
    public var shownFiles: [Int] {
        filter.isEmpty ? tree.order : rows.compactMap {
            if case .file(let file) = $0.row { return file }
            return nil
        }
    }

    // MARK: keys

    public mutating func handle(_ key: LineEditKey) -> Step {
        status = nil
        switch mode {
        case .filtering: return handleFiltering(key)
        case .list: return handleList(key)
        }
    }

    private mutating func handleList(_ key: LineEditKey) -> Step {
        switch key {
        case .up: moveUp()
        case .down: moveDown()
        case .pageUp: move(by: -pageSize)
        case .pageDown: move(by: pageSize)
        case .home: cursor = 0
        case .end: cursor = max(0, rows.count - 1)
        case .right: expand()
        case .left: collapse()
        case .tab:
            toggle()
            moveDown()
        case .submit: return .apply
        case .interrupt: return .cancel
        case .cancel:
            if !query.text.isEmpty { clearFilter() }
        case .insert(let character):
            switch character.lowercased() {
            case "k": moveUp()
            case "j": moveDown()
            case "l": expand()
            case "h": collapse()
            case " ": toggle()
            case "/": mode = .filtering
            case "a": selectShown()
            case "n": deselectShown()
            case "i": invertShown()
            case "p": return .prompt(.approach)
            case "d": return .prompt(.destination)
            case "q": return .cancel
            default: break
            }
        default:
            break
        }
        return .stay
    }

    private mutating func handleFiltering(_ key: LineEditKey) -> Step {
        switch key {
        case .up: moveUp()
        case .down: moveDown()
        case .pageUp: move(by: -pageSize)
        case .pageDown: move(by: pageSize)
        case .tab:
            toggle()
            moveDown()
        case .interrupt: return .cancel
        case .submit:
            mode = .list
            if !filter.isEmpty {
                status = "\(rows.count) file(s) shown; a, n and i act on them, esc clears the filter"
            }
        default:
            let before = query.text
            if query.apply(key) == .cancelled {
                clearFilter()
                mode = .list
            } else if query.text != before {
                refresh(keeping: nil)
                cursor = 0
            }
        }
        return .stay
    }

    // MARK: movement and folding

    public mutating func moveUp() { if cursor > 0 { cursor -= 1 } }
    public mutating func moveDown() { if cursor < rows.count - 1 { cursor += 1 } }

    private mutating func move(by offset: Int) {
        cursor = min(max(0, cursor + offset), max(0, rows.count - 1))
    }

    private var current: VisibleRow? { rows.indices.contains(cursor) ? rows[cursor] : nil }

    /// Opens the folder under the cursor; on an open one, steps into it.
    public mutating func expand() {
        guard let current, case .directory(let id) = current.row else { return }
        if expanded.contains(id) {
            moveDown()
        } else {
            expanded.insert(id)
            refresh(keeping: current.row)
        }
    }

    /// Closes the folder under the cursor; elsewhere, moves to the folder
    /// holding the row.
    public mutating func collapse() {
        guard let current else { return }
        if case .directory(let id) = current.row, expanded.contains(id) {
            expanded.remove(id)
            refresh(keeping: current.row)
            return
        }
        guard current.depth > 0 else { return }
        if let parent = rows[..<cursor].lastIndex(where: { $0.depth == current.depth - 1 }) {
            cursor = parent
        }
    }

    // MARK: selection

    /// Picks the row under the cursor, or a whole folder; a fully picked row
    /// or folder is unpicked.
    public mutating func toggle() {
        guard let current else { return }
        let files = self.files(of: current.row)
        if files.allSatisfy(selected.contains) {
            selected.subtract(files)
        } else {
            selected.formUnion(files)
        }
    }

    public mutating func selectShown() {
        let shown = shownFiles
        selected.formUnion(shown)
        status = "selected \(shown.count) \(shownDescription)"
    }

    public mutating func deselectShown() {
        let shown = shownFiles
        selected.subtract(shown)
        status = "deselected \(shown.count) \(shownDescription)"
    }

    public mutating func invertShown() {
        let shown = Set(shownFiles)
        selected = selected.symmetricDifference(shown)
        status = "inverted the selection of \(shown.count) \(shownDescription)"
    }

    private var shownDescription: String {
        filter.isEmpty ? "file(s), every file found" : "file(s) the filter shows"
    }

    /// Apply an approach to every selected row.
    public mutating func setApproach(_ approach: BulkProtectApproach) {
        for index in selected { assignments[index].approach = approach }
    }

    /// Apply a destination override (nil restores the default store) to every
    /// selected row.
    public mutating func setDestination(_ destination: String?) {
        for index in selected { assignments[index].destination = destination }
    }

    /// The rows that will actually be applied: selected and not skipped.
    public var effectiveAssignments: [BulkProtectAssignment] {
        tree.order
            .filter { selected.contains($0) && assignments[$0].approach != .skip }
            .map { assignments[$0] }
    }

    private func files(of row: Row) -> [Int] {
        switch row {
        case .file(let file): return [file]
        case .directory(let id): return tree.directories[id].descendants
        }
    }

    // MARK: rows

    private mutating func clearFilter() {
        let row = current?.row
        query = LineEditor()
        refresh(keeping: nil)
        // Back in the tree, the cursor goes to the deepest row holding the
        // file it was on, without opening folders the user left closed.
        if case .file(let file)? = row,
           let index = rows.lastIndex(where: { files(of: $0.row).contains(file) }) {
            cursor = index
        }
    }

    private mutating func refresh(keeping row: Row?) {
        rows = computeRows()
        if let row, let index = rows.firstIndex(where: { $0.row == row }) {
            cursor = index
        } else {
            cursor = min(cursor, max(0, rows.count - 1))
        }
    }

    private func computeRows() -> [VisibleRow] {
        let filter = self.filter
        if !filter.isEmpty {
            return tree.order.filter { filter.matches(paths(of: $0)) }.map {
                VisibleRow(row: .file($0), depth: 0, label: tree.displayPaths[$0])
            }
        }
        var rows: [VisibleRow] = []
        var pending: [(id: Int, depth: Int, next: Int)] = [(tree.top, 0, 0)]
        while var frame = pending.popLast() {
            let list = tree.entries[frame.id]
            guard frame.next < list.count else { continue }
            let item = list[frame.next]
            frame.next += 1
            pending.append(frame)
            switch item.entry {
            case .file(let file):
                rows.append(VisibleRow(row: .file(file), depth: frame.depth, label: item.label))
            case .directory(let id):
                rows.append(VisibleRow(row: .directory(id), depth: frame.depth, label: item.label))
                if expanded.contains(id) { pending.append((id, frame.depth + 1, 0)) }
            }
        }
        return rows
    }

    private func paths(of file: Int) -> [String] {
        [tree.displayPaths[file]] + assignments[file].file.aliasPaths.map {
            Self.displayPath($0, home: homeDirectory)
        }
    }

    private static func initialExpansion(_ tree: SetupSelectTree, budget: Int) -> Set<Int> {
        var expanded = Set<Int>()
        var shown = tree.entries[tree.top].count
        var closed = tree.entries[tree.top].compactMap { entry -> Int? in
            if case .directory(let id) = entry.entry { return id }
            return nil
        }
        while true {
            let fitting = closed.filter { shown + tree.entries[$0].count <= budget }
            guard let next = fitting.min(by: {
                (tree.entries[$0].count, tree.directories[$0].path)
                    < (tree.entries[$1].count, tree.directories[$1].path)
            }) else { break }
            expanded.insert(next)
            shown += tree.entries[next].count
            closed.removeAll { $0 == next }
            closed += tree.entries[next].compactMap { entry -> Int? in
                if case .directory(let id) = entry.entry { return id }
                return nil
            }
        }
        return expanded
    }

    // MARK: render

    public func render(color: Bool, width: Int, height: Int = 24) -> String {
        let clamp = max(20, width)
        var lines: [String] = []
        lines.append(TerminalStyle.paint(
            TerminalStyle.truncate("Select files to protect", to: clamp),
            TerminalStyle.Code.bold, color: color))
        let keys = mode == .filtering
            ? ["type to filter", "↑/↓ move", "tab pick and next", "enter back to the list", "esc clear filter"]
            : ["space pick", "tab pick and next", "/ filter", "a all", "n none", "i invert (rows shown)",
               "→/← open/close folder", "p approach", "d dest", "enter review plan", "q quit"]
        // The keys wrap rather than truncate: a key nobody can see is a key
        // nobody uses.
        var keyLines: [String] = []
        for key in keys {
            if let last = keyLines.last, last.count + 3 + key.count <= clamp {
                keyLines[keyLines.count - 1] = last + " · " + key
            } else {
                keyLines.append(key)
            }
        }
        for line in keyLines {
            lines.append(TerminalStyle.paint(
                TerminalStyle.truncate(line, to: clamp), TerminalStyle.Code.dim, color: color))
        }

        // A bounded window around the cursor so hundreds of rows never
        // overflow one redraw block: the rest of the block is the title, the
        // key lines, the header, both "more" markers, the cursor row's
        // details, the status, the filter and the footer.
        let windowSize = max(1, height - 8 - keyLines.count)
        let start = max(0, min(cursor - windowSize / 2, rows.count - windowSize))
        let end = min(rows.count, start + windowSize)
        if start > 0 {
            lines.append(TerminalStyle.paint(
                TerminalStyle.truncate("  … \(start) more above", to: clamp),
                TerminalStyle.Code.dim, color: color))
        }
        let typeWidth = clamp >= 100 ? 16 : 10
        let approachWidth = clamp >= 100 ? 24 : 12
        let pathWidth = max(8, clamp - 6 - typeWidth - approachWidth - 4)
        func cell(_ text: String, _ width: Int) -> String {
            TerminalStyle.truncate(ReviewDisplay.sanitized(text), to: width)
                .padding(toLength: width, withPad: " ", startingAt: 0)
        }
        lines.append(TerminalStyle.truncate(
            "      " + cell("FILE", pathWidth) + "  " + cell("TYPE", typeWidth)
                + "  " + cell("PROTECTION", approachWidth), to: clamp))
        if rows.isEmpty {
            lines.append(TerminalStyle.paint(
                TerminalStyle.truncate("  no files match the filter; edit it, or esc to clear it", to: clamp),
                TerminalStyle.Code.yellow, color: color))
        }
        for index in start..<end {
            let row = rows[index]
            let onCursor = index == cursor
            let marker = onCursor ? "> " : "  "
            let indent = String(repeating: "  ", count: row.depth)
            let raw: String
            var picked = false
            var skipped = false
            switch row.row {
            case .file(let file):
                let assignment = assignments[file]
                picked = selected.contains(file)
                skipped = assignment.approach == .skip
                raw = "\(marker)\(picked ? "[x]" : "[ ]") "
                    + cell(indent + "  " + row.label, pathWidth)
                    + "  " + cell(assignment.file.kind.displayLabel, typeWidth)
                    + "  " + cell(assignment.approach.displayToken, approachWidth)
            case .directory(let id):
                let files = tree.directories[id].descendants
                let count = files.filter(selected.contains).count
                picked = count > 0
                let box = count == 0 ? "[ ]" : count == files.count ? "[x]" : "[-]"
                let fold = expanded.contains(id) ? "▾ " : "▸ "
                raw = "\(marker)\(box) " + cell(indent + fold + row.label, pathWidth)
                    + "  " + cell("\(files.count) files", typeWidth)
                    + "  " + cell(count > 0 ? "\(count) selected" : "", approachWidth)
            }
            var line = TerminalStyle.truncate(raw, to: clamp)
            if onCursor {
                line = TerminalStyle.paint(line, TerminalStyle.Code.bold, color: color)
            } else if skipped {
                line = TerminalStyle.paint(line, TerminalStyle.Code.dim, color: color)
            } else if picked {
                line = TerminalStyle.paint(line, TerminalStyle.Code.green, color: color)
            }
            lines.append(line)
        }
        if end < rows.count {
            lines.append(TerminalStyle.paint(
                TerminalStyle.truncate("  … \(rows.count - end) more below", to: clamp),
                TerminalStyle.Code.dim, color: color))
        }
        if let current {
            lines.append(TerminalStyle.truncate(
                ReviewDisplay.sanitized(annotation(current.row)), to: clamp))
        }
        if let status {
            lines.append(TerminalStyle.truncate(ReviewDisplay.sanitized(status), to: clamp))
        }
        if mode == .list, !query.text.isEmpty {
            lines.append(TerminalStyle.paint(
                TerminalStyle.truncate(
                    ReviewDisplay.sanitized("filter: \(query.text) · \(rows.count) of "
                        + "\(assignments.count) files · / edit · esc clear"), to: clamp),
                TerminalStyle.Code.cyan, color: color))
        }
        var footer = "\(selected.count) of \(assignments.count) selected"
        let skippedCount = selected.filter { assignments[$0].approach == .skip }.count
        if skippedCount > 0 {
            footer += " (\(skippedCount) set to skip, so left as they are)"
        }
        if !filter.isEmpty {
            let shownSelected = rows.filter {
                if case .file(let file) = $0.row { return selected.contains(file) }
                return false
            }.count
            footer += " · \(shownSelected) of the \(rows.count) shown"
        }
        lines.append(TerminalStyle.paint(
            TerminalStyle.truncate(footer, to: clamp), TerminalStyle.Code.dim, color: color))
        return lines.joined(separator: "\n")
    }

    /// The two lines drawn under the picker while the filter is being typed:
    /// how matching works, then the query with its cursor column.
    public func renderFilterPrompt(color: Bool, width: Int) -> (lines: [String], cursorColumn: Int) {
        let clamp = max(20, width)
        let hint = "every word must appear in the path, any case · !word excludes · "
            + "word$ ends the path · * any characters"
        let first = TerminalStyle.paint(
            TerminalStyle.truncate(hint, to: clamp - 1), TerminalStyle.Code.dim, color: color)
        let edited = query.render(prompt: "/ ", width: clamp)
        return ([first, edited.line], edited.cursorColumn)
    }

    private func annotation(_ row: Row) -> String {
        switch row {
        case .file(let file):
            let assignment = assignments[file]
            var notes = [tree.displayPaths[file], assignment.file.kind.rawValue,
                         assignment.approach.displayToken]
            if let destination = assignment.destination { notes.append(destination) }
            if assignment.file.keychainFallback { notes.append("keychain fallback") }
            if !assignment.file.aliasPaths.isEmpty {
                notes.append("\(assignment.file.aliasPaths.count) hardlink(s)")
            }
            return notes.joined(separator: " · ")
        case .directory(let id):
            let files = tree.directories[id].descendants
            let count = files.filter(selected.contains).count
            return "\(tree.directories[id].path)/ · \(files.count) files, \(count) selected · "
                + "space picks or unpicks them all · \(expanded.contains(id) ? "← closes" : "→ opens")"
        }
    }

    static func displayPath(_ path: String, home homeDirectory: String) -> String {
        let home = homeDirectory.hasSuffix("/")
            ? String(homeDirectory.dropLast()) : homeDirectory
        if path == home { return "~" }
        if path.hasPrefix(home + "/") { return "~" + path.dropFirst(home.count) }
        return path
    }
}

/// The picker's text prompts (`p` approach, `d` destination), edited in place
/// under the table with `LineEditor`. A prompt stays open until its input
/// does something: an unknown approach or a malformed destination keeps the
/// text for editing with a message saying why. Esc leaves without a change.
public struct SetupSelectPrompt: Equatable {
    public enum Kind: Equatable, Sendable { case approach, destination }
    public enum Step: Equatable, Sendable { case stay, close }

    public let kind: Kind
    public private(set) var editor = LineEditor()
    public private(set) var message: String?

    public init(kind: Kind) {
        self.kind = kind
    }

    public static let approachTokens = "per-var, whole-file, ssh, creds-aws, preset:<name>, "
        + "env-token:<VAR>, skip"

    public mutating func handle(_ key: LineEditKey, model: inout SetupSelectModel) -> Step {
        let before = editor.text
        switch editor.apply(key) {
        case .editing:
            if editor.text != before { message = nil }
            return .stay
        case .cancelled:
            model.status = nil
            return .close
        case .submitted(let raw):
            return submit(raw.trimmingCharacters(in: .whitespaces), model: &model)
        }
    }

    private mutating func submit(_ token: String, model: inout SetupSelectModel) -> Step {
        let shown = ReviewDisplay.sanitized(token)
        switch kind {
        case .approach:
            guard !token.isEmpty else { return .close }
            guard let approach = BulkProtectApproach.parse(token) else {
                message = "unknown approach \(shown); use one of \(Self.approachTokens)"
                return .stay
            }
            model.setApproach(approach)
            model.status = "\(approach.displayToken) set on \(model.selected.count) selected file(s)"
            return .close
        case .destination:
            if token.isEmpty {
                model.setDestination(nil)
                model.status = "default store set on \(model.selected.count) selected file(s)"
                return .close
            }
            guard Self.isUsableDestination(token) else {
                message = "\(shown) is not a destination; use csec://STORE or op://VAULT[/ITEM]"
                return .stay
            }
            model.setDestination(token)
            model.status = "\(shown) set on \(model.selected.count) selected file(s)"
            return .close
        }
    }

    private static func isUsableDestination(_ token: String) -> Bool {
        if token.hasPrefix("csec://") {
            return (try? NativeStoreName(String(token.dropFirst("csec://".count)))) != nil
        }
        return token.hasPrefix("op://") && token.count > "op://".count
    }

    /// The two lines drawn under the picker while the prompt is open: a hint
    /// or message line, then the prompt with the text being edited. The
    /// cursor column belongs to the second line.
    public func render(model: SetupSelectModel, color: Bool, width: Int)
        -> (lines: [String], cursorColumn: Int)
    {
        let clamp = max(20, width)
        let selectedCount = model.selected.count
        let label: String
        var hint: String
        switch kind {
        case .approach:
            label = "approach for \(selectedCount) selected: "
            hint = Self.approachTokens
        case .destination:
            label = "destination for \(selectedCount) selected: "
            hint = "csec://STORE or op://VAULT[/ITEM]; empty for the default store"
        }
        hint += " · esc back · ctrl-a/ctrl-e start/end · ctrl-u/ctrl-k clear"
        let first: String
        if let message {
            first = TerminalStyle.paint(
                TerminalStyle.truncate(ReviewDisplay.sanitized(message), to: clamp - 1),
                TerminalStyle.Code.yellow, color: color)
        } else {
            first = TerminalStyle.paint(
                TerminalStyle.truncate(ReviewDisplay.sanitized(hint), to: clamp - 1),
                TerminalStyle.Code.dim, color: color)
        }
        let edited = editor.render(prompt: label, width: clamp)
        return ([first, edited.line], edited.cursorColumn)
    }
}
