#if canImport(AppKit)
  import AppKit
  import ConvenientSecurity
  import Foundation

  /// `csec backup`'s recovery-key field: the line under it counts what a
  /// paste brought, the field shows a whole key on one line, and the
  /// launcher's Edit menu gives it Command-V. The window is never ordered
  /// onscreen and the process is never activated; nothing here reads or
  /// writes a pasteboard.
  @MainActor
  func recoveryKeyEntryTests() async {
    let kit: String
    do {
      kit = try BackupRecoveryKit.generate().formatted
    } catch {
      check(false, "recovery key entry: a kit to type (\(error))")
      return
    }
    let total = BackupRecoveryKit.groupCount
    let groups = kit.split(separator: "-").dropFirst().map(String.init)
    check(total == 14 && groups.count == total, "recovery key entry: a kit is CSEC and 14 groups")

    func progress(_ text: String) -> BackupRecoveryKit.EntryProgress {
      BackupRecoveryKit.progress(of: text)
    }
    check(progress("") == .empty, "recovery key entry: an empty field has no progress")
    check(progress("  ") == .empty, "recovery key entry: spaces alone have no progress")
    for start in ["C", "cs", "CSE", "CSEC", "CSEC-"] {
      check(
        progress(start) == .partial(groups: 0, characters: 0),
        "recovery key entry: the prefix \(start) counts no group (got \(progress(start)))")
    }
    let nine = "CSEC-" + groups.prefix(9).joined(separator: "-")
    check(progress(nine) == .partial(groups: 9, characters: 0), "recovery key entry: nine groups count as nine")
    check(
      progress(nine + "-" + groups[9].prefix(2)) == .partial(groups: 9, characters: 2),
      "recovery key entry: two characters into the tenth group")
    check(
      progress(groups.prefix(3).joined()) == .partial(groups: 3, characters: 0),
      "recovery key entry: groups typed without the prefix or dashes count")
    check(progress(kit) == .complete, "recovery key entry: a whole kit checks out")
    check(progress(kit.lowercased()) == .complete, "recovery key entry: a lower-case kit checks out")
    check(progress(String(kit.dropFirst(5))) == .complete, "recovery key entry: a kit without CSEC checks out")
    check(progress(" \(kit)\n") == .complete, "recovery key entry: a paste with surrounding space checks out")

    let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    var changed = Array(kit)
    let last = changed.count - 1
    changed[last] = alphabet[(alphabet.firstIndex(of: changed[last])! + 1) % alphabet.count]
    check(progress(String(changed)) == .mistyped, "recovery key entry: a changed check character is mistyped")
    check(progress(kit + "-" + groups[0]) == .tooLong, "recovery key entry: an extra group is too long")
    check(progress(kit + "7") == .tooLong, "recovery key entry: an extra character is too long")
    check(progress("CSEC-" + "UUUU") == .unexpectedCharacter, "recovery key entry: U is no kit's character")
    check(progress(nine + "!") == .unexpectedCharacter, "recovery key entry: punctuation is no kit's character")

    let states: [BackupRecoveryKit.EntryProgress] = [
      .empty, .partial(groups: 9, characters: 0), .partial(groups: 13, characters: 1),
      .partial(groups: 2, characters: 3), .complete, .mistyped, .tooLong, .unexpectedCharacter,
    ]
    let texts = states.map(RecoveryKeyEntryView.statusText)
    check(Set(texts).count == texts.count, "recovery key entry: every state reads differently")
    check(texts[1] == "9 of 14 groups.", "recovery key entry: whole groups read as a count (got \(texts[1]))")
    check(
      texts[2] == "13 of 14 groups, and 1 character of the next.",
      "recovery key entry: a part group is counted too (got \(texts[2]))")
    check(texts[4] == "All 14 groups, and the key checks out.", "recovery key entry: a whole key says so")

    let entry = RecoveryKeyEntryView()
    let field = entry.field
    check(
      field.usesSingleLineMode && field.cell?.wraps == false && field.cell?.isScrollable == true,
      "recovery key entry: the field is one scrolling line")
    check(entry.status.stringValue == RecoveryKeyEntryView.statusText(.empty), "recovery key entry: an empty field says what goes in")

    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: RecoveryKeyEntryView.fieldWidth + 40, height: 80),
      styleMask: [.titled], backing: .buffered, defer: false)
    window.isReleasedWhenClosed = false
    window.contentView?.addSubview(entry)
    defer { window.close() }
    check(window.makeFirstResponder(field), "recovery key entry: the field takes the focus")
    guard let editor = field.currentEditor() as? NSTextView,
      let layout = editor.layoutManager, let container = editor.textContainer,
      let clip = editor.superview
    else {
      check(false, "recovery key entry: the field has a field editor")
      return
    }
    // A paste goes through the field editor as typing does, so this is the
    // path Command-V and the context menu's Paste both take.
    editor.insertText(kit, replacementRange: editor.selectedRange())
    check(entry.typed == kit, "recovery key entry: the field holds the inserted key")
    check(
      entry.status.stringValue == RecoveryKeyEntryView.statusText(.complete),
      "recovery key entry: the line updates as the key goes in (got \(entry.status.stringValue))")
    layout.ensureLayout(for: container)
    let used = layout.usedRect(for: container)
    let lineHeight = layout.defaultLineHeight(for: field.font ?? NSFont.systemFont(ofSize: 13))
    check(
      used.height <= lineHeight + 0.5,
      "recovery key entry: a whole key stays on one line (used \(used), line \(lineHeight))")
    check(
      used.width <= clip.bounds.width,
      "recovery key entry: every dot of a whole key fits in the field (used \(used.width) of \(clip.bounds.width))")
    check(
      groups.allSatisfy { !entry.status.stringValue.contains($0) },
      "recovery key entry: the line repeats no group of the key")

    editor.insertText("U", replacementRange: editor.selectedRange())
    check(
      entry.status.stringValue == RecoveryKeyEntryView.statusText(.unexpectedCharacter),
      "recovery key entry: a stray character is flagged as it goes in")
    entry.clear()
    check(
      entry.typed.isEmpty && entry.status.stringValue == RecoveryKeyEntryView.statusText(.empty),
      "recovery key entry: clearing empties the field and its line")

    let menu = StandardEditMenu.make()
    let items = menu.items.compactMap(\.submenu).flatMap(\.items)
    func item(_ key: String) -> NSMenuItem? { items.first { $0.keyEquivalent == key } }
    let expected: [(String, Selector)] = [
      ("x", #selector(NSText.cut(_:))), ("c", #selector(NSText.copy(_:))),
      ("v", #selector(NSText.paste(_:))), ("a", #selector(NSText.selectAll(_:))),
    ]
    for (key, action) in expected {
      let found = item(key)
      check(
        found?.action == action && found?.keyEquivalentModifierMask == .command && found?.target == nil,
        "recovery key entry: Command-\(key.uppercased()) sends \(action) to the focused field")
    }

    let application = NSApplication.shared
    let previous = application.mainMenu
    defer { application.mainMenu = previous }
    application.mainMenu = nil
    StandardEditMenu.installIfNeeded(in: application)
    check(
      application.mainMenu?.items.compactMap(\.submenu).flatMap(\.items)
        .contains { $0.keyEquivalent == "v" && $0.action == #selector(NSText.paste(_:)) } == true,
      "recovery key entry: a process with no menu gets Paste on Command-V")
    let own = NSMenu(title: "Own")
    application.mainMenu = own
    StandardEditMenu.installIfNeeded(in: application)
    check(application.mainMenu === own, "recovery key entry: an existing main menu is left alone")
  }
#endif
