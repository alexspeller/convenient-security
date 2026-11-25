#if canImport(AppKit)
  import AppKit
  import Foundation

  /// The masked field `csec backup` takes a recovery key in, at setup's
  /// paste-back and at restore, with a line under it saying how much of a
  /// key it holds.
  ///
  /// The field is single-line and scrolls sideways. A text field built in
  /// code wraps by default, so the 74 characters of a pasted key wrapped
  /// their last dot onto a second line, and the field scrolled down to it
  /// and showed a single dot. It is wide enough for every dot of a whole
  /// key, but 74 identical dots still can't be counted, so the line below
  /// counts the groups (`BackupRecoveryKit.progress(of:)`) and says when the
  /// key checks out. Neither shows any character of the key.
  public final class RecoveryKeyEntryView: NSView, NSTextFieldDelegate {
    public static let fieldWidth: CGFloat = 640

    public let field: NSSecureTextField
    public let status: NSTextField

    public init() {
      let width = Self.fieldWidth
      field = NSSecureTextField(frame: NSRect(x: 0, y: 22, width: width, height: 24))
      status = NSTextField(labelWithString: "")
      super.init(frame: NSRect(x: 0, y: 0, width: width, height: 46))
      field.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
      field.placeholderString = "CSEC-…"
      field.usesSingleLineMode = true
      field.cell?.wraps = false
      field.cell?.isScrollable = true
      field.delegate = self
      status.frame = NSRect(x: 0, y: 0, width: width, height: 16)
      status.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
      addSubview(field)
      addSubview(status)
      refresh()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    public var typed: String { field.stringValue }

    public func clear() {
      field.stringValue = ""
      refresh()
    }

    public func controlTextDidChange(_ notification: Notification) {
      refresh()
    }

    private func refresh() {
      let progress = BackupRecoveryKit.progress(of: field.stringValue)
      status.stringValue = Self.statusText(progress)
      switch progress {
      case .complete: status.textColor = .systemGreen
      case .mistyped, .tooLong, .unexpectedCharacter: status.textColor = .systemRed
      case .empty, .partial: status.textColor = .secondaryLabelColor
      }
    }

    public static func statusText(_ progress: BackupRecoveryKit.EntryProgress) -> String {
      let total = BackupRecoveryKit.groupCount
      switch progress {
      case .empty:
        return "CSEC, then \(total) groups of four characters."
      case .partial(let groups, let characters):
        let more = characters == 0
          ? "" : ", and \(characters) character\(characters == 1 ? "" : "s") of the next"
        return "\(groups) of \(total) groups\(more)."
      case .complete:
        return "All \(total) groups, and the key checks out."
      case .mistyped:
        return "All \(total) groups, but the key doesn't check out: a character is mistyped."
      case .tooLong:
        return "More than \(total) groups: there is extra text in the field."
      case .unexpectedCharacter:
        return "The field has a character no recovery key has."
      }
    }
  }

  /// Cut, Copy, Paste and Select All, with their keyboard shortcuts, for a
  /// process that has no menu bar of its own.
  ///
  /// AppKit gives a text field Command-V through the main menu's Paste item,
  /// not through the field's own key handling. The `csec` launcher draws its
  /// windows with no main menu, so Command-V did nothing in the recovery-key
  /// field while the context menu's Paste worked, and Command-C did nothing
  /// in the window that shows the key or in `csec edit`. The items have no
  /// target and reach the key window's first responder, so a secure field's
  /// own refusal to copy or cut still stands.
  @MainActor
  public enum StandardEditMenu {
    public static func installIfNeeded(in application: NSApplication) {
      guard application.mainMenu == nil else { return }
      application.mainMenu = make()
    }

    public static func make() -> NSMenu {
      let edit = NSMenu(title: "Edit")
      edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
      edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
      edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
      edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
      let editItem = NSMenuItem(title: "Edit", action: nil, keyEquivalent: "")
      editItem.submenu = edit
      let main = NSMenu(title: "Main")
      main.addItem(editItem)
      return main
    }
  }
#endif
