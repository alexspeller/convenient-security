#if canImport(AppKit)
  import AppKit
  import Foundation

  /// A command an approval panel shows whole: the sudo panel's submitted
  /// command, the access panel's full command line and the automation
  /// layout's exact command. The panel's warning asks the human to verify every
  /// argument, so the command is never cut down to a fixed peephole: the text
  /// is as tall as its content and scrolls only in what the screen's visible
  /// height leaves once the panel would no longer fit (`ReviewScreenFit`,
  /// csec-0.58). When it does scroll, nothing about that is left to an overlay
  /// scroller that shows only while scrolling: the scroller stays drawn and
  /// `overflowCue` says under the text that the command continues.
  /// Selectable with the mouse, as the label it replaced was, but outside
  /// the key view loop: Tab from the panel's keyboard sink reaches its
  /// controls, never the text (`PromptKeyboardSink`). The window's
  /// recalculated loop asks `acceptsFirstResponder`, so the text takes focus
  /// only from the click that starts a selection.
  private final class CommandTextView: NSTextView {
    override var canBecomeKeyView: Bool { false }
    override var acceptsFirstResponder: Bool {
      switch NSApplication.shared.currentEvent?.type {
      case .leftMouseDown, .rightMouseDown, .otherMouseDown: return true
      default: return false
      }
    }
  }

  @MainActor
  public final class ReviewCommandText: ReviewScreenFitting {
    /// The scrolling text, to place where the panel shows the command.
    let scrollView: NSScrollView
    /// The line saying the command continues past what is shown, hidden
    /// unless it does; the panel places it under `scrollView`.
    let overflowCue: NSTextField

    public static let overflowCueText =
      "This command is longer than the panel can show. Scroll it to read every argument."
    /// The cue's accessibility identifier, for `cs-selftest`.
    public static let overflowCueIdentifier = NSUserInterfaceItemIdentifier("csec.command-overflow-cue")

    private let textView: NSTextView
    let heightConstraint: NSLayoutConstraint
    private let width: CGFloat

    /// Whether the command is taller than the height it was given at the last
    /// `ReviewScreenFit.fit`.
    var scrolls: Bool { !overflowCue.isHidden }

    init(
      _ command: String, font: NSFont, width: CGFloat, inset: NSSize, borderType: NSBorderType
    ) {
      self.width = width
      // TextKit 1, laid out whole: `naturalHeight` measures the command
      // through its layout manager, which a TextKit 2 view only fakes and a
      // non-contiguous layout leaves partly unmeasured.
      let text = CommandTextView(usingTextLayoutManager: false)
      text.layoutManager?.allowsNonContiguousLayout = false
      text.string = command
      text.font = font
      text.textColor = .labelColor
      text.drawsBackground = false
      text.isEditable = false
      text.isSelectable = true
      text.isRichText = false
      text.textContainerInset = inset
      text.textContainer?.lineFragmentPadding = 0
      text.textContainer?.widthTracksTextView = true
      text.isHorizontallyResizable = false
      text.isVerticallyResizable = true
      text.minSize = .zero
      text.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: .greatestFiniteMagnitude)
      text.autoresizingMask = [.width]
      textView = text

      let scroll = NSScrollView()
      scroll.borderType = borderType
      scroll.drawsBackground = false
      scroll.hasVerticalScroller = true
      scroll.hasHorizontalScroller = false
      scroll.documentView = text
      scroll.translatesAutoresizingMaskIntoConstraints = false
      let height = scroll.heightAnchor.constraint(equalToConstant: 0)
      NSLayoutConstraint.activate([scroll.widthAnchor.constraint(equalToConstant: width), height])
      heightConstraint = height
      scrollView = scroll

      let cue = NSTextField(wrappingLabelWithString: Self.overflowCueText)
      cue.font = .systemFont(ofSize: 12, weight: .medium)
      cue.textColor = .systemOrange
      cue.maximumNumberOfLines = 0
      cue.preferredMaxLayoutWidth = width
      cue.identifier = Self.overflowCueIdentifier
      overflowCue = cue

      setScrolling(false)
    }

    func setScrolling(_ scrolling: Bool) {
      overflowCue.isHidden = !scrolling
      if scrolling {
        ReviewScreenFit.keepScrollerVisible(scrollView)
      } else {
        scrollView.scrollerStyle = NSScroller.preferredScrollerStyle
        scrollView.autohidesScrollers = true
      }
      heightConstraint.constant = naturalHeight()
    }

    /// The scroll view's height that shows the whole command at the width
    /// left beside the scroller the current style draws. Measured in a
    /// TextKit 1 stack of its own, laid out exactly as the text view lays out
    /// its text, since the view's own layout is torn down while it is resized.
    private func naturalHeight() -> CGFloat {
      let verticalScroller: AnyClass? = scrolls ? NSScroller.self : nil
      let clip = NSScrollView.contentSize(
        forFrameSize: NSSize(width: width, height: 10_000),
        horizontalScrollerClass: nil, verticalScrollerClass: verticalScroller,
        borderType: scrollView.borderType, controlSize: .regular,
        scrollerStyle: scrollView.scrollerStyle)
      let inset = textView.textContainerInset
      let storage = NSTextStorage(
        string: textView.string, attributes: [.font: textView.font ?? NSFont.systemFont(ofSize: 0)])
      let layout = NSLayoutManager()
      storage.addLayoutManager(layout)
      let container = NSTextContainer(
        size: NSSize(width: clip.width - inset.width * 2, height: .greatestFiniteMagnitude))
      container.lineFragmentPadding = 0
      layout.addTextContainer(container)
      layout.ensureLayout(for: container)
      let used = ceil(layout.usedRect(for: container).height) + inset.height * 2
      return NSScrollView.frameSize(
        forContentSize: NSSize(width: clip.width, height: used),
        horizontalScrollerClass: nil, verticalScrollerClass: verticalScroller,
        borderType: scrollView.borderType, controlSize: .regular,
        scrollerStyle: scrollView.scrollerStyle
      ).height
    }
  }
#endif
