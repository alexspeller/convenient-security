#if canImport(AppKit)
  import AppKit
  import Foundation

  /// A view an approval panel shows whole unless the panel would then pass the
  /// screen: a command (`ReviewCommandText`) or a list of secrets or restored
  /// approvals (`ReviewFittedList`). It scrolls only in what the screen leaves,
  /// and when it does its scroller is always drawn and `overflowCue` says
  /// what continues, so nothing the human approves sits out of sight behind a
  /// scroller that shows only while scrolling (csec-0.58, csec-lz39).
  @MainActor
  protocol ReviewScreenFitting: AnyObject {
    var scrollView: NSScrollView { get }
    /// The line under the view saying it holds more than it shows; hidden
    /// unless it scrolls.
    var overflowCue: NSTextField { get }
    /// The scroll view's height.
    var heightConstraint: NSLayoutConstraint { get }
    /// Whether the view is set up to scroll: scroller drawn, cue shown.
    var scrolls: Bool { get }
    /// Sets the view up to scroll or to show everything, and its height to
    /// all of its content at the width that leaves.
    func setScrolling(_ scrolling: Bool)
  }

  /// Fits every `ReviewScreenFitting` view of a panel to the screen together.
  /// Each one panel's views are fitted in one pass, since a list fitted alone
  /// could take the height an opened command then needs, or the reverse, and
  /// the panel would run past the bottom of the screen with its buttons.
  @MainActor
  enum ReviewScreenFit {
    /// Sizes `views` for `window`, whose content view already holds them: each
    /// as tall as its content, unless the window would then be taller than the
    /// visible area of its screen, when the ones that do not fit scroll in what
    /// that leaves (`ReviewDisclosureFit.heights`). Hidden views (a closed
    /// disclosure) show nothing and take no part. It sizes only the views and
    /// their cues; the panel then fits the window to its content as it always
    /// does. With no screen, everything shows. A view that scrolled before
    /// and still does keeps its place in what it holds, so a re-fit after an
    /// unrelated change does not move the text being read; one that has just
    /// started scrolling shows its beginning.
    static func fit(_ views: [any ReviewScreenFitting], in window: NSWindow) {
      let before = views.map { ($0.scrolls, $0.scrollView.contentView.bounds.origin) }
      for view in views { view.setScrolling(false) }
      let shown = views.filter { !$0.scrollView.isHiddenOrHasHiddenAncestor }
      guard !shown.isEmpty, let visibleHeight = (window.screen ?? NSScreen.main)?.visibleFrame.height,
        fittingFrameHeight(of: window) > visibleHeight + 0.5
      else { return }

      // Setting a view to scroll draws its cue and narrows what it holds,
      // which makes the panel taller again, so the share is worked out again
      // until no further view has to start scrolling. Each pass starts at
      // least one, so this ends.
      var heights: [CGFloat] = shown.map(\.heightConstraint.constant)
      for _ in 0...shown.count {
        let contents = shown.map(\.heightConstraint.constant)
        heights = ReviewDisclosureFit.heights(
          contentHeights: contents,
          otherHeight: fittingFrameHeight(of: window) - contents.reduce(0, +),
          visibleHeight: visibleHeight
        )
        let starting = shown.indices.filter { !shown[$0].scrolls && heights[$0] < contents[$0] - 0.5 }
        if starting.isEmpty { break }
        for index in starting { shown[index].setScrolling(true) }
      }
      for (view, height) in zip(shown, heights) {
        // One that turned out to have room at the narrower width shows all of
        // it: its cue would otherwise say it continues.
        if view.scrolls, height >= view.heightConstraint.constant - 0.5 {
          view.setScrolling(false)
        } else {
          view.heightConstraint.constant = height
        }
      }

      for (view, (scrolled, origin)) in zip(views, before) where view.scrolls {
        view.scrollView.layoutSubtreeIfNeeded()
        let clip = view.scrollView.contentView
        let documentHeight = view.scrollView.documentView?.frame.height ?? 0
        let y = scrolled ? min(max(0, origin.y), max(0, documentHeight - clip.bounds.height)) : 0
        clip.scroll(to: NSPoint(x: 0, y: y))
        view.scrollView.reflectScrolledClipView(clip)
      }
    }

    /// The height `window`'s frame takes once fitted to its content. Measured
    /// in a window already sized to that content, as the panel lays it out,
    /// since wrapped labels measure differently in a window too small for
    /// them; the frame is put back afterwards so a disclosure can still keep
    /// the panel's top edge where it was.
    static func fittingFrameHeight(of window: NSWindow) -> CGFloat {
      guard let content = window.contentView else { return window.frame.height }
      let saved = window.frame
      window.setContentSize(content.fittingSize)
      content.layoutSubtreeIfNeeded()
      let height = window.frameRect(forContentRect: NSRect(origin: .zero, size: content.fittingSize)).height
      window.setFrame(saved, display: false)
      return height
    }

    /// A scroller that cannot fade away: legacy style, always drawn, for any
    /// review view that holds more than it shows.
    static func keepScrollerVisible(_ scroll: NSScrollView) {
      scroll.hasVerticalScroller = true
      scroll.scrollerStyle = .legacy
      scroll.autohidesScrollers = false
    }
  }

  /// A list an approval panel shows whole unless the screen is too short for
  /// it: the secrets a release or an automation job gets, the approvals a
  /// restore reopens, the SSH request's details. Its rows have fixed widths
  /// (the secret tree, cards with borders), so a scroller drawn beside them
  /// would cover their right edge: when the list scrolls, `build` draws it
  /// again at the width the scroller leaves.
  @MainActor
  public final class ReviewFittedList: ReviewScreenFitting {
    /// The scrolling list, to place where the panel shows it.
    let scrollView: NSScrollView
    let overflowCue: NSTextField
    let heightConstraint: NSLayoutConstraint
    /// The list and its cue, one under the other: what the panel places.
    let view: NSView

    /// The scroll view's and the cue's accessibility identifiers, for
    /// `cs-selftest`.
    public static let scrollIdentifier = NSUserInterfaceItemIdentifier("csec.fitted-list")
    public static let overflowCueIdentifier = NSUserInterfaceItemIdentifier("csec.list-overflow-cue")

    private let width: CGFloat
    private let build: (CGFloat) -> NSView
    private let whole: NSView
    private var narrowed: NSView?

    var scrolls: Bool { !overflowCue.isHidden }

    /// A list `width` wide that `build` draws at the width it is given, under
    /// which `cue` says, when the list scrolls, that it continues.
    init(width: CGFloat, cue: String, build: @escaping (CGFloat) -> NSView) {
      self.width = width
      self.build = build
      whole = Self.document(build(width), width: width)

      let scroll = NSScrollView()
      scroll.identifier = Self.scrollIdentifier
      scroll.borderType = .noBorder
      scroll.drawsBackground = false
      scroll.hasHorizontalScroller = false
      scroll.translatesAutoresizingMaskIntoConstraints = false
      heightConstraint = scroll.heightAnchor.constraint(equalToConstant: 0)
      NSLayoutConstraint.activate([scroll.widthAnchor.constraint(equalToConstant: width), heightConstraint])
      scrollView = scroll

      let label = NSTextField(wrappingLabelWithString: cue)
      label.font = .systemFont(ofSize: 12, weight: .medium)
      label.textColor = .systemOrange
      label.maximumNumberOfLines = 0
      label.preferredMaxLayoutWidth = width
      label.identifier = Self.overflowCueIdentifier
      overflowCue = label

      let stack = NSStackView(views: [scroll, label])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 6
      stack.widthAnchor.constraint(equalToConstant: width).isActive = true
      view = stack

      setScrolling(false)
    }

    func setScrolling(_ scrolling: Bool) {
      overflowCue.isHidden = !scrolling
      let document: NSView
      if scrolling {
        ReviewScreenFit.keepScrollerVisible(scrollView)
        let narrowedWidth = width - NSScroller.scrollerWidth(for: .regular, scrollerStyle: .legacy)
        document = narrowed ?? Self.document(build(narrowedWidth), width: narrowedWidth)
        narrowed = document
      } else {
        // Nothing to scroll, so no scroller: the list has the whole width.
        scrollView.hasVerticalScroller = false
        document = whole
      }
      if scrollView.documentView !== document {
        scrollView.documentView = document
        NSLayoutConstraint.activate([
          document.leadingAnchor.constraint(equalTo: scrollView.contentView.leadingAnchor),
          document.topAnchor.constraint(equalTo: scrollView.contentView.topAnchor),
        ])
      }
      document.layoutSubtreeIfNeeded()
      heightConstraint.constant = ceil(document.fittingSize.height)
    }

    /// `content` in a flipped view of its own width, so the list starts at its
    /// top and scrolls down from there.
    private static func document(_ content: NSView, width: CGFloat) -> NSView {
      let document = FlippedDocument()
      document.translatesAutoresizingMaskIntoConstraints = false
      content.translatesAutoresizingMaskIntoConstraints = false
      document.addSubview(content)
      NSLayoutConstraint.activate([
        document.widthAnchor.constraint(equalToConstant: width),
        content.leadingAnchor.constraint(equalTo: document.leadingAnchor),
        content.topAnchor.constraint(equalTo: document.topAnchor),
        content.bottomAnchor.constraint(equalTo: document.bottomAnchor),
        content.widthAnchor.constraint(equalToConstant: width),
      ])
      return document
    }

    private final class FlippedDocument: NSView {
      override var isFlipped: Bool { true }
    }
  }
#endif
