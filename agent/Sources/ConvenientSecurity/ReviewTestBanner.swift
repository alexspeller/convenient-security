#if canImport(AppKit)
  import AppKit
#endif
import Foundation

/// The notice an approval panel carries when a developer check put it on
/// screen: `cs-review-preview` presenting a fixture, or one of the debug sudo
/// helper's live probes. Those panels are the real windows, built exactly as a
/// real request builds them, so without it a probe's panel and a request
/// waiting on the human look the same, and a human who has learned to expect
/// harmless test panels may touch the sensor for a real one, or ignore a real
/// one as a test.
///
/// The marker is process-wide and starts off. Only a test entry point turns it
/// on, before it builds a panel; csecd and the sudo review that PAM spawns
/// never do (`bin/ci` holds every write to the test executables), so a real
/// request can never be dressed as a test. A panel rendered offscreen for its
/// layout (`CSEC_PREVIEW_OFFSCREEN`, `csec-sudo-review --preview`,
/// `ApprovalPanelInspection`) is never on screen to be mistaken, and stays
/// unmarked so its picture shows the panel as a request draws it.
///
/// Every surface draws the same banner (`view(width:)`) as the first row of
/// its window, above the header, in every layout variant, and adds
/// `titleSuffix` to its window title.
public enum ReviewTestBanner {
  /// Whether panels this process builds say they are a test. Set only by a
  /// test entry point, before its first panel.
  @MainActor public static var isShown = false

  public static let headline = "TEST — NOT A REAL REQUEST"
  public static let detail =
    "A developer check put this panel up. Nothing is waiting on it: approving it "
    + "releases, signs or runs nothing."
  public static let titleSuffix = " — TEST"

  #if canImport(AppKit)
    public static let identifier = NSUserInterfaceItemIdentifier("csec.review.testBanner")

    /// The window title for a panel titled `title`.
    @MainActor static func title(_ title: String) -> String {
      isShown ? title + titleSuffix : title
    }

    /// The banner, `width` wide, or nil when this process is not a test.
    @MainActor static func view(width: CGFloat) -> NSView? {
      guard isShown else { return nil }
      let icon = NSImageView()
      icon.image = NSImage(
        systemSymbolName: "testtube.2", accessibilityDescription: "Test")
      icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 26, weight: .bold)
      icon.contentTintColor = .white
      icon.setContentHuggingPriority(.required, for: .horizontal)
      icon.setContentCompressionResistancePriority(.required, for: .horizontal)

      let headlineLabel = NSTextField(labelWithString: headline)
      headlineLabel.font = .systemFont(ofSize: 22, weight: .heavy)
      headlineLabel.textColor = .white

      let detailLabel = NSTextField(wrappingLabelWithString: detail)
      detailLabel.font = .systemFont(ofSize: 12, weight: .semibold)
      detailLabel.textColor = .white
      detailLabel.maximumNumberOfLines = 3
      detailLabel.preferredMaxLayoutWidth = width - 88

      let text = NSStackView(views: [headlineLabel, detailLabel])
      text.orientation = .vertical
      text.alignment = .leading
      text.spacing = 3

      let content = NSStackView(views: [icon, text])
      content.orientation = .horizontal
      content.alignment = .centerY
      content.spacing = 14
      content.translatesAutoresizingMaskIntoConstraints = false

      // A solid fill in both appearances: a tinted wash like the delivery
      // warnings would read as one more warning on a real request.
      let box = NSBox()
      box.boxType = .custom
      box.borderWidth = 0
      box.cornerRadius = 10
      box.fillColor = .systemRed
      box.contentViewMargins = .zero
      box.titlePosition = .noTitle
      box.identifier = identifier
      box.setAccessibilityLabel(headline + ". " + detail)
      box.translatesAutoresizingMaskIntoConstraints = false
      box.contentView?.addSubview(content)
      if let inner = box.contentView {
        NSLayoutConstraint.activate([
          content.leadingAnchor.constraint(equalTo: inner.leadingAnchor, constant: 18),
          content.trailingAnchor.constraint(lessThanOrEqualTo: inner.trailingAnchor, constant: -18),
          content.topAnchor.constraint(equalTo: inner.topAnchor, constant: 14),
          content.bottomAnchor.constraint(equalTo: inner.bottomAnchor, constant: -14),
        ])
      }
      box.widthAnchor.constraint(equalToConstant: width).isActive = true
      return box
    }
  #endif
}
