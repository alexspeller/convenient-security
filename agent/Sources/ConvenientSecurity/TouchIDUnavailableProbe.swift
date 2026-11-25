#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  import AppKit
  import Foundation
  @preconcurrency import LocalAuthenticationEmbeddedUI

  /// Dev-only, value-free samples of the approval panel on screen, for the
  /// on-device checks of a Mac that cannot take a touch
  /// (`ReviewTouchIDUnavailable`): `CSEC_PREVIEW_TOUCH_ID_PROBE=1
  /// cs-review-preview <scenario>` for the secret-access, SSH and restore
  /// panels, and `csec-sudo-review --no-touch-id-probe` for the sudo panel.
  /// Each tool drives its own sequence (the sudo panel closes once nobody can
  /// approve; the others stay up) and reads the panel through this.
  public enum TouchIDUnavailableProbe {
    public struct Sample: Sendable, CustomStringConvertible {
      /// Visible approval panels.
      public let panels: Int
      /// Every label the visible panels draw.
      public let lines: [String]
      /// Whether a visible panel shows an embedded Touch ID view (armed or
      /// about to be), and whether it holds a hidden one.
      public let touchIDShown: Bool
      public let touchIDHidden: Bool

      public func shows(_ line: String) -> Bool { lines.contains(line) }

      /// Which unavailable line, if any, a panel shows: `phone`, `nobody`,
      /// `sudo` or `none`. Fixed labels only, never the panel's other text.
      public var unavailableLine: String {
        if shows(ReviewTouchIDUnavailable.statusText(for: .secretAccess, phoneCanDecide: true)) { return "phone" }
        if shows(ReviewTouchIDUnavailable.statusText(for: .secretAccess, phoneCanDecide: false)) {
          return "nobody"
        }
        if shows(ReviewTouchIDUnavailable.statusText(for: .sudo, phoneCanDecide: true)) { return "sudo" }
        return "none"
      }

      public var description: String {
        let touchID = touchIDShown ? "shown" : (touchIDHidden ? "hidden" : "absent")
        return "panels=\(panels) touchID=\(touchID) unavailableLine=\(unavailableLine)"
      }
    }

    @MainActor
    public static func sample() -> Sample {
      func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
      let panels = NSApplication.shared.windows.filter { $0 is NSPanel && $0.isVisible }
      let views = panels.flatMap { all($0.contentView ?? NSView()) }
      let touchIDViews = views.filter { $0 is LAAuthenticationView }
      return Sample(
        panels: panels.count,
        lines: views.compactMap { ($0 as? NSTextField)?.stringValue },
        touchIDShown: touchIDViews.contains { !$0.isHidden },
        touchIDHidden: touchIDViews.contains(where: \.isHidden))
    }

    /// Whether this Mac can take a touch now, so a probe can tell a panel
    /// that did not re-arm from a Mac whose Touch ID never came back.
    public static var thisMacCanTakeATouch: Bool {
      ReviewTouchIDUnavailable.isAvailable(ReviewAuthenticationContext.make(for: .secretAccess))
    }
  }
#endif
