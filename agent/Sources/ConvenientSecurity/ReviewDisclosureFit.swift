import CoreGraphics
import Foundation

/// How an approval panel makes room for a disclosure it opens. The panel grows
/// to show everything the disclosure holds, so the facts a human checks are
/// never cut down to a peephole; only when the grown panel would no longer fit
/// the screen does the disclosure scroll, in whatever height the screen leaves.
public enum ReviewDisclosureFit {
  /// The least height an opened disclosure is given even when the panel is
  /// already as tall as the screen: enough for a line or two and a scroller.
  public static let minimumHeight: CGFloat = 60

  /// The heights for the views of one panel that each scroll only past the
  /// screen (`ReviewScreenFit`), whole at `contentHeights` while the rest of
  /// the panel takes `otherHeight`. When together they would take the panel
  /// past `visibleHeight`, they share what it leaves: the shorter ones keep
  /// their whole height and the taller ones are cut to one equal height, never
  /// below `minimumHeight`, so no view is squeezed to leave another one longer.
  /// With no screen to fit, every view shows all of its content.
  public static func heights(
    contentHeights: [CGFloat], otherHeight: CGFloat, visibleHeight: CGFloat?
  ) -> [CGFloat] {
    guard let visibleHeight else { return contentHeights }
    var remaining = visibleHeight - otherHeight
    guard contentHeights.reduce(0, +) > remaining + 0.5 else { return contentHeights }
    // Fill from the shortest: each view takes its whole height while that is
    // no more than an equal share of what is left; the first that is not sets
    // the share every taller one is cut to. Since all of them do not fit, one
    // always does not.
    var cut = minimumHeight
    var left = contentHeights.count
    for content in contentHeights.sorted() {
      let share = floor(remaining / CGFloat(left))
      if content <= share {
        remaining -= content
        left -= 1
      } else {
        cut = share
        break
      }
    }
    let height = max(minimumHeight, cut)
    return contentHeights.map { min($0, height) }
  }

  /// The bottom edge for a panel `height` tall whose top edge was `top`: the
  /// top stays where it was, so the text being read does not move, unless the
  /// panel would then run past the bottom of the screen's visible area, when it
  /// moves up just far enough to keep its buttons and Touch ID on screen —
  /// never so far that its title bar leaves the top.
  public static func originY(top: CGFloat, height: CGFloat, visibleFrame: CGRect?) -> CGFloat {
    let preserved = top - height
    guard let visibleFrame, preserved < visibleFrame.minY else { return preserved }
    return min(visibleFrame.minY, visibleFrame.maxY - height)
  }
}
