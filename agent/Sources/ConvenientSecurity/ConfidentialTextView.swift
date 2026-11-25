#if canImport(AppKit)
  import AppKit
  import Foundation

  /// A text view for plaintext secrets whose copies stay out of clipboard
  /// history and off other devices.
  ///
  /// A human editing a secret will copy part of it, and an ordinary copy is
  /// recorded by whatever clipboard manager is running: Raycast, Maccy, Paste
  /// and Alfred keep that history on disk for days or for good, and Universal
  /// Clipboard hands the same copy to every nearby iPhone, iPad and Mac. Every
  /// selection this view writes to a pasteboard (Copy, Cut, a drag, a
  /// Service) therefore also declares the nspasteboard.org markers that
  /// password managers use, `org.nspasteboard.ConcealedType` and
  /// `org.nspasteboard.TransientType`, which those managers check before they
  /// record anything, and is written as one pasteboard generation made
  /// `.currentHostOnly`, which keeps it off Universal Clipboard. Pasting into
  /// another app on this Mac works as before: the markers are extra types
  /// that a paste ignores.
  ///
  /// The markers and the text are declared together, before any data is
  /// written, so a manager polling the pasteboard never sees the text without
  /// them. The generation matters for the host-only option: AppKit applies it
  /// to the generation `prepareForNewContents(with:)` begins, and
  /// `declareTypes(_:owner:)` begins another, so this view adds its types to
  /// the prepared generation and writes each one there rather than handing
  /// the pasteboard to `super`.
  ///
  /// Nothing clears the pasteboard afterwards. A copy the human made stays
  /// pasteable until they copy something else, as with a password manager's
  /// copy.
  public final class ConfidentialTextView: NSTextView {
    /// Markers that ask clipboard managers not to record or show a copy.
    public static let clipboardHistoryMarkers: [NSPasteboard.PasteboardType] = [
      NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"),
      NSPasteboard.PasteboardType("org.nspasteboard.TransientType"),
    ]

    public override var writablePasteboardTypes: [NSPasteboard.PasteboardType] {
      super.writablePasteboardTypes + Self.clipboardHistoryMarkers
    }

    public override func writeSelection(
      to pboard: NSPasteboard,
      type: NSPasteboard.PasteboardType
    ) -> Bool {
      if Self.clipboardHistoryMarkers.contains(type) {
        return pboard.setData(Data(), forType: type)
      }
      return super.writeSelection(to: pboard, type: type)
    }

    public override func writeSelection(
      to pboard: NSPasteboard,
      types: [NSPasteboard.PasteboardType]
    ) -> Bool {
      // An empty selection writes nothing, so the human's previous copy stays.
      guard selectedRanges.contains(where: { $0.rangeValue.length > 0 }) else {
        return false
      }
      let markers = Self.clipboardHistoryMarkers
      let content = types.filter { !markers.contains($0) }
      guard !content.isEmpty else { return false }

      pboard.prepareForNewContents(with: .currentHostOnly)
      pboard.addTypes(markers + content, owner: nil)
      for marker in markers {
        _ = writeSelection(to: pboard, type: marker)
      }
      var wroteContent = false
      for type in content where writeSelection(to: pboard, type: type) {
        wroteContent = true
      }
      return wroteContent
    }
  }
#endif
