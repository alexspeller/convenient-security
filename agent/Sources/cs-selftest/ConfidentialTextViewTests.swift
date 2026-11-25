#if canImport(AppKit)
  import AppKit
  import ConvenientSecurity
  import Foundation

  /// `csec edit`'s copies carry the clipboard-history markers and keep the
  /// text a paste needs. Every write goes to a private named pasteboard, never
  /// the general one, so the suite neither reads nor replaces what the
  /// developer has copied, and a clipboard manager never sees it.
  @MainActor
  func confidentialTextViewTests() async {
    let markers = ConfidentialTextView.clipboardHistoryMarkers
    check(
      markers.map(\.rawValue) == ["org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"],
      "confidential text view: marks copies concealed and transient")

    func withPasteboard(_ body: (NSPasteboard) -> Void) {
      let pasteboard = NSPasteboard.withUniqueName()
      defer { pasteboard.releaseGlobally() }
      body(pasteboard)
    }

    func makeView(_ text: String) -> ConfidentialTextView {
      let view = ConfidentialTextView(frame: NSRect(x: 0, y: 0, width: 200, height: 100))
      view.isRichText = false
      view.string = text
      return view
    }

    do {
      let view = makeView(#"{"token": "not-a-real-secret"}"#)
      check(
        markers.allSatisfy(view.writablePasteboardTypes.contains),
        "confidential text view: Copy and Cut ask for the markers")
      view.setSelectedRange(NSRange(location: 11, length: 17))
      withPasteboard { pasteboard in
        let before = pasteboard.changeCount
        let wrote = view.writeSelection(to: pasteboard, types: view.writablePasteboardTypes)
        let types = pasteboard.types ?? []
        check(wrote, "confidential text view: a selection is written")
        check(
          markers.allSatisfy(types.contains),
          "confidential text view: the copy carries both markers (got \(types.map(\.rawValue)))")
        check(
          pasteboard.string(forType: .string) == "not-a-real-secret",
          "confidential text view: the copy pastes as the selected text")
        check(
          pasteboard.changeCount == before + 1,
          "confidential text view: text and markers are one pasteboard generation, the one made host-only")
      }
    }

    do {
      // Two selections paste back as two, as an ordinary text view's do.
      let view = makeView("abcdef\nghijkl")
      view.selectedRanges = [
        NSValue(range: NSRange(location: 0, length: 2)),
        NSValue(range: NSRange(location: 7, length: 3)),
      ]
      withPasteboard { pasteboard in
        let reference = NSTextView(frame: .zero)
        reference.isRichText = false
        reference.string = view.string
        reference.selectedRanges = view.selectedRanges
        let ordinary = NSPasteboard.withUniqueName()
        defer { ordinary.releaseGlobally() }
        _ = reference.writeSelection(to: ordinary, types: reference.writablePasteboardTypes)

        _ = view.writeSelection(to: pasteboard, types: view.writablePasteboardTypes)
        let types = Set(pasteboard.types ?? [])
        check(
          Set(ordinary.types ?? []).isSubset(of: types),
          "confidential text view: every type an ordinary copy writes is still written")
        check(
          pasteboard.string(forType: .string) == ordinary.string(forType: .string),
          "confidential text view: a multiple selection pastes as an ordinary copy would")
        let target = makeView("XX")
        target.setSelectedRange(NSRange(location: 2, length: 0))
        check(
          target.readSelection(from: pasteboard) && target.string == "XXab\nghi",
          "confidential text view: its copy pastes back into a text view (got \(target.string.debugDescription))")
      }
    }

    do {
      // Copy with nothing selected leaves the previous copy in place.
      let view = makeView("abc")
      view.setSelectedRange(NSRange(location: 1, length: 0))
      withPasteboard { pasteboard in
        pasteboard.clearContents()
        pasteboard.setString("previous", forType: .string)
        let before = pasteboard.changeCount
        let wrote = view.writeSelection(to: pasteboard, types: view.writablePasteboardTypes)
        check(!wrote, "confidential text view: an empty selection writes nothing")
        check(
          pasteboard.changeCount == before && pasteboard.string(forType: .string) == "previous",
          "confidential text view: an empty selection keeps the previous copy")
      }
    }

    do {
      // A caller asking only for the text (a drag or a Service) still gets
      // the markers. It asks in the view's own type, the legacy string type,
      // which AppKit also offers as UTF-8 plain text.
      let view = makeView("abc")
      view.setSelectedRange(NSRange(location: 0, length: 3))
      let textOnly = view.writablePasteboardTypes.filter { !markers.contains($0) }.prefix(1)
      withPasteboard { pasteboard in
        _ = view.writeSelection(to: pasteboard, types: Array(textOnly))
        let types = pasteboard.types ?? []
        check(
          markers.allSatisfy(types.contains) && pasteboard.string(forType: .string) == "abc",
          "confidential text view: a text-only write is marked too")
      }
    }
  }
#else
  func confidentialTextViewTests() async {}
#endif
