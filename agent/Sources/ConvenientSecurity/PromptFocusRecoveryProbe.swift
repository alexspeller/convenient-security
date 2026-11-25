#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  import AppKit
  import Foundation
  @preconcurrency import LocalAuthenticationEmbeddedUI

  /// Dev-only, value-free on-device check that a real approval panel follows
  /// `ReviewFocusRecovery`: that it says how to get Touch ID back when another
  /// app takes the focus, and re-arms Touch ID on a fresh context behind its
  /// typing guard when it is key again. Every approval surface shares it:
  /// `CSEC_PREVIEW_FOCUS_PROBE=1 cs-review-preview <scenario>` covers the
  /// secret-access and SSH reviews, and `csec-sudo-review --focus-probe` the
  /// sudo review.
  ///
  /// It prints samples in the grace probe's format, each with `touchID=#N`
  /// (which embedded Touch ID view the panel shows; a new number is a fresh
  /// context) and `clickToResume=shown|absent`:
  /// - `shown`, inside the first grace: not key, `touchID=#1`, controls
  ///   disabled.
  /// - `armed`, after the first grace: key, `touchID=#2` — the evaluation
  ///   armed with the window was renewed when the grace made the panel key —
  ///   controls enabled.
  /// - `away`, after Finder is brought to the front: not key, `touchID=#2`,
  ///   `clickToResume=shown`.
  /// - `back`, just after the panel is made key again as a click on it would:
  ///   `touchID=#3`, `clickToResume=absent`, controls disabled by the guard.
  /// - `left`, after Finder is brought to the front again inside that guard
  ///   and the guard has ended: still not key and not active (the re-arm's
  ///   guard never takes the focus back), `touchID=#3`, `clickToResume=shown`.
  /// - `back-again`: key, `touchID=#4`.
  /// - `settled`, after that grace: controls enabled and
  ///   `firstResponder=PromptKeyboardSink`, as in the grace probe.
  ///
  /// `whileAway`, when given, runs before the `away` sample (a preview
  /// waiting for its requester to exit). With `expectsClose` the panel must
  /// have closed by the `back` sample — the re-arm's requester check — and
  /// `onClosed` runs; a panel still up fails the probe.
  ///
  /// Touch ID is armed for about five seconds and nothing can be approved
  /// without a touch; never touch the sensor while it runs (the caller fails
  /// the run if a touch approves the panel). Because it makes the panel key
  /// itself, it can also take a touch meant for a real prompt and strand
  /// that prompt: run it only when no real prompt can appear. It cannot show
  /// that the fresh evaluation takes a touch another prompt stranded, which
  /// needs a finger (see `docs/development.md`).
  public enum PromptFocusRecoveryProbe {
    public static func schedule(
      whileAway: (@MainActor @Sendable () async -> Void)? = nil,
      expectsClose: Bool = false,
      onClosed: (@MainActor @Sendable () async -> Void)? = nil
    ) {
      Task { @MainActor in
        try? await Task.sleep(nanoseconds: nanoseconds(PromptInteractionGraceProbe.earlySample))
        report("shown")
        try? await Task.sleep(
          nanoseconds: nanoseconds(
            PromptInteractionGraceProbe.lateSample - PromptInteractionGraceProbe.earlySample))
        report("armed")
        guard let panel = NSApplication.shared.windows.first(where: { $0 is NSPanel }) else {
          exit(1)
        }
        await bringFinderForward()
        try? await Task.sleep(nanoseconds: nanoseconds(0.8))
        await whileAway?()
        report("away")
        PromptInteractionGrace.activateAndFocus(panel)
        try? await Task.sleep(nanoseconds: nanoseconds(0.2))
        report("back")
        if expectsClose {
          guard !panel.isVisible else {
            print("focus probe: FAIL — the panel stayed up after its requester exited")
            exit(1)
          }
          await onClosed?()
          exit(0)
        }
        await bringFinderForward()
        try? await Task.sleep(nanoseconds: nanoseconds(PromptInteractionGraceProbe.settle))
        report("left")
        PromptInteractionGrace.activateAndFocus(panel)
        try? await Task.sleep(nanoseconds: nanoseconds(0.2))
        report("back-again")
        try? await Task.sleep(nanoseconds: nanoseconds(PromptInteractionGraceProbe.settle))
        report("settled")
        exit(0)
      }
    }

    /// As a click on another app would: Finder becomes the active app.
    @MainActor
    private static func bringFinderForward() async {
      let finder = URL(fileURLWithPath: "/System/Library/CoreServices/Finder.app")
      let configuration = NSWorkspace.OpenConfiguration()
      configuration.activates = true
      _ = try? await NSWorkspace.shared.openApplication(at: finder, configuration: configuration)
    }

    private static func nanoseconds(_ seconds: TimeInterval) -> UInt64 {
      UInt64(seconds * 1_000_000_000)
    }

    /// Held strongly: a replaced view freed while the probe runs could hand
    /// its address to the next one and read as the same view.
    @MainActor private static var seenViews: [LAAuthenticationView] = []

    @MainActor
    private static func report(_ label: String) {
      guard let content = NSApplication.shared.windows.first(where: { $0 is NSPanel })?.contentView
      else {
        print("\(label): review panel never appeared")
        return
      }
      var touchID = "none"
      if let view = find(LAAuthenticationView.self, in: content) {
        if !seenViews.contains(where: { $0 === view }) { seenViews.append(view) }
        touchID = "#\((seenViews.firstIndex(where: { $0 === view }) ?? 0) + 1)"
      }
      let click = showsText(ReviewFocusRecovery.clickToResumeText, in: content)
      PromptInteractionGraceProbe.report(
        label, extra: "touchID=\(touchID) clickToResume=\(click ? "shown" : "absent") ")
    }

    @MainActor
    private static func find<T: NSView>(_ type: T.Type, in view: NSView) -> T? {
      if let match = view as? T { return match }
      for child in view.subviews {
        if let match = find(type, in: child) { return match }
      }
      return nil
    }

    @MainActor
    private static func showsText(_ text: String, in view: NSView) -> Bool {
      if let field = view as? NSTextField, !field.isHidden, field.stringValue == text { return true }
      return view.subviews.contains { showsText(text, in: $0) }
    }
  }
#endif
