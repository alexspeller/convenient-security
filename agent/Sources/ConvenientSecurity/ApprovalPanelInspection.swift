#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  import AppKit
  import Foundation

  /// Dev-only, value-free test harness over the approval panels. Each builds
  /// the real window its surface would put up, exactly as presenting it does,
  /// but never orders it onscreen and never starts Touch ID, so `cs-selftest`
  /// can drive the keyboard handling of every surface's own window rather than
  /// a stand-in. The refusing button still works: pressing it closes the
  /// window as a denial would, with nobody waiting for the outcome.
  @MainActor
  public struct ApprovalPanelInspection {
    public let window: NSPanel
    /// The session behind the window — its delegate and its buttons' target,
    /// which the window does not retain — held for as long as this value is.
    private let owner: AnyObject

    private init(_ built: (window: NSPanel, owner: AnyObject)) {
      window = built.window
      owner = built.owner
    }

    /// The secret-access, SSH, restore or automation panel, by `review`'s
    /// shape; with `deadline`, as a coding agent's request draws it; with
    /// `touchID`, as a Mac that cannot take a touch draws it, mirrored to the
    /// phone leg `phone` or, with none, to no phone.
    public static func access(
      _ review: AccessPolicyReview, deadline: ReviewDeadline? = nil,
      phone: ReviewPhoneStatus? = nil, touchID: ReviewTouchIDOverride? = nil
    ) -> ApprovalPanelInspection {
      ApprovalPanelInspection(
        TrustedAccessReviewSession.unpresented(
          review, deadline: deadline, phone: phone, touchID: touchID))
    }

    /// The sudo panel; with `touchID`, as a Mac that cannot take a touch
    /// draws it. Production always passes a deadline.
    public static func sudo(
      _ review: SudoAuthorizationReviewRequest,
      terminal: TerminalSessionContext,
      deadline: ReviewDeadline? = nil,
      touchID: ReviewTouchIDOverride? = nil
    ) -> ApprovalPanelInspection {
      ApprovalPanelInspection(
        TrustedSudoAuthorizationReviewSession.unpresented(
          review, terminal: terminal, deadline: deadline, touchID: touchID))
    }

    /// The reason the secret-access, SSH, restore or automation panel gives
    /// its first Touch ID evaluation for `review`.
    public static func accessAuthenticationReason(_ review: AccessPolicyReview) -> String {
      TrustedAccessReviewSession.initialAuthenticationReason(review)
    }

    /// Every button and pop-up the panel draws that its typing guard does not
    /// hold back: the controls not registered with `PromptInteractionGrace`.
    /// Empty for a correctly built panel; `bin/ci` counts the same thing in
    /// source, this checks the window each layout actually builds.
    public var unregisteredControls: [NSControl] {
      let registered: [NSControl]
      if let access = owner as? TrustedAccessReviewSession {
        registered = access.interactiveControls
      } else if let sudo = owner as? TrustedSudoAuthorizationReviewSession {
        registered = sudo.interactiveControls
      } else {
        registered = []
      }
      func controls(in view: NSView) -> [NSControl] {
        let own = (view as? NSButton).map { [$0 as NSControl] } ?? []
        return own + view.subviews.flatMap(controls)
      }
      return (window.contentView.map(controls) ?? []).filter { control in
        !registered.contains { $0 === control }
      }
    }

    /// The titles of the scope radios the panel offers, top to bottom; empty
    /// when it states a single root instead.
    public var scopeRadioTitles: [String] {
      (owner as? TrustedAccessReviewSession)?.scopeButtons.map(\.button.title) ?? []
    }

    /// The deadline line's text, or nil when the panel shows none.
    public var deadlineLine: String? {
      func find(_ view: NSView) -> NSTextField? {
        if let field = view as? NSTextField, field.identifier == ReviewDeadlineCountdown.lineIdentifier {
          return field
        }
        return view.subviews.lazy.compactMap(find).first
      }
      return window.contentView.flatMap(find)?.stringValue
    }
  }
#endif
