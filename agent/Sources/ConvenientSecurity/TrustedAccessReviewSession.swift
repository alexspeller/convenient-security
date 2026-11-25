#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @preconcurrency import AppKit
  import CSECRemoteApproval
  import Foundation
  @preconcurrency import LocalAuthentication
  @preconcurrency import LocalAuthenticationEmbeddedUI

  /// One trusted window owns policy selection and the LAContext-backed Touch ID
  /// view. Authentication starts as soon as the visible window is rendered; the
  /// window's buttons and selectors, and keyboard focus, follow only after a
  /// short grace period (see `PromptInteractionGrace`) so a sentence the human
  /// is mid-way through typing cannot deny or reshape the request. On success
  /// the exact visible review is returned to Agent, which must still accept it
  /// before this session releases its LAContext.
  @MainActor
  final class TrustedAccessReviewSession: NSObject, NSWindowDelegate,
    AccessPolicyAuthenticationSession
  {
    private enum State {
      case ready
      case selecting
      case awaitingPolicy
      case authenticating
      // The prompt was cancelled while the screen was locked. The request is
      // held open — not denied — until the Mac is unlocked and Touch ID can be
      // re-presented. See ScreenLockState.
      case waitingForUnlock
      case finished
    }

    private static let contentWidth: CGFloat = 640
    private static let horizontalMargin: CGFloat = 28
    private static var innerWidth: CGFloat { contentWidth - horizontalMargin * 2 }

    private let review: AccessPolicyReview
    /// When csecd withdraws this request unanswered: a coding agent's
    /// (`HumanWait`). Nil for every other request, which waits as long as it
    /// takes and shows no deadline line.
    private let deadline: ReviewDeadline?
    private var deadlineCountdown: ReviewDeadlineCountdown?
    // Not `let`: a prompt cancelled behind the lock screen spends its context,
    // and another prompt can strand it (`ReviewFocusRecovery`), so the unlock
    // retry and the focus re-arm evaluate a fresh one (and re-bind the
    // embedded view).
    private var context: LAContext
    private var state = State.ready
    private var selectionContinuation: CheckedContinuation<AccessPolicyReviewOutcome, Never>?
    private var biometricsAvailable = false
    /// The phone leg racing this panel, when `MirroredPolicyReview` mirrored
    /// the review (`ReviewPhoneStatus.current`); nil when only this panel can
    /// decide. It matters only while this Mac cannot take a touch
    /// (`ReviewTouchIDUnavailable`).
    private let phone: ReviewPhoneStatus?
    /// A dev-only stand-in for a Mac with no Touch ID; nil for every request.
    private let touchIDOverride: ReviewTouchIDOverride?
    /// When the panel was built, which the override's intervals count from.
    private let builtAt = ContinuousClock.now
    /// Polls for Touch ID coming back while the panel is up without it.
    private var touchIDWatch: TouchIDAvailabilityWatch?
    /// Drives the wait for the Mac to unlock while `state == .waitingForUnlock`.
    /// Polling (not the `com.apple.screenIsUnlocked` notification) so a dropped
    /// notification cannot strand a held-open request. Runs only while waiting.
    private var unlockPollTimer: Timer?
    /// Counts Touch ID evaluations. A re-arm invalidates a still-pending
    /// evaluation, whose late cancellation must not be read as this panel's
    /// answer, so each callback carries the generation it was started as.
    private var authenticationGeneration = 0
    /// Whether the window resigned key while the current evaluation was armed,
    /// and whether that evaluation started while the window was not key and it
    /// has not been key since. See `ReviewFocusRecovery`.
    private var lostKeyWhileArmed = false
    private var armedWhileNotKey = false
    /// Whether the panel renewed Touch ID after a system cancel since it last
    /// became or resigned key (`ReviewFocusRecovery.onSystemCancel`).
    private var renewedAfterSystemCancelWhileKey = false
    /// When the panel was last put in front of the human: its first
    /// presentation, or the re-present after an unlock. A focus re-arm leaves
    /// it alone (the panel stayed on screen), so a stranded interval counts
    /// toward the decision time. The approval reports the time from here to
    /// the biometric result for the decision log; it is measurement only and
    /// never gates anything.
    private var presentedAt: ContinuousClock.Instant?

    private var window: NSPanel!
    private var authenticationView: LAAuthenticationView!
    /// The horizontal row holding `authenticationView` + `statusLabel`, retained
    /// so the embedded Touch ID view can be swapped for a fresh-context one on an
    /// unlock retry or a focus re-arm.
    private var authenticationArea: NSStackView!
    private var statusLabel: NSTextField!
    private var denyButton: NSButton!
    /// Every control a keystroke or click can act on, registered as it is
    /// built, so the grace period can hold all of them back together.
    private(set) var interactiveControls: [NSControl] = []
    private var interactionGrace: PromptInteractionGrace?
    private var automationDetailsView: NSView?
    /// The SSH details, hidden until opened; as tall as they are, scrolling
    /// only in what the screen leaves (`ReviewFittedList`).
    private var sshDetailsView: NSView?
    /// Every command and list this panel shows whole unless the screen is too
    /// short, registered as it is built and fitted together on every re-fit
    /// (`ReviewScreenFit`), so none of them sits behind a fixed peephole.
    private var screenFitted: [any ReviewScreenFitting] = []
    private var sshScopeSummaryLabel: NSTextField?
    /// Radio buttons for the offered grant scopes, keyed by option id. The live
    /// selection is authoritative: `LAAuthenticationView` is documented as
    /// non-textual ("the reason for the authentication must be apparent from the
    /// surrounding UI"), so this window — not the LAContext reason string — is
    /// what the human is reading when they touch the sensor.
    private(set) var scopeButtons: [(id: String, button: NSButton)] = []
    private var selectedScopeOptionID: String?
    /// The grant-lifetime popup and its live "until …" companion. As with the
    /// scope radios, the popup's selection is authoritative and is read at
    /// biometric success.
    private var durationPopup: NSPopUpButton?
    /// The popup, or the fixed-lifetime label when no choice is offered.
    private var durationControl: NSView?
    private var expiryLabel: NSTextField?
    private var selectedDuration: GrantDuration?
    /// The delivery-metadata grid, collapsed behind a disclosure by default.
    private var deliveryDetailsView: NSView?
    /// The two renderings of a long command: a few-line preview and the full
    /// text, swapped by the "Show full command" disclosure.
    private var commandPreviewView: NSView?
    private var commandFullText: ReviewCommandText?
    /// The pairing line: shown exactly while the selection is the one that
    /// pairs (the default Claude Code scope for the session's lifetime).
    private var pairingLabel: NSTextField?

    private init(
      review: AccessPolicyReview, deadline: ReviewDeadline?, phone: ReviewPhoneStatus?,
      touchID override: ReviewTouchIDOverride?
    ) {
      self.review = review
      self.deadline = deadline
      self.phone = phone
      self.touchIDOverride = override
      self.context = ReviewAuthenticationContext.make(for: Self.surface(of: review))
      self.selectedScopeOptionID = review.scopeChoices?.defaultOptionID
      self.selectedDuration = review.durationChoices?.defaultOption
      super.init()
      configureAuthentication()
      configureWindow()
    }

    /// The real panel `review` would put up, never ordered onscreen and with
    /// no Touch ID evaluation started (`ApprovalPanelInspection`). `phone` is
    /// the mirror's phone leg, if any; `touchID` stands in for a Mac that
    /// cannot take a touch.
    static func unpresented(
      _ review: AccessPolicyReview, deadline: ReviewDeadline? = nil,
      phone: ReviewPhoneStatus? = nil, touchID: ReviewTouchIDOverride? = nil
    ) -> (window: NSPanel, owner: AnyObject) {
      let session = TrustedAccessReviewSession(
        review: review, deadline: deadline, phone: phone, touchID: touchID)
      return (session.window, session)
    }

    /// The deadline is the request's own (`HumanWait.current`, bound in this
    /// task by the service that received it): its withdrawal cancels this
    /// task, which closes the panel the line counted down for. The phone leg,
    /// when the review was mirrored, is bound the same way
    /// (`ReviewPhoneStatus.current`). `touchID` is for the preview tool only.
    static func present(
      _ review: AccessPolicyReview, touchID: ReviewTouchIDOverride? = nil
    ) async -> AccessPolicyReviewOutcome {
      let session = TrustedAccessReviewSession(
        review: review, deadline: ReviewDeadline(HumanWait.current),
        phone: ReviewPhoneStatus.current, touchID: touchID)
      return await withTaskCancellationHandler {
        await session.collectPolicySelection()
      } onCancel: {
        // A verified phone decision can win while the local Touch ID sheet is
        // active. Invalidate its LAContext and close the panel promptly so the
        // losing path cannot later produce a second decision.
        Task { @MainActor in
          await session.cancel()
        }
      }
    }

    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
      guard state == .awaitingPolicy, biometricsAvailable else {
        finishDenied(.authenticationFailed, closeWindow: true)
        return .denied
      }

      // Touch ID already succeeded before the selection crossed the actor
      // boundary. Only the authoritative policy decision can consume that
      // authentication and obtain the context used for a cold Keychain read.
      state = .finished
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = "Policy allowed: \(Self.safe(policySummary))"
      statusLabel.isHidden = false
      let unlock = CacheUnlock(context)
      closeWindow()
      return .approved(unlock: unlock)
    }

    /// Cancellation comes from the requester's side: its connection closed
    /// (the socket servers' peer-exit watch cancels the request's task), or a
    /// phone decision won the race, in which case this outcome is discarded.
    /// After an approval the selection has already been returned and there is
    /// no outcome left to give a reason to.
    func cancel() async {
      finishDenied(.requesterGone, closeWindow: true)
    }

    private func configureAuthentication() {
      var evaluationError: NSError?
      biometricsAvailable =
        touchIDOverride?.holdsUnavailable(builtAt: builtAt) != true
        && ReviewTouchIDUnavailable.isAvailable(context, error: &evaluationError)
      if !biometricsAvailable {
        let detail = evaluationError?.localizedDescription ?? "no error"
        let who = phone?.canDecide == true ? "only the phone can approve" : "nothing can approve"
        FileHandle.standardError.write(
          Data(
            "csecd: biometrics unavailable, \(who) until Touch ID returns (\(detail))\n".utf8
          ))
      }
    }

    /// Which approval surface this window is: the SSH signing review is its own
    /// dialog even though it shares this class, while the automation review is a
    /// layout variant of the secret-access one. Every `LAContext` this session
    /// evaluates — the first and each unlock rebuild — is built for that surface
    /// by `ReviewAuthenticationContext`, which is where the Touch-ID-reuse and
    /// button-title invariants live.
    private static func surface(of review: AccessPolicyReview)
      -> ReviewAuthenticationContext.Surface
    {
      review.ssh != nil ? .sshSigning : .secretAccess
    }

    // MARK: - Window construction

    private func configureWindow() {
      window = NSPanel(
        contentRect: NSRect(x: 0, y: 0, width: Self.contentWidth, height: 400),
        styleMask: [.titled, .closable],
        backing: .buffered,
        defer: false
      )
      window.title = ReviewTestBanner.title("Convenient Security")
      window.isRestorable = false
      window.isReleasedWhenClosed = false
      window.hidesOnDeactivate = false
      window.level = .modalPanel
      window.delegate = self

      // Keyboard focus rests on the content view itself in every variant of
      // this window, never on a control: see PromptKeyboardSink.
      let contentView = PromptKeyboardSink.install(in: window)

      let root = NSStackView()
      root.orientation = .vertical
      root.alignment = .leading
      root.spacing = 16
      root.translatesAutoresizingMaskIntoConstraints = false
      contentView.addSubview(root)

      // A panel a developer check put on screen says so before anything else,
      // in every variant (ReviewTestBanner); a real request never has it.
      if let testBanner = ReviewTestBanner.view(width: Self.innerWidth) {
        root.addArrangedSubview(testBanner)
      }
      root.addArrangedSubview(makeHeader())

      if review.automation != nil {
        root.addArrangedSubview(Self.makeAutomationWarning(width: Self.innerWidth))
      } else if let warning = DeliveryReviewCopy.warning(for: review) {
        let tint: NSColor =
          review.plan.recipientAssurance == .ordinaryPersistentFile
            ? .systemRed : .systemOrange
        root.addArrangedSubview(
          Self.makeBanner(text: warning, tint: tint, width: Self.innerWidth))
      }

      if review.isRestoreOnly, let restore = review.restore {
        // A restore approves nothing new, so this layout carries no delivery
        // warning and no scope, duration or other grant control: only what
        // the touch reopens.
        root.addArrangedSubview(makeRestoreSection(restore, width: Self.innerWidth))
      } else if let ssh = review.ssh {
        root.addArrangedSubview(makeSSHIdentitySummary(ssh))
        root.addArrangedSubview(makeSSHRequestDetails(ssh))
      } else if let automation = review.automation {
        root.addArrangedSubview(Self.makeSectionLabel("Credentials to be released"))
        root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
        let credentialCards = ReviewFittedList(
          width: Self.innerWidth, cue: Self.secretsOverflowCue
        ) { [weak self] width in self?.makeSecretsCard(width: width) ?? NSView() }
        screenFitted.append(credentialCards)
        root.addArrangedSubview(credentialCards.view)

        root.addArrangedSubview(Self.makeSectionLabel("Persistent automation job"))
        root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
        root.addArrangedSubview(makeAutomationSummary(automation, width: Self.innerWidth))
      } else if let change = review.settingsChange {
        // A change to csec's own settings releases nothing: only what the
        // touch changes, with no scope, lifetime or delivery.
        root.addArrangedSubview(Self.makeSectionLabel(SettingsChangeReviewDetails.sectionLabel))
        root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
        root.addArrangedSubview(Self.makeSettingsChanges(change, width: Self.innerWidth))
      } else {
        // A secret release: the three facts a human checks before touching the
        // sensor — which tab, which command, which secrets — lead at equal
        // weight, then the grant they are about to make, then the delivery
        // metadata behind a disclosure.
        root.addArrangedSubview(makeReleaseFacts(width: Self.innerWidth))
        root.setCustomSpacing(12, after: root.arrangedSubviews.last!)
        root.addArrangedSubview(makeGrantCard(width: Self.innerWidth))
        root.setCustomSpacing(10, after: root.arrangedSubviews.last!)
        root.addArrangedSubview(makeDeliveryDetails(width: Self.innerWidth))
        root.setCustomSpacing(10, after: root.arrangedSubviews.last!)
        // A release that also finds restored approvals still sealed carries
        // their restore section in the same panel: one touch, one Deny.
        if let restore = review.restore {
          root.addArrangedSubview(makeRestoreSection(restore, width: Self.innerWidth))
          root.setCustomSpacing(10, after: root.arrangedSubviews.last!)
        }
      }

      if review.ssh != nil, let choices = review.scopeChoices, choices.options.count > 1 {
        root.addArrangedSubview(Self.makeSectionLabel("Allow SSH from"))
        root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
        let selector = makeScopeSelector(choices, width: Self.innerWidth)
        root.addArrangedSubview(selector)
        NSLayoutConstraint.activate([
          selector.widthAnchor.constraint(equalToConstant: Self.innerWidth)
        ])
      }

      if review.ssh != nil {
        // How long the signing grant lasts is the human's choice here exactly as
        // it is for a secret release, so it is stated with the same control in
        // the same card shape, below whatever the grant covers.
        root.setCustomSpacing(10, after: root.arrangedSubviews.last!)
        root.addArrangedSubview(makeSSHGrantLifetimeCard(width: Self.innerWidth))
      }

      // `DeliveryReviewCopy.footnote` is the one source for this footnote and
      // the phone review's: a restore-only panel's says what its touch reopens,
      // SSH's that only a signature leaves csecd, a release's that the touch
      // authorizes exactly it.
      if review.automation == nil {
        let footnote = NSTextField(
          wrappingLabelWithString: DeliveryReviewCopy.footnote(for: review) ?? ""
        )
        footnote.font = .systemFont(ofSize: 11)
        footnote.textColor = .tertiaryLabelColor
        footnote.maximumNumberOfLines = 3
        footnote.preferredMaxLayoutWidth = Self.innerWidth
        root.addArrangedSubview(footnote)
        // Why Claude Code auto mode did not approve this on its own, and
        // what approving it also allows there. Secret-access and SSH layouts
        // only: a restore-only panel approves nothing new, and automation
        // enrollment is never delegated.
        if !review.isRestoreOnly, let delegationNote = review.delegationNote {
          root.setCustomSpacing(6, after: footnote)
          let note = NSTextField(wrappingLabelWithString: Self.safe(delegationNote.panelText))
          note.font = .systemFont(ofSize: 11)
          note.textColor = .tertiaryLabelColor
          note.maximumNumberOfLines = 3
          note.preferredMaxLayoutWidth = Self.innerWidth
          root.addArrangedSubview(note)
        }
        if !review.isRestoreOnly, let offer = review.pairingOffer {
          let line = NSTextField(wrappingLabelWithString: Self.safe(offer.line))
          line.font = .systemFont(ofSize: 12, weight: .medium)
          line.textColor = .secondaryLabelColor
          // Never truncated: approving pins every script the line names, so
          // all of it must be readable. `DelegationPairingOffer` bounds it.
          line.maximumNumberOfLines = 0
          line.preferredMaxLayoutWidth = Self.innerWidth
          line.isHidden = !offer.applies(scopeOptionID: selectedScopeOptionID, duration: selectedDuration)
          line.identifier = PromptInteractionGraceProbe.pairingLineIdentifier
          pairingLabel = line
          root.addArrangedSubview(line)
        }
      }

      let separator = NSBox()
      separator.boxType = .separator
      root.addArrangedSubview(separator)

      root.addArrangedSubview(makeAuthenticationArea())
      root.addArrangedSubview(makeFooter())

      NSLayoutConstraint.activate([
        root.leadingAnchor.constraint(
          equalTo: contentView.leadingAnchor, constant: Self.horizontalMargin),
        root.trailingAnchor.constraint(
          equalTo: contentView.trailingAnchor, constant: -Self.horizontalMargin),
        root.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 22),
        root.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -18),
        root.widthAnchor.constraint(equalToConstant: Self.innerWidth),
        separator.widthAnchor.constraint(equalTo: root.widthAnchor),
      ])

      contentView.layoutSubtreeIfNeeded()
      ReviewScreenFit.fit(screenFitted, in: window)
      contentView.layoutSubtreeIfNeeded()
      window.setContentSize(contentView.fittingSize)
    }

    /// Re-fit the window to its content after a disclosure opens or a selection
    /// changes what the window says, keeping the top edge where it is so the
    /// facts the human is reading do not move under their eyes. The commands
    /// and lists that scroll past the screen are fitted again first: what an
    /// opened disclosure takes, they give back.
    private func resizeToFitPreservingTop() {
      guard let contentView = window.contentView else { return }
      let previousTop = window.frame.maxY
      ReviewScreenFit.fit(screenFitted, in: window)
      contentView.layoutSubtreeIfNeeded()
      window.setContentSize(contentView.fittingSize)
      window.setFrameOrigin(NSPoint(
        x: window.frame.minX,
        y: ReviewDisclosureFit.originY(
          top: previousTop, height: window.frame.height, visibleFrame: visibleScreenFrame)
      ))
    }

    /// The visible area of the screen the panel is on, or of the main screen
    /// while it is not on one yet.
    private var visibleScreenFrame: NSRect? {
      (window.screen ?? NSScreen.main)?.visibleFrame
    }

    private func makeHeader() -> NSView {
      let icon = NSImageView()
      icon.image = NSImage(
        systemSymbolName: "lock.shield.fill",
        accessibilityDescription: "Convenient Security"
      )
      icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 30, weight: .medium)
        .applying(.init(hierarchicalColor: .controlAccentColor))
      icon.setContentHuggingPriority(.required, for: .horizontal)
      // Automation enrollment, a restore-only panel and a settings change keep
      // the large headline: for a release and for SSH the facts below are the
      // headline, and this line just names the kind of window.
      let largeHeadline = review.automation != nil || review.isRestoreOnly || review.settingsChange != nil
      if review.ssh != nil || largeHeadline {
        NSLayoutConstraint.activate([
          icon.widthAnchor.constraint(equalToConstant: 44),
          icon.heightAnchor.constraint(equalToConstant: 44),
        ])
      }

      let titleText: String
      if review.isRestoreOnly, let restore = review.restore {
        titleText = restore.header
      } else if let change = review.settingsChange {
        titleText = change.title
      } else if review.ssh != nil {
        titleText = "SSH Access Requested"
      } else {
        titleText = review.automation == nil
          ? ReviewDisplay.accessHeadline(for: review) : "Enable Unattended Automation"
      }
      let title: NSTextField
      if review.isRestoreOnly {
        // The only headline long enough to wrap: it names the restart cause.
        title = NSTextField(wrappingLabelWithString: titleText)
        title.maximumNumberOfLines = 2
        title.preferredMaxLayoutWidth = Self.innerWidth - 58
      } else {
        title = NSTextField(labelWithString: titleText)
      }
      let compact = !largeHeadline
      title.font = .systemFont(ofSize: compact ? 14 : 19, weight: .semibold)
      if compact {
        title.textColor = .secondaryLabelColor
      }
      if review.ssh == nil, !largeHeadline {
        icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 18, weight: .medium)
          .applying(.init(hierarchicalColor: .controlAccentColor))
        let header = NSStackView(views: [icon, title])
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 8
        NSLayoutConstraint.activate([
          icon.widthAnchor.constraint(equalToConstant: 24),
          icon.heightAnchor.constraint(equalToConstant: 24),
        ])
        return header
      }

      let purpose = NSTextField(
        wrappingLabelWithString: "“\(Self.safe(review.reason))”")
      purpose.font = .systemFont(ofSize: 13)
      purpose.textColor = .labelColor
      purpose.maximumNumberOfLines = 3
      purpose.preferredMaxLayoutWidth = Self.innerWidth - 58

      // The restore-only and settings headlines are their own purpose; the
      // terminal line under them names the request that raised them.
      let showsPurpose = review.ssh == nil && !review.isRestoreOnly && review.settingsChange == nil
      let labels = NSStackView(views: showsPurpose ? [title, purpose] : [title])
      labels.orientation = .vertical
      labels.alignment = .leading
      labels.spacing = 3
      labels.addArrangedSubview(makeTerminalLine(width: Self.innerWidth - 58))
      labels.setCustomSpacing(showsPurpose ? 5 : 3, after: showsPurpose ? purpose : title)

      let header = NSStackView(views: [icon, labels])
      header.orientation = .horizontal
      header.alignment = .centerY
      header.spacing = 14
      return header
    }

    /// Which terminal tab is asking. The title is the tab's self-reported one;
    /// the window/tab position and tty beside it are the part a process in the
    /// tab cannot forge. Shown on every variant of the window, including the
    /// "no terminal" case, which is itself worth a glance.
    private func makeTerminalLine(width: CGFloat) -> NSView {
      let icon = NSImageView()
      icon.image = NSImage(systemSymbolName: "terminal", accessibilityDescription: "Terminal")
      icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 11, weight: .medium)
      icon.contentTintColor = .secondaryLabelColor
      icon.setContentHuggingPriority(.required, for: .horizontal)
      icon.setContentCompressionResistancePriority(.required, for: .horizontal)

      let label = NSTextField(wrappingLabelWithString: Self.safe(review.caller.terminalSummary))
      label.font = .systemFont(ofSize: 12)
      label.textColor = .secondaryLabelColor
      label.maximumNumberOfLines = 2
      label.preferredMaxLayoutWidth = width - 20
      label.setAccessibilityLabel("Terminal: \(Self.safe(review.caller.terminalSummary))")

      let row = NSStackView(views: [icon, label])
      row.orientation = .horizontal
      row.alignment = .firstBaseline
      row.spacing = 6
      return row
    }

    // MARK: - SSH destination and key

    private func makeSSHIdentitySummary(_ ssh: SSHAccessReviewDetails) -> NSView {
      let width = Self.innerWidth - 36
      let host = Self.makeSSHFact(
        label: "Host", value: ssh.hostTitle,
        detail: "Sign in as \(ssh.remoteUser)", width: width,
        // "Unknown host" is a warning, not a name: it carries the banner's tint
        // so the largest fact in the window reads as one at a glance.
        valueColor: ssh.hostNames.isEmpty ? .systemOrange : .labelColor
      )
      host.toolTip = ssh.hostNames.joined(separator: ", ")
      let keyFact = Self.makeSSHFact(
        label: "SSH key", value: ssh.keyLabel, detail: ssh.keyAlgorithm, width: width
      )
      // Where the key resolves from decides which key signs: a provider's
      // notes and warnings (more than one 1Password account with its vault's
      // name) stand under it, as the release panel's secrets fact shows them,
      // never only inside the collapsed details.
      let provenance = Self.providerNotes(review.credentials.flatMap(\.secrets))
      let key = Self.verticalStack(spacing: 8)
      key.addArrangedSubview(keyFact)
      for note in provenance.notes {
        key.addArrangedSubview(Self.plainDetail(note, width: width))
      }
      for warning in provenance.warnings {
        key.addArrangedSubview(Self.inlineWarning(warning, width: width))
      }
      let separator = NSBox()
      separator.boxType = .separator
      separator.widthAnchor.constraint(equalToConstant: width).isActive = true

      let facts = NSStackView(views: [host, separator, key])
      facts.orientation = .vertical
      facts.alignment = .leading
      facts.spacing = 18

      return Self.paddedBox(
        content: facts, cornerRadius: 12,
        fill: NSColor.labelColor.withAlphaComponent(0.035),
        border: NSColor.separatorColor,
        horizontalPadding: 18, verticalPadding: 18, width: Self.innerWidth
      )
    }

    private static func makeSSHFact(
      label: String, value: String, detail: String, width: CGFloat,
      valueColor: NSColor = .labelColor
    ) -> NSView {
      let title = NSTextField(wrappingLabelWithString: value)
      title.font = .systemFont(ofSize: 28, weight: .semibold)
      title.textColor = valueColor
      title.lineBreakMode = .byWordWrapping
      title.preferredMaxLayoutWidth = width
      title.setAccessibilityLabel("\(label): \(value)")
      title.widthAnchor.constraint(equalToConstant: width).isActive = true

      let subtitle = NSTextField(wrappingLabelWithString: detail)
      subtitle.font = .systemFont(ofSize: 12)
      subtitle.textColor = .secondaryLabelColor
      subtitle.preferredMaxLayoutWidth = width

      let stack = NSStackView(views: [Self.makeSectionLabel(label), title, subtitle])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 5
      stack.widthAnchor.constraint(equalToConstant: width).isActive = true
      return stack
    }

    private func makeSSHRequestDetails(_ ssh: SSHAccessReviewDetails) -> NSView {
      let summary = NSTextField(wrappingLabelWithString: sshScopeSummaryText(ssh))
      summary.font = .systemFont(ofSize: 12)
      summary.textColor = .secondaryLabelColor
      summary.preferredMaxLayoutWidth = Self.innerWidth
      sshScopeSummaryLabel = summary

      let disclosure = NSButton(
        title: "Show details", target: self, action: #selector(toggleSSHDetails(_:))
      )
      disclosure.bezelStyle = .inline
      disclosure.controlSize = .small
      disclosure.font = .systemFont(ofSize: 12)
      disclosure.image = NSImage(systemSymbolName: "chevron.right", accessibilityDescription: nil)
      disclosure.imagePosition = .imageLeading
      interactiveControls.append(disclosure)

      // The one scroller here is this disclosure's own, so the card does not
      // nest a second one inside it. The key's provider notes and warnings
      // already stand under it in the summary above.
      let details = ReviewFittedList(
        width: Self.innerWidth, cue: Self.detailsOverflowCue
      ) { [weak self] width in self?.makeSSHDetailsBody(ssh, width: width) ?? NSView() }
      details.view.isHidden = true
      sshDetailsView = details.view
      screenFitted.append(details)

      let stack = NSStackView(views: [summary, disclosure, details.view])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 8
      stack.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
      return stack
    }

    /// What the SSH details hold, `width` wide: the known hosts when the
    /// summary names only some, the key's card and the request grid.
    private func makeSSHDetailsBody(_ ssh: SSHAccessReviewDetails, width: CGFloat) -> NSView {
      let details = NSStackView()
      details.orientation = .vertical
      details.alignment = .leading
      details.spacing = 10
      if ssh.hostNames.count > 2 {
        let hosts = Self.gridValue("Known hosts: \(ssh.hostNames.joined(separator: ", "))")
        hosts.maximumNumberOfLines = 0
        hosts.preferredMaxLayoutWidth = width
        details.addArrangedSubview(hosts)
      }
      details.addArrangedSubview(makeSecretsCard(width: width, showsProviderNotes: false))
      details.addArrangedSubview(makeDetailsGrid())
      details.widthAnchor.constraint(equalToConstant: width).isActive = true
      return details
    }

    /// What each list's overflow cue says (`ReviewFittedList`).
    private static let secretsOverflowCue =
      "This list is longer than the panel can show. Scroll it to see every secret."
    private static let restoreOverflowCue =
      "This list is longer than the panel can show. Scroll it to see every approval."
    private static let detailsOverflowCue =
      "These details are longer than the panel can show. Scroll them to read all of them."

    /// The lifetime the window currently reflects: the live popup selection, else
    /// the plan's requested lifetime (nil requested ⇒ process lifetime).
    private var currentDuration: GrantDuration {
      if let selectedDuration { return selectedDuration }
      if let seconds = review.plan.requestedTTLSeconds { return .bounded(seconds: seconds) }
      return .processLifetime
    }

    private func sshScopeSummaryText(_ ssh: SSHAccessReviewDetails) -> String {
      let scope = review.scopeChoices?.resolved(selectedID: selectedScopeOptionID)
      // The live selection, not the requested TTL: this sentence and the "For"
      // popup must never state two different lifetimes.
      // An unknown host is already stated by the banner and the tinted
      // headline; repeating it here in weaker words would only dilute it.
      let context = ssh.hostNames.isEmpty ? "" : " \(ssh.hostContext)"
      return ReviewDisplay.sshScopeSummary(scope, duration: currentDuration) + context
    }

    @objc private func toggleSSHDetails(_ sender: NSButton) {
      guard let details = sshDetailsView else { return }
      let expanding = details.isHidden
      // As the release panel's delivery details do, the window grows to show
      // all of them; they scroll only in what a smaller screen leaves
      // (`resizeToFitPreservingTop`).
      details.isHidden = !expanding
      sender.title = expanding ? "Hide details" : "Show details"
      sender.image = NSImage(
        systemSymbolName: expanding ? "chevron.down" : "chevron.right",
        accessibilityDescription: nil
      )
      resizeToFitPreservingTop()
    }

    private static func makeSectionLabel(_ text: String) -> NSTextField {
      let label = NSTextField(labelWithString: text.uppercased())
      label.font = .systemFont(ofSize: 11, weight: .semibold)
      label.textColor = .secondaryLabelColor
      return label
    }

    private static func makeBanner(text: String, tint: NSColor, width: CGFloat) -> NSView {
      let icon = NSImageView()
      icon.image = NSImage(
        systemSymbolName: "exclamationmark.triangle.fill",
        accessibilityDescription: "Warning"
      )
      icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 16, weight: .semibold)
      icon.contentTintColor = tint
      icon.setContentHuggingPriority(.required, for: .horizontal)
      icon.setContentCompressionResistancePriority(.required, for: .horizontal)

      let label = NSTextField(wrappingLabelWithString: text)
      label.font = .systemFont(ofSize: 12, weight: .semibold)
      label.textColor = tint
      label.maximumNumberOfLines = 14
      label.preferredMaxLayoutWidth = width - 60

      let content = NSStackView(views: [icon, label])
      content.orientation = .horizontal
      content.alignment = .top
      content.spacing = 10

      return Self.card(
        wrapping: content,
        fill: tint.withAlphaComponent(0.09),
        border: tint.withAlphaComponent(0.35),
        width: width
      )
    }

    private static func makeAutomationWarning(width: CGFloat) -> NSView {
      let tint = NSColor.systemRed

      let icon = NSImageView()
      icon.image = NSImage(
        systemSymbolName: "exclamationmark.triangle.fill",
        accessibilityDescription: "Warning"
      )
      icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 16, weight: .semibold)
      icon.contentTintColor = tint
      icon.setContentHuggingPriority(.required, for: .horizontal)
      icon.setContentCompressionResistancePriority(.required, for: .horizontal)

      let title = NSTextField(labelWithString: DeliveryReviewCopy.automationWarningTitle)
      title.font = .systemFont(ofSize: 12, weight: .semibold)
      title.textColor = tint

      let explanation = NSTextField(
        wrappingLabelWithString: DeliveryReviewCopy.automationWarningExplanation
      )
      explanation.font = .systemFont(ofSize: 12)
      explanation.textColor = .labelColor
      explanation.maximumNumberOfLines = 6
      explanation.preferredMaxLayoutWidth = width - 60

      let copy = NSStackView(views: [title, explanation])
      copy.orientation = .vertical
      copy.alignment = .leading
      copy.spacing = 3

      let content = NSStackView(views: [icon, copy])
      content.orientation = .horizontal
      content.alignment = .top
      content.spacing = 10

      return Self.card(
        wrapping: content,
        fill: tint.withAlphaComponent(0.09),
        border: tint.withAlphaComponent(0.35),
        width: width
      )
    }

    /// A rounded, filled container that pads `content`. NSBox is used because
    /// its fill/border colors stay appearance-aware, unlike raw layer colors.
    private static func paddedBox(
      content: NSView,
      cornerRadius: CGFloat,
      fill: NSColor,
      border: NSColor?,
      horizontalPadding: CGFloat,
      verticalPadding: CGFloat,
      width: CGFloat? = nil
    ) -> NSView {
      let box = NSBox()
      box.boxType = .custom
      box.titlePosition = .noTitle
      box.cornerRadius = cornerRadius
      box.fillColor = fill
      box.borderColor = border ?? .clear
      box.borderWidth = border == nil ? 0 : 1
      box.contentViewMargins = .zero
      box.translatesAutoresizingMaskIntoConstraints = false

      let host: NSView
      if let existing = box.contentView {
        host = existing
      } else {
        host = NSView()
        box.contentView = host
      }
      // Pinned inside the border rather than left to the box's autoresizing:
      // a box whose content view keeps its autoresizing constraints measures
      // a few points off from how it lays out, so a column of cards was
      // fitted to one height and drawn at another (csec-lz39).
      host.translatesAutoresizingMaskIntoConstraints = false
      content.translatesAutoresizingMaskIntoConstraints = false
      host.addSubview(content)
      NSLayoutConstraint.activate([
        host.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: box.borderWidth),
        host.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -box.borderWidth),
        host.topAnchor.constraint(equalTo: box.topAnchor, constant: box.borderWidth),
        host.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -box.borderWidth),
        content.leadingAnchor.constraint(equalTo: host.leadingAnchor, constant: horizontalPadding),
        content.trailingAnchor.constraint(
          equalTo: host.trailingAnchor, constant: -horizontalPadding),
        content.topAnchor.constraint(equalTo: host.topAnchor, constant: verticalPadding),
        content.bottomAnchor.constraint(equalTo: host.bottomAnchor, constant: -verticalPadding),
      ])
      if let width {
        box.widthAnchor.constraint(equalToConstant: width).isActive = true
      }
      return box
    }

    private static func card(
      wrapping content: NSView,
      fill: NSColor,
      border: NSColor,
      width: CGFloat?
    ) -> NSView {
      paddedBox(
        content: content,
        cornerRadius: 9,
        fill: fill,
        border: border,
        horizontalPadding: 12,
        verticalPadding: 10,
        width: width
      )
    }

    private static func assuranceTint(_ assurance: ConsumerAssurance) -> NSColor {
      switch assurance {
      case .verifiedProduct, .independentlyProtected: return .systemGreen
      case .sealed: return .systemBlue
      case .userWritable, .unverified: return .systemOrange
      }
    }

    // MARK: - Secrets (source › container › item › field)

    /// The automation and SSH layouts' secrets: the tree in one card. The
    /// automation layout shows it in a list that scrolls only past the screen,
    /// the SSH layout inside its details. Without `showsProviderNotes` the card
    /// leaves the providers' notes and warnings to a part of the panel that is
    /// always shown.
    private func makeSecretsCard(width: CGFloat, showsProviderNotes: Bool = true) -> NSView {
      // Inside the card's 12-point padding and 1-point border.
      let tree = Self.makeSecretTree(
        review.credentials.flatMap(\.secrets), width: width - 26, showsProviderNotes: showsProviderNotes)
      return Self.card(
        wrapping: tree,
        fill: NSColor.labelColor.withAlphaComponent(0.045),
        border: NSColor.separatorColor,
        width: width
      )
    }

    /// How far each level of the secret tree sits inside the one above it:
    /// the source line's dot and the space after it, so a child starts where
    /// its parent's text does.
    private static let secretTreeIndent: CGFloat = 16

    /// A review's secrets as one tree (`ReviewSecretTree`): each source, a
    /// provider and the account it resolves from, once; its vaults or stores
    /// beneath it, a single one sharing the source's line; and each item a
    /// label in its source's colour, its fields at the right. The release
    /// card, the automation and SSH card and every restore row draw this, so
    /// a secret reads the same wherever a panel names it. Nothing is elided:
    /// every name wraps rather than truncates. Without `showsProviderNotes`
    /// each container lists only its items, its notes and warnings drawn
    /// elsewhere on the panel (`providerNotes`).
    private static func makeSecretTree(
      _ secrets: [ReviewSecret], width: CGFloat, showsProviderNotes: Bool = true
    ) -> NSView {
      let tree = ReviewSecretTree(secrets)
      func body(_ container: ReviewSecretTree.Container, tint: ReviewSecretTint, width: CGFloat) -> NSView {
        secretContainerBody(container, tint: tint, width: width, showsProviderNotes: showsProviderNotes)
      }
      let indent = secretTreeIndent
      let stack = verticalStack(spacing: 13)
      for source in tree.sources {
        let node = verticalStack(spacing: 5)
        if source.title == nil {
          // References no provider described: listed bare, under no source.
          for container in source.containers {
            node.addArrangedSubview(body(container, tint: source.tint, width: width))
          }
        } else if source.foldsContainer, let container = source.containers.first {
          node.addArrangedSubview(secretSourceLine(source, container: container.name, width: width))
          node.addArrangedSubview(indented(
            body(container, tint: source.tint, width: width - indent), by: indent, width: width
          ))
        } else {
          node.addArrangedSubview(secretSourceLine(source, container: nil, width: width))
          let containers = verticalStack(spacing: 9)
          for container in source.containers {
            let group = verticalStack(spacing: 5)
            var bodyIndent: CGFloat = 0
            if let name = container.name {
              group.addArrangedSubview(secretContainerLine(name, width: width - indent))
              bodyIndent = indent
            }
            group.addArrangedSubview(indented(
              body(container, tint: source.tint, width: width - indent - bodyIndent),
              by: bodyIndent, width: width - indent
            ))
            containers.addArrangedSubview(group)
          }
          node.addArrangedSubview(indented(containers, by: indent, width: width))
        }
        stack.addArrangedSubview(node)
      }
      stack.widthAnchor.constraint(equalToConstant: width).isActive = true
      return stack
    }

    /// Every provider note and warning the tree's containers carry, once
    /// each, in the order the tree names them: what a panel shows outside the
    /// tree when it draws the tree with `showsProviderNotes` false.
    private static func providerNotes(
      _ secrets: [ReviewSecret]
    ) -> (notes: [String], warnings: [String]) {
      var notes: [String] = []
      var warnings: [String] = []
      for container in ReviewSecretTree(secrets).sources.flatMap(\.containers) {
        for note in container.notes where !notes.contains(note) { notes.append(note) }
        for warning in container.warnings where !warnings.contains(warning) { warnings.append(warning) }
      }
      return (notes, warnings)
    }

    private static func verticalStack(spacing: CGFloat) -> NSStackView {
      let stack = NSStackView()
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = spacing
      stack.translatesAutoresizingMaskIntoConstraints = false
      return stack
    }

    private static func indented(_ view: NSView, by inset: CGFloat, width: CGFloat) -> NSView {
      let wrapper = NSStackView(views: [view])
      wrapper.orientation = .vertical
      wrapper.alignment = .leading
      wrapper.edgeInsets = NSEdgeInsets(top: 0, left: inset, bottom: 0, right: 0)
      wrapper.translatesAutoresizingMaskIntoConstraints = false
      wrapper.widthAnchor.constraint(equalToConstant: width).isActive = true
      return wrapper
    }

    /// "● 1Password · acme.1password.eu › Employee": the source in its
    /// colour's dot, its provider, the account, and — when the source has one
    /// vault or store — that container, which then needs no line of its own.
    private static func secretSourceLine(
      _ source: ReviewSecretTree.Source, container: String?, width: CGFloat
    ) -> NSView {
      let secondary: [NSAttributedString.Key: Any] = [
        .font: NSFont.systemFont(ofSize: 12), .foregroundColor: NSColor.secondaryLabelColor,
      ]
      let text = NSMutableAttributedString(
        string: "●  ",
        attributes: [
          .font: NSFont.systemFont(ofSize: 9),
          .foregroundColor: secretLabelColors(source.tint).text,
          .baselineOffset: 1,
        ]
      )
      if let provider = source.provider {
        text.append(NSAttributedString(
          string: provider,
          attributes: secondary.merging([.font: NSFont.systemFont(ofSize: 12, weight: .semibold)]) { $1 }
        ))
      }
      if let account = source.account {
        text.append(NSAttributedString(string: source.provider == nil ? account : " · \(account)", attributes: secondary))
      }
      if let container {
        text.append(NSAttributedString(
          string: "  ›  ",
          attributes: secondary.merging([.foregroundColor: NSColor.tertiaryLabelColor]) { $1 }
        ))
        text.append(NSAttributedString(string: container, attributes: secretContainerAttributes))
      }
      let line = NSTextField(wrappingLabelWithString: "")
      line.attributedStringValue = text
      line.maximumNumberOfLines = 0
      line.preferredMaxLayoutWidth = width
      return line
    }

    private static var secretContainerAttributes: [NSAttributedString.Key: Any] {
      [.font: NSFont.systemFont(ofSize: 12.5, weight: .medium), .foregroundColor: NSColor.labelColor]
    }

    /// A vault or store on its own line, when its source has several.
    private static func secretContainerLine(_ name: String, width: CGFloat) -> NSView {
      let line = NSTextField(wrappingLabelWithString: "")
      line.attributedStringValue = NSAttributedString(string: name, attributes: secretContainerAttributes)
      line.maximumNumberOfLines = 0
      line.preferredMaxLayoutWidth = width
      return line
    }

    /// What one vault or store holds: the provider's notes and warnings about
    /// where its values resolve from, unless the panel draws them elsewhere,
    /// then its items.
    private static func secretContainerBody(
      _ container: ReviewSecretTree.Container, tint: ReviewSecretTint, width: CGFloat,
      showsProviderNotes: Bool = true
    ) -> NSView {
      let body = verticalStack(spacing: 5)
      if showsProviderNotes {
        for note in container.notes {
          body.addArrangedSubview(plainDetail(note, width: width))
        }
        for warning in container.warnings {
          body.addArrangedSubview(inlineWarning(warning, width: width))
        }
      }
      // Items with fields take a row each, their fields at the right; items
      // that are themselves the secret (a store's keys) wrap left to right,
      // so a store asked for twenty keys reads at a glance instead of
      // scrolling as a column.
      var flowing: [NSView] = []
      func flush() {
        guard !flowing.isEmpty else { return }
        body.addArrangedSubview(WrappingFlowView(
          items: flowing, width: width, horizontalSpacing: 6, verticalSpacing: 5
        ))
        flowing = []
      }
      for item in container.items {
        if item.fields.isEmpty {
          flowing.append(secretItemRow(item, tint: tint, width: width))
        } else {
          flush()
          body.addArrangedSubview(secretItemRow(item, tint: tint, width: width))
        }
      }
      flush()
      return body
    }

    /// One item: its label at the left, its fields at the right on the same
    /// line, or right-aligned on the next when both do not fit.
    private static func secretItemRow(
      _ item: ReviewSecretTree.Item, tint: ReviewSecretTint, width: CGFloat
    ) -> NSView {
      let labelFont: NSFont = item.isIdentifier
        ? .monospacedSystemFont(ofSize: 13.5, weight: .semibold)
        : .systemFont(ofSize: 14.5, weight: .semibold)
      let labelPadding: CGFloat = 16
      let gap: CGFloat = 16
      let fieldsText = item.fields.joined(separator: " · ")
      let fieldFont = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
      let nameWidth = singleLineWidth(item.name, font: labelFont)
      let fieldsWidth = singleLineWidth(fieldsText, font: fieldFont)
      let oneLine = nameWidth + labelPadding + (fieldsText.isEmpty ? 0 : gap + fieldsWidth) <= width

      let label = secretLabel(
        item.name, spoken: item.spokenName, font: labelFont, tint: tint, maxTextWidth: width - labelPadding
      )
      guard !fieldsText.isEmpty else { return label }

      let fields = NSTextField(wrappingLabelWithString: fieldsText)
      fields.font = fieldFont
      fields.textColor = .secondaryLabelColor
      fields.alignment = .right
      fields.maximumNumberOfLines = 0
      fields.preferredMaxLayoutWidth = oneLine ? fieldsWidth : width
      fields.setContentHuggingPriority(.required, for: .horizontal)

      let spacer = NSView()
      spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
      if oneLine {
        let row = NSStackView(views: [label, spacer, fields])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = gap
        row.translatesAutoresizingMaskIntoConstraints = false
        row.widthAnchor.constraint(equalToConstant: width).isActive = true
        return row
      }
      let fieldsRow = NSStackView(views: [spacer, fields])
      fieldsRow.orientation = .horizontal
      fieldsRow.translatesAutoresizingMaskIntoConstraints = false
      fieldsRow.widthAnchor.constraint(equalToConstant: width).isActive = true
      let stack = verticalStack(spacing: 3)
      stack.addArrangedSubview(label)
      stack.addArrangedSubview(fieldsRow)
      return stack
    }

    /// How wide a single-line label shows `text`, its text field's own insets
    /// included.
    private static func singleLineWidth(_ text: String, font: NSFont) -> CGFloat {
      guard !text.isEmpty else { return 0 }
      let probe = NSTextField(labelWithString: text)
      probe.font = font
      return ceil(probe.intrinsicContentSize.width)
    }

    /// An item's name as a label tinted by its source. Its identifier names
    /// the tint (`csec.secretLabel.<tint>`) so tests can find it.
    /// A name that fits on one line is a single-line label; only a longer one
    /// wraps, at `maxTextWidth`. The box states its own size, worked out from
    /// the text, so a layout that measures it early (`WrappingFlowView`) gets
    /// the size the name needs instead of a squeezed one that clips it.
    private static func secretLabel(
      _ name: String, spoken: String, font: NSFont, tint: ReviewSecretTint, maxTextWidth: CGFloat
    ) -> NSView {
      let colors = secretLabelColors(tint)
      let text: NSTextField
      let textSize: NSSize
      if singleLineWidth(name, font: font) <= maxTextWidth {
        text = NSTextField(labelWithString: name)
        text.font = font
        textSize = text.intrinsicContentSize
      } else {
        text = NSTextField(wrappingLabelWithString: name)
        text.font = font
        text.maximumNumberOfLines = 0
        text.preferredMaxLayoutWidth = maxTextWidth
        textSize = NSSize(
          width: maxTextWidth,
          height: text.cell?.cellSize(forBounds: NSRect(
            x: 0, y: 0, width: maxTextWidth, height: .greatestFiniteMagnitude
          )).height ?? text.intrinsicContentSize.height
        )
      }
      text.textColor = colors.text
      text.setAccessibilityLabel(spoken)
      let horizontalPadding: CGFloat = 8
      let verticalPadding: CGFloat = 3
      let border: CGFloat = 1
      let box = paddedBox(
        content: text, cornerRadius: 6, fill: colors.fill, border: colors.edge,
        horizontalPadding: horizontalPadding, verticalPadding: verticalPadding
      )
      NSLayoutConstraint.activate([
        box.widthAnchor.constraint(
          equalToConstant: ceil(textSize.width) + 2 * (horizontalPadding + border)),
        box.heightAnchor.constraint(
          equalToConstant: ceil(textSize.height) + 2 * (verticalPadding + border)),
      ])
      box.identifier = NSUserInterfaceItemIdentifier("csec.secretLabel.\(tint.rawValue)")
      return box
    }

    /// A label's text, fill and edge colours for `tint` in the panel's
    /// appearance, from the values the phone draws with too.
    private static func secretLabelColors(_ tint: ReviewSecretTint) -> (text: NSColor, fill: NSColor, edge: NSColor) {
      func dynamic(_ pick: @escaping @Sendable (ReviewSecretTint.Palette) -> NSColor) -> NSColor {
        NSColor(name: nil) { appearance in
          pick(tint.palette(dark: appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua))
        }
      }
      @Sendable func color(_ rgb: ReviewSecretTint.RGB, alpha: Double = 1) -> NSColor {
        NSColor(srgbRed: rgb.red, green: rgb.green, blue: rgb.blue, alpha: alpha)
      }
      return (
        dynamic { color($0.text) },
        dynamic { color($0.base, alpha: $0.fillAlpha) },
        dynamic { color($0.base, alpha: $0.edgeAlpha) }
      )
    }

    // MARK: - Restore (approvals csecd held before it restarted)

    /// One card per approval the touch reopens: who it was for, the scope the
    /// human chose, and its references (or its SSH key, server and user). The
    /// section offers nothing to choose: a restore approves nothing new. On a
    /// mixed panel it also says that the one Deny forgets these rows too.
    /// The settings layout's one card: each change on its own line.
    private static func makeSettingsChanges(
      _ change: SettingsChangeReviewDetails, width: CGFloat
    ) -> NSView {
      let lines = NSStackView()
      lines.orientation = .vertical
      lines.alignment = .leading
      lines.spacing = 8
      for text in change.changes {
        let bullet = NSTextField(labelWithString: "•")
        bullet.font = .systemFont(ofSize: 13, weight: .semibold)
        bullet.textColor = .secondaryLabelColor
        bullet.setContentHuggingPriority(.required, for: .horizontal)
        // Never truncated: the touch approves all of it, so all of it must
        // be readable. `SettingsChangeReviewDetails` bounds each line.
        let line = NSTextField(wrappingLabelWithString: safe(text))
        line.font = .systemFont(ofSize: 13)
        line.textColor = .labelColor
        line.maximumNumberOfLines = 0
        line.preferredMaxLayoutWidth = width - 44
        let row = NSStackView(views: [bullet, line])
        row.orientation = .horizontal
        row.alignment = .firstBaseline
        row.spacing = 6
        lines.addArrangedSubview(row)
      }
      return card(
        wrapping: lines,
        fill: NSColor.labelColor.withAlphaComponent(0.045),
        border: NSColor.separatorColor,
        width: width
      )
    }

    private func makeRestoreSection(_ restore: RestoreReviewDetails, width: CGFloat) -> NSView {
      // Every approval the touch reopens, whole unless the screen is too
      // short for them (`ReviewFittedList`).
      let restoreRows = restore.rows
      let rows = ReviewFittedList(width: width, cue: Self.restoreOverflowCue) { width in
        let rows = NSStackView()
        rows.orientation = .vertical
        rows.alignment = .leading
        rows.spacing = 8
        for row in restoreRows {
          rows.addArrangedSubview(Self.makeRestoreRow(row, width: width))
        }
        return rows
      }
      screenFitted.append(rows)
      let rowsView = rows.view

      let heading = Self.makeSectionLabel(
        review.isRestoreOnly ? "Approvals to reopen" : "Also reopens, after csecd restarted"
      )
      let section = NSStackView(views: [heading, rowsView])
      section.orientation = .vertical
      section.alignment = .leading
      section.spacing = 6
      if !review.isRestoreOnly {
        // This panel's touch also approves the new request above, so its
        // note never says that nothing new is approved.
        section.addArrangedSubview(Self.plainDetail(restore.mixedFootnote, width: width))
      }
      section.widthAnchor.constraint(equalToConstant: width).isActive = true
      return section
    }

    private static func makeRestoreRow(_ row: RestoreReviewRow, width: CGFloat) -> NSView {
      // Inside the card's 12-point padding and 1-point border.
      let innerWidth = width - 26
      let stack = NSStackView()
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 5

      let icon = NSImageView()
      let symbol: String
      switch row.kind {
      case .secretGrant: symbol = "key.fill"
      case .sshGrant: symbol = "network"
      case .pairedProject: symbol = "folder.fill"
      }
      icon.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
      icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 12, weight: .medium)
      icon.contentTintColor = .secondaryLabelColor
      icon.setContentHuggingPriority(.required, for: .horizontal)
      let title = NSTextField(labelWithString: Self.safe(row.title))
      title.font = .systemFont(ofSize: 13, weight: .semibold)
      title.lineBreakMode = .byTruncatingTail
      let header = NSStackView(views: [icon, title])
      header.orientation = .horizontal
      header.alignment = .centerY
      header.spacing = 6
      stack.addArrangedSubview(header)
      stack.addArrangedSubview(Self.plainDetail(Self.safe(row.detail), width: innerWidth))

      if let ssh = row.ssh {
        let line = NSTextField(
          wrappingLabelWithString: Self.safe(
            "SSH as \(ssh.remoteUser) to \(ssh.hostTitle) using \(ssh.keyLabel)"
          )
        )
        line.font = .systemFont(ofSize: 12, weight: .medium)
        line.maximumNumberOfLines = 3
        line.preferredMaxLayoutWidth = innerWidth
        stack.addArrangedSubview(line)
      } else {
        stack.addArrangedSubview(Self.makeSecretTree(row.secrets, width: innerWidth))
      }

      return Self.card(
        wrapping: stack,
        fill: NSColor.labelColor.withAlphaComponent(0.045),
        border: NSColor.separatorColor,
        width: width
      )
    }

    // MARK: - Release facts (terminal tab · command · secrets)

    private func makeReleaseFacts(width: CGFloat) -> NSView {
      // Inside the box's 16-point padding and 1-point border.
      let innerWidth = width - 34
      let facts = NSStackView()
      facts.orientation = .vertical
      facts.alignment = .leading
      facts.spacing = 12

      let terminal = ReviewDisplay.terminalFact(review.caller.terminal ?? .unidentified)
      facts.addArrangedSubview(Self.makeFact(
        label: "Terminal tab",
        value: Self.plainValue(Self.safe(terminal.title), size: 22, monospaced: false, width: innerWidth),
        detail: Self.plainDetail(Self.safe(terminal.detail), width: innerWidth),
        width: innerWidth
      ))
      facts.addArrangedSubview(Self.factSeparator(width: innerWidth))
      facts.addArrangedSubview(Self.makeFact(
        label: "Command",
        value: review.commandLine.map { makeCommandValue($0, width: innerWidth) }
          ?? makeReasonValue(width: innerWidth),
        detail: makeCommandDetail(width: innerWidth),
        width: innerWidth
      ))
      facts.addArrangedSubview(Self.factSeparator(width: innerWidth))
      facts.addArrangedSubview(makeSecretsFact(width: innerWidth))

      return Self.paddedBox(
        content: facts, cornerRadius: 12,
        fill: NSColor.labelColor.withAlphaComponent(0.035),
        border: NSColor.separatorColor,
        horizontalPadding: 16, verticalPadding: 14, width: width
      )
    }

    private static func factSeparator(width: CGFloat) -> NSView {
      let separator = NSBox()
      separator.boxType = .separator
      separator.widthAnchor.constraint(equalToConstant: width).isActive = true
      return separator
    }

    private static func makeFact(
      label: String, value: NSView, detail: NSView, width: CGFloat
    ) -> NSView {
      let stack = NSStackView(views: [makeSectionLabel(label), value, detail])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 3
      stack.setCustomSpacing(5, after: stack.arrangedSubviews[0])
      stack.widthAnchor.constraint(equalToConstant: width).isActive = true
      return stack
    }

    /// A headline value that wraps rather than truncates: it is the authoritative
    /// display of an attacker-influenced string, so nothing may be elided.
    private static func plainValue(
      _ text: String, size: CGFloat, monospaced: Bool, width: CGFloat
    ) -> NSTextField {
      let value = NSTextField(wrappingLabelWithString: text)
      value.font = monospaced
        ? .monospacedSystemFont(ofSize: size, weight: .semibold)
        : .systemFont(ofSize: size, weight: .semibold)
      value.textColor = .labelColor
      value.maximumNumberOfLines = 4
      value.preferredMaxLayoutWidth = width
      value.widthAnchor.constraint(equalToConstant: width).isActive = true
      return value
    }

    private static func plainDetail(_ text: String, width: CGFloat) -> NSTextField {
      let detail = NSTextField(wrappingLabelWithString: text)
      detail.font = .systemFont(ofSize: 12)
      detail.textColor = .secondaryLabelColor
      detail.maximumNumberOfLines = 3
      detail.preferredMaxLayoutWidth = width
      return detail
    }

    /// Marks the requester's own command line under its reason, so a test can
    /// find it.
    static let requesterCommandLineIdentifier = NSUserInterfaceItemIdentifier("csec.requester-command-line")

    /// A request with no argv of its own: the reason its requester wrote, and
    /// under it, when csecd could read it, that requester's real command line
    /// (`AccessPolicyReview.requesterCommandLine`). The reason is the one
    /// thing on the panel the requester chose; the command line is what lets
    /// the reader see a request that is not what it says.
    private func makeReasonValue(width: CGFloat) -> NSView {
      let reason = Self.plainValue(Self.safe(review.reason), size: 19, monospaced: true, width: width)
      guard let command = review.requesterCommandLine else { return reason }
      let caption = NSTextField(labelWithString: "Process command line")
      caption.font = .systemFont(ofSize: 11, weight: .medium)
      caption.textColor = .secondaryLabelColor
      let line = NSStackView(views: [caption, makeCommandValue(command, width: width)])
      line.orientation = .vertical
      line.alignment = .leading
      line.spacing = 2
      line.identifier = Self.requesterCommandLineIdentifier
      let stack = NSStackView(views: [reason, line])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 8
      stack.widthAnchor.constraint(equalToConstant: width).isActive = true
      return stack
    }

    /// How many lines of a command show before the reader has to ask for the
    /// rest.
    private static let commandPreviewLines = 4

    /// The full command line, already redacted and sanitized by csecd. A short
    /// one is simply a wrapping label. A long one shows its first lines with a
    /// "Show full command" disclosure that swaps in the complete, selectable
    /// text, as tall as the screen allows (`ReviewCommandText`) — nothing is
    /// ever silently cut.
    private func makeCommandValue(_ command: String, width: CGFloat) -> NSView {
      let font = NSFont.monospacedSystemFont(ofSize: 13, weight: .semibold)
      let preview = NSTextField(wrappingLabelWithString: command)
      preview.font = font
      preview.textColor = .labelColor
      preview.maximumNumberOfLines = Self.commandPreviewLines
      preview.lineBreakMode = .byWordWrapping
      preview.cell?.truncatesLastVisibleLine = true
      preview.preferredMaxLayoutWidth = width
      preview.widthAnchor.constraint(equalToConstant: width).isActive = true

      let fullHeight = Self.textHeight(command, font: font, width: width)
      let previewHeight = Self.textHeight(
        Array(repeating: "x", count: Self.commandPreviewLines).joined(separator: "\n"),
        font: font, width: width
      )
      guard fullHeight > previewHeight + 0.5 else { return preview }

      let full = Self.commandText(command, font: font, width: width)
      full.scrollView.isHidden = true
      commandPreviewView = preview
      commandFullText = full
      screenFitted.append(full)

      let disclosure = NSButton(
        title: "Show full command", target: self, action: #selector(toggleFullCommand(_:))
      )
      disclosure.bezelStyle = .inline
      disclosure.controlSize = .small
      disclosure.font = .systemFont(ofSize: 12)
      // Keyboard-reachable like every other disclosure: initial focus is pinned
      // to Deny in `configureWindow`, so this one no longer has to refuse it.
      disclosure.image = NSImage(systemSymbolName: "chevron.right", accessibilityDescription: nil)
      disclosure.imagePosition = .imageLeading
      interactiveControls.append(disclosure)

      let stack = NSStackView(views: [preview, full.scrollView, full.overflowCue, disclosure])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 4
      stack.widthAnchor.constraint(equalToConstant: width).isActive = true
      return stack
    }

    @objc private func toggleFullCommand(_ sender: NSButton) {
      guard let preview = commandPreviewView, let full = commandFullText else { return }
      let expanding = full.scrollView.isHidden
      full.scrollView.isHidden = !expanding
      preview.isHidden = expanding
      // Sized with the panel's other long views (`resizeToFitPreservingTop`).
      sender.title = expanding ? "Hide full command" : "Show full command"
      sender.image = NSImage(
        systemSymbolName: expanding ? "chevron.down" : "chevron.right",
        accessibilityDescription: nil
      )
      resizeToFitPreservingTop()
    }

    /// Height of `text` wrapped to `width` in `font`, as a label would lay it out.
    private static func textHeight(_ text: String, font: NSFont, width: CGFloat) -> CGFloat {
      let bounds = (text as NSString).boundingRect(
        with: NSSize(width: width, height: .greatestFiniteMagnitude),
        options: [.usesLineFragmentOrigin, .usesFontLeading],
        attributes: [.font: font]
      )
      return ceil(bounds.height)
    }

    /// "launcher [verified] (pid 65541) for ls [unverified]  UNVERIFIED": who asked
    /// on whose behalf, with the consuming executable's assurance as the one
    /// colored signal on the line.
    private func makeCommandDetail(width: CGFloat) -> NSTextField {
      let plan = review.plan
      let text = NSMutableAttributedString(
        string: Self.safe(review.caller.description),
        attributes: [
          .font: NSFont.systemFont(ofSize: 12),
          .foregroundColor: NSColor.secondaryLabelColor,
        ]
      )
      text.append(NSAttributedString(
        string: "  \(ReviewDisplay.assurance(plan.executable.assurance).uppercased())",
        attributes: [
          .font: NSFont.systemFont(ofSize: 10, weight: .bold),
          .foregroundColor: Self.assuranceTint(plan.executable.assurance),
        ]
      ))
      let detail = NSTextField(labelWithAttributedString: text)
      detail.lineBreakMode = .byWordWrapping
      detail.cell?.wraps = true
      detail.cell?.isScrollable = false
      detail.maximumNumberOfLines = 3
      detail.preferredMaxLayoutWidth = width
      detail.toolTip = Self.safe(plan.executable.canonicalPath)
      detail.widthAnchor.constraint(equalToConstant: width).isActive = true
      return detail
    }

    /// Which secrets the touch releases (or lets csecd use, for a daemon-proxy
    /// review), as the secret tree, under the same section label as the tab
    /// and the command. The list is as long as it is; only a screen too short
    /// for the panel makes it scroll, with its scroller drawn and a cue
    /// saying so (`ReviewFittedList`).
    private func makeSecretsFact(width: CGFloat) -> NSView {
      let secrets = review.credentials.flatMap(\.secrets)
      let heading = Self.makeSectionLabel(ReviewDisplay.secretsHeading(for: review, count: secrets.count))
      let tree = ReviewFittedList(width: width, cue: Self.secretsOverflowCue) { width in
        Self.makeSecretTree(secrets, width: width)
      }
      screenFitted.append(tree)

      let stack = NSStackView(views: [heading, tree.view])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 7
      stack.widthAnchor.constraint(equalToConstant: width).isActive = true
      return stack
    }

    private static func inlineWarning(_ text: String, width: CGFloat) -> NSView {
      let icon = NSImageView()
      icon.image = NSImage(
        systemSymbolName: "exclamationmark.triangle.fill",
        accessibilityDescription: "Warning"
      )
      icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 12, weight: .semibold)
      icon.contentTintColor = .systemOrange
      icon.setContentHuggingPriority(.required, for: .horizontal)
      icon.setContentCompressionResistancePriority(.required, for: .horizontal)

      let label = NSTextField(wrappingLabelWithString: text)
      label.font = .systemFont(ofSize: 12, weight: .semibold)
      label.textColor = .systemOrange
      label.maximumNumberOfLines = 6
      label.preferredMaxLayoutWidth = width - 22

      let row = NSStackView(views: [icon, label])
      row.orientation = .horizontal
      row.alignment = .top
      row.spacing = 6
      row.widthAnchor.constraint(equalToConstant: width).isActive = true
      return row
    }

    // MARK: - Grant (scope · duration)

    private func makeGrantCard(width: CGFloat) -> NSView {
      let innerWidth = width - 28
      let labelWidth: CGFloat = 64
      let grid = NSGridView()
      grid.columnSpacing = 14
      grid.rowSpacing = 12
      grid.rowAlignment = .none
      grid.xPlacement = .leading
      grid.yPlacement = .top
      grid.translatesAutoresizingMaskIntoConstraints = false

      let scopeLabel = Self.makeSectionLabel("Grant to")
      let scopeContent: NSView
      if let choices = review.scopeChoices, choices.options.count > 1 {
        scopeContent = makeScopeRows(choices, width: innerWidth - labelWidth - 14)
      } else {
        let single = review.scopeChoices?.defaultOption
        let text = single.map { ReviewDisplay.scopeSummary($0) }
          ?? ReviewDisplay.root(review.plan.root)
        let label = Self.plainDetail(Self.safe(text), width: innerWidth - labelWidth - 14)
        label.textColor = .labelColor
        label.font = .systemFont(ofSize: 13, weight: .medium)
        scopeContent = label
      }
      grid.addRow(with: [scopeLabel, scopeContent])
      grid.addRow(with: [Self.makeSectionLabel("For"), makeDurationRow(width: innerWidth - labelWidth - 14)])
      grid.column(at: 0).width = labelWidth
      // Section labels sit on the first text line of the control beside them.
      grid.cell(atColumnIndex: 0, rowIndex: 0).customPlacementConstraints = [
        scopeLabel.firstBaselineAnchor.constraint(
          equalTo: (scopeButtons.first?.button ?? scopeContent).firstBaselineAnchor)
      ]
      if let control = durationControl {
        let forLabel = grid.cell(atColumnIndex: 0, rowIndex: 1).contentView!
        grid.cell(atColumnIndex: 0, rowIndex: 1).customPlacementConstraints = [
          forLabel.centerYAnchor.constraint(equalTo: control.centerYAnchor)
        ]
      }

      return Self.paddedBox(
        content: grid, cornerRadius: 12,
        fill: NSColor.controlBackgroundColor,
        border: NSColor.separatorColor,
        horizontalPadding: 14, verticalPadding: 14, width: width
      )
    }

    /// The SSH variant's lifetime choice. The SSH window states its scope in
    /// its own selector card rather than a two-row grant grid, so the lifetime
    /// gets the same "For" label, the same control, and the same card as the
    /// release variant's grant card, on its own.
    private func makeSSHGrantLifetimeCard(width: CGFloat) -> NSView {
      let innerWidth = width - 28
      let labelWidth: CGFloat = 64
      let grid = NSGridView()
      grid.columnSpacing = 14
      grid.rowSpacing = 12
      grid.rowAlignment = .none
      grid.xPlacement = .leading
      grid.yPlacement = .top
      grid.translatesAutoresizingMaskIntoConstraints = false
      grid.addRow(with: [
        Self.makeSectionLabel("For"),
        makeDurationRow(width: innerWidth - labelWidth - 14),
      ])
      grid.column(at: 0).width = labelWidth
      if let control = durationControl, let forLabel = grid.cell(
        atColumnIndex: 0, rowIndex: 0
      ).contentView {
        grid.cell(atColumnIndex: 0, rowIndex: 0).customPlacementConstraints = [
          forLabel.centerYAnchor.constraint(equalTo: control.centerYAnchor)
        ]
      }

      return Self.paddedBox(
        content: grid, cornerRadius: 12,
        fill: NSColor.controlBackgroundColor,
        border: NSColor.separatorColor,
        horizontalPadding: 14, verticalPadding: 14, width: width
      )
    }

    /// The lifetime popup with its live expiry, or the fixed requested lifetime
    /// when the reviewer is not offered a choice.
    private func makeDurationRow(width: CGFloat) -> NSView {
      let row = NSStackView()
      row.orientation = .horizontal
      row.alignment = .centerY
      row.spacing = 10

      if let lifetime = ReviewDisplay.fixedLifetime(for: review) {
        // A code is made for this one command, and a lasting GitHub request
        // is approved for itself alone; nothing is minted, so there is no
        // lifetime to choose or state.
        let fixed = NSTextField(labelWithString: lifetime.title)
        fixed.font = .systemFont(ofSize: 13, weight: .medium)
        durationControl = fixed
        row.addArrangedSubview(fixed)
        let detail = NSTextField(wrappingLabelWithString: lifetime.detail)
        detail.font = .systemFont(ofSize: 12)
        detail.textColor = .secondaryLabelColor
        detail.maximumNumberOfLines = 2
        detail.preferredMaxLayoutWidth = width - 130
        row.addArrangedSubview(detail)
        row.widthAnchor.constraint(equalToConstant: width).isActive = true
        return row
      } else if let choices = review.durationChoices {
        let popup = NSPopUpButton(frame: .zero, pullsDown: false)
        popup.controlSize = .regular
        popup.font = .systemFont(ofSize: 13)
        // Tag by menu index so a process-lifetime option (no seconds) is
        // selectable alongside the bounded ones.
        for (index, option) in choices.options.enumerated() {
          popup.addItem(withTitle: ReviewDisplay.durationTitle(for: option))
          popup.lastItem?.tag = index
        }
        popup.selectItem(withTag: choices.defaultIndex)
        popup.target = self
        popup.action = #selector(durationChanged(_:))
        popup.setContentHuggingPriority(.required, for: .horizontal)
        durationPopup = popup
        durationControl = popup
        interactiveControls.append(popup)
        row.addArrangedSubview(popup)
      } else {
        let fixed = NSTextField(labelWithString: ReviewDisplay.durationTitle(for: currentDuration))
        fixed.font = .systemFont(ofSize: 13, weight: .medium)
        durationControl = fixed
        row.addArrangedSubview(fixed)
      }

      let expiry = NSTextField(wrappingLabelWithString: expiryText(duration: currentDuration))
      expiry.font = .systemFont(ofSize: 12)
      expiry.textColor = .secondaryLabelColor
      expiry.maximumNumberOfLines = 2
      expiry.preferredMaxLayoutWidth = width - 130
      expiryLabel = expiry
      row.addArrangedSubview(expiry)
      row.widthAnchor.constraint(equalToConstant: width).isActive = true
      return row
    }

    private func expiryText(duration: GrantDuration) -> String {
      let reuse: String
      if review.ssh != nil {
        // No secret is released to the caller here — only signatures — and the
        // sentence above the selector already states what reuses the grant.
        reuse = ""
      } else if let choices = review.scopeChoices, choices.options.count > 1 {
        reuse = " · commands in the chosen scope reuse these secrets without another prompt"
      } else {
        reuse = ""
      }
      return ReviewDisplay.expiry(for: duration) + reuse
    }

    @objc private func durationChanged(_ sender: NSPopUpButton) {
      // Like the scope radios, only meaningful until the biometric is consumed.
      guard state == .selecting || state == .authenticating,
        let choices = review.durationChoices
      else {
        // Wrong state: restore the popup to the committed selection.
        if let choices = review.durationChoices {
          let index = selectedDuration
            .flatMap { choices.options.firstIndex(of: $0) } ?? choices.defaultIndex
          sender.selectItem(withTag: index)
        }
        return
      }
      let chosen = choices.resolved(selectedIndex: sender.selectedTag())
      selectedDuration = chosen
      sender.selectItem(withTag: choices.options.firstIndex(of: chosen) ?? choices.defaultIndex)
      expiryLabel?.stringValue = expiryText(duration: chosen)
      // The SSH summary sentence and the line beside the sensor state the
      // chosen lifetime too, and they wrap, so the window is re-fitted exactly
      // as a scope change re-fits it.
      if let ssh = review.ssh {
        sshScopeSummaryLabel?.stringValue = sshScopeSummaryText(ssh)
      }
      refreshReadyStatus()
      resizeToFitPreservingTop()
      updatePairingLine()
    }

    /// Shows the pairing line exactly while the selection would pair: a
    /// narrower or wider scope, or a lifetime cap, hides it.
    private func updatePairingLine() {
      guard let pairingLabel, let offer = review.pairingOffer else { return }
      let hidden = !offer.applies(scopeOptionID: selectedScopeOptionID, duration: selectedDuration)
      guard pairingLabel.isHidden != hidden else { return }
      pairingLabel.isHidden = hidden
      resizeToFitPreservingTop()
    }

    // MARK: - Delivery details (collapsed)

    private func makeDeliveryDetails(width: CGFloat) -> NSView {
      let disclosure = NSButton(
        title: "Show delivery details", target: self, action: #selector(toggleDeliveryDetails(_:))
      )
      disclosure.bezelStyle = .inline
      disclosure.controlSize = .small
      disclosure.font = .systemFont(ofSize: 12)
      disclosure.image = NSImage(systemSymbolName: "chevron.right", accessibilityDescription: nil)
      disclosure.imagePosition = .imageLeading
      interactiveControls.append(disclosure)

      let grid = makeDetailsGrid()
      grid.isHidden = true
      deliveryDetailsView = grid

      let stack = NSStackView(views: [disclosure, grid])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 8
      stack.widthAnchor.constraint(equalToConstant: width).isActive = true
      return stack
    }

    @objc private func toggleDeliveryDetails(_ sender: NSButton) {
      guard let details = deliveryDetailsView else { return }
      let expanding = details.isHidden
      details.isHidden = !expanding
      sender.title = expanding ? "Hide delivery details" : "Show delivery details"
      sender.image = NSImage(
        systemSymbolName: expanding ? "chevron.down" : "chevron.right",
        accessibilityDescription: nil
      )
      resizeToFitPreservingTop()
    }

    // MARK: - Request details

    private func makeAutomationSummary(
      _ automation: AutomationReviewDetails,
      width: CGFloat
    ) -> NSView {
      let job = automation.job
      let innerWidth = width - 24

      let title = NSTextField(labelWithString: Self.safe(job.name))
      title.font = .systemFont(ofSize: 14, weight: .semibold)
      title.lineBreakMode = .byTruncatingTail

      let spacer = NSView()
      spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

      let authorization = Self.statusPill("UNTIL REVOKED", tint: .systemRed)
      let header = NSStackView(views: [title, spacer, authorization])
      header.orientation = .horizontal
      header.alignment = .centerY
      header.spacing = 8
      header.widthAnchor.constraint(equalToConstant: innerWidth).isActive = true

      let interval = job.minimumIntervalSeconds == 0
        ? "Every trigger allowed"
        : "At most once every \(ReviewDisplay.duration(seconds: job.minimumIntervalSeconds))"
      let runtime = job.maximumRuntimeSeconds
        .map { "\(ReviewDisplay.duration(seconds: $0)) max per run" }
        ?? "runs for the daemon's process lifetime"
      let summary = NSTextField(
        wrappingLabelWithString: "Mutable interpreted command  ·  \(interval)  ·  \(runtime)"
      )
      summary.font = .systemFont(ofSize: 12)
      summary.textColor = .secondaryLabelColor
      summary.maximumNumberOfLines = 3
      summary.preferredMaxLayoutWidth = innerWidth

      let disclosure = NSButton(
        title: "Show command and security details",
        target: self,
        action: #selector(toggleAutomationDetails(_:))
      )
      disclosure.bezelStyle = .inline
      disclosure.controlSize = .small
      disclosure.font = .systemFont(ofSize: 12)
      disclosure.image = NSImage(
        systemSymbolName: "chevron.right",
        accessibilityDescription: nil
      )
      disclosure.imagePosition = .imageLeading
      interactiveControls.append(disclosure)

      let details = makeAutomationDetails(job, width: innerWidth)
      details.isHidden = true
      automationDetailsView = details

      let stack = NSStackView(views: [header, summary, disclosure, details])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 7

      return Self.card(
        wrapping: stack,
        fill: NSColor.labelColor.withAlphaComponent(0.045),
        border: NSColor.separatorColor,
        width: width
      )
    }

    private func makeAutomationDetails(_ job: AutomationJob, width: CGFloat) -> NSView {
      let separator = NSBox()
      separator.boxType = .separator
      separator.widthAnchor.constraint(equalToConstant: width).isActive = true

      let commandLabel = Self.automationDetailLabel("Exact command")
      let commandText = Self.commandText(Self.safe(job.command.displayCommand), width: width)
      screenFitted.append(commandText)
      let command = NSStackView(views: [commandText.scrollView, commandText.overflowCue])
      command.orientation = .vertical
      command.alignment = .leading
      command.spacing = 4

      let workingDirectory = Self.automationDetail(
        label: "Working directory",
        value: Self.safe(job.command.workingDirectory),
        width: width,
        monospaced: true
      )
      let interpreter = Self.automationDetail(
        label: "Interpreter",
        value: "\(Self.safe(job.command.executable.canonicalPath))  ·  explicitly unverified",
        width: width,
        monospaced: true
      )
      let environment = Self.automationDetail(
        label: "Environment",
        value: "Sanitized trigger environment; not integrity-protected",
        width: width
      )

      let stack = NSStackView(
        views: [separator, commandLabel, command, workingDirectory, interpreter, environment]
      )
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 7
      stack.setCustomSpacing(9, after: command)
      stack.widthAnchor.constraint(equalToConstant: width).isActive = true
      return stack
    }

    private static func automationDetail(
      label: String,
      value: String,
      width: CGFloat,
      monospaced: Bool = false
    ) -> NSView {
      let heading = automationDetailLabel(label)
      let copy = NSTextField(wrappingLabelWithString: value)
      copy.font = monospaced
        ? .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        : .systemFont(ofSize: 12)
      copy.textColor = .labelColor
      copy.maximumNumberOfLines = 5
      copy.preferredMaxLayoutWidth = width
      copy.toolTip = value

      let stack = NSStackView(views: [heading, copy])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 2
      stack.widthAnchor.constraint(equalToConstant: width).isActive = true
      return stack
    }

    private static func automationDetailLabel(_ text: String) -> NSTextField {
      let label = NSTextField(labelWithString: text.uppercased())
      label.font = .systemFont(ofSize: 10, weight: .semibold)
      label.textColor = .secondaryLabelColor
      return label
    }

    /// A command in a bordered, selectable text box: see `ReviewCommandText`.
    private static func commandText(
      _ command: String,
      font: NSFont = .monospacedSystemFont(ofSize: 11.5, weight: .regular),
      width: CGFloat
    ) -> ReviewCommandText {
      ReviewCommandText(
        command, font: font, width: width, inset: NSSize(width: 7, height: 6), borderType: .lineBorder)
    }

    private static func statusPill(_ text: String, tint: NSColor) -> NSView {
      let label = NSTextField(labelWithString: text)
      label.font = .systemFont(ofSize: 9.5, weight: .bold)
      label.textColor = tint
      return paddedBox(
        content: label,
        cornerRadius: 5,
        fill: tint.withAlphaComponent(0.10),
        border: tint.withAlphaComponent(0.22),
        horizontalPadding: 7,
        verticalPadding: 3
      )
    }

    @objc private func toggleAutomationDetails(_ sender: NSButton) {
      guard let details = automationDetailsView else { return }
      let expanding = details.isHidden
      details.isHidden = !expanding
      // The whole exact command, scrolling only in what the screen leaves
      // (`resizeToFitPreservingTop`).
      sender.title = expanding
        ? "Hide command and security details"
        : "Show command and security details"
      sender.image = NSImage(
        systemSymbolName: expanding ? "chevron.down" : "chevron.right",
        accessibilityDescription: nil
      )
      resizeToFitPreservingTop()
    }

    // MARK: - Grant scope

    /// Radio buttons for the roots csecd resolved from live kernel ancestry.
    /// The default is pre-selected, so the one-tap path is unchanged; changing
    /// the selection needs no re-authentication because the LAContext reason is
    /// never displayed with an embedded `LAAuthenticationView`, and the choice is
    /// read at biometric success.
    private func makeScopeSelector(
      _ choices: GrantScopeChoices, width: CGFloat
    ) -> NSView {
      let rows = makeScopeRows(choices, width: width)

      let footnote = NSTextField(
        wrappingLabelWithString:
          review.ssh == nil
            ? "A wider scope lets other commands in that process tree reuse these "
              + "credentials, without another prompt, until the grant expires."
            : "Applies only to this SSH key, server identity, and username. "
              + "Approval ends when the selected process exits or the time limit is reached."
      )
      footnote.font = .systemFont(ofSize: 11)
      footnote.textColor = .tertiaryLabelColor
      footnote.maximumNumberOfLines = 3
      footnote.preferredMaxLayoutWidth = width - 28

      let content = NSStackView(views: [rows, footnote])
      content.orientation = .vertical
      content.alignment = .leading
      content.spacing = 10
      return Self.paddedBox(
        content: content,
        cornerRadius: 9,
        fill: NSColor.controlBackgroundColor,
        border: NSColor.separatorColor,
        horizontalPadding: 14,
        verticalPadding: 12,
        width: width
      )
    }

    /// One radio row per offered root, registered in `scopeButtons`.
    private func makeScopeRows(_ choices: GrantScopeChoices, width: CGFloat) -> NSStackView {
      let rows = NSStackView()
      rows.orientation = .vertical
      rows.alignment = .leading
      rows.spacing = 10
      rows.translatesAutoresizingMaskIntoConstraints = false

      for option in choices.options {
        let button = NSButton(
          radioButtonWithTitle: Self.safe(
            review.ssh == nil
              ? ReviewDisplay.scopeTitle(option) : ReviewDisplay.sshScopeTitle(option)
          ),
          target: self,
          action: #selector(scopePressed(_:))
        )
        button.font = .systemFont(ofSize: 13, weight: .medium)
        button.state = option.id == choices.defaultOptionID ? .on : .off
        button.tag = scopeButtons.count
        scopeButtons.append((id: option.id, button: button))
        interactiveControls.append(button)

        let detail = NSTextField(
          wrappingLabelWithString: Self.safe(
            review.ssh == nil
              ? ReviewDisplay.scopeDetail(option) : ReviewDisplay.sshScopeDetail(option)
          )
        )
        detail.font = .systemFont(ofSize: 11)
        detail.textColor = .secondaryLabelColor
        detail.maximumNumberOfLines = 2
        detail.preferredMaxLayoutWidth = width - 60

        let row = NSStackView(views: [button, detail])
        row.orientation = .vertical
        row.alignment = .leading
        row.spacing = 1
        row.edgeInsets = NSEdgeInsets(top: 0, left: 0, bottom: 0, right: 0)
        // Indent the detail under its radio label without breaking the button's
        // own leading edge.
        row.setCustomSpacing(1, after: button)
        detail.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        rows.addArrangedSubview(row)
        NSLayoutConstraint.activate([
          detail.leadingAnchor.constraint(equalTo: row.leadingAnchor, constant: 20)
        ])
      }
      return rows
    }

    @objc private func scopePressed(_ sender: NSButton) {
      // The selection is only meaningful until the biometric is consumed.
      guard state == .selecting || state == .authenticating else {
        for entry in scopeButtons {
          entry.button.state = entry.id == selectedScopeOptionID ? .on : .off
        }
        return
      }
      guard sender.tag >= 0, sender.tag < scopeButtons.count else { return }
      selectedScopeOptionID = scopeButtons[sender.tag].id
      // Group the radios explicitly rather than relying on implicit sibling
      // grouping, which the nested per-row stacks would defeat.
      for entry in scopeButtons {
        entry.button.state = entry.id == selectedScopeOptionID ? .on : .off
      }
      if let ssh = review.ssh {
        sshScopeSummaryLabel?.stringValue = sshScopeSummaryText(ssh)
      }
      refreshReadyStatus()
      resizeToFitPreservingTop()
      updatePairingLine()
    }

    private func makeDetailsGrid() -> NSView {
      let plan = review.plan
      let executableName = URL(fileURLWithPath: plan.executable.canonicalPath).lastPathComponent

      let emitterText = NSMutableAttributedString(
        string: Self.safe(executableName),
        attributes: [
          .font: NSFont.systemFont(ofSize: 13),
          .foregroundColor: NSColor.labelColor,
        ]
      )
      emitterText.append(
        NSAttributedString(
          string: "  \(ReviewDisplay.assurance(plan.executable.assurance).uppercased())",
          attributes: [
            .font: NSFont.systemFont(ofSize: 10.5, weight: .bold),
            .foregroundColor: Self.assuranceTint(plan.executable.assurance),
          ]
        ))
      let emitterValue = NSTextField(labelWithAttributedString: emitterText)
      emitterValue.lineBreakMode = .byTruncatingTail
      emitterValue.toolTip = Self.safe(plan.executable.canonicalPath)

      var rows: [(String, NSView)] = [
        ("Requested by", Self.gridValue(Self.safe(review.caller.description))),
        ("Emitted by", emitterValue),
        ("Delivered to", Self.gridValue(DeliveryReviewCopy.recipientDescription(for: plan))),
        (
          "Delivery",
          Self.gridValue(
            "\(ReviewDisplay.mechanism(plan.mechanism)) · \(ReviewDisplay.scope(plan.descendantScope))"
          )
        ),
      ]
      // The scope selector below is the authoritative statement of the root
      // whenever it is shown; a static row here would contradict a live choice.
      if (review.scopeChoices?.options.count ?? 0) <= 1 {
        let rootDescription: String
        if review.ssh != nil, let scope = review.scopeChoices?.defaultOption {
          rootDescription = ReviewDisplay.sshScopeRootSummary(scope)
        } else {
          rootDescription = ReviewDisplay.root(plan.root)
        }
        rows.append(("Grant root", Self.gridValue(rootDescription)))
      }
      rows += [
        ("Destination", Self.gridValue(ReviewDisplay.destination(plan.destination))),
        (
          "Requested duration",
          Self.gridValue(ReviewDisplay.durationTitle(
            for: plan.requestedTTLSeconds.map { .bounded(seconds: $0) } ?? .processLifetime
          ))
        ),
      ]

      let grid = NSGridView(
        views: rows.map { [Self.gridLabel($0.0), $0.1] })
      grid.columnSpacing = 14
      grid.rowSpacing = 6
      grid.rowAlignment = .none
      grid.column(at: 0).xPlacement = .trailing
      grid.translatesAutoresizingMaskIntoConstraints = false
      return grid
    }

    private static func gridLabel(_ text: String) -> NSTextField {
      let label = NSTextField(labelWithString: text)
      label.font = .systemFont(ofSize: 13)
      label.textColor = .secondaryLabelColor
      return label
    }

    /// Values render on one line when they fit and wrap (never truncate) when
    /// they do not: this is the authoritative display, and an over-long
    /// attacker-influenced string must not push its verification tags out of
    /// view. A one-line label is measured explicitly because a wrapping label
    /// inside NSGridView reserves wrapped height even for short text.
    private static func gridValue(_ text: String) -> NSTextField {
      let font = NSFont.systemFont(ofSize: 13)
      let availableWidth = innerWidth - 124
      let measured = (text as NSString).size(withAttributes: [.font: font]).width
      if measured <= availableWidth {
        let label = NSTextField(labelWithString: text)
        label.font = font
        label.textColor = .labelColor
        return label
      }
      let label = NSTextField(wrappingLabelWithString: text)
      label.font = font
      label.textColor = .labelColor
      label.maximumNumberOfLines = 4
      label.preferredMaxLayoutWidth = availableWidth
      return label
    }

    // MARK: - Authentication area and footer

    private func makeAuthenticationArea() -> NSView {
      authenticationView = LAAuthenticationView(context: context, controlSize: .small)
      authenticationView.setContentHuggingPriority(.required, for: .horizontal)
      authenticationView.setContentCompressionResistancePriority(.required, for: .horizontal)
      // With no Touch ID the embedded view draws nothing and is never armed;
      // the stack collapses it, so the status line says what to do instead.
      authenticationView.isHidden = !biometricsAvailable

      statusLabel = NSTextField(
        wrappingLabelWithString: authenticationStatusText()
      )
      statusLabel.font = .systemFont(ofSize: 13)
      statusLabel.textColor = biometricsAvailable ? .secondaryLabelColor : .systemRed
      statusLabel.alignment = .left
      statusLabel.maximumNumberOfLines = 3
      statusLabel.preferredMaxLayoutWidth = Self.innerWidth - 110

      let area = NSStackView(views: [authenticationView, statusLabel])
      area.orientation = .horizontal
      area.alignment = .centerY
      area.spacing = 14
      authenticationArea = area
      // Under the sensor row, apart from the status line, whose messages
      // (click to resume, waiting for unlock) it never replaces. Present from
      // the start, so the countdown moves nothing.
      var content: NSView = area
      if let deadline {
        let countdown = ReviewDeadlineCountdown(
          deadline: deadline, width: Self.innerWidth - 28, alignment: .left)
        deadlineCountdown = countdown
        let column = NSStackView(views: [area, countdown.label])
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 8
        content = column
      }
      return Self.paddedBox(
        content: content,
        cornerRadius: 9,
        fill: NSColor.controlAccentColor.withAlphaComponent(0.06),
        border: nil,
        horizontalPadding: 14,
        verticalPadding: 10,
        width: Self.innerWidth
      )
    }

    /// The line beside the sensor states the grant the live scope and
    /// lifetime selection would make, not just the request in front of it.
    private func authenticationStatusText() -> String {
      guard biometricsAvailable else {
        return ReviewTouchIDUnavailable.statusText(
          for: Self.surface(of: review), phoneCanDecide: phone?.canDecide ?? false)
      }
      return ReviewDisplay.touchIDReadyText(
        for: review,
        scope: review.scopeChoices?.resolved(selectedID: selectedScopeOptionID),
        duration: currentDuration
      )
    }

    /// After a scope or lifetime change, restate the grant beside the sensor —
    /// but only while it shows the ready line: click-to-resume, waiting for
    /// unlock and "Touch ID accepted…" say something a selection cannot change.
    private func refreshReadyStatus() {
      guard state == .authenticating, !lostKeyWhileArmed else { return }
      statusLabel.stringValue = authenticationStatusText()
    }

    private func makeFooter() -> NSView {
      let spacer = NSView()
      spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
      spacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

      denyButton = NSButton(title: denyTitle(authenticating: false), target: self, action: #selector(denyPressed(_:)))
      denyButton.keyEquivalent = "\u{1b}"
      denyButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 84).isActive = true
      interactiveControls.append(denyButton)

      let footer = NSStackView(views: [spacer, denyButton])
      footer.orientation = .horizontal
      footer.alignment = .centerY
      footer.spacing = 10
      footer.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
      return footer
    }

    /// The refusing button's label. On a restore-only panel it says what
    /// refusing does, whether or not Touch ID is armed; elsewhere it is Deny,
    /// or Cancel while the sensor waits.
    private func denyTitle(authenticating: Bool) -> String {
      if review.isRestoreOnly { return RestoreReviewDetails.forgetButtonTitle }
      return authenticating ? "Cancel" : "Deny"
    }

    // MARK: - Selection and authentication flow

    private func collectPolicySelection() async -> AccessPolicyReviewOutcome {
      guard state == .ready else { return .denied(.authenticationFailed) }
      state = .selecting
      return await withCheckedContinuation { continuation in
        selectionContinuation = continuation
        NSApplication.shared.setActivationPolicy(.accessory)
        window.center()
        // Visible at once, but neither key nor interactive until the grace
        // period passes. Touch ID below starts now, not after the grace,
        // though macOS hands it a touch only once the panel is key.
        let grace = PromptInteractionGrace(window: window, controls: interactiveControls)
        interactionGrace = grace
        // Taken as the panel is put up; Touch ID must start in the same
        // breath as the window, with nothing between them.
        presentedAt = .now
        grace.begin()
        window.displayIfNeeded()
        beginAuthentication()
        deadlineCountdown?.start()
        // With no Touch ID, `beginAuthentication` armed nothing. The panel
        // stays up either way (there is no other prompt to hand over to), says
        // whether the phone can still approve, and arms Touch ID if it comes
        // back (`ReviewTouchIDUnavailable`). Touch ID going away under an
        // armed evaluation leads here too (`touchIDLost`).
        if !biometricsAvailable {
          waitForTouchID()
        }
      }
    }

    private func waitForTouchID() {
      phone?.whenUnavailable { [weak self] in
        DispatchQueue.main.async { self?.phoneCannotDecide() }
      }
      let watch = TouchIDAvailabilityWatch(
        surface: Self.surface(of: review), override: touchIDOverride, builtAt: builtAt)
      touchIDWatch = watch
      watch.start { [weak self] available in self?.touchIDPolled(available: available) }
    }

    /// The phone leg gave up while this panel, with no Touch ID, was up: say
    /// that nothing can approve now.
    private func phoneCannotDecide() {
      guard state == .selecting, !biometricsAvailable else { return }
      statusLabel.stringValue = authenticationStatusText()
    }

    /// One poll of `touchIDWatch`: arm Touch ID once it is back, with the
    /// screen unlocked and the requester still running.
    private func touchIDPolled(available: Bool) {
      guard state == .selecting, !biometricsAvailable else {
        stopTouchIDWatch()
        return
      }
      let locked = available && ScreenLockState.isScreenLocked
      switch ReviewTouchIDUnavailable.onPoll(
        touchIDAvailable: available, screenLocked: locked,
        requesterAlive: available && !locked && AccessReviewRequester.isAlive(review.caller)
      ) {
      case .keepWaiting:
        return
      case .requesterGone:
        finishDenied(.requesterGone, closeWindow: true)
      case .arm:
        stopTouchIDWatch()
        biometricsAvailable = true
        // A fresh context from the factory, with its Touch ID view shown in
        // place of the hidden one, armed the way the first presentation arms.
        rebuildAuthenticationContext()
        beginAuthentication()
      }
    }

    private func stopTouchIDWatch() {
      touchIDWatch?.stop()
      touchIDWatch = nil
    }

    private func beginAuthentication() {
      guard state == .selecting, biometricsAvailable else { return }
      state = .authenticating
      authenticationGeneration += 1
      let generation = authenticationGeneration
      lostKeyWhileArmed = false
      armedWhileNotKey = !window.isKeyWindow
      denyButton.title = denyTitle(authenticating: true)
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = authenticationStatusText()

      context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason: Self.initialAuthenticationReason(review)
      ) { [weak self] success, error in
        DispatchQueue.main.async {
          self?.authenticationFinished(success: success, error: error, generation: generation)
        }
      }
      // Dev-only (`ReviewTouchIDOverride.lostAfter`): the lid closes under
      // this evaluation, which ends the way the system would end it.
      if let delay = touchIDOverride?.endsArmedEvaluation(builtAt: builtAt) {
        Task { @MainActor [weak self] in
          try? await Task.sleep(for: delay)
          guard let self, self.state == .authenticating, self.authenticationGeneration == generation
          else { return }
          self.context.invalidate()
        }
      }
    }

    /// Key status left the panel while Touch ID was armed. Touches reach only
    /// the window in front, and whatever took the focus may have taken the
    /// sensor too, so say what brings Touch ID back.
    func windowDidResignKey(_ notification: Notification) {
      renewedAfterSystemCancelWhileKey = false
      guard ReviewFocusRecovery.onResignKey(authenticating: state == .authenticating)
        == .showClickToResume
      else { return }
      lostKeyWhileArmed = true
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = ReviewFocusRecovery.clickToResumeText
    }

    /// The panel is key, and Touch ID was armed while it could not take a
    /// touch: another prompt may have stranded that evaluation, which then
    /// never answers (`ReviewFocusRecovery`). After losing key, the controls
    /// are held back at once — the click or keystrokes that made the panel key
    /// are still being delivered — behind a guard that never takes the focus
    /// back: the human made this panel key, and if they have left it again by
    /// the time the guard ends, the focus is theirs (another armed panel doing
    /// the same would otherwise trade the focus with this one forever). The
    /// evaluation itself is renewed one run-loop turn later, so the Touch ID
    /// view that click may be landing on is not swapped out from under it.
    func windowDidBecomeKey(_ notification: Notification) {
      renewedAfterSystemCancelWhileKey = false
      let recovery = ReviewFocusRecovery.onBecomeKey(
        authenticating: state == .authenticating, lostKeyWhileArmed: lostKeyWhileArmed,
        armedWhileNotKey: armedWhileNotKey)
      guard recovery != .none else { return }
      if recovery == .rearm {
        let grace = PromptInteractionGrace(
          window: window, controls: interactiveControls,
          focus: { [weak self] in
            guard let self else { return }
            PromptInteractionGrace.refocusIfStillKey(self.window)
          })
        interactionGrace = grace
        grace.begin()
      }
      DispatchQueue.main.async { [weak self] in self?.renewAfterBecomingKey() }
    }

    /// The same re-present the unlock path does, with the same requester check,
    /// on a panel that is still key and still waiting on Touch ID.
    private func renewAfterBecomingKey() {
      guard ReviewFocusRecovery.onBecomeKey(
        authenticating: state == .authenticating, lostKeyWhileArmed: lostKeyWhileArmed,
        armedWhileNotKey: armedWhileNotKey) != .none,
        window.isKeyWindow
      else { return }
      guard AccessReviewRequester.isAlive(review.caller) else {
        finishDenied(.requesterGone, closeWindow: true)
        return
      }
      state = .selecting
      rebuildAuthenticationContext()
      beginAuthentication()
    }

    @objc private func denyPressed(_ sender: Any?) {
      finishDenied(.human(decidedAt: .now, on: .mac, shownAt: presentedAt), closeWindow: true)
    }

    private func authenticationFinished(success: Bool, error: (any Error)?, generation: Int) {
      guard ReviewFocusRecovery.isCurrent(
        generation: generation, currentGeneration: authenticationGeneration,
        authenticating: state == .authenticating
      ) else { return }
      if success {
        authenticationApproved()
        return
      }
      // A cancellation while the screen is locked cannot be a human denial: this
      // window (and its Deny button) is behind the lock screen, so the cancel is
      // system-initiated. Hold the request open and re-present Touch ID when the
      // Mac is unlocked, rather than denying a request the human never saw.
      if ScreenLockState.action(screenLocked: ScreenLockState.isScreenLocked) == .waitForUnlock {
        let detail = error?.localizedDescription ?? "no error"
        FileHandle.standardError.write(
          Data(
            ("csecd: embedded biometric prompt cancelled while screen locked; "
              + "waiting for unlock to re-present (\(detail))\n").utf8
          ))
        waitForUnlockThenRetry()
        return
      }
      // Touch ID may have gone under the evaluation (the lid closed with an
      // external display): ask again rather than trust the error code, and if
      // it has, wait for the phone or for Touch ID to return instead of
      // ending a review the phone could still approve.
      let errorCode = (error as NSError?)?.code
      let touchIDAvailable = ReviewTouchIDUnavailable.isAvailableNow(
        for: Self.surface(of: review), override: touchIDOverride, builtAt: builtAt)
      let afterFailure = ReviewTouchIDUnavailable.afterFailure(
        errorCode: errorCode, touchIDAvailable: touchIDAvailable)
      let detail = error?.localizedDescription ?? "no error"
      let code = errorCode.map(String.init) ?? "none"
      if afterFailure == .touchIDLost {
        FileHandle.standardError.write(
          Data(
            ("csecd: Touch ID became unavailable during the embedded biometric prompt "
              + "(error \(code): \(detail)); waiting without it\n").utf8
          ))
        touchIDLost()
        return
      }
      if afterFailure == .systemCancelled {
        systemCancelled()
        return
      }
      if error != nil {
        FileHandle.standardError.write(
          Data(
            ("csecd: embedded biometric consent denied (error \(code): \(detail); "
              + "Touch ID \(touchIDAvailable ? "still available" : "unavailable"))\n").utf8
          ))
      }
      finishDenied(
        AccessPolicyDenialReason.afterAuthenticationFailure(error, shownAt: presentedAt),
        closeWindow: true
      )
    }

    /// macOS ended the armed evaluation itself with Touch ID still here:
    /// another app came forward, or another prompt took the sensor. That is
    /// not the human refusing, so the panel stays up waiting on Touch ID,
    /// renewing it at once while key or when it next becomes key
    /// (`ReviewFocusRecovery.onSystemCancel`).
    private func systemCancelled() {
      guard state == .authenticating else { return }
      let recovery = ReviewFocusRecovery.onSystemCancel(
        windowIsKey: window.isKeyWindow, renewedWhileKey: renewedAfterSystemCancelWhileKey)
      FileHandle.standardError.write(
        Data(
          ("csecd: embedded biometric prompt cancelled by the system with Touch ID available; "
            + (recovery == .renew ? "renewing it\n" : "waiting for the panel to become key\n")).utf8
        ))
      guard recovery == .renew else {
        lostKeyWhileArmed = true
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.stringValue = ReviewFocusRecovery.clickToResumeText
        return
      }
      renewedAfterSystemCancelWhileKey = true
      DispatchQueue.main.async { [weak self] in self?.renewAfterSystemCancel() }
    }

    /// The renewal `renewAfterBecomingKey` does, with the same requester
    /// check, for a panel still key after a system cancel.
    private func renewAfterSystemCancel() {
      guard state == .authenticating, window.isKeyWindow else { return }
      guard AccessReviewRequester.isAlive(review.caller) else {
        finishDenied(.requesterGone, closeWindow: true)
        return
      }
      state = .selecting
      rebuildAuthenticationContext()
      beginAuthentication()
    }

    /// Touch ID went away under the armed evaluation: carry on as a panel
    /// opened without it does (`collectPolicySelection`), saying whether the
    /// phone can still approve and arming Touch ID if it comes back.
    private func touchIDLost() {
      guard state == .authenticating else { return }
      state = .selecting
      biometricsAvailable = false
      lostKeyWhileArmed = false
      armedWhileNotKey = false
      authenticationView.isHidden = true
      denyButton.title = denyTitle(authenticating: false)
      statusLabel.textColor = .systemRed
      statusLabel.stringValue = authenticationStatusText()
      waitForTouchID()
    }

    /// Enter the held-open wait: replace the spent context so the retry presents a
    /// clean prompt, tell the user what is happening, and poll for unlock.
    private func waitForUnlockThenRetry() {
      guard state == .authenticating else { return }
      state = .waitingForUnlock
      denyButton.title = denyTitle(authenticating: false)
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = ScreenLockState.waitingForUnlockText
      // The grace still pending from the first presentation (the Mac may have
      // locked inside it) is left to the retry's grace, which supersedes it
      // when it begins (see PromptInteractionGrace).
      rebuildAuthenticationContext()
      startUnlockWatch()
    }

    private func startUnlockWatch() {
      guard unlockPollTimer == nil else { return }
      let timer = Timer(
        timeInterval: ScreenLockState.pollInterval, repeats: true
      ) { [weak self] _ in
        DispatchQueue.main.async { self?.handleUnlockSignal() }
      }
      // `.common` so the poll keeps firing even during window/menu tracking.
      RunLoop.main.add(timer, forMode: .common)
      unlockPollTimer = timer
    }

    private func stopUnlockWatch() {
      unlockPollTimer?.invalidate()
      unlockPollTimer = nil
    }

    private func handleUnlockSignal() {
      guard state == .waitingForUnlock else { return }
      // The request may have gone while the Mac was locked. Re-presenting it
      // would spend the human's first Touch ID after unlock on a request
      // nothing is waiting for, so check the requester's exact incarnation
      // first and close instead.
      let locked = ScreenLockState.isScreenLocked
      switch AccessReviewUnlock.action(
        screenLocked: locked,
        requesterAlive: locked || AccessReviewRequester.isAlive(review.caller)
      ) {
      case .keepWaiting:
        return
      case .requesterGone:
        FileHandle.standardError.write(
          Data(
            "csecd: requester exited while its review waited for unlock; closing it\n".utf8
          ))
        finishDenied(.requesterGone, closeWindow: true)
        return
      case .represent:
        break
      }
      stopUnlockWatch()
      state = .selecting
      // The human has just been typing at the lock screen and this panel is
      // still the key window, so the re-presented prompt gets the same typing
      // guard the first one had: controls held back until the keyboard has
      // been quiet, while Touch ID starts again at once.
      let grace = PromptInteractionGrace(window: window, controls: interactiveControls)
      interactionGrace = grace
      grace.begin()
      presentedAt = .now
      beginAuthentication()
    }

    /// Invalidate the spent or stranded context and swap the embedded Touch ID
    /// view for one bound to a fresh context, so the unlock retry or the focus
    /// re-arm evaluates cleanly.
    private func rebuildAuthenticationContext() {
      context.invalidate()
      let fresh = ReviewAuthenticationContext.make(for: Self.surface(of: review))
      context = fresh

      let replacement = LAAuthenticationView(context: fresh, controlSize: .small)
      replacement.setContentHuggingPriority(.required, for: .horizontal)
      replacement.setContentCompressionResistancePriority(.required, for: .horizontal)
      replacement.isHidden = !biometricsAvailable
      if let area = authenticationArea, let previous = authenticationView {
        area.removeArrangedSubview(previous)
        previous.removeFromSuperview()
        area.insertArrangedSubview(replacement, at: 0)
      }
      authenticationView = replacement
    }

    private func authenticationApproved() {
      guard state == .authenticating else { return }

      state = .awaitingPolicy
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = "Touch ID accepted…"
      // Decided: the deadline no longer applies (`HumanWait.decide`), so its
      // line goes rather than freezing on a stale warning.
      deadlineCountdown?.retire()

      // Freeze the scope the human had selected at the moment the biometric
      // succeeded; later clicks are ignored by `scopePressed`. A grace period
      // still pending must not re-enable these afterwards.
      interactionGrace?.cancel()
      for entry in scopeButtons { entry.button.isEnabled = false }
      durationPopup?.isEnabled = false

      let continuation = selectionContinuation
      selectionContinuation = nil
      continuation?.resume(
        returning: .approved(AccessPolicyApproval(
          authenticationSession: self,
          selectedScopeOptionID: selectedScopeOptionID,
          selectedDurationIndex: selectedDuration
            .flatMap { review.durationChoices?.options.firstIndex(of: $0) },
          decisionLatency: presentedAt.map { $0.duration(to: .now) },
          // The selection is frozen above, so the line's visibility now is
          // what the human saw when the biometric succeeded.
          pairingLineShown: pairingLabel.map { !$0.isHidden } ?? false,
          decidedOn: .mac
        )))
    }

    private func finishDenied(
      _ reason: AccessPolicyDenialReason, closeWindow shouldClose: Bool
    ) {
      guard state != .finished else { return }
      state = .finished
      stopUnlockWatch()
      stopTouchIDWatch()
      interactionGrace?.cancel()
      deadlineCountdown?.stop()
      context.invalidate()
      let selection = selectionContinuation
      selectionContinuation = nil
      if shouldClose { closeWindow() }
      selection?.resume(returning: .denied(reason))
    }

    private func closeWindow() {
      stopUnlockWatch()
      stopTouchIDWatch()
      interactionGrace?.cancel()
      deadlineCountdown?.stop()
      window.delegate = nil
      window.orderOut(nil)
      window.close()
    }

    /// Only the human closes this window: every programmatic close clears the
    /// delegate first (`closeWindow`).
    func windowWillClose(_ notification: Notification) {
      finishDenied(.human(decidedAt: .now, on: .mac, shownAt: presentedAt), closeWindow: false)
    }

    static func initialAuthenticationReason(_ review: AccessPolicyReview) -> String {
      if review.isRestoreOnly, let restore = review.restore {
        return "Reopen \(restore.storeCount) store\(restore.storeCount == 1 ? "" : "s") for "
          + "\(restore.rows.count) approval\(restore.rows.count == 1 ? "" : "s") csecd held "
          + "before it restarted; nothing new is approved"
      }
      if let automation = review.automation {
        return "Allow unattended job \(safe(automation.job.name)) to use the displayed references until revoked"
      }
      if let change = review.settingsChange {
        return ([change.title] + change.changes).joined(separator: " — ")
      }
      if let lasting = review.githubLastingAccess, ReviewDisplay.coversOneGitHubRequest(review) {
        // Nothing is granted past this one request.
        let references = review.credentials.flatMap(\.references)
        return "let \(safe(review.caller.description)) use "
          + "\(references.count == 1 ? "the requested value" : "the requested values") for one GitHub request only, "
          + "\(safe(lasting.request)), which \(lasting.kind.effect):\n"
          + references.map { "• \($0.displayString)" }.joined(separator: "\n")
          + "\nterminal: \(safe(review.caller.terminalSummary))"
      }
      if ReviewDisplay.releasesOnlyOneTimeCodes(review) {
        // Nothing is granted, so there is no scope or lifetime to state.
        let references = review.credentials.flatMap(\.references)
        return "release \(references.count == 1 ? "a one-time code" : "one-time codes") to "
          + "\(safe(review.caller.description)) for this command only:\n"
          + references.map { "• \($0.displayString)" }.joined(separator: "\n")
          + "\npurpose: \(safe(review.reason))\nterminal: \(safe(review.caller.terminalSummary))"
      }
      let plan = review.plan
      // The default scope only; the live selection is displayed in this window,
      // which is the authoritative surface for an embedded (non-textual)
      // LAAuthenticationView. See `scopeButtons`.
      let scopeLine = review.scopeChoices.map {
        "; grant scope \(ReviewDisplay.scopeSummary($0.defaultOption, for: review))"
      } ?? ""
      let policySummary =
        "delivery \(plan.mechanism.rawValue); scope \(plan.descendantScope.rawValue); "
        + "destination \(plan.destination.rawValue)\(scopeLine)"
      // The default lifetime for this initial reason (the live selection is shown
      // in the window, the authoritative surface for the embedded auth view).
      let defaultDuration = review.durationChoices?.defaultOption
        ?? plan.requestedTTLSeconds.map { .bounded(seconds: $0) }
        ?? .processLifetime
      return BiometricConsent.prompt(
        caller: review.caller,
        references: review.credentials.flatMap(\.references),
        reason: review.reason,
        ttl: defaultDuration.ttlSeconds.map(TimeInterval.init),
        policySummary: policySummary
      )
    }

    private static func safe(_ value: String) -> String {
      ReviewDisplay.sanitized(value)
    }
  }
  public extension AccessPolicyDenialReason {
    /// What a failed Touch ID evaluation means once the screen is known to be
    /// unlocked (a locked screen waits and re-presents instead). Apple's sheet
    /// titles its refusing button "Deny" (`ReviewAuthenticationContext`), and
    /// pressing it arrives as `LAError.userCancel`: the human refusing. Every
    /// other error — a failed match, a lockout, a system or app cancel — says
    /// nothing about what the human wants, so it must not refuse other requests.
    static func afterAuthenticationFailure(
      _ error: (any Error)?,
      shownAt: ContinuousClock.Instant? = nil
    ) -> AccessPolicyDenialReason {
      (error as? LAError)?.code == .userCancel
        ? .human(decidedAt: .now, on: .mac, shownAt: shownAt) : .authenticationFailed
    }
  }

  /// What a review held open behind the lock screen does when polled.
  public enum AccessReviewUnlock: Equatable {
    /// Still locked: keep waiting.
    case keepWaiting
    /// Unlocked with the requester still running: re-present Touch ID.
    case represent
    /// Unlocked, but the requester is gone: close as `.requesterGone`.
    case requesterGone

    /// The unlock re-present rule, as one pure function every csecd review
    /// layout (access, automation, SSH) runs through.
    public static func action(screenLocked: Bool, requesterAlive: Bool) -> AccessReviewUnlock {
      if screenLocked { return .keepWaiting }
      return requesterAlive ? .represent : .requesterGone
    }
  }

  /// The requester a csecd review was raised for.
  public enum AccessReviewRequester {
    /// Whether the exact process incarnation that asked is still running: the
    /// same pid with the same start time, so a recycled pid reads as gone. A
    /// caller with no known start time cannot be shown to be alive.
    public static func isAlive(_ caller: CallerInfo, using override: ProcessInspection? = nil) -> Bool {
      let inspection = override ?? caller.requestAnchor?.inspection ?? .live
      return caller.pid > 0 && caller.startTime > 0
        && inspection.startTime(of: caller.pid) == caller.startTime
        && caller.requestAnchor?.abandonment(using: inspection) == nil
    }
  }

  /// Lays out fixed-size items left to right, wrapping to a new row when the next
  /// item would overflow `width`. NSStackView cannot wrap, and a 20-key native
  /// store as one column is a scrolling list nobody reads before Touch ID.
  @MainActor
  final class WrappingFlowView: NSView {
    private let items: [NSView]
    private let width: CGFloat
    private let horizontalSpacing: CGFloat
    private let verticalSpacing: CGFloat
    private var contentHeight: CGFloat = 0

    override var isFlipped: Bool { true }

    init(items: [NSView], width: CGFloat, horizontalSpacing: CGFloat = 6, verticalSpacing: CGFloat = 6) {
      self.items = items
      self.width = width
      self.horizontalSpacing = horizontalSpacing
      self.verticalSpacing = verticalSpacing
      super.init(frame: NSRect(x: 0, y: 0, width: width, height: 0))
      translatesAutoresizingMaskIntoConstraints = false
      for item in items {
        // Items are positioned by frame here; their own internal Auto Layout
        // (a padded box around a label) still determines their size.
        item.translatesAutoresizingMaskIntoConstraints = true
        addSubview(item)
      }
      layoutItems()
      NSLayoutConstraint.activate([
        widthAnchor.constraint(equalToConstant: width),
        heightAnchor.constraint(equalToConstant: contentHeight),
      ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("unsupported") }

    private func layoutItems() {
      var x: CGFloat = 0
      var y: CGFloat = 0
      var rowHeight: CGFloat = 0
      for item in items {
        let size = item.fittingSize
        if x > 0, x + size.width > width {
          x = 0
          y += rowHeight + verticalSpacing
          rowHeight = 0
        }
        item.frame = NSRect(x: x, y: y, width: min(size.width, width), height: size.height)
        x += size.width + horizontalSpacing
        rowHeight = max(rowHeight, size.height)
      }
      contentHeight = items.isEmpty ? 0 : y + rowHeight
    }
  }
#endif
