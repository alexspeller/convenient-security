#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @preconcurrency import AppKit
  import Foundation
  @preconcurrency import LocalAuthentication
  @preconcurrency import LocalAuthenticationEmbeddedUI

  /// One trusted window owns policy selection and the LAContext-backed Touch ID
  /// view. Authentication starts as soon as the visible window is rendered. On
  /// success the exact visible review is returned to Agent, which must still
  /// accept it before this session releases its LAContext.
  @MainActor
  final class TrustedAccessReviewSession: NSObject, NSWindowDelegate,
    AccessPolicyAuthenticationSession
  {
    private enum State {
      case ready
      case selecting
      case awaitingPolicy
      case authenticating
      case finished
    }

    private static let contentWidth: CGFloat = 640
    private static let horizontalMargin: CGFloat = 28
    private static var innerWidth: CGFloat { contentWidth - horizontalMargin * 2 }

    private let review: AccessPolicyReview
    private let context: LAContext
    private var state = State.ready
    private var selectionContinuation: CheckedContinuation<AccessPolicyReviewOutcome, Never>?
    private var biometricsAvailable = false

    private var window: NSPanel!
    private var authenticationView: LAAuthenticationView!
    private var statusLabel: NSTextField!
    private var denyButton: NSButton!
    private var automationDetailsView: NSView?
    /// Radio buttons for the offered grant scopes, keyed by option id. The live
    /// selection is authoritative: `LAAuthenticationView` is documented as
    /// non-textual ("the reason for the authentication must be apparent from the
    /// surrounding UI"), so this window — not the LAContext reason string — is
    /// what the human is reading when they touch the sensor.
    private var scopeButtons: [(id: String, button: NSButton)] = []
    private var selectedScopeOptionID: String?

    private init(review: AccessPolicyReview) {
      self.review = review
      self.context = LAContext()
      self.selectedScopeOptionID = review.scopeChoices?.defaultOptionID
      super.init()
      configureAuthentication()
      configureWindow()
    }

    static func present(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
      let session = TrustedAccessReviewSession(review: review)
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
        finishDenied(closeWindow: true)
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

    func cancel() async {
      finishDenied(closeWindow: true)
    }

    private func configureAuthentication() {
      context.localizedCancelTitle = "Deny"
      context.localizedFallbackTitle = ""
      var evaluationError: NSError?
      biometricsAvailable = context.canEvaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        error: &evaluationError
      )
      if !biometricsAvailable {
        let detail = evaluationError?.localizedDescription ?? "Touch ID is unavailable."
        FileHandle.standardError.write(
          Data(
            "csecd: biometrics unavailable, denying consent (\(detail))\n".utf8
          ))
      }
    }

    // MARK: - Window construction

    private func configureWindow() {
      window = NSPanel(
        contentRect: NSRect(x: 0, y: 0, width: Self.contentWidth, height: 400),
        styleMask: [.titled, .closable],
        backing: .buffered,
        defer: false
      )
      window.title = "Convenient Security"
      window.isRestorable = false
      window.isReleasedWhenClosed = false
      window.hidesOnDeactivate = false
      window.level = .modalPanel
      window.delegate = self

      let contentView = NSView()
      window.contentView = contentView

      let root = NSStackView()
      root.orientation = .vertical
      root.alignment = .leading
      root.spacing = 16
      root.translatesAutoresizingMaskIntoConstraints = false
      contentView.addSubview(root)

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

      root.addArrangedSubview(Self.makeSectionLabel("Credentials to be released"))
      root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
      let credentialCards = makeCredentialCards(width: Self.innerWidth)
      root.addArrangedSubview(credentialCards)

      root.addArrangedSubview(Self.makeSectionLabel(
        review.automation == nil ? "Request" : "Persistent automation job"
      ))
      root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
      if let automation = review.automation {
        root.addArrangedSubview(makeAutomationSummary(automation, width: Self.innerWidth))
      } else {
        root.addArrangedSubview(makeDetailsGrid())
      }

      if review.automation == nil, let choices = review.scopeChoices, choices.options.count > 1 {
        root.addArrangedSubview(Self.makeSectionLabel("Grant scope"))
        root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
        let selector = makeScopeSelector(choices, width: Self.innerWidth)
        root.addArrangedSubview(selector)
        NSLayoutConstraint.activate([
          selector.widthAnchor.constraint(equalToConstant: Self.innerWidth)
        ])
      }

      if review.automation == nil {
        let footnote = NSTextField(
          wrappingLabelWithString:
            "Touch ID authorizes this exact release. No secret values are shown in this window."
        )
        footnote.font = .systemFont(ofSize: 11)
        footnote.textColor = .tertiaryLabelColor
        footnote.maximumNumberOfLines = 3
        footnote.preferredMaxLayoutWidth = Self.innerWidth
        root.addArrangedSubview(footnote)
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
        credentialCards.widthAnchor.constraint(equalTo: root.widthAnchor),
        separator.widthAnchor.constraint(equalTo: root.widthAnchor),
      ])

      contentView.layoutSubtreeIfNeeded()
      window.setContentSize(contentView.fittingSize)
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
      NSLayoutConstraint.activate([
        icon.widthAnchor.constraint(equalToConstant: 44),
        icon.heightAnchor.constraint(equalToConstant: 44),
      ])

      let title = NSTextField(labelWithString:
        review.automation == nil ? "Secret Access Requested" : "Enable Unattended Automation"
      )
      title.font = .systemFont(ofSize: 19, weight: .semibold)

      let purpose = NSTextField(
        wrappingLabelWithString: "“\(Self.safe(review.reason))”")
      purpose.font = .systemFont(ofSize: 13)
      purpose.textColor = .labelColor
      purpose.maximumNumberOfLines = 3
      purpose.preferredMaxLayoutWidth = Self.innerWidth - 58

      let labels = NSStackView(views: [title, purpose])
      labels.orientation = .vertical
      labels.alignment = .leading
      labels.spacing = 3

      let header = NSStackView(views: [icon, labels])
      header.orientation = .horizontal
      header.alignment = .centerY
      header.spacing = 14
      return header
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
      content.translatesAutoresizingMaskIntoConstraints = false
      host.addSubview(content)
      NSLayoutConstraint.activate([
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

    // MARK: - Credentials

    private func makeCredentialCards(width: CGFloat) -> NSView {
      let cards = NSStackView()
      cards.orientation = .vertical
      cards.alignment = .leading
      cards.spacing = 10
      cards.translatesAutoresizingMaskIntoConstraints = false

      for credential in review.credentials {
        let card = makeCredentialCard(credential, width: width)
        cards.addArrangedSubview(card)
      }

      cards.layoutSubtreeIfNeeded()
      let maximumHeight: CGFloat = 340
      guard cards.fittingSize.height > maximumHeight else { return cards }

      let scroll = NSScrollView()
      scroll.hasVerticalScroller = true
      scroll.autohidesScrollers = true
      scroll.borderType = .noBorder
      scroll.drawsBackground = false
      scroll.documentView = cards
      scroll.heightAnchor.constraint(equalToConstant: maximumHeight).isActive = true
      NSLayoutConstraint.activate([
        cards.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
        cards.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
        cards.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
        cards.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
      ])
      return scroll
    }

    private func makeCredentialCard(
      _ credential: PolicyReviewCredential, width: CGFloat
    ) -> NSView {
      let innerWidth = width - 24
      let stack = NSStackView()
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 7

      let group = ReviewDisplay.referenceGroup(for: credential)

      let keyIcon = NSImageView()
      keyIcon.image = NSImage(systemSymbolName: "key.fill", accessibilityDescription: nil)
      keyIcon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 13, weight: .medium)
      keyIcon.contentTintColor = .secondaryLabelColor
      keyIcon.setContentHuggingPriority(.required, for: .horizontal)

      let titleText = group.title ?? "Requested references"
      let title = NSTextField(labelWithString: titleText)
      title.font = .systemFont(ofSize: 14, weight: .semibold)
      title.lineBreakMode = .byTruncatingTail

      let spacer = NSView()
      spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

      let headerRow = NSStackView(views: [keyIcon, title, spacer])
      headerRow.orientation = .horizontal
      headerRow.alignment = .centerY
      headerRow.spacing = 7
      stack.addArrangedSubview(headerRow)
      headerRow.widthAnchor.constraint(equalToConstant: innerWidth).isActive = true

      if let subtitle = group.subtitle {
        let subtitleLabel = NSTextField(labelWithString: subtitle)
        subtitleLabel.font = .systemFont(ofSize: 12)
        subtitleLabel.textColor = .secondaryLabelColor
        stack.addArrangedSubview(subtitleLabel)
      }

      if !group.fields.isEmpty {
        let pills = NSStackView()
        pills.orientation = .horizontal
        pills.spacing = 6
        let joined = group.fields.joined(separator: " ").count
        if joined <= 64 {
          for field in group.fields {
            pills.addArrangedSubview(Self.fieldPill(field))
          }
          stack.addArrangedSubview(pills)
        } else {
          for field in group.fields {
            let row = NSTextField(labelWithString: field)
            row.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
            stack.addArrangedSubview(row)
          }
        }
      }

      for uri in group.rawReferences {
        let row = NSTextField(wrappingLabelWithString: uri)
        row.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        row.maximumNumberOfLines = 3
        row.preferredMaxLayoutWidth = innerWidth
        stack.addArrangedSubview(row)
      }

      // Where the value will actually come from. For a reference that names no
      // account (`op://vault/item/field` never does), this is the only place the
      // chosen source is stated before Touch ID authorizes it.
      for note in group.notes {
        let row = NSTextField(wrappingLabelWithString: note)
        row.font = .systemFont(ofSize: 12)
        row.textColor = .secondaryLabelColor
        row.maximumNumberOfLines = 3
        row.preferredMaxLayoutWidth = innerWidth
        stack.addArrangedSubview(row)
      }
      for warning in group.warnings {
        let icon = NSImageView()
        icon.image = NSImage(
          systemSymbolName: "exclamationmark.triangle.fill",
          accessibilityDescription: "Warning"
        )
        icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 12, weight: .semibold)
        icon.contentTintColor = .systemOrange
        icon.setContentHuggingPriority(.required, for: .horizontal)
        icon.setContentCompressionResistancePriority(.required, for: .horizontal)

        let label = NSTextField(wrappingLabelWithString: warning)
        label.font = .systemFont(ofSize: 12, weight: .semibold)
        label.textColor = .systemOrange
        label.maximumNumberOfLines = 6
        label.preferredMaxLayoutWidth = innerWidth - 22

        let row = NSStackView(views: [icon, label])
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 6
        stack.addArrangedSubview(row)
        row.widthAnchor.constraint(equalToConstant: innerWidth).isActive = true
      }

      return Self.card(
        wrapping: stack,
        fill: NSColor.labelColor.withAlphaComponent(0.045),
        border: NSColor.separatorColor,
        width: width
      )
    }

    private static func fieldPill(_ text: String) -> NSView {
      let label = NSTextField(labelWithString: text)
      label.font = .monospacedSystemFont(ofSize: 11.5, weight: .medium)
      label.textColor = .labelColor
      return paddedBox(
        content: label,
        cornerRadius: 5,
        fill: NSColor.labelColor.withAlphaComponent(0.07),
        border: nil,
        horizontalPadding: 7,
        verticalPadding: 3
      )
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
      let runtime = "\(ReviewDisplay.duration(seconds: job.maximumRuntimeSeconds)) max per run"
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
      let command = Self.commandTextView(Self.safe(job.command.displayCommand), width: width)

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

    private static func commandTextView(_ command: String, width: CGFloat) -> NSView {
      let text = NSTextView()
      text.string = command
      text.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
      text.textColor = .labelColor
      text.drawsBackground = false
      text.isEditable = false
      text.isSelectable = true
      text.isRichText = false
      text.textContainerInset = NSSize(width: 7, height: 6)
      text.textContainer?.lineFragmentPadding = 0
      text.textContainer?.widthTracksTextView = true
      text.isHorizontallyResizable = false
      text.isVerticallyResizable = true
      text.autoresizingMask = [.width]

      let scroll = NSScrollView()
      scroll.borderType = .lineBorder
      scroll.drawsBackground = false
      scroll.hasVerticalScroller = true
      scroll.autohidesScrollers = true
      scroll.documentView = text
      NSLayoutConstraint.activate([
        scroll.widthAnchor.constraint(equalToConstant: width),
        scroll.heightAnchor.constraint(equalToConstant: 88),
      ])
      return scroll
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
      guard let details = automationDetailsView, let contentView = window.contentView else {
        return
      }
      let expanding = details.isHidden
      details.isHidden = !expanding
      sender.title = expanding
        ? "Hide command and security details"
        : "Show command and security details"
      sender.image = NSImage(
        systemSymbolName: expanding ? "chevron.down" : "chevron.right",
        accessibilityDescription: nil
      )

      let previousTop = window.frame.maxY
      contentView.layoutSubtreeIfNeeded()
      window.setContentSize(contentView.fittingSize)
      window.setFrameOrigin(NSPoint(x: window.frame.minX, y: previousTop - window.frame.height))
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
      let rows = NSStackView()
      rows.orientation = .vertical
      rows.alignment = .leading
      rows.spacing = 10
      rows.translatesAutoresizingMaskIntoConstraints = false

      for option in choices.options {
        let button = NSButton(
          radioButtonWithTitle: Self.safe(ReviewDisplay.scopeTitle(option)),
          target: self,
          action: #selector(scopePressed(_:))
        )
        button.font = .systemFont(ofSize: 13, weight: .medium)
        button.state = option.id == choices.defaultOptionID ? .on : .off
        button.tag = scopeButtons.count
        scopeButtons.append((id: option.id, button: button))

        let detail = NSTextField(
          wrappingLabelWithString: Self.safe(ReviewDisplay.scopeDetail(option))
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

      let footnote = NSTextField(
        wrappingLabelWithString:
          "A wider scope lets other commands in that process tree reuse these "
          + "credentials, without another prompt, until the grant expires."
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
        rows.append(("Grant root", Self.gridValue(ReviewDisplay.root(plan.root))))
      }
      rows += [
        ("Destination", Self.gridValue(ReviewDisplay.destination(plan.destination))),
        (
          "Requested duration",
          Self.gridValue(ReviewDisplay.duration(seconds: plan.requestedTTLSeconds))
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
      return Self.paddedBox(
        content: area,
        cornerRadius: 9,
        fill: NSColor.controlAccentColor.withAlphaComponent(0.06),
        border: nil,
        horizontalPadding: 14,
        verticalPadding: 10,
        width: Self.innerWidth
      )
    }

    private func authenticationStatusText() -> String {
      guard biometricsAvailable else {
        return "Touch ID is unavailable, so this request cannot be authorized."
      }
      return review.automation == nil
        ? "Touch ID is ready. Touch the sensor to release the requested value."
        : "Touch ID is ready. Touch the sensor to enable this job until you revoke it."
    }

    private func makeFooter() -> NSView {
      let spacer = NSView()
      spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
      spacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

      denyButton = NSButton(title: "Deny", target: self, action: #selector(denyPressed(_:)))
      denyButton.keyEquivalent = "\u{1b}"
      denyButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 84).isActive = true

      let footer = NSStackView(views: [spacer, denyButton])
      footer.orientation = .horizontal
      footer.alignment = .centerY
      footer.spacing = 10
      footer.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
      return footer
    }

    // MARK: - Selection and authentication flow

    private func collectPolicySelection() async -> AccessPolicyReviewOutcome {
      guard state == .ready else { return .denied }
      state = .selecting
      return await withCheckedContinuation { continuation in
        selectionContinuation = continuation
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        application.activate(ignoringOtherApps: true)
        window.center()
        window.makeKeyAndOrderFront(nil)
        window.displayIfNeeded()
        beginAuthentication()
      }
    }

    private func beginAuthentication() {
      guard state == .selecting, biometricsAvailable else { return }
      state = .authenticating
      denyButton.title = "Cancel"
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = authenticationStatusText()

      context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason: Self.initialAuthenticationReason(review)
      ) { [weak self] success, error in
        DispatchQueue.main.async {
          self?.authenticationFinished(success: success, error: error)
        }
      }
    }

    @objc private func denyPressed(_ sender: Any?) {
      finishDenied(closeWindow: true)
    }

    private func authenticationFinished(success: Bool, error: (any Error)?) {
      guard state == .authenticating else { return }
      if success {
        authenticationApproved()
      } else {
        if let error {
          FileHandle.standardError.write(
            Data(
              "csecd: embedded biometric consent denied (\(error.localizedDescription))\n".utf8
            ))
        }
        finishDenied(closeWindow: true)
      }
    }

    private func authenticationApproved() {
      guard state == .authenticating else { return }

      state = .awaitingPolicy
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = "Touch ID accepted…"

      // Freeze the scope the human had selected at the moment the biometric
      // succeeded; later clicks are ignored by `scopePressed`.
      for entry in scopeButtons { entry.button.isEnabled = false }

      let continuation = selectionContinuation
      selectionContinuation = nil
      continuation?.resume(
        returning: .approved(AccessPolicyApproval(
          authenticationSession: self,
          selectedScopeOptionID: selectedScopeOptionID
        )))
    }

    private func finishDenied(closeWindow shouldClose: Bool) {
      guard state != .finished else { return }
      state = .finished
      context.invalidate()
      let selection = selectionContinuation
      selectionContinuation = nil
      if shouldClose { closeWindow() }
      selection?.resume(returning: .denied)
    }

    private func closeWindow() {
      window.delegate = nil
      window.orderOut(nil)
      window.close()
    }

    func windowWillClose(_ notification: Notification) {
      finishDenied(closeWindow: false)
    }

    private static func initialAuthenticationReason(_ review: AccessPolicyReview) -> String {
      if let automation = review.automation {
        return "Allow unattended job \(safe(automation.job.name)) to use the displayed references until revoked"
      }
      let plan = review.plan
      // The default scope only; the live selection is displayed in this window,
      // which is the authoritative surface for an embedded (non-textual)
      // LAAuthenticationView. See `scopeButtons`.
      let scopeLine = review.scopeChoices.map {
        "; grant scope \(ReviewDisplay.scopeSummary($0.defaultOption))"
      } ?? ""
      let policySummary =
        "delivery \(plan.mechanism.rawValue); scope \(plan.descendantScope.rawValue); "
        + "destination \(plan.destination.rawValue)\(scopeLine)"
      return BiometricConsent.prompt(
        caller: review.caller,
        references: review.credentials.flatMap(\.references),
        reason: review.reason,
        ttl: TimeInterval(plan.requestedTTLSeconds),
        policySummary: policySummary
      )
    }

    private static func safe(_ value: String) -> String {
      ReviewDisplay.sanitized(value)
    }
  }
#endif
