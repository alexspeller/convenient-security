#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @preconcurrency import AppKit
  import Foundation
  @preconcurrency import LocalAuthentication
  @preconcurrency import LocalAuthenticationEmbeddedUI

  /// One trusted window owns policy selection and the LAContext-backed Touch ID
  /// view. Authentication starts as soon as the visible window is rendered. On
  /// success the exact visible selections are frozen and returned to Agent,
  /// which must still accept them before this session releases its LAContext.
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

    private init(review: AccessPolicyReview) {
      self.review = review
      self.context = LAContext()
      super.init()
      configureAuthentication()
      configureWindow()
    }

    static func present(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
      let session = TrustedAccessReviewSession(review: review)
      return await session.collectPolicySelection()
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

      if let warning = DeliveryReviewCopy.warning(for: review) {
        let tint: NSColor =
          review.plan.recipientAssurance == .ordinaryPersistentFile ? .systemRed : .systemOrange
        root.addArrangedSubview(
          Self.makeBanner(text: warning, tint: tint, width: Self.innerWidth))
      }

      root.addArrangedSubview(Self.makeSectionLabel("Credentials to be released"))
      root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
      let credentialCards = makeCredentialCards(width: Self.innerWidth)
      root.addArrangedSubview(credentialCards)

      root.addArrangedSubview(Self.makeSectionLabel("Request"))
      root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
      root.addArrangedSubview(makeDetailsGrid())

      let footnote = NSTextField(
        wrappingLabelWithString:
          "Touch ID authorizes this exact release. No secret values are shown in this window."
      )
      footnote.font = .systemFont(ofSize: 11)
      footnote.textColor = .tertiaryLabelColor
      footnote.maximumNumberOfLines = 3
      footnote.preferredMaxLayoutWidth = Self.innerWidth
      root.addArrangedSubview(footnote)

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

      let title = NSTextField(labelWithString: "Secret Access Requested")
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

      let group = ReviewDisplay.referenceGroup(for: credential.references)

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

      let rows: [(String, NSView)] = [
        ("Requested by", Self.gridValue(Self.safe(review.caller.description))),
        ("Emitted by", emitterValue),
        ("Delivered to", Self.gridValue(DeliveryReviewCopy.recipientDescription(for: plan))),
        (
          "Delivery",
          Self.gridValue(
            "\(ReviewDisplay.mechanism(plan.mechanism)) · \(ReviewDisplay.scope(plan.descendantScope))"
          )
        ),
        ("Grant root", Self.gridValue(ReviewDisplay.root(plan.root))),
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
      authenticationView = LAAuthenticationView(context: context, controlSize: .large)
      authenticationView.setContentHuggingPriority(.required, for: .horizontal)
      authenticationView.setContentCompressionResistancePriority(.required, for: .horizontal)

      statusLabel = NSTextField(
        wrappingLabelWithString: biometricsAvailable
          ? "Touch ID is active. Touch the sensor to release the value, or Deny."
          : "Touch ID is unavailable, so this request cannot be authorized."
      )
      statusLabel.font = .systemFont(ofSize: 12)
      statusLabel.textColor = biometricsAvailable ? .secondaryLabelColor : .systemRed
      statusLabel.alignment = .center
      statusLabel.maximumNumberOfLines = 3
      statusLabel.preferredMaxLayoutWidth = Self.innerWidth - 80

      let area = NSStackView(views: [authenticationView, statusLabel])
      area.orientation = .vertical
      area.alignment = .centerX
      area.spacing = 8
      area.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
      return area
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
      statusLabel.stringValue =
        "Touch ID is active. Touch the sensor to authorize, or Deny."

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

      let continuation = selectionContinuation
      selectionContinuation = nil
      continuation?.resume(
        returning: .approved(AccessPolicyApproval(authenticationSession: self)))
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
      let plan = review.plan
      let policySummary =
        "delivery \(plan.mechanism.rawValue); scope \(plan.descendantScope.rawValue); "
        + "destination \(plan.destination.rawValue)"
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
