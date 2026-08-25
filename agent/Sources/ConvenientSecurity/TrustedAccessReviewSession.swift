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

    private let review: AccessPolicyReview
    private let context: LAContext
    private var state = State.ready
    private var selectionContinuation: CheckedContinuation<AccessPolicyReviewOutcome, Never>?
    private var selectors: [String: NSPopUpButton] = [:]
    private var acceptanceButtons: [String: NSButton] = [:]
    private var policyControls: [NSControl] = []
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

    private func configureWindow() {
      let contentWidth: CGFloat = 760
      window = NSPanel(
        contentRect: NSRect(x: 0, y: 0, width: contentWidth, height: 820),
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

      let header = makeHeader()
      let summary = NSTextField(wrappingLabelWithString: Self.summary(review))
      summary.font = .systemFont(ofSize: 13)
      summary.textColor = .labelColor
      summary.maximumNumberOfLines = 12
      summary.preferredMaxLayoutWidth = contentWidth - 48

      let credentials = makeCredentialList(width: contentWidth - 48)
      authenticationView = LAAuthenticationView(context: context, controlSize: .large)
      authenticationView.setContentHuggingPriority(.required, for: .horizontal)
      authenticationView.setContentCompressionResistancePriority(.required, for: .horizontal)

      statusLabel = NSTextField(
        wrappingLabelWithString: biometricsAvailable
          ? "Touch ID is active. The exact selection shown when it succeeds is checked before release."
          : "Touch ID is unavailable, so this request cannot be authorized."
      )
      statusLabel.font = .systemFont(ofSize: 12)
      statusLabel.textColor = biometricsAvailable ? .secondaryLabelColor : .systemRed
      statusLabel.maximumNumberOfLines = 3
      statusLabel.preferredMaxLayoutWidth = 440

      let authenticationRow = NSStackView()
      authenticationRow.orientation = .horizontal
      authenticationRow.alignment = .centerY
      authenticationRow.spacing = 14
      authenticationRow.addArrangedSubview(authenticationView)
      authenticationRow.addArrangedSubview(statusLabel)

      let footer = makeFooter()
      var arrangedViews: [NSView] = [header, summary]
      if let warning = DeliveryReviewCopy.warning(for: review) {
        let warningLabel = NSTextField(wrappingLabelWithString: warning)
        warningLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        warningLabel.textColor = review.plan.recipientAssurance == .ordinaryPersistentFile
          ? .systemRed : .systemOrange
        warningLabel.maximumNumberOfLines = 8
        warningLabel.preferredMaxLayoutWidth = contentWidth - 48
        arrangedViews.append(warningLabel)
      }
      arrangedViews.append(contentsOf: [credentials, authenticationRow, footer])
      for view in arrangedViews {
        root.addArrangedSubview(view)
      }

      NSLayoutConstraint.activate([
        root.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 24),
        root.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -24),
        root.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 24),
        root.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -20),
        credentials.widthAnchor.constraint(equalTo: root.widthAnchor),
        authenticationRow.widthAnchor.constraint(equalTo: root.widthAnchor),
        footer.widthAnchor.constraint(equalTo: root.widthAnchor),
      ])
    }

    private func makeHeader() -> NSView {
      let icon = NSImageView(image: NSApplication.shared.applicationIconImage)
      icon.imageScaling = .scaleProportionallyUpOrDown
      NSLayoutConstraint.activate([
        icon.widthAnchor.constraint(equalToConstant: 56),
        icon.heightAnchor.constraint(equalToConstant: 56),
      ])

      let title = NSTextField(labelWithString: "Convenient Security Access Requested")
      title.font = .systemFont(ofSize: 22, weight: .semibold)
      let subtitle = NSTextField(
        wrappingLabelWithString:
          "Review exactly what will be released. Touch ID is active as soon as this window appears."
      )
      subtitle.font = .systemFont(ofSize: 13)
      subtitle.textColor = .secondaryLabelColor
      subtitle.maximumNumberOfLines = 2

      let labels = NSStackView(views: [title, subtitle])
      labels.orientation = .vertical
      labels.alignment = .leading
      labels.spacing = 4

      let header = NSStackView(views: [icon, labels])
      header.orientation = .horizontal
      header.alignment = .centerY
      header.spacing = 14
      return header
    }

    private func makeCredentialList(width: CGFloat) -> NSScrollView {
      let stack = NSStackView()
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 10
      stack.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
      stack.translatesAutoresizingMaskIntoConstraints = false

      for (index, credential) in review.credentials.enumerated() {
        let references = credential.references.map { "• \($0.safeInlineURI)" }
          .joined(separator: "\n")
        let label = NSTextField(wrappingLabelWithString: references)
        label.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        label.maximumNumberOfLines = 8
        label.preferredMaxLayoutWidth = width - 48
        stack.addArrangedSubview(label)

        if credential.storedLevel == .unknown {
          let row = NSStackView()
          row.orientation = .horizontal
          row.spacing = 8
          row.addArrangedSubview(NSTextField(labelWithString: "Risk level:"))
          let selector = NSPopUpButton()
          selector.addItems(withTitles: ["Low", "Standard", "High", "Critical"])
          selector.selectItem(withTitle: "Standard")
          row.addArrangedSubview(selector)
          stack.addArrangedSubview(row)
          selectors[credential.identity.credentialKey] = selector
          policyControls.append(selector)
        } else {
          let status = NSTextField(
            labelWithString: "Risk: \(credential.storedLevel.rawValue)"
          )
          status.font = .systemFont(ofSize: 12, weight: .semibold)
          stack.addArrangedSubview(status)
        }

        if credential.scopeExpanded {
          let scope = NSTextField(
            wrappingLabelWithString:
              "This request adds fields to the stored credential scope."
          )
          scope.textColor = .systemOrange
          stack.addArrangedSubview(scope)
        }

        if credential.compatibilityReviewOffered {
          let checkbox = NSButton(
            checkboxWithTitle: DeliveryReviewCopy.compatibilityAcceptanceLabel(
              for: review.plan,
              storedLevel: credential.storedLevel
            ),
            target: nil,
            action: nil
          )
          checkbox.state = credential.compatibilityAccepted ? .on : .off
          checkbox.isEnabled = !credential.compatibilityAccepted
          stack.addArrangedSubview(checkbox)
          acceptanceButtons[credential.identity.credentialKey] = checkbox
          policyControls.append(checkbox)
        }

        if index < review.credentials.count - 1 {
          let separator = NSBox()
          separator.boxType = .separator
          stack.addArrangedSubview(separator)
          separator.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -24).isActive =
            true
        }
      }

      let scroll = NSScrollView()
      scroll.hasVerticalScroller = true
      scroll.autohidesScrollers = true
      scroll.borderType = .bezelBorder
      scroll.documentView = stack
      scroll.heightAnchor.constraint(equalToConstant: 280).isActive = true
      NSLayoutConstraint.activate([
        stack.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
        stack.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
        stack.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
        stack.bottomAnchor.constraint(equalTo: scroll.contentView.bottomAnchor),
        stack.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
      ])
      return scroll
    }

    private func makeFooter() -> NSView {
      let spacer = NSView()
      spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
      spacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

      denyButton = NSButton(title: "Deny", target: self, action: #selector(denyPressed(_:)))
      denyButton.keyEquivalent = "\u{1b}"

      let footer = NSStackView(views: [spacer, denyButton])
      footer.orientation = .horizontal
      footer.alignment = .centerY
      footer.spacing = 10
      return footer
    }

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
        "Touch ID is active. Adjust the selection if needed, then touch the sensor."

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

    private func selectedPolicy() -> AccessPolicyApproval? {
      var classifications: [String: RiskLevel] = [:]
      for (credentialKey, selector) in selectors {
        let raw = selector.titleOfSelectedItem?.lowercased() ?? ""
        guard let level = RiskLevel(rawValue: raw), level != .unknown else {
          showValidationError("Choose an explicit risk level for every new credential.")
          return nil
        }
        classifications[credentialKey] = level
      }

      let accepted = Set(
        acceptanceButtons.compactMap { key, button in
          button.state == .on ? key : nil
        })
      return AccessPolicyApproval(
        classifications: classifications,
        acceptedCompatibilityCredentialKeys: accepted
      )
    }

    private func showValidationError(_ message: String) {
      statusLabel.textColor = .systemRed
      statusLabel.stringValue = message
      statusLabel.isHidden = false
      NSSound.beep()
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
      guard let selection = selectedPolicy() else {
        finishDenied(closeWindow: true)
        return
      }

      state = .awaitingPolicy
      for control in policyControls {
        control.isEnabled = false
      }
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = "Touch ID accepted. Checking the exact selection…"

      let continuation = selectionContinuation
      selectionContinuation = nil
      continuation?.resume(
        returning: .approved(
          AccessPolicyApproval(
            classifications: selection.classifications,
            acceptedCompatibilityCredentialKeys: selection.acceptedCompatibilityCredentialKeys,
            authenticationSession: self
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

    private static func summary(_ review: AccessPolicyReview) -> String {
      let executable = URL(fileURLWithPath: review.plan.executable.canonicalPath).lastPathComponent
      return """
        Requester / grant owner: \(safe(review.caller.description))
        Emitter: \(safe(executable)) (\(review.plan.executable.assurance.rawValue))
        Recipient: \(safe(DeliveryReviewCopy.recipientDescription(for: review.plan)))
        Delivery: \(review.plan.mechanism.rawValue), \(review.plan.descendantScope.rawValue)
        Grant root: \(rootDescription(review.plan.root))
        Destination: \(review.plan.destination.rawValue)
        Requested duration: \(BiometricConsent.formatDuration(TimeInterval(review.plan.requestedTTLSeconds)))
        Purpose: \(safe(review.reason))

        Classification describes the credential itself. Compatibility delivery is accepted separately. No secret values are shown in this window.
        """
    }

    private static func initialAuthenticationReason(_ review: AccessPolicyReview) -> String {
      let plan = review.plan
      let policySummary =
        "use the risk selection visible in Convenient Security; delivery "
        + "\(plan.mechanism.rawValue); scope \(plan.descendantScope.rawValue); "
        + "destination \(plan.destination.rawValue)"
      return BiometricConsent.prompt(
        caller: review.caller,
        references: review.credentials.flatMap(\.references),
        reason: review.reason,
        ttl: TimeInterval(plan.requestedTTLSeconds),
        policySummary: policySummary
      )
    }

    private static func rootDescription(_ root: DeliveryRoot) -> String {
      switch root {
      case .caller: return "requesting launcher"
      case .directParent: return "verified direct parent"
      case .registeredSession: return "registered kernel-verified session"
      }
    }

    private static func safe(_ value: String) -> String {
      let bidiControls: Set<UInt32> = [
        0x061c, 0x200e, 0x200f,
        0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
        0x2066, 0x2067, 0x2068, 0x2069,
      ]
      return value.unicodeScalars.map { scalar in
        if CharacterSet.controlCharacters.contains(scalar)
          || CharacterSet.newlines.contains(scalar)
          || bidiControls.contains(scalar.value)
        {
          return "�"
        }
        return String(scalar)
      }.joined()
    }
  }
#endif
