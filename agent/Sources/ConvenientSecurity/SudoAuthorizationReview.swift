import Foundation

public struct SudoAuthorizationReviewRequest: Sendable, Equatable {
  public let submittedCommand: String
  public let workingDirectory: String
  public let terminal: String

  public init(
    submittedCommand: String,
    workingDirectory: String,
    terminal: String
  ) {
    self.submittedCommand = ReviewDisplay.sanitized(submittedCommand)
    self.workingDirectory = ReviewDisplay.sanitized(workingDirectory)
    self.terminal = ReviewDisplay.sanitized(terminal)
  }
}

public enum SudoAuthorizationReviewOutcome: Sendable, Equatable {
  case approved
  case usePassword
}

/// Narrow binary handoff from the root PAM process to the unprivileged review
/// helper. The command is already escaped and redacted before it enters this
/// frame; no raw argv or secret catalog crosses this boundary.
public enum SudoAuthorizationReviewWire {
  public static let maximumCommandBytes = 8_191
  public static let maximumContextBytes = 255

  private static let magic = Data("CSECSUDO".utf8)
  private static let version = 1
  private static let headerBytes = 8 + 4 + 4 + 4 + 4

  public static func encode(_ request: SudoAuthorizationReviewRequest) -> Data? {
    let command = Data(request.submittedCommand.utf8)
    let directory = Data(request.workingDirectory.utf8)
    let terminal = Data(request.terminal.utf8)
    guard !command.isEmpty,
      command.count <= maximumCommandBytes,
      directory.count <= maximumContextBytes,
      terminal.count <= maximumContextBytes,
      !command.contains(0),
      !directory.contains(0),
      !terminal.contains(0)
    else { return nil }

    var frame = Data()
    frame.reserveCapacity(headerBytes + command.count + directory.count + terminal.count)
    frame.append(magic)
    appendUInt32(UInt32(version), to: &frame)
    appendUInt32(UInt32(command.count), to: &frame)
    appendUInt32(UInt32(directory.count), to: &frame)
    appendUInt32(UInt32(terminal.count), to: &frame)
    frame.append(command)
    frame.append(directory)
    frame.append(terminal)
    return frame
  }

  public static func decode(_ frame: Data) -> SudoAuthorizationReviewRequest? {
    guard frame.count >= headerBytes,
      frame.prefix(magic.count) == magic
    else { return nil }

    var offset = magic.count
    guard let decodedVersion = readUInt32(frame, offset: &offset),
      decodedVersion == version,
      let commandLength = readUInt32(frame, offset: &offset),
      let directoryLength = readUInt32(frame, offset: &offset),
      let terminalLength = readUInt32(frame, offset: &offset),
      commandLength > 0,
      commandLength <= maximumCommandBytes,
      directoryLength <= maximumContextBytes,
      terminalLength <= maximumContextBytes
    else { return nil }

    let lengths = [commandLength, directoryLength, terminalLength]
    guard lengths.allSatisfy({ $0 <= Int.max - offset }) else { return nil }
    let expectedPayload = lengths.reduce(0, +)
    guard expectedPayload == frame.count - offset else { return nil }

    func readString(length: Int) -> String? {
      guard length <= frame.count - offset else { return nil }
      let bytes = frame[offset..<(offset + length)]
      offset += length
      guard !bytes.contains(0) else { return nil }
      return String(data: bytes, encoding: .utf8)
    }

    guard let command = readString(length: commandLength),
      let directory = readString(length: directoryLength),
      let terminal = readString(length: terminalLength),
      offset == frame.count
    else { return nil }
    return SudoAuthorizationReviewRequest(
      submittedCommand: command,
      workingDirectory: directory,
      terminal: terminal
    )
  }

  private static func appendUInt32(_ value: UInt32, to data: inout Data) {
    data.append(UInt8((value >> 24) & 0xff))
    data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
  }

  private static func readUInt32(_ data: Data, offset: inout Int) -> Int? {
    guard data.count - offset >= 4 else { return nil }
    let value =
      (UInt32(data[offset]) << 24)
      | (UInt32(data[offset + 1]) << 16)
      | (UInt32(data[offset + 2]) << 8)
      | UInt32(data[offset + 3])
    offset += 4
    return Int(value)
  }
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @preconcurrency import AppKit
  @preconcurrency import LocalAuthentication
  @preconcurrency import LocalAuthenticationEmbeddedUI

  @MainActor
  public final class TrustedSudoAuthorizationReviewSession: NSObject, NSWindowDelegate,
    NSApplicationDelegate
  {
    private enum State {
      case ready
      case authenticating
      case finished
    }

    private static let contentWidth: CGFloat = 640
    private static let horizontalMargin: CGFloat = 28
    private static var innerWidth: CGFloat { contentWidth - horizontalMargin * 2 }

    private let review: SudoAuthorizationReviewRequest
    private let context = LAContext()
    private var state = State.ready
    private var continuation: CheckedContinuation<SudoAuthorizationReviewOutcome, Never>?
    private var biometricsAvailable = false

    private var window: NSPanel!
    private var authenticationView: LAAuthenticationView!
    private var statusLabel: NSTextField!
    private var fallbackButton: NSButton!

    private init(review: SudoAuthorizationReviewRequest) {
      self.review = review
      super.init()
      configureAuthentication()
      configureWindow()
    }

    public static func present(
      _ review: SudoAuthorizationReviewRequest
    ) async -> SudoAuthorizationReviewOutcome {
      let session = TrustedSudoAuthorizationReviewSession(review: review)
      return await session.run()
    }

    /// Dev-only, value-free design harness. It renders the real panel without
    /// ordering it onscreen or starting LocalAuthentication.
    public static func previewPNG(
      _ review: SudoAuthorizationReviewRequest
    ) -> Data? {
      let session = TrustedSudoAuthorizationReviewSession(review: review)
      guard let content = session.window.contentView else { return nil }
      let target = content.superview ?? content
      target.layoutSubtreeIfNeeded()
      session.window.displayIfNeeded()
      guard let bitmap = target.bitmapImageRepForCachingDisplay(in: target.bounds) else {
        return nil
      }
      target.cacheDisplay(in: target.bounds, to: bitmap)
      return bitmap.representation(using: .png, properties: [:])
    }

    private func configureAuthentication() {
      context.localizedCancelTitle = "Use Password…"
      context.localizedFallbackTitle = ""
      context.touchIDAuthenticationAllowableReuseDuration = 0
      var evaluationError: NSError?
      biometricsAvailable = context.canEvaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        error: &evaluationError
      )
    }

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
      root.addArrangedSubview(
        Self.makeBanner(
          text: "ADMINISTRATOR ACCESS: An approved sudo command can modify any local "
            + "account or system file. Verify every displayed argument before touching "
            + "the sensor.",
          tint: .systemOrange,
          width: Self.innerWidth
        ))

      root.addArrangedSubview(Self.makeSectionLabel("Submitted command"))
      root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
      root.addArrangedSubview(makeCommandCard(width: Self.innerWidth))

      root.addArrangedSubview(Self.makeSectionLabel("Request"))
      root.setCustomSpacing(6, after: root.arrangedSubviews.last!)
      root.addArrangedSubview(makeDetailsGrid())

      let footnote = NSTextField(
        wrappingLabelWithString:
          "This is the frozen, redacted submitted argv received before Touch ID starts. "
          + "Touch ID verifies the current user; it does not attest the window pixels. "
          + "Sudo policy resolves the executable after authentication."
      )
      footnote.font = .systemFont(ofSize: 11)
      footnote.textColor = .tertiaryLabelColor
      footnote.maximumNumberOfLines = 4
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

      let title = NSTextField(labelWithString: "Administrator Access Requested")
      title.font = .systemFont(ofSize: 19, weight: .semibold)

      let purpose = NSTextField(
        wrappingLabelWithString:
          "sudo wants to run the submitted command with administrator privileges."
      )
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

    private func makeCommandCard(width: CGFloat) -> NSView {
      let innerWidth = width - 24
      let command = NSTextField(wrappingLabelWithString: review.submittedCommand)
      command.font = .monospacedSystemFont(ofSize: 12.5, weight: .regular)
      command.textColor = .labelColor
      command.isSelectable = true
      command.maximumNumberOfLines = 0
      command.preferredMaxLayoutWidth = innerWidth
      command.translatesAutoresizingMaskIntoConstraints = false
      command.widthAnchor.constraint(equalToConstant: innerWidth).isActive = true
      command.layoutSubtreeIfNeeded()

      let maximumHeight: CGFloat = 180
      let content: NSView
      if command.fittingSize.height <= maximumHeight {
        content = command
      } else {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.drawsBackground = false
        scroll.documentView = command
        scroll.heightAnchor.constraint(equalToConstant: maximumHeight).isActive = true
        NSLayoutConstraint.activate([
          command.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
          command.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
          command.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
          command.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
        ])
        content = scroll
      }

      return Self.card(
        wrapping: content,
        fill: NSColor.labelColor.withAlphaComponent(0.045),
        border: NSColor.separatorColor,
        width: width
      )
    }

    private func makeDetailsGrid() -> NSView {
      let rows: [(String, String)] = [
        ("Requested by", "sudo"),
        ("Privilege", "Administrator (root)"),
        ("Working directory", review.workingDirectory),
        ("Terminal", review.terminal),
        ("Argument filtering", "Active csec catalog + secret-like heuristics"),
      ]
      let grid = NSGridView(
        views: rows.map { [Self.gridLabel($0.0), Self.gridValue($0.1)] }
      )
      grid.columnSpacing = 14
      grid.rowSpacing = 6
      grid.rowAlignment = .none
      grid.column(at: 0).xPlacement = .trailing
      grid.translatesAutoresizingMaskIntoConstraints = false
      return grid
    }

    private func makeAuthenticationArea() -> NSView {
      authenticationView = LAAuthenticationView(context: context, controlSize: .large)
      authenticationView.setContentHuggingPriority(.required, for: .horizontal)
      authenticationView.setContentCompressionResistancePriority(.required, for: .horizontal)

      statusLabel = NSTextField(
        wrappingLabelWithString: biometricsAvailable
          ? "Touch ID is active. Touch the sensor to authorize, or use your password."
          : "Touch ID is unavailable. Continue with the standard password prompt."
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

      fallbackButton = NSButton(
        title: "Use Password…",
        target: self,
        action: #selector(usePasswordPressed(_:))
      )
      fallbackButton.keyEquivalent = "\u{1b}"
      fallbackButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 112).isActive = true

      let footer = NSStackView(views: [spacer, fallbackButton])
      footer.orientation = .horizontal
      footer.alignment = .centerY
      footer.spacing = 10
      footer.widthAnchor.constraint(equalToConstant: Self.innerWidth).isActive = true
      return footer
    }

    private func run() async -> SudoAuthorizationReviewOutcome {
      guard state == .ready else { return .usePassword }
      return await withCheckedContinuation { continuation in
        self.continuation = continuation
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        application.delegate = self
        application.activate(ignoringOtherApps: true)
        window.center()
        window.makeKeyAndOrderFront(nil)
        window.displayIfNeeded()
        beginAuthentication()
      }
    }

    private func beginAuthentication() {
      guard state == .ready, biometricsAvailable else { return }
      state = .authenticating
      context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason:
          "Confirm administrator access after reviewing the submitted sudo invocation."
      ) { [weak self] success, _ in
        DispatchQueue.main.async {
          self?.authenticationFinished(success: success)
        }
      }
    }

    private func authenticationFinished(success: Bool) {
      guard state == .authenticating else { return }
      if success {
        finish(.approved)
      } else {
        finish(.usePassword)
      }
    }

    @objc private func usePasswordPressed(_ sender: Any?) {
      finish(.usePassword)
    }

    private func finish(_ outcome: SudoAuthorizationReviewOutcome) {
      guard state != .finished else { return }
      state = .finished
      context.invalidate()
      let pending = continuation
      continuation = nil
      closeWindow()
      pending?.resume(returning: outcome)
    }

    private func closeWindow() {
      window.delegate = nil
      window.orderOut(nil)
      window.close()
    }

    public func windowWillClose(_ notification: Notification) {
      finish(.usePassword)
    }

    public func applicationShouldTerminate(
      _ sender: NSApplication
    ) -> NSApplication.TerminateReply {
      finish(.usePassword)
      return .terminateCancel
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
      return card(
        wrapping: content,
        fill: tint.withAlphaComponent(0.09),
        border: tint.withAlphaComponent(0.35),
        width: width
      )
    }

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

    private static func gridLabel(_ text: String) -> NSTextField {
      let label = NSTextField(labelWithString: text)
      label.font = .systemFont(ofSize: 13)
      label.textColor = .secondaryLabelColor
      return label
    }

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
  }
#else
  public enum TrustedSudoAuthorizationReviewSession {
    public static func present(
      _ review: SudoAuthorizationReviewRequest
    ) async -> SudoAuthorizationReviewOutcome {
      .usePassword
    }

    public static func previewPNG(
      _ review: SudoAuthorizationReviewRequest
    ) -> Data? {
      nil
    }
  }
#endif
