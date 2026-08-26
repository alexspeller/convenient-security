#if canImport(AppKit)
import AppKit
import Foundation
import LocalAuthentication

// The trusted, agent-owned checklist window for batched host remediation. Each
// reversible fix is a default-on, deselectable row; a single Touch ID (the system
// biometric sheet) authorizes the still-selected set. Only value-free titles and
// details are ever shown; the selection never crosses an untrusted IPC boundary
// (csecd owns both the controls and the apply). This is the remediation sibling
// of `TrustedAccessReviewSession`.
@MainActor
final class HostRemediationReviewSession: NSObject, NSWindowDelegate {
    private let items: [HostRemediationItem]
    private var checkboxes: [NSButton] = []
    private var actionButtons: [NSButton] = []
    private let context = LAContext()
    private var window: NSPanel!
    private var continuation: CheckedContinuation<HostRemediationOutcome, Never>?
    private var finished = false
    private var biometricsAvailable = false

    private init(items: [HostRemediationItem]) {
        self.items = items
        super.init()
        context.localizedCancelTitle = "Not now"
        context.localizedFallbackTitle = ""
        var error: NSError?
        biometricsAvailable = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &error)
        if !biometricsAvailable {
            FileHandle.standardError.write(Data(
                "csecd: biometrics unavailable, denying host remediation (\(error?.localizedDescription ?? "no Touch ID"))\n".utf8))
        }
    }

    static func present(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        let session = HostRemediationReviewSession(items: review.items)
        return await session.run()
    }

    private func run() async -> HostRemediationOutcome {
        guard biometricsAvailable, !items.isEmpty else { return .denied }
        buildWindow()
        return await withCheckedContinuation { continuation in
            self.continuation = continuation
            let application = NSApplication.shared
            application.setActivationPolicy(.accessory)
            application.activate(ignoringOtherApps: true)
            window.center()
            window.makeKeyAndOrderFront(nil)
            window.displayIfNeeded()
        }
    }

    // MARK: Layout

    private func buildWindow() {
        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.edgeInsets = NSEdgeInsets(top: 22, left: 28, bottom: 18, right: 28)
        root.spacing = 10
        root.translatesAutoresizingMaskIntoConstraints = false

        let title = label("Apply reversible security fixes", font: .boldSystemFont(ofSize: 15))
        let subtitle = label(
            "csec found \(items.count) safe, reversible fix(es). Deselect anything you want to keep as-is; one Touch ID applies the rest.",
            font: .systemFont(ofSize: 12), color: .secondaryLabelColor, wraps: true, width: 520)
        root.addArrangedSubview(title)
        root.addArrangedSubview(subtitle)
        root.setCustomSpacing(14, after: subtitle)

        for (index, item) in items.enumerated() {
            root.addArrangedSubview(makeRow(item, tag: index))
        }

        let buttons = NSStackView()
        buttons.orientation = .horizontal
        buttons.spacing = 12
        let apply = NSButton(title: "Apply with Touch ID", target: self, action: #selector(applyTapped))
        apply.keyEquivalent = "\r"
        apply.bezelStyle = .rounded
        let cancel = NSButton(title: "Not now", target: self, action: #selector(cancelTapped))
        cancel.keyEquivalent = "\u{1b}"
        cancel.bezelStyle = .rounded
        actionButtons = [apply, cancel]
        buttons.addArrangedSubview(cancel)
        buttons.addArrangedSubview(apply)
        root.setCustomSpacing(18, after: root.arrangedSubviews.last ?? subtitle)
        root.addArrangedSubview(buttons)

        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 580, height: 200),
            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = "Convenient Security"
        panel.level = .modalPanel
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.isRestorable = false
        panel.delegate = self
        panel.contentView = root
        if let content = panel.contentView {
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor).isActive = true
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor).isActive = true
            root.topAnchor.constraint(equalTo: content.topAnchor).isActive = true
            root.bottomAnchor.constraint(equalTo: content.bottomAnchor).isActive = true
        }
        root.layoutSubtreeIfNeeded()
        panel.setContentSize(root.fittingSize)
        window = panel
    }

    private func makeRow(_ item: HostRemediationItem, tag: Int) -> NSView {
        let checkbox = NSButton(checkboxWithTitle: "", target: nil, action: nil)
        checkbox.state = .on
        checkbox.tag = tag
        checkboxes.append(checkbox)

        let titleText = item.requiresRoot ? "\(Self.safe(item.title))  · root" : Self.safe(item.title)
        let heading = label(titleText, font: .systemFont(ofSize: 13, weight: .medium))
        let detail = label(Self.safe(item.detail), font: .systemFont(ofSize: 11),
                           color: .secondaryLabelColor, wraps: true, width: 500)
        let textStack = NSStackView(views: [heading, detail])
        textStack.orientation = .vertical
        textStack.alignment = .leading
        textStack.spacing = 2

        let row = NSStackView(views: [checkbox, textStack])
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 8
        return card(row)
    }

    // MARK: Actions

    @objc private func applyTapped() {
        guard !finished else { return }
        let selected = zip(checkboxes, items)
            .filter { $0.0.state == .on }
            .map { $0.1.key }
        guard !selected.isEmpty else {
            finish(.denied)
            return
        }
        for control in checkboxes + actionButtons { control.isEnabled = false }
        let reason = "apply \(selected.count) reversible security fix(es)"
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { [weak self] success, _ in
            DispatchQueue.main.async {
                self?.finish(success ? .approved(selectedKeys: selected) : .denied)
            }
        }
    }

    @objc private func cancelTapped() {
        finish(.denied)
    }

    func windowWillClose(_ notification: Notification) {
        finish(.denied)
    }

    private func finish(_ outcome: HostRemediationOutcome) {
        guard !finished else { return }
        finished = true
        if window.isVisible { window.close() }
        let continuation = self.continuation
        self.continuation = nil
        continuation?.resume(returning: outcome)
    }

    // MARK: Helpers

    private func label(_ text: String, font: NSFont, color: NSColor = .labelColor,
                       wraps: Bool = false, width: CGFloat = 0) -> NSTextField {
        let field = NSTextField(labelWithString: text)
        field.font = font
        field.textColor = color
        if wraps {
            field.lineBreakMode = .byWordWrapping
            field.maximumNumberOfLines = 0
            if width > 0 {
                field.preferredMaxLayoutWidth = width
                field.widthAnchor.constraint(lessThanOrEqualToConstant: width).isActive = true
            }
        }
        return field
    }

    private func card(_ content: NSView) -> NSView {
        let box = NSBox()
        box.boxType = .custom
        box.borderColor = .separatorColor
        box.fillColor = NSColor.labelColor.withAlphaComponent(0.04)
        box.cornerRadius = 9
        box.borderWidth = 1
        box.contentViewMargins = NSSize(width: 12, height: 10)
        box.contentView = content
        content.translatesAutoresizingMaskIntoConstraints = false
        if let inner = box.contentView {
            content.leadingAnchor.constraint(equalTo: inner.leadingAnchor, constant: 12).isActive = true
            content.trailingAnchor.constraint(equalTo: inner.trailingAnchor, constant: -12).isActive = true
            content.topAnchor.constraint(equalTo: inner.topAnchor, constant: 10).isActive = true
            content.bottomAnchor.constraint(equalTo: inner.bottomAnchor, constant: -10).isActive = true
        }
        return box
    }

    static func safe(_ value: String) -> String {
        ReviewDisplay.sanitized(value)
    }
}
#endif
