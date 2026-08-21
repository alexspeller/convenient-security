import Foundation
@preconcurrency import AppKit
import ConvenientSecurity

/// A deliberately fileless editor for native-store JSON. `NSTextView` and its
/// undo state live in the signed launcher's heap; no plaintext temp file, swap
/// file, editor backup, clipboard, or shell transport is created by csec.
enum NativeStoreEditor {
    static func edit(store: String, document: Data) throws -> Data? {
        guard let text = String(data: document, encoding: .utf8) else {
            throw NativeStoreError.invalidDocument
        }

        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)

        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "Edit native store “\(store)”"
        alert.informativeText = "Plaintext remains in this signed editor's memory. Saving validates the JSON and atomically replaces the authenticated ciphertext."
        alert.addButton(withTitle: "Save Encrypted")
        alert.addButton(withTitle: "Cancel")

        let scrollView = NSScrollView(frame: NSRect(x: 0, y: 0, width: 760, height: 500))
        scrollView.borderType = .bezelBorder
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true

        let textView = NSTextView(frame: scrollView.contentView.bounds)
        textView.isRichText = false
        textView.importsGraphics = false
        textView.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        textView.string = text
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = true
        textView.autoresizingMask = []
        textView.minSize = NSSize(width: 0, height: scrollView.contentSize.height)
        textView.maxSize = NSSize(
            width: CGFloat.greatestFiniteMagnitude,
            height: CGFloat.greatestFiniteMagnitude
        )
        textView.textContainer?.containerSize = NSSize(
            width: CGFloat.greatestFiniteMagnitude,
            height: CGFloat.greatestFiniteMagnitude
        )
        textView.textContainer?.widthTracksTextView = false
        textView.isContinuousSpellCheckingEnabled = false
        textView.isGrammarCheckingEnabled = false
        textView.isAutomaticSpellingCorrectionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticLinkDetectionEnabled = false
        textView.isAutomaticDataDetectionEnabled = false
        scrollView.documentView = textView
        alert.accessoryView = scrollView

        alert.window.title = "Convenient Security"
        alert.window.isRestorable = false
        alert.window.initialFirstResponder = textView
        application.activate(ignoringOtherApps: true)
        let response = alert.runModal()

        guard response == .alertFirstButtonReturn else {
            clear(textView)
            return nil
        }
        let edited = Data(textView.string.utf8)
        clear(textView)
        return edited
    }

    private static func clear(_ textView: NSTextView) {
        // A replacement can itself become an undo action. Disable registration
        // around the wipe, then remove actions on both sides so AppKit does not
        // retain the previous document for an Undo command until process exit.
        textView.breakUndoCoalescing()
        textView.undoManager?.removeAllActions()
        textView.undoManager?.disableUndoRegistration()
        textView.string = ""
        textView.undoManager?.enableUndoRegistration()
        textView.undoManager?.removeAllActions()
    }

    static func showValidationError(_ message: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "The store was not saved"
        alert.informativeText = message
        alert.addButton(withTitle: "Return to Editor")
        alert.window.title = "Convenient Security"
        alert.window.isRestorable = false
        NSApplication.shared.activate(ignoringOtherApps: true)
        alert.runModal()
    }
}
