import Foundation
@preconcurrency import AppKit
import ConvenientSecurity
#if canImport(Darwin)
import Darwin
#endif

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

enum ExternalNativeStoreEditorError: Error, LocalizedError {
    case temporaryWorkspaceUnavailable
    case editorLaunchFailed
    case editorFailed
    case editedFileUnavailable
    case editedFileUnsafe
    case editedFileTooLarge

    var errorDescription: String? {
        switch self {
        case .temporaryWorkspaceUnavailable:
            return "the private editor workspace could not be created"
        case .editorLaunchFailed:
            return "$EDITOR could not be started"
        case .editorFailed:
            return "$EDITOR did not exit successfully"
        case .editedFileUnavailable:
            return "$EDITOR did not leave an edited document"
        case .editedFileUnsafe:
            return "$EDITOR replaced the document with an unsafe filesystem object"
        case .editedFileTooLarge:
            return "$EDITOR produced a document over the 1 MiB limit"
        }
    }
}

/// Explicitly weaker editing mode for users who need a full external editor.
/// A randomized 0700 workspace and 0600 regular file limit accidental exposure
/// to other accounts, but do not defend the named plaintext from the same UID,
/// the selected editor, its plugins, or copies it creates elsewhere.
enum ExternalNativeStoreEditor {
    static let workspacePrefix = ".csec-edit-"

    private static let documentName = "secrets.json"
    private static let maximumWorkspaceAttempts = 16

    static func edit(command: ExternalEditorCommand, document: Data) throws -> Data {
        let workspace = try makeWorkspace()
        defer { workspace.removeBestEffort() }

        try writeInitialDocument(document, directoryFD: workspace.directoryFD)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: command.executablePath)
        process.arguments = command.arguments + [workspace.documentURL.path]
        process.environment = ProcessInfo.processInfo.environment
        process.standardInput = FileHandle.standardInput
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError
        do {
            try process.run()
        } catch {
            throw ExternalNativeStoreEditorError.editorLaunchFailed
        }
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else {
            throw ExternalNativeStoreEditorError.editorFailed
        }

        return try readEditedDocument(directoryFD: workspace.directoryFD)
    }

    private final class Workspace {
        let directoryFD: Int32
        let directoryURL: URL
        private let device: dev_t
        private let inode: ino_t

        init(directoryFD: Int32, directoryURL: URL, info: stat) {
            self.directoryFD = directoryFD
            self.directoryURL = directoryURL
            self.device = info.st_dev
            self.inode = info.st_ino
        }

        var documentURL: URL { directoryURL.appendingPathComponent(documentName) }

        func removeBestEffort() {
            documentName.withCString { _ = unlinkat(directoryFD, $0, 0) }

            // FileManager cleanup catches swap/backup files the editor left in
            // this exact randomized directory. Check identity first so a path
            // replacement cannot redirect this best-effort recursive removal.
            var pathInfo = stat()
            let unchanged = directoryURL.path.withCString {
                lstat($0, &pathInfo) == 0
            } && (pathInfo.st_mode & S_IFMT) == S_IFDIR
                && pathInfo.st_dev == device
                && pathInfo.st_ino == inode
            close(directoryFD)
            if unchanged {
                try? FileManager.default.removeItem(at: directoryURL)
            }
        }
    }

    private static func makeWorkspace() throws -> Workspace {
        do {
            try AgentSocket.ensureDirectory()
        } catch {
            throw ExternalNativeStoreEditorError.temporaryWorkspaceUnavailable
        }

        let basePath = AgentSocket.directory()
        let baseFD = basePath.withCString {
            open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard baseFD >= 0 else {
            throw ExternalNativeStoreEditorError.temporaryWorkspaceUnavailable
        }
        defer { close(baseFD) }

        var baseInfo = stat()
        guard fstat(baseFD, &baseInfo) == 0,
              (baseInfo.st_mode & S_IFMT) == S_IFDIR,
              baseInfo.st_uid == getuid(),
              fchmod(baseFD, mode_t(0o700)) == 0 else {
            throw ExternalNativeStoreEditorError.temporaryWorkspaceUnavailable
        }

        for _ in 0..<maximumWorkspaceAttempts {
            let name = workspacePrefix + UUID().uuidString.lowercased()
            let created = name.withCString { mkdirat(baseFD, $0, mode_t(0o700)) }
            if created != 0 {
                if errno == EEXIST { continue }
                throw ExternalNativeStoreEditorError.temporaryWorkspaceUnavailable
            }

            let directoryFD = name.withCString {
                openat(baseFD, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard directoryFD >= 0 else {
                name.withCString { _ = unlinkat(baseFD, $0, AT_REMOVEDIR) }
                throw ExternalNativeStoreEditorError.temporaryWorkspaceUnavailable
            }

            var info = stat()
            guard fstat(directoryFD, &info) == 0,
                  (info.st_mode & S_IFMT) == S_IFDIR,
                  info.st_uid == getuid(),
                  fchmod(directoryFD, mode_t(0o700)) == 0 else {
                close(directoryFD)
                name.withCString { _ = unlinkat(baseFD, $0, AT_REMOVEDIR) }
                throw ExternalNativeStoreEditorError.temporaryWorkspaceUnavailable
            }

            let url = URL(fileURLWithPath: basePath, isDirectory: true)
                .appendingPathComponent(name, isDirectory: true)
            return Workspace(directoryFD: directoryFD, directoryURL: url, info: info)
        }
        throw ExternalNativeStoreEditorError.temporaryWorkspaceUnavailable
    }

    private static func writeInitialDocument(_ document: Data, directoryFD: Int32) throws {
        guard document.count <= NativeStoreDocument.maximumBytes else {
            throw ExternalNativeStoreEditorError.editedFileTooLarge
        }
        let fd = documentName.withCString {
            openat(
                directoryFD,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard fd >= 0 else {
            throw ExternalNativeStoreEditorError.temporaryWorkspaceUnavailable
        }
        defer { close(fd) }

        var offset = 0
        try document.withUnsafeBytes { bytes in
            while offset < bytes.count {
                let count = Darwin.write(
                    fd,
                    bytes.baseAddress!.advanced(by: offset),
                    bytes.count - offset
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else {
                    throw ExternalNativeStoreEditorError.temporaryWorkspaceUnavailable
                }
                offset += count
            }
        }
        guard fchmod(fd, mode_t(0o600)) == 0 else {
            throw ExternalNativeStoreEditorError.temporaryWorkspaceUnavailable
        }
        // Do not fsync plaintext. This workspace is an editor compatibility
        // surface, not durable storage; the encrypted commit owns durability.
    }

    private static func readEditedDocument(directoryFD: Int32) throws -> Data {
        var directoryInfo = stat()
        guard fstat(directoryFD, &directoryInfo) == 0,
              (directoryInfo.st_mode & S_IFMT) == S_IFDIR,
              directoryInfo.st_uid == getuid(),
              (directoryInfo.st_mode & 0o077) == 0 else {
            throw ExternalNativeStoreEditorError.editedFileUnsafe
        }

        let fd = documentName.withCString {
            openat(directoryFD, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        if fd < 0, errno == ENOENT {
            throw ExternalNativeStoreEditorError.editedFileUnavailable
        }
        guard fd >= 0 else {
            throw ExternalNativeStoreEditorError.editedFileUnsafe
        }
        defer { close(fd) }

        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(),
              info.st_nlink == 1,
              info.st_size >= 0 else {
            throw ExternalNativeStoreEditorError.editedFileUnsafe
        }
        guard info.st_size <= NativeStoreDocument.maximumBytes else {
            throw ExternalNativeStoreEditorError.editedFileTooLarge
        }
        guard fchmod(fd, mode_t(0o600)) == 0 else {
            throw ExternalNativeStoreEditorError.editedFileUnsafe
        }

        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        var offset = 0
        let totalBytes = bytes.count
        while offset < totalBytes {
            let count = bytes.withUnsafeMutableBytes { buffer in
                Darwin.read(fd, buffer.baseAddress!.advanced(by: offset), totalBytes - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else {
                throw ExternalNativeStoreEditorError.editedFileUnsafe
            }
            offset += count
        }
        var extra: UInt8 = 0
        while true {
            let count = Darwin.read(fd, &extra, 1)
            if count < 0, errno == EINTR { continue }
            guard count == 0 else {
                throw ExternalNativeStoreEditorError.editedFileTooLarge
            }
            break
        }
        return Data(bytes)
    }
}
