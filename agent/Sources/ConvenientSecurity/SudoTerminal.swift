import Foundation

// The terminal tab a sudo review names, found by csecd.
//
// The tab line comes from asking the terminal application over AppleScript
// (`TerminalTitleQuery`), and macOS charges that Apple event to the asking
// process's *responsible* application. For csecd that is ConvenientSecurity,
// whose Automation prompt, with its own usage description, every approval
// panel's tab line already raises once per terminal. For the sudo review
// helper it would be whichever application ran sudo: responsibility passes
// down through sudo and the PAM module's spawn. Inside iTerm2 that is iTerm2 asking itself, which needs no grant,
// but a sudo in Terminal.app, Ghostty, an editor's terminal or an ssh login
// would make *that* application ask to control iTerm2 or Terminal halfway
// through a sudo, and a Yes would leave it able to drive them from then on.
// So the helper sends no Apple event: csecd does the lookup it does for every
// other panel, from the helper's own process upwards, and with no answer the
// panel names the PAM tty alone.

/// `sudo_terminal`: the sudo review helper's question, before it builds a
/// panel, of which terminal tab its sudo came from. csecd answers with
/// `TerminalSessionInspector.context(forCallerPID:)` for the helper that
/// asked, whose kernel parent is the sudo: the request carries nothing to
/// look up, so a helper can ask only about itself.
public struct SudoTerminalRequest: Codable, Sendable, Equatable {
    public let requestID: String

    public init(requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
    }

    public var isWellFormed: Bool { UUID(uuidString: requestID)?.uuidString.lowercased() == requestID }
}

extension Request {
    /// Whether this is the sudo review helper's terminal question.
    public var isSudoTerminal: Bool {
        if case .sudoTerminal = self { return true }
        return false
    }
}

extension SudoAuthorizationReviewRequest {
    /// What the panel names when csecd does not: the PAM tty alone, from the
    /// frame, with no application asked anything.
    public var ttyOnlyTerminal: TerminalSessionContext {
        guard let tty = TerminalSessionInspector.deviceName(terminal) else { return .unidentified }
        return TerminalSessionInspector.context(identity: TerminalSessionIdentity(tty: tty), title: nil)
    }
}

extension SudoAuthorizationReviewRequest {
    /// The terminal fact the sudo panel leads with, as the secret-access panel
    /// leads with `ReviewDisplay.terminalFact`. csecd finds the tab from the
    /// helper upwards, so it can name a tab whose tty is not sudo's own: a sudo
    /// from an agent's tool shell has no tty, while the agent's tab does. The
    /// tty PAM reported then stands in the detail line, so dropping the panel's
    /// separate tty row loses nothing; when it matches it is not repeated.
    public func terminalFact(_ context: TerminalSessionContext) -> ReviewDisplay.TerminalFact {
        let fact = ReviewDisplay.terminalFact(context)
        let pamTTY = TerminalSessionInspector.deviceName(terminal)
        guard pamTTY != context.tty else { return fact }
        let note = pamTTY.map { "sudo reports \($0)" } ?? "sudo itself has no tty"
        return ReviewDisplay.TerminalFact(title: fact.title, detail: fact.detail + " · " + note)
    }
}
