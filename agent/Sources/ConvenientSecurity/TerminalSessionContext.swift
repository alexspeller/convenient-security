import Foundation
import CSECRootProtocol

/// Value-free description of the terminal window and tab a request came from,
/// shown on every approval surface so the human can tell *which* tab is asking
/// before touching the sensor.
///
/// Two kinds of fact are combined here and the copy keeps them apart:
/// - `application`, `location`, `tty`, and `sessionID` come from the kernel
///   (controlling terminal, exec-time environment) and from the terminal
///   application's own window/tab bookkeeping. A process inside the tab cannot
///   rewrite them.
/// - `title` is the tab's *self-reported* title. Any process in the tab can set
///   it with an OSC escape, so it orients the human and proves nothing; the
///   window/tab position and tty beside it are the part a rogue process cannot
///   forge.
public struct TerminalSessionContext: Sendable, Equatable, Codable {
    public static let maximumTitleBytes = 160
    public static let maximumFieldBytes = 96

    /// Display name of the terminal application ("iTerm2", "Terminal"), or nil
    /// when no terminal application could be identified.
    public let application: String?
    /// The tab title the terminal application displays, if queried — what the
    /// human sees in the tab bar.
    public let title: String?
    /// The session's own name when the application distinguishes it from the
    /// tab title: iTerm2 lets the running program set it (fish shows the current
    /// command and directory), while a custom tab title stays put. Nil when it
    /// is unknown or identical to `title`.
    public let sessionName: String?
    /// Live position inside the application, e.g. "window 1, tab 5".
    public let location: String?
    /// The components of `location`, when known.
    public let windowIndex: Int?
    public let tabIndex: Int?
    /// Controlling terminal device name, e.g. "ttys012".
    public let tty: String?
    /// The terminal's own session identifier from the environment.
    public let sessionID: String?
    /// A multiplexer between the process and its terminal ("tmux", "screen").
    public let multiplexer: String?
    /// Why less is known than usual, e.g. "tab title unavailable".
    public let note: String?

    public init(
        application: String?,
        title: String? = nil,
        sessionName: String? = nil,
        location: String? = nil,
        windowIndex: Int? = nil,
        tabIndex: Int? = nil,
        tty: String? = nil,
        sessionID: String? = nil,
        multiplexer: String? = nil,
        note: String? = nil
    ) {
        self.application = Self.field(application, maxBytes: Self.maximumFieldBytes)
        self.title = Self.field(title, maxBytes: Self.maximumTitleBytes)
        let cleanSessionName = Self.field(sessionName, maxBytes: Self.maximumTitleBytes)
        self.sessionName = cleanSessionName == self.title ? nil : cleanSessionName
        if let location {
            self.location = Self.field(location, maxBytes: Self.maximumFieldBytes)
        } else if let windowIndex, let tabIndex {
            self.location = "window \(windowIndex), tab \(tabIndex)"
        } else {
            self.location = nil
        }
        self.windowIndex = windowIndex
        self.tabIndex = tabIndex
        self.tty = Self.field(tty, maxBytes: Self.maximumFieldBytes)
        self.sessionID = Self.field(sessionID, maxBytes: Self.maximumFieldBytes)
        self.multiplexer = Self.field(multiplexer, maxBytes: Self.maximumFieldBytes)
        self.note = Self.field(note, maxBytes: Self.maximumTitleBytes)
    }

    /// No terminal anywhere above the requesting process: a daemon, a launchd
    /// job, or a GUI application asked. That is itself worth a glance.
    public static let unidentified = TerminalSessionContext(application: nil)

    /// One line for the trusted window, the Touch ID reason text, the sudo
    /// review, and the mirrored phone review.
    public var summary: String {
        if let multiplexer {
            var text = multiplexer
            if let sessionID { text += " pane \(sessionID)" }
            if let tty { text += " (\(tty))" }
            return text + " — host terminal tab not identifiable through \(multiplexer)"
        }
        guard let application else {
            if let tty { return "unidentified terminal (\(tty))" }
            return "no terminal — nothing above the requesting process owns a terminal"
        }
        var parts = [application]
        if let title, !title.isEmpty { parts.append("“\(title)”") }
        if let location { parts.append(location) }
        if let tty { parts.append(tty) }
        if let sessionName { parts.append("running “\(sessionName)”") }
        var text = parts.joined(separator: " · ")
        if title == nil, let note { text += " (\(note))" }
        return text
    }

    private enum CodingKeys: String, CodingKey {
        case application, title, sessionName, location, windowIndex, tabIndex, tty, sessionID, multiplexer, note
    }

    /// A decoded context, csecd's answer to the sudo review helper among them,
    /// is held to the same bounds and sanitizing as one built here.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            application: try container.decodeIfPresent(String.self, forKey: .application),
            title: try container.decodeIfPresent(String.self, forKey: .title),
            sessionName: try container.decodeIfPresent(String.self, forKey: .sessionName),
            location: try container.decodeIfPresent(String.self, forKey: .location),
            windowIndex: try container.decodeIfPresent(Int.self, forKey: .windowIndex),
            tabIndex: try container.decodeIfPresent(Int.self, forKey: .tabIndex),
            tty: try container.decodeIfPresent(String.self, forKey: .tty),
            sessionID: try container.decodeIfPresent(String.self, forKey: .sessionID),
            multiplexer: try container.decodeIfPresent(String.self, forKey: .multiplexer),
            note: try container.decodeIfPresent(String.self, forKey: .note)
        )
    }

    private static func field(_ value: String?, maxBytes: Int) -> String? {
        guard let value else { return nil }
        // Trim before sanitizing so a whitespace-only value collapses to absent
        // instead of surviving as a neutralized newline marker.
        let clean = ReviewDisplay.sanitized(
            value.trimmingCharacters(in: .whitespacesAndNewlines)
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { return nil }
        return ReviewDisplay.bounded(clean, maxBytes: maxBytes)
    }
}

/// What the exec-time environment above a request says about its terminal,
/// before the terminal application is asked anything.
public struct TerminalSessionIdentity: Sendable, Equatable {
    public enum Application: Sendable, Equatable {
        case iTerm2
        case appleTerminal
        case ghostty
        case wezterm
        case kitty
        case alacritty
        case vscode
        case warp
        case hyper
        case other(String)

        public var displayName: String {
            switch self {
            case .iTerm2: return "iTerm2"
            case .appleTerminal: return "Terminal"
            case .ghostty: return "Ghostty"
            case .wezterm: return "WezTerm"
            case .kitty: return "kitty"
            case .alacritty: return "Alacritty"
            case .vscode: return "VS Code terminal"
            case .warp: return "Warp"
            case .hyper: return "Hyper"
            case let .other(name): return name
            }
        }

        /// Whether csec knows how to ask this application for a tab title.
        public var supportsTitleQuery: Bool {
            self == .iTerm2 || self == .appleTerminal
        }
    }

    public var application: Application?
    /// The terminal's own session identifier as exported to the shell.
    public var sessionID: String?
    /// The UUID part of an iTerm2 session id (`w0t1p0:UUID`), used to find the
    /// exact session even after the tab has been moved.
    public var iTermSessionUUID: String?
    public var multiplexer: String?
    public var tty: String?

    public init(
        application: Application? = nil,
        sessionID: String? = nil,
        iTermSessionUUID: String? = nil,
        multiplexer: String? = nil,
        tty: String? = nil
    ) {
        self.application = application
        self.sessionID = sessionID
        self.iTermSessionUUID = iTermSessionUUID
        self.multiplexer = multiplexer
        self.tty = tty
    }

    /// Environment variables that identify a terminal. Only these keys are ever
    /// copied out of a process's exec-time environment block.
    public static let environmentKeys: [String] = [
        "TERM_PROGRAM", "ITERM_SESSION_ID", "TERM_SESSION_ID",
        "TMUX", "TMUX_PANE", "STY",
        "WEZTERM_PANE", "KITTY_WINDOW_ID", "ALACRITTY_WINDOW_ID", "GHOSTTY_RESOURCES_DIR",
        "__CFBundleIdentifier",
    ]

    /// Reads one process's environment subset. Returns nil when it names no
    /// terminal at all, so an ancestry walk can keep looking upward.
    ///
    /// Under tmux or screen the shell's environment describes the multiplexer,
    /// not the tab it is attached to: tmux does not refresh `ITERM_SESSION_ID`
    /// for new sessions, so any such value would name whichever tab started the
    /// server. It is deliberately ignored rather than shown as a wrong tab.
    public static func identify(environment env: [String: String]) -> TerminalSessionIdentity? {
        if let tmux = env["TMUX"], !tmux.isEmpty {
            return TerminalSessionIdentity(sessionID: env["TMUX_PANE"], multiplexer: "tmux")
        }
        if let screen = env["STY"], !screen.isEmpty {
            return TerminalSessionIdentity(sessionID: screen, multiplexer: "screen")
        }

        var identity = TerminalSessionIdentity()
        switch env["TERM_PROGRAM"] {
        case "iTerm.app": identity.application = .iTerm2
        case "Apple_Terminal": identity.application = .appleTerminal
        case "ghostty": identity.application = .ghostty
        case "WezTerm": identity.application = .wezterm
        case "vscode": identity.application = .vscode
        case "WarpTerminal": identity.application = .warp
        case "Hyper": identity.application = .hyper
        case "tmux": identity.multiplexer = "tmux"
        case let .some(other) where !other.isEmpty: identity.application = .other(other)
        default: break
        }
        if identity.multiplexer != nil {
            return TerminalSessionIdentity(sessionID: env["TMUX_PANE"], multiplexer: "tmux")
        }
        if identity.application == nil {
            if env["ITERM_SESSION_ID"] != nil {
                identity.application = .iTerm2
            } else if env["KITTY_WINDOW_ID"] != nil {
                identity.application = .kitty
            } else if env["ALACRITTY_WINDOW_ID"] != nil {
                identity.application = .alacritty
            } else if env["WEZTERM_PANE"] != nil {
                identity.application = .wezterm
            } else if env["GHOSTTY_RESOURCES_DIR"] != nil {
                identity.application = .ghostty
            } else {
                switch env["__CFBundleIdentifier"] {
                case "com.googlecode.iterm2": identity.application = .iTerm2
                case "com.apple.Terminal": identity.application = .appleTerminal
                case "com.mitchellh.ghostty": identity.application = .ghostty
                case "com.github.wez.wezterm": identity.application = .wezterm
                case "net.kovidgoyal.kitty": identity.application = .kitty
                case "org.alacritty": identity.application = .alacritty
                case "dev.warp.Warp-Stable": identity.application = .warp
                default: break
                }
            }
        }
        guard let application = identity.application else { return nil }

        switch application {
        case .iTerm2:
            let raw = env["ITERM_SESSION_ID"] ?? env["TERM_SESSION_ID"]
            identity.sessionID = raw
            if let raw, let colon = raw.lastIndex(of: ":") {
                let uuid = String(raw[raw.index(after: colon)...])
                identity.iTermSessionUUID = UUID(uuidString: uuid) != nil ? uuid : nil
            }
        case .appleTerminal:
            identity.sessionID = env["TERM_SESSION_ID"]
        case .wezterm:
            identity.sessionID = env["WEZTERM_PANE"].map { "pane \($0)" }
        case .kitty:
            identity.sessionID = env["KITTY_WINDOW_ID"].map { "window \($0)" }
        case .alacritty:
            identity.sessionID = env["ALACRITTY_WINDOW_ID"].map { "window \($0)" }
        case .ghostty, .vscode, .warp, .hyper, .other:
            identity.sessionID = env["TERM_SESSION_ID"]
        }
        return identity
    }
}

/// What a terminal application answered about one session.
public struct TerminalTitleQueryResult: Sendable, Equatable {
    public enum Match: Sendable, Equatable {
        case sessionID
        case tty
    }

    public let application: TerminalSessionIdentity.Application
    /// The displayed tab title.
    public let title: String?
    /// The session's own name, when the application reports one separately.
    public let sessionName: String?
    public let windowIndex: Int?
    public let tabIndex: Int?
    /// The session's tty as the application reports it, e.g. "ttys012".
    public let tty: String?
    public let matchedBy: Match

    public init(
        application: TerminalSessionIdentity.Application,
        title: String?,
        sessionName: String? = nil,
        windowIndex: Int?,
        tabIndex: Int?,
        tty: String?,
        matchedBy: Match
    ) {
        self.application = application
        self.title = title
        self.sessionName = sessionName
        self.windowIndex = windowIndex
        self.tabIndex = tabIndex
        self.tty = tty
        self.matchedBy = matchedBy
    }
}

/// Finds the terminal a request came from. Production uses `live`, which walks
/// kernel ancestry from the caller and then asks the terminal application over
/// AppleScript; the injectable form keeps tests deterministic and keeps
/// headless test agents from ever sending an Apple event.
public struct TerminalSessionInspector: Sendable {
    public static let maximumAncestorHops = 64

    private let environmentLookup: @Sendable (pid_t) -> [String: String]?
    private let parentLookup: @Sendable (pid_t) -> pid_t?
    private let terminalNameLookup: @Sendable (pid_t) -> String?
    private let titleQuery: @Sendable (TerminalSessionIdentity) async -> TerminalTitleQueryResult?

    public init(
        environment: @escaping @Sendable (pid_t) -> [String: String]?,
        parent: @escaping @Sendable (pid_t) -> pid_t?,
        terminalName: @escaping @Sendable (pid_t) -> String?,
        titleQuery: @escaping @Sendable (TerminalSessionIdentity) async -> TerminalTitleQueryResult?
    ) {
        environmentLookup = environment
        parentLookup = parent
        terminalNameLookup = terminalName
        self.titleQuery = titleQuery
    }

    /// Walks lineage parents, so a job detached from an agent's tool shell
    /// shows the terminal of the session that started it.
    public static let live = live(titleQueryTimeout: TerminalTitleQuery.timeout)

    /// `live` with another bound on the title query. Production keeps
    /// `TerminalTitleQuery.timeout`, which bounds a review panel; the self-test
    /// uses a longer one to tell a slow answer on a loaded Mac from no answer.
    public static func live(titleQueryTimeout: TimeInterval) -> TerminalSessionInspector {
        TerminalSessionInspector(
            environment: {
                ProcessAncestry.environmentSubset(of: $0, keys: TerminalSessionIdentity.environmentKeys)
            },
            parent: { SessionLineage.shared.parent(of: $0) },
            terminalName: { ProcessAncestry.controllingTerminalName(of: $0) },
            titleQuery: { await TerminalTitleQuery.run($0, timeout: titleQueryTimeout) }
        )
    }

    /// Sees no terminal and never asks an application anything. For tests and
    /// for agents that must never send an Apple event.
    public static let unavailable = TerminalSessionInspector(
        environment: { _ in nil },
        parent: { _ in nil },
        terminalName: { _ in nil },
        titleQuery: { _ in nil }
    )

    /// The environment-derived identity above `callerPID`: the nearest ancestor
    /// (the caller included) whose exec-time environment names a terminal, plus
    /// the nearest controlling terminal. A coding agent's per-tool-call shell
    /// has no controlling terminal, so the tty usually comes from the agent or
    /// the interactive shell above it.
    public func identity(forCallerPID callerPID: pid_t) -> TerminalSessionIdentity {
        var identity: TerminalSessionIdentity?
        var tty: String?
        var visited: Set<pid_t> = []
        var candidate = callerPID
        for _ in 0..<Self.maximumAncestorHops {
            guard candidate > 1, visited.insert(candidate).inserted else { break }
            if tty == nil { tty = terminalNameLookup(candidate) }
            if identity == nil, let env = environmentLookup(candidate) {
                identity = TerminalSessionIdentity.identify(environment: env)
            }
            if identity != nil, tty != nil { break }
            guard let parent = parentLookup(candidate), parent != candidate else { break }
            candidate = parent
        }
        var result = identity ?? TerminalSessionIdentity()
        result.tty = tty
        return result
    }

    /// The complete context for a request from `callerPID`, asking the terminal
    /// application for the live tab title when it is one csec can query.
    public func context(forCallerPID callerPID: pid_t) async -> TerminalSessionContext {
        let identity = identity(forCallerPID: callerPID)
        let title = identity.application?.supportsTitleQuery == true
            && identity.multiplexer == nil
            ? await titleQuery(identity) : nil
        return Self.context(identity: identity, title: title)
    }

    /// Pure assembly of the displayed context from the two sources.
    public static func context(
        identity: TerminalSessionIdentity,
        title: TerminalTitleQueryResult?
    ) -> TerminalSessionContext {
        if let multiplexer = identity.multiplexer {
            return TerminalSessionContext(
                application: nil,
                tty: identity.tty,
                sessionID: identity.sessionID,
                multiplexer: multiplexer
            )
        }
        var note: String?
        if identity.application?.supportsTitleQuery == true, title == nil {
            note = "tab title unavailable"
        }
        return TerminalSessionContext(
            application: identity.application?.displayName,
            title: title?.title,
            sessionName: title?.sessionName,
            windowIndex: title?.windowIndex,
            tabIndex: title?.tabIndex,
            tty: identity.tty ?? title?.tty,
            sessionID: identity.sessionID,
            note: note
        )
    }

    /// "ttys012" from "/dev/ttys012" or "ttys012"; nil for "no tty" and blanks.
    public static func deviceName(_ raw: String) -> String? {
        var name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.hasPrefix("/dev/") { name.removeFirst(5) }
        guard !name.isEmpty, !name.contains("/"), !name.contains(" "),
              name.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.contains($0) })
        else { return nil }
        return name
    }
}

/// Asks iTerm2 or Terminal.app which tab owns a session, over AppleScript in a
/// bounded `osascript` subprocess. The scripts only *read* window and tab
/// bookkeeping; they never write to, or read the contents of, any session.
///
/// Each script takes the application's whole window/tab/session tree in a fixed
/// handful of Apple events — a plural specifier such as `tty of sessions of
/// tabs of windows` answers with one nested list — and then finds the session
/// with no further events. Asking each session for its own `id` and `tty`
/// instead costs an Apple event round trip per property per session, which put
/// the cost of every prompt in front of it on a curve that rises with the
/// number of tabs the user keeps open — far enough, for a heavy user, to reach
/// `timeout` and lose the title outright.
///
/// Everything here degrades to nil: an application that is not running (the
/// script checks before addressing it, so nothing is launched), an Automation
/// permission the user declined, or a hung application after the timeout. A
/// missing title never blocks or alters an approval.
public enum TerminalTitleQuery {
    public static let timeout: TimeInterval = 2.5
    static let fieldSeparator: Character = "\u{1F}"

    public static func run(
        _ identity: TerminalSessionIdentity,
        timeout: TimeInterval = timeout
    ) async -> TerminalTitleQueryResult? {
        guard let application = identity.application, identity.multiplexer == nil else {
            return nil
        }
        let script: String
        switch application {
        case .iTerm2: script = iTermScript
        case .appleTerminal: script = terminalScript
        default: return nil
        }
        let uuid = identity.iTermSessionUUID ?? ""
        let device = identity.tty.map { "/dev/\($0)" } ?? ""
        guard !(uuid.isEmpty && device.isEmpty) else { return nil }
        guard let output = await OSAScriptRunner.run(
            script: script, arguments: [uuid, device], timeout: timeout
        ) else { return nil }
        return parse(output, application: application)
    }

    /// Parses `tabTitle␟sessionName␟tty␟window␟tab␟matchedBy` into a result;
    /// nil on no match.
    public static func parse(
        _ output: String,
        application: TerminalSessionIdentity.Application
    ) -> TerminalTitleQueryResult? {
        let trimmed = output.trimmingCharacters(in: .newlines)
        let fields = trimmed.split(separator: fieldSeparator, omittingEmptySubsequences: false)
            .map(String.init)
        guard fields.count == 6 else { return nil }
        let matchedBy: TerminalTitleQueryResult.Match
        switch fields[5] {
        case "id": matchedBy = .sessionID
        case "tty": matchedBy = .tty
        default: return nil
        }
        func clean(_ raw: String) -> String? {
            let text = ReviewDisplay.sanitized(raw).trimmingCharacters(in: .whitespacesAndNewlines)
            return text.isEmpty ? nil : text
        }
        return TerminalTitleQueryResult(
            application: application,
            title: clean(fields[0]),
            sessionName: clean(fields[1]),
            windowIndex: Int(fields[3]),
            tabIndex: Int(fields[4]),
            tty: TerminalSessionInspector.deviceName(fields[2]),
            matchedBy: matchedBy
        )
    }

    /// Finds the iTerm2 session by its GUID (`id`, the UUID in
    /// `ITERM_SESSION_ID`) first, then by tty. Window and tab indices are
    /// iTerm2's live ordering, which is what the human sees. The tab's `title`
    /// is what the tab bar displays; the session's `name` is what the running
    /// program last set (fish: the current command and directory), and the two
    /// differ whenever the tab has a custom title.
    ///
    /// Four plural gets bring back the whole tree — `allIDs`, `allTTYs` and
    /// `allNames` nested window→tab→session, `allTitles` nested window→tab —
    /// and `matchITermSession` does the rest with no further Apple events.
    ///
    /// Public so a test can assert the shape that makes it fast: a lookup that
    /// went back to iterating sessions inside the `tell` would still answer
    /// correctly, and would surface only as latency on a busy Mac.
    public static let iTermScript = """
    on run argv
      set wantedID to item 1 of argv
      set wantedTTY to item 2 of argv
      if wantedID is "" and wantedTTY is "" then return ""
      try
        if not (application "iTerm2" is running) then return ""
      on error
        return ""
      end try
      try
        tell application "iTerm2"
          set allIDs to id of sessions of tabs of windows
          set allTTYs to tty of sessions of tabs of windows
          set allNames to name of sessions of tabs of windows
          set allTitles to title of tabs of windows
        end tell
      on error
        return ""
      end try
      return matchITermSession(wantedID, wantedTTY, allIDs, allTTYs, allNames, allTitles)
    end run

    \(iTermMatchProgram)
    """

    /// The half of `iTermScript` that touches no application: it walks the four
    /// fetched tables in iTerm2's own window→tab→session order and answers with
    /// the same `tabTitle␟sessionName␟tty␟window␟tab␟matchedBy` line the
    /// per-session scan used to build, preferring a GUID match over a tty match
    /// at the same position and the earliest position overall.
    ///
    /// The four tables are fetched as four separate Apple events, so a tab
    /// opened or closed between them would leave them describing different
    /// trees and a row could name another tab's title or position. The counts
    /// are compared at every level and a disagreement answers with no match:
    /// the position and tty beside the title are the part a rogue process
    /// cannot forge, so showing a shifted one is worse than showing none.
    ///
    /// Public so a test can run this exact text against synthetic tables —
    /// nothing here addresses an application, so no Apple event is sent and no
    /// terminal has to be running.
    public static let iTermMatchProgram = """
    on matchITermSession(wantedID, wantedTTY, allIDs, allTTYs, allNames, allTitles)
      set fieldSeparator to character id 31
      if wantedID is "" and wantedTTY is "" then return ""
      set windowCount to count of allIDs
      if (count of allTTYs) is not windowCount then return ""
      if (count of allNames) is not windowCount then return ""
      if (count of allTitles) is not windowCount then return ""
      repeat with windowIndex from 1 to windowCount
        set windowIDs to item windowIndex of allIDs
        set windowTTYs to item windowIndex of allTTYs
        set windowNames to item windowIndex of allNames
        set windowTitles to item windowIndex of allTitles
        set tabCount to count of windowIDs
        if (count of windowTTYs) is not tabCount then return ""
        if (count of windowNames) is not tabCount then return ""
        if (count of windowTitles) is not tabCount then return ""
        repeat with tabIndex from 1 to tabCount
          set tabIDs to item tabIndex of windowIDs
          set tabTTYs to item tabIndex of windowTTYs
          set tabNames to item tabIndex of windowNames
          set sessionCount to count of tabIDs
          if (count of tabTTYs) is not sessionCount then return ""
          if (count of tabNames) is not sessionCount then return ""
          repeat with sessionIndex from 1 to sessionCount
            set sessionTTY to item sessionIndex of tabTTYs
            set matchedBy to ""
            if wantedID is not "" and (item sessionIndex of tabIDs) is wantedID then
              set matchedBy to "id"
            else if wantedTTY is not "" and sessionTTY is wantedTTY then
              set matchedBy to "tty"
            end if
            if matchedBy is not "" then
              return (item tabIndex of windowTitles) & fieldSeparator ¬
                & (item sessionIndex of tabNames) & fieldSeparator ¬
                & sessionTTY & fieldSeparator & windowIndex & fieldSeparator ¬
                & tabIndex & fieldSeparator & matchedBy
            end if
          end repeat
        end repeat
      end repeat
      return ""
    end matchITermSession
    """

    /// Terminal.app exposes no session id to AppleScript, so the tab is found
    /// by tty. Its title is the custom title when one is set; otherwise the
    /// window title, which reflects the tab only while that tab is selected.
    ///
    /// Terminal.app has no session layer, so its five plural gets nest only
    /// window→tab (and `allWindowNames` is flat), but the shape is the same:
    /// the whole tree in a fixed number of Apple events, then
    /// `matchTerminalTab` with none. Public for the same shape guard as
    /// `iTermScript`.
    public static let terminalScript = """
    on run argv
      set wantedTTY to item 2 of argv
      if wantedTTY is "" then return ""
      try
        if not (application "Terminal" is running) then return ""
      on error
        return ""
      end try
      try
        tell application "Terminal"
          set allTTYs to tty of tabs of windows
          set allCustomTitles to custom title of tabs of windows
          set allShowCustom to title displays custom title of tabs of windows
          set allSelected to selected of tabs of windows
          set allWindowNames to name of windows
        end tell
      on error
        return ""
      end try
      return matchTerminalTab(wantedTTY, allTTYs, allCustomTitles, allShowCustom, ¬
        allSelected, allWindowNames)
    end run

    \(terminalMatchProgram)
    """

    /// The application-free half of `terminalScript`, the sibling of
    /// `iTermMatchProgram`: same window→tab order, same answer line (with an
    /// always-empty session-name field, since Terminal.app reports none), and
    /// the same count checks so tables that stopped describing the same tree
    /// answer with no match rather than a shifted tab.
    ///
    /// Public for the same reason: a test runs this text against synthetic
    /// tables without Terminal.app running and without an Apple event.
    public static let terminalMatchProgram = """
    on matchTerminalTab(wantedTTY, allTTYs, allCustomTitles, allShowCustom, ¬
      allSelected, allWindowNames)
      set fieldSeparator to character id 31
      if wantedTTY is "" then return ""
      set windowCount to count of allTTYs
      if (count of allCustomTitles) is not windowCount then return ""
      if (count of allShowCustom) is not windowCount then return ""
      if (count of allSelected) is not windowCount then return ""
      if (count of allWindowNames) is not windowCount then return ""
      repeat with windowIndex from 1 to windowCount
        set windowTTYs to item windowIndex of allTTYs
        set windowCustomTitles to item windowIndex of allCustomTitles
        set windowShowCustom to item windowIndex of allShowCustom
        set windowSelected to item windowIndex of allSelected
        set tabCount to count of windowTTYs
        if (count of windowCustomTitles) is not tabCount then return ""
        if (count of windowShowCustom) is not tabCount then return ""
        if (count of windowSelected) is not tabCount then return ""
        repeat with tabIndex from 1 to tabCount
          set tabTTY to item tabIndex of windowTTYs
          if tabTTY is wantedTTY then
            set titleText to ""
            if item tabIndex of windowShowCustom then
              set titleText to item tabIndex of windowCustomTitles
            else if item tabIndex of windowSelected then
              set titleText to item windowIndex of allWindowNames
            end if
            return titleText & fieldSeparator & fieldSeparator & tabTTY & fieldSeparator ¬
              & windowIndex & fieldSeparator & tabIndex & fieldSeparator & "tty"
          end if
        end repeat
      end repeat
      return ""
    end matchTerminalTab
    """
}

/// Runs `/usr/bin/osascript -` with the script on stdin and the untrusted
/// values as argv, so no value is ever spliced into script text. Output is
/// bounded and the process is terminated, then killed, at the timeout.
enum OSAScriptRunner {
    static let maximumOutputBytes = 16 * 1_024

    static func run(script: String, arguments: [String], timeout: TimeInterval) async -> String? {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: runBlocking(
                    script: script, arguments: arguments, timeout: timeout
                ))
            }
        }
    }

    private static func runBlocking(
        script: String, arguments: [String], timeout: TimeInterval
    ) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-"] + arguments
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"]
        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return nil
        }
        let watchdog = DispatchWorkItem {
            if process.isRunning { process.terminate() }
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) {
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: watchdog)
        input.fileHandleForWriting.write(Data(script.utf8))
        try? input.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        watchdog.cancel()
        guard process.terminationReason == .exit, process.terminationStatus == 0,
              data.count <= maximumOutputBytes
        else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
