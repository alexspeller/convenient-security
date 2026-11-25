import ConvenientSecurity
import CSECRemoteApproval
import CSECRootProtocol
import Foundation
#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  import AppKit
#endif

/// Which terminal tab is asking: environment-derived identity, the assembled
/// display line, the AppleScript answer parser, the ancestry walk, and the
/// wiring into every approval surface's caller.
///
/// The synthetic trees mirror the measured coding-agent shape: the launcher
/// under a per-tool-call shell (no controlling terminal, environment readable)
/// under the agent (owns the tty) under an interactive shell whose exec-time
/// environment carries the terminal's session variables.
private struct SyntheticTerminalTree {
    var parents: [pid_t: pid_t] = [:]
    var environments: [pid_t: [String: String]] = [:]
    var ttys: [pid_t: String] = [:]
    /// Processes whose environment cannot be read (another user's, or gone).
    var unreadable: Set<pid_t> = []

    mutating func add(
        pid: pid_t, parent: pid_t, env: [String: String] = [:],
        tty: String? = nil, unreadable: Bool = false
    ) {
        parents[pid] = parent
        environments[pid] = env
        if let tty { ttys[pid] = tty }
        if unreadable { self.unreadable.insert(pid) }
    }

    func inspector(
        titleQuery: @escaping @Sendable (TerminalSessionIdentity) async -> TerminalTitleQueryResult?
            = { _ in nil }
    ) -> TerminalSessionInspector {
        let parents = parents, environments = environments, ttys = ttys, unreadable = unreadable
        return TerminalSessionInspector(
            environment: { unreadable.contains($0) ? nil : environments[$0] },
            parent: { parents[$0] },
            terminalName: { ttys[$0] },
            titleQuery: titleQuery
        )
    }
}

private let iTermEnvironment: [String: String] = [
    "TERM_PROGRAM": "iTerm.app",
    "TERM_PROGRAM_VERSION": "3.6.11",
    "ITERM_SESSION_ID": "w1t2p3:9EE8062D-0A54-4B65-A987-3261B57FF22E",
    "TERM_SESSION_ID": "w1t2p3:9EE8062D-0A54-4B65-A987-3261B57FF22E",
    "__CFBundleIdentifier": "com.googlecode.iterm2",
]

/// Renders a synthetic value as AppleScript source. Control characters become
/// `character id N` concatenations so a hostile title can carry a newline or a
/// BEL without ending the literal.
private func appleScriptSource(_ text: String) -> String {
    var pieces: [String] = []
    var literal = ""
    for scalar in text.unicodeScalars {
        if scalar.value < 0x20 || scalar.value == 0x7F {
            if !literal.isEmpty { pieces.append("\"\(literal)\"") }
            literal = ""
            pieces.append("(character id \(scalar.value))")
        } else {
            if scalar == "\"" || scalar == "\\" { literal.unicodeScalars.append("\\") }
            literal.unicodeScalars.append(scalar)
        }
    }
    if !literal.isEmpty || pieces.isEmpty { pieces.append("\"\(literal)\"") }
    return pieces.joined(separator: " & ")
}

private func appleScriptSource(_ values: [Bool]) -> String {
    "{" + values.map { $0 ? "true" : "false" }.joined(separator: ", ") + "}"
}

private func appleScriptSource(_ values: [String]) -> String {
    "{" + values.map(appleScriptSource).joined(separator: ", ") + "}"
}

private func appleScriptSource(_ values: [[Bool]]) -> String {
    "{" + values.map(appleScriptSource).joined(separator: ", ") + "}"
}

private func appleScriptSource(_ values: [[String]]) -> String {
    "{" + values.map(appleScriptSource).joined(separator: ", ") + "}"
}

private func appleScriptSource(_ values: [[[String]]]) -> String {
    "{" + values.map(appleScriptSource).joined(separator: ", ") + "}"
}

/// Runs a shipped match handler against synthetic tables. Neither handler
/// addresses an application, so this sends no Apple event and needs no terminal
/// running — it is the exact text the live query uses, exercised offline.
/// Returns nil when osascript itself refuses the script, which is how a
/// malformed synthetic table would show up rather than as a silent pass.
private func runMatchProgram(_ program: String, call: String, arguments: [String]) -> String? {
    let script = """
    on run argv
      \(call)
    end run

    \(program)
    """
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    process.arguments = ["-"] + arguments
    process.environment = ["PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"]
    let input = Pipe(), output = Pipe()
    process.standardInput = input
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    do { try process.run() } catch { return nil }
    input.fileHandleForWriting.write(Data(script.utf8))
    try? input.fileHandleForWriting.close()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return nil }
    return String(data: data, encoding: .utf8)
}

/// An iTerm2 window/tab/session tree exactly as the four plural gets return it:
/// `ids`, `ttys` and `names` nested window→tab→session, `titles` window→tab.
private struct SyntheticITermTables {
    var ids: [[[String]]]
    var ttys: [[[String]]]
    var names: [[[String]]]
    var titles: [[String]]

    func answer(id: String = "", tty: String = "") -> String? {
        runMatchProgram(
            TerminalTitleQuery.iTermMatchProgram,
            call: "return matchITermSession(item 1 of argv, item 2 of argv, "
                + "\(appleScriptSource(ids)), \(appleScriptSource(ttys)), "
                + "\(appleScriptSource(names)), \(appleScriptSource(titles)))",
            arguments: [id, tty]
        )
    }

    func result(id: String = "", tty: String = "") -> TerminalTitleQueryResult? {
        answer(id: id, tty: tty).flatMap { TerminalTitleQuery.parse($0, application: .iTerm2) }
    }
}

/// A Terminal.app window/tab tree as its five plural gets return it. There is
/// no session layer, so `windowNames` is flat.
private struct SyntheticTerminalTables {
    var ttys: [[String]]
    var customTitles: [[String]]
    var showsCustom: [[Bool]]
    var selected: [[Bool]]
    var windowNames: [String]

    func answer(tty: String) -> String? {
        runMatchProgram(
            TerminalTitleQuery.terminalMatchProgram,
            call: "return matchTerminalTab(item 1 of argv, "
                + "\(appleScriptSource(ttys)), \(appleScriptSource(customTitles)), "
                + "\(appleScriptSource(showsCustom)), \(appleScriptSource(selected)), "
                + "\(appleScriptSource(windowNames)))",
            arguments: [tty]
        )
    }

    func result(tty: String) -> TerminalTitleQueryResult? {
        answer(tty: tty).flatMap { TerminalTitleQuery.parse($0, application: .appleTerminal) }
    }
}

private actor TitleQueryRecorder {
    private(set) var identities: [TerminalSessionIdentity] = []
    private let answer: TerminalTitleQueryResult?
    init(answer: TerminalTitleQueryResult?) { self.answer = answer }
    func record(_ identity: TerminalSessionIdentity) -> TerminalTitleQueryResult? {
        identities.append(identity)
        return answer
    }
}

/// Approves and keeps the caller it was shown, so the wiring test can read the
/// terminal the agent attached before presenting the review.
private actor TerminalCapturingReview: PolicyReviewProvider {
    private(set) var reviewedCaller: CallerInfo?
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviewedCaller = review.caller
        return .approved(AccessPolicyApproval())
    }
    func caller() -> CallerInfo? { reviewedCaller }
}

private struct TerminalFixtureProvider: SecretProvider {
    let values: [String: Data]
    var schemes: Set<String> { ["op"] }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private struct ApprovingConsent: ConsentProvider {
    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String,
        ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome { .approved(unlock: nil) }
    func authenticate(reason: String) async -> ConsentOutcome { .approved(unlock: nil) }
}

func terminalSessionTests() async {
    print("\n# Terminal session context (which tab is asking)")

    // MARK: Environment-derived identity

    let iterm = TerminalSessionIdentity.identify(environment: iTermEnvironment)
    check(iterm?.application == .iTerm2
          && iterm?.sessionID == "w1t2p3:9EE8062D-0A54-4B65-A987-3261B57FF22E"
          && iterm?.iTermSessionUUID == "9EE8062D-0A54-4B65-A987-3261B57FF22E",
          "iTerm2 is identified from TERM_PROGRAM with its session id and GUID split out")

    let malformed = TerminalSessionIdentity.identify(environment: [
        "TERM_PROGRAM": "iTerm.app", "ITERM_SESSION_ID": "w0t0p0:not-a-uuid",
    ])
    check(malformed?.application == .iTerm2 && malformed?.iTermSessionUUID == nil
          && malformed?.sessionID == "w0t0p0:not-a-uuid",
          "a malformed iTerm2 session id keeps the application but offers no GUID to match on")

    let appleTerminal = TerminalSessionIdentity.identify(environment: [
        "TERM_PROGRAM": "Apple_Terminal",
        "TERM_SESSION_ID": "5D2C7B8A-1F3E-4C9A-9B1D-2E3F4A5B6C7D",
    ])
    check(appleTerminal?.application == .appleTerminal
          && appleTerminal?.sessionID == "5D2C7B8A-1F3E-4C9A-9B1D-2E3F4A5B6C7D",
          "Terminal.app is identified from TERM_PROGRAM with its session id")

    let tmux = TerminalSessionIdentity.identify(environment: [
        "TERM_PROGRAM": "tmux", "TMUX": "/private/tmp/tmux-501/default,812,0",
        "TMUX_PANE": "%3",
        // Stale: tmux does not refresh this for new sessions, so it must not be
        // shown as the requesting tab.
        "ITERM_SESSION_ID": "w0t0p0:9EE8062D-0A54-4B65-A987-3261B57FF22E",
    ])
    check(tmux?.multiplexer == "tmux" && tmux?.sessionID == "%3"
          && tmux?.application == nil && tmux?.iTermSessionUUID == nil,
          "under tmux the stale host-terminal session id is ignored and the pane is named instead")

    let tmuxWithoutTermProgram = TerminalSessionIdentity.identify(environment: [
        "TMUX": "/private/tmp/tmux-501/default,812,0", "TERM_PROGRAM": "iTerm.app",
        "ITERM_SESSION_ID": "w0t0p0:9EE8062D-0A54-4B65-A987-3261B57FF22E",
    ])
    check(tmuxWithoutTermProgram?.multiplexer == "tmux"
          && tmuxWithoutTermProgram?.application == nil,
          "TMUX alone marks a multiplexed session even when TERM_PROGRAM still names the host")

    let screen = TerminalSessionIdentity.identify(environment: ["STY": "1234.pts-0.host"])
    check(screen?.multiplexer == "screen" && screen?.sessionID == "1234.pts-0.host",
          "GNU screen is identified from STY")

    let kitty = TerminalSessionIdentity.identify(environment: ["KITTY_WINDOW_ID": "7"])
    check(kitty?.application == .kitty && kitty?.sessionID == "window 7"
          && kitty?.application.map(\.supportsTitleQuery) == false,
          "kitty is identified from its window id and offers no title query")

    let ghostty = TerminalSessionIdentity.identify(environment: [
        "TERM_PROGRAM": "ghostty", "TERM_SESSION_ID": "abc",
    ])
    check(ghostty?.application == .ghostty && ghostty?.application?.displayName == "Ghostty",
          "Ghostty is identified from TERM_PROGRAM")

    let bundleOnly = TerminalSessionIdentity.identify(environment: [
        "__CFBundleIdentifier": "com.apple.Terminal",
    ])
    check(bundleOnly?.application == .appleTerminal,
          "the LaunchServices bundle identifier identifies the terminal application on its own")

    let unknown = TerminalSessionIdentity.identify(environment: ["TERM_PROGRAM": "FancyTerm"])
    check(unknown?.application == .other("FancyTerm")
          && unknown?.application?.displayName == "FancyTerm",
          "an unrecognized TERM_PROGRAM is shown by its own name")

    check(TerminalSessionIdentity.identify(environment: ["PATH": "/usr/bin", "HOME": "/"]) == nil,
          "an environment naming no terminal yields no identity, so the walk continues upward")
    check(TerminalSessionIdentity.identify(environment: [:]) == nil,
          "an empty environment yields no identity")

    // MARK: Display line

    let full = TerminalSessionContext(
        application: "iTerm2", title: "deploy — ~/project", location: "window 1, tab 5",
        tty: "ttys012", sessionID: "w1t2p3:9EE8062D-0A54-4B65-A987-3261B57FF22E"
    )
    check(full.summary == "iTerm2 · “deploy — ~/project” · window 1, tab 5 · ttys012",
          "the summary names the application, the tab's title, its live position, and the tty")

    // iTerm2 distinguishes the tab's displayed title from the session name the
    // running program sets. The tab title is what the human sees in the tab bar,
    // so it leads; the session name follows only when it says something else.
    let customTab = TerminalSessionContext(
        application: "iTerm2", title: "🌲 manifest-v3",
        sessionName: "csec exec ls ~/d/w/manifest-v3 (csec)",
        windowIndex: 1, tabIndex: 11, tty: "ttys027"
    )
    check(customTab.location == "window 1, tab 11",
          "the location line is derived from the window and tab indices")
    check(customTab.summary
            == "iTerm2 · “🌲 manifest-v3” · window 1, tab 11 · ttys027 · running “csec exec ls ~/d/w/manifest-v3 (csec)”",
          "the summary leads with the displayed tab title and adds the session name it differs from")
    check(TerminalSessionContext(
            application: "iTerm2", title: "~/d/terraform (-fish)",
            sessionName: "~/d/terraform (-fish)", tty: "ttys021"
          ).sessionName == nil,
          "a session name identical to the tab title is dropped rather than repeated")
    let customFact = ReviewDisplay.terminalFact(customTab)
    check(customFact == ReviewDisplay.TerminalFact(
            title: "Tab 11 · 🌲 manifest-v3",
            detail: "iTerm2 · window 1 · ttys027 · running “csec exec ls ~/d/w/manifest-v3 (csec)”"),
          "the window's headline fact is the tab number and displayed title, with the unforgeable parts below")
    check(ReviewDisplay.terminalFact(TerminalSessionContext(
            application: "iTerm2", tty: "ttys012", note: "tab title unavailable"
          )) == ReviewDisplay.TerminalFact(
            title: "iTerm2", detail: "ttys012 · tab title unavailable"),
          "with no title the application is the headline and the missing title is stated")
    check(ReviewDisplay.terminalFact(.unidentified)
            == ReviewDisplay.TerminalFact(
                title: "No terminal",
                detail: "nothing above the requesting process owns a terminal"),
          "no terminal at all is a headline fact in its own right")
    check(ReviewDisplay.terminalFact(TerminalSessionContext(
            application: nil, tty: "ttys020", sessionID: "%3", multiplexer: "tmux"
          )) == ReviewDisplay.TerminalFact(
            title: "tmux pane %3",
            detail: "ttys020 · host terminal tab not identifiable through tmux"),
          "a multiplexed session names the pane and says why the host tab is unknown")

    let untitled = TerminalSessionContext(
        application: "iTerm2", tty: "ttys012", note: "tab title unavailable"
    )
    check(untitled.summary == "iTerm2 · ttys012 (tab title unavailable)",
          "a missing title is stated rather than silently omitted")

    check(TerminalSessionContext(application: "Ghostty", tty: "ttys003").summary
            == "Ghostty · ttys003",
          "a terminal csec cannot query shows what the kernel and environment know")

    let tmuxContext = TerminalSessionContext(
        application: nil, tty: "ttys020", sessionID: "%3", multiplexer: "tmux"
    )
    check(tmuxContext.summary
            == "tmux pane %3 (ttys020) — host terminal tab not identifiable through tmux",
          "a multiplexed session says why the host tab is not named")

    check(TerminalSessionContext(application: nil, tty: "ttys004").summary
            == "unidentified terminal (ttys004)",
          "a tty with no recognizable terminal application is still shown")
    check(TerminalSessionContext.unidentified.summary
            == "no terminal — nothing above the requesting process owns a terminal",
          "no terminal at all is stated explicitly: a daemon or GUI app asked")

    let hostile = TerminalSessionContext(
        application: "iTerm2",
        title: "safe\u{202E}looks reversed\nsecond line\u{07}",
        tty: "ttys012"
    )
    check(hostile.title == "safe�looks reversed�second line�",
          "a self-reported tab title has its bidi, newline, and control characters neutralized")

    let long = TerminalSessionContext(
        application: "iTerm2",
        title: String(repeating: "é", count: 200),
        tty: "ttys012"
    )
    // `ReviewDisplay.bounded` keeps the ellipsis outside the byte budget.
    check(long.title.map { $0.utf8.count <= TerminalSessionContext.maximumTitleBytes + "…".utf8.count } == true
          && long.title?.hasSuffix("…") == true
          && long.title?.dropLast().allSatisfy { $0 == "é" } == true,
          "an over-long tab title is bounded without splitting a character")

    check(TerminalSessionContext(application: "   ", title: "", tty: "\n").summary
            == TerminalSessionContext.unidentified.summary,
          "blank fields collapse to absent")

    // MARK: AppleScript answer parsing

    let sep = "\u{1F}"
    let parsed = TerminalTitleQuery.parse(
        "🧰 mailer\(sep)◑ deploy — ~/project\(sep)/dev/ttys012\(sep)1\(sep)5\(sep)id\n",
        application: .iTerm2
    )
    check(parsed == TerminalTitleQueryResult(
            application: .iTerm2, title: "🧰 mailer", sessionName: "◑ deploy — ~/project",
            windowIndex: 1, tabIndex: 5, tty: "ttys012", matchedBy: .sessionID),
          "an iTerm2 answer parses into tab title, session name, tty, window, tab, and how it matched")
    check(TerminalTitleQuery.parse("\(sep)\(sep)/dev/ttys012\(sep)2\(sep)1\(sep)tty", application: .appleTerminal)
            == TerminalTitleQueryResult(
                application: .appleTerminal, title: nil, sessionName: nil, windowIndex: 2, tabIndex: 1,
                tty: "ttys012", matchedBy: .tty),
          "empty title fields parse as absent, matched by tty")
    check(TerminalTitleQuery.parse("", application: .iTerm2) == nil
          && TerminalTitleQuery.parse("\n", application: .iTerm2) == nil,
          "an empty answer means no matching session")
    check(TerminalTitleQuery.parse("a\(sep)b\(sep)c\(sep)d\(sep)e\(sep)bogus", application: .iTerm2) == nil,
          "an answer with an unknown match kind is rejected")
    check(TerminalTitleQuery.parse("only-a-title", application: .iTerm2) == nil
          && TerminalTitleQuery.parse("title\(sep)/dev/ttys1\(sep)1\(sep)1\(sep)id", application: .iTerm2) == nil,
          "an answer with the wrong field count (including the old five-field form) is rejected")
    check(TerminalTitleQuery.parse("x\u{202E}y\(sep)s\u{202E}n\(sep)/dev/ttys1\(sep)1\(sep)1\(sep)id", application: .iTerm2)
            == TerminalTitleQueryResult(
                application: .iTerm2, title: "x�y", sessionName: "s�n", windowIndex: 1, tabIndex: 1,
                tty: "ttys1", matchedBy: .sessionID),
          "a bidi override in a reported title or session name is neutralized at parse time")

    // MARK: Bulk-fetch matching (no iTerm2, no Apple event)

    // The query takes the whole tree in a fixed number of plural gets and then
    // matches with no further Apple events, so its cost no longer grows with
    // the number of open sessions. These run the shipped match handlers against
    // synthetic tables: same text, no application addressed.
    let iTermQuery = TerminalTitleQuery.iTermScript
    let iTermTellBody = iTermQuery
        .components(separatedBy: "tell application \"iTerm2\"").last?
        .components(separatedBy: "end tell").first ?? ""
    check(iTermTellBody.contains("id of sessions of tabs of windows")
          && iTermTellBody.contains("tty of sessions of tabs of windows")
          && iTermTellBody.contains("name of sessions of tabs of windows")
          && iTermTellBody.contains("title of tabs of windows")
          && !iTermTellBody.contains("repeat"),
          "the iTerm2 query takes the whole tree in plural gets and iterates nothing inside the tell")
    let terminalQuery = TerminalTitleQuery.terminalScript
    let terminalTellBody = terminalQuery
        .components(separatedBy: "tell application \"Terminal\"").last?
        .components(separatedBy: "end tell").first ?? ""
    check(terminalTellBody.contains("tty of tabs of windows")
          && terminalTellBody.contains("custom title of tabs of windows")
          && terminalTellBody.contains("title displays custom title of tabs of windows")
          && terminalTellBody.contains("selected of tabs of windows")
          && terminalTellBody.contains("name of windows")
          && !terminalTellBody.contains("repeat"),
          "the Terminal.app query takes the whole tree in plural gets and iterates nothing inside the tell")
    check(iTermQuery.contains(TerminalTitleQuery.iTermMatchProgram)
          && terminalQuery.contains(TerminalTitleQuery.terminalMatchProgram),
          "each shipped query carries the very match handler these tests exercise")

    // Two windows; the first has two tabs (two sessions, then one), the second
    // one tab of three. The match is looked for in every position, last included.
    let tables = SyntheticITermTables(
        ids: [[["id-A", "id-B"], ["id-C"]], [["id-D", "id-E", "id-F"]]],
        ttys: [
            [["/dev/ttys001", "/dev/ttys002"], ["/dev/ttys003"]],
            [["/dev/ttys004", "/dev/ttys005", "/dev/ttys006"]],
        ],
        names: [[["name A", "name B"], ["name C"]], [["name D", "name E", "name F"]]],
        titles: [["tab one", "tab two"], ["tab three"]]
    )
    check(tables.result(id: "id-A") == TerminalTitleQueryResult(
            application: .iTerm2, title: "tab one", sessionName: "name A",
            windowIndex: 1, tabIndex: 1, tty: "ttys001", matchedBy: .sessionID),
          "the first session matches by GUID and carries its own tab's title and position")
    check(tables.result(id: "id-F") == TerminalTitleQueryResult(
            application: .iTerm2, title: "tab three", sessionName: "name F",
            windowIndex: 2, tabIndex: 1, tty: "ttys006", matchedBy: .sessionID),
          "a match in the very last position of the last window is still found and correctly placed")
    check(tables.result(id: "id-C") == TerminalTitleQueryResult(
            application: .iTerm2, title: "tab two", sessionName: "name C",
            windowIndex: 1, tabIndex: 2, tty: "ttys003", matchedBy: .sessionID),
          "the tab index counts within its window, not across the whole tree")
    check(tables.result(tty: "/dev/ttys005") == TerminalTitleQueryResult(
            application: .iTerm2, title: "tab three", sessionName: "name E",
            windowIndex: 2, tabIndex: 1, tty: "ttys005", matchedBy: .tty),
          "a session with no GUID to match on is found by tty")
    check(tables.result(id: "id-B", tty: "/dev/ttys002")?.matchedBy == .sessionID,
          "when both name the same session the GUID is what it reports matching on")
    check(tables.result(id: "id-F", tty: "/dev/ttys001") == TerminalTitleQueryResult(
            application: .iTerm2, title: "tab one", sessionName: "name A",
            windowIndex: 1, tabIndex: 1, tty: "ttys001", matchedBy: .tty),
          "a GUID and a tty naming different sessions resolve to the earlier position, as before")
    check(tables.answer(id: "id-Z", tty: "/dev/ttys999")?
            .trimmingCharacters(in: .whitespacesAndNewlines) == ""
          && tables.result(id: "id-Z", tty: "/dev/ttys999") == nil,
          "a GUID and tty nobody owns answer with no match")
    check(tables.result() == nil,
          "with neither a GUID nor a tty to match on nothing is claimed")

    let onlySession = SyntheticITermTables(
        ids: [[["id-only"]]], ttys: [[["/dev/ttys042"]]],
        names: [[["just me"]]], titles: [["only tab"]]
    )
    check(onlySession.result(id: "id-only") == TerminalTitleQueryResult(
            application: .iTerm2, title: "only tab", sessionName: "just me",
            windowIndex: 1, tabIndex: 1, tty: "ttys042", matchedBy: .sessionID),
          "one window of one tab of one session still nests, and matches")

    // Four separate Apple events fetch the four tables, so a tab opened or
    // closed between them leaves the tables describing different trees. A row
    // could then name another tab's title or position — the unforgeable part —
    // so a disagreement answers with no match rather than a shifted one.
    check(SyntheticITermTables(
            ids: tables.ids, ttys: [[["/dev/ttys001", "/dev/ttys002"], ["/dev/ttys003"]]],
            names: tables.names, titles: tables.titles
          ).result(id: "id-A") == nil,
          "tables that disagree about how many windows are open claim nothing")
    check(SyntheticITermTables(
            ids: tables.ids, ttys: tables.ttys, names: tables.names,
            titles: [["tab one"], ["tab three"]]
          ).result(id: "id-A") == nil,
          "tables that disagree about a window's tab count claim nothing")
    check(SyntheticITermTables(
            ids: tables.ids, ttys: tables.ttys,
            names: [[["name A"], ["name C"]], [["name D", "name E", "name F"]]],
            titles: tables.titles
          ).result(id: "id-A") == nil,
          "tables that disagree about a tab's session count claim nothing")

    let hostileTables = SyntheticITermTables(
        ids: [[["id-hostile"]]], ttys: [[["/dev/ttys050"]]],
        names: [[["run\u{202E}reversed"]]],
        titles: [["safe\u{202E}looks reversed\nsecond line\u{07}"]]
    )
    check(hostileTables.result(id: "id-hostile") == TerminalTitleQueryResult(
            application: .iTerm2, title: "safe�looks reversed�second line�",
            sessionName: "run�reversed", windowIndex: 1, tabIndex: 1,
            tty: "ttys050", matchedBy: .sessionID),
          "a title carrying a bidi override, a newline and a BEL survives the round trip neutralized")

    let oversizeTitle = String(repeating: "é", count: 400)
    let oversize = SyntheticITermTables(
        ids: [[["id-long"]]], ttys: [[["/dev/ttys051"]]],
        names: [[["short"]]], titles: [[oversizeTitle]]
    )
    let oversizeResult = oversize.result(id: "id-long")
    check(oversizeResult?.title == oversizeTitle,
          "an over-long tab title reaches Swift whole rather than being truncated in the script")
    let oversizeContext = TerminalSessionInspector.context(
        identity: TerminalSessionIdentity(application: .iTerm2, tty: "ttys051"),
        title: oversizeResult
    )
    check(oversizeContext.title.map {
            $0.utf8.count <= TerminalSessionContext.maximumTitleBytes + "…".utf8.count
          } == true && oversizeContext.title?.hasSuffix("…") == true,
          "and is bounded where every other displayed field is, on the way into the context")

    // Terminal.app has no session layer and no session id: tabs are found by
    // tty, and the title is the custom title, else the window's name while the
    // tab is selected, else nothing.
    let terminalTables = SyntheticTerminalTables(
        ttys: [["/dev/ttys010", "/dev/ttys011", "/dev/ttys013"], ["/dev/ttys012"]],
        customTitles: [["custom one", "unused", "unused"], ["custom three"]],
        showsCustom: [[true, false, false], [true]],
        selected: [[false, false, true], [true]],
        windowNames: ["window one name", "window two name"]
    )
    check(terminalTables.result(tty: "/dev/ttys010") == TerminalTitleQueryResult(
            application: .appleTerminal, title: "custom one", sessionName: nil,
            windowIndex: 1, tabIndex: 1, tty: "ttys010", matchedBy: .tty),
          "a Terminal.app tab showing a custom title reports it, with no session name")
    check(terminalTables.result(tty: "/dev/ttys011") == TerminalTitleQueryResult(
            application: .appleTerminal, title: nil, sessionName: nil,
            windowIndex: 1, tabIndex: 2, tty: "ttys011", matchedBy: .tty),
          "an unselected tab with no custom title reports none rather than a neighbour's")
    check(terminalTables.result(tty: "/dev/ttys013") == TerminalTitleQueryResult(
            application: .appleTerminal, title: "window one name", sessionName: nil,
            windowIndex: 1, tabIndex: 3, tty: "ttys013", matchedBy: .tty),
          "a selected tab with no custom title falls back to its own window's name")
    check(terminalTables.result(tty: "/dev/ttys012") == TerminalTitleQueryResult(
            application: .appleTerminal, title: "custom three", sessionName: nil,
            windowIndex: 2, tabIndex: 1, tty: "ttys012", matchedBy: .tty),
          "the last tab of the last window is found and placed in that window")
    check(terminalTables.result(tty: "/dev/ttys999") == nil
          && terminalTables.result(tty: "") == nil,
          "a tty nobody owns, and no tty at all, claim nothing")
    check(SyntheticTerminalTables(
            ttys: terminalTables.ttys, customTitles: terminalTables.customTitles,
            showsCustom: terminalTables.showsCustom, selected: terminalTables.selected,
            windowNames: ["window one name"]
          ).result(tty: "/dev/ttys010") == nil,
          "Terminal.app tables that disagree about how many windows are open claim nothing")
    check(SyntheticTerminalTables(
            ttys: terminalTables.ttys,
            customTitles: [["custom one"], ["custom three"]],
            showsCustom: terminalTables.showsCustom, selected: terminalTables.selected,
            windowNames: terminalTables.windowNames
          ).result(tty: "/dev/ttys010") == nil,
          "Terminal.app tables that disagree about a window's tab count claim nothing")

    check(TerminalSessionInspector.deviceName("/dev/ttys012") == "ttys012"
          && TerminalSessionInspector.deviceName("ttys012") == "ttys012"
          && TerminalSessionInspector.deviceName("no tty") == nil
          && TerminalSessionInspector.deviceName("/dev/../etc") == nil
          && TerminalSessionInspector.deviceName("") == nil,
          "device names are normalized and anything but a bare device name is rejected")

    // MARK: Ancestry walk

    var tree = SyntheticTerminalTree()
    tree.add(pid: 1602, parent: 1, env: ["__CFBundleIdentifier": "com.googlecode.iterm2"])
    tree.add(pid: 2584, parent: 1602, env: iTermEnvironment, tty: "ttys012")   // login
    tree.add(pid: 2589, parent: 2584, env: iTermEnvironment, tty: "ttys012")   // fish
    tree.add(pid: 31163, parent: 2589, env: iTermEnvironment, tty: "ttys012")  // claude
    tree.add(pid: 40001, parent: 31163, env: iTermEnvironment)                 // zsh -c, no tty
    tree.add(pid: 40002, parent: 40001, env: [:], unreadable: true)            // csec launcher
    let identity = tree.inspector().identity(forCallerPID: 40002)
    check(identity.application == .iTerm2 && identity.tty == "ttys012"
          && identity.iTermSessionUUID == "9EE8062D-0A54-4B65-A987-3261B57FF22E",
          "the walk skips an unreadable caller, takes the nearest terminal-bearing environment, and the nearest tty")

    var scrubbed = SyntheticTerminalTree()
    scrubbed.add(pid: 2589, parent: 1, env: iTermEnvironment, tty: "ttys012")
    scrubbed.add(pid: 50000, parent: 2589, env: ["PATH": "/usr/bin"], tty: "ttys012") // env -i
    scrubbed.add(pid: 50001, parent: 50000, env: ["PATH": "/usr/bin"])
    let scrubbedIdentity = scrubbed.inspector().identity(forCallerPID: 50001)
    check(scrubbedIdentity.application == .iTerm2 && scrubbedIdentity.tty == "ttys012",
          "a scrubbed environment between the caller and its shell is walked through")

    var daemon = SyntheticTerminalTree()
    daemon.add(pid: 60000, parent: 1, env: ["PATH": "/usr/bin"])
    daemon.add(pid: 60001, parent: 60000, env: ["PATH": "/usr/bin"])
    let daemonIdentity = daemon.inspector().identity(forCallerPID: 60001)
    check(daemonIdentity.application == nil && daemonIdentity.tty == nil
          && daemonIdentity.multiplexer == nil,
          "a launchd-rooted process tree yields no terminal")
    let daemonContext = await daemon.inspector().context(forCallerPID: 60001)
    check(daemonContext == .unidentified, "no terminal resolves to the explicit unidentified context")

    var cyclic = SyntheticTerminalTree()
    cyclic.add(pid: 70000, parent: 70001, env: [:])
    cyclic.add(pid: 70001, parent: 70000, env: [:])
    check(cyclic.inspector().identity(forCallerPID: 70000).application == nil,
          "a cyclic parent chain terminates")

    // MARK: Title query gating and assembly

    let iTermAnswer = TerminalTitleQueryResult(
        application: .iTerm2, title: "deploy — ~/project", sessionName: "yarn dev (node)",
        windowIndex: 1, tabIndex: 5, tty: "ttys012", matchedBy: .sessionID
    )
    let recorder = TitleQueryRecorder(answer: iTermAnswer)
    let context = await tree.inspector(titleQuery: { await recorder.record($0) })
        .context(forCallerPID: 40002)
    let asked = await recorder.identities
    check(asked.count == 1 && asked.first?.iTermSessionUUID == "9EE8062D-0A54-4B65-A987-3261B57FF22E"
          && asked.first?.tty == "ttys012",
          "iTerm2 is asked once, with both the session GUID and the tty to match on")
    check(context == TerminalSessionContext(
            application: "iTerm2", title: "deploy — ~/project", sessionName: "yarn dev (node)",
            windowIndex: 1, tabIndex: 5,
            tty: "ttys012", sessionID: "w1t2p3:9EE8062D-0A54-4B65-A987-3261B57FF22E"),
          "the answer and the environment assemble into the displayed context")
    check(context.summary
            == "iTerm2 · “deploy — ~/project” · window 1, tab 5 · ttys012 · running “yarn dev (node)”",
          "the assembled context's summary carries the tab title, position, tty, and session name")

    let unanswered = await tree.inspector(titleQuery: { _ in nil }).context(forCallerPID: 40002)
    check(unanswered.application == "iTerm2" && unanswered.title == nil
          && unanswered.note == "tab title unavailable" && unanswered.tty == "ttys012",
          "an unanswered query (not running, denied, or timed out) still shows the application and tty")

    var kittyTree = SyntheticTerminalTree()
    kittyTree.add(pid: 80000, parent: 1, env: ["KITTY_WINDOW_ID": "2"], tty: "ttys030")
    let kittyRecorder = TitleQueryRecorder(answer: iTermAnswer)
    let kittyContext = await kittyTree.inspector(titleQuery: { await kittyRecorder.record($0) })
        .context(forCallerPID: 80000)
    check(await kittyRecorder.identities.isEmpty && kittyContext.summary == "kitty · ttys030",
          "a terminal csec cannot query is never asked and shows no title note")

    var tmuxTree = SyntheticTerminalTree()
    tmuxTree.add(pid: 90000, parent: 1, env: [
        "TERM_PROGRAM": "tmux", "TMUX": "/tmp/tmux-501/default,1,0", "TMUX_PANE": "%1",
        "ITERM_SESSION_ID": "w0t0p0:9EE8062D-0A54-4B65-A987-3261B57FF22E",
    ], tty: "ttys040")
    let tmuxRecorder = TitleQueryRecorder(answer: iTermAnswer)
    let tmuxResolved = await tmuxTree.inspector(titleQuery: { await tmuxRecorder.record($0) })
        .context(forCallerPID: 90000)
    check(await tmuxRecorder.identities.isEmpty && tmuxResolved.multiplexer == "tmux"
          && tmuxResolved.application == nil,
          "under tmux no terminal application is asked, so a stale tab is never shown")

    // The sudo review (csec-kua.7). csecd answers the helper's sudo_terminal
    // with context(forCallerPID: helper): the helper's minimal environment
    // names no terminal, and the root sudo above it can be read neither for
    // its environment nor its tty, so the walk goes past both to the shell or
    // agent that ran sudo, as it does for every other surface.
    var sudoTree = SyntheticTerminalTree()
    sudoTree.add(pid: 70000, parent: 1, env: iTermEnvironment, tty: "ttys012")  // shell in the tab
    sudoTree.add(pid: 70010, parent: 70000, unreadable: true)  // sudo, euid 0
    sudoTree.add(pid: 70020, parent: 70010, env: ["PATH": "/usr/bin:/bin", "LANG": "C"], tty: "ttys012")  // helper
    let sudoRecorder = TitleQueryRecorder(answer: iTermAnswer)
    let sudoResolved = await sudoTree.inspector(titleQuery: { await sudoRecorder.record($0) })
        .context(forCallerPID: 70020)
    let sudoAsked = await sudoRecorder.identities
    check(sudoAsked.count == 1 && sudoAsked.first?.application == .iTerm2
            && sudoAsked.first?.iTermSessionUUID == "9EE8062D-0A54-4B65-A987-3261B57FF22E"
            && sudoAsked.first?.tty == "ttys012",
          "csecd's lookup for the sudo helper asks iTerm2 once, by the session id of the shell that ran sudo")
    check(sudoResolved.application == "iTerm2" && sudoResolved.tty == "ttys012" && sudoResolved.title != nil,
          "csecd names the sudo's iTerm2 tab from above the unreadable root sudo")

    // A sudo Claude Code ran: its tool shell, sudo and the helper have no
    // controlling terminal, so the tab is the agent's, as on the other panels.
    var agentSudoTree = SyntheticTerminalTree()
    agentSudoTree.add(pid: 71000, parent: 1, env: iTermEnvironment, tty: "ttys012")  // interactive shell
    agentSudoTree.add(pid: 71010, parent: 71000, env: iTermEnvironment, tty: "ttys012")  // agent
    agentSudoTree.add(pid: 71020, parent: 71010, env: ["PATH": "/usr/bin"])  // tool shell
    agentSudoTree.add(pid: 71030, parent: 71020, unreadable: true)  // sudo
    agentSudoTree.add(pid: 71040, parent: 71030, env: ["PATH": "/usr/bin:/bin", "LANG": "C"])  // helper
    let agentSudo = await agentSudoTree.inspector(titleQuery: { _ in iTermAnswer }).context(forCallerPID: 71040)
    check(agentSudo.application == "iTerm2" && agentSudo.tty == "ttys012",
          "csecd names the agent's tab for a sudo from a tool shell with no tty")

    // A sudo in tmux asks no application, exactly as the other panels do.
    var tmuxSudoTree = SyntheticTerminalTree()
    tmuxSudoTree.add(pid: 72000, parent: 1, env: [
        "TERM_PROGRAM": "tmux", "TMUX": "/tmp/tmux-501/default,1,0", "TMUX_PANE": "%1",
    ], tty: "ttys041")
    tmuxSudoTree.add(pid: 72010, parent: 72000, unreadable: true)
    tmuxSudoTree.add(pid: 72020, parent: 72010, env: ["PATH": "/usr/bin:/bin"], tty: "ttys041")
    let tmuxSudoRecorder = TitleQueryRecorder(answer: iTermAnswer)
    let tmuxSudo = await tmuxSudoTree.inspector(titleQuery: { await tmuxSudoRecorder.record($0) })
        .context(forCallerPID: 72020)
    check(await tmuxSudoRecorder.identities.isEmpty && tmuxSudo.multiplexer == "tmux",
          "a sudo in tmux asks no terminal application")

    // With no answer from csecd the helper names the PAM tty alone, and
    // asks no application anything (it has no inspector to ask with).
    func pamFrame(_ tty: String) -> SudoAuthorizationReviewRequest {
        SudoAuthorizationReviewRequest(
            submittedCommand: "sudo /usr/bin/true", workingDirectory: "/Users/example", terminal: tty
        )
    }
    check(pamFrame("/dev/ttys012").ttyOnlyTerminal.summary == "unidentified terminal (ttys012)"
            && pamFrame("ttys012").ttyOnlyTerminal.tty == "ttys012",
          "with no csecd answer the sudo panel names the PAM tty alone")
    check(pamFrame("no tty").ttyOnlyTerminal == .unidentified && pamFrame("").ttyOnlyTerminal == .unidentified,
          "PAM's \"no tty\" placeholder resolves to no terminal")

    // The sudo panel leads with the access panel's terminal fact, and says
    // sudo's own tty only where csecd's tab does not carry it.
    let agentTab = TerminalSessionContext(
        application: "iTerm2", title: "agent", windowIndex: 1, tabIndex: 3, tty: "ttys012")
    check(pamFrame("/dev/ttys012").terminalFact(agentTab) == ReviewDisplay.terminalFact(agentTab),
          "sudo terminal fact: a tab with sudo's own tty is the access panel's fact, the tty not repeated")
    check(pamFrame("no tty").terminalFact(agentTab) == ReviewDisplay.TerminalFact(
            title: "Tab 3 · agent", detail: "iTerm2 · window 1 · ttys012 · sudo itself has no tty"),
          "sudo terminal fact: a sudo with no tty under a named tab says so")
    check(pamFrame("/dev/ttys040").terminalFact(agentTab).detail.hasSuffix(" · ttys012 · sudo reports ttys040"),
          "sudo terminal fact: a tab whose tty is not sudo's names sudo's")
    check(pamFrame("/dev/ttys012").terminalFact(pamFrame("/dev/ttys012").ttyOnlyTerminal)
            == ReviewDisplay.TerminalFact(
                title: "Unidentified terminal", detail: "ttys012 · no recognizable terminal application")
            && pamFrame("no tty").terminalFact(pamFrame("no tty").ttyOnlyTerminal)
                == ReviewDisplay.terminalFact(.unidentified),
          "sudo terminal fact: with no csecd answer the PAM tty alone is the fact, said once")
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await sudoPanelTerminalFactTests(agentTab: agentTab)
    #endif

    // A decoded context is sanitized and bounded like a built one, so a
    // hostile title in csecd's answer cannot reach the panel raw.
    let hostileTitle = "evil\u{1B}]0;fake\u{07}\n" + String(repeating: "x", count: 400)
    let hostileFrame: [String: Any] = [
        "application": "iTerm2", "title": hostileTitle, "tty": "ttys012", "windowIndex": 1, "tabIndex": 2,
    ]
    let decodedHostile = (try? JSONSerialization.data(withJSONObject: hostileFrame))
        .flatMap { try? JSONDecoder().decode(TerminalSessionContext.self, from: $0) }
    let builtHostile = TerminalSessionContext(
        application: "iTerm2", title: hostileTitle, windowIndex: 1, tabIndex: 2, tty: "ttys012"
    )
    let decodedTitle = decodedHostile?.title ?? ""
    check(decodedHostile == builtHostile && decodedTitle.count < hostileTitle.count
            && !decodedTitle.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7F },
          "a decoded terminal context is sanitized and bounded like a built one")
    let built = TerminalSessionContext(
        application: "iTerm2", title: "deploy", sessionName: "fish", windowIndex: 1, tabIndex: 5,
        tty: "ttys012", sessionID: "w0t4p0:ABC", note: nil
    )
    check((try? JSONEncoder().encode(built)).flatMap { try? JSONDecoder().decode(TerminalSessionContext.self, from: $0) }
            == built, "a terminal context round-trips unchanged")

    // MARK: Surfaces

    var caller = CallerInfo(pid: 42, startTime: 7, description: "ruby")
    check(caller.terminalSummary == TerminalSessionContext.unidentified.summary,
          "a caller whose terminal was never resolved reads as unidentified, not omitted")
    caller.terminal = full
    let prompt = BiometricConsent.prompt(
        caller: caller, references: [try! SecretRef("op://vault/item/field")],
        reason: "run migrations", ttl: 60
    )
    check(prompt.contains("terminal: iTerm2 · “deploy — ~/project” · window 1, tab 5 · ttys012"),
          "the standalone Touch ID reason names the terminal tab")

    let reviewPlan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 900,
        operationContext: "run migrations"
    )
    let review = AccessPolicyReview(
        caller: caller, reason: "run migrations", plan: reviewPlan,
        credentials: [PolicyReviewCredential(references: [try! SecretRef("op://vault/item/field")])]
    )
    do {
        let mirrored = try RemoteApprovalReview(accessPolicyReview: review)
        check(mirrored.terminalDescription == full.summary,
              "the mirrored phone review carries the same terminal line")
        let request = RemoteApprovalRequest(
            macDeviceID: UUID().uuidString, macDeviceName: "Mac",
            createdAtMilliseconds: 1, review: mirrored
        )
        let without = RemoteApprovalRequest(
            requestID: request.requestID, macDeviceID: request.macDeviceID, macDeviceName: "Mac",
            createdAtMilliseconds: 1,
            review: RemoteReviewParts.changing(mirrored) { $0.terminalDescription = nil }
        )
        check(try request.signingData() != without.signingData(),
              "the terminal line is part of the signed request, so the phone shows what the Mac signed")
        let oversized = RemoteReviewParts.changing(mirrored) {
            $0.terminalDescription = String(repeating: "x", count: 513)
        }
        do {
            try oversized.validate()
            check(false, "an over-long terminal line is rejected by the phone protocol")
        } catch RemoteApprovalValidationError.fieldOutOfBounds {
            check(true, "an over-long terminal line is rejected by the phone protocol")
        } catch {
            check(false, "an over-long terminal line is rejected by the phone protocol (\(error))")
        }
    } catch {
        check(false, "the mirrored review builds from a review with a terminal (\(error))")
    }

    // MARK: Agent wiring

    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "the terminal wiring test can read its own start time")
        return
    }
    var wiring = SyntheticTerminalTree()
    wiring.add(pid: me, parent: 1, env: iTermEnvironment, tty: "ttys012")
    let reference = "op://vault/terminal/password"
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(TerminalFixtureProvider(
        values: [reference: Data("synthetic-terminal-value".utf8)]
    ))
    let capturing = TerminalCapturingReview()
    let agent = Agent(
        resolver: resolver,
        grants: GrantTable(),
        consent: ApprovingConsent(),
        policyReview: capturing,
        allowUnverifiedPlansForTesting: true,
        terminalInspection: wiring.inspector(titleQuery: { _ in iTermAnswer })
    )
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .unverified),
        root: .caller,
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 600,
        operationContext: "csec exec ruby"
    )
    let response = await agent.handle(
        request: try! AccessRequest(
            references: [reference], reason: "csec exec ruby", ttlSeconds: 600, deliveryPlan: plan
        ),
        caller: CallerInfo(pid: me, startTime: myStart, description: "synthetic launcher")
    )
    let shown = await capturing.caller()
    check(response.values?[reference] != nil,
          "the terminal-wired access request releases its value")
    check(shown?.terminal?.summary
            == "iTerm2 · “deploy — ~/project” · window 1, tab 5 · ttys012 · running “yarn dev (node)”",
          "the agent resolves the caller's terminal from its pid and shows it in the review")

    // MARK: Live kernel readers (this process)

    let liveKeys = ["TERM_PROGRAM", "ITERM_SESSION_ID", "TERM_SESSION_ID", "HOME"]
    let expected = ProcessInfo.processInfo.environment.filter { liveKeys.contains($0.key) }
    let subset = ProcessAncestry.environmentSubset(of: me, keys: liveKeys)
    check(subset == expected,
          "the kernel exec-time environment subset of this process matches its own environment for the requested keys")
    check(ProcessAncestry.environmentSubset(of: me, keys: ["CSEC_SELFTEST_ABSENT_KEY"]) == [:],
          "a key absent from the environment is simply not returned")
    check(ProcessAncestry.environmentSubset(of: 1, keys: liveKeys) == nil,
          "launchd's environment (another user's process) is unreadable and reported as such")
    let liveTTY = ProcessAncestry.controllingTerminalName(of: me)
    if let liveTTY {
        check(liveTTY.hasPrefix("tty") && TerminalSessionInspector.deviceName(liveTTY) == liveTTY,
              "this process's controlling terminal reads as a bare device name (\(liveTTY))")
    } else {
        print("  (skipped: this process has no controlling terminal)")
    }

    if let liveIdentity = TerminalSessionIdentity.identify(environment: expected),
       liveIdentity.application == .iTerm2, liveIdentity.iTermSessionUUID != nil {
        var liveContext = await TerminalSessionInspector.live.context(forCallerPID: me)
        // On a loaded Mac a cold osascript can take seconds to answer, past the
        // 2.5 s bound that keeps a review panel waiting no longer. How long
        // depends on iTerm2's own backlog as much as the load average: 6 s at a
        // load near 750 once, but 36 s for the query's four Apple events at a
        // load near 300 with dozens of sessions open. A missed bound is not a
        // wrong answer, so ask once more with a long bound and hold that answer
        // to the same check: a broken script or a declined Automation
        // permission still fails.
        if liveContext.title == nil {
            let retryTimeout: TimeInterval = 120
            var load = [Double](repeating: 0, count: 3)
            getloadavg(&load, 3)
            print("  (live title query missed its \(TerminalTitleQuery.timeout) s bound at load average "
                  + "\(load.map { String(format: "%.0f", $0) }.joined(separator: " ")); "
                  + "asking again with \(Int(retryTimeout)) s)")
            liveContext = await TerminalSessionInspector.live(titleQueryTimeout: retryTimeout)
                .context(forCallerPID: me)
        }
        check(liveContext.application == "iTerm2" && liveContext.title != nil
              && liveContext.location?.hasPrefix("window ") == true,
              "running under iTerm2, the live inspector names this tab: \(liveContext.summary)")
    } else {
        print("  (skipped: not running under an iTerm2 session, live title query not exercised)")
    }
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  /// The real sudo window: the terminal fact leads, above the submitted
  /// command, and the details grid no longer repeats it in a row.
  @MainActor
  private func sudoPanelTerminalFactTests(agentTab: TerminalSessionContext) {
    NSApplication.shared.setActivationPolicy(.accessory)
    func views(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(views) }
    let review = SudoAuthorizationReviewRequest(
        submittedCommand: "sudo /usr/bin/true", workingDirectory: "/Users/example", terminal: "no tty")
    let panel = ApprovalPanelInspection.sudo(review, terminal: agentTab)
    let content = panel.window.contentView ?? NSView()
    content.layoutSubtreeIfNeeded()
    let fields = views(content).compactMap { $0 as? NSTextField }
    func field(_ identifier: String) -> NSTextField? {
        fields.first { $0.identifier?.rawValue == identifier }
    }
    let title = field(TrustedSudoAuthorizationReviewSession.terminalTitleIdentifier)
    let detail = field(TrustedSudoAuthorizationReviewSession.terminalDetailIdentifier)
    let commandHeading = fields.first { $0.stringValue == "SUBMITTED COMMAND" }
    check(title?.stringValue == "Tab 3 · agent" && title?.font?.pointSize == 22
            && detail?.stringValue == "iTerm2 · window 1 · ttys012 · sudo itself has no tty",
          "sudo panel: the terminal fact shows the tab at the access panel's weight, and sudo's missing tty")
    if let title, let commandHeading {
        // Flipped or not, the fact is drawn above the command's heading.
        let titleY = title.convert(title.bounds, to: content).midY
        let commandY = commandHeading.convert(commandHeading.bounds, to: content).midY
        check(content.isFlipped ? titleY < commandY : titleY > commandY,
              "sudo panel: the terminal fact leads, above the submitted command")
    } else {
        check(false, "sudo panel: the terminal fact leads, above the submitted command")
    }
    check(!fields.contains { $0.stringValue == "Terminal" || $0.stringValue == "Terminal tab" || $0.stringValue == "no tty" },
          "sudo panel: the details grid has no terminal rows left to repeat the fact")
    withExtendedLifetime(panel) {}
  }
#endif
