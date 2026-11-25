import CSECRemoteApproval
import Foundation

/// Value-free presentation copy for the trusted review surfaces. Everything
/// here formats policy metadata that is already plaintext-free; dynamic
/// components pass through `sanitized`, which neutralizes control, newline,
/// and bidirectional-formatting characters exactly like `SecretRef`.
public enum ReviewDisplay {

    /// A reference no provider described, shown whole in monospace under no
    /// source, so nothing about it is elided or guessed.
    public static func undescribedSecret(_ reference: SecretRef) -> ReviewSecret {
        ReviewSecret(
            provider: nil, tint: .gray, account: nil, container: nil,
            item: reference.safeInlineURI, field: nil, itemIsIdentifier: true
        )
    }

    /// `secret` as a review shows it for `reference`: unchanged for an
    /// ordinary reference; for a one-time code, with csec's own note first,
    /// saying the code is made for this command only and never kept. Every
    /// Mac panel and the phone draw a secret's notes, so they all say so.
    public static func oneTimeCodeSecret(_ secret: ReviewSecret, for reference: SecretRef) -> ReviewSecret {
        guard reference.isOneTimeCode else { return secret }
        return ReviewSecret(
            provider: secret.provider, tint: secret.tint, account: secret.account,
            container: secret.container, item: secret.item, field: secret.field,
            itemIsIdentifier: secret.itemIsIdentifier,
            notes: Array(([oneTimeCodeNote(item: secret.item)] + secret.notes).prefix(maximumNotes)),
            warnings: secret.warnings
        )
    }

    /// The note on a one-time code's row.
    public static func oneTimeCodeNote(item: String) -> String {
        "One-time code from “\(item)”: made fresh for this command only and never kept."
            + " The next command that needs one asks again."
    }

    /// How many of `review`'s secrets are one-time codes.
    public static func oneTimeCodeCount(_ review: AccessPolicyReview) -> Int {
        review.credentials.flatMap(\.references).filter(\.isOneTimeCode).count
    }

    /// Whether every secret `review` releases is a one-time code: such a
    /// panel grants nothing past this one command, so it offers no scope or
    /// lifetime and says so.
    public static func releasesOnlyOneTimeCodes(_ review: AccessPolicyReview) -> Bool {
        let references = review.credentials.flatMap(\.references)
        return !references.isEmpty && references.allSatisfy(\.isOneTimeCode)
            && review.ssh == nil && review.automation == nil && review.settingsChange == nil
    }

    /// Whether `review` lets its requester use a token for one GitHub request
    /// that can give lasting access, and nothing more: like a one-time code's
    /// panel, it offers no scope or lifetime and says so.
    public static func coversOneGitHubRequest(_ review: AccessPolicyReview) -> Bool {
        review.githubLastingAccess != nil && review.settingsChange == nil
    }

    /// The secret-access panel's headline.
    public static func accessHeadline(for review: AccessPolicyReview) -> String {
        if coversOneGitHubRequest(review) { return "Lasting GitHub Access Requested" }
        guard releasesOnlyOneTimeCodes(review) else { return "Secret Access Requested" }
        return oneTimeCodeCount(review) == 1 ? "One-Time Code Requested" : "One-Time Codes Requested"
    }

    /// What a one-time-code-only panel's "For" row says in place of a lifetime.
    public static let oneTimeCodeLifetime = "This command only"
    public static let oneTimeCodeLifetimeDetail = "nothing is kept · the next command asks again"
    /// And a lasting GitHub request's.
    public static let oneGitHubRequestLifetime = "This request only"
    public static let oneGitHubRequestLifetimeDetail = "nothing is kept · the next one asks again"

    /// The fixed "For" row of a panel that grants nothing past what it asks
    /// for, or nil for a panel with a lifetime to choose.
    public static func fixedLifetime(for review: AccessPolicyReview) -> (title: String, detail: String)? {
        if coversOneGitHubRequest(review) { return (oneGitHubRequestLifetime, oneGitHubRequestLifetimeDetail) }
        if releasesOnlyOneTimeCodes(review) { return (oneTimeCodeLifetime, oneTimeCodeLifetimeDetail) }
        return nil
    }

    /// A provider's description of a reference, made display-safe: every part
    /// originates outside csec (a vault name, an account's sign-in address),
    /// so each has its control, newline and bidirectional-formatting
    /// characters neutralized and is bounded, and at most `maximumNotes`
    /// notes and warnings are kept.
    public static func displaySafe(_ secret: ReviewSecret) -> ReviewSecret {
        let safe = secret.mapStrings { value, part in
            let limit: Int
            switch part {
            case .provider: limit = 64
            case .account: limit = 256
            case .container, .field: limit = 512
            case .item: limit = 1_024
            case .note, .warning: limit = 1_024
            }
            return fitted(value.trimmingCharacters(in: .whitespaces), maxBytes: limit)
        }
        return ReviewSecret(
            provider: safe.provider, tint: safe.tint, account: safe.account,
            container: safe.container, item: safe.item, field: safe.field,
            itemIsIdentifier: safe.itemIsIdentifier,
            notes: Array(safe.notes.prefix(maximumNotes)),
            warnings: Array(safe.warnings.prefix(maximumNotes))
        )
    }

    /// The most notes, and separately warnings, one secret carries: the phone
    /// review's own bound.
    public static let maximumNotes = RemoteApprovalProtocolV3.maximumWarnings

    public static func mechanism(_ mechanism: DeliveryMechanism) -> String {
        switch mechanism {
        case .directHeap: return "Direct to process memory"
        case .execHook: return "Injected at launch"
        case .inheritedFileDescriptor: return "Inherited file descriptor"
        case .capabilityGIDFile: return "Capability-protected file"
        case .restrictedLateEnvironment: return "Restricted late environment"
        case .sealedEnvironment: return "Sealed environment"
        case .unrestrictedInitialEnvironment: return "Unrestricted initial environment"
        case .rawStandardOutput: return "Raw standard output"
        case .namedPlaintextFile: return "Named plaintext file"
        case .credentialProtocol: return "Credential helper protocol"
        case .daemonProxy: return "Used inside Convenient Security (never released)"
        }
    }

    public static func scope(_ scope: DescendantScope) -> String {
        switch scope {
        case .exactProcess: return "exact process only"
        case .subtree: return "process and its descendants"
        case .broadSession: return "entire registered session"
        }
    }

    public static func destination(_ destination: DestinationClass) -> String {
        switch destination {
        case .localDevelopment: return "Local development"
        case .staging: return "Staging"
        case .production: return "Production"
        case .aiTool: return "AI tool"
        case .humanOutput: return "Human output"
        case .shellDelegatedPipe: return "Shell-delegated pipe"
        case .persistentPlaintextFile: return "Persistent plaintext file"
        case .credentialConsumer: return "Credential consumer"
        case .unknown: return "Unknown"
        }
    }

    public static func assurance(_ assurance: ConsumerAssurance) -> String {
        switch assurance {
        case .verifiedProduct: return "Verified product"
        case .independentlyProtected: return "Protected path"
        case .userWritable: return "User-writable"
        case .unverified: return "Unverified"
        case .sealed: return "Sealed"
        }
    }

    /// Short title for one selectable grant scope, e.g. shown beside a radio
    /// button. `processLabel` is already sanitized when the option is built.
    public static func scopeTitle(_ option: GrantScopeOption) -> String {
        switch option.kind {
        case .requestingCommand:
            return "Requesting process only"
        case .codingAgent:
            return "\(option.processLabel) and everything it runs"
        case .terminalSession:
            return "This terminal session"
        }
    }

    /// The process this scope is rooted at, plus what the choice means.
    public static func scopeDetail(_ option: GrantScopeOption) -> String {
        switch option.kind {
        case .requestingCommand:
            return "\(option.processLabel) (pid \(option.pid)) and its descendants — this command only"
        case .codingAgent:
            return "\(option.processLabel) (pid \(option.pid)) — every command it runs, until the grant expires"
        case .terminalSession:
            return "\(option.processLabel) (pid \(option.pid)) — everything started in this terminal, until the grant expires"
        }
    }

    /// One-line scope description for the Touch ID reason text, the post-approval
    /// status line, and the mirrored phone review of a secret release. The SSH
    /// review states its root with `sshScopeRootSummary`.
    public static func scopeSummary(_ option: GrantScopeOption) -> String {
        "\(scopeTitle(option)) — \(option.processLabel) (pid \(option.pid))"
    }

    /// The SSH review's counterpart of `scopeSummary`: the root in the words
    /// its scope radios use, "This SSH command — ssh (pid 812)".
    public static func sshScopeRootSummary(_ option: GrantScopeOption) -> String {
        "\(sshScopeTitle(option)) — \(option.processLabel) (pid \(option.pid))"
    }

    /// `scopeSummary` or `sshScopeRootSummary`, whichever vocabulary `review`'s
    /// layout uses, so a line about the root never mixes the two.
    public static func scopeSummary(_ option: GrantScopeOption, for review: AccessPolicyReview) -> String {
        review.ssh != nil ? sshScopeRootSummary(option) : scopeSummary(option)
    }

    public static func sshScopeTitle(_ option: GrantScopeOption) -> String {
        switch option.kind {
        case .requestingCommand: return "This SSH command"
        case .codingAgent: return "This \(option.processLabel) session"
        case .terminalSession: return "This \(option.processLabel) terminal session"
        }
    }

    public static func sshScopeDetail(_ option: GrantScopeOption) -> String {
        let process = "\(option.processLabel) (pid \(option.pid))"
        switch option.kind {
        case .requestingCommand:
            return "\(process) — only this command and its descendants"
        case .codingAgent:
            return "\(process) — includes SSH from the commands this agent runs"
        case .terminalSession:
            return "\(process) — includes commands and coding agents started in this terminal"
        }
    }

    /// What one touch allows on the SSH review, from the live selection:
    /// "allow SSH from this fish terminal session for up to 12 hours". The
    /// summary under the scope selector and the line beside the sensor are
    /// both built from it, so the two cannot state different grants.
    public static func sshGrantPhrase(_ option: GrantScopeOption?, duration: GrantDuration) -> String {
        let cap = grantCap(duration)
        guard let option, option.kind != .requestingCommand else {
            let tail = cap.isEmpty ? "" : ",\(cap)"
            return "allow this SSH command until it exits\(tail)"
        }
        let session = option.kind == .terminalSession ? "terminal session" : "session"
        return "allow SSH from this \(option.processLabel) \(session)\(cap.isEmpty ? " for as long as it runs" : cap)"
    }

    public static func sshScopeSummary(_ option: GrantScopeOption?, duration: GrantDuration) -> String {
        sentence(sshGrantPhrase(option, duration: duration))
    }

    /// What one touch allows on a secret release, from the live selection:
    /// "release the requested value to Claude Code and everything it runs for
    /// up to 12 hours". Commands in the chosen scope reuse the grant, so the
    /// line beside the sensor names the scope and lifetime, not just this read.
    ///
    /// A value csecd uses on the requester's behalf (`daemonUse`, the GitHub
    /// token proxy) is never released to it, so the line says the scope may
    /// use it instead: "let Claude Code and everything it runs use the
    /// requested value for as long as it runs".
    public static func releaseGrantPhrase(
        _ option: GrantScopeOption?, duration: GrantDuration, referenceCount: Int, daemonUse: Bool = false
    ) -> String {
        let value = referenceCount == 1 ? "the requested value" : "the requested values"
        guard let option else { return daemonUse ? "let this command use \(value)" : "release \(value)" }
        let cap = grantCap(duration)
        let lifetime = cap.isEmpty ? " for as long as it runs" : cap
        switch option.kind {
        case .requestingCommand:
            let tail = cap.isEmpty ? "" : ",\(cap)"
            return daemonUse
                ? "let this command use \(value) until it exits\(tail)"
                : "release \(value) to this command until it exits\(tail)"
        case .codingAgent:
            return daemonUse
                ? "let \(option.processLabel) and everything it runs use \(value)\(lifetime)"
                : "release \(value) to \(option.processLabel) and everything it runs\(lifetime)"
        case .terminalSession:
            return daemonUse
                ? "let this \(option.processLabel) terminal session use \(value)\(lifetime)"
                : "release \(value) to this \(option.processLabel) terminal session\(lifetime)"
        }
    }

    /// The line beside the armed Touch ID sensor on the secret-access, SSH,
    /// restore and automation layouts, for the scope and lifetime selected
    /// now. The sudo panel has its own: it grants nothing past one invocation.
    public static func touchIDReadyText(
        for review: AccessPolicyReview, scope: GrantScopeOption?, duration: GrantDuration
    ) -> String {
        let action: String
        if review.isRestoreOnly {
            action = "reopen these approvals"
        } else if review.settingsChange != nil {
            action = SettingsChangeReviewDetails.readyAction
        } else if review.ssh != nil {
            action = sshGrantPhrase(scope, duration: duration)
        } else if review.automation != nil {
            action = "enable this job until you revoke it"
        } else if coversOneGitHubRequest(review) {
            action = "let this command use the requested value for this one request"
        } else if releasesOnlyOneTimeCodes(review) {
            action = oneTimeCodeCount(review) == 1
                ? "release a one-time code to this command"
                : "release one-time codes to this command"
        } else {
            let codes = oneTimeCodeCount(review)
            action = releaseGrantPhrase(
                scope, duration: duration,
                referenceCount: review.credentials.flatMap(\.references).count - codes,
                daemonUse: review.plan.mechanism == .daemonProxy
            ) + (codes == 0 ? "" : codes == 1
                ? ", and a one-time code to this command only"
                : ", and one-time codes to this command only")
        }
        return "Touch ID is ready. Touch the sensor to \(action)."
    }

    /// The label over a review's secrets: "Secret released", or, for a value
    /// csecd only uses on the requester's behalf, "Secret used, never released".
    public static func secretsHeading(for review: AccessPolicyReview, count: Int) -> String {
        if releasesOnlyOneTimeCodes(review) {
            return count == 1 ? "One-time code released" : "One-time codes released"
        }
        if review.plan.mechanism == .daemonProxy {
            return count == 1 ? "Secret used, never released" : "Secrets used, never released"
        }
        return count == 1 ? "Secret released" : "Secrets released"
    }

    /// " for up to 12 hours" for a bounded lifetime, empty for a process lifetime.
    private static func grantCap(_ duration: GrantDuration) -> String {
        switch duration {
        case .processLifetime: return ""
        case let .bounded(seconds): return " for up to \(self.duration(seconds: seconds))"
        }
    }

    private static func sentence(_ phrase: String) -> String {
        phrase.prefix(1).uppercased() + phrase.dropFirst() + "."
    }

    /// The terminal fact the trusted window leads with: what the human sees in
    /// their tab bar as the headline, and the parts a process in the tab cannot
    /// forge (application, live position, tty) as the detail line.
    public struct TerminalFact: Equatable, Sendable {
        public let title: String
        public let detail: String

        public init(title: String, detail: String) {
            self.title = title
            self.detail = detail
        }
    }

    public static func terminalFact(_ context: TerminalSessionContext) -> TerminalFact {
        if let multiplexer = context.multiplexer {
            var title = multiplexer
            if let sessionID = context.sessionID { title += " pane \(sessionID)" }
            var detail = ["host terminal tab not identifiable through \(multiplexer)"]
            if let tty = context.tty { detail.insert(tty, at: 0) }
            return TerminalFact(title: title, detail: detail.joined(separator: " · "))
        }
        guard let application = context.application else {
            if let tty = context.tty {
                return TerminalFact(
                    title: "Unidentified terminal",
                    detail: "\(tty) · no recognizable terminal application"
                )
            }
            return TerminalFact(
                title: "No terminal",
                detail: "nothing above the requesting process owns a terminal"
            )
        }
        let title: String
        var detail: [String] = []
        switch (context.tabIndex, context.title) {
        case let (tab?, tabTitle?): title = "Tab \(tab) · \(tabTitle)"
        case let (nil, tabTitle?): title = tabTitle
        case let (tab?, nil): title = "Tab \(tab)"
        case (nil, nil): title = application
        }
        if title != application { detail.append(application) }
        if let window = context.windowIndex { detail.append("window \(window)") }
        if let tty = context.tty { detail.append(tty) }
        if let sessionName = context.sessionName { detail.append("running “\(sessionName)”") }
        if context.title == nil, let note = context.note { detail.append(note) }
        return TerminalFact(title: title, detail: detail.joined(separator: " · "))
    }

    /// The popup title for a grant-lifetime option: "Until it exits" for a
    /// process-lifetime grant, or the bounded duration ("1 hour").
    public static func durationTitle(for duration: GrantDuration) -> String {
        switch duration {
        case .processLifetime: return "Until it exits"
        case let .bounded(seconds): return self.duration(seconds: seconds)
        }
    }

    /// The live expiry line for a grant-lifetime option: a clock time for a
    /// bounded cap, or a no-clock statement for a process-lifetime grant.
    public static func expiry(
        for duration: GrantDuration,
        from now: Date = Date(),
        calendar: Calendar = .current
    ) -> String {
        switch duration {
        case .processLifetime: return "no time limit — available while it runs"
        case let .bounded(seconds):
            return expiry(seconds: seconds, from: now, calendar: calendar)
        }
    }

    /// "until 15:42" for a lifetime ending today, "until Wed 15:42" otherwise.
    public static func expiry(
        seconds: Int,
        from now: Date = Date(),
        calendar: Calendar = .current
    ) -> String {
        let end = now.addingTimeInterval(TimeInterval(seconds))
        let formatter = DateFormatter()
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = calendar.isDate(end, inSameDayAs: now) ? "HH:mm" : "EEE HH:mm"
        return "until \(formatter.string(from: end))"
    }

    public static func root(_ root: DeliveryRoot) -> String {
        switch root {
        case .caller: return "Requesting launcher"
        case .directParent: return "Verified direct parent"
        case .registeredSession: return "Registered kernel-verified session"
        }
    }

    public static func duration(seconds total: Int) -> String {
        func unit(_ count: Int, _ singular: String) -> String {
            count == 1 ? "1 \(singular)" : "\(count) \(singular)s"
        }
        if total < 60 { return unit(max(total, 0), "second") }
        if total < 3600 {
            let minutes = total / 60
            let seconds = total % 60
            return seconds == 0
                ? unit(minutes, "minute")
                : "\(unit(minutes, "minute")) \(unit(seconds, "second"))"
        }
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        return minutes == 0
            ? unit(hours, "hour")
            : "\(unit(hours, "hour")) \(unit(minutes, "minute"))"
    }

    /// Trims `value` to at most `maxBytes` UTF-8 bytes without splitting a
    /// character, for surfaces whose wire format enforces a byte bound.
    /// The most bytes of a command line a review surface renders. Longer argv is
    /// cut here with an explicit note rather than silently, so the reader knows
    /// the window is not showing everything the launcher will run.
    public static let maximumCommandLineDisplayBytes = 16_384

    /// One argv vector as a shell-readable line: each argument sanitized, and
    /// single-quoted only when it holds a character a shell would interpret.
    /// Newlines inside an argument survive (a `bash -c` program is often
    /// multi-line); every other control and bidi character is neutralized.
    public static func commandLine(_ arguments: [String]) -> String {
        let line = arguments.map(commandArgument).joined(separator: " ")
        guard line.utf8.count > maximumCommandLineDisplayBytes else { return line }
        return bounded(line, maxBytes: maximumCommandLineDisplayBytes)
            + "\n… command line truncated for display"
    }

    public static func commandArgument(_ value: String) -> String {
        let safe = sanitized(value, allowNewlines: true)
        guard !safe.isEmpty else { return "''" }
        let unquoted = safe.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122)
                || [43, 44, 45, 46, 47, 58, 61, 64, 95].contains($0)
        }
        if unquoted { return safe }
        return "'" + safe.replacingOccurrences(of: "'", with: "'\\''", options: .literal) + "'"
    }

    public static func bounded(_ value: String, maxBytes: Int) -> String {
        guard value.utf8.count > maxBytes else { return value }
        var trimmed = ""
        var used = 0
        for character in value {
            let size = String(character).utf8.count
            if used + size > maxBytes - 1 { break }
            trimmed.append(character)
            used += size
        }
        return trimmed + "…"
    }

    /// `sanitized`, then cut to at most `maxBytes` UTF-8 bytes *including* the
    /// ellipsis that marks the cut, at a character boundary. For a wire field
    /// that enforces its byte bound: `bounded` lets its ellipsis run two bytes
    /// past the budget, and sanitizing after it can still grow the text (each
    /// newline or control byte becomes a three-byte U+FFFD). This result always
    /// fits and never holds a NUL, so a long or multi-line value is shortened
    /// rather than rejected.
    public static func fitted(
        _ value: String,
        maxBytes: Int,
        allowNewlines: Bool = false
    ) -> String {
        let safe = sanitized(value, allowNewlines: allowNewlines)
        guard safe.utf8.count > maxBytes else { return safe }
        let ellipsis = "…"
        let budget = maxBytes - ellipsis.utf8.count
        guard budget >= 0 else { return "" }
        var kept = ""
        var used = 0
        for character in safe {
            let size = character.utf8.count
            if used + size > budget { break }
            kept.append(character)
            used += size
        }
        return kept + ellipsis
    }

    /// Neutralizes bidirectional-formatting, newline, and control characters in
    /// text that may be attacker-influenced before it reaches a trusted window.
    /// Bidi overrides are always neutralized (they can reorder a consent line).
    /// `allowNewlines` keeps newlines (for multi-line evidence/fragments) and
    /// `allowOtherControls` keeps the remaining control characters (for value-free
    /// document fragments that legitimately carry tabs/formatting) — the three
    /// combinations replace the former `sanitized`, `auditSafe`, `setupSafe`,
    /// `setupDocumentSafe`, and `promptSafe` helpers.
    public static func sanitized(
        _ value: String,
        allowNewlines: Bool = false,
        allowOtherControls: Bool = false
    ) -> String {
        let bidiControls: Set<UInt32> = [
            0x061c, 0x200e, 0x200f,
            0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
            0x2066, 0x2067, 0x2068, 0x2069,
        ]
        return value.unicodeScalars.map { scalar in
            if bidiControls.contains(scalar.value) { return "�" }
            if CharacterSet.newlines.contains(scalar) {
                return allowNewlines ? String(scalar) : "�"
            }
            if CharacterSet.controlCharacters.contains(scalar) {
                return allowOtherControls ? String(scalar) : "�"
            }
            return String(scalar)
        }.joined()
    }
}
