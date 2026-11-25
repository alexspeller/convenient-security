import Foundation

/// How wide a subtree an approved grant is rooted at, narrowest first.
///
/// The kind only *names* a root that csecd found by walking kernel ancestry from
/// the verified plan root. Whichever kind is chosen, the grant is still bound to
/// an exact PID/start-time pair and every later use must pass a fresh ancestry
/// walk to that same live process incarnation.
public enum GrantScopeKind: String, Codable, Sendable, CaseIterable {
    /// The root the delivery plan itself asked for — the pre-existing behavior.
    case requestingCommand = "requesting_command"
    /// The nearest coding agent above the request (Claude Code, Codex).
    case codingAgent = "coding_agent"
    /// The outermost shell above the request that owns a controlling terminal.
    case terminalSession = "terminal_session"

    /// Whether a grant rooted here may be reused by a *different* command of the
    /// same release shape. Only the requesting-command root keeps the original
    /// exact delivery-plan-digest binding.
    public var reusesAcrossCommands: Bool { self != .requestingCommand }
}

/// One selectable root, resolved from live kernel ancestry.
public struct GrantScopeOption: Sendable, Equatable, Codable {
    public let kind: GrantScopeKind
    public let pid: pid_t
    /// Start time of `pid`, the PID-reuse guard carried into the minted grant.
    public let startTime: UInt64
    /// Already-sanitized human label ("Claude Code", "fish", "csec").
    public let processLabel: String

    public init(kind: GrantScopeKind, pid: pid_t, startTime: UInt64, processLabel: String) {
        self.kind = kind
        self.pid = pid
        self.startTime = startTime
        self.processLabel = processLabel
    }

    /// Stable within one review. It is a lookup hint only: the agent resolves it
    /// against the list it computed itself and re-verifies ancestry before use,
    /// so it authorizes nothing by possession.
    public var id: String { "\(kind.rawValue)-\(pid)-\(startTime)" }
}

/// The scope options offered for one review, with the pre-selected default.
public struct GrantScopeChoices: Sendable, Equatable, Codable {
    public let options: [GrantScopeOption]
    public let defaultOptionID: String

    public init(options: [GrantScopeOption], defaultOptionID: String) {
        self.options = options
        self.defaultOptionID = defaultOptionID
    }

    public var defaultOption: GrantScopeOption {
        option(id: defaultOptionID) ?? options[0]
    }

    public func option(id: String) -> GrantScopeOption? {
        options.first { $0.id == id }
    }

    /// The option a reviewer selected, falling back to the default for an
    /// unknown, stale, or absent identifier. Never widens on bad input: an
    /// unrecognized id can only resolve to the default the human already saw.
    public func resolved(selectedID: String?) -> GrantScopeOption {
        guard let selectedID, let option = option(id: selectedID) else {
            return defaultOption
        }
        return option
    }
}

/// Finds the selectable grant roots above a verified delivery-plan root.
public enum GrantScopeInspector {
    /// How far up the ancestry chain a candidate may be found.
    public static let maximumAncestorHops = 64

    /// Process accounting names that identify an interactive shell. Matching is
    /// on the kernel's short accounting name, lowercased, with a login shell's
    /// leading "-" removed. This only selects a candidate root for the human to
    /// approve; it is never an identity or authorization claim.
    static let shellNames: Set<String> = [
        "sh", "bash", "dash", "zsh", "fish", "ksh", "mksh", "tcsh", "csh", "ash",
    ]

    /// The options to offer for a request whose plan root is
    /// `planRootPID`/`planRootStartTime`.
    ///
    /// - The requesting-command option is always present and always first.
    /// - A coding agent is the *nearest* matching ancestor: an agent creates a
    ///   fresh shell per tool call, so the agent is the stable boundary.
    /// - A terminal session is the *outermost* shell ancestor that owns a
    ///   controlling terminal. The controlling-terminal test is what excludes the
    ///   pipe-wired shells an agent spawns per tool call (measured: those report
    ///   NODEV) and daemon `sh` wrappers; "outermost" is what makes it the
    ///   terminal session rather than an intermediate script shell.
    /// - Every widened candidate must still contain the plan root's subtree.
    public static func choices(
        planRootPID: pid_t,
        planRootStartTime: UInt64,
        requestingLabel: String,
        inspection: ProcessInspection = .live
    ) -> GrantScopeChoices {
        let requesting = GrantScopeOption(
            kind: .requestingCommand,
            pid: planRootPID,
            startTime: planRootStartTime,
            processLabel: ReviewDisplay.sanitized(requestingLabel)
        )

        var codingAgent: GrantScopeOption?
        var terminalSession: GrantScopeOption?
        var visited: Set<pid_t> = [planRootPID]
        // Lineage parents, so a job its tree detached is offered the roots of
        // the tree it was started in (`SessionLineage`).
        var candidate = inspection.lineageParent(of: planRootPID) ?? 0

        for _ in 0..<maximumAncestorHops {
            guard candidate > 1, visited.insert(candidate).inserted,
                  let startTime = inspection.startTime(of: candidate) else { break }

            let name = inspection.name(of: candidate)
            let executablePath = inspection.executablePath(of: candidate)
            let hasTerminal = inspection.hasControllingTerminal(candidate)
            let parent = inspection.lineageParent(of: candidate)
            // Everything above was read field-by-field; discard the whole
            // candidate if the PID was recycled underneath the reads.
            guard inspection.startTime(of: candidate) == startTime else { break }

            // A widened root must strictly contain the plan root's subtree.
            if inspection.descends(planRootPID, from: candidate, rootStartTime: startTime) {
                if codingAgent == nil,
                   let client = CodingAgentIdentity.client(
                    name: name, executablePath: executablePath
                   ) {
                    codingAgent = GrantScopeOption(
                        kind: .codingAgent,
                        pid: candidate,
                        startTime: startTime,
                        processLabel: CodingAgentIdentity.displayName(client)
                    )
                }
                if hasTerminal, let shell = shellName(name) {
                    // Keep overwriting: the last shell seen walking upward is the
                    // outermost one, which is the terminal session itself.
                    terminalSession = GrantScopeOption(
                        kind: .terminalSession,
                        pid: candidate,
                        startTime: startTime,
                        processLabel: shell
                    )
                }
            }

            guard let parent, parent > 1, parent != candidate else { break }
            candidate = parent
        }

        var options = [requesting]
        if let codingAgent { options.append(codingAgent) }
        if let terminalSession, terminalSession.pid != codingAgent?.pid {
            options.append(terminalSession)
        }

        let defaultOption = codingAgent ?? terminalSession ?? requesting
        return GrantScopeChoices(options: options, defaultOptionID: defaultOption.id)
    }

    /// The sanitized shell name for an accounting name, or nil if it is not a
    /// recognized shell.
    static func shellName(_ name: String?) -> String? {
        guard var name = name?.lowercased() else { return nil }
        // A login shell is conventionally exec'd with a leading "-". The kernel
        // accounting name normally omits it; strip it defensively anyway.
        if name.hasPrefix("-") { name.removeFirst() }
        guard shellNames.contains(name) else { return nil }
        return ReviewDisplay.sanitized(name)
    }
}

/// A grant lifetime a reviewer can choose: bound to the process/session it is
/// granted to, or a deliberate shorter wall-clock cap.
public enum GrantDuration: Sendable, Equatable, Codable {
    /// Lives as long as the granted process subtree — no wall-clock expiry. The
    /// process-liveness sweep is the sole authority; nothing re-prompts the human
    /// on a clock.
    case processLifetime
    /// A deliberate shorter opt-in cap, in seconds.
    case bounded(seconds: Int)

    /// The wall-clock cap in seconds, or nil for process lifetime.
    public var ttlSeconds: Int? {
        switch self {
        case .processLifetime: return nil
        case let .bounded(seconds): return seconds
        }
    }
}

/// The grant lifetimes a review offers, with the pre-selected default.
///
/// The default is process lifetime: one Touch ID keeps the credential usable for
/// as long as the granted process subtree lives, so a human is never re-prompted
/// on a clock for a decision they already made. Shorter opt-in caps (1h, 12h)
/// are offered beside it for a human who deliberately wants to narrow the window.
/// When the launcher requested an explicit bound (`--for`), that bound is the
/// default and the unbounded option is withheld — a deliberate request is not
/// silently widened.
public struct GrantDurationChoices: Sendable, Equatable, Codable {
    /// Shorter opt-in caps offered on every review, in seconds: 1 hour, 12 hours.
    public static let standardBoundedSeconds = [60 * 60, 12 * 60 * 60]

    /// The lifetimes offered, in menu order (the default is not implicitly first).
    public let options: [GrantDuration]
    /// The pre-selected option.
    public let defaultOption: GrantDuration

    public init(options: [GrantDuration], defaultOption: GrantDuration) {
        self.options = options
        self.defaultOption = defaultOption
    }

    /// The choices for a plan that requested `requestedTTLSeconds` (nil ⇒ the
    /// default process-lifetime grant).
    public static func offered(requestedTTLSeconds: Int?) -> GrantDurationChoices {
        guard let requested = requestedTTLSeconds else {
            return GrantDurationChoices(
                options: [.processLifetime]
                    + standardBoundedSeconds.map { .bounded(seconds: $0) },
                defaultOption: .processLifetime
            )
        }
        // An explicit bound is honored as the default; the standard shorter caps
        // are offered too, but not the unbounded option.
        let requestedBound = max(requested, 1)
        let seconds = Set(standardBoundedSeconds + [requestedBound]).sorted()
        return GrantDurationChoices(
            options: seconds.map { .bounded(seconds: $0) },
            defaultOption: .bounded(seconds: requestedBound)
        )
    }

    /// The lifetime a reviewer selected by menu index, falling back to the
    /// default for an absent or out-of-range index. Never widens on bad input:
    /// only an option the human was shown can be minted.
    public func resolved(selectedIndex: Int?) -> GrantDuration {
        guard let selectedIndex, options.indices.contains(selectedIndex) else {
            return defaultOption
        }
        return options[selectedIndex]
    }

    /// The menu index of `defaultOption`, for pre-selecting the popup.
    public var defaultIndex: Int {
        options.firstIndex(of: defaultOption) ?? 0
    }
}
