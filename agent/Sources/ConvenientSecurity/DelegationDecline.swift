import Foundation

/// Why csecd did not let Claude Code's auto-mode classifier stand in for a
/// panel, so the request went to the human instead.
///
/// Every case is csecd-authored copy with bounded, sanitized parameters: a
/// flag or environment name comes from the fixed gate lists, never from P's
/// raw argv or environment, and a reference or path is metadata the panel
/// already shows. The panel renders `panelText` below its footnote on the
/// secret-access, SSH and sudo layouts, and the phone card under its
/// footnote (never on a restore-only panel), and the decision log records
/// `code` with the same text.
public enum DelegationDecline: Sendable, Equatable {
    /// No registration from csec's Claude Code hook matched this command.
    case notRegistered
    /// The hook registered the command in another permission mode.
    case notAutoMode(String)
    /// P is not the interactive foreground job of a terminal (G3).
    case notInteractive
    /// P was started with a launch option on the G4 list.
    case launchOption(String)
    /// P was started with a name on the G5 list set (or a code-loading
    /// `NODE_OPTIONS`).
    case injectedEnvironment(String)
    /// P's exec-time environment (or argv) could not be read, as for a
    /// restricted build whose environment the kernel withholds.
    case environmentUnreadable
    /// P's `HOME` is not the account's home, so it reads settings the gate
    /// would not.
    case homeMismatch
    /// P's `CLAUDE_CONFIG_DIR` is empty, relative, or not on a local disk.
    case configDirectoryUnusable
    /// P is neither Claude Code signed by Anthropic nor a build trusted by
    /// cdhash.
    case unverifiedBuild(String)
    /// P's code identity has not been source-verified against the settings gate.
    case uncheckedBuild(String)
    /// P's working directory (or the hook's) is not on a local disk, so
    /// csecd neither reads its settings nor pairs it.
    case projectNotLocal
    /// P's working directory could not be read.
    case projectUnavailable
    /// csecd could not collect P's facts in time: a read blocked (a hung
    /// network mount), or an earlier one still does.
    case factsUnavailable
    /// A Claude Code settings file could not be read (or csecd has no
    /// settings gate).
    case settingsUnreadable(String)
    /// A settings `env` block sets a name on the G5 list.
    case settingsEnvironment(name: String, path: String)
    /// G1: `autoMode.classifyAllShell` is not set in user or policy settings.
    case allowRulesActive
    /// G2: a hook the human has not acknowledged can approve Bash commands,
    /// or (`blocksReload`, a `ConfigChange` hook) can keep Claude Code from
    /// reloading its hooks, which keeps an approving hook in force.
    /// `launch` names P's launch option that alone brings the hook in (a
    /// plugin its inline `--settings` enables, an `--add-dir` directory's
    /// skill): `csec setup` never sees P's argv, so it cannot show the hook.
    case otherHook(String, blocksReload: Bool = false, launch: String? = nil)
    /// G2: a settings source carries auto-mode classifier rules the human
    /// has not acknowledged as they are now.
    case classifierRules(String)
    /// G6: the sandbox can approve commands.
    case sandboxAutoAllow(String)
    /// G6: `permissions.defaultMode` makes bypass reachable.
    case bypassReachable(String)
    /// G6: hooks are switched off, so csec's own never runs.
    case hooksDisabled(setting: String, path: String)
    /// One of Claude Code's credential records holds a Cloud-gateway sign-in,
    /// which sends the classifier's requests to the gateway (csec-kpep).
    case gatewaySignIn
    /// csecd could not list or read Claude Code's credential records, so it
    /// cannot rule a Cloud-gateway sign-in out.
    case gatewaySignInUnchecked
    /// A reference no human has paired with this project.
    case notApprovedForProject(reference: String, project: String)
    /// A paired reference csecd does not hold unlocked, and (`reason`, the
    /// provider's own value-free sentence) why its provider could not serve
    /// it just now with no interaction.
    case notHeld(String, reason: String? = nil)
    /// A one-time code, which auto mode never releases: a person approves
    /// each one (csec-0.65).
    case oneTimeCode(String)
    /// A GitHub request through csecd's socket that can give access
    /// outlasting any approval (`GitHubLastingAccess`), which auto mode never
    /// approves: a person approves each one (csec-0.49).
    case lastingAccess(String)
    /// `process` (sudo, or the `timeout` that runs it) does not match any
    /// simple command of the text auto mode judged.
    case commandMismatch(process: String)
    /// `process` (the command's shell) was started with `name`, which can
    /// redirect what it does, set.
    case environmentSteering(process: String, name: String)
    /// sudo descends from a process other than the command's shell, the
    /// `csec ai` that ran it, or `timeout`.
    case sudoIndirect(String)
    /// sudo was run with an option that hands root something the classifier
    /// never read (`-E`, `-s`, `-i`, `-e` or their long forms), or one csec
    /// cannot read; named from `SudoInvocation`'s fixed list.
    case sudoOption(String)
    /// No human has let auto mode run sudo in this project.
    case sudoNotApproved(project: String)
    /// A process named Claude Code ran this itself (`gh issue list`), not as
    /// a command auto mode approved, and it is none of Claude Code's own
    /// queries csecd lets through.
    case agentOwnCommand(String)

    /// Stable, value-free identifier for the decision log and status.
    public var code: String {
        switch self {
        case .notRegistered: return "not_registered"
        case .notAutoMode: return "not_auto_mode"
        case .notInteractive: return "not_interactive"
        case .launchOption: return "launch_option"
        case .injectedEnvironment: return "injected_environment"
        case .environmentUnreadable: return "environment_unreadable"
        case .homeMismatch: return "home_mismatch"
        case .configDirectoryUnusable: return "config_directory_unusable"
        case .unverifiedBuild: return "unverified_build"
        case .uncheckedBuild: return "unchecked_build"
        case .projectNotLocal: return "project_not_local"
        case .projectUnavailable: return "project_unavailable"
        case .factsUnavailable: return "facts_unavailable"
        case .settingsUnreadable: return "settings_unreadable"
        case .settingsEnvironment: return "settings_environment"
        case .allowRulesActive: return "allow_rules_active"
        case .otherHook: return "other_hook"
        case .classifierRules: return "classifier_rules"
        case .sandboxAutoAllow: return "sandbox_auto_allow"
        case .bypassReachable: return "bypass_reachable"
        case .hooksDisabled: return "hooks_disabled"
        case .gatewaySignIn: return "gateway_sign_in"
        case .gatewaySignInUnchecked: return "gateway_sign_in_unchecked"
        case .notApprovedForProject: return "not_approved_for_project"
        case .notHeld: return "not_held"
        case .oneTimeCode: return "one_time_code"
        case .lastingAccess: return "lasting_access"
        case .commandMismatch: return "command_mismatch"
        case .environmentSteering: return "environment_steering"
        case .sudoIndirect: return "sudo_indirect"
        case .sudoOption: return "sudo_option"
        case .sudoNotApproved: return "sudo_not_approved"
        case .agentOwnCommand: return "agent_own_command"
        }
    }

    /// What follows "Auto mode didn't approve this: ".
    public var reason: String {
        switch self {
        case .notRegistered:
            return "csec's Claude Code hook didn't register this command."
        case let .notAutoMode(mode):
            return "Claude Code was in \(Self.modeName(mode)) mode."
        case .notInteractive:
            return "this Claude Code session isn't the foreground job of a terminal."
        case let .launchOption(flag):
            return "Claude Code was started with \(Self.safe(flag, 64))."
        case let .injectedEnvironment(name):
            return "Claude Code was started with \(Self.safe(name, 128)) set."
        case .environmentUnreadable:
            return "csecd couldn't read how this Claude Code session was started."
        case .homeMismatch:
            return "Claude Code was started with a HOME other than your home directory."
        case .configDirectoryUnusable:
            return "Claude Code's CLAUDE_CONFIG_DIR isn't a local absolute path csecd can read."
        case let .unverifiedBuild(label):
            return "Claude Code \(Self.safe(label, 64)) isn't signed by Anthropic — trust it with \(Self.setupCommand)."
        case let .uncheckedBuild(label):
            return "csec hasn't checked Claude Code \(Self.safe(label, 64)) against its settings gate yet, so this "
                + "request needs Touch ID. Auto mode resumes by itself once csec's list of checked releases includes it."
        case .projectNotLocal:
            return "this Claude Code session's project isn't on a local disk."
        case .projectUnavailable:
            return "csecd couldn't read this Claude Code session's project directory."
        case .factsUnavailable:
            return "csecd couldn't read this session's process facts in time."
        case let .settingsUnreadable(path):
            return "csecd couldn't read \(Self.safe(path, 256))."
        case let .settingsEnvironment(name, path):
            return "\(Self.safe(path, 256)) sets \(Self.safe(name, 128)) for Claude Code."
        case .allowRulesActive:
            return "autoMode.classifyAllShell is off, so allow rules can approve commands — run \(Self.setupCommand)."
        case let .otherHook(display, blocksReload, launch):
            let does = blocksReload ? "can keep Claude Code from reloading its hooks" : "can approve shell commands"
            guard let launch else {
                return "\(Self.safe(display, 256)) \(does) — review it with \(Self.setupCommand)."
            }
            return "\(Self.safe(display, 256)) \(does) and comes from Claude Code's \(Self.safe(launch, 64)), "
                + "which csec setup can't see — start Claude Code without it."
        case let .classifierRules(display):
            return "\(Self.safe(display, 256)) steer the classifier and aren't acknowledged as they are now"
                + " — review them with \(Self.setupCommand)."
        case let .sandboxAutoAllow(path):
            return "sandbox.enabled in \(Self.safe(path, 256)) lets the sandbox approve commands."
        case let .bypassReachable(path):
            return "permissions.defaultMode in \(Self.safe(path, 256)) makes bypass reachable."
        case let .hooksDisabled(setting, path):
            return "\(Self.safe(setting, 64)) in \(Self.safe(path, 256)) turns csec's hook off."
        case .gatewaySignIn:
            return "Claude Code is signed in to a Cloud gateway, which would answer auto mode's classifier."
        case .gatewaySignInUnchecked:
            return "csecd couldn't check whether Claude Code is signed in to a Cloud gateway."
        case let .notApprovedForProject(reference, project):
            return "\(Self.safe(reference, 512)) hasn't been approved for \(Self.safe(project, 128))."
        case let .notHeld(reference, reason):
            guard let reason else { return "\(Self.safe(reference, 512)) isn't unlocked in csecd yet." }
            return "\(Self.safe(reference, 512)) couldn't be fetched without you: \(Self.safe(reason, 384))."
        case let .oneTimeCode(reference):
            return "\(Self.safe(reference, 512)) is a one-time code, and every one needs you."
        case let .lastingAccess(request):
            return "\(Self.safe(request, 300)) can give access that outlasts any approval, and every such request needs you."
        case let .commandMismatch(process):
            return "\(Self.safe(process, 256)) doesn't match the command auto mode approved."
        case let .environmentSteering(process, name):
            return "\(Self.safe(process, 256)) was started with \(Self.safe(name, 64)) set."
        case let .sudoIndirect(name):
            return "sudo was started by \(Self.safe(name, 64)), not by the command auto mode approved."
        case let .sudoOption(option):
            return "sudo was run with \(Self.safe(option, 64)), which gives root more than the command shows."
        case let .sudoNotApproved(project):
            return "sudo hasn't been approved for auto mode in \(Self.safe(project, 128))."
        case let .agentOwnCommand(command):
            return "Claude Code ran \(Self.safe(command, 64)) itself, not as a command auto mode approved."
        }
    }

    /// The line the panel shows.
    public var panelText: String { Self.panelPrefix + reason }

    /// The command that fixes what `needsSetup` reasons name.
    public static let setupCommand = "csec setup auto-mode"

    /// Whether this declined on an unacknowledged G2 source (a hook or a
    /// source's classifier rules), which csecd's one-touch panel can
    /// acknowledge.
    public var isUnacknowledgedSettings: Bool {
        switch self {
        case .otherHook, .classifierRules: return true
        default: return false
        }
    }

    /// Whether the human can end this decline with `csec setup auto-mode`
    /// (trust a build, restore classifyAllShell, acknowledge a hook or
    /// classifier rules): until they do, every delegated request in the
    /// session declines the same way.
    public var needsSetup: Bool {
        switch self {
        case .unverifiedBuild, .allowRulesActive, .classifierRules: return true
        case let .otherHook(_, _, launch): return launch == nil
        default: return false
        }
    }

    /// When approving a panel this declined lets auto mode act in the
    /// project, for a reason pairing cannot end: every request of the session
    /// declines at this gate before any pairing is consulted, so the pairing
    /// line says when it starts to count ("once Claude Code is started without
    /// --settings") rather than promising it now. Nil for a reason that is
    /// the pairing itself or belongs to this one request (an option, a
    /// mode, a value not held), after which the next request can use it.
    public var pairingCondition: String? {
        switch self {
        case .notInteractive:
            return "once Claude Code runs as a terminal's foreground job"
        case let .launchOption(flag):
            return "once Claude Code is started without \(Self.safe(flag, 64))"
        case let .injectedEnvironment(name):
            return "once Claude Code is started without \(Self.safe(name, 128)) set"
        case .environmentUnreadable:
            return "once csecd can read how Claude Code was started"
        case .homeMismatch:
            return "once Claude Code is started with your home directory as HOME"
        case .configDirectoryUnusable:
            return "once Claude Code is started with a local absolute CLAUDE_CONFIG_DIR"
        case let .unverifiedBuild(label):
            return "once you trust Claude Code \(Self.safe(label, 64)) with \(Self.setupCommand)"
        case let .uncheckedBuild(label):
            return "once csec's list of checked releases includes Claude Code \(Self.safe(label, 64))"
        case .projectNotLocal:
            return "once this Claude Code session's directories are on a local disk"
        case .projectUnavailable:
            return "once csecd can read this Claude Code session's project directory"
        case .settingsUnreadable:
            return "once csecd can read Claude Code's settings"
        case let .settingsEnvironment(name, _):
            return "once Claude Code's settings no longer set \(Self.safe(name, 128))"
        case .allowRulesActive:
            return "once you run \(Self.setupCommand)"
        case let .otherHook(_, _, launch?):
            return "once Claude Code is started without the \(Self.safe(launch, 64)) that bring in that hook"
        case .otherHook:
            return "once you review that hook with \(Self.setupCommand)"
        case .classifierRules:
            return "once you review those rules with \(Self.setupCommand)"
        case .sandboxAutoAllow:
            return "once sandbox.enabled is off"
        case .bypassReachable:
            return "once permissions.defaultMode no longer makes bypass reachable"
        case let .hooksDisabled(setting, _):
            return "once \(Self.safe(setting, 64)) is off"
        case .gatewaySignIn:
            return "once Claude Code is signed out of the Cloud gateway"
        case .gatewaySignInUnchecked:
            return "once csecd can check Claude Code's sign-in"
        case .notRegistered, .notAutoMode, .factsUnavailable, .notApprovedForProject, .notHeld, .oneTimeCode,
             .lastingAccess, .commandMismatch, .environmentSteering, .sudoIndirect, .sudoOption, .sudoNotApproved,
             .agentOwnCommand:
            return nil
        }
    }

    /// What `csec ai` prints to the session when a request under it declined
    /// for a `needsSetup` reason, so the agent can tell the human: nil for any
    /// other reason. Value-free, csecd-authored, within
    /// `maximumSetupNoticeBytes`.
    public var setupNotice: String? {
        guard needsSetup else { return nil }
        return ReviewDisplay.bounded(
            "delegated approvals are waiting on setup, so auto mode's approval went to Touch ID instead: "
                + reason + " Ask the user to run `\(Self.setupCommand)` in a terminal.",
            maxBytes: Self.maximumSetupNoticeBytes)
    }

    public static let maximumSetupNoticeBytes = 1_024

    /// What every panel note starts with.
    public static let panelPrefix = "Auto mode didn't approve this: "

    /// The status row's `lastDecline`, within `DelegationStatus`'s bound.
    public var statusText: String {
        ReviewDisplay.bounded(panelText, maxBytes: DelegationStatus.maximumLastDeclineBytes)
    }

    /// The name Claude Code's own mode indicator shows for a `permission_mode`
    /// the hook reported ("manual mode" for `default`, "accept edits" for
    /// `acceptEdits`), so the note names the mode the human saw; a name csec
    /// does not know passes through sanitized.
    static func modeName(_ permissionMode: String) -> String {
        switch permissionMode {
        case "default": return "manual"
        case "acceptEdits": return "accept edits"
        case "dontAsk": return "don't ask"
        case "bypassPermissions": return "bypass permissions"
        default: return safe(permissionMode, 32)
        }
    }

    private static func safe(_ value: String, _ maximumBytes: Int) -> String {
        ReviewDisplay.bounded(ReviewDisplay.sanitized(value), maxBytes: maximumBytes)
    }
}
