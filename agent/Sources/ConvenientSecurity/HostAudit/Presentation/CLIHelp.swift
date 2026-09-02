import Foundation

// The single source of truth for `csec`'s command-line help. These pure,
// `Sendable` value types describe every dispatchable command; `CLIHelpRenderer`
// turns them into the global and per-command help screens. They live here — next
// to `TerminalStyle`/`AuditReportRenderer`, the established "pure presentation in
// the library" home — so the renderers and the completeness tests run from the
// framework-free `cs-selftest`. The launcher (`csec`) only wires stream/exit/color
// selection around these; it holds no help text of its own.
//
// These types are CLI-wide (not audit-specific); they share this directory only
// because it is where the package keeps unit-testable terminal presentation.

/// One flag a command accepts, with its one-line summary.
public struct CLIOption: Sendable, Equatable {
    public let flags: String
    public let summary: String

    public init(flags: String, summary: String) {
        self.flags = flags
        self.summary = summary
    }
}

/// One named sub-action of a command (e.g. `csec ssh register`).
public struct CLISubaction: Sendable, Equatable {
    public let name: String
    public let summary: String

    public init(name: String, summary: String) {
        self.name = name
        self.summary = summary
    }
}

/// The category a command is grouped under in the global help listing.
public enum CLICategory: String, CaseIterable, Sendable {
    case secrets
    case filesAndSSH
    case hostAudit
    case onboarding
    case admin

    public var title: String {
        switch self {
        case .secrets: return "Secret access"
        case .filesAndSSH: return "Files & SSH keys"
        case .hostAudit: return "Host posture audit"
        case .onboarding: return "Onboarding & coding agents"
        case .admin: return "Service & status"
        }
    }
}

/// The complete description of one dispatchable command.
public struct CLICommand: Sendable {
    public let name: String
    public let summary: String
    public let synopsis: [String]
    public let discussion: String
    public let options: [CLIOption]
    public let subactions: [CLISubaction]
    public let category: CLICategory
    /// A command dispatched but intentionally kept out of the global listing
    /// (e.g. `bridge`, a private language-client protocol). It still has a
    /// per-command help page reachable by name.
    public let hidden: Bool

    public init(
        name: String,
        summary: String,
        synopsis: [String],
        discussion: String = "",
        options: [CLIOption] = [],
        subactions: [CLISubaction] = [],
        category: CLICategory,
        hidden: Bool = false
    ) {
        self.name = name
        self.summary = summary
        self.synopsis = synopsis
        self.discussion = discussion
        self.options = options
        self.subactions = subactions
        self.category = category
        self.hidden = hidden
    }
}

/// The catalog of every `csec` command — one entry per dispatch case.
public enum CLICatalog {
    public static let program = "csec"

    /// A one-line description of what `csec` is, shown atop the global help.
    public static let tagline =
        "Resolve secret references one Touch-ID tap at a time, and audit the Mac it runs on."

    public static func command(named name: String) -> CLICommand? {
        commands.first { $0.name == name }
    }

    /// The nearest non-hidden command name within edit distance 2, for the
    /// "did you mean?" hint on an unknown command. `nil` when nothing is close.
    public static func suggestion(for name: String) -> String? {
        let sanitized = ReviewDisplay.sanitized(name)
        var best: (name: String, distance: Int)?
        for command in commands where !command.hidden {
            let distance = levenshtein(sanitized, command.name)
            if distance <= 2, best == nil || distance < best!.distance {
                best = (command.name, distance)
            }
        }
        return best?.name
    }

    /// Bounded Levenshtein edit distance over Characters (the command names are
    /// short ASCII), using a single rolling row.
    static func levenshtein(_ lhs: String, _ rhs: String) -> Int {
        let a = Array(lhs)
        let b = Array(rhs)
        if a.isEmpty { return b.count }
        if b.isEmpty { return a.count }
        var previous = Array(0...b.count)
        var current = [Int](repeating: 0, count: b.count + 1)
        for i in 1...a.count {
            current[0] = i
            for j in 1...b.count {
                let cost = a[i - 1] == b[j - 1] ? 0 : 1
                current[j] = min(
                    previous[j] + 1,        // deletion
                    current[j - 1] + 1,     // insertion
                    previous[j - 1] + cost  // substitution
                )
            }
            swap(&previous, &current)
        }
        return previous[b.count]
    }

    public static let commands: [CLICommand] = [
        // MARK: - Secret access

        CLICommand(
            name: "get",
            summary: "Fetch one secret to the reviewed stdout shape (terminal, pipe, or file)",
            synopsis: [
                "csec get <reference> [--reason <text>] [--for <seconds>] [--reveal | --allow-plaintext-file]",
            ],
            discussion: """
            Fetch a secret from csecd and write it to the selected stdout shape:
              csec get REF | command          pipe to a command — allowed
              value=$(csec get REF)           command substitution — allowed
              csec get REF                    terminal — refused; --reveal to echo
              csec get REF > file             file — refused; --allow-plaintext-file

            A raw value is refused when it would land in terminal scrollback, on disk, \
            or in a non-interactive (agent/script) capture, since a coding agent or \
            logger could retain it; the matching flag overrides under Touch ID. Prefer \
            csec exec / exec-file / creds, which hand the value to a tool without \
            returning it here. Each delivery shape is approved separately.
            """,
            options: [
                CLIOption(flags: "--reason <text>", summary: "Operation context shown in the review window"),
                CLIOption(flags: "--for <seconds>", summary: "Grant lifetime, 1–86400 seconds"),
                CLIOption(flags: "--reveal", summary: "Echo the raw value to a terminal or captured pipe anyway"),
                CLIOption(flags: "--allow-plaintext-file", summary: "Write the raw value to a persistent file anyway"),
            ],
            category: .secrets
        ),
        CLICommand(
            name: "exec",
            summary: "Run a command with secret references resolved into its environment",
            synopsis: [
                "csec exec [--reason <text>] [--for <seconds>] [--set NAME=<reference>]…",
                "          [--redact-output=always|tty|never]",
                "          [--redact-output-label=reference|opaque] [--redact-short-values]",
                "          [--redact-output-warn] -- <cmd> [args…]",
            ],
            discussion: """
            Run <cmd> with secret references resolved into its environment. Any env value \
            that is a secret reference (DATABASE_URL=csec://…) is resolved in place; \
            --set NAME=<ref> injects additional ones. If the project holds *.csec \
            sidecars (from csec protect), csec instead materializes each protected file \
            back at its original path for the wrapped tree on root-owned tmpfs.

            Resolved values appearing in the child's output are masked everywhere by \
            default (--redact-output=always): terminals, pipes, and captured logs. \
            --redact-output=tty limits masking to terminal output, and \
            --redact-output=never disables it for a byte-exact stream. A masked value is \
            replaced in-band with [redacted: <reference>]; --redact-output-label=opaque \
            restores an opaque [csec:secret-N]. A per-match stderr warning is opt-in via \
            --redact-output-warn.
            """,
            options: [
                CLIOption(flags: "--reason <text>", summary: "Operation context shown in the review window"),
                CLIOption(flags: "--for <seconds>", summary: "Grant lifetime, 1–86400 seconds"),
                CLIOption(flags: "--set NAME=<reference>", summary: "Inject an additional reference as env NAME"),
                CLIOption(flags: "--redact-output=always|tty|never", summary: "Where to mask resolved values in output"),
                CLIOption(flags: "--redact-output-label=reference|opaque", summary: "Style of the in-band redaction label"),
                CLIOption(flags: "--redact-short-values", summary: "Also match values shorter than the automatic minimum"),
                CLIOption(flags: "--redact-output-warn", summary: "Emit a per-match warning to stderr"),
            ],
            category: .secrets
        ),
        CLICommand(
            name: "session",
            summary: "Register a kernel-verified broad grant root, then run a command at the same PID",
            synopsis: ["csec session -- <cmd> [args…]"],
            discussion: """
            Register this PID/start-time as an explicit broad session root, then replace \
            csec with the requested command so grants in that subtree reuse one review.
            """,
            category: .secrets
        ),
        CLICommand(
            name: "creds",
            summary: "Serve a tool-native credential protocol (AWS, Git) over a private pipe",
            synopsis: [
                "csec creds aws (--item <reference> |",
                "               --access-key-id-ref <reference> --secret-access-key-ref <reference>",
                "               [--session-token-ref <reference>] [--expiration-ref <reference>])",
                "               [--reason <text>] [--for <seconds>]",
                "csec creds git --host <host> [--protocol <scheme>] [--path <repository>]",
                "               [--username-ref <reference>] --password-ref <reference>",
                "               [--reason <text>] [--for <seconds>] get|store|erase",
            ],
            discussion: """
            Serve AWS credential_process output or Git credential-helper output through a \
            private stdout pipe, so the consuming tool receives the value without it \
            crossing a terminal or a file.
            """,
            options: [
                CLIOption(flags: "--reason <text>", summary: "Operation context shown in the review window"),
                CLIOption(flags: "--for <seconds>", summary: "Grant lifetime, 1–86400 seconds"),
            ],
            subactions: [
                CLISubaction(name: "aws", summary: "Serve an AWS credential_process JSON bundle"),
                CLISubaction(name: "git", summary: "Serve a Git credential-helper response for one host"),
            ],
            category: .secrets
        ),
        CLICommand(
            name: "exec-fd",
            summary: "Stream file-shaped secrets into inherited anonymous descriptors",
            synopsis: [
                "csec exec-fd [--reason <text>] [--for <seconds>]",
                "             (--fd ENV_NAME=<reference> |",
                "              --preset {pgpass|kubeconfig|aws-shared-credentials|google-service-account}=<reference>)…",
                "             [--redact-output=always|tty|never]",
                "             [--redact-output-label=reference|opaque] [--redact-short-values]",
                "             [--redact-output-warn] -- <cmd> [args…]",
            ],
            discussion: """
            Give a child anonymous single-open secret files at /dev/fd/N. Presets set \
            PGPASSFILE, KUBECONFIG, AWS_SHARED_CREDENTIALS_FILE, or \
            GOOGLE_APPLICATION_CREDENTIALS to the non-secret descriptor path.
            """,
            options: [
                CLIOption(flags: "--fd ENV_NAME=<reference>", summary: "Bind a reference to an inherited descriptor"),
                CLIOption(flags: "--preset NAME=<reference>", summary: "Bind a reference through a known file template"),
                CLIOption(flags: "--reason <text>", summary: "Operation context shown in the review window"),
                CLIOption(flags: "--for <seconds>", summary: "Grant lifetime, 1–86400 seconds"),
                CLIOption(flags: "--redact-output=always|tty|never", summary: "Where to mask resolved values in output"),
                CLIOption(flags: "--redact-output-label=reference|opaque", summary: "Style of the in-band redaction label"),
                CLIOption(flags: "--redact-short-values", summary: "Also match values shorter than the automatic minimum"),
                CLIOption(flags: "--redact-output-warn", summary: "Emit a per-match warning to stderr"),
            ],
            category: .secrets
        ),
        CLICommand(
            name: "exec-file",
            summary: "Give a process tree protected regular files on bounded tmpfs",
            synopsis: [
                "csec exec-file [--reason <text>] [--for <seconds>] [--hard-ttl]",
                "               (--file ENV_NAME=<reference> | --gh-config <reference>)…",
                "               [--github-host <host>] [--github-user <login>]",
                "               [--github-git-protocol https|ssh]",
                "               [--redact-output=always|tty|never]",
                "               [--redact-output-label=reference|opaque] [--redact-short-values]",
                "               [--redact-output-warn] -- <cmd> [args…]",
            ],
            discussion: """
            Give a launched process tree seekable/reopenable root-owned regular files on \
            bounded tmpfs. A fresh primary GID is the per-launch capability; csec never \
            receives the file bytes. --gh-config creates a protected hosts.yml only after \
            ambient GitHub authentication has been removed.
            """,
            options: [
                CLIOption(flags: "--file ENV_NAME=<reference>", summary: "Bind a reference to a protected regular file"),
                CLIOption(flags: "--gh-config <reference>", summary: "Create a protected GitHub CLI hosts.yml"),
                CLIOption(flags: "--github-host <host>", summary: "GitHub host for --gh-config (default github.com)"),
                CLIOption(flags: "--github-user <login>", summary: "GitHub login recorded in the protected config"),
                CLIOption(flags: "--github-git-protocol https|ssh", summary: "Git protocol recorded in the protected config"),
                CLIOption(flags: "--hard-ttl", summary: "Tear the files down when the grant expires, mid-run"),
                CLIOption(flags: "--reason <text>", summary: "Operation context shown in the review window"),
                CLIOption(flags: "--for <seconds>", summary: "Grant lifetime, 1–86400 seconds"),
                CLIOption(flags: "--redact-output=always|tty|never", summary: "Where to mask resolved values in output"),
                CLIOption(flags: "--redact-output-label=reference|opaque", summary: "Style of the in-band redaction label"),
                CLIOption(flags: "--redact-short-values", summary: "Also match values shorter than the automatic minimum"),
                CLIOption(flags: "--redact-output-warn", summary: "Emit a per-match warning to stderr"),
            ],
            category: .secrets
        ),
        CLICommand(
            name: "tool-exec",
            summary: "Fail-closed AI command broker that scans output before releasing it",
            synopsis: ["csec tool-exec --destination ai -- <cmd> [args…]"],
            discussion: """
            Run a command whose output is scanned against every active value in the \
            resident agent before any bytes are returned to an AI command runner. If the \
            scanner is unavailable the command does not run.
            """,
            options: [
                CLIOption(flags: "--destination ai", summary: "Required output recipient class (AI tool)"),
            ],
            category: .secrets
        ),
        CLICommand(
            name: "bridge",
            summary: "Private framed stdin/stdout protocol for language clients",
            synopsis: ["csec bridge"],
            discussion: """
            Private framed stdin/stdout protocol for language clients; not for terminals. \
            stdin and stdout must both be private pipes.
            """,
            category: .secrets,
            hidden: true
        ),

        // MARK: - Files & SSH keys

        CLICommand(
            name: "protect",
            summary: "Move plaintext secret files or env vars into the encrypted store",
            synopsis: [
                "csec protect [--store <store>] [--keep-plaintext] [--dry-run] <path>…",
                "csec protect --ssh [--store <store>] [--keep-plaintext] [--dry-run] <private-key>…",
                "csec protect --env [--store <store> | --dest <csec://STORE|op://VAULT[/ITEM]>]",
                "             [--dry-run] <file>",
            ],
            discussion: """
            Move whole plaintext secret files into the encrypted store and replace each \
            with a tiny <name>.csec sidecar; a later csec exec materializes them. The \
            value is durable in the store before any plaintext is removed. \
            --keep-plaintext leaves the original in place; --dry-run only reports.

            --env instead treats one file as an env file (direnv semantics): an \
            interactive picker chooses which variables to import into the native store or \
            1Password (--dest op://VAULT[/ITEM]), then the file is rewritten in place \
            with csec:// / op:// references.

            --ssh protects explicitly named private keys (including paths outside the \
            current project), registers only their canonical references and public \
            metadata with csecd's SSH signer, preserves existing .pub files, and creates \
            a missing .pub. The private key is removed only after both succeed.
            """,
            options: [
                CLIOption(flags: "--store <store>", summary: "Destination native store name"),
                CLIOption(flags: "--dest <csec://…|op://…>", summary: "Destination for --env (native store or 1Password)"),
                CLIOption(flags: "--env", summary: "Import selected variables from one env file, rewrite in place"),
                CLIOption(flags: "--ssh", summary: "Protect and register named private keys with the SSH signer"),
                CLIOption(flags: "--keep-plaintext", summary: "Leave the original plaintext in place after import"),
                CLIOption(flags: "--dry-run", summary: "Report the plan without changing anything"),
            ],
            category: .filesAndSSH
        ),
        CLICommand(
            name: "edit",
            summary: "Edit a csec:// store as JSON, or set one secret by reference",
            synopsis: [
                "csec edit [--editor] <store>",
                "csec edit <reference>",
            ],
            discussion: """
            Edit a csec:// store as strict JSON. The default built-in editor is fileless; \
            --editor uses $EDITOR with a temporary plaintext file.

            With a full reference (csec://STORE/KEY or op://VAULT/ITEM/FIELD) it sets that \
            one secret instead: on a terminal the value is typed into a hidden prompt \
            (entered twice, never echoed); otherwise it is read from stdin (one trailing \
            newline stripped). A missing csec:// key is created; the value never appears \
            in argv or output.
            """,
            options: [
                CLIOption(flags: "--editor", summary: "Use $EDITOR with a temporary plaintext file instead of the built-in editor"),
            ],
            category: .filesAndSSH
        ),
        CLICommand(
            name: "ssh",
            summary: "Manage the backend-neutral SSH key catalog and print the agent socket",
            synopsis: [
                "csec ssh socket | env | list",
                "csec ssh register [--label <label>] <reference|sidecar.csec>",
                "csec ssh remove <SHA256:fingerprint>",
            ],
            discussion: """
            Manage the backend-neutral SSH key catalog and print the manual agent socket. \
            register accepts csec://, op://, future provider references, or an ordinary \
            .csec sidecar. Use `export SSH_AUTH_SOCK="$(csec ssh socket)"`; signing is \
            limited to Apple /usr/bin/ssh, a verified non-forwarded destination session, \
            SSH user-auth payloads, and bounded host-key + remote-user + process-subtree \
            grants.
            """,
            options: [
                CLIOption(flags: "--label <label>", summary: "Human label recorded with a registered key"),
            ],
            subactions: [
                CLISubaction(name: "socket", summary: "Print the SSH agent socket path"),
                CLISubaction(name: "env", summary: "Print an export SSH_AUTH_SOCK line"),
                CLISubaction(name: "list", summary: "List registered protected SSH keys"),
                CLISubaction(name: "register", summary: "Register a key from a reference or sidecar"),
                CLISubaction(name: "remove", summary: "Remove a registered key by fingerprint"),
            ],
            category: .filesAndSSH
        ),

        // MARK: - Host posture audit

        CLICommand(
            name: "audit",
            summary: "Run the value-free host posture audit and offer the reversible fixes",
            synopsis: ["csec audit [--report-only] [--json] [--attest] [--scan-filesystem]"],
            discussion: """
            Run the value-free host posture audit through csecd and render the findings \
            (severity-ordered, ★ marks controls that shrink same-user malware blast \
            radius). On a terminal the scan animates live progress; piped or --json output \
            stays plain. By default it then offers the reversible fixes as an in-terminal \
            checkbox picker (one bare Touch ID in csecd applies the selected set), triages \
            whatever is still failing, and prints a copy-paste attestation of the final \
            posture.
            """,
            options: [
                CLIOption(flags: "--report-only", summary: "Print the report without remediation or triage"),
                CLIOption(flags: "--json", summary: "Emit the machine-readable report (implies --report-only)"),
                CLIOption(flags: "--attest", summary: "Print only the pasteable attestation"),
                CLIOption(flags: "--scan-filesystem", summary: "Add the bounded SUID/world-writable sweep"),
            ],
            category: .hostAudit
        ),

        // MARK: - Onboarding & coding agents

        CLICommand(
            name: "setup",
            summary: "Guided interactive onboarding for csecd, Full Disk Access, and agent hooks",
            synopsis: ["csec setup [--project <directory>]"],
            discussion: """
            A guided, interactive flow: assess the resident agent, Full Disk Access, and \
            supported coding agents, then for each actionable item explain what it does, \
            ask, and either apply it or walk you through it. Finishes with the bounded \
            security-audit prompt and an optional host audit. Requires an interactive \
            terminal; it changes nothing without a per-step confirmation.
            """,
            options: [
                CLIOption(flags: "--project <directory>", summary: "Target project directory (default: current directory)"),
            ],
            category: .onboarding
        ),
        CLICommand(
            name: "hook",
            summary: "PreToolUse stdin/stdout adapter for Claude Code or Codex",
            synopsis: ["csec hook claude|codex"],
            discussion: "PreToolUse stdin/stdout adapter for Claude Code or Codex; reads hook JSON and rewrites the proposed command.",
            subactions: [
                CLISubaction(name: "claude", summary: "Adapt Claude Code PreToolUse input"),
                CLISubaction(name: "codex", summary: "Adapt Codex PreToolUse input"),
            ],
            category: .onboarding
        ),
        CLICommand(
            name: "hook-config",
            summary: "Print a hook JSON fragment using this exact csec executable",
            synopsis: ["csec hook-config claude|codex"],
            discussion: "Print the value-free hook JSON fragment for the selected client, using this exact csec executable path.",
            subactions: [
                CLISubaction(name: "claude", summary: "Print the Claude Code hook fragment"),
                CLISubaction(name: "codex", summary: "Print the Codex hook fragment"),
            ],
            category: .onboarding
        ),
        CLICommand(
            name: "automation",
            summary: "Register an explicit mutable-script trust exception for unattended jobs",
            synopsis: [
                "csec automation add <name> --ref <reference>… [--reason <text>]",
                "                     [--every <seconds>] [--max-runtime <seconds>]",
                "                     [--cwd <directory>] -- <cmd> [args…]",
                "csec automation list | run <name> | revoke <name>",
            ],
            discussion: """
            Register an exact command and canonical references once under Touch ID, then \
            run it unattended with `csec automation run NAME`. This explicitly trusts the \
            mutable script, dependencies, working-directory contents, arguments, and \
            ordinary sanitized trigger environment with those references until revoked. \
            The signed csec runner, interpreter identity, direct-child process \
            incarnation, max runtime, and output redaction stay enforced. Use the run \
            form from cron or launchd; never invoke the stored script directly.
            """,
            options: [
                CLIOption(flags: "--ref <reference>", summary: "A canonical reference the job is trusted with (repeatable)"),
                CLIOption(flags: "--reason <text>", summary: "Operation context recorded with the job"),
                CLIOption(flags: "--every <seconds>", summary: "Minimum interval between runs"),
                CLIOption(flags: "--max-runtime <seconds>", summary: "Maximum runtime before the run is terminated"),
                CLIOption(flags: "--cwd <directory>", summary: "Working directory for the command"),
            ],
            subactions: [
                CLISubaction(name: "add", summary: "Enroll a new unattended job under Touch ID"),
                CLISubaction(name: "list", summary: "List enrolled jobs and their trust"),
                CLISubaction(name: "run", summary: "Run an enrolled job (from cron/launchd)"),
                CLISubaction(name: "revoke", summary: "Revoke an enrolled job"),
            ],
            category: .onboarding
        ),
        CLICommand(
            name: "grants",
            summary: "List the live grants csecd is holding",
            synopsis: ["csec grants"],
            discussion: """
            Show every live grant: the process subtree it is rooted at, the \
            references it covers, when it expires, and whether it is reusable by \
            other commands in that tree. Grants live only in csecd's memory, \
            disappear when their root process exits or csecd restarts, and are \
            never shown with a secret value. The scope of each grant is the one \
            picked in its Touch ID review window.
            """,
            category: .secrets
        ),
        CLICommand(
            name: "revoke",
            summary: "Drop a live grant before it expires",
            synopsis: ["csec revoke <grant-id>", "csec revoke --all"],
            discussion: """
            Drop one grant (by the id or id prefix shown in `csec grants`) or every \
            live grant. The next access to those references prompts again. \
            Revocation only removes access, so it needs no Touch ID.
            """,
            options: [
                CLIOption(flags: "--all", summary: "Revoke every live grant"),
            ],
            category: .secrets
        ),

        // MARK: - Service & status

        CLICommand(
            name: "install",
            summary: "Register csecd as a login-item LaunchAgent",
            synopsis: ["csec install"],
            discussion: "Register csecd as a login-item LaunchAgent so it runs in the background at login.",
            category: .admin
        ),
        CLICommand(
            name: "uninstall",
            summary: "Unregister the csecd LaunchAgent",
            synopsis: ["csec uninstall"],
            discussion: "Unregister the csecd LaunchAgent.",
            category: .admin
        ),
        CLICommand(
            name: "status",
            summary: "Show app, agent, provider, SSH, remote-approval, and root-helper status",
            synopsis: ["csec status"],
            discussion: """
            Show app, LaunchAgent, authenticated agent/provider, SSH, shell, \
            remote-approval, and root-helper status together, with an overall verdict.
            """,
            category: .admin
        ),
        CLICommand(
            name: "doctor",
            summary: "Diagnose and repair the installed agent, sockets, and service health",
            synopsis: ["csec doctor [--check]"],
            discussion: """
            Diagnose and repair the installed app's per-user agent, stale sockets, and \
            service health. --check performs no repairs.
            """,
            options: [
                CLIOption(flags: "--check", summary: "Diagnose only; perform no repairs"),
            ],
            category: .admin
        ),
        CLICommand(
            name: "root-status",
            summary: "Verify that the authenticated root helper is reachable",
            synopsis: ["csec root-status"],
            discussion: "Verify that the authenticated regular-file root helper is reachable.",
            category: .admin
        ),
        CLICommand(
            name: "remote",
            summary: "Opt one iPhone into mirrored approvals",
            synopsis: ["csec remote status | enable <phone-pairing-code> | disable"],
            discussion: """
            Explicitly opt one iPhone into mirrored approvals. `enable` pins the phone's \
            public pairing code under local Touch ID, then prints the Mac public pairing \
            code to import in the phone app. Once both sides are paired, the local and \
            phone prompts race; the first authenticated decision wins. `disable` removes \
            the pin under local Touch ID. Pairing codes contain no credential values.
            """,
            subactions: [
                CLISubaction(name: "status", summary: "Show remote approval configuration"),
                CLISubaction(name: "enable", summary: "Pair an iPhone by its public pairing code"),
                CLISubaction(name: "disable", summary: "Remove the paired iPhone under Touch ID"),
            ],
            category: .admin
        ),
    ]
}
