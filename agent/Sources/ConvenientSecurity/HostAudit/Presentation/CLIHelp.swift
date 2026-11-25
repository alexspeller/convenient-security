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
                CLIOption(flags: "--for <seconds>", summary: "Cap the grant at this many seconds (any positive number)"),
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
                "          [--with-file <path>]… [--redact-output=always|tty|never]",
                "          [--redact-output-label=reference|opaque] [--redact-short-values]",
                "          [--redact-output-warn] -- <cmd> [args…]",
            ],
            discussion: """
            Run <cmd> with secret references resolved into its environment. Any env value \
            that is a secret reference is resolved in place. Prefer csec_DATABASE_URL=csec://…: \
            the child gets DATABASE_URL and the csec_ alias is removed. Both names set \
            is an error unless --set selects a reference. The prefix is case-sensitive; \
            --set NAME=<ref> injects additional ones. If the project holds *.csec \
            sidecars (from csec protect), csec instead materializes each protected file \
            back at its original path for the wrapped tree on root-owned tmpfs.

            A protected token file in your home directory (~/.vault-token, \
            ~/.cargo/credentials.toml…) is restored for the tool that reads it, from any \
            directory: csec exec -- vault … brings back the Vault token and no other. \
            --with-file <path> names one for a tool started through a wrapper or library \
            (npx, a Python script). Each file is listed in the same review.

            Environment injection is a compatibility path: same-user processes can \
            read secrets from the child's initial environment. Output masking does \
            not hide it. Each injecting launch warns on stderr. Prefer credential \
            adapters (csec creds aws / csec creds git), csec exec-fd or csec exec-file \
            when the tool supports them.

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
                CLIOption(flags: "--for <seconds>", summary: "Cap the grant at this many seconds (any positive number)"),
                CLIOption(flags: "--set NAME=<reference>", summary: "Inject an additional reference as env NAME"),
                CLIOption(flags: "--with-file <path>", summary: "Also restore this protected home file (repeatable)"),
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
                "csec creds google --item <reference> [--reason <text>] [--for <seconds>]",
            ],
            discussion: """
            Serve AWS credential_process output or Git credential-helper output through a \
            private stdout pipe, so the consuming tool receives the value without it \
            crossing a terminal or a file.
            """,
            options: [
                CLIOption(flags: "--reason <text>", summary: "Operation context shown in the review window"),
                CLIOption(flags: "--for <seconds>", summary: "Cap the grant at this many seconds (any positive number)"),
            ],
            subactions: [
                CLISubaction(name: "aws", summary: "Serve an AWS credential_process JSON bundle"),
                CLISubaction(name: "git", summary: "Serve a Git credential-helper response for one host"),
                CLISubaction(name: "google", summary: "Serve a Google external-account executable's OIDC token"),
            ],
            category: .secrets
        ),
        CLICommand(
            name: "gcloud",
            summary: "Run Google Cloud API commands with a reviewed token kept in memory",
            synopsis: ["csec gcloud --item <reference> -- <gcloud arguments…>"],
            discussion: """
            setup google installs a gcloud shell function using this command. It resolves \
            any provider's access-token reference after review, delivers it through the \
            process environment and disables gcloud's file logging and token caching. \
            Same-user process inspection can read the environment. Use gcloud storage \
            instead of gsutil, and client libraries for BigQuery. Credential-management \
            commands, alternate credentials and gcloud-side impersonation are refused. \
            The token cannot refresh inside a long-running command.
            """,
            category: .secrets
        ),
        CLICommand(
            name: "fly",
            summary: "Run the Fly.io CLI with its token kept out of its config file",
            synopsis: [
                "csec fly <fly arguments…>",
                "csec fly register [<reference> | --remove]",
            ],
            discussion: """
            Run fly with the registered token in FLY_API_TOKEN, through csec exec's review \
            and grants: a terminal-session grant covers every later fly command in that \
            terminal. `csec protect --fly` imports and registers fly's token; register \
            names any provider's reference instead, shows the registration with no \
            argument, or forgets it with --remove. The registration lives in csec.json \
            beside fly's config. fly's agent runs isolated (FLY_AGENT_ISOLATED=1) so it \
            exits with the command. `csec fly auth login` takes the new token out of the \
            file again; `csec fly auth logout` also forgets the registration. Every other \
            argument, --help included, goes to fly. Same-user process inspection can read \
            fly's environment while it runs.
            """,
            subactions: [
                CLISubaction(name: "register", summary: "Show, set or remove the Fly token reference"),
            ],
            category: .secrets
        ),
        CLICommand(
            name: "exec-fd",
            summary: "Stream file-shaped secrets into inherited anonymous descriptors",
            synopsis: [
                "csec exec-fd [--reason <text>] [--for <seconds>]",
                "             (--fd ENV_NAME=<reference> |",
                "              --preset {pgpass|kubeconfig|aws-shared-credentials|google-service-account|npm}=<reference>)…",
                "             [--redact-output=always|tty|never]",
                "             [--redact-output-label=reference|opaque] [--redact-short-values]",
                "             [--redact-output-warn] -- <cmd> [args…]",
            ],
            discussion: """
            Give a child anonymous single-open secret files at /dev/fd/N. Presets set \
            PGPASSFILE, KUBECONFIG, AWS_SHARED_CREDENTIALS_FILE, \
            GOOGLE_APPLICATION_CREDENTIALS, or NPM_CONFIG_USERCONFIG to the non-secret \
            descriptor path. The npm preset streams the live ~/.npmrc with the \
            referenced auth lines added.
            """,
            options: [
                CLIOption(flags: "--fd ENV_NAME=<reference>", summary: "Bind a reference to an inherited descriptor"),
                CLIOption(flags: "--preset NAME=<reference>", summary: "Bind a reference through a known file template"),
                CLIOption(flags: "--reason <text>", summary: "Operation context shown in the review window"),
                CLIOption(flags: "--for <seconds>", summary: "Cap the grant at this many seconds (any positive number)"),
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
                CLIOption(flags: "--for <seconds>", summary: "Cap the grant at this many seconds (any positive number)"),
                CLIOption(flags: "--redact-output=always|tty|never", summary: "Where to mask resolved values in output"),
                CLIOption(flags: "--redact-output-label=reference|opaque", summary: "Style of the in-band redaction label"),
                CLIOption(flags: "--redact-short-values", summary: "Also match values shorter than the automatic minimum"),
                CLIOption(flags: "--redact-output-warn", summary: "Emit a per-match warning to stderr"),
            ],
            category: .secrets
        ),
        CLICommand(
            name: "ai",
            summary: "Coding-agent command broker: resolve references and redact output",
            synopsis: ["csec ai -- '<command>'"],
            discussion: """
            The wrapper the Claude Code / Codex PreToolUse hook rewrites every Bash \
            command to. It resolves any secret references in the environment into the \
            command's environment (csec_NAME references become NAME, with the alias \
            removed; legacy unprefixed references still resolve in place), then scans the command's output \
            against every active value in the resident agent before any bytes reach the \
            AI, masking them as opaque [csec:secret-N].

            Environment injection is a compatibility path: same-user processes can \
            read secrets from the child's initial environment. Output masking does \
            not hide it. Each injecting launch warns on stderr; secret-free commands \
            that skip injection do not. Prefer credential adapters (csec creds aws / \
            csec creds git), csec exec-fd or csec exec-file when the tool supports them.

            It shares one injection engine with csec exec; they differ only in trigger and \
            output posture. exec is human-invoked with terminal-facing, disable-able \
            redaction; ai is hook-invoked with always-on, opaque, fail-closed redaction. \
            The first secret-using command in a coding-agent session prompts once for \
            Touch ID (scope "Claude Code"); later commands of the same shape reuse it with \
            no prompt. If the agent is unavailable the command retries briefly, then warns \
            and runs without injection or output scanning — see csec doctor.
            """,
            category: .secrets
        ),
        CLICommand(
            name: "tool-exec",
            summary: "Deprecated alias for csec ai",
            synopsis: ["csec tool-exec --destination ai -- <cmd> [args…]"],
            discussion: """
            Deprecated hidden alias for csec ai, kept so hook rewrites emitted by an older \
            csec keep working. Use csec ai instead.
            """,
            options: [
                CLIOption(flags: "--destination ai", summary: "Required output recipient class (AI tool)"),
            ],
            category: .secrets,
            hidden: true
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
                "csec protect --aws [--aws-config <config>] [--store <store>] [--dry-run] <file>",
                "csec protect --gh [--store <store>] [--keep-plaintext] [--dry-run]",
                "csec protect --fly [--store <store> | --dest <csec://STORE|op://VAULT[/ITEM]>]",
                "             [--keep-plaintext] [--dry-run]",
            ],
            discussion: """
            Protect explicitly named files anywhere, independent of the current directory. \
            Choose the protection by file type using setup's credential catalog. Unknown \
            files (or --whole-file) become encrypted blobs with a <name>.csec sidecar; \
            a later csec exec within the containing project materializes them. The \
            value is durable in the store before any plaintext is removed. \
            --keep-plaintext leaves the original in place; --dry-run only reports.

            AWS shared credentials use csec creds aws: import static profiles, configure \
            credential_process, then remove migrated static fields. Preserve other settings \
            and derived profiles. --aws selects this for a custom filename; --aws-config \
            overrides AWS_CONFIG_FILE (default ~/.aws/config). The config parent must exist.

            --env instead treats one file as an env file (direnv semantics): an \
            interactive picker chooses which variables to import into the native store or \
            1Password (--dest op://VAULT[/ITEM]), then the file is rewritten in place \
            with csec_NAME="csec://…" / csec_NAME="op://…" references. Existing references \
            are renamed without re-importing; conflicting live NAME/csec_NAME definitions \
            are rejected before import. Reload the file and unset stale NAME exports.

            --ssh protects explicitly named private keys (including paths outside the \
            current project), registers only their canonical references and public \
            metadata with csecd's SSH signer, preserves existing .pub files, and creates \
            a missing .pub. The private key is removed only after both succeed.

            --gh moves the GitHub CLI's token into csec (store github by default) with \
            one Touch ID, registers it with csecd's GitHub socket, points gh at that \
            socket with a placeholder token, and then deletes gh's keychain copy. gh keeps \
            working; the token itself never leaves csecd.

            --fly moves the Fly.io CLI's token out of fly's config.yml (FLY_CONFIG_DIR or \
            ~/.fly) into csec (store fly by default, or 1Password with --dest) with one \
            confirmation, registers it for csec fly, and empties access_token and \
            metrics_token, keeping every other setting. Alias fly to csec fly; csec \
            prints the line and edits no shell profile.
            """,
            options: [
                CLIOption(flags: "--store <store>", summary: "Destination native store name"),
                CLIOption(flags: "--dest <csec://…|op://…>", summary: "Destination for --env or --fly (native store or 1Password)"),
                CLIOption(flags: "--env", summary: "Import selected variables from one env file, rewrite in place"),
                CLIOption(flags: "--ssh", summary: "Protect and register named private keys with the SSH signer"),
                CLIOption(flags: "--aws", summary: "Migrate AWS static profiles and configure credential_process"),
                CLIOption(flags: "--gh", summary: "Move gh's token into csec and route gh through csecd's GitHub socket"),
                CLIOption(flags: "--fly", summary: "Move fly's token out of its config into csec, for csec fly"),
                CLIOption(flags: "--aws-config <path>", summary: "AWS config file to update after import"),
                CLIOption(flags: "--whole-file", summary: "Use encrypted whole-file protection instead of type detection"),
                CLIOption(flags: "--keep-plaintext", summary: "Leave the original plaintext in place after import"),
                CLIOption(flags: "--dry-run", summary: "Report the plan without changing anything"),
            ],
            category: .filesAndSSH
        ),
        CLICommand(
            name: "edit",
            summary: "Edit a csec:// store as JSON, set one secret, or delete stored files",
            synopsis: [
                "csec edit [--editor] <store>",
                "csec edit <reference>",
                "csec edit --remove <csec://STORE/KEY>…",
            ],
            discussion: """
            Edit a csec:// store as strict JSON. The default built-in editor is fileless; \
            --editor uses $EDITOR with a temporary plaintext file.

            With a full reference (csec://STORE/KEY or op://VAULT/ITEM/FIELD) it sets that \
            one secret instead: on a terminal the value is typed into a hidden prompt \
            (entered twice, never echoed); otherwise it is read from stdin (one trailing \
            newline stripped). A missing csec:// key is created; the value never appears \
            in argv or output.

            --remove deletes whole-file values (what csec protect stored) from one native \
            store, up to six at a time, after one Touch ID whose panel names each of them; \
            their grants and auto-mode pairings go with them, and the store's backup is \
            rewritten without them. csecd refuses a value its SSH agent, GitHub socket or an \
            automation job uses (csec ssh remove, csec github remove or csec automation \
            revoke first), and one whose .csec sidecar is still where the file was \
            protected from. A sidecar or env-file reference elsewhere stops resolving. \
            Remove a document value with csec edit <store>.
            """,
            options: [
                CLIOption(flags: "--editor", summary: "Use $EDITOR with a temporary plaintext file instead of the built-in editor"),
                CLIOption(flags: "--remove", summary: "Delete the named whole-file values after one Touch ID"),
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

        CLICommand(
            name: "github",
            summary: "Manage the GitHub token csecd adds to gh's requests",
            synopsis: [
                "csec github socket | status",
                "csec github register <reference|sidecar.csec>",
                "csec github remove",
            ],
            discussion: """
            csecd's GitHub socket lets gh use your token without ever holding it. gh's \
            http_unix_socket setting sends its requests there with a placeholder token; \
            csecd puts the real token on requests to github.com and its subdomains for a \
            process you approved, the same review and grants as any secret, and forwards \
            them over TLS. `csec protect --gh` sets everything up. register accepts \
            csec://, op:// or other provider references, or a .csec sidecar; remove \
            forgets the registration and leaves the value in its store.
            """,
            subactions: [
                CLISubaction(name: "socket", summary: "Print the GitHub socket path"),
                CLISubaction(name: "status", summary: "Show the registered token reference and gh's configuration"),
                CLISubaction(name: "register", summary: "Use the token a reference names"),
                CLISubaction(name: "remove", summary: "Forget the registered token reference"),
            ],
            category: .filesAndSSH
        ),

        CLICommand(
            name: "identity",
            summary: "Sign in to AWS, Google Cloud and others as this Mac, with no stored keys",
            synopsis: [
                "csec identity status",
                "csec identity create [<identity>] --issuer <https-url> [--subject <subject>]",
                "csec identity remove <identity>",
                "csec identity target add <identity>/<target> --aws-role <role-arn> [--region <region>]",
                "                         [--audience <audience>] [--lifetime <seconds>]",
                "csec identity target add <identity>/<target> --audience <audience> [--lifetime <seconds>]",
                "csec identity target remove <identity>/<target>",
                "csec identity publish [<identity>] [--dir <path>]",
                "                      [--s3-bucket <bucket> --region <region> --admin <arn>]",
                "csec identity check [<identity>]",
                "csec identity accept-key <identity> <thumbprint>…",
                "csec identity setup aws <identity>/<target> [--profile <name>] [--dir <path>]",
                "csec identity setup google <identity>/<target> [--service-account <email>]",
                "                           [--file <path>] [--dir <path>]",
            ],
            discussion: """
            Makes this Mac its own OpenID Connect issuer. A key in the Secure Enclave, held \
            by csecd, signs short-lived tokens that a cloud's workload identity federation \
            trusts, so no access key is stored and no SSO sign-in expires. Each sign-in is a \
            csec-identity://<identity>/<target> reference, reviewed and granted like any \
            secret: an AWS target gives csec creds aws that role's temporary credentials \
            (csecd exchanges the token with STS itself); any other target gives the token, for \
            csec creds google, csec exec --env or csec get. create, target add, accept-key and \
            remove each take one Touch ID. publish writes the issuer's two public files, and \
            with --s3-bucket the commands for a bucket only one administrator can change; \
            whoever can change the published key set can sign in as the identity, and csecd \
            checks it daily. setup writes the AWS profile or Google credential file, installs \
            Google's shell wrapper with a separate reviewed access-token target, and prints \
            the cloud-side commands to run with your own administrator credentials.
            """,
            options: [
                CLIOption(flags: "--issuer <https-url>", summary: "Where the issuer's files are served (any HTTPS host)"),
                CLIOption(flags: "--subject <subject>", summary: "Who the tokens say signs in (default: this Mac's name)"),
                CLIOption(flags: "--aws-role <role-arn>", summary: "Sign in to this IAM role through AWS STS"),
                CLIOption(flags: "--audience <audience>", summary: "The token's audience (Google: the provider resource name)"),
                CLIOption(flags: "--lifetime <seconds>", summary: "How long a token or AWS session lasts (at most 3600)"),
                CLIOption(flags: "--dir <path>", summary: "Where to write public files (default: the current directory)"),
            ],
            subactions: [
                CLISubaction(name: "status", summary: "List identities, their keys and sign-ins"),
                CLISubaction(name: "create", summary: "Make a Secure Enclave identity key"),
                CLISubaction(name: "remove", summary: "Destroy an identity and its key"),
                CLISubaction(name: "target", summary: "Add or remove a sign-in"),
                CLISubaction(name: "publish", summary: "Write the issuer files, optionally with S3 bucket commands"),
                CLISubaction(name: "check", summary: "Compare the published key set with this Mac's keys"),
                CLISubaction(name: "accept-key", summary: "Accept another key in the published key set"),
                CLISubaction(name: "setup", summary: "Configure AWS or Google Cloud tools and print the cloud steps"),
            ],
            category: .secrets
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
            synopsis: [
                "csec setup [--project <directory>]",
                "csec setup auto-mode [--project <directory>]",
                "csec setup shell-prefix [--remove]",
                "csec setup --protect-files [--scan-root <directory>] [--dry-run | --apply]",
            ],
            discussion: """
            A guided, interactive flow: assess the resident agent, Full Disk Access, and \
            supported coding agents, then for each actionable item explain what it does, \
            ask, and either apply it or walk you through it. For Claude Code it can also \
            turn on delegated approvals, which let auto mode's classifier approve secrets \
            you already approved for a project (one Touch ID), and turns them off again. \
            Finishes with the bounded security-audit prompt and an optional host audit. \
            Requires an interactive terminal; it changes nothing without a per-step \
            confirmation. `csec setup auto-mode` runs only the Claude Code auto-mode \
            approvals step: turn delegated approvals on or off, acknowledge new hooks and \
            auto-mode classifier rules, and trust new Claude Code builds. `csec ai` names \
            it when delegated approvals are waiting on it. `csec setup shell-prefix` sets \
            Claude Code's CLAUDE_CODE_SHELL_PREFIX to csec's own prefix script, so its Bash \
            and Monitor commands run under `csec ai` after auto mode has reviewed them and \
            the hook no longer rewrites them; it refuses to replace another prefix, and \
            `--remove` takes csec's away again (`csec uninstall` does that first).
            """,
            options: [
                CLIOption(flags: "--project <directory>", summary: "Target project directory (default: current directory)"),
                CLIOption(flags: "--protect-files", summary: "Scan for secret files and select protection in bulk"),
                CLIOption(flags: "--scan-root <directory>", summary: "Scan this root (repeatable; default: home)"),
                CLIOption(flags: "--dry-run", summary: "Print the value-free protection table without changing files"),
                CLIOption(flags: "--include-excluded", summary: "Include app internals, installed tools, fixture keys and env templates"),
                CLIOption(flags: "--glob <pattern=approach[:destination]>", summary: "Override protection or skip matching files (repeatable)"),
                CLIOption(flags: "--apply", summary: "Apply the bulk plan without the interactive picker"),
                CLIOption(flags: "--keep-plaintext", summary: "Retain originals after import"),
                CLIOption(flags: "--remove", summary: "With shell-prefix: take csec's shell prefix out of Claude Code's settings"),
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
            synopsis: [
                "csec hook-config claude|codex",
                "csec hook-config codex --system [--launcher <csec path>]",
                "csec hook-config codex --system --remove",
            ],
            discussion: "Print the value-free hook JSON fragment for the selected client, using this exact csec executable path. With --system, print the complete managed Codex document for /etc/codex/hooks.json: csec's handler merged into the installed file, every other hook kept. csec setup offers to install it. Codex runs managed hooks without per-hook trust. With --system --remove, print that file with csec's handler taken out and every other hook kept, or nothing when no file should remain; csec uninstall --all writes it.",
            subactions: [
                CLISubaction(name: "claude", summary: "Print the Claude Code hook fragment"),
                CLISubaction(name: "codex", summary: "Print the Codex hook fragment (--system: the managed /etc/codex document)"),
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
                CLIOption(flags: "--max-runtime <seconds>", summary: "Maximum runtime before the run is terminated, or `none` for a process-lifetime daemon (auth once, no runtime kill)"),
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
            references it covers (or, for an SSH grant, the key, server and \
            user it signs for), when it expires, and whether it is reusable by \
            other commands in that tree. A grant ends when its root process \
            exits. It survives a csecd restart (not a reboot) in an item only \
            csecd can read, and after a restart one Touch ID reopens what it \
            needs. Grants are never shown with a secret value. The scope of each \
            grant is the one picked in its Touch ID review window. Each entry has \
            a typed id: grant- (a secret grant), ssh- (an SSH grant) and, while \
            delegated approvals are on, pair- (a project's pairing), build- (a \
            trusted Claude Code build) and hook- (an acknowledged hook).
            """,
            category: .secrets
        ),
        CLICommand(
            name: "revoke",
            summary: "Drop a live grant before it expires",
            synopsis: ["csec revoke <id>", "csec revoke --all"],
            discussion: """
            Drop one entry of `csec grants` by its typed id or a prefix of it \
            (grant-, ssh-, pair-, build- or hook-; a bare id names a secret \
            grant). A prefix matches only entries of its own kind, and one that \
            matches more than one removes nothing and lists them. Revoking a \
            build- or hook- id stops trusting that build or forgets that hook, as \
            csec setup would. --all drops every secret grant, SSH grant and \
            project pairing. The next access prompts again. The revocation is \
            persisted before csec returns, so a csecd restart cannot bring it \
            back. Revocation only removes access, so it needs no Touch ID.
            """,
            options: [
                CLIOption(flags: "--all", summary: "Revoke every secret grant, SSH grant and project pairing"),
            ],
            category: .secrets
        ),
        CLICommand(
            name: "refresh",
            summary: "Read references fresh from their provider at the next release",
            synopsis: ["csec refresh <reference>..."],
            discussion: """
            Drop csecd's cached copy of each reference, so the next release \
            reads it from its provider: use it after changing a value outside \
            csec, such as a field edited in the 1Password app, when csecd cannot \
            see the change itself (it re-reads 1Password values over a session \
            it already holds open, and when you approve a release at the Mac). \
            No value is read or shown, so it needs no Touch ID; it grants \
            nothing, and the next release is reviewed as it would be anyway. \
            Reading the value again may raise the provider's own sign-in once.
            """,
            category: .secrets
        ),
        CLICommand(
            name: "log",
            summary: "Show csecd's decision log, or verify it",
            synopsis: ["csec log [--since <time>] [--kind <kind>] [--json]", "csec log --verify"],
            discussion: """
            Show what csecd decided and why: every review panel with its outcome, \
            who decided and how long the panel was up; requests refused by an \
            earlier Deny; revocations; settings changes; restarts; and integrity \
            findings. Grant reuses are in a separate stream: ask for them with \
            --kind reuse. The log is sealed under a key only csecd holds, so the \
            files on disk are ciphertext, and any edit, deletion, truncation or \
            rollback of them is detected, recorded as log_integrity and notified. \
            Records are value-free: references, the panel's redacted command \
            line, scopes and outcomes, never a secret. Reading needs no Touch ID. \
            --verify checks the whole log now and exits non-zero on a finding.
            """,
            options: [
                CLIOption(flags: "--since <time>", summary: "Only records at or after an ISO 8601 time or date, or an age such as 30m, 12h or 7d"),
                CLIOption(flags: "--kind <kind>", summary: "Only records of this kind (repeatable, or comma-separated): panel, refusal, reuse, revoke, settings, restart, log_integrity, …"),
                CLIOption(flags: "--json", summary: "One JSON record per line"),
                CLIOption(flags: "--verify", summary: "Verify the log's chain and checkpoint; exit non-zero on a finding"),
            ],
            category: .secrets
        ),

        // MARK: - Service & status

        CLICommand(
            name: "restore",
            summary: "Reopen existing approvals after csecd restarts",
            synopsis: ["csec restore"],
            discussion: """
            Raise or join the one restore review for csecd's eligible saved approvals \
            and paired projects. Touch ID or the paired iPhone reopens the listed \
            batch; Forget these approvals keeps your choice and completes the step. \
            Nothing new is approved and no secret values are returned. There is no \
            prompt if nothing needs reopening or restoration already completed. The \
            installer runs this after restarting csecd, while you are at the Mac. \
            Cancellation or an incomplete restore fails without an automatic retry.
            """,
            category: .admin
        ),
        CLICommand(
            name: "install",
            summary: "Register csecd as a login-item LaunchAgent",
            synopsis: ["csec install"],
            discussion: "Register csecd as a login-item LaunchAgent so it runs in the background at login.",
            category: .admin
        ),
        CLICommand(
            name: "uninstall",
            summary: "Remove csec for this account, or with --all from this Mac, keeping your secrets",
            synopsis: ["csec uninstall [--all]"],
            discussion: """
            First put back the Claude Code settings csec setup changed for \
            delegated approvals. Then ask csecd, under one Touch ID, to delete \
            everything only it can delete: its protected Keychain items \
            (grants, project pairings and delegation settings), the decision \
            log and the sealed host-audit baseline. From that moment csecd \
            writes nothing more. Then unregister the csecd LaunchAgent. Cached \
            secret values, native stores, the SSH key and automation catalogs \
            and the iPhone pairing are left in place, and a reinstall uses them \
            again. If Touch ID is refused, nothing is uninstalled: csec writes \
            back the Claude Code settings it had reverted (or says which to \
            restore by hand if it cannot). If csecd cannot be reached, the \
            LaunchAgent is unregistered anyway and its protected Keychain \
            items, encrypted log and sealed baseline remain; a reinstall reuses \
            them.

            With --all, csec also takes its hook out of Claude Code's and \
            Codex's user settings, then runs the package's uninstaller \
            through sudo, which removes everything the package and setup \
            installed for every account on this Mac: the sudo review (its PAM \
            line goes first, and only a harmless sudo that still works through \
            Apple's Touch ID or your password lets the module and helper be \
            deleted), the managed Codex hook in /etc/codex/hooks.json, the \
            root helper and its LaunchDaemon, the app, the language bridge \
            and the package receipt. It ends by listing what stayed.
            """,
            options: [
                CLIOption(flags: "--all", summary: "Also remove the app, root helper, sudo review, Codex hook and package receipt (asks for sudo)"),
            ],
            category: .admin
        ),
        CLICommand(
            name: "status",
            summary: "Show app, agent, provider, SSH, remote-approval, root-helper, and sudo-review status",
            synopsis: ["csec status [--claude-builds-json]"],
            discussion: """
            Show app, LaunchAgent, authenticated agent/provider, SSH, shell, \
            remote-approval, root-helper, and sudo-review status together, with an \
            overall verdict. The sudo-review row reports whether the helper the csec \
            sudo PAM line hands off to is installed, hardened, and current; it reads \
            "not installed" when that PAM line is not active. \
            --claude-builds-json prints only csecd's value-free Claude Code release \
            inventory for automated verification checks; unavailable inventory fails.
            """,
            category: .admin
        ),
        CLICommand(
            name: "doctor",
            summary: "Diagnose and repair the installed agent, sockets, and service health",
            synopsis: ["csec doctor [--check] [--runtime]", "csec doctor --report"],
            discussion: """
            Diagnose and repair the installed app's per-user agent, stale sockets, and \
            service health. It also checks the sudo review helper whenever the csec \
            sudo PAM line is active: a missing or stale helper (one the installed PAM \
            module does not hand off to) is reported as unhealthy. Run csec setup \
            and accept the sudo review step to repair it. \
            --check performs no repairs. --runtime limits the check to the app and \
            live services, excluding sudo; the installer uses it before installing \
            the sudo integration, then requires a complete check afterward. Its \
            Updates row says whether a newer csec release is available, from the \
            last signed release manifest csecd fetched; an update never makes the \
            installation unhealthy.
            """,
            options: [
                CLIOption(flags: "--check", summary: "Diagnose only; perform no repairs"),
                CLIOption(flags: "--runtime", summary: "Check app and live services only; exclude sudo integration"),
                CLIOption(flags: "--report", summary: "Write a private support report in the current directory for you to review"),
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
            synopsis: ["csec remote status [--json] | enable <phone-pairing-code> | disable"],
            discussion: """
            Explicitly opt one iPhone into mirrored approvals. `enable` pins the phone's \
            public pairing code under local Touch ID, then prints the Mac public pairing \
            code to import in the phone app. Once both sides are paired, the local and \
            phone prompts race; the first authenticated decision wins. `disable` removes \
            the pin under local Touch ID. Pairing codes contain no credential values. \
            `status --json` prints csecd's readiness as one value-free JSON object, \
            including whether the phone shows Claude Code hook acknowledgements.
            """,
            options: [
                CLIOption(flags: "--json", summary: "With status: one JSON object naming no phone, key or device"),
            ],
            subactions: [
                CLISubaction(name: "status", summary: "Show remote approval configuration"),
                CLISubaction(name: "enable", summary: "Pair an iPhone by its public pairing code"),
                CLISubaction(name: "disable", summary: "Remove the paired iPhone under Touch ID"),
            ],
            category: .admin
        ),
        CLICommand(
            name: "backup",
            summary: "Keep sealed backups of the native stores off this Mac",
            synopsis: [
                "csec backup status | sync | off",
                "csec backup setup [--folder <path>]",
                "csec backup restore [--folder <path>]",
            ],
            discussion: """
            Native-store keys are bound to this Mac and its Touch ID, so a secret kept \
            only in a csec:// store is lost with the Mac. `setup` shows a recovery key once, \
            in csec's own window, for you to keep in 1Password or on paper, then seals every \
            native store and the SSH key catalog to it in iCloud Drive (or `--folder`). From \
            then on every store change refreshes its sealed bundle with no extra prompt. \
            `restore` on another Mac takes the recovery key in a window, lists what the \
            backup holds, and puts back the stores that Mac lacks. `setup`, `sync`, \
            `restore` and `off` each take one Touch ID. The terminal never shows the key or \
            a value.
            """,
            options: [
                CLIOption(flags: "--folder <path>", summary: "Keep or find backups in this folder instead of iCloud Drive"),
            ],
            subactions: [
                CLISubaction(name: "status", summary: "Show which stores are backed up"),
                CLISubaction(name: "setup", summary: "Make a recovery key and back up every native store"),
                CLISubaction(name: "sync", summary: "Bring every store's backup up to date"),
                CLISubaction(name: "restore", summary: "Put stores back from a backup with the recovery key"),
                CLISubaction(name: "off", summary: "Stop writing backups"),
            ],
            category: .admin
        ),
    ]
}
