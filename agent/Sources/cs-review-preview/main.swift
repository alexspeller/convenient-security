#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
import AppKit
import ConvenientSecurity
import CSECRemoteApproval
import Foundation

// Dev-only screenshot harness for the trusted access-review window. It builds
// synthetic, value-free AccessPolicyReview fixtures, presents the real window,
// captures its content view to a PNG, and exits. Touch ID may engage briefly
// while the window is up; the process exits without ever approving anything.
// A presented panel carries the red TEST banner so it cannot pass for a real
// request (ReviewTestBanner); an offscreen one (CSEC_PREVIEW_OFFSCREEN=1) is
// drawn exactly as a request draws it.
//
// Usage: cs-review-preview <scenario> <output.png> [light|dark]
//        cs-review-preview <scenario> [light|dark]   (a run that writes no PNG)
//   A run that reports on the live panel instead of capturing it (every
//   probe below, CSEC_PREVIEW_HOLD, and CSEC_PREVIEW_UNLOCK_RECHECK outside
//   the requester-gone scenarios) takes no output path, and refuses one.
//   scenarios: basic | bridge | ssh | ssh-agent | ssh-command | ssh-unknown | ssh-shared
//              ssh-ambiguous | warning | unknown | file | mixed | automation | setup
//              account | ambiguous-account | scope | sidecar-scope | exec-many
//              exec-long | requester-gone | ssh-requester-gone | requester-orphaned |
//              ssh-requester-orphaned | restore | restore-mixed | restore-long
//              github | github-lasting | settings | rules-changed | hooks-changed
//   github: gh's request through csecd's GitHub socket under Claude Code: the
//     token is used inside csec (daemon proxy), so the footnote says it stays
//     there, and the command is gh's own argv as csecd reads it.
//   github-lasting: `gh ssh-key add` through the same socket, a request that
//     can give lasting access (csec-0.49): its warning names the request and
//     what it can add, and it covers that one request, with no wider scope
//     or lifetime.
//   ssh-ambiguous: an SSH key held in 1Password whose vault name more than one
//     signed-in account has, so the panel carries the provider's warning.
//   setup: a native-store edit, setup at this Mac's terminal (`macOnly`):
//     like SSH key registration it offers no scope or lifetime choice.
//   settings: `csec setup auto-mode` turning on Claude Code auto-mode
//     approvals and acknowledging a hook and changed classifier rules, as
//     csecd's settings layout shows it (`SettingsChangeReviewDetails`):
//     Mac-only, releasing nothing. CSEC_PREVIEW_TYPING_PROBE=1 on it is the
//     on-device check that a Space typed as it appears no longer denies it.
//   rules-changed: the panel csecd raises itself when a Claude Code request
//     declined only because the auto-mode classifier rules changed
//     (csec-0.64): the settings layout with the added rules, a lost
//     "$defaults" and the removed count, from the Claude Code tab.
//   hooks-changed: the same panel for a hook added since the last
//     acknowledgement (csec-0.64.7): the hook and what it runs.
//   Release fixtures that spell out no scope choice get production's
//   single-root shape (the requesting command only), as a request with no
//   coding agent or terminal session above it is offered.
//   bridge: a language client's request over `csec bridge`, whose reason its
//     program wrote, with that program's command line (as csecd reads it from
//     the kernel) under the reason.
//   restore: the restore-only panel a restarted csecd raises to reopen the
//     stores behind grants it restored and the projects live Claude Code
//     sessions are paired with (secret, SSH and paired-project rows, no scope
//     or duration control, "Forget these approvals" as the fail-safe button).
//   restore-mixed: an ordinary release panel that also carries that restore
//     section, as when a request asks for new references while covered ones
//     are still sealed after the restart.
//   exec-long / restore-long: exec-many with 80 keys across 40 stores, and the
//     restore-only panel with its rows ten times over: lists longer than any
//     screen, which scroll in what the screen leaves with their scroller
//     drawn and a cue under them (`ReviewFittedList`, csec-lz39).
//   requester-gone / ssh-requester-gone: the requester is a real short-lived
//     process that exits while its panel is up. The harness stands in for
//     csecd's peer-exit watch (it cancels the review when the requester is
//     gone), captures the PNG while the panel is still up, then checks the
//     panel closed as `.denied(.requesterGone)` and prints one line.
//     CSEC_PREVIEW_UNLOCK_RECHECK=1 drops that stand-in and gives the
//     requester ten seconds: lock the Mac while the panel is up, wait for the
//     requester to exit, and unlock — the unlock re-present must close the
//     panel as `.denied(.requesterGone)` instead of asking for Touch ID.
//   Every other scenario's requester is this preview process itself, a real
//   live process, so a panel held behind the lock screen behaves as in
//   production. CSEC_PREVIEW_UNLOCK_RECHECK=1 with one of them writes no PNG:
//   lock the Mac while the panel is up, unlock, and the harness checks the
//   panel stayed up and asked for Touch ID again (the live-requester branch),
//   whether macOS cancelled Touch ID at the lock or only paused it, printing
//   `PASS` and which (PromptUnlockRecheckProbe; `csec-sudo-review
//   --unlock-probe` is the sudo panel's equivalent). Do not touch the sensor;
//   nothing is approved.
//   CSEC_PREVIEW_EXPAND=1 opens progressive-disclosure details before capture,
//     on a presented panel or an offscreen one.
//   CSEC_PREVIEW_OFFSCREEN=1 builds the real window without presenting it
//     (`ApprovalPanelInspection`: never onscreen, no Touch ID) and captures it,
//     so a layout check puts nothing in front of the developer; the Touch ID
//     view is drawn only on a presented panel, and the probes need one.
//   CSEC_PREVIEW_DELEGATION=<code> adds the delegated-approval decline note a
//     Claude Code request gets ("Auto mode didn't approve this: …") to any
//     secret-access or SSH scenario; <code> is a `DelegationDecline.code`
//     such as not_registered, not_auto_mode, not_approved_for_project,
//     not_held, command_mismatch or environment_steering.
//     Restore-only and automation panels refuse it:
//     they never carry the note.
//   CSEC_PREVIEW_PAIRING=1 adds the pairing line ("Approving also lets Claude
//     Code auto mode use these in … until you revoke them"; github's says
//     "in every project") for a secret-access scenario whose default scope is
//     Claude Code (scope). An SSH panel never
//     offers one (csec-0.11), so ssh-agent refuses it. It shows only while
//     that default and the process lifetime are selected: capture it again
//     with CSEC_PREVIEW_SCOPE or CSEC_PREVIEW_DURATION to see it hide. With
//     a CSEC_PREVIEW_DELEGATION code pairing can't end (launch_option, …) the
//     line says when the pairing counts ("… once Claude Code is started
//     without --settings"), as csecd writes it.
//   CSEC_PREVIEW_SCOPE=<GrantScopeKind raw value> selects an offered scope
//     (the access layout's radios, or the SSH layout's).
//   CSEC_PREVIEW_DURATION=<seconds> picks an offered grant lifetime the same way
//     a human would, so the window's live response to the choice is captured.
//   CSEC_PREVIEW_GRACE_PROBE=1 writes no PNG; instead it reports the panel's
//     key/active state and every control's enabled state shortly after the
//     window appears and again after the typing-guard grace period, so the
//     real panel's wiring of PromptInteractionGrace can be checked on-device
//     (PromptInteractionGraceProbe; `csec-sudo-review --grace-probe` is the
//     sudo panel's equivalent). CSEC_PREVIEW_SCOPE / CSEC_PREVIEW_DURATION
//     are applied before the first sample, and a panel with the pairing line
//     reports `pairingLine=shown|hidden` in both.
//   CSEC_PREVIEW_TYPING_PROBE=1 writes no PNG; keep typing (no Return) as the
//     panel appears, then stop: it reports the panel held while keys go down
//     and live only once none has for the keyboard quiet period, with a
//     PASS/FAIL/INCONCLUSIVE verdict (`csec-sudo-review --typing-probe` is
//     the sudo panel's equivalent).
//   CSEC_PREVIEW_FOCUS_PROBE=1 writes no PNG; it brings Finder to the front
//     while Touch ID is armed, makes the panel key again, and reports whether
//     the panel re-armed Touch ID on a fresh context behind a typing guard
//     that never takes the focus back (PromptFocusRecoveryProbe;
//     `csec-sudo-review --focus-probe` is the sudo panel's equivalent). On
//     requester-gone / ssh-requester-gone the requester exits while the panel
//     is away, and making it key again must close it as requesterGone.
//   CSEC_PREVIEW_HOLD=1 writes no PNG; it keeps the panel up for a real
//     decision and prints `hold: approved` or `hold: denied(<reason>)`.
//   CSEC_PREVIEW_DEADLINE=<seconds> gives the request a coding agent's wait
//     limit of that many seconds (`HumanWait`), so the panel shows the
//     deadline line (`ReviewDeadline`): quiet above 30 s, a countdown below.
//     Presented, the real withdrawal runs: with CSEC_PREVIEW_HOLD=1 and no
//     answer the panel counts down, closes at the deadline and prints
//     `hold: denied(timedOut)`.
//   CSEC_PREVIEW_NO_TOUCH_ID=1 draws the panel as a Mac that cannot take a
//     touch shows it (`ReviewTouchIDUnavailable`), presented or offscreen;
//     a number of seconds above 1 instead lets Touch ID come back that long
//     after the panel is built, as a lid opened while it is up, so with
//     CSEC_PREVIEW_HOLD=1 the panel re-arms Touch ID for a real touch.
//     CSEC_PREVIEW_PHONE=1 mirrors it to a phone leg that may still decide,
//     so the line says to approve on the iPhone; without it, no phone.
//   CSEC_PREVIEW_TOUCH_ID_PROBE=1 writes no PNG; with Touch ID held
//     unavailable for three seconds and a phone leg that gives up after one,
//     it samples the panel saying the phone can approve, then that nothing
//     can, then arming Touch ID once it is back, and prints PASS (or
//     INCONCLUSIVE when this Mac cannot take a touch at all). Touch ID is
//     armed for about a second at the end; do not touch the sensor.
//   CSEC_PREVIEW_TOUCH_ID_LOST_PROBE=1 writes no PNG; the panel arms Touch
//     ID, which goes away two seconds after the panel is built, ending the
//     armed evaluation as a lid closed with an external display would. With a
//     phone leg that may still decide, it samples the panel armed, then still
//     up saying the phone can approve, then, once the phone gives up, that
//     nothing can, and prints PASS (INCONCLUSIVE when this Mac cannot take a
//     touch at all). Touch ID is armed for the first two seconds; do not
//     touch the sensor.

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("cs-review-preview: \(message)\n".utf8))
    exit(64)
}

let scenarioNames = "basic|bridge|ssh|ssh-agent|ssh-command|ssh-unknown|ssh-shared|ssh-ambiguous|warning|unknown|file|mixed|automation|setup|account|ambiguous-account|scope|sidecar-scope|exec-many|exec-long|requester-gone|ssh-requester-gone|requester-orphaned|ssh-requester-orphaned|restore|restore-mixed|restore-long|github|github-lasting|settings|rules-changed|hooks-changed"
guard CommandLine.arguments.count >= 2 else {
    fail("usage: cs-review-preview <\(scenarioNames)> <output.png> [light|dark]")
}
let scenario = CommandLine.arguments[1]
let expectsOrphanedRequester = scenario == "requester-orphaned" || scenario == "ssh-requester-orphaned"
let expectsRequesterGone = scenario == "requester-gone" || scenario == "ssh-requester-gone" || expectsOrphanedRequester

/// The runs that report on the live panel instead of capturing it, so they
/// take no output path. A requester-gone scenario under
/// CSEC_PREVIEW_UNLOCK_RECHECK still captures one before its requester exits.
let reportingModes = [
    "CSEC_PREVIEW_GRACE_PROBE", "CSEC_PREVIEW_TYPING_PROBE", "CSEC_PREVIEW_FOCUS_PROBE",
    "CSEC_PREVIEW_TOUCH_ID_PROBE", "CSEC_PREVIEW_TOUCH_ID_LOST_PROBE", "CSEC_PREVIEW_HOLD",
].filter { ProcessInfo.processInfo.environment[$0] != nil }
    + (ProcessInfo.processInfo.environment["CSEC_PREVIEW_UNLOCK_RECHECK"] != nil && !expectsRequesterGone
        ? ["CSEC_PREVIEW_UNLOCK_RECHECK"] : [])
if !reportingModes.isEmpty, ProcessInfo.processInfo.environment["CSEC_PREVIEW_OFFSCREEN"] != nil {
    fail("CSEC_PREVIEW_OFFSCREEN only captures a PNG; it runs no \(reportingModes.joined(separator: " or "))")
}
let outputArguments = Array(CommandLine.arguments.dropFirst(2))
let outputPath: String?
let appearanceArgument: String?
if reportingModes.isEmpty {
    guard (1...2).contains(outputArguments.count) else {
        fail("usage: cs-review-preview <\(scenarioNames)> <output.png> [light|dark]")
    }
    outputPath = outputArguments[0]
    appearanceArgument = outputArguments.dropFirst().first
} else {
    guard outputArguments.count <= 1 else {
        fail("usage: \(reportingModes.joined(separator: "=1 "))=1 cs-review-preview <scenario> [light|dark]")
    }
    outputPath = nil
    appearanceArgument = outputArguments.first
}
if let appearanceArgument, appearanceArgument != "light", appearanceArgument != "dark" {
    fail(outputPath == nil
        ? "\(reportingModes.joined(separator: " and ")) writes no PNG, so it takes no output path, only [light|dark]"
        : "appearance must be light or dark")
}
let appearanceName: NSAppearance.Name? = appearanceArgument.map { $0 == "light" ? .aqua : .darkAqua }

func ref(_ uri: String) -> SecretRef {
    guard let parsed = try? SecretRef(uri) else { fail("bad fixture URI \(uri)") }
    return parsed
}

let slackReferences = [
    ref("op://Employee/Demo Slack User Token/password"),
    ref("op://Employee/Demo Slack User Token/web cookie"),
    ref("op://Employee/Demo Slack User Token/web token"),
]
let terminalTab = TerminalSessionContext(
    application: "iTerm2",
    title: "🧰 mailer",
    sessionName: "◑ deploy preview — ~/opensource/mailer",
    windowIndex: 1,
    tabIndex: 5,
    tty: "ttys012",
    sessionID: "w1t2p3:9EE8062D-0A54-4B65-A987-3261B57FF22E"
)
/// The requester the fixtures show: this process, so it is alive for as long as
/// the panel is up. The unlock re-present checks the requester's exact
/// incarnation, so a made-up pid would close every panel held behind the lock
/// screen instead of re-presenting it.
let liveRequesterPID = getpid()
guard let liveRequesterStart = ProcessAncestry.startTime(of: liveRequesterPID) else {
    fail("cannot read this process's start time")
}
let caller = CallerInfo(
    pid: liveRequesterPID,
    startTime: liveRequesterStart,
    description: "node [unverified] (pid 51758) via launcher [verified] (pid 51759)",
    terminal: terminalTab
)
let nodeExecutable = PlannedExecutable(
    canonicalPath: "/Users/dev/.local/share/mise/installs/node/22.14.0/bin/node",
    assurance: .unverified
)

/// What the providers say about a fixture reference: 1Password names
/// account › vault › item › field, the native store this Mac › store › key.
/// An `op://` reference names no account, so the account comes from the
/// provider's warm index, and with none the tree starts at the vault.
func described(
    _ reference: SecretRef, account: String? = nil, warnings: [String] = []
) -> ReviewSecret {
    let parts = reference.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    switch reference.scheme {
    case "op" where parts.count >= 3:
        return ReviewSecret(
            provider: "1Password", tint: .teal, account: account, container: parts[0],
            item: parts[1], field: parts[2...].joined(separator: "/"), warnings: warnings
        )
    case "csec" where parts.count == 2 && parts[1] == "*":
        // The edit-consent reference, as the native provider describes it.
        return ReviewSecret(
            provider: "csec", tint: .purple, account: "this Mac", container: parts[0],
            item: "all keys (edit access)", field: nil
        )
    case "csec" where parts.count == 2:
        return ReviewSecret(
            provider: "csec", tint: .purple, account: "this Mac", container: parts[0],
            item: parts[1], field: nil, itemIsIdentifier: true
        )
    default:
        return ReviewDisplay.undescribedSecret(reference)
    }
}

func credential(
    references: [SecretRef] = slackReferences,
    account: String? = nil,
    warnings: [String] = []
) -> PolicyReviewCredential {
    PolicyReviewCredential(described: references.map {
        ($0, described($0, account: account, warnings: warnings))
    })
}

/// The window is where the account an `op://` reference resolves from becomes
/// visible, and where an ambiguous vault name is called out before Touch ID
/// rather than after.
let fixtureAccount = "acme.1password.eu"
let ambiguityWarning = "More than one signed-in account has a vault named “Employee”"
    + " (also my.1password.com). This value will come from acme.1password.eu."
    + " To name one account exactly, use the vault's unique id in the reference."

let checksUnlockRecheck = ProcessInfo.processInfo.environment["CSEC_PREVIEW_UNLOCK_RECHECK"] != nil

/// A real requester for the requester-gone scenarios: it outlives the PNG
/// capture and the grace probe, then exits while the panel is still up.
func startShortLivedRequester() -> CallerInfo {
    let requester = Process()
    requester.executableURL = URL(fileURLWithPath: "/bin/sleep")
    requester.arguments = [checksUnlockRecheck ? "10" : "3"]
    do { try requester.run() } catch { fail("could not start the requester fixture") }
    let pid = requester.processIdentifier
    guard let startTime = ProcessAncestry.startTime(of: pid) else {
        fail("the requester fixture has no live incarnation")
    }
    return CallerInfo(
        pid: pid,
        startTime: startTime,
        description: "sleep [unverified] (pid \(pid)) via launcher [verified]",
        terminal: terminalTab
    )
}

/// Keep the requester alive after SIGKILL of its waiting shell, as happened
/// to the abandoned git push. The anchor must close the panel, not an exit of
/// the requester itself. All processes and references here are synthetic.
var orphanParent: Process?
func startOrphanedRequester() -> CallerInfo {
    let parent = Process(), output = Pipe()
    parent.executableURL = URL(fileURLWithPath: "/bin/sh")
    parent.arguments = ["-c", "/bin/sleep 30 & child=$!; echo \"$child\"; wait \"$child\""]
    parent.standardOutput = output
    parent.standardError = FileHandle.nullDevice
    do { try parent.run() } catch { fail("could not start the orphan requester fixture") }
    let text = String(decoding: output.fileHandleForReading.availableData, as: UTF8.self)
    guard let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)),
          let start = ProcessAncestry.startTime(of: pid) else {
        fail("the orphan requester fixture has no live incarnation")
    }
    orphanParent = parent
    return CallerInfo(pid: pid, startTime: start, description: "orphan fixture", terminal: terminalTab).anchored()
}

var review: AccessPolicyReview
switch scenario {
case "basic":
    review = AccessPolicyReview(
        caller: caller,
        reason: "yarn slack — read unread Slack messages",
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: nodeExecutable,
            root: .directParent(pid: 51759, startTime: 999_998),
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: 3600,
            operationContext: "yarn slack"
        ),
        credentials: [credential()]
    )
case "bridge":
    // A language client over `csec bridge`: the reason is the one its program
    // wrote, and under it the program's own command line as csecd reads it.
    review = AccessPolicyReview(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            description: "python3.12 [unverified] (pid 46452) via csec [verified]",
            terminal: terminalTab
        ),
        reason: "harbor: read the relay on nimbus as harbord (Approve presses)",
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: PlannedExecutable(
                canonicalPath: "/Users/dev/.local/share/uv/python/cpython-3.12.8-macos-aarch64-none/bin/python3.12",
                assurance: .unverified
            ),
            root: .directParent(pid: 46452, startTime: 999_998),
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: nil,
            operationContext: "harbor: read the relay on nimbus as harbord (Approve presses)"
        ),
        requesterCommandLine: ReviewDisplay.commandLine([
            "/Users/dev/opensource/harbor/.venv/bin/python3", "/Users/dev/opensource/harbor/.venv/bin/pytest", "-q",
        ]),
        credentials: [credential(references: [ref("csec://harbor/RELAY_TOKEN")])]
    )
case "ssh", "ssh-agent", "ssh-command", "ssh-unknown", "ssh-shared", "ssh-ambiguous":
    let hostNames: [String] = scenario == "ssh-unknown" ? []
        : scenario == "ssh-shared"
            ? ["production.example.com", "staging.example.com", "third.example.com"]
            : ["server.example.com"]
    let ssh = SSHAccessReviewDetails(
        hostNames: hostNames, remoteUser: "alex",
        keyLabel: "id_ecdsa", keyAlgorithm: "ecdsa-sha2-nistp256"
    )
    let command = GrantScopeOption(
        kind: .requestingCommand, pid: 25312, startTime: 999_999, processLabel: "ssh"
    )
    let agent = GrantScopeOption(
        kind: .codingAgent, pid: 25100, startTime: 999_998, processLabel: "Claude Code"
    )
    let terminal = GrantScopeOption(
        kind: .terminalSession, pid: 24849, startTime: 999_997, processLabel: "fish"
    )
    let options = scenario == "ssh-command" ? [command]
        : scenario == "ssh-agent" ? [command, agent, terminal] : [command, terminal]
    let defaultOption = scenario == "ssh-command" ? command
        : scenario == "ssh-agent" ? agent : terminal
    review = AccessPolicyReview(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            description: "Apple SSH [verified] (pid 25312)",
            terminal: terminalTab
        ),
        reason: ssh.reason,
        plan: DeliveryPlan(
            mechanism: .credentialProtocol,
            executable: PlannedExecutable(
                canonicalPath: "/usr/bin/ssh",
                signingIdentifier: "com.apple.ssh",
                assurance: .independentlyProtected
            ),
            root: .caller,
            descendantScope: .subtree,
            destination: .credentialConsumer,
            requestedTTLSeconds: 12 * 3600,
            operationContext: "SSH authentication"
        ),
        credentials: [scenario == "ssh-ambiguous"
            ? credential(
                references: [ref("op://Employee/GitHub SSH key/private key")],
                account: fixtureAccount, warnings: [ambiguityWarning]
            )
            : credential(references: [
                ref("csec://ssh-keys/_Users_alex_sensitive_.ssh_id_ecdsa_f80d5622fc38"),
            ])],
        scopeChoices: GrantScopeChoices(options: options, defaultOptionID: defaultOption.id),
        ssh: ssh
    )
case "warning":
    review = AccessPolicyReview(
        caller: caller,
        reason: "pipe a deploy token into an audit script",
        plan: DeliveryPlan(
            mechanism: .rawStandardOutput,
            executable: PlannedExecutable(canonicalPath: "/opt/csec/bin/csec", assurance: .verifiedProduct),
            root: .directParent(pid: 51759, startTime: 999_998),
            descendantScope: .exactProcess,
            destination: .shellDelegatedPipe,
            recipientAssurance: .unverifiedPipeReader,
            requestedTTLSeconds: 300,
            operationContext: "csec get"
        ),
        credentials: [credential()]
    )
case "unknown":
    review = AccessPolicyReview(
        caller: caller,
        reason: "claude code — deploy preview environment",
        plan: DeliveryPlan(
            mechanism: .execHook,
            executable: nodeExecutable,
            root: .caller,
            descendantScope: .exactProcess,
            destination: .aiTool,
            requestedTTLSeconds: 900,
            operationContext: "claude"
        ),
        credentials: [
            credential(),
            credential(references: [
                ref("op://Infrastructure/AWS Deploy Key/access key id"),
                ref("op://Infrastructure/AWS Deploy Key/secret access key"),
            ]),
        ]
    )
case "file":
    review = AccessPolicyReview(
        caller: caller,
        reason: "write kubeconfig for legacy tooling",
        plan: DeliveryPlan(
            mechanism: .namedPlaintextFile,
            executable: PlannedExecutable(canonicalPath: "/opt/csec/bin/csec", assurance: .verifiedProduct),
            root: .caller,
            descendantScope: .exactProcess,
            destination: .persistentPlaintextFile,
            recipientAssurance: .ordinaryPersistentFile,
            requestedTTLSeconds: 300,
            operationContext: "csec get"
        ),
        credentials: [credential()]
    )
case "mixed":
    review = AccessPolicyReview(
        caller: caller,
        reason: "boot rails with mixed providers",
        plan: DeliveryPlan(
            mechanism: .sealedEnvironment,
            executable: PlannedExecutable(canonicalPath: "/opt/homebrew/bin/ruby", assurance: .userWritable),
            root: .caller,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: 1800,
            operationContext: "rails boot"
        ),
        credentials: [
            credential(references: [
                ref("op://Employee/Demo Slack User Token/password"),
                ref("csec://acme-dev/DATABASE_URL"),
            ])
        ]
    )
case "automation":
    let reference = ref("csec://projects-mailer/OPENROUTER_API_KEY")
    let inlineScript = #"""
    const { access } = await import("convenient-security"); const ref = "csec://projects-mailer/OPENROUTER_API_KEY"; const values = await access([ref], { reason: "Verify unattended MAILER csec access without network use", ttl: 30 }); if (typeof values[ref] !== "string" || values[ref].length === 0) throw new Error("missing automation value"); process.stdout.write("mailer-csec-automation-ok\n");
    """#
    let commandLine = [
        nodeExecutable.canonicalPath,
        "--input-type=module",
        "-e",
        inlineScript,
    ]
    guard let commandDigest = try? ExecutableInspection.commandDigest(commandLine) else {
        fail("could not digest the automation fixture command")
    }
    let command = AutomationCommand(
        executable: nodeExecutable,
        commandLine: commandLine,
        workingDirectory: "/Users/dev/projects/mailer",
        commandDigest: commandDigest
    )
    let timestamp = Date(timeIntervalSince1970: 1_700_000_000)
    let job = AutomationJob(
        id: "00000000-0000-0000-0000-000000000001",
        revision: "00000000-0000-0000-0000-000000000002",
        name: "mailer-csec-smoke",
        reason: "Verify unattended MAILER csec access without network use",
        references: [reference.uri],
        command: command,
        minimumIntervalSeconds: 0,
        maximumRuntimeSeconds: 30,
        consumerTrust: .mutableInterpreted,
        createdAt: timestamp,
        updatedAt: timestamp
    )
    guard job.isWellFormed else { fail("automation fixture is not well formed") }
    review = AccessPolicyReview(
        caller: caller,
        reason: job.reason,
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: nodeExecutable,
            root: .caller,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: job.maximumRuntimeSeconds,
            operationContext: job.reason,
            commandDigest: command.commandDigest
        ),
        credentials: [credential(references: [reference])],
        automation: AutomationReviewDetails(job: job)
    )
case "setup":
    // `csec edit` of a native store, as csecd plans it: the editor is the
    // launcher itself, bound to its own process with no clock, and decided at
    // this Mac only.
    review = AccessPolicyReview(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            description: "csec [verified] (pid 51760)",
            terminal: terminalTab
        ),
        reason: "built-in native-store editor",
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: PlannedExecutable(
                canonicalPath: "/opt/csec/bin/csec",
                signingIdentifier: ProductCodeIdentity.launcherIdentifier,
                teamIdentifier: ProductCodeIdentity.teamIdentifier,
                assurance: .verifiedProduct
            ),
            root: .caller,
            descendantScope: .exactProcess,
            destination: .localDevelopment,
            requestedTTLSeconds: nil,
            operationContext: "built-in native-store editor"
        ),
        credentials: [credential(references: [ref("csec://acme-dev/*")])],
        macOnly: true
    )
case "settings":
    review = .settingsChange(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            description: "csec [verified] (pid 51760)",
            terminal: terminalTab
        ),
        change: SettingsChangeReviewDetails(
            title: "Turn On Claude Code Auto-Mode Approvals",
            changes: [
                "Let Claude Code auto mode approve csec secrets for its commands in projects you pair",
                "Acknowledge cc-caffeine@samber · PreToolUse *, which can approve Claude Code's shell commands",
                "Acknowledge ~/.claude/settings.json · 119 auto-mode classifier rules, which steer the auto-mode classifier",
            ]
        )
    )
case "rules-changed":
    let settingsPath = "/Users/dev/.claude/settings.json"
    let kept = ["Routine PR merges: merging an approved PR with its checks green is allowed",
                "csec exec, csec get and csec ai are csec's own tools"]
        .map { ClaudeClassifierRules.Rule(section: "allow", text: $0) }
    let added = [
        ClaudeClassifierRules.Rule(
            section: "allow",
            text: "WebApp QA magic links: opening a review app's magic-link URL for a QA account is allowed"),
        ClaudeClassifierRules.Rule(
            section: "environment",
            text: "Org-specific CLIs: dv, av and bd are this organisation's own command-line tools"),
    ]
    let defaults = ClaudeClassifierRules.Rule(section: "soft_deny", text: ClaudeClassifierRules.defaultsMarker)
    let now = kept + added
    review = .settingsChange(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            description: "csec [verified] (synthetic ai)",
            terminal: terminalTab
        ),
        change: ClaudeDelegationService.changedRulesReview(
            [ClaudeHookSource(
                kind: .classifierRules, sourceID: settingsPath, event: nil, matcher: nil,
                digest: String(repeating: "2", count: 64),
                display: "~/.claude/settings.json · \(now.count) auto-mode classifier rules", fetchesUnpinnedCode: false,
                ruleDigests: now.map(\.digest), rules: now, shownWhole: true)],
            acknowledged: [AcknowledgedClaudeHook(
                digest: String(repeating: "1", count: 64), display: "~/.claude/settings.json · 3 auto-mode classifier rules", acknowledgedAt: Date(timeIntervalSince1970: 1_793_000_000),
                classifierRules: AcknowledgedClassifierRules(
                    sourceID: settingsPath, ruleDigests: (kept + [defaults]).map(\.digest)))]
        )
    )
case "hooks-changed":
    // A hook added to the user's settings (a pr-cap hook):
    // csecd's one panel names it and what it runs (csec-0.64.7).
    review = .settingsChange(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            description: "csec [verified] (synthetic ai)",
            terminal: terminalTab
        ),
        change: ClaudeDelegationService.changedRulesReview(
            [ClaudeHookSource(
                kind: .settings, sourceID: "/Users/dev/.claude/settings.json", event: "PreToolUse", matcher: "Bash",
                digest: String(repeating: "3", count: 64), display: "~/.claude/settings.json · PreToolUse Bash",
                fetchesUnpinnedCode: false,
                handlerSummaries: ["python3 ~/.local/share/harbor/harbor-hook.py pr-cap claude"], shownWhole: true)],
            acknowledged: []
        )
    )
case "scope":
    // The measured coding-agent shape: a `csec exec` under a per-tool-call shell
    // under Claude Code under an interactive fish session.
    review = AccessPolicyReview(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            // Production omits a "(grant root pid …)" suffix when the scope
            // selector is shown; the selector states the root instead.
            description: "csec [verified] for rails [unverified]",
            terminal: terminalTab
        ),
        reason: "csec exec rails",
        plan: DeliveryPlan(
            mechanism: .unrestrictedInitialEnvironment,
            executable: PlannedExecutable(
                canonicalPath: "/Users/dev/project/bin/rails",
                assurance: .unverified
            ),
            root: .caller,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: 12 * 3600,
            operationContext: "csec exec rails",
            outputGuard: OutputGuardPlan(mode: .tty)
        ),
        // A long agent-authored one-liner: the window previews the first lines
        // and offers "Show full command" for the rest.
        commandLine: ReviewDisplay.commandLine([
            "bash", "-c",
            "echo \"len=${#T} prefix=${T:0:4}\"; curl -s -o /dev/null -D - "
                + "-H \"Authorization: Bearer $T\" https://api.github.com/user 2>/dev/null "
                + "| grep -iE '^HTTP|x-oauth-scopes'; bin/rails db:migrate && "
                + "bin/rails db:seed && yarn install --immutable && yarn build 2>&1 | tail -20",
        ]),
        credentials: [credential(references: [
            ref("op://Engineering/Postgres/url"),
            ref("op://Engineering/Postgres/password"),
        ])],
        scopeChoices: GrantScopeChoices(
            options: [
                GrantScopeOption(
                    kind: .requestingCommand, pid: 65060,
                    startTime: 999_999, processLabel: "rails"
                ),
                GrantScopeOption(
                    kind: .codingAgent, pid: 31163,
                    startTime: 999_997, processLabel: "Claude Code"
                ),
                GrantScopeOption(
                    kind: .terminalSession, pid: 2589,
                    startTime: 999_996, processLabel: "fish"
                ),
            ],
            defaultOptionID: GrantScopeOption(
                kind: .codingAgent, pid: 31163,
                startTime: 999_997, processLabel: "Claude Code"
            ).id
        )
    )
case "github":
    let gh = GrantScopeOption(kind: .requestingCommand, pid: 71204, startTime: 999_999, processLabel: "gh")
    let claude = GrantScopeOption(kind: .codingAgent, pid: 31163, startTime: 999_997, processLabel: "Claude Code")
    let fish = GrantScopeOption(kind: .terminalSession, pid: 2589, startTime: 999_996, processLabel: "fish")
    review = AccessPolicyReview(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            description: "gh [unverified] (pid 71204) for gh [user_writable]",
            terminal: terminalTab
        ),
        reason: Agent.githubProxyReason(firstRequest: "POST api.github.com/graphql"),
        plan: DeliveryPlan(
            mechanism: .daemonProxy,
            executable: PlannedExecutable(canonicalPath: "/opt/homebrew/Cellar/gh/2.101.0/bin/gh", assurance: .userWritable),
            root: .caller,
            descendantScope: .subtree,
            destination: .credentialConsumer,
            operationContext: Agent.githubProxyContext
        ),
        commandLine: ReviewDisplay.commandLine([
            "gh", "pr", "create", "--title", "Fix the flaky upload test", "--body-file", "pr.md",
        ]),
        credentials: [credential(references: [ref("csec://github/gh-token")])],
        scopeChoices: GrantScopeChoices(options: [gh, claude, fish], defaultOptionID: claude.id)
    )
case "github-lasting":
    let gh = GrantScopeOption(kind: .requestingCommand, pid: 71204, startTime: 999_999, processLabel: "gh")
    let lasting = GitHubLastingAccess(kind: .sshKey, request: "POST api.github.com/user/keys")
    review = AccessPolicyReview(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            description: "gh [unverified] (pid 71204) for gh [user_writable]",
            terminal: terminalTab
        ),
        reason: lasting.reason,
        plan: DeliveryPlan(
            mechanism: .daemonProxy,
            executable: PlannedExecutable(canonicalPath: "/opt/homebrew/Cellar/gh/2.101.0/bin/gh", assurance: .userWritable),
            root: .caller,
            descendantScope: .subtree,
            destination: .credentialConsumer,
            operationContext: Agent.githubLastingAccessContext
        ),
        commandLine: ReviewDisplay.commandLine(["gh", "ssh-key", "add", "/Users/me/.ssh/id_ed25519.pub"]),
        credentials: [credential(references: [ref("csec://github/gh-token")])],
        scopeChoices: GrantScopeChoices(options: [gh], defaultOptionID: gh.id),
        delegationNote: .lastingAccess(lasting.request),
        githubLastingAccess: lasting
    )
case "sidecar-scope":
    // `csec exec` in a project holding a `*.csec` sidecar: a capability-GID
    // launch, straight from an interactive fish session with no agent between.
    // This shape is offered the scope selector like any other.
    review = AccessPolicyReview(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            description: "launcher [verified] for bash [unverified]",
            // No terminal anywhere above the request: the line says so.
            terminal: .unidentified
        ),
        reason: "csec exec (1 protected file(s)) bash",
        plan: DeliveryPlan(
            mechanism: .capabilityGIDFile,
            executable: PlannedExecutable(canonicalPath: "/bin/bash", assurance: .unverified),
            root: .caller,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: 3600,
            operationContext: "csec exec (1 protected file(s)) bash",
            outputGuard: OutputGuardPlan(mode: .always)
        ),
        credentials: [credential(references: [
            ref("op://Employee/Demo Slack User Token/password"),
        ])],
        scopeChoices: GrantScopeChoices(
            options: [
                GrantScopeOption(
                    kind: .requestingCommand, pid: 72880,
                    startTime: 999_999, processLabel: "bash"
                ),
                GrantScopeOption(
                    kind: .terminalSession, pid: 2589,
                    startTime: 999_996, processLabel: "fish"
                ),
            ],
            defaultOptionID: GrantScopeOption(
                kind: .terminalSession, pid: 2589,
                startTime: 999_996, processLabel: "fish"
            ).id
        )
    )
case "exec-many", "exec-long":
    // A plain `csec exec ls` in a project whose .envrc names a whole native
    // store: many keys, a custom iTerm2 tab title, and a terminal-session
    // default scope. The shape the window is laid out for.
    let keys = [
        "BUGSNAG_TOKEN", "CHROBINSON_CLIENT_ID", "CHROBINSON_CLIENT_SECRET",
        "DEMO_AWS_SECRET_ACCESS_KEY", "DEMO_SECRET_KEY_BASE", "DEPLOY_ACCESS_KEY_ID",
        "DEPLOY_SECRET_ACCESS_KEY", "DEPOT_TOKEN", "DEVOPS_GITHUB_BOT_PAT",
        "GCLOUD_SECRET_KEY_BASE", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
        "GRAFANA_API_TOKEN", "OPENAI_API_KEY", "SENTRY_DSN", "SLACK_BOT_TOKEN",
        "STRIPE_SECRET_KEY", "TWILIO_AUTH_TOKEN", "VONAGE_API_SECRET",
    ]
    let plan = DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/bin/ls", assurance: .unverified),
        root: .caller,
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 3600,
        operationContext: "csec exec ls",
        outputGuard: OutputGuardPlan(mode: .tty)
    )
    review = AccessPolicyReview(
        caller: CallerInfo(
            pid: liveRequesterPID,
            startTime: liveRequesterStart,
            description: "launcher [verified] (pid 65541) for ls [unverified]",
            terminal: TerminalSessionContext(
                application: "iTerm2",
                title: "🌲 manifest-v3",
                sessionName: "csec exec ls ~/d/w/manifest-v3 (csec)",
                windowIndex: 1,
                tabIndex: 11,
                tty: "ttys027",
                sessionID: "w1t11p0:9EE8062D-0A54-4B65-A987-3261B57FF22E"
            )
        ),
        reason: "csec exec ls",
        plan: plan,
        commandLine: ReviewDisplay.commandLine(["ls", "-la", "node_modules/@acme"]),
        credentials: [credential(references: scenario == "exec-long"
            ? (1...40).flatMap { store in keys.prefix(2).map { ref("csec://project-\(store)/\($0)") } }
            : keys.map { ref("csec://work-WebApp/\($0)") })],
        scopeChoices: GrantScopeChoices(
            options: [
                GrantScopeOption(
                    kind: .requestingCommand, pid: 65541,
                    startTime: 999_999, processLabel: "ls"
                ),
                GrantScopeOption(
                    kind: .terminalSession, pid: 41248,
                    startTime: 999_996, processLabel: "fish"
                ),
            ],
            defaultOptionID: GrantScopeOption(
                kind: .terminalSession, pid: 41248,
                startTime: 999_996, processLabel: "fish"
            ).id
        ),
        durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: plan.requestedTTLSeconds)
    )
case "account":
    review = AccessPolicyReview(
        caller: caller,
        reason: "yarn slack — read unread Slack messages",
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: nodeExecutable,
            root: .directParent(pid: 51759, startTime: 999_998),
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: 3600,
            operationContext: "yarn slack"
        ),
        credentials: [credential(account: fixtureAccount)]
    )
case "ambiguous-account":
    review = AccessPolicyReview(
        caller: caller,
        reason: "yarn slack — read unread Slack messages",
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: nodeExecutable,
            root: .directParent(pid: 51759, startTime: 999_998),
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: 3600,
            operationContext: "yarn slack"
        ),
        credentials: [credential(account: fixtureAccount, warnings: [ambiguityWarning])]
    )
case "requester-gone", "requester-orphaned":
    review = AccessPolicyReview(
        caller: scenario == "requester-orphaned" ? startOrphanedRequester() : startShortLivedRequester(),
        reason: scenario == "requester-orphaned"
            ? "the requester's parent exits while this panel is up" : "the requester exits while this panel is up",
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: nodeExecutable,
            root: .caller,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: 3600,
            operationContext: "requester-gone preview"
        ),
        credentials: [credential()]
    )
case "ssh-requester-gone", "ssh-requester-orphaned":
    let requester = scenario == "ssh-requester-orphaned" ? startOrphanedRequester() : startShortLivedRequester()
    let ssh = SSHAccessReviewDetails(
        hostNames: ["server.example.com"], remoteUser: "alex",
        keyLabel: "id_ecdsa", keyAlgorithm: "ecdsa-sha2-nistp256"
    )
    let command = GrantScopeOption(
        kind: .requestingCommand, pid: requester.pid, startTime: requester.startTime,
        processLabel: "ssh"
    )
    let terminal = GrantScopeOption(
        kind: .terminalSession, pid: 24849, startTime: 999_997, processLabel: "fish"
    )
    review = AccessPolicyReview(
        caller: CallerInfo(
            pid: requester.pid, startTime: requester.startTime,
            description: "Apple SSH [verified] (pid \(requester.pid))", terminal: terminalTab,
            requestAnchor: requester.requestAnchor
        ),
        reason: ssh.reason,
        plan: DeliveryPlan(
            mechanism: .credentialProtocol,
            executable: PlannedExecutable(
                canonicalPath: "/usr/bin/ssh", signingIdentifier: "com.apple.ssh",
                assurance: .independentlyProtected
            ),
            root: .caller,
            descendantScope: .subtree,
            destination: .credentialConsumer,
            requestedTTLSeconds: nil,
            operationContext: "SSH authentication"
        ),
        credentials: [credential(references: [ref("csec://ssh-keys/requester-gone-preview")])],
        scopeChoices: GrantScopeChoices(options: [command, terminal], defaultOptionID: terminal.id),
        ssh: ssh
    )
case "restore", "restore-mixed", "restore-long":
    let fixture = RestoreReviewDetails(
        cause: .upgrade,
        rows: [
            RestoreReviewRow(
                kind: .secretGrant, title: "Claude Code",
                detail: "Claude Code and everything it runs · pid 25100",
                references: [
                    "csec://mailer/SLACK_TOKEN", "csec://mailer/OPENAI_API_KEY",
                    "op://Employee/Demo Slack User Token/password",
                ]
            ),
            RestoreReviewRow(
                kind: .secretGrant, title: "fish",
                detail: "This terminal session · pid 24849",
                references: ["csec://acme/DATABASE_URL"]
            ),
            RestoreReviewRow(
                kind: .sshGrant, title: "fish",
                detail: "This fish terminal session · pid 24849",
                references: ["csec://ssh-keys/_Users_alex_sensitive_.ssh_id_ecdsa_f80d5622fc38"],
                ssh: RestoreReviewRow.SSH(
                    hostTitle: "github.com", remoteUser: "git", keyLabel: "id_ecdsa"
                )
            ),
            // A project a live Claude Code session is paired with, as
            // `DelegationRestoreSource` lists it: what delegated approvals
            // there use, including the key of a paired SSH use.
            RestoreReviewRow(
                kind: .pairedProject, title: "mailer",
                detail: "Claude Code auto mode in /Users/dev/projects/mailer",
                references: [
                    "csec://mailer/ANTHROPIC_API_KEY",
                    "op://Employee/Mailer Gmail/credential",
                    "csec://ssh-keys/_Users_alex_sensitive_.ssh_id_ed25519_3a91c07d5e12",
                ]
            ),
        ],
        storeCount: 4
    )
    let restore = RestoreReviewDetails(
        cause: fixture.cause,
        rows: Array(repeating: fixture.rows, count: scenario == "restore-long" ? 10 : 1).joined().map { row in
            row.described(by: Dictionary(uniqueKeysWithValues: row.references.compactMap { uri in
                (try? SecretRef(uri)).map { (uri, described($0, account: fixtureAccount)) }
            }))
        },
        storeCount: fixture.storeCount
    )
    if scenario != "restore-mixed" {
        review = AccessPolicyReview.restoreOnly(caller: caller, restore: restore)
    } else {
        review = AccessPolicyReview(
            caller: caller,
            reason: "yarn slack — read unread Slack messages",
            plan: DeliveryPlan(
                mechanism: .directHeap,
                executable: nodeExecutable,
                root: .directParent(pid: 51759, startTime: 999_998),
                descendantScope: .subtree,
                destination: .localDevelopment,
                requestedTTLSeconds: 3600,
                operationContext: "yarn slack"
            ),
            credentials: [credential()],
            restore: restore
        )
    }
default:
    fail("unknown scenario \(scenario)")
}

// Production offers a scope and a lifetime choice on every release and SSH
// review (`GrantScopeInspector.choices` always offers at least the requesting
// command); fixtures that did not spell one out get the same defaults so the
// window is shown as built. Automation enrollment lasts until it is revoked, a
// restore-only panel approves nothing new, setup at this Mac (`macOnly`) is
// bound to its own process, and a settings change (one the phone may decide
// included) grants nothing, so all four are excluded, as is a panel that
// grants nothing past what it asks for (`ReviewDisplay.fixedLifetime`).
if review.automation == nil, !review.isRestoreOnly, !review.macOnly, review.settingsChange == nil,
   ReviewDisplay.fixedLifetime(for: review) == nil,
   review.scopeChoices == nil || review.durationChoices == nil {
    let rootPID: pid_t, rootStartTime: UInt64
    switch review.plan.root {
    case let .directParent(pid, startTime): (rootPID, rootStartTime) = (pid, startTime)
    default: (rootPID, rootStartTime) = (review.caller.pid, review.caller.startTime)
    }
    // Labelled as csecd labels the requesting command: its executable's name.
    let requesting = GrantScopeOption(
        kind: .requestingCommand, pid: rootPID, startTime: rootStartTime,
        processLabel: URL(
            fileURLWithPath: (review.plan.requestingExecutable ?? review.plan.executable).canonicalPath
        ).lastPathComponent
    )
    review = AccessPolicyReview(
        caller: review.caller, reason: review.reason, plan: review.plan,
        commandLine: review.commandLine,
        requesterCommandLine: review.requesterCommandLine,
        credentials: review.credentials,
        scopeChoices: review.scopeChoices
            ?? GrantScopeChoices(options: [requesting], defaultOptionID: requesting.id),
        durationChoices: review.durationChoices ?? GrantDurationChoices.offered(
            requestedTTLSeconds: review.plan.requestedTTLSeconds
        ),
        ssh: review.ssh,
        restore: review.restore
    )
}

/// One sample of each delegated-approval decline, by its code, with the
/// fixtures' own references and names.
let delegationSamples: [String: DelegationDecline] = Dictionary(uniqueKeysWithValues: [
    DelegationDecline.notRegistered,
    .notAutoMode("default"),
    .notInteractive,
    .launchOption("--print"),
    .injectedEnvironment("NODE_OPTIONS --require"),
    .environmentUnreadable,
    .homeMismatch,
    .configDirectoryUnusable,
    .unverifiedBuild("2.1.257"),
    .uncheckedBuild("new release"),
    .projectNotLocal,
    .projectUnavailable,
    .factsUnavailable,
    .settingsUnreadable("/Users/dev/.claude/settings.json"),
    .settingsEnvironment(name: "ANTHROPIC_BASE_URL", path: "/Users/dev/projects/mailer/.claude/settings.json"),
    .allowRulesActive,
    .otherHook("cc-caffeine@samber · PreToolUse *"),
    .classifierRules("~/.claude/settings.json · 119 auto-mode classifier rules"),
    .sandboxAutoAllow("/Users/dev/.claude/settings.json"),
    .bypassReachable("/Users/dev/.claude/settings.json"),
    .hooksDisabled(setting: "disableAllHooks", path: "/Users/dev/.claude/settings.json"),
    .gatewaySignIn,
    .gatewaySignInUnchecked,
    .notApprovedForProject(reference: "op://Employee/Demo Slack User Token/password", project: "mailer"),
    .notHeld(
        "op://Employee/Demo Slack User Token/password",
        reason: "the 1Password CLI is not authorized; unlock 1Password and try again"
    ),
    .commandMismatch(process: "sudo"),
    .environmentSteering(process: "the command's shell", name: "ZDOTDIR"),
    .sudoIndirect("node"),
    .sudoOption("-E"),
    .sudoNotApproved(project: "mailer"),
    .agentOwnCommand("gh issue list"),
    .lastingAccess("POST api.github.com/user/keys"),
].map { ($0.code, $0) })
let delegationCode = ProcessInfo.processInfo.environment["CSEC_PREVIEW_DELEGATION"]
let showsPairing = ProcessInfo.processInfo.environment["CSEC_PREVIEW_PAIRING"] != nil
if showsPairing, review.ssh != nil {
    fail("an SSH panel never offers a pairing line (csec-0.11): use CSEC_PREVIEW_PAIRING=1 on scope")
}
if delegationCode != nil || showsPairing {
    guard review.automation == nil, !review.isRestoreOnly, !review.macOnly, review.settingsChange == nil else {
        fail("restore-only, automation, setup and settings panels never carry the delegation note or pairing line")
    }
    var note: DelegationDecline?
    if let delegationCode {
        guard let sample = delegationSamples[delegationCode] else {
            fail("unknown delegation code \(delegationCode); one of \(delegationSamples.keys.sorted().joined(separator: ", "))")
        }
        note = sample
    }
    var offer: DelegationPairingOffer?
    if showsPairing {
        guard let choices = review.scopeChoices, choices.defaultOption.kind == .codingAgent else {
            fail("the pairing line needs a scenario whose default scope is Claude Code (scope)")
        }
        // A use csecd makes itself (the GitHub socket) pairs for every project.
        offer = DelegationPairingOffer(
            projectName: "mailer", scopeOptionID: choices.defaultOptionID,
            everyProject: review.plan.mechanism == .daemonProxy, condition: note?.pairingCondition
        )
    }
    review = AccessPolicyReview(
        caller: review.caller, reason: review.reason, plan: review.plan,
        commandLine: review.commandLine,
        requesterCommandLine: review.requesterCommandLine,
        credentials: review.credentials, scopeChoices: review.scopeChoices,
        // A `csec ai` request asks for no lifetime, so its panel defaults to
        // the process lifetime, the one selection that pairs.
        durationChoices: showsPairing ? GrantDurationChoices.offered(requestedTTLSeconds: nil) : review.durationChoices,
        ssh: review.ssh,
        restore: review.restore,
        delegationNote: note,
        pairingOffer: offer,
        githubLastingAccess: review.githubLastingAccess
    )
}

/// `CSEC_PREVIEW_TOUCH_ID_PROBE`, `CSEC_PREVIEW_NO_TOUCH_ID` and
/// `CSEC_PREVIEW_PHONE`: a Mac that cannot take a touch, and the phone leg
/// the panel is told about.
let checksTouchIDReturn = ProcessInfo.processInfo.environment["CSEC_PREVIEW_TOUCH_ID_PROBE"] != nil
let touchIDProbeReturnsAfter = Duration.seconds(3)
let checksTouchIDLost = ProcessInfo.processInfo.environment["CSEC_PREVIEW_TOUCH_ID_LOST_PROBE"] != nil
let touchIDProbeLostAfter = Duration.seconds(2)
if checksTouchIDReturn, checksTouchIDLost {
    fail("CSEC_PREVIEW_TOUCH_ID_PROBE and CSEC_PREVIEW_TOUCH_ID_LOST_PROBE are separate runs")
}
let previewTouchID: ReviewTouchIDOverride? =
    checksTouchIDReturn
    ? .returnsAfter(touchIDProbeReturnsAfter)
    : checksTouchIDLost
    ? .lostAfter(touchIDProbeLostAfter)
    : ProcessInfo.processInfo.environment["CSEC_PREVIEW_NO_TOUCH_ID"].map {
        guard let override = ReviewTouchIDOverride(previewValue: $0) else {
            fail("CSEC_PREVIEW_NO_TOUCH_ID must be 1 or a number of seconds above 1")
        }
        return override
    }
let previewPhone: ReviewPhoneStatus? =
    checksTouchIDReturn || checksTouchIDLost || ProcessInfo.processInfo.environment["CSEC_PREVIEW_PHONE"] != nil
    ? ReviewPhoneStatus() : nil
if previewPhone != nil, review.automation != nil || review.settingsChange != nil {
    fail("automation enrollment and settings changes are never mirrored to the phone")
}

/// The review the way csecd presents it, with the phone leg bound as
/// `MirroredPolicyReview` binds it.
@Sendable func presentPreviewReview() async -> AccessPolicyReviewOutcome {
    await ReviewPhoneStatus.$current.withValue(previewPhone) {
        await TrustedPolicyReview(touchID: previewTouchID).reviewAccess(review)
    }
}

/// `CSEC_PREVIEW_DEADLINE`: the wait limit a coding agent's request has.
let previewDeadline: Duration? = ProcessInfo.processInfo.environment["CSEC_PREVIEW_DEADLINE"].map {
    guard let seconds = Int($0), seconds > 0 else { fail("CSEC_PREVIEW_DEADLINE must be a number of seconds") }
    return .seconds(seconds)
}
if previewDeadline != nil, review.isRestoreOnly || review.automation != nil || review.settingsChange != nil {
    fail("restore, automation and settings panels have no deadline: a coding agent's wait never reaches them")
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
// Every presented scenario puts the real panel on screen, where it must not
// pass for a real request: it carries the red TEST banner (ReviewTestBanner).
// An offscreen capture is never on screen, so it shows the panel exactly as a
// request draws it, for layout checks and design pictures.
if ProcessInfo.processInfo.environment["CSEC_PREVIEW_OFFSCREEN"] == nil {
    MainActor.assumeIsolated { ReviewTestBanner.isShown = true }
}
if let appearanceName {
    app.appearance = NSAppearance(named: appearanceName)
}

/// Every collapsed section's disclosure, for CSEC_PREVIEW_EXPAND.
@MainActor func previewDisclosures(in view: NSView) -> [NSButton] {
    if let button = view as? NSButton,
        [
            "Show command and security details", "Show details",
            "Show delivery details", "Show full command",
        ].contains(button.title) {
        return [button]
    }
    return view.subviews.flatMap { previewDisclosures(in: $0) }
}

if ProcessInfo.processInfo.environment["CSEC_PREVIEW_OFFSCREEN"] != nil {
    // The real window, built the way presenting it builds it but never ordered
    // onscreen and with no Touch ID (`ApprovalPanelInspection`), captured
    // straight to the PNG: a layout check that puts nothing in front of the
    // developer. The Touch ID view is drawn only on a presented panel.
    MainActor.assumeIsolated {
        let inspection = ApprovalPanelInspection.access(
            review, deadline: previewDeadline.map { ReviewDeadline(remaining: $0) },
            phone: previewPhone, touchID: previewTouchID)
        let window = inspection.window
        window.alphaValue = 0
        window.setFrameOrigin(NSPoint(x: -20_000, y: -20_000))
        guard let content = window.contentView else { fail("the panel has no content") }
        if ProcessInfo.processInfo.environment["CSEC_PREVIEW_EXPAND"] != nil {
            let disclosures = previewDisclosures(in: content)
            guard !disclosures.isEmpty else { fail("details disclosure was not found") }
            for disclosure in disclosures { disclosure.performClick(nil) }
        }
        let target = content.superview ?? content
        target.layoutSubtreeIfNeeded()
        guard let bitmap = target.bitmapImageRepForCachingDisplay(in: target.bounds) else {
            fail("could not create bitmap")
        }
        target.cacheDisplay(in: target.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            fail("could not encode PNG")
        }
        guard let outputPath else { fail("this run writes no PNG") }
        do {
            try png.write(to: URL(fileURLWithPath: outputPath))
        } catch {
            fail("could not write \(outputPath): \(error)")
        }
        print("wrote \(outputPath) offscreen (\(Int(target.bounds.width))×\(Int(target.bounds.height)))")
        withExtendedLifetime(inspection) {}
    }
    exit(0)
}

let reviewTask = Task { @MainActor in
    if expectsOrphanedRequester {
        let wait = HumanWait(
            requester: .init(pid: review.caller.pid, startTime: review.caller.startTime),
            summary: "orphan preview", limit: nil, requestAnchor: review.caller.requestAnchor
        )
        return await wait.bounding { await presentPreviewReview() }
    }
    if let previewDeadline {
        // A coding agent's request: the same wait csecd binds, withdrawn at
        // its deadline exactly as there.
        let wait = HumanWait(
            requester: .init(pid: review.caller.pid, startTime: review.caller.startTime),
            summary: "deadline preview", limit: previewDeadline
        )
        let outcome = await wait.bounding { await presentPreviewReview() }
        guard case .denied = outcome, wait.isExpired else { return outcome }
        return .denied(wait.effectiveReason(.requesterGone))
    }
    return await presentPreviewReview()
}

/// The panel's content once it is on screen, within a second.
@MainActor @Sendable func panelContent() async -> NSView? {
    for _ in 0..<200 {
        if let panel = app.windows.first(where: { $0 is NSPanel && $0.isVisible }), let content = panel.contentView {
            return content
        }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return nil
}

/// Makes the `CSEC_PREVIEW_SCOPE` / `CSEC_PREVIEW_DURATION` choices through
/// the window's own action handlers, as a click or a menu pick sends them.
/// The actions go straight to their targets, so a choice lands while the
/// typing guard still holds the controls disabled, before a grace probe
/// samples the panel.
@MainActor @Sendable func applySelections(in content: NSView) async {
    if let kind = ProcessInfo.processInfo.environment["CSEC_PREVIEW_SCOPE"] {
        guard let option = review.scopeChoices?.options.first(where: { $0.kind.rawValue == kind })
        else { fail("requested scope is not offered") }
        let title = review.ssh != nil ? ReviewDisplay.sshScopeTitle(option) : ReviewDisplay.scopeTitle(option)
        @MainActor func findScope(in view: NSView) -> NSButton? {
            if let button = view as? NSButton, button.title == title { return button }
            for child in view.subviews {
                if let button = findScope(in: child) { return button }
            }
            return nil
        }
        guard let button = findScope(in: content), let action = button.action else {
            fail("scope selector was not found")
        }
        NSApp.sendAction(action, to: button.target, from: button)
        try? await Task.sleep(nanoseconds: 150_000_000)
    }
    if let requested = ProcessInfo.processInfo.environment["CSEC_PREVIEW_DURATION"] {
        // "session"/"process" selects the process-lifetime option; a number
        // selects the bounded option of that many seconds.
        let target: GrantDuration
        if requested == "session" || requested == "process" {
            target = .processLifetime
        } else if let seconds = Int(requested) {
            target = .bounded(seconds: seconds)
        } else {
            fail("requested lifetime is not a number or 'session'")
        }
        guard let choices = review.durationChoices,
              let index = choices.options.firstIndex(of: target)
        else { fail("requested lifetime is not offered") }
        @MainActor func findLifetime(in view: NSView) -> NSPopUpButton? {
            if let popup = view as? NSPopUpButton { return popup }
            for child in view.subviews {
                if let popup = findLifetime(in: child) { return popup }
            }
            return nil
        }
        guard let popup = findLifetime(in: content), let action = popup.action else {
            fail("lifetime selector was not found")
        }
        // Selecting and then sending the action is what a menu pick does, so the
        // window's own handler runs and everything it updates is captured. Items
        // are tagged by menu index.
        popup.selectItem(withTag: index)
        NSApp.sendAction(action, to: popup.target, from: popup)
        try? await Task.sleep(nanoseconds: 150_000_000)
    }
}

/// A probe's samples mean nothing once a touch has approved its panel (the
/// approval freezes the controls), so a touch fails the run.
func failIfATouchApproves() {
    Task { @MainActor in
        if case .approved = await reviewTask.value {
            print("probe: APPROVED — a touch reached this probe's panel; rerun without touching the sensor")
            exit(2)
        }
    }
}

if ProcessInfo.processInfo.environment["CSEC_PREVIEW_GRACE_PROBE"] != nil {
    failIfATouchApproves()
    // The same probe `csec-sudo-review --grace-probe` uses, so every approval
    // surface is checked the same way. Any scope or lifetime choice is made
    // first, so the samples report the pairing line under it.
    PromptInteractionGraceProbe.schedule(beforeSampling: {
        guard let content = await panelContent() else { return }
        await applySelections(in: content)
    })
    app.run()
}

if ProcessInfo.processInfo.environment["CSEC_PREVIEW_TYPING_PROBE"] != nil {
    // The same check `csec-sudo-review --typing-probe` runs: keep typing as
    // the panel appears, and it must stay held until the keyboard is quiet.
    failIfATouchApproves()
    PromptInteractionGraceProbe.scheduleTypingCheck()
    app.run()
}

if ProcessInfo.processInfo.environment["CSEC_PREVIEW_FOCUS_PROBE"] != nil {
    // The same probe `csec-sudo-review --focus-probe` uses: Finder takes the
    // focus, the panel is made key again, and Touch ID must re-arm. On the
    // requester-gone scenarios nothing stands in for csecd's peer-exit watch:
    // the requester exits while the panel is away, and making the panel key
    // again must close it through the re-arm's own requester check.
    failIfATouchApproves()
    if !expectsRequesterGone {
        PromptFocusRecoveryProbe.schedule()
        app.run()
    }
    let requester = review.caller
    PromptFocusRecoveryProbe.schedule(
        whileAway: {
            while AccessReviewRequester.isAlive(requester) {
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
        },
        expectsClose: true,
        onClosed: {
            guard case .denied(.requesterGone) = await reviewTask.value else {
                fail("focus probe: the panel closed, but not as requesterGone")
            }
            print("focus probe: the requester exited while the panel was away; making it key again closed it as denied(requesterGone)")
        })
    app.run()
}

if checksTouchIDReturn {
    // Touch ID is unavailable for three seconds after the panel is built and
    // the phone leg gives up after one: the line must say the phone can
    // approve, then that nothing can, and the panel must arm Touch ID once it
    // is back. Touch ID is then armed for about a second; a touch fails the
    // run.
    failIfATouchApproves()
    Task { @MainActor in
        var failures: [String] = []
        try? await Task.sleep(for: .milliseconds(700))
        let phonePending = TouchIDUnavailableProbe.sample()
        print("touch-id probe: phone pending: \(phonePending)")
        if phonePending.panels != 1 || phonePending.unavailableLine != "phone" || phonePending.touchIDShown {
            failures.append("with the phone able to decide the panel did not say to approve on the iPhone")
        }
        previewPhone?.markUnavailable()
        try? await Task.sleep(for: .milliseconds(500))
        let phoneGone = TouchIDUnavailableProbe.sample()
        print("touch-id probe: phone gave up: \(phoneGone)")
        if phoneGone.panels != 1 || phoneGone.unavailableLine != "nobody" || phoneGone.touchIDShown {
            failures.append("once the phone gave up the panel did not say nothing can approve")
        }
        // Touch ID returns three seconds after the panel was built; the next
        // poll, within a second, arms it.
        try? await Task.sleep(for: touchIDProbeReturnsAfter + .milliseconds(Int(TouchIDAvailabilityWatch.pollInterval * 1000) + 300))
        let returned = TouchIDUnavailableProbe.sample()
        print("touch-id probe: Touch ID back: \(returned)")
        let canTakeATouch = TouchIDUnavailableProbe.thisMacCanTakeATouch
        if canTakeATouch, returned.panels != 1 || returned.unavailableLine != "none" || !returned.touchIDShown {
            failures.append("once Touch ID was back the panel did not arm it")
        }
        reviewTask.cancel()
        let outcome = await reviewTask.value
        guard case .denied(.requesterGone) = outcome else {
            fail("touch-id probe: the panel did not close as requesterGone when cancelled")
        }
        if !failures.isEmpty {
            print("touch-id probe: FAIL — " + failures.joined(separator: "; "))
            exit(1)
        }
        print(canTakeATouch
            ? "touch-id probe: PASS"
            : "touch-id probe: INCONCLUSIVE — this Mac cannot take a touch, so the re-arm was not seen")
        exit(canTakeATouch ? 0 : 3)
    }
    app.run()
}

if checksTouchIDLost {
    // Touch ID is armed, then goes two seconds after the panel is built,
    // ending the armed evaluation, while a phone leg may still decide: the
    // panel must stay up saying the phone can approve, then say nothing can
    // once the phone gives up. A touch in the first two seconds fails the run.
    failIfATouchApproves()
    Task { @MainActor in
        var failures: [String] = []
        try? await Task.sleep(for: .seconds(1))
        let armed = TouchIDUnavailableProbe.sample()
        print("touch-id lost probe: armed: \(armed)")
        guard armed.touchIDShown else {
            reviewTask.cancel()
            _ = await reviewTask.value
            print("touch-id lost probe: INCONCLUSIVE — this Mac cannot take a touch, so nothing was armed to lose")
            exit(3)
        }
        if armed.panels != 1 || armed.unavailableLine != "none" {
            failures.append("with Touch ID available the panel was not up and armed")
        }
        // Touch ID goes two seconds after the panel was built; the evaluation
        // ends then and the panel asks again at once.
        try? await Task.sleep(for: touchIDProbeLostAfter - .seconds(1) + .milliseconds(700))
        let lost = TouchIDUnavailableProbe.sample()
        print("touch-id lost probe: Touch ID gone, phone pending: \(lost)")
        if lost.panels != 1 || lost.unavailableLine != "phone" || lost.touchIDShown {
            failures.append("once Touch ID went the panel did not stay up saying to approve on the iPhone")
        }
        previewPhone?.markUnavailable()
        try? await Task.sleep(for: .milliseconds(500))
        let phoneGone = TouchIDUnavailableProbe.sample()
        print("touch-id lost probe: phone gave up: \(phoneGone)")
        if phoneGone.panels != 1 || phoneGone.unavailableLine != "nobody" || phoneGone.touchIDShown {
            failures.append("once the phone gave up the panel did not say nothing can approve")
        }
        reviewTask.cancel()
        let outcome = await reviewTask.value
        guard case .denied(.requesterGone) = outcome else {
            fail("touch-id lost probe: the panel did not close as requesterGone when cancelled")
        }
        if !failures.isEmpty {
            print("touch-id lost probe: FAIL — " + failures.joined(separator: "; "))
            exit(1)
        }
        print("touch-id lost probe: PASS")
        exit(0)
    }
    app.run()
}

if ProcessInfo.processInfo.environment["CSEC_PREVIEW_HOLD"] != nil {
    // Keeps the panel up for a real decision — a touch, the refusing button,
    // or closing it — and prints the outcome. Nothing is behind the preview,
    // so an approval releases nothing.
    Task { @MainActor in
        switch await reviewTask.value {
        case .approved:
            print("hold: approved")
        case .denied(.human):
            print("hold: denied(human)")
        case .denied(.requesterGone):
            print("hold: denied(requesterGone)")
        case .denied(.authenticationFailed):
            print("hold: denied(authenticationFailed)")
        case .denied(.withdrawn):
            print("hold: denied(withdrawn)")
        case .denied(.timedOut):
            print("hold: denied(timedOut)")
        }
        exit(0)
    }
    app.run()
}

if expectsRequesterGone {
    Task { @MainActor in
        if let parent = orphanParent {
            try? await Task.sleep(for: .seconds(3))
            kill(parent.processIdentifier, SIGKILL)
            parent.waitUntilExit()
        }
        // Stands in for csecd's peer-exit watch, which cancels a request when
        // its requester's connection closes — unless the unlock re-present's
        // own check is the one under test.
        while AccessReviewRequester.isAlive(review.caller) {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        let goneAt = Date()
        if !checksUnlockRecheck && !expectsOrphanedRequester { reviewTask.cancel() }
        let outcome = await reviewTask.value
        let milliseconds = Int(Date().timeIntervalSince(goneAt) * 1000)
        let panelVisible = app.windows.contains { $0 is NSPanel && $0.isVisible }
        guard case .denied(.requesterGone) = outcome, !panelVisible else {
            fail("requester-gone: the panel did not close as requesterGone (visible=\(panelVisible))")
        }
        print("requester-gone: the \(expectsOrphanedRequester ? "parent" : "requester") exited; "
            + "the panel closed as denied(requesterGone) \(milliseconds) ms later")
        if expectsOrphanedRequester {
            guard ProcessAncestry.startTime(of: review.caller.pid) == review.caller.startTime else {
                fail("requester-orphaned: the requester itself exited before the panel closed")
            }
            kill(review.caller.pid, SIGKILL)
            print("requester-orphaned: its parent exited while the requester stayed alive; the shared watch closed the panel")
        }
        exit(0)
    }
}

if checksUnlockRecheck && !expectsRequesterGone {
    // The live-requester branch of the unlock re-present, through the probe
    // `csec-sudo-review --unlock-probe` shares.
    PromptUnlockRecheckProbe.schedule(prefix: "unlock-recheck")
}

Task { @MainActor in
    try? await Task.sleep(nanoseconds: 1_000_000_000)
    // The live-requester unlock check writes no PNG.
    if checksUnlockRecheck && !expectsRequesterGone { return }
    guard let panel = app.windows.first(where: { $0 is NSPanel }),
        let content = panel.contentView
    else {
        fail("review panel never appeared")
    }
    await applySelections(in: content)
    if ProcessInfo.processInfo.environment["CSEC_PREVIEW_EXPAND"] != nil {
        // Every collapsed section opens, so one expanded capture shows the
        // full command and the delivery grid together.
        let disclosures = previewDisclosures(in: content)
        guard !disclosures.isEmpty else { fail("details disclosure was not found") }
        for disclosure in disclosures { disclosure.performClick(nil) }
        try? await Task.sleep(nanoseconds: 150_000_000)
    }
    // Capture the window's frame view so the appearance-correct window
    // background and title bar are part of the image; the content view alone
    // has a transparent background.
    let target = content.superview ?? content
    target.layoutSubtreeIfNeeded()
    guard let bitmap = target.bitmapImageRepForCachingDisplay(in: target.bounds) else {
        fail("could not create bitmap")
    }
    target.cacheDisplay(in: target.bounds, to: bitmap)
    guard let png = bitmap.representation(using: .png, properties: [:]) else {
        fail("could not encode PNG")
    }
    guard let outputPath else { fail("this run writes no PNG") }
    do {
        try png.write(to: URL(fileURLWithPath: outputPath))
    } catch {
        fail("could not write \(outputPath): \(error)")
    }
    if ProcessInfo.processInfo.environment["CSEC_PREVIEW_DUMP"] != nil {
        @MainActor func dump(_ view: NSView, depth: Int) {
            let indent = String(repeating: "  ", count: depth)
            let field = (view as? NSTextField).map { " “\($0.stringValue.prefix(40))”" } ?? ""
            print("\(indent)\(type(of: view)) \(NSIntegralRect(view.frame))\(field)")
            for child in view.subviews { dump(child, depth: depth + 1) }
        }
        dump(content, depth: 0)
    }
    print("wrote \(outputPath) (\(Int(target.bounds.width))×\(Int(target.bounds.height)))")
    // The requester-gone scenarios exit once the panel has closed.
    if !expectsRequesterGone { exit(0) }
}

app.run()
#else
FileHandle.standardError.write(Data("cs-review-preview requires AppKit\n".utf8))
exit(64)
#endif
