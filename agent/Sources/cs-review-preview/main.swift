#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
import AppKit
import ConvenientSecurity
import Foundation

// Dev-only screenshot harness for the trusted access-review window. It builds
// synthetic, value-free AccessPolicyReview fixtures, presents the real window,
// captures its content view to a PNG, and exits. Touch ID may engage briefly
// while the window is up; the process exits without ever approving anything.
//
// Usage: cs-review-preview <scenario> <output.png> [light|dark]
//   scenarios: basic | warning | unknown | file | mixed | automation
//              account | ambiguous-account
//   CSEC_PREVIEW_EXPAND=1 opens progressive-disclosure details before capture.

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("cs-review-preview: \(message)\n".utf8))
    exit(64)
}

guard (3...4).contains(CommandLine.arguments.count) else {
    fail("usage: cs-review-preview <basic|warning|unknown|file|mixed|automation|account|ambiguous-account> <output.png> [light|dark]")
}
let scenario = CommandLine.arguments[1]
let outputPath = CommandLine.arguments[2]
let appearanceName: NSAppearance.Name? =
    CommandLine.arguments.count == 4
    ? (CommandLine.arguments[3] == "light" ? .aqua : .darkAqua)
    : nil

func ref(_ uri: String) -> SecretRef {
    guard let parsed = try? SecretRef(uri) else { fail("bad fixture URI \(uri)") }
    return parsed
}

let slackReferences = [
    ref("op://Employee/Dexory Slack User Token/password"),
    ref("op://Employee/Dexory Slack User Token/web cookie"),
    ref("op://Employee/Dexory Slack User Token/web token"),
]
let caller = CallerInfo(
    pid: 51758,
    startTime: 999_999,
    description: "node [unverified] (pid 51758) via launcher [verified] (pid 51759)"
)
let nodeExecutable = PlannedExecutable(
    canonicalPath: "/Users/dev/.local/share/mise/installs/node/22.14.0/bin/node",
    assurance: .unverified
)

func credential(
    references: [SecretRef] = slackReferences,
    notes: [ProviderReviewNote] = []
) -> PolicyReviewCredential {
    PolicyReviewCredential(references: references, providerNotes: notes)
}

/// An `op://` reference names no account, so the window is where the account it
/// resolves from becomes visible — and where an ambiguous vault name is called
/// out before Touch ID rather than after.
let accountNote = ProviderReviewNote(label: "account", detail: "acme.1password.eu")
let ambiguityWarning = ProviderReviewNote(
    label: "",
    detail: "More than one signed-in account has a vault named “Employee”"
        + " (also my.1password.com). This value will come from acme.1password.eu."
        + " To name one account exactly, use the vault's unique id in the reference.",
    isWarning: true
)

let review: AccessPolicyReview
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
                ref("op://Employee/Dexory Slack User Token/password"),
                ref("csec://dexory-dev/DATABASE_URL"),
            ])
        ]
    )
case "automation":
    let reference = ref("csec://projects-mailai/OPENROUTER_API_KEY")
    let inlineScript = #"""
    const { access } = await import("convenient-security"); const ref = "csec://projects-mailai/OPENROUTER_API_KEY"; const values = await access([ref], { reason: "Verify unattended MAILAI csec access without network use", ttl: 30 }); if (typeof values[ref] !== "string" || values[ref].length === 0) throw new Error("missing automation value"); process.stdout.write("mailai-csec-automation-ok\n");
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
        workingDirectory: "/Users/dev/projects/mailai",
        commandDigest: commandDigest
    )
    let timestamp = Date(timeIntervalSince1970: 1_700_000_000)
    let job = AutomationJob(
        id: "00000000-0000-0000-0000-000000000001",
        revision: "00000000-0000-0000-0000-000000000002",
        name: "mailai-csec-smoke",
        reason: "Verify unattended MAILAI csec access without network use",
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
        credentials: [credential(notes: [accountNote])]
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
        credentials: [credential(notes: [accountNote, ambiguityWarning])]
    )
default:
    fail("unknown scenario \(scenario)")
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
if let appearanceName {
    app.appearance = NSAppearance(named: appearanceName)
}

Task { @MainActor in
    _ = await TrustedPolicyReview().reviewAccess(review)
}

Task { @MainActor in
    try? await Task.sleep(nanoseconds: 1_000_000_000)
    guard let panel = app.windows.first(where: { $0 is NSPanel }),
        let content = panel.contentView
    else {
        fail("review panel never appeared")
    }
    if ProcessInfo.processInfo.environment["CSEC_PREVIEW_EXPAND"] != nil {
        @MainActor func findDisclosure(in view: NSView) -> NSButton? {
            if let button = view as? NSButton,
                button.title == "Show command and security details" {
                return button
            }
            for child in view.subviews {
                if let button = findDisclosure(in: child) { return button }
            }
            return nil
        }
        guard let disclosure = findDisclosure(in: content) else {
            fail("automation details disclosure was not found")
        }
        disclosure.performClick(nil)
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
    exit(0)
}

app.run()
#else
FileHandle.standardError.write(Data("cs-review-preview requires AppKit\n".utf8))
exit(64)
#endif
