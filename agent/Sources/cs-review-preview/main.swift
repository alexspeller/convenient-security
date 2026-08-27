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
//   scenarios: basic | warning | unknown | file | mixed

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("cs-review-preview: \(message)\n".utf8))
    exit(64)
}

guard (3...4).contains(CommandLine.arguments.count) else {
    fail("usage: cs-review-preview <basic|warning|unknown|file|mixed> <output.png> [light|dark]")
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

let slackIdentity = CredentialIdentity(
    provider: "op",
    providerAccountKey: String(repeating: "a", count: 64),
    credentialKey: String(repeating: "b", count: 64),
    memberReferenceKeys: [String(repeating: "c", count: 64)]
)
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
    level: RiskLevel,
    references: [SecretRef] = slackReferences,
    scopeExpanded: Bool = false,
    compatibilityOffered: Bool = false
) -> PolicyReviewCredential {
    PolicyReviewCredential(
        identity: slackIdentity,
        references: references,
        storedLevel: level,
        scopeExpanded: scopeExpanded,
        compatibilityReviewOffered: compatibilityOffered,
        compatibilityAccepted: false
    )
}

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
        credentials: [credential(level: .standard)]
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
        credentials: [credential(level: .standard, compatibilityOffered: true)]
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
            credential(level: .unknown),
            credential(
                level: .high,
                references: [
                    ref("op://Infrastructure/AWS Deploy Key/access key id"),
                    ref("op://Infrastructure/AWS Deploy Key/secret access key"),
                ],
                scopeExpanded: true
            ),
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
        credentials: [credential(level: .critical, compatibilityOffered: true)]
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
            credential(
                level: .standard,
                references: [
                    ref("op://Employee/Dexory Slack User Token/password"),
                    ref("csec://dexory-dev/DATABASE_URL"),
                ]
            )
        ]
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
