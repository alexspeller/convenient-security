import CSECRemoteApproval
import LocalAuthentication
import SwiftUI

// The reviewer demo: what deciding looks like, for someone with no Mac to
// pair (App Review, or anyone deciding whether to set csec up). It is in
// every build, entered only by its button on the unpaired screens, and kept
// apart from real approvals by construction: nothing in this file can reach
// the mailbox, iCloud, the Keychain, the phone's Secure Enclave keys or the
// app's model. Its cards are built here, on the iPhone, unsigned, so they
// could never verify as a Mac's request anywhere; its Face ID is one
// throwaway `LAContext` that no key ever sees. `bin/ci` holds this file to
// that, and the UI tests check the demo changes nothing a real decision
// would.

/// The demo's state: three sample cards and what was decided on each. It is
/// the cards' host, so a card's Approve and Deny land here and nowhere else.
@MainActor
final class DemoApprovals: ApprovalCardHost {
    @Published private(set) var items: [PendingRemoteApproval]
    @Published private(set) var sentDecisions: [String: RemoteApprovalDecision] = [:]
    @Published private(set) var decidingRequestID: String?
    @Published private(set) var outcome: ApprovalOutcome?
    /// The demo never refuses an answer.
    let answersNotTaken: Set<String> = []

    var faceIDActionInProgress: Bool { decidingRequestID != nil }
    var decisionsReachAMac: Bool { false }

    init() {
        items = DemoFixtures.items(now: Date())
    }

    /// Fresh cards, as if the Mac had just asked again.
    func startAgain() {
        guard !faceIDActionInProgress else { return }
        items = DemoFixtures.items(now: Date())
        sentDecisions = [:]
        outcome = nil
    }

    /// The same freeze-then-Face-ID order a real decision has, with nothing
    /// after Face ID but this outcome: no signature, no key, no send.
    func decide(
        _ item: PendingRemoteApproval,
        decision: RemoteApprovalDecision,
        choice: RemoteApprovalChoice
    ) async {
        guard !faceIDActionInProgress, sentDecisions[item.id] == nil,
              items.contains(where: { $0.id == item.id }) else { return }
        decidingRequestID = item.id
        defer { decidingRequestID = nil }
        let verb = decision == .approve ? "Approve" : "Deny"
        switch await DemoFaceID.confirm(reason: "\(verb) this demo request. Nothing is sent.") {
        case .passed:
            sentDecisions[item.id] = decision
            outcome = ApprovalOutcome(tone: .success, text: Self.decidedText(item, decision))
        case .cancelled:
            outcome = ApprovalOutcome(
                tone: .info,
                text: "Face ID was cancelled, so nothing was decided. The card is still waiting."
            )
        case let .unavailable(why):
            // A demo with no way forward shows nothing; the real app would
            // stop here, and says so.
            sentDecisions[item.id] = decision
            outcome = ApprovalOutcome(
                tone: .info,
                text: "\(why) The real app needs Face ID for every decision; the demo went on without it. "
                    + Self.decidedText(item, decision)
            )
        case .failed:
            outcome = ApprovalOutcome(
                tone: .failure,
                text: "Face ID did not recognise you, so nothing was decided. The card is still waiting."
            )
        }
    }

    private static func decidedText(_ item: PendingRemoteApproval, _ decision: RemoteApprovalDecision) -> String {
        let what = DemoFixtures.shortName(of: item)
        switch decision {
        case .approve:
            return "Approved the \(what) with Face ID. With a real Mac, csec would now go ahead with it. This is a demo: nothing was sent."
        case .deny:
            return "Denied the \(what) with Face ID. With a real Mac, csec would now refuse it. This is a demo: nothing was sent."
        }
    }
}

/// One Face ID check whose context is thrown away: it unlocks nothing.
enum DemoFaceID {
    enum Result: Equatable {
        case passed
        case cancelled
        case failed
        /// Face ID cannot run here, with the reason in a sentence.
        case unavailable(String)
    }

    @MainActor
    static func confirm(reason: String) async -> Result {
        let context = LAContext()
        defer { context.invalidate() }
        context.localizedCancelTitle = "Cancel"
        // Face ID only, as for a real decision: no passcode fallback button.
        context.localizedFallbackTitle = ""
        var availability: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &availability) else {
            switch availability.flatMap({ LAError.Code(rawValue: $0.code) }) {
            case .biometryNotEnrolled?:
                return .unavailable("Face ID is not set up on this iPhone.")
            case .biometryLockout?:
                return .unavailable("Face ID is locked until you enter your passcode.")
            default:
                return .unavailable("Face ID is not available on this iPhone.")
            }
        }
        #if DEBUG && targetEnvironment(simulator)
        SimulatorInstrumentation.shared.recordFaceIDPrompt()
        #endif
        do {
            _ = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .systemCancel, .appCancel, .userFallback:
                return .cancelled
            case .biometryLockout:
                return .unavailable("Face ID is locked until you enter your passcode.")
            default:
                return .failed
            }
        } catch {
            return .failed
        }
        #if DEBUG && targetEnvironment(simulator)
        SimulatorInstrumentation.shared.recordFaceIDMatch()
        #endif
        return .passed
    }
}

/// The demo's sample requests, one of each kind a Mac most often sends:
/// secret access, an SSH sign-in, sudo. Value-free like every real review,
/// and unsigned: the envelope's signature is empty.
enum DemoFixtures {
    static let macName = "Demo Mac"

    /// Which sample a card is, in a few words.
    static func shortName(of item: PendingRemoteApproval) -> String {
        switch item.review.kind {
        case .access: return "secret access request"
        case .ssh: return "SSH sign-in"
        case .sudo: return "sudo request"
        case .restore: return "request to reopen approvals"
        case .settings: return "settings change"
        }
    }

    static func items(now: Date) -> [PendingRemoteApproval] {
        // Asked a little before the demo opened, as a real card would have been.
        let asked = UInt64(max(0, now.timeIntervalSince1970 - 20) * 1_000)
        let mac = PinnedMac(
            RemoteApprovalMacPairing(
                macDeviceID: "demo-mac",
                macDeviceName: macName,
                macPublicKeyX963: Data(),
                cloudKitContainerIdentifier: ""
            ),
            confirmation: nil,
            pairedAtMilliseconds: 0
        )
        return [access, ssh, sudo].map { review in
            let request = RemoteApprovalRequest(
                requestID: "demo-\(review.kind.rawValue)-\(UUID().uuidString.lowercased())",
                macDeviceID: "demo-mac",
                macDeviceName: macName,
                createdAtMilliseconds: asked,
                review: review
            )
            return PendingRemoteApproval(
                envelope: SignedRemoteApprovalRequest(request: request, signatureDER: Data()),
                mac: mac
            )
        }
    }

    /// Stands in for the digests a Mac computes over its real request.
    private static let placeholderDigest = Data(count: 32)
    private static let terminal = "Terminal · “my-app” · window 1, tab 1 · ttys003"

    private static func stored(_ item: String) -> ReviewSecret {
        ReviewSecret(
            provider: "csec", tint: .purple, account: "this Mac", container: "deploy",
            item: item, field: nil, itemIsIdentifier: true
        )
    }

    private static let access = RemoteApprovalReview(
        kind: .access,
        headline: "terraform plan -var-file=staging.tfvars",
        callerDescription: "terraform (pid 4242) ← zsh ← Terminal",
        terminalDescription: terminal,
        secrets: [stored("cloud-access-key-id"), stored("cloud-secret-access-key")],
        referenceSetDigest: placeholderDigest,
        delivery: .init(
            emitterName: "terraform",
            emitterPath: "/opt/homebrew/bin/terraform",
            emitterAssurance: "Developer ID · HashiCorp",
            recipientDescription: "planned executable consumer",
            deliveryDescription: "Environment of the launched process",
            destinationDescription: "Child process environment"
        ),
        warnings: [],
        footnote: "Face ID authorizes this exact release. No secret values are shown on this iPhone.",
        scopeOptions: [
            .init(id: "process", title: "This command", detail: "terraform (pid 4242) and the processes it starts"),
            .init(id: "terminal-tab", title: "This terminal tab", detail: "Terminal window 1, tab 1, until the tab closes"),
        ],
        defaultScopeID: "process",
        durationOptions: ["While it runs", "15 minutes", "1 hour"],
        defaultDurationIndex: 0,
        operationDigest: placeholderDigest
    )

    private static let ssh = RemoteApprovalReview(
        kind: .ssh,
        headline: "ssh deploy@203.0.113.7",
        callerDescription: "ssh (pid 5150) ← zsh ← Terminal",
        terminalDescription: terminal,
        secrets: [stored("ssh-deploy-key")],
        referenceSetDigest: placeholderDigest,
        delivery: .init(
            emitterName: "ssh",
            emitterPath: "/usr/bin/ssh",
            emitterAssurance: "Apple",
            recipientDescription: "SSH server at 203.0.113.7",
            deliveryDescription: "One signature through the csec SSH agent",
            destinationDescription: "SSH authentication"
        ),
        warnings: [
            "UNKNOWN HOST: No name in your known_hosts matches this server's identity. "
                + "That is expected only for a first connection to a new server, or after "
                + "the server changed its host key — if neither applies, deny.",
        ],
        footnote: "Your private key stays in Convenient Security. SSH receives only a signature.",
        ssh: .init(
            hostNames: [],
            hostContext: "No hostname found in known_hosts.",
            unknownHost: true,
            remoteUser: "deploy",
            keyLabel: "deploy@my-app",
            keyAlgorithm: "Ed25519"
        ),
        scopeOptions: [
            .init(id: "connection", title: "This connection", detail: "One sign-in from ssh (pid 5150)"),
            .init(id: "terminal-tab", title: "This server from this terminal tab", detail: "Terminal window 1, tab 1, until the tab closes"),
        ],
        defaultScopeID: "connection",
        durationOptions: ["This sign-in only", "15 minutes", "1 hour"],
        defaultDurationIndex: 0,
        operationDigest: placeholderDigest
    )

    private static let sudo = RemoteApprovalReview(
        kind: .sudo,
        headline: "sudo softwareupdate --install --all",
        callerDescription: "sudo (pid 6001) ← zsh ← Terminal",
        terminalDescription: terminal,
        secrets: [],
        referenceSetDigest: placeholderDigest,
        delivery: nil,
        warnings: [],
        footnote: "Face ID authorizes this one sudo authentication.",
        sudo: .init(
            command: "softwareupdate --install --all",
            workingDirectory: "/Users/you",
            targetUser: "root"
        ),
        operationDigest: placeholderDigest
    )
}

/// The demo's screen: what it is, the three cards, and a way to start again.
struct DemoView: View {
    @StateObject private var demo = DemoApprovals()

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Demo: sample requests", systemImage: "play.rectangle.fill")
                        .font(.headline)
                        .foregroundStyle(.purple)
                    Text("These requests were made up on this iPhone. Nothing here comes from a Mac or reaches one, and Face ID here unlocks no key. Try Approve and Deny to see how deciding works.")
                        .font(.subheadline)
                    Text("Once you pair a Mac running Convenient Security, its own approval prompts appear in this app: secret access, SSH sign-ins and sudo. Face ID decides each one, and the Mac acts on your answer.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("demo-banner")
            }
            if let outcome = demo.outcome {
                Section {
                    Label(outcome.text, systemImage: symbol(outcome.tone))
                        .foregroundStyle(tint(outcome.tone))
                        .font(.subheadline)
                        .accessibilityIdentifier("demo-outcome")
                }
            }
            Section {
                ForEach(demo.items) { item in
                    ApprovalCard(item: item, host: demo)
                        .id(item.id)
                }
            } header: {
                Text("Sample requests")
            }
            Section {
                Button("Start the demo again") {
                    demo.startAgain()
                }
                .disabled(demo.faceIDActionInProgress)
            }
        }
        .navigationTitle("Demo")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func symbol(_ tone: ApprovalOutcome.Tone) -> String {
        switch tone {
        case .success: return "checkmark.circle.fill"
        case .info: return "info.circle.fill"
        case .failure: return "exclamationmark.circle.fill"
        }
    }

    private func tint(_ tone: ApprovalOutcome.Tone) -> Color {
        switch tone {
        case .success: return .green
        case .info: return .blue
        case .failure: return .red
        }
    }
}
