#if DEBUG && targetEnvironment(simulator)
import CSECRemoteApproval
import CryptoKit
import Foundation

/// Synthetic, value-free requests for the Simulator test mode, one per review
/// kind, signed by a simulated Mac. None of them reaches CloudKit and none
/// resolves anything; they exercise the cards, the frozen selection, the
/// signature binding, and — for the fixtures that carry a challenge — the
/// whole cold-unlock computation against this Simulator identity's
/// key-agreement key.
enum SimulatorFixture: String, CaseIterable, Identifiable {
    case access
    case bridge
    case ssh
    case sudo
    case restore
    case coldUnlock
    case longAccess
    case longSSH
    case delegatedSSH
    case delegatedSudo
    case closingSudo
    case hooksChanged

    var id: String { rawValue }

    var menuTitle: String {
        switch self {
        case .access: return "Secret access: choices, notes, warnings"
        case .bridge: return "Secret access from a language client"
        case .ssh: return "SSH sign-in to an unknown host"
        case .sudo: return "sudo"
        case .restore: return "Reopen approvals after a restart"
        case .coldUnlock: return "Secret access + restore, with cold unlock"
        case .longAccess: return "Long secret access from a lookalike Mac"
        case .longSSH: return "Long SSH sign-in from a lookalike Mac"
        case .delegatedSSH: return "SSH from a script auto mode declined"
        case .delegatedSudo: return "sudo auto mode declined"
        case .closingSudo: return "sudo closing in 29 seconds"
        case .hooksChanged: return "New Claude Code hook to acknowledge"
        }
    }

    /// Whether the simulated Mac asks this phone to open cold storage.
    var carriesUnlockChallenge: Bool {
        self == .restore || self == .coldUnlock
    }

    /// The long fixtures come from a second simulated Mac whose name carries
    /// the characters a hostile pairing code would use to disguise itself.
    var fromLookalikeMac: Bool {
        self == .longAccess || self == .longSSH
    }
}

/// What the simulated Mac keeps to check the phone's unlock answer: its
/// enrollment, this request's blinding, and the pairing binding.
struct SimulatorUnlockCheck {
    let enrollment: RemoteUnlockCrypto.Enrollment
    let challenge: RemoteUnlockCrypto.Challenge
    let binding: Data
}

/// A stand-in Mac: a software signing key, a device ID, and a remote-unlock
/// enrollment made against this phone's key-agreement key exactly as `csec
/// remote enable` makes one. It keeps no remote private key: like the real
/// Mac, it can open that key only with the phone's answer.
final class SimulatedMac {
    /// A name built to mislead: a right-to-left override that would show
    /// "MacBook" reversed, and a newline that would start a second line.
    /// `PinnedMac.displayName` must show each as U+FFFD.
    static let lookalikeName = "Lookalike Mac\u{202E}kooBcaM\nApprove everything"

    let deviceID: String
    let deviceName: String
    private let key: P256.Signing.PrivateKey

    /// A new Mac, or — given an ID — that Mac again: with its stored key
    /// (the simulated mailbox's Macs, across a relaunch), or with a new key
    /// under the same ID, which no `csec remote enable` makes and the phone
    /// must show as a key change.
    init(
        deviceName: String = "Simulated Mac",
        deviceID: String = UUID().uuidString.lowercased(),
        key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()
    ) {
        self.deviceName = deviceName
        self.deviceID = deviceID
        self.key = key
    }
    private var enrollment: (phoneKey: Data, enrollment: RemoteUnlockCrypto.Enrollment, binding: Data)?

    var publicKeyX963: Data { key.publicKey.x963Representation }
    /// Synthetic and Simulator-only: what the simulated mailbox stores to sign
    /// as this Mac again after a relaunch.
    var keyRawRepresentation: Data { key.rawRepresentation }

    var pairing: RemoteApprovalMacPairing {
        RemoteApprovalMacPairing(
            macDeviceID: deviceID,
            macDeviceName: deviceName,
            macPublicKeyX963: publicKeyX963,
            cloudKitContainerIdentifier: PhoneIdentityStore.containerIdentifier
        )
    }

    /// What `csec remote enable` leaves for the phone it pinned: this Mac's
    /// pairing, offered to that phone and signed with this Mac's key.
    func offer(
        to phoneDeviceID: String,
        phonePublicKeyX963: Data,
        phoneKeyAgreementPublicKeyX963: Data
    ) throws -> SignedRemoteApprovalPairingOffer {
        let offer = RemoteApprovalPairingOffer(
            mac: pairing,
            phoneDeviceID: phoneDeviceID,
            phonePublicKeyX963: phonePublicKeyX963,
            phoneKeyAgreementPublicKeyX963: phoneKeyAgreementPublicKeyX963,
            createdAtMilliseconds: currentTimeMilliseconds()
        )
        return SignedRemoteApprovalPairingOffer(
            offer: offer,
            signatureDER: try key.signature(for: offer.signingData()).derRepresentation
        )
    }

    func request(
        _ fixture: SimulatorFixture,
        phoneDeviceID: String,
        phoneKeyAgreementPublicKeyX963: Data,
        at now: UInt64
    ) throws -> (envelope: SignedRemoteApprovalRequest, unlock: SimulatorUnlockCheck?) {
        var unlock: SimulatorUnlockCheck?
        var challenge: RemoteApprovalUnlockChallenge?
        if fixture.carriesUnlockChallenge {
            let enrolled = try currentEnrollment(
                phoneDeviceID: phoneDeviceID,
                phoneKeyAgreementPublicKeyX963: phoneKeyAgreementPublicKeyX963
            )
            let blinding = try RemoteUnlockCrypto.challenge(for: enrolled.enrollment)
            unlock = SimulatorUnlockCheck(
                enrollment: enrolled.enrollment,
                challenge: blinding,
                binding: enrolled.binding
            )
            challenge = RemoteApprovalUnlockChallenge(
                enrollmentID: enrolled.enrollment.enrollmentID,
                blindedPoint: blinding.blindedPoint
            )
        }
        let request = RemoteApprovalRequest(
            macDeviceID: deviceID,
            macDeviceName: deviceName,
            createdAtMilliseconds: now,
            review: try Self.review(for: fixture, now: now),
            unlockChallenge: challenge
        )
        let envelope = try SignedRemoteApprovalRequest.signed(request, by: key)
        try envelope.verify(macPublicKeyX963: publicKeyX963, at: now)
        return (envelope, unlock)
    }

    /// The Mac's side of a cold unlock: unblind the phone's answer, open the
    /// remote key, and prove that key opens storage material sealed to it.
    static func checkUnlock(_ check: SimulatorUnlockCheck, answer: Data) throws {
        let remoteKey = try RemoteUnlockCrypto.openRemoteKey(
            enrollment: check.enrollment,
            challenge: check.challenge,
            answer: answer,
            binding: check.binding
        )
        let context = Data("csec.simulator.native-store.default".utf8)
        let sample = Data("simulator store key material".utf8)
        let sealed = try RemoteUnlockCrypto.seal(
            sample,
            toRemotePublicKey: check.enrollment.remotePublicKey,
            context: context
        )
        guard try RemoteUnlockCrypto.open(sealed, remoteKey: remoteKey, context: context)
            == sample else {
            throw RemoteUnlockCrypto.Failure.unwrapFailed
        }
    }

    private func currentEnrollment(
        phoneDeviceID: String,
        phoneKeyAgreementPublicKeyX963: Data
    ) throws -> (enrollment: RemoteUnlockCrypto.Enrollment, binding: Data) {
        if let enrollment, enrollment.phoneKey == phoneKeyAgreementPublicKeyX963 {
            return (enrollment.enrollment, enrollment.binding)
        }
        let binding = Data(
            "csec.simulator.remote-unlock-binding\n\(deviceID)\n\(phoneDeviceID)".utf8
        )
        // The Mac discards the remote private key after sealing storage to its
        // public half; so does this one.
        let enrolled = try RemoteUnlockCrypto.enroll(
            phoneKeyAgreementPublicKeyX963: phoneKeyAgreementPublicKeyX963,
            binding: binding
        )
        enrollment = (phoneKeyAgreementPublicKeyX963, enrolled.enrollment, binding)
        return (enrolled.enrollment, binding)
    }

    // MARK: - Reviews

    private static func digest(_ text: String) -> Data {
        Data(SHA256.hash(data: Data(text.utf8)))
    }

    private static let simulatedTerminal = "iTerm2 · “simulator fixture” · window 1, tab 2 · ttys003"

    /// `now` is when the simulated Mac signs the request; a review with a
    /// deadline closes the time the real one would after it: a sudo just
    /// before the PAM module's five minutes, a coding agent's request after
    /// its 20-minute wait, and one sudo inside the 30-second countdown.
    private static func review(for fixture: SimulatorFixture, now: UInt64) throws -> RemoteApprovalReview {
        let review: RemoteApprovalReview
        switch fixture {
        case .access:
            let references = [
                "op://Infrastructure/AWS deploy/access key id",
                "op://Infrastructure/AWS deploy/secret access key",
            ]
            review = RemoteApprovalReview(
                kind: .access,
                headline: "terraform apply -var-file=environments/production.tfvars "
                    + "-target=module.edge_cache -target=module.api_gateway "
                    + "-parallelism=4 -lock-timeout=120s -input=false "
                    + "-refresh=true -auto-approve  # rotate the edge certificates "
                    + "before the Friday freeze, per the change ticket",
                callerDescription: "zsh (grant root pid 4242) ← iTerm2",
                terminalDescription: simulatedTerminal,
                secrets: ["access key id", "secret access key"].map {
                    onePassword(
                        "Infrastructure", "AWS deploy", $0,
                        notes: ["Read through the 1Password desktop app on the Mac."],
                        warnings: ["Shared vault: 4 other people can change this item."]
                    )
                },
                referenceSetDigest: digest(references.joined(separator: "\n")),
                delivery: .init(
                    emitterName: "terraform",
                    emitterPath: "/opt/homebrew/bin/terraform",
                    emitterAssurance: "Developer ID · HashiCorp",
                    recipientDescription: "planned executable consumer",
                    deliveryDescription: "Environment of the launched process",
                    destinationDescription: "Child process environment"
                ),
                warnings: ["Synthetic Simulator request: nothing is resolved."],
                footnote: "Face ID authorizes this exact release. No secret values are shown on this iPhone.",
                scopeOptions: [
                    .init(
                        id: "process",
                        title: "This command",
                        detail: "terraform (pid 4242) and the processes it starts"
                    ),
                    .init(
                        id: "terminal-tab",
                        title: "This terminal tab",
                        detail: "iTerm2 window 1, tab 2, until the tab closes"
                    ),
                ],
                defaultScopeID: "process",
                durationOptions: ["While it runs", "15 minutes", "1 hour", "8 hours"],
                defaultDurationIndex: 0,
                operationDigest: digest("csec.simulator.access.v3")
            )
        case .ssh:
            let references = ["csec://ssh-keys/deploy"]
            review = RemoteApprovalReview(
                kind: .ssh,
                headline: "ssh deploy@203.0.113.7",
                callerDescription: "ssh (pid 5150) ← zsh ← iTerm2",
                terminalDescription: simulatedTerminal,
                secrets: [native("ssh-keys", "deploy")],
                referenceSetDigest: digest(references.joined(separator: "\n")),
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
                    keyLabel: "deploy@ci",
                    keyAlgorithm: "Ed25519"
                ),
                scopeOptions: [
                    .init(
                        id: "connection",
                        title: "This connection",
                        detail: "One sign-in from ssh (pid 5150)"
                    ),
                    .init(
                        id: "terminal-tab",
                        title: "This server from this terminal tab",
                        detail: "iTerm2 window 1, tab 2, until the tab closes"
                    ),
                ],
                defaultScopeID: "connection",
                durationOptions: ["This sign-in only", "15 minutes", "1 hour"],
                defaultDurationIndex: 0,
                operationDigest: digest("csec.simulator.ssh.v3")
            )
        case .delegatedSSH:
            // A Claude Code session's script started ssh, and auto mode did
            // not approve it because the script is not pinned yet: the card
            // shows why, and the pairing line while the Claude Code session
            // and "Until it exits" are selected.
            let references = ["csec://ssh-keys/deploy"]
            review = RemoteApprovalReview(
                kind: .ssh,
                headline: "SSH as git to github.com",
                callerDescription: "ssh (pid 5180) ← bash ← zsh ← Claude Code",
                terminalDescription: simulatedTerminal,
                secrets: [native("ssh-keys", "deploy")],
                referenceSetDigest: digest(references.joined(separator: "\n")),
                delivery: .init(
                    emitterName: "ssh",
                    emitterPath: "/usr/bin/ssh",
                    emitterAssurance: "Apple",
                    recipientDescription: "SSH server github.com",
                    deliveryDescription: "One signature through the csec SSH agent",
                    destinationDescription: "SSH authentication"
                ),
                warnings: [],
                footnote: "Your private key stays in Convenient Security. SSH receives only a signature.",
                ssh: .init(
                    hostNames: ["github.com"],
                    hostContext: "Recognized from known_hosts.",
                    unknownHost: false,
                    remoteUser: "git",
                    keyLabel: "deploy@ci",
                    keyAlgorithm: "Ed25519"
                ),
                scopeOptions: [
                    .init(
                        id: "coding-agent",
                        title: "This Claude Code session",
                        detail: "Claude Code (pid 5100), includes SSH from the commands this agent runs"
                    ),
                    .init(id: "connection", title: "This SSH command", detail: "ssh (pid 5180)"),
                ],
                defaultScopeID: "coding-agent",
                durationOptions: ["Until it exits", "1 hour"],
                defaultDurationIndex: 0,
                delegation: .init(
                    note: "Auto mode didn't approve this: ssh was started by bin/deploy, "
                        + "which you haven't trusted for auto mode yet.",
                    pairing: .init(
                        line: "Approving also lets Claude Code auto mode start SSH from bin/deploy "
                            + "(with bin/_common.sh) in app until you revoke them or they change",
                        scopeID: "coding-agent",
                        processLifetimeIndex: 0
                    )
                ),
                closesAtMilliseconds: now + 1_200_000,
                operationDigest: digest("csec.simulator.delegated-ssh.v3")
            )
        case .sudo, .closingSudo:
            review = RemoteApprovalReview(
                kind: .sudo,
                headline: "sudo launchctl bootstrap system /Library/LaunchDaemons/com.example.agent.plist",
                callerDescription: "sudo (pid 6001) ← zsh ← Terminal",
                terminalDescription: "Terminal · “admin” · window 2, tab 1 · ttys004",
                secrets: [],
                referenceSetDigest: digest(""),
                delivery: nil,
                warnings: [],
                footnote: "Face ID authorizes this one sudo authentication.",
                sudo: .init(
                    command: "launchctl bootstrap system /Library/LaunchDaemons/com.example.agent.plist",
                    workingDirectory: "/Users/you/src/agent",
                    targetUser: "root"
                ),
                closesAtMilliseconds: now + (fixture == .closingSudo ? 29_000 : 297_000),
                operationDigest: digest("csec.simulator.sudo.v3")
            )
        case .delegatedSudo:
            // A Claude Code session ran sudo in a project where no one has
            // let auto mode run it yet: the card shows why, and the pairing
            // line, which a sudo card always shows, having no scope or
            // lifetime to choose.
            review = RemoteApprovalReview(
                kind: .sudo,
                headline: "sudo fs_usage -w -f pathname -t 8",
                callerDescription: "sudo (pid 6101) ← zsh ← csec ai ← Claude Code, no terminal",
                terminalDescription: nil,
                secrets: [],
                referenceSetDigest: digest(""),
                delivery: nil,
                warnings: [],
                footnote: "Face ID authorizes this one sudo authentication.",
                sudo: .init(
                    command: "fs_usage -w -f pathname -t 8",
                    workingDirectory: "/Users/you/src/app",
                    targetUser: nil
                ),
                delegation: .init(
                    note: "Auto mode didn't approve this: sudo hasn't been approved for auto mode in app.",
                    pairing: .unscoped(
                        line: "Approving also lets Claude Code auto mode run sudo in app until you revoke it"
                    )
                ),
                closesAtMilliseconds: now + 297_000,
                operationDigest: digest("csec.simulator.delegated-sudo.v3")
            )
        case .hooksChanged:
            // A Claude Code request declined on a hooks module its launch
            // brought in: acknowledging it is a change to csec's settings,
            // which releases nothing and offers no choice.
            review = RemoteApprovalReview(
                kind: .settings,
                headline: "New Claude Code Hook",
                callerDescription: "claude (pid 5100) ← csec ai ← zsh ← iTerm2",
                terminalDescription: simulatedTerminal,
                secrets: [],
                referenceSetDigest: digest(""),
                delivery: nil,
                warnings: [],
                footnote: "A hook can approve a shell command without the classifier, so acknowledging one trusts "
                    + "its code. Approving acknowledges exactly what is listed, and auto mode approves secret use "
                    + "again. Deny sends each request to its own approval instead. No secret is released by this "
                    + "approval.",
                settings: .init(changes: [
                    "New hook: harbor-artifact-defer@harbor · hooks module, which can approve shell commands",
                    // An unbroken digest, which has to wrap at the largest
                    // text size.
                    "Its module \u{201C}register.mjs sha256:5d701a15f102bea3419d82442e5a3d446435116ff98375a7741898c8db82fe3a\u{201D}",
                    "csec can't show what it runs: acknowledge it only if you have reviewed it where it is defined",
                ]),
                closesAtMilliseconds: now + 1_200_000,
                operationDigest: digest("csec.simulator.hooks-changed.v3")
            )
        case .restore:
            review = RemoteApprovalReview(
                kind: .restore,
                headline: "csecd restarted and holds approvals you already gave",
                callerDescription: "csecd (restarted after an update)",
                terminalDescription: simulatedTerminal,
                secrets: [],
                referenceSetDigest: digest("csec://default/github/token\ncsec://default/ssh/github"),
                delivery: nil,
                warnings: [],
                footnote: nil,
                restore: Self.restoreSection,
                operationDigest: digest("csec.simulator.restore.v3")
            )
        case .bridge:
            // A program asking through a language client over `csec bridge`:
            // the headline is the reason it wrote itself, and under it the
            // command line the Mac read for it.
            let references = ["csec://harbor/RELAY_TOKEN"]
            review = RemoteApprovalReview(
                kind: .access,
                headline: "harbor: read the relay on nimbus as harbord (Approve presses)",
                callerDescription: "python3.12 [unverified] (pid 46452) via csec [verified]",
                terminalDescription: simulatedTerminal,
                secrets: [native("harbor", "RELAY_TOKEN")],
                referenceSetDigest: digest(references.joined(separator: "\n")),
                delivery: .init(
                    emitterName: "python3.12",
                    emitterPath: "/Users/you/.local/share/uv/python/cpython-3.12.8-macos-aarch64-none/bin/python3.12",
                    emitterAssurance: "Unverified",
                    recipientDescription: "Verified direct parent",
                    deliveryDescription: "Direct to process memory",
                    destinationDescription: "Local development"
                ),
                warnings: [],
                footnote: "Face ID authorizes this exact release. No secret values are shown on this iPhone.",
                scopeOptions: [
                    .init(id: "process", title: "Requesting process only", detail: "python3.12 (pid 46452)"),
                ],
                defaultScopeID: "process",
                durationOptions: ["Until it exits", "1 hour"],
                defaultDurationIndex: 0,
                requesterCommand: "/Users/you/src/harbor/.venv/bin/python3 /Users/you/src/harbor/.venv/bin/pytest -q",
                operationDigest: digest("csec.simulator.bridge.v3")
            )
        case .coldUnlock:
            let references = ["csec://default/GITHUB_TOKEN"]
            review = RemoteApprovalReview(
                kind: .access,
                headline: "gh release create v2.4.0 --notes-file CHANGELOG.md",
                callerDescription: "gh (pid 7070) ← zsh ← iTerm2",
                terminalDescription: simulatedTerminal,
                secrets: [
                    native(
                        "default", "GITHUB_TOKEN",
                        notes: ["Opening it needs this iPhone's answer: the Mac has had no Touch ID since csecd started."]
                    ),
                ],
                referenceSetDigest: digest(references.joined(separator: "\n")),
                delivery: .init(
                    emitterName: "gh",
                    emitterPath: "/opt/homebrew/bin/gh",
                    emitterAssurance: "Developer ID · GitHub",
                    recipientDescription: "planned executable consumer",
                    deliveryDescription: "Environment of the launched process",
                    destinationDescription: "Child process environment"
                ),
                warnings: [],
                footnote: "Face ID authorizes this exact release. No secret values are shown on this iPhone.",
                restore: Self.restoreSection,
                scopeOptions: [
                    .init(id: "process", title: "This command", detail: "gh (pid 7070)"),
                ],
                defaultScopeID: "process",
                durationOptions: ["While it runs", "1 hour"],
                defaultDurationIndex: 0,
                operationDigest: digest("csec.simulator.cold-unlock.v3")
            )
        case .longAccess:
            review = longAccessReview()
        case .longSSH:
            review = longSSHReview()
        }
        try review.validate()
        return review
    }

    // MARK: - Long and suspicious metadata

    /// The last words of both long headlines, so a test can tell the whole
    /// headline is on the card.
    static let headlineTail = "# end of a very long command line"

    /// A long unbroken token: it has to wrap mid-word rather than push the
    /// card wider than the screen.
    private static let unbrokenToken = String(
        repeating: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        count: 5
    )

    /// Every field near the size a Mac fits it to, the most choices a review
    /// may offer, and U+FFFD where the Mac would already have replaced a
    /// bidirectional or control character (`ReviewDisplay.sanitized`).
    private static func longAccessReview() -> RemoteApprovalReview {
        let references = (1...3).map {
            "op://Infrastructure/AWS production deploy \($0)/"
                + String(repeating: "nested section/", count: 10)
                + "secret access key"
        }
        return RemoteApprovalReview(
            kind: .access,
            headline: "aws s3 sync ./build s3://release-artifacts/invoice\u{FFFD}fdp.exe "
                + "--sse-kms-key-id=arn:aws:kms:eu-west-2:123456789012:key/\(unbrokenToken) "
                + String(repeating: "--exclude '*.map' --exclude '*.tmp' ", count: 12)
                + headlineTail,
            callerDescription: (1...8).map { "node (pid \(4_000 + $0))" }.joined(separator: " ← ")
                + " ← zsh ← iTerm2",
            terminalDescription: "iTerm2 · “build\u{FFFD}prod” · window 12, tab 9 · ttys042",
            secrets: (1...10).map {
                onePassword(
                    "Infrastructure\u{FFFD}Shared",
                    "AWS production deploy key for the release pipeline that uploads "
                        + "signed artifacts to every region, including the ones in the "
                        + "disaster-recovery account",
                    "field \($0) of the deploy key",
                    account: "a-very-long-team-name-for-the-release-org.1password.eu",
                    notes: [
                        "Read through the 1Password desktop app on the Mac.",
                        "This item was edited 3 minutes ago by someone else.",
                    ],
                    warnings: [
                        "Shared vault: 41 other people can change this item.",
                        "The item's name contains a character csec replaced with \u{FFFD}.",
                    ]
                )
            } + (1...3).map {
                onePassword(
                    "Infrastructure\u{FFFD}Shared", "AWS production deploy \($0)",
                    String(repeating: "nested section/", count: 10) + "secret access key",
                    account: "a-very-long-team-name-for-the-release-org.1password.eu"
                )
            },
            referenceSetDigest: digest(references.joined(separator: "\n")),
            delivery: .init(
                emitterName: "aws",
                emitterPath: "/Users/you/"
                    + String(repeating: "very-deeply-nested-checkout/", count: 12)
                    + "node_modules/.bin/aws",
                emitterAssurance: "Unsigned",
                recipientDescription: "planned executable consumer",
                deliveryDescription: "Environment of the launched process",
                destinationDescription: "Child process environment"
            ),
            warnings: [
                "Unsigned executable: nothing vouches for this program. "
                    + String(repeating: "It was written to disk minutes before it asked. ", count: 6),
                "Synthetic Simulator request: nothing is resolved.",
            ],
            footnote: "Face ID authorizes this exact release. No secret values are shown on this iPhone.",
            scopeOptions: (1...4).map { index in
                .init(
                    id: "scope-\(index)",
                    title: "Scope \(index): "
                        + String(repeating: "a long description of what this covers ", count: 3),
                    detail: String(repeating: "and the processes it starts ", count: 8)
                )
            },
            defaultScopeID: "scope-1",
            durationOptions: [
                "While it runs", "5 minutes", "15 minutes", "30 minutes",
                "1 hour", "4 hours", "8 hours",
                "Until csecd restarts, however long that takes on this Mac",
            ],
            defaultDurationIndex: 0,
            operationDigest: digest("csec.simulator.long-access.v3")
        )
    }

    /// A server known under the most names a review may carry, a long user,
    /// key label and reference, and a long headline.
    private static func longSSHReview() -> RemoteApprovalReview {
        let references = ["csec://default/ssh/" + String(repeating: "deploy-", count: 30) + "key"]
        let host = "build-\(unbrokenToken.prefix(40)).eu-west-2.compute.internal"
        let hostNames = [host] + (2...16).map { "bastion-\($0).internal.example.com" }
        return RemoteApprovalReview(
            kind: .ssh,
            headline: "ssh -J bastion-2.internal.example.com "
                + String(repeating: "-o ServerAliveInterval=30 ", count: 10)
                + "deploy@\(host) "
                + headlineTail,
            callerDescription: "ssh (pid 5150) ← git (pid 5149) ← zsh ← iTerm2",
            terminalDescription: "iTerm2 · “deploy\u{FFFD}prod” · window 3, tab 11 · ttys017",
            // A key name the native store cannot parse is shown whole, in
            // grey, as the Mac shows it.
            secrets: references.map(whole),
            referenceSetDigest: digest(references.joined(separator: "\n")),
            delivery: .init(
                emitterName: "ssh",
                emitterPath: "/usr/bin/ssh",
                emitterAssurance: "Apple",
                recipientDescription: "SSH server at 198.51.100.23",
                deliveryDescription: "One signature through the csec SSH agent",
                destinationDescription: "SSH authentication"
            ),
            warnings: [
                "This server is known under 16 names. Check that the one you meant is among them.",
            ],
            footnote: "Your private key stays in Convenient Security. SSH receives only a signature.",
            ssh: .init(
                hostNames: hostNames,
                hostContext: "Recognized from known_hosts under 16 names.",
                unknownHost: false,
                remoteUser: "deploy-" + String(repeating: "x", count: 50),
                keyLabel: "deploy@ci " + String(repeating: "(rotated key) ", count: 10),
                keyAlgorithm: "Ed25519"
            ),
            scopeOptions: [
                .init(id: "connection", title: "This connection", detail: "One sign-in from ssh (pid 5150)"),
                .init(
                    id: "terminal-tab",
                    title: "This server from this terminal tab",
                    detail: "iTerm2 window 3, tab 11, until the tab closes"
                ),
            ],
            defaultScopeID: "connection",
            durationOptions: ["This sign-in only", "15 minutes", "1 hour"],
            defaultDurationIndex: 0,
            operationDigest: digest("csec.simulator.long-ssh.v3")
        )
    }

    /// What the Mac's providers say about a fixture reference: 1Password names
    /// account › vault › item › field, the native store this Mac › store › key.
    private static func onePassword(
        _ vault: String, _ item: String, _ field: String,
        account: String = "acme.1password.eu", notes: [String] = [], warnings: [String] = []
    ) -> ReviewSecret {
        ReviewSecret(
            provider: "1Password", tint: .teal, account: account, container: vault,
            item: item, field: field, notes: notes, warnings: warnings
        )
    }

    private static func native(_ store: String, _ key: String, notes: [String] = []) -> ReviewSecret {
        ReviewSecret(
            provider: "csec", tint: .purple, account: "this Mac", container: store,
            item: key, field: nil, itemIsIdentifier: true, notes: notes
        )
    }

    /// A reference no provider described, as the Mac sends it.
    private static func whole(_ reference: String) -> ReviewSecret {
        ReviewSecret(
            provider: nil, tint: .gray, account: nil, container: nil,
            item: reference, field: nil, itemIsIdentifier: true
        )
    }

    private static let restoreSection = RemoteApprovalReview.Restore(
        header: "Reopen 2 stores for 3 approvals csecd held before it restarted",
        footnote: "Nothing new is approved: this reopens what you had already approved on this Mac.",
        storeCount: 2,
        rows: [
            .init(
                kind: "secret_grant",
                title: "GITHUB_TOKEN for gh",
                detail: "iTerm2 · window 1, tab 1 · while the process runs",
                secrets: [native("default", "GITHUB_TOKEN")],
                ssh: nil
            ),
            .init(
                kind: "ssh_grant",
                title: "SSH to github.com",
                detail: "Terminal · window 2, tab 1 · for 1 hour",
                secrets: [native("ssh-keys", "github")],
                ssh: .init(
                    hostNames: ["github.com"],
                    hostContext: "Recognized from known_hosts.",
                    unknownHost: false,
                    remoteUser: "git",
                    keyLabel: "you@mac",
                    keyAlgorithm: "Ed25519"
                )
            ),
            .init(
                kind: "paired_project",
                title: "Claude Code project ~/src/app",
                detail: "Paired references, until you unpair the project",
                secrets: [onePassword("Development", "app", "API key")],
                ssh: nil
            ),
        ]
    )
}
#endif
