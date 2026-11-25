import CSECRemoteApproval
import Foundation
#if canImport(AppKit)
@preconcurrency import AppKit
#endif

/// One logical credential shown in a trusted access-policy review. It carries
/// value-free reference metadata only — never a resolved value, and (after the
/// risk-level collapse) no classification or acceptance state.
public struct PolicyReviewCredential: Sendable {
    public let references: [SecretRef]
    /// How the review names each reference, in `references` order: its
    /// provider's own description, made display-safe, or the whole reference
    /// when no provider described it. The core never interprets them; it
    /// draws them (`ReviewSecretTree`).
    public let secrets: [ReviewSecret]

    /// References no provider has described, each shown whole.
    public init(references: [SecretRef]) {
        self.init(described: references.map { ($0, ReviewDisplay.undescribedSecret($0)) })
    }

    /// References with the description each one is shown by.
    public init(described: [(reference: SecretRef, secret: ReviewSecret)]) {
        let sorted = described.sorted { $0.reference.uri < $1.reference.uri }
        self.references = sorted.map(\.reference)
        self.secrets = sorted.map(\.secret)
    }
}

/// Display-only SSH facts supplied by the signing service after it verifies the
/// destination binding. Names are known_hosts matches, never authorization keys.
public struct SSHAccessReviewDetails: Sendable, Equatable {
    public let hostNames: [String]
    public let remoteUser: String
    public let keyLabel: String
    public let keyAlgorithm: String

    public init(hostNames: [String], remoteUser: String, keyLabel: String, keyAlgorithm: String) {
        self.hostNames = SSHKnownHostsLookup.safeNames(hostNames)
        self.remoteUser = ReviewDisplay.bounded(ReviewDisplay.sanitized(remoteUser), maxBytes: 64)
        let label = ReviewDisplay.bounded(ReviewDisplay.sanitized(keyLabel), maxBytes: 256)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        self.keyLabel = label.isEmpty ? "SSH key" : label
        switch keyAlgorithm {
        case "ssh-ed25519": self.keyAlgorithm = "Ed25519"
        case "ssh-rsa": self.keyAlgorithm = "RSA"
        case "ecdsa-sha2-nistp256": self.keyAlgorithm = "ECDSA P-256"
        case "ecdsa-sha2-nistp384": self.keyAlgorithm = "ECDSA P-384"
        case "ecdsa-sha2-nistp521": self.keyAlgorithm = "ECDSA P-521"
        default: self.keyAlgorithm = "SSH"
        }
    }

    public var hostTitle: String {
        guard !hostNames.isEmpty else { return "Unknown host" }
        let shown = hostNames.prefix(2).joined(separator: ", ")
        return hostNames.count > 2 ? "\(shown) (+\(hostNames.count - 2) more)" : shown
    }

    public var hostContext: String {
        switch hostNames.count {
        case 0: return "No hostname found in known_hosts."
        case 1: return "Recognized from known_hosts."
        default: return "These known hosts share the same server identity."
        }
    }

    public var reason: String {
        // The mirrored phone review has a 512-byte reason limit. Keep both
        // primary facts in that copy even when their full desktop labels wrap.
        let host = ReviewDisplay.bounded(hostTitle, maxBytes: 256)
        let key = ReviewDisplay.bounded(keyLabel, maxBytes: 128)
        return "SSH to \(host) as \(remoteUser) using \(key)"
    }
}

/// One approval a restore panel reopens. Display-only and value-free; the
/// panel renders every kind the same way (a title, a detail line, reference
/// pills, and the SSH tuple when there is one), so a new kind of restorable
/// approval is a new `Kind` plus the code that lists it.
public struct RestoreReviewRow: Sendable, Equatable {
    public enum Kind: String, Sendable, Equatable {
        /// A secret grant restored from the persisted grants item.
        case secretGrant
        /// An SSH signing grant restored from the persisted grants item.
        case sshGrant
        /// A project a human paired with Claude Code auto mode, whose
        /// references a live verified Claude Code session there needs.
        case pairedProject
    }

    /// The SSH facts a restored signing grant is bound to.
    public struct SSH: Sendable, Equatable {
        public let hostTitle: String
        public let remoteUser: String
        public let keyLabel: String
        /// The known_hosts names matching the server's identity; empty for an
        /// unknown host. The phone review carries them as the SSH layout does.
        public let hostNames: [String]
        public let hostContext: String
        public let keyAlgorithm: String

        public init(hostTitle: String, remoteUser: String, keyLabel: String) {
            self.hostTitle = ReviewDisplay.bounded(ReviewDisplay.sanitized(hostTitle), maxBytes: 256)
            self.remoteUser = ReviewDisplay.bounded(ReviewDisplay.sanitized(remoteUser), maxBytes: 64)
            self.keyLabel = ReviewDisplay.bounded(ReviewDisplay.sanitized(keyLabel), maxBytes: 256)
            // Only the title is known: it names the host unless it says there
            // is none.
            let unknown = SSHAccessReviewDetails(
                hostNames: [], remoteUser: remoteUser, keyLabel: keyLabel, keyAlgorithm: ""
            )
            self.hostNames = self.hostTitle == unknown.hostTitle ? [] : [self.hostTitle]
            self.hostContext = self.hostNames.isEmpty ? unknown.hostContext : "Recognized from known_hosts."
            self.keyAlgorithm = unknown.keyAlgorithm
        }

        /// The row for a signing grant whose facts the signing service verified.
        public init(_ details: SSHAccessReviewDetails) {
            self.hostTitle = ReviewDisplay.bounded(ReviewDisplay.sanitized(details.hostTitle), maxBytes: 256)
            self.remoteUser = ReviewDisplay.bounded(ReviewDisplay.sanitized(details.remoteUser), maxBytes: 64)
            self.keyLabel = ReviewDisplay.bounded(ReviewDisplay.sanitized(details.keyLabel), maxBytes: 256)
            self.hostNames = details.hostNames
            self.hostContext = details.hostContext
            self.keyAlgorithm = details.keyAlgorithm
        }
    }

    public let kind: Kind
    /// Who the approval was for: the grant root's label.
    public let title: String
    /// What it covers: the scope the human chose when approving.
    public let detail: String
    /// Canonical reference URIs (for an SSH grant, its key's reference).
    public let references: [String]
    /// How the row names each of `references`, in the same order: as a
    /// release names its secrets once `described(by:)` has the providers'
    /// descriptions, the whole reference before.
    public let secrets: [ReviewSecret]
    public let ssh: SSH?

    public init(kind: Kind, title: String, detail: String, references: [String], ssh: SSH? = nil) {
        self.kind = kind
        self.title = ReviewDisplay.bounded(ReviewDisplay.sanitized(title), maxBytes: 256)
        self.detail = ReviewDisplay.bounded(ReviewDisplay.sanitized(detail), maxBytes: 512)
        self.references = references.sorted()
        self.secrets = self.references.map { uri in
            (try? SecretRef(uri)).map(ReviewDisplay.undescribedSecret)
                ?? ReviewSecret(
                    provider: nil, tint: .gray, account: nil, container: nil,
                    item: ReviewDisplay.bounded(ReviewDisplay.sanitized(uri), maxBytes: 1_024),
                    field: nil, itemIsIdentifier: true
                )
        }
        self.ssh = ssh
    }

    private init(copying row: RestoreReviewRow, secrets: [ReviewSecret]) {
        kind = row.kind
        title = row.title
        detail = row.detail
        references = row.references
        self.secrets = secrets
        ssh = row.ssh
    }

    /// The same row naming its references by `describe`, a reference's
    /// display-safe provider description keyed by its URI; a reference
    /// missing from it keeps its whole-reference form.
    public func described(by describe: [String: ReviewSecret]) -> RestoreReviewRow {
        RestoreReviewRow(
            copying: self,
            secrets: zip(references, secrets).map { uri, current in describe[uri] ?? current }
        )
    }
}

/// The restore section of a review: what csecd approved before it restarted
/// and must reopen with one touch. It is a variant of the secret-access
/// surface; a restore approves nothing new, so it carries no scope or duration
/// choice. It reaches the paired phone exactly when a phone approval could
/// reopen every row: each reference that needs an unlock is covered by the
/// phone-held unlock factor (`MirroredPolicyReview`); otherwise it stays on
/// this Mac, whose touch is the only thing that could reopen it.
public struct RestoreReviewDetails: Sendable, Equatable {
    /// Why the previous csecd stopped, when it is known.
    public let cause: CsecdRestartCause?
    public let rows: [RestoreReviewRow]
    /// How many sealed stores the touch reopens.
    public let storeCount: Int

    public init(cause: CsecdRestartCause?, rows: [RestoreReviewRow], storeCount: Int) {
        self.cause = cause
        self.rows = rows
        self.storeCount = storeCount
    }

    public var header: String {
        switch cause {
        case let known? where [.upgrade, .restart, .crash, .reboot].contains(known):
            return "csecd restarted (\(known.rawValue)): reopen what you approved"
        default:
            return "csecd restarted: reopen what you approved"
        }
    }

    /// The restore-only panel's footnote: that touch approves nothing new.
    public var footnote: String {
        "Touch ID reopens \(storeCount) store\(storeCount == 1 ? "" : "s"). Nothing new is approved."
    }

    /// The restore section's note on a mixed panel, whose touch also approves
    /// the new request above it, so it must not say nothing new is approved.
    public var mixedFootnote: String {
        "Touch ID also reopens \(storeCount) store\(storeCount == 1 ? "" : "s") for approvals "
            + "you already made. Deny refuses this request and forgets these approvals too."
    }

    /// The label of the refusing button on a restore-only panel.
    public static let forgetButtonTitle = "Forget these approvals"
}

/// The line a panel shows when approving it would also pair its references
/// with a Claude Code project: only for a Claude Code secret request
/// delegation declined, and only while the window's selection is exactly the
/// default Claude Code scope for the process's lifetime (the conditions under
/// which csecd writes the pairing). An approval pairs only when the surface it
/// was made on showed this line (`AccessPolicyApproval.pairingLineShown`).
public struct DelegationPairingOffer: Sendable, Equatable {
    /// The project directory's name, sanitized.
    public let projectName: String
    /// The scope option whose selection pairs: the default Claude Code one.
    public let scopeOptionID: String
    /// The pairing is csecd's use of the references (`daemon_proxy`), which
    /// holds for auto mode in every project, not only `projectName`.
    public let everyProject: Bool
    /// When the pairing starts to count, for a decline pairing cannot end
    /// (`DelegationDecline.pairingCondition`); nil when it counts at once.
    public let condition: String?

    public init(projectName: String, scopeOptionID: String, everyProject: Bool = false, condition: String? = nil) {
        self.projectName = ReviewDisplay.bounded(ReviewDisplay.sanitized(projectName), maxBytes: 128)
        self.scopeOptionID = scopeOptionID
        self.everyProject = everyProject
        self.condition = condition.map { ReviewDisplay.bounded(ReviewDisplay.sanitized($0), maxBytes: 256) }
    }

    public var line: String {
        let when = condition ?? "until you revoke them"
        return everyProject
            ? "Approving also lets Claude Code auto mode use these, inside csec, in every project \(when)"
            : "Approving also lets Claude Code auto mode use these in \(projectName) \(when)"
    }

    /// Whether the window's current selection would pair.
    public func applies(scopeOptionID selected: String?, duration: GrantDuration?) -> Bool {
        selected == scopeOptionID && duration == .processLifetime
    }
}

/// A change to csec's own settings — turning on Claude Code auto-mode
/// approvals, trusting a Claude Code build, acknowledging hooks or classifier
/// rules — shown as the settings layout of the secret-access panel. It
/// releases nothing and names no secret. Only this Mac's Touch ID makes it,
/// except the acknowledgement csecd raises for a request (the rules- and
/// hooks-changed panel), which the paired phone may also decide
/// (`phoneOperationDigest`).
///
/// These changes used to be a bare Touch ID sheet, which macOS draws and csec
/// cannot guard: a sheet that came up while the human was typing took the
/// next Space as its Deny. In the panel, keyboard focus rests on
/// `PromptKeyboardSink` and Deny waits out `PromptInteractionGrace`, as on
/// every other csec approval.
public struct SettingsChangeReviewDetails: Sendable, Equatable {
    public static let maximumChanges = 6
    public static let maximumChangeBytes = 640

    /// The panel's headline, naming the kind of change.
    public let title: String
    /// What approving changes, one line each, sanitized and bounded; the
    /// callers already cap how many items one line lists.
    public let changes: [String]
    /// What the touch does, under the changes. Most changes are to csec's
    /// settings (`settingsFootnote`); a restore, a host fix or the uninstall
    /// cleanup is not, and says what it is instead.
    public let footnote: String
    /// SHA-256 over exactly what approving does, present only for a change
    /// the paired phone may decide as well as this Mac: the rules- and
    /// hooks-changed acknowledgement csecd raises for a request whose human
    /// may be away from this Mac (av-rcqg). The phone's signed answer is
    /// bound to it. Nil keeps the change at this Mac
    /// (`AccessPolicyReview.macOnly`): setup run at its terminal is decided
    /// there. The initializer drops it when the change is not shown whole
    /// (a line cut short, lines left out) or it is not 32 bytes.
    public let phoneOperationDigest: Data?

    public init(
        title: String, changes: [String], footnote: String = Self.settingsFootnote,
        phoneOperationDigest: Data? = nil
    ) {
        self.title = ReviewDisplay.fitted(title, maxBytes: 128)
        let bounded = changes.prefix(Self.maximumChanges).map {
            ReviewDisplay.fitted($0, maxBytes: Self.maximumChangeBytes)
        }
        let rest = changes.count - bounded.count
        self.changes = rest > 0 ? bounded + ["and \(rest) more change\(rest == 1 ? "" : "s")"] : bounded
        self.footnote = ReviewDisplay.fitted(footnote, maxBytes: Self.maximumChangeBytes)
        // The phone decides only a change shown whole: none of it cut short
        // or left out, and a digest that can be what it signs over.
        let whole = rest == 0
            && zip(changes, bounded).allSatisfy { ReviewDisplay.sanitized($0) == $1 }
            && ReviewDisplay.sanitized(title) == self.title && ReviewDisplay.sanitized(footnote) == self.footnote
        self.phoneOperationDigest = whole && phoneOperationDigest?.count == 32 ? phoneOperationDigest : nil
    }

    public static let settingsFootnote =
        "Touch ID approves exactly these changes to Convenient Security's settings. No secret is released."
    public static let sectionLabel = "Changes"
    public static let readyAction = "approve these changes"
}

/// Complete value-free context for the review window owned by csecd.
public struct AccessPolicyReview: Sendable {
    public let caller: CallerInfo
    public let reason: String
    public let plan: DeliveryPlan
    /// The launcher's full command as one display-ready line: already passed
    /// through csecd's output redaction against every value it has released,
    /// sanitized, and bounded. Nil when the request carried no argv (a `csec
    /// get`, SSH signing, a native-store edit), in which case `reason` is the
    /// headline.
    public let commandLine: String?
    /// For a request with no argv of its own whose plan root is the
    /// requester's direct parent (a language client over `csec bridge`, a
    /// `csec get`): that requester's own command line, read by csecd from the
    /// kernel by pid and start time, never claimed by the request, and
    /// display-ready exactly like `commandLine` (redacted, sanitized,
    /// bounded). Shown under `reason`, which the requester wrote itself, so a
    /// request that is not what its reason says can be seen to be. Untrusted
    /// metadata: never identity or policy input. Nil when it could not be
    /// read, and on SSH, automation and restore-only reviews.
    public let requesterCommandLine: String?
    public let credentials: [PolicyReviewCredential]
    /// Present only for explicit attended enrollment of a persistent unattended
    /// job. It carries value-free job metadata and is never inferred from access.
    public let automation: AutomationReviewDetails?
    /// The grant roots csecd resolved from live kernel ancestry above this
    /// request, with the pre-selected default. Nil when the reviewer must not
    /// offer a choice (automation enrollment) or none could be resolved.
    public let scopeChoices: GrantScopeChoices?
    /// The grant lifetimes the reviewer may choose between, defaulting to the
    /// requested TTL. Nil when the lifetime is not the human's to choose
    /// (automation enrollment, which lasts until it is revoked).
    public let durationChoices: GrantDurationChoices?
    /// Present only for a verified SSH signing request. The trusted window uses
    /// these facts directly rather than parsing an arbitrary reason string.
    public let ssh: SSHAccessReviewDetails?
    /// Present when the review also reopens what csecd approved before it
    /// restarted. With no credentials it is a restore-only panel; with them,
    /// one panel carries both the new release and the restore.
    public let restore: RestoreReviewDetails?
    /// Why Claude Code auto mode did not approve this request on its own.
    /// Set only for a Claude Code request with delegated approvals on, and
    /// shown on the secret-access and SSH layouts only: never on a
    /// restore-only panel or in the automation layout.
    public let delegationNote: DelegationDecline?
    /// The pairing line's offer; see `DelegationPairingOffer`.
    public let pairingOffer: DelegationPairingOffer?
    /// Decided on this Mac's panel only, never mirrored to the paired phone:
    /// setup the person is doing at this Mac's terminal — a native-store edit
    /// or import, registering SSH keys — whose writes to sealed storage only a
    /// local Touch ID can make, and every settings change without a
    /// `phoneOperationDigest`. Automation enrollment is Mac-only through
    /// `automation`.
    public let macOnly: Bool
    /// Present only for a change to csec's own settings
    /// (`SettingsChangeReviewDetails`): no credentials, scope, lifetime,
    /// delegation note or pairing line, and `macOnly` unless the change may
    /// be decided on the phone (`phoneOperationDigest`).
    public let settingsChange: SettingsChangeReviewDetails?
    /// Present only on the review of a GitHub request that can give lasting
    /// access, through csecd's GitHub socket: it covers that one request, so
    /// the panel offers no wider scope or lifetime, and its warning names
    /// the request and what it can add.
    public let githubLastingAccess: GitHubLastingAccess?

    public init(
        caller: CallerInfo,
        reason: String,
        plan: DeliveryPlan,
        commandLine: String? = nil,
        requesterCommandLine: String? = nil,
        credentials: [PolicyReviewCredential],
        automation: AutomationReviewDetails? = nil,
        scopeChoices: GrantScopeChoices? = nil,
        durationChoices: GrantDurationChoices? = nil,
        ssh: SSHAccessReviewDetails? = nil,
        restore: RestoreReviewDetails? = nil,
        delegationNote: DelegationDecline? = nil,
        pairingOffer: DelegationPairingOffer? = nil,
        macOnly: Bool = false,
        settingsChange: SettingsChangeReviewDetails? = nil,
        githubLastingAccess: GitHubLastingAccess? = nil
    ) {
        self.caller = caller
        self.reason = reason
        self.plan = plan
        self.commandLine = commandLine
        self.credentials = credentials
        self.automation = automation
        self.scopeChoices = scopeChoices
        self.durationChoices = durationChoices
        self.ssh = ssh
        self.restore = restore
        self.settingsChange = settingsChange
        self.githubLastingAccess = plan.mechanism == .daemonProxy && ssh == nil && automation == nil
            ? githubLastingAccess : nil
        // A settings change is decided at this Mac only, like other setup,
        // unless it names the operation a phone approval is bound to.
        self.macOnly = macOnly || (settingsChange != nil && settingsChange?.phoneOperationDigest == nil)
        // A panel that approves nothing new carries neither.
        let restoreOnly = restore != nil && credentials.isEmpty
        let noRelease = restoreOnly || automation != nil || settingsChange != nil
        self.delegationNote = noRelease ? nil : delegationNote
        self.pairingOffer = noRelease ? nil : pairingOffer
        // Only the release layout draws it, under a reason it stands beside.
        self.requesterCommandLine = commandLine == nil && !noRelease && ssh == nil
            ? requesterCommandLine : nil
    }

    /// A panel that only reopens restored approvals: no new release, so no
    /// scope, duration, delegation note or pairing line.
    public var isRestoreOnly: Bool { restore != nil && credentials.isEmpty }

    /// The review a settings-change panel shows. The plan is display-only, as
    /// a restore-only panel's is: nothing is delivered.
    public static func settingsChange(
        caller: CallerInfo, change: SettingsChangeReviewDetails
    ) -> AccessPolicyReview {
        AccessPolicyReview(
            caller: caller,
            reason: change.title,
            plan: DeliveryPlan(
                mechanism: .directHeap,
                executable: PlannedExecutable(canonicalPath: "csecd", assurance: .verifiedProduct),
                root: .caller,
                descendantScope: .exactProcess,
                destination: .localDevelopment,
                requestedTTLSeconds: nil,
                operationContext: "change csec's settings"
            ),
            credentials: [],
            settingsChange: change
        )
    }

    /// The review a restore-only panel shows. The plan is display-only: the
    /// restore layout states the rows it reopens, not a delivery.
    public static func restoreOnly(caller: CallerInfo, restore: RestoreReviewDetails) -> AccessPolicyReview {
        AccessPolicyReview(
            caller: caller,
            reason: restore.header,
            plan: DeliveryPlan(
                mechanism: .directHeap,
                executable: PlannedExecutable(canonicalPath: "csecd", assurance: .verifiedProduct),
                root: .caller,
                descendantScope: .exactProcess,
                destination: .localDevelopment,
                requestedTTLSeconds: nil,
                operationContext: "reopen approvals after csecd restarted"
            ),
            credentials: [],
            restore: restore
        )
    }
}

/// Value-free copy for the trusted review window and tests. It never accepts a
/// path, argv, reference value, or resolved secret, so warnings cannot disclose
/// the redirection target or plaintext. The one request it names, a lasting
/// GitHub request's method and API path, is csecd's own parse of what it is
/// about to send, and the review's reason names it too.
public enum DeliveryReviewCopy {
    public static let automationWarningTitle = "Unattended access until you revoke it"
    public static let automationWarningExplanation =
        "Touch ID creates device-only copies that this mutable job can use without asking again. Anyone who can change its command, scripts, dependencies, working directory, arguments, or ordinary environment can obtain these secrets on its next run."

    /// Shown when no `known_hosts` name matches the server's verified host key.
    /// The server identity is still cryptographically bound to the grant; what
    /// is missing is any evidence that the human has met this server before.
    /// Value-free: it names the condition, never the host-key fingerprint.
    public static let unknownHostWarning =
        "UNKNOWN HOST: No name in your known_hosts matches this server's identity. That is expected only for a first connection to a new server, or after the server changed its host key — if neither applies, deny."

    /// The footnote of a secret release's panel.
    public static let releaseFootnote =
        "Touch ID authorizes this exact release. No secret values are shown in this window."
    /// The footnote of an SSH signing panel.
    public static let sshFootnote =
        "Your private key stays in Convenient Security. SSH receives only a signature."
    /// The footnote of a panel for a value csecd uses on the requester's
    /// behalf (the GitHub token proxy): nothing is released to it.
    public static let daemonUseFootnote =
        "The token stays in Convenient Security, which adds it to this program's GitHub requests. The program receives only GitHub's responses."

    /// The footnote a panel shows under its facts, one source for the Mac
    /// window and the phone review: a restore-only panel's says what its touch
    /// reopens, an SSH panel's that only a signature leaves csecd, a release's
    /// that the touch authorizes exactly it. The automation layout has none.
    public static func footnote(for review: AccessPolicyReview) -> String? {
        if review.automation != nil { return nil }
        if let change = review.settingsChange { return change.footnote }
        if review.isRestoreOnly { return review.restore?.footnote }
        if review.ssh != nil { return sshFootnote }
        return review.plan.mechanism == .daemonProxy ? daemonUseFootnote : releaseFootnote
    }

    public static func recipientDescription(for plan: DeliveryPlan) -> String {
        switch plan.recipientAssurance {
        case .interactiveTerminal:
            return "requesting terminal (interactive human output)"
        case .unverifiedPipeReader:
            return "unverified pipe reader (identity unavailable; delegated by the shell)"
        case .ordinaryPersistentFile:
            return "ordinary persistent file (unverified; potentially same-user readable)"
        case nil:
            return "planned executable consumer"
        }
    }

    /// The warning shown in the trusted window for a same-user-inspectable
    /// delivery. Touch ID authorizes it; this text is the WYSIWYG signal that
    /// lets a human decline. For a non-interactive `csec get` (no controlling
    /// terminal — an agent, script, or logger is capturing the output) it also
    /// steers toward the injection commands, which never return the value here.
    ///
    /// An SSH signing review has no `recipientAssurance` to switch on — the
    /// recipient is a verified server, not a local reader — so its one warning
    /// condition is an unrecognized server identity, checked before the plan.
    public static func warning(for review: AccessPolicyReview) -> String? {
        // A restore-only panel releases nothing to anyone: it reopens stores.
        // Nor does a settings change.
        if review.isRestoreOnly || review.settingsChange != nil { return nil }
        if review.automation != nil {
            return "\(automationWarningTitle): \(automationWarningExplanation)"
        }
        if let ssh = review.ssh, ssh.hostNames.isEmpty {
            return unknownHostWarning
        }
        // csecd's own description of the GitHub request it parsed: method,
        // host and path, never a value, and what the request can add.
        if let lasting = review.githubLastingAccess { return lasting.warning }
        let plan = review.plan
        let base: String
        switch plan.recipientAssurance {
        case .unverifiedPipeReader:
            base = "UNVERIFIED PIPE READER: The requesting shell delegates csec's output, but generic Unix pipelines do not reveal or authenticate the sibling process that reads it. That reader can retain or forward the plaintext."
        case .ordinaryPersistentFile:
            base = "PERSISTENT PLAINTEXT FILE: Plaintext will persist in an ordinary file. Other processes running as you may be able to read it. Convenient Security cannot control copying, backups, synchronization, or later access."
        case .interactiveTerminal:
            base = "TERMINAL PLAINTEXT: The value will be printed to the requesting terminal and may be retained by terminal logging, scrollback, or screen capture."
        case nil:
            return nil
        }
        if (plan.mechanism == .rawStandardOutput || plan.mechanism == .namedPlaintextFile)
            && !plan.interactive {
            return base + "\n\nNo interactive terminal is attached — a coding agent, script, or logger appears to be capturing this output and would receive the value. Prefer csec exec, exec-file, or a credential helper, which hand the value to the consuming tool without returning it here."
        }
        return base
    }
}

/// Where a human answered a review: this Mac's own trusted panel, or the paired
/// iPhone. A delegation pairing rests on `AccessPolicyApproval
/// .pairingLineShown`, which only a human surface that drew the pairing line
/// sets, never on the absence of a phone.
public enum HumanDecisionSurface: String, Sendable, Equatable, CaseIterable {
    /// The Mac panel: its window, or Apple's Touch ID sheet over it.
    case mac
    /// The paired iPhone, verified by its pinned key.
    case phone
}

/// The result of a trusted access review. After the collapse there are no policy
/// choices to return — a successful biometric IS the authorization — so this
/// carries only the optional embedded authentication session used to unlock a
/// cold cache or native-store key with the same Touch ID.
public struct AccessPolicyApproval: Sendable {
    /// A trusted review authenticates inside its own window and retains the
    /// evaluated context so a cold cached value or native-store key can be
    /// unlocked by the same biometric. Injected/headless reviewers leave this
    /// nil and use the ordinary ConsentProvider instead.
    public let authenticationSession: (any AccessPolicyAuthenticationSession)?
    /// Which `GrantScopeOption` the human had selected when the biometric
    /// succeeded. A lookup hint only: the agent resolves it against the list it
    /// computed itself and re-verifies ancestry, so an unknown value falls back
    /// to the displayed default and can never widen the grant.
    public let selectedScopeOptionID: String?
    /// Which grant-lifetime menu option the human had selected when the biometric
    /// succeeded, as an index into the offered `GrantDurationChoices.options`.
    /// A hint only: the agent resolves it against the choices it offered, so an
    /// out-of-range index falls back to the displayed default and can never
    /// lengthen the grant.
    public let selectedDurationIndex: Int?
    /// How long the panel was on screen before the biometric succeeded, from
    /// its most recent presentation (the first, or the re-present after an
    /// unlock). Recorded in the decision log as the time to decision; never
    /// used to authorize anything. Nil when no panel measured it.
    public let decisionLatency: Duration?
    /// Whether the surface the human approved on showed the review's pairing
    /// line (`DelegationPairingOffer`) at the moment of approval: the Mac
    /// panel from the line's own visibility when Touch ID succeeded, the phone
    /// from its signed acknowledgement, which csecd checked against the
    /// signed selection. Only then may approving pair. False from every other
    /// reviewer.
    public let pairingLineShown: Bool
    /// Where the human approved: `.mac` from the trusted panel, `.phone` from
    /// the paired iPhone, nil from an injected or headless reviewer that is no
    /// human surface at all. Nil is never taken as the Mac.
    public let decidedOn: HumanDecisionSurface?

    public init(
        authenticationSession: (any AccessPolicyAuthenticationSession)? = nil,
        selectedScopeOptionID: String? = nil,
        selectedDurationIndex: Int? = nil,
        decisionLatency: Duration? = nil,
        pairingLineShown: Bool = false,
        decidedOn: HumanDecisionSurface? = nil
    ) {
        self.authenticationSession = authenticationSession
        self.selectedScopeOptionID = selectedScopeOptionID
        self.selectedDurationIndex = selectedDurationIndex
        self.decisionLatency = decisionLatency
        self.pairingLineShown = pairingLineShown
        self.decidedOn = decidedOn
    }
}

/// The completion seam of a trusted access review. Production starts Touch ID in
/// the review window and, on success, retains the evaluated context here; the
/// agent calls `completeAfterPolicyApproval` to release it, or `cancel` to
/// invalidate it. Injected/headless reviewers leave this unused. This is a
/// dependency-injection seam, like PolicyReviewProvider and ConsentProvider.
public protocol AccessPolicyAuthenticationSession: Sendable {
    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome
    func cancel() async
}

/// Why a trusted access review ended without an approval.
///
/// Only `.human` is a decision about the request. It is the one reason that
/// refuses the identical requests already waiting behind it and ends an SSH
/// connection's signing. The other two say nothing about whether the human
/// would allow the request, so they never affect any other request.
public enum AccessPolicyDenialReason: Sendable, Equatable {
    /// The human refused: the Deny button (or Escape), closing the window, the
    /// "Deny" button of Apple's Touch ID sheet, or a Deny on the paired phone.
    ///
    /// `decidedAt` is when the refusal was made (or, for the phone, when this
    /// Mac accepted the verified Deny, before withdrawing the phone's request),
    /// on the monotonic clock `HumanDenialLedger` stamps
    /// arrivals with. It orders the Deny against other requests — only those
    /// that arrived before it are the question it answered — because the
    /// outcome can reach the service much later: the mirrored review waits
    /// for the phone's CloudKit request to be withdrawn first. It is never
    /// compared with the present, so it is not an expiry.
    ///
    /// `on` is where the human refused; nil from an injected reviewer that is
    /// no human surface. `shownAt` is when the Mac panel the human answered
    /// was last put in front of them (its first presentation, or the
    /// re-present after an unlock), on the same clock, so the decision log can
    /// record the time to decision; nil when no panel measured it, including
    /// every phone Deny, since this Mac cannot know when the phone showed its
    /// copy. Neither authorizes or refuses anything.
    case human(
        decidedAt: ContinuousClock.Instant,
        on: HumanDecisionSurface? = nil,
        shownAt: ContinuousClock.Instant? = nil
    )
    /// The requester went away while its review waited or was on screen: its
    /// connection closed, or its process exited before an unlock re-present or
    /// a focus renewal (`ReviewFocusRecovery`).
    case requesterGone
    /// The requester went away while its review waited on the shared UI queue,
    /// before any panel was shown. Logged as a `withdrawn` record, never as a
    /// panel.
    case withdrawn
    /// Nobody decided before a coding agent's request reached its deadline
    /// (`HumanWait`), so the request was withdrawn, queued or on screen.
    /// Not a human refusal: it answers no other request.
    case timedOut
    /// Touch ID ended with an error that is neither a human refusal nor a
    /// screen-lock cancel (a locked screen waits and re-presents instead), or
    /// the review could not be shown at all.
    case authenticationFailed
}

public extension AccessPolicyDenialReason {
    /// The words every unapproved review's failure starts with. Sessions and
    /// their supervisors match on them, so the reason follows them rather than replacing
    /// them.
    static let deniedPrefix = "policy review denied"

    /// How the review ended, value-free, for the requester. A bare "denied"
    /// reads as the human refusing, so a session would treat a failed Touch
    /// ID as a decision and not ask again; these say which it was, in the
    /// decision log's terms (`DecisionLogRecord.outcome(for:)`).
    var endedText: String {
        switch self {
        case let .human(_, on, _):
            switch on {
            case .mac: return "the human refused it on the Mac (Deny, Escape or closing the panel)"
            case .phone: return "the human refused it on the paired iPhone"
            case nil: return "the reviewer refused it"
            }
        case .requesterGone:
            return "the request went away while its panel was up"
        case .withdrawn:
            return "the request went away before its panel was shown"
        case .timedOut:
            return "nobody answered in time, so csec withdrew the request"
        case .authenticationFailed:
            return "Touch ID ended without approving, or the panel could not be shown; "
                + "nobody pressed Deny, so this is not a refusal (`csec log` has the outcome)"
        }
    }

    func deniedMessage(prefix: String = deniedPrefix) -> String {
        "\(prefix): \(endedText)"
    }
}

public enum AccessPolicyReviewOutcome: Sendable {
    case denied(AccessPolicyDenialReason)
    case approved(AccessPolicyApproval)
}

public protocol PolicyReviewProvider: Sendable {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome
    /// Present the batched host-remediation checklist (one review, one Touch ID).
    /// Defaulted so existing reviewers need no change.
    func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome
    /// Where `review` could be answered if it were presented now, judged
    /// before the requester is told it is waiting (`QueuedPolicyReview`).
    /// Never prompts and releases nothing. Defaulted: a reviewer that does
    /// not judge it leaves the notice as it was.
    func approvalReach(for review: AccessPolicyReview) async -> ApprovalReach
}

public extension PolicyReviewProvider {
    func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        .denied
    }

    func approvalReach(for review: AccessPolicyReview) async -> ApprovalReach {
        .notJudged
    }
}

/// A reviewer's judgement of where a review can be answered. A mirrored
/// review keeps the phone's readiness with it, so a request presented at
/// once is judged once, and the notice and the panel cannot disagree.
public enum ApprovalReach: Sendable, Equatable {
    case notJudged
    /// The paired phone's readiness (`MirroredPolicyReview`) at that moment.
    case judged(RemoteReviewReadiness)

    /// What the requester's notice says: only a judged `.unavailable` keeps
    /// the request on the Mac.
    public var place: HumanWait.Place? {
        switch self {
        case .notJudged: return nil
        case .judged(.unavailable): return .macOnly
        case .judged(.ready): return .macOrPhone
        }
    }

    /// The judgement a reviewer may reuse at presentation: bound by
    /// `QueuedPolicyReview` only for a request that did not wait in the
    /// queue, since one that waited is judged again when its turn comes.
    @TaskLocal public static var prejudged: ApprovalReach?
}

/// Test-only reviewer. It is constructor-injected and is not selectable through
/// shipping arguments or environment variables.
public struct AutoApprovePolicyReview: PolicyReviewProvider {
    public init() {}

    public func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        FileHandle.standardError.write(Data(
            "⚠️  AutoApprovePolicyReview: approving value-free policy metadata WITHOUT a human. DEV ONLY.\n".utf8
        ))
        return .approved(AccessPolicyApproval())
    }

    public func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        FileHandle.standardError.write(Data(
            "⚠️  AutoApprovePolicyReview: approving host remediation WITHOUT a human. DEV ONLY.\n".utf8
        ))
        return .approved(selectedKeys: review.items.map(\.key))
    }
}

/// AppKit review rendered by the authenticated resident agent. The window shows
/// only value-free metadata and embeds Touch ID in that same trusted surface;
/// there are no editable policy controls, so a successful biometric is itself
/// the authorization. csecd owns the display and the decision.
public struct TrustedPolicyReview: PolicyReviewProvider {
    private let touchID: ReviewTouchIDOverride?

    /// `touchID` stands in for a Mac that cannot take a touch, for the preview
    /// tool only; csecd passes none.
    public init(touchID: ReviewTouchIDOverride? = nil) {
        self.touchID = touchID
    }

    public func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
        return await TrustedAccessReviewSession.present(review, touchID: touchID)
        #else
        return .denied(.authenticationFailed)
        #endif
    }

    /// The fixes the terminal picker selected, in the settings layout of the
    /// secret-access panel (`HostRemediationReview.change`): typing-guarded
    /// like every other approval, where Apple's bare sheet took a Space typed
    /// as it appeared as its refusal. Touch ID approves exactly the selection.
    public func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
        guard !review.items.isEmpty, !Task.isCancelled else { return .denied }
        let shown = AccessPolicyReview.settingsChange(caller: review.caller, change: review.change)
        guard case let .approved(approval) = await TrustedAccessReviewSession.present(shown, touchID: touchID),
              let session = approval.authenticationSession,
              case let .approved(unlock) = await session.completeAfterPolicyApproval(policySummary: "host remediation")
        else { return .denied }
        // Applying the fixes reads nothing the touch could unlock.
        unlock?.invalidate()
        return Task.isCancelled ? .denied : .approved(selectedKeys: review.items.map(\.key))
        #else
        return .denied
        #endif
    }
}
