import CSECRemoteApproval
import SwiftUI

/// What a card reads its state from and hands its decision to. The card
/// reaches nothing else: the paired list passes the real model, which signs
/// and publishes; the reviewer demo passes `DemoApprovals`, which can do
/// neither. So the card cannot reach the mailbox or the phone's keys except
/// through the host it was given.
@MainActor
protocol ApprovalCardHost: ObservableObject {
    var sentDecisions: [String: RemoteApprovalDecision] { get }
    var answersNotTaken: Set<String> { get }
    var decidingRequestID: String? { get }
    /// While true, every card's choices and buttons are frozen.
    var faceIDActionInProgress: Bool { get }
    /// Whether a decision here is sent to a Mac. Only the demo says no, and
    /// its card says so instead of "sent".
    var decisionsReachAMac: Bool { get }
    func decide(
        _ item: PendingRemoteApproval,
        decision: RemoteApprovalDecision,
        choice: RemoteApprovalChoice
    ) async
}

/// One mirrored request, laid out for its kind the way the Mac panel lays it
/// out. Everything shown comes from the verified, signed review; the scope and
/// lifetime shown selected are what an approval signs, frozen at the tap.
struct ApprovalCard<Host: ApprovalCardHost>: View {
    @ObservedObject private var model: Host
    @Environment(\.dynamicTypeSize) private var typeSize
    let item: PendingRemoteApproval
    @State private var choice: RemoteApprovalChoice

    init(item: PendingRemoteApproval, host: Host) {
        self.item = item
        _model = ObservedObject(wrappedValue: host)
        _choice = State(initialValue: RemoteApprovalChoice(defaultsOf: item.review))
    }

    private var review: RemoteApprovalReview { item.review }
    private var macName: String { item.mac.displayName }
    private var sentDecision: RemoteApprovalDecision? { model.sentDecisions[item.id] }
    private var isDecidingThis: Bool { model.decidingRequestID == item.id }
    /// Nothing on a card changes once it is being decided or has been sent.
    private var isFrozen: Bool { sentDecision != nil || model.faceIDActionInProgress }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header

            ForEach(Array(review.warnings.enumerated()), id: \.offset) { _, warning in
                WarningBanner(text: warning)
            }

            switch review.kind {
            case .ssh:
                if let ssh = review.ssh {
                    SSHSummary(ssh: ssh, warnings: review.warnings)
                }
            case .sudo:
                if let sudo = review.sudo {
                    SudoSummary(sudo: sudo)
                }
            case .restore:
                if let restore = review.restore {
                    RestoreSection(restore: restore, restoreOnly: true)
                }
            case .settings:
                if let settings = review.settings {
                    SettingsSummary(settings: settings)
                }
            case .access:
                EmptyView()
            }

            if !review.secrets.isEmpty {
                SecretTreeView(secrets: review.secrets)
                    .padding(10)
                    .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 9))
            }

            if review.kind == .access, let restore = review.restore {
                RestoreSection(restore: restore, restoreOnly: false)
            }

            details

            if item.request.unlockChallenge != nil {
                Label(
                    "Approving also opens csec's locked storage on \(macName) for this request. Face ID on this iPhone is the key.",
                    systemImage: "lock.open"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            if !review.scopeOptions.isEmpty {
                ScopePicker(options: review.scopeOptions, selection: $choice.scopeID)
                    .disabled(isFrozen)
            }
            if !review.durationOptions.isEmpty {
                DurationPicker(options: review.durationOptions, selection: $choice.durationIndex)
                    .disabled(isFrozen)
            }

            if let footnote = review.footnote {
                Text(footnote)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .wrapping()
            }

            // Why Claude Code auto mode did not approve this, and, while the
            // selection is the one that pairs, what approving also allows:
            // the Mac panel's two lines, by the rule csecd checks the
            // signed answer against.
            if let note = review.delegation?.note {
                Text(note)
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .wrapping()
                    .accessibilityIdentifier("delegation-note")
            }
            if let pairing = review.delegation?.pairing,
               review.pairingLineApplies(scopeID: choice.scopeID, durationIndex: choice.durationIndex) {
                Text(pairing.line)
                    .font(.footnote.weight(.medium))
                    .foregroundStyle(.secondary)
                    .wrapping()
                    .accessibilityIdentifier("pairing-line")
            }

            waitingLine
            deadlineLine
            if model.answersNotTaken.contains(item.id) {
                Label(
                    "Your answer was not accepted. \(macName) is still waiting: decide again.",
                    systemImage: "arrow.uturn.backward.circle"
                )
                .font(.caption)
                .foregroundStyle(.orange)
            }
            actions
        }
        .padding(.vertical, 8)
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: kindSymbol)
                .font(.title2)
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(kindTitle)
                    .font(.headline)
                    .wrapping()
                    .accessibilityAddTraits(.isHeader)
                Text("From \(macName)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .wrapping()
                ExpandableText(text: "“\(review.headline)”", font: .subheadline)
                // Under the reason its program wrote, that program's own
                // command line, read by csecd: the Mac panel's line.
                if let command = review.requesterCommand {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Process command line")
                            .font(.caption.weight(.medium))
                            .foregroundStyle(.secondary)
                        ExpandableText(text: command, font: .system(.subheadline, design: .monospaced))
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("requester-command")
                }
                if let terminal = review.terminalDescription {
                    Label(terminal, systemImage: "terminal")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("Terminal: \(terminal)")
                }
            }
        }
    }

    /// Shared with the notification, so the alert and the card agree.
    private var kindTitle: String {
        RemoteApprovalNotificationText.kindTitle(review.kind)
    }

    private var kindSymbol: String {
        switch review.kind {
        case .access: return "lock.shield.fill"
        case .ssh: return "key.fill"
        case .sudo: return "terminal.fill"
        case .restore: return "arrow.clockwise.circle.fill"
        case .settings: return "gearshape.fill"
        }
    }

    // MARK: - Facts

    private var details: some View {
        VStack(alignment: .leading, spacing: 8) {
            FactRow(label: "Requested by", value: review.callerDescription)
            if let delivery = review.delivery {
                FactRow(
                    label: "Emitted by",
                    value: "\(delivery.emitterName) · \(delivery.emitterAssurance)"
                )
                FactRow(label: "Executable", value: delivery.emitterPath, monospaced: true)
                FactRow(label: "Delivered to", value: delivery.recipientDescription)
                FactRow(label: "Delivery", value: delivery.deliveryDescription)
                FactRow(label: "Destination", value: delivery.destinationDescription)
            }
        }
    }

    // How long the Mac has been waiting. When it will stop waiting, for a
    // request that has a deadline, is the line below.
    private var waitingLine: some View {
        HStack(spacing: 4) {
            Image(systemName: "clock")
                .accessibilityHidden(true)
            Text("Waiting for")
            Text(item.createdAt, style: .relative)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .accessibilityElement(children: .combine)
    }

    // The Mac panel's deadline line, in its words (`ReviewDeadlineText`):
    // when the Mac closes this request if nobody answers, then a countdown
    // for the last 30 seconds. Only a request with a deadline (a coding
    // agent's, a sudo) has one, and only until an answer is sent, as the Mac
    // panel retires its line on a decision. The close itself is the Mac's
    // withdrawal, which takes the card away and says so; this line decides
    // nothing, and the buttons stay as they are until then.
    @ViewBuilder
    private var deadlineLine: some View {
        if let closesAt = item.closesAt, sentDecision == nil {
            let now = Date()
            TimelineView(.explicit([now] + ReviewDeadlineText.changes(closesAt: closesAt, from: now))) { context in
                let line = ReviewDeadlineText.line(closesAt: closesAt, now: context.date)
                Label(line.text, systemImage: line.isCountdown ? "timer" : "hourglass")
                    .font(line.isCountdown ? .caption.weight(.semibold) : .caption)
                    .foregroundStyle(line.isCountdown ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                    .wrapping()
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("review-deadline")
            }
        }
    }

    // MARK: - Actions

    @ViewBuilder
    private var actions: some View {
        if let sentDecision {
            Label(sentLine(sentDecision), systemImage: sentDecision == .approve
                ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(sentDecision == .approve ? .green : .secondary)
        } else {
            Group {
                if typeSize.isAccessibilitySize {
                    // Side by side, an accessibility size would squeeze the
                    // titles; stacked, each button gets the full width.
                    VStack(alignment: .leading, spacing: 10) {
                        approveButton
                        refuseButton
                        if isDecidingThis { ProgressView() }
                    }
                } else {
                    HStack {
                        refuseButton
                        Spacer()
                        if isDecidingThis { ProgressView() }
                        approveButton
                    }
                }
            }
            .disabled(model.faceIDActionInProgress)
        }
    }

    private var refuseTitle: String {
        item.isRestoreOnly ? "Forget these approvals" : "Deny"
    }

    private var approveTitle: String {
        item.isRestoreOnly ? "Reopen" : "Approve"
    }

    private var refuseButton: some View {
        Button(role: .destructive) {
            decide(.deny)
        } label: {
            Text(refuseTitle)
        }
        .buttonStyle(.bordered)
        .accessibilityLabel(
            item.isRestoreOnly
                ? "Forget these approvals on \(macName)"
                : "Deny the request from \(macName)"
        )
        .accessibilityHint(decisionHint)
    }

    private var approveButton: some View {
        Button {
            decide(.approve)
        } label: {
            FaceIDLabel(title: approveTitle)
        }
        .buttonStyle(.borderedProminent)
        .accessibilityLabel(
            item.isRestoreOnly
                ? "Reopen these approvals on \(macName)"
                : "Approve the request from \(macName)"
        )
        .accessibilityHint(decisionHint)
    }

    private var decisionHint: String {
        model.decisionsReachAMac
            ? "Asks for Face ID, then sends the decision."
            : "Asks for Face ID. This is a demo: nothing is sent."
    }

    private func decide(_ decision: RemoteApprovalDecision) {
        // The selection is copied here, at the tap: this is what gets signed.
        let frozenChoice = choice
        Task { await model.decide(item, decision: decision, choice: frozenChoice) }
    }

    private func sentLine(_ decision: RemoteApprovalDecision) -> String {
        guard model.decisionsReachAMac else {
            switch decision {
            case .approve: return "Approved in the demo — nothing was sent"
            case .deny: return "Denied in the demo — nothing was sent"
            }
        }
        switch (decision, item.isRestoreOnly) {
        case (.approve, true): return "Reopened — sent to \(macName)"
        case (.deny, true): return "Forgotten — sent to \(macName)"
        case (.approve, false): return "Approved — sent to \(macName)"
        case (.deny, false): return "Denied — sent to \(macName)"
        }
    }
}

// MARK: - Kind sections

private struct SSHSummary: View {
    let ssh: RemoteApprovalReview.SSH
    let warnings: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text("HOST")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(ssh.hostTitle)
                    .font(.title2.weight(.semibold))
                    .wrapping()
                    .foregroundStyle(ssh.unknownHost ? Color.orange : Color.primary)
                    .accessibilityLabel("Host: \(ssh.hostTitle)")
                if ssh.unknownHost {
                    Label("UNKNOWN HOST", systemImage: "exclamationmark.octagon.fill")
                        .font(.subheadline.weight(.bold))
                        .foregroundStyle(.red)
                }
                Text("Sign in as \(ssh.remoteUser)")
                    .font(.subheadline)
                Text(ssh.hostContext)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .wrapping()
                if ssh.hostNames.count > 2 {
                    Text("Known hosts: \(ssh.hostNames.joined(separator: ", "))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .wrapping()
                }
            }
            // The Mac puts the unknown-host explanation in the review's
            // warnings; say it here too if a review ever arrives without it.
            if ssh.unknownHost, !warnings.contains(where: { $0.contains("UNKNOWN HOST") }) {
                WarningBanner(
                    text: "UNKNOWN HOST: No name in your known_hosts matches this server's identity. That is expected only for a first connection to a new server, or after the server changed its host key — if neither applies, deny.",
                    tint: .red
                )
            }
            Divider()
            VStack(alignment: .leading, spacing: 4) {
                Text("SSH KEY")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(ssh.keyLabel)
                    .font(.headline)
                    .wrapping()
                Text(ssh.keyAlgorithm)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 12))
    }
}

private struct SudoSummary: View {
    let sudo: RemoteApprovalReview.Sudo

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("sudo wants to run this command with administrator privileges.")
                .font(.subheadline)
                .wrapping()
            ExpandableText(
                text: sudo.command,
                font: .system(.subheadline, design: .monospaced)
            )
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 9))
            FactRow(label: "Working directory", value: sudo.workingDirectory, monospaced: true)
            if let targetUser = sudo.targetUser {
                FactRow(label: "Run as", value: targetUser)
            }
        }
    }
}

/// A change to csec's settings, under its title: what approving changes,
/// one line each, as the Mac panel's settings layout lists them.
private struct SettingsSummary: View {
    let settings: RemoteApprovalReview.Settings

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("CHANGES")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            ForEach(Array(settings.changes.enumerated()), id: \.offset) { _, change in
                Label {
                    Text(change)
                        .font(.subheadline)
                        .wrapping()
                } icon: {
                    Image(systemName: "circle.fill")
                        .font(.system(size: 5))
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("settings-change")
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 9))
    }
}

private struct RestoreSection: View {
    let restore: RemoteApprovalReview.Restore
    /// A restore-only review approves nothing new; a release that also
    /// reopens says so under its own request.
    let restoreOnly: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(restore.header)
                .font(restoreOnly ? .headline : .subheadline.weight(.semibold))
                .wrapping()
            Text(restoreOnly ? "APPROVALS TO REOPEN" : "ALSO REOPENS, AFTER CSECD RESTARTED")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            ForEach(Array(restore.rows.enumerated()), id: \.offset) { _, row in
                RestoreRowView(row: row)
            }
            Text(restore.footnote)
                .font(.caption)
                .foregroundStyle(.secondary)
                .wrapping()
        }
    }
}

private struct RestoreRowView: View {
    let row: RemoteApprovalReview.RestoreRow

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(.secondary)
                .accessibilityLabel(kindName)
            VStack(alignment: .leading, spacing: 3) {
                Text(row.title)
                    .font(.subheadline.weight(.semibold))
                    .wrapping()
                Text(row.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .wrapping()
                // As on the Mac: a signing grant states its SSH facts, any
                // other grant its secrets, named as a release names them.
                if let ssh = row.ssh {
                    Text("SSH as \(ssh.remoteUser) to \(ssh.hostTitle) using \(ssh.keyLabel)")
                        .font(.caption)
                        .wrapping()
                } else {
                    SecretTreeView(secrets: row.secrets)
                        .padding(.top, 2)
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 9))
    }

    private var symbol: String {
        switch row.kind {
        case "secret_grant": return "key.fill"
        case "ssh_grant": return "network"
        case "paired_project": return "folder.fill"
        default: return "questionmark.circle"
        }
    }

    private var kindName: String {
        switch row.kind {
        case "secret_grant": return "Secret approval"
        case "ssh_grant": return "SSH approval"
        case "paired_project": return "Paired project"
        default: return row.kind
        }
    }
}

// MARK: - Secrets

/// A review's secrets as the Mac panel draws them (`ReviewSecretTree`): each
/// source, a provider and the account it resolves from, once; its vaults or
/// stores beneath it, a single one sharing the source's line; and each item a
/// label in its source's colour, its fields beside it.
struct SecretTreeView: View {
    let secrets: [ReviewSecret]

    var body: some View {
        let tree = ReviewSecretTree(secrets)
        VStack(alignment: .leading, spacing: 12) {
            ForEach(Array(tree.sources.enumerated()), id: \.offset) { _, source in
                SecretSourceView(source: source)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct SecretSourceView: View {
    let source: ReviewSecretTree.Source
    private let indent: CGFloat = 16

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            if source.title == nil {
                // References no provider described: listed bare, under no source.
                ForEach(Array(source.containers.enumerated()), id: \.offset) { _, container in
                    SecretContainerBody(container: container, tint: source.tint)
                }
            } else if source.foldsContainer, let container = source.containers.first {
                sourceLine(container: container.name)
                SecretContainerBody(container: container, tint: source.tint)
                    .padding(.leading, indent)
            } else {
                sourceLine(container: nil)
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(Array(source.containers.enumerated()), id: \.offset) { _, container in
                        VStack(alignment: .leading, spacing: 5) {
                            if let name = container.name {
                                Text(name)
                                    .font(.subheadline.weight(.medium))
                                    .wrapping()
                            }
                            SecretContainerBody(container: container, tint: source.tint)
                                .padding(.leading, container.name == nil ? 0 : indent)
                        }
                    }
                }
                .padding(.leading, indent)
            }
        }
    }

    /// "● 1Password · acme.1password.eu › Employee".
    private func sourceLine(container: String?) -> some View {
        var dot = AttributedString("●  ")
        dot.foregroundColor = SecretLabelColors.text(source.tint)
        dot.font = .system(size: 8)
        var line = dot
        if let provider = source.provider {
            var name = AttributedString(provider)
            name.font = .caption.weight(.semibold)
            line += name
        }
        if let account = source.account {
            line += AttributedString(source.provider == nil ? account : " · \(account)")
        }
        if let container {
            var chevron = AttributedString("  ›  ")
            chevron.foregroundColor = Color(.tertiaryLabel)
            var name = AttributedString(container)
            name.foregroundColor = .primary
            name.font = .caption.weight(.medium)
            line += chevron + name
        }
        return Text(line)
            .font(.caption)
            .foregroundStyle(.secondary)
            .wrapping()
            .accessibilityLabel(
                [source.title, container].compactMap { $0 }.joined(separator: ", ")
            )
    }
}

private struct SecretContainerBody: View {
    let container: ReviewSecretTree.Container
    let tint: ReviewSecretTint

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            ForEach(Array(container.warnings.enumerated()), id: \.offset) { _, warning in
                WarningBanner(text: warning)
            }
            ForEach(Array(container.notes.enumerated()), id: \.offset) { _, note in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Image(systemName: "info.circle")
                        .accessibilityHidden(true)
                    Text(note)
                        .wrapping()
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            // As on the Mac: items with fields take a row each; items that are
            // themselves the secret (a store's keys) wrap left to right.
            ForEach(Array(itemRuns.enumerated()), id: \.offset) { _, run in
                if run.count == 1, !run[0].fields.isEmpty {
                    SecretItemRow(item: run[0], tint: tint)
                } else {
                    SecretFlowLayout(spacing: 6) {
                        ForEach(Array(run.enumerated()), id: \.offset) { _, item in
                            SecretItemRow(item: item, tint: tint)
                        }
                    }
                }
            }
        }
    }

    /// The items in order, each with fields alone and consecutive items
    /// without fields together.
    private var itemRuns: [[ReviewSecretTree.Item]] {
        var runs: [[ReviewSecretTree.Item]] = []
        for item in container.items {
            if item.fields.isEmpty, let last = runs.last, last.allSatisfy(\.fields.isEmpty) {
                runs[runs.count - 1].append(item)
            } else {
                runs.append([item])
            }
        }
        return runs
    }
}

/// Lays out labels left to right, wrapping to a new row when the next would
/// overflow the width.
private struct SecretFlowLayout: Layout {
    var spacing: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        var widest: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(ProposedViewSize(width: width, height: nil))
            if x > 0, x + size.width > width {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
            widest = max(widest, x - spacing)
        }
        return CGSize(width: proposal.width ?? widest, height: subviews.isEmpty ? 0 : y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var rowHeight: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(ProposedViewSize(width: bounds.width, height: nil))
            if x > bounds.minX, x + size.width > bounds.maxX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            view.place(
                at: CGPoint(x: x, y: y),
                proposal: ProposedViewSize(width: min(size.width, bounds.width), height: size.height)
            )
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}

/// One item: its label, its fields at the right on the same line, or on the
/// next line, right-aligned, when both do not fit.
private struct SecretItemRow: View {
    let item: ReviewSecretTree.Item
    let tint: ReviewSecretTint

    var body: some View {
        Group {
            if item.fields.isEmpty {
                label
            } else {
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .center, spacing: 12) {
                        label.fixedSize()
                        Spacer(minLength: 12)
                        fields.fixedSize()
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        label
                        fields.frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
            }
        }
    }

    private var label: some View {
        Text(item.name)
            .font(item.isIdentifier
                ? .system(.subheadline, design: .monospaced).weight(.semibold)
                : .subheadline.weight(.semibold))
            .foregroundStyle(SecretLabelColors.text(tint))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(SecretLabelColors.fill(tint), in: RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(SecretLabelColors.edge(tint), lineWidth: 1))
            .wrapping()
            .accessibilityLabel(item.spokenName)
            .accessibilityIdentifier("secret-label-\(tint.rawValue)")
    }

    private var fields: some View {
        Text(item.fields.joined(separator: " · "))
            .font(.system(.caption, design: .monospaced))
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.trailing)
            .wrapping()
    }
}

/// A label's colours for `tint` in the current appearance, from the values the
/// Mac panel draws with too (`ReviewSecretTint.palette`).
enum SecretLabelColors {
    static func text(_ tint: ReviewSecretTint) -> Color { color(tint) { ($0.text, 1) } }
    static func fill(_ tint: ReviewSecretTint) -> Color { color(tint) { ($0.base, $0.fillAlpha) } }
    static func edge(_ tint: ReviewSecretTint) -> Color { color(tint) { ($0.base, $0.edgeAlpha) } }

    private static func color(
        _ tint: ReviewSecretTint,
        _ pick: @escaping @Sendable (ReviewSecretTint.Palette) -> (ReviewSecretTint.RGB, Double)
    ) -> Color {
        Color(uiColor: UIColor { traits in
            let (rgb, alpha) = pick(tint.palette(dark: traits.userInterfaceStyle == .dark))
            return UIColor(red: rgb.red, green: rgb.green, blue: rgb.blue, alpha: alpha)
        })
    }
}

// MARK: - Choices

private struct ScopePicker: View {
    let options: [RemoteApprovalReview.ScopeOption]
    @Binding var selection: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("SCOPE")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            ForEach(options, id: \.id) { option in
                Button {
                    selection = option.id
                } label: {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: selection == option.id
                            ? "largecircle.fill.circle" : "circle")
                            .foregroundStyle(.tint)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(option.title)
                                .font(.subheadline.weight(.medium))
                                .foregroundStyle(.primary)
                                .wrapping()
                            Text(option.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .wrapping()
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .contentShape(Rectangle())
                }
                // Plain, not borderless: the option's text keeps its own
                // colours, and the button still answers only its own taps.
                .buttonStyle(.plain)
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(selection == option.id ? .isSelected : [])
            }
        }
    }
}

private struct DurationPicker: View {
    let options: [String]
    @Binding var selection: UInt16?
    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        let layout = typeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 4))
            : AnyLayout(HStackLayout())
        layout {
            Text("For")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            if !typeSize.isAccessibilitySize { Spacer() }
            Picker("For", selection: $selection) {
                ForEach(Array(options.enumerated()), id: \.offset) { index, title in
                    Text(title).tag(Optional(UInt16(index)))
                }
            }
            .pickerStyle(.menu)
            .labelsHidden()
        }
        .accessibilityElement(children: .contain)
    }
}

// MARK: - Building blocks

private struct FactRow: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(monospaced ? .system(.subheadline, design: .monospaced) : .subheadline)
                .textSelection(.enabled)
                .wrapping()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

struct WarningBanner: View {
    let text: String
    var tint: Color = .orange

    var body: some View {
        Label {
            Text(text)
                .font(.subheadline.weight(.semibold))
                .wrapping()
                .frame(maxWidth: .infinity, alignment: .leading)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill")
        }
        .foregroundStyle(tint)
        .padding(10)
        .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Warning: \(text)")
    }
}

/// Full text, collapsed to a few lines when long, with a control to expand it.
private struct ExpandableText: View {
    let text: String
    var font: Font = .body
    var collapsedLineLimit = 4
    @State private var expanded = false

    private var isLong: Bool {
        text.count > 180 || text.filter(\.isNewline).count >= collapsedLineLimit
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(text)
                .font(font)
                .lineLimit(expanded || !isLong ? nil : collapsedLineLimit)
                .textSelection(.enabled)
                .wrapping()
                .frame(maxWidth: .infinity, alignment: .leading)
            if isLong {
                Button(expanded ? "Show less" : "Show all") {
                    expanded.toggle()
                }
                .buttonStyle(.borderless)
                .font(.caption)
            }
        }
    }
}

/// A button title with the Face ID glyph. Not a `Label`: a prominent button
/// draws a label's icon in the tint colour, invisible against its
/// tint-coloured fill, while glyph and text in one stack share the button's
/// foreground.
struct FaceIDLabel: View {
    let title: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "faceid")
                .accessibilityHidden(true)
            Text(title)
        }
    }
}

extension View {
    /// Multi-line text nested inside a List row's sub-views otherwise gets a
    /// single line and an ellipsis; this sizes it to its full height.
    func wrapping() -> some View {
        fixedSize(horizontal: false, vertical: true)
    }
}

extension RemoteApprovalReview.SSH {
    /// The Mac panel's host headline: up to two known_hosts names, or
    /// "Unknown host".
    var hostTitle: String {
        guard !hostNames.isEmpty else { return "Unknown host" }
        let shown = hostNames.prefix(2).joined(separator: ", ")
        return hostNames.count > 2 ? "\(shown) (+\(hostNames.count - 2) more)" : shown
    }
}
