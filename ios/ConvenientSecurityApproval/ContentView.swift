import CSECRemoteApproval
import SwiftUI
import UIKit

struct ContentView: View {
    @EnvironmentObject private var model: ApprovalViewModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack {
            List {
                #if DEBUG && targetEnvironment(simulator)
                simulatorWarningSection
                #endif
                if model.phonePairingCode == nil {
                    setupSection
                } else {
                    approvalsSection
                    pairingSection
                    #if DEBUG && targetEnvironment(simulator)
                    simulatorActionsSection
                    #endif
                }
                if let message = model.message {
                    Section {
                        Text(message)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Approvals")
            .refreshable { await model.refresh() }
            .toolbar {
                if model.phonePairingCode != nil {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button {
                            Task { await model.refresh() }
                        } label: {
                            if model.isRefreshing {
                                ProgressView()
                            } else {
                                Image(systemName: "arrow.clockwise")
                            }
                        }
                        .disabled(model.isRefreshing)
                    }
                }
            }
            .onChange(of: scenePhase) { newPhase in
                guard newPhase == .active else { return }
                Task { await model.refresh() }
            }
        }
    }

    #if DEBUG && targetEnvironment(simulator)
    private var simulatorWarningSection: some View {
        Section {
            Label {
                VStack(alignment: .leading, spacing: 4) {
                    Text("SIMULATOR TEST MODE")
                        .font(.headline)
                    Text("Uses a software signing key. Approvals here are synthetic and provide no security.")
                        .font(.footnote)
                }
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
            .foregroundStyle(.orange)
        }
    }

    private var simulatorActionsSection: some View {
        Section("Simulator") {
            Button {
                model.injectSimulatorRequest()
            } label: {
                Label("Inject signed sample request", systemImage: "testtube.2")
            }
            Text("In Simulator, choose Features › Face ID › Enrolled, then use Matching Face or Non-matching Face when deciding.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
    #endif

    private var setupSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {
                Label("Approve Mac requests from this iPhone", systemImage: "iphone.and.arrow.forward")
                    .font(.headline)
                Text("Opt in once, pair one Mac, then its ordinary local prompt is mirrored here. Face ID gates every decision.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button("Set up this iPhone") {
                    model.setUpPhone()
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(.vertical, 6)
        }
    }

    @ViewBuilder
    private var approvalsSection: some View {
        Section("Pending") {
            if model.pending.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.shield")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("No pending approvals")
                        .font(.headline)
                    Text(
                        model.pinnedMacs.isEmpty
                            ? "Pair a Mac below to start."
                            : "New Mac prompts will appear here automatically."
                    )
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 22)
            } else {
                ForEach(model.pending) { item in
                    ApprovalCard(item: item)
                }
            }
        }
    }

    private var pairingSection: some View {
        Section("Pairing") {
            if !model.pinnedMacs.isEmpty {
                ForEach(model.pinnedMacs) { mac in
                    Label(mac.deviceName, systemImage: "laptopcomputer.and.iphone")
                }
            }

            DisclosureGroup("Pair another Mac") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("1. Copy this public phone code into `csec remote enable …` on the Mac.")
                        .font(.footnote)
                    if let code = model.phonePairingCode {
                        PairingCodeView(code: code, copyLabel: "Copy phone code")
                    }
                    Text("2. Paste the public Mac code returned after Touch ID.")
                        .font(.footnote)
                    TextEditor(text: $model.macPairingCode)
                        .font(.system(.caption2, design: .monospaced))
                        .frame(minHeight: 88)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(.quaternary)
                        )
                    Button("Accept Mac with Face ID") {
                        Task { await model.pairMac() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.macPairingCode.trimmingCharacters(
                        in: .whitespacesAndNewlines
                    ).isEmpty)
                }
                .padding(.vertical, 8)
            }
        }
    }
}

private struct PairingCodeView: View {
    let code: String
    let copyLabel: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ScrollView(.horizontal) {
                Text(code)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
            }
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
            Button {
                UIPasteboard.general.string = code
            } label: {
                Label(copyLabel, systemImage: "doc.on.doc")
            }
        }
    }
}

private struct ApprovalCard: View {
    @EnvironmentObject private var model: ApprovalViewModel
    let item: PendingRemoteApproval

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                Image(systemName: "lock.shield.fill")
                    .font(.title2)
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Secret Access Requested")
                        .font(.headline)
                    Text("“\(item.review.reason)”")
                        .font(.subheadline)
                }
                Spacer()
            }

            if let warning = item.review.warning {
                Label {
                    Text(warning)
                        .font(.caption.weight(.semibold))
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                }
                .foregroundStyle(.orange)
                .padding(10)
                .background(.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 9))
            }

            ForEach(Array(item.review.credentials.enumerated()), id: \.offset) { _, credential in
                CredentialView(credential: credential)
            }

            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 7) {
                detail("Requested by", item.review.callerDescription)
                detail("Emitted by", "\(item.review.emitterName) · \(item.review.emitterAssurance)")
                detail("Executable", item.review.emitterPath)
                detail("Delivered to", item.review.recipientDescription)
                detail("Delivery", item.review.deliveryDescription)
                detail("Grant root", item.review.grantRootDescription)
                detail("Destination", item.review.destinationDescription)
                detail("Duration", item.review.requestedDurationDescription)
                detail("Mac", item.mac.deviceName)
            }
            .font(.caption)

            TimelineView(.periodic(from: .now, by: 1)) { context in
                let remaining = max(0, Int(item.expiresAt.timeIntervalSince(context.date)))
                Text("Expires in \(remaining)s")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(remaining < 15 ? .red : .secondary)
            }

            HStack {
                Button("Deny", role: .destructive) {
                    Task { await model.decide(item, decision: .deny) }
                }
                .buttonStyle(.bordered)
                Spacer()
                Button {
                    Task { await model.decide(item, decision: .approve) }
                } label: {
                    Label("Approve", systemImage: "faceid")
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(.vertical, 8)
    }

    private func detail(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            Text(value)
                .gridColumnAlignment(.leading)
        }
    }
}

private struct CredentialView: View {
    let credential: RemoteApprovalReview.Credential

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            if let title = credential.title {
                Text(title).font(.subheadline.weight(.semibold))
            }
            if let subtitle = credential.subtitle {
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            ForEach(Array(credential.fields.enumerated()), id: \.offset) { _, field in
                Text(field)
                    .font(.system(.caption, design: .monospaced).weight(.medium))
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 5))
            }
            ForEach(Array(credential.rawReferences.enumerated()), id: \.offset) { _, reference in
                Text(reference)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 9))
    }
}
