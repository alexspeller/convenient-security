import CSECRemoteApproval
import SwiftUI
import UIKit

struct ContentView: View {
    @EnvironmentObject private var model: ApprovalViewModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var macToUnpair: PinnedMac?
    /// The reviewer demo (`DemoView`), pushed from the unpaired screens.
    @State private var showingDemo = false
    #if DEBUG && !targetEnvironment(simulator)
    @State private var spikeOutput = ""
    #endif

    private static let pendingAnchor = "pending-anchor"

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                List {
                    #if DEBUG && targetEnvironment(simulator)
                    simulatorWarningSection
                    if model.setup == .ready, let mailbox = SimulatedMailbox.shared {
                        // At the top, where it is reached without scrolling
                        // past the cards.
                        Section {
                            SimulatedMailboxControls(mailbox: mailbox)
                        }
                    }
                    #endif
                    if let outcome = model.outcome {
                        outcomeSection(outcome)
                    }
                    switch model.setup {
                    case .loading:
                        Section {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                        }
                    case .notSetUp:
                        setupSection(
                            title: "Approve Mac requests from this iPhone",
                            explanation: "Pair once with your Mac, and its approval prompts appear here as well. Face ID decides every one. Setting up creates two keys in this iPhone's Secure Enclave, both locked to your current Face ID, for one Face ID.",
                            button: "Set up this iPhone"
                        )
                        demoSection
                    case .outdated:
                        setupSection(
                            title: "Set up this iPhone again",
                            explanation: "This iPhone was set up by an earlier version of Convenient Security. That setup has no key for opening csec's locked storage on your Mac, and your Mac no longer accepts it. Set this iPhone up again, then pair your Mac again with csec remote enable and the new code.",
                            button: "Set up this iPhone again"
                        )
                    case let .temporarilyUnavailable(status):
                        unavailableSection(status: status)
                    case .unusable:
                        setupSection(
                            title: "Set up this iPhone again",
                            explanation: "This iPhone's approval keys can no longer be used — for example, its stored records were damaged. Set it up again, then pair your Mac again with csec remote enable and the new code.",
                            button: "Set up this iPhone again"
                        )
                    case .ready:
                        if let candidate = model.pairingCandidate, candidate.offered {
                            offeredPairingSection(candidate)
                        }
                        notificationSection
                        alertSubscriptionSection
                        settledSubscriptionSection
                        approvalsSection
                        pairedMacsSection
                        pairingSection
                        #if DEBUG && targetEnvironment(simulator)
                        simulatorActionsSection
                        #endif
                    }
                    #if DEBUG && !targetEnvironment(simulator)
                    spikeSection
                    #endif
                    privacySection
                }
                .onChange(of: model.pendingFocusRequest) { _ in
                    withAnimation {
                        proxy.scrollTo(model.pendingFocusTarget ?? Self.pendingAnchor, anchor: .top)
                    }
                }
                .onAppear {
                    // An alert tap that launched the app can be handled
                    // before this list first appears.
                    if model.pendingFocusRequest > 0 {
                        proxy.scrollTo(model.pendingFocusTarget ?? Self.pendingAnchor, anchor: .top)
                    }
                }
            }
            .navigationTitle("Approvals")
            .refreshable { await model.refresh() }
            .navigationDestination(isPresented: $showingDemo) {
                DemoView()
            }
            .toolbar {
                if model.setup == .ready {
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
                        .accessibilityLabel("Refresh approvals")
                    }
                }
            }
            .onChange(of: scenePhase) { newPhase in
                switch newPhase {
                case .active:
                    Task { await model.sceneBecameActive() }
                case .background:
                    model.stopWatchingForPairingOffers()
                default:
                    break
                }
            }
            .confirmationDialog(
                "Unpair \(macToUnpair?.displayName ?? "this Mac")?",
                isPresented: Binding(
                    get: { macToUnpair != nil },
                    set: { if !$0 { macToUnpair = nil } }
                ),
                titleVisibility: .visible,
                presenting: macToUnpair
            ) { mac in
                Button("Unpair with Face ID", role: .destructive) {
                    Task { await model.unpair(mac) }
                }
            } message: { mac in
                Text("This iPhone stops showing the requests of \(mac.displayName) (key \(mac.fingerprint)). Also run csec remote disable on the Mac: until then it keeps sending requests here.")
            }
        }
        #if DEBUG && targetEnvironment(simulator)
        // On the stack, not the list, so the demo it pushes keeps it too.
        .safeAreaInset(edge: .bottom, spacing: 0) {
            SimulatorCountersView(
                instrumentation: SimulatorInstrumentation.shared,
                notifications: model.notifications
            )
        }
        #endif
    }

    // MARK: - Privacy policy

    /// App Review asks for the privacy policy inside the app as well as on
    /// its App Store page (guideline 5.1.1(i)), so it is on every screen of
    /// the list, set up or not.
    private var privacySection: some View {
        Section {
            Link("Privacy policy", destination: Self.privacyPolicyURL)
        }
    }

    static let privacyPolicyURL = URL(string: "https://convenientsecurity.app/privacy")!

    // MARK: - Status

    private func outcomeSection(_ outcome: ApprovalOutcome) -> some View {
        Section {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: outcomeSymbol(outcome.tone))
                    .foregroundStyle(outcomeTint(outcome.tone))
                    .accessibilityHidden(true)
                Text(outcome.text)
                    .font(.subheadline)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    model.dismissOutcome()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Dismiss message")
            }
        }
    }

    private func outcomeSymbol(_ tone: ApprovalOutcome.Tone) -> String {
        switch tone {
        case .success: return "checkmark.circle.fill"
        case .info: return "info.circle.fill"
        case .failure: return "exclamationmark.circle.fill"
        }
    }

    private func outcomeTint(_ tone: ApprovalOutcome.Tone) -> Color {
        switch tone {
        case .success: return .green
        case .info: return .blue
        case .failure: return .red
        }
    }

    /// iCloud refused the subscription that alerts this iPhone to a request.
    /// Notification permission cannot fix that, so it is shown whatever the
    /// permission is.
    @ViewBuilder
    private var alertSubscriptionSection: some View {
        if let problem = model.subscriptionProblem {
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Requests won't alert this iPhone", systemImage: "bell.slash")
                        .font(.headline)
                        .foregroundStyle(.orange)
                    Text("iCloud refused the subscription that raises an alert for a request from your Mac, so requests appear only when you open this app. csec status on the Mac reports it after your next Face ID here. iCloud said: \(problem)")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }
        }
    }

    /// iCloud refused the subscription that tells this iPhone a request is
    /// over. Shown only while alerts themselves work: with the alert
    /// subscription refused too, that line says more.
    @ViewBuilder
    private var settledSubscriptionSection: some View {
        if model.subscriptionProblem == nil, let problem = model.settledSubscriptionProblem {
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Answered requests may stay on this iPhone", systemImage: "bell.badge")
                        .font(.headline)
                        .foregroundStyle(.orange)
                    Text("iCloud refused the subscription that tells this iPhone a request is over, so an alert for a request already answered, and its count on the app icon, can stay until you open this app or the next alert arrives. iCloud said: \(problem)")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }
        }
    }

    @ViewBuilder
    private var notificationSection: some View {
        switch model.notifications {
        case .notDetermined:
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Allow notifications", systemImage: "bell.badge")
                        .font(.headline)
                    Text("With notifications on, a request from your Mac alerts this iPhone while the app is closed. Once the request's Mac signature verifies, the alert shows what it asks for: the kind of request, the Mac, the command and who asked. An alert can come late or not at all, so opening this app always shows every request waiting.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Button("Allow notifications") {
                        Task { await model.requestNotificationAuthorization() }
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.vertical, 4)
            }
        case .off:
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Notifications are off", systemImage: "bell.slash")
                        .font(.headline)
                        .foregroundStyle(.orange)
                    Text("Requests from your Mac appear only when you open this app, so a request can wait on your Mac without you knowing. Turn on Allow Notifications, with alerts, for Convenient Security in Settings.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Button("Open Settings") {
                        openNotificationSettings()
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.vertical, 4)
            }
        case .enabled, .unknown:
            if model.pushRegistrationFailed {
                Section {
                    Label(
                        "This iPhone could not register for push notifications, so requests appear only when you open this app.",
                        systemImage: "exclamationmark.triangle"
                    )
                    .font(.subheadline)
                    .foregroundStyle(.orange)
                }
            }
        }
    }

    private func openNotificationSettings() {
        if let url = URL(string: UIApplication.openNotificationSettingsURLString) {
            UIApplication.shared.open(url)
        }
    }

    // MARK: - Setup

    private func setupSection(title: String, explanation: String, button: String) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {
                Label(title, systemImage: "iphone.and.arrow.forward")
                    .font(.headline)
                Text(explanation)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button {
                    Task { await model.setUpPhone() }
                } label: {
                    FaceIDLabel(title: button)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.faceIDActionInProgress)
            }
            .padding(.vertical, 6)
        }
    }

    // MARK: - Demo

    /// Before setup: the demo needs no keys and makes none.
    private var demoSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 10) {
                Text("No Mac to pair yet? See what a request looks like and how Face ID decides it, with sample requests that never leave this iPhone.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                demoButton
            }
            .padding(.vertical, 6)
        }
    }

    /// Only while no Mac is paired, so a sample is never shown beside a real
    /// request.
    private var demoButton: some View {
        Button {
            showingDemo = true
        } label: {
            Label("Try a demo request", systemImage: "play.rectangle")
        }
        .buttonStyle(.bordered)
        .disabled(model.faceIDActionInProgress)
    }

    /// The records exist but could not be read just now. Nothing is offered
    /// that would replace them: reading again is the whole fix.
    private func unavailableSection(status: Int32) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {
                Label("Approvals are not available yet", systemImage: "lock.iphone")
                    .font(.headline)
                // The status as a code, not a localized number ("-25,308").
                Text("This iPhone's approval records could not be read just now (Keychain status \(String(status))). That usually means the iPhone has not been unlocked since it restarted. Nothing needs setting up again: unlock the iPhone and try again.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button("Try again") {
                    Task { await model.retryLoadingIdentity() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.faceIDActionInProgress)
                #if DEBUG && targetEnvironment(simulator)
                // The Simulator's stand-in for unlocking the iPhone.
                Button("Stop refusing Keychain reads (Simulator)") {
                    SimulatorKeychainRefusal.shared.isOn = false
                }
                .buttonStyle(.bordered)
                #endif
            }
            .padding(.vertical, 6)
        }
    }

    // MARK: - Pending

    @ViewBuilder
    private var approvalsSection: some View {
        Section {
            if model.pending.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.shield")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                    Text("No pending approvals")
                        .font(.headline)
                    Text(
                        model.pinnedMacs.isEmpty
                            ? "Pair a Mac below to start."
                            : "New requests from your Mac appear here."
                    )
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    if model.pinnedMacs.isEmpty {
                        demoButton
                            .padding(.top, 6)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 22)
                .id(Self.pendingAnchor)
            } else {
                ForEach(model.pending) { item in
                    ApprovalCard(item: item, host: model)
                        .id(item.id)
                }
            }
        } header: {
            Text("Pending")
        } footer: {
            if let problem = model.relayProblem {
                Label(problem, systemImage: "icloud.slash")
            }
        }
    }

    // MARK: - Pairing

    private var pairedMacsSection: some View {
        Section("Paired Macs") {
            if model.pinnedMacs.isEmpty {
                Text("No Mac is paired with this iPhone yet.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            ForEach(model.pinnedMacs) { mac in
                VStack(alignment: .leading, spacing: 6) {
                    Label(mac.displayName, systemImage: "laptopcomputer")
                        .font(.headline)
                    Text("Mac key \(mac.fingerprint)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("paired-mac-key")
                    if !mac.confirmationDelivered {
                        Label(
                            "The pairing confirmation has not reached iCloud yet. It is sent automatically; until then the Mac keeps waiting.",
                            systemImage: "icloud.and.arrow.up"
                        )
                        .font(.caption)
                        .foregroundStyle(.orange)
                    }
                    Button(role: .destructive) {
                        macToUnpair = mac
                    } label: {
                        Text("Unpair…")
                    }
                    .buttonStyle(.borderless)
                    .disabled(model.faceIDActionInProgress)
                    .accessibilityLabel("Unpair \(mac.displayName), key \(mac.fingerprint)")
                }
                .padding(.vertical, 4)
            }
        }
    }

    /// A Mac's offer, at the top where it is seen without opening the
    /// pairing steps.
    private func offeredPairingSection(_ candidate: MacPairingCandidate) -> some View {
        Section("A Mac asks to pair") {
            PairingCandidateView(candidate: candidate)
        }
    }

    private var pairingSection: some View {
        Section {
            DisclosureGroup(model.pinnedMacs.isEmpty ? "Pair a Mac" : "Pair another Mac") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("1. Run this command in Terminal on your Mac:")
                        .font(.footnote)
                    if let code = model.phonePairingCode {
                        PairingCodeView(
                            code: RemoteApprovalPairingCode.enableCommand(phoneCode: code),
                            copyLabel: "Copy the command for your Mac"
                        )
                    }
                    if let fingerprint = model.phoneFingerprint {
                        Text("This iPhone's key: \(fingerprint)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Text("Touch ID on the Mac names this key. Check it matches before you touch.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text("2. After Touch ID on the Mac, it appears here with this app open: check which Mac it is and accept it with Face ID. If it does not, paste the csec-mac-v2: code the Mac prints.")
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
                        .accessibilityLabel("Mac pairing code")
                        .onChange(of: model.macPairingCode) { _ in
                            model.pastedCodeChanged()
                        }
                    if let candidate = model.pairingCandidate, !candidate.offered {
                        PairingCandidateView(candidate: candidate)
                    } else {
                        Button("Check Mac code") {
                            model.reviewMacPairingCode()
                        }
                        .buttonStyle(.bordered)
                        .disabled(
                            model.faceIDActionInProgress
                                || model.pairingCandidate != nil
                                || model.macPairingCode.trimmingCharacters(
                                    in: .whitespacesAndNewlines
                                ).isEmpty
                        )
                    }
                }
                .padding(.vertical, 8)
            }
        }
    }

    // MARK: - Simulator test mode

    #if DEBUG && targetEnvironment(simulator)
    private var simulatorWarningSection: some View {
        Section {
            Label {
                VStack(alignment: .leading, spacing: 4) {
                    Text("SIMULATOR TEST MODE")
                        .font(.headline)
                    Text("Uses software keys. Approvals here are synthetic and provide no security.")
                        .font(.footnote)
                }
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
            .foregroundStyle(.orange)
            // Test-mode chrome: at the accessibility text sizes it would
            // otherwise fill the first screen and push the cards below it.
            .dynamicTypeSize(...DynamicTypeSize.xxLarge)
        }
    }

    private var simulatorActionsSection: some View {
        Section("Simulator") {
            Menu {
                Button("One of each") {
                    model.injectAllSimulatorRequests()
                }
                ForEach(SimulatorFixture.allCases) { fixture in
                    Button(fixture.menuTitle) {
                        model.injectSimulatorRequest(fixture)
                    }
                }
            } label: {
                Label("Inject signed sample request", systemImage: "testtube.2")
            }
            // With the simulated mailbox, its Macs make the offers, from the
            // menu at the top.
            if SimulatedMailbox.shared == nil {
                Button {
                    Task { await model.offerSimulatorPairing() }
                } label: {
                    Label("Offer pairing from a new simulated Mac", systemImage: "laptopcomputer")
                }
                Button {
                    Task { await model.offerSimulatorPairing(sameMacNewKey: true) }
                } label: {
                    Label("Offer pairing again from the last simulated Mac, with a new key", systemImage: "key")
                }
            }
            Text("In Simulator, choose Features › Face ID › Enrolled, then use Matching Face or Non-matching Face when deciding. The cold-unlock fixtures check the answer against the simulated Mac's enrollment.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
    #endif

    // MARK: - Diagnostics

    #if DEBUG && !targetEnvironment(simulator)
    /// csec-vo4.15: whether one Face ID covers a signature and a key agreement.
    private var spikeSection: some View {
        Section("Diagnostics") {
            DisclosureGroup("Face ID coverage probe") {
                ForEach(Array(SecureEnclaveSpike.variants.enumerated()), id: \.offset) { _, variant in
                    Button("Run: \(variant.name)") {
                        Task {
                            let result = await SecureEnclaveSpike.run(variant)
                            spikeOutput = spikeOutput.isEmpty ? result : spikeOutput + "\n\n" + result
                        }
                    }
                }
                if !spikeOutput.isEmpty {
                    Text(spikeOutput)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                    Button {
                        UIPasteboard.general.string = spikeOutput
                    } label: {
                        Label("Copy results", systemImage: "doc.on.doc")
                    }
                }
            }
        }
    }
    #endif
}

/// Which Mac a pasted code or a Mac's offer names, shown before Face ID: its
/// name, made safe to display, and its key fingerprint, which `csec remote
/// enable` prints on the Mac. When it would replace a pairing — the same Mac,
/// or a Mac of the same name — the key paired now is shown beside the new
/// one, so a changed key is seen before Face ID pins it; for a Mac of the
/// same name the reader chooses whether this replaces it or adds another.
private struct PairingCandidateView: View {
    @EnvironmentObject private var model: ApprovalViewModel
    let candidate: MacPairingCandidate

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(candidate.displayName, systemImage: "laptopcomputer")
                .font(.headline)
            if candidate.offered {
                Text("Offered to this iPhone through your iCloud account.")
                    .font(.footnote)
            }
            Text("Mac key \(candidate.fingerprint)")
                .font(.system(.callout, design: .monospaced))
                .accessibilityIdentifier("candidate-mac-key")
            Text("Check that this is the key csec remote enable printed on your Mac.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            if let replacing = candidate.replacing {
                Label(
                    "This iPhone is already paired with this Mac. Accepting replaces that pairing.",
                    systemImage: "arrow.triangle.2.circlepath"
                )
                .font(.footnote)
                pairedKey(replacing)
                if replacing.publicKeyX963 == candidate.pairing.macPublicKeyX963 {
                    Text("The key is the same.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    Label(
                        "The key changes. Accept only if the new key above is the one csec remote enable printed on your Mac.",
                        systemImage: "exclamationmark.triangle"
                    )
                    .font(.footnote)
                    .foregroundStyle(.orange)
                }
            }
            ForEach(candidate.sameNamed) { mac in
                Label(
                    "This iPhone is already paired with another Mac named \(mac.displayName).",
                    systemImage: "exclamationmark.triangle"
                )
                .font(.footnote)
                .foregroundStyle(.orange)
                pairedKey(mac)
            }
            if candidate.sameNamed.isEmpty {
                Button {
                    Task { await model.confirmPairing(replacingSameNamed: false) }
                } label: {
                    FaceIDLabel(title: "Accept Mac with Face ID")
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.faceIDActionInProgress)
            } else {
                Text("If it is the same Mac paired again, replace the old pairing. If it is a different Mac, add it; the keys tell them apart.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Button {
                    Task { await model.confirmPairing(replacingSameNamed: true) }
                } label: {
                    FaceIDLabel(title: "Replace with Face ID")
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.faceIDActionInProgress)
                Button {
                    Task { await model.confirmPairing(replacingSameNamed: false) }
                } label: {
                    FaceIDLabel(title: "Add as another Mac with Face ID")
                }
                .buttonStyle(.bordered)
                .disabled(model.faceIDActionInProgress)
            }
            Button("Cancel", role: .cancel) {
                model.cancelPairing()
            }
            .buttonStyle(.borderless)
            .disabled(model.faceIDActionInProgress)
        }
        .padding(10)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }

    /// The key a pinned Mac has now, set like the new key so the two can be
    /// compared at a glance.
    private func pairedKey(_ mac: PinnedMac) -> some View {
        Text("Currently paired key \(mac.fingerprint)")
            .font(.system(.callout, design: .monospaced))
            .accessibilityIdentifier("candidate-paired-key")
    }
}

#if DEBUG && targetEnvironment(simulator)
/// What the simulated mailbox holds, and the simulated Macs' side of it in
/// one menu: an offer to pair, a request to post (or one the mailbox query
/// leaves out), confirmations that go missing, answers the Mac refuses or
/// takes, a Mac that goes quiet and comes back, a reply that is lost, and the
/// iCloud account.
private struct SimulatedMailboxControls: View {
    @EnvironmentObject private var model: ApprovalViewModel
    @ObservedObject var mailbox: SimulatedMailbox

    private static let fixtures: [SimulatorFixture] = [.access, .ssh, .sudo]

    var body: some View {
        Menu {
            item("Offer pairing from a new mailbox Mac") {
                Task { await model.offerSimulatorPairing() }
            }
            item("Offer pairing again from the last mailbox Mac, with a new key") {
                Task { await model.offerSimulatorPairing(sameMacNewKey: true) }
            }
            Menu("Post a request") {
                ForEach(Self.fixtures) { fixture in
                    item(fixture.menuTitle) {
                        Task { await model.postSimulatedMailboxRequest(fixture) }
                    }
                }
                ForEach(Self.fixtures) { fixture in
                    item("\(fixture.menuTitle), left out of the list") {
                        Task { await model.postSimulatedMailboxRequest(fixture, leftOutOfList: true) }
                    }
                }
            }
            item("Delete the pairing confirmations") {
                model.deleteSimulatedMailboxConfirmations()
            }
            item("Refuse the answers: the Mac deletes them and keeps waiting") {
                mailbox.refuseAnswers()
            }
            item("Take the answers: the Mac withdraws what was answered") {
                mailbox.takeAnswers()
            }
            item("Answer at the Mac: it withdraws what nobody answered here") {
                mailbox.answerAtTheMac()
            }
            item("Go quiet: the Mac stops saving its requests again") {
                mailbox.goQuiet()
            }
            item("Come back: the Mac saves its requests again") {
                mailbox.comeBack()
            }
            item(
                mailbox.losesNextReply
                    ? "The reply to the next answer will be lost"
                    : "Lose the reply to the next answer"
            ) {
                mailbox.loseNextReply()
            }
            Menu("Simulated iCloud: \(mailbox.iCloud.menuTitle)") {
                ForEach(SimulatedICloud.allCases) { account in
                    item(account.menuTitle) {
                        Task { await model.setSimulatedICloud(account) }
                    }
                }
            }
        } label: {
            Label("Simulated mailbox actions", systemImage: "tray")
        }
        Text(mailbox.summary)
            .font(.footnote.monospacedDigit())
            .foregroundStyle(.secondary)
            .accessibilityIdentifier("simulated-mailbox")
            .accessibilityValue("\(mailbox.actionsRun) actions run")
        // What reached the list, beside what the mailbox holds.
        Text("The list shows \(String(model.pending.count)) cards")
            .font(.footnote.monospacedDigit())
            .foregroundStyle(.secondary)
            .accessibilityIdentifier("simulator-card-count")
    }

    /// A menu item that counts its action as run before running it.
    private func item(_ title: String, action: @escaping () -> Void) -> some View {
        Button(title) {
            mailbox.noteActionRun()
            action()
        }
    }
}
#endif

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
            .buttonStyle(.borderless)
        }
    }
}
