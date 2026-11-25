import ConvenientSecurity
import Foundation

// Every setup step's Touch ID is csecd's settings panel, typing-guarded like
// every other approval, never Apple's bare sheet, which took a Space typed as
// it appeared as its Deny (csec-0.60, after av-0.721 moved the auto-mode
// settings). The backup, pairing and machine identity flows check this in
// their own suites; this one covers the uninstall cleanup, removing an SSH
// key and host fixes, and the panel each shows. The panel's typing guard is
// `--prompt-grace-only`'s and `--panel-controls-only`'s.

/// The csec launcher a setup step's tests stand in for.
let setupCaller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")

/// The tab the panel names, as a socket handler resolves it.
private let setupTab = TerminalSessionContext(
    application: "iTerm2", title: "setup", location: "window 1, tab 2", tty: "ttys007"
)

/// Records each setup touch as csecd's settings panel would show it, and
/// any bare sheet asked for instead.
actor SettingsPanelRecorder: ConsentProvider {
    private(set) var panels: [(change: SettingsChangeReviewDetails, caller: CallerInfo)] = []
    private(set) var bareSheets = 0
    private var approve: Bool

    init(approve: Bool = true) { self.approve = approve }

    func set(approve: Bool) { self.approve = approve }

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        approve ? .approved(unlock: nil) : .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        bareSheets += 1
        return approve ? .approved(unlock: nil) : .denied
    }

    func authenticateSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> ConsentAnswer {
        panels.append((change, caller))
        return approve ? .approved(unlock: nil) : .refused(.unexplained)
    }
}

func settingsPanelFlowTests() async {
    print("\n# Setup steps take csecd's settings panel, not the bare Touch ID sheet (csec-0.60)")
    settingsChangeFootnoteTests()
    await uninstallPanelTests()
    await sshKeyRemovalPanelTests()
    await hostRemediationPanelTests()
}

private func settingsChangeFootnoteTests() {
    let plain = SettingsChangeReviewDetails(title: "T", changes: ["c"])
    check(plain.footnote == SettingsChangeReviewDetails.settingsFootnote
            && DeliveryReviewCopy.footnote(for: .settingsChange(caller: setupCaller, change: plain))
                == SettingsChangeReviewDetails.settingsFootnote,
          "settings panel: a change to csec's settings keeps the settings footnote")
    let own = SettingsChangeReviewDetails(title: "T", changes: ["c"], footnote: "Touch ID restores\u{07} these.")
    check(DeliveryReviewCopy.footnote(for: .settingsChange(caller: setupCaller, change: own)) == own.footnote
            && !own.footnote.contains("\u{07}"),
          "settings panel: a step that is not a settings change shows its own footnote, sanitized")
}

private func uninstallPanelTests() async {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("csec-uninstall-panel-\(UUID().uuidString.lowercased())").path
    try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: directory) }
    var caller = setupCaller
    caller.terminal = setupTab
    let refusing = SettingsPanelRecorder(approve: false)
    let outcome = await CsecdUninstaller(
        consent: refusing, stores: nil, log: nil, logDirectory: SealedRecordDirectory(path: directory)
    ).run(caller: caller)
    let panel = await refusing.panels.first
    let bareSheets = await refusing.bareSheets
    check(outcome == .denied && FileManager.default.fileExists(atPath: directory),
          "uninstall: a refused panel deletes nothing")
    check(await refusing.panels.count == 1 && bareSheets == 0
            && panel?.change.title == "Uninstall Convenient Security"
            && panel?.change.changes.first == "Delete csecd's \(CsecdUninstaller.deletedSummary)"
            && panel?.change.changes.last?.hasPrefix("Keep \(CsecdUninstaller.keptSummary)") == true
            && panel?.caller.pid == setupCaller.pid && panel?.caller.terminal == setupTab,
          "uninstall: the Touch ID is csecd's settings panel, saying what goes and what stays, naming the tab")
}

private func sshKeyRemovalPanelTests() async {
    let key: Ed25519SSHFixture
    do { key = try Ed25519SSHFixture(seed: 211) } catch {
        check(false, "SSH removal: the synthetic key builds (\(error))")
        return
    }
    let fingerprint = sshFingerprint(key.publicKeyBlob)
    let catalog = SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [
        SSHKeyMetadata(
            reference: "fake://ssh/removed", fingerprint: fingerprint,
            algorithm: "ssh-ed25519", publicKeyBlob: key.publicKeyBlob, label: "removed key"
        ),
    ]))
    let consent = SettingsPanelRecorder(approve: false)
    let service = SSHSigningService(
        resolver: SecretResolver(cache: NullSecretCache()), catalog: catalog,
        consent: consent, policyReview: AutoApprovePolicyReview(),
        allowUnverifiedCallersForTesting: true, terminalInspection: .unavailable
    )
    let refused = (try? await service.remove(fingerprint: fingerprint, caller: setupCaller)) == nil
    let kept = ((try? await catalog.list()) ?? []).map(\.fingerprint)
    check(refused && kept == [fingerprint], "SSH removal: a refused panel removes nothing")
    await consent.set(approve: true)
    let removed = (try? await service.remove(fingerprint: fingerprint, caller: setupCaller)) == true
    let left = ((try? await catalog.list()) ?? []).count
    let panels = await consent.panels
    let bareSheets = await consent.bareSheets
    check(removed && left == 0, "SSH removal: an approved panel removes the key")
    check(panels.count == 2 && bareSheets == 0
            && panels.allSatisfy {
                $0.change.title == "Remove a Protected SSH Key"
                    && $0.change.changes == ["Remove SSH key \(fingerprint) from csec's SSH agent, with every signing grant for it"]
                    && $0.caller.pid == setupCaller.pid && $0.caller.terminal != nil
            },
          "SSH removal: each Touch ID is csecd's settings panel for the csec that asked, naming the key")
}

private func hostRemediationPanelTests() async {
    var caller = setupCaller
    caller.terminal = setupTab
    let items = (1...8).map {
        HostRemediationItem(key: "HA-T0\($0)", title: "Synthetic fix \($0)", detail: "reversible", requiresRoot: $0 % 2 == 0)
    }
    let review = HostRemediationReview(items: items, caller: caller)
    let shown = AccessPolicyReview.settingsChange(caller: review.caller, change: review.change)
    check(review.change.title == "Apply 8 Security Fixes"
            && review.change.changes.prefix(6) == ["Synthetic fix 1", "Synthetic fix 2", "Synthetic fix 3",
                                                   "Synthetic fix 4", "Synthetic fix 5", "Synthetic fix 6"]
            && review.change.changes.last == "and 2 more changes"
            && review.change.footnote.hasPrefix("Touch ID applies exactly these reversible fixes"),
          "host fixes: the panel lists the selected fixes by title and says what the touch applies")
    check(HostRemediationReview(items: [items[0]], caller: caller).change.title == "Apply a Security Fix",
          "host fixes: one fix is named as one")
    check(shown.macOnly && shown.credentials.isEmpty && shown.scopeChoices == nil && shown.durationChoices == nil
            && shown.caller.pid == setupCaller.pid && shown.caller.terminal == setupTab,
          "host fixes: the panel is Mac-only, releases nothing, and is for the launcher whose picker chose them")
}
