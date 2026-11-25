import ConvenientSecurity
import CSECRemoteApproval
import Foundation
#if canImport(AppKit)
  import AppKit
#endif

/// The secret tree every approval surface names a review's secrets with:
/// source (provider and account) › vault or store › item › field, each level
/// once, a source with one container sharing its line, and each item a label
/// coloured by its source. Providers describe their own references; the core
/// only makes a description display-safe and draws it.
func secretTreeTests() async {
    print("\n# Secret tree (provider-described review secrets)")
    secretTreeFoldingTests()
    secretDisplaySafetyTests()
    await secretDescriptionNeutralityTests()
    await nativeSecretDescriptionTests()
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await MainActor.run {
        secretTreePanelTests()
      }
    #endif
}

private func onePassword(
    _ vault: String, _ item: String, _ field: String,
    account: String? = "acme.1password.eu", warnings: [String] = []
) -> ReviewSecret {
    ReviewSecret(
        provider: "1Password", tint: .teal, account: account, container: vault,
        item: item, field: field, warnings: warnings
    )
}

private func nativeKey(_ store: String, _ key: String) -> ReviewSecret {
    ReviewSecret(
        provider: "csec", tint: .purple, account: "this Mac", container: store,
        item: key, field: nil, itemIsIdentifier: true
    )
}

private func secretTreeFoldingTests() {
    let screenshot = ReviewSecretTree([
        onePassword("Employee", "Demo Openrouter Management Key", "password"),
        onePassword("Employee", "Demo Slack User Token", "password"),
    ])
    let source = screenshot.sources.first
    check(screenshot.sources.count == 1 && screenshot.secretCount == 2
            && source?.title == "1Password · acme.1password.eu" && source?.tint == .teal
            && source?.foldsContainer == true
            && source?.containers.first?.name == "Employee"
            && source?.containers.first?.items.map(\.name)
                == ["Demo Openrouter Management Key", "Demo Slack User Token"]
            && source?.containers.first?.items.allSatisfy({ $0.fields == ["password"] && !$0.isIdentifier }) == true,
          "two items in one vault of one account: one source line folding the vault, one row per item")

    let fields = ReviewSecretTree([
        onePassword("Employee", "Demo Slack User Token", "password"),
        onePassword("Employee", "Demo Slack User Token", "web cookie"),
        onePassword("Employee", "Demo Slack User Token", "web token"),
    ])
    check(fields.secretCount == 3
            && fields.sources.first?.containers.first?.items.count == 1
            && fields.sources.first?.containers.first?.items.first?.fields
                == ["password", "web cookie", "web token"],
          "an item's fields share its one row, in order")

    let vaults = ReviewSecretTree([
        onePassword("Employee", "Slack", "password"),
        onePassword("Engineering", "Sentry", "auth token"),
        onePassword("Employee", "OpenRouter", "password"),
    ])
    check(vaults.sources.count == 1 && vaults.sources.first?.foldsContainer == false
            && vaults.sources.first?.containers.map(\.name) == ["Employee", "Engineering"]
            && vaults.sources.first?.containers.first?.items.map(\.name) == ["Slack", "OpenRouter"],
          "two vaults of one account unfold under one account line, each vault once in first-named order")

    let accounts = ReviewSecretTree([
        onePassword("Employee", "Slack", "password"),
        onePassword("Private", "GitHub", "token", account: "my.1password.com"),
        nativeKey("development", "NPM_TOKEN"),
    ])
    check(accounts.sources.map(\.title) == [
              "1Password · acme.1password.eu", "1Password · my.1password.com", "csec · this Mac",
          ]
            && accounts.sources.map(\.tint) == [.teal, .teal, .purple]
            && accounts.sources.allSatisfy(\.foldsContainer),
          "each account and the native store are their own source, coloured by provider")

    let native = ReviewSecretTree([nativeKey("development", "GITHUB_TOKEN"), nativeKey("development", "NPM_TOKEN")])
    check(native.sources.first?.containers.first?.items.allSatisfy({ $0.isIdentifier && $0.fields.isEmpty }) == true
            && native.sources.first?.containers.first?.items.count == 2,
          "native keys are identifiers with no field level")
    check(native.sources.first?.containers.first?.items.first?.spokenName == "GITHUB TOKEN"
            && screenshot.sources.first?.containers.first?.items.first?.spokenName
                == "Demo Openrouter Management Key",
          "an identifier is spoken with its underscores as spaces, any other name as written")

    let unindexed = ReviewSecretTree([onePassword("Employee", "Slack", "password", account: nil)])
    check(unindexed.sources.first?.title == "1Password" && unindexed.sources.first?.account == nil,
          "with no account known the source names only the provider and the tree starts at the vault")

    let warning = "More than one signed-in account has a vault named “Private”."
    let warned = ReviewSecretTree([
        onePassword("Private", "GitHub", "token", warnings: [warning]),
        onePassword("Private", "GitLab", "token", warnings: [warning]),
        onePassword("Employee", "Slack", "password"),
    ])
    let privateVault = warned.sources.first?.containers.first(where: { $0.name == "Private" })
    let employeeVault = warned.sources.first?.containers.first(where: { $0.name == "Employee" })
    check(privateVault?.warnings == [warning] && employeeVault?.warnings.isEmpty == true,
          "a provider warning sits once under the vault it is about, and nowhere else")

    let undescribed = ReviewSecretTree([ReviewDisplay.undescribedSecret(try! SecretRef("vault://kv/app/token"))])
    let bare = undescribed.sources.first
    check(bare?.title == nil && bare?.tint == .gray
            && bare?.containers.first?.name == nil
            && bare?.containers.first?.items.first?.name == "vault://kv/app/token"
            && bare?.containers.first?.items.first?.isIdentifier == true,
          "a reference no provider described is listed whole, in grey, under no source")
}

private func secretDisplaySafetyTests() {
    let hostile = ReviewDisplay.displaySafe(ReviewSecret(
        provider: "1Pass\u{202e}word", tint: .teal, account: "evil\u{202E}corp\nnew",
        container: "Emp\u{202e}loyee", item: "It\u{0007}em", field: "fie\u{0007}ld",
        notes: Array(repeating: "note", count: 12),
        warnings: ["warn\u{202e}ing"]
    ))
    check(hostile.provider == "1Pass�word" && hostile.account == "evil�corp�new"
            && hostile.container == "Emp�loyee" && hostile.item == "It�em" && hostile.field == "fie�ld"
            && hostile.warnings == ["warn�ing"]
            && hostile.notes.count == ReviewDisplay.maximumNotes,
          "every part of a provider's description neutralizes bidi and control characters, notes bounded")

    let long = ReviewDisplay.displaySafe(onePassword("V", String(repeating: "界", count: 2_000), "f"))
    check(long.item.utf8.count <= 1_024, "an item name is bounded")

    let empty = ReviewDisplay.displaySafe(ReviewSecret(
        provider: "x", tint: .mint, account: " ", container: "", item: "", field: ""
    ))
    check(empty.item == "(unnamed)" && empty.account == nil && empty.container == nil && empty.field == nil,
          "an empty part is dropped and an empty item is named, never blank")

    let undescribed = ReviewDisplay.undescribedSecret(try! SecretRef("op://Emp\u{202e}loyee/Item"))
    check(!undescribed.item.contains("\u{202e}") && undescribed.tint == .gray && undescribed.provider == nil,
          "a whole reference is shown prompt-safe")
}

private struct DescribingFixtureProvider: SecretProvider {
    let schemes: Set<String> = ["vault"]

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        throw ProviderError.notImplemented
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
    func reviewDescription(for ref: SecretRef) async -> ReviewSecret? {
        guard ref.path.hasPrefix("kv/") else { return nil }
        return ReviewSecret(
            provider: "Vault", tint: .indigo, account: "prod\u{202e} cluster", container: "kv",
            item: String(ref.path.dropFirst(3)), field: nil, itemIsIdentifier: true,
            notes: ["read through the cluster agent"]
        )
    }
}

/// A backend the core has never heard of is drawn from its own description;
/// a reference it declines, or one no provider claims, is shown whole.
private func secretDescriptionNeutralityTests() async {
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(DescribingFixtureProvider())
    let described = await resolver.reviewSecret(for: try! SecretRef("vault://kv/app-token"))
    check(described.provider == "Vault" && described.tint == .indigo
            && described.account == "prod� cluster" && described.container == "kv"
            && described.item == "app-token" && described.notes == ["read through the cluster agent"],
          "neutrality: a new backend's own description is drawn, made display-safe")
    let declined = await resolver.reviewSecret(for: try! SecretRef("vault://other/path"))
    let unclaimed = await resolver.reviewSecret(for: try! SecretRef("op://Employee/Item/field"))
    check(declined == ReviewDisplay.undescribedSecret(try! SecretRef("vault://other/path"))
            && unclaimed == ReviewDisplay.undescribedSecret(try! SecretRef("op://Employee/Item/field")),
          "neutrality: a declined or unclaimed reference is shown whole, never parsed by the core")

    let credential = await resolver.reviewCredential(for: [
        try! SecretRef("vault://kv/zeta"), try! SecretRef("vault://kv/alpha"),
    ])
    check(credential.references.map(\.uri) == ["vault://kv/alpha", "vault://kv/zeta"]
            && credential.secrets.map(\.item) == ["alpha", "zeta"],
          "a credential's descriptions stay paired with their references when sorted")

    let row = RestoreReviewRow(
        kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
        references: ["vault://kv/alpha", "vault://other/path"]
    )
    check(row.secrets.allSatisfy({ $0.provider == nil && $0.tint == .gray }),
          "a restore row names its references whole until it is described")
    let describedRow = row.described(by: await resolver.reviewSecrets(for: row.references.map { try! SecretRef($0) }))
    check(describedRow.secrets.map(\.provider) == ["Vault", nil]
            && describedRow.references == row.references && describedRow.title == row.title,
          "a described restore row names each reference by its provider's description")
}

private func nativeSecretDescriptionTests() async {
    let native = NativeEncryptedFileProvider(
        keyBackend: InMemoryNativeStoreKeyBackend(), fileBackend: InMemoryNativeStoreFileBackend()
    )
    let key = await native.reviewDescription(for: try! SecretRef("csec://development/GITHUB_TOKEN"))
    check(key == nativeKey("development", "GITHUB_TOKEN"),
          "the native store describes a key as this Mac › store › key, in purple")
    let edit = await native.reviewDescription(
        for: NativeSecretReference.editConsentReference(for: try! NativeStoreName("development"))
    )
    check(edit?.container == "development" && edit?.item == "all keys (edit access)"
            && edit?.itemIsIdentifier == false && edit?.field == nil,
          "the native store describes its edit consent as every key of the store")
    let invalid = await native.reviewDescription(for: try! SecretRef("csec://not a store/KEY"))
    check(invalid == nil, "the native store declines a reference it cannot parse")
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @MainActor
  private func secretTreePanelTests() {
    NSApplication.shared.setActivationPolicy(.accessory)
    let caller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
    let plan = DeliveryPlan(
      mechanism: .directHeap,
      executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
      descendantScope: .subtree, destination: .localDevelopment,
      requestedTTLSeconds: nil, operationContext: "run migrations"
    )
    let warning = "More than one signed-in account has a vault named “Private”."
    func credential(_ pairs: [(String, ReviewSecret)]) -> PolicyReviewCredential {
      PolicyReviewCredential(described: pairs.map { (try! SecretRef($0.0), $0.1) })
    }
    let credentials = [
      credential([
        ("op://Employee/Demo Slack User Token/password",
         onePassword("Employee", "Demo Slack User Token", "password")),
        ("op://Employee/Demo Slack User Token/web token",
         onePassword("Employee", "Demo Slack User Token", "web token")),
      ]),
      credential([
        ("op://Private/GitHub/token",
         onePassword("Private", "GitHub", "token", account: "my.1password.com", warnings: [warning])),
      ]),
      credential([("csec://dev/API_TOKEN", nativeKey("dev", "API_TOKEN"))]),
      PolicyReviewCredential(references: [try! SecretRef("vault://kv/app/token")]),
    ]
    let release = AccessPolicyReview(
      caller: caller, reason: "run migrations", plan: plan, commandLine: "bin/rails db:migrate",
      credentials: credentials
    )
    let panel = ApprovalPanelInspection.access(release)
    let content = laidOut(panel.window)
    let labels = secretLabels(in: content)
    check(labels.map(\.tint) == ["teal", "teal", "purple", "gray"]
            && labels.map(\.text) == ["Demo Slack User Token", "GitHub", "API_TOKEN", "vault://kv/app/token"],
          "release panel: each item is one label, coloured by its source: 1Password teal, csec purple, undescribed grey")
    let texts = textFields(in: content).map(\.stringValue)
    check(texts.contains(where: { $0.contains("1Password · acme.1password.eu") && $0.hasSuffix("Employee") })
            && texts.contains(where: { $0.contains("1Password · my.1password.com") && $0.hasSuffix("Private") })
            && texts.contains(where: { $0.contains("csec · this Mac") && $0.hasSuffix("dev") }),
          "release panel: each source line names provider and account, folding its one vault or store")
    check(texts.contains("password · web token") && texts.contains("token") && texts.contains(warning),
          "release panel: fields sit beside their item and the warning under its vault")
    check(!texts.contains(where: { $0.contains("op://") || $0.contains("csec://") }),
          "release panel: a described reference is never shown as a raw URI")
    check(texts.contains("SECRETS RELEASED"), "release panel: the section keeps its label")
    if let slack = labelText(in: content, named: "Demo Slack User Token"),
       let nativeLabel = labelText(in: content, named: "API_TOKEN") {
      func matches(_ field: NSTextField, _ tint: ReviewSecretTint, dark: Bool) -> Bool {
        resolved(field.textColor, dark: dark)?.isClose(to: tint.palette(dark: dark).text) == true
      }
      check(nativeLabel.accessibilityLabel() == "API TOKEN" && slack.accessibilityLabel() == "Demo Slack User Token",
            "release panel: VoiceOver reads a key's underscores as spaces")
      check(matches(slack, .teal, dark: true) && matches(slack, .teal, dark: false)
              && matches(nativeLabel, .purple, dark: true) && matches(nativeLabel, .purple, dark: false),
            "release panel: a label's text uses its source's shared colour in both appearances")
    } else {
      check(false, "release panel: the labels' text fields are found")
    }

    let keys = ["A_TOKEN", "B_TOKEN", "CHROBINSON_CLIENT_SECRET", "D_TOKEN"]
    let storePanel = ApprovalPanelInspection.access(AccessPolicyReview(
      caller: caller, reason: "run migrations", plan: plan, commandLine: "bin/rails db:migrate",
      credentials: [credential(keys.map { ("csec://dev/\($0)", nativeKey("dev", $0)) } + [
        ("op://Employee/Slack/password", onePassword("Employee", "Slack", "password")),
        ("op://Employee/Sentry/token", onePassword("Employee", "Sentry", "token")),
      ])]
    ))
    let storeContent = laidOut(storePanel.window)
    let rows = { (names: [String]) -> Set<Int> in
      Set(allViews(storeContent).filter {
        $0.identifier?.rawValue.hasPrefix("csec.secretLabel.") == true
          && names.contains(textFields(in: $0).first?.stringValue ?? "")
      }.map { Int($0.convert($0.bounds, to: storeContent).minY.rounded()) })
    }
    check(rows(keys).count < keys.count && rows(["Slack", "Sentry"]).count == 2,
          "release panel: a store's keys wrap left to right, while each item with fields keeps its own row")
    check(clippedLabels(in: storeContent).isEmpty && clippedLabels(in: content).isEmpty,
          "release panel: no label clips its name (clipped: "
            + (clippedLabels(in: storeContent) + clippedLabels(in: content)).joined(separator: ", ") + ")")

    let scopes = GrantScopeChoices(
      options: [
        GrantScopeOption(kind: .requestingCommand, pid: 51, startTime: 9, processLabel: "ssh"),
        GrantScopeOption(kind: .terminalSession, pid: 20, startTime: 2, processLabel: "fish"),
      ],
      defaultOptionID: "terminal_session-20-2"
    )
    let ssh = SSHAccessReviewDetails(
      hostNames: ["github.com"], remoteUser: "git", keyLabel: "work", keyAlgorithm: "ssh-ed25519")
    let sshPanel = ApprovalPanelInspection.access(AccessPolicyReview(
      caller: caller, reason: ssh.reason,
      plan: DeliveryPlan(
        mechanism: .credentialProtocol,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
        descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
      ),
      credentials: [credential([("csec://dev/id_ed25519", nativeKey("dev", "id_ed25519"))])],
      scopeChoices: scopes, durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil), ssh: ssh
    ))
    check(secretLabels(in: laidOut(sshPanel.window)).map { "\($0.tint):\($0.text)" } == ["purple:id_ed25519"],
          "SSH panel: the signing key is a label in its source's colour")

    // Which account a 1Password key resolves from decides which key signs, so
    // its provider notes and warnings show with the details collapsed, once.
    let keyNote = "This key will come from my.1password.com."
    let ambiguousPanel = ApprovalPanelInspection.access(AccessPolicyReview(
      caller: caller, reason: ssh.reason,
      plan: DeliveryPlan(
        mechanism: .credentialProtocol,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
        descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
      ),
      credentials: [credential([(
        "op://Private/GitHub SSH key/private key",
        ReviewSecret(
          provider: "1Password", tint: .teal, account: "my.1password.com", container: "Private",
          item: "GitHub SSH key", field: "private key", notes: [keyNote], warnings: [warning]
        )
      )])],
      scopeChoices: scopes, durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil), ssh: ssh
    ))
    let ambiguousFields = textFields(in: laidOut(ambiguousPanel.window))
    for (name, text) in [("warning", warning), ("note", keyNote)] {
      let drawn = ambiguousFields.filter { $0.stringValue == text }
      check(drawn.count == 1 && drawn.allSatisfy { !$0.isHiddenOrHasHiddenAncestor },
            "SSH panel: the key's provider \(name) shows once with the details collapsed (drawn \(drawn.count), "
              + "visible \(drawn.filter { !$0.isHiddenOrHasHiddenAncestor }.count))")
    }

    let automationPanel = ApprovalPanelInspection.access(AccessPolicyReview(
      caller: caller, reason: "enroll backup", plan: plan,
      credentials: [credential([("csec://dev/X", nativeKey("dev", "X"))])],
      automation: v3AutomationDetails()
    ))
    check(secretLabels(in: laidOut(automationPanel.window)).map { "\($0.tint):\($0.text)" } == ["purple:X"],
          "automation panel: the job's secrets are labels in their source's colour")

    let restoreRow = RestoreReviewRow(
      kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
      references: ["csec://dev/API_TOKEN", "op://Employee/Demo Slack User Token/password"]
    ).described(by: [
      "csec://dev/API_TOKEN": nativeKey("dev", "API_TOKEN"),
      "op://Employee/Demo Slack User Token/password": onePassword(
        "Employee", "Demo Slack User Token", "password"),
    ])
    let restore = RestoreReviewDetails(cause: .restart, rows: [restoreRow], storeCount: 2)
    let restorePanel = ApprovalPanelInspection.access(.restoreOnly(caller: caller, restore: restore))
    let restoreContent = laidOut(restorePanel.window)
    check(Set(secretLabels(in: restoreContent).map { "\($0.tint):\($0.text)" })
            == ["purple:API_TOKEN", "teal:Demo Slack User Token"]
            && !textFields(in: restoreContent).contains(where: { $0.stringValue.contains("csec://") }),
          "restore panel: a restored grant names its secrets as a release does")

    let mixedPanel = ApprovalPanelInspection.access(AccessPolicyReview(
      caller: caller, reason: "run migrations", plan: plan, commandLine: "bin/rails db:migrate",
      credentials: [credential([("csec://dev/DATABASE_URL", nativeKey("dev", "DATABASE_URL"))])],
      restore: restore
    ))
    check(secretLabels(in: laidOut(mixedPanel.window)).map(\.text).sorted()
            == ["API_TOKEN", "DATABASE_URL", "Demo Slack User Token"],
          "release panel with a restore section: both the release and the restored grant use the tree")
    withExtendedLifetime([panel, storePanel, sshPanel, ambiguousPanel, automationPanel, restorePanel, mixedPanel]) {}
    pairingLinePanelTests(caller: caller, plan: plan, credentials: credentials)
  }

  /// The delegation note and pairing line on the secret-access, SSH and sudo
  /// layouts: the line shows whole exactly while the selection pairs, and an
  /// SSH panel, which csecd never offers one (csec-0.11), shows only its note.
  @MainActor
  private func pairingLinePanelTests(
    caller: CallerInfo, plan: DeliveryPlan, credentials: [PolicyReviewCredential]
  ) {
    let scopes = GrantScopeChoices(
      options: [
        GrantScopeOption(kind: .codingAgent, pid: 40, startTime: 4, processLabel: "Claude Code"),
        GrantScopeOption(kind: .requestingCommand, pid: 51, startTime: 9, processLabel: "ssh"),
      ],
      defaultOptionID: "coding_agent-40-4"
    )
    let offer = DelegationPairingOffer(projectName: "garden-lights", scopeOptionID: "coding_agent-40-4")
    let ssh = SSHAccessReviewDetails(
      hostNames: ["nimbus.local"], remoteUser: "root", keyLabel: "id_rsa", keyAlgorithm: "ssh-rsa")
    func sshReview(durations: GrantDurationChoices, note: DelegationDecline = .notRegistered) -> AccessPolicyReview {
      AccessPolicyReview(
        caller: caller, reason: ssh.reason,
        plan: DeliveryPlan(
          mechanism: .credentialProtocol,
          executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
          descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
        ),
        credentials: [PolicyReviewCredential(described: [(try! SecretRef("csec://dev/id_rsa"), ReviewSecret(
          provider: "csec", tint: .purple, account: "this Mac", container: "dev", item: "id_rsa", field: nil, warnings: []
        ))])],
        scopeChoices: scopes, durationChoices: durations, ssh: ssh,
        delegationNote: note
      )
    }
    func accessReview(durations: GrantDurationChoices) -> AccessPolicyReview {
      AccessPolicyReview(
        caller: caller, reason: "run migrations", plan: plan, commandLine: "bin/rails db:migrate",
        credentials: credentials, scopeChoices: scopes, durationChoices: durations,
        delegationNote: .notApprovedForProject(reference: "csec://dev/API_TOKEN", project: "garden-lights"),
        pairingOffer: offer
      )
    }
    func pairingLine(_ view: NSView) -> NSTextField? {
      allViews(view).first { $0.identifier == PromptInteractionGraceProbe.pairingLineIdentifier } as? NSTextField
    }
    func clipped(_ field: NSTextField) -> Bool {
      guard let cell = field.cell else { return true }
      let needed = cell.cellSize(forBounds: NSRect(x: 0, y: 0, width: field.bounds.width, height: .greatestFiniteMagnitude))
      return needed.height > field.bounds.height + 0.5
    }
    let sshPanel = ApprovalPanelInspection.access(sshReview(durations: GrantDurationChoices.offered(requestedTTLSeconds: nil)))
    let sshContent = laidOut(sshPanel.window)
    check(pairingLine(sshContent) == nil
            && textFields(in: sshContent).contains { $0.stringValue == DelegationDecline.notRegistered.panelText },
          "pairing line: the SSH panel shows why auto mode did not approve, and no pairing line")
    let accessPanel = ApprovalPanelInspection.access(accessReview(durations: GrantDurationChoices.offered(requestedTTLSeconds: nil)))
    if let line = pairingLine(laidOut(accessPanel.window)) {
      check(!line.isHidden && line.stringValue == offer.line && !clipped(line)
              && line.stringValue.hasSuffix("in garden-lights until you revoke them"),
            "pairing line: the secret-access panel shows the whole line while Claude Code and its lifetime are selected")
    } else {
      check(false, "pairing line: the secret-access panel shows the whole line while Claude Code and its lifetime are selected")
    }
    let capped = ApprovalPanelInspection.access(accessReview(durations: GrantDurationChoices.offered(requestedTTLSeconds: 3_600)))
    check(pairingLine(laidOut(capped.window))?.isHidden == true,
          "pairing line: hidden while a lifetime cap is the selection")
    // The sudo panel: the note and the whole line, always shown when csecd
    // offered one (a sudo panel selects no scope or lifetime), and neither
    // when it did not.
    let sudoTerminal = TerminalSessionContext(application: "iTerm2", title: "agent", location: "window 1, tab 1", tty: "ttys009")
    let sudoOffer = SudoPairingOffer(projectName: "garden-lights")
    let sudoNote = DelegationDecline.sudoNotApproved(project: "garden-lights").panelText
    let sudoPanel = ApprovalPanelInspection.sudo(
      SudoAuthorizationReviewRequest(
        submittedCommand: "sudo fs_usage -w -f pathname -t 8", workingDirectory: "/Users/example/garden-lights",
        terminal: "no tty", delegationNote: sudoNote, pairingLine: sudoOffer.line
      ),
      terminal: sudoTerminal
    )
    let sudoContent = laidOut(sudoPanel.window)
    if let line = pairingLine(sudoContent) {
      check(!line.isHidden && line.stringValue == sudoOffer.line && !clipped(line),
            "pairing line: the sudo panel shows the whole line it was given")
    } else {
      check(false, "pairing line: the sudo panel shows the whole line it was given")
    }
    check(textFields(in: sudoContent).contains { $0.stringValue == sudoNote },
          "pairing line: the sudo panel shows why auto mode did not approve")
    let plainSudo = ApprovalPanelInspection.sudo(
      SudoAuthorizationReviewRequest(
        submittedCommand: "sudo id", workingDirectory: "/Users/example", terminal: "/dev/ttys009"
      ),
      terminal: sudoTerminal
    )
    let plainContent = laidOut(plainSudo.window)
    check(pairingLine(plainContent) == nil
            && !textFields(in: plainContent).contains { $0.stringValue.hasPrefix(DelegationDecline.panelPrefix) },
          "pairing line: a sudo panel csecd said nothing about shows neither note nor line")
    let overlong = SudoAuthorizationReviewRequest(
      submittedCommand: "sudo id", workingDirectory: "/Users/example", terminal: "no tty",
      delegationNote: sudoNote,
      pairingLine: String(repeating: "x", count: SudoDelegationAnswer.maximumPairingLineBytes + 1)
    )
    check(overlong.pairingLine == nil, "pairing line: a sudo line too long to show whole is dropped, never shortened")
    // A decline pairing can't end (csec-tcbq): both panels show the whole
    // conditioned line, the longest condition with a long project name.
    let condition = DelegationDecline.otherHook("h", launch: "--settings or --add-dir").pairingCondition
    let conditionedOffer = DelegationPairingOffer(
      projectName: String(repeating: "garden-lights-", count: 9), scopeOptionID: "coding_agent-40-4", condition: condition)
    let conditionedAccess = ApprovalPanelInspection.access(AccessPolicyReview(
      caller: caller, reason: "run migrations", plan: plan, commandLine: "bin/rails db:migrate",
      credentials: credentials, scopeChoices: scopes,
      durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil),
      delegationNote: .otherHook("h", launch: "--settings or --add-dir"), pairingOffer: conditionedOffer
    ))
    let conditionedAccessLine = pairingLine(laidOut(conditionedAccess.window))
    let conditionedSudoOffer = SudoPairingOffer(projectName: String(repeating: "garden-lights-", count: 9), condition: condition)
    let conditionedSudo = ApprovalPanelInspection.sudo(
      SudoAuthorizationReviewRequest(
        submittedCommand: "sudo id", workingDirectory: "/Users/example/garden-lights", terminal: "no tty",
        delegationNote: DelegationDecline.launchOption("--settings").panelText, pairingLine: conditionedSudoOffer.line
      ),
      terminal: sudoTerminal
    )
    let conditionedSudoLine = pairingLine(laidOut(conditionedSudo.window))
    check(conditionedAccessLine.map { !$0.isHidden && $0.stringValue == conditionedOffer.line && !clipped($0) } == true
            && conditionedSudoLine.map { !$0.isHidden && $0.stringValue == conditionedSudoOffer.line && !clipped($0) } == true
            && conditionedSudoOffer.line.hasSuffix("once Claude Code is started without the --settings or --add-dir that bring in that hook"),
          "pairing line: the secret-access and sudo panels show a conditioned line whole")
    for (label, decline) in [
      ("unchecked-image", DelegationDecline.uncheckedBuild("new release")),
      ("generated-policy", .settingsUnreadable("/Library/Application Support/ClaudeCode/managed-settings.json")),
    ] {
      let access = ApprovalPanelInspection.access(AccessPolicyReview(
        caller: caller, reason: "run migrations", plan: plan, commandLine: "bin/rails db:migrate",
        credentials: credentials, scopeChoices: scopes,
        durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil), delegationNote: decline
      ))
      let ssh = ApprovalPanelInspection.access(sshReview(
        durations: GrantDurationChoices.offered(requestedTTLSeconds: nil), note: decline))
      let sudo = ApprovalPanelInspection.sudo(SudoAuthorizationReviewRequest(
        submittedCommand: "sudo id", workingDirectory: "/Users/example", terminal: "no tty",
        delegationNote: decline.panelText), terminal: sudoTerminal)
      for (name, panel) in [("secret", access), ("SSH", ssh), ("sudo", sudo)] {
        let note = textFields(in: laidOut(panel.window)).first { $0.stringValue == decline.panelText }
        check(note.map { !clipped($0) } == true, "release gate: the real \(name) panel shows the complete \(label) reason")
      }
      withExtendedLifetime([access, ssh, sudo]) {}
    }
    withExtendedLifetime([sshPanel, capped, accessPanel, sudoPanel, plainSudo]) {}
  }

  /// The window's content laid out, without moving, showing or ordering the
  /// window: frames, text sizes and colours need nothing more.
  @MainActor
  private func laidOut(_ window: NSPanel) -> NSView {
    window.contentView?.layoutSubtreeIfNeeded()
    return window.contentView ?? NSView()
  }

  @MainActor
  private func allViews(_ view: NSView) -> [NSView] {
    [view] + view.subviews.flatMap(allViews)
  }

  @MainActor
  private func textFields(in view: NSView) -> [NSTextField] {
    allViews(view).compactMap { $0 as? NSTextField }
  }

  @MainActor
  private func secretLabels(in view: NSView) -> [(tint: String, text: String)] {
    let prefix = "csec.secretLabel."
    return allViews(view).compactMap { candidate in
      guard let identifier = candidate.identifier?.rawValue, identifier.hasPrefix(prefix) else { return nil }
      return (String(identifier.dropFirst(prefix.count)), textFields(in: candidate).first?.stringValue ?? "")
    }
  }

  /// Labels whose text needs more room than its field has: a wrapped last
  /// character on a line the box cannot show, or a line cut short.
  @MainActor
  private func clippedLabels(in view: NSView) -> [String] {
    allViews(view)
      .filter { $0.identifier?.rawValue.hasPrefix("csec.secretLabel.") == true }
      .flatMap { textFields(in: $0) }
      .filter { field in
        guard let cell = field.cell else { return true }
        let needed = cell.cellSize(forBounds: NSRect(
          x: 0, y: 0, width: field.bounds.width, height: .greatestFiniteMagnitude))
        return needed.height > field.bounds.height + 0.5
      }
      .map(\.stringValue)
  }

  @MainActor
  private func labelText(in view: NSView, named name: String) -> NSTextField? {
    allViews(view)
      .filter { $0.identifier?.rawValue.hasPrefix("csec.secretLabel.") == true }
      .flatMap { textFields(in: $0) }
      .first { $0.stringValue == name }
  }

  @MainActor
  private func resolved(_ color: NSColor?, dark: Bool) -> ReviewSecretTint.RGB? {
    guard let color, let appearance = NSAppearance(named: dark ? .darkAqua : .aqua) else { return nil }
    var rgb: ReviewSecretTint.RGB?
    appearance.performAsCurrentDrawingAppearance {
      if let srgb = color.usingColorSpace(.sRGB) {
        rgb = ReviewSecretTint.RGB(
          red: Double(srgb.redComponent), green: Double(srgb.greenComponent), blue: Double(srgb.blueComponent)
        )
      }
    }
    return rgb
  }
#endif
