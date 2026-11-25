import AppKit
import ConvenientSecurity
import CSECRemoteApprovalCloudKit
import CSecuritySupport
import CloudKit
import CryptoKit
import Foundation
import OnePasswordAdapter
import Security
import UserNotifications
import CSECBuildIdentity

#if canImport(Darwin)
  import Darwin
#endif

func startAgentServer() async {
  // The resident agent. It listens, authenticates peers, tracks subtree grants,
  // gates new references through Touch ID, and resolves through registered providers,
  // caching resolved values in the biometric-gated data-protection keychain.
  //
  // There is deliberately no environment- or argument-controlled approval
  // switch in this shipping executable: one would also be available to same-uid
  // malware launching the genuine signed binary. Automated tests use
  // cs-fake-agent or inject a ConsentProvider in process. The only automatic
  // approver is Claude Code delegation, turned on only by a Touch-ID-confirmed
  // setting csecd keeps in its own protected item (`csec setup`): it approves
  // one classifier-judged command at a time, mints no grant, and releases only
  // references a human paired with that project on this Mac.

  guard cs_disable_core_dumps() == 0 else {
    FileHandle.standardError.write(
      Data("csecd: refusing startup because core dumps could not be disabled.\n".utf8)
    )
    exit(1)
  }

  let socketPath = AgentSocket.defaultPath()
  do {
    try AgentSocket.ensureDirectory()
  } catch {
    FileHandle.standardError.write(Data("csecd: cannot prepare socket directory: \(error)\n".utf8))
    exit(1)
  }

  // Under launchd there is no terminal, so send our log to a file rather than let
  // it vanish. Keep it inside the private 0700 socket dir — never world-readable
  // /tmp. Logs are value-free, but executable paths and security state are still
  // local metadata. When run interactively (a tty), leave stdout/stderr alone so
  // dev runs print normally.
  if isatty(fileno(stderr)) == 0 {
    do {
      try BoundedDaemonLog.redirect(in: AgentSocket.directory())
    } catch {
      FileHandle.standardError.write(Data("csecd: diagnostic log unavailable.\n".utf8))
    }
  }

  // The at-rest cache and native-store keys need the provisioned access-group
  // entitlement, which only a signed build carries. Probe once (non-interactive)
  // and fall back to neither feature in an unsigned development run.
  let keychainProbe = SecurityKeychainBackend.probe()
  let cacheEnabled = keychainProbe == errSecSuccess
  // The phone-held unlock factor's items (enrollment, epoch, and the sealed
  // mirrors of native key records and cache entries) share the same access
  // group. Inert until a phone is paired: without an enrollment nothing is
  // written and nothing is served.
  let remoteUnlock: RemoteUnlockStore? =
    cacheEnabled ? RemoteUnlockStore.dataProtectionKeychain() : nil
  let cache: SecretCache =
    cacheEnabled ? KeychainSecretCache(remoteUnlock: remoteUnlock) : NullSecretCache()
  let providerPath = OnePasswordCLI.locate()
  let providerReport = providerPath.map { OnePasswordCLI.trustReport(for: $0) }
  let providerTrusted = providerReport?.trusted == true
  let startupReport = StartupSecurityReport.currentAgent()
  // csecd-only documents (delegation settings, persisted grants, pairing, the
  // decision log's key and checkpoint, the baseline pointer) live in explicit-
  // group Keychain items behind the same probe. A release build without the
  // group keeps the features they back off rather than persist anywhere weaker.
  let protectedStores: ProtectedStores?
  if cacheEnabled {
    protectedStores = .dataProtectionKeychain()
  } else {
    #if DEBUG
      // Unsigned development builds keep the documents process-local, like the
      // SSH catalog and automation fallbacks below; nothing outlives the run.
      protectedStores = .processLocal()
    #else
      protectedStores = nil
    #endif
  }
  // Sealed backups of the native stores and the SSH catalog, kept current on
  // every write once `csec backup setup` has run (NativeStoreBackup.swift).
  // Its settings are a protected item, so it needs the same group.
  let nativeStoreBackup: NativeStoreBackup? =
    cacheEnabled
    ? protectedStores.map { NativeStoreBackup(stores: $0, locations: .production()) } : nil
  var nativeBlobStore: NativeBlobStore?
  var nativeStore: NativeEncryptedFileProvider?
  if cacheEnabled {
    do {
      let files = try SecureNativeStoreFileBackend()
      // The file/blob tier of the same csec:// namespace: whole-file (including
      // binary) values in per-value envelopes, under their own directory and
      // keychain service so a blob store and a document store may share a name
      // without their key records colliding. A single blob envelope (or the
      // index) is larger than the 1 MiB document, so the ciphertext cap is raised.
      let blobFiles = try SecureNativeStoreFileBackend(
        directoryPath: NativeBlobStore.defaultBlobDirectoryPath(),
        maximumCiphertextBytes: max(
          NativeBlobIndex.maximumIndexBytes, NativeBlobStore.maximumBlobBytes) + 1024
      )
      let blobStore = NativeBlobStore(
        keyBackend: SecurityNativeStoreKeyBackend(
          service: SecurityNativeStoreKeyBackend.blobService),
        fileBackend: blobFiles,
        remoteUnlock: remoteUnlock,
        backup: nativeStoreBackup
      )
      nativeBlobStore = blobStore
      nativeStore = NativeEncryptedFileProvider(
        keyBackend: SecurityNativeStoreKeyBackend(),
        fileBackend: files,
        blobStore: blobStore,
        remoteUnlock: remoteUnlock,
        backup: nativeStoreBackup
      )
    } catch {
      FileHandle.standardError.write(
        Data(
          "csecd: native encrypted store unavailable; refusing insecure fallback\n".utf8
        ))
    }
  }


  for line in startupReport.logLines(
    socketPath: socketPath,
    cacheEnabled: cacheEnabled,
    providerPath: providerReport?.canonicalPath,
    providerTrusted: providerTrusted
  ) {
    FileHandle.standardError.write(Data("\(line)\n".utf8))
  }

  #if !DEBUG
    guard startupReport.productionReady else {
      FileHandle.standardError.write(
        Data(
          "csecd: refusing production startup because a non-negotiable security check failed.\n"
            .utf8
        ))
      exit(1)
    }
    guard providerTrusted || nativeStore != nil else {
      FileHandle.standardError.write(
        Data(
          "csecd: refusing production startup because no secure secret provider is available.\n"
            .utf8
        ))
      exit(1)
    }
  #endif

  // The decision log is anchored in two protected items (its key and
  // checkpoint), so it exists exactly when they do. A process-local run keeps
  // its segments in a directory of its own: its key dies with the process, and
  // it must never set aside the installed csecd's log as unreadable.
  let decisionLogDirectory = SealedRecordDirectory(
    path: protectedStores?.persistence == .processLocal
      ? (NSTemporaryDirectory() as NSString)
        .appendingPathComponent("convenient-security-decision-log-\(getpid())")
      : DecisionLog.defaultDirectoryPath()
  )
  let decisionLog: DecisionLog? = protectedStores.map { stores in
    DecisionLog(
      directory: decisionLogDirectory,
      stores: stores,
      onIntegrityEvent: { notifyDecisionLogIntegrity($0) }
    )
  }
  let lifecycle: CsecdLifecycle? = protectedStores.map {
    CsecdLifecycle(stores: $0, log: decisionLog)
  }
  if let decisionLog {
    let verification = await decisionLog.open()
    FileHandle.standardError.write(Data(
      "csecd: decision log \(verification.status.rawValue)\(verification.detail.map { " (\($0))" } ?? "").\n".utf8
    ))
  }
  // The accepted host-audit baseline is sealed under a key the decision log
  // derives for it, with its pointer in a protected item, so a same-UID
  // process cannot add an exemption to silence a regression. Opening it
  // before serving imports an older csecd's plaintext file once, or reports
  // an altered baseline. A process-local run keeps an in-memory baseline:
  // the installed csecd's files are not its to migrate or judge.
  let sealedBaseline: SealedBaselineStore?
  if let protectedStores, protectedStores.persistence == .dataProtectionKeychain, let decisionLog {
    let store = SealedBaselineStore(
      stores: protectedStores,
      log: decisionLog,
      onNotice: { PeriodicHostAudit.reportBaselineNotice($0) }
    )
    HostAuditService.installBaselineStore(store)
    let state = await store.open()
    FileHandle.standardError.write(Data("csecd: host-audit baseline \(state).\n".utf8))
    sealedBaseline = store
  } else {
    sealedBaseline = nil
    HostAuditService.installBaselineStore(InMemoryBaselineStore())
    FileHandle.standardError.write(Data(
      "csecd: host-audit baseline in memory — nothing persists past this run.\n".utf8
    ))
  }
  // Every secret and SSH grant is persisted in one protected item, owned by
  // one actor that both tables hand their changes to, so a restart restores
  // what the human approved instead of asking again.
  let grantPersistence: GrantPersistence? = protectedStores.map {
    GrantPersistence(stores: $0, decisionLog: decisionLog)
  }
  installTerminationHandler(
    stores: protectedStores, log: decisionLog, lifecycle: lifecycle, grants: grantPersistence
  )

  let resolver = SecretResolver(cache: cache)
  let onePasswordProvider = OnePasswordProvider(
    statusObserver: { status in
    let message: String?
    switch status {
    case .notStarted:
      message = nil
    case .cliUnavailable:
      message = "csecd: 1Password CLI unavailable; waiting for a trusted installation.\n"
    case .connecting:
      message = "csecd: requesting 1Password desktop access.\n"
    case .connected:
      message = "csecd: 1Password desktop access ready; keeping it active.\n"
    case .disconnected:
      message = "csecd: 1Password desktop access unavailable; retrying in the background.\n"
    }
    if let message {
      FileHandle.standardError.write(Data(message.utf8))
    }
  },
    attentionObserver: { notifyProviderAttention($0) }
  )
  // Always claim op:// so a missing CLI fails closed instead of allowing a raw
  // reference through as ordinary process data. The provider locates and
  // re-validates the official CLI on every command, which also notices a trusted
  // installation added after csecd launched.
  await resolver.register(onePasswordProvider)
  if let nativeStore {
    await resolver.register(nativeStore)
  } else {
    // csec:// is this daemon's own namespace: with its store unavailable a
    // reference is not known to be absent, so it is never refused as if it were.
    await resolver.registerUnavailable(scheme: "csec")
  }
  let grants = GrantTable(persistence: grantPersistence)
  let consentQueue = ConsentQueue(presentationLock: .shared)
  let consent: ConsentProvider = QueuedConsentProvider(
    underlying: BiometricConsent(), queue: consentQueue
  )
  // Every change to csec's settings (and the other setup steps a touch
  // approves: backups, a restore, phone pairing, machine identities, removing
  // an SSH key or an automation job, deleting stored files, the uninstall
  // cleanup, host fixes) shows csecd's settings panel, typing-guarded like
  // every other approval, not a bare sheet a keystroke can dismiss. These
  // panels are Mac-only, so the mirrored reviewer would hand them straight to
  // the local one; taking the local one on the same queue here lets the
  // services built before it (the remote approval manager the mirror needs)
  // use the panel too.
  let settingsConsent = SettingsChangeConsent(
    underlying: consent,
    review: QueuedPolicyReview(underlying: TrustedPolicyReview(), queue: consentQueue)
  )
  let remoteApproval: RemoteApprovalManager
  if let remoteRelay = CloudKitRemoteApprovalRelay.makeIfEntitled(
    containerIdentifiers: startupReport.cloudKitContainerIdentifiers
  ) {
    remoteApproval = RemoteApprovalManager(
      store: SecurityRemoteApprovalConfigurationStore(),
      relay: remoteRelay,
      consent: settingsConsent,
      cloudKitContainerIdentifier: CloudKitRemoteApprovalRelay.defaultContainerIdentifier,
      accountStatus: { await remoteRelay.approvalAccountStatus() },
      // Which reviews a phone approval could carry out is the providers' to
      // say, through the resolver: a request is mirrored when nothing it
      // names needs an unlock, or everything that does is covered by the
      // phone-held unlock factor.
      remoteUnlock: remoteUnlock,
      coverage: { references in await resolver.remoteUnlockCoverage(references) },
      // Pairing seals a copy of every existing stored item for the phone,
      // reading them with the pairing's one Touch ID.
      backfill: { unlock in await resolver.backfillRemoteUnlockMirrors(localUnlock: unlock) },
      // The request reaches the phone at once; its alert waits while the Mac's
      // own prompt can still be answered here.
      alertGate: RemoteApprovalAlertTiming.live
    )
    // A sign-in, a sign-out, or an account becoming ready changes whether the
    // paired phone can be reached; readiness is rechecked rather than left as
    // it was read at startup.
    NotificationCenter.default.addObserver(
      forName: CloudKitRemoteApprovalRelay.accountChangedNotification,
      object: nil,
      queue: nil
    ) { _ in
      Task { await remoteApproval.accountDidChange() }
    }
  } else {
    remoteApproval = RemoteApprovalManager(
      store: SecurityRemoteApprovalConfigurationStore(),
      relay: UnavailableRemoteApprovalRelay(),
      consent: settingsConsent,
      cloudKitContainerIdentifier: CloudKitRemoteApprovalRelay.defaultContainerIdentifier,
      relayIsConfigured: false,
      // Never asked: without the entitlement readiness stops before the account.
      accountStatus: { .unavailable(.noAccount) }
    )
  }
  // Logs the value-free readiness it finds (or why it is unavailable).
  await remoteApproval.prepare()
  let policyReview: PolicyReviewProvider = QueuedPolicyReview(
    underlying: MirroredPolicyReview(local: TrustedPolicyReview(), remote: remoteApproval),
    queue: consentQueue
  )
  // Delegated approvals: the opt-in, trusted builds, acknowledged hooks and
  // project pairings come only from the protected stores, and the settings
  // gate from C1's factory. Without protected stores it reports unavailable.
  // Its Touch ID steps are csecd's settings panel over the mirrored reviewer:
  // the rules- and hooks-changed acknowledgement it raises for a request can
  // be answered on the paired phone too (av-rcqg), and every other change it
  // makes is Mac-only, which the mirror keeps on this Mac.
  let delegationSettingsConsent = SettingsChangeConsent(
    underlying: consent,
    review: policyReview
  )
  let delegation = ClaudeDelegationService(
    stores: protectedStores,
    gate: makeClaudeSettingsGate(),
    consent: delegationSettingsConsent,
    decisionLog: decisionLog,
    terminalInspection: .live,
    manifestStore: ReleaseManifestStore(),
    uncheckedBuildSeen: { ReleaseUpdateSchedule.checkSoon() },
    credentialStore: KeychainClaudeCredentialStore.shared
  )
  await delegation.load()
  FileHandle.standardError.write(Data(
    "csecd: Claude Code auto-mode approvals \(await delegation.state.rawValue).\n".utf8
  ))
  // The one restore panel of this daemon lifetime, shared by the access and
  // SSH paths so concurrent requests of either kind wait on the same touch.
  let restoration = GrantRestoration(
    resolver: resolver,
    policyReview: policyReview,
    consent: consent,
    persistence: grantPersistence,
    decisionLog: decisionLog,
    terminalInspection: .live
  )
  await restoration.addGrantSource(grants)
  let automationService: AutomationService?
  if cacheEnabled {
    automationService = AutomationService(
      resolver: resolver,
      grantStore: SecurityAutomationGrantStore(),
      materializationStore: SecurityAutomationMaterializationStore(),
      consent: settingsConsent,
      policyReview: policyReview,
      terminalInspection: .live,
      decisionLog: decisionLog,
      runStore: protectedStores?.store(for: AutomationRunsDocument.self)
    )
  } else {
    #if DEBUG
      // Unsigned development builds cannot persist in the product Keychain.
      // Keep the complete feature process-local; release builds never fall back.
      automationService = AutomationService(
        resolver: resolver,
        grantStore: InMemoryAutomationGrantStore(),
        materializationStore: InMemoryAutomationMaterializationStore(),
        consent: settingsConsent,
        policyReview: policyReview,
        terminalInspection: .live,
        decisionLog: decisionLog
      )
    #else
      automationService = nil
    #endif
  }
  // Requests waiting on a human, for a `csec ai` to report the ones started
  // under it (an `ssh`, a bridge client) that cannot say so themselves.
  let humanWaitBoard = HumanWaitBoard()
  let sshSigningService: SSHSigningService?
  let sshKeyCatalog: SSHKeyCatalog? =
    cacheEnabled ? SSHKeyCatalog(store: SecuritySSHKeyCatalogStore(), backup: nativeStoreBackup) : nil
  if cacheEnabled, let sshKeyCatalog {
    sshSigningService = SSHSigningService(
      resolver: resolver,
      catalog: sshKeyCatalog,
      consent: settingsConsent,
      policyReview: policyReview,
      terminalInspection: .live,
      decisionLog: decisionLog,
      persistence: grantPersistence,
      restoration: restoration,
      delegation: delegation,
      humanWaitBoard: humanWaitBoard
    )
  } else {
    #if DEBUG
      // Unsigned local development cannot access the product Keychain group.
      // Keep the catalog process-local and conspicuous; release never silently
      // falls back from code-identity-protected persistence.
      sshSigningService = SSHSigningService(
        resolver: resolver,
        catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore()),
        consent: settingsConsent,
        policyReview: policyReview,
        allowUnverifiedCallersForTesting: true,
        terminalInspection: .live,
        decisionLog: decisionLog,
        persistence: grantPersistence,
        restoration: restoration,
        delegation: delegation,
        humanWaitBoard: humanWaitBoard
      )
    #else
      sshSigningService = nil
    #endif
  }
  if let sshSigningService {
    await restoration.addGrantSource(sshSigningService)
  }
  // The GitHub token proxy keeps only its token's reference, in a csecd-only
  // protected item; with no protected stores there is nowhere to keep it.
  let githubProxy: GitHubProxyService? = protectedStores.map {
    GitHubProxyService(store: $0.store(for: GitHubProxyDocument.self))
  }
  await githubProxy?.load()
  // Machine identities (dev-machine OIDC): the catalog of Secure Enclave key
  // handles and sign-in targets lives in a csecd-only protected item, and its
  // `csec-identity://` references are registered like any provider's, so
  // every sign-in is reviewed, granted, delegated and logged as a secret is.
  // Registered before the persisted grants load, so grants for sign-ins
  // survive a restart.
  let machineIdentityKeys: MachineIdentityKeyFactory?
  if SecureEnclave.isAvailable {
    machineIdentityKeys = .secureEnclave
  } else {
    #if DEBUG
      // An unsigned development build on a Mac without a Secure Enclave keeps
      // software keys for this process only; release builds never do.
      machineIdentityKeys = .processLocalSoftware
    #else
      machineIdentityKeys = nil
    #endif
  }
  let machineIdentityService: MachineIdentityService?
  if let machineIdentityKeys {
    let persistsIdentities = SecureEnclave.isAvailable && protectedStores != nil
    let catalog = MachineIdentityCatalog(
      store: persistsIdentities ? protectedStores?.store(for: MachineIdentityDocument.self) : nil,
      keys: machineIdentityKeys
    )
    await catalog.load()
    await resolver.register(MachineIdentityProvider(catalog: catalog))
    machineIdentityService = MachineIdentityService(
      catalog: catalog,
      consent: settingsConsent,
      hardwareKeys: SecureEnclave.isAvailable,
      persistent: persistsIdentities && protectedStores?.persistence == .dataProtectionKeychain,
      // A removed sign-in takes its grants and its auto-mode pairings with
      // it: a target added later under the same name may sign in elsewhere.
      revokeReferences: { references in
        let removed = await grants.revoke(references: references)
        if removed > 0 { _ = await grantPersistence?.persistNow() }
        _ = await delegation.unpairEverywhere(
          references: references, because: "the machine identity sign-in was removed"
        )
        return removed
      },
      record: { detail, touched in
        await decisionLog?.record(DecisionLogRecord(
          kind: .settings, decider: touched ? .humanLocal : nil, detail: detail
        ))
      },
      terminalInspection: .live
    )
  } else {
    // Without a Secure Enclave there is nothing to sign with; the scheme is
    // still claimed so a reference is never mistaken for an absent one.
    await resolver.registerUnavailable(scheme: MachineIdentityProvider.scheme)
    machineIdentityService = nil
  }
  // Paired projects of live verified Claude Code sessions join the one
  // restore panel: a delegated release never unlocks anything itself.
  await restoration.addItemSource(
    DelegationRestoreSource(delegation: delegation, resolver: resolver, sshKeys: sshSigningService)
  )

  // Before anything is served: put back the grants the previous csecd
  // persisted that pass every load check (same boot, same root process
  // incarnation, unexpired, still-registered references, SSH key still in
  // the catalog, current policy epoch), then record the restart with what was
  // restored and dropped. Restored grants wait for the one restore panel
  // before their sealed stores are reopened.
  var grantCounts: DecisionLogRecord.GrantCounts?
  if let grantPersistence {
    let load = await grantPersistence.load(
      registeredSchemes: Set(await resolver.registeredSchemes()),
      sshKeyFingerprints: await sshSigningService?.catalogFingerprints()
    )
    await grants.restore(load.secret)
    await sshSigningService?.restore(load.ssh)
    grantCounts = load.counts
    let droppedCount = load.counts.dropped?.values.reduce(0, +) ?? 0
    FileHandle.standardError.write(Data(
      ("csecd: restored \(load.counts.secret) secret and \(load.counts.ssh) SSH grant(s); "
        + "dropped \(droppedCount).\n").utf8
    ))
  }
  if let lifecycle {
    let cause = await lifecycle.start(grantCounts: grantCounts)
    await restoration.setRestartCause(cause)
    FileHandle.standardError.write(Data("csecd: restart cause \(cause.rawValue).\n".utf8))
  }
  // Every item a load above found unreadable is kept as found for this run
  // (the build that wrote it, or a Keychain that reads it again, gets it
  // back); csec doctor fails until then, and the log says so once per start.
  for held in protectedStores?.heldItems ?? [] {
    let entry = HeldProtectedItem(item: held.item, reason: held.reason)
    FileHandle.standardError.write(Data(
      "csecd: kept \(held.item) as found: \(held.reason); \(entry.remedy).\n".utf8
    ))
    await decisionLog?.record(DecisionLogRecord(
      kind: .settings,
      detail: "kept \(entry.name) as found: this csecd cannot read the item (\(held.reason)), so what is "
        + "approved meanwhile holds for this run only; \(entry.remedy)"
    ))
  }
  // Before serving anything: if a build that does not keep the remote-unlock
  // mirrors ran since the last one that did, it may have committed or
  // invalidated without them, so every mirror is dropped (each comes back on
  // the next local open or cache write). No mirror is served before this.
  if let remoteUnlock {
    let outcome = await remoteUnlock.reconcileEpoch(previousRun: await lifecycle?.previousRun)
    FileHandle.standardError.write(Data("csecd: remote unlock mirrors \(outcome.rawValue).\n".utf8))
  }
  #if DEBUG
    let agent = Agent(
      resolver: resolver,
      grants: grants,
      consent: consent,
      policyReview: policyReview,
      nativeStore: nativeStore,
      sshSigningService: sshSigningService,
      githubProxy: githubProxy,
      automationService: automationService,
      allowUnverifiedPlansForTesting: true,
      allowUnverifiedAutomationCallersForTesting: true,
      terminalInspection: .live,
      decisionLog: decisionLog,
      grantPersistence: grantPersistence,
      restoration: restoration,
      delegation: delegation,
      humanWaitBoard: humanWaitBoard
    )
    let clientTrustPolicy: SocketPeerTrustPolicy = .allowUnverifiedForTesting
    let sudoAttributions = SudoReviewAttributions(delegatedAgent: { await delegation.sudoAgent(for: $0) })
    let sudoRemoteReviews = SudoRemoteReviewService(
      remote: remoteApproval, decisionLog: decisionLog, allowUnverifiedCallersForTesting: true,
      note: { await delegation.sudoNote(for: $0) },
      recordPairing: { _ = await delegation.recordSudoApproval(helper: $0, surface: .phone) },
      attribution: { await sudoAttributions.attribution(for: $0) }
    )
    let sudoReviewEnds = SudoReviewEndService(
      attributions: sudoAttributions, decisionLog: decisionLog, allowUnverifiedCallersForTesting: true
    )
  #else
    let agent = Agent(
      resolver: resolver,
      grants: grants,
      consent: consent,
      policyReview: policyReview,
      nativeStore: nativeStore,
      sshSigningService: sshSigningService,
      githubProxy: githubProxy,
      automationService: automationService,
      terminalInspection: .live,
      decisionLog: decisionLog,
      grantPersistence: grantPersistence,
      restoration: restoration,
      delegation: delegation,
      humanWaitBoard: humanWaitBoard
    )
    // The launcher, and the sudo review helper for its one request.
    let clientTrustPolicy: SocketPeerTrustPolicy = .requireProductClients
    // Who each sudo review helper's sudo is for, taken while the sudo runs, so
    // a review it abandoned is still logged under its coding agent.
    let sudoAttributions = SudoReviewAttributions(delegatedAgent: { await delegation.sudoAgent(for: $0) })
    let sudoRemoteReviews = SudoRemoteReviewService(
      remote: remoteApproval, decisionLog: decisionLog, note: { await delegation.sudoNote(for: $0) },
      recordPairing: { _ = await delegation.recordSudoApproval(helper: $0, surface: .phone) },
      attribution: { await sudoAttributions.attribution(for: $0) }
    )
    let sudoReviewEnds = SudoReviewEndService(attributions: sudoAttributions, decisionLog: decisionLog)
  #endif

  shutdownAutomation = automationService
  // Before serving anything: put back the automation run leases whose
  // launchers outlived the previous csecd, so a daemon job's next bridge
  // request is served as automation instead of raising an attended panel.
  if let runs = await agent.restoreAutomationRuns() {
    if let unreadable = runs.unreadable {
      FileHandle.standardError.write(Data(
        "csecd: persisted automation runs unreadable (\(unreadable)); restoring none.\n".utf8
      ))
    } else {
      FileHandle.standardError.write(Data(
        ("csecd: restored \(runs.live) automation run(s) and \(runs.tombstones) ended one(s); "
          + "dropped \(runs.dropped).\n").utf8
      ))
    }
  }

  // Tracks in-flight streaming audits so `csec audit` can poll live progress.
  let hostAuditBoard = HostAuditProgressBoard()
  // Uninstall deletes the sealed baseline with everything else: through the
  // store, so it runs after any save already queued and nothing is sealed
  // behind it. Without protected stores an earlier run may still have left
  // the files. A process-local run leaves the installed csecd's alone.
  let eraseBaseline: CsecdUninstaller.FileCleanup
  if let sealedBaseline {
    eraseBaseline = { await sealedBaseline.eraseForUninstall() }
  } else {
    eraseBaseline = { SealedBaselineStore.eraseFiles() }
  }
  let baselineCleanup: [CsecdUninstaller.FileCleanup] =
    protectedStores?.persistence == .processLocal ? [] : [eraseBaseline]
  let uninstaller = CsecdUninstaller(
    consent: settingsConsent, stores: protectedStores, log: decisionLog,
    logDirectory: decisionLogDirectory, fileCleanups: baselineCleanup,
    delegation: delegation
  )
  let nativeStoreBackupService: NativeStoreBackupService?
  if let nativeStoreBackup, let nativeStore {
    nativeStoreBackupService = NativeStoreBackupService(
      backup: nativeStoreBackup,
      nativeStore: nativeStore,
      blobStore: nativeBlobStore,
      catalog: sshKeyCatalog,
      consent: settingsConsent,
      terminalInspection: .live,
      record: { detail in
        await decisionLog?.record(DecisionLogRecord(kind: .settings, decider: .humanLocal, detail: detail))
      }
    )
  } else {
    nativeStoreBackupService = nil
  }
  // `csec edit --remove`: deleting whole-file values csecd's own
  // registrations no longer use. A deleted value takes its grants, its
  // auto-mode pairings and any cached copy with it: a value protected later
  // under the same reference may be a different file.
  let nativeStoreRemovalService: NativeStoreRemovalService? = nativeBlobStore.map { blobStore in
    NativeStoreRemovalService(
      blobStore: blobStore,
      consent: settingsConsent,
      terminalInspection: .live,
      uses: {
        var uses: [String: String] = [:]
        for job in try await automationService?.list() ?? [] {
          for reference in job.references { uses[reference] = "used by the automation job \(job.name)" }
        }
        if let token = await githubProxy?.tokenReference {
          uses[token.uri] = "csec's GitHub token (csec github remove forgets it)"
        }
        for key in try await sshSigningService?.listedSSHKeys() ?? [] {
          uses[key.reference] = "the SSH key \(key.fingerprint) (csec ssh remove \(key.fingerprint) removes it)"
        }
        return uses
      },
      forget: { references in
        let revoked = await grants.revoke(references: references)
        if revoked > 0 { _ = await grantPersistence?.persistNow() }
        _ = await delegation.unpairEverywhere(references: references, because: "the stored value was deleted")
        let lingering = await resolver.invalidate(references: references)
        if !lingering.isEmpty {
          FileHandle.standardError.write(Data(
            "csecd: \(lingering.count) deleted value(s) may still have a cached copy at rest\n".utf8
          ))
        }
        return revoked
      },
      record: { detail, references in
        await decisionLog?.record(DecisionLogRecord(
          kind: .settings, surface: .nativeEdit, refs: references.sorted(), decider: .humanLocal, detail: detail
        ))
      }
    )
  }

  let server = SocketServer(path: socketPath, clientTrustPolicy: clientTrustPolicy) {
    request, caller in
    switch request {
    case .access(let access):
      SessionLineage.shared.record(from: caller.pid)
      return await agent.handle(request: access, caller: caller)
    case .schemes:
      // csec ai and csec exec ask for the schemes before they run anything,
      // so this records the session of every agent tool shell while its
      // leader still runs: what links a job it detaches back to the agent.
      SessionLineage.shared.record(from: caller.pid)
      return await agent.schemes()
    case .capabilities:
      return await agent.capabilities()
    case let .restoreApprovals(request):
      return await agent.restoreApprovals(request: request, caller: caller)
    case .configureRemoteApproval(let request):
      switch request.action {
      case .status:
        return Response(
          requestID: request.requestID,
          remoteApprovalStatus: await wireRemoteApprovalStatus(remoteApproval)
        )
      case .enable:
        guard let phonePairingCode = request.phonePairingCode else {
          return .failed(
            .invalidRequest,
            message: "a phone pairing code is required",
            requestID: request.requestID
          )
        }
        do {
          var shown = caller
          shown.terminal = await TerminalSessionInspector.live.context(forCallerPID: caller.pid)
          let enabled = try await remoteApproval.enable(phonePairingCode: phonePairingCode, caller: shown)
          await decisionLog?.record(DecisionLogRecord(
            kind: .settings, decider: .humanLocal, detail: "iPhone remote approval enabled"
          ))
          return Response(
            requestID: request.requestID,
            remoteApprovalStatus: await wireRemoteApprovalStatus(remoteApproval),
            remoteApprovalMacPairingCode: enabled.macPairingCode,
            remoteApprovalPairingOfferPublished: enabled.pairingOfferPublished
          )
        } catch RemoteApprovalManagerError.denied {
          return .failed(
            .consentDenied,
            message: "remote approval enrollment denied",
            requestID: request.requestID
          )
        } catch RemoteApprovalManagerError.unsupportedBuild {
          return .failed(
            .providerUnavailable,
            message: "this csecd build lacks the CloudKit container entitlement, so it cannot "
              + "reach the iCloud relay. " + PackagePayload.installAdvice,
            requestID: request.requestID
          )
        } catch RemoteApprovalManagerError.remoteUnlockUnavailable {
          return .failed(
            .internalError,
            message: "the phone-held unlock could not be enrolled, so nothing was paired; "
              + "run `csec remote enable` again",
            requestID: request.requestID
          )
        } catch let RemoteApprovalManagerError.iCloudAccountUnavailable(problem) {
          return .failed(
            .providerUnavailable,
            message: "this Mac's iCloud account is unavailable (\(problem.rawValue)); sign into "
              + "iCloud on this Mac with the same Apple Account as the iPhone, then try again",
            requestID: request.requestID
          )
        } catch {
          return .failed(
            .invalidRequest,
            message: "remote approval enrollment could not be completed",
            requestID: request.requestID
          )
        }
      case .disable:
        do {
          var shown = caller
          shown.terminal = await TerminalSessionInspector.live.context(forCallerPID: caller.pid)
          try await remoteApproval.disable(caller: shown)
          await decisionLog?.record(DecisionLogRecord(
            kind: .settings, decider: .humanLocal, detail: "iPhone remote approval disabled"
          ))
          return Response(
            requestID: request.requestID,
            remoteApprovalStatus: wireRemoteApprovalStatus(await remoteApproval.status())
          )
        } catch RemoteApprovalManagerError.denied {
          return .failed(
            .consentDenied,
            message: "remote approval removal denied",
            requestID: request.requestID
          )
        } catch {
          return .failed(
            .internalError,
            message: "remote approval removal could not be completed",
            requestID: request.requestID
          )
        }
      }
    case .configureSSH(let request):
      return await agent.configureSSH(request: request, caller: caller)
    case .configureGitHub(let request):
      return await agent.configureGitHub(request: request, caller: caller)
    case .configureAutomation(let request):
      return await agent.configureAutomation(request: request, caller: caller)
    case let .grants(request):
      return await agent.handleGrants(request: request, caller: caller)
    case .beginSession(let begin):
      return await agent.beginSession(request: begin, caller: caller)
    case .beginOutputRedaction(let begin):
      return await agent.beginOutputRedaction(request: begin, caller: caller)
    case .redactOutputChunk(let chunk):
      return await agent.redactOutputChunk(request: chunk, caller: caller)
    case .endOutputRedaction(let end):
      return await agent.endOutputRedaction(request: end, caller: caller)
    case .takeApprovalNotices(let take):
      return await agent.takeApprovalNotices(request: take, caller: caller)
    case .beginNativeStoreEdit(let begin):
      return await agent.beginNativeStoreEdit(request: begin, caller: caller)
    case .commitNativeStoreEdit(let commit):
      return await agent.commitNativeStoreEdit(request: commit, caller: caller)
    case .commitNativeStoreBlobs(let commit):
      return await agent.commitNativeStoreBlobs(request: commit, caller: caller)
    case .cancelNativeStoreEdit(let cancel):
      return await agent.cancelNativeStoreEdit(request: cancel, caller: caller)
    case .approveProtectedLaunch(let approval):
      guard approval.validate(caller: caller) else {
        return .failed(
          .invalidRequest,
          message: "invalid protected-file launch binding",
          requestID: approval.requestID
        )
      }
      let access = await agent.handle(request: approval.accessRequest, caller: caller)
      if let failure = access.failure {
        return Response(requestID: approval.requestID, failure: failure)
      }
      guard let values = access.values else {
        return .failed(
          .internalError,
          message: "protected-file approval did not produce a release",
          requestID: approval.requestID
        )
      }
      // nil ⇒ a process-lifetime delivery: rootd tears the tmpfs down when the
      // launcher and every capability-GID holder exit, with no wall-clock kill.
      let expiresAt = access.accessExpiresAt
      // Planted-sidecar defense: a symlink-delivered binding may only materialize
      // where its blob was protected. This runs after resolution, so it reuses the
      // already-unlocked store record and adds no second Touch ID.
      guard await agent.protectedFilePathsAreBound(approval.launchPlan.files) else {
        return .failed(
          .invalidRequest,
          message: "a protected-file sidecar does not match its stored path",
          requestID: approval.requestID
        )
      }
      do {
        let payloads = try ProtectedFilePayloadRenderer.render(
          bindings: approval.launchPlan.files,
          values: values
        )
        #if DEBUG
          let rootTrust: RootHelperServerTrustPolicy = .allowUnverifiedForTesting
        #else
          let rootTrust: RootHelperServerTrustPolicy = .requireProductRootHelper
        #endif
        try RootHelperClient(trustPolicy: rootTrust).approve(
          nonce: approval.rendezvousNonce,
          planDigest: approval.launchPlanDigest,
          payloads: payloads,
          expiresAt: expiresAt
        )
        return Response(
          requestID: approval.requestID,
          protectedLaunchApproved: true
        )
      } catch {
        return approval.rootHelperRefusal(error)
      }
    case .hostAudit(let request):
      // Read-only, value-free posture audit. The socket already requires a
      // verified launcher peer; csecd runs the engine with its own privileged
      // (agent-role) root-helper channel and Full Disk Access. This is the
      // interactive path, so it also records the accepted baseline.
      let report = await HostAuditService.runInteractive(
        scanFilesystem: request.scanFilesystem,
        generatedAtHint: ISO8601DateFormatter().string(from: Date()),
        includeRemediation: true
      )
      return Response(requestID: request.requestID, hostAuditReport: report)
    case .hostAuditStart(let request):
      // Streaming path: kick off the same interactive audit as a background job
      // and return the initial progress snapshot. The launcher polls for updates.
      return await hostAuditBoard.start(request)
    case .hostAuditPoll(let request):
      return await hostAuditBoard.poll(request)
    case .hostRemediate(let request):
      return await agent.runHostRemediation(request: request, caller: caller)
    case .hostRecordTriage(let request):
      return await agent.recordHostTriage(request: request, caller: caller)
    case .invalidateCachedReferences(let request):
      return await agent.invalidateCachedReferences(request: request, caller: caller)
    case .decisionLog(let request):
      return await agent.handleDecisionLog(request: request, caller: caller)
    case .uninstallCleanup(let request):
      // One Touch ID in csecd's settings panel naming the terminal (the
      // remote-disable precedent), then the terminal uninstalled state, then
      // the deletions.
      var shown = caller
      shown.terminal = await TerminalSessionInspector.live.context(forCallerPID: caller.pid)
      let outcome = await uninstaller.run(caller: shown)
      switch outcome {
      case .denied:
        return .failed(
          .consentDenied,
          message: "uninstall cleanup denied",
          requestID: request.requestID
        )
      case let .completed(result):
        FileHandle.standardError.write(Data(
          ("csecd: uninstall cleanup finished; "
            + (result.isComplete ? "nothing remains" : "some items remain")
            + "; writing nothing more.\n").utf8
        ))
        return Response(requestID: request.requestID, uninstallCleanup: result)
      }
    case .registerAgentCommand(let registration):
      // Straight to the delegation actor, never behind Agent work: the hook
      // waits on this reply, and a registration touches no secret.
      return Response(
        requestID: registration.requestID,
        agentCommandRegistered: await delegation.register(registration, caller: caller)
      )
    case .configureDelegation(let request):
      return await agent.configureDelegation(request: request, caller: caller)
    case .sudoRemoteReview(let request):
      // Only the sudo review helper gets here (`SocketPeerTrustPolicy`). Straight
      // to the remote provider: no consent queue, no Mac panel, no grant.
      return await sudoRemoteReviews.handle(request, caller: caller)
    case .sudoDelegation(let request):
      // Only the sudo review helper gets here. Straight to the delegation
      // actor: the helper shows no panel until this answers.
      return Response(
        requestID: request.requestID,
        sudoDelegation: await delegation.sudoDelegation(request, caller: caller)
      )
    case .sudoTerminal(let request):
      // Only the sudo review helper gets here. csecd asks the terminal under
      // its own Automation grant, from the helper upwards (its kernel parent
      // is the sudo), so the helper itself never sends an Apple event that
      // macOS would charge to whichever application ran sudo. Every panel
      // asks it first, while its sudo runs: csecd notes then who the sudo is
      // for, for the review's end record.
      await sudoAttributions.note(caller)
      return Response(
        requestID: request.requestID,
        sudoTerminal: await TerminalSessionInspector.live.context(forCallerPID: caller.pid)
      )
    case .sudoReviewEnd(let request):
      // Only the sudo review helper gets here: its report of how its review
      // ended, logged under the coding agent above its sudo.
      return Response(
        requestID: request.requestID,
        sudoReviewEnded: await sudoReviewEnds.handle(request, caller: caller)
      )
    case .sudoPairing(let request):
      // The helper's panel was approved on this Mac with csecd's pairing
      // line showing; csecd checks it made that offer to this very helper.
      return Response(
        requestID: request.requestID,
        sudoPaired: await delegation.recordSudoApproval(helper: caller, surface: .mac)
      )
    case .nativeStoreBackup(let request):
      guard let nativeStoreBackupService else {
        return .failed(
          .providerUnavailable,
          message: "native-store backups need csecd's signed build and its native store",
          requestID: request.requestID
        )
      }
      return await nativeStoreBackupService.handle(request, caller: caller)
    case .configureMachineIdentity(let request):
      guard let machineIdentityService else {
        return .failed(
          .providerUnavailable,
          message: "machine identities need a Mac with a Secure Enclave (Apple silicon or a T2 chip)",
          requestID: request.requestID
        )
      }
      return await machineIdentityService.handle(request, caller: caller)
    case .removeNativeValues(let request):
      guard let nativeStoreRemovalService else {
        return .failed(
          .nativeStoreUnavailable,
          message: "the native encrypted store is unavailable",
          requestID: request.requestID
        )
      }
      return await nativeStoreRemovalService.handle(request, caller: caller)
    }
  }

  FileHandle.standardError.write(Data("csecd: listening on \(socketPath)\n".utf8))
  FileHandle.standardError.write(
    Data(
      "csecd: new references require biometric approval.\n".utf8
    ))
  if cacheEnabled {
    FileHandle.standardError.write(
      Data(
        "csecd: at-rest cache on — resolved values persist in the biometric-gated data-protection keychain.\n"
          .utf8
      ))
  } else {
    let detail = SecCopyErrorMessageString(keychainProbe, nil).map { $0 as String } ?? "unknown"
    let message =
      "⚠️  at-rest cache OFF (keychain probe: OSStatus \(keychainProbe): \(detail)). "
      + "Running WITHOUT persistence — sign, provision, and run the .app build for the SE-cache.\n"
    FileHandle.standardError.write(Data(message.utf8))
  }
  if let nativeStore {
    let directory = await nativeStore.encryptedDirectoryPath()
    FileHandle.standardError.write(
      Data(
        "csecd: native encrypted store on — ciphertext directory \(directory).\n".utf8
      ))
  } else {
    FileHandle.standardError.write(
      Data(
        "csecd: native encrypted store OFF — a provisioned biometric keychain is required.\n".utf8
      ))
  }
  switch protectedStores?.persistence {
  case .dataProtectionKeychain:
    FileHandle.standardError.write(
      Data("csecd: protected stores on — csecd-only documents persist in the data-protection keychain.\n".utf8)
    )
  case .processLocal:
    FileHandle.standardError.write(
      Data("csecd: protected stores process-local — nothing persists past this run (development build).\n".utf8)
    )
  case nil:
    FileHandle.standardError.write(
      Data("csecd: protected stores OFF — the provisioned keychain access group is required.\n".utf8)
    )
  }
  let sshServer: SSHAgentServer?
  if let sshSigningService {
    #if DEBUG
      let sshTrustPolicy: SSHSocketPeerTrustPolicy = .allowUnverifiedForTesting
    #else
      let sshTrustPolicy: SSHSocketPeerTrustPolicy = .requireAppleSSH
    #endif
    sshServer = SSHAgentServer(
      trustPolicy: sshTrustPolicy,
      provider: sshSigningService
    )
    FileHandle.standardError.write(
      Data("csecd: SSH agent listening on \(SSHAgentSocket.defaultPath())\n".utf8)
    )
  } else {
    sshServer = nil
    FileHandle.standardError.write(
      Data("csecd: SSH agent OFF — protected catalog persistence is unavailable.\n".utf8)
    )
  }

  let githubServer: GitHubProxyServer? = githubProxy.map {
    GitHubProxyServer(service: $0, authorizer: agent)
  }
  if githubServer != nil {
    FileHandle.standardError.write(
      Data("csecd: GitHub token proxy listening on \(GitHubProxySocket.defaultPath())\n".utf8)
    )
  } else {
    FileHandle.standardError.write(
      Data("csecd: GitHub token proxy OFF — protected persistence is unavailable.\n".utf8)
    )
  }

  // AppKit policy review must be presented on the main actor. Keep the socket
  // accept loop on its documented dedicated thread and run the accessory app's
  // event loop on the process main thread.
  Thread.detachNewThread {
    do {
      try server.run()
    } catch {
      FileHandle.standardError.write(Data("csecd: \(error)\n".utf8))
      exit(1)
    }
  }
  if let sshServer {
    Thread.detachNewThread {
      do {
        try sshServer.run()
      } catch {
        FileHandle.standardError.write(Data("csecd: SSH agent failed: \(error)\n".utf8))
      }
    }
  }
  if let githubServer {
    Thread.detachNewThread {
      do {
        try githubServer.run()
      } catch {
        FileHandle.standardError.write(Data("csecd: GitHub token proxy failed: \(error)\n".utf8))
      }
    }
  }

  // Serving local requests does not wait for 1Password, and csecd never
  // reaches for a 1Password authorization on its own: the first one is
  // acquired by the first request that needs it. This loop only holds an
  // existing session inside the desktop integration's ten-minute idle window,
  // so a later read costs no second prompt on top of csec's own Touch ID.
  observeLockStateForOnePassword(onePasswordProvider)
  Task(priority: .utility) {
    await onePasswordProvider.maintainConnection()
  }

  // Periodic value-free re-audit + regression notifications (Decision 6).
  PeriodicHostAudit.start(machineIdentities: machineIdentityService)

  // The signed release manifest: one notification when a newer csec exists.
  ReleaseUpdateSchedule.start()
}

/// The SIGTERM handler. `launchctl kickstart -k`, `bootout` and every pkg
/// upgrade stop csecd with SIGTERM, so this is where a run ends cleanly: a
/// grants write still in flight lands (so a grant approved a moment ago is
/// restored), the usage checkpoint is flushed and `last-run` marked clean, so
/// the next start can tell a restart from a crash. After `csec uninstall` it
/// writes nothing: every protected write is refused by then. It then re-raises
/// SIGTERM with the default action, so launchd sees the same termination it
/// always did.
private func installTerminationHandler(
  stores: ProtectedStores?,
  log: DecisionLog?,
  lifecycle: CsecdLifecycle?,
  grants: GrantPersistence?
) {
  // Caught, not ignored: an ignored signal stays ignored in every program
  // csecd spawns (host-audit commands among them), a caught one does not.
  CsecdShutdown.catchTerminationSignal()
  let source = DispatchSource.makeSignalSource(
    signal: SIGTERM,
    queue: DispatchQueue(label: CSECBuildIdentity.named("shutdown"))
  )
  source.setEventHandler {
    let finished = DispatchSemaphore(value: 0)
    Task.detached {
      await grants?.settle()
      // A run lease begun a moment ago is restored after the restart.
      await shutdownAutomation?.flushPersistedRuns()
      _ = await CsecdShutdown.flush(stores: stores, log: log, lifecycle: lifecycle)
      finished.signal()
    }
    _ = finished.wait(timeout: .now() + .seconds(CsecdShutdown.flushDeadlineSeconds))
    CsecdShutdown.restoreDefaultTerminationSignal()
    kill(getpid(), SIGTERM)
  }
  source.resume()
  terminationSource = source
}

/// Retained for csecd's lifetime; the source stops delivering when released.
nonisolated(unsafe) private var terminationSource: DispatchSourceSignal?

/// The automation service whose lease writes the SIGTERM handler lands. Set
/// once, before csecd serves anything; the handler only reads it.
nonisolated(unsafe) private var shutdownAutomation: AutomationService?

/// One notification per integrity finding (the host audit's regression
/// notification is the precedent). A development binary without a bundle
/// cannot post one and logs instead.
private func notifyDecisionLogIntegrity(_ verification: DecisionLogVerification) {
  let summary = verification.findings
    .map { "\($0.stream.rawValue) \($0.finding.rawValue.replacingOccurrences(of: "_", with: " "))" }
    .joined(separator: ", ")
  FileHandle.standardError.write(Data(
    ("csecd: decision log integrity finding: \(summary); "
      + (verification.recorded ? "recorded as log_integrity.\n" : "could not be recorded; the log is held.\n")).utf8
  ))
  guard Bundle.main.bundleIdentifier != nil else { return }
  Task { @MainActor in
    let content = UNMutableNotificationContent()
    content.title = "Decision log altered"
    content.body = verification.recorded
      ? "csec's decision log was changed outside csecd (\(summary)). "
        + "The finding is recorded and the log continues; run `csec log --kind log_integrity`."
      : "csec's decision log was changed outside csecd (\(summary)), and the finding could not "
        + "be recorded. The log is held until it can be; run `csec log --verify`."
    try? await UNUserNotificationCenter.current().add(UNNotificationRequest(
      identifier: "csec-log-integrity-\(UUID().uuidString.lowercased())",
      content: content, trigger: nil))
  }
}

/// What a provider's own app needs from the person at the Mac
/// (`ProviderAttention`): one notification per account, which each new state
/// replaces and a settled one withdraws. The one saying a prompt is waiting
/// sounds, as it is only worth anything while that prompt is still up. A
/// development binary without a bundle cannot post one and logs instead.
private func notifyProviderAttention(_ attention: ProviderAttention) {
  let identifier = attention.notificationIdentifier
  let words = attention.notification
  guard Bundle.main.bundleIdentifier != nil else {
    if let words {
      FileHandle.standardError.write(Data("csecd: \(words.title): \(words.body)\n".utf8))
    }
    return
  }
  let sounds = attention.kind == .awaitingAuthorization
  Task { @MainActor in
    let center = UNUserNotificationCenter.current()
    guard let words else {
      center.removeDeliveredNotifications(withIdentifiers: [identifier])
      return
    }
    let content = UNMutableNotificationContent()
    content.title = words.title
    content.body = words.body
    if sounds { content.sound = .default }
    try? await center.add(UNNotificationRequest(identifier: identifier, content: content, trigger: nil))
  }
}

private func wireRemoteApprovalStatus(
  _ status: RemoteApprovalManagerStatus
) -> RemoteApprovalConfigurationStatus {
  RemoteApprovalConfigurationStatus(status)
}

/// The status with what csecd knows about the paired phone: its confirmation
/// of the pairing, its app, notification and alert state, and the unlock
/// enrollment.
private func wireRemoteApprovalStatus(
  _ manager: RemoteApprovalManager
) async -> RemoteApprovalConfigurationStatus {
  let status = await manager.status()
  let health = await manager.pairingHealth()
  return RemoteApprovalConfigurationStatus(status, health: health)
}


/// Stop holding 1Password sessions warm while the machine is asleep, or while
/// the screen is locked *and* 1Password locks with the device.
///
/// A keepalive ping is only worth suppressing when it could re-authorize — a
/// Touch ID prompt with no user action behind it. That is the case on sleep, and
/// on screen lock when 1Password's `onDeviceLock` is set (the app revokes its
/// session then). When 1Password does *not* lock with the device, the session
/// survives a screen lock, so csec keeps pinging and the next request after
/// unlocking costs no prompt. Nothing resumes a suspend but a real request.
func observeLockStateForOnePassword(_ provider: OnePasswordProvider) {
  let suspend: @Sendable (Notification) -> Void = { notification in
    let reason = notification.name.rawValue
    Task { await provider.suspendKeepalive(reason: reason) }
  }
  // Screen lock is gated on 1Password's own onDeviceLock setting: the provider
  // reads it and either suspends or holds the session open across the lock.
  DistributedNotificationCenter.default().addObserver(
    forName: Notification.Name("com.apple.screenIsLocked"),
    object: nil,
    queue: nil
  ) { _ in
    Task { await provider.handleScreenLock() }
  }
  let workspace = NSWorkspace.shared.notificationCenter
  for name in [
    NSWorkspace.willSleepNotification,
    NSWorkspace.screensDidSleepNotification,
    NSWorkspace.sessionDidResignActiveNotification,
  ] {
    workspace.addObserver(forName: name, object: nil, queue: nil, using: suspend)
  }
}
