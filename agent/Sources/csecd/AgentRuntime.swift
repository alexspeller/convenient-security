import ConvenientSecurity
import Foundation
import OnePasswordAdapter
import Security

#if canImport(Darwin)
  import Darwin
#endif

func startAgentServer() async {
  // The resident agent. It listens, authenticates peers, tracks subtree grants,
  // gates new references through Touch ID, and resolves through registered providers,
  // caching resolved values in the biometric-gated data-protection keychain.
  //
  // There is deliberately no runtime auto-approval switch in this shipping
  // executable. Automated tests use cs-fake-agent or inject a ConsentProvider in
  // process; an environment-controlled bypass here would also be available to
  // same-uid malware launching the genuine signed binary.

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
    let logPath = (AgentSocket.directory() as NSString).appendingPathComponent("csecd.log")
    freopen(logPath, "a", stdout)
    freopen(logPath, "a", stderr)
  }

  // The at-rest cache and native-store keys need the provisioned access-group
  // entitlement, which only a signed build carries. Probe once (non-interactive)
  // and fall back to neither feature in an unsigned development run.
  let keychainProbe = SecurityKeychainBackend.probe()
  let cacheEnabled = keychainProbe == errSecSuccess
  let cache: SecretCache = cacheEnabled ? KeychainSecretCache() : NullSecretCache()
  let providerPath = OnePasswordCLI.locate()
  let providerReport = providerPath.map { OnePasswordCLI.trustReport(for: $0) }
  let providerTrusted = providerReport?.trusted == true
  let startupReport = StartupSecurityReport.currentAgent()
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
        fileBackend: blobFiles
      )
      nativeStore = NativeEncryptedFileProvider(
        keyBackend: SecurityNativeStoreKeyBackend(),
        fileBackend: files,
        blobStore: blobStore
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

  let resolver = SecretResolver(cache: cache)
  #if DEBUG
    let registerOnePassword = providerPath != nil
  #else
    let registerOnePassword = providerTrusted
  #endif
  if registerOnePassword, let providerPath {
    await resolver.register(OnePasswordProvider(cliPath: providerPath))
  }
  if let nativeStore {
    await resolver.register(nativeStore)
  }
  let grants = GrantTable()
  let consent: ConsentProvider = BiometricConsent()
  let riskBackend: RiskJudgmentBackend =
    cacheEnabled
    ? SecurityRiskJudgmentBackend()
    : InMemoryRiskJudgmentBackend()
  let riskJudgments = RiskJudgmentStore(backend: riskBackend)
  let policyReview: PolicyReviewProvider = TrustedPolicyReview()
  #if DEBUG
    let agent = Agent(
      resolver: resolver,
      grants: grants,
      consent: consent,
      riskJudgments: riskJudgments,
      policyReview: policyReview,
      nativeStore: nativeStore,
      allowUnverifiedPlansForTesting: true
    )
    let clientTrustPolicy: SocketPeerTrustPolicy = .allowUnverifiedForTesting
  #else
    let agent = Agent(
      resolver: resolver,
      grants: grants,
      consent: consent,
      riskJudgments: riskJudgments,
      policyReview: policyReview,
      nativeStore: nativeStore
    )
    let clientTrustPolicy: SocketPeerTrustPolicy = .requireProductLauncher
  #endif

  // Tracks in-flight streaming audits so `csec audit` can poll live progress.
  let hostAuditBoard = HostAuditProgressBoard()

  let server = SocketServer(path: socketPath, clientTrustPolicy: clientTrustPolicy) {
    request, caller in
    switch request {
    case .access(let access):
      return await agent.handle(request: access, caller: caller)
    case .schemes:
      return await agent.schemes()
    case .capabilities:
      return await agent.capabilities()
    case .beginSession(let begin):
      return await agent.beginSession(request: begin, caller: caller)
    case .beginOutputRedaction(let begin):
      return await agent.beginOutputRedaction(request: begin, caller: caller)
    case .redactOutputChunk(let chunk):
      return await agent.redactOutputChunk(request: chunk, caller: caller)
    case .endOutputRedaction(let end):
      return await agent.endOutputRedaction(request: end, caller: caller)
    case .beginNativeStoreEdit(let begin):
      return await agent.beginNativeStoreEdit(request: begin, caller: caller)
    case .commitNativeStoreEdit(let commit):
      return await agent.commitNativeStoreEdit(request: commit, caller: caller)
    case .commitNativeStoreBlobs(let commit):
      return await agent.commitNativeStoreBlobs(request: commit, caller: caller)
    case .cancelNativeStoreEdit(let cancel):
      return await agent.cancelNativeStoreEdit(request: cancel, caller: caller)
    case .risk(let risk):
      return await agent.handleRiskOperation(request: risk, caller: caller)
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
      guard let values = access.values,
        let expiresAt = access.accessExpiresAt
      else {
        return .failed(
          .internalError,
          message: "protected-file approval did not produce a bounded release",
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
        return .failed(
          .deliveryNotSupported,
          message: "the authenticated root helper could not accept this launch",
          requestID: approval.requestID
        )
      }
    case .hostAudit(let request):
      // Read-only, value-free posture audit. The socket already requires a
      // verified launcher peer; csecd runs the engine with its own privileged
      // (agent-role) root-helper channel and Full Disk Access. This is the
      // interactive path, so it also records the accepted baseline.
      let report = await HostAuditService.runInteractive(
        scanFilesystem: request.scanFilesystem,
        generatedAtHint: ISO8601DateFormatter().string(from: Date())
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
    }
  }

  FileHandle.standardError.write(Data("csecd: listening on \(socketPath)\n".utf8))
  FileHandle.standardError.write(
    Data(
      "csecd: new references require Touch ID.\n".utf8
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

  // Periodic value-free re-audit + regression notifications (Decision 6).
  PeriodicHostAudit.start()
}
