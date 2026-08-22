import Foundation
import Security
@preconcurrency import AppKit
import ConvenientSecurity
import OnePasswordAdapter
#if canImport(Darwin)
import Darwin
#endif

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
        nativeStore = NativeEncryptedFileProvider(
            keyBackend: SecurityNativeStoreKeyBackend(),
            fileBackend: files
        )
    } catch {
        FileHandle.standardError.write(Data(
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
    FileHandle.standardError.write(Data(
        "csecd: refusing production startup because a non-negotiable security check failed.\n".utf8
    ))
    exit(1)
}
guard providerTrusted || nativeStore != nil else {
    FileHandle.standardError.write(Data(
        "csecd: refusing production startup because no secure secret provider is available.\n".utf8
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
let riskBackend: RiskJudgmentBackend = cacheEnabled
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

let server = SocketServer(path: socketPath, clientTrustPolicy: clientTrustPolicy) { request, caller in
    switch request {
    case let .access(access):
        return await agent.handle(request: access, caller: caller)
    case .schemes:
        return await agent.schemes()
    case .capabilities:
        return await agent.capabilities()
    case let .beginOutputRedaction(begin):
        return await agent.beginOutputRedaction(request: begin, caller: caller)
    case let .redactOutputChunk(chunk):
        return await agent.redactOutputChunk(request: chunk, caller: caller)
    case let .endOutputRedaction(end):
        return await agent.endOutputRedaction(request: end, caller: caller)
    case let .beginNativeStoreEdit(begin):
        return await agent.beginNativeStoreEdit(request: begin, caller: caller)
    case let .commitNativeStoreEdit(commit):
        return await agent.commitNativeStoreEdit(request: commit, caller: caller)
    case let .cancelNativeStoreEdit(cancel):
        return await agent.cancelNativeStoreEdit(request: cancel, caller: caller)
    }
}

FileHandle.standardError.write(Data("csecd: listening on \(socketPath)\n".utf8))
FileHandle.standardError.write(Data(
    "csecd: new references require Touch ID.\n".utf8
))
if cacheEnabled {
    FileHandle.standardError.write(Data(
        "csecd: at-rest cache on — resolved values persist in the biometric-gated data-protection keychain.\n".utf8
    ))
} else {
    let detail = SecCopyErrorMessageString(keychainProbe, nil).map { $0 as String } ?? "unknown"
    let message = "⚠️  at-rest cache OFF (keychain probe: OSStatus \(keychainProbe): \(detail)). "
        + "Running WITHOUT persistence — sign, provision, and run the .app build for the SE-cache.\n"
    FileHandle.standardError.write(Data(message.utf8))
}
if let nativeStore {
    let directory = await nativeStore.encryptedDirectoryPath()
    FileHandle.standardError.write(Data(
        "csecd: native encrypted store on — ciphertext directory \(directory).\n".utf8
    ))
} else {
    FileHandle.standardError.write(Data(
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
let application = NSApplication.shared
application.setActivationPolicy(.accessory)
application.run()
