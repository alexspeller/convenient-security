import Foundation
import Security
import ConvenientSecurity
import OnePasswordAdapter
#if canImport(Darwin)
import Darwin
#endif

// The resident agent. It listens, authenticates peers, tracks subtree grants,
// gates new references through Touch ID, and resolves through the provider,
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

// The at-rest SE-cache needs the provisioned access-group entitlement, which only
// a signed build carries. Probe once (non-interactive) and fall back to no
// persistence in an unsigned dev run, rather than failing every write.
let keychainProbe = SecurityKeychainBackend.probe()
let cacheEnabled = keychainProbe == errSecSuccess
let cache: SecretCache = cacheEnabled ? KeychainSecretCache() : NullSecretCache()
let providerPath = OnePasswordCLI.locate()
let providerReport = providerPath.map { OnePasswordCLI.trustReport(for: $0) }
let providerTrusted = providerReport?.trusted == true
let startupReport = StartupSecurityReport.currentAgent()

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
guard providerTrusted, let providerPath else {
    FileHandle.standardError.write(Data(
        "csecd: refusing production startup without the verified official 1Password CLI.\n".utf8
    ))
    exit(1)
}
#endif

let resolver = SecretResolver(cache: cache)
await resolver.register(OnePasswordProvider(cliPath: providerPath))
let grants = GrantTable()
let consent: ConsentProvider = BiometricConsent()
#if DEBUG
let agent = Agent(
    resolver: resolver,
    grants: grants,
    consent: consent,
    allowUnverifiedPlansForTesting: true
)
let clientTrustPolicy: SocketPeerTrustPolicy = .allowUnverifiedForTesting
#else
let agent = Agent(resolver: resolver, grants: grants, consent: consent)
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

do {
    try server.run() // blocks, accepting connections
} catch {
    FileHandle.standardError.write(Data("csecd: \(error)\n".utf8))
    exit(1)
}
