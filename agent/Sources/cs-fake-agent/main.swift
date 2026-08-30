import Foundation
import ConvenientSecurity

// A long-running FAKE agent for cross-language client integration tests. It
// serves a fixed set of demo references from memory with auto-approved consent —
// no 1Password, no real secrets, no biometrics. NOT a production surface; it
// exists so the Ruby and Node.js clients can be tested against a real agent
// speaking the real wire protocol without a provisioned build or a live vault.
//
// Listens on AgentSocket.defaultPath() (honouring CSEC_SOCKET), so a test points
// it at a private temp socket and runs the client against that.

struct StaticProvider: SecretProvider {
    let values: [String: String]
    var schemes: Set<String> { ["op"] }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: Data(value.utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

let demoValues = ["op://demo/db/url": "postgres://s3cr3t"]

let socketPath = AgentSocket.defaultPath()
try? AgentSocket.ensureDirectory()

let resolver = SecretResolver(cache: NullSecretCache())
await resolver.register(StaticProvider(values: demoValues))
let grants = GrantTable()
let agent = Agent(
    resolver: resolver,
    grants: grants,
    consent: AutoApproveConsent(),
    policyReview: AutoApprovePolicyReview(),
    allowLegacyAccessForTesting: true,
    allowUnverifiedPlansForTesting: true
)

let server = SocketServer(path: socketPath, clientTrustPolicy: .allowUnverifiedForTesting) { request, caller in
    switch request {
    case let .access(access):
        return await agent.handle(request: access, caller: caller)
    case .schemes:
        return await agent.schemes()
    case .capabilities:
        return await agent.capabilities()
    case let .beginSession(begin):
        return await agent.beginSession(request: begin, caller: caller)
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
    case let .commitNativeStoreBlobs(commit):
        return await agent.commitNativeStoreBlobs(request: commit, caller: caller)
    case let .cancelNativeStoreEdit(cancel):
        return await agent.cancelNativeStoreEdit(request: cancel, caller: caller)
    case let .approveProtectedLaunch(approval):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent has no root-helper rendezvous",
            requestID: approval.requestID
        )
    case let .hostAudit(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent does not run the host posture audit",
            requestID: request.requestID
        )
    case let .hostAuditStart(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent does not run the host posture audit",
            requestID: request.requestID
        )
    case let .hostAuditPoll(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent does not run the host posture audit",
            requestID: request.requestID
        )
    case let .hostRemediate(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent does not run host remediation",
            requestID: request.requestID
        )
    case let .hostRecordTriage(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent does not persist host triage",
            requestID: request.requestID
        )
    case let .invalidateCachedReferences(request):
        return await agent.invalidateCachedReferences(request: request, caller: caller)
    }
}

FileHandle.standardError.write(Data(
    "cs-fake-agent: listening on \(socketPath) (in-memory demo values, auto-approve)\n".utf8
))

do {
    try server.run()
} catch {
    FileHandle.standardError.write(Data("cs-fake-agent: \(error)\n".utf8))
    exit(1)
}
