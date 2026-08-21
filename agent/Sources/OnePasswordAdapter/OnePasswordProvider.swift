import Foundation
import ConvenientSecurity

/// 1Password provider backed by the `op` CLI. All 1Password specifics — locating
/// `op`, invoking it, and letting it parse `op://vault/item[/section]/field` —
/// live here. `op read` authenticates on demand via the desktop app, so the
/// value returns straight into the agent's heap over a pipe.
///
/// The CLI is one integration mechanism; a native SDK or a Rust-core FFI could
/// replace it behind this same interface without touching the agent core.
public struct OnePasswordProvider: SecretProvider {
    private let cliPath: String?
    private let cacheMaxAge: TimeInterval

    public init(cliPath: String? = OnePasswordCLI.locate(), cacheMaxAge: TimeInterval = 24 * 3600) {
        self.cliPath = cliPath
        self.cacheMaxAge = cacheMaxAge
    }

    public var schemes: Set<String> { ["op"] }

    public func resolve(_ ref: SecretRef) async throws -> ResolvedSecret {
        guard let cliPath else { throw OnePasswordError.cliNotFound }

        let result = try await OnePasswordCLI.run(cliPath, ["read", "--no-newline", ref.uri])
        guard result.status == 0 else {
            let stderr = String(data: result.stderr, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let message = (stderr?.isEmpty == false) ? stderr! : "op exited \(result.status)"
            throw OnePasswordError.readFailed(reference: ref.uri, status: result.status, message: message)
        }
        guard let value = String(data: result.stdout, encoding: .utf8) else {
            throw OnePasswordError.notUTF8(ref.uri)
        }
        return ResolvedSecret(value: value, cacheHint: .cacheable(maxAge: cacheMaxAge))
    }

    public func authenticate() async throws {
        // `op read` authenticates on demand via the 1Password desktop app, so
        // there is nothing to pre-establish here.
    }

    public func isAvailable() async -> Bool {
        cliPath != nil
    }
}

public enum OnePasswordError: Error, CustomStringConvertible {
    case cliNotFound
    case readFailed(reference: String, status: Int32, message: String)
    case notUTF8(String)

    public var description: String {
        switch self {
        case .cliNotFound:
            return "the verified official 1Password CLI (op) was not found"
        case let .readFailed(reference, status, message):
            return "op read \(reference) failed (exit \(status)): \(message)"
        case let .notUTF8(reference):
            return "op returned non-UTF-8 data for \(reference)"
        }
    }
}
