import Foundation

/// A consumer of an ordinary reference, independent of its storage provider.
public enum GcloudCommand {
    /// Additional API transports (notably storage downloads) reload credentials.
    /// An exec-fd pipe drains, so use exec's environment delivery, never token argv.
    public static let tokenVariable = "CLOUDSDK_AUTH_ACCESS_TOKEN"

    public static let environment: [String: String] = [
        "CLOUDSDK_CORE_DISABLE_FILE_LOGGING": "true",
        "CLOUDSDK_CORE_LOG_HTTP": "false",
        "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT": "",
        "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE": "",
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": "",
    ]

    public static func accepts(_ arguments: [String]) -> Bool {
        // Management/export commands don't consume the supplied access token.
        // Impersonation stays in csecd: gcloud's own path caches its result.
        // An argv file can conceal alternate authentication or logging flags.
        let refusedWords: Set<String> = ["auth", "config", "components", "bq", "gsutil"]
        let refusedFlags = ["--impersonate-service-account", "--access-token-file", "--flags-file", "--log-http"]
        return !arguments.contains { word in
            let flag = (word.components(separatedBy: "=").first ?? "").replacingOccurrences(of: "_", with: "-")
            return refusedWords.contains(word)
                || (flag.hasPrefix("--") && flag.count > 2 && refusedFlags.contains { $0.hasPrefix(flag) })
        }
    }

    public static func shellFunction(executable: String, reference: String, fish: Bool) -> String {
        let command = MachineIdentityShell.command([executable, "gcloud", "--item", reference, "--"])
        if fish { return "# csec Google sign-in\nfunction gcloud\n    \(command) $argv\nend\n" }
        return "# csec Google sign-in\ngcloud() {\n    \(command) \"$@\"\n}\n"
    }

    public static func shellStartup(_ original: String, sourcePath: String) throws -> String {
        let start = "# >>> csec gcloud >>>"
        let end = "# <<< csec gcloud <<<"
        let block = "\(start)\n. \(MachineIdentityShell.quote(sourcePath))\n\(end)"
        if let first = original.range(of: start) {
            guard let last = original.range(of: end, range: first.upperBound..<original.endIndex),
                  original.range(of: start, range: first.upperBound..<original.endIndex) == nil,
                  original.range(of: end, range: last.upperBound..<original.endIndex) == nil else {
                throw MachineIdentitySetupError.invalidCommand
            }
            return original.replacingCharacters(in: first.lowerBound..<last.upperBound, with: block)
        }
        guard !original.contains(end) else { throw MachineIdentitySetupError.invalidCommand }
        return original + (original.isEmpty || original.hasSuffix("\n") ? "" : "\n") + block + "\n"
    }
}
