import Foundation

/// Recognizes a coding agent in a process ancestry chain.
///
/// A coding agent creates a fresh non-interactive shell (and often another
/// wrapper) for every tool call, so the agent itself — not the per-call shell —
/// is the stable boundary a human is actually approving. The process name and
/// executable path only *select* that bounded root for display and grant
/// scoping; they are never an authentication claim. Kernel ancestry, the
/// recorded PID/start-time pair, the audit session, and the human review remain
/// the authority checks.
public enum CodingAgentIdentity {
    /// The coding agent `pid` is running, or nil. Both inputs are advisory
    /// kernel metadata; neither is trusted beyond choosing a root and a label.
    public static func client(
        name: String?,
        executablePath: String?
    ) -> AICommandHookClient? {
        if let name, let client = AICommandHookClient(rawValue: name) { return client }
        guard let executablePath, executablePath.hasPrefix("/") else { return nil }

        let basename = (executablePath as NSString).lastPathComponent
        if let client = AICommandHookClient(rawValue: basename) { return client }

        // Anthropic's native installer currently execs a version-named binary,
        // so proc_name and the basename are both the version. Match only its
        // dedicated CLI versions directory; do not collapse Claude.app or an
        // arbitrary process whose argv happens to call itself "claude".
        let marker = "/.local/share/claude/versions/"
        guard !executablePath.contains(".app/Contents/"),
              let markerRange = executablePath.range(of: marker) else { return nil }
        let version = executablePath[markerRange.upperBound...]
        return !version.isEmpty && !version.contains("/") ? .claude : nil
    }

    /// Human-facing product name for a recognized client.
    public static func displayName(_ client: AICommandHookClient) -> String {
        switch client {
        case .claude: return "Claude Code"
        case .codex: return "Codex"
        }
    }
}
