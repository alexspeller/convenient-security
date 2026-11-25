import Foundation

/// Value-free Codex configuration planning. Socket paths come from AgentSocket,
/// never from a machine-specific example or a secret storage provider.
public enum CodexSandboxConfiguration {
    public struct Merge {
        public let data: Data
        public let detail: String
        public let preview: String
    }

    public static func merge(_ original: Data, socketPath: String) throws -> Merge {
        guard socketPath.hasPrefix("/"), socketPath.utf8.count <= 4_096,
              !socketPath.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw SetupOnboardingError.configurationConflict("the csecd socket path is invalid")
        }
        let socket = URL(fileURLWithPath: socketPath).standardizedFileURL.resolvingSymlinksInPath().path
        var document = try SetupTOMLDocument(original)
        let selected = try document.string(["default_permissions"])
        let legacyMode = try document.string(["sandbox_mode"]) ?? "workspace-write"
        let proxyEnabled = try document.boolean(["features", "network_proxy"]) ?? false
        if selected == ":danger-full-access" || (selected == nil && legacyMode == "danger-full-access") {
            return try finish(&document, socket: socket, keeping: selected,
                              detail: "Codex full-access mode already permits the agent socket")
        }

        let profile: String
        let network: [[String]: String]
        var changes: [([String], String)] = []
        if let selected, !selected.hasPrefix(":") {
            profile = selected
            network = try effectiveNetwork(profile: profile, document: document)
        } else {
            guard selected == nil || selected == ":workspace" || selected == ":read-only",
                  selected != nil || ["workspace-write", "read-only"].contains(legacyMode) else {
                throw SetupTOMLDocument.unsupported()
            }
            let readOnly = selected == ":read-only" || (selected == nil && legacyMode == "read-only")
            if !readOnly, selected == nil,
               try document.boolean(["sandbox_workspace_write", "network_access"]) == true,
               !proxyEnabled {
                return try finish(&document, socket: socket, keeping: selected,
                                  detail: "Codex already permits local agent connections")
            }
            let base = readOnly ? "csec-read-only" : "csec-workspace"
            var available = base
            var suffix = 2
            while document.contains(["permissions", available])
                && !(isOwnedProfile(available, document: document, socket: socket)
                     && !document.references(available, outside: ["permissions", available])) {
                available = "\(base)-\(suffix)"
                suffix += 1
            }
            profile = available
            network = [:]
            changes.append((["default_permissions"], SetupTOMLDocument.quote(profile)))
            changes.append((["permissions", profile, "extends"],
                            SetupTOMLDocument.quote(readOnly ? ":read-only" : ":workspace")))
            if !readOnly && selected == nil {
                let filesystem = ["permissions", profile, "filesystem"]
                for (option, path) in [("exclude_tmpdir_env_var", ":tmpdir"), ("exclude_slash_tmp", ":slash_tmp")] {
                    if try document.boolean(["sandbox_workspace_write", option]) == true {
                        changes.append((filesystem + [path], "\"read\""))
                    }
                }
                var seenRoots = Set<String>()
                for root in try document.strings(["sandbox_workspace_write", "writable_roots"]) ?? [] {
                    guard root.hasPrefix("/") || root.hasPrefix("~/") else { throw SetupTOMLDocument.unsupported() }
                    guard seenRoots.insert(root).inserted else { continue }
                    changes.append((filesystem + [root], "\"write\""))
                }
            }
        }

        let networkEnabled = try boolean(network[["enabled"]]) ?? false
        if networkEnabled && !proxyEnabled {
            return try finish(&document, socket: socket, keeping: profile,
                              detail: "Codex already permits local agent connections")
        }
        if !networkEnabled {
            // Activating a previously disabled network must not also activate
            // dormant domain/socket allowances or broad local-service access.
            let dormantAllowance = try network.contains { path, raw in
                if path.first == "domains" || path.first == "unix_sockets" {
                    return raw != "\"deny\"" && raw != "'deny'"
                        && path != ["unix_sockets", socket]
                }
                if ["allow_local_binding", "dangerously_allow_all_unix_sockets",
                    "dangerously_allow_non_loopback_proxy"].contains(path.first ?? "") {
                    return try boolean(raw) == true
                }
                return false
            }
            guard !dormantAllowance else {
                throw SetupOnboardingError.configurationConflict(
                    "the selected Codex profile has inactive network allowances; enabling its proxy "
                        + "would also activate those permissions. Review that profile's network policy "
                        + "before adding the csecd socket"
                )
            }
        }
        changes.append((["features", "network_proxy"], "true"))
        let networkPath = ["permissions", profile, "network"]
        changes.append((networkPath + ["enabled"], "true"))
        // Ephemeral listener ports avoid clashes with another Codex session.
        for option in ["proxy_url", "socks_url"] where network[[option]] == nil {
            changes.append((networkPath + [option], "\"http://127.0.0.1:0\""))
        }
        changes.append((networkPath + ["unix_sockets", socket], "\"allow\""))

        var preview: [String] = []
        for (path, value) in changes {
            try document.set(path, value)
            preview.append(path.map(SetupTOMLDocument.quote).joined(separator: ".") + " = " + value)
        }
        return try finish(
            &document, socket: socket, keeping: profile,
            detail: "allow the current user's csecd socket in Codex profile \(profile), keeping its filesystem rules and filtered network policy",
            preview: preview
        )
    }

    /// Positional hook trust belongs to Codex. Only erase slots identified by
    /// the user-hook removal plan; never create or change a trusted hash.
    public static func removingHookState(_ original: Data, keys: [String]) throws -> Merge {
        var document = try SetupTOMLDocument(original)
        var preview: [String] = []
        for key in keys.sorted() {
            let path = ["hooks", "state", key]
            guard document.contains(path) else { continue }
            try document.remove(path)
            preview.append("remove hooks.state.\(SetupTOMLDocument.quote(key))")
        }
        return Merge(data: try document.rendered(), detail: "remove superseded csec user-hook state",
                     preview: preview.joined(separator: "\n"))
    }

    private static func finish(
        _ document: inout SetupTOMLDocument, socket: String, keeping selected: String?,
        detail: String, preview: [String] = []
    ) throws -> Merge {
        var preview = preview
        let names = Set(document.tablePaths(beneath: ["permissions"]).compactMap { $0.count > 1 ? $0[1] : nil })
            .union(document.entries.keys.compactMap { $0.first == "permissions" && $0.count > 1 ? $0[1] : nil })
        for name in names.sorted() where name != selected {
            let prefix = ["permissions", name]
            guard isOwnedProfile(name, document: document, socket: socket),
                  !document.references(name, outside: prefix) else { continue }
            try document.remove(prefix)
            preview.append("remove unreferenced permissions.\(SetupTOMLDocument.quote(name))")
        }
        return Merge(data: try document.rendered(), detail: detail, preview: preview.joined(separator: "\n"))
    }

    /// Setup generated exactly these five
    /// fields. A csec-like name alone is not ownership: any customization,
    /// extra table, different socket or external reference keeps the profile.
    private static func isOwnedProfile(
        _ name: String, document: SetupTOMLDocument, socket: String
    ) -> Bool {
        let base: String
        if name == "csec-workspace" || name.hasPrefix("csec-workspace-") { base = "csec-workspace" }
        else if name == "csec-read-only" || name.hasPrefix("csec-read-only-") { base = "csec-read-only" }
        else { return false }
        if name != base {
            let suffix = String(name.dropFirst(base.count + 1))
            guard let number = Int(suffix), number >= 2, String(number) == suffix else { return false }
        }
        let prefix = ["permissions", name]
        let fields = document.entries.filter { $0.key.starts(with: prefix) }
        guard fields.count == 5,
              (try? document.string(prefix + ["extends"])) == (base == "csec-read-only" ? ":read-only" : ":workspace"),
              (try? document.boolean(prefix + ["network", "enabled"])) == true,
              (try? document.string(prefix + ["network", "proxy_url"])) == "http://127.0.0.1:0",
              (try? document.string(prefix + ["network", "socks_url"])) == "http://127.0.0.1:0" else { return false }
        let socketPrefix = prefix + ["network", "unix_sockets"]
        guard let socketEntry = fields.keys.first(where: { $0.starts(with: socketPrefix) && $0.count == 5 }),
              socketEntry.last?.hasPrefix("/") == true,
              URL(fileURLWithPath: socketEntry.last!).standardizedFileURL.resolvingSymlinksInPath().path == socket,
              (try? document.string(socketEntry)) == "allow" else { return false }
        let allowedTables = [prefix, prefix + ["network"], socketPrefix]
        return document.tablePaths(beneath: prefix).allSatisfy { allowedTables.contains($0) }
    }

    public static func recoveryMessage(socketPath: String) -> String {
        "agent socket access denied by sandbox or filesystem permissions. "
            + "Retry the original command outside the sandbox through the normal approval flow "
            + "(Codex: sandbox_permissions=\"require_escalated\"), or add this socket to the active "
            + "Codex permission profile in config.toml:\n"
            + "[permissions.<active-profile>.network.unix_sockets]\n"
            + "\(SetupTOMLDocument.quote(socketPath)) = \"allow\"\n"
            + "The profile needs network.enabled=true and features.network_proxy=true; keep the proxy "
            + "enabled to preserve network filtering. Run `csec setup` in a terminal to configure this "
            + "automatically, then select the updated profile or restart Codex."
    }

    private static func boolean(_ raw: String?) throws -> Bool? {
        switch raw {
        case nil: return nil
        case "true": return true
        case "false": return false
        default: throw SetupTOMLDocument.unsupported()
        }
    }

    private static func effectiveNetwork(
        profile: String, document: SetupTOMLDocument
    ) throws -> [[String]: String] {
        var result: [[String]: String] = [:]
        var current: String? = profile
        var visited = Set<String>()
        while let name = current {
            if name == ":workspace" || name == ":read-only" { break }
            guard visited.count < 32, visited.insert(name).inserted,
                  document.contains(["permissions", name]) else { throw SetupTOMLDocument.unsupported() }
            let prefix = ["permissions", name, "network"]
            for (path, entry) in document.entries where path.starts(with: prefix) {
                let key = Array(path.dropFirst(prefix.count))
                guard !key.isEmpty else { throw SetupTOMLDocument.unsupported() }
                if result[key] == nil { result[key] = entry.raw }
            }
            current = try document.string(["permissions", name, "extends"])
        }
        return result
    }
}
