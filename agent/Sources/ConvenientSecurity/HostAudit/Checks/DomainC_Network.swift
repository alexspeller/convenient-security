import Foundation
import CSECRootProtocol

// Domain C — Network exposure (catalog HA-C01…HA-C10).
//
// Same shape as `DomainA_Platform`: each check is a small `HostCheck` value that
// reads the injected `HostAuditContext`, parses tolerantly, and returns a
// value-free `HostFinding` via `meta.finding(...)`. This domain is all about how
// reachable/interceptable the host is on the network — the inbound firewall, the
// exposed listeners, sharing daemons, custom trust anchors, proxies and tunnels.
//
// VALUE-FREE discipline is especially load-bearing here: `scutil --dns`,
// `scutil --proxy` and `security dump-trust-settings` all emit real nameserver
// IPs, proxy hosts, PAC URLs, and CA common names. None of that ever reaches
// evidence/anchor — we report counts, presence flags, and classification only.

public enum DomainC_Network {
    public static var checks: [any HostCheck] {
        [ApplicationFirewall(), FirewallHardening(), OutboundFirewall(),
         ExposedServices(), SharingServices(), DiscoverySharing(),
         ResolverIntegrity(), CustomTrustAnchors(), SystemProxy(), VPNPosture()]
    }

    // MARK: HA-C01

    /// Inbound Application Firewall global state. `--getglobalstate` prints
    /// "Firewall is enabled. (State = 1)" / "... disabled. (State = 0)". State can
    /// also be 2 (block-all). We key on the numeric State token for robustness.
    struct ApplicationFirewall: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-C01", title: "Inbound Application Firewall on",
            severity: .medium, tier: .runtimeReadable,
            remediation: .autoPrivileged, remediationKey: "HA-C01",
            anchor: "System Settings → Network → Firewall (`socketfilterfw --setglobalstate on`)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
                arguments: ["--getglobalstate"], label: "socketfilterfw.getglobalstate"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not read the application-firewall global state.")
            }
            let out = r.standardOutput.lowercased()
            if let state = DomainC_Network.firewallState(out) {
                return state >= 1
                    ? meta.finding(.pass, evidence: "The inbound application firewall is enabled.")
                    : meta.finding(.fail, evidence: "The inbound application firewall is disabled.")
            }
            // Fall back to the English word when the State token is missing.
            if out.contains("enabled") && !out.contains("disabled") {
                return meta.finding(.pass, evidence: "The inbound application firewall is enabled.")
            }
            if out.contains("disabled") {
                return meta.finding(.fail, evidence: "The inbound application firewall is disabled.")
            }
            return meta.finding(.unknown, evidence: "The application-firewall global state was unreadable.")
        }
    }

    /// Extract the numeric `State = <n>` token from a lowercased socketfilterfw line.
    static func firewallState(_ lowercased: String) -> Int? {
        guard let range = lowercased.range(of: "state = ") else { return nil }
        let tail = lowercased[range.upperBound...]
        let digits = tail.prefix { $0.isNumber }
        return Int(digits)
    }

    // MARK: HA-C02

    /// Firewall hardening: stealth mode, block-all, and the "automatically allow
    /// signed/downloaded software" holes. `--getloggingmode` is GONE on macOS 26
    /// (prints usage, exits 255, and in a combined call aborts everything after
    /// it), so we query each supported flag individually and report logging mode
    /// as unknown/unsupported rather than a fail.
    struct FirewallHardening: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-C02", title: "Stealth mode + block-all + logging",
            severity: .low, tier: .runtimeReadable,
            remediation: .autoPrivileged, remediationKey: "HA-C02",
            anchor: "System Settings → Network → Firewall → Options (stealth mode; stop auto-allowing signed software)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let stealth = await ctx.commands.run(HostCommand(
                executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
                arguments: ["--getstealthmode"], label: "socketfilterfw.getstealthmode"))
            let allowSigned = await ctx.commands.run(HostCommand(
                executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
                arguments: ["--getallowsigned"], label: "socketfilterfw.getallowsigned"))

            let stealthOut = stealth.succeeded ? stealth.standardOutput.lowercased() : nil
            let stealthOn = stealthOut.map { $0.contains("stealth mode is on") } ?? false
            let stealthReadable = stealthOut != nil

            // getallowsigned prints two lines: built-in signed and downloaded
            // signed. The downloaded-signed hole is the one that quietly lets
            // freshly downloaded signed apps through the firewall.
            let allowOut = allowSigned.succeeded ? allowSigned.standardOutput.lowercased() : nil
            let downloadedSignedAllowed: Bool? = allowOut.flatMap { text in
                for line in text.split(separator: "\n") where line.contains("downloaded signed") {
                    if line.contains("enabled") { return true }
                    if line.contains("disabled") { return false }
                }
                return nil
            }

            // Fail if a readable hardening flag is in its weaker state: either
            // stealth mode is off, or downloaded-signed software is auto-allowed.
            let downloadedHole = downloadedSignedAllowed == true
            if (stealthReadable && !stealthOn) || downloadedHole {
                var parts: [String] = []
                if stealthReadable && !stealthOn { parts.append("stealth mode is off") }
                if downloadedHole { parts.append("downloaded signed software is auto-allowed through the firewall") }
                return meta.finding(.fail, evidence: parts.joined(separator: "; ") + ".")
            }
            if !stealthReadable && downloadedSignedAllowed == nil {
                return meta.finding(.unknown, evidence: "Firewall hardening flags were unreadable (logging mode is unsupported on this macOS).")
            }
            return meta.finding(.pass, evidence: "Stealth mode is on and downloaded signed software is not auto-allowed (logging mode is not readable on this macOS).")
        }
    }

    // MARK: HA-C03

    /// ★ Outbound firewall present (LuLu / Little Snitch). The direct exfiltration
    /// tripwire for same-user malware. Presence is confirmed by the app bundle AND
    /// an active network_extension provider — installed-but-inactive is unknown.
    struct OutboundFirewall: HostCheck {
        static let bundles = ["/Applications/LuLu.app", "/Applications/Little Snitch.app"]
        // Network-extension bundle-id fragments that prove the outbound firewall
        // is actually enforcing (not merely installed).
        static let neNeedles = ["lulu", "at.obdev", "littlesnitch"]

        let meta = HostCheckMeta(
            id: "HA-C03", title: "Outbound firewall present",
            severity: .medium, tier: .runtimeReadable, onThesis: true,
            remediation: .advise,
            anchor: "Install LuLu (Objective-See) or Little Snitch to add an outbound tripwire")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let installed = Self.bundles.contains { ctx.files.isDirectory($0) || ctx.files.fileExists($0) }
            // Cross-reference the active system extensions for an enforcing NE.
            let sysext = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/systemextensionsctl", arguments: ["list"],
                label: "systemextensionsctl.list"))
            let active: Bool = {
                guard sysext.succeeded else { return false }
                let lower = sysext.standardOutput.lowercased()
                return sysext.standardOutput.split(separator: "\n").contains { line in
                    let l = line.lowercased()
                    return l.contains("activated enabled") && Self.neNeedles.contains { lower.contains($0) && l.contains($0) }
                }
            }()

            if installed && active {
                return meta.finding(.pass, evidence: "An outbound firewall is installed and its network extension is active (note: a default-allow ruleset weakens it; the ruleset is not verifiable non-invasively).")
            }
            if installed && !active {
                return meta.finding(.unknown, evidence: "An outbound-firewall app is present but its enforcing network extension was not observed active.")
            }
            return meta.finding(.fail, evidence: "No outbound firewall (LuLu / Little Snitch) is installed; there is no per-connection exfiltration tripwire.")
        }
    }

    // MARK: HA-C04

    /// ★ Exposed local services. `lsof` NAME column encodes the bind scope:
    /// `*:PORT` / `0.0.0.0:PORT` / a LAN IP is off-box reachable; `127.0.0.1:` /
    /// `[::1]:` is loopback. We flag the bind address, not the port, and never
    /// echo PIDs, users, or the literal addresses. As non-root this undercounts.
    struct ExposedServices: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-C04", title: "Exposed local services",
            severity: .medium, tier: .runtimeReadable, onThesis: true,
            remediation: .advise,
            anchor: "Bind dev services (Postgres/Redis/Mongo/Elasticsearch) to 127.0.0.1, not 0.0.0.0/*")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let tcp = await ctx.commands.run(HostCommand(
                executable: "/usr/sbin/lsof",
                arguments: ["-nP", "-iTCP", "-sTCP:LISTEN"], label: "lsof.tcp.listen"))
            let udp = await ctx.commands.run(HostCommand(
                executable: "/usr/sbin/lsof", arguments: ["-nP", "-iUDP"], label: "lsof.udp"))

            // `lsof` exits non-zero on zero matches — that is "no listeners", not
            // a launch failure. Only a genuine launchFailed is unknown.
            if tcp.launchFailed && udp.launchFailed {
                return meta.finding(.unknown, evidence: "Could not enumerate listening sockets.")
            }

            let exposed = DomainC_Network.offBoxBinds(tcp.standardOutput)
                + DomainC_Network.offBoxBinds(udp.standardOutput)
            if exposed == 0 {
                return meta.finding(.pass, evidence: "No listening service is bound off-box; visible listeners are loopback-only (non-root enumeration is a lower bound).")
            }
            return meta.finding(.fail, evidence: "\(exposed) listening socket(s) are bound to a non-loopback address and reachable off-box (non-root enumeration is a lower bound).")
        }
    }

    /// Count `lsof` rows whose NAME bind address is off-box reachable
    /// (`*`, `0.0.0.0`, `::`, or a routable LAN IP), excluding loopback.
    static func offBoxBinds(_ output: String) -> Int {
        var count = 0
        for line in output.split(separator: "\n") {
            let lower = line.lowercased()
            if lower.hasPrefix("command ") { continue }          // header row
            // The NAME field is the last whitespace token before an optional
            // "(LISTEN)" suffix; extract the bind address left of the final ':'.
            guard let name = bindName(String(line)) else { continue }
            guard let addr = bindAddress(name) else { continue }
            if addr == "127.0.0.1" || addr == "::1" || addr.hasPrefix("[::1]") { continue }
            if addr == "*" || addr == "0.0.0.0" || addr == "::" || addr == "[::]" {
                count += 1
                continue
            }
            // Any remaining concrete address (a LAN IP or hostname) is off-box.
            if !addr.isEmpty { count += 1 }
        }
        return count
    }

    /// The NAME token (host:port form) from an lsof row, ignoring a trailing state.
    static func bindName(_ line: String) -> String? {
        let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard !fields.isEmpty else { return nil }
        // Drop a trailing "(LISTEN)" / "(ESTABLISHED)" state marker.
        var idx = fields.count - 1
        if fields[idx].hasPrefix("(") { idx -= 1 }
        guard idx >= 0 else { return nil }
        let token = fields[idx]
        return token.contains(":") ? token : nil
    }

    /// The bind address left of the final ':' in a `host:port` NAME token.
    static func bindAddress(_ name: String) -> String? {
        guard let sep = name.lastIndex(of: ":") else { return nil }
        return String(name[..<sep])
    }

    // MARK: HA-C05

    /// Sharing services off unless needed (Remote Login/SSH, ARD, Screen/File
    /// Sharing, …). Tier R! — the authoritative per-service confirmation needs
    /// root, so we read it through `ctx.privileged.read(.sharingServices)`. On
    /// `.unavailable` we report unknown, never a pass.
    struct SharingServices: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-C05", title: "Sharing services off unless needed",
            severity: .medium, tier: .runtimePrivileged,
            remediation: .autoPrivileged, remediationKey: "HA-C05",
            anchor: "System Settings → General → Sharing (disable unused sharing services)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.sharingServices) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "Sharing-service state needs the root helper, which was unavailable.")
            case let .output(result):
                let lower = result.output.lowercased()
                if result.exitCode != 0 && lower.isEmpty {
                    return meta.finding(.unknown, evidence: "The root helper returned no readable sharing-service state.")
                }
                // The helper reports each service label's on/off state. Count the
                // labels observed enabled — the value-free "how many are on".
                let enabled = DomainC_Network.enabledSharingServiceCount(result.output)
                if enabled == 0 {
                    return meta.finding(.pass, evidence: "No sharing services are enabled.")
                }
                return meta.finding(.fail, evidence: "\(enabled) sharing service(s) are enabled; disable any you are not actively using.")
            }
        }
    }

    /// Count sharing-service labels reported enabled by the root helper. Tolerates
    /// both the `launchctl print-disabled` (`"<label>" => enabled|disabled`) form
    /// and a `<name>: On|Off` / `<name> enabled` summary form.
    static func enabledSharingServiceCount(_ output: String) -> Int {
        var count = 0
        for rawLine in output.split(separator: "\n") {
            let line = rawLine.lowercased()
            if line.contains("=>") {
                // launchctl print-disabled: a *disabled service* line means the
                // service is OFF; `=> enabled` means it is NOT disabled → running.
                if line.contains("=> enabled") { count += 1 }
                continue
            }
            // systemsetup / summary style: "remote login: on", "... enabled".
            if line.contains(": on") || line.hasSuffix(" on") { count += 1; continue }
            if (line.contains("enabled")) && !line.contains("disabled") && line.contains("sharing") { count += 1 }
        }
        return count
    }

    // MARK: HA-C06

    /// AirDrop discoverability / AirPlay Receiver scope. AirDrop
    /// `DiscoverableMode == "Everyone"` is the broad-exposure flag. AirPlay key is
    /// Apple's own misspelling `AirplayReceiverEnabled` (read via -currentHost).
    struct DiscoverySharing: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-C06", title: "AirDrop / AirPlay Receiver / Bonjour",
            severity: .low, tier: .runtimeReadable,
            remediation: .advise,
            anchor: "Control Center → AirDrop (not \"Everyone\"); System Settings → General → AirDrop & Handoff (AirPlay Receiver)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let airdrop = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/defaults",
                arguments: ["read", "com.apple.sharingd", "DiscoverableMode"],
                label: "defaults.sharingd.discoverablemode"))
            let airplay = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/defaults",
                arguments: ["-currentHost", "read", "com.apple.controlcenter", "AirplayReceiverEnabled"],
                label: "defaults.controlcenter.airplayreceiver"))

            let airdropEveryone = airdrop.succeeded
                && airdrop.standardOutput.lowercased().contains("everyone")
            let airplayOn = airplay.succeeded
                && airplay.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines) == "1"

            if airdropEveryone {
                let extra = airplayOn ? " AirPlay Receiver is also on." : ""
                return meta.finding(.fail, evidence: "AirDrop is discoverable to Everyone.\(extra)")
            }
            if airplayOn {
                return meta.finding(.fail, evidence: "AirPlay Receiver is enabled; confirm its scope is appropriate.")
            }
            return meta.finding(.pass, evidence: "AirDrop is not discoverable to Everyone and the AirPlay Receiver is off (or at a default scope).")
        }
    }

    // MARK: HA-C07

    /// Resolver integrity via `scutil --dns`. VALUE-FREE: we count resolvers and
    /// flag the presence of custom search domains on the default resolver — we
    /// never echo nameserver IPs or search-domain names. A missing default
    /// resolver is unknown, not a pass.
    struct ResolverIntegrity: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-C07", title: "Resolver integrity",
            severity: .low, tier: .runtimeReadable,
            remediation: .advise,
            anchor: "System Settings → Network → DNS (verify resolvers match your network/VPN)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/sbin/scutil", arguments: ["--dns"], label: "scutil.dns"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not read the DNS resolver configuration.")
            }
            let lower = r.standardOutput.lowercased()
            let resolvers = lower.components(separatedBy: "resolver #").count - 1
            guard resolvers > 0 else {
                return meta.finding(.unknown, evidence: "No resolver stanzas were readable from the DNS configuration.")
            }
            // Presence of any search-domain line is worth surfacing (a hijacking
            // search domain can redirect short-name lookups). Count only.
            let searchDomains = lower.components(separatedBy: "search domain[").count - 1
            if searchDomains > 0 {
                return meta.finding(.fail, evidence: "The DNS configuration has \(resolvers) resolver(s) and defines search domain(s); verify none can redirect short-name lookups.")
            }
            return meta.finding(.pass, evidence: "The DNS configuration has \(resolvers) resolver(s) and no search-domain override; verify they match your network/VPN.")
        }
    }

    // MARK: HA-C08

    /// ★ Custom root CAs / trust anchors. Every non-Apple root anchor in the
    /// admin (`-d`) or user domain enables silent TLS interception. CRITICAL
    /// value-free: never echo a CN/hostname — we count `Cert N:` entries and the
    /// TrustRoot/TrustAsRoot result types only, and redact all label text.
    struct CustomTrustAnchors: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-C08", title: "Custom root CAs / trust anchors",
            severity: .high, tier: .runtimeReadable, onThesis: true,
            remediation: .advise,
            anchor: "Keychain Access → System/login → Certificates (review non-Apple trusted roots)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let admin = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/security",
                arguments: ["dump-trust-settings", "-d"], label: "security.dump-trust-settings.admin"))
            let user = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/security",
                arguments: ["dump-trust-settings"], label: "security.dump-trust-settings.user"))

            // `security dump-trust-settings` exits non-zero when a domain has no
            // trust settings ("No Trust Settings were found."). That is the secure
            // state (no added anchors), not a read failure — only a launchFailed
            // on BOTH domains is genuinely unknown.
            if admin.launchFailed && user.launchFailed {
                return meta.finding(.unknown, evidence: "Could not read custom trust settings.")
            }
            let added = DomainC_Network.addedAnchorCount(admin.standardOutput)
                + DomainC_Network.addedAnchorCount(user.standardOutput)
            if added == 0 {
                return meta.finding(.pass, evidence: "No user- or admin-added root trust anchors are present beyond the Apple baseline.")
            }
            return meta.finding(.fail, evidence: "\(added) user/admin-added root trust anchor(s) are present; each enables silent TLS interception (corporate-proxy CAs are legitimate but still worth reviewing).")
        }
    }

    /// Count added root anchors in one `dump-trust-settings` domain by counting
    /// `Cert N:` entries. VALUE-FREE: the CN/label following the colon is never
    /// read or retained — only the entry is counted.
    static func addedAnchorCount(_ output: String) -> Int {
        var count = 0
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("Cert ") && trimmed.contains(":") { count += 1 }
        }
        return count
    }

    // MARK: HA-C09

    /// Global HTTP(S) proxy / PAC via `scutil --proxy`. VALUE-FREE: flag that a
    /// proxy or PAC is enabled; never echo the host or the PAC URL. Benign
    /// defaults (ExceptionsList / FTPPassive only) are a pass.
    struct SystemProxy: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-C09", title: "Global HTTP(S) proxy",
            severity: .medium, tier: .runtimeReadable,
            remediation: .advise,
            anchor: "System Settings → Network → Proxies (remove an unexpected proxy or PAC URL)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/sbin/scutil", arguments: ["--proxy"], label: "scutil.proxy"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not read the system proxy configuration.")
            }
            let httpEnabled = DomainC_Network.proxyFlagEnabled(r.standardOutput, key: "HTTPEnable")
            let httpsEnabled = DomainC_Network.proxyFlagEnabled(r.standardOutput, key: "HTTPSEnable")
            let pacEnabled = DomainC_Network.proxyFlagEnabled(r.standardOutput, key: "ProxyAutoConfigEnable")

            var flags: [String] = []
            if httpEnabled { flags.append("an HTTP proxy") }
            if httpsEnabled { flags.append("an HTTPS proxy") }
            if pacEnabled { flags.append("a PAC auto-config URL") }
            if flags.isEmpty {
                return meta.finding(.pass, evidence: "No system HTTP/HTTPS proxy and no PAC URL are configured.")
            }
            return meta.finding(.fail, evidence: "A system network proxy is configured (\(flags.joined(separator: ", "))); confirm it is expected (classic MITM persistence).")
        }
    }

    /// Whether a `scutil --proxy` dictionary key (e.g. `HTTPEnable`) is set to 1.
    static func proxyFlagEnabled(_ output: String, key: String) -> Bool {
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix(key) else { continue }
            // Form: "HTTPEnable : 1"
            if let sep = trimmed.range(of: ":") {
                let value = trimmed[sep.upperBound...].trimmingCharacters(in: .whitespaces)
                return value == "1"
            }
        }
        return false
    }

    // MARK: HA-C10

    /// VPN / relay posture via `scutil --nc list`. Informational (catalog Fix
    /// n/a). VALUE-FREE: count configured and connected tunnels; never echo the
    /// display name, UUID, or provider bundle.
    struct VPNPosture: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-C10", title: "VPN / relay posture",
            severity: .low, tier: .runtimeReadable, remediation: .none,
            anchor: "Informational — review configured VPN/relay tunnels in System Settings → VPN")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/sbin/scutil", arguments: ["--nc", "list"], label: "scutil.nc.list"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not enumerate configured VPN connections.")
            }
            var configured = 0
            var connected = 0
            for line in r.standardOutput.split(separator: "\n") {
                let lower = line.lowercased()
                // Connection rows begin with a "*"/" " enabled marker and carry a
                // "(connected)"/"(disconnected)" state. Skip the header line.
                guard lower.contains("(connected)") || lower.contains("(disconnected)") else { continue }
                configured += 1
                if lower.contains("(connected)") { connected += 1 }
            }
            if configured == 0 {
                return meta.finding(.pass, evidence: "No VPN/relay tunnels are configured.")
            }
            return meta.finding(.pass, evidence: "\(configured) VPN/relay tunnel(s) are configured (\(connected) connected); confirm each is one you recognize.")
        }
    }
}
