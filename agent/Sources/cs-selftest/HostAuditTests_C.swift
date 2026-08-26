import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain C — Network exposure (HA-C01…HA-C10). Every check gets a PASS and a
// FAIL case; R!/read-failure-bearing checks also get an UNKNOWN case asserting
// the honest-coverage guarantee (never .pass when the underlying read failed).
// All fixtures are synthetic and value-free: fake bundle ids, fake counts, fake
// version strings only — never a real secret, token, or /Users path.
func hostAuditTests_C() async {

    // MARK: HA-C01 — Inbound Application Firewall (label socketfilterfw.getglobalstate)

    await expectStatus("HA-C01", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "socketfilterfw.getglobalstate": ok("Firewall is enabled. (State = 1)")]),
        .pass, "firewall State = 1 -> pass")
    // Block-all (State = 2) is still "on".
    await expectStatus("HA-C01", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "socketfilterfw.getglobalstate": ok("Firewall is enabled. (State = 2)")]),
        .pass, "firewall State = 2 (block-all) -> pass")
    await expectStatus("HA-C01", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "socketfilterfw.getglobalstate": ok("Firewall is disabled. (State = 0)")]),
        .fail, "firewall State = 0 -> fail")
    await expectStatus("HA-C01", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "socketfilterfw.getglobalstate": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "firewall state unreadable -> unknown")

    // MARK: HA-C02 — Stealth mode + downloaded-signed hole
    // labels socketfilterfw.getstealthmode, socketfilterfw.getallowsigned

    // Pass: stealth on AND downloaded-signed disabled (both flags readable).
    await expectStatus("HA-C02", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "socketfilterfw.getstealthmode": ok("Firewall stealth mode is on"),
            "socketfilterfw.getallowsigned": ok(
                "Automatically allow built-in signed software ENABLED.\n" +
                "Automatically allow downloaded signed software DISABLED.")]),
        .pass, "stealth on + downloaded-signed disabled -> pass")
    // Fail: stealth off.
    await expectStatus("HA-C02", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "socketfilterfw.getstealthmode": ok("Firewall stealth mode is off"),
            "socketfilterfw.getallowsigned": ok(
                "Automatically allow built-in signed software ENABLED.\n" +
                "Automatically allow downloaded signed software DISABLED.")]),
        .fail, "stealth off -> fail")
    // Fail: downloaded-signed software auto-allowed (the quiet hole).
    await expectStatus("HA-C02", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "socketfilterfw.getstealthmode": ok("Firewall stealth mode is on"),
            "socketfilterfw.getallowsigned": ok(
                "Automatically allow built-in signed software ENABLED.\n" +
                "Automatically allow downloaded signed software ENABLED.")]),
        .fail, "downloaded-signed auto-allowed -> fail")
    // Unknown: both hardening flags unreadable (logging mode unsupported on this OS).
    await expectStatus("HA-C02", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "socketfilterfw.getstealthmode": HostCommandResult(exitCode: 255, launchFailed: true),
            "socketfilterfw.getallowsigned": HostCommandResult(exitCode: 255, launchFailed: true)]),
        .unknown, "both hardening flags unreadable -> unknown")

    // MARK: HA-C03 — Outbound firewall present (LuLu / Little Snitch)
    // bundle presence via files + label systemextensionsctl.list

    // Pass: bundle installed AND an active enforcing network extension.
    await expectStatus("HA-C03", in: DomainC_Network.checks,
        makeAuditContext(
            commands: ["systemextensionsctl.list": ok(
                "1 extension(s)\n" +
                "--- com.apple.system_extension.network_extension\n" +
                "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
                "*\t*\tTEAMIDXXXX\tcom.objective-see.lulu.extension (1.0/1.0)\tLuLu\t[activated enabled]")],
            files: FakeFileInspector(directories: ["/Applications/LuLu.app"])),
        .pass, "outbound FW installed + NE active -> pass")
    // Unknown: bundle present but no active enforcing extension observed.
    await expectStatus("HA-C03", in: DomainC_Network.checks,
        makeAuditContext(
            commands: ["systemextensionsctl.list": ok("0 extension(s)")],
            files: FakeFileInspector(directories: ["/Applications/LuLu.app"])),
        .unknown, "outbound FW installed but NE inactive -> unknown")
    // Fail: no outbound firewall installed at all.
    await expectStatus("HA-C03", in: DomainC_Network.checks,
        makeAuditContext(
            commands: ["systemextensionsctl.list": ok("0 extension(s)")],
            files: FakeFileInspector()),
        .fail, "no outbound firewall installed -> fail")

    // MARK: HA-C04 — Exposed local services (labels lsof.tcp.listen, lsof.udp)

    // Pass: only loopback listeners visible.
    await expectStatus("HA-C04", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "lsof.tcp.listen": ok(
                "COMMAND     PID USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME\n" +
                "PLACEHDR    222 user   6u   IPv4   0xXXXX      0t0  TCP 127.0.0.1:6379 (LISTEN)"),
            "lsof.udp": HostCommandResult(exitCode: 1)]),
        .pass, "loopback-only listeners -> pass")
    // Fail: a wildcard bind reachable off-box.
    await expectStatus("HA-C04", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "lsof.tcp.listen": ok(
                "COMMAND     PID USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME\n" +
                "PLACEHDR    111 user   5u   IPv4   0xXXXX      0t0  TCP *:5432 (LISTEN)"),
            "lsof.udp": HostCommandResult(exitCode: 1)]),
        .fail, "wildcard bind off-box -> fail")
    // Unknown: both lsof probes genuinely failed to launch.
    await expectStatus("HA-C04", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "lsof.tcp.listen": HostCommandResult(exitCode: 1, launchFailed: true),
            "lsof.udp": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "lsof cannot enumerate -> unknown")

    // MARK: HA-C05 — Sharing services off unless needed (R!, privileged .sharingServices)

    // Pass: root helper reports no sharing services enabled.
    await expectStatus("HA-C05", in: DomainC_Network.checks,
        makeAuditContext(privileged: [
            .sharingServices: .output(HostHelperResult(exitCode: 0, output:
                "\tdisabled services = {\n" +
                "\t\t\"com.apple.PLACEHOLDERd\" => disabled\n" +
                "\t}"))]),
        .pass, "no sharing services enabled -> pass")
    // Fail: a sharing service label reported enabled.
    await expectStatus("HA-C05", in: DomainC_Network.checks,
        makeAuditContext(privileged: [
            .sharingServices: .output(HostHelperResult(exitCode: 0, output:
                "\tdisabled services = {\n" +
                "\t\t\"com.apple.PLACEHOLDERd\" => enabled\n" +
                "\t}"))]),
        .fail, "a sharing service enabled -> fail")
    // Unknown: root helper unavailable — never a pass.
    await expectStatus("HA-C05", in: DomainC_Network.checks,
        makeAuditContext(privileged: [.sharingServices: .unavailable]),
        .unknown, "sharing-service helper unavailable -> unknown")

    // MARK: HA-C06 — AirDrop / AirPlay Receiver
    // labels defaults.sharingd.discoverablemode, defaults.controlcenter.airplayreceiver

    // Pass: AirDrop not "Everyone" and AirPlay receiver off.
    await expectStatus("HA-C06", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "defaults.sharingd.discoverablemode": ok("Contacts Only"),
            "defaults.controlcenter.airplayreceiver": ok("0")]),
        .pass, "AirDrop contacts-only + AirPlay off -> pass")
    // Fail: AirDrop discoverable to Everyone.
    await expectStatus("HA-C06", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "defaults.sharingd.discoverablemode": ok("Everyone"),
            "defaults.controlcenter.airplayreceiver": ok("0")]),
        .fail, "AirDrop everyone -> fail")
    // Fail: AirPlay Receiver enabled.
    await expectStatus("HA-C06", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "defaults.sharingd.discoverablemode": ok("Off"),
            "defaults.controlcenter.airplayreceiver": ok("1")]),
        .fail, "AirPlay receiver on -> fail")

    // MARK: HA-C07 — Resolver integrity (label scutil.dns)

    // Pass: at least one resolver, no search-domain override.
    await expectStatus("HA-C07", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.dns": ok(
                "DNS configuration\n\n" +
                "resolver #1\n" +
                "  nameserver[0] : <IP>\n" +
                "  if_index : 1 (<iface>)\n" +
                "  order    : 12345")]),
        .pass, "resolvers present, no search domain -> pass")
    // Fail: a search-domain override that could redirect short names.
    await expectStatus("HA-C07", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.dns": ok(
                "DNS configuration\n\n" +
                "resolver #1\n" +
                "  nameserver[0] : <IP>\n" +
                "  search domain[0] : <hijack-domain>\n" +
                "  order    : 12345")]),
        .fail, "resolver with search domain -> fail")
    // Unknown: no resolver stanzas readable.
    await expectStatus("HA-C07", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.dns": ok("DNS configuration\n")]),
        .unknown, "no resolver stanzas -> unknown")
    // Unknown: command failed to launch.
    await expectStatus("HA-C07", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.dns": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "scutil --dns unreadable -> unknown")

    // MARK: HA-C08 — Custom root CAs / trust anchors
    // labels security.dump-trust-settings.admin, security.dump-trust-settings.user

    // Pass: no added anchors in admin or user domains.
    await expectStatus("HA-C08", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "security.dump-trust-settings.admin": HostCommandResult(exitCode: 1,
                standardOutput: "No Trust Settings were found.\n"),
            "security.dump-trust-settings.user": HostCommandResult(exitCode: 1,
                standardOutput: "No Trust Settings were found.\n")]),
        .pass, "no user/admin-added anchors -> pass")
    // Fail: an added root anchor in the user domain.
    await expectStatus("HA-C08", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "security.dump-trust-settings.admin": HostCommandResult(exitCode: 1,
                standardOutput: "No Trust Settings were found.\n"),
            "security.dump-trust-settings.user": ok(
                "Number of trusted certs = 1\n" +
                "Cert 0: <REDACTED-CA-LABEL>\n" +
                "   Number of trust settings : 1\n" +
                "   Trust Setting 0:\n" +
                "      Result Type           : kSecTrustSettingsResultTrustAsRoot")]),
        .fail, "user-added root anchor -> fail")
    // Unknown: both domains genuinely failed to launch.
    await expectStatus("HA-C08", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "security.dump-trust-settings.admin": HostCommandResult(exitCode: 1, launchFailed: true),
            "security.dump-trust-settings.user": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "trust settings unreadable -> unknown")

    // MARK: HA-C09 — Global HTTP(S) proxy / PAC (label scutil.proxy)

    // Pass: benign defaults only (no proxy/PAC enabled).
    await expectStatus("HA-C09", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.proxy": ok(
                "<dictionary> {\n" +
                "  ExceptionsList : <array> {\n" +
                "    0 : *.local\n" +
                "    1 : 169.254/16\n" +
                "  }\n" +
                "  FTPPassive : 1\n" +
                "}")]),
        .pass, "no proxy/PAC configured -> pass")
    // Fail: an HTTP proxy is enabled.
    await expectStatus("HA-C09", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.proxy": ok(
                "<dictionary> {\n" +
                "  HTTPEnable : 1\n" +
                "  HTTPProxy : <REDACTED-HOST>\n" +
                "  HTTPPort : 8080\n" +
                "}")]),
        .fail, "HTTP proxy enabled -> fail")
    // Fail: a PAC auto-config URL is enabled.
    await expectStatus("HA-C09", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.proxy": ok(
                "<dictionary> {\n" +
                "  ProxyAutoConfigEnable : 1\n" +
                "  ProxyAutoConfigURLString : <REDACTED-PAC-URL>\n" +
                "}")]),
        .fail, "PAC URL enabled -> fail")
    // Unknown: command failed to launch.
    await expectStatus("HA-C09", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.proxy": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "scutil --proxy unreadable -> unknown")

    // MARK: HA-C10 — VPN / relay posture (label scutil.nc.list, informational)

    // Pass: no tunnels configured.
    await expectStatus("HA-C10", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.nc.list": ok(
                "Available network connection services in the current set (*=enabled):")]),
        .pass, "no tunnels configured -> pass (informational)")
    // Pass: tunnels configured — informational, still a pass but enumerated.
    await expectStatus("HA-C10", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.nc.list": ok(
                "Available network connection services in the current set (*=enabled):\n" +
                "* (Connected)      <UUID> VPN (com.example.vpn) \"PLACEHOLDER\"   [VPN:com.example.vpn]")]),
        .pass, "connected tunnel present -> pass (informational, enumerated)")
    // Unknown: command failed to launch — informational check must not pass blindly.
    await expectStatus("HA-C10", in: DomainC_Network.checks,
        makeAuditContext(commands: [
            "scutil.nc.list": HostCommandResult(exitCode: 1, launchFailed: true)]),
        .unknown, "scutil --nc list unreadable -> unknown")
}
