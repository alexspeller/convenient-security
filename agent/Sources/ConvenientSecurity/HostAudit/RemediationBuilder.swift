import Foundation
import CSECRootProtocol

// Maps each fixable finding (status .fail with an auto/autoPrivileged remediation
// key) to the concrete, reversible changes that remediate it. Fixed fixes map to
// a constant change; parameterized fixes (boot-args token, sharing service) re-
// read the exact state so only the observed problem is touched — the guarded
// HA-A03 clear, for instance, only ever removes a known-dangerous token.

public struct HostRemediationPlan: Sendable {
    public let item: HostRemediationItem
    public let privileged: [HostRootChange]
    public let local: [HostLocalChange]
    public init(item: HostRemediationItem, privileged: [HostRootChange], local: [HostLocalChange]) {
        self.item = item
        self.privileged = privileged
        self.local = local
    }
}

public enum HostRemediationBuilder {
    public static func plans(for report: HostAuditReport, ctx: HostAuditContext) async -> [HostRemediationPlan] {
        var plans: [HostRemediationPlan] = []
        for finding in report.batchFixable {
            if let plan = await plan(for: finding, ctx: ctx) {
                plans.append(plan)
            }
        }
        return plans
    }

    private static func plan(for finding: HostFinding, ctx: HostAuditContext) async -> HostRemediationPlan? {
        guard let key = finding.remediationKey else { return nil }
        switch key {
        case "HA-C01":
            return fixed(finding, [.enableApplicationFirewall],
                         detail: "Turns the inbound application firewall on. Reversible.")
        case "HA-C02":
            return fixed(finding, [.setFirewallStealthMode(true), .setFirewallAllowSigned(false)],
                         detail: "Enables stealth mode and stops auto-allowing signed software. Reversible.")
        case "HA-B04":
            return fixed(finding, [
                .setSoftwareUpdateFlag(.configDataInstall, enabled: true),
                .setSoftwareUpdateFlag(.criticalUpdateInstall, enabled: true),
                .setSoftwareUpdateFlag(.automaticCheckEnabled, enabled: true),
                .setSoftwareUpdateFlag(.automaticDownload, enabled: true),
            ], detail: "Enables automatic security-data and critical updates. Reversible.")
        case "HA-G01":
            return fixed(finding, [.removeAutoLoginUser, .setDisableFDEAutoLogin(true)],
                         detail: "Removes automatic login and disables FileVault auto-login. Only tightens.")
        case "HA-G02":
            return HostRemediationPlan(
                item: HostRemediationItem(key: key, title: finding.title,
                    detail: "Requires a password immediately after the screensaver starts. Reversible.",
                    requiresRoot: false),
                privileged: [], local: [.setScreenLockImmediate])
        case "HA-G04":
            return fixed(finding, [.disableRootAccount],
                         detail: "Disables the root account (should already be off). Reversible.")
        case "HA-G05":
            return fixed(finding, [.disableGuestAccount],
                         detail: "Disables the guest account. Reversible.")
        case "HA-G08":
            return fixed(finding, [.installSudoTouchID],
                         detail: "Adds Touch ID for sudo via /etc/pam.d/sudo_local. Additive, update-safe, reversible.")
        case "HA-I01":
            return fixed(finding, [.enableNetworkTime],
                         detail: "Enables automatic network time. Reversible.")
        case "HA-A03":
            return await bootArgsPlan(finding, ctx: ctx)
        case "HA-C05":
            return await sharingPlan(finding, ctx: ctx)
        default:
            return nil
        }
    }

    private static func fixed(
        _ finding: HostFinding, _ changes: [HostRootChange], detail: String
    ) -> HostRemediationPlan {
        HostRemediationPlan(
            item: HostRemediationItem(
                key: finding.remediationKey ?? finding.id,
                title: finding.title, detail: detail, requiresRoot: !changes.isEmpty),
            privileged: changes, local: [])
    }

    /// HA-A03 — clear ONLY the known-dangerous boot-args tokens actually present.
    private static func bootArgsPlan(_ finding: HostFinding, ctx: HostAuditContext) async -> HostRemediationPlan? {
        let state = await DomainA_Platform.readBootArgs(ctx)
        let clearable = state.dangerous.compactMap(\.clearable)
        guard !clearable.isEmpty else { return nil }
        return HostRemediationPlan(
            item: HostRemediationItem(
                key: finding.remediationKey ?? finding.id,
                title: finding.title,
                detail: "Clears the dangerous boot-args token(s) only; all other tokens are preserved. Reversible NVRAM write.",
                requiresRoot: true),
            privileged: clearable.map { .clearBootArgsToken($0) }, local: [])
    }

    /// HA-C05 — the reliably-mappable subset: turn Remote Login (SSH) off when it
    /// is on. Other sharing services stay advise-only (surfaced but not auto-toggled)
    /// because their launchd labels are not unambiguously derivable here.
    private static func sharingPlan(_ finding: HostFinding, ctx: HostAuditContext) async -> HostRemediationPlan? {
        guard case let .output(result) = await ctx.privileged.read(.sharingServices) else { return nil }
        let out = result.output.lowercased()
        guard out.contains("remote login: on") else { return nil }
        return HostRemediationPlan(
            item: HostRemediationItem(
                key: finding.remediationKey ?? finding.id,
                title: "Turn off Remote Login (SSH)",
                detail: "Disables inbound SSH (Remote Login), the highest-value exposed sharing service. Reversible.",
                requiresRoot: true),
            privileged: [.setSharingService(.remoteLogin, enabled: false)], local: [])
    }
}
