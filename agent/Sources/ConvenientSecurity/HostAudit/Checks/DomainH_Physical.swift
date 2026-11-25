import Foundation
import CSECRootProtocol

// Domain H — Physical / device posture (catalog HA-H01…HA-H04).
//
// The physical-threat lens: what protects the Mac when it is lost, stolen, or an
// attacker has hands-on/USB access. Every read here is value-free — Activation
// Lock reporting deliberately extracts ONLY the lock line and discards the serial
// number, Hardware UUID, provisioning UDID, and model number that share the same
// `system_profiler` block. USB "Allow accessories" is not runtime-readable on
// Apple Silicon (an X control): honest `unknown` + advise, never a fabricated
// pass. Lockdown Mode is informational (off is the expected default). HA-H04 is a
// composite: it re-reads the boot-chain signals (SIP, sealed system volume,
// Apple-Silicon boot policy) and renders one worst-of verdict for this lens.

public enum DomainH_Physical {
    public static var checks: [any HostCheck] {
        [ActivationLock(), USBAccessories(), LockdownMode(), SecureBootChain()]
    }

    // MARK: HA-H01

    /// Find My Mac / Activation Lock. `system_profiler SPHardwareDataType` prints a
    /// Hardware Overview block; only the `Activation Lock Status:` line is read and
    /// every other field (serial, UUID, UDID, model) is discarded value-free.
    struct ActivationLock: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-H01", title: "Find My Mac / Activation Lock enabled",
            severity: .medium, tier: .runtimeReadable,
            anchor: "System Settings → [Apple Account] → Find My → Find My Mac")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/sbin/system_profiler",
                arguments: ["SPHardwareDataType"],
                label: "system_profiler.hardware"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not read the hardware profile to determine Activation Lock status.")
            }
            // Extract ONLY the Activation Lock status line; ignore serial/UUID/UDID.
            var status: String?
            for rawLine in r.standardOutput.split(separator: "\n") {
                let line = rawLine.trimmingCharacters(in: .whitespaces)
                guard line.lowercased().hasPrefix("activation lock status") else { continue }
                let lower = line.lowercased()
                if lower.contains("enabled") { status = "enabled" }
                else if lower.contains("disabled") { status = "disabled" }
                break
            }
            switch status {
            case "enabled":
                return meta.finding(.pass, evidence: "Activation Lock is enabled; a lost or stolen Mac cannot be reactivated without the owner's credentials.")
            case "disabled":
                return meta.finding(.fail, evidence: "Activation Lock is disabled; enable Find My Mac so a lost or stolen Mac cannot be reactivated.")
            default:
                // Line absent entirely (older / unenrolled hardware) → honest unknown.
                return meta.finding(.unknown, evidence: "The hardware profile does not report an Activation Lock status; verify Find My Mac is enabled.")
            }
        }
    }

    // MARK: HA-H02

    /// USB / Thunderbolt "Allow accessories to connect" (Ask / Always). Not exposed
    /// in any user-readable defaults domain on Apple Silicon — an X control. The
    /// only observable signal is a config-profile `allowUSBRestrictedMode`
    /// restriction (ties to HA-E03); absent that, report honest `unknown` + advise.
    struct USBAccessories: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-H02", title: "USB/Thunderbolt accessory auto-connect restricted",
            severity: .low, tier: .unverifiable,
            anchor: "System Settings → Privacy & Security → Allow accessories to connect")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // The runtime setting is hardware/MDM-controlled and not readable from
            // any plain defaults domain; never fabricate a pass. A managed profile
            // restriction is the only proxy, and that lives in HA-E03's surface.
            return meta.finding(.unknown, evidence: "The USB accessory-connect setting is not readable at runtime on this Mac; restrict new-accessory auto-connect while locked to blunt malicious USB.")
        }
    }

    // MARK: HA-H03

    /// Lockdown Mode. Authoritative key `LDMGlobalEnabled` in NSGlobalDomain exists
    /// only when enabled; "does not exist" means off (the expected default), never
    /// unknown. Informational (advise-only for high-risk users) — no fail state.
    struct LockdownMode: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-H03", title: "Lockdown Mode state (informational)",
            severity: .info, tier: .runtimeReadable, remediation: .advise,
            anchor: "System Settings → Privacy & Security → Lockdown Mode")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/defaults",
                arguments: ["read", "-g", "LDMGlobalEnabled"],
                label: "defaults.ldm-global-enabled"))
            // `defaults` exits non-zero when the key is absent — that means OFF,
            // which is the expected default. This check never fails; it reports
            // state and advises only for high-risk users.
            let value = r.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines)
            if r.succeeded && value == "1" {
                return meta.finding(.pass, evidence: "Lockdown Mode is enabled.")
            }
            return meta.finding(.pass, evidence: "Lockdown Mode is off (the expected default); enable it only if you are a high-risk or targeted user, as it disables many everyday features.")
        }
    }

    // MARK: HA-H04

    /// Secure boot chain verdict for the physical-threat lens. Aggregates the
    /// already-defined boot-chain signals: HA-A01 (SIP), HA-A02 (sealed system
    /// volume), and HA-A05 (Apple-Silicon boot policy, itself an X/inferred
    /// control). Verdict = worst-of: all pass ⇒ pass; any fail ⇒ fail; otherwise
    /// (an unverifiable A05 with nothing failing) ⇒ unknown — never a green pass
    /// while A05 could not be verified.
    struct SecureBootChain: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-H04", title: "Secure boot chain integrity",
            severity: .high, tier: .runtimeReadable,
            anchor: "recoveryOS: `csrutil enable`; Startup Security Utility → Full Security")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let sip = await sipStatus(ctx)
            let ssv = await sealedVolumeStatus(ctx)
            let boot = await bootPolicyStatus(ctx)
            let signals = [sip, ssv, boot]

            if signals.contains(.fail) {
                let failed = describeFailed(sip: sip, ssv: ssv, boot: boot)
                return meta.finding(.fail, evidence: "Boot chain is not fully protected: \(failed).")
            }
            if signals.contains(.unknown) {
                return meta.finding(.unknown, evidence: "Boot chain is not fully green: the Apple-Silicon boot policy is not runtime-readable; verify Full Security in recoveryOS.")
            }
            return meta.finding(.pass, evidence: "Boot chain is intact: SIP is on, the system volume seal is sealed, and no Reduced-Security signal was found.")
        }

        // Re-read the same underlying signals Domain A parses, so this lens does not
        // depend on the ordering or results of other check instances.

        private func sipStatus(_ ctx: HostAuditContext) async -> FindingStatus {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/csrutil", arguments: ["status"], label: "csrutil.status"))
            guard r.succeeded else { return .unknown }
            let out = r.standardOutput.lowercased()
            if out.contains("enabled") && !out.contains("disabled") && !out.contains("custom") && !out.contains("unknown configuration") {
                return .pass
            }
            return .fail
        }

        private func sealedVolumeStatus(_ ctx: HostAuditContext) async -> FindingStatus {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/csrutil", arguments: ["authenticated-root", "status"],
                label: "csrutil.authenticated-root"))
            guard r.succeeded else { return .unknown }
            let out = r.standardOutput.lowercased()
            return (out.contains("enabled") && !out.contains("disabled")) ? .pass : .fail
        }

        private func bootPolicyStatus(_ ctx: HostAuditContext) async -> FindingStatus {
            // HA-A05 is not runtime-readable. A loaded third-party kext implies
            // Reduced Security (a fail proxy); otherwise it is honestly unknown.
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/kmutil", arguments: ["showloaded", "--list-only"],
                label: "kmutil.showloaded"))
            let hasThirdParty = r.succeeded && r.standardOutput
                .split(separator: "\n")
                .contains { !$0.lowercased().contains("com.apple.") && $0.contains(".") }
            return hasThirdParty ? .fail : .unknown
        }

        private func describeFailed(sip: FindingStatus, ssv: FindingStatus, boot: FindingStatus) -> String {
            var parts: [String] = []
            if sip == .fail { parts.append("SIP is disabled or partial") }
            if ssv == .fail { parts.append("the system volume seal is broken") }
            if boot == .fail { parts.append("a Reduced-Security boot policy is implied by a loaded third-party kext") }
            return parts.joined(separator: "; ")
        }
    }
}
