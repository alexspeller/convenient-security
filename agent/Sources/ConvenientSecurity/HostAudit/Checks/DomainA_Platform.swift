import Foundation
import CSECRootProtocol

// Domain A — Platform & kernel integrity (catalog HA-A01…HA-A09).
//
// This file is the reference shape for every domain: each check is a small
// `HostCheck` value with a `meta` (catalog identity + classification) and an
// `evaluate` that reads the injected `HostAuditContext`, parses tolerantly, and
// returns a value-free `HostFinding` via `meta.finding(...)`. Never emit a raw
// unsanitized string; never render an unavailable read as a pass.

public enum DomainA_Platform {
    public static var checks: [any HostCheck] {
        [SIP(), SignedSystemVolume(), BootArgs(), ThirdPartyKexts(),
         BootSecurity(), SystemExtensions(), AMFI(), FirmwarePassword(), Rosetta()]
    }

    /// Tokens in `boot-args` that weaken kernel/code-signing integrity. Each maps
    /// (where clearable) to a `HostDangerousBootArg` the guarded HA-A03 fix removes.
    static let dangerousBootArgs: [(needle: String, clearable: HostDangerousBootArg?)] = [
        ("amfi_get_out_of_my_way", .amfiGetOutOfMyWay),
        ("amfi=", .amfiDisable),
        ("amfi_allow_any_signature", .libraryValidationDisable),
        ("cs_enforcement_disable", .csEnforcementDisable),
        ("-arm64e_preview_abi", .arm64ePreviewABI),
    ]

    /// Parsed `nvram boot-args`: `.unset` (secure default) or `.value(String)`.
    enum BootArgsState {
        case unset
        case value(String)

        var dangerous: [(needle: String, clearable: HostDangerousBootArg?)] {
            guard case let .value(v) = self else { return [] }
            let lower = v.lowercased()
            return dangerousBootArgs.filter { lower.contains($0.needle) }
        }
    }

    static func readBootArgs(_ ctx: HostAuditContext) async -> BootArgsState {
        let result = await ctx.commands.run(HostCommand(
            executable: "/usr/sbin/nvram", arguments: ["boot-args"], label: "nvram.boot-args"))
        // `nvram` exits non-zero when the variable is unset — the secure default.
        guard result.succeeded else { return .unset }
        // Output: "boot-args\t<value>".
        let text = result.standardOutput
        guard let sep = text.firstIndex(where: { $0 == "\t" }) ?? text.firstIndex(of: " ") else {
            return .unset
        }
        let value = String(text[text.index(after: sep)...]).trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? .unset : .value(value)
    }

    // MARK: HA-A01

    struct SIP: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-A01", title: "System Integrity Protection enabled and complete",
            severity: .high, tier: .runtimeReadable,
            anchor: "Recovery: `csrutil enable` (System Integrity Protection)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/csrutil", arguments: ["status"], label: "csrutil.status"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not read SIP status.")
            }
            let out = r.standardOutput.lowercased()
            if out.contains("enabled") && !out.contains("disabled") && !out.contains("custom") && !out.contains("unknown configuration") {
                return meta.finding(.pass, evidence: "SIP is enabled.")
            }
            if out.contains("custom") {
                return meta.finding(.fail, evidence: "SIP is in a custom/partial configuration; some protections are disabled.")
            }
            return meta.finding(.fail, evidence: "SIP is disabled.")
        }
    }

    // MARK: HA-A02

    struct SignedSystemVolume: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-A02", title: "Signed System Volume sealed",
            severity: .high, tier: .runtimeReadable,
            anchor: "Recovery: reinstall macOS to restore the sealed system volume")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/csrutil", arguments: ["authenticated-root", "status"],
                label: "csrutil.authenticated-root"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not read authenticated-root status.")
            }
            let out = r.standardOutput.lowercased()
            if out.contains("enabled") && !out.contains("disabled") {
                return meta.finding(.pass, evidence: "The signed system volume seal is intact.")
            }
            return meta.finding(.fail, evidence: "The system volume seal is broken (authenticated-root disabled).")
        }
    }

    // MARK: HA-A03

    struct BootArgs: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-A03", title: "Clean boot-args (no kernel/code-signing disablers)",
            severity: .high, tier: .runtimeReadable, onThesis: true,
            remediation: .autoPrivileged, remediationKey: "HA-A03",
            anchor: "`sudo nvram -d boot-args` (guarded clear of the dangerous token)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let state = await DomainA_Platform.readBootArgs(ctx)
            switch state {
            case .unset:
                return meta.finding(.pass, evidence: "boot-args is unset.")
            case .value:
                let bad = state.dangerous
                if bad.isEmpty {
                    return meta.finding(.pass, evidence: "boot-args is set but contains no known integrity-weakening token.")
                }
                let names = bad.map(\.needle).joined(separator: ", ")
                // A fix is only offered when *every* dangerous token is on the
                // guarded clearable allow-list.
                let allClearable = bad.allSatisfy { $0.clearable != nil }
                return HostFinding(
                    id: meta.id, title: meta.title, severity: meta.severity, tier: meta.tier,
                    status: .fail, onThesis: meta.onThesis,
                    evidence: ReviewDisplay.sanitized("boot-args includes integrity-weakening token(s): \(names)."),
                    anchor: ReviewDisplay.sanitized(meta.anchor),
                    remediation: allClearable ? .autoPrivileged : .advise,
                    remediationKey: allClearable ? meta.remediationKey : nil)
            }
        }
    }

    // MARK: HA-A04

    struct ThirdPartyKexts: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-A04", title: "No third-party kernel extensions loaded",
            severity: .medium, tier: .runtimeReadable,
            anchor: "Review loaded kexts; migrate to a System Extension where possible")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/kmutil", arguments: ["showloaded", "--list-only"],
                label: "kmutil.showloaded"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not enumerate loaded kexts.")
            }
            let thirdParty = r.standardOutput
                .split(separator: "\n")
                .filter { line in
                    let l = line.lowercased()
                    return l.contains(".") && !l.contains("com.apple.") && !l.contains("as.vantron")
                }
                .count
            if thirdParty == 0 {
                return meta.finding(.pass, evidence: "No third-party kernel extensions are loaded.")
            }
            return meta.finding(.fail, evidence: "\(thirdParty) third-party kernel extension(s) loaded, implying Reduced Security on Apple Silicon.")
        }
    }

    // MARK: HA-A05

    struct BootSecurity: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-A05", title: "Apple-Silicon boot security = Full",
            severity: .medium, tier: .unverifiable,
            anchor: "Recovery: Startup Security Utility → Full Security (verify with `bputil -d`)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // Not runtime-readable. Infer a proxy signal from HA-A04: a loaded
            // third-party kext implies Reduced Security. Absent that, report the
            // honest unverifiable state (never a green pass).
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/kmutil", arguments: ["showloaded", "--list-only"],
                label: "kmutil.showloaded"))
            let hasThirdParty = r.succeeded && r.standardOutput
                .split(separator: "\n")
                .contains { !$0.lowercased().contains("com.apple.") && $0.contains(".") }
            if hasThirdParty {
                return meta.finding(.fail, evidence: "A loaded third-party kext implies Reduced Security boot policy.")
            }
            return meta.finding(.unknown, evidence: "Boot security level is not runtime-readable; verify Full Security in recoveryOS.")
        }
    }

    // MARK: HA-A06

    struct SystemExtensions: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-A06", title: "System-extension inventory reviewed",
            severity: .medium, tier: .runtimeReadable,
            anchor: "System Settings → General → Login Items & Extensions")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/systemextensionsctl", arguments: ["list"],
                label: "systemextensionsctl.list"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Could not enumerate system extensions.")
            }
            let lower = r.standardOutput.lowercased()
            let enabled = r.standardOutput.split(separator: "\n").filter { $0.contains("[activated enabled]") }.count
            let hasESorNE = lower.contains("endpointsecurity") || lower.contains("networkextension")
            if enabled == 0 {
                return meta.finding(.pass, evidence: "No third-party system extensions are activated.")
            }
            let kind = hasESorNE ? " including Endpoint-Security / Network-Extension providers that see all process events or traffic" : ""
            return meta.finding(.fail, evidence: "\(enabled) system extension(s) activated\(kind); confirm each is a tool you installed.")
        }
    }

    // MARK: HA-A07

    struct AMFI: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-A07", title: "AMFI / library validation not globally disabled",
            severity: .high, tier: .runtimeReadable, onThesis: true,
            anchor: "Clear the AMFI-disabling boot-args token (see HA-A03)")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let state = await DomainA_Platform.readBootArgs(ctx)
            let amfiTokens = state.dangerous.filter { $0.needle.hasPrefix("amfi") }
            if amfiTokens.isEmpty {
                return meta.finding(.pass, evidence: "No AMFI/library-validation disabler is present in boot-args.")
            }
            return meta.finding(.fail, evidence: "AMFI/library validation is disabled via boot-args (\(amfiTokens.map(\.needle).joined(separator: ", "))).")
        }
    }

    // MARK: HA-A08

    struct FirmwarePassword: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-A08", title: "Firmware password (Intel) present",
            severity: .medium, tier: .runtimePrivileged,
            anchor: "Intel: `firmwarepasswd -setpasswd`. Apple Silicon: owner passcode")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.firmwarePassword) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "Firmware-password state needs the root helper (or is Apple-Silicon owner passcode, not locally readable).")
            case let .output(result):
                let out = result.output.lowercased()
                if out.contains("password is not set") {
                    return meta.finding(.fail, evidence: "No firmware password is set (Intel).")
                }
                if out.contains("password is set") {
                    return meta.finding(.pass, evidence: "A firmware password is set.")
                }
                // Apple Silicon has no firmwarepasswd; treat as not applicable.
                return meta.finding(.notApplicable, evidence: "Firmware password does not apply (Apple Silicon uses the owner passcode).")
            }
        }
    }

    // MARK: HA-A09

    struct Rosetta: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-A09", title: "Rosetta 2 presence (informational)",
            severity: .info, tier: .runtimeReadable, remediation: .none,
            anchor: "Informational only")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let present = ctx.files.fileExists("/Library/Apple/usr/libexec/oah")
            return meta.finding(.pass, evidence: present
                ? "Rosetta 2 is installed; x86 emulation is available on this Mac."
                : "Rosetta 2 is not installed.")
        }
    }
}
