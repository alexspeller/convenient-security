import Foundation
import CSECRootProtocol

// Domain J — Data leakage / sync (catalog HA-J01…HA-J06).
//
// This is the CIS-depth completeness tier: mostly low-severity, advisory checks
// about where secret-bearing data can quietly leave the machine (clipboard
// history, backups, browser auto-open, Spotlight, iCloud sync, screenshots).
// Value-free discipline is at its sharpest here: several of these reads touch a
// person's real name (iCloud DisplayName), account paths under /Users, backup
// destination names/IDs, VPN service names, and pasteboard blob UUIDs. This file
// keys off *stable constants and enum states* only and never lets a name, path,
// UUID, or blob into the evidence — it reports scope/state, not content.

public enum DomainJ_Leakage {
    public static var checks: [any HostCheck] {
        [ClipboardExposure(), TimeMachineEncryption(), SafariAutoOpen(),
         SpotlightIndexing(), ICloudSyncScope(), ScreenshotDefaults()]
    }

    /// Process names of clipboard managers known to persist clipboard history to
    /// disk (a durable copy of every secret ever copied). Matched case-folded
    /// against `pgrep -il` output; only the fixed name is ever emitted, never the
    /// argv of the running process.
    static let diskPersistingClipboardManagers: [String] = [
        "Maccy", "ClipboardManager", "Clipy", "CopyClip", "Pasta", "Paste",
        "Flycut", "Jumpcut", "Alfred", "Raycast", "PastePal", "CopyLess",
        "Unclutter",
    ]

    /// iCloud data-class ServiceID constants that indicate broad file sync — the
    /// vectors by which a secret-bearing file quietly leaves the Mac. Keyed on the
    /// stable constant, never on the account name or the Name field.
    static let syncServiceIDs: [(id: String, label: String)] = [
        ("com.apple.Dataclass.CloudDesktop", "Desktop & Documents sync"),
        ("com.apple.Dataclass.Ubiquity", "iCloud Drive"),
        ("com.apple.Dataclass.MobileDocuments", "iCloud Drive documents"),
    ]

    // MARK: HA-J01

    struct ClipboardExposure: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-J01", title: "No disk-persisting clipboard manager; Universal Clipboard surfaced",
            severity: .low, tier: .runtimeReadable, remediation: .advise,
            anchor: "Quit clipboard managers that persist history; review Handoff in System Settings → General → AirDrop & Handoff")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // (a) Universal Clipboard / Handoff — presence of the remote pasteboard
            //     key means the clipboard crosses devices. Informational context.
            let handoff = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/defaults",
                arguments: ["read", "com.apple.coreservices.useractivityd"],
                label: "defaults.useractivityd"))
            let universalClipboard = handoff.succeeded
                && handoff.standardOutput.contains("kRemotePasteboardBlobName")

            // (b) Running clipboard managers — match process NAMES only against the
            //     fixed known list. Never dump argv or the full process listing.
            let managers = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/pgrep",
                arguments: ["-il", DomainJ_Leakage.diskPersistingClipboardManagers.joined(separator: "|")],
                label: "pgrep.clipboard-managers"))
            var running: [String] = []
            if managers.succeeded {
                let lower = managers.standardOutput.lowercased()
                for name in DomainJ_Leakage.diskPersistingClipboardManagers where lower.contains(name.lowercased()) {
                    running.append(name)
                }
            }

            let handoffNote = universalClipboard
                ? " Universal Clipboard is active, so copied values reach paired devices."
                : ""
            if running.isEmpty {
                return meta.finding(.pass, evidence: "No known disk-persisting clipboard manager is running.\(handoffNote)")
            }
            return meta.finding(.fail, evidence: "\(running.count) known clipboard manager(s) that persist history to disk are running (\(running.joined(separator: ", "))); copied secrets may be written to disk.\(handoffNote)")
        }
    }

    // MARK: HA-J02

    struct TimeMachineEncryption: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-J02", title: "Time Machine destinations are encrypted",
            severity: .medium, tier: .runtimePrivileged, remediation: .advise,
            anchor: "System Settings → General → Time Machine → select destination → Encrypt backups")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.timeMachineDestinations) {
            case .unavailable:
                return meta.finding(.unknown, evidence: "Time Machine encryption state needs the root helper and could not be read.")
            case let .output(result):
                let out = result.output
                let lower = out.lowercased()
                // No backups configured at all — nothing to encrypt.
                if lower.contains("no destinations configured") {
                    return meta.finding(.notApplicable, evidence: "No Time Machine backup destination is configured.")
                }
                // Count per-destination encryption verdicts by state, never by name.
                var encrypted = 0
                var notEncrypted = 0
                var hadEncryptionField = false
                for line in out.split(separator: "\n") {
                    let l = line.lowercased()
                    guard l.contains("encryptionstate") else { continue }
                    hadEncryptionField = true
                    if l.contains("notencrypted") || l.contains("not encrypted") {
                        notEncrypted += 1
                    } else if l.contains("encrypted") {
                        encrypted += 1
                    }
                }
                if !hadEncryptionField {
                    // A destination exists but the encryption field was absent — do
                    // NOT assume unencrypted; honest unknown.
                    return meta.finding(.unknown, evidence: "A Time Machine destination is configured but its encryption state was not reported.")
                }
                if notEncrypted > 0 {
                    return meta.finding(.fail, evidence: "\(notEncrypted) Time Machine destination(s) are unencrypted; backed-up secrets are restorable off a stolen drive.")
                }
                return meta.finding(.pass, evidence: "\(encrypted) Time Machine destination(s) are encrypted.")
            }
        }
    }

    // MARK: HA-J03

    struct SafariAutoOpen: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-J03", title: "Safari does not auto-open \"safe\" downloads",
            severity: .low, tier: .runtimeReadable, remediation: .advise,
            anchor: "Safari → Settings → General → uncheck \"Open \u{201C}safe\u{201D} files after downloading\"")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // The real value lives in Safari's sandbox container plist, not the
            // `defaults com.apple.Safari` indirection (which returns "does not
            // exist" on modern macOS). Read the container plist directly; a same-
            // user process can read its own container. Absent/false is the secure
            // default (auto-open OFF).
            let path = "\(ctx.files.homeDirectory)/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist"
            guard ctx.files.fileExists(path) else {
                // No Safari container — Safari not set up on this account.
                return meta.finding(.pass, evidence: "Safari's auto-open setting is at its secure default (no Safari container present).")
            }
            guard let plist = ctx.files.readPropertyList(path),
                  let dict = plist as? [String: Any] else {
                // Present but unreadable — for a separate daemon this is an FDA gate.
                return meta.finding(.unknown, evidence: "Safari's download preference could not be read (Full Disk Access may be required to read its container).",
                    anchorOverride: "System Settings → Privacy & Security → Full Disk Access")
            }
            let autoOpen = (dict["AutoOpenSafeDownloads"] as? Bool) ?? false
            if autoOpen {
                return meta.finding(.fail, evidence: "Safari auto-opens \"safe\" downloads, a drive-by execution vector.")
            }
            return meta.finding(.pass, evidence: "Safari does not auto-open downloads.")
        }
    }

    // MARK: HA-J04

    struct SpotlightIndexing: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-J04", title: "Spotlight indexing state on the root volume (informational)",
            severity: .low, tier: .runtimeReadable, remediation: .advise,
            anchor: "System Settings → Spotlight; exclude secret-bearing directories from indexing")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/mdutil", arguments: ["-s", "/"],
                label: "mdutil.status.root"))
            guard r.succeeded else {
                return meta.finding(.unknown, evidence: "Spotlight indexing state on the root volume could not be read.")
            }
            let lower = r.standardOutput.lowercased()
            if lower.contains("indexing enabled") {
                return meta.finding(.pass, evidence: "Spotlight indexing is enabled on the root volume; ensure secret-bearing directories are excluded.")
            }
            if lower.contains("indexing disabled") {
                return meta.finding(.pass, evidence: "Spotlight indexing is disabled on the root volume.")
            }
            // "invalid operation" / unexpected shape.
            return meta.finding(.unknown, evidence: "Spotlight indexing state on the root volume could not be determined.")
        }
    }

    // MARK: HA-J05

    struct ICloudSyncScope: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-J05", title: "iCloud sync scope surfaced (Desktop/Documents, Drive, Private Relay, tunnels)",
            severity: .low, tier: .runtimeReadable, remediation: .advise,
            anchor: "System Settings → [account] → iCloud; review what syncs off-device")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            // (a) iCloud data-class scope — key ONLY off ServiceID constants. Never
            //     touch the DisplayName (a real person's name) or Name fields.
            let accounts = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/defaults",
                arguments: ["read", "\(ctx.files.homeDirectory)/Library/Preferences/MobileMeAccounts"],
                label: "defaults.mobilemeaccounts"))
            var syncLabels: [String] = []
            if accounts.succeeded {
                for service in DomainJ_Leakage.syncServiceIDs where accounts.standardOutput.contains(service.id) {
                    syncLabels.append(service.label)
                }
            }

            // (b) iCloud Private Relay — probe presence of the status manager key
            //     only; never dump the opaque blob.
            let relay = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/defaults",
                arguments: ["read", "com.apple.networkserviceproxy"],
                label: "defaults.networkserviceproxy"))
            let privateRelayConfigured = relay.succeeded
                && relay.standardOutput.contains("NSPServiceStatusManagerInfo")

            // (c) VPN / relay tunnels — count only; strip names and UUIDs. Each
            //     enabled tunnel line in `scutil --nc list` begins with "* (".
            let tunnels = await ctx.commands.run(HostCommand(
                executable: "/usr/sbin/scutil", arguments: ["--nc", "list"],
                label: "scutil.nc.list"))
            var enabledTunnels = 0
            if tunnels.succeeded {
                for line in tunnels.standardOutput.split(separator: "\n") {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    if trimmed.hasPrefix("* (") { enabledTunnels += 1 }
                }
            }

            var parts: [String] = []
            if syncLabels.isEmpty {
                parts.append("no broad iCloud file sync detected")
            } else {
                parts.append("iCloud file sync active for: \(syncLabels.joined(separator: ", "))")
            }
            parts.append(privateRelayConfigured ? "iCloud Private Relay is configured" : "iCloud Private Relay is not configured")
            parts.append(enabledTunnels == 0 ? "no enabled VPN tunnels" : "\(enabledTunnels) enabled VPN tunnel(s)")
            // Informational surface: Desktop/Documents sync means secret-bearing
            // files leave the device, but this is a user judgment call, not a fail.
            return meta.finding(.pass, evidence: "iCloud sync scope: \(parts.joined(separator: "; ")).")
        }
    }

    // MARK: HA-J06

    struct ScreenshotDefaults: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-J06", title: "Screenshots do not save into an iCloud-synced location",
            severity: .low, tier: .runtimeReadable, remediation: .advise,
            anchor: "Screenshot app → Options → Save to; avoid Desktop/Documents when those sync to iCloud")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let r = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/defaults",
                arguments: ["read", "com.apple.screencapture"],
                label: "defaults.screencapture"))
            // Absent domain / unset keys => secure default (~/Desktop, file).
            guard r.succeeded else {
                return meta.finding(.pass, evidence: "Screenshot defaults are unset; screenshots save to the local default location.")
            }
            let out = r.standardOutput
            let target = DomainJ_Leakage.defaultsStringValue(out, key: "target")
            if target?.lowercased() == "clipboard" {
                return meta.finding(.pass, evidence: "Screenshots are sent to the clipboard rather than saved to a synced folder.")
            }
            // Determine whether the configured save location sits inside an
            // iCloud-synced directory. Report only iCloud-synced yes/no, never the
            // literal path (which contains the username).
            guard let location = DomainJ_Leakage.defaultsStringValue(out, key: "location") else {
                return meta.finding(.pass, evidence: "Screenshot save location is unset; screenshots use the local default location.")
            }
            let home = ctx.files.homeDirectory
            let syncedRoots = [
                "\(home)/Library/Mobile Documents",
                "\(home)/Desktop",
                "\(home)/Documents",
            ]
            let iCloudSynced = syncedRoots.contains { location.hasPrefix($0) }
                || location.contains("/Mobile Documents/")
            if iCloudSynced {
                return meta.finding(.fail, evidence: "Screenshots save into a directory that iCloud can sync (Desktop/Documents/iCloud Drive); screenshots of secret-bearing windows would leave the device.")
            }
            return meta.finding(.pass, evidence: "Screenshots save to a location that is not iCloud-synced.")
        }
    }

    /// Extract a `defaults read` scalar value for `key` (`    key = value;`) without
    /// emitting it — returns the raw token so a *caller* can classify it (e.g. an
    /// enum like `clipboard`); callers must NOT place a path value into evidence.
    static func defaultsStringValue(_ output: String, key: String) -> String? {
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("\(key) =") || trimmed.hasPrefix("\"\(key)\" =") else { continue }
            guard let eq = trimmed.firstIndex(of: "=") else { continue }
            var value = String(trimmed[trimmed.index(after: eq)...])
                .trimmingCharacters(in: .whitespaces)
            if value.hasSuffix(";") { value.removeLast() }
            value = value.trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("\"") && value.hasSuffix("\"") && value.count >= 2 {
                value = String(value.dropFirst().dropLast())
            }
            return value
        }
        return nil
    }
}
