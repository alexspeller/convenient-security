import Foundation
import CSECRootProtocol

// Domain D — Privacy / TCC (catalog HA-D01…HA-D08), Full Disk Access gated.
//
// These checks enumerate the highest-value privilege surface on the Mac: apps
// that hold Full Disk Access, Accessibility, Screen Recording, Input Monitoring,
// Automation, Developer-Tools, or Camera/Microphone TCC grants. Any such grant
// lets a same-user process bypass much of what csec protects, so the section is
// worth the FDA csec requests at setup.
//
// Reads go through `ctx.tcc.grantees(service)` (which unions the system and
// per-user TCC.db via `sqlite3 -readonly`). A `.noFullDiskAccess` outcome means
// csec itself lacks FDA — the honest result is `.unknown` with a deep-link into
// the exact System Settings pane, NEVER a green pass with zero grantees. All
// evidence is value-free: counts and service semantics only, never the grantee
// bundle id or path. HA-D08 (Location Services master flag) lives under a
// root-only path, so it goes through the privileged root helper.

public enum DomainD_Privacy {
    public static var checks: [any HostCheck] {
        [FullDiskAccessGrantees(), AccessibilityGrantees(), ScreenCaptureGrantees(),
         InputMonitoringGrantees(), AutomationGrantees(), DeveloperToolGrantees(),
         CameraMicrophoneGrantees(), LocationServices()]
    }

    /// The System Settings deep-link to surface when csec lacks Full Disk Access
    /// and a TCC read is therefore `.unknown` rather than a pass.
    static func settingsAnchor(_ pane: String) -> String {
        "System Settings → Privacy & Security → \(pane)"
    }

    /// The shared shape for HA-D02…HA-D06: enumerate one TCC service, and flag on
    /// the count of *allowed* grantees. `ctx.tcc.grantees` unions the system and
    /// per-user databases; `grant.allowed` already means auth_value ≥ 2 (2 =
    /// allowed, 3 = limited). A `.noFullDiskAccess` outcome degrades to `.unknown`
    /// with the Settings deep-link — never a pass. Evidence stays value-free: a
    /// count of holders, never a grantee identifier.
    static func evaluateSimpleService(
        _ ctx: HostAuditContext,
        meta: HostCheckMeta,
        service: TCCService,
        pane: String,
        capability: String
    ) async -> HostFinding {
        switch await ctx.tcc.grantees(service) {
        case .noFullDiskAccess:
            return meta.finding(
                .unknown,
                evidence: "csec lacks Full Disk Access, so the TCC grantee list could not be read.",
                anchorOverride: settingsAnchor(pane))
        case let .grants(grants):
            let allowed = grants.filter(\.allowed).count
            if allowed == 0 {
                return meta.finding(.pass, evidence: "No apps hold this grant.")
            }
            return meta.finding(
                .fail,
                evidence: "\(allowed) app(s) hold this grant (\(capability)); review each in the Settings pane.")
        }
    }

    // MARK: HA-D01

    /// Full Disk Access grantees. csec's own FDA grant is expected-self (it is
    /// what makes this very audit possible), so it is either the sole grantee (the
    /// whole check is `.expectedSelf`) or excluded from the flagged count while
    /// being noted.
    struct FullDiskAccessGrantees: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-D01", title: "Full Disk Access grantees reviewed",
            severity: .high, tier: .fullDiskAccess,
            anchor: "System Settings → Privacy & Security → Full Disk Access")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.tcc.grantees(.allFiles) {
            case .noFullDiskAccess:
                return meta.finding(
                    .unknown,
                    evidence: "csec lacks Full Disk Access, so Full Disk Access grantees could not be enumerated.",
                    anchorOverride: DomainD_Privacy.settingsAnchor("Full Disk Access"))
            case let .grants(grants):
                let allowed = grants.filter(\.allowed)
                let selfGrants = allowed.filter { ctx.selfIdentity.matches($0.client) }.count
                let others = allowed.count - selfGrants
                if allowed.isEmpty {
                    return meta.finding(.pass, evidence: "No apps hold Full Disk Access.")
                }
                if others == 0 {
                    // The only Full Disk Access holder is csec itself — expected,
                    // and required to run this privacy audit.
                    return meta.finding(
                        .expectedSelf,
                        evidence: "Only csec holds Full Disk Access, which it requires for the privacy audit.")
                }
                let selfNote = selfGrants > 0
                    ? " (csec's own grant is expected-self and excluded from this count)"
                    : ""
                return meta.finding(
                    .fail,
                    evidence: "\(others) app(s) besides csec hold Full Disk Access\(selfNote); review each — an FDA holder can read every app's data and csec's own files.")
            }
        }
    }

    // MARK: HA-D02

    /// Accessibility grantees — synthetic input + full UI control (keylogging,
    /// dismissing prompts).
    struct AccessibilityGrantees: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-D02", title: "Accessibility grantees reviewed",
            severity: .high, tier: .fullDiskAccess,
            anchor: "System Settings → Privacy & Security → Accessibility")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            await DomainD_Privacy.evaluateSimpleService(
                ctx, meta: meta, service: .accessibility, pane: "Accessibility",
                capability: "can synthesize input and drive the full UI, including keylogging and dismissing prompts")
        }
    }

    // MARK: HA-D03

    /// Screen Recording grantees — can capture the consent window and any
    /// on-screen secret.
    struct ScreenCaptureGrantees: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-D03", title: "Screen Recording grantees reviewed",
            severity: .high, tier: .fullDiskAccess,
            anchor: "System Settings → Privacy & Security → Screen & System Audio Recording")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            await DomainD_Privacy.evaluateSimpleService(
                ctx, meta: meta, service: .screenCapture, pane: "Screen & System Audio Recording",
                capability: "can capture the consent window and any on-screen secret")
        }
    }

    // MARK: HA-D04

    /// Input Monitoring grantees — raw keystroke access.
    struct InputMonitoringGrantees: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-D04", title: "Input Monitoring grantees reviewed",
            severity: .high, tier: .fullDiskAccess,
            anchor: "System Settings → Privacy & Security → Input Monitoring")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            await DomainD_Privacy.evaluateSimpleService(
                ctx, meta: meta, service: .listenEvent, pane: "Input Monitoring",
                capability: "has raw keystroke access")
        }
    }

    // MARK: HA-D05

    /// Automation (AppleEvents) grantees — app A scripting app B (privilege
    /// chaining). Grantee pairs (source app → automation target) are app metadata;
    /// the value-free finding reports the count only.
    struct AutomationGrantees: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-D05", title: "Automation (AppleEvents) grantees reviewed",
            severity: .medium, tier: .fullDiskAccess,
            anchor: "System Settings → Privacy & Security → Automation")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            await DomainD_Privacy.evaluateSimpleService(
                ctx, meta: meta, service: .appleEvents, pane: "Automation",
                capability: "can script another app, enabling privilege chaining")
        }
    }

    // MARK: HA-D06

    /// Developer Tools / debugger grantees — overlaps the
    /// `com.apple.security.cs.debugger` entitlement exemption.
    struct DeveloperToolGrantees: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-D06", title: "Developer Tools grantees reviewed",
            severity: .medium, tier: .fullDiskAccess,
            anchor: "System Settings → Privacy & Security → Developer Tools")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            await DomainD_Privacy.evaluateSimpleService(
                ctx, meta: meta, service: .developerTool, pane: "Developer Tools",
                capability: "is exempt from some code-signing checks, like a debugger")
        }
    }

    // MARK: HA-D07

    /// Camera / Microphone grantees. Two services enumerated together; a
    /// `.noFullDiskAccess` on either read degrades the whole check to `.unknown`.
    struct CameraMicrophoneGrantees: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-D07", title: "Camera and Microphone grantees reviewed",
            severity: .low, tier: .fullDiskAccess,
            anchor: "System Settings → Privacy & Security → Camera / Microphone")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let cameraOutcome = await ctx.tcc.grantees(.camera)
            let microphoneOutcome = await ctx.tcc.grantees(.microphone)
            // Either DB read being unavailable (missing FDA) makes the combined
            // result unverifiable — never a pass.
            guard case let .grants(cameraGrants) = cameraOutcome,
                  case let .grants(microphoneGrants) = microphoneOutcome else {
                return meta.finding(
                    .unknown,
                    evidence: "csec lacks Full Disk Access, so Camera/Microphone grantees could not be enumerated.",
                    anchorOverride: DomainD_Privacy.settingsAnchor("Camera / Microphone"))
            }
            let camera = cameraGrants.filter(\.allowed).count
            let microphone = microphoneGrants.filter(\.allowed).count
            if camera == 0 && microphone == 0 {
                return meta.finding(.pass, evidence: "No apps hold Camera or Microphone access.")
            }
            return meta.finding(
                .fail,
                evidence: "\(camera) app(s) hold Camera and \(microphone) hold Microphone access; review each in the Settings pane.")
        }
    }

    // MARK: HA-D08

    /// Location Services master enable flag. The flag lives under a root-only path
    /// (`/var/db/locationd`), so the read is a privileged root-helper hop. This is
    /// informational: enabled is the normal state. A read that cannot obtain the
    /// value renders `.unknown`, never a green pass.
    struct LocationServices: HostCheck {
        let meta = HostCheckMeta(
            id: "HA-D08", title: "Location Services state (informational)",
            severity: .low, tier: .runtimePrivileged, remediation: .none,
            anchor: "System Settings → Privacy & Security → Location Services")
        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            switch await ctx.privileged.read(.locationServices) {
            case .unavailable:
                return meta.finding(
                    .unknown,
                    evidence: "Location Services state needs the root helper (the master flag is under a root-only path).")
            case let .output(result):
                let out = result.output.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                // A permission-denied / missing read must not be read as "disabled".
                if out.contains("permission denied") || out.contains("does not exist") {
                    return meta.finding(
                        .unknown,
                        evidence: "Location Services master flag could not be read without elevation.")
                }
                if out.hasPrefix("1") {
                    return meta.finding(.pass, evidence: "Location Services is enabled (informational).")
                }
                if out.hasPrefix("0") {
                    return meta.finding(.pass, evidence: "Location Services is disabled (informational).")
                }
                return meta.finding(
                    .unknown,
                    evidence: "Location Services state could not be determined from the read.")
            }
        }
    }
}
