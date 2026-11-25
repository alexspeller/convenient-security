import Foundation

/// Non-sensitive machine identity for the attestation header. All fields are
/// value-free system facts (never a serial number or credential); the launcher
/// gathers them and passes them in so this renderer stays pure and testable.
public struct AttestationIdentity: Equatable, Sendable {
    public let hostname: String?
    public let hardwareModel: String?
    public let osVersion: String?
    public init(hostname: String? = nil, hardwareModel: String? = nil, osVersion: String? = nil) {
        self.hostname = hostname
        self.hardwareModel = hardwareModel
        self.osVersion = osVersion
    }
}

/// Renders a copy-paste **markdown** attestation of the host's security posture —
/// suitable for pasting into Slack / a ticket / an email to show the laptop is
/// properly configured. Pure and value-free: findings are already sanitized, and
/// dynamic strings pass through `ReviewDisplay.sanitized`. The caller supplies the
/// *final* exemptions/todos (persisted plus any decided this session) so the
/// artifact reflects the true end state.
public enum AttestationRenderer {
    public static func render(
        report: HostAuditReport,
        identity: AttestationIdentity,
        exemptions: [HostTriageInfo],
        todos: [HostTriageInfo],
        generatedAtHint: String
    ) -> String {
        func safe(_ s: String) -> String { ReviewDisplay.sanitized(s) }
        let byID = Dictionary(report.findings.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let exemptedIDs = Set(exemptions.map(\.id))
        let deferredIDs = Set(todos.map(\.id))

        let passing = report.findings.filter { $0.status == .pass }
        let expectedSelf = report.findings.filter { $0.status == .expectedSelf }
        let notApplicable = report.findings.filter { $0.status == .notApplicable }
        let unknowns = report.findings.filter { $0.status == .unknown }
        let needsAttention = report.findings.filter {
            $0.status == .fail && !exemptedIDs.contains($0.id) && !deferredIDs.contains($0.id)
        }
        let verified = passing + expectedSelf

        var lines: [String] = []
        lines.append("## macOS Security Posture Attestation")
        lines.append("")
        if let machine = machineLine(identity) { lines.append("- **Machine:** \(machine)") }
        lines.append("- **Generated:** \(safe(generatedAtHint))")
        lines.append("- **Tool:** Convenient Security (csec) — host posture audit")
        lines.append("- **Result:** " + resultCounts(
            verified: verified.count, needsAttention: needsAttention.count,
            accepted: exemptions.count, planned: todos.count,
            couldNotVerify: unknowns.count, notApplicable: notApplicable.count))
        lines.append("")
        lines.append(needsAttention.isEmpty
            ? "✅ **All applicable controls are verified or have a recorded decision.**"
            : "⚠️ **\(needsAttention.count) control(s) still need attention** (see below).")

        if !needsAttention.isEmpty {
            lines.append("")
            lines.append("### Needs attention (\(needsAttention.count))")
            for finding in needsAttention {
                lines.append("- \(AuditReportRenderer.severityIcon(finding.severity)) \(finding.id) — \(safe(finding.title))")
            }
        }

        if !verified.isEmpty {
            lines.append("")
            lines.append("### Verified controls (\(verified.count))")
            for finding in verified.sorted(by: { $0.id < $1.id }) {
                lines.append("- ✅ \(finding.id) — \(safe(finding.title))")
            }
        }

        if !exemptions.isEmpty {
            lines.append("")
            lines.append("### Accepted risks (\(exemptions.count))")
            for info in exemptions.sorted(by: { $0.id < $1.id }) {
                let title = byID[info.id].map { safe($0.title) } ?? info.id
                var line = "- ⚠️ \(info.id) — \(title)"
                if let hint = info.recordedAtHint { line += " — accepted \(safe(shortDate(hint)))" }
                if let note = info.note, !note.isEmpty { line += " — “\(safe(note))”" }
                lines.append(line)
            }
        }

        if !todos.isEmpty {
            lines.append("")
            lines.append("### Planned remediation (\(todos.count))")
            for info in todos.sorted(by: { $0.id < $1.id }) {
                let title = byID[info.id].map { safe($0.title) } ?? info.id
                var line = "- ⏳ \(info.id) — \(title)"
                if let hint = info.recordedAtHint { line += " — added \(safe(shortDate(hint)))" }
                lines.append(line)
            }
        }

        if !unknowns.isEmpty {
            lines.append("")
            lines.append("### Could not verify (\(unknowns.count))")
            for finding in unknowns.sorted(by: { $0.id < $1.id }) {
                lines.append("- ▫️ \(finding.id) — \(safe(finding.title))")
            }
        }

        if !report.coverageNotes.isEmpty {
            lines.append("")
            lines.append("_Coverage: " + report.coverageNotes.map(safe).joined(separator: "; ") + "._")
        }

        return lines.joined(separator: "\n")
    }

    private static func machineLine(_ identity: AttestationIdentity) -> String? {
        func safe(_ s: String) -> String { ReviewDisplay.sanitized(s) }
        var parts: [String] = []
        if let model = identity.hardwareModel, !model.isEmpty { parts.append(safe(model)) }
        if let os = identity.osVersion, !os.isEmpty { parts.append("macOS \(safe(os))") }
        if let host = identity.hostname, !host.isEmpty { parts.append("hostname `\(safe(host))`") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private static func resultCounts(
        verified: Int, needsAttention: Int, accepted: Int, planned: Int,
        couldNotVerify: Int, notApplicable: Int
    ) -> String {
        var parts = ["\(verified) verified"]
        parts.append("\(needsAttention) need attention")
        if accepted > 0 { parts.append("\(accepted) accepted risks") }
        if planned > 0 { parts.append("\(planned) planned") }
        if couldNotVerify > 0 { parts.append("\(couldNotVerify) could not verify") }
        if notApplicable > 0 { parts.append("\(notApplicable) n/a") }
        return parts.joined(separator: " · ")
    }

    /// Trim an ISO8601 hint to its date for the human-facing attestation.
    private static func shortDate(_ hint: String) -> String {
        String(hint.prefix(10))
    }
}
