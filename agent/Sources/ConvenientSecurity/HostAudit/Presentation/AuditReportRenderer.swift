import Foundation

// Formatted, value-free terminal rendering of a `HostAuditReport`. Pure: it takes
// the report plus explicit `color`/`width` and returns a String, so it renders the
// same to a pipe (no color) or a terminal, and is unit-testable without a TTY.
// Replaces the launcher's old raw-markdown dump. Dynamic strings pass through
// `ReviewDisplay.sanitized` (control/newline/bidi-safe) at this display boundary.
public enum AuditReportRenderer {
    public static func render(_ report: HostAuditReport, color: Bool, width: Int) -> String {
        var lines: [String] = []
        func emit(_ line: String = "") { lines.append(line) }
        func bold(_ s: String) -> String { TerminalStyle.paint(s, TerminalStyle.Code.bold, color: color) }
        func dim(_ s: String) -> String { TerminalStyle.paint(s, TerminalStyle.Code.dim, color: color) }
        func safe(_ s: String) -> String { ReviewDisplay.sanitized(s) }

        let exempted = Set(report.exemptions.map(\.id))
        let deferred = Set(report.todos.map(\.id))
        let byID = Dictionary(report.findings.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })

        let fails = report.findings.filter { $0.status == .fail }
        let needsAttention = fails.filter { !exempted.contains($0.id) && !deferred.contains($0.id) }
        let unknowns = report.findings.filter { $0.status == .unknown }
        let passing = report.findings.filter { $0.status == .pass }
        let expectedSelf = report.findings.filter { $0.status == .expectedSelf }
        let notApplicable = report.findings.filter { $0.status == .notApplicable }

        let ruleWidth = max(24, min(width, 66))
        emit(bold("Host posture audit"))
        emit(dim(String(repeating: "─", count: ruleWidth)))
        emit(safe(report.verdict))
        emit(summaryLine(
            verified: passing.count + expectedSelf.count,
            needsAttention: needsAttention.count,
            accepted: report.exemptions.count,
            planned: report.todos.count,
            couldNotVerify: unknowns.count,
            notApplicable: notApplicable.count,
            color: color))
        if let hint = report.generatedAtHint { emit(dim("generated \(safe(hint))")) }

        if !needsAttention.isEmpty {
            emit()
            emit(header("Needs attention", needsAttention.count, TerminalStyle.Code.red, color: color))
            for finding in needsAttention { emitFinding(finding, into: &lines, color: color) }
        }

        if !unknowns.isEmpty {
            emit()
            emit(header("Could not verify", unknowns.count, TerminalStyle.Code.yellow, color: color))
            for finding in unknowns { emitUnknown(finding, into: &lines, color: color) }
        }

        if !report.exemptions.isEmpty {
            emit()
            emit(header("Accepted risks", report.exemptions.count, TerminalStyle.Code.magenta, color: color))
            for info in report.exemptions {
                emitTriage("⚠", info, finding: byID[info.id], into: &lines, color: color)
            }
        }

        if !report.todos.isEmpty {
            emit()
            emit(header("Planned / TODO", report.todos.count, TerminalStyle.Code.blue, color: color))
            for info in report.todos {
                emitTriage("⏳", info, finding: byID[info.id], into: &lines, color: color)
            }
        }

        if !passing.isEmpty {
            emit()
            emit(header("Passing", passing.count, TerminalStyle.Code.green, color: color))
            emit("  " + dim(passing.map(\.id).joined(separator: ", ")))
        }
        if !expectedSelf.isEmpty {
            emit()
            emit(bold("Expected (csec's own)"))
            for finding in expectedSelf { emit("  \(finding.id)  \(dim(safe(finding.evidence)))") }
        }
        if !notApplicable.isEmpty {
            emit()
            emit(header("Not applicable", notApplicable.count, TerminalStyle.Code.dim, color: color))
            emit("  " + dim(notApplicable.map(\.id).joined(separator: ", ")))
        }
        if !report.coverageNotes.isEmpty {
            emit()
            emit(bold("Coverage notes"))
            for note in report.coverageNotes { emit("  - \(dim(safe(note)))") }
        }

        return lines.joined(separator: "\n")
    }

    // MARK: - Pieces

    private static func summaryLine(
        verified: Int, needsAttention: Int, accepted: Int, planned: Int,
        couldNotVerify: Int, notApplicable: Int, color: Bool
    ) -> String {
        func part(_ n: Int, _ label: String, _ code: String) -> String? {
            guard n > 0 else { return nil }
            return TerminalStyle.paint("\(n) \(label)", code, color: color)
        }
        let parts = [
            part(verified, "verified", TerminalStyle.Code.green),
            part(needsAttention, "need attention", TerminalStyle.Code.red),
            part(accepted, "accepted", TerminalStyle.Code.magenta),
            part(planned, "planned", TerminalStyle.Code.blue),
            part(couldNotVerify, "could not verify", TerminalStyle.Code.yellow),
            part(notApplicable, "n/a", TerminalStyle.Code.dim),
        ].compactMap { $0 }
        return parts.joined(separator: TerminalStyle.paint(" · ", TerminalStyle.Code.dim, color: color))
    }

    private static func header(_ title: String, _ count: Int, _ code: String, color: Bool) -> String {
        TerminalStyle.paint("\(title) (\(count))", code, color: color)
    }

    private static func emitFinding(_ finding: HostFinding, into lines: inout [String], color: Bool) {
        let star = finding.onThesis ? "★ " : ""
        let tag = remediationTag(finding.remediation)
        let tagText = tag.isEmpty ? "" : "  " + TerminalStyle.paint(tag, TerminalStyle.Code.cyan, color: color)
        lines.append("  \(severityIcon(finding.severity)) \(star)\(finding.id)  \(ReviewDisplay.sanitized(finding.title))\(tagText)")
        lines.append("       \(ReviewDisplay.sanitized(finding.evidence))")
        lines.append("       " + TerminalStyle.paint("↳ \(ReviewDisplay.sanitized(finding.anchor))", TerminalStyle.Code.dim, color: color))
    }

    private static func emitUnknown(_ finding: HostFinding, into lines: inout [String], color: Bool) {
        let star = finding.onThesis ? "★ " : ""
        lines.append("  · \(star)\(finding.id)  \(ReviewDisplay.sanitized(finding.title))")
        lines.append("       \(ReviewDisplay.sanitized(finding.evidence))")
        lines.append("       " + TerminalStyle.paint("↳ \(ReviewDisplay.sanitized(finding.anchor))", TerminalStyle.Code.dim, color: color))
    }

    private static func emitTriage(
        _ icon: String, _ info: HostTriageInfo, finding: HostFinding?, into lines: inout [String], color: Bool
    ) {
        let title = finding.map { ReviewDisplay.sanitized($0.title) } ?? info.id
        var line = "  \(icon) \(info.id)  \(title)"
        if let note = info.note, !note.isEmpty {
            line += "  " + TerminalStyle.paint("— “\(ReviewDisplay.sanitized(note))”", TerminalStyle.Code.dim, color: color)
        }
        lines.append(line)
    }

    // MARK: - Shared glyphs

    public static func severityIcon(_ severity: HostSeverity) -> String {
        switch severity {
        case .high: return "🔴"
        case .medium: return "🟠"
        case .low: return "🟡"
        case .info: return "·"
        }
    }

    public static func remediationTag(_ remediation: RemediationClass) -> String {
        switch remediation {
        case .auto: return "[auto-fix]"
        case .autoPrivileged: return "[auto-fix · root]"
        case .guided: return "[guided]"
        case .advise: return "[review]"
        case .none: return ""
        }
    }
}
