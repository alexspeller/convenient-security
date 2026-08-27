import ConvenientSecurity
import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// The per-finding triage decisions collected from the terminal.
struct TriageDecisions {
    var exemptions: [HostTriageDecision] = []
    var todos: [String] = []
    var isEmpty: Bool { exemptions.isEmpty && todos.isEmpty }
}

/// Raw-mode driver for the post-remediation triage: walk each still-failing
/// finding and ask whether to fix it later (TODO), accept it as a documented risk
/// (exemption, with an optional one-line note), or skip it. Returns nil only when
/// the terminal is non-interactive (the caller then skips triage). I/O only — the
/// decisions it returns are persisted by the caller through csecd.
enum AuditTriageView {
    static func run(findings: [HostFinding]) -> TriageDecisions? {
        guard !findings.isEmpty else { return TriageDecisions() }
        guard let raw = TerminalRawMode() else { return nil }
        defer { raw.restore() }
        let color = TerminalStyle.colorEnabled(STDERR_FILENO)
        var decisions = TriageDecisions()

        func write(_ s: String) { FileHandle.standardError.write(Data(s.utf8)) }
        func line(_ s: String = "") { write(s + "\n") }
        func bold(_ s: String) -> String { TerminalStyle.paint(s, TerminalStyle.Code.bold, color: color) }
        func dim(_ s: String) -> String { TerminalStyle.paint(s, TerminalStyle.Code.dim, color: color) }

        line()
        line(bold("Triage — \(findings.count) unresolved finding(s):"))
        line(dim("  [f] fix later (TODO, weekly reminders) · [e] exempt (accept risk) · [s] skip · [q] stop"))

        for (index, finding) in findings.enumerated() {
            line()
            line("  \(AuditReportRenderer.severityIcon(finding.severity)) \(finding.id)  "
                + "\(ReviewDisplay.sanitized(finding.title))  \(dim("(\(index + 1)/\(findings.count))"))")
            line("       \(dim(ReviewDisplay.sanitized(finding.evidence)))")

            decision: while true {
                write("    \(bold("[f]ix later / [e]xempt / [s]kip / [q]uit? "))")
                switch raw.readKey() {
                case .char("f"), .char("F"):
                    decisions.todos.append(finding.id)
                    line(dim("→ kept as TODO"))
                    break decision
                case .char("e"), .char("E"):
                    line()
                    write("    reason (optional, Enter to skip): ")
                    let note = raw.readLine(maxLength: 120)?.trimmingCharacters(in: .whitespaces)
                    decisions.exemptions.append(HostTriageDecision(
                        id: finding.id, note: (note?.isEmpty ?? true) ? nil : note))
                    line(dim("→ exempted (accepted risk)"))
                    break decision
                case .char("s"), .char("S"):
                    line(dim("→ skipped (will resurface next audit)"))
                    break decision
                case .char("q"), .char("Q"), .escape, .ctrlC, .eof:
                    line(dim("→ stopped triage"))
                    return decisions
                default:
                    line()
                    continue
                }
            }
        }
        return decisions
    }
}
