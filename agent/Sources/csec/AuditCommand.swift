import Foundation
import ConvenientSecurity

// `csec audit` — the host posture audit surface (docs/host-audit-catalog.md).
//
// The launcher is a thin client: it asks the resident agent (csecd) to run the
// value-free audit and returns a `HostAuditReport`. All privileged reads (R!),
// TCC/Full-Disk-Access enumeration, and remediation happen inside csecd. This
// command renders the report (severity-ordered, ★ on-thesis first), then — unless
// `--report-only` — asks csecd to present the batched remediation review (one
// Touch ID) and prints the applied/skipped/failed summary.

func runAudit(_ arguments: [String]) -> Never {
    var reportOnly = false
    var json = false
    var scanFilesystem = false
    for argument in arguments {
        switch argument {
        case "--report-only": reportOnly = true
        case "--json":
            json = true
            reportOnly = true      // JSON is a read-only data view
        case "--scan-filesystem": scanFilesystem = true
        default:
            FileHandle.standardError.write(Data("csec audit: unknown option \(auditSafe(argument))\n".utf8))
            usage()
        }
    }
    exit(performHostAudit(scanFilesystem: scanFilesystem, reportOnly: reportOnly, json: json))
}

/// Runs the audit and (optionally) remediation without exiting, so `csec setup`
/// can finish with a host posture pass (Decision 1). Returns a process exit code.
@discardableResult
func performHostAudit(scanFilesystem: Bool, reportOnly: Bool, json: Bool, quietWhenUnavailable: Bool = false) -> Int32 {
    let client = makeAgentClient()
    let report: HostAuditReport
    do {
        report = try client.hostAudit(scanFilesystem: scanFilesystem)
    } catch {
        if quietWhenUnavailable {
            print("\ncsec audit: the resident agent (csecd) is not reachable; run `csec audit` after it is running.")
            return 0
        }
        FileHandle.standardError.write(Data(
            "csec audit: could not reach the resident agent (csecd). Is it running? (`csec status`)\n".utf8))
        return 1
    }

    if json {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        if let data = try? encoder.encode(report), let text = String(data: data, encoding: .utf8) {
            print(text)
            return report.findings.contains { $0.status == .fail } ? 2 : 0
        }
        FileHandle.standardError.write(Data("csec audit: failed to encode report as JSON\n".utf8))
        return 1
    }

    renderReport(report)

    // Remediation: offer the batched, one-Touch-ID review unless report-only.
    let hasFixables = report.batchFixable.isEmpty == false
    let hasGuided = report.findings.contains { $0.status == .fail && $0.remediation == .guided }
    if !reportOnly, hasFixables {
        print("\n## Remediation")
        print("csecd will present \(report.batchFixable.count) reversible fix(es) as one review — a single Touch ID applies the ones you keep selected.")
        do {
            let summary = try client.hostRemediate(scanFilesystem: scanFilesystem)
            renderRemediation(summary)
        } catch {
            print("- remediation review could not be presented (csecd unavailable or denied).")
        }
    }

    // Guided helpers (FileVault, Santa) — interactive, launched on opt-in.
    if !reportOnly, hasGuided {
        let fails = Set(report.findings.filter { $0.status == .fail }.map(\.id))
        if fails.contains("HA-G03") { GuidedHelper.fileVault() }
        if fails.contains("HA-B08") { GuidedHelper.santa() }
    }

    return report.findings.contains { $0.status == .fail } ? 2 : 0
}

// MARK: - Rendering (value-free)

private func renderReport(_ report: HostAuditReport) {
    print("# Host posture audit")
    if let hint = report.generatedAtHint { print("_generated \(auditSafe(hint))_") }
    print("\n\(auditSafe(report.verdict))")

    let actionable = report.findings.filter { $0.status == .fail || $0.status == .unknown }
    let fails = actionable.filter { $0.status == .fail }
    if !fails.isEmpty {
        print("\n## Needs attention (\(fails.count))")
        for finding in fails { printFinding(finding) }
    }

    let unknowns = actionable.filter { $0.status == .unknown }
    if !unknowns.isEmpty {
        print("\n## Could not verify (\(unknowns.count))")
        for finding in unknowns {
            print("- \(finding.onThesis ? "★ " : "")\(finding.id)  \(auditSafe(finding.title))")
            print("    \(auditSafe(finding.evidence))")
            print("    ↳ \(auditSafe(finding.anchor))")
        }
    }

    let passing = report.findings.filter { $0.status == .pass }
    let expectedSelf = report.findings.filter { $0.status == .expectedSelf }
    let notApplicable = report.findings.filter { $0.status == .notApplicable }
    if !passing.isEmpty {
        print("\n## Passing (\(passing.count))")
        print("  " + passing.map(\.id).joined(separator: ", "))
    }
    if !expectedSelf.isEmpty {
        print("\n## Expected (csec's own)")
        for finding in expectedSelf { print("- \(finding.id)  \(auditSafe(finding.evidence))") }
    }
    if !notApplicable.isEmpty {
        print("\n## Not applicable (\(notApplicable.count))")
        print("  " + notApplicable.map(\.id).joined(separator: ", "))
    }
    if !report.coverageNotes.isEmpty {
        print("\n## Coverage notes")
        for note in report.coverageNotes { print("- \(auditSafe(note))") }
    }
}

private func printFinding(_ finding: HostFinding) {
    let icon: String
    switch finding.severity {
    case .high: icon = "🔴"
    case .medium: icon = "🟠"
    case .low: icon = "🟡"
    case .info: icon = "·"
    }
    let star = finding.onThesis ? "★ " : ""
    print("- \(icon) \(star)\(finding.id)  \(auditSafe(finding.title))  \(remediationTag(finding.remediation))")
    print("    \(auditSafe(finding.evidence))")
    print("    ↳ \(auditSafe(finding.anchor))")
}

private func remediationTag(_ remediation: RemediationClass) -> String {
    switch remediation {
    case .auto: return "[auto-fix]"
    case .autoPrivileged: return "[auto-fix · root]"
    case .guided: return "[guided]"
    case .advise: return "[review]"
    case .none: return ""
    }
}

private func renderRemediation(_ summary: HostRemediationSummary) {
    if !summary.approved {
        print("- no changes applied (review declined).")
        return
    }
    if !summary.applied.isEmpty { print("- applied: \(summary.applied.map(auditSafe).joined(separator: ", "))") }
    if !summary.skipped.isEmpty { print("- skipped: \(summary.skipped.map(auditSafe).joined(separator: ", "))") }
    if !summary.failed.isEmpty { print("- failed:  \(summary.failed.map(auditSafe).joined(separator: ", "))") }
    if summary.applied.isEmpty && summary.failed.isEmpty { print("- no changes were selected.") }
}

/// Neutralize control / bidi characters in any string sent to the terminal.
/// The findings are already value-free and sanitized in the engine; this is a
/// belt-and-suspenders pass at the display boundary.
func auditSafe(_ value: String) -> String {
    let bidiControls: Set<UInt32> = [
        0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
        0x2066, 0x2067, 0x2068, 0x2069,
    ]
    return value.unicodeScalars.map { scalar in
        if CharacterSet.controlCharacters.contains(scalar) || bidiControls.contains(scalar.value) {
            return "\u{FFFD}"
        }
        return String(scalar)
    }.joined()
}
