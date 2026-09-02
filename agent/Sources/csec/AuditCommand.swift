import Foundation
import ConvenientSecurity

#if canImport(Darwin)
import Darwin
#endif

// `csec audit` — the host posture audit surface (docs/host-audit-catalog.md).
//
// The launcher is a thin client: it asks the resident agent (csecd) to run the
// value-free audit and returns a `HostAuditReport`. All privileged reads (R!),
// TCC/Full-Disk-Access enumeration, and remediation happen inside csecd. This
// command renders a formatted terminal report, then — when interactive and not
// `--report-only` — drives an in-terminal checkbox picker for the reversible
// fixes (one bare Touch ID in csecd applies the selected set), triages whatever
// is still failing (accept as an exemption, or keep as a TODO with weekly
// reminders), and prints a copy-paste attestation of the final posture.

func runAudit(_ arguments: [String]) -> Never {
    var reportOnly = false
    var json = false
    var scanFilesystem = false
    var attest = false
    for argument in arguments {
        switch argument {
        case "--report-only": reportOnly = true
        case "--json":
            json = true
            reportOnly = true      // JSON is a read-only data view
        case "--attest": attest = true
        case "--scan-filesystem": scanFilesystem = true
        default:
            csecError("audit", "unknown option \(ReviewDisplay.sanitized(argument, allowNewlines: true))")
            usage("audit")
        }
    }
    exit(performHostAudit(
        scanFilesystem: scanFilesystem, reportOnly: reportOnly, json: json, attest: attest))
}

/// Runs the audit and (optionally) remediation/triage/attestation without exiting,
/// so `csec setup` can finish with a host posture pass (Decision 1). Returns a
/// process exit code.
@discardableResult
func performHostAudit(
    scanFilesystem: Bool,
    reportOnly: Bool,
    json: Bool,
    attest: Bool = false,
    quietWhenUnavailable: Bool = false
) -> Int32 {
    let client = makeAgentClient()
    // Animate the scan on an interactive terminal; keep machine output (piped
    // stdout or --json) on the plain, blocking request.
    let animate = !json && auditAnimationEnabled()
    let report: HostAuditReport
    do {
        report = animate
            ? try runAnimatedAudit(client: client, scanFilesystem: scanFilesystem)
            : try client.hostAudit(scanFilesystem: scanFilesystem)
    } catch {
        if quietWhenUnavailable {
            print("\ncsec audit: the resident agent (csecd) is not reachable; run `csec audit` after it is running.")
            return 0
        }
        csecError("audit", "could not reach the resident agent (csecd). Is it running? (`csec status`)")
        return 1
    }

    if json {
        return emitJSON(report)
    }

    if attest {
        // The regenerate-on-demand path: only the pasteable attestation to stdout.
        printAttestation(report: report, exemptions: report.exemptions, todos: report.todos)
        return exitCode(for: report)
    }

    print(AuditReportRenderer.render(
        report, color: TerminalStyle.colorEnabled(STDOUT_FILENO),
        width: TerminalStyle.terminalWidth(fd: STDOUT_FILENO)))

    guard !reportOnly, auditInteractionEnabled() else {
        return exitCode(for: report)
    }

    // --- Remediation: terminal checkbox picker → csecd applies under one Touch ID.
    var fixesApplied = false
    if !report.remediationItems.isEmpty {
        if let selectedKeys = AuditSelectView.run(items: report.remediationItems) {
            if selectedKeys.isEmpty {
                print("No fixes selected.")
            } else {
                do {
                    let summary = try remediateWithProgress(
                        client: client, selectedKeys: selectedKeys,
                        scanFilesystem: scanFilesystem, animate: animate)
                    renderRemediation(summary)
                    fixesApplied = !summary.applied.isEmpty
                } catch {
                    print("Remediation could not be completed (csecd unavailable or denied).")
                }
            }
        }
    }

    // Guided helpers (FileVault, Santa) — interactive, launched on opt-in. Anything
    // left failing afterwards still flows through triage below.
    let guidedFails = Set(report.findings.filter { $0.status == .fail && $0.remediation == .guided }.map(\.id))
    if guidedFails.contains("HA-G03") { GuidedHelper.fileVault() }
    if guidedFails.contains("HA-B08") { GuidedHelper.santa() }

    // --- Re-audit after applying fixes so the triage + attestation reflect the
    //     freshly measured state (the user chose verified freshness).
    var finalReport = report
    if fixesApplied {
        if let refreshed = try? refreshReport(client: client, scanFilesystem: scanFilesystem, animate: animate) {
            finalReport = refreshed
        }
    }

    // --- Triage everything still failing that has not already been triaged.
    let alreadyTriaged = Set(finalReport.exemptions.map(\.id)).union(finalReport.todos.map(\.id))
    let toTriage = finalReport.findings.filter { $0.status == .fail && !alreadyTriaged.contains($0.id) }

    var sessionExemptions: [HostTriageInfo] = []
    var sessionTodos: [HostTriageInfo] = []
    if !toTriage.isEmpty, let decisions = AuditTriageView.run(findings: toTriage), !decisions.isEmpty {
        try? client.hostRecordTriage(exemptions: decisions.exemptions, todos: decisions.todos)
        let nowHint = ISO8601DateFormatter().string(from: Date())
        sessionExemptions = decisions.exemptions.map {
            HostTriageInfo(id: $0.id, note: $0.note, recordedAtHint: nowHint)
        }
        sessionTodos = decisions.todos.map { HostTriageInfo(id: $0, recordedAtHint: nowHint) }
    }

    // --- Final attestation: fresh report + persisted-and-this-session triage.
    let mergedExemptions = mergeTriage(
        finalReport.exemptions, sessionExemptions, removing: Set(sessionTodos.map(\.id)))
    let mergedTodos = mergeTriage(
        finalReport.todos, sessionTodos, removing: Set(sessionExemptions.map(\.id)))
    printAttestation(report: finalReport, exemptions: mergedExemptions, todos: mergedTodos)

    return exitCode(for: finalReport)
}

// MARK: - JSON + exit codes

private func emitJSON(_ report: HostAuditReport) -> Int32 {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    if let data = try? encoder.encode(report), let text = String(data: data, encoding: .utf8) {
        print(text)
        return exitCode(for: report)
    }
    csecError("audit", "failed to encode report as JSON")
    return 1
}

private func exitCode(for report: HostAuditReport) -> Int32 {
    report.findings.contains { $0.status == .fail } ? 2 : 0
}

// MARK: - Streaming scan (animated)

/// Drive the streaming audit: kick off the background job in csecd, then poll it
/// on a fixed cadence and animate a value-free progress line until the report is
/// ready. Degrades gracefully to the blocking audit if the resident agent does
/// not speak the streaming verbs (an older csecd) or the stream breaks mid-run.
private func runAnimatedAudit(client: AgentClient, scanFilesystem: Bool) throws -> HostAuditReport {
    installAuditInterruptCursorRestore()
    let stream: HostAuditProgressStream
    do {
        stream = try client.beginHostAudit(scanFilesystem: scanFilesystem)
    } catch {
        // No streaming support (or a transient failure) — fall back so the user
        // still gets a report. If csecd is simply unreachable this rethrows and
        // the caller renders the standard "is it running?" message.
        return try client.hostAudit(scanFilesystem: scanFilesystem)
    }

    var view = AuditProgressView(start: Date())
    view.render(stream.snapshot)
    while !stream.isDone {
        usleep(90_000)      // ~11 fps: smooth spinner, negligible socket traffic
        do {
            try stream.poll()
        } catch {
            view.finish()
            return try client.hostAudit(scanFilesystem: scanFilesystem)
        }
        view.render(stream.snapshot)
    }
    view.finish()
    guard let report = stream.report else {
        return try client.hostAudit(scanFilesystem: scanFilesystem)
    }
    return report
}

/// Re-run the audit for the verified end state after fixes were applied, animating
/// it like the first scan.
private func refreshReport(client: AgentClient, scanFilesystem: Bool, animate: Bool) throws -> HostAuditReport {
    animate
        ? try runAnimatedAudit(client: client, scanFilesystem: scanFilesystem)
        : try client.hostAudit(scanFilesystem: scanFilesystem)
}

/// Present a spinner while the (blocking) remediation runs. csecd re-checks the
/// host and presents the Touch ID prompt; without this the terminal would sit
/// silent for several seconds. The blocking call stays on the calling thread; only
/// the spinner animates on a helper thread.
private func remediateWithProgress(
    client: AgentClient, selectedKeys: [String], scanFilesystem: Bool, animate: Bool
) throws -> HostRemediationSummary {
    guard animate else {
        return try client.hostRemediate(selectedKeys: selectedKeys, scanFilesystem: scanFilesystem)
    }
    installAuditInterruptCursorRestore()
    let stop = AtomicFlag()
    let finished = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
        var spinner = IndeterminateSpinner(
            label: "Applying fixes — approve in the Touch ID prompt when it appears…")
        while !stop.value {
            spinner.tick()
            usleep(90_000)
        }
        spinner.stop()
        finished.signal()
    }
    defer {
        stop.set()
        finished.wait()
    }
    return try client.hostRemediate(selectedKeys: selectedKeys, scanFilesystem: scanFilesystem)
}

/// A tiny lock-guarded boolean shared with the spinner helper thread.
private final class AtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    var value: Bool { lock.lock(); defer { lock.unlock() }; return flag }
    func set() { lock.lock(); flag = true; lock.unlock() }
}

// MARK: - Remediation summary + attestation

private func renderRemediation(_ summary: HostRemediationSummary) {
    if !summary.approved {
        print("No changes applied (Touch ID declined or unavailable).")
        return
    }
    func safe(_ value: String) -> String { ReviewDisplay.sanitized(value, allowNewlines: true) }
    if !summary.applied.isEmpty { print("Applied: \(summary.applied.map(safe).joined(separator: ", "))") }
    if !summary.skipped.isEmpty { print("Skipped: \(summary.skipped.map(safe).joined(separator: ", "))") }
    if !summary.failed.isEmpty { print("Failed:  \(summary.failed.map(safe).joined(separator: ", "))") }
    if summary.applied.isEmpty && summary.failed.isEmpty { print("No changes were applied.") }
}

/// Print the copy-paste attestation. The pasteable markdown block goes to stdout;
/// the framing banner goes to stderr, so `csec audit --attest > file` captures only
/// the block.
private func printAttestation(
    report: HostAuditReport, exemptions: [HostTriageInfo], todos: [HostTriageInfo]
) {
    let generatedAt = report.generatedAtHint ?? ISO8601DateFormatter().string(from: Date())
    let body = AttestationRenderer.render(
        report: report, identity: HostIdentity.current(),
        exemptions: exemptions, todos: todos, generatedAtHint: generatedAt)
    FileHandle.standardError.write(Data("\n─── copy the attestation below ───\n".utf8))
    print(body)
    FileHandle.standardError.write(Data("──────────────────────────────────\n".utf8))
}

/// Merge persisted + this-session triage infos by id (this session wins), dropping
/// any id that moved to the other bucket this session.
private func mergeTriage(
    _ persisted: [HostTriageInfo], _ session: [HostTriageInfo], removing movedAway: Set<String>
) -> [HostTriageInfo] {
    var byID: [String: HostTriageInfo] = [:]
    for info in persisted { byID[info.id] = info }
    for info in session { byID[info.id] = info }
    for id in movedAway { byID.removeValue(forKey: id) }
    return byID.values.sorted { $0.id < $1.id }
}

