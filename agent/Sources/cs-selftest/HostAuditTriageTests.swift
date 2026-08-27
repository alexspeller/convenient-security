import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Triage lifecycle + terminal presenters: the wire round-trip of the new
// `host_record_triage` verb, tolerant Codable for the report/baseline (older
// payloads without the triage fields still decode), the pure baseline merge and
// reminder logic, and the value-free report / attestation renderers and picker
// state machine. All pure — no TTY, no on-disk baseline touched.

private func finding(
    _ id: String,
    _ status: FindingStatus,
    severity: HostSeverity = .medium,
    title: String? = nil,
    remediation: RemediationClass = .none,
    key: String? = nil
) -> HostFinding {
    HostFinding(
        id: id, title: title ?? "\(id) title", severity: severity, tier: .runtimeReadable,
        status: status, onThesis: false, evidence: "\(id) evidence", anchor: "\(id) anchor",
        remediation: remediation, remediationKey: key)
}

private func item(_ key: String, root: Bool = false) -> HostRemediationItem {
    HostRemediationItem(key: key, title: "\(key) fix", detail: "\(key) reversible detail", requiresRoot: root)
}

func hostAuditTriageTests() {
    triageWireRoundTrip()
    reportCodableTolerantDecode()
    baselineTolerantDecode()
    triageMergeSemantics()
    baselineAutoClear()
    regressionAndReminderLogic()
    reportRenderer()
    attestationRenderer()
    selectModel()
}

// MARK: - wire + codable

private func triageWireRoundTrip() {
    let request = HostTriageRequest(
        exemptions: [HostTriageDecision(id: "HA-B08", note: "using CrowdStrike")],
        todos: ["HA-C03", "HA-G08"],
        cleared: ["HA-X01"])
    do {
        let data = try JSONEncoder().encode(Request.hostRecordTriage(request))
        let decoded = try JSONDecoder().decode(Request.self, from: data)
        guard case let .hostRecordTriage(back) = decoded else {
            check(false, "triage wire: decodes back to a hostRecordTriage request")
            return
        }
        check(back == request, "triage wire: round-trips exemptions/todos/cleared + requestID")
    } catch {
        check(false, "triage wire: encodes/decodes without error (\(error))")
    }
}

private func reportCodableTolerantDecode() {
    let report = HostAuditReport(
        findings: [finding("HA-C01", .fail, remediation: .autoPrivileged, key: "HA-C01")],
        verdict: "v",
        remediationItems: [item("HA-C01", root: true)],
        exemptions: [HostTriageInfo(id: "HA-B08", note: "n", recordedAtHint: "2026-08-20T00:00:00Z")],
        todos: [HostTriageInfo(id: "HA-C03", recordedAtHint: "2026-08-21T00:00:00Z")])
    do {
        let data = try JSONEncoder().encode(report)
        let back = try JSONDecoder().decode(HostAuditReport.self, from: data)
        check(back == report, "report codable: new triage/remediation fields round-trip")
    } catch {
        check(false, "report codable: encodes/decodes (\(error))")
    }

    // A payload predating the fields must still decode (defaults to empty).
    let legacy = Data(#"{"findings":[],"unverifiable":[],"coverageNotes":[],"verdict":"ok"}"#.utf8)
    do {
        let old = try JSONDecoder().decode(HostAuditReport.self, from: legacy)
        check(old.remediationItems.isEmpty && old.exemptions.isEmpty && old.todos.isEmpty,
              "report codable: a payload without triage fields decodes to empty")
    } catch {
        check(false, "report codable: legacy payload without new fields still decodes (\(error))")
    }
}

private func baselineTolerantDecode() {
    let legacy = Data(#"{"entries":{"HA-A01":{"status":"pass"}}}"#.utf8)
    do {
        let baseline = try JSONDecoder().decode(HostAuditBaseline.self, from: legacy)
        check(baseline.entries["HA-A01"]?.status == "pass"
              && baseline.exemptions.isEmpty && baseline.todos.isEmpty,
              "baseline codable: an existing file without triage maps loads with empty maps")
    } catch {
        check(false, "baseline codable: legacy baseline decodes (\(error))")
    }

    var full = HostAuditBaseline(entries: ["HA-A01": BaselineEntry(status: "pass", acceptedAtHint: nil)])
    full.exemptions["HA-B08"] = TriageRecord(note: "reason", recordedAtHint: "2026-08-20T00:00:00Z")
    full.todos["HA-C03"] = TriageRecord(recordedAtHint: "2026-08-21T00:00:00Z", lastRemindedAtHint: "2026-08-22T00:00:00Z")
    do {
        let data = try JSONEncoder().encode(full)
        let back = try JSONDecoder().decode(HostAuditBaseline.self, from: data)
        check(back == full, "baseline codable: exemptions/todos round-trip")
    } catch {
        check(false, "baseline codable: full baseline round-trips (\(error))")
    }
}

// MARK: - merge + auto-clear

private func triageMergeSemantics() {
    var baseline = HostAuditBaseline()
    baseline.todos["HA-C03"] = TriageRecord(recordedAtHint: "2026-08-01T00:00:00Z", lastRemindedAtHint: "2026-08-10T00:00:00Z")

    // Exempting a finding that was a TODO supersedes the TODO.
    let exempt = HostAuditService.applyingTriage(
        HostTriageRequest(exemptions: [HostTriageDecision(id: "HA-C03", note: "ok")]),
        to: baseline, recordedAtHint: "2026-08-27T00:00:00Z")
    check(exempt.exemptions["HA-C03"]?.note == "ok" && exempt.todos["HA-C03"] == nil,
          "triage merge: exempting supersedes an existing TODO")

    // Re-recording a TODO preserves its reminder cadence.
    let reTodo = HostAuditService.applyingTriage(
        HostTriageRequest(todos: ["HA-C03"]), to: baseline, recordedAtHint: "2026-08-27T00:00:00Z")
    check(reTodo.todos["HA-C03"]?.lastRemindedAtHint == "2026-08-10T00:00:00Z",
          "triage merge: re-recording a TODO preserves lastRemindedAtHint")

    // Cleared removes from both maps.
    var seeded = HostAuditBaseline()
    seeded.exemptions["HA-B08"] = TriageRecord(note: "x")
    seeded.todos["HA-C03"] = TriageRecord()
    let cleared = HostAuditService.applyingTriage(
        HostTriageRequest(cleared: ["HA-B08", "HA-C03"]), to: seeded)
    check(cleared.exemptions.isEmpty && cleared.todos.isEmpty,
          "triage merge: cleared removes exemptions and todos")
}

private func baselineAutoClear() {
    var baseline = HostAuditBaseline()
    baseline.exemptions["HA-B08"] = TriageRecord(note: "x")
    baseline.todos["HA-C03"] = TriageRecord()

    let nowPass = HostAuditReport(
        findings: [finding("HA-B08", .pass), finding("HA-C03", .fail)], verdict: "v")
    let advanced = HostAuditService.applyingBaseline(nowPass, to: baseline, acceptedAtHint: "2026-08-27T00:00:00Z")
    check(advanced.exemptions["HA-B08"] == nil,
          "baseline auto-clear: an exemption clears when its finding now passes")
    check(advanced.todos["HA-C03"] != nil,
          "baseline auto-clear: a TODO whose finding still fails is retained")
}

private func regressionAndReminderLogic() {
    var baseline = HostAuditBaseline(entries: [
        "HA-C01": BaselineEntry(status: "pass", acceptedAtHint: nil),
        "HA-C02": BaselineEntry(status: "pass", acceptedAtHint: nil),
    ])
    baseline.exemptions["HA-C02"] = TriageRecord(note: "accepted")
    let report = HostAuditReport(
        findings: [finding("HA-C01", .fail), finding("HA-C02", .fail)], verdict: "v")
    let regressions = HostAuditService.baselineRegressions(report: report, baseline: baseline)
    check(regressions.map(\.id) == ["HA-C01"],
          "regressions: a pass→fail control regresses, but an exempted one is skipped")

    // Reminder windowing.
    let now = Date(timeIntervalSince1970: 1_700_000_000)
    let iso = ISO8601DateFormatter()
    var todoBaseline = HostAuditBaseline()
    todoBaseline.todos["HA-A"] = TriageRecord()                                              // never reminded
    todoBaseline.todos["HA-B"] = TriageRecord(lastRemindedAtHint: iso.string(from: now.addingTimeInterval(-2 * 86_400)))  // 2 days
    todoBaseline.todos["HA-C"] = TriageRecord(lastRemindedAtHint: iso.string(from: now.addingTimeInterval(-8 * 86_400)))  // 8 days
    todoBaseline.todos["HA-D"] = TriageRecord()                                              // now passing
    let todoReport = HostAuditReport(findings: [
        finding("HA-A", .fail), finding("HA-B", .fail), finding("HA-C", .fail), finding("HA-D", .pass),
    ], verdict: "v")
    let due = HostAuditService.dueTodoReminders(report: todoReport, baseline: todoBaseline, now: now)
    check(due == ["HA-A", "HA-C"],
          "reminders: due = never-reminded or >7d old, and only while the finding still fails")

    let stamped = HostAuditService.stamping(due, in: todoBaseline, atHint: iso.string(from: now))
    check(stamped.todos["HA-A"]?.lastRemindedAtHint == iso.string(from: now),
          "reminders: stamping records the reminder time for due todos")
}

// MARK: - presenters

private func reportRenderer() {
    let report = HostAuditReport(
        findings: [
            finding("HA-C01", .fail, severity: .high, title: "Firewall off", remediation: .autoPrivileged, key: "HA-C01"),
            finding("HA-A01", .pass, title: "SIP on"),
            finding("HA-A02", .pass, title: "Secure boot"),
            finding("HA-B08", .fail, title: "Santa missing"),
            finding("HA-D07", .unknown, title: "TCC unverifiable"),
        ],
        verdict: "posture: fair",
        generatedAtHint: "2026-08-27T00:00:00Z",
        remediationItems: [item("HA-C01", root: true)],
        exemptions: [HostTriageInfo(id: "HA-B08", note: "using CrowdStrike", recordedAtHint: "2026-08-20T00:00:00Z")])
    let out = AuditReportRenderer.render(report, color: false, width: 80)
    check(out.contains("Needs attention (1)"), "report: exempted fails are excluded from needs-attention")
    check(out.contains("Accepted risks (1)") && out.contains("using CrowdStrike"),
          "report: exemptions render with their note")
    check(out.contains("Could not verify (1)"), "report: unknowns render under could-not-verify")
    check(out.contains("Passing (2)"), "report: passing controls are counted")
    check(out.contains("[auto-fix · root]"), "report: the fix tag is shown for a fixable fail")
    check(!out.contains("\u{1B}["), "report: no ANSI escapes when color is off")
}

private func attestationRenderer() {
    let report = HostAuditReport(
        findings: [
            finding("HA-C01", .fail, severity: .high, title: "Firewall off"),
            finding("HA-A01", .pass, title: "SIP on"),
            finding("HA-A02", .pass, title: "Secure boot"),
            finding("HA-B08", .fail, title: "Santa missing"),
        ],
        verdict: "v")
    let identity = AttestationIdentity(hostname: "test-mbp", hardwareModel: "Mac15,3", osVersion: "15.2")
    let out = AttestationRenderer.render(
        report: report, identity: identity,
        exemptions: [HostTriageInfo(id: "HA-B08", note: "using CrowdStrike", recordedAtHint: "2026-08-20T00:00:00Z")],
        todos: [], generatedAtHint: "2026-08-27T12:00:00Z")
    check(out.contains("Mac15,3") && out.contains("macOS 15.2") && out.contains("hostname `test-mbp`"),
          "attestation: machine header carries model + macOS version + hostname")
    check(out.contains("Verified controls (2)"), "attestation: verified controls are listed")
    check(out.contains("Accepted risks (1)") && out.contains("using CrowdStrike"),
          "attestation: accepted risks carry the note")
    check(out.contains("Needs attention (1)"), "attestation: honestly surfaces remaining failures")

    // A clean machine reads as fully configured.
    let clean = HostAuditReport(findings: [finding("HA-A01", .pass)], verdict: "v")
    let cleanOut = AttestationRenderer.render(
        report: clean, identity: identity, exemptions: [], todos: [], generatedAtHint: "2026-08-27T12:00:00Z")
    check(cleanOut.contains("All applicable controls are verified"),
          "attestation: a clean machine reads as properly configured")
}

private func selectModel() {
    var model = AuditSelectModel(items: [item("A"), item("B"), item("C")])
    check(model.selectedKeys == ["A", "B", "C"], "picker: every fix starts selected")

    model.moveDown()
    model.toggle()
    check(model.selectedKeys == ["A", "C"], "picker: space toggles the cursor row off")

    model.toggleAll()
    check(model.selected.count == 3, "picker: toggle-all selects all when some are off")
    model.toggleAll()
    check(model.selected.isEmpty, "picker: toggle-all clears when everything was selected")

    var single = AuditSelectModel(items: [item("A")])
    single.moveUp(); single.moveDown()
    check(single.cursor == 0, "picker: the cursor stays within bounds")

    let block = AuditSelectModel(items: [item("A")]).render(color: false, width: 80)
    check(block.contains("[x] A") && !block.contains("\u{1B}["),
          "picker: renders a plain checkbox block with no ANSI when color is off")
}
