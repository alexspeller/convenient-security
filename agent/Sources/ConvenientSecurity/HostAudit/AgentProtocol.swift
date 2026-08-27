import Foundation
import CSECRootProtocol

// Agent-protocol request/response payloads for the host audit, plus the shared
// runner csecd uses both for an on-demand `csec audit` and for the periodic
// re-audit. The `csec` launcher is a thin client: it asks csecd (the agent) to
// run the audit and returns the value-free `HostAuditReport`; the privileged
// reads (R!), TCC (FDA), and any remediation all happen inside csecd.

public struct HostAuditRequest: Sendable, Equatable {
    public let requestID: String
    public let scanFilesystem: Bool
    public init(scanFilesystem: Bool = false, requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.scanFilesystem = scanFilesystem
    }
    /// Reconstruct from a decoded wire UUID.
    public init(scanFilesystem: Bool, requestUUID: UUID) {
        self.requestID = requestUUID.uuidString.lowercased()
        self.scanFilesystem = scanFilesystem
    }
}

/// A value-free live snapshot of an in-flight audit, streamed to the launcher so
/// `csec audit` can animate progress instead of appearing to hang. Every field is
/// static catalog metadata (counts and the catalog id/title of the check being
/// run) — never evidence, command output, or a credential value.
public struct HostAuditProgressSnapshot: Codable, Sendable, Equatable {
    /// Total registered checks in this run.
    public let total: Int
    /// Checks already completed (0…total).
    public let completed: Int
    /// Catalog id of the check now running (e.g. "HA-D03"); empty when finalizing.
    public let currentID: String
    /// Value-free catalog title of the check now running; empty when finalizing.
    public let currentTitle: String
    /// True once the report is ready (the terminal poll also carries the report).
    public let done: Bool

    public init(total: Int, completed: Int, currentID: String, currentTitle: String, done: Bool) {
        self.total = total
        self.completed = completed
        self.currentID = currentID
        self.currentTitle = currentTitle
        self.done = done
    }

    /// The snapshot a freshly-started job reports before its first check runs.
    public static func starting(total: Int) -> HostAuditProgressSnapshot {
        HostAuditProgressSnapshot(total: total, completed: 0, currentID: "", currentTitle: "", done: false)
    }
}

/// Poll one in-flight audit job for its current progress snapshot. Carries its own
/// `requestID` (bound to this poll's response for the nonce check) and the `jobID`
/// returned by `hostAuditStart` (the job to look up).
public struct HostAuditPollRequest: Sendable, Equatable {
    public let requestID: String
    public let jobID: String
    public init(jobID: String, requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.jobID = jobID
    }
    public init(jobID: String, requestUUID: UUID) {
        self.requestID = requestUUID.uuidString.lowercased()
        self.jobID = jobID
    }
}

public struct HostRemediationRequest: Sendable, Equatable {
    public let requestID: String
    /// Remediation keys (catalog ids) the caller pre-selected. Empty = offer the
    /// full batch of fixable findings in the review checklist.
    public let selectedKeys: [String]
    public let scanFilesystem: Bool
    public init(selectedKeys: [String] = [], scanFilesystem: Bool = false, requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.selectedKeys = selectedKeys
        self.scanFilesystem = scanFilesystem
    }
    public init(selectedKeys: [String], scanFilesystem: Bool, requestUUID: UUID) {
        self.requestID = requestUUID.uuidString.lowercased()
        self.selectedKeys = selectedKeys
        self.scanFilesystem = scanFilesystem
    }
}

/// Value-free outcome of a batched remediation.
public struct HostRemediationSummary: Codable, Sendable, Equatable {
    public let approved: Bool
    public let applied: [String]
    public let skipped: [String]
    public let failed: [String]
    public init(approved: Bool, applied: [String] = [], skipped: [String] = [], failed: [String] = []) {
        self.approved = approved
        self.applied = applied
        self.skipped = skipped
        self.failed = failed
    }
}

/// One triage decision the launcher records for a finding: accept it as a
/// documented risk (an exemption, with an optional value-free note). The
/// `todos`/`cleared` lists on the request carry bare ids.
public struct HostTriageDecision: Codable, Sendable, Equatable {
    public let id: String
    public let note: String?
    public init(id: String, note: String? = nil) {
        self.id = id
        self.note = note
    }
}

/// Persist a batch of triage decisions into the accepted baseline: `exemptions`
/// (accept-risk, with notes), `todos` (deferred fixes, weekly reminders), and
/// `cleared` (remove from triage). Value-free — notes are the user's own text.
public struct HostTriageRequest: Sendable, Equatable {
    public let requestID: String
    public let exemptions: [HostTriageDecision]
    public let todos: [String]
    public let cleared: [String]
    public init(
        exemptions: [HostTriageDecision] = [],
        todos: [String] = [],
        cleared: [String] = [],
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.exemptions = exemptions
        self.todos = todos
        self.cleared = cleared
    }
    public init(
        exemptions: [HostTriageDecision],
        todos: [String],
        cleared: [String],
        requestUUID: UUID
    ) {
        self.requestID = requestUUID.uuidString.lowercased()
        self.exemptions = exemptions
        self.todos = todos
        self.cleared = cleared
    }
}

/// Value-free result of a periodic background scan: `pass → fail` regressions and
/// the TODO ids whose weekly reminder is now due.
public struct PeriodicHostFindings: Sendable {
    public let regressions: [HostFinding]
    public let dueTodoReminders: [String]
    public init(regressions: [HostFinding], dueTodoReminders: [String]) {
        self.regressions = regressions
        self.dueTodoReminders = dueTodoReminders
    }
}

/// Builds the production audit context (real command runner, root-helper
/// privileged ops as the agent role, FDA-gated TCC reader) and runs the engine.
/// Shared by the on-demand handler and the periodic re-audit so there is exactly
/// one audit engine.
public enum HostAuditService {
    public static func productionContext(scanFilesystem: Bool) -> HostAuditContext {
        #if DEBUG
        let rootTrust: RootHelperServerTrustPolicy = .allowUnverifiedForTesting
        #else
        let rootTrust: RootHelperServerTrustPolicy = .requireProductRootHelper
        #endif
        let client = RootHelperClient(trustPolicy: rootTrust)
        return HostAuditContext.production(
            rootHelper: client,
            options: HostAuditOptions(scanFilesystem: scanFilesystem, reportOnly: false)
        )
    }

    public static func runReport(
        scanFilesystem: Bool,
        generatedAtHint: String? = nil,
        includeRemediation: Bool = false,
        onProgress: (@Sendable (Int, Int, String, String) async -> Void)? = nil
    ) async -> HostAuditReport {
        let ctx = productionContext(scanFilesystem: scanFilesystem)
        let report = await HostAuditEngine().run(
            ctx, generatedAtHint: generatedAtHint, onProgress: onProgress)
        return await annotate(report, ctx: ctx, includeRemediation: includeRemediation)
    }

    /// The interactive path (user-initiated `csec audit`). Produces the report and
    /// records the current state as the accepted baseline — the user has now seen
    /// it, so a later background run only flags a *change* from this point. An
    /// optional `onProgress` callback streams value-free per-check progress so the
    /// launcher can animate the scan. The report is annotated *after* the baseline
    /// advance so it reflects any triage cleared by a now-passing finding.
    public static func runInteractive(
        scanFilesystem: Bool,
        generatedAtHint: String? = nil,
        includeRemediation: Bool = false,
        onProgress: (@Sendable (Int, Int, String, String) async -> Void)? = nil
    ) async -> HostAuditReport {
        let ctx = productionContext(scanFilesystem: scanFilesystem)
        let base = await HostAuditEngine().run(
            ctx, generatedAtHint: generatedAtHint, onProgress: onProgress)
        recordBaseline(base, acceptedAtHint: generatedAtHint)
        return await annotate(base, ctx: ctx, includeRemediation: includeRemediation)
    }

    /// Attach the launcher-facing, value-free triage/remediation metadata: the
    /// accepted exemptions and TODOs from the baseline, and (when requested) the
    /// reversible fixes the launcher renders as a checkbox picker. Building the
    /// remediation items reuses the run's memoized ctx, so it is near-free.
    static func annotate(
        _ report: HostAuditReport, ctx: HostAuditContext, includeRemediation: Bool
    ) async -> HostAuditReport {
        let baseline = ctx.baseline.load()
        let exemptions = triageInfos(baseline.exemptions)
        let todos = triageInfos(baseline.todos)
        var items: [HostRemediationItem] = []
        if includeRemediation {
            items = await HostRemediationBuilder.plans(for: report, ctx: ctx).map(\.item)
        }
        return report.annotated(remediationItems: items, exemptions: exemptions, todos: todos)
    }

    private static func triageInfos(_ records: [String: TriageRecord]) -> [HostTriageInfo] {
        records
            .map { HostTriageInfo(id: $0.key, note: $0.value.note, recordedAtHint: $0.value.recordedAtHint) }
            .sorted { $0.id < $1.id }
    }

    /// Persist the current statuses as the accepted baseline (Decision 6). Only the
    /// interactive path calls this; the background timer never advances the baseline.
    public static func recordBaseline(_ report: HostAuditReport, acceptedAtHint: String? = nil) {
        let store = FileBaselineStore()
        store.save(applyingBaseline(report, to: store.load(), acceptedAtHint: acceptedAtHint))
    }

    /// Pure baseline advance — testable without touching the on-disk store.
    public static func applyingBaseline(
        _ report: HostAuditReport, to baseline: HostAuditBaseline, acceptedAtHint: String? = nil
    ) -> HostAuditBaseline {
        var baseline = baseline
        for finding in report.findings {
            baseline.entries[finding.id] = BaselineEntry(
                status: finding.status.rawValue, acceptedAtHint: acceptedAtHint)
        }
        // A triaged finding that now holds a secure/expected/n-a status is resolved;
        // drop its exemption/TODO so it stops surfacing (and stops reminding).
        for finding in report.findings
        where finding.status == .pass || finding.status == .expectedSelf || finding.status == .notApplicable {
            baseline.exemptions.removeValue(forKey: finding.id)
            baseline.todos.removeValue(forKey: finding.id)
        }
        // Decision 7: remember the last time the online update catalog was actually
        // reachable (HA-B06 determinable). Offline runs then report `unknown` with
        // this timestamp rather than ever rendering an unreachable catalog as pass.
        if let hint = acceptedAtHint,
           let pending = report.findings.first(where: { $0.id == "HA-B06" }),
           pending.status != .unknown {
            baseline.lastVersionCheckHint = hint
        }
        return baseline
    }

    /// Merge a batch of user triage decisions into the accepted baseline. An
    /// exemption supersedes a TODO for the same id and vice versa; `cleared` removes
    /// both. Re-recording a TODO preserves its reminder cadence.
    public static func recordTriage(_ request: HostTriageRequest, recordedAtHint: String? = nil) {
        let store = FileBaselineStore()
        store.save(applyingTriage(request, to: store.load(), recordedAtHint: recordedAtHint))
    }

    /// Pure triage merge — testable without touching the on-disk store.
    public static func applyingTriage(
        _ request: HostTriageRequest, to baseline: HostAuditBaseline, recordedAtHint: String? = nil
    ) -> HostAuditBaseline {
        var baseline = baseline
        for decision in request.exemptions {
            baseline.exemptions[decision.id] = TriageRecord(
                note: decision.note, recordedAtHint: recordedAtHint)
            baseline.todos.removeValue(forKey: decision.id)
        }
        for id in request.todos {
            let existing = baseline.todos[id]
            baseline.todos[id] = TriageRecord(
                note: nil,
                recordedAtHint: existing?.recordedAtHint ?? recordedAtHint,
                lastRemindedAtHint: existing?.lastRemindedAtHint)
            baseline.exemptions.removeValue(forKey: id)
        }
        for id in request.cleared {
            baseline.exemptions.removeValue(forKey: id)
            baseline.todos.removeValue(forKey: id)
        }
        return baseline
    }

    /// Run a value-free re-audit and return the findings that **regressed**: a
    /// control that was `pass` in the accepted baseline and is now `fail` (skipping
    /// anything the user has exempted). The high-signal event — it can mean malware
    /// disabling a defense. Notify-only.
    public static func regressions() async -> [HostFinding] {
        let baseline = FileBaselineStore().load()
        let report = await runReport(scanFilesystem: false)
        return baselineRegressions(report: report, baseline: baseline)
    }

    /// One background tick's worth of work derived from a single re-audit:
    /// regressions plus the TODOs whose weekly reminder is now due.
    public static func periodicScan(now: Date) async -> PeriodicHostFindings {
        let baseline = FileBaselineStore().load()
        let report = await runReport(scanFilesystem: false)
        return PeriodicHostFindings(
            regressions: baselineRegressions(report: report, baseline: baseline),
            dueTodoReminders: dueTodoReminders(report: report, baseline: baseline, now: now))
    }

    /// Pure regression diff — testable without a live audit.
    public static func baselineRegressions(
        report: HostAuditReport, baseline: HostAuditBaseline
    ) -> [HostFinding] {
        report.findings.filter { finding in
            baseline.entries[finding.id]?.status == FindingStatus.pass.rawValue
                && finding.status == .fail
                && baseline.exemptions[finding.id] == nil
        }
    }

    /// TODO ids due for a weekly reminder: the finding still fails and the last
    /// reminder is absent or older than `interval`. Pure over its inputs.
    public static func dueTodoReminders(
        report: HostAuditReport,
        baseline: HostAuditBaseline,
        now: Date,
        interval: TimeInterval = 7 * 24 * 60 * 60
    ) -> [String] {
        let failing = Set(report.findings.filter { $0.status == .fail }.map(\.id))
        return baseline.todos.compactMap { id, record -> String? in
            guard failing.contains(id) else { return nil }
            guard let hint = record.lastRemindedAtHint,
                  let last = ISO8601DateFormatter().date(from: hint) else { return id }
            return now.timeIntervalSince(last) >= interval ? id : nil
        }.sorted()
    }

    /// Record that a weekly TODO reminder was just posted for these ids.
    public static func stampTodoReminders(_ ids: [String], atHint: String) {
        guard !ids.isEmpty else { return }
        let store = FileBaselineStore()
        store.save(stamping(ids, in: store.load(), atHint: atHint))
    }

    /// Pure reminder-stamp — testable without touching the on-disk store.
    public static func stamping(
        _ ids: [String], in baseline: HostAuditBaseline, atHint: String
    ) -> HostAuditBaseline {
        var baseline = baseline
        for id in ids where baseline.todos[id] != nil {
            baseline.todos[id]?.lastRemindedAtHint = atHint
        }
        return baseline
    }
}
