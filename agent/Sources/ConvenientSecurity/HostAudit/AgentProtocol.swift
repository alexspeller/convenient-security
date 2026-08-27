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
        onProgress: (@Sendable (Int, Int, String, String) async -> Void)? = nil
    ) async -> HostAuditReport {
        let ctx = productionContext(scanFilesystem: scanFilesystem)
        return await HostAuditEngine().run(ctx, generatedAtHint: generatedAtHint, onProgress: onProgress)
    }

    /// The interactive path (user-initiated `csec audit`). Produces the report and
    /// records the current state as the accepted baseline — the user has now seen
    /// it, so a later background run only flags a *change* from this point. An
    /// optional `onProgress` callback streams value-free per-check progress so the
    /// launcher can animate the scan.
    public static func runInteractive(
        scanFilesystem: Bool,
        generatedAtHint: String? = nil,
        onProgress: (@Sendable (Int, Int, String, String) async -> Void)? = nil
    ) async -> HostAuditReport {
        let report = await runReport(
            scanFilesystem: scanFilesystem, generatedAtHint: generatedAtHint, onProgress: onProgress)
        recordBaseline(report, acceptedAtHint: generatedAtHint)
        return report
    }

    /// Persist the current statuses as the accepted baseline (Decision 6). Only the
    /// interactive path calls this; the background timer never advances the baseline.
    public static func recordBaseline(_ report: HostAuditReport, acceptedAtHint: String? = nil) {
        let store = FileBaselineStore()
        var baseline = store.load()
        for finding in report.findings {
            baseline.entries[finding.id] = BaselineEntry(
                status: finding.status.rawValue, acceptedAtHint: acceptedAtHint)
        }
        // Decision 7: remember the last time the online update catalog was actually
        // reachable (HA-B06 determinable). Offline runs then report `unknown` with
        // this timestamp rather than ever rendering an unreachable catalog as pass.
        if let hint = acceptedAtHint,
           let pending = report.findings.first(where: { $0.id == "HA-B06" }),
           pending.status != .unknown {
            baseline.lastVersionCheckHint = hint
        }
        store.save(baseline)
    }

    /// Run a value-free re-audit and return the findings that **regressed**: a
    /// control that was `pass` in the accepted baseline and is now `fail`. This is
    /// the high-signal event (it can mean malware disabling a defense). Notify-only.
    public static func regressions() async -> [HostFinding] {
        let baseline = FileBaselineStore().load()
        let report = await runReport(scanFilesystem: false)
        return report.findings.filter { finding in
            baseline.entries[finding.id]?.status == FindingStatus.pass.rawValue
                && finding.status == .fail
        }
    }
}
