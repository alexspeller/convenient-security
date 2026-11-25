import Foundation

// Tracks in-flight host audits so `csec audit` can stream live progress instead
// of blocking on one silent request/response. csecd runs the engine here on a
// detached task keyed by the start request's id; the launcher polls for a
// value-free snapshot and, on the terminal poll, the finished report.
//
// Why a poll board rather than server-push: the socket server is strictly one
// framed response per framed request and re-validates the peer's live code
// identity before every response. A client-driven poll rides that model exactly
// — no change to the security-sensitive handler/transport, and every poll goes
// through the same per-frame peer re-validation. The board is the only shared
// state, and it is an actor, so concurrent start/poll/update calls serialize.
public actor HostAuditProgressBoard {
    /// Runs an audit and returns its report, invoking `onProgress` with
    /// `(completed, total, currentID, currentTitle)` before each check. Injectable
    /// so tests can drive the board with a fast, deterministic fake run.
    public typealias RunAudit = @Sendable (
        _ scanFilesystem: Bool,
        _ onProgress: @escaping @Sendable (Int, Int, String, String) async -> Void
    ) async -> HostAuditReport

    private struct Entry {
        var snapshot: HostAuditProgressSnapshot
        var report: HostAuditReport?
    }

    private let runAudit: RunAudit
    private var entries: [String: Entry] = [:]

    public init(runAudit: @escaping RunAudit = HostAuditProgressBoard.productionRun) {
        self.runAudit = runAudit
    }

    /// The shipping run: the interactive audit path (records the accepted baseline)
    /// with a fresh generated-at hint, streaming per-check progress.
    public static let productionRun: RunAudit = { scanFilesystem, onProgress in
        await HostAuditService.runInteractive(
            scanFilesystem: scanFilesystem,
            generatedAtHint: ISO8601DateFormatter().string(from: Date()),
            includeRemediation: true,
            onProgress: onProgress
        )
    }

    /// Begin an audit job. Returns immediately with the initial snapshot; the
    /// engine runs on a detached task so the actor stays free to answer polls.
    public func start(_ request: HostAuditRequest) -> Response {
        // Drop any completed-but-undelivered jobs from earlier runs so the board
        // never grows unbounded when a launcher exits without a final poll.
        entries = entries.filter { !$0.value.snapshot.done }

        let jobID = request.requestID
        let total = HostCheckRegistry.all.count
        let initial = HostAuditProgressSnapshot.starting(total: total)
        entries[jobID] = Entry(snapshot: initial, report: nil)

        let run = runAudit
        let scanFilesystem = request.scanFilesystem
        Task.detached { [self] in
            let report = await run(scanFilesystem) { completed, total, id, title in
                await self.update(jobID, completed: completed, total: total, id: id, title: title)
            }
            await self.finish(jobID, report: report)
        }
        return Response(requestID: jobID, hostAuditProgress: initial)
    }

    /// Return the current snapshot for a job. The terminal poll (job finished)
    /// also carries the report and retires the job — deliver-once cleanup.
    public func poll(_ request: HostAuditPollRequest) -> Response {
        guard let entry = entries[request.jobID] else {
            return .failed(.invalidRequest, message: "unknown or expired audit job", requestID: request.requestID)
        }
        if entry.snapshot.done, let report = entry.report {
            entries.removeValue(forKey: request.jobID)
            return Response(
                requestID: request.requestID,
                hostAuditReport: report,
                hostAuditProgress: entry.snapshot
            )
        }
        return Response(requestID: request.requestID, hostAuditProgress: entry.snapshot)
    }

    private func update(_ jobID: String, completed: Int, total: Int, id: String, title: String) {
        guard entries[jobID] != nil else { return }
        entries[jobID]?.snapshot = HostAuditProgressSnapshot(
            total: total, completed: completed, currentID: id, currentTitle: title, done: false)
    }

    private func finish(_ jobID: String, report: HostAuditReport) {
        guard let existing = entries[jobID] else { return }
        entries[jobID] = Entry(
            snapshot: HostAuditProgressSnapshot(
                total: existing.snapshot.total, completed: existing.snapshot.total,
                currentID: "", currentTitle: "", done: true),
            report: report
        )
    }
}
