import Foundation

/// Bounds the `absent_reference` records one service (secret access, SSH,
/// automation) writes in a csecd run; each keeps its own. A refusal before
/// any panel arrives at socket speed, where every other decisions-stream
/// record arrives at the speed of a human answering a panel, so without a
/// bound a loop of requests for references that cannot resolve could fill
/// the decisions stream and prune the panel records it exists to keep.
///
/// Each distinct refusal (its surface, requester class and reference set) is
/// recorded once per run, and at most `maximumPerRun` are recorded in all; the
/// last one says so. The bound is a count, not a clock: a repeat says nothing
/// the first record did not.
public struct AbsentReferenceRecords: Sendable {
    public static let maximumPerRun = 64

    private var recorded: Set<String> = []

    public init() {}

    /// The record to write for this refusal, or nil when an identical one was
    /// already recorded this run or the run's allowance is spent.
    public mutating func admit(_ record: DecisionLogRecord) -> DecisionLogRecord? {
        guard recorded.count < Self.maximumPerRun else { return nil }
        let identity = [
            record.surface?.rawValue ?? "",
            record.requester?.class ?? "",
            (record.refs ?? []).sorted().joined(separator: "\n"),
        ].joined(separator: "\u{0}")
        guard recorded.insert(identity).inserted else { return nil }
        guard recorded.count == Self.maximumPerRun else { return record }
        var last = record
        last.detail = "the last refusal like this csecd records until it restarts: " + (record.detail ?? "")
        return last
    }
}
