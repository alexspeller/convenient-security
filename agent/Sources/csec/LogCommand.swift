import ConvenientSecurity
import Foundation

/// `csec log` — page through csecd's decision log, or verify it. Reading needs
/// no Touch ID: the records are value-free, and csecd serves them only to the
/// verified launcher, like `csec grants`.
///
/// Without `--kind` it lists the `decisions` stream (panels, refusals,
/// revocations, settings, restarts, integrity findings); grant reuses live in
/// the `usage` stream and are listed with `--kind reuse`.
func runLog(_ arguments: [String]) -> Never {
    var since: Date?
    var kinds: [DecisionLogRecord.Kind] = []
    var json = false
    var verify = false
    var index = 0
    while index < arguments.count {
        let argument = arguments[index]
        switch argument {
        case "--json":
            json = true
        case "--verify":
            verify = true
        case "--since":
            index += 1
            guard index < arguments.count,
                  let parsed = DecisionLogTime.parseSince(arguments[index]) else { usage("log") }
            since = parsed
        case "--kind":
            index += 1
            guard index < arguments.count else { usage("log") }
            for name in arguments[index].split(separator: ",") {
                guard let kind = DecisionLogRecord.Kind(rawValue: String(name)) else {
                    csecError("log", "unknown record kind \(ReviewDisplay.sanitized(String(name)))")
                    exit(2)
                }
                if !kinds.contains(kind) { kinds.append(kind) }
            }
        default:
            usage("log")
        }
        index += 1
    }
    guard !verify || (since == nil && kinds.isEmpty) else { usage("log") }

    let client = makeAgentClient()
    if verify {
        do {
            let result = try client.verifyDecisionLog()
            printVerification(result, json: json)
            exit(result.status == .clean || result.status == .repaired || result.status == .firstRun ? 0 : 1)
        } catch {
            csecError("log", "\(error.localizedDescription)")
            exit(1)
        }
    }

    let streams = kinds.isEmpty
        ? [DecisionLogStream.decisions]
        : Array(Set(kinds.flatMap(\.streams))).sorted()
    var query = DecisionLogQuery(
        streams: streams,
        kinds: kinds.isEmpty ? nil : kinds,
        since: since.map(DecisionLogTime.init)
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    var printed = 0
    var incomplete = false
    do {
        while true {
            let page = try client.decisionLogPage(query)
            incomplete = incomplete || page.incomplete
            for record in page.records {
                if json {
                    guard let data = try? encoder.encode(record) else { continue }
                    FileHandle.standardOutput.write(data + Data("\n".utf8))
                } else {
                    if printed == 0 { print(DecisionLogRecord.displayHeader()) }
                    print(record.displayLine())
                }
                printed += 1
            }
            // A page can be empty yet not the last: csecd bounds how much of
            // the log one page may scan. Stop only when the cursor stops.
            guard let next = page.next, next != query.after else { break }
            query.after = next
        }
    } catch {
        csecError("log", "\(error.localizedDescription)")
        exit(1)
    }
    if printed == 0, !json {
        print("csec: no matching log records")
    }
    if incomplete {
        csecError("log", "a record did not authenticate while reading; run `csec log --verify`")
        exit(1)
    }
    exit(0)
}

private func printVerification(_ result: DecisionLogVerification, json: Bool) {
    if json {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        if let data = try? encoder.encode(result) {
            FileHandle.standardOutput.write(data + Data("\n".utf8))
        }
        return
    }
    let heads = "decisions through #\(result.decisionsHeadSeq ?? 0), usage through #\(result.usageHeadSeq ?? 0)"
    switch result.status {
    case .clean:
        print("csec: decision log verified: \(heads)")
    case .firstRun:
        print("csec: decision log is new and empty")
    case .repaired:
        let streams = result.tornTails.map(\.rawValue).joined(separator: ", ")
        print("csec: decision log verified (\(heads)); cut a partly written final frame from \(streams)")
    case .discrepancy:
        print(result.recorded
            ? "csec: DECISION LOG ALTERED: recorded as log_integrity and resumed from the checkpoint"
            : "csec: DECISION LOG ALTERED: the finding could not be recorded; the log is held at its checkpoint"
                + (result.detail.map { " (\(ReviewDisplay.sanitized($0)))" } ?? ""))
        for finding in result.findings {
            let more = finding.quarantinedCount > finding.quarantined.count
                ? " and \(finding.quarantinedCount - finding.quarantined.count) more" : ""
            let setAside = finding.quarantined.isEmpty
                ? "" : "; set aside \(finding.quarantined.joined(separator: ", "))\(more)"
            print("  \(finding.stream.rawValue): \(finding.finding.rawValue)\(setAside)")
        }
    case .unavailable:
        print("csec: decision log could not be verified"
            + (result.detail.map { ": \(ReviewDisplay.sanitized($0))" } ?? ""))
    }
}
