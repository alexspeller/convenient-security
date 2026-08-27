import ConvenientSecurity
import Foundation
import UserNotifications

// Periodic re-audit + regression detection (Decision 6). csecd runs a value-free
// re-audit on a daily dispatch timer, diffs it against the accepted baseline, and
// on a `pass → fail` regression posts a notification naming the finding. It is
// **notify-only**: nothing is mutated in the background; the user re-runs
// `csec audit` to review and re-apply. The baseline advances only through that
// interactive path, so unreviewed drift keeps surfacing.
enum PeriodicHostAudit {
    // Retained for csecd's lifetime (the timer is otherwise released on scope exit).
    nonisolated(unsafe) private static var timer: DispatchSourceTimer?

    private static var intervalSeconds: Int {
        if let raw = ProcessInfo.processInfo.environment["CSEC_AUDIT_INTERVAL_SECONDS"],
           let value = Int(raw), value >= 60 {
            return value
        }
        return 24 * 60 * 60
    }

    /// Whether notifications can be posted. `UNUserNotificationCenter.current()`
    /// requires a bundle identifier; a `swift run` dev binary has none and would
    /// crash, so we degrade to a stderr log there.
    private static var notificationsAvailable: Bool { Bundle.main.bundleIdentifier != nil }

    static func start() {
        if notificationsAvailable {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        }
        let interval = intervalSeconds
        let source = DispatchSource.makeTimerSource(queue: .global(qos: .background))
        // Warm up before the first run so an interactive baseline can exist; then
        // repeat at the configured cadence.
        source.schedule(deadline: .now() + .seconds(min(interval, 300)), repeating: .seconds(interval))
        source.setEventHandler {
            Task {
                let now = Date()
                let findings = await HostAuditService.periodicScan(now: now)
                if !findings.regressions.isEmpty {
                    await report(findings.regressions)
                }
                if !findings.dueTodoReminders.isEmpty {
                    await remindTodos(
                        findings.dueTodoReminders,
                        atHint: ISO8601DateFormatter().string(from: now))
                }
            }
        }
        source.resume()
        timer = source
    }

    private static func report(_ regressions: [HostFinding]) async {
        guard notificationsAvailable else {
            let ids = regressions.map(\.id).joined(separator: ", ")
            FileHandle.standardError.write(Data(
                "csecd: host posture regression(s) detected: \(ids) — run `csec audit`\n".utf8))
            return
        }
        await MainActor.run {
            let center = UNUserNotificationCenter.current()
            for finding in regressions {
                let content = UNMutableNotificationContent()
                content.title = "Security posture regression"
                content.body = "\(finding.id): \(ReviewDisplay.sanitized(finding.title)) — run `csec audit` to review and re-apply."
                center.add(UNNotificationRequest(
                    identifier: "csec-regression-\(finding.id)", content: content, trigger: nil))
            }
        }
    }

    /// Weekly reminder for still-open TODOs the user deferred. One rolling
    /// notification (rate-limited per finding via `stampTodoReminders`), so the
    /// user is nudged without being nagged daily.
    private static func remindTodos(_ ids: [String], atHint: String) async {
        // Value-free ids only; cap the inline list so the body stays short.
        let shown = ids.prefix(4).joined(separator: ", ")
        let suffix = ids.count > 4 ? ", …" : ""
        guard notificationsAvailable else {
            FileHandle.standardError.write(Data(
                "csecd: \(ids.count) security TODO(s) still open: \(shown)\(suffix) — run `csec audit`\n".utf8))
            HostAuditService.stampTodoReminders(ids, atHint: atHint)
            return
        }
        await MainActor.run {
            let center = UNUserNotificationCenter.current()
            let content = UNMutableNotificationContent()
            content.title = "Security TODOs still open"
            content.body = ids.count == 1
                ? "\(shown) is still deferred — run `csec audit` to fix or re-triage."
                : "\(ids.count) deferred fixes (\(shown)\(suffix)) — run `csec audit` to fix or re-triage."
            center.add(UNNotificationRequest(
                identifier: "csec-todo-reminder", content: content, trigger: nil))
        }
        HostAuditService.stampTodoReminders(ids, atHint: atHint)
    }
}
