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
                let regressions = await HostAuditService.regressions()
                guard !regressions.isEmpty else { return }
                await report(regressions)
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
}
