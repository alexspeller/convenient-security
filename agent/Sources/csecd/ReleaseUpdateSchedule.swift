import ConvenientSecurity
import Foundation
import UserNotifications

// The update notice (csec-0.39.11): a few minutes after csecd starts, then
// once a day, fetch the signed release manifest (ReleaseUpdateChecker) and,
// the first time it announces a release newer than this build, post one
// notification. Notify-only: csec never downloads or installs a package.
//
// The same manifest carries the audited Claude Code list (csec-0.39.14), so
// a request that declines on an unchecked Claude Code image asks for a check
// sooner (`checkSoon`), at most once per `earlyInterval`: an image audited
// since the last check then delegates again within the hour, not the day.
enum ReleaseUpdateSchedule {
    // Retained for csecd's lifetime (the timer is otherwise released on scope exit).
    nonisolated(unsafe) private static var timer: DispatchSourceTimer?
    private static let runner = Runner()

    private static let interval = 24 * 60 * 60
    private static let firstCheckDelay = 5 * 60
    static let earlyInterval: TimeInterval = 30 * 60

    static func start() {
        let source = DispatchSource.makeTimerSource(queue: .global(qos: .background))
        source.schedule(deadline: .now() + .seconds(firstCheckDelay), repeating: .seconds(interval))
        source.setEventHandler {
            Task { await runner.run(early: false) }
        }
        source.resume()
        timer = source
    }

    /// An unchecked Claude Code image was seen: check now unless any check
    /// ran in the last `earlyInterval`, one is running, or checking is off.
    static func checkSoon() {
        Task { await runner.run(early: true) }
    }

    /// One check at a time, so the daily and early checks never write the
    /// Updates folder together.
    private actor Runner {
        private let checker = ReleaseUpdateChecker()
        private var running = false
        private var off = false

        func run(early: Bool) async {
            guard !running, !off else { return }
            if early, let last = checker.store.loadState().lastAttempt,
               Date().timeIntervalSince(last) < ReleaseUpdateSchedule.earlyInterval { return }
            running = true
            defer { running = false }
            if early { log("update check: early, for an unchecked Claude Code image") }
            switch await checker.check() {
            case let .off(reason):
                // Nothing to check in this build; stop asking every day.
                log("update check off: \(reason)")
                off = true
                timer?.cancel()
            case let .failed(summary):
                log("update check failed: \(summary)")
            case .checked:
                break
            case let .announce(release, running):
                log("csec \(release.build) is available (this is \(running))")
                await announce(release, running: running)
            }
        }
    }

    private static func log(_ message: String) {
        FileHandle.standardError.write(Data("csecd: \(message)\n".utf8))
    }

    /// A development binary without a bundle cannot post a notification and
    /// has logged the release above instead.
    private static func announce(_ release: ReleaseManifest.Release, running: ReleaseBuild) async {
        guard Bundle.main.bundleIdentifier != nil else { return }
        let words = ReleaseUpdateNotice.words(release: release, running: running)
        await MainActor.run {
            let content = UNMutableNotificationContent()
            content.title = words.title
            content.body = words.body
            UNUserNotificationCenter.current().add(UNNotificationRequest(
                identifier: ReleaseUpdateNotice.identifier, content: content, trigger: nil))
        }
    }
}
