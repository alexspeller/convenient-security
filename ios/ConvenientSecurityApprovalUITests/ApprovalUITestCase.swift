import notify
import XCTest

/// The Simulator's Face ID, driven the way Features › Face ID drives it: by
/// Darwin notifications, which reach the Simulator's notification center
/// because this runner is itself a process inside the Simulator. No host-side
/// helper is involved.
enum SimulatedFaceID {
    /// Features › Face ID › Enrolled. Idempotent.
    static func enroll() {
        var token: Int32 = 0
        notify_register_check("com.apple.BiometricKit.enrollmentChanged", &token)
        notify_set_state(token, 1)
        notify_post("com.apple.BiometricKit.enrollmentChanged")
        notify_cancel(token)
    }

    /// Features › Face ID › Matching Face or Non-matching Face. The simulated
    /// sensor acts on it only while a Face ID sheet is waiting for a face.
    static func present(matching: Bool) {
        notify_post(
            matching
                ? "com.apple.BiometricKit_Sim.pearl.match"
                : "com.apple.BiometricKit_Sim.pearl.nomatch"
        )
    }
}

/// What the Simulator test mode's navigation bar reports the app did since
/// launch: Face ID sheets raised, how many a matching face passed, and key
/// agreements made to answer an unlock challenge.
struct SimulatorCounters: Equatable, CustomStringConvertible {
    var faceIDPrompts: Int
    var faceIDMatches: Int
    var keyAgreements: Int

    var description: String {
        "Face ID \(faceIDMatches)/\(faceIDPrompts), key agreements \(keyAgreements)"
    }

    /// What one more action added: `prompts` sheets, `matches` of them passed.
    func adding(prompts: Int, matches: Int, keyAgreements added: Int) -> SimulatorCounters {
        SimulatorCounters(
            faceIDPrompts: faceIDPrompts + prompts,
            faceIDMatches: faceIDMatches + matches,
            keyAgreements: keyAgreements + added
        )
    }
}

/// Launches the app in its Simulator test mode, sets it up, injects signed
/// sample requests, and answers Face ID. Every wait is bounded and a test
/// stops at its first failure, so a broken build fails within one wait's
/// bound rather than walking into one timeout after another.
class ApprovalUITestCase: XCTestCase {
    static let macName = "Simulated Mac"
    static let largestTextSize = "UICTContentSizeCategoryAccessibilityXXXL"
    /// How long a test waits for the app's asynchronous work to show: a
    /// launch, a refresh, a mailbox call, a menu's action. A wait returns as
    /// soon as what it waits for shows, so a passing run pays nothing for
    /// this bound. It is long because a Mac running other sessions' builds
    /// and tests (load averages above 200 on 10 CPUs) starves the Simulator
    /// for seconds at a time. What must not happen is still watched for over
    /// a short window: load can make such a check pass, never fail it.
    static let appWork: TimeInterval = 30

    let app = XCUIApplication()
    let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")

    override func setUpWithError() throws {
        try super.setUpWithError()
        continueAfterFailure = false
        SimulatedFaceID.enroll()
    }

    override func tearDown() {
        app.terminate()
        super.tearDown()
    }

    // MARK: - Launching and setting up

    enum StartingState {
        /// No approval records.
        case notSetUp
        /// A format-1 identity from a protocol v2 build.
        case legacyIdentity
        /// An identity record that does not decode.
        case undecodableIdentity
        /// An identity whose keys do not match what was stored.
        case mismatchedIdentity
        /// Whatever the last launch left.
        case asLeft
    }

    /// The simulated mailbox's iCloud account at launch.
    enum SimulatedICloud: String {
        case signedOut = "--csec-simulator-icloud-signed-out"
        case restricted = "--csec-simulator-icloud-restricted"
        case notReady = "--csec-simulator-icloud-not-ready"
        case unreachable = "--csec-simulator-icloud-unreachable"
    }

    /// `mailbox` puts the simulated mailbox in place of iCloud; `iCloud` sets
    /// its account. `refuseKeychainReads` makes the Keychain refuse reads as a
    /// locked iPhone does. `openAlertForHiddenRequest` opens the app as a tap
    /// on the alert for the mailbox's latest request its query leaves out.
    func launch(
        _ state: StartingState,
        textSize: String? = nil,
        refuseSubscription: Bool = false,
        refuseSettledSubscription: Bool = false,
        mailbox: Bool = false,
        iCloud: SimulatedICloud? = nil,
        refuseKeychainReads: Bool = false,
        openAlertForHiddenRequest: Bool = false
    ) {
        var arguments: [String] = []
        if refuseSubscription { arguments.append("--csec-simulator-refuse-subscription") }
        if refuseSettledSubscription { arguments.append("--csec-simulator-refuse-settled-subscription") }
        if mailbox { arguments.append("--csec-simulator-mailbox") }
        if let iCloud { arguments.append(iCloud.rawValue) }
        if refuseKeychainReads { arguments.append("--csec-simulator-refuse-keychain-reads") }
        if openAlertForHiddenRequest { arguments.append("--csec-simulator-open-alert-for-hidden-request") }
        switch state {
        case .notSetUp: arguments.append("--csec-simulator-erase-identity")
        case .legacyIdentity: arguments.append("--csec-simulator-seed-legacy-identity")
        case .undecodableIdentity: arguments.append("--csec-simulator-seed-undecodable-identity")
        case .mismatchedIdentity: arguments.append("--csec-simulator-seed-mismatched-identity")
        case .asLeft: break
        }
        if let textSize {
            arguments += ["-UIPreferredContentSizeCategoryName", textSize]
        }
        app.launchArguments = arguments
        app.launch()
        // Opened from an alert, the list may already be scrolled past the
        // banner; the counters strip is always on screen.
        let testMode = openAlertForHiddenRequest
            ? app.staticTexts["simulator-counters"]
            : text("SIMULATOR TEST MODE")
        XCTAssertTrue(testMode.waitForExistence(timeout: Self.appWork), "the Simulator test mode is on")
    }

    /// Launch with the identity an earlier test left, setting up first only
    /// if there is none. Only `SetupUITests` pays for setup in every test.
    func launchSetUp(textSize: String? = nil) {
        launch(.asLeft, textSize: textSize)
        // The refresh button is in the navigation bar, so it is found at any
        // text size; the setup button may be below a banner the largest text
        // size makes taller than the screen.
        let ready = button("Refresh approvals")
        let setupButton = button(beginningWith: "Set up this iPhone")
        if !waitUntil(timeout: Self.appWork, { ready.exists || setupButton.exists }) {
            reveal(setupButton, maxDrags: 3)
        }
        if ready.exists { return }
        XCTAssertTrue(setupButton.exists, "the app is either set up or offers setup")
        setUpPhone(button: setupButton.label)
    }

    /// Tap the setup button, give it one matching face, and answer the
    /// notification prompt that follows. Asserts it cost exactly one Face ID.
    func setUpPhone(button title: String = "Set up this iPhone", file: StaticString = #filePath, line: UInt = #line) {
        let setup = button(title)
        XCTAssertTrue(
            setup.waitForExistence(timeout: Self.appWork) || reveal(setup, maxDrags: 3),
            "\(title) button", file: file, line: line
        )
        XCTAssertFalse(springboard.alerts.firstMatch.exists, "no system alert before setup", file: file, line: line)
        let before = counters()
        let mustAsk = notificationsUndecided(file: file, line: line)
        setup.tap()
        matchFace(untilActive: false, file: file, line: line)
        answerNotificationPrompt(mustAsk: mustAsk, file: file, line: line)
        XCTAssertTrue(
            waitForOutcome("This iPhone is set up. Under Pair a Mac, copy the command and run it on your Mac."),
            "setup outcome", file: file, line: line
        )
        XCTAssertEqual(
            counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 0),
            "setting up creates and binds both keys with one Face ID", file: file, line: line
        )
        waitUntilActive(file: file, line: line)
    }

    /// After setup the app asks for notification permission. The system asks
    /// only while the answer is undecided, which is exactly when the app shows
    /// its "Allow notifications" button. `mustAsk` is whether it was undecided
    /// before setup, so the prompt has to come: on a Simulator where the app
    /// was never installed, as bin/ci's is, that is the first setup.
    private func answerNotificationPrompt(mustAsk: Bool, file: StaticString, line: UInt) {
        let alert = springboard.alerts.firstMatch
        let undecided = button("Allow notifications")
        // Setup's outcome is published before the permission request starts.
        _ = waitUntil(timeout: Self.appWork) {
            alert.exists || undecided.exists || self.text("No pending approvals").exists
        }
        if mustAsk || alert.exists || undecided.exists {
            XCTAssertTrue(
                alert.waitForExistence(timeout: Self.appWork),
                "setup asks for notification permission", file: file, line: line
            )
            // Under the prompt, the app says what an alert shows: the
            // verified request's words, since the notification extension.
            XCTAssertTrue(
                undecided.exists, "the app explains notifications while they are undecided", file: file, line: line
            )
            XCTAssertTrue(
                text(containing: "Once the request's Mac signature verifies, the alert shows what it asks for").exists,
                "the explanation says the alert shows the verified request", file: file, line: line
            )
            XCTAssertFalse(
                text(containing: "says only that an approval is waiting").exists,
                "no copy from before the alert showed the request", file: file, line: line
            )
            let allow = alert.buttons["Allow"]
            XCTAssertTrue(allow.exists, "the permission prompt offers Allow", file: file, line: line)
            allow.tap()
        }
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { !alert.exists && !undecided.exists },
            "notifications are decided once the prompt is answered", file: file, line: line
        )
    }

    // MARK: - Face ID

    /// Present a matching face until the sheet has passed one. The simulated
    /// sensor ignores a face while no sheet is up, so the face is presented
    /// again every second, for at most `timeout`. Returns once the sheet has
    /// gone and the app is active again, unless `untilActive` is false: setup
    /// raises the notification prompt straight after its sheet.
    func matchFace(
        timeout: TimeInterval = 20,
        untilActive: Bool = true,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let matched = counters().faceIDMatches
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            SimulatedFaceID.present(matching: true)
            if waitUntil(timeout: 1, { self.counters().faceIDMatches > matched }) {
                if untilActive { waitUntilActive(file: file, line: line) }
                return
            }
        }
        XCTFail("Face ID did not pass a matching face within \(Int(timeout)) s", file: file, line: line)
    }

    /// Wait until the app is active, as the counters strip reads it. A Face
    /// ID sheet leaves the app inactive until the sheet has gone, which on a
    /// loaded Mac can be well after the face has passed, and the app looks
    /// for a Mac's offer, or for cards the Mac withdrew, only while it is
    /// active.
    func waitUntilActive(file: StaticString = #filePath, line: UInt = #line) {
        var scene = "unread"
        let active = {
            scene = self.stripValue()?.scene ?? "unread"
            return scene == "active"
        }
        if waitUntil(timeout: Self.appWork, active) { return }
        // What holds it inactive is drawn by SpringBoard, over the app.
        print("UITEST: the app stayed \(scene)\n\(springboard.debugDescription)\n\(app.debugDescription)")
        app.activate()
        let recovered = waitUntil(timeout: Self.appWork, active)
        print("UITEST: after activating the app again, scene \(scene)")
        XCTAssertTrue(recovered, "the app is active again: scene \(scene)", file: file, line: line)
    }

    /// Present a non-matching face until the sheet says it did not recognise
    /// one, then tap the sheet's Cancel. The sheet stops listening after the
    /// first refusal, so exactly one face is refused, far short of a lockout.
    func refuseFaceThenCancel(file: StaticString = #filePath, line: UInt = #line) {
        let retry = faceIDSheetButton("try-again")
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline, !retry.exists {
            SimulatedFaceID.present(matching: false)
            _ = retry.waitForExistence(timeout: 1)
        }
        XCTAssertTrue(retry.exists, "the Face ID sheet reports an unrecognised face", file: file, line: line)
        XCTAssertEqual(retry.label, "Try Face ID Again", file: file, line: line)
        let cancel = faceIDSheetButton("cancel")
        XCTAssertTrue(cancel.exists, "the Face ID sheet offers Cancel", file: file, line: line)
        cancel.tap()
    }

    /// The Face ID sheet's buttons, which SpringBoard draws over the app.
    private func faceIDSheetButton(_ name: String) -> XCUIElement {
        springboard.buttons.matching(
            identifier: "com.apple.localauthentication.ax.authentication.button.\(name)"
        ).firstMatch
    }

    // MARK: - Simulator test mode

    /// The counters strip's accessibility value: `notifications <state>;
    /// scene <phase>`.
    private func stripValue() -> (notifications: String, scene: String)? {
        let element = app.staticTexts["simulator-counters"]
        guard element.exists, let value = element.value as? String else { return nil }
        let parts = value.components(separatedBy: "; ")
        guard parts.count == 2, parts[1].hasPrefix("scene ") else { return nil }
        return (parts[0], String(parts[1].dropFirst("scene ".count)))
    }

    /// Whether notification permission is still undecided, as the app read it
    /// from the system and the counters strip's accessibility value says. It
    /// says "unread" until the app has read it, so this waits for that.
    func notificationsUndecided(file: StaticString = #filePath, line: UInt = #line) -> Bool {
        var value = ""
        let read = waitUntil(timeout: Self.appWork) {
            guard let strip = self.stripValue() else { return false }
            value = strip.notifications
            return value != "notifications unread"
        }
        XCTAssertTrue(read, "the app reads the notification permission: \(value)", file: file, line: line)
        XCTAssertTrue(
            ["notifications undecided", "notifications on", "notifications off"].contains(value),
            "notification permission parses: \(value)", file: file, line: line
        )
        return value == "notifications undecided"
    }

    func counters(file: StaticString = #filePath, line: UInt = #line) -> SimulatorCounters {
        let element = app.staticTexts["simulator-counters"]
        // `exists` first: `waitForExistence` costs a second even when the
        // element is already there, and this is read in a polling loop.
        XCTAssertTrue(
            element.exists || element.waitForExistence(timeout: Self.appWork),
            "simulator counters", file: file, line: line
        )
        let label = element.label
        func number(after name: String) -> Int {
            guard let range = label.range(of: name + " ") else { return -1 }
            return Int(label[range.upperBound...].prefix(while: \.isNumber)) ?? -1
        }
        let counters = SimulatorCounters(
            faceIDPrompts: number(after: "Face ID prompts"),
            faceIDMatches: number(after: "matched"),
            keyAgreements: number(after: "key agreements")
        )
        XCTAssertTrue(
            counters.faceIDPrompts >= 0 && counters.faceIDMatches >= 0 && counters.keyAgreements >= 0,
            "counters parse: \(label)", file: file, line: line
        )
        return counters
    }

    /// Inject one signed sample request from the Simulator menu, in the
    /// list's last section.
    func inject(_ menuTitle: String, file: StaticString = #filePath, line: UInt = #line) {
        choose(menuTitle, fromSimulatorMenu: "Inject signed sample request", file: file, line: line)
        // The card is inserted at the top while the list stays at the bottom.
        scrollToTop()
        XCTAssertTrue(waitForOutcome("Injected a signed"), "injected", file: file, line: line)
    }

    /// Tap a control in the Simulator section, the list's last.
    func tapSimulatorControl(_ label: String, file: StaticString = #filePath, line: UInt = #line) {
        let control = button(label)
        for _ in 0..<6 where !isHittableNow(control) {
            window.swipeUp(velocity: .fast)
        }
        XCTAssertTrue(control.exists, "the Simulator control \(label)", file: file, line: line)
        control.tap()
    }

    /// Choose `item` from a menu in the Simulator section.
    func choose(
        _ item: String,
        fromSimulatorMenu menuTitle: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let choice = button(item)
        // A tap on a menu that lands while its list is still settling can
        // open nothing; tap it again.
        for _ in 0..<3 where !choice.exists {
            tapSimulatorControl(menuTitle, file: file, line: line)
            _ = choice.waitForExistence(timeout: 3)
            // The open menu covers its control, so a covered control means
            // it opened. At a large text size it scrolls, and an item further
            // down exists only once it is on screen.
            for _ in 0..<8 where !isHittableNow(choice) && !isHittableNow(button(menuTitle)) {
                window.swipeUp()
            }
        }
        if !choice.exists {
            print("UITEST: menu item \(item) not found\n\(app.debugDescription)")
        }
        XCTAssertTrue(choice.exists, "menu item \(item)", file: file, line: line)
        choice.tap()
    }

    // MARK: - Simulated mailbox

    /// Choose an action from the simulated mailbox's menu, at the top of the
    /// list: `path` names the item, through a submenu if it is in one. It
    /// returns once the action has run, exactly once.
    ///
    /// On a loaded Mac a tap on a menu can be lost (a submenu's often was),
    /// and a test that went on would wait for an effect that never comes.
    /// The mailbox counts every action its menu runs, before the action does
    /// anything, so a tap whose count did not move is made again, and one
    /// that moved it never is.
    func mailboxAction(_ path: String..., file: StaticString = #filePath, line: UInt = #line) {
        let before = mailboxActionsRun(file: file, line: line)
        for attempt in 1...3 {
            walkMailboxMenu(path, file: file, line: line)
            var ran = before
            // The count is read once the app is idle, and the action counts
            // itself as soon as the menu hands it the tap.
            if waitUntil(timeout: 10, {
                ran = self.mailboxActionsRunNow() ?? before
                return ran != before
            }) {
                XCTAssertEqual(ran, before + 1, "one tap, one action: \(path)", file: file, line: line)
                return
            }
            print("UITEST: menu item \(path.last ?? "") tapped, no action ran (attempt \(attempt))\n\(app.debugDescription)")
            closeMenus(path)
        }
        XCTFail("menu item \(path.last ?? "") runs its action", file: file, line: line)
    }

    /// Tap through the simulated mailbox's menu to `path`'s last item.
    private func walkMailboxMenu(_ path: [String], file: StaticString, line: UInt) {
        let menu = button("Simulated mailbox actions")
        if !isHittableNow(menu) { scrollToTop() }
        // `exists` first: `waitForExistence` costs a second even when the
        // element is already there.
        XCTAssertTrue(
            menu.exists || menu.waitForExistence(timeout: Self.appWork),
            "the simulated mailbox's menu", file: file, line: line
        )
        let items = path.map { button($0) }
        // A tap that lands while a menu is still opening can open nothing, at
        // any level: on a loaded Mac a submenu's items take seconds to show.
        // So each tap starts from the deepest level showing: a submenu whose
        // items have not appeared is tapped again, and a menu that closed is
        // opened again. A submenu waits longer than the menu before its tap
        // is repeated, so a slow one is not tapped again while it opens, and
        // the menu is tapped again only once its button can be hit: while
        // the menu is up or still coming up, its button is not there to tap.
        for _ in 0..<(3 * path.count) {
            guard let shown = items.lastIndex(where: { $0.exists }) else {
                let tappable = { self.isHittableNow(menu) }
                _ = waitUntil(timeout: Self.appWork) { items[0].exists || tappable() }
                if items[0].exists { continue }
                if !tappable() { closeMenus(path) }
                menu.tap()
                _ = waitUntil(timeout: 3) { items[0].exists }
                continue
            }
            let next = shown + 1
            items[shown].tap()
            if next == items.count { return }
            _ = waitUntil(timeout: 5) { items[next].exists }
        }
        print("UITEST: menu item \(path.last ?? "") not reached through \(path)\n\(app.debugDescription)")
        XCTFail("menu item \(path.last ?? "")", file: file, line: line)
    }

    /// Close whatever is left of the mailbox's menu, open or stuck opening,
    /// with a tap on the navigation bar's title, which nothing else answers,
    /// and bring the menu back on screen. A menu is open while any of its
    /// items is showing. (The `AdditionalDimmingOverlay` under the navigation
    /// bar is not a menu's: it is the bar's scroll edge, there whenever the
    /// list is scrolled down.)
    private func closeMenus(_ path: [String]) {
        let open = { path.contains { self.button($0).exists } }
        for _ in 0..<3 where open() {
            app.navigationBars.firstMatch.staticTexts["Approvals"].tap()
            _ = waitUntil(timeout: 5) { !open() }
        }
        scrollToTop()
    }

    /// Signatures the phone's signing key made since launch, after setup:
    /// decisions, pairing confirmations and statuses, as the counters strip
    /// reads.
    func phoneKeySignatures(file: StaticString = #filePath, line: UInt = #line) -> Int {
        let element = app.staticTexts["simulator-counters"]
        XCTAssertTrue(
            element.exists || element.waitForExistence(timeout: Self.appWork),
            "simulator counters", file: file, line: line
        )
        let label = element.label
        guard let range = label.range(of: "signatures ") else {
            XCTFail("the counters strip counts signatures: \(label)", file: file, line: line)
            return -1
        }
        return Int(label[range.upperBound...].prefix(while: \.isNumber)) ?? -1
    }

    /// How many actions the simulated mailbox's menu has run since launch.
    func mailboxActionsRun(file: StaticString = #filePath, line: UInt = #line) -> Int {
        _ = mailboxSummary(file: file, line: line)
        guard let count = mailboxActionsRunNow() else {
            XCTFail("the mailbox counts its actions", file: file, line: line)
            return -1
        }
        return count
    }

    /// The count as its line reads now, with no scrolling: nil while the line
    /// is not in the list's materialized rows.
    private func mailboxActionsRunNow() -> Int? {
        let summary = app.staticTexts["simulated-mailbox"]
        guard summary.exists, let value = summary.value as? String,
              value.hasSuffix(" actions run") else { return nil }
        return Int(value.dropLast(" actions run".count))
    }

    /// Accept the simulated mailbox's offer from a new Mac with one Face ID.
    func pairMailboxMac(file: StaticString = #filePath, line: UInt = #line) {
        mailboxAction("Offer pairing from a new mailbox Mac", file: file, line: line)
        let accept = button("Accept Mac with Face ID")
        XCTAssertTrue(reveal(accept, fromTop: true), "the mailbox Mac's offer", file: file, line: line)
        let before = counters()
        accept.tap()
        matchFace(file: file, line: line)
        XCTAssertTrue(waitForOutcome("Paired with \(Self.macName)"), "paired", file: file, line: line)
        XCTAssertEqual(
            counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 0),
            "pairing takes one Face ID", file: file, line: line
        )
    }

    /// Have the paired mailbox Mac post a request, as `csec` would.
    func post(_ menuTitle: String, file: StaticString = #filePath, line: UInt = #line) {
        mailboxAction("Post a request", menuTitle, file: file, line: line)
        XCTAssertTrue(waitForOutcome("Posted a signed"), "posted", file: file, line: line)
    }

    /// What the simulated mailbox holds, as its line at the top of the list
    /// reads.
    func mailboxSummary(file: StaticString = #filePath, line: UInt = #line) -> String {
        let summary = app.staticTexts["simulated-mailbox"]
        if !isHittableNow(summary) { scrollToTop() }
        XCTAssertTrue(
            summary.exists || summary.waitForExistence(timeout: Self.appWork),
            "the simulated mailbox's line", file: file, line: line
        )
        return summary.label
    }

    /// The mailbox's line for a wait's condition: nil while it cannot be read.
    /// While a refresh redraws the list, one accessibility snapshot can find
    /// the line with an empty label or no frame to hit-test, and on a loaded
    /// Mac a poll often lands in one. A wait reads that as "not yet", in
    /// either direction, where `mailboxSummary` would fail the test.
    func mailboxSummaryNow() -> String? {
        let summary = app.staticTexts["simulated-mailbox"]
        if !summary.exists { scrollToTop() }
        guard summary.exists else { return nil }
        let label = summary.label
        return label.hasPrefix("Simulated mailbox: ") ? label : nil
    }

    /// The card count for a wait's condition: nil while it cannot be read, as
    /// `mailboxSummaryNow`.
    func cardCountNow() -> Int? {
        let count = app.staticTexts["simulator-card-count"]
        if !count.exists { scrollToTop() }
        guard count.exists else { return nil }
        let label = count.label
        guard label.hasPrefix("The list shows ") else { return nil }
        return Int(label.dropFirst("The list shows ".count).prefix(while: \.isNumber))
    }

    /// How many cards the pending list has, as the simulated mailbox's
    /// section counts them.
    func cardCount(file: StaticString = #filePath, line: UInt = #line) -> Int {
        let count = app.staticTexts["simulator-card-count"]
        if !isHittableNow(count) { scrollToTop() }
        XCTAssertTrue(
            count.exists || count.waitForExistence(timeout: Self.appWork),
            "the list's card count", file: file, line: line
        )
        let label = count.label
        let digits = label.dropFirst("The list shows ".count).prefix(while: \.isNumber)
        guard label.hasPrefix("The list shows "), let value = Int(digits) else {
            XCTFail("card count parses: \(label)", file: file, line: line)
            return -1
        }
        return value
    }

    /// Whether `element` is anywhere in the pending list, looked for from the
    /// top down to the paired Macs, which follow it. Quiet when it is not,
    /// unlike `reveal`.
    func isAnywhereInPending(_ element: XCUIElement) -> Bool {
        let unpair = app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Unpair ")).firstMatch
        let noMac = text("No Mac is paired with this iPhone yet.")
        scrollToTop()
        for _ in 0..<12 {
            if element.exists { return true }
            if isHittableNow(unpair) || isHittableNow(noMac) { break }
            scrollDown()
        }
        return element.exists
    }

    // MARK: - Accessibility

    /// Xcode's accessibility audit of what is on screen, for the problems no
    /// card may have: a control or text with no usable description, or with
    /// the wrong traits. The other audits are not gated, because what they
    /// report here is a design choice, a false positive, or depends on where
    /// the list happens to stop: contrast (the orange and red warnings and
    /// secondary text), hit region (the message's close button and selectable
    /// reference text), Dynamic Type and clipping (reported for SwiftUI text
    /// that `testLargestTextSizeStacksTheDecisionButtons` shows does scale),
    /// and element detection, which reads the screenshot and flags whatever
    /// line of text a scroll position leaves half under a bar.
    func auditAccessibility() throws {
        try app.performAccessibilityAudit(for: [.sufficientElementDescription, .trait])
    }

    // MARK: - Finding things

    /// Whether `element` can be tapped now. XCTest's `isHittable` fails the
    /// test instead of answering when it catches an element mid-redraw with no
    /// frame to find a hit point in ("Activation point invalid"), and on a
    /// loaded Mac a poll often does. Such an element is not hittable yet.
    func isHittableNow(_ element: XCUIElement) -> Bool {
        guard element.exists else { return false }
        let frame = element.frame
        guard !frame.isEmpty, frame.intersects(window.frame) else { return false }
        return element.isHittable
    }

    func text(_ label: String) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label == %@", label)).firstMatch
    }

    func text(containing fragment: String) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", fragment)).firstMatch
    }

    func button(_ label: String) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "label == %@", label)).firstMatch
    }

    func button(beginningWith prefix: String) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", prefix)).firstMatch
    }

    func button(containing fragment: String) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "label CONTAINS %@", fragment)).firstMatch
    }

    func approveButton(_ mac: String = ApprovalUITestCase.macName) -> XCUIElement {
        button("Approve the request from \(mac)")
    }

    func denyButton(_ mac: String = ApprovalUITestCase.macName) -> XCUIElement {
        button("Deny the request from \(mac)")
    }

    /// The outcome line sits near the top of the list, which may be scrolled
    /// well down when it appears.
    @discardableResult
    func waitForOutcome(_ fragment: String, timeout: TimeInterval = ApprovalUITestCase.appWork) -> Bool {
        let outcome = text(containing: fragment)
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if outcome.exists || outcome.waitForExistence(timeout: 1) { return true }
            scrollToTop()
        } while Date() < deadline
        return outcome.exists
    }

    // MARK: - Scrolling

    var window: XCUIElement { app.windows.firstMatch }

    /// The part of the screen the list shows unobscured: below the navigation
    /// bar and above the Simulator counters strip.
    var visibleArea: CGRect {
        let frame = window.frame
        let top = app.navigationBars.firstMatch.frame.maxY
        let strip = app.staticTexts["simulator-counters"]
        // The strip's padding sits above its text.
        let bottom = strip.exists ? strip.frame.minY - 8 : frame.maxY - 34
        return CGRect(x: frame.minX, y: top, width: frame.width, height: bottom - top)
    }

    /// On screen from top to bottom, or, for something taller than the screen,
    /// on screen at all. Width is checked separately: a pairing code is meant
    /// to scroll sideways.
    func isOnScreen(_ element: XCUIElement) -> Bool {
        guard isHittableNow(element) else { return false }
        let frame = element.frame
        let visible = visibleArea
        if frame.height >= visible.height {
            return frame.intersects(visible)
        }
        return frame.minY >= visible.minY && frame.maxY <= visible.maxY
    }

    /// The Simulator banner is the list's first row: at the top it sits just
    /// under the navigation bar.
    func scrollToTop() {
        let banner = text("SIMULATOR TEST MODE")
        for _ in 0..<5 {
            if banner.exists, banner.frame.minY >= app.navigationBars.firstMatch.frame.maxY - 2 { return }
            window.swipeDown(velocity: .fast)
        }
    }

    /// Drag the list up by 40% of the screen, slowly, and hold before lifting,
    /// so it moves by the drag and does not fling past what is looked for.
    func scrollDown() {
        let start = window.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.72))
        let end = window.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.32))
        start.press(forDuration: 0.05, thenDragTo: end, withVelocity: .slow, thenHoldForDuration: 0.1)
    }

    /// Scroll down (from the top, if asked) until `element` is in the list's
    /// materialized rows. A card is one row, so everything on it is found
    /// once any of it is; `tap()` scrolls its target fully into view itself.
    /// From the top, the pass is made again until `timeout` has passed: what
    /// is looked for from the top is often still arriving (an offer, the
    /// card a refresh adds), and on a loaded Mac it can arrive after one pass
    /// has scrolled past where it appears. If the element never turns up,
    /// the screen's accessibility tree goes to the log, which is all bin/ci
    /// keeps of a failed run.
    @discardableResult
    func reveal(
        _ element: XCUIElement,
        fromTop: Bool = false,
        maxDrags: Int = 8,
        timeout: TimeInterval = ApprovalUITestCase.appWork
    ) -> Bool {
        let deadline = Date().addingTimeInterval(fromTop ? timeout : 0)
        var passes = 0
        repeat {
            passes += 1
            if fromTop { scrollToTop() }
            for _ in 0..<maxDrags {
                if element.exists { return true }
                scrollDown()
            }
            if element.exists { return true }
        } while Date() < deadline
        print("UITEST: not found in \(passes) passes of \(maxDrags) drags: \(element)\n\(app.debugDescription)")
        return false
    }

    /// Scroll down until `element` is wholly on screen, for an audit of what
    /// is around it.
    func scrollOnScreen(_ element: XCUIElement, file: StaticString = #filePath, line: UInt = #line) {
        for _ in 0..<8 where !isOnScreen(element) {
            scrollDown()
        }
        XCTAssertTrue(isOnScreen(element), "\(element) on screen", file: file, line: line)
    }

    /// Poll `condition` until it holds or `timeout` passes.
    @discardableResult
    func waitUntil(timeout: TimeInterval, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if condition() { return true }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date() < deadline
        return condition()
    }
}
