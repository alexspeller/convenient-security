import XCTest

/// The reviewer demo: sample cards decided with Face ID that reach nothing a
/// real decision does. The phone's signing key signs nothing, no key
/// agreement is made, no identity is created, and the mailbox receives no
/// answer or confirmation, whether the demo is opened before setup or beside
/// a set-up iPhone with no Mac paired.
final class DemoUITests: ApprovalUITestCase {
    static let demoMac = "Demo Mac"

    func testDemoBeforeSetupDecidesWithFaceIDAndCreatesNothing() throws {
        launch(.notSetUp)
        XCTAssertTrue(button("Set up this iPhone").waitForExistence(timeout: Self.appWork), "the setup screen")
        let signaturesBefore = phoneKeySignatures()
        openDemo()
        try auditAccessibility()

        decideEach()

        XCTAssertEqual(phoneKeySignatures(), signaturesBefore, "the phone's signing key signed nothing")
        leaveDemo()
        XCTAssertTrue(
            button("Set up this iPhone").waitForExistence(timeout: Self.appWork),
            "the demo created no identity: the iPhone still needs setting up"
        )

        // A relaunch finds no identity either: the demo stored nothing.
        app.terminate()
        launch(.asLeft)
        XCTAssertTrue(
            button("Set up this iPhone").waitForExistence(timeout: Self.appWork),
            "after a relaunch, still no identity"
        )
    }

    func testDemoBesideAnUnpairedIPhoneSendsNothingToTheMailbox() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        let mailboxBefore = mailboxSummary()
        let signaturesBefore = phoneKeySignatures()
        XCTAssertEqual(cardCount(), 0, "no card before the demo")

        let start = button("Try a demo request")
        XCTAssertTrue(reveal(start, fromTop: true), "the unpaired list offers the demo")
        openDemo()
        decideEach()

        XCTAssertEqual(phoneKeySignatures(), signaturesBefore, "the phone's signing key signed nothing")
        leaveDemo()
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { self.mailboxSummaryNow() != nil },
            "back on the list"
        )
        XCTAssertEqual(mailboxSummary(), mailboxBefore, "the mailbox received no answer or confirmation")
        XCTAssertEqual(cardCount(), 0, "no demo card reached the real list")
        XCTAssertEqual(phoneKeySignatures(), signaturesBefore, "and nothing was signed after leaving")
    }

    func testStartingAgainBringsTheCardsBack() {
        launch(.notSetUp)
        openDemo()
        let approve = approveButton(Self.demoMac)
        XCTAssertTrue(reveal(approve), "the first card's Approve")
        approve.tap()
        matchFace()
        XCTAssertTrue(waitForDemoOutcome("Approved the secret access request with Face ID."))

        let again = button("Start the demo again")
        XCTAssertTrue(reveal(again), "Start the demo again")
        again.tap()
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { !self.text(containing: "Approved in the demo").exists },
            "the decided card is undecided again"
        )
        XCTAssertFalse(app.staticTexts["demo-outcome"].exists, "the outcome is cleared")
    }

    // MARK: - Steps

    private func openDemo(file: StaticString = #filePath, line: UInt = #line) {
        let start = button("Try a demo request")
        XCTAssertTrue(
            start.waitForExistence(timeout: Self.appWork) || reveal(start, fromTop: true),
            "Try a demo request", file: file, line: line
        )
        start.tap()
        XCTAssertTrue(
            app.otherElements["demo-banner"].waitForExistence(timeout: Self.appWork)
                || app.staticTexts["demo-banner"].waitForExistence(timeout: 1),
            "the demo says what it is", file: file, line: line
        )
        XCTAssertTrue(
            text("From \(Self.demoMac)").waitForExistence(timeout: Self.appWork),
            "sample cards from the demo Mac", file: file, line: line
        )
    }

    private func leaveDemo(file: StaticString = #filePath, line: UInt = #line) {
        let back = app.navigationBars.buttons["Approvals"]
        XCTAssertTrue(back.waitForExistence(timeout: Self.appWork), "back to Approvals", file: file, line: line)
        back.tap()
    }

    /// Approve the secret access, deny the SSH sign-in after a cancelled Face
    /// ID, and approve the sudo, each with one matching face. Cards are
    /// decided top to bottom: a decided card's buttons are gone, so the first
    /// Approve or Deny on screen is the next card's.
    private func decideEach(file: StaticString = #filePath, line: UInt = #line) {
        let start = counters(file: file, line: line)

        let approve = approveButton(Self.demoMac)
        XCTAssertTrue(reveal(approve), "the secret access card's Approve", file: file, line: line)
        approve.tap()
        matchFace(file: file, line: line)
        XCTAssertTrue(
            waitForDemoOutcome("Approved the secret access request with Face ID."),
            "secret access approved", file: file, line: line
        )
        XCTAssertTrue(text(containing: "nothing was sent").exists, "the outcome says nothing was sent", file: file, line: line)

        let deny = denyButton(Self.demoMac)
        XCTAssertTrue(reveal(deny), "the SSH card's Deny", file: file, line: line)
        XCTAssertTrue(reveal(text("UNKNOWN HOST")), "the SSH card warns of the unknown host", file: file, line: line)
        deny.tap()
        refuseFaceThenCancel(file: file, line: line)
        XCTAssertTrue(
            waitForDemoOutcome("Face ID was cancelled, so nothing was decided."),
            "a cancelled Face ID decides nothing", file: file, line: line
        )
        waitUntilActive(file: file, line: line)
        // Reading the outcome scrolled the list to its top, so the SSH card
        // may be off screen, where the list has not drawn its buttons.
        XCTAssertTrue(reveal(deny), "the SSH card is still there", file: file, line: line)
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { deny.isEnabled },
            "the SSH card can still be decided", file: file, line: line
        )
        deny.tap()
        matchFace(file: file, line: line)
        XCTAssertTrue(
            waitForDemoOutcome("Denied the SSH sign-in with Face ID."),
            "SSH denied", file: file, line: line
        )

        let sudoApprove = approveButton(Self.demoMac)
        XCTAssertTrue(reveal(text("sudo wants to run this command with administrator privileges.")),
                      "the sudo card", file: file, line: line)
        XCTAssertTrue(reveal(sudoApprove), "the sudo card's Approve", file: file, line: line)
        sudoApprove.tap()
        matchFace(file: file, line: line)
        XCTAssertTrue(
            waitForDemoOutcome("Approved the sudo request with Face ID."),
            "sudo approved", file: file, line: line
        )

        XCTAssertEqual(
            counters(file: file, line: line), start.adding(prompts: 4, matches: 3, keyAgreements: 0),
            "four Face ID sheets, three passed, and no key agreement", file: file, line: line
        )
        XCTAssertFalse(approveButton(Self.demoMac).exists, "every card is decided", file: file, line: line)
        XCTAssertFalse(denyButton(Self.demoMac).exists, file: file, line: line)
    }

    /// The demo's outcome sits at the top of its list.
    private func waitForDemoOutcome(_ fragment: String) -> Bool {
        let outcome = text(containing: fragment)
        let deadline = Date().addingTimeInterval(Self.appWork)
        repeat {
            if outcome.exists || outcome.waitForExistence(timeout: 1) { return true }
            window.swipeDown(velocity: .fast)
        } while Date() < deadline
        return outcome.exists
    }
}
