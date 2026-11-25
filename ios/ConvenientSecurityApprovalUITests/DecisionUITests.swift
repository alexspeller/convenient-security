import XCTest

/// Deciding each kind of request with simulated Face ID. The simulated Mac
/// checks every answer with `SignedRemoteApprovalResponse.verify` and reports
/// what it received; the navigation bar's counters show how many Face ID
/// sheets and key agreements the decision cost.
final class DecisionUITests: ApprovalUITestCase {
    override func setUpWithError() throws {
        try super.setUpWithError()
        launchSetUp()
    }

    func testColdUnlockApprovalOpensTheMacsStorageWithOneFaceID() {
        inject("Secret access + restore, with cold unlock")
        XCTAssertTrue(reveal(text("ALSO REOPENS, AFTER CSECD RESTARTED"), fromTop: true), "the restore section")
        XCTAssertTrue(
            reveal(text(containing: "Approving also opens csec's locked storage on \(Self.macName) for this request.")),
            "the card says approving also unlocks, naming the Mac"
        )

        let before = counters()
        let approve = approveButton()
        XCTAssertTrue(reveal(approve), "Approve, labelled with the Mac's name")
        approve.tap()
        matchFace()
        XCTAssertTrue(
            waitForOutcome("The unlock answer opened the simulated Mac's remote key and the storage sealed to it."),
            "the simulated Mac opened its remote key with the phone's answer"
        )
        XCTAssertEqual(
            counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 1),
            "one Face ID covers the signature and the one key agreement"
        )
    }

    func testChangedScopeAndDurationAreWhatIsSigned() throws {
        inject("Secret access: choices, notes, warnings")
        XCTAssertTrue(
            reveal(text("Warning: Shared vault: 4 other people can change this item."), fromTop: true),
            "a credential warning is read as a warning"
        )
        XCTAssertTrue(reveal(text("Read through the 1Password desktop app on the Mac.")), "credential note")
        XCTAssertTrue(
            text("Terminal: iTerm2 · “simulator fixture” · window 1, tab 2 · ttys003").exists,
            "the terminal is read as the terminal"
        )

        let tab = button(beginningWith: "This terminal tab")
        let command = button(beginningWith: "This command")
        XCTAssertTrue(reveal(tab), "scope option")
        scrollOnScreen(approveButton())
        try auditAccessibility()
        XCTAssertTrue(command.isSelected, "the Mac's default scope is preselected")
        XCTAssertFalse(tab.isSelected)
        tab.tap()
        XCTAssertTrue(tab.isSelected, "the chosen scope is marked selected")
        XCTAssertFalse(command.isSelected)

        let duration = button(containing: "While it runs")
        XCTAssertTrue(reveal(duration), "duration menu")
        duration.tap()
        let hour = button("1 hour")
        XCTAssertTrue(hour.waitForExistence(timeout: Self.appWork), "duration choice")
        hour.tap()
        XCTAssertTrue(button(containing: "1 hour").waitForExistence(timeout: Self.appWork), "the menu shows the chosen duration")

        let before = counters()
        let approve = approveButton()
        let deny = denyButton()
        XCTAssertTrue(reveal(approve), "Approve")
        XCTAssertTrue(deny.exists, "Deny, labelled with the Mac's name")
        approve.tap()
        // Frozen before Face ID: nothing on the card can change or be tapped
        // again while the sheet is up.
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { !approve.isEnabled && !deny.isEnabled && !tab.isEnabled },
            "the card is frozen while Face ID is up"
        )
        matchFace()
        XCTAssertTrue(
            waitForOutcome("Approved (Simulator). The simulated Mac accepted it, scope “This terminal tab”, for “1 hour”."),
            "the signed answer carries the scope and duration on screen at the tap"
        )
        XCTAssertEqual(counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 0))
    }

    /// A request Claude Code auto mode declined: the card says why, and shows
    /// the pairing line exactly while the Claude Code session and "Until it
    /// exits" are selected, as the Mac panel does. What is signed says
    /// whether the line was on screen at the tap, and only that pairs.
    func testPairingLineFollowsTheSelectionAndIsWhatIsSigned() throws {
        inject("SSH from a script auto mode declined")
        let note = text(containing: "Auto mode didn't approve this: ssh was started by bin/deploy")
        let line = text(containing: "Approving also lets Claude Code auto mode start SSH from bin/deploy")
        XCTAssertTrue(reveal(note, fromTop: true), "the card says why auto mode did not approve")
        XCTAssertTrue(reveal(line), "the pairing line shows with the Mac's default selection")
        try auditAccessibility()

        let session = button(beginningWith: "This Claude Code session")
        let command = button(beginningWith: "This SSH command")
        XCTAssertTrue(reveal(command), "scope option")
        command.tap()
        XCTAssertTrue(waitUntil(timeout: Self.appWork) { !line.exists }, "another scope hides the line")
        session.tap()
        XCTAssertTrue(waitUntil(timeout: Self.appWork) { line.exists }, "the Claude Code session shows it again")

        let duration = button(containing: "Until it exits")
        XCTAssertTrue(reveal(duration), "duration menu")
        duration.tap()
        let hour = button("1 hour")
        XCTAssertTrue(hour.waitForExistence(timeout: Self.appWork), "duration choice")
        hour.tap()
        XCTAssertTrue(waitUntil(timeout: Self.appWork) { !line.exists }, "a lifetime cap hides the line")
        let capped = button(containing: "1 hour")
        XCTAssertTrue(reveal(capped), "the menu shows the cap")
        capped.tap()
        let untilExit = button("Until it exits")
        XCTAssertTrue(untilExit.waitForExistence(timeout: Self.appWork), "the process lifetime choice")
        untilExit.tap()
        XCTAssertTrue(waitUntil(timeout: Self.appWork) { line.exists }, "the process lifetime shows it again")

        let approve = approveButton()
        XCTAssertTrue(reveal(approve), "Approve")
        approve.tap()
        matchFace()
        XCTAssertTrue(
            waitForOutcome(
                "Approved (Simulator). The simulated Mac accepted it, scope “This Claude Code session”, "
                    + "for “Until it exits”, and pairs it for auto mode."
            ),
            "an approval made with the line on screen says so, and the simulated Mac pairs"
        )
    }

    func testApprovalWithTheLineHiddenDoesNotPair() {
        inject("SSH from a script auto mode declined")
        let duration = button(containing: "Until it exits")
        XCTAssertTrue(reveal(duration, fromTop: true), "duration menu")
        duration.tap()
        let hour = button("1 hour")
        XCTAssertTrue(hour.waitForExistence(timeout: Self.appWork), "duration choice")
        hour.tap()
        let approve = approveButton()
        XCTAssertTrue(reveal(approve), "Approve")
        approve.tap()
        matchFace()
        XCTAssertTrue(
            waitForOutcome(
                "Approved (Simulator). The simulated Mac accepted it, scope “This Claude Code session”, "
                    + "for “1 hour”, without pairing."
            ),
            "an approval made with the line hidden signs that, and pairs nothing"
        )
    }

    /// A sudo that Claude Code auto mode did not approve: the card says why
    /// and always shows the pairing line, since a sudo card has no scope or
    /// lifetime to choose, and the approval signs that it showed it.
    func testSudoPairingLineAlwaysShowsAndIsWhatIsSigned() throws {
        inject("sudo auto mode declined")
        let note = text(containing: "Auto mode didn't approve this: sudo hasn't been approved for auto mode in app")
        let line = text(containing: "Approving also lets Claude Code auto mode run sudo in app")
        XCTAssertTrue(reveal(note, fromTop: true), "the card says why auto mode did not approve")
        XCTAssertTrue(reveal(line), "the pairing line shows with nothing selected")
        try auditAccessibility()
        let approve = approveButton()
        XCTAssertTrue(reveal(approve), "Approve")
        approve.tap()
        matchFace()
        XCTAssertTrue(
            waitForOutcome("Approved (Simulator). The simulated Mac accepted it, and pairs it for auto mode."),
            "the approval signs that the line was on screen, and the simulated Mac pairs"
        )
    }

    func testForgettingRestoredApprovalsComputesNoKeyAgreement() throws {
        inject("Reopen approvals after a restart")
        XCTAssertTrue(reveal(text("APPROVALS TO REOPEN"), fromTop: true), "restore-only heading")
        XCTAssertTrue(reveal(text("SSH as git to github.com using you@mac")), "an SSH row")
        XCTAssertTrue(reveal(text("Claude Code project ~/src/app")), "a paired-project row")

        let before = counters()
        let forget = button("Forget these approvals on \(Self.macName)")
        XCTAssertTrue(reveal(forget), "the refusing button forgets, naming the Mac")
        scrollOnScreen(forget)
        try auditAccessibility()
        XCTAssertTrue(button("Reopen these approvals on \(Self.macName)").exists, "the approving button reopens")
        XCTAssertFalse(denyButton().exists, "a restore-only card has no Deny")
        forget.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome(
            "Denied (Simulator). The simulated Mac accepted the signed denial; no key agreement was computed."
        ))
        XCTAssertEqual(
            counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 0),
            "the request carries an unlock challenge, but forgetting never answers it"
        )
    }

    func testNonMatchingFaceThenCancelSendsNothing() throws {
        inject("sudo")
        XCTAssertTrue(
            reveal(text("sudo wants to run this command with administrator privileges."), fromTop: true),
            "the sudo explanation"
        )
        try auditAccessibility()
        XCTAssertTrue(
            reveal(text("launchctl bootstrap system /Library/LaunchDaemons/com.example.agent.plist")),
            "the exact command"
        )
        XCTAssertTrue(reveal(text(containing: "/Users/you/src/agent")), "the working directory")

        let before = counters()
        let approve = approveButton()
        XCTAssertTrue(reveal(approve), "Approve")
        approve.tap()
        refuseFaceThenCancel()
        XCTAssertTrue(waitForOutcome("No decision was sent: Face ID was cancelled."), "nothing was signed")
        XCTAssertEqual(counters(), before.adding(prompts: 1, matches: 0, keyAgreements: 0))

        // The card is still there and can be decided again.
        XCTAssertTrue(reveal(approve), "the card stays")
        XCTAssertTrue(waitUntil(timeout: Self.appWork) { approve.isEnabled }, "and is enabled again")
        approve.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Approved (Simulator). The simulated Mac accepted it."))
        XCTAssertEqual(counters(), before.adding(prompts: 2, matches: 1, keyAgreements: 0))
    }

    /// The acknowledgement csecd raises when a Claude Code request declined
    /// on a new hook: the Mac panel's title, lines and footnote, no secret,
    /// scope or lifetime, and an Approve that signs exactly that.
    func testHooksChangedAcknowledgementIsShownAndCanBeApproved() throws {
        inject("New Claude Code hook to acknowledge")
        XCTAssertTrue(reveal(text("Settings change requested"), fromTop: true), "the kind")
        XCTAssertTrue(text(containing: "New Claude Code Hook").exists, "the Mac panel's title is the headline")
        let changes = app.descendants(matching: .any).matching(identifier: "settings-change")
        XCTAssertEqual(changes.count, 3, "each change the Mac panel lists is a line")
        XCTAssertTrue(
            changes.element(boundBy: 0).label.contains("harbor-artifact-defer@harbor · hooks module"),
            "the hook it acknowledges"
        )
        XCTAssertTrue(
            changes.element(boundBy: 1).label.contains(
                "register.mjs sha256:5d701a15f102bea3419d82442e5a3d446435116ff98375a7741898c8db82fe3a"),
            "its module's whole digest, to compare with the file"
        )
        XCTAssertTrue(
            changes.element(boundBy: 2).label.contains("csec can't show what it runs"),
            "that csec cannot show what the module does"
        )
        try auditAccessibility()
        XCTAssertTrue(reveal(text(containing: "Approving acknowledges exactly what is listed")), "the footnote")
        XCTAssertFalse(app.descendants(matching: .any).matching(identifier: "pairing-line").firstMatch.exists,
                       "no pairing line")

        let before = counters()
        let approve = approveButton()
        XCTAssertTrue(reveal(approve), "Approve")
        approve.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Approved (Simulator). The simulated Mac accepted it."),
                      "the approval selects no scope or lifetime")
        XCTAssertEqual(counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 0))
    }

    func testUnknownSSHHostIsShownAndCanBeDenied() throws {
        inject("SSH sign-in to an unknown host")
        XCTAssertTrue(reveal(text("Host: Unknown host"), fromTop: true), "the host, read as the host")
        XCTAssertTrue(text("UNKNOWN HOST").exists, "the unknown-host label")
        XCTAssertTrue(
            text(containing: "Warning: UNKNOWN HOST: No name in your known_hosts matches").exists,
            "the unknown-host warning is read as a warning"
        )
        try auditAccessibility()
        XCTAssertTrue(reveal(text("Sign in as deploy")), "the remote user")
        XCTAssertTrue(reveal(text("deploy@ci")), "the key")
        XCTAssertTrue(reveal(text(containing: "SSH receives only a signature")), "the footnote")

        let before = counters()
        let approve = approveButton()
        let deny = denyButton()
        XCTAssertTrue(reveal(deny), "Deny, labelled with the Mac's name")
        XCTAssertTrue(approve.exists, "Approve beside it")
        XCTAssertEqual(deny.frame.midY, approve.frame.midY, accuracy: 4, "at the default text size the buttons share a row")
        XCTAssertLessThan(deny.frame.maxX, approve.frame.minX, "Deny on the left, Approve on the right")

        deny.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Denied (Simulator). The simulated Mac accepted the signed denial"))
        XCTAssertEqual(counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 0))
    }
}
