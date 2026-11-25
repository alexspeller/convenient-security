import XCTest

/// The app against the simulated mailbox, the Simulator's stand-in for the
/// private iCloud database: the real refresh, decision and confirmation code,
/// with a mailbox that keeps what it holds across a relaunch and whose Mac
/// never withdraws anything — the Mac whose delete failed.
final class MailboxUITests: ApprovalUITestCase {
    static let sudoExplanation = "sudo wants to run this command with administrator privileges."

    override func tearDown() {
        // Leave no pinned Mac and no mailbox behind: other tests launch with
        // what the last one left.
        app.terminate()
        launch(.notSetUp)
        super.tearDown()
    }

    func testAnAnsweredRequestIsNotActionableAfterARelaunch() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        pairMailboxMac()

        post("sudo")
        let deadline = app.descendants(matching: .any).matching(identifier: "review-deadline").firstMatch
        XCTAssertTrue(reveal(deadline, fromTop: true), "the sudo card says when the Mac closes it")
        let approve = approveButton()
        XCTAssertTrue(reveal(approve, fromTop: true), "the mailbox's request is a card")
        approve.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Approved. Sent to \(Self.macName)."), "the answer reached the mailbox")
        XCTAssertTrue(
            reveal(text("Approved — sent to \(Self.macName)"), fromTop: true),
            "while the request stays in the mailbox, its card says it was sent"
        )
        XCTAssertFalse(deadline.exists, "a sent card drops the deadline line: the answer no longer waits on it")
        // A second request, left unanswered: what the relaunch must still show.
        post("SSH sign-in to an unknown host")
        XCTAssertTrue(
            mailboxSummary().hasPrefix("Simulated mailbox: 2 requests (0 left out of the list), 1 answers"),
            "the Mac never deleted the answered request"
        )

        app.terminate()
        launch(.asLeft, mailbox: true)
        XCTAssertTrue(
            mailboxSummary().hasPrefix("Simulated mailbox: 2 requests (0 left out of the list), 1 answers"),
            "after the relaunch the mailbox still holds both requests"
        )
        // Of the two, one card: the unanswered SSH request, live. The sudo
        // request this iPhone answered before the relaunch is not shown
        // again, not even as sent. The list starts empty and each refresh
        // replaces it whole, so the first cards it shows are what the
        // relaunch's first refresh made of both requests: on a loaded Mac
        // that refresh can take a while, but a second card is never a
        // matter of waiting.
        var cards = 0
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) {
                cards = self.cardCountNow() ?? 0
                return cards > 0
            },
            "the relaunch's refresh shows the requests"
        )
        XCTAssertEqual(cards, 1, "one card for two requests")
        XCTAssertTrue(
            reveal(text("Host: Unknown host"), fromTop: true),
            "the request this iPhone did not answer is shown"
        )
        XCTAssertTrue(denyButton().exists, "and can be decided")
        XCTAssertTrue(approveButton().exists)
        XCTAssertFalse(text(Self.sudoExplanation).exists, "the answered sudo request is not that card")
        XCTAssertFalse(text("Approved — sent to \(Self.macName)").exists)
    }

    func testTappingAnAlertOpensItsRequestThoughTheListLeavesItOut() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        pairMailboxMac()
        post("Secret access: choices, notes, warnings")
        post("Secret access: choices, notes, warnings")
        post("SSH sign-in to an unknown host")
        post("sudo, left out of the list")
        XCTAssertTrue(
            mailboxSummary().hasPrefix("Simulated mailbox: 4 requests (1 left out of the list)"),
            "the newest request is one the mailbox query does not return"
        )
        XCTAssertEqual(cardCount(), 3, "without its alert, the list does not have it")
        let sudo = text(Self.sudoExplanation)

        // Opened by a tap on that request's alert.
        app.terminate()
        launch(.asLeft, mailbox: true, openAlertForHiddenRequest: true)
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { self.isOnScreen(sudo) },
            "the tapped request is read by its ID, verified and brought on screen"
        )
        XCTAssertFalse(
            isOnScreen(text("SIMULATOR TEST MODE")),
            "the list scrolled to it: it is the newest, under three other cards"
        )

        // Still on the list after another refresh, though the query still
        // leaves it out.
        button("Refresh approvals").tap()
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { self.button("Refresh approvals").isEnabled },
            "the refresh finishes"
        )
        XCTAssertTrue(sudo.exists, "a refresh keeps the alerted request on the list")
        XCTAssertTrue(isOnScreen(sudo), "where it was")

        // The card is that request's own: its Approve is the next one below.
        let approve = app.buttons
            .matching(NSPredicate(format: "label == %@", "Approve the request from \(Self.macName)"))
            .allElementsBoundByIndex
            .filter { $0.frame.minY > sudo.frame.maxY }
            .min { $0.frame.minY < $1.frame.minY }
        guard let approve else {
            XCTFail("the tapped request's card can be approved")
            return
        }
        let before = counters()
        approve.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Approved. Sent to \(Self.macName)."), "it is decided like any card")
        XCTAssertEqual(counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 0))
        XCTAssertTrue(
            mailboxSummary().hasPrefix("Simulated mailbox: 4 requests (1 left out of the list), 1 answers"),
            "the answer is in the mailbox"
        )
        XCTAssertEqual(cardCount(), 4, "the cards the query returned are still there beside it")
    }

    func testAMissingPairingConfirmationIsPublishedAgainOncePerActivation() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        pairMailboxMac()
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) {
                self.mailboxSummaryNow()?.hasSuffix("1 pairing confirmations, 1 confirmation saves") == true
            },
            "pairing published the confirmation: \(mailboxSummary())"
        )
        let faceIDs = counters()

        mailboxAction("Delete the pairing confirmations")
        XCTAssertTrue(mailboxSummary().hasSuffix("0 pairing confirmations, 1 confirmation saves"))
        // It was looked for when this activation began, so a refresh does
        // not look again.
        scrollToTop()
        button("Refresh approvals").tap()
        XCTAssertFalse(
            waitUntil(timeout: 3) {
                self.mailboxSummaryNow().map { !$0.hasSuffix("0 pairing confirmations, 1 confirmation saves") } == true
            },
            "once per activation: a refresh does not publish it again"
        )
        // A poll that could not read the line counted as unchanged, so the
        // line is read once more where it must parse.
        XCTAssertTrue(mailboxSummary().hasSuffix("0 pairing confirmations, 1 confirmation saves"))

        // The next activation finds it missing and publishes it again.
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) {
                self.mailboxSummaryNow()?.hasSuffix("1 pairing confirmations, 2 confirmation saves") == true
            },
            "the next activation publishes the missing confirmation again: \(mailboxSummary())"
        )
        XCTAssertEqual(counters(), faceIDs, "it is already signed: no Face ID")

        // Gone again in the same activation, it stays gone until the next.
        mailboxAction("Delete the pairing confirmations")
        scrollToTop()
        button("Refresh approvals").tap()
        XCTAssertFalse(
            waitUntil(timeout: 3) {
                self.mailboxSummaryNow().map { !$0.hasSuffix("0 pairing confirmations, 2 confirmation saves") } == true
            },
            "at most once per activation"
        )
        XCTAssertTrue(mailboxSummary().hasSuffix("0 pairing confirmations, 2 confirmation saves"))
        app.terminate()
        launch(.asLeft, mailbox: true)
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) {
                self.mailboxSummaryNow()?.hasSuffix("1 pairing confirmations, 3 confirmation saves") == true
            },
            "a relaunch is an activation too: \(mailboxSummary())"
        )
        XCTAssertFalse(
            isAnywhereInPending(text(containing: "The pairing confirmation has not reached iCloud yet")),
            "the paired Mac's confirmation reads as delivered"
        )
    }

    /// iCloud refusing the subscription that tells the phone a request is
    /// over costs only the clearing: alerts still work, the refusal has its
    /// own line with iCloud's reason, and a later save that works clears it.
    func testARefusedSettledSubscriptionIsShownWhileAlertsStillWork() {
        launch(.notSetUp, refuseSettledSubscription: true, mailbox: true)
        setUpPhone()
        pairMailboxMac()

        let heading = text("Answered requests may stay on this iPhone")
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { self.isAnywhereInPending(heading) },
            "a refused settled subscription is shown, not dropped"
        )
        XCTAssertTrue(
            isAnywhereInPending(text(containing: "attempting to create a subscription in a production container")),
            "the reason iCloud gave is shown"
        )
        XCTAssertFalse(
            isAnywhereInPending(text("Requests won't alert this iPhone")),
            "the alert subscription was saved: requests still alert this iPhone"
        )

        app.terminate()
        launch(.asLeft, mailbox: true)
        XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork))
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { !self.isAnywhereInPending(heading) },
            "once iCloud takes the settled subscription, the line goes"
        )
    }

    func testICloudAccountProblemsAreToldApartFromNetworkTrouble() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()

        // No Mac is paired, so nothing reads the mailbox: only the account
        // check at activation can tell.
        app.terminate()
        launch(.asLeft, mailbox: true, iCloud: .signedOut)
        assertICloudLine(
            "Requests from your Mac cannot reach this iPhone: this iPhone is not signed in to iCloud. "
                + "In Settings, sign in to the Apple Account your Mac uses."
        )

        app.terminate()
        launch(.asLeft, mailbox: true)
        pairMailboxMac()

        let accountProblems: [(SimulatedICloud, String)] = [
            (.signedOut, "this iPhone is not signed in to iCloud. In Settings, sign in to the Apple Account your Mac uses."),
            (.restricted, "iCloud is restricted on this iPhone by Screen Time or device management."),
            (.notReady, "this iPhone's iCloud account is not ready yet. Settings may ask you to verify your Apple Account."),
        ]
        for (account, reason) in accountProblems {
            app.terminate()
            launch(.asLeft, mailbox: true, iCloud: account)
            assertICloudLine(
                "Requests from your Mac cannot reach this iPhone: \(reason) "
                    + "Showing the requests this iPhone last verified."
            )
            XCTAssertFalse(
                text("Requests won't alert this iPhone").exists,
                "an account problem is not reported as a refused subscription (\(account))"
            )
        }

        app.terminate()
        launch(.asLeft, mailbox: true, iCloud: .unreachable)
        assertICloudLine("Could not reach iCloud. Showing the requests this iPhone last verified.")

        app.terminate()
        launch(.asLeft, mailbox: true)
        XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork))
        XCTAssertFalse(text(containing: "cannot reach this iPhone").exists, "an available account says nothing")
        XCTAssertFalse(text(containing: "Could not reach iCloud").exists, "a reachable mailbox says nothing")
    }

    func testADecisionThatCannotReachICloudSaysWhy() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        pairMailboxMac()
        post("sudo")

        mailboxAction("Simulated iCloud: Available", "Signed out")
        assertICloudLine(
            "Requests from your Mac cannot reach this iPhone: this iPhone is not signed in to iCloud. "
                + "In Settings, sign in to the Apple Account your Mac uses. "
                + "Showing the requests this iPhone last verified."
        )
        let approve = approveButton()
        XCTAssertTrue(reveal(approve, fromTop: true), "the last verified card stays")
        approve.tap()
        matchFace()
        XCTAssertTrue(
            waitForOutcome("No decision was sent: this iPhone is not signed in to iCloud."),
            "the decision says why it was not sent"
        )
        XCTAssertTrue(mailboxSummary().contains("0 answers"), "nothing reached the mailbox")

        mailboxAction("Simulated iCloud: Signed out", "Available")
        XCTAssertTrue(reveal(approve, fromTop: true), "the card can be decided again")
        approve.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Approved. Sent to \(Self.macName)."))
        XCTAssertTrue(mailboxSummary().contains("1 answers"))
    }

    /// An iCloud that does not answer does not hold a decision: it gives up
    /// within its bounds, says the Mac may not have it, and leaves the card,
    /// and Face ID, free to decide again. The save it gave up on lands once
    /// iCloud answers, as a CloudKit save can, and the next tap reports that
    /// earlier answer rather than overwriting it.
    func testADecisionICloudDoesNotAnswerCanBeGivenAgain() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        pairMailboxMac()
        post("sudo")

        mailboxAction("Simulated iCloud: Available", "Not answering")
        let approve = approveButton()
        XCTAssertTrue(reveal(approve, fromTop: true), "the last verified card stays")
        approve.tap()
        matchFace()
        // The withdrawn check's 5 s and the save's 15 s, with room to spare.
        XCTAssertTrue(
            waitForOutcome(
                "Could not reach iCloud, so \(Self.macName) may not have received this decision. Try again.",
                timeout: 45
            ),
            "the decision gives up on an iCloud that does not answer"
        )
        XCTAssertTrue(mailboxSummary().contains("0 answers"), "nothing reached the mailbox yet")
        XCTAssertTrue(reveal(approve, fromTop: true), "the card stays")
        XCTAssertTrue(approve.isEnabled, "Face ID is free for the next decision")

        mailboxAction("Simulated iCloud: Not answering", "Available")
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { self.mailboxSummaryNow()?.contains("1 answers") == true },
            "the save given up on lands once iCloud answers: \(mailboxSummary())"
        )
        let deny = denyButton()
        XCTAssertTrue(reveal(deny, fromTop: true), "the card can be decided again")
        deny.tap()
        matchFace()
        XCTAssertTrue(
            waitForOutcome("This tap was not sent: this iPhone had already answered this request with Approve"),
            "the answer that landed is the one reported"
        )
        XCTAssertTrue(mailboxSummary().contains("1 answers"), "the earlier answer was not overwritten")
    }

    /// A refresh iCloud does not answer finishes, says so under the list and
    /// leaves Refresh working, so a request posted once iCloud answers again
    /// reaches the list.
    func testARefreshICloudDoesNotAnswerFinishes() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        pairMailboxMac()

        // Switching the account checks it and refreshes, as an activation
        // does: the account check's 5 s, then the mailbox read's 5 s. The
        // line is looked for once the refresh is over: scrolling the list
        // while the refresh redraws it can leave XCTest unable to hit-test it.
        mailboxAction("Simulated iCloud: Available", "Not answering")
        let refresh = button("Refresh approvals")
        XCTAssertTrue(waitUntil(timeout: Self.appWork) { !refresh.isEnabled }, "the switch refreshes")
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { refresh.isEnabled },
            "the refresh finished, so another can start"
        )
        assertICloudLine("Could not reach iCloud. Showing the requests this iPhone last verified.")
        refresh.tap()
        XCTAssertTrue(waitUntil(timeout: Self.appWork) { !refresh.isEnabled }, "a second refresh starts")
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) { refresh.isEnabled },
            "a refresh started while iCloud does not answer finishes too"
        )

        mailboxAction("Simulated iCloud: Not answering", "Available")
        post("sudo")
        XCTAssertTrue(reveal(approveButton(), fromTop: true), "the next request reaches the list")
        XCTAssertFalse(text(containing: "Could not reach iCloud").exists, "a mailbox that answers says nothing")
    }

    func testARequestAnsweredAtTheMacLeavesThePhoneWithNoRefresh() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        pairMailboxMac()
        post("sudo")
        XCTAssertTrue(reveal(approveButton(), fromTop: true))
        XCTAssertEqual(cardCount(), 1)

        // The Mac's own panel answers: csecd withdraws the request. Nothing
        // pushes that; the open app sees it go by itself.
        mailboxAction("Answer at the Mac: it withdraws what nobody answered here")
        XCTAssertTrue(mailboxSummary().hasPrefix("Simulated mailbox: 0 requests"))
        let gone = NSPredicate { _, _ in self.cardCountNow() == 0 }
        XCTAssertEqual(
            XCTWaiter().wait(for: [expectation(for: gone, evaluatedWith: nil)], timeout: Self.appWork), .completed,
            "the card leaves within moments, with no refresh"
        )
        XCTAssertFalse(approveButton().exists, "no Approve is left for a request the Mac already decided")
    }

    func testARequestWhoseMacWentQuietLeavesThePhoneUntilTheMacComesBack() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        pairMailboxMac()
        post("sudo")
        XCTAssertTrue(reveal(approveButton(), fromTop: true))
        XCTAssertEqual(cardCount(), 1)

        // The Mac stops saving its request again, as one that crashed and
        // never runs csecd again: the record stays, nothing listens for it.
        mailboxAction("Go quiet: the Mac stops saving its requests again")
        XCTAssertTrue(mailboxSummary().hasPrefix("Simulated mailbox: 1 requests"),
                      "the record is still in the mailbox")
        let gone = NSPredicate { _, _ in self.cardCountNow() == 0 }
        XCTAssertEqual(
            XCTWaiter().wait(for: [expectation(for: gone, evaluatedWith: nil)], timeout: Self.appWork), .completed,
            "the card leaves with no refresh"
        )
        XCTAssertFalse(approveButton().exists, "no Approve is left for a Mac that has gone quiet")
        button("Refresh approvals").tap()
        let back = expectation(for: NSPredicate { _, _ in (self.cardCountNow() ?? 0) > 0 }, evaluatedWith: nil)
        back.isInverted = true
        XCTAssertEqual(
            XCTWaiter().wait(for: [back], timeout: 5), .completed,
            "a refresh does not bring it back while the Mac is quiet"
        )
        // A poll that could not read the count counted as no card, so the
        // count is read once more where it must parse.
        XCTAssertEqual(cardCount(), 0, "no card came back while the Mac was quiet")

        // The Mac wakes and saves its request again: nothing was decided, so
        // the card comes back, still answerable.
        mailboxAction("Come back: the Mac saves its requests again")
        button("Refresh approvals").tap()
        XCTAssertTrue(reveal(approveButton(), fromTop: true), "the card comes back with the Mac")
        XCTAssertEqual(cardCount(), 1)
    }

    func testAnAnswerTheMacDidNotTakeCanBeGivenAgain() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        pairMailboxMac()
        post("sudo")
        let approve = approveButton()
        XCTAssertTrue(reveal(approve, fromTop: true))
        approve.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Approved. Sent to \(Self.macName)."))

        // The Mac refuses the answer — as csecd refuses one whose clock is far
        // from its own — deleting it and waiting on.
        mailboxAction("Refuse the answers: the Mac deletes them and keeps waiting")
        XCTAssertTrue(mailboxSummary().hasPrefix("Simulated mailbox: 1 requests (0 left out of the list), 0 answers"))
        button("Refresh approvals").tap()
        XCTAssertTrue(
            waitForOutcome("\(Self.macName) did not accept this iPhone's answer and is still waiting. Decide again."),
            "the iPhone notices the Mac still waiting without its answer"
        )
        let note = text("Your answer was not accepted. \(Self.macName) is still waiting: decide again.")
        XCTAssertTrue(reveal(note, fromTop: true), "the card says so")
        XCTAssertTrue(approve.exists && approve.isEnabled, "and can be decided again")
        XCTAssertFalse(text("Approved — sent to \(Self.macName)").exists, "it is no longer marked as sent")

        // Not remembered as answered: a relaunch still offers it.
        app.terminate()
        launch(.asLeft, mailbox: true)
        XCTAssertTrue(reveal(approve, fromTop: true), "after a relaunch it is still there to decide")

        let before = counters()
        approve.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Approved. Sent to \(Self.macName)."), "decided again")
        XCTAssertEqual(counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 0))
        XCTAssertTrue(mailboxSummary().contains("1 answers"), "the new answer is in the mailbox")
    }

    func testAfterALostReplyAWithdrawnRequestSaysTheEarlierAnswerMayHaveCounted() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        pairMailboxMac()
        post("sudo")

        mailboxAction("Lose the reply to the next answer")
        let approve = approveButton()
        XCTAssertTrue(reveal(approve, fromTop: true))
        approve.tap()
        matchFace()
        XCTAssertTrue(
            waitForOutcome("Could not reach iCloud, so \(Self.macName) may not have received this decision. Try again."),
            "the save reported a failure"
        )
        XCTAssertTrue(mailboxSummary().contains("1 answers"), "though the answer landed: only its reply was lost")

        // The Mac took that answer and stopped waiting. The open app sees the
        // request go by itself, and says the earlier answer may have counted.
        mailboxAction("Take the answers: the Mac withdraws what was answered")
        XCTAssertTrue(mailboxSummary().hasPrefix("Simulated mailbox: 0 requests"))
        XCTAssertTrue(
            waitForOutcome("\(Self.macName) is no longer waiting. Your earlier answer may have been applied."),
            "the earlier answer may be the one the Mac took"
        )
        XCTAssertFalse(approve.exists, "the card left with its request")
        XCTAssertEqual(cardCount(), 0)
        XCTAssertFalse(text(containing: "No decision was sent").exists)
    }

    /// The line under the pending list says exactly `line`.
    private func assertICloudLine(_ line: String, file: StaticString = #filePath, lineNumber: UInt = #line) {
        let shown = text(line)
        // It sits under the pending list, which may reach below the screen.
        let deadline = Date().addingTimeInterval(Self.appWork)
        repeat {
            if waitUntil(timeout: 1, { shown.exists }) || isAnywhereInPending(shown) { return }
        } while Date() < deadline
        XCTFail("the line under the list: \(line)\n\(app.debugDescription)", file: file, line: lineNumber)
    }
}
