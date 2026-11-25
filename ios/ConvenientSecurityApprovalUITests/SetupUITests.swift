import XCTest

/// Setting up this iPhone: one Face ID for both keys, then the notification
/// prompt; and an identity from an earlier version, which must be set up again.
final class SetupUITests: ApprovalUITestCase {
    static let nothingYet = SimulatorCounters(faceIDPrompts: 0, faceIDMatches: 0, keyAgreements: 0)

    func testSetupTakesOneFaceIDThenAsksForNotifications() {
        launch(.notSetUp)
        XCTAssertEqual(counters(), Self.nothingYet)
        XCTAssertTrue(text("Approve Mac requests from this iPhone").exists, "setup heading")
        XCTAssertTrue(
            text(containing: "both locked to your current Face ID, for one Face ID").exists,
            "the setup explanation says what the one Face ID creates"
        )

        setUpPhone()

        XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork), "empty pending list")
        XCTAssertTrue(text("Pair a Mac below to start.").exists)
        let pair = button("Pair a Mac")
        XCTAssertTrue(reveal(pair), "pairing disclosure")
        pair.tap()
        let command = text(containing: "csec remote enable 'csec-phone-v2:")
        XCTAssertTrue(reveal(command), "the whole Mac command, with the phone's code quoted, is shown")
        XCTAssertTrue(button("Copy the command for your Mac").exists, "the command is what the copy button offers")
        XCTAssertTrue(text(containing: "This iPhone's key:").exists, "the phone's key fingerprint is shown")

        // A relaunch reads the stored identity back without any Face ID.
        app.terminate()
        launch(.asLeft)
        XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork), "still set up after relaunch")
        XCTAssertFalse(button("Set up this iPhone").exists)
        XCTAssertEqual(counters(), Self.nothingYet, "loading the identity needs no Face ID")
    }

    /// App Review asks for the privacy policy inside the app, so it is
    /// reachable before setup and once set up.
    func testThePrivacyPolicyIsLinkedBeforeAndAfterSetup() {
        launch(.notSetUp)
        // A Link in a List row reaches accessibility as a button.
        let policy = button("Privacy policy")
        XCTAssertTrue(reveal(policy, fromTop: true), "before setup")
        setUpPhone()
        XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork))
        XCTAssertTrue(reveal(policy, fromTop: true), "once set up")
    }

    func testARefusedAlertSubscriptionIsShownWithICloudsReason() {
        launch(.notSetUp, refuseSubscription: true)
        setUpPhone()
        XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork))
        let heading = text("Requests won't alert this iPhone")
        XCTAssertTrue(reveal(heading), "a refused subscription is shown, not dropped")
        XCTAssertTrue(
            text(containing: "attempting to create a subscription in a production container").exists,
            "the reason iCloud gave is shown"
        )
    }

    /// An identity record that was read and is damaged — it does not decode,
    /// or its keys no longer match it — is unusable: the app offers to set up
    /// again, and only that.
    func testDamagedIdentityRecordsAskToSetUpAgain() {
        for state in [StartingState.undecodableIdentity, .mismatchedIdentity] {
            launch(state)
            XCTAssertTrue(
                text(containing: "This iPhone's approval keys can no longer be used")
                    .waitForExistence(timeout: Self.appWork),
                "\(state): the unusable identity is explained"
            )
            XCTAssertFalse(button("Try again").exists, "\(state): reading again cannot fix it")
            XCTAssertFalse(button("Inject signed sample request").exists, "\(state): nothing is decidable")

            setUpPhone(button: "Set up this iPhone again")
            XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork), "\(state): set up again")
            app.terminate()
        }
    }

    /// A Keychain read refused as a locked iPhone refuses it is not a broken
    /// identity: the app says the records are not available yet and offers
    /// Try again, never setup, and once the read works the same identity is
    /// back with no Face ID.
    func testARefusedKeychainReadIsReadAgainAndReplacesNothing() {
        launch(.notSetUp)
        setUpPhone()
        let key = phoneKey()
        app.terminate()

        launch(.asLeft, refuseKeychainReads: true)
        XCTAssertTrue(
            text("Approvals are not available yet").waitForExistence(timeout: Self.appWork),
            "a refused read is temporarily unavailable"
        )
        XCTAssertTrue(
            text(containing: "(Keychain status -25308)").exists,
            "with the Keychain's own status, errSecInteractionNotAllowed"
        )
        XCTAssertFalse(button(beginningWith: "Set up this iPhone").exists, "nothing offers to set up again")
        let tryAgain = button("Try again")
        XCTAssertTrue(tryAgain.exists, "Try again is offered")
        tryAgain.tap()
        XCTAssertTrue(
            text("Approvals are not available yet").waitForExistence(timeout: Self.appWork),
            "still refused, still only Try again"
        )
        XCTAssertFalse(button(beginningWith: "Set up this iPhone").exists)

        // The iPhone is unlocked: the read works.
        button("Stop refusing Keychain reads (Simulator)").tap()
        tryAgain.tap()
        XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork), "the records are read again")
        XCTAssertEqual(counters(), Self.nothingYet, "reading them needs no Face ID")
        XCTAssertEqual(phoneKey(), key, "the same identity: nothing was re-created")
    }

    /// This iPhone's key fingerprint, as the pairing steps show it.
    private func phoneKey(file: StaticString = #filePath, line: UInt = #line) -> String {
        let pair = button(beginningWith: "Pair a")
        XCTAssertTrue(reveal(pair, fromTop: true), "pairing disclosure", file: file, line: line)
        let key = text(containing: "This iPhone's key: ")
        if !key.exists { pair.tap() }
        XCTAssertTrue(reveal(key), "the phone's key", file: file, line: line)
        return String(key.label.dropFirst("This iPhone's key: ".count))
    }

    func testIdentityFromAnEarlierVersionAsksToSetUpAgain() {
        launch(.legacyIdentity)
        XCTAssertTrue(
            text(containing: "This iPhone was set up by an earlier version of Convenient Security")
                .waitForExistence(timeout: Self.appWork),
            "the outdated setup is explained"
        )
        XCTAssertFalse(button("Inject signed sample request").exists, "nothing is decidable before setting up again")

        setUpPhone(button: "Set up this iPhone again")
        XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork))

        app.terminate()
        launch(.asLeft)
        XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork), "set up after relaunch")
        XCTAssertFalse(
            text(containing: "set up by an earlier version").exists,
            "the format-1 record was replaced"
        )
    }
}
