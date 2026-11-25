import XCTest

/// A Mac's offer from `csec remote enable`: shown at the top with the Mac's
/// name and key while the app is open, turned down for this run by Cancel,
/// and pinned with one Face ID like a pasted code.
final class PairingOfferUITests: ApprovalUITestCase {
    override func tearDown() {
        // Leave no pinned Mac behind: other tests launch with what the last
        // one left.
        app.terminate()
        launch(.notSetUp)
        super.tearDown()
    }

    func testAMacsOfferIsShownAndAcceptedWithOneFaceID() {
        launch(.notSetUp)
        setUpPhone()
        XCTAssertTrue(text("No pending approvals").waitForExistence(timeout: Self.appWork), "set up, nothing paired")

        let offerButton = button("Offer pairing from a new simulated Mac")
        let offered = text("Offered to this iPhone through your iCloud account.")
        XCTAssertTrue(reveal(offerButton), "the Simulator can play a Mac running csec remote enable")
        offerButton.tap()
        XCTAssertTrue(
            reveal(offered, fromTop: true),
            "the Mac's offer is shown without pasting its code"
        )
        XCTAssertTrue(text(containing: "Mac key ").exists, "the offer shows the Mac's key to compare")
        XCTAssertTrue(
            text("Check that this is the key csec remote enable printed on your Mac.").exists,
            "the offer asks for the same check as a pasted code"
        )

        // Cancel turns this offer down for the rest of the run, though the
        // watch keeps reading it.
        let cancel = button("Cancel")
        XCTAssertTrue(cancel.exists, "the offer can be turned down")
        cancel.tap()
        XCTAssertFalse(
            waitUntil(timeout: 5) { offered.exists },
            "a turned-down offer is not shown again"
        )

        // An offer from a Mac with another key — a new csec remote enable — is
        // shown again, and accepting it costs exactly one Face ID.
        XCTAssertTrue(reveal(offerButton))
        offerButton.tap()
        XCTAssertTrue(reveal(offered, fromTop: true), "a new offer is shown")
        let accept = button("Accept Mac with Face ID")
        XCTAssertTrue(accept.exists, "the offer is accepted with Face ID")
        let before = counters()
        accept.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Paired with \(Self.macName)"), "the offered Mac is paired")
        XCTAssertEqual(
            counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 0),
            "pinning the offered Mac takes one Face ID"
        )
        XCTAssertFalse(
            waitUntil(timeout: 5) { offered.exists },
            "a Mac pinned with the offered key is not offered again"
        )
    }

    /// An iCloud that does not answer does not hold the pairing up: its
    /// outcome is shown once the confirmation's save has had its bound, and
    /// the confirmation reaches the mailbox, with no Face ID, once iCloud
    /// answers.
    func testAPairingIsShownWhileICloudDoesNotAnswer() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        _ = offeredKey()
        mailboxAction("Simulated iCloud: Available", "Not answering")
        accept("Accept Mac with Face ID")
        XCTAssertTrue(
            text(containing: "on this iPhone, but iCloud could not be reached.").exists,
            "the outcome says the confirmation has not been sent"
        )
        XCTAssertTrue(
            mailboxSummary().hasSuffix("0 pairing confirmations, 0 confirmation saves"),
            "nothing reached the mailbox: \(mailboxSummary())"
        )
        XCTAssertTrue(
            isAnywhereInPending(text(containing: "The pairing confirmation has not reached iCloud yet")),
            "the paired Mac says its confirmation is waiting"
        )
        let faceIDs = counters()

        // The saves given up on land then too, as a CloudKit save can, so
        // only the retry's answer marks the confirmation delivered.
        mailboxAction("Simulated iCloud: Not answering", "Available")
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) {
                self.mailboxSummaryNow()?.contains(" 1 pairing confirmations, ") == true
            },
            "the confirmation is sent once iCloud answers: \(mailboxSummary())"
        )
        XCTAssertEqual(counters(), faceIDs, "it is already signed: no Face ID")
        XCTAssertTrue(
            waitUntil(timeout: Self.appWork) {
                !self.isAnywhereInPending(text(containing: "The pairing confirmation has not reached iCloud yet"))
            },
            "the paired Mac's confirmation reads as delivered"
        )
    }

    /// Macs of the same name are told apart by their keys: the offer shows
    /// the key each one has now, and the reader adds the new Mac beside them
    /// or replaces them. The simulated mailbox stands in for iCloud, so the
    /// pairings' confirmations go somewhere.
    func testAMacOfTheSameNameIsAddedOrReplacedByItsKey() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()

        let first = offeredKey()
        XCTAssertTrue(candidatePairedKeys().isEmpty, "nothing is paired yet, so no key is replaced")
        accept("Accept Mac with Face ID")
        XCTAssertEqual(pairedKeys(), [first])

        let second = offeredKey()
        XCTAssertNotEqual(second, first, "another Mac, another key")
        XCTAssertTrue(
            text("This iPhone is already paired with another Mac named \(Self.macName).").exists,
            "the offer says a Mac of that name is paired"
        )
        XCTAssertEqual(candidatePairedKeys(), [first], "and shows the key that Mac has now")
        XCTAssertFalse(button("Accept Mac with Face ID").exists, "the reader chooses: add or replace")
        accept("Add as another Mac with Face ID")
        // Macs of one name are listed in no particular order.
        let both = pairedKeys()
        XCTAssertEqual(both.count, 2, "added beside it")
        XCTAssertEqual(Set(both), [first, second], "added beside it")

        let third = offeredKey()
        XCTAssertEqual(
            Set(candidatePairedKeys()), [first, second],
            "both Macs of that name show their keys"
        )
        accept("Replace with Face ID")
        XCTAssertEqual(pairedKeys(), [third], "both replaced by the new one")
    }

    /// An offer from a paired Mac — same ID — with a key that is not the one
    /// paired shows both keys and says the key changes, before Face ID.
    func testAnOfferForAPairedMacShowsTheKeyPairedNow() {
        launch(.notSetUp, mailbox: true)
        setUpPhone()
        let paired = offeredKey()
        accept("Accept Mac with Face ID")

        let rekeyed = offeredKey(action: "Offer pairing again from the last mailbox Mac, with a new key")
        XCTAssertNotEqual(rekeyed, paired, "the offer carries a new key")
        XCTAssertTrue(
            text("This iPhone is already paired with this Mac. Accepting replaces that pairing.").exists,
            "the offer says it replaces the pairing"
        )
        XCTAssertEqual(candidatePairedKeys(), [paired], "the key paired now is shown beside the new one")
        XCTAssertTrue(
            text("The key changes. Accept only if the new key above is the one csec remote enable printed on your Mac.")
                .exists,
            "the change is called out"
        )
        accept("Accept Mac with Face ID")
        XCTAssertEqual(pairedKeys(), [rekeyed], "the pairing now holds the new key")
    }

    // MARK: - Keys on screen

    /// Have a mailbox Mac offer to pair, and read the key its offer shows.
    private func offeredKey(
        action: String = "Offer pairing from a new mailbox Mac",
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> String {
        mailboxAction(action, file: file, line: line)
        let key = app.staticTexts["candidate-mac-key"]
        XCTAssertTrue(reveal(key, fromTop: true), "the offer's key", file: file, line: line)
        return fingerprint(key.label, after: "Mac key ", file: file, line: line)
    }

    /// The keys the offer shows as paired now.
    private func candidatePairedKeys(file: StaticString = #filePath, line: UInt = #line) -> [String] {
        app.staticTexts.matching(identifier: "candidate-paired-key").allElementsBoundByIndex.map {
            fingerprint($0.label, after: "Currently paired key ", file: file, line: line)
        }
    }

    private func accept(_ title: String, file: StaticString = #filePath, line: UInt = #line) {
        let accept = button(title)
        XCTAssertTrue(accept.exists, "\(title) is offered", file: file, line: line)
        let before = counters()
        accept.tap()
        matchFace(file: file, line: line)
        XCTAssertTrue(waitForOutcome("Paired with \(Self.macName)"), "paired", file: file, line: line)
        XCTAssertEqual(
            counters(), before.adding(prompts: 1, matches: 1, keyAgreements: 0),
            "one Face ID pins it", file: file, line: line
        )
    }

    /// Every key under Paired Macs, top to bottom.
    private func pairedKeys(file: StaticString = #filePath, line: UInt = #line) -> [String] {
        let keys = app.staticTexts.matching(identifier: "paired-mac-key")
        XCTAssertTrue(reveal(keys.firstMatch, fromTop: true), "the paired Macs", file: file, line: line)
        var found: [String] = []
        for _ in 0..<3 {
            for element in keys.allElementsBoundByIndex where element.exists {
                let key = fingerprint(element.label, after: "Mac key ", file: file, line: line)
                if !found.contains(key) { found.append(key) }
            }
            scrollDown()
        }
        return found
    }

    private func fingerprint(
        _ label: String,
        after prefix: String,
        file: StaticString,
        line: UInt
    ) -> String {
        XCTAssertTrue(label.hasPrefix(prefix), "\(label) starts with \(prefix)", file: file, line: line)
        return String(label.dropFirst(prefix.count))
    }
}
