import XCTest

/// How cards hold up: the largest accessibility text size, a small screen
/// (bin/ci runs on the smallest Face ID iPhone its runtime offers), long
/// metadata, and a Mac name built to mislead.
final class PresentationUITests: ApprovalUITestCase {
    /// `SimulatedMac.lookalikeName` as the phone must show it: its
    /// right-to-left override and its newline each replaced with U+FFFD.
    static let lookalikeShown = "Lookalike Mac\u{FFFD}kooBcaM\u{FFFD}Approve everything"
    static let headlineTail = "# end of a very long command line"

    func testLargestTextSizeStacksTheDecisionButtons() {
        launchSetUp(textSize: Self.largestTextSize)
        inject("SSH sign-in to an unknown host")

        XCTAssertTrue(reveal(text("Host: Unknown host"), fromTop: true), "the host")
        XCTAssertTrue(reveal(text("UNKNOWN HOST")), "the unknown-host label")
        XCTAssertTrue(reveal(text("Sign in as deploy")), "the remote user")
        let duration = button(containing: "This sign-in only")
        XCTAssertTrue(reveal(duration), "the duration menu")
        assertWithinScreenWidth(duration, "duration menu")

        let approve = approveButton()
        let deny = denyButton()
        XCTAssertTrue(reveal(deny), "Deny")
        XCTAssertTrue(approve.exists, "Approve")
        XCTAssertLessThanOrEqual(
            approve.frame.maxY, deny.frame.minY,
            "at an accessibility size Approve and Deny are stacked, each on its own line"
        )
        assertWithinScreenWidth(approve, "Approve")
        assertWithinScreenWidth(deny, "Deny")

        deny.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Denied (Simulator). The simulated Mac accepted the signed denial"))
    }

    /// A settings change's lines wrap inside the card at the largest text
    /// size, however long the hook's name.
    func testSettingsChangeLinesWrapAtTheLargestTextSize() {
        launchSetUp(textSize: Self.largestTextSize)
        inject("New Claude Code hook to acknowledge")
        let change = app.descendants(matching: .any).matching(identifier: "settings-change").firstMatch
        XCTAssertTrue(reveal(change, fromTop: true), "the first change")
        assertWithinScreenWidth(change, "a change line")
        let approve = approveButton()
        XCTAssertTrue(reveal(approve), "Approve")
        assertWithinScreenWidth(approve, "Approve")
        keepScreenshot("settings change: largest text size")
    }

    /// Secrets are drawn as the Mac panel draws them: an account and its one
    /// vault share the source line, each item is one label in its source's
    /// colour with its fields beside it, and a store's key is a label under
    /// its own source.
    func testSecretsAreATreeOfLabelsColouredBySource() {
        launchSetUp()
        inject("Secret access: choices, notes, warnings")
        XCTAssertTrue(
            reveal(text("1Password · acme.1password.eu, Infrastructure"), fromTop: true),
            "the account and its one vault share the source line"
        )
        let item = app.staticTexts.matching(identifier: "secret-label-teal").firstMatch
        XCTAssertTrue(item.exists, "a 1Password item is a teal label")
        XCTAssertEqual(item.label, "AWS deploy", "the label names the item")
        XCTAssertEqual(
            app.staticTexts.matching(NSPredicate(format: "label == %@", "AWS deploy")).count, 1,
            "the item is named once however many of its fields are released"
        )
        XCTAssertTrue(text("access key id · secret access key").exists, "its fields share its row")
        keepScreenshot("secret tree: 1Password item")

        inject("Secret access + restore, with cold unlock")
        let key = app.staticTexts.matching(identifier: "secret-label-purple").firstMatch
        XCTAssertTrue(reveal(key, fromTop: true), "a native key is a purple label")
        XCTAssertEqual(key.label, "GITHUB TOKEN", "the label names the key, its underscore read as a space")
        XCTAssertTrue(text("csec · this Mac, default").exists, "the store shares its source's line")
        keepScreenshot("secret tree: native key")
    }

    /// A language client's request: the headline is the reason its program
    /// wrote, and under it the command line the Mac read for that program,
    /// so a request that is not what its reason says can be seen to be.
    func testLanguageClientRequestShowsTheProgramsCommandLine() {
        launchSetUp()
        inject("Secret access from a language client")
        XCTAssertTrue(
            reveal(text(containing: "harbor: read the relay on nimbus as harbord"), fromTop: true),
            "the reason the program wrote is the headline"
        )
        let command = app.descendants(matching: .any).matching(identifier: "requester-command").firstMatch
        XCTAssertTrue(reveal(command, fromTop: true), "the program's command line is on the card")
        XCTAssertTrue(command.label.contains("Process command line"), "it is labelled as the process's command line")
        XCTAssertTrue(command.label.contains(".venv/bin/pytest -q"), "it is the command the Mac read")
        assertWithinScreenWidth(command, "the command line wraps inside the card")
        keepScreenshot("language client: command line under the reason")

        let deny = denyButton()
        XCTAssertTrue(reveal(deny), "Deny")
        deny.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Denied (Simulator). The simulated Mac accepted the signed denial"))

        // A request whose headline is its own command carries no second one.
        inject("Secret access: choices, notes, warnings")
        XCTAssertTrue(reveal(text(containing: "terraform apply"), fromTop: true), "the command headline")
        XCTAssertFalse(
            app.descendants(matching: .any).matching(identifier: "requester-command").firstMatch.exists,
            "no process command line under a command headline"
        )
    }

    /// A request the Mac closes unanswered (a sudo, a coding agent's) says
    /// when, in the Mac panel's words, and counts down its last 30 seconds;
    /// one that waits as long as it takes says nothing. That a sent card
    /// drops it is `MailboxUITests`', where a sent card stays.
    func testDeadlineLineSaysWhenTheMacClosesTheRequest() {
        launchSetUp()
        let line = app.descendants(matching: .any).matching(identifier: "review-deadline").firstMatch

        inject("Secret access: choices, notes, warnings")
        XCTAssertTrue(reveal(text(containing: "terraform apply"), fromTop: true), "the card")
        XCTAssertFalse(line.exists, "a terminal's request, which waits as long as it takes, has no deadline line")
        let denyAccess = denyButton()
        XCTAssertTrue(reveal(denyAccess), "Deny")
        denyAccess.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Denied (Simulator)"))

        inject("sudo")
        XCTAssertTrue(reveal(line, fromTop: true), "a sudo card says when the Mac closes it")
        XCTAssertTrue(
            line.label.hasPrefix("If nobody answers by ")
                && line.label.hasSuffix(", this closes without approving anything."),
            "five minutes out it names the time, as the Mac panel does: \(line.label)"
        )
        assertWithinScreenWidth(line, "the deadline line wraps inside the card")
        let denySudo = denyButton()
        XCTAssertTrue(reveal(denySudo), "Deny")
        denySudo.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Denied (Simulator)"))

        inject("sudo closing in 29 seconds")
        XCTAssertTrue(reveal(line, fromTop: true), "a sudo about to close shows the countdown")
        // A loaded Simulator can take most of the 29 seconds to get here, so
        // any second of the countdown, or the closing line after it, is the
        // Mac's words; a countdown must then move on within its second.
        let first = line.label
        let closing = "Closing: nobody answered in time. Nothing was approved."
        let countdown = first.range(
            of: #"^Closes in [0-9]+ seconds? if nobody answers, without approving anything\.$"#,
            options: .regularExpression
        ) != nil
        XCTAssertTrue(countdown || first == closing, "inside its last 30 seconds the line counts down: \(first)")
        keepScreenshot("sudo: deadline countdown")
        if countdown {
            let moved = NSPredicate(format: "label != %@", first)
            XCTAssertEqual(
                XCTWaiter().wait(for: [expectation(for: moved, evaluatedWith: line)], timeout: 5), .completed,
                "the countdown's number drops as the seconds pass"
            )
        }
    }

    private func keepScreenshot(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    func testLongAccessFromALookalikeMacIsShownWholeAndNeutralized() {
        launchSetUp()
        inject("Long secret access from a lookalike Mac")

        assertLookalikeNameIsNeutralized()
        let headline = text(containing: Self.headlineTail)
        XCTAssertTrue(reveal(headline, fromTop: true), "the headline, to its last words")
        assertWithinScreenWidth(headline, "an unbroken token wraps inside the card")
        let collapsedHeight = headline.frame.height
        let showAll = button("Show all")
        XCTAssertTrue(reveal(showAll), "a long headline can be expanded")
        showAll.tap()
        XCTAssertTrue(button("Show less").waitForExistence(timeout: Self.appWork), "and collapsed again")
        XCTAssertGreaterThan(headline.frame.height, collapsedHeight, "expanding shows every line")

        let executable = text(containing: "node_modules/.bin/aws")
        XCTAssertTrue(reveal(executable), "the long executable path")
        assertWithinScreenWidth(executable, "executable path")

        // The last of the most scope options a review may carry, and the last
        // duration, with the longest title.
        let lastScope = button(beginningWith: "Scope 4:")
        XCTAssertTrue(reveal(lastScope), "the fourth scope option")
        lastScope.tap()
        XCTAssertTrue(lastScope.isSelected)
        let duration = button(containing: "While it runs")
        XCTAssertTrue(reveal(duration), "duration menu")
        duration.tap()
        let longest = button("Until csecd restarts, however long that takes on this Mac")
        XCTAssertTrue(longest.waitForExistence(timeout: Self.appWork), "the longest duration")
        longest.tap()

        let approve = approveButton(Self.lookalikeShown)
        XCTAssertTrue(reveal(approve), "Approve names the Mac as shown")
        assertWithinScreenWidth(approve, "Approve")
        approve.tap()
        matchFace()
        XCTAssertTrue(
            waitForOutcome("scope “Scope 4: a long description of what this covers"),
            "the long scope is the one signed"
        )
        XCTAssertTrue(
            text(containing: "for “Until csecd restarts, however long that takes on this Mac”").exists,
            "the long duration is the one signed"
        )
    }

    func testLongSSHFromALookalikeMacIsShownWholeAndNeutralized() {
        launchSetUp()
        inject("Long SSH sign-in from a lookalike Mac")

        assertLookalikeNameIsNeutralized()
        let host = text(containing: "(+14 more)")
        XCTAssertTrue(reveal(host, fromTop: true), "the host headline names two of 16 names and counts the rest")
        assertWithinScreenWidth(host, "host headline")
        let known = text(containing: "Known hosts: ")
        XCTAssertTrue(reveal(known), "every known name is listed")
        XCTAssertTrue(known.label.hasSuffix("bastion-16.internal.example.com"), "to the last one")
        XCTAssertTrue(reveal(text(containing: "Sign in as deploy-xxxxxxxx")), "the long remote user")
        let key = text(containing: "deploy@ci (rotated key)")
        XCTAssertTrue(reveal(key), "the long key label")
        assertWithinScreenWidth(key, "key label")
        XCTAssertTrue(reveal(text(containing: "csec://default/ssh/deploy-deploy-")), "the long reference")

        let deny = denyButton(Self.lookalikeShown)
        XCTAssertTrue(reveal(deny), "Deny names the Mac as shown")
        assertWithinScreenWidth(deny, "Deny")
        deny.tap()
        matchFace()
        XCTAssertTrue(waitForOutcome("Denied (Simulator). The simulated Mac accepted the signed denial"))
    }

    /// The Mac name reaches the screen and VoiceOver with its override and
    /// newline replaced, never as a reversed or second line.
    private func assertLookalikeNameIsNeutralized(file: StaticString = #filePath, line: UInt = #line) {
        let from = text("From \(Self.lookalikeShown)")
        XCTAssertTrue(reveal(from, fromTop: true), "the card names the Mac with U+FFFD in place of each control", file: file, line: line)
        let raw = app.descendants(matching: .any).matching(
            NSPredicate(format: "label CONTAINS %@ OR label CONTAINS %@", "\u{202E}", "kooBcaM\nApprove")
        )
        XCTAssertEqual(raw.count, 0, "no label carries the raw override or newline", file: file, line: line)
    }

    private func assertWithinScreenWidth(
        _ element: XCUIElement,
        _ what: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let screen = window.frame
        XCTAssertGreaterThanOrEqual(element.frame.minX, screen.minX, "\(what) starts on screen", file: file, line: line)
        XCTAssertLessThanOrEqual(element.frame.maxX, screen.maxX, "\(what) ends on screen", file: file, line: line)
    }
}
