import ConvenientSecurity
import Foundation
import LocalAuthentication

// A buyer's install finishes from the signed package and `csec setup`
// (csec-0.39.10): setup says first whether this Mac can take the touch every
// approval needs, finds `csec` on PATH through the package's link, and offers
// the sudo review from the package's payload only when there is one, Touch ID
// can approve its live check, and the installed review is missing, unsound or
// not the package's build.

func packagePayloadTests() {
    print("\n# Package payload: Touch ID readiness, csec on PATH, setup's sudo review offer")
    touchIDReadinessTests()
    commandLinkTests()
    payloadMatchTests()
    sudoReviewOfferTests()
}

private func touchIDReadinessTests() {
    check(TouchIDReadiness.classify(available: true, errorCode: nil) == .ready,
          "Touch ID readiness: an evaluable policy is ready")
    let expected: [(LAError.Code, TouchIDReadiness)] = [
        (.biometryNotAvailable, .noSensor),
        (.biometryDisconnected, .noSensor),
        (.biometryNotPaired, .noSensor),
        (.biometryNotEnrolled, .noEnrolledFinger),
        (.biometryLockout, .lockedOut),
        (.passcodeNotSet, .noPassword),
    ]
    for (code, readiness) in expected {
        check(TouchIDReadiness.classify(available: false, errorCode: code.rawValue) == readiness,
              "Touch ID readiness: LAError \(code.rawValue) reads as \(readiness)")
    }
    check(TouchIDReadiness.classify(available: false, errorCode: LAError.Code.invalidContext.rawValue)
            == .unrecognised(code: LAError.Code.invalidContext.rawValue),
          "Touch ID readiness: an unexpected code is named, not guessed at")
    let unusable: [TouchIDReadiness] = [.noSensor, .noEnrolledFinger, .lockedOut, .noPassword, .unrecognised(code: -1)]
    check(TouchIDReadiness.ready.canApprove && unusable.allSatisfy { !$0.canApprove },
          "Touch ID readiness: only a ready sensor can approve")
    check(unusable.allSatisfy { !$0.problem.isEmpty && $0.remedy.contains("csec setup") },
          "Touch ID readiness: every unusable state says what is wrong and how to come back to setup")
    check(TouchIDReadiness.noSensor.problem.contains("Magic Keyboard with Touch ID")
            && TouchIDReadiness.noSensor.problem.contains("lid"),
          "Touch ID readiness: no sensor names the keyboard and the closed lid")
    check(TouchIDReadiness.consequence.contains("no request can be approved")
            && TouchIDReadiness.consequence.contains("sudo review off"),
          "Touch ID readiness: the consequence says nothing can be approved and the sudo review stays off")
}

private func commandLinkTests() {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("cs-selftest-command-link-\(getpid())", isDirectory: true)
    try? FileManager.default.removeItem(at: directory)
    try! FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let launcher = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    let link = directory.appendingPathComponent("csec").path

    check(CommandLinkState.inspect(linkPath: link, launcherPath: launcher) == .missing,
          "csec on PATH: no file there is missing")
    check(CommandLinkState.missing.failsDoctor, "csec on PATH: a missing link fails doctor")

    try! FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: launcher)
    check(CommandLinkState.inspect(linkPath: link, launcherPath: launcher) == .linked,
          "csec on PATH: a link naming the installed launcher is csec's")
    check(!CommandLinkState.linked.failsDoctor, "csec on PATH: the package's link passes doctor")

    try! FileManager.default.removeItem(atPath: link)
    try! FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: "/opt/elsewhere/csec")
    let elsewhere = CommandLinkState.inspect(linkPath: link, launcherPath: launcher)
    check(elsewhere == .linksElsewhere("/opt/elsewhere/csec") && !elsewhere.failsDoctor
            && elsewhere.rowValue.contains("/opt/elsewhere/csec"),
          "csec on PATH: a link elsewhere is named and only warns, since the package left it alone")

    try! FileManager.default.removeItem(atPath: link)
    try! Data("#!/bin/sh\n".utf8).write(to: URL(fileURLWithPath: link))
    let other = CommandLinkState.inspect(linkPath: link, launcherPath: launcher)
    check(other == .otherFile && !other.failsDoctor,
          "csec on PATH: another program holding the name only warns")
}

private func payloadMatchTests() {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("cs-selftest-sudo-payload-\(getpid())", isDirectory: true)
    try? FileManager.default.removeItem(at: directory)
    try! FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    func file(_ name: String, _ text: String) -> String {
        let path = directory.appendingPathComponent(name).path
        try! Data(text.utf8).write(to: URL(fileURLWithPath: path))
        return path
    }
    let installedModule = file("installed-module", "module build 2")
    let installedHelper = file("installed-helper", "helper build 2")
    let packageModule = file("package-module", "module build 2")
    let packageHelper = file("package-helper", "helper build 2")
    let absent = directory.appendingPathComponent("absent").path

    check(SudoReviewPayloadMatch.compare(
            installedModule: installedModule, installedHelper: installedHelper,
            packageModule: packageModule, packageHelper: packageHelper) == .matches,
          "sudo payload: the package's exact bytes installed match")
    let newerHelper = file("package-helper-newer", "helper build 3")
    check(SudoReviewPayloadMatch.compare(
            installedModule: installedModule, installedHelper: installedHelper,
            packageModule: packageModule, packageHelper: newerHelper) == .differs,
          "sudo payload: a helper that is not the package's differs")
    check(SudoReviewPayloadMatch.compare(
            installedModule: absent, installedHelper: absent,
            packageModule: packageModule, packageHelper: packageHelper) == .differs,
          "sudo payload: nothing installed differs from a package that carries the review")
    check(SudoReviewPayloadMatch.compare(
            installedModule: installedModule, installedHelper: installedHelper,
            packageModule: absent, packageHelper: packageHelper) == .noPackagePayload,
          "sudo payload: without the package's payload there is nothing to compare")

    let rootOwned = "/usr/bin/true"
    check(PackagePayload.isRootOwnedFile(rootOwned) && !PackagePayload.isRootOwnedFile(installedModule)
            && !PackagePayload.isRootOwnedFile(absent),
          "package payload: setup runs only a root-owned regular file")
}

private func sudoReviewOfferTests() {
    let healthy = SudoIntegrationState.healthy(codeDirectoryHash: "0123456789abcdef0123")
    func decide(
        _ state: SudoIntegrationState, _ payload: SudoReviewPayloadMatch,
        installer: Bool = true, touchID: TouchIDReadiness = .ready
    ) -> SetupSudoReviewOffer {
        SetupSudoReviewOffer.decide(state: state, payload: payload, packageInstallerPresent: installer, touchID: touchID)
    }
    check(decide(.notInstalled, .differs) == .install,
          "sudo review offer: not installed, with the package's payload, is offered")
    check(decide(healthy, .matches) == .current && decide(healthy, .noPackagePayload, installer: false) == .current,
          "sudo review offer: a sound review that is the package's build, or with no package to compare, is current")
    check(decide(healthy, .differs) == .update,
          "sudo review offer: a sound review that is not the package's build is offered as an update")
    check(decide(.helperMissing, .differs) == .repair(.helperMissing),
          "sudo review offer: an active review that will not hand off is offered as a repair")
    check(decide(.helperSignatureUnreadable, .differs) == .current,
          "sudo review offer: an unreadable signature is undetermined, so no touch is asked for on a guess")
    check(decide(.notInstalled, .differs, touchID: .noEnrolledFinger) == .needsTouchID(.noEnrolledFinger)
            && decide(healthy, .differs, touchID: .noSensor) == .needsTouchID(.noSensor),
          "sudo review offer: nothing is offered while Touch ID cannot approve the live check")
    check(decide(healthy, .matches, touchID: .noSensor) == .current,
          "sudo review offer: a current review stays current without Touch ID; nothing needs approving")
    check(decide(.notInstalled, .noPackagePayload, installer: false) == .noPackage(.notInstalled)
            && decide(.notInstalled, .differs, installer: false) == .noPackage(.notInstalled),
          "sudo review offer: without the package's installer and payload, setup names the checkout route")
}
