import ConvenientSecurity
import Darwin
import Foundation

func sudoReviewParentTrustTests() async {
    print("\n# sudo review helper: authenticate its root parent before accepting input")
    let parent: pid_t = 123
    check(SudoReviewParentTrust.isTrusted(
        originalParent: parent, currentParent: { parent }, effectiveUID: { $0 == parent ? 0 : nil }
    ), "sudo parent trust: a live effective-root parent is accepted")
    for uid: uid_t? in [501, nil] {
        check(!SudoReviewParentTrust.isTrusted(
            originalParent: parent, currentParent: { parent }, effectiveUID: { _ in uid }
        ), "sudo parent trust: a non-root or unreadable parent is refused (\(String(describing: uid)))")
    }
    for invalid: pid_t in [-1, 0, 1] {
        var readUID = false
        let trusted = SudoReviewParentTrust.isTrusted(
            originalParent: invalid, currentParent: { invalid },
            effectiveUID: { _ in readUID = true; return 0 }
        )
        check(!trusted && !readUID, "sudo parent trust: invalid or orphan parent \(invalid) is refused before lookup")
    }
    check(!SudoReviewParentTrust.isTrusted(
        originalParent: parent, currentParent: { 1 }, effectiveUID: { _ in 0 }
    ), "sudo parent trust: reparenting before the lookup is refused")
    var parentReads = 0
    check(!SudoReviewParentTrust.isTrusted(
        originalParent: parent,
        currentParent: { parentReads += 1; return parentReads == 1 ? parent : 1 },
        effectiveUID: { _ in 0 }
    ), "sudo parent trust: reparenting during the lookup is refused")

    guard geteuid() != 0 else { return }
    // Read a real kernel record, with no privilege or daemon dependency.
    check(!SudoReviewParentTrust.isTrusted(originalParent: getppid()),
          "sudo parent trust: the real unprivileged parent is refused")
    // Apple's set-id top has the same effective-root / real-login-UID shape
    // as sudo. Exercise the real sysctl reader without a sudo or Touch ID ask;
    // only the parent relationship is injected for this lookup.
    let top = Process()
    top.executableURL = URL(fileURLWithPath: "/usr/bin/top")
    top.arguments = ["-l", "0", "-s", "1"]
    top.standardInput = FileHandle.nullDevice
    top.standardOutput = FileHandle.nullDevice
    top.standardError = FileHandle.nullDevice
    let topExit = ChildProcessExit(top)
    do {
        try top.run()
        var trusted = false
        for _ in 0..<100 {
            trusted = SudoReviewParentTrust.isTrusted(
                originalParent: top.processIdentifier, currentParent: { top.processIdentifier })
            if trusted { break }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        check(trusted, "sudo parent trust: a real set-id-root process is readable and accepted by effective UID")
        top.terminate()
        let exited = await topExit.wait(within: 5)
        if !exited {
            kill(top.processIdentifier, SIGKILL)
            _ = await topExit.wait(within: 5)
        }
        check(exited, "sudo parent trust: the set-id fixture exits")
    } catch {
        check(false, "sudo parent trust: the set-id fixture starts (\(error))")
    }
    let helper = (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0]))
        .deletingLastPathComponent().appendingPathComponent("csec-sudo-review")
    let request = SudoAuthorizationReviewRequest(
        submittedCommand: "sudo /usr/bin/true attacker-chosen", workingDirectory: "/tmp", terminal: "no tty")
    guard let frame = SudoAuthorizationReviewWire.encode(request) else {
        check(false, "sudo parent trust: the adversarial frame encodes")
        return
    }
    // An open, empty pipe proves rejection happens before a blocking read.
    // A complete valid frame proves decoding never authorizes the sender.
    for input: Data? in [nil, frame] {
        let child = Process()
        child.executableURL = helper
        let pipe = Pipe()
        let error = Pipe()
        child.standardInput = pipe
        child.standardOutput = FileHandle.nullDevice
        child.standardError = error
        let exit = ChildProcessExit(child)
        do {
            try child.run()
            try error.fileHandleForWriting.close()
            if let input {
                try pipe.fileHandleForWriting.write(contentsOf: input)
                try pipe.fileHandleForWriting.close()
            }
            let exited = await exit.wait(within: 5)
            if !exited {
                kill(child.processIdentifier, SIGKILL)
                _ = await exit.wait(within: 5)
            }
            let diagnostic = String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            check(exited && child.terminationStatus == 69
                  && diagnostic.contains(SudoReviewLog.line(.rejected(.untrustedParent, exitStatus: 69))),
                  "sudo parent trust: the real helper refuses \(input == nil ? "stdin held open" : "a valid forged frame") before any review")
        } catch {
            if child.isRunning { kill(child.processIdentifier, SIGKILL) }
            check(false, "sudo parent trust: the real helper rejection runs (\(error))")
        }
        try? pipe.fileHandleForWriting.close()
    }
}
