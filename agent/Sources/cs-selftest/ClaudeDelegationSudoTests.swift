import ConvenientSecurity
import Foundation

// Delegated sudo, the parts that need no process tree: decoding the PAM
// module's rendering of sudo's argv, reading sudo's options, and matching an
// argv whose redacted arguments are known only up to a prefix. The chain and
// the gates are tested through the service in ClaudeDelegationTests.

func sudoDelegationRuleTests() {
    print("\n# Delegated sudo: the PAM module's argv, sudo's options, redacted matching")
    sudoCommandDisplayTests()
    sudoInvocationTests()
    sudoRedactedMatchTests()
    liveSetIDRootRecordTests()
}

private func known(_ text: String) -> ShellArgumentElement { .known(Array(text.utf8)) }

private func sudoCommandDisplayTests() {
    // Exactly what `csec_build_redacted_command` writes.
    check(SudoCommandDisplay.arguments("sudo") == [], "sudo display: bare sudo has no arguments")
    check(SudoCommandDisplay.arguments("sudo fs_usage -w -f pathname -t 8")
            == ["fs_usage", "-w", "-f", "pathname", "-t", "8"].map(known),
          "sudo display: plain arguments decode as written")
    check(SudoCommandDisplay.arguments(#"sudo "a b" "x\"y" "\$HOME" "\`id\`" "back\\slash" "\x09tab" """#)
            == [known("a b"), known("x\"y"), known("$HOME"), known("`id`"), known("back\\slash"), known("\ttab"), known("")],
          "sudo display: quoted arguments decode their escapes, \\xHH bytes and the empty argument")
    check(SudoCommandDisplay.arguments(#"sudo "caf\xC3\xA9""#) == [known("café")],
          "sudo display: bytes outside ASCII decode from \\xHH")
    check(SudoCommandDisplay.arguments(#"sudo "launchctl print 'system/x'""#) == [known("launchctl print 'system/x'")],
          "sudo display: a single quote stays literal inside double quotes")

    // Anything the module would never write is refused, so a display maps to
    // exactly one argv.
    for (label, display) in [
        ("a quoted plain argument", #"sudo "abc""#),
        ("two spaces", "sudo  a"),
        ("a trailing space", "sudo a "),
        ("a missing separator", "sudox"),
        ("another program", "su do"),
        ("an unterminated quote", #"sudo "abc"#),
        ("an unknown escape", #"sudo "\q""#),
        ("lower-case hex", #"sudo "\x0a""#),
        ("a short hex escape", #"sudo "\x0""#),
        ("an escaped printable byte", #"sudo "\x41""#),
        ("a raw non-ASCII byte", "sudo é"),
        ("a raw tab", "sudo \"a\tb\""),
        ("a quote inside a plain argument", #"sudo a"b"#),
        ("an unescaped dollar", #"sudo "$HOME""#),
    ] {
        check(SudoCommandDisplay.arguments(display) == nil, "sudo display: \(label) is not the module's rendering")
    }
    let maximum = SudoCommandDisplay.maximumArguments
    check(SudoCommandDisplay.arguments("sudo" + String(repeating: " a", count: maximum))?.count == maximum
            && SudoCommandDisplay.arguments("sudo" + String(repeating: " a", count: maximum + 1)) == nil,
          "sudo display: at most the module's 64 arguments")

    // The module's two redactions, and the active-secret matcher's label.
    check(SudoCommandDisplay.arguments(#"sudo tool "[csec:secret-like]""#)
            == [known("tool"), .redacted(prefix: [])],
          "sudo display: a whole redacted argument is known not at all")
    check(SudoCommandDisplay.arguments(#"sudo "TOKEN=[csec:secret-like]" tool"#)
            == [.redacted(prefix: Array("TOKEN=".utf8)), known("tool")],
          "sudo display: NAME=[csec:secret-like] is known up to its =")
    check(SudoCommandDisplay.arguments(#"sudo tool "--token=[csec:secret-3]x""#)
            == [known("tool"), .redacted(prefix: Array("--token=".utf8))],
          "sudo display: a released value's label hides everything after it")
}

private func sudoInvocationTests() {
    func scan(_ words: [String]) -> SudoInvocation.Scan { SudoInvocation.scan(words.map(known)) }
    for words in [
        ["fs_usage", "-w"], ["-u", "root", "id"], ["-uroot", "id"], ["-H", "-u", "nobody", "id"],
        ["-v"], ["-k"], ["-k", "id"], ["-n", "id"], ["-h"], ["-hhost", "id"],
        ["VAR=1", "id"], ["-u", "root", "VAR=1", "id"], ["--user=root", "id"], ["--user", "root", "id"],
        ["--non-interactive", "id"], ["--us=root", "id"], ["--", "-E"], ["id", "-E"], ["-uE", "id"],
        ["-p", "prompt: ", "id"], ["-C", "3", "id"], ["-D", "/tmp", "id"], ["-T", "30", "id"], ["-b", "id"],
        ["timeout", "8", "tcpdump", "-n"], ["/usr/bin/true"], [],
        ["-h", "MacBook.local", "id"], ["-h", "MacBook.local", "-u", "root", "id"], ["-h", "VAR=1", "id"],
    ] {
        check(scan(words) == .accepted, "sudo options: \(words.joined(separator: " ")) is accepted")
    }
    for (words, refused) in [
        (["-E", "id"], "-E"), (["-sE"], "-s"), (["-Hs"], "-s"), (["-i"], "-i"), (["-e", "/etc/hosts"], "-e"),
        (["--preserve-env", "id"], "--preserve-env"), (["--preserve-env=PATH", "id"], "--preserve-env"),
        (["--preserve-e", "id"], "--preserve-env"), (["--login"], "--login"), (["--shell"], "--shell"),
        (["--sh"], "--shell"), (["--edit", "/etc/hosts"], "--edit"),
        (["VAR=1", "-E", "id"], "-E"), (["-u", "root", "-i"], "-i"),
        // A bare -h takes the next word as the remote host and parsing goes
        // on (sudo's got_host_flag), so what follows the host is sudo's.
        (["-h", "MacBook.local", "-E", "make", "install"], "-E"), (["-h", "MacBook.local", "-s"], "-s"),
        (["-h", "MacBook.local", "-e", "/etc/hosts"], "-e"), (["-h", "-E", "id"], "-E"),
    ] {
        check(scan(words) == .refused(refused), "sudo options: \(words.joined(separator: " ")) is refused as \(refused)")
    }
    // `--pres` could be --preserve-env or --preserve-groups: getopt_long
    // refuses an ambiguous abbreviation, and so does csec.
    for words in [["-X", "id"], ["--frobnicate", "id"], ["--s", "id"], ["--pres", "id"], ["--help=x"]] {
        check(scan(words) == .refused("an option csec can't read"),
              "sudo options: \(words.joined(separator: " ")) cannot be read, so it is refused")
    }
    check(SudoInvocation.scan([.redacted(prefix: []), known("id")]) == .refused("an option csec can't read"),
          "sudo options: an argument redacted where an option may stand is refused")
    check(SudoInvocation.scan([known("-p"), .redacted(prefix: []), known("id")]) == .accepted,
          "sudo options: a redacted option argument is skipped")
    check(SudoInvocation.scan([.redacted(prefix: Array("TOKEN=".utf8)), known("id")]) == .accepted,
          "sudo options: a redacted assignment is an assignment")
    check(SudoInvocation.scan([.redacted(prefix: Array("--preserve-env=".utf8)), known("id")]) == .refused("an option csec can't read"),
          "sudo options: a redacted word that starts with - is an option getopt reads first, never an assignment")
    check(SudoInvocation.scan([known("-h"), .redacted(prefix: Array("host".utf8)), known("-E"), known("id")])
            == .refused("an option csec can't read"),
          "sudo options: a redacted word after a bare -h cannot be read, so it is refused")
    check(SudoInvocation.scan([known("id"), .redacted(prefix: [])]) == .accepted,
          "sudo options: nothing after the command is sudo's")
}

private func sudoRedactedMatchTests() {
    func command(_ text: String) -> ShellSimpleCommand? { LauncherScript.simpleCommands(in: text)?.first }
    guard let anyWord = command(#"sudo tool $TOKEN"#),
          let quoted = command(#"sudo tool "$TOKEN""#),
          let prefixed = command(#"sudo tool "--token=$TOKEN""#),
          let suffixed = command(#"sudo tool "$TOKEN"x"#),
          let literal = command(#"sudo tool '[csec:secret-like]'"#) else {
        check(false, "sudo matching: the fixtures parse")
        return
    }
    let whole: [ShellArgumentElement] = [known("tool"), .redacted(prefix: [])]
    check(anyWord.matches(elements: whole) && quoted.matches(elements: whole),
          "sudo matching: a redacted argument matches an expansion")
    check(!literal.matches(elements: whole),
          "sudo matching: a redacted argument never matches literal text, even the marker itself")
    check(!suffixed.matches(elements: whole),
          "sudo matching: a pattern that must end in a literal cannot be checked against a redacted argument")
    check(prefixed.matches(elements: [known("tool"), .redacted(prefix: Array("--token=".utf8))]),
          "sudo matching: a pattern ending in an expansion matches a redacted argument whose known prefix it covers")
    check(!prefixed.matches(elements: [known("tool"), .redacted(prefix: Array("--tok".utf8))])
            && !prefixed.matches(elements: [known("tool"), .redacted(prefix: Array("--other=".utf8))]),
          "sudo matching: a known prefix the pattern does not cover is no match")
    check(quoted.matches(elements: [known("tool"), known("value")]) && !literal.matches(elements: [known("tool"), known("value")]),
          "sudo matching: known arguments match as ever")
}

/// What csecd reads of a set-id root process, measured on this Mac with
/// `/usr/bin/top` (setuid root, and like sudo signed as part of the OS) in
/// sudo's place: its kernel record answers, while `proc_pidinfo` does not, so
/// the sudo walk cannot use `incarnation(of:)` for sudo itself.
private func liveSetIDRootRecordTests() {
    let provider = LiveClaudeSessionFactProvider()
    let top = Process()
    top.executableURL = URL(fileURLWithPath: "/usr/bin/top")
    top.arguments = ["-l", "30", "-s", "1"]
    top.standardOutput = FileHandle.nullDevice
    top.standardError = FileHandle.nullDevice
    do {
        try top.run()
    } catch {
        check(false, "sudo kernel record: /usr/bin/top starts (\(error))")
        return
    }
    defer {
        top.terminate()
        top.waitUntilExit()
    }
    // setuid takes effect at exec; wait for it rather than racing it.
    var record: KernelProcessRecord?
    for _ in 0..<100 {
        record = provider.kernelRecord(of: top.processIdentifier)
        if record?.effectiveUID == 0, record?.executablePath == "/usr/bin/top" { break }
        usleep(20_000)
    }
    check(record?.effectiveUID == 0 && record?.realUID == getuid() && record?.parent == getpid()
            && record?.executablePath == "/usr/bin/top" && record?.isValidPlatformBinary == true,
          "sudo kernel record: a live setuid-root process reports root, this user, its parent, its path and an OS signature (\(String(describing: record)))")
    check(provider.incarnation(of: top.processIdentifier) == nil
            && provider.argv(of: ProcessIncarnation(pid: top.processIdentifier, startTime: record?.process.startTime ?? 0)) == nil,
          "sudo kernel record: the kernel refuses this user that process's proc_pidinfo and argv")
    let me = provider.kernelRecord(of: getpid())
    check(me != nil && me?.process == provider.incarnation(of: getpid()) && me?.effectiveUID == getuid(),
          "sudo kernel record: for this user's own process the record's start time is the incarnation's")
}
