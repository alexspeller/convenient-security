import CSecuritySupport
import Darwin
import Foundation

// Delegated approval of a sudo that Claude Code auto mode ran.
//
// The sudo PAM module runs inside sudo and spawns the sudo review helper,
// which asks csecd (`sudo_delegation`) before it builds a window. csecd
// cannot read sudo's argv: sudo runs with euid 0, and the kernel refuses
// another user's `KERN_PROCARGS2` (xnu `sysctl_procargsx`) and
// `PROC_PIDTBSDINFO` (`proc_security_policy` compares effective uids). The
// argv it judges is the one the PAM module rendered for the panel, decoded
// here; everything else (which process is sudo, its parent, the chain up to
// the `csec ai` and Claude Code) csecd reads from the kernel itself.

// MARK: - The PAM module's command display

/// sudo's argv as the PAM module renders it for the review frame
/// (`csec_build_redacted_command`, packaging/sudo/pam_csec_sudo.c): `sudo`,
/// then for each argument after argv[0] one space and either the argument
/// itself, when every byte is one of `[A-Za-z0-9_@%+=:,./-]`, or the argument
/// in double quotes, with `\`, `"`, `$` and `` ` `` backslash-escaped and every
/// byte outside printable ASCII written `\xHH` (`""` for an empty argument).
/// That rendering is one-to-one, so the display decodes to exactly the argv
/// the module rendered.
///
/// Before rendering, the module replaces arguments that look secret with
/// `[csec:secret-like]` (the whole argument, or what follows `NAME=`), and the
/// active-secret matcher it runs them through replaces a released value with
/// `[csec:secret-N]`. An argument holding either marker is known only up to
/// the marker (`ShellArgumentElement.redacted`).
public enum SudoCommandDisplay {
    /// The PAM module renders at most this many arguments
    /// (`CSEC_ARGUMENT_MAX`); a longer argv reaches no helper.
    public static let maximumArguments = 64

    static let redactionMarker = Array("[csec:secret-".utf8)

    /// sudo's argv after argv[0], or nil when `display` is not exactly what the
    /// PAM module renders for some argv.
    public static func arguments(_ display: String) -> [ShellArgumentElement]? {
        guard let raw = rawArguments(display), raw.count <= maximumArguments,
              render(raw) == display else { return nil }
        return raw.map(element)
    }

    /// The argument bytes, before redaction is recognised.
    static func rawArguments(_ display: String) -> [[UInt8]]? {
        let bytes = Array(display.utf8)
        let head = Array("sudo".utf8)
        guard bytes.starts(with: head) else { return nil }
        var index = head.count
        var arguments: [[UInt8]] = []
        while index < bytes.count {
            guard bytes[index] == UInt8(ascii: " "), index + 1 < bytes.count else { return nil }
            index += 1
            if bytes[index] == UInt8(ascii: "\"") {
                index += 1
                var argument: [UInt8] = []
                var closed = false
                while index < bytes.count {
                    let byte = bytes[index]
                    if byte == UInt8(ascii: "\"") {
                        closed = true
                        index += 1
                        break
                    }
                    guard byte >= 0x20, byte <= 0x7e else { return nil }
                    if byte != UInt8(ascii: "\\") {
                        argument.append(byte)
                        index += 1
                        continue
                    }
                    guard index + 1 < bytes.count else { return nil }
                    let escaped = bytes[index + 1]
                    if "\\\"$`".utf8.contains(escaped) {
                        argument.append(escaped)
                        index += 2
                    } else if escaped == UInt8(ascii: "x"), index + 3 < bytes.count,
                              let high = hexValue(bytes[index + 2]), let low = hexValue(bytes[index + 3]) {
                        argument.append(high << 4 | low)
                        index += 4
                    } else {
                        return nil
                    }
                }
                guard closed else { return nil }
                arguments.append(argument)
            } else {
                var argument: [UInt8] = []
                while index < bytes.count, bytes[index] != UInt8(ascii: " ") {
                    argument.append(bytes[index])
                    index += 1
                }
                guard !argument.isEmpty else { return nil }
                arguments.append(argument)
            }
        }
        return arguments
    }

    /// `csec_build_redacted_command` for these arguments.
    static func render(_ arguments: [[UInt8]]) -> String {
        var output = Array("sudo".utf8)
        for argument in arguments {
            output.append(UInt8(ascii: " "))
            if argument.isEmpty {
                output += Array("\"\"".utf8)
            } else if argument.allSatisfy(isPlain) {
                output += argument
            } else {
                output.append(UInt8(ascii: "\""))
                for byte in argument {
                    if byte >= 0x20, byte <= 0x7e {
                        if "\\\"$`".utf8.contains(byte) { output.append(UInt8(ascii: "\\")) }
                        output.append(byte)
                    } else {
                        output += Array(String(format: "\\x%02X", byte).utf8)
                    }
                }
                output.append(UInt8(ascii: "\""))
            }
        }
        return String(decoding: output, as: UTF8.self)
    }

    static func element(_ argument: [UInt8]) -> ShellArgumentElement {
        guard let marker = firstIndex(of: redactionMarker, in: argument) else { return .known(argument) }
        return .redacted(prefix: Array(argument[..<marker]))
    }

    private static func isPlain(_ byte: UInt8) -> Bool {
        (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
            || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
            || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            || "_@%+=:,./-".utf8.contains(byte)
    }

    /// Upper-case hex only: the module writes `%02X`.
    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return byte - UInt8(ascii: "A") + 10
        default: return nil
        }
    }

    private static func firstIndex(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard haystack.count >= needle.count else { return nil }
        for start in 0...(haystack.count - needle.count)
        where haystack[start..<(start + needle.count)].elementsEqual(needle) {
            return start
        }
        return nil
    }
}

// MARK: - sudo's options

/// sudo's options and environment assignments, read as sudo 1.9.17p2's
/// `parse_args` reads them (src/parse_args.c: `getopt_long` with
/// `+Aa:BbC:c:D:Eeg:Hh::iKklNnPp:R:r:SsT:t:U:u:Vv`, the long options beside
/// it, and a `NAME=value` that starts with neither `/` nor `=` taken as an
/// environment assignment until `--` or the command).
///
/// Auto mode never approves the options that hand root something the
/// classifier never read: `-E`/`--preserve-env` (the agent's whole
/// environment), `-s`/`--shell` (the shell `$SHELL` names), `-i`/`--login`
/// (a login shell) and `-e`/`--edit` (sudoedit). Everything else on the line
/// is text the classifier read.
public enum SudoInvocation {
    public enum Scan: Sendable, Equatable {
        case accepted
        /// A refused option by its own name (`-E`, `--preserve-env`, even
        /// when typed `--pres` or `--preserve-env=PATH`), or `unreadable`:
        /// never text from the argv.
        case refused(String)
    }

    static let unreadable = "an option csec can't read"

    enum Argument {
        case none, required, optional
    }

    static let refusedShortOptions: Set<UInt8> = Set("Eeis".utf8)
    static let shortOptionArguments: [UInt8: Argument] = {
        var table: [UInt8: Argument] = [:]
        for byte in "ABbHKklNnPSVv".utf8 { table[byte] = Argument.none }
        for byte in "aCcDgpRrTtUu".utf8 { table[byte] = .required }
        table[UInt8(ascii: "h")] = .optional
        for byte in "Eeis".utf8 { table[byte] = Argument.none }
        return table
    }()

    static let longOptions: [(name: String, argument: Argument, refused: Bool)] = [
        ("background", .none, false), ("preserve-env", .optional, true), ("edit", .none, true),
        ("set-home", .none, false), ("login", .none, true), ("remove-timestamp", .none, false),
        ("list", .none, false), ("preserve-groups", .none, false), ("shell", .none, true),
        ("other-user", .required, false), ("validate", .none, false), ("askpass", .none, false),
        ("auth-type", .required, false), ("bell", .none, false), ("close-from", .required, false),
        ("login-class", .required, false), ("chdir", .required, false), ("group", .required, false),
        ("help", .none, false), ("host", .required, false), ("reset-timestamp", .none, false),
        ("no-update", .none, false), ("non-interactive", .none, false), ("prompt", .required, false),
        ("chroot", .required, false), ("role", .required, false), ("stdin", .none, false),
        ("command-timeout", .required, false), ("type", .required, false), ("user", .required, false),
        ("version", .none, false),
    ]

    /// Reads sudo's arguments up to the command. An option csec cannot read
    /// exactly (unknown, an ambiguous abbreviation, or one the PAM module
    /// redacted) is refused like a refused option.
    public static func scan(_ arguments: [ShellArgumentElement]) -> Scan {
        var index = 0
        while index < arguments.count {
            let bytes: [UInt8]
            switch arguments[index] {
            case let .known(known):
                bytes = known
            case let .redacted(prefix):
                // What follows the prefix is unknown. getopt reads a word
                // that starts with `-` as an option before sudo ever asks
                // whether it is an assignment (`--preserve-env=…` is an
                // option), so such a word, or one with nothing known, cannot
                // be read; an assignment's name is whole before its `=`.
                if prefix.isEmpty || prefix.first == UInt8(ascii: "-") { return .refused(unreadable) }
                if isAssignment(prefix) {
                    index += 1
                    continue
                }
                return .accepted
            }
            if bytes == Array("--".utf8) { return .accepted }
            if bytes.count >= 2, bytes[0] == UInt8(ascii: "-"), bytes[1] == UInt8(ascii: "-") {
                let body = Array(bytes.dropFirst(2))
                let nameBytes = body.split(separator: UInt8(ascii: "="), maxSplits: 1, omittingEmptySubsequences: false)[0]
                let name = String(decoding: nameBytes, as: UTF8.self)
                let hasValue = body.contains(UInt8(ascii: "="))
                let exact = longOptions.filter { $0.name == name }
                let candidates = exact.isEmpty ? longOptions.filter { $0.name.hasPrefix(name) } : exact
                guard !name.isEmpty, candidates.count == 1, let option = candidates.first else {
                    return .refused(unreadable)
                }
                if option.refused { return .refused("--" + option.name) }
                switch option.argument {
                case .none:
                    if hasValue { return .refused(unreadable) }
                    index += 1
                case .optional:
                    index += 1
                case .required:
                    index += hasValue ? 1 : 2
                }
                continue
            }
            if bytes == Array("-h".utf8) {
                // `parse_args`' `got_host_flag`: a bare `-h` takes the next
                // word as the remote host when that word is neither an option
                // nor an assignment, and option parsing goes on after it
                // (`sudo -h host -E make` preserves the environment).
                // Otherwise `-h` asks for help.
                guard index + 1 < arguments.count else { return .accepted }
                switch arguments[index + 1] {
                case let .known(next):
                    index += next.first == UInt8(ascii: "-") || isAssignment(next) ? 1 : 2
                case .redacted:
                    return .refused(unreadable)
                }
                continue
            }
            if bytes.count >= 2, bytes[0] == UInt8(ascii: "-") {
                var position = 1
                var consumed = 1
                while position < bytes.count {
                    let letter = bytes[position]
                    guard let argument = shortOptionArguments[letter] else { return .refused(unreadable) }
                    if refusedShortOptions.contains(letter) {
                        return .refused("-" + String(decoding: [letter], as: UTF8.self))
                    }
                    if argument == .required {
                        // The rest of the word, or the next word.
                        if position == bytes.count - 1 { consumed = 2 }
                        break
                    }
                    if argument == .optional { break }  // `-h`: attached only.
                    position += 1
                }
                index += consumed
                continue
            }
            if isAssignment(bytes) {
                index += 1
                continue
            }
            // The command.
            return .accepted
        }
        return .accepted
    }

    /// sudo's `is_envar`: not starting with `/` or `=`, holding an `=`. For a
    /// redacted argument, `bytes` is the known prefix, so its `=` is whole.
    static func isAssignment(_ bytes: [UInt8]) -> Bool {
        guard let first = bytes.first, first != UInt8(ascii: "/"), first != UInt8(ascii: "=") else { return false }
        return bytes.contains(UInt8(ascii: "="))
    }
}

// MARK: - The sudo process

/// What the kernel tells any user about a process: `KERN_PROC_PID`'s parent,
/// effective and real user, start time and whether it has exec'd,
/// `proc_pidpath` and the CS_OPS_STATUS flags. For a set-id root process such as sudo these are all
/// there is: the kernel refuses another user its `proc_pidinfo`
/// (`PROC_PIDTBSDINFO`), its argv and its task name port. Measured on macOS
/// 26.2 against setuid-root `/usr/bin/top`: every read here answers.
public struct KernelProcessRecord: Sendable, Equatable {
    /// The pid and start time, on the same microsecond clock as
    /// `ProcessIncarnation` everywhere else (both are the kernel's `p_start`).
    public let process: ProcessIncarnation
    public let parent: pid_t
    public let effectiveUID: uid_t
    public let realUID: uid_t
    public let executablePath: String?
    public let codeSigningFlags: UInt32?

    public init(
        process: ProcessIncarnation, parent: pid_t, effectiveUID: uid_t, realUID: uid_t,
        executablePath: String?, codeSigningFlags: UInt32?
    ) {
        self.process = process
        self.parent = parent
        self.effectiveUID = effectiveUID
        self.realUID = realUID
        self.executablePath = executablePath
        self.codeSigningFlags = codeSigningFlags
    }

    /// CS_VALID and CS_PLATFORM_BINARY (xnu bsd/sys/codesign.h).
    static let validFlag: UInt32 = 0x0000_0001
    static let platformBinaryFlag: UInt32 = 0x0400_0000
    /// P_EXEC (xnu bsd/sys/proc.h), in `kp_proc.p_flag`.
    static let execFlag: Int32 = 0x0000_4000

    /// Valid and signed as part of the OS.
    public var isValidPlatformBinary: Bool {
        guard let flags = codeSigningFlags else { return false }
        return flags & Self.validFlag != 0 && flags & Self.platformBinaryFlag != 0
    }

    /// The kernel's record of `pid`, with its path and signing status read
    /// between two identical `KERN_PROC_PID` reads, so they belong to the same
    /// process with the same parent.
    static func live(_ pid: pid_t) -> KernelProcessRecord? {
        guard pid > 0, let before = kernelProcess(pid) else { return nil }
        var buffer = [CChar](repeating: 0, count: 4 * 1_024)
        let written = cs_proc_path(pid, &buffer, Int32(buffer.count))
        var flags: UInt32 = 0
        let status = cs_proc_code_status(pid, &flags)
        guard let after = kernelProcess(pid), after == before else { return nil }
        let path = written > 0 ? String(cString: buffer) : ""
        return KernelProcessRecord(
            process: ProcessIncarnation(pid: pid, startTime: before.startTime),
            parent: before.parent,
            effectiveUID: before.effectiveUID,
            realUID: before.realUID,
            executablePath: path.isEmpty ? nil : path,
            codeSigningFlags: status == 0 ? flags : nil
        )
    }

    private struct Entry: Equatable {
        let parent: pid_t
        let effectiveUID: uid_t
        let realUID: uid_t
        let startTime: UInt64
        /// Whether the process has exec'd since it was forked (`P_EXEC`),
        /// compared only: an exec between the two reads changes it, so the
        /// path and signing status read between them are refused.
        let hasExecuted: Bool
    }

    private static func kernelProcess(_ pid: pid_t) -> Entry? {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0,
              size == MemoryLayout<kinfo_proc>.stride, info.kp_proc.p_pid == pid else { return nil }
        let start = info.kp_proc.p_un.__p_starttime
        guard start.tv_sec > 0 else { return nil }
        return Entry(
            parent: info.kp_eproc.e_ppid,
            effectiveUID: info.kp_eproc.e_ucred.cr_uid,
            realUID: info.kp_eproc.e_pcred.p_ruid,
            startTime: UInt64(start.tv_sec) * 1_000_000 + UInt64(start.tv_usec),
            hasExecuted: info.kp_proc.p_flag & execFlag != 0
        )
    }
}

// MARK: - The chain

/// One process between sudo and the `csec ai` that ran the approved text.
struct SudoChainLink: Sendable {
    let process: ProcessIncarnation
    let path: String?
    let argv: [String]?
}

/// What may stand between sudo and the `csec ai` above it, and how sudo must
/// match the approved text.
///
/// sudo's parent is the program shell for a command among others
/// (`X; Y`, `X | grep`, `X && Y`, `$(X)`), the `csec ai` itself for a text
/// that is the one command (zsh execs it), or `timeout`. Anything else (node,
/// python, a script, `xargs`, a git hook, a subshell) is a process the
/// classifier never read, and declines `sudo_indirect`.
enum SudoChainRule {
    static let sudoPath = "/usr/bin/sudo"

    enum Kind: Equatable {
        case programShell
        case timeout(String)
        case other(String)
    }

    /// `parents[0]` is sudo's parent; the last is the one directly below
    /// the `csec ai`.
    static func kind(of link: SudoChainLink, isTop: Bool) -> Kind {
        let path = link.path ?? ""
        let name = (path as NSString).lastPathComponent
        if isTop, path == AICommandExec.shellPath, let argv = link.argv, argv.count >= 2,
           ClaudeDelegationService.bytesEqual(argv[1], AICommandExec.shellFlag) {
            return .programShell
        }
        if name == "timeout" || name == "gtimeout" { return .timeout(name) }
        return .other(name.isEmpty ? "an unknown process" : name)
    }

    /// Whether `kinds` is one of the shapes a text runs sudo in: nothing (the
    /// `csec ai` exec'd it), the program shell, or `timeout` under either.
    static func shapeFailure(_ kinds: [Kind]) -> DelegationDecline? {
        let allowed: Bool
        if kinds.isEmpty || kinds == [.programShell] {
            allowed = true
        } else if case .timeout = kinds[0] {
            allowed = kinds.count == 1 || (kinds.count == 2 && kinds[1] == .programShell)
        } else {
            allowed = false
        }
        guard !allowed else { return nil }
        // Name a process the rule does not know first, nearest sudo first;
        // else the timeout out of place.
        for case let .other(name) in kinds { return .sudoIndirect(name) }
        for case let .timeout(name) in kinds { return .sudoIndirect(name) }
        return .sudoIndirect("zsh")
    }

    /// The first failure, or nil. `arguments` is sudo's argv after argv[0]
    /// (`SudoCommandDisplay`), nil when the display did not decode;
    /// `program` the text the `csec ai` ran; `environment` what its program
    /// shell started from.
    static func structuralFailure(
        parents: [SudoChainLink], arguments: [ShellArgumentElement]?, program: String?,
        environment: SSHChainAnchorEnvironment
    ) -> DelegationDecline? {
        let kinds = parents.indices.map { kind(of: parents[$0], isTop: $0 == parents.count - 1) }
        if let failure = shapeFailure(kinds) { return failure }
        // ZDOTDIR points the program shell's startup files somewhere else.
        if let failure = SSHChainRule.shellSteering(environment) { return failure }
        guard let arguments else { return .commandMismatch(process: "sudo") }
        guard let program, let commands = LauncherScript.simpleCommands(in: program) else {
            return .commandMismatch(process: "sudo")
        }
        if case let .timeout(name)? = kinds.first {
            // timeout runs exactly the rest of its argv: that must be sudo
            // with exactly these arguments, and timeout a command of the text.
            guard let argv = parents[0].argv,
                  commands.contains(where: { command in
                      guard let commandName = command.name else { return false }
                      let base = (commandName as NSString).lastPathComponent
                      return (base == "timeout" || base == "gtimeout") && command.matches(argumentTail: Array(argv.dropFirst()))
                  }) else {
                return .commandMismatch(process: name)
            }
            guard let command = SSHChainRule.timeoutCommand(argv).map(SSHChainRule.execedCommand),
                  let first = command.first, (first as NSString).lastPathComponent == "sudo",
                  command.count - 1 == arguments.count,
                  zip(command.dropFirst(), arguments).allSatisfy({ typed, element in
                      element == .known(Array(typed.utf8))
                  }) else {
                return .commandMismatch(process: "sudo")
            }
        } else {
            let matched = commands.contains { command in
                guard let commandName = command.name else { return false }
                return (commandName as NSString).lastPathComponent == "sudo" && command.matches(elements: arguments)
            }
            guard matched else { return .commandMismatch(process: "sudo") }
        }
        if case let .refused(option) = SudoInvocation.scan(arguments) {
            return .sudoOption(option)
        }
        return nil
    }
}

// MARK: - Wire

/// `sudo_delegation`: the sudo review helper asks, before it builds a panel,
/// whether Claude Code auto mode's approval of the command stands in for it.
/// `command` is the PAM module's display of sudo's argv, exactly as the frame
/// carried it. The helper's pid and start time, and so which sudo it serves,
/// are never taken from here: csecd reads them from the kernel.
public struct SudoDelegationRequest: Codable, Sendable, Equatable {
    public let requestID: String
    public let command: String

    public init(requestID: UUID = UUID(), command: String) {
        self.requestID = requestID.uuidString.lowercased()
        self.command = command
    }

    public var isWellFormed: Bool {
        UUID(uuidString: requestID)?.uuidString.lowercased() == requestID
            && !command.isEmpty && command.utf8.count <= SudoRemoteReviewRequest.maximumCommandBytes
            && !command.utf8.contains(0)
    }
}

/// csecd's answer to `sudo_delegation`.
public struct SudoDelegationAnswer: Codable, Sendable, Equatable {
    public enum Decision: String, Codable, Sendable {
        /// Auto mode's approval stands: the helper ends the authentication
        /// with no panel.
        case approved
        /// A Claude Code sudo csecd did not approve: the panel shows `note`.
        case declined
        /// Not a Claude Code sudo, or delegation is off: the panel as ever.
        case notApplicable = "not_applicable"
    }

    public static let maximumNoteBytes = 1_024
    public static let maximumPairingLineBytes = 512

    public let decision: Decision
    /// For `declined`: "Auto mode didn't approve this: …".
    public let note: String?
    /// For `declined`, when approving the panel would let auto mode run sudo
    /// in the project from now on: the line that says so
    /// (`SudoPairingOffer.line`). The panel shows it whole; an approval of
    /// that panel is recorded with `sudo_pairing`.
    public let pairingLine: String?

    public init(decision: Decision, note: String? = nil, pairingLine: String? = nil) {
        self.decision = decision
        self.note = decision == .declined ? note : nil
        self.pairingLine = decision == .declined ? pairingLine : nil
    }

    public static let notApplicable = SudoDelegationAnswer(decision: .notApplicable)

    public var isWellFormed: Bool {
        func fits(_ value: String?, _ maximum: Int) -> Bool {
            value.map { !$0.isEmpty && $0.utf8.count <= maximum && !$0.utf8.contains(0) } ?? true
        }
        return (decision == .declined || (note == nil && pairingLine == nil))
            && fits(note, Self.maximumNoteBytes) && fits(pairingLine, Self.maximumPairingLineBytes)
    }
}

/// What a declined sudo's panel shows below its footnote, kept by csecd for
/// the phone's copy of that panel.
public struct SudoDelegationNote: Sendable, Equatable {
    public let note: String
    public let pairingLine: String?

    public init(note: String, pairingLine: String?) {
        self.note = note
        self.pairingLine = pairingLine
    }
}

/// The line a sudo panel shows when approving it would let Claude Code auto
/// mode run sudo in the project (csec-2rno.1: once per project). A sudo panel
/// offers no scope or lifetime, so the line always shows with it.
public struct SudoPairingOffer: Sendable, Equatable {
    public let projectName: String
    /// When the pairing starts to count, for a decline pairing cannot end
    /// (`DelegationDecline.pairingCondition`); nil when it counts at once.
    public let condition: String?

    public init(projectName: String, condition: String? = nil) {
        self.projectName = ReviewDisplay.bounded(ReviewDisplay.sanitized(projectName), maxBytes: 128)
        self.condition = condition.map { ReviewDisplay.bounded(ReviewDisplay.sanitized($0), maxBytes: 256) }
    }

    public var line: String {
        "Approving also lets Claude Code auto mode run sudo in \(projectName) \(condition ?? "until you revoke it")"
    }
}

/// `sudo_pairing`: the sudo review helper's report that a human approved its
/// panel on this Mac while it showed the pairing line csecd offered. csecd
/// records it only for the helper it made the offer to (`recordSudoApproval`);
/// a phone approval csecd records itself.
public struct SudoPairingRequest: Codable, Sendable, Equatable {
    public let requestID: String

    public init(requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
    }

    public var isWellFormed: Bool { UUID(uuidString: requestID)?.uuidString.lowercased() == requestID }
}

extension Request {
    /// Whether this is one of the sudo review helper's delegation requests:
    /// its question, or its report of an approval that paired.
    public var isSudoDelegation: Bool {
        switch self {
        case .sudoDelegation, .sudoPairing: return true
        default: return false
        }
    }
}

// MARK: - The helper

/// The sudo review helper's round trips to csecd before and after its panel
/// (`sudo_delegation`, `sudo_terminal`, `sudo_pairing`, `sudo_review_end`), each bounded: the
/// panel waits on them, so a csecd that does not answer within its deadline
/// leaves the panel as it would be with no csecd.
public struct SudoDelegationClient: Sendable {
    /// csecd answers in tens of milliseconds; the helper's own check of
    /// csecd's code identity can take longer while trustd is loaded.
    public static let deadline: Duration = .milliseconds(2_500)
    /// csecd's terminal lookup may wait out `TerminalTitleQuery.timeout` on a
    /// slow terminal application, on top of the identity check.
    public static let terminalDeadline: Duration =
        .milliseconds(Int(TerminalTitleQuery.timeout * 1_000)) + deadline
    /// The end report goes last, after the review closed: on the deadline's
    /// path the module's own deadline is at most `closingMargin` away, so it
    /// gets well under that.
    public static let endDeadline: Duration = .milliseconds(1_000)

    private let path: String
    private let serverTrustPolicy: AgentServerTrustPolicy
    private let deadline: Duration
    private let terminalDeadline: Duration

    public init(
        path: String, serverTrustPolicy: AgentServerTrustPolicy, deadline: Duration = Self.deadline,
        terminalDeadline: Duration = Self.terminalDeadline
    ) {
        self.path = path
        self.serverTrustPolicy = serverTrustPolicy
        self.deadline = deadline
        self.terminalDeadline = terminalDeadline
    }

    /// The installed csecd. An approval ends a root authentication with no
    /// panel, so a release helper takes it only from the product agent, as
    /// the phone leg does; the relaxed trust exists only in a debug build.
    public static var installed: SudoDelegationClient {
        #if DEBUG
        let trust: AgentServerTrustPolicy = .allowUnverifiedForTesting
        #else
        let trust: AgentServerTrustPolicy = .requireProductAgent
        #endif
        return SudoDelegationClient(path: AgentSocket.defaultPath(), serverTrustPolicy: trust)
    }

    /// Report a Mac approval of a panel that showed csecd's pairing line,
    /// within the same bound. False when csecd did not record it.
    public func pair(_ request: SudoPairingRequest) async -> Bool {
        await bounded(within: deadline, otherwise: false) { client, cancellation in
            client.sudoPairing(request, cancellation: cancellation)
        }
    }

    /// Report how the review ended, within `endDeadline`. False when csecd
    /// did not log it.
    public func end(_ request: SudoReviewEndRequest) async -> Bool {
        await bounded(within: Self.endDeadline, otherwise: false) { client, cancellation in
            client.sudoReviewEnd(request, cancellation: cancellation)
        }
    }

    public func ask(_ request: SudoDelegationRequest) async -> SudoDelegationAnswer {
        await bounded(within: deadline, otherwise: .notApplicable) { client, cancellation in
            client.sudoDelegation(request, cancellation: cancellation)
        }
    }

    /// csecd's name for the terminal tab the sudo came from, or nil.
    public func terminal(_ request: SudoTerminalRequest = SudoTerminalRequest()) async -> TerminalSessionContext? {
        await bounded(within: terminalDeadline, otherwise: nil) { client, cancellation in
            client.sudoTerminal(request, cancellation: cancellation)
        }
    }

    /// One blocking call on a thread of its own, answered by `otherwise` once
    /// `deadline` passes; the connection is then shut so the thread ends.
    private func bounded<Answer: Sendable>(
        within deadline: Duration, otherwise: Answer,
        _ call: @escaping @Sendable (AgentClient, AgentCallCancellation) -> Answer
    ) async -> Answer {
        let cancellation = AgentCallCancellation()
        let path = self.path
        let trust = self.serverTrustPolicy
        return await withTaskGroup(of: Answer?.self) { group in
            group.addTask {
                await withCheckedContinuation { continuation in
                    Thread.detachNewThread {
                        continuation.resume(returning: call(AgentClient(path: path, serverTrustPolicy: trust), cancellation))
                    }
                }
            }
            group.addTask { [deadline] in
                try? await Task.sleep(for: deadline)
                return nil
            }
            let first = await group.next() ?? nil
            cancellation.cancel()
            group.cancelAll()
            return first ?? otherwise
        }
    }
}
