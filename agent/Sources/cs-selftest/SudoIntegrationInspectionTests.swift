import ConvenientSecurity
import Foundation

// `SudoIntegrationInspection` — the shared inspection behind HA-G11 and the
// `csec doctor` "Sudo review" row.
//
// The sudo review dialog is installed by its own stage of
// `packaging/bin/build-and-install.sh`, not by the .app, so reinstalling the app
// leaves a stale or absent helper behind while every other surface moves on. The
// inspection re-checks, from the outside, exactly what the PAM module's
// `csec_review_helper_is_protected()` and its SecCode validation require before
// it will hand a sudo prompt to csec.
//
// Fixtures are synthetic and value-free: fake mode/owner triples, a fake module
// image built only from the two NUL-terminated literals the real module embeds,
// and captured-shape `codesign` output. The one live case reads this Mac
// read-only and asserts invariants that hold on any machine.

// MARK: - Shared fixtures (also used by HostAuditTests_G for HA-G11)

enum SudoFixtures {
    static let rootDirectory = HostFilePermissions(mode: 0o755, ownerUID: 0, groupGID: 0)
    static let rootExecutable = HostFilePermissions(mode: 0o755, ownerUID: 0, groupGID: 0)
    static let groupWritable = HostFilePermissions(mode: 0o775, ownerUID: 0, groupGID: 0)
    static let userOwned = HostFilePermissions(mode: 0o755, ownerUID: 501, groupGID: 20)

    static let cdHash = "4d44a47062432a160b9188097b3991a7aa1fb030"

    /// A sudo_local with an active csec line (plus the stock pam_tid line that
    /// follows it on a real install).
    static let activeConfiguration = """
        # sudo_local: local config file which survives system update
        auth       sufficient     /usr/local/lib/pam/pam_csec_sudo.so
        auth       requisite      /usr/local/lib/pam/pam_csec_sudo.so review_guard
        auth       sufficient     pam_tid.so

        """

    /// The same file with the csec line commented out — the integration is off.
    static let commentedConfiguration = """
        # auth       sufficient     /usr/local/lib/pam/pam_csec_sudo.so
        auth       sufficient     pam_tid.so

        """

    /// A stand-in for the module image: the two NUL-terminated literals a real
    /// build embeds, surrounded by filler. Nothing here is ever echoed by the
    /// inspection — it only tests for the literals.
    static func moduleImage(
        helper: String = SudoIntegrationInspection.helperPath,
        identifier: String = SudoIntegrationInspection.helperIdentifier
    ) -> String {
        "\u{0}__TEXT\u{0}/usr/local/libexec\u{0}" + helper + "\u{0}" + identifier
            + "\u{0}review_guard\u{0}dyld_stub\u{0}"
    }

    /// Assemble a fake filesystem for the sudo integration. Every knob defaults
    /// to the healthy shape so a test names only what it perturbs.
    static func files(
        configuration: String? = activeConfiguration,
        moduleImage: String? = SudoFixtures.moduleImage(),
        modulePermissions: HostFilePermissions? = rootExecutable,
        helperPermissions: HostFilePermissions? = rootExecutable,
        directoryPermissions: [String: HostFilePermissions] = [:],
        symlinks: Set<String> = []
    ) -> FakeFileInspector {
        let directories = Set(
            SudoIntegrationInspection.moduleDirectories
                + SudoIntegrationInspection.helperDirectories)
        var permissions: [String: HostFilePermissions] = [:]
        for directory in directories {
            permissions[directory] = directoryPermissions[directory] ?? rootDirectory
        }
        permissions[SudoIntegrationInspection.modulePath] = modulePermissions
        permissions[SudoIntegrationInspection.helperPath] = helperPermissions

        var texts: [String: String] = [:]
        texts[SudoIntegrationInspection.pamConfigurationPath] = configuration
        texts[SudoIntegrationInspection.modulePath] = moduleImage

        return FakeFileInspector(
            texts: texts,
            perms: permissions,
            directories: directories,
            symlinks: symlinks)
    }

    /// Captured-shape `codesign -dvvv` output (the display goes to stderr).
    static func codesignDisplay(
        identifier: String = SudoIntegrationInspection.helperIdentifier,
        flags: String = "0x10000(runtime)",
        candidateHash: String = cdHash,
        hash: String = cdHash,
        teamIdentifier: String = SudoIntegrationInspection.teamIdentifier
    ) -> HostCommandResult {
        HostCommandResult(exitCode: 0, standardError: """
            Executable=/usr/local/libexec/csec-sudo-review
            Identifier=\(identifier)
            Format=Mach-O thin (arm64)
            CodeDirectory v=20500 size=9654 flags=\(flags) hashes=295+2 location=embedded
            CandidateCDHash sha256=\(candidateHash)
            CandidateCDHashFull sha256=\(candidateHash)ffeeddccbbaa99887766554433221100
            CDHash=\(hash)
            Signature size=9054
            Info.plist=not bound
            TeamIdentifier=\(teamIdentifier)
            Runtime Version=26.2.0
            Sealed Resources=none

            """)
    }

    /// The command fixtures for a helper that verifies and displays cleanly.
    static func commands(
        verify: HostCommandResult = HostCommandResult(exitCode: 0),
        display: HostCommandResult = SudoFixtures.codesignDisplay()
    ) -> [String: HostCommandResult] {
        [
            SudoIntegrationInspection.verifyCommandLabel: verify,
            SudoIntegrationInspection.displayCommandLabel: display,
        ]
    }
}

// MARK: - Tests

func sudoIntegrationInspectionTests() async {
    await notInstalledTests()
    await healthyTests()
    await deadlineGuardTests()
    await teamSigningTests()
    await moduleDefectTests()
    await helperDefectTests()
    await signatureDefectTests()
    summaryTests()
    await liveInspectionTest()
}

private func inspect(
    _ files: FakeFileInspector,
    _ commands: [String: HostCommandResult] = SudoFixtures.commands()
) async -> SudoIntegrationState {
    await SudoIntegrationInspection.inspect(
        files: files, commands: FakeCommandRunner(commands))
}

private func notInstalledTests() async {
    check(await inspect(SudoFixtures.files(configuration: nil)) == .notInstalled,
          "sudo inspection: no /etc/pam.d/sudo_local -> notInstalled")
    check(await inspect(SudoFixtures.files(configuration: SudoFixtures.commentedConfiguration))
            == .notInstalled,
          "sudo inspection: a commented-out csec PAM line -> notInstalled")
    // A sudo_local with only the stock Touch ID line is not csec's integration.
    check(await inspect(SudoFixtures.files(configuration: "auth sufficient pam_tid.so\n"))
            == .notInstalled,
          "sudo inspection: pam_tid.so alone -> notInstalled")
    // Nothing below the PAM line is read when the integration is inactive: a
    // missing module and helper still report notInstalled, never a defect.
    let bare = FakeFileInspector()
    check(await inspect(bare) == .notInstalled,
          "sudo inspection: an empty filesystem -> notInstalled, not a defect")
}

private func healthyTests() async {
    let state = await inspect(SudoFixtures.files())
    check(state == .healthy(codeDirectoryHash: SudoFixtures.cdHash),
          "sudo inspection: protected module + hardened helper -> healthy with the CDHash")
    check(state.isHealthy && !state.isDefect,
          "sudo inspection: healthy is not a defect")

    // The CDHash comes from the `CDHash=` line, not the `CandidateCDHash` line
    // above it. The two are equal on a real binary; they differ here only to
    // pin down which line the parser reads.
    let distinct = await inspect(
        SudoFixtures.files(),
        SudoFixtures.commands(display: SudoFixtures.codesignDisplay(
            candidateHash: "0000000000000000000000000000000000000000",
            hash: "1111111111111111111111111111111111111111")))
    check(distinct == .healthy(codeDirectoryHash: "1111111111111111111111111111111111111111"),
          "sudo inspection: the CDHash= line wins over CandidateCDHash")
}

private func teamSigningTests() async {
    let adhoc = await inspect(
        SudoFixtures.files(),
        SudoFixtures.commands(display: SudoFixtures.codesignDisplay(
            flags: "0x10002(adhoc,runtime)", teamIdentifier: "not set")))
    check(adhoc == .helperNotTeamSigned && adhoc.isDefect,
          "sudo inspection: an ad-hoc helper is a defect — csecd will not relay its reviews to the phone")
    let otherTeam = await inspect(
        SudoFixtures.files(),
        SudoFixtures.commands(display: SudoFixtures.codesignDisplay(teamIdentifier: "ABCDE12345")))
    check(otherTeam == .helperNotTeamSigned,
          "sudo inspection: a helper signed by another team is not the product helper")
    check(SudoIntegrationState.helperNotTeamSigned.summary.contains("csec setup"),
          "sudo inspection: the not-team-signed summary names setup")
}

private func deadlineGuardTests() async {
    let review = "auth sufficient \(SudoIntegrationInspection.modulePath)"
    let guardEntry = "auth requisite \(SudoIntegrationInspection.modulePath) review_guard"
    let tid = "auth sufficient pam_tid.so"
    for lines in [
        [review, tid], [guardEntry, review, tid], [review, tid, guardEntry],
        [review, guardEntry, guardEntry, tid], [review, guardEntry],
        [tid, review, guardEntry], [review, "auth optional pam_permit.so", guardEntry, tid],
        [review, guardEntry.replacingOccurrences(of: "requisite", with: "optional"), tid],
    ] {
        let state = await inspect(SudoFixtures.files(configuration: lines.joined(separator: "\n")))
        check(state == .deadlineGuardMissing && state.isDefect,
              "sudo inspection: absent, bypassed or misordered expiry guard is unhealthy")
    }
    check(await inspect(SudoFixtures.files(configuration:
        [review, "# a comment is not a PAM factor", guardEntry, tid].joined(separator: "\n")))
        == .healthy(codeDirectoryHash: SudoFixtures.cdHash),
        "sudo inspection: whitespace and comments preserve the active deadline guard")
    check(SudoIntegrationState.deadlineGuardMissing.summary.contains("csec setup"),
          "sudo inspection: missing deadline guard points to setup")
    check(await inspect(SudoFixtures.files(moduleImage:
        SudoFixtures.moduleImage().replacingOccurrences(of: "review_guard\u{0}", with: "")))
        == .deadlineGuardMissing,
        "sudo inspection: a guarded policy with an older module still needs reinstalling")
}

private func moduleDefectTests() async {
    check(await inspect(SudoFixtures.files(moduleImage: nil, modulePermissions: nil))
            == .moduleMissing,
          "sudo inspection: an active PAM line with no installed module -> moduleMissing")

    // The literals are NUL-terminated, so the spike's longer path and identifier
    // cannot satisfy the canonical ones.
    let spike = await inspect(SudoFixtures.files(moduleImage: SudoFixtures.moduleImage(
        helper: SudoIntegrationInspection.spikeHelperPath,
        identifier: SudoIntegrationInspection.spikeIdentifier)))
    check(spike == .moduleNamesAnotherHelper(spike: true),
          "sudo inspection: a module naming csec-sudo-review-spike -> moduleNamesAnotherHelper(spike)")

    let other = await inspect(SudoFixtures.files(moduleImage: SudoFixtures.moduleImage(
        helper: "/usr/local/libexec/csec-sudo-review-next",
        identifier: "com.example.other")))
    check(other == .moduleNamesAnotherHelper(spike: false),
          "sudo inspection: a module naming an unrelated helper -> moduleNamesAnotherHelper")

    check(await inspect(SudoFixtures.files(moduleImage: "")) == .moduleNamesAnotherHelper(spike: false),
          "sudo inspection: a module naming nothing recognizable -> moduleNamesAnotherHelper")

    if case let .moduleUnsafe(reason) = await inspect(
        SudoFixtures.files(modulePermissions: SudoFixtures.groupWritable)) {
        check(reason.contains(SudoIntegrationInspection.modulePath)
                && reason.contains("group- or other-writable"),
              "sudo inspection: a group-writable module -> moduleUnsafe naming the path")
    } else {
        check(false, "sudo inspection: a group-writable module -> moduleUnsafe")
    }

    if case let .moduleUnsafe(reason) = await inspect(SudoFixtures.files(
        directoryPermissions: ["/usr/local/lib/pam": SudoFixtures.groupWritable])) {
        check(reason.contains("/usr/local/lib/pam"),
              "sudo inspection: a group-writable PAM directory -> moduleUnsafe naming it")
    } else {
        check(false, "sudo inspection: a group-writable PAM directory -> moduleUnsafe")
    }

    if case .moduleUnsafe = await inspect(
        SudoFixtures.files(symlinks: [SudoIntegrationInspection.modulePath])) {
        check(true, "sudo inspection: a symlinked module -> moduleUnsafe")
    } else {
        check(false, "sudo inspection: a symlinked module -> moduleUnsafe")
    }
}

private func helperDefectTests() async {
    check(await inspect(SudoFixtures.files(helperPermissions: nil)) == .helperMissing,
          "sudo inspection: a current module with no installed helper -> helperMissing")

    if case let .helperUnsafePath(reason) = await inspect(
        SudoFixtures.files(helperPermissions: SudoFixtures.userOwned)) {
        check(reason.contains(SudoIntegrationInspection.helperPath)
                && reason.contains("not root-owned"),
              "sudo inspection: a user-owned helper -> helperUnsafePath naming the path")
    } else {
        check(false, "sudo inspection: a user-owned helper -> helperUnsafePath")
    }

    if case let .helperUnsafePath(reason) = await inspect(
        SudoFixtures.files(helperPermissions: SudoFixtures.groupWritable)) {
        check(reason.contains("group- or other-writable"),
              "sudo inspection: a group-writable helper -> helperUnsafePath")
    } else {
        check(false, "sudo inspection: a group-writable helper -> helperUnsafePath")
    }

    if case let .helperUnsafePath(reason) = await inspect(SudoFixtures.files(
        directoryPermissions: ["/usr/local/libexec": SudoFixtures.groupWritable])) {
        check(reason.contains("/usr/local/libexec"),
              "sudo inspection: a group-writable /usr/local/libexec -> helperUnsafePath")
    } else {
        check(false, "sudo inspection: a group-writable /usr/local/libexec -> helperUnsafePath")
    }

    if case let .helperUnsafePath(reason) = await inspect(
        SudoFixtures.files(symlinks: [SudoIntegrationInspection.helperPath])) {
        check(reason.contains("symlink"),
              "sudo inspection: a symlinked helper -> helperUnsafePath")
    } else {
        check(false, "sudo inspection: a symlinked helper -> helperUnsafePath")
    }

    if case let .helperUnsafePath(reason) = await inspect(SudoFixtures.files(
        helperPermissions: HostFilePermissions(mode: 0o644, ownerUID: 0, groupGID: 0))) {
        check(reason.contains("not executable by its owner"),
              "sudo inspection: a non-executable helper -> helperUnsafePath")
    } else {
        check(false, "sudo inspection: a non-executable helper -> helperUnsafePath")
    }
}

private func signatureDefectTests() async {
    check(await inspect(SudoFixtures.files(), SudoFixtures.commands(
            verify: HostCommandResult(exitCode: 1, standardError: "code object is not signed at all")))
            == .helperSignatureInvalid,
          "sudo inspection: codesign --verify --strict failing -> helperSignatureInvalid")

    check(await inspect(SudoFixtures.files(), SudoFixtures.commands(
            display: SudoFixtures.codesignDisplay(flags: "0x2(adhoc)")))
            == .helperNotHardened,
          "sudo inspection: a signature without the runtime flag -> helperNotHardened")

    check(await inspect(SudoFixtures.files(), SudoFixtures.commands(
            display: SudoFixtures.codesignDisplay(
                identifier: SudoIntegrationInspection.spikeIdentifier)))
            == .helperIdentifierMismatch(found: SudoIntegrationInspection.spikeIdentifier),
          "sudo inspection: a spike-identifier helper -> helperIdentifierMismatch")

    // codesign unavailable is undetermined, not a defect — it must never be
    // reported as a healthy install either.
    let unreadable = await inspect(SudoFixtures.files(), SudoFixtures.commands(
        verify: .unavailable, display: .unavailable))
    check(unreadable == .helperSignatureUnreadable && !unreadable.isHealthy
            && !unreadable.isDefect,
          "sudo inspection: codesign unavailable -> helperSignatureUnreadable, neither healthy nor a defect")

    check(await inspect(SudoFixtures.files(), SudoFixtures.commands(
            display: HostCommandResult(exitCode: 0, standardError: "Executable=/usr/local/libexec/csec-sudo-review\n")))
            == .helperSignatureUnreadable,
          "sudo inspection: display output with no Identifier line -> helperSignatureUnreadable")
}

private func summaryTests() {
    // Every summary is a value-free single line naming the canonical path or
    // identifier, safe to print in a status row and inside audit evidence.
    let states: [SudoIntegrationState] = [
        .notInstalled, .healthy(codeDirectoryHash: SudoFixtures.cdHash),
        .moduleMissing, .moduleUnsafe(reason: "/usr/local is not root-owned"),
        .moduleUnreadable, .deadlineGuardMissing, .moduleNamesAnotherHelper(spike: true),
        .moduleNamesAnotherHelper(spike: false), .helperMissing,
        .helperUnsafePath(reason: "/usr/local/libexec is group- or other-writable"),
        .helperSignatureInvalid, .helperSignatureUnreadable,
        .helperIdentifierMismatch(found: SudoIntegrationInspection.spikeIdentifier),
        .helperNotHardened, .helperNotTeamSigned,
    ]
    for state in states {
        check(!state.summary.isEmpty && !state.summary.contains("\n"),
              "sudo inspection: every state has a one-line summary [\(state)]")
        check(ReviewDisplay.sanitized(state.summary) == state.summary,
              "sudo inspection: every summary is already sanitized [\(state)]")
        // StatusRenderer gives a row value ~53 columns on an 80-column terminal,
        // so the compact form must not be truncated away there.
        check(!state.rowValue.isEmpty && state.rowValue.count <= 50
                && !state.rowValue.contains("\n"),
              "sudo inspection: every state has a row value that fits a narrow terminal [\(state)]")
        check(ReviewDisplay.sanitized(state.rowValue) == state.rowValue,
              "sudo inspection: every row value is already sanitized [\(state)]")
    }
    check(SudoIntegrationState.notInstalled.rowValue == "not installed",
          "sudo inspection: the not-installed row reads \"not installed\"")
    check(SudoIntegrationState.healthy(codeDirectoryHash: SudoFixtures.cdHash).rowValue
            .contains(SudoFixtures.cdHash.prefix(16)),
          "sudo inspection: the healthy row carries a CDHash prefix")
    check(SudoIntegrationState.healthy(codeDirectoryHash: SudoFixtures.cdHash).summary
            .contains(SudoFixtures.cdHash),
          "sudo inspection: the healthy summary carries the CDHash")
    check(SudoIntegrationState.helperMissing.summary
            .contains(SudoIntegrationInspection.helperPath),
          "sudo inspection: the helperMissing summary names the expected helper path")
}

// MARK: - Live, read-only inspection of this Mac

/// Runs the real inspection against the installed integration. Skipped (not
/// failed) when no csec PAM line is active. The assertions are invariants that
/// hold on any machine — a machine with a correct install passes them as a
/// healthy verdict, and one whose helper is absent or stale passes them as a
/// named defect.
private func liveInspectionTest() async {
    let files = SystemFileInspector()
    guard SudoIntegrationInspection.isActive(files: files) else {
        print("skip - sudo inspection (live): no active csec line in \(SudoIntegrationInspection.pamConfigurationPath)")
        return
    }
    let state = await SudoIntegrationInspection.inspect(
        files: files, commands: SystemCommandRunner())
    print("     - sudo inspection (live): \(state.summary)")

    check(state != .notInstalled,
          "sudo inspection (live): an active csec PAM line is never reported as not-installed")
    if !files.fileExists(SudoIntegrationInspection.helperPath) {
        check(state.isDefect,
              "sudo inspection (live): an active integration whose canonical helper is absent is a defect")
    }
    if case let .healthy(hash) = state {
        check(files.isRegularFile(SudoIntegrationInspection.helperPath) && !hash.isEmpty,
              "sudo inspection (live): a healthy verdict implies an installed helper and a CDHash")
    }

    // The same reading through the catalog check, against real readers: HA-G11
    // is what `csec audit` renders, and it must agree with the inspection.
    let context = HostAuditContext(
        commands: SystemCommandRunner(),
        privileged: StubPrivilegedHostOps(),
        tcc: FakeTCCReader(),
        files: files,
        environment: [:],
        baseline: InMemoryBaselineStore())
    guard let finding = await evaluateAudit("HA-G11", in: DomainG_Accounts.checks, context) else { return }
    print("     - HA-G11 (live): \(finding.status.rawValue) — \(finding.evidence)")
    check(finding.status != .notApplicable,
          "HA-G11 (live): an active csec PAM line is never notApplicable")
    check(state.isDefect ? finding.status == .fail : finding.status != .fail,
          "HA-G11 (live): the catalog check agrees with the inspection verdict")
}
