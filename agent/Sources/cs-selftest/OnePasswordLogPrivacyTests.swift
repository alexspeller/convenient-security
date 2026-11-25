import Foundation
import OSLog
import ConvenientSecurity
import OnePasswordAdapter
import CSECBuildIdentity

/// The 1Password adapter writes to the unified log, which any process that can
/// run `log show` reads and every sysdiagnose copies. These checks drive the
/// real logging paths, then read this process's own log back the way `log
/// show` would present it: nothing that names a reference, vault, item or
/// account, and none of the bridge's stderr, may appear in the clear, while the
/// opaque tags that let lines be correlated must.
func onePasswordLogPrivacyTests() async {
    print("\n# 1Password unified-log privacy")

    onePasswordBridgeStderrClassificationTests()
    let run = UUID().uuidString.prefix(8).lowercased()
    let vault = "PrivacyVault\(run)"
    let item = "PrivacyItem\(run)"
    let missingItem = "PrivacyMissing\(run)"
    let alphaHost = "alpha-\(run).1password.com"
    let betaHost = "beta-\(run).1password.eu"
    let stderrMarker = "stderr-\(run)"
    let markers = [vault, item, missingItem, alphaHost, betaHost, stderrMarker, "value-\(run)"]

    let started = Date().addingTimeInterval(-1)
    let subsystem = CSECBuildIdentity.identifier
    let control = Logger(subsystem: subsystem, category: "onepassword-privacy-control")
    let controlMarker = "control-\(run)"
    control.notice("control \(controlMarker, privacy: .private)")

    let alpha = OnePasswordAccount(
        userID: "user-alpha-\(run)", accountID: "acct-alpha-\(run)",
        url: alphaHost, email: "alpha-\(run)@example.invalid"
    )
    let beta = OnePasswordAccount(
        userID: "user-beta-\(run)", accountID: "acct-beta-\(run)",
        url: betaHost, email: "beta-\(run)@example.invalid"
    )
    let found = try! SecretRef("op://\(vault)/\(item)/password")
    let missing = try! SecretRef("op://\(vault)/\(missingItem)/password")

    let runner = FakeOnePasswordCommandRunner()
    await runner.setAccounts(
        [(alpha.userID, alpha.url), (beta.userID, beta.url)], vaults: [:]
    )
    // Alpha's bridge cannot be made, with an error whose words name a vault
    // and an account; beta holds the vault, so the index selects it.
    let registry = FakeBackendRegistry { _ in
        FakeOnePasswordBackend(
            vaults: [OnePasswordVault(id: "v-\(run)", name: vault, isPersonal: false)],
            items: ["v-\(run)": [OnePasswordItemIdentity(id: "i-\(run)", title: item)]],
            values: [found.uri: "value-\(run)"]
        )
    }
    let make = registry.factory()
    let provider = OnePasswordProvider(
        cliPath: "/synthetic/op",
        configuration: OnePasswordConnectionConfiguration(
            keepaliveInterval: 4, sessionIdleWindow: 10, authenticationTimeout: 7,
            missRetryDelays: [0.001]
        ),
        makeBackend: { account in
            if account.userID == alpha.userID {
                throw OnePasswordError.vaultAmbiguous(vault: vault, accounts: [alpha.label])
            }
            return try make(account)
        },
        runCommand: { path, arguments, timeout in
            try await runner.run(path: path, arguments: arguments, timeout: timeout)
        },
        sleep: { _ in }
    )

    do {
        let resolved = try await provider.resolve(found, unlock: nil)
        check(resolved.value == Data("value-\(run)".utf8),
              "the privacy fixture resolves from the account that holds the vault")
    } catch {
        check(false, "the privacy fixture resolves (\(error))")
    }
    do {
        _ = try await provider.resolve(missing, unlock: nil)
        check(false, "a reference to a missing item fails")
    } catch {
        check(true, "a reference to a missing item fails")
    }
    await provider.shutdownBackends()

    #if DEBUG
    // A bridge process whose stderr names things, through the session's own
    // default sink: the unified log.
    do {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("csec-bridge-log-privacy-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let executable = directory.appendingPathComponent("bridge-fixture")
        let script = """
        #!/bin/sh
        IFS= read -r request || exit 1
        printf 'fixture: %s could not read %s\\n' '\(stderrMarker)' '\(vault)' >&2
        exit 3
        """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let previous = ProcessInfo.processInfo.environment["CSEC_OP_BRIDGE_PATH"]
        setenv("CSEC_OP_BRIDGE_PATH", executable.path, 1)
        defer {
            if let previous { setenv("CSEC_OP_BRIDGE_PATH", previous, 1) }
            else { unsetenv("CSEC_OP_BRIDGE_PATH") }
        }
        let session = OnePasswordBridgeSession(
            account: beta, executablePath: executable.path, requestTimeout: 30,
            outputDrainTimeout: 30
        )
        _ = try? await session.vaults()
        await session.shutdown()
    } catch {
        check(false, "the bridge log-privacy fixture starts (\(error))")
    }
    #endif

    let messages: [(category: String, text: String)]
    do {
        let store = try OSLogStore(scope: .currentProcessIdentifier)
        messages = try store.getEntries(at: store.position(date: started))
            .compactMap { $0 as? OSLogEntryLog }
            .filter { $0.subsystem == subsystem }
            .map { ($0.category, $0.composedMessage) }
    } catch {
        check(false, "this process's unified log can be read back (\(error))")
        return
    }
    let controlLines = messages.filter { $0.category == "onepassword-privacy-control" }.map(\.text)
    guard controlLines.contains("control <private>") else {
        // A Mac with private data logging turned on shows `.private` values
        // in the clear, so this readback cannot tell private from public
        // there; bin/ci's allowlist of `.public` interpolations still holds.
        print("note - this Mac logs private data in the clear (\(controlLines)); "
              + "the unified-log readback cannot check redaction here")
        return
    }
    let lines = messages.filter { $0.category == "onepassword" }.map(\.text)
    check(!lines.isEmpty, "the 1Password adapter's lines reach the unified log")
    let leaked = lines.filter { line in markers.contains { line.contains($0) } }
    check(leaked.isEmpty,
          "no reference, vault, item, account label, bridge stderr or value is logged in the clear: \(leaked)")
    let tagged = { (pattern: String) in lines.contains { $0.range(of: pattern, options: .regularExpression) != nil } }
    // The whole readback is shown only when a check fails.
    let checkLines = { (condition: Bool, label: String) in
        check(condition, condition ? label : "\(label): \(lines)")
    }
    checkLines(tagged(#"^ref#\d+ is <private>$"#) && tagged(#"^account#\d+ is <private>$"#),
          "each reference and account tag is paired with its text once, privately")
    checkLines(tagged(#"^resolve ref#\d+: reading from account#\d+ \(index\)$"#),
          "which account served a reference is logged by tag")
    checkLines(tagged(#"^select ref#\d+: unique, account#\d+$"#),
          "an account selection is logged by tag")
    checkLines(tagged(#"^bridge for account#\d+ could not be created: OnePasswordError\.vaultAmbiguous \(<private>\)$"#),
          "a failure's kind is logged in the clear and its reason privately")
    checkLines(tagged(#"^miss confirmed: ref#\d+ is not in account#\d+ \(item listed: false\)$"#),
          "a confirmed miss is logged by tag")
    #if DEBUG
    checkLines(tagged(#"^bridge\[account#\d+\]: stderr: <private>$"#),
          "a bridge stderr line is logged privately under its account's tag")
    checkLines(tagged(#"^bridge\[account#\d+\]: bridge process #\d+ started pid=\d+$"#),
          "the bridge's own events stay readable")
    #endif
}

/// The bridge's own stderr lines keep their outcome and timing in the clear,
/// without the account UUID or the SDK's error text; anything else the bridge
/// writes is private whole.
private func onePasswordBridgeStderrClassificationTests() {
    let uuid = "ACCT0000-1111-2222-3333-444455556666"
    let cases: [(line: String, event: String, detail: String?)] = [
        ("12:00:01.250 request id=7 op=resolve ok took=12ms",
         "12:00:01.250 request id=7 op=resolve ok took=12ms", nil),
        ("12:00:01.250 request id=8 op=vaults ok took=3.5s (slower than a warm session; 1Password re-authorized or prompted)",
         "12:00:01.250 request id=8 op=vaults ok took=3.5s (slower than a warm session; 1Password re-authorized or prompted)", nil),
        ("12:00:01.250 request id=9 op=resolve failed kind=not_found took=40ms: vault Acme Payroll not found",
         "12:00:01.250 request id=9 op=resolve failed kind=not_found took=40ms", "vault Acme Payroll not found"),
        ("12:00:01.250 request id=10 op=shutdown", "12:00:01.250 request id=10 op=shutdown", nil),
        ("12:00:01.250 started pid=4242 account=\(uuid)", "12:00:01.250 started pid=4242", nil),
        ("12:00:01.250 authorizing: creating the SDK client for account=\(uuid) (1Password will prompt if this account is not already authorized)",
         "12:00:01.250 authorizing: creating the SDK client (1Password will prompt if this account is not already authorized)", nil),
        ("12:00:01.250 authorized account=\(uuid) after 2m3.5s", "12:00:01.250 authorized after 2m3.5s", nil),
        ("12:00:01.250 authorization failed after 900ms: user alex@example.invalid declined",
         "12:00:01.250 authorization failed after 900ms", "user alex@example.invalid declined"),
        ("12:00:01.250 exiting: stdin closed or shutdown requested",
         "12:00:01.250 exiting", "stdin closed or shutdown requested"),
    ]
    for (line, event, detail) in cases {
        check(OnePasswordBridgeDiagnostic.fromStderr(line) == OnePasswordBridgeDiagnostic(event: event, detail: detail),
              "bridge stderr \"\(line)\" is logged as event \"\(event)\" with \(detail == nil ? "no detail" : "a private detail")")
    }
    let untrusted = [
        "12:00:01.250 request id=9 op=resolve failed kind=Acme_Payroll took=40ms",
        "12:00:01.250 request id=7 op=resolve ok took=12ms and vault Acme Payroll",
        "12:00:01.250 started pid=4242 account=\(uuid) vault=Acme",
        "12:00:01.250 authorized account=\(uuid) after soon",
        "fixture: authorizing account=acct-user-work",
        "",
    ]
    for line in untrusted {
        check(OnePasswordBridgeDiagnostic.fromStderr(line)
              == OnePasswordBridgeDiagnostic(event: OnePasswordBridgeDiagnostic.stderr, detail: line),
              "bridge stderr outside the bridge's own shapes is private whole: \"\(line)\"")
    }
}
