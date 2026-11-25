import ConvenientSecurity
import Darwin
import Foundation

// Fly's token through the real `csec` launcher and socket: `csec protect --fly`
// against a scripted fly in a private FLY_CONFIG_DIR, `csec fly` delivering the
// registered token, a new login taken back out of the file, a registration from
// another provider, and logout. No real Fly credential or network is touched.

private let flyE2EToken = "FlyV1 fm2_flyE2ESyntheticToken0123456789+/=,fm2_flyE2ESecondMacaroon"
private let flyE2ENewToken = "FlyV1 fm2_flyE2ENewLoginToken9876543210"

/// A fly that logs each call (arguments, then the token variables and the
/// agent setting it was given) and answers the commands the tests run from
/// files in its FLY_CONFIG_DIR.
private let scriptedFly = """
#!/bin/sh
set -eu
printf '%s|%s|%s|%s\\n' "$*" "${FLY_API_TOKEN-unset}" "${FLY_ACCESS_TOKEN-unset}" "${FLY_AGENT_ISOLATED-unset}" \\
  >> "$FLY_CONFIG_DIR/../fly.log"
case "$*" in
  "auth login")
    printf 'access_token: %s\\nauto_update: true\\nmetrics_token: fm2_newMetrics\\n' "$CS_E2E_FLY_NEW_TOKEN" \\
      > "$FLY_CONFIG_DIR/config.yml" ;;
  "auth token")
    printf '%s\\n' "$FLY_API_TOKEN" ;;
  *) ;;
esac
"""

func flyE2ETests() {
    let root = NSTemporaryDirectory() + "cs-e2e-fly-\(getpid())"
    let bin = root + "/bin"
    let config = root + "/config"
    for directory in [bin, config] {
        try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    }
    chmod(config, 0o700)
    defer { try? FileManager.default.removeItem(atPath: root) }
    try? scriptedFly.write(toFile: bin + "/fly", atomically: true, encoding: .utf8)
    chmod(bin + "/fly", 0o755)
    let configPath = config + "/config.yml"
    let original = """
        access_token: \(flyE2EToken)
        auto_update: false
        metrics_token: fm2_flyE2EMetrics
        wire_guard_state:
            personal:
                region: lhr

        """
    FileManager.default.createFile(atPath: configPath, contents: Data(original.utf8),
                                   attributes: [.posixPermissions: NSNumber(value: Int16(0o600))])
    let environment = [
        "PATH": bin + ":" + (ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin"),
        "FLY_CONFIG_DIR": config,
        "CS_E2E_FLY_NEW_TOKEN": flyE2ENewToken,
    ]
    // runCsec starts from this process's environment: no Fly settings in it.
    for name in ["FLY_API_TOKEN", "FLY_ACCESS_TOKEN", "FLY_AGENT_ISOLATED", "FLY_CONFIG_DIR"] { unsetenv(name) }
    func run(_ arguments: [String], _ extra: [String: String] = [:]) -> (status: Int32, out: String, err: String) {
        let result = runCsec(arguments, extraEnv: environment.merging(extra) { $1 })
        return (result.status, result.out, result.err)
    }
    func flyLog() -> [String] {
        ((try? String(contentsOfFile: root + "/fly.log", encoding: .utf8)) ?? "")
            .split(separator: "\n").map(String.init)
    }
    func file(_ path: String) -> String { (try? String(contentsOfFile: path, encoding: .utf8)) ?? "" }

    let unregistered = run(["fly", "register"])
    check(unregistered.status == 0 && unregistered.out.contains("not registered")
            && unregistered.out.contains("holds a plaintext token") && !unregistered.out.contains("fm2_"),
          "csec fly register reports fly's plaintext token without showing it")

    let dryRun = run(["protect", "--fly", "--dry-run", "--store", "e2e-fly"])
    check(dryRun.status == 0 && dryRun.out.contains("csec://e2e-fly/FLY_API_TOKEN")
            && dryRun.out.contains("nothing changed") && file(configPath) == original
            && !FileManager.default.fileExists(atPath: config + "/csec.json"),
          "csec protect --fly --dry-run reports the plan and changes nothing")

    let protected = run(["protect", "--fly", "--store", "e2e-fly"])
    let blanked = original
        .replacingOccurrences(of: "access_token: \(flyE2EToken)", with: "access_token: \"\"")
        .replacingOccurrences(of: "metrics_token: fm2_flyE2EMetrics", with: "metrics_token: \"\"")
    check(protected.status == 0 && protected.out.contains("protected fly's token as csec://e2e-fly/FLY_API_TOKEN")
            && protected.out.contains("alias fly='csec fly'") && protected.out.contains("can read fly's environment")
            && !protected.out.contains("fm2_"),
          "csec protect --fly imports fly's token and prints the alias lines (\(protected.err))")
    check(file(configPath) == blanked,
          "config.yml keeps every other setting with both token lines emptied")
    check(file(config + "/csec.json") == "{\"token_reference\":\"csec://e2e-fly/FLY_API_TOKEN\",\"version\":1}\n",
          "the registration beside fly's config holds only the reference")
    check(flyLog().last == "agent stop|unset|unset|unset",
          "csec protect --fly stops fly's background agent, giving it no token")

    let deploy = run(["fly", "apps", "list"])
    check(deploy.status == 0 && flyLog().last == "apps list|\(flyE2EToken)|unset|1"
            && !deploy.err.contains("warning"),
          "csec fly runs fly with the imported token in FLY_API_TOKEN and an isolated agent, without exec's per-run warning (\(deploy.err))")
    let shown = run(["fly", "auth", "token"])
    check(shown.status == 0 && !shown.out.contains("fm2_") && shown.out.contains("[redacted"),
          "a token fly prints back is redacted in csec fly's output")
    let help = run(["fly", "deploy", "--help"])
    check(help.status == 0 && flyLog().last?.hasPrefix("deploy --help|") == true,
          "csec fly passes --help on to fly")
    let explicit = run(["fly", "apps", "list"], ["FLY_API_TOKEN": "explicit-shell-token", "FLY_AGENT_ISOLATED": "0"])
    check(explicit.status == 0 && flyLog().last == "apps list|explicit-shell-token|unset|0",
          "a token and agent setting the shell sets are fly's to use")

    let again = run(["protect", "--fly", "--store", "e2e-fly"])
    check(again.status == 0 && again.out.contains("nothing to do") && file(configPath) == blanked,
          "running csec protect --fly once more changes nothing")

    // A new login saves a new plaintext token; csec fly takes it back out into
    // the registered reference, so the next command gets the new token.
    let login = run(["fly", "auth", "login"])
    let loginCall = flyLog().first { $0.hasPrefix("auth login|") }
    check(login.status == 0 && loginCall == "auth login|unset|unset|unset"
            && login.err.contains("protected the new token as csec://e2e-fly/FLY_API_TOKEN"),
          "csec fly auth login runs fly without a token, then protects the new one (\(login.err))")
    check(!file(configPath).contains("fm2_") && file(configPath).contains("access_token: \"\""),
          "the new login's token is emptied from config.yml")
    _ = run(["fly", "status"])
    check(flyLog().last == "status|\(flyE2ENewToken)|unset|1",
          "the next fly command gets the new login's token from the same reference")

    // Any provider's reference can be registered instead.
    let registered = run(["fly", "register", "op://demo/api/key"])
    _ = run(["fly", "machines", "list"])
    check(registered.status == 0 && flyLog().last == "machines list|sk-demo-123|unset|1",
          "a registered 1Password reference is the token fly gets")

    let logout = run(["fly", "auth", "logout"])
    let after = run(["fly", "register"])
    check(logout.status == 0 && logout.err.contains("forgot the registered Fly token")
            && flyLog().last == "auth logout|unset|unset|unset"
            && after.out.contains("not registered") && !FileManager.default.fileExists(atPath: config + "/csec.json"),
          "csec fly auth logout forgets the registration and runs fly's logout without a token")
    _ = run(["fly", "apps", "list"])
    check(flyLog().last == "apps list|unset|unset|unset",
          "with nothing registered csec fly runs fly as it is")
}
