import ConvenientSecurity
import Foundation

/// `csec setup --protect-files` splits an auth-bearing `~/.npmrc` instead of
/// removing it: the cooldown and `ignore-scripts` stay for plain npm, only the
/// auth lines reach the store, and `exec-fd --preset npm` gives npm both.
/// Every invocation runs in a synthetic home with a scrubbed environment.
@MainActor func npmSplitTests() async {
    print("\n# Bulk protection: npm userconfig split")
    let fm = FileManager.default
    let root = NSTemporaryDirectory() + "csec-npm-split-e2e-\(UUID().uuidString.lowercased())"
    defer { try? fm.removeItem(atPath: root) }
    let token = "npm-split-e2e-synthetic-token"
    let settings = "min-release-age=7\nignore-scripts=true\n"
    let original = Data((settings + "//registry.npmjs.org/:_authToken=\(token)\n"
        + "registry=https://registry.npmjs.org/\n").utf8)
    do {
        for keep in [false, true] {
            let home = root + "/keep-\(keep)/home"
            try fm.createDirectory(atPath: home, withIntermediateDirectories: true)
            let npmrc = home + "/.npmrc"
            try original.write(to: URL(fileURLWithPath: npmrc))
            try fm.setAttributes([.posixPermissions: NSNumber(value: 0o600)], ofItemAtPath: npmrc)
            let store = "npm-split-\(keep)"
            let environment = ["HOME": home, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": root + "/"]
            func run(_ arguments: [String]) -> (status: Int32, out: String, err: String) {
                runCsecPipedAt(cwd: home, arguments, input: Data(), baseEnvironment: environment)
            }
            let label = "keep=\(keep)"

            // Isolation interlock: the plan must name exactly the fixture file.
            let dry = run(["setup", "--protect-files", "--scan-root", home, "--dry-run"])
            guard dry.status == 0, dry.out.contains("plan: 1 unique file(s)"),
                  dry.out.contains("~/.npmrc"), dry.out.contains("preset:npm") else {
                check(false, "\(label): REFUSING apply, the plan is not the isolated npm fixture (\(dry.err))")
                continue
            }
            let applied = run(["setup", "--protect-files", "--scan-root", home,
                               "--glob", ".npmrc=csec://\(store)", "--apply"]
                              + (keep ? ["--keep-plaintext"] : []))
            let reference = "csec://\(store)/NPMRC_AUTH"
            check(applied.status == 0 && applied.out.contains(reference)
                  && applied.out.contains("csec exec-fd --preset npm=\(reference) -- npm <command>"),
                  "\(label): the split applies and prints the exec-fd recipe (\(applied.err))")
            check(!applied.out.contains(token) && !applied.err.contains(token),
                  "\(label): the report is metadata only")
            check(!fm.fileExists(atPath: npmrc + ".csec"),
                  "\(label): no whole-file sidecar replaces the config")

            let current = (try? Data(contentsOf: URL(fileURLWithPath: npmrc))) ?? Data()
            let text = String(decoding: current, as: UTF8.self)
            if keep {
                check(current == original, "\(label): the config is left exactly as it was")
            } else {
                check(text.hasPrefix(settings) && text.contains("registry=https://registry.npmjs.org/")
                      && text.contains("; csec: auth lines moved to \(reference)") && !text.contains(token),
                      "\(label): the config keeps its settings in place and loses only the token")
                let attributes = try fm.attributesOfItem(atPath: npmrc)
                check((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,
                      "\(label): the rewritten config keeps its mode")
                let again = run(["setup", "--protect-files", "--scan-root", home, "--dry-run"])
                check(again.status == 0 && !again.out.contains("~/.npmrc"),
                      "\(label): the split config is no longer a discovery finding")
            }

            // Delivery: the live file plus the stored auth lines, on the pipe.
            let delivered = run([
                "exec-fd", "--redact-output=never", "--preset", "npm=\(reference)", "--",
                "/bin/sh", "-c",
                "case \"$NPM_CONFIG_USERCONFIG\" in /dev/fd/*) ;; *) exit 81;; esac; "
                    + "/bin/cat \"$NPM_CONFIG_USERCONFIG\"",
            ])
            check(delivered.status == 0 && delivered.out.hasPrefix(settings)
                  && delivered.out.contains("//registry.npmjs.org/:_authToken=\(token)\n")
                  && delivered.out.contains("registry=https://registry.npmjs.org/"),
                  "\(label): exec-fd streams the live settings with the stored auth lines (\(delivered.err))")

            // The token printed on its own is masked, not only the whole value.
            let masked = run([
                "exec-fd", "--preset", "npm=\(reference)", "--",
                "/bin/sh", "-c", "printf '%s\\n' '\(token)'",
            ])
            check(masked.status == 0 && !masked.out.contains(token),
                  "\(label): output masking catches a stored token printed alone (\(masked.err))")
        }

        // An enclosing descriptor or a lower-case override never leaks into
        // the child: npm sees exactly the one merged descriptor.
        let home = root + "/override/home"
        try fm.createDirectory(atPath: home, withIntermediateDirectories: true)
        let alternate = root + "/override/alt-npmrc"
        try Data("save-exact=true\n".utf8).write(to: URL(fileURLWithPath: alternate))
        let reviewsBeforeOverride = await accessReviewCapture.snapshot().count
        let overridden = runCsecPipedAt(
            cwd: home,
            ["exec-fd", "--redact-output=never", "--preset", "npm=op://fd-presets/npm/content", "--",
             "/bin/sh", "-c",
             "test -z \"$npm_config_userconfig\" || exit 82; /bin/cat \"$NPM_CONFIG_USERCONFIG\""],
            input: Data(),
            baseEnvironment: ["HOME": home, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/",
                              "npm_config_userconfig": alternate])
        check(overridden.status == 0
              && overridden.out == "save-exact=true\n//registry.npmjs.org/:_authToken=npm-fd-secret\n",
              "an op:// npm preset merges the overriding userconfig and drops its other spelling "
                + "(\(overridden.status), \(overridden.err))")
        let reviewsAfterOverride = await accessReviewCapture.snapshot().count

        // An unusable live config fails before csec asks for anything.
        let badHome = root + "/bad/home"
        try fm.createDirectory(atPath: badHome, withIntermediateDirectories: true)
        try Data("min-release-age=7\n\u{0}\n".utf8).write(to: URL(fileURLWithPath: badHome + "/.npmrc"))
        let refused = runCsecPipedAt(
            cwd: badHome,
            ["exec-fd", "--preset", "npm=op://fd-presets/npm/content", "--", "/usr/bin/true"],
            input: Data(),
            baseEnvironment: ["HOME": badHome, "PATH": "/usr/bin:/bin", "TMPDIR": root + "/"])
        let reviewsAfterRefusal = await accessReviewCapture.snapshot().count
        check(reviewsAfterOverride > reviewsBeforeOverride && refused.status != 0
              && reviewsAfterRefusal == reviewsAfterOverride,
              "a NUL-bearing live npm config is refused before the review a good one gets (\(refused.err))")
    } catch {
        check(false, "npm split fixture setup failed: \(error)")
    }
}
