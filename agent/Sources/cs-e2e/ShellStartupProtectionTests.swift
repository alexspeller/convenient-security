import ConvenientSecurity
import Foundation

func shellStartupProtectionE2ETests() {
    print("\n# Shell startup preservation end to end")
    let fm = FileManager.default
    let home = NSTemporaryDirectory() + "csec-shell-startup-e2e-\(UUID().uuidString)"
    defer { try? fm.removeItem(atPath: home) }
    let lookup = "export API_TOKEN=\"$(op read op://vault/item/token)\"\nalias ll='ls -al'\n"
    let literal = "synthetic-shell-startup-token-123456"
    let invalid = Data([0, 1, 2])
    let store = "shell-startup-e2e"
    do {
        func write(_ relative: String, _ data: Data) throws {
            let url = URL(fileURLWithPath: home + "/" + relative)
            try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: url)
        }
        func read(_ relative: String) -> Data? {
            try? Data(contentsOf: URL(fileURLWithPath: home + "/" + relative))
        }
        func run(_ arguments: [String]) -> (status: Int32, out: String, err: String) {
            runCsecPipedAt(
                cwd: home,
                ["setup", "--protect-files", "--scan-root", home] + arguments,
                input: Data(), baseEnvironment: [
                    "HOME": home, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": home + "/",
                ])
        }
        try write(".zshrc", Data(lookup.utf8))
        try write(".zprofile", invalid)
        try write(".bashrc", Data(("export LITERAL_TOKEN=\(literal)\n" + lookup).utf8))
        try write("project/.env", Data(lookup.utf8))
        try write("project/.envrc", Data(lookup.utf8))
        let dry = run(["--dry-run"])
        let expected = ["~/.zshrc", "~/.zprofile", "~/.bashrc", "~/project/.env", "~/project/.envrc"]
        let paths = dry.out.split(separator: "\n").filter { $0.hasPrefix("| ~/") }.map {
            $0.split(separator: "|")[0].trimmingCharacters(in: .whitespaces)
        }
        guard dry.status == 0, Set(paths) == Set(expected), paths.count == expected.count else {
            check(false, "REFUSING shell-startup apply: dry run must name exactly the synthetic fixture")
            return
        }
        let applied = run(["--glob", "**=csec://\(store)", "--apply"])
        check(applied.status == 0 && !applied.out.contains(literal) && !applied.err.contains(literal),
              "mixed shell-startup bulk protection succeeds without exposing a value")
        check(read(".zshrc") == Data(lookup.utf8) && read(".zprofile") == invalid
              && !fm.fileExists(atPath: home + "/.zshrc.csec")
              && !fm.fileExists(atPath: home + "/.zprofile.csec"),
              "automatic bulk apply preserves unsupported and unparseable startup files with no sidecars")
        let mixed = String(decoding: read(".bashrc") ?? Data(), as: UTF8.self)
        check(mixed.contains("csec_LITERAL_TOKEN=\"csec://\(store)/LITERAL_TOKEN")
              && mixed.contains(lookup) && !mixed.contains(literal)
              && !fm.fileExists(atPath: home + "/.bashrc.csec"),
              "a mixed startup file rewrites its literal and preserves lookups and aliases")
        check(applied.out.contains("unsupported assignments") && applied.out.contains("manual"),
              "apply explains that unsupported startup assignments still need manual migration")
        check(read("project/.env") == nil && read("project/.envrc") == nil
              && fm.fileExists(atPath: home + "/project/.env.csec")
              && fm.fileExists(atPath: home + "/project/.envrc.csec"),
              "dotenv and envrc still fall back to whole-file during apply")

        let perVar = run(["--glob", "**=skip", "--glob", ".zshrc=per-var:csec://\(store)", "--apply"])
        check(perVar.status == 0 && read(".zshrc") == Data(lookup.utf8)
              && !fm.fileExists(atPath: home + "/.zshrc.csec")
              && perVar.out.contains("startup file preserved"),
              "the per-var apply path preserves an unsupported-only startup file instead of falling back")
        let whole = run(["--glob", "**=skip", "--glob", ".zshrc=whole-file:csec://\(store)", "--apply"])
        check(whole.status == 0 && read(".zshrc") == nil
              && fm.fileExists(atPath: home + "/.zshrc.csec"),
              "an explicit whole-file choice still protects a startup file through a sidecar")
    } catch {
        check(false, "the synthetic shell-startup e2e fixture can be exercised")
    }
}
