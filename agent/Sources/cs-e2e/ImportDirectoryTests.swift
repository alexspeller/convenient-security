import ConvenientSecurity
import Darwin
import Foundation

/// An explicit import belongs to the target's project, even when launched
/// from another project. No store override may hide a cwd-derived default.
@MainActor func importDirectoryTests() async {
    print("\n# Import destinations follow the target directory")
    let fm = FileManager.default
    let temporary = NSTemporaryDirectory() + "csec-import-directory-\(UUID().uuidString.lowercased())"
    defer { try? fm.removeItem(atPath: temporary) }
    do {
        try fm.createDirectory(atPath: temporary, withIntermediateDirectories: true)
        // Foundation keeps /var, but the importer records realpath's /private/var.
        guard let canonicalRoot = realpath(temporary, nil) else {
            throw CocoaError(.fileReadUnknown)
        }
        let root = String(cString: canonicalRoot)
        free(canonicalRoot)
        let home = root + "/home"
        let caller = home + "/caller"
        let target = home + "/projects/import-target"
        let worktree = target + "/nested-worktree"
        let global = home + "/.config/service"
        let outside = root + "/outside-home"
        for directory in [caller + "/.git", target + "/.git", target + "/config",
                          worktree + "/config", global, outside] {
            try fm.createDirectory(atPath: directory, withIntermediateDirectories: true)
        }
        // Worktrees have a .git file; the nearest marker governs the import.
        try Data("gitdir: /synthetic/unused-git-dir\n".utf8)
            .write(to: URL(fileURLWithPath: worktree + "/.git"))
        let paths = [target + "/config/.env", worktree + "/config/.env",
                     global + "/.env", outside + "/.env"]
        let token = "import-directory-synthetic-token"
        let original = Data("API_TOKEN=\(token)\n".utf8)
        for path in paths { try original.write(to: URL(fileURLWithPath: path)) }
        let alias = home + "/target-alias"
        try fm.createSymbolicLink(atPath: alias, withDestinationPath: target)
        let environment = ["HOME": home, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": root + "/"]
        // The csec under test names stores against this account's real
        // native store index (HOME does not move it), so a store already
        // named like a fixture's directory (`home`, say) takes a suffix
        // there; the expectation must use the same index.
        let index = NativeStoreDirectoryIndex()
        func store(for directory: String) throws -> NativeStoreName {
            try ProtectedFileImportPlanner.resolveDefaultStore(
                projectRoot: directory, homeDirectory: home, index: index)
        }
        func run(cwd: String = caller, _ arguments: [String]) -> (status: Int32, out: String, err: String) {
            runCsecPipedAt(cwd: cwd, arguments, input: Data(), baseEnvironment: environment)
        }
        func dry(
            _ label: String, cwd: String = caller, path: String,
            expectedRoot: String, options: [String] = [], destination: String? = nil
        ) throws {
            let expected = try destination ?? "csec://" + store(for: expectedRoot).value
            let result = run(cwd: cwd, ["protect", "--env", "--dry-run"] + options + [path])
            check(result.status == 0 && result.out.contains("  ->  \(expected)\n"),
                  "\(label): env import chooses the target destination")
            check(try Data(contentsOf: URL(fileURLWithPath: path.hasPrefix("/")
                                           ? path : cwd + "/" + path)) == original,
                  "\(label): dry run leaves the source byte-identical")
            check(!result.out.contains(token) && !result.err.contains(token),
                  "\(label): dry run emits metadata only")
        }
        try dry("absolute path from another project", path: paths[0], expectedRoot: target)
        try dry("relative path from another project", path: "../projects/import-target/config/.env",
                expectedRoot: target)
        try dry("within the target project", cwd: target, path: "config/.env", expectedRoot: target)
        try dry("symlinked parent", path: alias + "/config/.env", expectedRoot: target)
        try dry("nearest worktree marker", path: paths[1], expectedRoot: worktree)
        try dry("home-global file", path: paths[2], expectedRoot: home)
        try dry("outside-home file", path: paths[3], expectedRoot: outside)
        try dry("explicit store", path: paths[0], expectedRoot: target,
                options: ["--store", "import-explicit"], destination: "csec://import-explicit")
        try dry("provider item title", path: paths[0], expectedRoot: target,
                options: ["--dest", "op://fixture-vault"], destination: "op://fixture-vault/import-target")
        try dry("explicit provider item", path: paths[0], expectedRoot: target,
                options: ["--dest", "op://fixture-vault/chosen"], destination: "op://fixture-vault/chosen")

        // Automatic env protection must use the same default as the picker,
        // both for its canonical reference and its authenticated store origin.
        let targetStore = try store(for: target)
        let reference = "csec://\(targetStore.value)/API_TOKEN"
        let applied = run(["protect", paths[0]])
        check(applied.status == 0
              && (try? String(contentsOfFile: paths[0], encoding: .utf8))
                  == "csec_API_TOKEN=\"\(reference)\"\n",
              "automatic import from another project writes the target-derived reference")
        let resolved = try client.access(
            references: [reference], reason: "synthetic import-directory regression", ttlSeconds: 60)
        check(resolved[reference] == Data(token.utf8),
              "the target-derived reference resolves the imported synthetic value")
        let marker = await nativeFileBackend.read(named: NativeStoreOriginMarker.fileName(store: targetStore))
        check(marker.flatMap(NativeStoreOriginMarker.parseOrigin(fromCleartext:)) == target,
              "automatic import records the target project as the store origin")
        let repeated = run(["protect", paths[0]])
        check(repeated.status == 0
              && (try? String(contentsOfFile: paths[0], encoding: .utf8))
                  == "csec_API_TOKEN=\"\(reference)\"\n",
              "repeating the import from another project preserves its reference")
    } catch {
        check(false, "import-directory end-to-end checks complete")
    }
}
