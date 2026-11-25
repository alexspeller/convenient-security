import ConvenientSecurity
import Foundation

func shellStartupProtectionTests() {
    print("\n# Preserve shell startup files in bulk protection")
    let fm = FileManager.default
    let home = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("csec-shell-startup-\(UUID().uuidString)")
        .resolvingSymlinksInPath().path
    defer { try? fm.removeItem(atPath: home) }
    let lookup = "export API_TOKEN=\"$(op read op://vault/item/token)\"\nalias ll='ls -al'\n"
    do {
        func write(_ relative: String, _ data: Data) throws {
            let url = URL(fileURLWithPath: home + "/" + relative)
            try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: url)
        }
        try write(".zshrc", Data(lookup.utf8))
        try write(".zprofile", Data([0, 1, 2]))
        try write(".vault-token", Data(lookup.utf8))
        try fm.linkItem(atPath: home + "/.vault-token", toPath: home + "/.bash_profile")
        try write(".bashrc", Data(("export ACCESS_TOKEN=synthetic-startup-token-123456\n" + lookup).utf8))
        try write("project/.env", Data(lookup.utf8))
        try write("project/.envrc", Data(lookup.utf8))
        try write("linked/.env", Data(lookup.utf8))
        try fm.linkItem(atPath: home + "/linked/.env", toPath: home + "/linked/.profile")
        try write("symlinked/.env", Data(lookup.utf8))
        try fm.createSymbolicLink(atPath: home + "/symlinked/.zshrc", withDestinationPath: ".env")

        let report = SecretFileDiscoveryEngine.discover(roots: [home], homeDirectory: home, environment: [:])
        let defaults = SetupProtectPlanner.assignments(files: report.files, rules: [], homeDirectory: home)
        func assignment(_ suffix: String) -> BulkProtectAssignment? {
            defaults.first { $0.file.canonicalPath.hasSuffix(suffix) }
        }
        for suffix in ["/.zshrc", "/.zprofile", "/.vault-token", "/linked/.env", "/symlinked/.env"] {
            let item = assignment(suffix)
            check(item?.approach == .skip,
                  "unsupported or unparseable startup file \(suffix) is listed but skipped")
            check(item?.file.notes.contains(where: { $0.contains("startup file") && $0.contains("manual") }) == true,
                  "startup file \(suffix) explains manual migration without exposing its content")
        }
        check(assignment("/.bashrc")?.approach == .perVar,
              "supported literal assignments in a mixed startup file remain protectable per-variable")
        check(assignment("/project/.env")?.approach == .wholeFile
              && assignment("/project/.envrc")?.approach == .wholeFile,
              "dotenv and envrc keep their automatic whole-file fallback")
        let destinationOnly = SetupProtectPlanner.assignments(
            files: report.files,
            rules: [BulkProtectRule(pattern: ".zshrc", approach: nil, destination: "csec://startup")],
            homeDirectory: home)
        check(destinationOnly.first { $0.file.canonicalPath.hasSuffix("/.zshrc") }?.approach == .skip,
              "a destination-only rule cannot enable whole-file removal of a startup file")
        let explicit = SetupProtectPlanner.assignments(
            files: report.files,
            rules: [BulkProtectRule(pattern: ".zshrc", approach: .wholeFile, destination: nil)],
            homeDirectory: home)
        check(explicit.first { $0.file.canonicalPath.hasSuffix("/.zshrc") }?.approach == .wholeFile,
              "a deliberate whole-file rule remains available for a shell startup file")
        let model = SetupSelectModel(assignments: defaults, homeDirectory: home)
        check(!model.effectiveAssignments.contains { $0.file.canonicalPath.hasSuffix("/.zshrc") },
              "the picker leaves unsupported-only startup files unchecked")
        check(try Data(contentsOf: URL(fileURLWithPath: home + "/.zshrc")) == Data(lookup.utf8),
              "discovery and planning preserve the startup file exactly")
    } catch {
        check(false, "the synthetic shell-startup fixture can be inspected")
    }
}
