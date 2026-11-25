import ConvenientSecurity
import Foundation
import Darwin

func shellHistoryAuditTests() async {
    print("\n# Value-free shell history audit")
    let path = "/Users/tester/.local/share/fish/fish_history"
    let token = "ghp_syntheticHistoryMarker1234567890"
    let secret = "sk-syntheticHistoryMarker1234567890"
    let userinfo = "https://synthetic-user:synthetic-password@example.test/"
    let history = """
    - cmd: curl '\(userinfo)'
      when: 123
    - cmd: curl -H 'Authorization: Bearer syntheticBearerMarker123456'
    - cmd: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    - cmd: export GITHUB_TOKEN=\(token)
    - cmd: export API_KEY=\(secret)
    """
    guard let found = await evaluateAudit("HA-J07", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(texts: [path: history]))) else { return }
    check(found.status == .fail && found.onThesis, "history credential patterns are an on-thesis finding")
    for label in ["userinfo URLs: 1", "bearer headers: 1", "AWS access key IDs: 1", "GitHub tokens: 1", "API keys: 1"] {
        check(found.evidence.contains(label), "history reports a fixed pattern count (\(label))")
    }
    let rendered = found.evidence + found.anchor + (found.coverageNote ?? "")
    check(![token, secret, userinfo, "synthetic-password", "syntheticBearerMarker", "AKIAIOSFODNN7EXAMPLE", "synthetic-user", "cmd:"].contains(where: rendered.contains),
          "history findings contain no matched bytes, excerpts or user identifiers")

    await expectStatus("HA-J07", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(texts: [path: "- cmd: git status\n- cmd: csec get op://vault/item/token\n"])),
        .pass, "ordinary commands and references have no supported history credential patterns")
    await expectStatus("HA-J07", in: DomainJ_Leakage.checks, makeAuditContext(),
        .notApplicable, "no known history locations are present")
    await expectStatus("HA-J07", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(perms: [path: HostFilePermissions(mode: 0, ownerUID: 0, groupGID: 0)])),
        .unknown, "unreadable history is unknown rather than clean")
    await expectStatus("HA-J07", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(texts: [path: history], symlinks: [path])),
        .unknown, "history symlinks are not followed")
    await expectStatus("HA-J07", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(texts: [path: String(repeating: " ", count: 8 * 1024 * 1024 + 1)])),
        .unknown, "oversized history never produces a clean verdict")
    let custom = "/synthetic/history"
    await expectStatus("HA-J07", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(texts: [custom: history]), environment: ["HISTFILE": custom]),
        .fail, "an absolute HISTFILE override is audited")
    await expectStatus("HA-J07", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(texts: ["/synthetic/data/fish/fish_history": history]),
                         environment: ["XDG_DATA_HOME": "/synthetic/data"]),
        .fail, "an absolute XDG fish data directory is audited")

    if let partial = await evaluateAudit("HA-J07", in: DomainJ_Leakage.checks,
        makeAuditContext(files: FakeFileInspector(texts: [path: history],
            perms: ["/Users/tester/.bash_history": HostFilePermissions(mode: 0, ownerUID: 0, groupGID: 0)]),
            environment: ["HISTFILE": path])) {
        check(partial.status == .fail && partial.evidence.contains("GitHub tokens: 1")
              && partial.coverageNote?.contains("1 unreadable") == true,
              "known findings survive incomplete coverage and duplicate history paths are counted once")
    }

    let root = NSTemporaryDirectory() + "csec-history-reader-\(UUID().uuidString)"
    let fm = FileManager.default
    try? fm.createDirectory(atPath: root, withIntermediateDirectories: true)
    defer { try? fm.removeItem(atPath: root) }
    try? Data("synthetic bounded text".utf8).write(to: URL(fileURLWithPath: root + "/file"))
    try? fm.createSymbolicLink(atPath: root + "/link", withDestinationPath: root + "/file")
    let reader = SystemFileInspector()
    check(reader.readText(root + "/file", maxBytes: 9) == "synthetic",
          "the production history reader enforces its byte bound")
    check(reader.readText(root + "/link", maxBytes: 9) == nil,
          "the production history reader refuses a final symlink")
    if mkfifo(root + "/fifo", 0o600) == 0 {
        check(reader.readText(root + "/fifo", maxBytes: 9) == nil,
              "the production history reader refuses a FIFO without blocking")
    } else { check(false, "the synthetic FIFO fixture could be created") }
}
