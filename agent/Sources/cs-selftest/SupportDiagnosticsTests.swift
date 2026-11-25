import ConvenientSecurity
import Foundation

/// Exercise the real stream redirection in a child so the test harness keeps
/// its own stdout and stderr. Send one short line while the writer is alive.
func daemonLogProbe(directory: String) throws {
    try BoundedDaemonLog.redirect(in: directory)
    try FileHandle.standardOutput.write(contentsOf: Data("stdout\n".utf8))
    try FileHandle.standardError.write(contentsOf: Data("stderr\n".utf8))
    let url = URL(fileURLWithPath: directory).appendingPathComponent("csecd.log")
    for _ in 0..<100 {
        if (try? Data(contentsOf: url)) == Data("stdout\nstderr\n".utf8) { return }
        Thread.sleep(forTimeInterval: 0.02)
    }
    throw POSIXError(.ETIMEDOUT)
}

func supportDiagnosticsTests() throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: dir) }

    let path = dir.appendingPathComponent("csecd.log").path
    let writer = try BoundedDaemonLog(path: path, capacity: 16)
    try writer.append(Data((String(repeating: "a", count: 16) + String(repeating: "b", count: 16)
                           + String(repeating: "c", count: 16) + "last").utf8))
    let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
    check(Set(files) == ["csecd.log", "csecd.log.1", "csecd.log.2", "csecd.log.lock"], "log keeps two generations")
    withExtendedLifetime(writer) {
        check((try? BoundedDaemonLog(path: path, capacity: 16)) == nil, "concurrent daemon cannot rotate this log")
    }
    for (suffix, expected) in [("", "last"), (".1", String(repeating: "c", count: 16)),
                               (".2", String(repeating: "b", count: 16))] {
        let actual = try String(contentsOfFile: path + suffix, encoding: .utf8)
        check(actual == expected, "log capacity and byte order \(suffix)")
    }
    let marker = "PRIVATE-FIXTURE"
    let lines = "csecd: listening on /Users/\(marker)/socket\nop://\(marker)/field\n"
    let privateLog = dir.appendingPathComponent("privacy.log")
    // A rotation can split a UTF-8 line at any byte.
    try Data(lines.utf8.prefix(3)).write(to: privateLog.appendingPathExtension("1"))
    try Data(lines.utf8.dropFirst(3)).write(to: privateLog)
    let tail = SupportDiagnostics.logTail(path: privateLog.path)
    check(tail.contains("listening") && !tail.contains(marker), "only log event categories leave the log")
    let grades = SupportDiagnostics.doctorChecks([
        StatusRow(label: "GitHub token proxy", value: "op://\(marker)/field", state: .ok),
        StatusRow(label: marker, value: marker, state: .warn)
    ])
    check(grades == ["GitHub token proxy: OK", "Additional check: warning"],
          "doctor exports fixed check names and grades")

    let oversized = dir.appendingPathComponent("legacy.log")
    try Data("0123456789abcdef".utf8).write(to: oversized)
    let migrated = try BoundedDaemonLog(path: oversized.path, capacity: 8)
    try migrated.append(Data("x".utf8))
    let kept = try Data(contentsOf: oversized.appendingPathExtension("1"))
    check(kept == Data("89abcdef".utf8), "upgrade retains only the bounded tail of a legacy log")
    let crash = dir.appendingPathComponent("csecd-2026-11-23-000000.ips")
    let ips = """
    {"app_name":"csecd","bug_type":"309"}
    {"procName":"csecd","asi":"\(marker)","faultingThread":0,
     "usedImages":[{"name":"csecd","path":"/Users/\(marker)/csecd"}],
     "threads":[{"frames":[{"imageIndex":0,"imageOffset":4096,"symbol":"\(marker)"}]}]}
    """
    try Data(ips.utf8).write(to: crash)
    try Data(ips.utf8).write(to: dir.appendingPathComponent("unrelated-2026-11-23.ips"))
    let old = dir.appendingPathComponent("csecd-2020-01-01.ips")
    try Data(ips.utf8).write(to: old)
    try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 100)], ofItemAtPath: old.path)
    let link = dir.appendingPathComponent("csecd-2026-11-23-symlink.ips")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: crash)
    let crashes = SupportDiagnostics.recentCrashes(directory: dir)
    check(crashes.count == 1, "unrelated, stale and symlinked crashes are excluded")
    check(crashes.contains { $0.process == "csecd" && $0.stack.contains("csecd +4096") },
          "crashed thread retains a symbolication offset")
    check(!crashes.map(\.stack).joined().contains(marker), "crash notes, symbol strings and paths stay local")
    let large = dir.appendingPathComponent("csec-sudo-review-2026-11-23.ips")
    try Data("{\"app_name\":\"csec-sudo-review\",\"bug_type\":\"309\"}\n".utf8).write(to: large)
    let sparse = try FileHandle(forWritingTo: large)
    try sparse.truncate(atOffset: 5 * 1024 * 1024)
    try sparse.close()
    check(SupportDiagnostics.recentCrashes(directory: dir, for: "csec-sudo-review").first?.stack == "Stack unavailable",
          "large crash is still reported without reading its full body")
    let legacy = dir.appendingPathComponent("csec-rootd_2026-11-23_PRIVATE.crash")
    try Data("Process: csec-rootd [7]\nThread 2 Crashed:\n0  csec-rootd  0x1111 \(marker)\n".utf8).write(to: legacy)
    check(SupportDiagnostics.recentCrashes(directory: dir, for: "csec-rootd").first?.stack == "csec-rootd",
          "legacy crash omits filename, address and free-form symbols")
    let saved = try SupportDiagnostics.save("fixture", directory: dir)
    let mode = try FileManager.default.attributesOfItem(atPath: saved.path)[.posixPermissions] as? NSNumber
    check(mode?.intValue == 0o600, "support file is private from creation")

    let probeDirectory = dir.appendingPathComponent("probe")
    try FileManager.default.createDirectory(at: probeDirectory, withIntermediateDirectories: false)
    let probe = Process()
    probe.executableURL = Bundle.main.executableURL
    probe.arguments = ["--daemon-log-probe", probeDirectory.path]
    try probe.run()
    probe.waitUntilExit()
    check(probe.terminationStatus == 0, "short writes to both daemon streams reach the active log promptly")
}
