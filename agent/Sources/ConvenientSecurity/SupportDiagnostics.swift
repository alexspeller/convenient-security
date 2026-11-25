import Darwin
import Foundation
import CSECBuildIdentity

public enum SupportDiagnostics {
    /// StatusRow.value is for the local terminal and may name a reference or
    /// account. Only known diagnostic labels and their four grades travel.
    public static func doctorChecks(_ rows: [StatusRow]) -> [String] {
        let labels: Set<String> = [
            "Installed app", "LaunchAgent", "Updates", "Agent control channel", "Providers", "SSH agent",
            "Protected SSH keys", "GitHub token proxy", "Shell SSH_AUTH_SOCK", "Remote approval",
            "Agent approval wait", NativeStoreBackupStatusReport.label, "Decision log", "Saved approvals",
            "Root helper", "Uninstaller", "Sudo review", "csec on PATH", "Codex hook", "Codex rules",
            "Codex hooks", "Codex user hook", "Claude Code hook", "Agent allow rules",
            ClaudeDelegationStatusRows.label, ClaudeDelegationStatusRows.buildsLabel,
            ClaudeDelegationStatusRows.verificationLabel, ClaudeDelegationStatusRows.identityLookupLabel,
            ClaudeDelegationStatusRows.lastDeclineLabel
        ]
        return rows.map { row in
            let grade: String
            switch row.state {
            case .ok: grade = "OK"
            case .warn: grade = "warning"
            case .bad: grade = "failed"
            case .neutral: grade = "informational"
            }
            return "\(labels.contains(row.label) ? row.label : "Additional check"): \(grade)"
        }
    }

    public struct Crash {
        public let process: String
        public let date: Date
        public let stack: String
    }

    private static let processes: Set<String> = [
        "csec", "csecd", "csec-rootd", CSECBuildIdentity.named("rootd"),
        "csec-sudo-review", "csec-op-bridge"
    ]
    private static let systemImages: Set<String> = [
        "libsystem_kernel.dylib", "libsystem_pthread.dylib", "libsystem_c.dylib",
        "libdispatch.dylib", "libswiftCore.dylib", "libswift_Concurrency.dylib",
        "Foundation", "CoreFoundation", "Security", "AppKit", "dyld"
    ]

    /// Only fixed event names go into a support file. An unknown line can be
    /// a future log format, subprocess output or a continuation of either.
    private static let events = [
        "csecd: listening on", "csecd: SSH agent listening on", "csecd: GitHub token proxy listening on",
        "csecd: SSH agent OFF", "csecd: GitHub token proxy OFF", "csecd: SSH agent failed",
        "csecd: GitHub token proxy failed", "csecd: new references require biometric approval",
        "csecd: native encrypted store on", "csecd: native encrypted store OFF",
        "csecd: native encrypted store unavailable", "csecd: protected stores on",
        "csecd: protected stores OFF", "csecd: protected stores process-local",
        "csecd: refusing production startup", "csecd: 1Password CLI unavailable",
        "csecd: requesting 1Password desktop access", "csecd: 1Password desktop access ready",
        "csecd: 1Password desktop access unavailable", "csecd: decision log integrity finding",
        "csecd: cannot prepare socket directory", "csecd: persisted automation runs unreadable",
        "csecd: restart cause crash", "csecd: host-audit baseline", "csecd: restored",
        "csecd: settings-change panel ended without approval", "csecd: Touch ID sheet ended without approval",
        "csecd: requester exited while its review waited for unlock",
        "csecd: embedded biometric prompt cancelled while screen locked",
        "csecd: embedded biometric prompt cancelled by the system", "csecd: biometric prompt cancelled while screen locked",
        "csecd: a sudo review stays on the Mac", "csecd: remote approval was not paired",
        "csecd: remote approval was not re-paired", "csecd: persisted grants write failed"
    ]

    public static func logTail(path: String) -> String {
        let byteLimit = 65_536
        var bytes = Data()
        var skippedPrefix = false
        for suffix in ["", ".1", ".2"] {
            guard let (file, info) = regularFile(path + suffix) else { continue }
            let count = min(Int64(byteLimit - bytes.count), info.st_size)
            let start = info.st_size - count
            guard count > 0, (try? file.seek(toOffset: UInt64(start))) != nil,
                  let part = try? file.read(upToCount: Int(count)) else { continue }
            bytes.insert(contentsOf: part, at: bytes.startIndex)
            if bytes.count >= byteLimit {
                skippedPrefix = start > 0
                break
            }
        }
        var lines = bytes.split(separator: 10)
        if skippedPrefix, !lines.isEmpty { lines.removeFirst() }
        var result: [String] = []
        var omitted = 0
        for line in lines.suffix(100) {
            let text = String(decoding: line.prefix(100), as: UTF8.self)
            if let event = events.first(where: { text.hasPrefix($0) }) {
                if omitted > 0 { result.append("[\(omitted) unrecognised lines omitted]"); omitted = 0 }
                result.append(event)
            } else {
                omitted += 1
            }
        }
        if omitted > 0 { result.append("[\(omitted) unrecognised lines omitted]") }
        return result.isEmpty ? "No log lines available." : result.joined(separator: "\n")
    }

    public static var crashDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/DiagnosticReports")
    }

    /// Keep at most three reports per component from the past seven days.
    /// Never echo a filename (older macOS reports put the hostname in it).
    public static func recentCrashes(directory: URL = crashDirectory, now: Date = Date(),
                                     for requestedProcess: String? = nil) -> [Crash] {
        let keys: Set<URLResourceKey> = [.contentModificationDateKey, .isRegularFileKey, .isSymbolicLinkKey]
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: Array(keys), options: [.skipsHiddenFiles]) else { return [] }
        var candidates: [(url: URL, process: String, date: Date)] = []
        for url in entries where ["ips", "crash"].contains(url.pathExtension) {
            let name = url.lastPathComponent
            guard let process = processes.first(where: {
                (name.hasPrefix($0 + "-") || name.hasPrefix($0 + "_"))
                    && name.dropFirst($0.count + 1).first?.isNumber == true
            }), requestedProcess == nil || requestedProcess == process,
                  let attrs = try? url.resourceValues(forKeys: keys),
                  attrs.isRegularFile == true, attrs.isSymbolicLink != true,
                  let date = attrs.contentModificationDate, date <= now,
                  date >= now.addingTimeInterval(-7 * 86400) else { continue }
            candidates.append((url, process, date))
        }
        var crashes: [Crash] = []
        for item in candidates.sorted(by: { $0.date > $1.date }) {
            guard crashes.filter({ $0.process == item.process }).count < 3,
                  let (file, info) = regularFile(item.url.path),
                  info.st_size > 0 else { continue }
            let oversized = info.st_size > 4 * 1024 * 1024
            guard let data = try? file.read(upToCount: oversized ? 8192 : Int(info.st_size)) else { continue }
            let frames: [String]?
            if item.url.pathExtension == "ips" {
                frames = ipsFrames(data, process: item.process, headerOnly: oversized)
            } else {
                frames = legacyFrames(data, process: item.process)
            }
            if let frames {
                crashes.append(Crash(process: item.process, date: item.date,
                                     stack: frames.isEmpty ? "Stack unavailable" : frames.joined(separator: "\n")))
            }
        }
        return crashes
    }

    private static func ipsFrames(_ data: Data, process: String, headerOnly: Bool) -> [String]? {
        guard let newline = data.firstIndex(of: 10),
              let header = (try? JSONSerialization.jsonObject(with: data[..<newline])) as? [String: Any],
              header["bug_type"] as? String == "309" else { return nil }
        if headerOnly { return header["app_name"] as? String == process ? [] : nil }
        guard let body = (try? JSONSerialization.jsonObject(with: data[(newline + 1)...])) as? [String: Any],
              body["procName"] as? String == process else { return nil }
        guard let images = body["usedImages"] as? [[String: Any]],
              let threads = body["threads"] as? [[String: Any]],
              let triggered = body["faultingThread"] as? Int ?? threads.firstIndex(where: { $0["triggered"] as? Bool == true }),
              threads.indices.contains(triggered), let frames = threads[triggered]["frames"] as? [[String: Any]]
        else { return [] }
        return frames.prefix(64).map { frame in
            guard let index = frame["imageIndex"] as? Int, images.indices.contains(index),
                  let name = images[index]["name"] as? String,
                  processes.contains(name) || systemImages.contains(name),
                  let offset = frame["imageOffset"] as? Int, (0...Int(UInt32.max)).contains(offset)
            else { return "[other frame]" }
            return "\(name) +\(offset)"
        }
    }

    private static func legacyFrames(_ data: Data, process: String) -> [String]? {
        let lines = String(decoding: data, as: UTF8.self).components(separatedBy: .newlines)
        guard lines.contains(where: { line in
            line.hasPrefix("Process:") && line.dropFirst(8).split(whereSeparator: \.isWhitespace).first == Substring(process)
        }) else { return nil }
        guard let start = lines.firstIndex(where: { $0.hasPrefix("Thread ") && $0.contains(" Crashed:") }) else { return [] }
        var frames: [String] = []
        for line in lines.dropFirst(start + 1).prefix(64) {
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 3, Int(fields[0]) != nil else { break }
            let name = String(fields[1])
            frames.append(processes.contains(name) || systemImages.contains(name) ? name : "[other frame]")
        }
        return frames
    }

    private static func regularFile(_ path: String) -> (FileHandle, stat)? {
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(), info.st_nlink == 1 else { return nil }
        return (file, info)
    }

    public static func save(_ text: String, directory: URL) throws -> URL {
        let url = directory.appendingPathComponent("csec-doctor-\(UUID().uuidString).txt")
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try file.write(contentsOf: Data(text.utf8))
            try file.close()
        } catch {
            try? FileManager.default.removeItem(at: url)
            throw error
        }
        return url
    }
}
