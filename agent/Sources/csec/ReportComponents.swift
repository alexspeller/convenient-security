import ConvenientSecurity
import Darwin
import Foundation
import MachO
import Security
import CSECBuildIdentity

/// Inspect the installed images without launching them (or contacting the phone).
enum ReportComponents {
    static func rows(phoneVersion: String?) -> [String] {
        let app = "/Applications/ConvenientSecurity.app"
        let bin = app + "/Contents/MacOS/"
        let support = PackagePayload.supportDirectory
        let info = Bundle(url: URL(fileURLWithPath: app))?.infoDictionary
        let version = (info?["CFBundleShortVersionString"] as? String).flatMap(ReleaseVersion.init)
        let build = (info?["CFBundleVersion"] as? String).flatMap(Int.init)
        let appVersion = version.map { version in
            build.map { "\(version) (build \($0))" } ?? version.description
        } ?? "version unavailable"
        var rows = ["Mac app: \(appVersion), \(signature(app))"]
        let binaries = [
            ("Launcher", bin + "csec"), ("Resident agent", bin + "csecd"),
            ("Language bridge", support + "/bin/csec"),
            ("Root helper", "/Library/PrivilegedHelperTools/\(CSECBuildIdentity.identifier).rootd"),
            ("1Password bridge", bin + "csec-op-bridge"),
            ("Packaged sudo module", PackagePayload.sudoModule), ("Packaged sudo helper", PackagePayload.sudoHelper),
            ("Active sudo module", SudoIntegrationInspection.modulePath),
            ("Active sudo helper", SudoIntegrationInspection.helperPath)
        ]
        for (name, path) in binaries {
            guard FileManager.default.fileExists(atPath: path) else {
                rows.append("\(name): missing")
                continue
            }
            let release = installedStamp(path).flatMap { ReleaseBuild($0) }?.description ?? "no release stamp"
            rows.append("\(name): \(release), \(signature(path))")
        }

        let resources = [
            ("1Password guard", app + "/Contents/Resources/ai-guard/op"),
            ("Claude shell adapter", app + "/Contents/Resources/claude-code-shell/csec-claude-code-shell"),
            ("LaunchAgent", app + "/Contents/Library/LaunchAgents/\(CSECBuildIdentity.identifier).plist"),
            ("Root LaunchDaemon", "/Library/LaunchDaemons/\(CSECBuildIdentity.identifier).rootd.plist"),
            ("Codex hook installer", PackagePayload.codexHookInstaller),
            ("Installed Codex hook", CodingAgentSetup.codexSystemHookPath),
            ("Sudo installer", PackagePayload.sudoReviewInstaller),
            ("Sudo policy script", support + "/libexec/sudo-review-policy.sh"),
            ("Build identity", support + "/libexec/identity.xcconfig"),
            ("Build identity reader", support + "/libexec/identity.sh"),
            ("Uninstaller", CompleteUninstall.scriptPath)
        ]
        for (name, path) in resources {
            rows.append("\(name): " + (FileManager.default.fileExists(atPath: path)
                ? "present (no independent version or code signature)" : "missing"))
        }
        // The paired app supplies this field. Never forward an arbitrary label.
        let phone = phoneVersion.flatMap { text in
            text.range(of: #"\A[0-9]{1,9}(?:\.[0-9]{1,9}){0,2} \([0-9]{1,12}\)\z"#,
                       options: .regularExpression) != nil ? text : nil
        } ?? "version unavailable"
        rows.append("iPhone approval app: \(phone), signature unavailable from Mac")
        return rows
    }

    private static func signature(_ path: String) -> String {
        guard FileManager.default.fileExists(atPath: path) else { return "missing" }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return "signature unavailable" }
        let validation: SecCSFlags = [SecCSFlags(rawValue: kSecCSStrictValidate), .noNetworkAccess]
        switch SecStaticCodeCheckValidity(code, validation, nil) {
        case errSecCSUnsigned: return "unsigned"
        case errSecSuccess: break
        default: return "invalid or unverifiable signature"
        }
        var result: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &result) == errSecSuccess,
              let flags = (result as? [String: Any])?[kSecCodeInfoFlags as String] as? UInt32
        else { return "valid signature" }
        return SecCodeSignatureFlags(rawValue: flags).contains(.adhoc) ? "valid ad hoc signature" : "valid signature"
    }

    /// The package ships thin Apple Silicon images. Inspect only their bounded
    /// load-command table and exact release section, without mapping executable code.
    private static func installedStamp(_ path: String) -> ReleaseStamp? {
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              let prefix = try? file.read(upToCount: MemoryLayout<mach_header_64>.size),
              prefix.count == MemoryLayout<mach_header_64>.size else { return nil }
        let header = prefix.withUnsafeBytes { $0.loadUnaligned(as: mach_header_64.self) }
        guard header.magic == MH_MAGIC_64, header.sizeofcmds > 0, header.sizeofcmds <= 1024 * 1024,
              let table = try? file.read(upToCount: Int(header.sizeofcmds)),
              table.count == Int(header.sizeofcmds) else { return nil }
        var cursor = 0
        for _ in 0..<header.ncmds {
            guard table.count - cursor >= MemoryLayout<load_command>.size else { return nil }
            let cmd = table.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor, as: load_command.self) }
            let size = Int(cmd.cmdsize)
            guard size >= MemoryLayout<load_command>.size, size <= table.count - cursor else { return nil }
            if cmd.cmd == LC_SEGMENT_64 {
                let segmentSize = MemoryLayout<segment_command_64>.size
                let sectionSize = MemoryLayout<section_64>.size
                guard size >= segmentSize else { return nil }
                let segment = table.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: cursor, as: segment_command_64.self) }
                guard Int(segment.nsects) <= (size - segmentSize) / sectionSize else { return nil }
                for index in 0..<Int(segment.nsects) {
                    let offset = cursor + segmentSize + index * sectionSize
                    let section = table.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: section_64.self) }
                    guard fieldName(section.segname) == ReleaseStamp.sectionSegment,
                          fieldName(section.sectname) == ReleaseStamp.sectionName else { continue }
                    guard section.size > 0, section.size <= 4096,
                          (try? file.seek(toOffset: UInt64(section.offset))) != nil,
                          let stamp = try? file.read(upToCount: Int(section.size)),
                          stamp.count == Int(section.size) else { return nil }
                    return ReleaseStamp.decode(stamp)
                }
            }
            cursor += size
        }
        return nil
    }

    private static func fieldName<T>(_ value: T) -> String {
        withUnsafeBytes(of: value) { String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self) }
    }
}
