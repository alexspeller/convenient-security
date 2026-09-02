import Foundation
import ConvenientSecurity

// Guided helpers (Decision 4). Some more-secure states need a choice or a state
// transition csec should walk the user through rather than silently flip:
//   - FileVault (HA-G03): drive `fdesetup enable`, keep the recovery key local
//     (never silently escrow to iCloud), and prompt the restart.
//   - Santa (HA-B08): link to the official signed North Pole Security package
//     (never download-and-exec) and describe a MONITOR-mode starting posture;
//     the helper never sets LOCKDOWN.
// Both are fully interactive terminal flows launched from `csec audit`.

enum GuidedHelper {
    // MARK: FileVault (HA-G03)

    static func fileVault() {
        Prompt.title("Guided: FileVault full-disk encryption")
        let status = runCapturing("/usr/bin/fdesetup", ["status"])
        if status.lowercased().contains("filevault is on") {
            Prompt.success("FileVault is already on. Nothing to do.")
            return
        }
        Prompt.note("""
        FileVault encrypts the whole startup disk so a lost or stolen Mac cannot be read.
        Enabling it:
          • requires your administrator password (via sudo),
          • generates a personal recovery key that will be shown ONCE — write it down and keep it safe,
          • keeps that key local (this helper never escrows it to iCloud),
          • needs a restart to begin encrypting.
        """)
        guard Prompt.confirm("Enable FileVault now?") else {
            Prompt.note("Skipped. You can enable it later in System Settings → Privacy & Security → FileVault.")
            return
        }
        // Run interactively, inheriting the terminal, so macOS handles the sudo
        // prompt and prints the recovery key directly to you — csec never captures
        // or stores the key value.
        let code = runInteractive("/usr/bin/sudo", ["fdesetup", "enable"])
        if code != 0 {
            Prompt.warn("fdesetup did not complete (exit \(code)). FileVault was not enabled.")
            return
        }
        Prompt.note("""
        FileVault is now enabling. IMPORTANT:
          • Save the recovery key shown above in a safe place.
          • To keep it inside a csec vault, run:  csec edit <store>   and add it as a field.
          • Restart to begin encryption:          sudo shutdown -r now
        """)
    }

    // MARK: Santa (HA-B08)

    static let santaReleasesURL = "https://github.com/northpolesec/santa/releases/latest"

    static func santa() {
        Prompt.title("Guided: Santa binary allow-listing")
        let installed = FileManager.default.fileExists(atPath: "/Applications/Santa.app")
            || FileManager.default.isExecutableFile(atPath: "/usr/local/bin/santactl")
        if installed {
            let status = runCapturing("/usr/local/bin/santactl", ["status"])
            let mode = status.lowercased().contains("lockdown") ? "LOCKDOWN" :
                (status.lowercased().contains("monitor") ? "MONITOR" : "unknown")
            Prompt.note("""
            Santa is installed (mode: \(mode)).
            Recommended starting posture is MONITOR mode — it logs every execution without
            blocking, so you learn what runs before you ever tighten to LOCKDOWN. Do not switch
            to LOCKDOWN until you have reviewed the MONITOR logs; a bad rule can lock you out of
            your own binaries.
            """)
            return
        }
        Prompt.note("""
        Santa (North Pole Security) is the single strongest control against a trojaned CLI
        executing: it allow-lists which binaries may run. csec will NOT download or install it
        automatically — install only the official signed package yourself:

          \(santaReleasesURL)

        After installing, start in MONITOR mode (log-only). Tighten to LOCKDOWN later, once you
        have reviewed what runs. csec deliberately never sets LOCKDOWN for you.
        """)
        if Prompt.confirm("Open the official Santa releases page now?") {
            _ = runInteractive("/usr/bin/open", [santaReleasesURL])
        }
    }

    // MARK: process helpers

    private static func runCapturing(_ path: String, _ args: [String]) -> String {
        guard FileManager.default.isExecutableFile(atPath: path) else { return "" }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    /// Run a command inheriting the terminal (interactive auth, live output).
    private static func runInteractive(_ path: String, _ args: [String]) -> Int32 {
        guard FileManager.default.isExecutableFile(atPath: path) else { return 127 }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        do { try process.run() } catch { return 126 }
        process.waitUntilExit()
        return process.terminationStatus
    }
}
