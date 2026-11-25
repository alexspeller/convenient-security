import ConvenientSecurity
import CoreGraphics
import Darwin
import Foundation
import IOKit

/// An independent read of this process's screen-lock state, for checking the
/// live `ScreenLockState.isScreenLocked` probe whether or not the Mac is locked.
///
/// The CoreGraphics session dictionary the probe reads is this audit session's
/// entry in the IORegistry root's `IOConsoleUsers` list (the same keys and
/// session UUID, less `kCGSSessionIDKey`), and `loginwindow` sets the lock flag
/// there. Reading that list through IOKit and picking the entry whose
/// `kSCSecuritySessionID` is this process's audit session gives the value the
/// probe must report.
enum ScreenLockOracle {
    struct ConsoleEntry: Equatable {
        let found: Bool
        let locked: Bool
    }

    struct Sample {
        /// Whether CoreGraphics gave this process a session dictionary at all;
        /// without one (headless) the probe reads unlocked.
        let hasCGSession: Bool
        let consoleEntry: ConsoleEntry
        let probe: Bool

        var expected: Bool { hasCGSession && consoleEntry.locked }
    }

    static func consoleEntry() -> ConsoleEntry {
        var audit = auditinfo_addr()
        guard getaudit_addr(&audit, Int32(MemoryLayout<auditinfo_addr>.size)) == 0 else {
            return ConsoleEntry(found: false, locked: false)
        }
        let root = IORegistryGetRootEntry(kIOMainPortDefault)
        defer { IOObjectRelease(root) }
        guard
            let users = IORegistryEntryCreateCFProperty(
                root, "IOConsoleUsers" as CFString, kCFAllocatorDefault, 0)?
                .takeRetainedValue() as? [[String: Any]],
            let entry = users.first(where: {
                ($0["kSCSecuritySessionID"] as? NSNumber)?.int32Value == audit.ai_asid
            })
        else {
            return ConsoleEntry(found: false, locked: false)
        }
        let locked = (entry["CGSSessionScreenIsLocked"] as? NSNumber)?.boolValue ?? false
        return ConsoleEntry(found: true, locked: locked)
    }

    /// Reads the console entry on both sides of the probe so a lock or unlock
    /// landing mid-read is retried rather than reported as a mismatch. Nil only
    /// if the state kept changing across every attempt.
    static func sample(attempts: Int = 5) -> Sample? {
        for _ in 0..<attempts {
            let before = consoleEntry()
            let hasCGSession = CGSessionCopyCurrentDictionary() != nil
            let probe = ScreenLockState.isScreenLocked
            if consoleEntry() == before {
                return Sample(hasCGSession: hasCGSession, consoleEntry: before, probe: probe)
            }
            usleep(200_000)
        }
        return nil
    }
}
