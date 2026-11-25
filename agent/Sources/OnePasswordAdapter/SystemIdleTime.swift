import Foundation
import IOKit

/// How long since someone last used the Mac's keyboard, mouse or trackpad.
///
/// 1Password's idle auto-lock counts from the same moment, so a Mac used
/// more recently than that lock's window proves 1Password has not
/// idle-locked. Read from IOHIDSystem's `HIDIdleTime`, which needs no
/// privilege and carries no content.
public enum SystemIdleTime {
    /// Seconds since the last input event, or nil when IOKit has no answer.
    public static func seconds() -> TimeInterval? {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOHIDSystem"))
        guard service != IO_OBJECT_NULL else { return nil }
        defer { IOObjectRelease(service) }
        guard let property = IORegistryEntryCreateCFProperty(
            service, "HIDIdleTime" as CFString, kCFAllocatorDefault, 0
        )?.takeRetainedValue(),
            let nanoseconds = property as? NSNumber
        else { return nil }
        return TimeInterval(nanoseconds.uint64Value) / 1_000_000_000
    }
}
