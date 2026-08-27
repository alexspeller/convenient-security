import ConvenientSecurity
import Foundation

#if canImport(Darwin)
import Darwin
#endif

// Gathers the non-sensitive machine identity for the attestation header: computer
// name (hostname), hardware model, and macOS version. All are value-free system
// facts — never a serial number or any credential. Unprivileged, launcher-side.
enum HostIdentity {
    static func current() -> AttestationIdentity {
        AttestationIdentity(
            hostname: Host.current().localizedName ?? ProcessInfo.processInfo.hostName,
            hardwareModel: sysctlString("hw.model"),
            osVersion: osVersionString())
    }

    private static func osVersionString() -> String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return v.patchVersion == 0
            ? "\(v.majorVersion).\(v.minorVersion)"
            : "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
        let value = String(cString: buffer)
        return value.isEmpty ? nil : value
    }
}
