import Foundation

/// One bound registration as the `delegation`/`registrations-v1` protected
/// item holds it: csec's hook saw Claude Code process P approve this program
/// in `permissionMode`, and the `csec ai` (or Bash tool shell) `command` has
/// already claimed it. A restarted csecd puts it back only while both
/// processes are the same incarnations in the same boot session, so a
/// long-running command keeps what the previous csecd already knew about it.
/// Every gate is judged again on each request; this carries only the hook's
/// observation, never an approval of a release.
public struct PersistedDelegationRegistration: Codable, Sendable, Equatable {
    public var agentPID: Int32
    public var agentStartTime: UInt64
    public var commandPID: Int32
    public var commandStartTime: UInt64
    public var programSHA256: String
    public var permissionMode: String
    public var hookCWD: String
    public var unwrapped: Bool
    public var launcherPath: String?
    /// On `DelegationProcessClock`, which counts from boot, so it stays
    /// comparable across csecd restarts within one boot session.
    public var arrivedAt: UInt64
    public var bootSessionUUID: String?

    public init(
        agentPID: Int32,
        agentStartTime: UInt64,
        commandPID: Int32,
        commandStartTime: UInt64,
        programSHA256: String,
        permissionMode: String,
        hookCWD: String,
        unwrapped: Bool,
        launcherPath: String?,
        arrivedAt: UInt64,
        bootSessionUUID: String?
    ) {
        self.agentPID = agentPID
        self.agentStartTime = agentStartTime
        self.commandPID = commandPID
        self.commandStartTime = commandStartTime
        self.programSHA256 = programSHA256
        self.permissionMode = permissionMode
        self.hookCWD = hookCWD
        self.unwrapped = unwrapped
        self.launcherPath = launcherPath
        self.arrivedAt = arrivedAt
        self.bootSessionUUID = bootSessionUUID
    }

    public var isWellFormed: Bool {
        agentPID > 1 && agentStartTime > 0 && commandPID > 1 && commandStartTime > 0
            && WireField.isLowercaseHex(programSHA256, length: 64)
            && !permissionMode.isEmpty
            && permissionMode.utf8.count <= AgentCommandRegistration.maximumPermissionModeBytes
            && permissionMode.utf8.allSatisfy { ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) }
            && WireField.isAbsolutePath(hookCWD)
            && (launcherPath.map { WireField.isAbsolutePath($0) } ?? true)
            && (bootSessionUUID.map { !$0.isEmpty && $0.utf8.count <= 256 } ?? true)
    }
}

/// The `delegation`/`registrations-v1` document. The item is csecd-only (see
/// `ProtectedItem`), so a same-UID process can neither forge a registration
/// into it nor roll it back to one a disable removed.
public struct DelegationRegistrationsDocument: ProtectedDocument, Equatable {
    public static let protectedItem: ProtectedItem = .delegationRegistrations
    public static let formatVersion = 1
    public static let maximumRegistrations = 1_024
    /// It records no decision, and every bind or prune rewrites it whole from
    /// csecd's own registrations. Holding one this build cannot read would
    /// only keep this csecd from persisting its own.
    public static let holdsUnreadableItem = false

    public var registrations: [PersistedDelegationRegistration]

    public init(registrations: [PersistedDelegationRegistration] = []) {
        self.registrations = registrations
    }

    public var isWellFormed: Bool {
        registrations.count <= Self.maximumRegistrations && registrations.allSatisfy(\.isWellFormed)
    }
}
