import Foundation

/// `csec backup …` over the authenticated socket.
public enum NativeStoreBackupAction: String, Codable, Sendable {
    case status
    /// csecd makes a recovery kit and holds it for this caller; the reply
    /// carries it to the launcher, which shows it in its own window.
    case beginSetup = "begin_setup"
    /// After one Touch ID, the held kit becomes the backup and every store
    /// is backed up under it.
    case completeSetup = "complete_setup"
    case cancelSetup = "cancel_setup"
    /// One Touch ID, then every store's bundle is brought up to date.
    case sync
    /// The bundles a recovery kit opens, listed value-free; nothing changes
    /// (iCloud Drive is asked to download any bundle it has not yet).
    case previewRestore = "preview_restore"
    /// One Touch ID, then the stores this Mac lacks are put back; a Mac with
    /// no backup of its own carries the backup on, in a new folder under the
    /// same kit.
    case restore
    /// One Touch ID, then no more bundles are written.
    case off
}

public struct NativeStoreBackupRequest: Codable, Sendable {
    public static let maximumKitBytes = 512
    public static let maximumFolderBytes = 1024

    public let requestID: String
    public let action: NativeStoreBackupAction
    /// `complete_setup` / `cancel_setup`: the session `begin_setup` returned.
    public let sessionID: String?
    /// `preview_restore` / `restore`: the kit the human typed into the
    /// launcher's window. Never accepted for any other action.
    public let recoveryKit: String?
    /// `begin_setup`, `preview_restore`, `restore`: a folder other than
    /// iCloud Drive's to keep or find backups in.
    public let folder: String?

    public init(
        action: NativeStoreBackupAction,
        sessionID: String? = nil,
        recoveryKit: String? = nil,
        folder: String? = nil,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.action = action
        self.sessionID = sessionID
        self.recoveryKit = recoveryKit
        self.folder = folder
    }

    public var isWellFormed: Bool {
        let needsSession = action == .completeSetup || action == .cancelSetup
        let takesKit = action == .previewRestore || action == .restore
        let takesFolder = action == .beginSetup || takesKit
        return (sessionID != nil) == needsSession
            && (sessionID.map { UUID(uuidString: $0) != nil } ?? true)
            && (recoveryKit != nil) == takesKit
            && (recoveryKit.map { $0.utf8.count <= Self.maximumKitBytes } ?? true)
            && (folder == nil || takesFolder)
            && (folder.map {
                $0.hasPrefix("/") && $0.utf8.count <= Self.maximumFolderBytes && !$0.utf8.contains(0)
            } ?? true)
    }
}

/// One store a restore found, and what happened to it (or would).
public struct NativeStoreBackupRestoredItem: Codable, Sendable, Equatable {
    public enum Outcome: String, Codable, Sendable {
        /// Preview: it would be put back.
        case willRestore = "will_restore"
        case restored
        /// This Mac already has a store by that name; it is left as it is.
        case exists
        /// The bundle opened but its contents did not check out.
        case invalid
        /// The SSH catalog: how many keys it adds is in `count`.
        case merged
    }

    /// `doc`, `blob` or `ssh-catalog`; `store` is empty for the catalog.
    public let kind: String
    public let store: String
    /// Keys, blobs, or SSH keys held.
    public let count: Int
    public let backedUpAt: Date
    public let outcome: Outcome
}

public struct NativeStoreBackupRestoreReport: Codable, Sendable, Equatable {
    public let folder: String
    public let items: [NativeStoreBackupRestoredItem]
    /// Bundles in the folder that did not open under this kit.
    public let unreadableBundles: Int
    /// Whether this Mac carries on the restored backup (or, in a preview,
    /// would): only when it keeps no backup of its own and no store of its
    /// own shares a name with one in the backup.
    public let continuesBackup: Bool
    /// Bundles iCloud Drive had not downloaded to this Mac yet; csec asked
    /// for them, and a restore run again once they are here takes them too.
    public let notDownloadedBundles: Int
}

/// The one reply field for every backup action.
public struct NativeStoreBackupReply: Codable, Sendable, Equatable {
    public let status: NativeStoreBackupStatus?
    public let setupSessionID: String?
    /// `begin_setup` only: the kit, for the launcher's window.
    public let recoveryKit: String?
    /// `complete_setup` and `sync`.
    public let report: NativeStoreBackupReport?
    public let restore: NativeStoreBackupRestoreReport?

    public init(
        status: NativeStoreBackupStatus? = nil,
        setupSessionID: String? = nil,
        recoveryKit: String? = nil,
        report: NativeStoreBackupReport? = nil,
        restore: NativeStoreBackupRestoreReport? = nil
    ) {
        self.status = status
        self.setupSessionID = setupSessionID
        self.recoveryKit = recoveryKit
        self.report = report
        self.restore = restore
    }
}
