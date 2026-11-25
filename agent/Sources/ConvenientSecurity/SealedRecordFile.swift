import CryptoKit
import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Why a private csecd record directory or file could not be used. Every case is
/// value-free: it names the condition, never a path's contents.
public enum SealedRecordError: Error, Sendable, Equatable, CustomStringConvertible {
    /// A name that could escape the directory (`/`, `..`, NUL, empty, too long).
    case unsafeName
    /// The directory or file is not a regular csecd-owned object: a symlink, a
    /// different owner, or the wrong file type.
    case notPrivate
    /// The file is larger than the caller allows.
    case tooLarge
    /// The file already exists where an exclusive create was asked for.
    case exists
    /// The sealed bytes do not authenticate under the key and domain given.
    case authenticationFailed
    /// A system call failed with this errno.
    case system(Int32)

    public var description: String {
        switch self {
        case .unsafeName: return "unsafe record file name"
        case .notPrivate: return "the record path is not a private csecd-owned object"
        case .tooLarge: return "the record file exceeds its size limit"
        case .exists: return "the record file already exists"
        case .authenticationFailed: return "the sealed record does not authenticate"
        case let .system(code): return "record file I/O failed (errno \(code))"
        }
    }
}

/// How far an append or sync pushes data before it returns.
public enum SealedSyncLevel: Sendable, Equatable {
    /// Written to the file; the kernel flushes it later.
    case none
    /// `fsync`: handed to the drive, which may still hold it in its cache.
    case fsync
    /// `F_FULLFSYNC`: the drive flushes its cache too, so a power loss cannot
    /// leave the Keychain checkpoint ahead of the bytes it names.
    case full
}

/// One private directory csecd keeps sealed records in (the decision log's
/// segments, the sealed host-audit baseline). Every operation opens the
/// directory itself with `O_NOFOLLOW` and requires it to be a directory owned
/// by this user, then works on names relative to that descriptor with
/// `openat`/`O_NOFOLLOW`, so a symlink planted at either level redirects
/// nothing. Every open of a name that already exists is `O_NONBLOCK`, so a
/// FIFO planted in place of a file can never hold csecd on the open; the type
/// check then refuses it. Permissions are defense in depth, repaired to exactly 0700/0600
/// whenever they drift, including an owner who locked csecd out of its own
/// directory or file: confidentiality and integrity come from the AEAD under a
/// key in the protected Keychain, never from the mode bits.
public struct SealedRecordDirectory: Sendable {
    public struct Entry: Sendable, Equatable {
        public let name: String
        public let size: UInt64
    }

    public let path: String

    public init(path: String) {
        self.path = path
    }

    /// Whether the directory exists as a directory (without following a
    /// symlink at its last component).
    public func exists() -> Bool {
        var info = stat()
        guard lstat(path, &info) == 0 else { return false }
        return (info.st_mode & S_IFMT) == S_IFDIR
    }

    /// Creates the directory (and its parents) as 0700 if needed, then checks
    /// it is a real, csecd-owned directory.
    public func prepare() throws {
        do {
            try FileManager.default.createDirectory(
                atPath: path,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: NSNumber(value: Int16(0o700))]
            )
        } catch {
            throw SealedRecordError.system(EIO)
        }
        let fd = try openDirectory()
        close(fd)
    }

    /// Regular files in the directory, by name. Anything else (a symlink, a
    /// subdirectory, another owner's file) is listed with size 0 under
    /// `foreignNames` so a caller can treat it as out of place.
    public func entries() throws -> (files: [Entry], foreignNames: [String]) {
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        let names: [String]
        do {
            names = try FileManager.default.contentsOfDirectory(atPath: path)
        } catch {
            throw SealedRecordError.system(EIO)
        }
        var files: [Entry] = []
        var foreign: [String] = []
        for name in names.sorted() where Self.isSafeName(name) {
            var info = stat()
            let status = name.withCString {
                fstatat(directoryFD, $0, &info, AT_SYMLINK_NOFOLLOW)
            }
            guard status == 0 else { continue }
            if (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == getuid(), info.st_size >= 0 {
                files.append(Entry(name: name, size: UInt64(info.st_size)))
            } else {
                foreign.append(name)
            }
        }
        return (files, foreign)
    }

    /// The whole file, or nil when it does not exist.
    public func read(_ name: String, maximumBytes: Int) throws -> Data? {
        guard Self.isSafeName(name) else { throw SealedRecordError.unsafeName }
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        guard let (fd, size) = try Self.openRegularFile(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) else {
            return nil
        }
        defer { close(fd) }
        guard size <= UInt64(maximumBytes) else { throw SealedRecordError.tooLarge }
        var bytes = [UInt8](repeating: 0, count: Int(size))
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { raw in
                Darwin.read(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw SealedRecordError.system(count < 0 ? errno : EIO) }
            offset += count
        }
        return Data(bytes)
    }

    /// Creates `name` as a new, empty 0600 file for appending. Fails with
    /// `.exists` rather than reuse a file someone else placed there.
    public func createExclusive(_ name: String) throws -> SealedAppendHandle {
        guard Self.isSafeName(name) else { throw SealedRecordError.unsafeName }
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        let fd = name.withCString {
            openat(
                directoryFD, $0,
                O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        if fd < 0, errno == EEXIST { throw SealedRecordError.exists }
        guard fd >= 0 else { throw SealedRecordError.system(errno) }
        guard fchmod(fd, mode_t(0o600)) == 0, fsync(directoryFD) == 0 else {
            let code = errno
            close(fd)
            throw SealedRecordError.system(code)
        }
        return SealedAppendHandle(fd: fd, length: 0)
    }

    /// Opens an existing csecd-owned regular file for appending at its end.
    public func openForAppend(_ name: String) throws -> SealedAppendHandle {
        guard Self.isSafeName(name) else { throw SealedRecordError.unsafeName }
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        guard let (fd, size) = try Self.openRegularFile(
            directoryFD, name, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC
        ) else { throw SealedRecordError.system(ENOENT) }
        return SealedAppendHandle(fd: fd, length: size)
    }

    /// Cuts `name` back to `length` bytes and makes that durable.
    public func truncate(_ name: String, to length: UInt64) throws {
        guard Self.isSafeName(name) else { throw SealedRecordError.unsafeName }
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        guard let (fd, _) = try Self.openRegularFile(directoryFD, name, O_WRONLY | O_NOFOLLOW | O_CLOEXEC) else {
            throw SealedRecordError.system(ENOENT)
        }
        defer { close(fd) }
        guard ftruncate(fd, off_t(length)) == 0, Self.synchronize(fd, .full) else {
            throw SealedRecordError.system(errno)
        }
    }

    /// Renames within the directory, refusing to replace an existing name.
    public func rename(_ name: String, to newName: String) throws {
        guard Self.isSafeName(name), Self.isSafeName(newName) else {
            throw SealedRecordError.unsafeName
        }
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        let status = name.withCString { from in
            newName.withCString { to in
                renameatx_np(directoryFD, from, directoryFD, to, UInt32(RENAME_EXCL))
            }
        }
        guard status == 0 else { throw SealedRecordError.system(errno) }
        _ = fsync(directoryFD)
    }

    /// Unlinks `name`; a name that is already gone is not an error.
    public func remove(_ name: String) throws {
        guard Self.isSafeName(name) else { throw SealedRecordError.unsafeName }
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        let status = name.withCString { unlinkat(directoryFD, $0, 0) }
        guard status == 0 || errno == ENOENT else { throw SealedRecordError.system(errno) }
        _ = fsync(directoryFD)
    }

    /// Replaces `name` with `data` through a synced temporary file and an atomic
    /// rename, so a reader sees the old bytes or the new ones, never a mix.
    public func writeAtomically(_ name: String, data: Data) throws {
        guard Self.isSafeName(name) else { throw SealedRecordError.unsafeName }
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        let temporary = ".csec-write-\(UUID().uuidString.lowercased())"
        let fd = temporary.withCString {
            openat(
                directoryFD, $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard fd >= 0 else { throw SealedRecordError.system(errno) }
        var keepTemporary = true
        defer {
            close(fd)
            if keepTemporary {
                temporary.withCString { _ = unlinkat(directoryFD, $0, 0) }
            }
        }
        try Self.writeAll(fd, data)
        guard fchmod(fd, mode_t(0o600)) == 0, Self.synchronize(fd, .full) else {
            throw SealedRecordError.system(errno)
        }
        let renamed = temporary.withCString { from in
            name.withCString { to in renameat(directoryFD, from, directoryFD, to) }
        }
        guard renamed == 0, Self.synchronize(directoryFD, .full) else { throw SealedRecordError.system(errno) }
        keepTemporary = false
    }

    /// Deletes every entry in the directory and then the directory itself. Used
    /// only by uninstall; an absent directory is already the goal.
    public func removeDirectory() throws {
        guard exists() else { return }
        let directoryFD = try openDirectory()
        let names = (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []
        var failure: Int32?
        for name in names where Self.isSafeName(name) {
            var info = stat()
            let isDirectory = name.withCString {
                fstatat(directoryFD, $0, &info, AT_SYMLINK_NOFOLLOW) == 0
            } && (info.st_mode & S_IFMT) == S_IFDIR
            let status = name.withCString {
                unlinkat(directoryFD, $0, isDirectory ? AT_REMOVEDIR : 0)
            }
            if status != 0, errno != ENOENT { failure = errno }
        }
        close(directoryFD)
        if let failure { throw SealedRecordError.system(failure) }
        guard Darwin.rmdir(path) == 0 || errno == ENOENT else {
            throw SealedRecordError.system(errno)
        }
    }

    /// Pushes everything written in this directory to stable storage:
    /// `F_FULLFSYNC` asks the drive to flush its whole cache, so this also
    /// covers files synced earlier with plain `fsync`.
    public func fullSynchronize() throws {
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        guard Self.synchronize(directoryFD, .full) else { throw SealedRecordError.system(errno) }
    }

    public static func isSafeName(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 255
            && !value.contains("/")
            && !value.contains("\0")
            && value != "."
            && value != ".."
    }

    private func openDirectory() throws -> Int32 {
        // `O_DIRECTORY` already refuses a FIFO here (ENOTDIR) before it could
        // wait; `O_NONBLOCK` keeps every existing-name open to the same rule.
        let flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        var fd = path.withCString { open($0, flags) }
        if fd < 0, errno == EACCES, Self.repairOwnMode(AT_FDCWD, path, directory: true) {
            fd = path.withCString { open($0, flags) }
        }
        guard fd >= 0 else {
            throw errno == ENOTDIR || errno == ELOOP
                ? SealedRecordError.notPrivate : SealedRecordError.system(errno)
        }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == getuid() else {
            close(fd)
            throw SealedRecordError.notPrivate
        }
        if (info.st_mode & 0o777) != 0o700, fchmod(fd, mode_t(0o700)) != 0 {
            close(fd)
            throw SealedRecordError.notPrivate
        }
        return fd
    }

    /// Opens an existing csecd-owned regular file, with its size; nil when the
    /// name does not exist. The open is `O_NONBLOCK` whatever the caller asks:
    /// a FIFO planted under the name (after a listing, or in place of a sealed
    /// file) would otherwise hold csecd on the open until another process
    /// opened its other end. Opened that way, it returns at once (for writing,
    /// ENXIO with no reader), the type check refuses it, and only a regular
    /// file goes on, with the flag cleared again.
    private static func openRegularFile(
        _ directoryFD: Int32, _ name: String, _ flags: Int32
    ) throws -> (fd: Int32, size: UInt64)? {
        let fd = openRepairing(directoryFD, name, flags | O_NONBLOCK)
        if fd < 0, errno == ENOENT { return nil }
        guard fd >= 0 else {
            throw errno == ENXIO ? SealedRecordError.notPrivate : SealedRecordError.system(errno)
        }
        do {
            let size = try checkedRegularFile(fd)
            let current = fcntl(fd, F_GETFL)
            guard current >= 0, fcntl(fd, F_SETFL, current & ~O_NONBLOCK) == 0 else {
                throw SealedRecordError.system(errno)
            }
            return (fd, size)
        } catch {
            close(fd)
            throw error
        }
    }

    /// Opens `name`, and when the owner's own mode bits lock csecd out
    /// (EACCES), restores 0600 on the file itself (never through a symlink)
    /// and tries once more.
    private static func openRepairing(_ directoryFD: Int32, _ name: String, _ flags: Int32) -> Int32 {
        let fd = name.withCString { openat(directoryFD, $0, flags) }
        guard fd < 0, errno == EACCES, repairOwnMode(directoryFD, name, directory: false) else { return fd }
        return name.withCString { openat(directoryFD, $0, flags) }
    }

    /// Restores csecd's own mode on a directory or regular file it owns,
    /// without following a symlink. False when the object is not one csecd
    /// should repair: a file with a second link is not csecd's alone (a hard
    /// link planted under csecd's name names someone else's file), so its
    /// mode is never changed.
    private static func repairOwnMode(_ directoryFD: Int32, _ name: String, directory: Bool) -> Bool {
        var info = stat()
        guard name.withCString({ fstatat(directoryFD, $0, &info, AT_SYMLINK_NOFOLLOW) }) == 0,
              info.st_uid == getuid(),
              (info.st_mode & S_IFMT) == (directory ? S_IFDIR : S_IFREG),
              directory || info.st_nlink == 1 else { return false }
        let mode = mode_t(directory ? 0o700 : 0o600)
        return name.withCString { fchmodat(directoryFD, $0, mode, AT_SYMLINK_NOFOLLOW) } == 0
    }

    /// `fsync`, or `F_FULLFSYNC` with `fsync` as the fallback when the file
    /// system does not support it.
    fileprivate static func synchronize(_ fd: Int32, _ level: SealedSyncLevel) -> Bool {
        switch level {
        case .none: return true
        case .fsync: return fsync(fd) == 0
        case .full: return fcntl(fd, F_FULLFSYNC) == 0 || fsync(fd) == 0
        }
    }

    /// The size of a csecd-owned regular file, repairing a drifted mode.
    private static func checkedRegularFile(_ fd: Int32) throws -> UInt64 {
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(),
              info.st_size >= 0 else {
            throw SealedRecordError.notPrivate
        }
        // Only a file csecd alone names has its mode repaired.
        if (info.st_mode & 0o777) != 0o600, info.st_nlink == 1, fchmod(fd, mode_t(0o600)) != 0 {
            throw SealedRecordError.notPrivate
        }
        return UInt64(info.st_size)
    }

    fileprivate static func writeAll(_ fd: Int32, _ data: Data) throws {
        var offset = 0
        try data.withUnsafeBytes { raw in
            while offset < raw.count {
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw SealedRecordError.system(count < 0 ? errno : EIO) }
                offset += count
            }
        }
    }
}

/// An open append-only file inside a `SealedRecordDirectory`. Owned by one
/// actor, which serializes every call; it is never shared across tasks.
public final class SealedAppendHandle: @unchecked Sendable {
    private var fd: Int32
    /// Bytes in the file, as this handle has written them.
    public private(set) var length: UInt64

    fileprivate init(fd: Int32, length: UInt64) {
        self.fd = fd
        self.length = length
    }

    deinit {
        close()
    }

    /// Appends `data` in full, or leaves the file exactly as long as before:
    /// a failed or partial write is cut back, so the file never ends in half a
    /// frame this process wrote. `sync` says how durable the append is when
    /// this returns.
    public func append(_ data: Data, sync: SealedSyncLevel) throws {
        guard fd >= 0 else { throw SealedRecordError.system(EBADF) }
        do {
            try SealedRecordDirectory.writeAll(fd, data)
            guard SealedRecordDirectory.synchronize(fd, sync) else { throw SealedRecordError.system(errno) }
        } catch {
            _ = ftruncate(fd, off_t(length))
            throw error
        }
        length += UInt64(data.count)
    }

    /// Makes every earlier append durable to `level`.
    public func synchronize(_ level: SealedSyncLevel = .fsync) throws {
        guard fd >= 0 else { throw SealedRecordError.system(EBADF) }
        guard SealedRecordDirectory.synchronize(fd, level) else { throw SealedRecordError.system(errno) }
    }

    public func close() {
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
    }
}

/// One whole-file sealed record: `magic "CSR1" | nonce12 | AES-GCM(ciphertext)
/// | tag16`, authenticated under a 32-byte key with the caller's domain and
/// associated data. A file sealed for one domain never opens as another, so
/// one key can seal the decision log and the host-audit baseline without one
/// standing in for the other.
public enum SealedRecordFile {
    public static let magic = Data("CSR1".utf8)
    /// Magic, nonce and tag.
    public static let overhead = 4 + 12 + 16

    public static func seal(
        _ plaintext: Data,
        key: SymmetricKey,
        domain: String,
        associatedData: Data = Data()
    ) throws -> Data {
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.seal(
                plaintext, using: key,
                authenticating: aad(domain: domain, associatedData: associatedData)
            )
        } catch {
            throw SealedRecordError.authenticationFailed
        }
        guard let combined = box.combined else { throw SealedRecordError.authenticationFailed }
        return magic + combined
    }

    public static func open(
        _ sealed: Data,
        key: SymmetricKey,
        domain: String,
        associatedData: Data = Data()
    ) throws -> Data {
        guard sealed.count >= overhead, sealed.prefix(magic.count) == magic else {
            throw SealedRecordError.authenticationFailed
        }
        do {
            let box = try AES.GCM.SealedBox(combined: sealed.dropFirst(magic.count))
            return try AES.GCM.open(
                box, using: key,
                authenticating: aad(domain: domain, associatedData: associatedData)
            )
        } catch {
            throw SealedRecordError.authenticationFailed
        }
    }

    private static func aad(domain: String, associatedData: Data) -> Data {
        var data = Data("csec-sealed-record-v1\0".utf8)
        data.append(Data(domain.utf8))
        data.append(0)
        data.append(associatedData)
        return data
    }
}
