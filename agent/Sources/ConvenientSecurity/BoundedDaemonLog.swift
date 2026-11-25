import Darwin
import Foundation

/// Both standard streams feed one writer. Rotation therefore also bounds
/// output from libraries which write directly to stderr, between restarts.
public final class BoundedDaemonLog {
    private let path: String
    private let capacity: Int
    /// Stable across renames. A second daemon starting in the same private
    /// directory must never append to an archive or rotate the first one's log.
    private let writerLock: FileHandle
    private var file: FileHandle
    private var length: Int

    public init(path: String, capacity: Int = 1_048_576) throws {
        precondition(capacity > 0)
        self.path = path
        self.capacity = capacity
        let lock = open(path + ".lock", O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0o600)
        guard lock >= 0 else { throw POSIXError(.EIO) }
        writerLock = FileHandle(fileDescriptor: lock, closeOnDealloc: true)
        var lockInfo = stat()
        guard fstat(lock, &lockInfo) == 0, (lockInfo.st_mode & S_IFMT) == S_IFREG,
              lockInfo.st_uid == getuid(), lockInfo.st_nlink == 1,
              flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw POSIXError(.EBUSY) }
        let fd = open(path, O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0o600)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(), info.st_nlink == 1, fchmod(fd, 0o600) == 0 else {
            throw POSIXError(.EPERM)
        }
        length = Int(info.st_size)
        if length > capacity {
            // Preserve the tail of an existing, pre-rotation log on upgrade.
            try file.seek(toOffset: UInt64(length - capacity))
            let tail = try file.read(upToCount: capacity) ?? Data()
            try file.truncate(atOffset: 0)
            try file.write(contentsOf: tail)
            length = tail.count
        }
    }

    /// Called only by the pipe reader (or synchronously in tests).
    public func append(_ data: Data) throws {
        var offset = data.startIndex
        while offset < data.endIndex {
            if length >= capacity { try rotate() }
            let count = min(capacity - length, data.endIndex - offset)
            let written = data.withUnsafeBytes { raw in
                write(file.fileDescriptor, raw.baseAddress!.advanced(by: offset - data.startIndex), count)
            }
            if written < 0 && errno == EINTR { continue }
            guard written > 0 else { throw POSIXError(.EIO) }
            length += written
            offset += written
        }
    }

    private func rotate() throws {
        guard rename(path + ".1", path + ".2") == 0 || errno == ENOENT,
              rename(path, path + ".1") == 0 else { throw POSIXError(.EIO) }
        let fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            // Keep the full log reachable for a later retry (for instance
            // after free space returns). Never append past its cap.
            _ = rename(path + ".1", path)
            throw POSIXError(.EIO)
        }
        file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        length = 0
    }

    public static func redirect(in directory: String) throws {
        let log = try BoundedDaemonLog(path: (directory as NSString).appendingPathComponent("csecd.log"))
        let pipe = Pipe()
        let reader = pipe.fileHandleForReading
        let writer = pipe.fileHandleForWriting
        Thread.detachNewThread {
            var buffer = [UInt8](repeating: 0, count: 16_384)
            while true {
                let count = read(reader.fileDescriptor, &buffer, buffer.count)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { break }
                // Keep draining if the disk is full so diagnostics cannot stall the agent.
                try? log.append(Data(buffer.prefix(count)))
            }
        }
        guard dup2(writer.fileDescriptor, STDOUT_FILENO) >= 0,
              dup2(writer.fileDescriptor, STDERR_FILENO) >= 0 else { throw POSIXError(.EIO) }
    }
}
