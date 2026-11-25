import Darwin
import Foundation

// The one write path for HA-F13's fixes: replace a package manager's user-level
// config file under the home directory, atomically.
//
// csecd may hold Full Disk Access, which the user's own processes lack, so a
// symlink planted at ~/.npmrc or ~/.config could otherwise turn a fix into a
// write somewhere the user cannot write. Every directory from the home down is
// opened with O_NOFOLLOW relative to its parent, and the file itself must be a
// regular file or absent: a symlinked config (a dotfiles link, say) is refused,
// and the user sets it in the linked file. The new contents go to a temporary
// file in the same directory and are renamed over the old one, so a reader sees
// the old file or the new one, never a half-written one.

public protocol UserConfigWriting: Sendable {
    /// Replace `relativePath` under `home` with `contents`, creating missing
    /// directories (mode 0700) and a missing file (mode 0600); an existing file
    /// keeps its mode. Returns false, changing nothing, on any failure.
    func replace(home: String, relativePath: String, contents: String) -> Bool
}

public struct SystemUserConfigWriter: UserConfigWriting {
    public init() {}

    public func replace(home: String, relativePath: String, contents: String) -> Bool {
        let components = relativePath.split(separator: "/").map(String.init)
        guard let name = components.last,
              !components.contains(where: { $0 == "." || $0 == ".." || $0.isEmpty })
        else { return false }

        var directory = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { return false }
        for component in components.dropLast() {
            var next = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if next < 0, errno == ENOENT {
                guard mkdirat(directory, component, 0o700) == 0 || errno == EEXIST else {
                    close(directory)
                    return false
                }
                next = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            close(directory)
            guard next >= 0 else { return false }
            directory = next
        }
        defer { close(directory) }

        var mode: mode_t = 0o600
        var existing = stat()
        if fstatat(directory, name, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard (existing.st_mode & S_IFMT) == S_IFREG else { return false }
            mode = existing.st_mode & 0o7777
        } else if errno != ENOENT {
            return false
        }

        let temporary = ".\(name).csec-\(UUID().uuidString).tmp"
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard fd >= 0 else { return false }
        let bytes = Array(contents.utf8)
        var written = 0
        var ok = true
        while written < bytes.count {
            let n = bytes.withUnsafeBufferPointer { buffer in
                write(fd, buffer.baseAddress! + written, bytes.count - written)
            }
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { ok = false; break }
            written += n
        }
        // The open's mode is masked by the umask; set the intended one exactly.
        if ok { ok = fchmod(fd, mode) == 0 && fsync(fd) == 0 }
        close(fd)
        if ok { ok = renameat(directory, temporary, directory, name) == 0 }
        if !ok { unlinkat(directory, temporary, 0) }
        return ok
    }
}

/// Test double: records each replacement instead of touching the disk.
public final class FakeUserConfigWriter: UserConfigWriting, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [String: String] = [:]
    private let succeeds: Bool

    public init(succeeds: Bool = true) {
        self.succeeds = succeeds
    }

    /// Every successful replacement so far, by `home/relativePath`.
    public var writes: [String: String] {
        lock.lock(); defer { lock.unlock() }
        return recorded
    }

    public func replace(home: String, relativePath: String, contents: String) -> Bool {
        guard succeeds else { return false }
        lock.lock(); defer { lock.unlock() }
        recorded["\(home)/\(relativePath)"] = contents
        return true
    }
}
