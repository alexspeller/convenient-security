import Darwin
import Foundation

/// One human review at a time across csecd and every sudo helper for this user.
/// This is presentation coordination, never authorization: the file is empty,
/// and every review still makes its own policy and biometric decision.
public struct ReviewPresentationLock: Sendable {
    public enum Failure: Error { case unsafePath, unavailable }

    /// confstr, rather than TMPDIR, gives the daemon and PAM's clean-environment
    /// helper the same private runtime directory. Never unlink the lock file:
    /// existing waiters must keep contending on the same inode.
    public static var shared: Self { Self(directory: AgentSocket.directory()) }

    private let directory: String

    /// An isolated private directory can be supplied by integration tests.
    public init(directory: String) { self.directory = directory }

    public func acquire() async throws -> Permit {
        try Task.checkCancellation()
        if mkdir(directory, 0o700) != 0, errno != EEXIST { throw Failure.unavailable }
        let parent = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw Failure.unsafePath }
        defer { close(parent) }
        var info = stat()
        guard fstat(parent, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o7777 == 0o700 else {
            throw Failure.unsafePath
        }
        let descriptor = openat(
            parent, "review.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600
        )
        guard descriptor >= 0 else { throw Failure.unsafePath }
        var handedOff = false
        defer { if !handedOff { close(descriptor) } }
        guard fstat(descriptor, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
              info.st_uid == getuid(), info.st_mode & 0o7777 == 0o600 else {
            throw Failure.unsafePath
        }
        while true {
            try Task.checkCancellation()
            if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
                // Cancellation can race the owner's release. Never present a
                // cancelled request just because it acquired the turn too.
                try Task.checkCancellation()
                handedOff = true
                return Permit(descriptor: descriptor)
            }
            guard errno == EWOULDBLOCK || errno == EINTR else { throw Failure.unavailable }
            // Do not block an executor thread or the main run loop on a human.
            // Existing requester watches and deadlines can cancel this wait.
            try await Task.sleep(nanoseconds: 50_000_000)
        }
    }

    /// Closing the descriptor releases the turn, including on process death.
    /// CLOEXEC prevents a child from accidentally keeping it alive.
    public final class Permit: @unchecked Sendable {
        private let lock = NSLock()
        private var descriptor: Int32

        fileprivate init(descriptor: Int32) { self.descriptor = descriptor }

        public func release() {
            lock.lock()
            let descriptor = self.descriptor
            self.descriptor = -1
            lock.unlock()
            if descriptor >= 0 { close(descriptor) }
        }

        deinit { release() }
    }
}
