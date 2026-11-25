import Foundation

/// A relay read that a person's command waits on — `csec remote status`,
/// `csec doctor`, pairing — must not hang on a wedged system service. The bound
/// decides nothing: the fallback is always a transient "could not tell", and
/// the next status check, request or account change asks again.
public enum RemoteApprovalBound {
    /// How long such a read may take.
    public static let readNanoseconds: UInt64 = 5_000_000_000

    /// `operation`'s result, or `fallback` once `bound` passes first. The
    /// operation is not awaited past the bound: a call that ignores
    /// cancellation must not hold the caller.
    public static func firstAnswer<Value: Sendable>(
        within bound: UInt64,
        otherwise fallback: Value,
        _ operation: @escaping @Sendable () async -> Value
    ) async -> Value {
        let answer = FirstAnswer<Value>()
        return await withCheckedContinuation { continuation in
            answer.install(continuation)
            let work = Task { answer.resume(with: await operation()) }
            let timer = Task {
                try? await Task.sleep(nanoseconds: bound)
                if !Task.isCancelled { answer.resume(with: fallback) }
            }
            answer.onResume = { work.cancel(); timer.cancel() }
        }
    }
}

/// Resumes one continuation with whichever answer arrives first.
private final class FirstAnswer<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Never>?
    private var cleanup: (@Sendable () -> Void)?
    private var finished = false

    func install(_ continuation: CheckedContinuation<Value, Never>) {
        lock.lock()
        self.continuation = continuation
        lock.unlock()
    }

    var onResume: (@Sendable () -> Void)? {
        get { lock.withLock { cleanup } }
        set {
            lock.lock()
            if finished {
                lock.unlock()
                newValue?()
                return
            }
            cleanup = newValue
            lock.unlock()
        }
    }

    func resume(with value: Value) {
        lock.lock()
        guard !finished, let continuation else {
            lock.unlock()
            return
        }
        finished = true
        self.continuation = nil
        let cleanup = self.cleanup
        self.cleanup = nil
        lock.unlock()
        continuation.resume(returning: value)
        cleanup?()
    }
}
