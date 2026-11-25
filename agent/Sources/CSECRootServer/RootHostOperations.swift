import Foundation
import CSECRootProtocol

/// Serves csecd's host-audit reads and applies apart from the launch
/// coordinator. A request runs fixed system tools that may each take up to
/// `HostOpsExecutor`'s per-command timeout, so it blocks its caller for
/// seconds at a time, and csecd's audit sends a dozen of them. Run inside
/// `RootLaunchCoordinator` they held up every launch transition and the
/// maintenance timer's soft-TTL, hard-TTL and launcher-death kill sweeps for
/// the whole audit; run on a cooperative-pool thread they would starve every
/// actor in rootd. The server therefore calls this from the connection's own
/// thread, where blocking holds up nothing but that connection.
///
/// One request runs at a time, as it did inside the coordinator: an apply's
/// commands never interleave with another apply's or a read's against the same
/// system configuration, and rootd never has more than one host tool running.
public final class RootHostOperations: @unchecked Sendable {
    /// Stands in for the privileged tools in synthetic mode.
    public typealias SyntheticRead = @Sendable (HostRootRead) -> HostHelperResult

    private let mode: RootHelperRuntimeMode
    private let syntheticRead: SyntheticRead
    private let oneAtATime = NSLock()

    public init(mode: RootHelperRuntimeMode, syntheticRead: SyntheticRead? = nil) {
        self.mode = mode
        self.syntheticRead = syntheticRead ?? { HostOpsExecutor.syntheticRead($0) }
    }

    /// Run one allow-listed, read-only host query as root and return its bounded
    /// output for the verified agent to parse value-free. `query` selects a fixed
    /// command in `HostOpsExecutor`; no caller string is ever executed.
    public func read(query: HostRootRead) throws -> RootHelperResponse {
        oneAtATime.lock()
        defer { oneAtATime.unlock() }
        let result: HostHelperResult
        switch mode {
        case .production:
            guard geteuid() == 0 else { throw RootHelperRuntimeError.rootRequired }
            result = HostOpsExecutor.read(query)
        case .syntheticTesting:
            result = syntheticRead(query)
        }
        return RootHelperResponse(requestID: "", hostResult: result)
    }

    /// Apply one reversible, allow-listed privileged change. The caller-supplied
    /// digest must equal this exact change's independently-recomputed digest, so
    /// a tampered or unreviewed change fails closed before any mutation.
    public func apply(change: HostRootChange, digest: String) throws -> RootHelperResponse {
        guard let expected = try? change.digest(), expected == digest else {
            throw RootHelperRuntimeError.invalidTransition
        }
        oneAtATime.lock()
        defer { oneAtATime.unlock() }
        let result: HostHelperResult
        switch mode {
        case .production:
            guard geteuid() == 0 else { throw RootHelperRuntimeError.rootRequired }
            result = HostOpsExecutor.apply(change)
        case .syntheticTesting:
            result = HostHelperResult(exitCode: 0, applied: true)
        }
        return RootHelperResponse(requestID: "", hostResult: result)
    }
}
