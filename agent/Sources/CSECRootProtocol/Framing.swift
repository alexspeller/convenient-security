import Foundation
#if canImport(Darwin)
import Darwin
#endif

// Length-prefixed framing over a raw fd: a 4-byte big-endian length, then that
// many bytes of payload. See docs/protocol.md.

private let maxFrameBytes = 8 * 1024 * 1024

public func readExactly(_ fd: Int32, _ count: Int) -> [UInt8]? {
    guard count > 0 else { return [] }
    var buffer = [UInt8](repeating: 0, count: count)
    var offset = 0
    while offset < count {
        let n = buffer.withUnsafeMutableBytes { raw -> Int in
            read(fd, raw.baseAddress!.advanced(by: offset), count - offset)
        }
        if n < 0, errno == EINTR { continue }
        if n <= 0 { return nil }
        offset += n
    }
    return buffer
}

public func writeExactly(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
    var offset = 0
    while offset < bytes.count {
        let n = bytes.withUnsafeBytes { raw -> Int in
            write(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset)
        }
        if n < 0, errno == EINTR { continue }
        if n <= 0 { return false }
        offset += n
    }
    return true
}

public func readFrame(_ fd: Int32) -> Data? {
    guard let header = readExactly(fd, 4) else { return nil }
    let length = (UInt32(header[0]) << 24) | (UInt32(header[1]) << 16)
        | (UInt32(header[2]) << 8) | UInt32(header[3])
    if length == 0 || length > UInt32(maxFrameBytes) { return nil }
    guard let body = readExactly(fd, Int(length)) else { return nil }
    return Data(body)
}

@discardableResult
public func writeFrame(_ fd: Int32, _ data: Data) -> Bool {
    let length = UInt32(data.count)
    let header: [UInt8] = [
        UInt8((length >> 24) & 0xff),
        UInt8((length >> 16) & 0xff),
        UInt8((length >> 8) & 0xff),
        UInt8(length & 0xff),
    ]
    return writeExactly(fd, header + [UInt8](data))
}

// MARK: - Bounded silence
//
// The bounded variants below bound SILENCE — the gap between bytes — and never
// the total duration of a transfer. That distinction is the whole point: a
// request that is waiting on a human may legitimately take an hour, so nothing
// here may cap how long a caller waits; what it may cap is how long a peer that
// is supposed to be alive can say nothing at all.

/// How a bounded read ended. `timedOut` is deliberately distinct from `closed`:
/// only silence from a peer that is still connected points at a wedged process,
/// and only that case is reported as an unresponsive daemon.
public enum FrameReadOutcome: Sendable, Equatable {
    case frame(Data)
    case closed
    case timedOut
}

/// How a bounded write ended, with the same `timedOut` / `failed` split.
public enum FrameWriteOutcome: Sendable, Equatable {
    case written
    case timedOut
    case failed
}

private enum PollOutcome {
    case ready
    case expired
    case failed
}

/// Wait for `events` on `fd` until `deadline`. The deadline is a monotonic
/// `DispatchTime`, so changing the wall clock can neither shorten nor extend it.
private func waitFor(_ fd: Int32, events: Int32, until deadline: DispatchTime) -> PollOutcome {
    while true {
        let now = DispatchTime.now()
        guard now < deadline else { return .expired }
        let remaining = deadline.uptimeNanoseconds - now.uptimeNanoseconds
        let milliseconds = Int32(min(remaining / 1_000_000, UInt64(Int32.max)))
        var waiter = pollfd(fd: fd, events: Int16(events), revents: 0)
        let ready = poll(&waiter, 1, max(milliseconds, 1))
        if ready < 0 {
            if errno == EINTR { continue }
            return .failed
        }
        if ready == 0 { continue }
        return .ready
    }
}

/// Read exactly `count` bytes, restarting the `silence` clock on every byte that
/// arrives. A non-positive `silence` means "no bound" and falls back to the
/// plain blocking read.
public func readExactly(
    _ fd: Int32, _ count: Int, silence: TimeInterval
) -> FrameReadOutcome {
    guard count > 0 else { return .frame(Data()) }
    guard silence > 0 else {
        guard let bytes = readExactly(fd, count) else { return .closed }
        return .frame(Data(bytes))
    }
    var buffer = [UInt8](repeating: 0, count: count)
    var offset = 0
    while offset < count {
        switch waitFor(fd, events: Int32(POLLIN), until: DispatchTime.now() + silence) {
        case .failed: return .closed
        case .expired: return .timedOut
        case .ready: break
        }
        let n = buffer.withUnsafeMutableBytes { raw -> Int in
            read(fd, raw.baseAddress!.advanced(by: offset), count - offset)
        }
        if n < 0, errno == EINTR || errno == EAGAIN { continue }
        if n <= 0 { return .closed }
        offset += n
    }
    return .frame(Data(buffer))
}

/// `readFrame` with a bound on silence rather than on the total wait. Any frame
/// — a heartbeat or a real response — restarts the caller's clock.
public func readFrame(_ fd: Int32, silence: TimeInterval) -> FrameReadOutcome {
    let header: [UInt8]
    switch readExactly(fd, 4, silence: silence) {
    case .timedOut: return .timedOut
    case .closed: return .closed
    case let .frame(data): header = [UInt8](data)
    }
    let length = (UInt32(header[0]) << 24) | (UInt32(header[1]) << 16)
        | (UInt32(header[2]) << 8) | UInt32(header[3])
    if length == 0 || length > UInt32(maxFrameBytes) { return .closed }
    return readExactly(fd, Int(length), silence: silence)
}

/// `writeFrame` bounded the same way: a peer that will not drain its receive
/// buffer for `silence` seconds is reported as unresponsive rather than waited
/// on forever.
public func writeFrame(
    _ fd: Int32, _ data: Data, silence: TimeInterval
) -> FrameWriteOutcome {
    let length = UInt32(data.count)
    let header: [UInt8] = [
        UInt8((length >> 24) & 0xff),
        UInt8((length >> 16) & 0xff),
        UInt8((length >> 8) & 0xff),
        UInt8(length & 0xff),
    ]
    let bytes = header + [UInt8](data)
    guard silence > 0 else { return writeExactly(fd, bytes) ? .written : .failed }
    var offset = 0
    while offset < bytes.count {
        switch waitFor(fd, events: Int32(POLLOUT), until: DispatchTime.now() + silence) {
        case .failed: return .failed
        case .expired: return .timedOut
        case .ready: break
        }
        let n = bytes.withUnsafeBytes { raw -> Int in
            write(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset)
        }
        if n < 0, errno == EINTR || errno == EAGAIN { continue }
        if n <= 0 { return .failed }
        offset += n
    }
    return .written
}

/// Whether the peer has closed its end, without consuming a byte of the
/// protocol. `MSG_PEEK` leaves anything already queued in the socket buffer
/// exactly where it is, so a streaming client whose next frame is already
/// waiting is correctly reported as alive.
public func peerHasClosed(_ fd: Int32) -> Bool {
    var waiter = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
    var ready = poll(&waiter, 1, 0)
    while ready < 0 && errno == EINTR {
        waiter.revents = 0
        ready = poll(&waiter, 1, 0)
    }
    if ready < 0 { return true }
    if ready == 0 { return false }
    if waiter.revents & Int16(POLLERR | POLLNVAL) != 0 { return true }
    guard waiter.revents & Int16(POLLIN) != 0 else {
        // A bare POLLHUP with nothing readable is a closed peer.
        return waiter.revents & Int16(POLLHUP) != 0
    }
    var probe: UInt8 = 0
    while true {
        let n = withUnsafeMutablePointer(to: &probe) { pointer -> Int in
            recv(fd, pointer, 1, Int32(MSG_PEEK) | Int32(MSG_DONTWAIT))
        }
        if n == 0 { return true }
        if n > 0 { return false }
        if errno == EINTR { continue }
        // EAGAIN/EWOULDBLOCK: connected, nothing queued. Anything else is a
        // broken connection, which is the same "requester gone" condition.
        return errno != EAGAIN && errno != EWOULDBLOCK
    }
}
