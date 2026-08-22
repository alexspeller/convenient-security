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
