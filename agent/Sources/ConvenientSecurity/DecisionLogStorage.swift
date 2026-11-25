import CryptoKit
import Foundation

/// Size bounds for the decision log. Retention is by size only: a cap bounds
/// disk use and is not an expiry, and the files are sealed under a key only
/// csecd can read, so nothing argues for a time window. The usage
/// checkpoint's delay is a write-coalescing bound on how often a busy agent
/// rewrites the Keychain item, not an expiry of anything. The read budget
/// bounds how many frames one page of `csec log` may decrypt, so a filter that
/// matches little returns a partial page and a cursor instead of scanning the
/// whole log in one call.
public struct DecisionLogLimits: Sendable, Equatable {
    public var segmentBytes: UInt64
    public var decisionsCapBytes: UInt64
    public var usageCapBytes: UInt64
    public var usageCheckpointDelay: Duration
    public var maximumRecordBytes: Int
    public var readScanFrames: Int

    public static let standard = DecisionLogLimits(
        segmentBytes: 4 * 1_024 * 1_024,
        decisionsCapBytes: 32 * 1_024 * 1_024,
        usageCapBytes: 64 * 1_024 * 1_024,
        usageCheckpointDelay: .seconds(10),
        maximumRecordBytes: 64 * 1_024,
        readScanFrames: 20_000
    )

    public init(
        segmentBytes: UInt64,
        decisionsCapBytes: UInt64,
        usageCapBytes: UInt64,
        usageCheckpointDelay: Duration,
        maximumRecordBytes: Int,
        readScanFrames: Int = 20_000
    ) {
        self.segmentBytes = segmentBytes
        self.decisionsCapBytes = decisionsCapBytes
        self.usageCapBytes = usageCapBytes
        self.usageCheckpointDelay = usageCheckpointDelay
        self.maximumRecordBytes = maximumRecordBytes
        self.readScanFrames = max(1, readScanFrames)
    }

    public func cap(for stream: DecisionLogStream) -> UInt64 {
        stream == .decisions ? decisionsCapBytes : usageCapBytes
    }
}

/// The log's 32-byte master key, in the `decision-log`/`key-v1` protected
/// item. Frames are sealed under a key derived from it for the log alone;
/// other sealed csecd files derive their own (`DecisionLog.sealingKey`).
public struct DecisionLogKeyDocument: ProtectedDocument {
    public static let protectedItem: ProtectedItem = .decisionLogKey
    public static let formatVersion = 1

    public let key: Data

    public init(key: Data) {
        self.key = key
    }

    public var isWellFormed: Bool { key.count == 32 }
}

/// Where a stream's durable chain ended when the checkpoint was written.
public struct DecisionLogStreamHead: Codable, Sendable, Equatable {
    public var segmentID: String
    public var seq: UInt64
    public var tag: Data
    /// The segment's length in bytes just after that frame.
    public var length: UInt64
    /// Every sequence number at or below this was pruned on purpose.
    public var prunedThroughSeq: UInt64
    public var formatVersion: Int

    public init(segmentID: String, seq: UInt64, tag: Data, length: UInt64, prunedThroughSeq: UInt64) {
        self.segmentID = segmentID
        self.seq = seq
        self.tag = tag
        self.length = length
        self.prunedThroughSeq = prunedThroughSeq
        self.formatVersion = DecisionLogFrame.formatVersion
    }

    public var link: DecisionLogChainLink {
        DecisionLogChainLink(segmentID: segmentID, seq: seq, tag: tag)
    }

    var isWellFormed: Bool {
        DecisionLogSegmentName.isSegmentID(segmentID)
            && seq > 0
            && tag.count == DecisionLogFrame.tagBytes
            && length >= UInt64(DecisionLogFrame.minimumFrameBytes)
            && prunedThroughSeq < seq
            && formatVersion == DecisionLogFrame.formatVersion
    }
}

/// The `decision-log`/`head-v1` protected item: each stream's durable head.
/// Same-UID code can neither write nor roll it back, so a log file that ends
/// before it, or disagrees with it, was cut or replaced.
public struct DecisionLogCheckpoint: ProtectedDocument {
    public static let protectedItem: ProtectedItem = .decisionLogCheckpoint
    public static let formatVersion = 1

    /// The most unmovable junk or foreign files remembered. Past this, the
    /// lowest digests are kept and the others are recorded again at each start
    /// until they can be moved, which is harmless: they break no chain.
    public static let maximumUnmovable = 32
    /// The most of csecd's own damaged segments remembered. They are kept
    /// apart from `unmovable` and never evicted to make room, because one that
    /// is walked again breaks the chain at every start. Real segments bound
    /// them (about 24 live at the standard caps, and each one costs a recorded
    /// finding); this bound keeps the item within its 4 KiB.
    public static let maximumExcludedSegments = 96

    public var decisions: DecisionLogStreamHead?
    public var usage: DecisionLogStreamHead?
    /// Digests of files a finding already recorded that csecd could not set
    /// aside (an immutable entry): they are skipped quietly afterwards, so a
    /// file csecd cannot move neither holds the log nor raises the same
    /// finding at every start. `csec status` keeps listing them.
    public var unmovable: [String]?
    /// Digests of csecd's own segments (their first frame authenticates) that
    /// a recorded finding took out of the chain but could not set aside. They
    /// are left out of every later walk. Planted files never go here, so they
    /// cannot push one out.
    public var excludedSegments: [String]?

    public init(
        decisions: DecisionLogStreamHead? = nil,
        usage: DecisionLogStreamHead? = nil,
        unmovable: [String]? = nil,
        excludedSegments: [String]? = nil
    ) {
        self.decisions = decisions
        self.usage = usage
        self.unmovable = unmovable
        self.excludedSegments = excludedSegments
    }

    public subscript(stream: DecisionLogStream) -> DecisionLogStreamHead? {
        get { stream == .decisions ? decisions : usage }
        set {
            if stream == .decisions { decisions = newValue } else { usage = newValue }
        }
    }

    public var isWellFormed: Bool {
        (decisions?.isWellFormed ?? true) && (usage?.isWellFormed ?? true)
            && (unmovable?.count ?? 0) <= Self.maximumUnmovable
            && (excludedSegments?.count ?? 0) <= Self.maximumExcludedSegments
            && ((unmovable ?? []) + (excludedSegments ?? [])).allSatisfy {
                $0.count == 16 && $0.allSatisfy(\.isHexDigit)
            }
    }

    /// The digest `unmovable` holds for a file name.
    public static func unmovableDigest(_ name: String) -> String {
        SHA256.hash(data: Data(name.utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
    }
}

/// `<stream>-<8-digit number>-<16 hex>.clog`. The segment ID (`number-random`)
/// is bound into every frame's associated data, so a segment renamed, copied
/// under another name, or moved to the other stream no longer authenticates.
/// The format is exact: csecd only ever generates names `parse` accepts (the
/// number is at most eight digits), and any other segment-shaped name is a
/// foreign file, never a segment.
struct DecisionLogSegmentName: Sendable, Equatable {
    static let fileExtension = ".clog"
    static let quarantineSuffix = ".quarantined"
    static let maximumNumber: UInt64 = 99_999_999

    let stream: DecisionLogStream
    let number: UInt64
    let random: String

    var segmentID: String { "\(Self.paddedNumber(number))-\(random)" }
    var fileName: String { "\(stream.rawValue)-\(segmentID)\(Self.fileExtension)" }
    var quarantinedFileName: String { fileName + Self.quarantineSuffix }

    /// A new segment name, or nil when `number` does not fit the format (a
    /// legitimate log never gets near it: numbers come only from verified
    /// segments, one per 4 MiB).
    static func fresh(stream: DecisionLogStream, number: UInt64) -> DecisionLogSegmentName? {
        guard number >= 1, number <= maximumNumber else { return nil }
        var bytes = [UInt8](repeating: 0, count: 8)
        for index in bytes.indices { bytes[index] = UInt8.random(in: 0...255) }
        let name = DecisionLogSegmentName(
            stream: stream, number: number,
            random: bytes.map { String(format: "%02x", $0) }.joined()
        )
        return parse(name.fileName) == name ? name : nil
    }

    /// The stream a segment-shaped name claims by its prefix, for a file whose
    /// name does not parse.
    static func claimedStream(_ fileName: String) -> DecisionLogStream? {
        DecisionLogStream.allCases.first { fileName.hasPrefix("\($0.rawValue)-") }
    }

    /// A live segment file name, or nil for anything else.
    static func parse(_ fileName: String) -> DecisionLogSegmentName? {
        guard fileName.hasSuffix(fileExtension) else { return nil }
        let stem = fileName.dropLast(fileExtension.count)
        let parts = stem.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let stream = DecisionLogStream(rawValue: String(parts[0])),
              isSegmentID("\(parts[1])-\(parts[2])"),
              let number = UInt64(parts[1]), number >= 1 else { return nil }
        return DecisionLogSegmentName(stream: stream, number: number, random: String(parts[2]))
    }

    /// A quarantined segment's stream and number, for size accounting.
    static func parseQuarantined(_ fileName: String) -> DecisionLogSegmentName? {
        guard fileName.hasSuffix(quarantineSuffix) else { return nil }
        return parse(String(fileName.dropLast(quarantineSuffix.count)))
    }

    static func isSegmentID(_ value: String) -> Bool {
        let parts = value.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[0].count == 8, parts[1].count == 16 else { return false }
        return parts[0].allSatisfy { $0.isASCII && $0.isNumber }
            && parts[1].allSatisfy { $0.isASCII && $0.isHexDigit && !$0.isUppercase }
    }

    private static func paddedNumber(_ number: UInt64) -> String {
        let digits = String(number)
        return String(repeating: "0", count: max(0, 8 - digits.count)) + digits
    }
}

/// One sealed frame: `magic "CSL1" | u32 len | u64 seq | nonce12 |
/// AES-GCM(JSON record) | tag16`, big-endian, where `len` is the ciphertext
/// length. The associated data is `"csec-decision-log-v1\0" | stream | 0 |
/// segmentID | 0 | seq | prevTag`: the previous frame's tag chains every
/// frame to the one before it. A segment's first frame uses an all-zero
/// `prevTag`; its link to the previous segment is the record's own `chain`
/// field, authenticated with the rest of the record. That lets a segment
/// that resumes the chain after an integrity finding be verified without
/// the checkpoint it resumed from.
enum DecisionLogFrame {
    static let formatVersion = 1
    static let magic: [UInt8] = Array("CSL1".utf8)
    static let headerBytes = 4 + 4 + 8 + 12
    static let tagBytes = 16
    static let minimumFrameBytes = headerBytes + tagBytes
    static let zeroTag = Data(repeating: 0, count: tagBytes)

    enum Parsed {
        case end
        /// Fewer bytes remain than a whole frame needs.
        case incomplete
        /// The bytes at this offset are not a frame header.
        case malformed
        case frame(seq: UInt64, nonce: Data, ciphertext: Data, tag: Data, next: Int)
    }

    static func associatedData(
        stream: DecisionLogStream, segmentID: String, seq: UInt64, previousTag: Data
    ) -> Data {
        var data = Data("csec-decision-log-v1\0".utf8)
        data.append(Data(stream.rawValue.utf8))
        data.append(0)
        data.append(Data(segmentID.utf8))
        data.append(0)
        appendBigEndian(seq, to: &data)
        data.append(previousTag)
        return data
    }

    static func seal(
        _ plaintext: Data,
        key: SymmetricKey,
        stream: DecisionLogStream,
        segmentID: String,
        seq: UInt64,
        previousTag: Data
    ) throws -> (frame: Data, tag: Data) {
        let box = try AES.GCM.seal(
            plaintext, using: key, nonce: AES.GCM.Nonce(),
            authenticating: associatedData(
                stream: stream, segmentID: segmentID, seq: seq, previousTag: previousTag
            )
        )
        var frame = Data(magic)
        appendBigEndian(UInt32(box.ciphertext.count), to: &frame)
        appendBigEndian(seq, to: &frame)
        frame.append(contentsOf: box.nonce)
        frame.append(box.ciphertext)
        frame.append(box.tag)
        return (frame, Data(box.tag))
    }

    static func parse(_ bytes: [UInt8], at offset: Int, maximumRecordBytes: Int) -> Parsed {
        let remaining = bytes.count - offset
        if remaining == 0 { return .end }
        if remaining < magic.count {
            return Array(bytes[offset...]) == Array(magic.prefix(remaining)) ? .incomplete : .malformed
        }
        guard Array(bytes[offset..<(offset + magic.count)]) == magic else { return .malformed }
        guard remaining >= headerBytes else { return .incomplete }
        let length = Int(readBigEndian(bytes, at: offset + 4, count: 4))
        guard length <= maximumRecordBytes else { return .malformed }
        let seq = readBigEndian(bytes, at: offset + 8, count: 8)
        let total = headerBytes + length + tagBytes
        guard remaining >= total else { return .incomplete }
        let nonceStart = offset + 16
        let cipherStart = nonceStart + 12
        let tagStart = cipherStart + length
        return .frame(
            seq: seq,
            nonce: Data(bytes[nonceStart..<cipherStart]),
            ciphertext: Data(bytes[cipherStart..<tagStart]),
            tag: Data(bytes[tagStart..<(tagStart + tagBytes)]),
            next: offset + total
        )
    }

    static func open(
        nonce: Data, ciphertext: Data, tag: Data, key: SymmetricKey, associatedData: Data
    ) -> Data? {
        guard let nonce = try? AES.GCM.Nonce(data: nonce),
              let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag) else {
            return nil
        }
        return try? AES.GCM.open(box, using: key, authenticating: associatedData)
    }

    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        withUnsafeBytes(of: value.bigEndian) { data.append(contentsOf: $0) }
    }

    private static func readBigEndian(_ bytes: [UInt8], at offset: Int, count: Int) -> UInt64 {
        var value: UInt64 = 0
        for index in offset..<(offset + count) {
            value = value << 8 | UInt64(bytes[index])
        }
        return value
    }
}
