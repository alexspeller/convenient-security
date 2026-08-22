import Foundation
import CSECRootProtocol

/// A representation of a protected value that the output guard knows how to
/// recognize. These are deliberately finite, deterministic encodings; this is
/// not a claim that arbitrary transformations can be detected.
public enum OutputRedactionRepresentation: String, Codable, Sendable, Hashable {
    case exact
    case base64
    case base64URL = "base64url"
    case percentEncoded = "percent_encoded"
    case jsonEscaped = "json_escaped"
}

/// Value-free metadata returned when output was replaced. It is safe to use in
/// a warning or audit event: neither the secret nor its reference is present.
public struct OutputRedactionMatch: Codable, Sendable, Hashable {
    public let opaqueID: String
    public let representation: OutputRedactionRepresentation

    public init(opaqueID: String, representation: OutputRedactionRepresentation) {
        self.opaqueID = opaqueID
        self.representation = representation
    }
}

/// One streaming matcher rule. Pattern and replacement bytes stay private so
/// logging or reflecting a rule cannot accidentally print protected material.
public struct OutputRedactionPattern: Sendable {
    public let opaqueID: String
    public let representation: OutputRedactionRepresentation
    fileprivate let bytes: [UInt8]
    fileprivate let replacement: [UInt8]

    public init(
        opaqueID: String,
        representation: OutputRedactionRepresentation,
        bytes: Data,
        replacement: Data
    ) {
        self.opaqueID = opaqueID
        self.representation = representation
        self.bytes = Array(bytes)
        self.replacement = Array(replacement)
    }
}

/// Stable rules derived from the values resolved for one launch. The catalog
/// never fetches additional vault values: it can protect only values that this
/// launcher already received.
public struct OutputRedactionCatalog: Sendable {
    /// Below this threshold, automatic replacement is likely to corrupt normal
    /// output (for example a secret equal to `true`, `dev`, or `1`). Callers can
    /// explicitly opt in when that trade-off is appropriate.
    public static let minimumAutomaticSecretBytes = 8

    public let patterns: [OutputRedactionPattern]
    public let protectedValueCount: Int
    public let skippedShortValueCount: Int
    public let skippedEmptyValueCount: Int

    public init(
        valuesByReference: [String: String],
        labelStyle: OutputRedactionLabelStyle = .opaque,
        includeShortValues: Bool = false
    ) {
        // Multiple references can intentionally resolve to the same credential.
        // Deduplicate by value and choose the lexically first reference so IDs
        // and opt-in reference replacements are deterministic.
        var referenceForValue: [Data: String] = [:]
        var empty = 0
        for reference in valuesByReference.keys.sorted() {
            guard let value = valuesByReference[reference] else { continue }
            let bytes = Data(value.utf8)
            guard !bytes.isEmpty else {
                empty += 1
                continue
            }
            if referenceForValue[bytes] == nil {
                referenceForValue[bytes] = reference
            }
        }

        let ordered = referenceForValue.map { (bytes: $0.key, reference: $0.value) }
            .sorted { lhs, rhs in lhs.reference < rhs.reference }
        var built: [OutputRedactionPattern] = []
        var globallyClaimedPatterns: [Data: Int] = [:]
        var skippedShort = 0

        for (offset, entry) in ordered.enumerated() {
            guard includeShortValues || entry.bytes.count >= Self.minimumAutomaticSecretBytes else {
                skippedShort += 1
                continue
            }

            let opaqueID = "secret-\(offset + 1)"
            let replacement: Data
            switch labelStyle {
            case .opaque:
                replacement = Data("[csec:\(opaqueID)]".utf8)
            case .reference:
                let safeReference = (try? SecretRef(entry.reference))?.safeInlineURI
                    ?? "[csec:\(opaqueID)]"
                replacement = Data(safeReference.utf8)
            }

            for variant in Self.variants(of: entry.bytes) {
                // A representation can collide with another value or encoding.
                // An exact value owns its own bytes over another credential's
                // derived encoding; other ties retain stable reference order.
                let pattern = OutputRedactionPattern(
                    opaqueID: opaqueID,
                    representation: variant.representation,
                    bytes: variant.bytes,
                    replacement: replacement
                )
                if let existing = globallyClaimedPatterns[variant.bytes] {
                    if variant.representation == .exact,
                       built[existing].representation != .exact {
                        built[existing] = pattern
                    }
                    continue
                }
                globallyClaimedPatterns[variant.bytes] = built.count
                built.append(pattern)
            }
        }

        // Candidates sharing a first byte are tried longest-first. The matcher
        // therefore has deterministic longest-match semantics for prefixes.
        patterns = built.sorted {
            if $0.bytes.count != $1.bytes.count { return $0.bytes.count > $1.bytes.count }
            if $0.opaqueID != $1.opaqueID { return $0.opaqueID < $1.opaqueID }
            return $0.representation.rawValue < $1.representation.rawValue
        }
        protectedValueCount = ordered.count
        skippedShortValueCount = skippedShort
        skippedEmptyValueCount = empty
    }

    private static func variants(
        of bytes: Data
    ) -> [(bytes: Data, representation: OutputRedactionRepresentation)] {
        var result: [(Data, OutputRedactionRepresentation)] = []
        var seen = Set<Data>()

        func append(_ candidate: Data, _ representation: OutputRedactionRepresentation) {
            guard !candidate.isEmpty, seen.insert(candidate).inserted else { return }
            result.append((candidate, representation))
        }

        append(bytes, .exact)

        let base64 = bytes.base64EncodedData()
        append(base64, .base64)

        if let base64String = String(data: base64, encoding: .ascii) {
            let urlPadded = base64String
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
            append(Data(urlPadded.utf8), .base64URL)
            let paddingCount = urlPadded.reversed().prefix(while: { $0 == "=" }).count
            if paddingCount > 0 {
                append(Data(urlPadded.dropLast(paddingCount).utf8), .base64URL)
            }
        }

        let percentUpper = percentEncode(bytes, lowercaseHex: false)
        append(percentUpper, .percentEncoded)
        append(percentEncode(bytes, lowercaseHex: true), .percentEncoded)

        if let value = String(data: bytes, encoding: .utf8),
           let encoded = try? JSONEncoder().encode(value),
           encoded.count >= 2 {
            append(encoded.subdata(in: 1..<(encoded.count - 1)), .jsonEscaped)
        }

        return result
    }

    private static func percentEncode(_ bytes: Data, lowercaseHex: Bool) -> Data {
        let hex = Array((lowercaseHex ? "0123456789abcdef" : "0123456789ABCDEF").utf8)
        var output: [UInt8] = []
        output.reserveCapacity(bytes.count * 3)
        for byte in bytes {
            let unreserved = (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122)
                || (byte >= 48 && byte <= 57)
                || byte == 45 || byte == 46 || byte == 95 || byte == 126
            if unreserved {
                output.append(byte)
            } else {
                output.append(37) // %
                output.append(hex[Int(byte >> 4)])
                output.append(hex[Int(byte & 0x0f)])
            }
        }
        return Data(output)
    }
}

public struct OutputRedactionResult: Sendable {
    public let data: Data
    public let matches: [OutputRedactionMatch]

    public init(data: Data, matches: [OutputRedactionMatch]) {
        self.data = data
        self.matches = matches
    }
}

/// Binary-safe streaming substitution. It withholds at most
/// `longestPatternLength - 1` bytes, so a protected value split across arbitrary
/// child writes cannot be partially forwarded before the matcher can decide.
public struct StreamingOutputRedactor: Sendable {
    private var candidatesByFirstByte: [UInt8: [OutputRedactionPattern]] = [:]
    private var longestPatternLength = 0
    private var claimedPatterns = Set<Data>()
    private var pending: [UInt8] = []

    public init(patterns: [OutputRedactionPattern]) {
        add(patterns: patterns)
    }

    /// Add newly-active values without discarding a possible prefix already
    /// withheld from the previous chunk. Existing rules are retained for the
    /// lifetime of the stream even if their registry lease expires mid-command.
    public mutating func add(patterns: [OutputRedactionPattern]) {
        for pattern in patterns where !pattern.bytes.isEmpty {
            guard claimedPatterns.insert(Data(pattern.bytes)).inserted else { continue }
            candidatesByFirstByte[pattern.bytes[0], default: []].append(pattern)
            longestPatternLength = max(longestPatternLength, pattern.bytes.count)
        }
        for key in candidatesByFirstByte.keys {
            candidatesByFirstByte[key]?.sort {
                if $0.bytes.count != $1.bytes.count { return $0.bytes.count > $1.bytes.count }
                if $0.opaqueID != $1.opaqueID { return $0.opaqueID < $1.opaqueID }
                return $0.representation.rawValue < $1.representation.rawValue
            }
        }
    }

    public mutating func process(_ data: Data) -> OutputRedactionResult {
        pending.append(contentsOf: data)
        return drain(flushing: false)
    }

    public mutating func finish() -> OutputRedactionResult {
        drain(flushing: true)
    }

    private mutating func drain(flushing: Bool) -> OutputRedactionResult {
        guard longestPatternLength > 0 else {
            let result = Data(pending)
            pending.removeAll(keepingCapacity: true)
            return OutputRedactionResult(data: result, matches: [])
        }

        let safeStartLimit = flushing
            ? pending.count
            : max(0, pending.count - longestPatternLength + 1)
        var output: [UInt8] = []
        output.reserveCapacity(pending.count)
        var matches: [OutputRedactionMatch] = []
        var index = 0

        while index < pending.count, flushing || index < safeStartLimit {
            var matched: OutputRedactionPattern?
            if let candidates = candidatesByFirstByte[pending[index]] {
                for candidate in candidates {
                    let end = index + candidate.bytes.count
                    guard end <= pending.count else { continue }
                    if pending[index..<end].elementsEqual(candidate.bytes) {
                        matched = candidate
                        break // candidates are longest-first
                    }
                }
            }

            if let matched {
                output.append(contentsOf: matched.replacement)
                matches.append(OutputRedactionMatch(
                    opaqueID: matched.opaqueID,
                    representation: matched.representation
                ))
                index += matched.bytes.count
            } else {
                output.append(pending[index])
                index += 1
            }
        }

        if index > 0 {
            pending.removeFirst(index)
        }
        return OutputRedactionResult(data: Data(output), matches: matches)
    }
}
