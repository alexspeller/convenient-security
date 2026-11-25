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

/// Metadata returned when output was replaced. The secret value is never
/// present. The originating reference — value-free metadata the user already
/// holds in their sidecar/environment — is carried so an opt-in warning can name
/// which reference was redacted rather than an opaque ordinal.
public struct OutputRedactionMatch: Codable, Sendable, Hashable {
    public let opaqueID: String
    public let representation: OutputRedactionRepresentation
    /// Prompt-safe reference URI when the agent knows which reference produced
    /// this value, else `nil` (opaque ordinal only).
    public let reference: String?

    public init(
        opaqueID: String,
        representation: OutputRedactionRepresentation,
        reference: String? = nil
    ) {
        self.opaqueID = opaqueID
        self.representation = representation
        self.reference = reference
    }
}

/// One streaming matcher rule. Pattern and replacement bytes stay private so
/// logging or reflecting a rule cannot accidentally print protected material.
public struct OutputRedactionPattern: Sendable {
    public let opaqueID: String
    public let representation: OutputRedactionRepresentation
    /// Prompt-safe reference URI this value resolved from, when known. Surfaced
    /// only in an opt-in warning; never used to build the replacement bytes for
    /// an opaque label.
    public let reference: String?
    fileprivate let bytes: [UInt8]
    fileprivate let replacement: [UInt8]

    public init(
        opaqueID: String,
        representation: OutputRedactionRepresentation,
        reference: String? = nil,
        bytes: Data,
        replacement: Data
    ) {
        self.opaqueID = opaqueID
        self.representation = representation
        self.reference = reference
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
        valuesByReference: [String: Data],
        labelStyle: OutputRedactionLabelStyle = .opaque,
        includeShortValues: Bool = false
    ) {
        // Multiple references can intentionally resolve to the same credential.
        // Deduplicate by value and choose the lexically first reference so IDs
        // and opt-in reference replacements are deterministic.
        var referenceForValue: [Data: String] = [:]
        var empty = 0
        for reference in valuesByReference.keys.sorted() {
            guard let bytes = valuesByReference[reference] else { continue }
            guard !bytes.isEmpty else {
                empty += 1
                continue
            }
            if referenceForValue[bytes] == nil {
                referenceForValue[bytes] = reference
            }
        }
        self.init(
            nonEmpty: referenceForValue,
            emptyValueCount: empty,
            labelStyle: labelStyle,
            includeShortValues: includeShortValues
        )
    }

    /// Every value to mask, each with the reference it resolved from. Several
    /// values may name one reference — a rotated secret's old and new values
    /// were both released — and every one is masked.
    public init(
        referenceByValue: [Data: String],
        labelStyle: OutputRedactionLabelStyle = .opaque,
        includeShortValues: Bool = false
    ) {
        self.init(
            nonEmpty: referenceByValue.filter { !$0.key.isEmpty },
            emptyValueCount: referenceByValue.keys.filter(\.isEmpty).count,
            labelStyle: labelStyle,
            includeShortValues: includeShortValues
        )
    }

    private init(
        nonEmpty referenceForValue: [Data: String],
        emptyValueCount empty: Int,
        labelStyle: OutputRedactionLabelStyle,
        includeShortValues: Bool
    ) {
        // Reference order, then value order for values that share a reference,
        // keeps IDs deterministic.
        let ordered = referenceForValue.map { (bytes: $0.key, reference: $0.value) }
            .sorted { lhs, rhs in
                if lhs.reference != rhs.reference { return lhs.reference < rhs.reference }
                return lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
            }
        var built: [OutputRedactionPattern] = []
        var globallyClaimedPatterns: [Data: Int] = [:]
        var skippedShort = 0

        for (offset, entry) in ordered.enumerated() {
            guard includeShortValues || entry.bytes.count >= Self.minimumAutomaticSecretBytes else {
                skippedShort += 1
                continue
            }

            let opaqueID = "secret-\(offset + 1)"
            // Prompt-safe reference when the entry key is a real reference (the
            // agent's active-secret registry supplies these); a synthetic
            // registry key yields nil so callers fall back to the ordinal.
            let safeReference = (try? SecretRef(entry.reference))?.safeInlineURI
            let replacement: Data
            switch labelStyle {
            case .opaque:
                replacement = Data("[csec:\(opaqueID)]".utf8)
            case .reference:
                replacement = safeReference.map { Data("[redacted: \($0)]".utf8) }
                    ?? Data("[csec:\(opaqueID)]".utf8)
            }

            for variant in Self.variants(of: entry.bytes) {
                // A representation can collide with another value or encoding.
                // An exact value owns its own bytes over another credential's
                // derived encoding; other ties retain stable reference order.
                let pattern = OutputRedactionPattern(
                    opaqueID: opaqueID,
                    representation: variant.representation,
                    reference: safeReference,
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
    /// Escape-sequence state after the last byte that left `pending`; nil when
    /// the stream's bytes are not drawn by a terminal.
    private var terminalSyntax: TerminalControlSyntax?

    /// `interpretsTerminalControls` is for a stream a terminal draws (the
    /// supervised PTY). There a match never starts on a byte of an escape
    /// sequence's own structure — ESC, a CSI's parameters and final byte, a
    /// string's introducer or terminator — because the terminal consumes those
    /// bytes and never shows them. Without this, a query such as `ESC [ 0 c`
    /// whose final byte happens to begin a value's encoding is withheld, the
    /// terminal never answers, and the program waiting for the reply stalls.
    /// Text inside OSC/DCS strings (window titles, shell integration) is still
    /// scanned. Pipes and files keep strict byte matching: what reads them may
    /// not be a terminal.
    public init(patterns: [OutputRedactionPattern], interpretsTerminalControls: Bool = false) {
        terminalSyntax = interpretsTerminalControls ? TerminalControlSyntax() : nil
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
            if terminalSyntax != nil {
                for byte in pending { _ = terminalSyntax!.consume(byte) }
            }
            let result = Data(pending)
            pending.removeAll(keepingCapacity: true)
            return OutputRedactionResult(data: result, matches: [])
        }

        var output: [UInt8] = []
        output.reserveCapacity(pending.count)
        var matches: [OutputRedactionMatch] = []
        var index = 0
        // Advanced only over bytes that leave `pending`, so a withheld tail is
        // parsed afresh with the next chunk.
        var syntax = terminalSyntax

        scan: while index < pending.count {
            var syntaxAfterByte = syntax
            let isControlStructure = syntaxAfterByte?.consume(pending[index]) ?? false
            if !isControlStructure, let candidates = candidatesByFirstByte[pending[index]] {
                // Candidates are longest-first, so a still-completable longer
                // value is considered before a shorter complete match could
                // claim its leading bytes and break longest-match semantics.
                for candidate in candidates {
                    let end = index + candidate.bytes.count
                    if end <= pending.count {
                        guard pending[index..<end].elementsEqual(candidate.bytes) else { continue }
                        output.append(contentsOf: candidate.replacement)
                        matches.append(OutputRedactionMatch(
                            opaqueID: candidate.opaqueID,
                            representation: candidate.representation,
                            reference: candidate.reference
                        ))
                        if syntax != nil {
                            for byte in pending[index..<end] { _ = syntax!.consume(byte) }
                        }
                        index = end
                        continue scan
                    }
                    // Withhold only a tail that genuinely tracks this
                    // candidate's leading bytes: unseen input could still
                    // complete the match. Anything else is forwarded
                    // immediately — a fixed lookback window would hold back
                    // interactive prompts and echoes for dozens of bytes and
                    // make a supervised shell unusable.
                    if !flushing,
                       pending[index...].elementsEqual(candidate.bytes.prefix(pending.count - index)) {
                        break scan
                    }
                }
            }
            output.append(pending[index])
            syntax = syntaxAfterByte
            index += 1
        }

        if index > 0 {
            pending.removeFirst(index)
        }
        terminalSyntax = syntax
        return OutputRedactionResult(data: Data(output), matches: matches)
    }
}

/// Enough of the ECMA-48 / VT parser to tell which bytes a terminal consumes
/// as escape-sequence structure. It follows the terminal's own reading: C0
/// controls inside a sequence are executed without ending it, CAN and SUB
/// abort it, ESC restarts it, and 8-bit C1 is not recognised (in UTF-8 output
/// those bytes are continuation bytes).
struct TerminalControlSyntax: Sendable, Equatable {
    private enum State: Sendable, Equatable {
        case ground
        case escape
        case escapeIntermediate
        case controlSequence
        /// OSC, DCS, APC, PM or SOS content, ended by BEL or ST (`ESC \`).
        case controlString
        case controlStringEscape
    }

    private var state: State = .ground

    /// Feed one byte; true when the terminal reads it as sequence structure
    /// rather than as text to draw or a control to execute.
    mutating func consume(_ byte: UInt8) -> Bool {
        let escape: UInt8 = 0x1B
        let cancel: UInt8 = 0x18, substitute: UInt8 = 0x1A
        switch state {
        case .ground:
            if byte == escape { state = .escape; return true }
            return false
        case .escape:
            switch byte {
            case escape: return true
            case 0x5B: state = .controlSequence; return true // [
            case 0x5D, 0x50, 0x58, 0x5E, 0x5F: state = .controlString; return true // ] P X ^ _
            case 0x20...0x2F: state = .escapeIntermediate; return true
            case 0x30...0x7E: state = .ground; return true
            case cancel, substitute: state = .ground; return false
            case 0x00...0x1F: return false
            default: state = .ground; return false
            }
        case .escapeIntermediate:
            switch byte {
            case escape: state = .escape; return true
            case 0x20...0x2F: return true
            case 0x30...0x7E: state = .ground; return true
            case cancel, substitute: state = .ground; return false
            case 0x00...0x1F: return false
            default: state = .ground; return false
            }
        case .controlSequence:
            switch byte {
            case escape: state = .escape; return true
            case 0x20...0x3F: return true
            case 0x40...0x7E: state = .ground; return true
            case cancel, substitute: state = .ground; return false
            case 0x00...0x1F: return false
            default: state = .ground; return false
            }
        case .controlString:
            switch byte {
            case 0x07: state = .ground; return true
            case escape: state = .controlStringEscape; return true
            case cancel, substitute: state = .ground; return false
            default: return false
            }
        case .controlStringEscape:
            if byte == 0x5C { state = .ground; return true } // \ completes ST
            // Any other byte after ESC abandons the string and is read as the
            // start of a new escape sequence.
            state = .escape
            return consume(byte)
        }
    }
}
