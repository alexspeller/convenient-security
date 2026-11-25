import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Liveness bounds for the authenticated agent socket.
///
/// csec's design ethos treats a time bound as presumptively wrong: it has to
/// prevent a concrete harm, never re-verify a decision on a clock. These bounds
/// earn their place against exactly one harm — a wedged `csecd` (a deadlocked
/// main actor, a hung synchronous call, SIGSTOP, an actor that never resumes)
/// hangs every `csec` command until the user notices and presses Ctrl-C.
///
/// What is bounded is the DAEMON'S SILENCE, never the human's wait. A prompt
/// cancelled behind the lock screen waits indefinitely for unlock and then
/// re-presents; a remote approval on a phone may be answered an hour later.
/// Those waits stay unbounded: while a request is being handled, an opted-in
/// client receives a heartbeat frame every `heartbeatInterval` seconds, and any
/// frame at all — heartbeat or response — restarts the client's clock. The
/// client only fails when `silenceDeadline` seconds pass with the daemon saying
/// nothing whatsoever, which no live daemon ever does.
public struct AgentLiveness: Sendable, Equatable {
    /// How often a busy server proves it is still alive to an opted-in client.
    public let heartbeatInterval: TimeInterval
    /// How long a client tolerates complete silence. Four missed heartbeats, so
    /// a loaded machine that drops a tick or two is never mistaken for a wedge.
    public let silenceDeadline: TimeInterval
    /// How long `connect()` may take. A wedged daemon that never calls accept()
    /// fills its listen backlog, after which a blocking connect waits forever.
    public let connectDeadline: TimeInterval
    /// How long a request write may stall against a peer that never drains its
    /// receive buffer.
    public let writeDeadline: TimeInterval
    /// Server side: how long an accepted connection may say nothing at all
    /// before its FIRST frame. Deliberately not applied to the gap between
    /// later frames — see `SocketServer.serve`.
    public let firstFrameDeadline: TimeInterval

    public init(
        heartbeatInterval: TimeInterval,
        silenceDeadline: TimeInterval,
        connectDeadline: TimeInterval,
        writeDeadline: TimeInterval,
        firstFrameDeadline: TimeInterval = AgentLiveness.defaultFirstFrameDeadline
    ) {
        self.heartbeatInterval = heartbeatInterval
        self.silenceDeadline = silenceDeadline
        self.connectDeadline = connectDeadline
        self.writeDeadline = writeDeadline
        self.firstFrameDeadline = firstFrameDeadline
    }

    public static let defaultHeartbeatInterval: TimeInterval = 5
    public static let defaultSilenceDeadline: TimeInterval = 20
    public static let defaultConnectDeadline: TimeInterval = 5
    public static let defaultWriteDeadline: TimeInterval = 10
    /// Generous on purpose: a peer that has connected is already code-identity
    /// checked and is about to write one small frame it already holds, so 30 s
    /// of complete silence is an abandoned or stuck connection, never a slow
    /// one. It bounds only the first frame, so it can never cut a session short.
    public static let defaultFirstFrameDeadline: TimeInterval = 30
    /// How often a busy server checks whether the requesting client has gone
    /// away. Cheap (one non-destructive poll/peek), so it can be brisk.
    public static let peerExitPollInterval: TimeInterval = 1

    /// The shipping bounds. Debug builds may shorten the silence deadline for
    /// integration tests that have to wedge a real daemon and watch a real
    /// client give up; release builds compile the lookup out entirely, exactly
    /// like `CSEC_SOCKET`. Shortening a liveness bound can only make csec fail
    /// sooner — it releases nothing and relaxes no trust check — so this knob
    /// weakens no security property even where it exists.
    public static var `default`: AgentLiveness {
        AgentLiveness(
            heartbeatInterval: debugOverrideSeconds.map { max($0 / 4, 0.05) }
                ?? defaultHeartbeatInterval,
            silenceDeadline: debugOverrideSeconds ?? defaultSilenceDeadline,
            connectDeadline: debugOverrideSeconds.map { min($0, defaultConnectDeadline) }
                ?? defaultConnectDeadline,
            writeDeadline: debugOverrideSeconds.map { min($0, defaultWriteDeadline) }
                ?? defaultWriteDeadline
        )
    }

    /// True only in a debug build with an integration-test bound selected.
    public static var isUsingDebugOverride: Bool { debugOverrideSeconds != nil }

    private static var debugOverrideSeconds: TimeInterval? {
        #if DEBUG
        guard let raw = getenv("CSEC_LIVENESS_DEADLINE_SECONDS"),
              let seconds = TimeInterval(String(cString: raw)),
              seconds.isFinite, seconds > 0, seconds <= defaultSilenceDeadline else {
            return nil
        }
        return seconds
        #else
        return nil
        #endif
    }

    /// The whole-request bound cs-selftest uses when it drives an in-process
    /// server: short enough to keep the suite fast, long enough that a loaded
    /// machine does not trip it spuriously.
    public static func forTesting(
        silenceDeadline: TimeInterval,
        firstFrameDeadline: TimeInterval = AgentLiveness.defaultFirstFrameDeadline
    ) -> AgentLiveness {
        AgentLiveness(
            heartbeatInterval: max(silenceDeadline / 4, 0.02),
            silenceDeadline: silenceDeadline,
            connectDeadline: silenceDeadline,
            writeDeadline: silenceDeadline,
            firstFrameDeadline: firstFrameDeadline
        )
    }
}

/// Transport-level framing that sits beside the request/response payloads: the
/// heartbeat frame, and the per-connection flag that says a client can read one.
///
/// This lives outside `Request` on purpose. Whether a client understands a
/// heartbeat is a property of the connection, not of the verb being asked, and
/// keeping it out of the `Request` enum means no per-case encoder has to know
/// about it. On the wire it is one extra top-level JSON key; the `Request`
/// decoder reads a keyed container, which silently ignores keys it does not
/// know, so an older daemon decodes the request exactly as before.
public enum WireTransport {
    /// The discriminator of a server→client liveness frame. `Response` has no
    /// `type` key of its own, so this can never collide with a real response.
    public static let heartbeatType = "heartbeat"
    /// The discriminator of a server→client notice: one value-free line for
    /// the requester's user, sent mid-request (that the request now waits on
    /// a human, `HumanWait`). Like a heartbeat it never satisfies the request.
    public static let noticeType = "notice"
    /// A notice's bound. csec prints it on one line.
    public static let maximumNoticeBytes = 512

    private struct Heartbeat: Codable {
        let version: Int
        let type: String
    }

    private struct Notice: Codable {
        let version: Int
        let type: String
        let message: String
    }

    private struct TransportEnvelope: Encodable {
        let request: Request
        let supportsHeartbeats: Bool
        let supportsNotices: Bool

        private enum TransportKeys: String, CodingKey {
            case supportsHeartbeats
            case supportsNotices
        }

        func encode(to encoder: Encoder) throws {
            // Both containers write into the same top-level JSON object: the
            // verb's own keys, then the transport flags beside them.
            try request.encode(to: encoder)
            var container = encoder.container(keyedBy: TransportKeys.self)
            try container.encode(supportsHeartbeats, forKey: .supportsHeartbeats)
            // Written only when set, so a client that reads no notices sends a
            // byte-identical frame to before.
            if supportsNotices {
                try container.encode(true, forKey: .supportsNotices)
            }
        }
    }

    private struct TransportFlags: Decodable {
        let supportsHeartbeats: Bool?
        let supportsNotices: Bool?
        let type: String?
        let message: String?
    }

    /// Encode a request frame, declaring whether this client can read heartbeat
    /// and notice frames on the connection.
    public static func encodeRequest(
        _ request: Request, supportsHeartbeats: Bool, supportsNotices: Bool = false
    ) throws -> Data {
        try JSONEncoder().encode(
            TransportEnvelope(
                request: request, supportsHeartbeats: supportsHeartbeats, supportsNotices: supportsNotices
            )
        )
    }

    /// One notice frame's body, sanitized and bounded.
    public static func noticeFrame(_ message: String) -> Data {
        let shown = ReviewDisplay.fitted(message, maxBytes: maximumNoticeBytes)
        return (try? JSONEncoder().encode(
            Notice(version: WireProtocol.version, type: noticeType, message: shown)
        )) ?? Data()
    }

    /// The message of a notice frame, sanitized and bounded again on receipt;
    /// nil for any other frame.
    public static func notice(in frame: Data) -> String? {
        guard let flags = try? JSONDecoder().decode(TransportFlags.self, from: frame),
              flags.type == noticeType else { return nil }
        return ReviewDisplay.fitted(flags.message ?? "", maxBytes: maximumNoticeBytes)
    }

    /// Whether the client that sent this request frame can read notices.
    /// Absent (every foreign client, and every client built before notices
    /// existed) means no, and such a connection is never sent one.
    public static func requestSupportsNotices(_ frame: Data) -> Bool {
        (try? JSONDecoder().decode(TransportFlags.self, from: frame))?.supportsNotices == true
    }

    /// One heartbeat frame's body.
    public static func heartbeatFrame() -> Data {
        // A fixed, tiny, value-free body. It carries no request id and no
        // payload: its entire meaning is "this daemon is still running your
        // request".
        (try? JSONEncoder().encode(
            Heartbeat(version: WireProtocol.version, type: heartbeatType)
        )) ?? Data("{\"version\":\(WireProtocol.version),\"type\":\"\(heartbeatType)\"}".utf8)
    }

    /// Whether a received frame is a heartbeat rather than a `Response`.
    public static func isHeartbeat(_ frame: Data) -> Bool {
        (try? JSONDecoder().decode(TransportFlags.self, from: frame))?.type == heartbeatType
    }

    /// Whether the client that sent this request frame can read heartbeats.
    /// Absent (every foreign client, and every client built before heartbeats
    /// existed) means no, and such a connection is never sent one.
    public static func requestSupportsHeartbeats(_ frame: Data) -> Bool {
        (try? JSONDecoder().decode(TransportFlags.self, from: frame))?.supportsHeartbeats == true
    }
}
