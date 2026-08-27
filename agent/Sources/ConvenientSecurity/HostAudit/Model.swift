import Foundation

// Core value types for the host posture audit (docs/host-audit-catalog.md).
//
// These are pure, `Sendable`, `Codable` data types with no I/O and no ambient
// clock reads: a `HostFinding` is the value-free result of one catalog check, and
// a `HostAuditReport` is the severity-ordered collection the CLI/agent renders.
// Timestamps are stamped by the caller (CLI or csecd), never read here, mirroring
// the codebase's avoidance of ambient `Date()` in pure protocol/report types.
//
// Value-free discipline (non-negotiable): no field here ever carries a credential
// value. Evidence strings are already sanitized by `ReviewDisplay.sanitized` /
// `safeMetadata` / `boundedMetadata` before they reach a `HostFinding`.

/// How badly a failed control weakens the host, ordered for report grouping.
public enum HostSeverity: String, Codable, Sendable, CaseIterable, Comparable {
    case high
    case medium
    case low
    case info

    /// Descending blast-radius rank so `sort` leads with `high`.
    private var rank: Int {
        switch self {
        case .high: return 0
        case .medium: return 1
        case .low: return 2
        case .info: return 3
        }
    }

    public static func < (lhs: HostSeverity, rhs: HostSeverity) -> Bool {
        lhs.rank < rhs.rank
    }
}

/// How csec established (or could not establish) a finding from a running system.
/// Mirrors the catalog legend: an `unverifiable` check must never render as a
/// pass — honest coverage is a ground rule of the plan.
public enum DetectionTier: String, Codable, Sendable {
    /// `R` — runtime-readable, value-free, no elevation.
    case runtimeReadable
    /// `R!` — runtime-readable but needs root (a `csec-rootd` hop).
    case runtimePrivileged
    /// `F` — needs Full Disk Access (reads a SIP-protected DB like TCC/BTM).
    case fullDiskAccess
    /// `X` — not verifiable from a running system (recoveryOS-only, iCloud-side,
    /// or physical). Advise-and-link; infer where a proxy signal exists.
    case unverifiable
}

/// The remediation channel a finding is eligible for.
public enum RemediationClass: String, Codable, Sendable {
    /// Safe, reversible, in-process (e.g. a `defaults` write, writing
    /// `/etc/pam.d/sudo_local`).
    case auto
    /// Safe and reversible but privileged — applied through `csec-rootd`
    /// `hostApply` under the same digest/role gating as `.approve`.
    case autoPrivileged
    /// More-secure but needs a choice or state transition — an interactive helper
    /// (FileVault, Santa).
    case guided
    /// Surface + exact command/link, but csec never mutates (disruptive,
    /// irreversible, or a human judgment call).
    case advise
    /// Reporting only.
    case none
}

/// The outcome of evaluating one check.
public enum FindingStatus: String, Codable, Sendable {
    /// The secure setting is in place.
    case pass
    /// The insecure/at-risk state was observed.
    case fail
    /// Could not be determined (tier `X`, or an `F`/`R!` read that was
    /// unavailable). Never rendered as a pass.
    case unknown
    /// A grant/state that is csec's own and expected — e.g. csec's own Full Disk
    /// Access (HA-D01, Decision 8). Never a finding.
    case expectedSelf
    /// The check does not apply to this hardware/OS (e.g. an Intel-only control on
    /// Apple Silicon).
    case notApplicable
}

/// One catalog check's value-free result.
public struct HostFinding: Codable, Sendable, Equatable {
    /// Stable catalog id, e.g. `"HA-C01"`. The wire/JSON contract.
    public let id: String
    public let title: String
    public let severity: HostSeverity
    public let tier: DetectionTier
    public let status: FindingStatus
    /// `★` — directly reduces the blast radius of csec's same-UID adversary.
    /// Used to group tier-1 controls first in the report.
    public let onThesis: Bool
    /// Value-free, already-sanitized explanation of what was observed.
    public let evidence: String
    /// Where to act — a path, a System Settings pane, or a command. Value-free.
    public let anchor: String
    public let remediation: RemediationClass
    /// Opaque key into the remediation registry (nil when nothing is applicable).
    public let remediationKey: String?
    /// Value-free note declaring a scan's bound (e.g. HA-F10), so partial
    /// coverage never reads as full coverage. Surfaced in `coverageNotes`.
    public let coverageNote: String?

    public init(
        id: String,
        title: String,
        severity: HostSeverity,
        tier: DetectionTier,
        status: FindingStatus,
        onThesis: Bool,
        evidence: String,
        anchor: String,
        remediation: RemediationClass,
        remediationKey: String? = nil,
        coverageNote: String? = nil
    ) {
        self.id = id
        self.title = title
        self.severity = severity
        self.tier = tier
        self.status = status
        self.onThesis = onThesis
        self.evidence = evidence
        self.anchor = anchor
        self.remediation = remediation
        self.remediationKey = remediationKey
        self.coverageNote = coverageNote
    }

    /// A finding contributes a remediation proposal only when it failed and has a
    /// batchable (non-guided, non-advise) fix wired up.
    public var isBatchFixable: Bool {
        status == .fail
            && remediationKey != nil
            && (remediation == .auto || remediation == .autoPrivileged)
    }

    /// Whether this finding is one the report should surface as actionable
    /// (a real failure) rather than a pass / expected-self / not-applicable line.
    public var isActionable: Bool {
        status == .fail || status == .unknown
    }
}

/// One finding the user has triaged (accepted as an exemption, or deferred as a
/// TODO). Value-free: `note` is the user's own local reason text, never a
/// credential; timestamps are opaque hints stamped by the agent.
public struct HostTriageInfo: Codable, Sendable, Equatable {
    public let id: String
    public let note: String?
    public let recordedAtHint: String?
    public init(id: String, note: String? = nil, recordedAtHint: String? = nil) {
        self.id = id
        self.note = note
        self.recordedAtHint = recordedAtHint
    }
}

/// The severity-ordered collection the CLI/agent renders, plus honest-coverage
/// bookkeeping so the report never over-claims.
public struct HostAuditReport: Codable, Sendable, Equatable {
    /// All findings, severity-ordered with `★` on-thesis controls first.
    public let findings: [HostFinding]
    /// Ids reported `unknown` and the reason, so an `X`/unavailable check never
    /// reads as a pass.
    public let unverifiable: [UnverifiableNote]
    /// Logged bounds for bounded scans (e.g. the HA-F10 SUID sweep), so partial
    /// coverage never implies full coverage.
    public let coverageNotes: [String]
    /// Overall posture summary line.
    public let verdict: String
    /// Stamped by the caller (CLI/agent), not the model.
    public let generatedAtHint: String?
    /// Value-free display metadata: the reversible fixes the launcher renders as a
    /// checkbox picker. Populated only on the interactive/streaming path.
    public let remediationItems: [HostRemediationItem]
    /// Findings the user has accepted as documented risks (value-free notes).
    public let exemptions: [HostTriageInfo]
    /// Findings the user has deferred as TODOs (weekly notification reminders).
    public let todos: [HostTriageInfo]

    public init(
        findings: [HostFinding],
        unverifiable: [UnverifiableNote] = [],
        coverageNotes: [String] = [],
        verdict: String,
        generatedAtHint: String? = nil,
        remediationItems: [HostRemediationItem] = [],
        exemptions: [HostTriageInfo] = [],
        todos: [HostTriageInfo] = []
    ) {
        self.findings = findings
        self.unverifiable = unverifiable
        self.coverageNotes = coverageNotes
        self.verdict = verdict
        self.generatedAtHint = generatedAtHint
        self.remediationItems = remediationItems
        self.exemptions = exemptions
        self.todos = todos
    }

    /// Return a copy with the launcher-facing triage/remediation metadata attached
    /// (the base engine produces only findings; the service annotates afterwards).
    public func annotated(
        remediationItems: [HostRemediationItem],
        exemptions: [HostTriageInfo],
        todos: [HostTriageInfo]
    ) -> HostAuditReport {
        HostAuditReport(
            findings: findings, unverifiable: unverifiable, coverageNotes: coverageNotes,
            verdict: verdict, generatedAtHint: generatedAtHint,
            remediationItems: remediationItems, exemptions: exemptions, todos: todos)
    }

    private enum CodingKeys: String, CodingKey {
        case findings, unverifiable, coverageNotes, verdict, generatedAtHint
        case remediationItems, exemptions, todos
    }

    // Custom Codable so a payload without the newer triage/remediation fields (an
    // older sender, or an external `--json` fixture) still decodes cleanly.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        findings = try c.decode([HostFinding].self, forKey: .findings)
        unverifiable = try c.decodeIfPresent([UnverifiableNote].self, forKey: .unverifiable) ?? []
        coverageNotes = try c.decodeIfPresent([String].self, forKey: .coverageNotes) ?? []
        verdict = try c.decode(String.self, forKey: .verdict)
        generatedAtHint = try c.decodeIfPresent(String.self, forKey: .generatedAtHint)
        remediationItems = try c.decodeIfPresent([HostRemediationItem].self, forKey: .remediationItems) ?? []
        exemptions = try c.decodeIfPresent([HostTriageInfo].self, forKey: .exemptions) ?? []
        todos = try c.decodeIfPresent([HostTriageInfo].self, forKey: .todos) ?? []
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(findings, forKey: .findings)
        try c.encode(unverifiable, forKey: .unverifiable)
        try c.encode(coverageNotes, forKey: .coverageNotes)
        try c.encode(verdict, forKey: .verdict)
        try c.encodeIfPresent(generatedAtHint, forKey: .generatedAtHint)
        try c.encode(remediationItems, forKey: .remediationItems)
        try c.encode(exemptions, forKey: .exemptions)
        try c.encode(todos, forKey: .todos)
    }

    public struct UnverifiableNote: Codable, Sendable, Equatable {
        public let id: String
        public let reason: String
        public init(id: String, reason: String) {
            self.id = id
            self.reason = reason
        }
    }

    /// Findings that need user attention, in report order.
    public var actionable: [HostFinding] { findings.filter(\.isActionable) }

    /// Findings eligible for the batched one-Touch-ID remediation review.
    public var batchFixable: [HostFinding] { findings.filter(\.isBatchFixable) }

    /// Deterministic ordering: on-thesis first, then by severity, then by id, so
    /// the report and its JSON are stable across runs (ids are the contract).
    public static func ordered(_ findings: [HostFinding]) -> [HostFinding] {
        findings.sorted { lhs, rhs in
            if lhs.onThesis != rhs.onThesis { return lhs.onThesis && !rhs.onThesis }
            if lhs.severity != rhs.severity { return lhs.severity < rhs.severity }
            return lhs.id < rhs.id
        }
    }
}
