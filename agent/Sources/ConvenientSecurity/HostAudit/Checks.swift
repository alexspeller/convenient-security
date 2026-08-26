import Foundation

// The check protocol, the value-free finding-builder, the registry that
// assembles every domain, and the engine that runs them into a report.
//
// A `HostCheck` is a small value that reads a `HostAuditContext` and returns one
// value-free `HostFinding`. Checks are grouped one file per catalog domain
// (`DomainA_Platform.swift` … `DomainK_Coverage.swift`); each domain file exposes
// a `static var checks: [any HostCheck]` that `HostCheckRegistry` concatenates.

/// Immutable catalog metadata for a check (its identity and how a finding it
/// produces should be classified/remediated).
public struct HostCheckMeta: Sendable {
    public let id: String
    public let title: String
    public let severity: HostSeverity
    public let tier: DetectionTier
    public let onThesis: Bool
    public let remediation: RemediationClass
    public let remediationKey: String?
    /// Where to act — path, Settings pane, or command. Value-free.
    public let anchor: String

    public init(
        id: String,
        title: String,
        severity: HostSeverity,
        tier: DetectionTier,
        onThesis: Bool = false,
        remediation: RemediationClass = .advise,
        remediationKey: String? = nil,
        anchor: String
    ) {
        self.id = id
        self.title = title
        self.severity = severity
        self.tier = tier
        self.onThesis = onThesis
        self.remediation = remediation
        self.remediationKey = remediationKey
        self.anchor = anchor
    }

    /// Build a finding from this check's metadata + an outcome. Evidence and
    /// anchor are sanitized here so no check can leak an unsanitized string.
    /// `remediationKey` is only attached to a genuine failure, so a pass or an
    /// expected-self line can never be picked up by the remediation batch.
    public func finding(
        _ status: FindingStatus,
        evidence: String,
        anchorOverride: String? = nil,
        coverageNote: String? = nil
    ) -> HostFinding {
        HostFinding(
            id: id,
            title: title,
            severity: severity,
            tier: tier,
            status: status,
            onThesis: onThesis,
            evidence: ReviewDisplay.sanitized(evidence),
            anchor: ReviewDisplay.sanitized(anchorOverride ?? anchor),
            remediation: remediation,
            remediationKey: status == .fail ? remediationKey : nil,
            coverageNote: coverageNote.map(ReviewDisplay.sanitized)
        )
    }
}

public protocol HostCheck: Sendable {
    var meta: HostCheckMeta { get }
    func evaluate(_ ctx: HostAuditContext) async -> HostFinding
}

public extension HostCheck {
    var id: String { meta.id }
}

/// Assembles every domain's checks into the full audit. Domains are added here as
/// their files land; each is an independent `enum` exposing `static var checks`.
public enum HostCheckRegistry {
    public static var all: [any HostCheck] {
        var checks: [any HostCheck] = []
        checks += DomainA_Platform.checks
        checks += DomainB_Malware.checks
        checks += DomainC_Network.checks
        checks += DomainD_Privacy.checks
        checks += DomainE_Persistence.checks
        checks += DomainF_Developer.checks
        checks += DomainG_Accounts.checks
        checks += DomainH_Physical.checks
        checks += DomainI_Logging.checks
        checks += DomainJ_Leakage.checks
        checks += DomainK_Coverage.checks
        return checks
    }
}

/// Runs every registered check against a context and produces the severity
/// -ordered, honest-coverage report.
public struct HostAuditEngine: Sendable {
    public init() {}

    public func run(_ ctx: HostAuditContext, generatedAtHint: String? = nil) async -> HostAuditReport {
        var findings: [HostFinding] = []
        for check in HostCheckRegistry.all {
            findings.append(await check.evaluate(ctx))
        }
        let ordered = HostAuditReport.ordered(findings)
        let unverifiable = ordered
            .filter { $0.status == .unknown }
            .map { HostAuditReport.UnverifiableNote(id: $0.id, reason: $0.evidence) }
        let coverageNotes = ordered.compactMap(\.coverageNote)
        return HostAuditReport(
            findings: ordered,
            unverifiable: unverifiable,
            coverageNotes: coverageNotes,
            verdict: Self.verdict(for: ordered),
            generatedAtHint: generatedAtHint
        )
    }

    static func verdict(for findings: [HostFinding]) -> String {
        let fails = findings.filter { $0.status == .fail }
        let highs = fails.filter { $0.severity == .high }.count
        let onThesisFails = fails.filter(\.onThesis).count
        let unknowns = findings.filter { $0.status == .unknown }.count
        if fails.isEmpty {
            return unknowns == 0
                ? "Host posture is solid — every checked control is in its more-secure state."
                : "No failing controls; \(unknowns) could not be verified (see the unverifiable list)."
        }
        var parts = ["\(fails.count) control(s) need attention"]
        if highs > 0 { parts.append("\(highs) high-severity") }
        if onThesisFails > 0 { parts.append("\(onThesisFails) directly shrink same-user-malware blast radius") }
        if unknowns > 0 { parts.append("\(unknowns) unverifiable") }
        return parts.joined(separator: "; ") + "."
    }
}
