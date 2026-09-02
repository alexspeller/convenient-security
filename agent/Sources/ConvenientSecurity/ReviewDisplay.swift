import Foundation

/// Value-free presentation copy for the trusted review surfaces. Everything
/// here formats policy metadata that is already plaintext-free; dynamic
/// components pass through `sanitized`, which neutralizes control, newline,
/// and bidirectional-formatting characters exactly like `SecretRef`.
public enum ReviewDisplay {

    /// One credential's references prepared for display. When every reference
    /// is a fully-qualified field under one 1Password vault and item (or one
    /// native store), the shared context is shown once and the distinct
    /// fields are listed. Any other mix falls back to the complete canonical
    /// URIs so no reference is ever elided or abbreviated.
    public struct CredentialReferenceGroup: Equatable, Sendable {
        public let title: String?
        public let subtitle: String?
        public let fields: [String]
        public let rawReferences: [String]
        /// Provider context lines, already labeled and sanitized, e.g.
        /// `account: dexory.1password.eu`.
        public let notes: [String]
        /// Provider warnings about where the value will come from.
        public let warnings: [String]

        public init(
            title: String?,
            subtitle: String?,
            fields: [String],
            rawReferences: [String],
            notes: [String] = [],
            warnings: [String] = []
        ) {
            self.title = title
            self.subtitle = subtitle
            self.fields = fields
            self.rawReferences = rawReferences
            self.notes = notes
            self.warnings = warnings
        }

        /// The same content as one string per line, for surfaces that render a
        /// single block of text rather than styled rows.
        public var noteLines: [String] { notes + warnings }
    }

    /// Convenience for a credential that already carries its provider notes.
    public static func referenceGroup(
        for credential: PolicyReviewCredential
    ) -> CredentialReferenceGroup {
        referenceGroup(for: credential.references, providerNotes: credential.providerNotes)
    }

    public static func referenceGroup(
        for references: [SecretRef],
        providerNotes: [ProviderReviewNote] = []
    ) -> CredentialReferenceGroup {
        let group = plainReferenceGroup(for: references)
        guard !providerNotes.isEmpty else { return group }
        // A note's label and detail both originate outside csec (a vault name, a
        // sign-in URL), so both are sanitized and bounded before display.
        let formatted = providerNotes.map { note -> (text: String, isWarning: Bool) in
            let label = sanitized(String(note.label.prefix(32)))
            let detail = sanitized(String(note.detail.prefix(400)))
            return (label.isEmpty ? detail : "\(label): \(detail)", note.isWarning)
        }
        return CredentialReferenceGroup(
            title: group.title,
            subtitle: group.subtitle,
            fields: group.fields,
            rawReferences: group.rawReferences,
            notes: formatted.filter { !$0.isWarning }.map(\.text),
            warnings: formatted.filter(\.isWarning).map(\.text)
        )
    }

    private static func plainReferenceGroup(
        for references: [SecretRef]
    ) -> CredentialReferenceGroup {
        let fallback = CredentialReferenceGroup(
            title: nil,
            subtitle: nil,
            fields: [],
            rawReferences: references.map(\.safeInlineURI)
        )
        guard !references.isEmpty else { return fallback }

        if references.allSatisfy({ $0.scheme == "op" }) {
            let parsed = references.compactMap { reference -> (vault: String, item: String, field: String)? in
                let parts = reference.path.split(separator: "/", omittingEmptySubsequences: false)
                guard parts.count == 3, parts.allSatisfy({ !$0.isEmpty }) else { return nil }
                return (String(parts[0]), String(parts[1]), String(parts[2]))
            }
            guard parsed.count == references.count,
                let sample = parsed.first,
                parsed.allSatisfy({ $0.vault == sample.vault && $0.item == sample.item })
            else { return fallback }
            return CredentialReferenceGroup(
                title: sanitized(sample.item),
                subtitle: "1Password · vault “\(sanitized(sample.vault))”",
                fields: parsed.map { sanitized($0.field) },
                rawReferences: []
            )
        }

        if references.allSatisfy({ $0.scheme == "csec" }) {
            let parsed = references.compactMap { reference -> (store: String, key: String)? in
                let parts = reference.path.split(separator: "/", omittingEmptySubsequences: false)
                guard parts.count == 2, parts.allSatisfy({ !$0.isEmpty }) else { return nil }
                return (String(parts[0]), String(parts[1]))
            }
            guard parsed.count == references.count,
                let sample = parsed.first,
                parsed.allSatisfy({ $0.store == sample.store })
            else { return fallback }
            return CredentialReferenceGroup(
                title: sanitized(sample.store),
                subtitle: "Native encrypted store",
                fields: parsed.map {
                    $0.key == "*" ? "all keys (edit access)" : sanitized($0.key)
                },
                rawReferences: []
            )
        }

        return fallback
    }

    public static func mechanism(_ mechanism: DeliveryMechanism) -> String {
        switch mechanism {
        case .directHeap: return "Direct to process memory"
        case .execHook: return "Injected at launch"
        case .inheritedFileDescriptor: return "Inherited file descriptor"
        case .capabilityGIDFile: return "Capability-protected file"
        case .restrictedLateEnvironment: return "Restricted late environment"
        case .sealedEnvironment: return "Sealed environment"
        case .unrestrictedInitialEnvironment: return "Unrestricted initial environment"
        case .rawStandardOutput: return "Raw standard output"
        case .namedPlaintextFile: return "Named plaintext file"
        case .credentialProtocol: return "Credential helper protocol"
        }
    }

    public static func scope(_ scope: DescendantScope) -> String {
        switch scope {
        case .exactProcess: return "exact process only"
        case .subtree: return "process and its descendants"
        case .broadSession: return "entire registered session"
        }
    }

    public static func destination(_ destination: DestinationClass) -> String {
        switch destination {
        case .localDevelopment: return "Local development"
        case .staging: return "Staging"
        case .production: return "Production"
        case .aiTool: return "AI tool"
        case .humanOutput: return "Human output"
        case .shellDelegatedPipe: return "Shell-delegated pipe"
        case .persistentPlaintextFile: return "Persistent plaintext file"
        case .credentialConsumer: return "Credential consumer"
        case .unknown: return "Unknown"
        }
    }

    public static func assurance(_ assurance: ConsumerAssurance) -> String {
        switch assurance {
        case .verifiedProduct: return "Verified product"
        case .independentlyProtected: return "Protected path"
        case .userWritable: return "User-writable"
        case .unverified: return "Unverified"
        case .sealed: return "Sealed"
        }
    }

    public static func root(_ root: DeliveryRoot) -> String {
        switch root {
        case .caller: return "Requesting launcher"
        case .directParent: return "Verified direct parent"
        case .registeredSession: return "Registered kernel-verified session"
        }
    }

    public static func duration(seconds total: Int) -> String {
        func unit(_ count: Int, _ singular: String) -> String {
            count == 1 ? "1 \(singular)" : "\(count) \(singular)s"
        }
        if total < 60 { return unit(max(total, 0), "second") }
        if total < 3600 {
            let minutes = total / 60
            let seconds = total % 60
            return seconds == 0
                ? unit(minutes, "minute")
                : "\(unit(minutes, "minute")) \(unit(seconds, "second"))"
        }
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        return minutes == 0
            ? unit(hours, "hour")
            : "\(unit(hours, "hour")) \(unit(minutes, "minute"))"
    }

    /// Trims `value` to at most `maxBytes` UTF-8 bytes without splitting a
    /// character, for surfaces whose wire format enforces a byte bound.
    public static func bounded(_ value: String, maxBytes: Int) -> String {
        guard value.utf8.count > maxBytes else { return value }
        var trimmed = ""
        var used = 0
        for character in value {
            let size = String(character).utf8.count
            if used + size > maxBytes - 1 { break }
            trimmed.append(character)
            used += size
        }
        return trimmed + "…"
    }

    /// Neutralizes bidirectional-formatting, newline, and control characters in
    /// text that may be attacker-influenced before it reaches a trusted window.
    /// Bidi overrides are always neutralized (they can reorder a consent line).
    /// `allowNewlines` keeps newlines (for multi-line evidence/fragments) and
    /// `allowOtherControls` keeps the remaining control characters (for value-free
    /// document fragments that legitimately carry tabs/formatting) — the three
    /// combinations replace the former `sanitized`, `auditSafe`, `setupSafe`,
    /// `setupDocumentSafe`, and `promptSafe` helpers.
    public static func sanitized(
        _ value: String,
        allowNewlines: Bool = false,
        allowOtherControls: Bool = false
    ) -> String {
        let bidiControls: Set<UInt32> = [
            0x061c, 0x200e, 0x200f,
            0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
            0x2066, 0x2067, 0x2068, 0x2069,
        ]
        return value.unicodeScalars.map { scalar in
            if bidiControls.contains(scalar.value) { return "�" }
            if CharacterSet.newlines.contains(scalar) {
                return allowNewlines ? String(scalar) : "�"
            }
            if CharacterSet.controlCharacters.contains(scalar) {
                return allowOtherControls ? String(scalar) : "�"
            }
            return String(scalar)
        }.joined()
    }
}
