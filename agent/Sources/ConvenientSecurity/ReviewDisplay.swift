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

        public init(
            title: String?,
            subtitle: String?,
            fields: [String],
            rawReferences: [String]
        ) {
            self.title = title
            self.subtitle = subtitle
            self.fields = fields
            self.rawReferences = rawReferences
        }
    }

    public static func referenceGroup(
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

    public static func riskLabel(_ level: RiskLevel) -> String {
        switch level {
        case .unknown: return "Unclassified"
        case .low: return "Low"
        case .standard: return "Standard"
        case .high: return "High"
        case .critical: return "Critical"
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

    /// Neutralizes control, newline, and bidirectional-formatting characters in
    /// text that may be attacker-influenced before it reaches a trusted window.
    public static func sanitized(_ value: String) -> String {
        let bidiControls: Set<UInt32> = [
            0x061c, 0x200e, 0x200f,
            0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
            0x2066, 0x2067, 0x2068, 0x2069,
        ]
        return value.unicodeScalars.map { scalar in
            if CharacterSet.controlCharacters.contains(scalar)
                || CharacterSet.newlines.contains(scalar)
                || bidiControls.contains(scalar.value) {
                return "�"
            }
            return String(scalar)
        }.joined()
    }
}
