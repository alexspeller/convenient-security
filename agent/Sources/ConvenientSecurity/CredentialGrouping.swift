import Foundation

/// Transient provider grouping metadata. Raw references and logical names are
/// used only to render the trusted review and to mint subtree grants; they are
/// never serialized anywhere.
public struct CredentialGroupDescriptor: Sendable, Equatable {
    public let provider: String
    public let providerAccount: String
    public let group: String
    public let references: [SecretRef]

    public init(
        provider: String,
        providerAccount: String,
        group: String,
        references: [SecretRef]
    ) {
        self.provider = provider
        self.providerAccount = providerAccount
        self.group = group
        self.references = references.sorted { $0.uri < $1.uri }
    }
}

/// Stable provider-specific grouping rules. 1Password fields are one logical
/// vault/item credential; native-store keys and edit access are one store.
/// Unknown future schemes fail safely to one group per exact reference. The
/// grouping now serves display and grant shaping only — there is no per-group
/// risk classification behind it.
public enum CredentialGrouping {
    public static let onePasswordAccount = "default-cli-account-v1"
    public static let nativeStoreAccount = "this-device-v1"

    public static func onePasswordGroup(for reference: SecretRef) -> String? {
        guard reference.scheme == "op" else { return nil }
        let components = reference.path.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty,
              components.count <= 64,
              components.allSatisfy({ !$0.isEmpty }) else { return nil }
        return components.prefix(min(2, components.count)).joined(separator: "/")
    }

    public static func nativeStoreGroup(for reference: SecretRef) -> String? {
        guard reference.scheme == "csec",
              let slash = reference.path.firstIndex(of: "/"),
              slash != reference.path.startIndex else { return nil }
        let store = String(reference.path[..<slash])
        return (try? NativeStoreName(store))?.value
    }

    public static func groups(for references: [SecretRef]) -> [CredentialGroupDescriptor] {
        struct Key: Hashable {
            let provider: String
            let account: String
            let group: String
        }

        var grouped: [Key: Set<SecretRef>] = [:]
        for reference in Set(references) {
            let key: Key
            switch reference.scheme {
            case "op":
                key = Key(
                    provider: "op",
                    account: onePasswordAccount,
                    group: onePasswordGroup(for: reference) ?? reference.uri
                )
            case "csec":
                key = Key(
                    provider: "csec",
                    account: nativeStoreAccount,
                    group: nativeStoreGroup(for: reference) ?? reference.uri
                )
            default:
                key = Key(
                    provider: reference.scheme,
                    account: "default-provider-account-v1",
                    group: reference.uri
                )
            }
            grouped[key, default: []].insert(reference)
        }

        return grouped.map { key, members in
            CredentialGroupDescriptor(
                provider: key.provider,
                providerAccount: key.account,
                group: key.group,
                references: Array(members)
            )
        }.sorted {
            ($0.provider, $0.providerAccount, $0.group)
                < ($1.provider, $1.providerAccount, $1.group)
        }
    }
}
