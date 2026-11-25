import Foundation

public enum SecretDestinationSpecError: Error, Equatable, CustomStringConvertible {
    case unsupportedScheme(String)
    case invalidStoreName(String)
    case invalidOnePasswordComponent(String)

    public var description: String {
        switch self {
        case .unsupportedScheme(let scheme):
            return "unsupported destination scheme \"\(scheme)\" (use csec://STORE or op://VAULT[/ITEM])"
        case .invalidStoreName(let name):
            return "invalid native store name \"\(name)\""
        case .invalidOnePasswordComponent(let component):
            return "invalid 1Password vault/item name \"\(component)\""
        }
    }
}

/// Where an env-file import writes its secrets, parsed from `--dest` or the
/// interactive destination prompt. Pure so the grammar is unit-testable:
///   csec://STORE   (or a bare store name)  -> the native encrypted store
///   op://VAULT     -> 1Password, item named after the project
///   op://VAULT/ITEM -> 1Password, explicit item title
public enum SecretDestinationSpec: Equatable {
    case native(NativeStoreName)
    case onePassword(vault: String, item: String)

    public static func parse(_ text: String, defaultItemTitle: String) throws -> SecretDestinationSpec {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard let separator = trimmed.range(of: "://") else {
            return .native(try storeName(trimmed))
        }
        let scheme = String(trimmed[trimmed.startIndex..<separator.lowerBound]).lowercased()
        let path = String(trimmed[separator.upperBound...])
        switch scheme {
        case "csec":
            return .native(try storeName(path))
        case "op":
            let components = path.split(separator: "/", omittingEmptySubsequences: false)
                .map(String.init)
            guard components.count <= 2 else {
                throw SecretDestinationSpecError.invalidOnePasswordComponent(path)
            }
            let vault = components.first ?? ""
            let item = components.count == 2 ? components[1] : defaultItemTitle
            guard isValidOnePasswordComponent(vault) else {
                throw SecretDestinationSpecError.invalidOnePasswordComponent(vault)
            }
            guard isValidOnePasswordComponent(item) else {
                throw SecretDestinationSpecError.invalidOnePasswordComponent(item)
            }
            return .onePassword(vault: vault, item: item)
        default:
            throw SecretDestinationSpecError.unsupportedScheme(scheme)
        }
    }

    /// Value-free display form, also accepted back by `parse`.
    public var displayString: String {
        switch self {
        case .native(let store):
            return "csec://\(store.value)"
        case .onePassword(let vault, let item):
            return "op://\(vault)/\(item)"
        }
    }

    private static func storeName(_ text: String) throws -> NativeStoreName {
        do {
            return try NativeStoreName(text)
        } catch {
            throw SecretDestinationSpecError.invalidStoreName(text)
        }
    }

    /// Vault and item names become path components of `op://vault/item/field`
    /// references spliced into env files as double-quoted values: reject
    /// anything ambiguous (`/`), shell-active inside double quotes (`"`, `\`,
    /// `$`, backtick), or unprintable. Mirrored by the 1Password adapter's
    /// write-side validation.
    public static func isValidOnePasswordComponent(_ component: String) -> Bool {
        guard !component.isEmpty, component.utf8.count <= 128 else { return false }
        guard component == component.trimmingCharacters(in: .whitespaces) else { return false }
        return !component.utf8.contains { byte in
            byte < 0x20 || byte == 0x7F || byte == 0x2F
                || byte == 0x22 || byte == 0x5C
                || byte == 0x24 || byte == 0x60
        }
    }
}
