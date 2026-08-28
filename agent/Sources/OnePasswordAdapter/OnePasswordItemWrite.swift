import Foundation

public enum OnePasswordWriteError: Error, LocalizedError, Equatable {
    case invalidComponent(String)
    case malformedItem

    public var errorDescription: String? {
        switch self {
        case .invalidComponent(let component):
            return "1Password vault/item name is not usable in a reference: \(component)"
        case .malformedItem:
            return "op returned item JSON in an unexpected shape"
        }
    }
}

/// Pure builders for writing concealed fields to 1Password items. Everything
/// value-bearing goes through an item JSON template piped to `op` on stdin;
/// the argv builders below carry only vault/item metadata, never a value —
/// argv is visible machine-wide via the process table, a pipe is not.
public enum OnePasswordItemWrite {
    public struct Field: Equatable {
        public let label: String
        public let value: String

        public init(label: String, value: String) {
            self.label = label
            self.value = value
        }
    }

    /// Vault and item names become path components of `op://vault/item/field`
    /// references spliced into env files as double-quoted values. Reject
    /// anything that would make the reference ambiguous (`/`), unsplicable
    /// (`"`, `\`, `$`, backtick — shell-active inside double quotes), or
    /// unprintable.
    public static func isValidComponent(_ component: String) -> Bool {
        guard !component.isEmpty, component.utf8.count <= 128 else { return false }
        guard component == component.trimmingCharacters(in: .whitespaces) else { return false }
        return !component.utf8.contains { byte in
            byte < 0x20 || byte == 0x7F || byte == 0x2F // control, DEL, '/'
                || byte == 0x22 || byte == 0x5C // '"' '\'
                || byte == 0x24 || byte == 0x60 // '$' '`'
        }
    }

    public static func reference(vault: String, title: String, field: String) -> String {
        "op://\(vault)/\(title)/\(field)"
    }

    /// Item JSON for `… | op item create --vault <vault> -`: a Login item with
    /// one concealed custom field per env var.
    public static func createTemplate(title: String, fields: [Field]) throws -> Data {
        guard isValidComponent(title) else {
            throw OnePasswordWriteError.invalidComponent(title)
        }
        let object: [String: Any] = [
            "title": title,
            "category": "LOGIN",
            "fields": fields.map { field in
                ["type": "CONCEALED", "label": field.label, "value": field.value]
            },
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    /// Full-item JSON for `… | op item edit <item>`: the item exactly as
    /// `op item get --format json` returned it, with each field's value
    /// updated in place when its label already exists and appended as a new
    /// concealed field otherwise. Every other key (ids, sections, vault,
    /// version) passes through untouched.
    public static func updatedItemJSON(existingItem: Data, fields: [Field]) throws -> Data {
        guard var item = try JSONSerialization.jsonObject(with: existingItem) as? [String: Any]
        else { throw OnePasswordWriteError.malformedItem }
        var itemFields = item["fields"] as? [[String: Any]] ?? []
        for field in fields {
            if let index = itemFields.firstIndex(where: { ($0["label"] as? String) == field.label }) {
                itemFields[index]["value"] = field.value
            } else {
                itemFields.append(["type": "CONCEALED", "label": field.label, "value": field.value])
            }
        }
        item["fields"] = itemFields
        return try JSONSerialization.data(withJSONObject: item, options: [.sortedKeys])
    }

    // MARK: - argv builders (metadata only, unit-tested to stay value-free)

    public static func getItemArguments(title: String, vault: String) -> [String] {
        ["item", "get", title, "--vault", vault, "--format", "json"]
    }

    public static func createArguments(vault: String) -> [String] {
        ["item", "create", "--vault", vault, "--format", "json", "-"]
    }

    public static func editArguments(itemID: String) -> [String] {
        ["item", "edit", itemID, "--format", "json"]
    }
}
