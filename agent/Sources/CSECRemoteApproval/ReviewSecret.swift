import Foundation

/// The colour a review draws a provider's secrets in. Each provider picks its
/// own, so a review's labels say where each secret comes from. None of these
/// means anything else on the review panels: green and orange state a
/// consumer's assurance, blue a sealed one, red is Deny, orange a warning.
public enum ReviewSecretTint: String, Codable, Sendable, CaseIterable {
    case teal
    case purple
    case mint
    case indigo
    case brown
    /// A reference no provider described.
    case gray

    /// One sRGB colour, components in 0...1.
    public struct RGB: Equatable, Sendable {
        public let red: Double
        public let green: Double
        public let blue: Double

        init(_ red: Double, _ green: Double, _ blue: Double) {
            self.red = red / 255
            self.green = green / 255
            self.blue = blue / 255
        }

        public init(red: Double, green: Double, blue: Double) {
            self.red = red
            self.green = green
            self.blue = blue
        }

        /// Whether `other` is this colour to within what a colour-space
        /// round trip changes.
        public func isClose(to other: RGB, tolerance: Double = 0.004) -> Bool {
            abs(red - other.red) <= tolerance && abs(green - other.green) <= tolerance
                && abs(blue - other.blue) <= tolerance
        }

        func mixed(_ fraction: Double, with other: RGB) -> RGB {
            RGB(
                red: red + (other.red - red) * fraction,
                green: green + (other.green - green) * fraction,
                blue: blue + (other.blue - blue) * fraction
            )
        }
    }

    /// How one label is drawn in one appearance: a fill and an edge in the
    /// base colour at `fillAlpha` and `edgeAlpha`, and text in `text`, the
    /// base pushed toward white on dark and toward black on light so it reads
    /// on its own fill. The Mac panels and the phone draw from these same
    /// values, so a source has one colour everywhere.
    public struct Palette: Equatable, Sendable {
        public let base: RGB
        public let text: RGB
        public let fillAlpha: Double
        public let edgeAlpha: Double
    }

    public func palette(dark: Bool) -> Palette {
        let base = dark ? darkBase : lightBase
        return dark
            ? Palette(base: base, text: base.mixed(0.22, with: RGB(255, 255, 255)), fillAlpha: 0.20, edgeAlpha: 0.40)
            : Palette(base: base, text: base.mixed(0.34, with: RGB(0, 0, 0)), fillAlpha: 0.14, edgeAlpha: 0.34)
    }

    /// The system colour of the same name, light appearance.
    private var lightBase: RGB {
        switch self {
        case .teal: return RGB(48, 176, 199)
        case .purple: return RGB(175, 82, 222)
        case .mint: return RGB(0, 199, 190)
        case .indigo: return RGB(88, 86, 214)
        case .brown: return RGB(162, 132, 94)
        case .gray: return RGB(142, 142, 147)
        }
    }

    /// The system colour of the same name, dark appearance.
    private var darkBase: RGB {
        switch self {
        case .teal: return RGB(64, 203, 224)
        case .purple: return RGB(191, 90, 242)
        case .mint: return RGB(99, 230, 226)
        case .indigo: return RGB(94, 92, 230)
        case .brown: return RGB(172, 142, 104)
        case .gray: return RGB(142, 142, 147)
        }
    }
}

/// One secret a review names, as the provider that holds it describes it,
/// outermost first: where the value resolves from (a 1Password account, this
/// Mac), the vault or store, the item, and the field. Value-free. Every Mac
/// panel and the phone draw a review's secrets from these, through
/// `ReviewSecretTree`, so none of them parses a reference itself.
public struct ReviewSecret: Codable, Equatable, Sendable {
    /// The provider's display name, e.g. `1Password`. Nil for a reference no
    /// provider described.
    public let provider: String?
    public let tint: ReviewSecretTint
    /// Where the value resolves from: a 1Password account, `this Mac`. Nil
    /// when the provider cannot say yet.
    public let account: String?
    /// The vault or store. Nil for a reference shown whole as `item`.
    public let container: String?
    /// The item or key; for a reference no provider described, the complete
    /// reference.
    public let item: String
    /// The field within the item. Nil when the item is itself the secret.
    public let field: String?
    /// The item is an identifier (a key name, a whole reference), set in
    /// monospace.
    public let itemIsIdentifier: Bool
    /// Provider context about where the value will come from.
    public let notes: [String]
    /// Provider warnings about that choice, shown as warnings.
    public let warnings: [String]

    public init(
        provider: String?,
        tint: ReviewSecretTint,
        account: String?,
        container: String?,
        item: String,
        field: String?,
        itemIsIdentifier: Bool = false,
        notes: [String] = [],
        warnings: [String] = []
    ) {
        self.provider = provider
        self.tint = tint
        self.account = account
        self.container = container
        self.item = item
        self.field = field
        self.itemIsIdentifier = itemIsIdentifier
        self.notes = notes
        self.warnings = warnings
    }

    /// The same secret with every string passed through `transform`, which is
    /// how the Mac makes a provider's description display-safe. A part that
    /// comes back empty is dropped, except the item, which is never empty.
    public func mapStrings(
        _ transform: (_ value: String, _ part: Part) -> String
    ) -> ReviewSecret {
        func optional(_ value: String?, _ part: Part) -> String? {
            guard let value else { return nil }
            let mapped = transform(value, part)
            return mapped.isEmpty ? nil : mapped
        }
        let item = transform(self.item, .item)
        return ReviewSecret(
            provider: optional(provider, .provider),
            tint: tint,
            account: optional(account, .account),
            container: optional(container, .container),
            item: item.isEmpty ? "(unnamed)" : item,
            field: optional(field, .field),
            itemIsIdentifier: itemIsIdentifier,
            notes: notes.map { transform($0, .note) }.filter { !$0.isEmpty },
            warnings: warnings.map { transform($0, .warning) }.filter { !$0.isEmpty }
        )
    }

    public enum Part: Sendable {
        case provider, account, container, item, field, note, warning
    }
}

/// A review's secrets as one tree: source (provider and account) › container
/// (vault or store) › item › fields. Each level appears once however many
/// secrets share it, in the order the secrets first name it, and a source
/// with a single container shares its line with it. The Mac panels and the
/// phone both draw this, so they cannot disagree about what folds.
public struct ReviewSecretTree: Equatable, Sendable {
    public struct Item: Equatable, Sendable {
        public let name: String
        public let isIdentifier: Bool
        /// Every field of the item the review names, in order, once each.
        public internal(set) var fields: [String]

        /// The name as VoiceOver reads it: an identifier's underscores read as
        /// spaces ("GITHUB TOKEN" rather than "GITHUB underscore TOKEN"), and
        /// any other name as written. Every surface labels the item with it.
        public var spokenName: String {
            isIdentifier ? name.replacingOccurrences(of: "_", with: " ") : name
        }
    }

    public struct Container: Equatable, Sendable {
        /// Nil for references no provider described.
        public let name: String?
        public internal(set) var items: [Item]
        /// Provider notes and warnings for anything in this container, once
        /// each: they say where the container's values resolve from.
        public internal(set) var notes: [String]
        public internal(set) var warnings: [String]
    }

    public struct Source: Equatable, Sendable {
        public let provider: String?
        public let account: String?
        public let tint: ReviewSecretTint
        public internal(set) var containers: [Container]

        /// One container shares the source's line ("1Password ·
        /// acme.1password.eu › Employee"); with more, each container gets its
        /// own line beneath it.
        public var foldsContainer: Bool { containers.count == 1 }

        /// The source's own line, "1Password · acme.1password.eu", or nil for
        /// references no provider described, which are listed bare.
        public var title: String? {
            guard let provider else { return account }
            return [provider, account].compactMap { $0 }.joined(separator: " · ")
        }
    }

    public let sources: [Source]
    /// How many secrets the tree holds: one per reference.
    public let secretCount: Int

    public init(_ secrets: [ReviewSecret]) {
        var sources: [Source] = []
        for secret in secrets {
            let sourceIndex: Int
            if let index = sources.firstIndex(where: {
                $0.provider == secret.provider && $0.account == secret.account
            }) {
                sourceIndex = index
            } else {
                sources.append(Source(
                    provider: secret.provider, account: secret.account,
                    tint: secret.tint, containers: []
                ))
                sourceIndex = sources.count - 1
            }

            var source = sources[sourceIndex]
            let containerIndex: Int
            if let index = source.containers.firstIndex(where: { $0.name == secret.container }) {
                containerIndex = index
            } else {
                source.containers.append(Container(name: secret.container, items: [], notes: [], warnings: []))
                containerIndex = source.containers.count - 1
            }

            var container = source.containers[containerIndex]
            for note in secret.notes where !container.notes.contains(note) {
                container.notes.append(note)
            }
            for warning in secret.warnings where !container.warnings.contains(warning) {
                container.warnings.append(warning)
            }
            let itemIndex: Int
            if let index = container.items.firstIndex(where: {
                $0.name == secret.item && $0.isIdentifier == secret.itemIsIdentifier
            }) {
                itemIndex = index
            } else {
                container.items.append(Item(name: secret.item, isIdentifier: secret.itemIsIdentifier, fields: []))
                itemIndex = container.items.count - 1
            }
            if let field = secret.field, !container.items[itemIndex].fields.contains(field) {
                container.items[itemIndex].fields.append(field)
            }
            source.containers[containerIndex] = container
            sources[sourceIndex] = source
        }
        self.sources = sources
        self.secretCount = secrets.count
    }
}
