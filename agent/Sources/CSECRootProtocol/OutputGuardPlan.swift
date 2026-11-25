import Foundation

/// Which standard-output destinations the launcher is allowed to interpose.
public enum OutputGuardMode: String, Codable, Sendable, CaseIterable {
    case tty
    case always
    case never
}

/// How supervised output identifies a protected value after replacement.
public enum OutputRedactionLabelStyle: String, Codable, Sendable, CaseIterable {
    case opaque
    case reference
}

/// Value-free output configuration bound into every relevant launch digest.
public struct OutputGuardPlan: Codable, Sendable, Equatable {
    public static let currentMatcherVersion = 1

    public let mode: OutputGuardMode
    public let labelStyle: OutputRedactionLabelStyle
    public let includeShortValues: Bool
    public let matcherVersion: Int

    public init(
        mode: OutputGuardMode,
        labelStyle: OutputRedactionLabelStyle = .opaque,
        includeShortValues: Bool = false,
        matcherVersion: Int = Self.currentMatcherVersion
    ) {
        self.mode = mode
        self.labelStyle = labelStyle
        self.includeShortValues = includeShortValues
        self.matcherVersion = matcherVersion
    }
}
