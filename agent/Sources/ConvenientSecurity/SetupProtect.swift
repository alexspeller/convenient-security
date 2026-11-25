import Foundation

/// The approach a bulk-protect assignment applies to one discovered file —
/// `CredentialDelivery` plus the explicit human override `skip`. String forms
/// are the non-interactive `--glob 'PATTERN=approach[:dest]'` vocabulary.
public enum BulkProtectApproach: Equatable, Sendable {
    case perVar
    case wholeFile
    case sshKey
    case credsAws
    case filePreset(preset: String, pathEnvironmentVariable: String?)
    case envToken(variables: [String])
    case fly
    case skip

    public init(delivery: CredentialDelivery) {
        switch delivery {
        case .perVar: self = .perVar
        case .wholeFile: self = .wholeFile
        case .sshKey: self = .sshKey
        case .credsAws: self = .credsAws
        case let .filePreset(preset, variable):
            self = .filePreset(preset: preset, pathEnvironmentVariable: variable)
        case .envToken(let variables): self = .envToken(variables: variables)
        case .flyToken: self = .fly
        }
    }

    /// Parse a `--glob` approach token: `per-var`, `whole-file`, `ssh`,
    /// `creds-aws`, `fly`, `skip`, `preset:<name>`, `env-token:<VAR>[,VAR…]`.
    public static func parse(_ token: String) -> BulkProtectApproach? {
        switch token {
        case "per-var": return .perVar
        case "whole-file": return .wholeFile
        case "ssh": return .sshKey
        case "creds-aws": return .credsAws
        case "fly": return .fly
        case "skip": return .skip
        default:
            if token.hasPrefix("preset:") {
                let name = String(token.dropFirst("preset:".count))
                guard !name.isEmpty else { return nil }
                return .filePreset(preset: name, pathEnvironmentVariable: nil)
            }
            if token.hasPrefix("env-token:") {
                let variables = token.dropFirst("env-token:".count)
                    .split(separator: ",").map(String.init)
                guard !variables.isEmpty,
                      variables.allSatisfy(SecretHeuristics.isEnvironmentName) else {
                    return nil
                }
                return .envToken(variables: variables)
            }
            return nil
        }
    }

    public var displayToken: String {
        switch self {
        case .perVar: return "per-var"
        case .wholeFile: return "whole-file"
        case .sshKey: return "ssh"
        case .credsAws: return "creds-aws"
        case .filePreset(let preset, _): return "preset:\(preset)"
        case .envToken(let variables): return "env-token:\(variables.joined(separator: ","))"
        case .fly: return "fly"
        case .skip: return "skip"
        }
    }
}

/// One `--glob 'PATTERN=approach[:dest]'` rule (or one interactive subset
/// assignment). Later rules win over earlier ones.
public struct BulkProtectRule: Equatable, Sendable {
    public let pattern: String
    /// Nil keeps each matched file's default approach (destination-only rule).
    public let approach: BulkProtectApproach?
    /// `csec://STORE` or `op://VAULT[/ITEM]`; nil keeps the default store
    /// resolved from the file's project root.
    public let destination: String?

    public init(pattern: String, approach: BulkProtectApproach?, destination: String?) {
        self.pattern = pattern
        self.approach = approach
        self.destination = destination
    }

    /// `PATTERN=approach[:dest]`. The destination is recognized by its scheme
    /// (`csec://` or `op://`), so preset/env-token approach tokens may
    /// themselves contain `:` unambiguously.
    public static func parse(_ token: String) -> BulkProtectRule? {
        guard let equals = token.firstIndex(of: "="), equals != token.startIndex else {
            return nil
        }
        let pattern = String(token[..<equals])
        var value = String(token[token.index(after: equals)...])
        guard !value.isEmpty else { return nil }

        var destination: String?
        for scheme in ["csec://", "op://"] {
            if let range = value.range(of: ":" + scheme) {
                destination = String(value[value.index(after: range.lowerBound)...])
                value = String(value[..<range.lowerBound])
                break
            }
            if value.hasPrefix(scheme) {
                destination = value
                value = ""
                break
            }
        }
        if value.isEmpty {
            guard destination != nil else { return nil }
            return BulkProtectRule(pattern: pattern, approach: nil, destination: destination)
        }
        guard let approach = BulkProtectApproach.parse(value) else { return nil }
        return BulkProtectRule(pattern: pattern, approach: approach, destination: destination)
    }
}

/// One file's resolved bulk-protect intent: the file, the approach that will
/// be applied, and the destination override (nil = the legible default store
/// for the file's project root, resolved at apply time).
public struct BulkProtectAssignment: Equatable, Sendable {
    public let file: DiscoveredSecretFile
    public var approach: BulkProtectApproach
    public var destination: String?
    public var matchedPattern: String?

    public init(
        file: DiscoveredSecretFile,
        approach: BulkProtectApproach,
        destination: String? = nil,
        matchedPattern: String? = nil
    ) {
        self.file = file
        self.approach = approach
        self.destination = destination
        self.matchedPattern = matchedPattern
    }
}

public enum SetupProtectPlanner {
    /// Every discovered file with its default approach, then each rule
    /// applied in order to the files its glob matches (canonical or alias
    /// path). Later rules win; a destination-only rule keeps the approach.
    public static func assignments(
        files: [DiscoveredSecretFile],
        rules: [BulkProtectRule],
        homeDirectory: String
    ) -> [BulkProtectAssignment] {
        var assignments = files.map {
            BulkProtectAssignment(file: $0, approach: defaultApproach(for: $0))
        }
        for rule in rules {
            for index in assignments.indices where ruleMatches(
                rule, file: assignments[index].file, homeDirectory: homeDirectory
            ) {
                if let approach = rule.approach {
                    assignments[index].approach = approach
                }
                if let destination = rule.destination {
                    assignments[index].destination = destination
                }
                assignments[index].matchedPattern = rule.pattern
            }
        }
        return assignments
    }

    /// The approach a file gets before any rule. A file its tool rewrites
    /// during ordinary commands defaults to `skip` when its only delivery is
    /// whole-file, which would break the tool or put the plaintext back, so it
    /// is listed with the reason and protected only if the user chooses to.
    /// Fly's token comes out of its file instead, which the rewrites keep.
    /// Shell startup files also skip whole-file replacement by default,
    /// because ordinary startup cannot load their sidecars.
    public static func defaultApproach(for file: DiscoveredSecretFile) -> BulkProtectApproach {
        let approach = BulkProtectApproach(delivery: file.suggestedApproach)
        if file.kind == .shellRc, approach != .perVar { return .skip }
        return file.toolRewritesFile && approach != .fly ? .skip : approach
    }

    public static func ruleMatches(
        _ rule: BulkProtectRule,
        file: DiscoveredSecretFile,
        homeDirectory: String
    ) -> Bool {
        if GlobMatcher.matches(rule.pattern, path: file.canonicalPath, homeDirectory: homeDirectory) {
            return true
        }
        return file.aliasPaths.contains {
            GlobMatcher.matches(rule.pattern, path: $0, homeDirectory: homeDirectory)
        }
    }
}

/// Value-free protection plan. Pipes keep full paths on one line; terminals
/// wrap cells instead of hiding the end of a path in a confirmation prompt.
public enum SetupProtectPlanRenderer {
    public static func render(
        _ assignments: [BulkProtectAssignment], homeDirectory: String, width: Int? = nil
    ) -> String {
        func safe(_ value: String) -> String {
            ReviewDisplay.sanitized(value).replacingOccurrences(of: "|", with: "\\|")
        }
        func path(_ value: String) -> String {
            let home = homeDirectory.hasSuffix("/") ? String(homeDirectory.dropLast()) : homeDirectory
            let displayed = value.hasPrefix(home + "/") ? "~" + value.dropFirst(home.count) : value
            return safe(displayed)
        }
        var rows = [["FILE", "TYPE", "PROTECTION", "NOTES"]]
        for assignment in assignments {
            var notes = assignment.file.notes
            if let destination = assignment.destination { notes.insert("Destination: " + destination, at: 0) }
            rows.append([path(assignment.file.canonicalPath), assignment.file.kind.displayLabel,
                         safe(assignment.approach.displayToken),
                         safe(notes.joined(separator: "; "))])
            for alias in assignment.file.aliasPaths.sorted() {
                rows.append([path(alias), "Hardlink", "same file", ""])
            }
        }
        let hasNotes = rows.dropFirst().contains { !$0[3].isEmpty }
        if !hasNotes { rows = rows.map { Array($0.prefix(3)) } }
        var widths = (0..<rows[0].count).map { column in rows.map { $0[column].count }.max() ?? 0 }
        if let width {
            let available = max(40, width) - (widths.count * 3 + 1)
            widths[1] = min(widths[1], max(6, available / 6))
            widths[2] = min(widths[2], max(8, available / 5))
            if hasNotes { widths[3] = min(widths[3], max(8, available / 4)) }
            widths[0] = max(8, available - widths.dropFirst().reduce(0, +))
        }
        func chunks(_ text: String, width: Int) -> [String] {
            var rest = text[...]
            var result: [String] = []
            while !rest.isEmpty {
                result.append(String(rest.prefix(width)))
                rest = rest.dropFirst(width)
            }
            return result.isEmpty ? [""] : result
        }
        let count = assignments.filter { $0.approach != .skip }.count
        var lines = ["plan: \(count) unique file(s) to protect"]
        for (index, row) in rows.enumerated() {
            let cells = row.enumerated().map { chunks($0.element, width: widths[$0.offset]) }
            for line in 0..<(cells.map(\.count).max() ?? 1) {
                lines.append("| " + cells.enumerated().map { column, parts in
                    let part = line < parts.count ? parts[line] : ""
                    return part.padding(toLength: widths[column], withPad: " ", startingAt: 0)
                }.joined(separator: " | ") + " |")
            }
            if index == 0 {
                lines.append("|-" + widths.map { String(repeating: "-", count: $0) }.joined(separator: "-+-") + "-|")
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }
}

extension SecretFileKind {
    public var displayLabel: String {
        switch self {
        case .dotenv: return "Env file"
        case .envrc: return "direnv"
        case .shellRc: return "Shell config"
        case .sshPrivateKey: return "SSH key"
        case .keyMaterial: return "Key material"
        case .toolCredential: return "Tool credentials"
        case .other: return "Other"
        }
    }
}

