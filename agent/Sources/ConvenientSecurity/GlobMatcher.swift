import Foundation

/// Path glob matching for the bulk-protect selection UI. Deliberately small:
/// `*` (within one component), `?` (one non-`/` character), `**` (a full
/// component matching any number of components, including none), `~` (the
/// caller's home), and `/`-anchored patterns. A pattern without a leading `/`
/// or `~` floats: it matches when it matches any suffix of the path starting
/// at a component boundary, so `*.envrc` and `work/**/.env` do what they
/// read as. No character classes, no escaping — bounded and predictable.
public enum GlobMatcher {
    public static let maximumPatternBytes = 512
    public static let maximumPathBytes = 4096

    public static func matches(
        _ pattern: String,
        path: String,
        homeDirectory: String
    ) -> Bool {
        guard pattern.utf8.count <= maximumPatternBytes,
              path.utf8.count <= maximumPathBytes,
              !pattern.isEmpty, !path.isEmpty else { return false }

        var expanded = pattern
        if expanded == "~" { expanded = homeDirectory }
        else if expanded.hasPrefix("~/") {
            let home = homeDirectory.hasSuffix("/")
                ? String(homeDirectory.dropLast()) : homeDirectory
            expanded = home + expanded.dropFirst(1)
        }

        let anchored = expanded.hasPrefix("/")
        let patternComponents = expanded.split(separator: "/").map(String.init)
        let pathComponents = path.split(separator: "/").map(String.init)
        guard !patternComponents.isEmpty, !pathComponents.isEmpty else { return false }

        if anchored {
            return matchComponents(patternComponents, pathComponents)
        }
        // Floating: any suffix starting at a component boundary.
        for start in pathComponents.indices {
            if matchComponents(patternComponents, Array(pathComponents[start...])) {
                return true
            }
        }
        return false
    }

    private static func matchComponents(_ pattern: [String], _ path: [String]) -> Bool {
        // Iterative matcher with single-star backtracking over `**`: track the
        // last `**` position and retry with it consuming one more component.
        var patternIndex = 0
        var pathIndex = 0
        var starPatternIndex = -1
        var starPathIndex = -1

        while pathIndex < path.count {
            if patternIndex < pattern.count, pattern[patternIndex] == "**" {
                starPatternIndex = patternIndex
                starPathIndex = pathIndex
                patternIndex += 1
            } else if patternIndex < pattern.count,
                      matchComponent(pattern[patternIndex], path[pathIndex]) {
                patternIndex += 1
                pathIndex += 1
            } else if starPatternIndex >= 0 {
                starPathIndex += 1
                patternIndex = starPatternIndex + 1
                pathIndex = starPathIndex
            } else {
                return false
            }
        }
        while patternIndex < pattern.count, pattern[patternIndex] == "**" {
            patternIndex += 1
        }
        return patternIndex == pattern.count
    }

    /// fnmatch-style single-component match: `*` spans within the component,
    /// `?` one character, everything else literal.
    static func matchComponent(_ pattern: String, _ name: String) -> Bool {
        let patternChars = Array(pattern)
        let nameChars = Array(name)
        var patternIndex = 0
        var nameIndex = 0
        var starPatternIndex = -1
        var starNameIndex = -1

        while nameIndex < nameChars.count {
            if patternIndex < patternChars.count,
               patternChars[patternIndex] == "*" {
                starPatternIndex = patternIndex
                starNameIndex = nameIndex
                patternIndex += 1
            } else if patternIndex < patternChars.count,
                      patternChars[patternIndex] == "?"
                          || patternChars[patternIndex] == nameChars[nameIndex] {
                patternIndex += 1
                nameIndex += 1
            } else if starPatternIndex >= 0 {
                starNameIndex += 1
                patternIndex = starPatternIndex + 1
                nameIndex = starNameIndex
            } else {
                return false
            }
        }
        while patternIndex < patternChars.count, patternChars[patternIndex] == "*" {
            patternIndex += 1
        }
        return patternIndex == patternChars.count
    }
}
