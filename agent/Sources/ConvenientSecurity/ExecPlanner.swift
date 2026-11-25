import Foundation

/// Plans an `csec exec` invocation: decide which environment variables hold
/// secret references (so a program run under `csec exec` sees resolved values in
/// its environment), then rebuild the child environment once values arrive.
///
/// This is deliberately pure — no sockets, no process launching — so the
/// detection and rewriting rules are unit-testable without a running agent.
public enum ExecPlanner {
    public static let referencePrefix = "csec_"

    /// Strip exactly one reserved, case-sensitive prefix. Nested prefixes are
    /// ambiguous across wrapped launches, so reject them instead of guessing.
    public static func destinationName(_ name: String) throws -> String {
        guard name.hasPrefix(referencePrefix) else { return name }
        let destination = String(name.dropFirst(referencePrefix.count))
        guard SecretHeuristics.isEnvironmentName(destination),
              !destination.hasPrefix(referencePrefix) else {
            throw PlanError.invalidEnvironmentName
        }
        return destination
    }

    public enum PlanError: Error, Equatable, CustomStringConvertible {
        /// An explicit `--set NAME=ref` whose value isn't a parseable reference.
        case invalidReference(name: String, value: String)
        /// A reference whose scheme no running provider can resolve.
        case unresolvableScheme(name: String, scheme: String)
        /// The agent returned no value for a reference we planned to inject.
        case missingValue(name: String, reference: String)
        /// Environment keys cannot contain `=` or NUL; accepting one would make
        /// the exec environment ambiguous.
        case invalidEnvironmentName
        case invalidPrefixedReference(name: String)
        case conflictingEnvironmentNames(name: String)
        /// POSIX environment strings cannot carry NUL. Keep this diagnostic
        /// value-free because the rejected value is protected material.
        case valueNotEnvironmentCompatible(name: String)

        public var description: String {
            switch self {
            case let .invalidReference(name, value):
                return "--set \(name)=\(value): not a valid secret reference"
            case let .unresolvableScheme(name, scheme):
                return "\(name): no provider for scheme '\(scheme)://' (agent resolves: see `csec` docs)"
            case let .missingValue(name, reference):
                return "\(name): agent returned no value for \(reference)"
            case .invalidEnvironmentName:
                return "invalid environment variable name"
            case let .invalidPrefixedReference(name):
                return "\(name): csec_ variables must contain a valid secret reference"
            case let .conflictingEnvironmentNames(name):
                return "both \(name) and csec_\(name) are set; unset one or choose with --set \(name)=<reference>"
            case let .valueNotEnvironmentCompatible(name):
                return "\(name): protected value cannot be represented in a POSIX environment"
            }
        }
    }

    /// A mapping of environment variable name → the secret reference to inject.
    public struct Plan: Sendable, Equatable {
        /// Environment variable name → canonical reference URI to resolve into it.
        public let assignments: [String: String]
        /// Source aliases must not survive alongside the resolved destinations.
        public let referenceNames: Set<String>

        public init(assignments: [String: String], referenceNames: Set<String> = []) {
            self.assignments = assignments
            self.referenceNames = referenceNames
        }

        public func removingReferenceNames(from environment: [String: String]) -> [String: String] {
            environment.filter { !referenceNames.contains($0.key) }
        }

        /// The unique references to request from the agent, in a stable order.
        public var references: [String] {
            Array(Set(assignments.values)).sorted()
        }
    }

    /// Build a plan from the current environment plus explicit `--set` entries.
    ///
    /// - Environment values that parse as a `SecretRef` whose scheme the agent
    ///   handles are treated as references (the `op run` ergonomic — set
    ///   `DATABASE_URL=csec://…` in your `.envrc` and it's resolved in place). A
    ///   plain `https://…` URL is left untouched because its scheme isn't one the
    ///   agent resolves.
    /// - `csec_NAME=ref` reserves a reference alias: validate it strictly, resolve
    ///   into `NAME`, and remove the alias from the child. Ambient NAME and
    ///   csec_NAME together require an explicit --set to choose the binding.
    /// - Explicit `--set NAME=ref` entries always apply and override any env-scan
    ///   match for the same name; their scheme must be resolvable.
    public static func plan(
        environment: [String: String],
        explicit: [(name: String, reference: String)],
        knownSchemes: Set<String>
    ) throws -> Plan {
        var assignments: [String: String] = [:]
        var referenceNames: Set<String> = []
        let explicitNames = try Set(explicit.map { try destinationName($0.name) })

        // Env-scan: opportunistic, silently skips anything that isn't a resolvable
        // reference (ordinary values and URLs pass through unchanged).
        for (name, value) in environment.sorted(by: { $0.key < $1.key }) {
            if name.hasPrefix(referencePrefix) {
                let destination = try destinationName(name)
                referenceNames.insert(name)
                // --set is authoritative, including over malformed aliases.
                if explicitNames.contains(destination) { continue }
                guard environment[destination] == nil else {
                    throw PlanError.conflictingEnvironmentNames(name: destination)
                }
                guard let ref = try? SecretRef(value) else {
                    throw PlanError.invalidPrefixedReference(name: name)
                }
                guard knownSchemes.contains(ref.scheme) else {
                    throw PlanError.unresolvableScheme(name: name, scheme: ref.scheme)
                }
                assignments[destination] = ref.uri
                continue
            }
            guard let ref = try? SecretRef(value), knownSchemes.contains(ref.scheme) else { continue }
            assignments[name] = ref.uri
        }

        // Explicit --set: authoritative, and validated so typos fail loudly rather
        // than silently launching without the secret.
        for entry in explicit {
            guard !entry.name.isEmpty,
                  !entry.name.contains("="),
                  !entry.name.utf8.contains(0) else {
                throw PlanError.invalidEnvironmentName
            }
            guard let ref = try? SecretRef(entry.reference) else {
                throw PlanError.invalidReference(name: entry.name, value: entry.reference)
            }
            guard knownSchemes.contains(ref.scheme) else {
                throw PlanError.unresolvableScheme(name: entry.name, scheme: ref.scheme)
            }
            let destination = try destinationName(entry.name)
            if destination != entry.name { referenceNames.insert(entry.name) }
            assignments[destination] = ref.uri
        }

        return Plan(assignments: assignments, referenceNames: referenceNames)
    }

    /// Apply resolved values to produce the child environment. Every assignment's
    /// reference must be present in `values`; a missing one is a hard error rather
    /// than launching the child with a stale or empty variable.
    public static func resolvedEnvironment(
        base: [String: String],
        plan: Plan,
        values: [String: Data]
    ) throws -> [String: String] {
        var environment = plan.removingReferenceNames(from: base)
        for (name, reference) in plan.assignments {
            guard let bytes = values[reference] else {
                throw PlanError.missingValue(name: name, reference: reference)
            }
            // An environment variable is a NUL-free UTF-8 C string. A value that
            // is not representable as one — a binary file, say — is a real value
            // that simply cannot be delivered through the environment; it must go
            // via a materialized file instead.
            guard let value = String(data: bytes, encoding: .utf8),
                  !value.utf8.contains(0) else {
                throw PlanError.valueNotEnvironmentCompatible(name: name)
            }
            environment[name] = value
        }
        return environment
    }
}
