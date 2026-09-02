import ConvenientSecurity
import Foundation

/// `csec grants` — value-free listing of the live subtree grants csecd holds —
/// and `csec revoke`, which drops them. Neither command can release a value, and
/// revocation only removes access, so neither is gated by Touch ID.
func runGrants(_ arguments: [String]) -> Never {
    guard arguments.isEmpty else { usage("grants") }
    do {
        let grants = try makeAgentClient().listGrants()
        guard !grants.isEmpty else {
            print("csec: no live grants")
            exit(0)
        }
        for grant in grants {
            print("\(String(grant.id.prefix(8)))  \(scopeLabel(grant))")
            print("  root: \(grant.rootProcessLabel) (pid \(grant.rootPID))")
            print("  references: \(grant.references.joined(separator: ", "))")
            if !grant.reason.isEmpty {
                print("  purpose: \(ReviewDisplay.sanitized(grant.reason))")
            }
            print("  expires: \(ISO8601DateFormatter().string(from: grant.expiresAt))")
            print(
                "  reuse: "
                + (grant.reusesAcrossCommands
                   ? "any command of the same delivery shape in this process tree"
                   : "only an identical command")
            )
        }
        exit(0)
    } catch {
        csecError("grants", "\(error.localizedDescription)")
        exit(1)
    }
}

func runRevoke(_ arguments: [String]) -> Never {
    var all = false
    var grantID: String?
    var index = 0
    while index < arguments.count {
        switch arguments[index] {
        case "--all":
            all = true
        case let value where !value.hasPrefix("-"):
            guard grantID == nil else { usage("revoke") }
            grantID = value
        default:
            usage("revoke")
        }
        index += 1
    }
    guard all != (grantID != nil) else { usage("revoke") }

    do {
        let count = try makeAgentClient().revokeGrants(grantID: grantID, all: all)
        // `--all` is idempotent: having nothing left to revoke is the desired
        // state, not an error. A named grant that matches nothing is a mistake
        // worth reporting.
        guard all || count > 0 else {
            csecError("revoke", "no live grant matches \(ReviewDisplay.sanitized(grantID ?? ""))")
            exit(1)
        }
        print("csec: revoked \(count) grant\(count == 1 ? "" : "s")")
        exit(0)
    } catch {
        csecError("revoke", "\(error.localizedDescription)")
        exit(1)
    }
}

private func scopeLabel(_ grant: GrantSummary) -> String {
    switch grant.scopeKind {
    case .requestingCommand: return "requesting process only"
    case .codingAgent: return "coding agent"
    case .terminalSession: return "terminal session"
    }
}
