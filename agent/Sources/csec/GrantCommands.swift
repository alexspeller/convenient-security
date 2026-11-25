import ConvenientSecurity
import Foundation

/// `csec grants` — value-free listing of everything csecd would let run without
/// asking, each under its typed id: live secret (`grant-…`) and SSH (`ssh-…`)
/// grants, and while delegated approvals are on, project pairings (`pair-…`),
/// trusted Claude Code builds (`build-…`) and acknowledged hooks (`hook-…`) —
/// and `csec revoke`, which drops them. Neither command can release a value,
/// and revocation only removes access, so neither is gated by Touch ID.
func runGrants(_ arguments: [String]) -> Never {
    guard arguments.isEmpty else { usage("grants") }
    do {
        let listing = try makeAgentClient().grantListing()
        let delegation = listing.delegation
        let delegationIsEmpty = delegation.map {
            $0.pairings.isEmpty && $0.trustedBuilds.isEmpty && $0.acknowledgedHooks.isEmpty
        } ?? true
        guard !listing.grants.isEmpty || !delegationIsEmpty else {
            print("csec: no live grants")
            exit(0)
        }
        for grant in listing.grants {
            printGrant(grant)
        }
        if let delegation {
            for pairing in delegation.pairings {
                printPairing(pairing)
            }
            for build in delegation.trustedBuilds {
                print("\(build.displayID)  trusted Claude Code build \(ReviewDisplay.sanitized(build.versionLabel))")
                print("  path: \(ReviewDisplay.sanitized(build.path))")
                if let trustedAt = build.trustedAt {
                    print("  trusted: \(ISO8601DateFormatter().string(from: trustedAt)) (until revoked)")
                }
            }
            for hook in delegation.acknowledgedHooks {
                print("\(hook.displayID)  acknowledged hook \(ReviewDisplay.sanitized(hook.display))")
                if let acknowledgedAt = hook.acknowledgedAt {
                    print("  acknowledged: \(ISO8601DateFormatter().string(from: acknowledgedAt)) (until it changes)")
                }
            }
        }
        exit(0)
    } catch {
        csecError("grants", "\(error.localizedDescription)")
        exit(1)
    }
}

private func printGrant(_ grant: GrantSummary) {
    print("\(grant.displayID)  \(scopeLabel(grant))")
    print("  root: \(ReviewDisplay.sanitized(grant.rootProcessLabel)) (pid \(grant.rootPID))")
    if let ssh = grant.ssh {
        let host = ssh.hostNames.first.map { ReviewDisplay.sanitized($0) }
            ?? "host key \(ReviewDisplay.sanitized(ssh.hostKeyFingerprint))"
        print("  ssh: as \(ReviewDisplay.sanitized(ssh.remoteUser)) to \(host)")
        let label = ssh.keyLabel.map { "\(ReviewDisplay.sanitized($0)) " } ?? ""
        print("  key: \(label)(\(ReviewDisplay.sanitized(ssh.keyFingerprint)))")
        if !grant.references.isEmpty {
            print("  key reference: \(grant.references.joined(separator: ", "))")
        }
    } else {
        print("  references: \(grant.references.joined(separator: ", "))")
        if !grant.reason.isEmpty {
            print("  purpose: \(ReviewDisplay.sanitized(grant.reason))")
        }
    }
    if let expiresAt = grant.expiresAt {
        print("  expires: \(ISO8601DateFormatter().string(from: expiresAt))")
    } else {
        print("  expires: when the process exits (no time limit)")
    }
    if grant.grantKind == .secret {
        print(
            "  reuse: "
            + (grant.reusesAcrossCommands
               ? "any command of the same delivery shape in this process tree"
               : "only an identical command")
        )
    }
    if grant.restored == true {
        print("  restored after csecd restarted")
    }
}

private func printPairing(_ pairing: ProjectPairingSummary) {
    print("\(pairing.displayID)  Claude Code auto mode in \(ReviewDisplay.sanitized(ProjectKey.displayDescription(forPath: pairing.projectPath)))")
    if !pairing.references.isEmpty {
        print("  references: \(pairing.references.map { ReviewDisplay.sanitized($0) }.joined(separator: ", "))")
    }
    if !pairing.usedReferences.isEmpty {
        // A use paired for csecd alone holds for auto mode in every project
        // until every pairing that lists it is revoked.
        print("  used inside csec, never released (every project): "
              + pairing.usedReferences.map { ReviewDisplay.sanitized($0) }.joined(separator: ", "))
    }
    for ssh in pairing.ssh {
        let host = ssh.hostNames.first.map { ReviewDisplay.sanitized($0) }
            ?? "host key \(ReviewDisplay.sanitized(ssh.hostKeyFingerprint))"
        let label = ssh.keyLabel.map { "\(ReviewDisplay.sanitized($0)) " } ?? ""
        // An approved SSH destination holds for auto mode in every project;
        // it is listed with the project it was approved in, whose revocation
        // removes it.
        print("  ssh (every project): key \(label)(\(ReviewDisplay.sanitized(ssh.keyFingerprint))) "
              + "as \(ReviewDisplay.sanitized(ssh.remoteUser)) to \(host)")
    }
    for launcher in pairing.launchers {
        let sources = launcher.sources.isEmpty
            ? "" : " (+ \(launcher.sources.map { ReviewDisplay.sanitized($0) }.joined(separator: ", ")))"
        print("  ssh launcher: \(ReviewDisplay.sanitized(launcher.path))\(sources)")
    }
    if pairing.sudo {
        print("  sudo: auto mode may run sudo in this project")
    }
    print("  expires: when revoked")
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

    let client = makeAgentClient()
    do {
        guard let grantID else {
            // `--all` is idempotent: having nothing left to revoke is the
            // desired state, not an error.
            let revoked = try client.revokeAll()
            print("csec: revoked \(revokedSummary(count: revoked.count, removed: revoked.removed, kind: .secret))")
            printRemoved(revoked.removed)
            exit(0)
        }
        guard let selector = GrantIDSelector(grantID) else {
            csecError("revoke", "\(ReviewDisplay.sanitized(grantID)) is not an id `csec grants` shows "
                + "(grant-…, ssh-…, pair-…, build-…, hook-…, or a bare grant id)")
            exit(2)
        }
        switch try client.revoke(id: grantID) {
        case let .ambiguous(matches):
            // Nothing was removed. Each match is shown in full, so any one of
            // them is an id that names only it.
            csecError("revoke", "\(ReviewDisplay.sanitized(grantID)) matches \(matches.count) entries and "
                + "revoked none; give more of the id:")
            for match in matches {
                FileHandle.standardError.write(Data(
                    "  \(match.kind.typedPrefix)\(match.id)  \(ReviewDisplay.sanitized(match.label))\n".utf8))
            }
            exit(1)
        case let .revoked(count, removed):
            // A named entry that matches nothing is a mistake worth reporting.
            guard count > 0 else {
                csecError("revoke", "no live grant matches \(ReviewDisplay.sanitized(grantID))")
                exit(1)
            }
            print("csec: revoked \(revokedSummary(count: count, removed: removed, kind: selector.kind))")
            printRemoved(removed)
            exit(0)
        }
    } catch {
        csecError("revoke", "\(error.localizedDescription)")
        exit(1)
    }
}

/// `csec refresh <reference>...`: drop csecd's cached copy of each reference
/// (every tier, through the same verb `csec edit` sends after a write), so
/// the next release reads it from its provider. Value-free: nothing is read,
/// shown or granted, so it needs no Touch ID.
func runRefresh(_ arguments: [String]) -> Never {
    guard !arguments.isEmpty, arguments.allSatisfy({ !$0.hasPrefix("-") }) else { usage("refresh") }
    var references: [String] = []
    for argument in arguments {
        guard let ref = try? SecretRef(argument) else {
            csecError("refresh", "\(ReviewDisplay.sanitized(argument)) is not a secret reference "
                + "(op://vault/item/field or csec://store/KEY)")
            exit(2)
        }
        if !references.contains(ref.uri) { references.append(ref.uri) }
    }
    guard references.count <= InvalidateCachedReferencesRequest.maximumReferences else {
        csecError("refresh", "at most \(InvalidateCachedReferencesRequest.maximumReferences) references at a time")
        exit(2)
    }
    do {
        try makeAgentClient().invalidateCachedReferences(references)
    } catch {
        csecError("refresh", "\(error.localizedDescription)")
        exit(1)
    }
    let noun = references.count == 1 ? "reference" : "references"
    print("csec: dropped csecd's cached copy of \(references.count) \(noun); the next release reads "
        + "\(references.count == 1 ? "it" : "them") from the provider")
    exit(0)
}

/// "1 grant", "2 grants and 1 pairing": by kind when csecd listed what it
/// removed, else (a csecd that reports only a count) in the named kind.
private func revokedSummary(count: Int, removed: [RevocableEntry], kind: GrantIDKind) -> String {
    guard !removed.isEmpty else { return revokedNoun(count, kind) }
    let parts = GrantIDKind.allCases.compactMap { kind -> String? in
        let matching = removed.filter { $0.kind == kind }.count
        return matching > 0 ? revokedNoun(matching, kind) : nil
    }
    guard parts.count > 1 else { return parts.first ?? revokedNoun(count, kind) }
    return parts.dropLast().joined(separator: ", ") + " and " + (parts.last ?? "")
}

private func revokedNoun(_ count: Int, _ kind: GrantIDKind) -> String {
    let (singular, plural): (String, String)
    switch kind {
    case .secret: (singular, plural) = ("grant", "grants")
    case .ssh: (singular, plural) = ("SSH grant", "SSH grants")
    case .pairing: (singular, plural) = ("pairing", "pairings")
    case .build: (singular, plural) = ("trusted build", "trusted builds")
    case .hook: (singular, plural) = ("acknowledged hook", "acknowledged hooks")
    }
    return "\(count) \(count == 1 ? singular : plural)"
}

private func printRemoved(_ removed: [RevocableEntry]) {
    for entry in removed {
        print("  \(entry.displayID)  \(ReviewDisplay.sanitized(entry.label))")
    }
}

private func scopeLabel(_ grant: GrantSummary) -> String {
    let scope: String
    switch grant.scopeKind {
    case .requestingCommand: scope = "requesting process only"
    case .codingAgent: scope = "coding agent"
    case .terminalSession: scope = "terminal session"
    }
    return grant.grantKind == .ssh ? "SSH signing, \(scope)" : scope
}
