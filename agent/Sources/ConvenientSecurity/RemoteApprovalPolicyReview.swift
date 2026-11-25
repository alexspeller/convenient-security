import CryptoKit
import CSECRemoteApproval
import Foundation

/// Whether the paired phone can carry a review, judged from its references
/// before anything is published. Provider-neutral: the answer comes from the
/// owning providers through the resolver, never from a reference's scheme.
public enum RemoteReviewReadiness: Sendable, Equatable {
    /// The Mac panel alone decides: no usable pairing or iCloud account, or a
    /// reference needs an unlock that no phone approval could open.
    case unavailable
    /// The phone can decide, and `unlock` says what a phone approval does
    /// with the phone-held unlock factor.
    case ready(unlock: RemoteUnlockUse)
}

/// What a phone approval does with the phone-held unlock factor.
public enum RemoteUnlockUse: Sendable, Equatable {
    /// Nothing to open: the request carries no unlock challenge.
    case notNeeded
    /// A cached copy the unlock opens is read before the provider is asked
    /// (`RemoteUnlockCoverage.cachedRemotely`). The provider can still fetch
    /// every value, so an approval whose unlock cannot be made or does not
    /// open still stands, and the provider is asked as it would be with none.
    case preferred
    /// Some reference only opens with the unlock (every one is covered): an
    /// approval whose unlock does not open is no decision.
    case required
}

/// The phone leg's answer to one mirrored review.
public enum RemoteAccessReviewResult: Sendable {
    /// No phone decision: relay, pairing or unlock trouble, a withdrawal, or
    /// an approval whose unlock did not open. The local prompt carries the
    /// request; this is never a denial.
    case unavailable
    /// The pinned phone's verified Deny, stamped when this Mac accepted it.
    case denied(receivedAt: ContinuousClock.Instant)
    /// The pinned phone's verified approval: the scope and lifetime it
    /// selected (options the review offered), and, when the review needed
    /// one, the remote unlock its answer opened for this one request.
    case approved(selection: RemoteApprovalSelection, unlock: CacheUnlock?)
}

/// Adapter seam between the agent's immutable local review and a remote
/// requester. Returning unavailable never suppresses or denies the local prompt.
public protocol RemoteAccessPolicyReviewProvider: Sendable {
    /// Whether a phone approval could carry out a review that resolves
    /// `references` and reopens `restoring` (its restore section's rows), and
    /// whether it would need the phone-held unlock factor. A restore reopens
    /// from local sealed state only, never through a provider, so a restore
    /// reference that only the cold cache holds needs an unlock even when its
    /// provider could fetch it (`SecretResolver.remoteUnlockCoverage(_:restoring:)`).
    /// Never prompts, never contacts the relay, and returns no value.
    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness
    /// Whether a phone approval could decide a settings review, which
    /// releases and opens nothing: only a phone that shows settings reviews
    /// can. Never prompts and never waits on the relay.
    func remoteSettingsReadiness() async -> RemoteReviewReadiness
    /// Publish `review` to the pinned phone and wait for its decision. When
    /// `unlock` is not `.notNeeded` the request carries a blinded unlock
    /// challenge where one can be made, and an approval returns the unlock it
    /// opened; `.required` makes an approval without one no decision, while
    /// `.preferred` returns the approval with no unlock instead.
    func reviewRemoteAccess(
        _ review: RemoteApprovalReview,
        unlock: RemoteUnlockUse
    ) async -> RemoteAccessReviewResult
}

public extension RemoteAccessPolicyReviewProvider {
    /// Readiness for a review with no restore section.
    func remoteReadiness(for references: [SecretRef]) async -> RemoteReviewReadiness {
        await remoteReadiness(for: references, restoring: [])
    }

    /// A provider that cannot say what the phone shows keeps settings changes
    /// on this Mac.
    func remoteSettingsReadiness() async -> RemoteReviewReadiness { .unavailable }
}

/// A requester on its own, with no phone-held unlock factor: it is ready for
/// any review that needs no unlock and never opens one. For callers (tests,
/// tools) whose references need no unlock; csecd uses `RemoteApprovalManager`.
public struct RequesterRemoteAccessPolicyReviewProvider: RemoteAccessPolicyReviewProvider {
    private let requester: RemoteApprovalRequester

    public init(requester: RemoteApprovalRequester) {
        self.requester = requester
    }

    public func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        .ready(unlock: .notNeeded)
    }

    public func remoteSettingsReadiness() async -> RemoteReviewReadiness { .ready(unlock: .notNeeded) }

    public func reviewRemoteAccess(
        _ review: RemoteApprovalReview,
        unlock: RemoteUnlockUse
    ) async -> RemoteAccessReviewResult {
        guard unlock != .required else { return .unavailable }
        return RemoteAccessReviewResult(await requester.requestApproval(for: review))
    }
}

extension RemoteAccessReviewResult {
    /// A requester's answer to a request that carried no unlock challenge.
    init(_ result: RemoteApprovalRequesterResult) {
        switch result {
        case .unavailable: self = .unavailable
        case let .denied(receivedAt): self = .denied(receivedAt: receivedAt)
        case let .approved(selection): self = .approved(selection: selection.withoutUnlockAnswer, unlock: nil)
        }
    }
}

extension RemoteApprovalSelection {
    /// The selection with the phone's unlock answer dropped: once it has
    /// opened (or failed to open) the remote key it is of no further use, and
    /// nothing downstream reads it.
    var withoutUnlockAnswer: RemoteApprovalSelection {
        RemoteApprovalSelection(
            scopeOptionID: scopeOptionID, durationIndex: durationIndex, unlockAnswer: nil,
            pairingLineShown: pairingLineShown
        )
    }
}

/// Policy reviewer that presents the ordinary local Touch ID prompt and mirrors
/// the exact frozen, value-free transaction to one pinned phone. The first
/// authenticated decision wins. Host remediation remains local-only.
///
/// Which reviews reach the phone does not depend on where their values are
/// stored: every release, SSH signature and restore is mirrored exactly when
/// the remote provider says a phone approval could carry it out
/// (`remoteReadiness`), whichever providers own its references. The rules-
/// and hooks-changed acknowledgement, which names no reference, is mirrored
/// whenever the pairing is usable. Automation enrollment and setup done at
/// this Mac (`AccessPolicyReview.macOnly`, every other settings change) stay
/// on the Mac.
public struct MirroredPolicyReview: PolicyReviewProvider {
    private let local: any PolicyReviewProvider
    private let remote: any RemoteAccessPolicyReviewProvider
    private let log: @Sendable (String) -> Void

    public init(
        local: any PolicyReviewProvider = TrustedPolicyReview(),
        remote: any RemoteAccessPolicyReviewProvider,
        log: @escaping @Sendable (String) -> Void = { line in
            FileHandle.standardError.write(Data("\(line)\n".utf8))
        }
    ) {
        self.local = local
        self.remote = remote
        self.log = log
    }

    public func approvalReach(for review: AccessPolicyReview) async -> ApprovalReach {
        .judged(await phoneReadiness(of: review))
    }

    /// Whether the phone could carry `review` now. The phone may approve a
    /// restore section only if its approval could reopen every row, judged
    /// the way the restore reopens them: from local sealed state, never
    /// through a provider.
    private func phoneReadiness(of review: AccessPolicyReview) async -> RemoteReviewReadiness {
        guard review.automation == nil, !review.macOnly else { return .unavailable }
        // A settings change the phone may decide releases and opens nothing,
        // and only an app that shows settings reviews can decide one.
        if review.settingsChange != nil { return await remote.remoteSettingsReadiness() }
        guard let references = Self.remoteReferences(of: review) else { return .unavailable }
        return await remote.remoteReadiness(for: references.resolving, restoring: references.restoring)
    }

    public func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        // The judgement the requester's notice was given, when the queue
        // presents this review at once; otherwise a fresh one.
        let readiness: RemoteReviewReadiness
        if case let .judged(prejudged)? = ApprovalReach.prejudged {
            readiness = prejudged
        } else {
            readiness = await phoneReadiness(of: review)
        }
        guard case let .ready(unlock) = readiness else {
            HumanWait.current?.stayOnMac()
            return await local.reviewAccess(review)
        }
        let frozen: RemoteApprovalReview
        do {
            // The deadline the local panel shows (`HumanWait.current`, bound
            // by the queue around this race), so both copies close together.
            frozen = try RemoteApprovalReview(
                accessPolicyReview: review, deadline: ReviewDeadline(HumanWait.current)
            )
        } catch {
            // Every field is fitted to its bound, so what is left is a review
            // the phone format cannot carry at all. Say so: a request that
            // silently never reaches the phone looks like a relay fault.
            log("csecd: this request stays on the Mac; "
                + Self.unmirrorableReason(review, error: error) + ".")
            HumanWait.current?.stayOnMac()
            return await local.reviewAccess(review)
        }

        // The local panel is told whether the phone may still decide, so a Mac
        // that cannot take a touch says the phone can approve instead of
        // "cannot be authorized" (`ReviewTouchIDUnavailable`).
        let phone = ReviewPhoneStatus()
        return await withTaskGroup(of: PolicyReviewRaceResult.self) { group in
            group.addTask {
                .local(await ReviewPhoneStatus.$current.withValue(phone) {
                    await local.reviewAccess(review)
                })
            }
            group.addTask {
                .remote(await remote.reviewRemoteAccess(frozen, unlock: unlock))
            }

            var winner: AccessPolicyReviewOutcome?
            while winner == nil, let result = await group.next() {
                switch result {
                case let .local(outcome):
                    // Every local outcome ends the race, `.authenticationFailed`
                    // included, and that is deliberate: the Mac panel is the one
                    // surface the person at this Mac can see and cancel. Once it
                    // cannot be shown or its Touch ID failed, a request pending
                    // only on the phone would be invisible here.
                    winner = outcome
                case let .remote(.approved(selection, unlock)):
                    // Exactly the scope and lifetime the phone signed, which
                    // the requester already checked are options this review
                    // offered; the agent resolves them against its own lists.
                    // The phone showed the pairing line exactly when it
                    // signed so and the requester confirmed that against
                    // the signed selection.
                    winner = .approved(AccessPolicyApproval(
                        authenticationSession: RemoteApprovedAuthenticationSession(unlock: unlock),
                        selectedScopeOptionID: selection.scopeOptionID,
                        selectedDurationIndex: selection.durationIndex,
                        pairingLineShown: selection.pairingLineShown,
                        decidedOn: .phone
                    ))
                case let .remote(.denied(receivedAt)):
                    // A verified phone Deny is the human's decision, exactly
                    // like the Mac window's Deny button. It is ordered by when
                    // this Mac received it, not by when the requester returned.
                    winner = .denied(.human(decidedAt: receivedAt, on: .phone))
                case .remote(.unavailable):
                    // CloudKit/account/network trouble is not a decision. Leave
                    // the ordinary local prompt running; only a panel with no
                    // Touch ID changes, to say nobody else can approve now.
                    phone.markUnavailable()
                    continue
                }
            }

            // The losing leg is cancelled and answers promptly: the panel closes
            // on a main-actor hop, and the requester withdraws on an actor hop
            // while the phone's mailbox delete finishes in the background. What
            // it returns is not dropped unseen: a local approval that lost the
            // race still holds an evaluated LAContext and an open panel, so it is
            // cancelled, which invalidates the context and closes the window;
            // a phone approval that lost it may hold an opened remote unlock,
            // which is dropped.
            group.cancelAll()
            for await loser in group {
                switch loser {
                case let .local(.approved(approval)):
                    await approval.authenticationSession?.cancel()
                case let .remote(.approved(_, unlock)):
                    unlock?.invalidate()
                default:
                    break
                }
            }
            // Unreachable while the local review always returns; if it is ever
            // reached, nobody decided, so the denial must not propagate.
            return winner ?? .denied(.authenticationFailed)
        }
    }

    public func reviewHostRemediation(
        _ review: HostRemediationReview
    ) async -> HostRemediationOutcome {
        await local.reviewHostRemediation(review)
    }

    /// Every reference the approved operation would resolve (the release's
    /// credentials) or reopen (each restore row's), kept apart because a
    /// restore reopens differently. Nil when there is none, or when a restore
    /// row names one that does not parse; the review then stays on the Mac.
    static func remoteReferences(
        of review: AccessPolicyReview
    ) -> (resolving: [SecretRef], restoring: [SecretRef])? {
        let resolving = review.credentials.flatMap(\.references)
        var restoring: [SecretRef] = []
        for row in review.restore?.rows ?? [] {
            for uri in row.references {
                guard let reference = try? SecretRef(uri) else { return nil }
                restoring.append(reference)
            }
        }
        return resolving.isEmpty && restoring.isEmpty ? nil : (resolving, restoring)
    }

    /// Why a review could not be frozen for the phone, as bounded, value-free
    /// counts and error codes.
    static func unmirrorableReason(_ review: AccessPolicyReview, error: Error) -> String {
        typealias V3 = RemoteApprovalProtocolV3
        let referenceCount = review.credentials.reduce(0) { $0 + $1.references.count }
        let rowCount = review.restore?.rows.count ?? 0
        if referenceCount > V3.maximumReferences {
            return "it names \(referenceCount) references and the phone review carries at most "
                + "\(V3.maximumReferences)"
        }
        if rowCount > V3.maximumRestoreRows {
            return "it reopens \(rowCount) approvals and the phone review carries at most "
                + "\(V3.maximumRestoreRows)"
        }
        if let validation = error as? RemoteApprovalValidationError {
            return "its phone review failed validation (\(validation))"
        }
        return "its phone review could not be built (\(type(of: error)))"
    }
}

private enum PolicyReviewRaceResult: Sendable {
    case local(AccessPolicyReviewOutcome)
    case remote(RemoteAccessReviewResult)
}

/// Converts the phone's already-verified, single-request signature into the
/// existing agent completion seam. It supplies no Mac Keychain context: its
/// unlock, when the review needed one, is the remote unlock the phone's answer
/// opened for this request alone. It can be consumed only once, and cancelling
/// it drops that unlock.
public actor RemoteApprovedAuthenticationSession: AccessPolicyAuthenticationSession {
    private var available = true
    private let unlock: CacheUnlock?

    public init(unlock: CacheUnlock? = nil) {
        self.unlock = unlock
    }

    public func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        guard available else { return .denied }
        available = false
        return .approved(unlock: unlock)
    }

    public func cancel() async {
        available = false
        unlock?.invalidate()
    }
}

public extension RemoteApprovalReview {
    /// Freeze every string the phone will render before either biometric path
    /// begins, from the same sanitized copy the Mac panel shows. The
    /// reference-set digest and the operation digest bind this presentation to
    /// the agent's immutable authorization transaction.
    ///
    /// The delegation note and the pairing line travel too, in a block only a
    /// declined Claude Code request carries. The line is never fitted: a
    /// line too long for the wire is left off, so the phone shows none and
    /// its approval cannot pair.
    ///
    /// Every string is sanitized first and then fitted to its wire bound with
    /// the ellipsis inside the budget (`ReviewDisplay.fitted`), so a long or
    /// multi-line command, caller, or provider note is shortened on the phone
    /// instead of failing validation. What can still fail is a review the
    /// phone format cannot hold at all, such as more than 64 references, or an
    /// automation enrollment or a Mac-only settings change, which never leave
    /// the Mac.
    ///
    /// `deadline` is when the Mac panel closes unanswered (the request's
    /// `HumanWait`), which the card shows as the panel does. A restore-only
    /// review has none.
    /// The deadline as the phone's copy can carry it, or none. The request
    /// refuses one more than a day after it was made
    /// (`RemoteApprovalProtocolV3.maximumDeadlineMilliseconds`), and it is
    /// made after this, so a later deadline is dropped here: the card then
    /// lacks only its line, where the refused request would never reach the
    /// phone at all.
    static func carried(
        _ deadline: ReviewDeadline?, nowMilliseconds: UInt64 = currentTimeMilliseconds()
    ) -> UInt64? {
        guard let closesAt = deadline?.unixMilliseconds else { return nil }
        let (latest, overflow) = nowMilliseconds.addingReportingOverflow(
            RemoteApprovalProtocolV3.maximumDeadlineMilliseconds)
        return overflow || closesAt <= latest ? closesAt : nil
    }

    init(accessPolicyReview review: AccessPolicyReview, deadline: ReviewDeadline? = nil) throws {
        typealias Limit = RemoteApprovalReview.FieldLimit
        guard review.automation == nil else { throw RemoteApprovalValidationError.inconsistentKind }
        if let change = review.settingsChange {
            try self.init(settingsChange: change, review: review, deadline: deadline)
            return
        }
        let kind: Kind = review.isRestoreOnly ? .restore : review.ssh != nil ? .ssh : .access
        let plan = review.plan

        let headline: String
        if kind == .restore, let restore = review.restore {
            headline = Self.required(restore.header, maxBytes: Limit.headline, placeholder: "csecd restarted")
        } else if let commandLine = review.commandLine {
            // The full redacted command, newlines kept as the Mac panel keeps
            // them; the phone shows it expandable.
            headline = Self.required(
                commandLine, maxBytes: Limit.headline, placeholder: "(no command)", allowNewlines: true
            )
        } else {
            headline = Self.required(review.reason, maxBytes: Limit.headline, placeholder: "(no reason given)")
        }
        // Under that reason, the requester's own command line, newlines kept
        // as the Mac panel keeps them.
        let requesterCommand = kind == .access
            ? review.requesterCommandLine.map {
                ReviewDisplay.fitted($0, maxBytes: Limit.requesterCommand, allowNewlines: true)
            }.flatMap { $0.isEmpty ? nil : $0 }
            : nil

        var scopeOptions: [ScopeOption] = []
        var defaultScopeID: String?
        var durationOptions: [String] = []
        var defaultDurationIndex: UInt16?
        if kind != .restore {
            // Exactly the choices the Mac panel offers, titled as its radio
            // buttons and lifetime menu title them.
            if let choices = review.scopeChoices {
                scopeOptions = choices.options.map { option in
                    ScopeOption(
                        id: option.id,
                        title: Self.required(
                            kind == .ssh ? ReviewDisplay.sshScopeTitle(option) : ReviewDisplay.scopeTitle(option),
                            maxBytes: Limit.choiceTitle, placeholder: option.kind.rawValue
                        ),
                        detail: Self.required(
                            kind == .ssh ? ReviewDisplay.sshScopeDetail(option) : ReviewDisplay.scopeDetail(option),
                            maxBytes: Limit.choiceDetail, placeholder: "pid \(option.pid)"
                        )
                    )
                }
                defaultScopeID = choices.defaultOption.id
            }
            if let choices = review.durationChoices {
                durationOptions = choices.options.map {
                    Self.required(
                        ReviewDisplay.durationTitle(for: $0), maxBytes: Limit.choiceTitle, placeholder: "Until it exits"
                    )
                }
                defaultDurationIndex = UInt16(clamping: choices.defaultIndex)
            }
        }

        let terminal = ReviewDisplay.fitted(review.caller.terminalSummary, maxBytes: Limit.terminalDescription)
        let restoreReferences = review.restore?.rows.flatMap(\.references) ?? []
        let delegation = kind == .restore ? nil : Self.delegation(for: review, scopeOptions: scopeOptions)
        self.init(
            kind: kind,
            headline: headline,
            callerDescription: Self.required(
                review.caller.description,
                maxBytes: Limit.callerDescription,
                placeholder: "(unidentified caller)"
            ),
            terminalDescription: terminal.isEmpty ? nil : terminal,
            secrets: review.credentials.flatMap(\.secrets).map(Self.secret(for:)),
            referenceSetDigest: Self.referenceSetDigest(
                review.credentials.flatMap(\.references).map(\.uri) + restoreReferences
            ),
            delivery: kind == .restore ? nil : Self.delivery(for: plan),
            // Every warning the Mac panel shows as a banner, csec's own copy,
            // whose paragraph break the phone keeps. Provider warnings travel
            // with their credential.
            warnings: [DeliveryReviewCopy.warning(for: review)].compactMap { $0 }.map {
                Self.required($0, maxBytes: Limit.warning, placeholder: "WARNING", allowNewlines: true)
            },
            footnote: DeliveryReviewCopy.footnote(for: review).map {
                Self.required($0, maxBytes: Limit.footnote, placeholder: "Approve only what you expect.")
            },
            ssh: kind == .ssh ? review.ssh.map(Self.ssh(for:)) : nil,
            restore: review.restore.map { Self.restore($0, mixed: kind != .restore) },
            scopeOptions: scopeOptions,
            defaultScopeID: defaultScopeID,
            durationOptions: durationOptions,
            defaultDurationIndex: defaultDurationIndex,
            delegation: delegation,
            requesterCommand: requesterCommand,
            closesAtMilliseconds: kind == .restore ? nil : Self.carried(deadline),
            operationDigest: kind == .restore
                ? Self.restoreOperationDigest(review.restore?.rows ?? [])
                : try Self.decodeSHA256(try plan.digest())
        )
        try validate()
    }

    /// A settings change the phone may decide: the panel's title as the
    /// headline, its lines and footnote, bound to the operation it names. It
    /// releases, opens and offers nothing.
    private init(
        settingsChange change: SettingsChangeReviewDetails, review: AccessPolicyReview, deadline: ReviewDeadline?
    ) throws {
        typealias Limit = RemoteApprovalReview.FieldLimit
        guard let operation = change.phoneOperationDigest, operation.count == SHA256.byteCount,
              review.credentials.isEmpty, review.restore == nil, review.ssh == nil else {
            throw RemoteApprovalValidationError.inconsistentKind
        }
        let terminal = ReviewDisplay.fitted(review.caller.terminalSummary, maxBytes: Limit.terminalDescription)
        self.init(
            kind: .settings,
            headline: Self.required(change.title, maxBytes: Limit.headline, placeholder: "Settings change"),
            callerDescription: Self.required(
                review.caller.description,
                maxBytes: Limit.callerDescription,
                placeholder: "(unidentified caller)"
            ),
            terminalDescription: terminal.isEmpty ? nil : terminal,
            secrets: [],
            referenceSetDigest: Self.referenceSetDigest([]),
            delivery: nil,
            warnings: [],
            footnote: Self.required(
                change.footnote, maxBytes: Limit.footnote, placeholder: "Approve only what you expect."
            ),
            settings: Settings(changes: change.changes.prefix(RemoteApprovalProtocolV3.maximumSettingsChanges).map {
                Self.required($0, maxBytes: Limit.settingsChange, placeholder: "(change)")
            }),
            closesAtMilliseconds: Self.carried(deadline),
            operationDigest: operation
        )
        try validate()
    }

    /// The decline note, fitted like any other note, and the pairing line
    /// with the scope option and lifetime index it applies at, or nil when
    /// the review carries neither.
    private static func delegation(for review: AccessPolicyReview, scopeOptions: [ScopeOption]) -> Delegation? {
        typealias Limit = RemoteApprovalReview.FieldLimit
        let note = review.delegationNote.map {
            required($0.panelText, maxBytes: Limit.delegationNote, placeholder: DelegationDecline.panelPrefix)
        }
        var pairing: Delegation.Pairing?
        if let offer = review.pairingOffer,
           let lifetime = review.durationChoices?.options.firstIndex(of: .processLifetime),
           scopeOptions.contains(where: { $0.id == offer.scopeOptionID }) {
            let line = ReviewDisplay.sanitized(offer.line)
            if !line.isEmpty, line.utf8.count <= Limit.pairingLine {
                pairing = Delegation.Pairing(
                    line: line, scopeID: offer.scopeOptionID, processLifetimeIndex: UInt16(clamping: lifetime)
                )
            }
        }
        guard note != nil || pairing != nil else { return nil }
        return Delegation(note: note, pairing: pairing)
    }

    /// One secret as the Mac draws it, fitted to the phone review's bounds.
    private static func secret(for secret: ReviewSecret) -> ReviewSecret {
        typealias Limit = RemoteApprovalReview.FieldLimit
        let fitted = secret.mapStrings { value, part in
            let limit: Int
            switch part {
            case .provider: limit = Limit.secretProvider
            case .account: limit = Limit.secretAccount
            case .container: limit = Limit.secretContainer
            case .item: limit = Limit.secretItem
            case .field: limit = Limit.secretField
            case .note, .warning: limit = Limit.secretNote
            }
            return ReviewDisplay.fitted(value, maxBytes: limit)
        }
        return ReviewSecret(
            provider: fitted.provider, tint: fitted.tint, account: fitted.account,
            container: fitted.container, item: fitted.item, field: fitted.field,
            itemIsIdentifier: fitted.itemIsIdentifier,
            notes: Array(fitted.notes.prefix(RemoteApprovalProtocolV3.maximumWarnings)),
            warnings: Array(fitted.warnings.prefix(RemoteApprovalProtocolV3.maximumWarnings))
        )
    }

    /// Who receives what, as the Mac panel's delivery details state it.
    private static func delivery(for plan: DeliveryPlan) -> Delivery {
        typealias Limit = RemoteApprovalReview.FieldLimit
        return Delivery(
            emitterName: required(
                URL(fileURLWithPath: plan.executable.canonicalPath).lastPathComponent,
                maxBytes: Limit.emitterName,
                placeholder: "(unnamed executable)"
            ),
            emitterPath: required(plan.executable.canonicalPath, maxBytes: Limit.emitterPath, placeholder: "(no path)"),
            emitterAssurance: required(
                ReviewDisplay.assurance(plan.executable.assurance),
                maxBytes: Limit.emitterAssurance,
                placeholder: "Unverified"
            ),
            recipientDescription: required(
                DeliveryReviewCopy.recipientDescription(for: plan),
                maxBytes: Limit.recipientDescription,
                placeholder: "planned executable consumer"
            ),
            deliveryDescription: required(
                "\(ReviewDisplay.mechanism(plan.mechanism)) · " + ReviewDisplay.scope(plan.descendantScope),
                maxBytes: Limit.deliveryDescription,
                placeholder: ReviewDisplay.mechanism(plan.mechanism)
            ),
            destinationDescription: required(
                ReviewDisplay.destination(plan.destination),
                maxBytes: Limit.destinationDescription,
                placeholder: "Unknown"
            )
        )
    }

    /// The SSH facts the signing layout shows. The names are display only; the
    /// server identity itself is bound by the delivery plan, so a fleet with
    /// more names than the wire carries shows the first sixteen.
    private static func ssh(for details: SSHAccessReviewDetails) -> SSH {
        ssh(
            hostNames: details.hostNames, hostContext: details.hostContext,
            remoteUser: details.remoteUser, keyLabel: details.keyLabel, keyAlgorithm: details.keyAlgorithm
        )
    }

    private static func ssh(
        hostNames: [String], hostContext: String, remoteUser: String, keyLabel: String, keyAlgorithm: String
    ) -> SSH {
        typealias Limit = RemoteApprovalReview.FieldLimit
        let names = hostNames.prefix(RemoteApprovalProtocolV3.maximumHostNames).map {
            required($0, maxBytes: Limit.hostName, placeholder: "(unnamed host)")
        }
        return SSH(
            hostNames: names,
            hostContext: required(hostContext, maxBytes: Limit.hostContext, placeholder: "known_hosts"),
            unknownHost: names.isEmpty,
            remoteUser: required(remoteUser, maxBytes: Limit.remoteUser, placeholder: "(unknown user)"),
            keyLabel: required(keyLabel, maxBytes: Limit.keyLabel, placeholder: "SSH key"),
            keyAlgorithm: required(keyAlgorithm, maxBytes: Limit.keyAlgorithm, placeholder: "SSH")
        )
    }

    /// The restore section as the Mac panel lists it. `mixed`: it rides on a
    /// release whose touch also approves something new, so its note is the
    /// mixed panel's.
    private static func restore(_ details: RestoreReviewDetails, mixed: Bool) -> Restore {
        typealias Limit = RemoteApprovalReview.FieldLimit
        return Restore(
            header: required(details.header, maxBytes: Limit.restoreHeader, placeholder: "csecd restarted"),
            footnote: required(
                mixed ? details.mixedFootnote : details.footnote,
                maxBytes: Limit.footnote,
                placeholder: "Reopens approvals you already made."
            ),
            storeCount: UInt16(clamping: details.storeCount),
            rows: details.rows.map { row in
                RestoreRow(
                    kind: row.kind.wireName,
                    title: required(row.title, maxBytes: Limit.restoreTitle, placeholder: "(approval)"),
                    detail: required(row.detail, maxBytes: Limit.restoreDetail, placeholder: "(no detail)"),
                    secrets: row.secrets.map(secret(for:)),
                    ssh: row.ssh.map {
                        ssh(
                            hostNames: $0.hostNames, hostContext: $0.hostContext,
                            remoteUser: $0.remoteUser, keyLabel: $0.keyLabel, keyAlgorithm: $0.keyAlgorithm
                        )
                    }
                )
            }
        )
    }

    /// What a restore-only approval does: reopen exactly these rows. SHA-256
    /// over a domain-separated, length-prefixed encoding of each row's kind,
    /// title, detail, sorted references and SSH facts.
    static func restoreOperationDigest(_ rows: [RestoreReviewRow]) -> Data {
        var bytes = Data()
        func field(_ value: Data) {
            let count = UInt32(value.count)
            bytes.append(contentsOf: [
                UInt8((count >> 24) & 0xff), UInt8((count >> 16) & 0xff),
                UInt8((count >> 8) & 0xff), UInt8(count & 0xff),
            ])
            bytes.append(value)
        }
        func field(_ value: String) { field(Data(value.utf8)) }
        field("csec.remote-approval.restore-operation.v1")
        field(String(rows.count))
        for row in rows {
            field(row.kind.wireName)
            field(row.title)
            field(row.detail)
            let references = row.references.sorted()
            field(String(references.count))
            for reference in references { field(reference) }
            if let ssh = row.ssh {
                field("ssh")
                field(String(ssh.hostNames.count))
                for name in ssh.hostNames { field(name) }
                field(ssh.hostTitle)
                field(ssh.remoteUser)
                field(ssh.keyLabel)
                field(ssh.keyAlgorithm)
            } else {
                field("no-ssh")
            }
        }
        return Data(SHA256.hash(data: bytes))
    }

    /// A field the phone format requires to be non-empty: sanitized, fitted,
    /// and never empty.
    private static func required(
        _ value: String, maxBytes: Int, placeholder: String, allowNewlines: Bool = false
    ) -> String {
        let fitted = ReviewDisplay.fitted(value, maxBytes: maxBytes, allowNewlines: allowNewlines)
        return fitted.isEmpty ? ReviewDisplay.fitted(placeholder, maxBytes: maxBytes) : fitted
    }

    private static func optional(_ value: String?, maxBytes: Int) -> String? {
        guard let value else { return nil }
        let fitted = ReviewDisplay.fitted(value, maxBytes: maxBytes)
        return fitted.isEmpty ? nil : fitted
    }

    /// Every canonical reference the review names, the release's and the
    /// restore rows', once each and in sorted order.
    private static func referenceSetDigest(_ references: [String]) -> Data {
        var bytes = Data("csec.remote-approval.references.v1".utf8)
        for reference in Set(references).sorted() {
            let value = Data(reference.utf8)
            let count = UInt32(value.count)
            bytes.append(UInt8((count >> 24) & 0xff))
            bytes.append(UInt8((count >> 16) & 0xff))
            bytes.append(UInt8((count >> 8) & 0xff))
            bytes.append(UInt8(count & 0xff))
            bytes.append(value)
        }
        return Data(SHA256.hash(data: bytes))
    }

    private static func decodeSHA256(_ value: String) throws -> Data {
        guard value.utf8.count == SHA256.byteCount * 2 else {
            throw RemoteApprovalValidationError.invalidDigest
        }
        var result = Data()
        result.reserveCapacity(SHA256.byteCount)
        var index = value.startIndex
        while index < value.endIndex {
            let end = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<end], radix: 16) else {
                throw RemoteApprovalValidationError.invalidDigest
            }
            result.append(byte)
            index = end
        }
        return result
    }
}

extension RestoreReviewRow.Kind {
    /// The row kind as the phone review names it.
    var wireName: String {
        switch self {
        case .secretGrant: return "secret_grant"
        case .sshGrant: return "ssh_grant"
        case .pairedProject: return "paired_project"
        }
    }
}
