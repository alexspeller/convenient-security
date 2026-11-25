import CryptoKit
import Foundation

/// Versioned, value-free remote approval protocol shared by the Mac agent and
/// the iPhone companion. CloudKit (or any future relay) is deliberately outside
/// this module: signatures, request binding, and replay state are the
/// authority.
///
/// v3 is the provider-neutral exchange. A request says which kind of approval
/// it is (secret access, SSH signing, sudo, reopening what a restarted csecd
/// had approved, or acknowledging a change to csec's settings) and carries
/// that kind's facts rather than folding them into
/// one reason line; it offers the same scope and lifetime choices as the Mac
/// panel, and the phone signs the one it selected; and it may carry a blinded
/// point (`RemoteUnlockCrypto`) that the phone answers with the key agreement
/// only its Face ID unlocks, which is how a phone approval opens cold storage.
///
/// There is still no request lifetime: a request is single-use because csecd
/// is still waiting on it, never because a clock has not run out. v3 changes
/// the signed bytes, the signing domains and the CloudKit record types, so a
/// v2 build and a v3 build never read each other's mailbox.
public enum RemoteApprovalProtocolV3 {
    /// Version of the signed request/response exchange.
    public static let version: UInt16 = 3
    /// Pairing v2 adds the phone's key-agreement key and the signed pairing
    /// confirmation.
    public static let pairingVersion: UInt16 = 2
    /// Tolerance for the two devices' clocks disagreeing. It binds messages to
    /// each other — a request may not come from the future, a decision may not
    /// predate the request it answers — and never bounds how long a wait lasts.
    public static let allowedClockSkewMilliseconds: UInt64 = 30_000
    public static let maximumReferences = 64
    public static let maximumWarnings = 8
    public static let maximumScopeOptions = 4
    public static let maximumDurationOptions = 8
    public static let maximumHostNames = 16
    public static let maximumRestoreRows = 64
    /// A settings review's lines: the Mac panel's six and its "and N more".
    public static let maximumSettingsChanges = 8
    /// The furthest a review's deadline may lie after its request was made:
    /// the longest wait a coding agent's request can be given
    /// (`CodingAgentApprovalWaitMinutes`, at most a day).
    public static let maximumDeadlineMilliseconds: UInt64 = 86_400_000
}

public enum RemoteApprovalValidationError: Error, Equatable, Sendable {
    case invalidVersion
    case invalidIdentifier
    case invalidTimestamp
    case fieldOutOfBounds
    case invalidDigest
    case invalidPublicKey
    case invalidSignature
    case wrongDevice
    case wrongRequest
    /// The decision names a request this process is not currently waiting on:
    /// never published, already answered, or withdrawn.
    case notPending
    case alreadyConsumed
    /// The review's facts do not match its kind (an SSH review without its
    /// SSH facts, a sudo review with credentials, …).
    case inconsistentKind
    /// An approval that selects a scope or lifetime the request did not offer,
    /// omits one it did, or selects one on a denial.
    case invalidSelection
    /// An unlock answer on a request that asked for none, a missing or
    /// malformed one on a request that did, or any answer on a denial.
    case invalidUnlockAnswer
}

/// Exact display model rendered on the phone, built from the same sanitized
/// strings as the Mac panel. The reference-set and operation digests bind the
/// display to the agent's immutable authorization input without transmitting
/// values.
public struct RemoteApprovalReview: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Equatable, Sendable, CaseIterable {
        /// Releasing secrets to a planned consumer (get, exec, file, FD,
        /// credential helper). May also carry a restore section.
        case access
        /// Signing one SSH authentication with a key csecd holds.
        case ssh
        /// One sudo authentication.
        case sudo
        /// Reopening what a restarted csecd had approved; approves nothing new.
        case restore
        /// Acknowledging a change to csec's own settings that csecd raised
        /// for a request: Claude Code hooks or auto-mode classifier rules
        /// added since the last acknowledgement. Releases, opens and grants
        /// nothing; the operation digest names exactly what it acknowledges.
        case settings
    }

    /// The UTF-8 byte bound `validate()` enforces on each string field. The
    /// Mac fits every string to these numbers before building a review, so a
    /// long value is shortened rather than rejected.
    public enum FieldLimit {
        public static let headline = 2_048
        public static let callerDescription = 1_024
        public static let terminalDescription = 512
        public static let secretProvider = 64
        public static let secretAccount = 256
        public static let secretContainer = 1_024
        /// An item, or a whole reference no provider described.
        public static let secretItem = 4_096
        public static let secretField = 1_024
        public static let secretNote = 1_024
        public static let emitterName = 512
        public static let emitterPath = 4_096
        public static let emitterAssurance = 128
        public static let recipientDescription = 1_024
        public static let deliveryDescription = 512
        public static let destinationDescription = 512
        public static let warning = 4_096
        public static let footnote = 1_024
        public static let hostName = 256
        public static let hostContext = 256
        public static let remoteUser = 64
        public static let keyLabel = 256
        public static let keyAlgorithm = 64
        public static let sudoCommand = 2_048
        public static let workingDirectory = 1_024
        public static let targetUser = 64
        public static let restoreHeader = 512
        public static let restoreTitle = 256
        public static let restoreDetail = 512
        public static let restoreKind = 32
        public static let choiceID = 128
        public static let choiceTitle = 256
        public static let choiceDetail = 1_024
        public static let delegationNote = 1_024
        /// Far longer than any pairing line the Mac draws (a fixed sentence
        /// around a 128-byte project name); the bound once also fit launcher
        /// script paths, and stays so a phone and a Mac of different builds
        /// agree on it. A longer line is not mirrored at all.
        public static let pairingLine = 4_096
        public static let requesterCommand = 2_048
        /// The Mac panel bounds each line to 640 bytes.
        public static let settingsChange = 1_024
    }

    /// Who receives what, for a release or a signature.
    public struct Delivery: Codable, Equatable, Sendable {
        public let emitterName: String
        public let emitterPath: String
        public let emitterAssurance: String
        public let recipientDescription: String
        public let deliveryDescription: String
        public let destinationDescription: String

        public init(
            emitterName: String,
            emitterPath: String,
            emitterAssurance: String,
            recipientDescription: String,
            deliveryDescription: String,
            destinationDescription: String
        ) {
            self.emitterName = emitterName
            self.emitterPath = emitterPath
            self.emitterAssurance = emitterAssurance
            self.recipientDescription = recipientDescription
            self.deliveryDescription = deliveryDescription
            self.destinationDescription = destinationDescription
        }
    }

    /// The facts an SSH signing review shows.
    public struct SSH: Codable, Equatable, Sendable {
        /// known_hosts names that match the server's verified host key; empty
        /// for an unknown host.
        public let hostNames: [String]
        public let hostContext: String
        public let unknownHost: Bool
        public let remoteUser: String
        public let keyLabel: String
        public let keyAlgorithm: String

        public init(
            hostNames: [String],
            hostContext: String,
            unknownHost: Bool,
            remoteUser: String,
            keyLabel: String,
            keyAlgorithm: String
        ) {
            self.hostNames = hostNames
            self.hostContext = hostContext
            self.unknownHost = unknownHost
            self.remoteUser = remoteUser
            self.keyLabel = keyLabel
            self.keyAlgorithm = keyAlgorithm
        }
    }

    /// The facts a sudo review shows.
    public struct Sudo: Codable, Equatable, Sendable {
        /// The submitted command, already passed through csec's redaction.
        public let command: String
        public let workingDirectory: String
        public let targetUser: String?

        public init(command: String, workingDirectory: String, targetUser: String?) {
            self.command = command
            self.workingDirectory = workingDirectory
            self.targetUser = targetUser
        }
    }

    /// One approval a restore reopens.
    public struct RestoreRow: Codable, Equatable, Sendable {
        /// `secret_grant`, `ssh_grant` or `paired_project`.
        public let kind: String
        public let title: String
        public let detail: String
        /// What the approval covers, drawn as the release's secrets are.
        public let secrets: [ReviewSecret]
        public let ssh: SSH?

        public init(kind: String, title: String, detail: String, secrets: [ReviewSecret], ssh: SSH?) {
            self.kind = kind
            self.title = title
            self.detail = detail
            self.secrets = secrets
            self.ssh = ssh
        }
    }

    /// The facts a settings review shows under its headline (the panel's
    /// title): what approving changes, one line each, as the Mac panel lists
    /// them. Its footnote is the review's.
    public struct Settings: Codable, Equatable, Sendable {
        public let changes: [String]

        public init(changes: [String]) {
            self.changes = changes
        }
    }

    public struct Restore: Codable, Equatable, Sendable {
        public let header: String
        public let footnote: String
        public let storeCount: UInt16
        public let rows: [RestoreRow]

        public init(header: String, footnote: String, storeCount: UInt16, rows: [RestoreRow]) {
            self.header = header
            self.footnote = footnote
            self.storeCount = storeCount
            self.rows = rows
        }
    }

    /// A grant root the reviewer may choose, as the Mac panel offers it.
    public struct ScopeOption: Codable, Equatable, Sendable {
        /// Stable within this request only; the Mac resolves it against the
        /// list it computed and re-verifies ancestry before use.
        public let id: String
        public let title: String
        public let detail: String

        public init(id: String, title: String, detail: String) {
            self.id = id
            self.title = title
            self.detail = detail
        }
    }

    /// Why Claude Code auto mode did not approve the request, and the line
    /// that says approving would also let auto mode use what it approves in
    /// the project (pair it). The
    /// line applies exactly while `pairing.scopeID` and the lifetime at
    /// `pairing.processLifetimeIndex` are selected (`pairingLineApplies`);
    /// a phone approval pairs only when it signed that it showed the line.
    /// A sudo review offers no scope or lifetime: its line's `scopeID` is
    /// empty and its index 0 (`Pairing.unscoped`), and it applies to the one
    /// approval there is.
    public struct Delegation: Codable, Equatable, Sendable {
        public struct Pairing: Codable, Equatable, Sendable {
            public let line: String
            public let scopeID: String
            public let processLifetimeIndex: UInt16

            public init(line: String, scopeID: String, processLifetimeIndex: UInt16) {
                self.line = line
                self.scopeID = scopeID
                self.processLifetimeIndex = processLifetimeIndex
            }

            /// The line of a review that offers no choice (a sudo review).
            public static func unscoped(line: String) -> Pairing {
                Pairing(line: line, scopeID: "", processLifetimeIndex: 0)
            }

            public var isUnscoped: Bool { scopeID.isEmpty }
        }

        /// "Auto mode didn't approve this: …"
        public let note: String?
        public let pairing: Pairing?

        public init(note: String?, pairing: Pairing?) {
            self.note = note
            self.pairing = pairing
        }
    }

    public let kind: Kind
    /// The one-line summary: the redacted command line when the request
    /// carries argv, otherwise the request's reason.
    public let headline: String
    public let callerDescription: String
    /// The terminal window and tab the request came from, as one bounded line.
    public let terminalDescription: String?
    /// The secrets the operation releases, as `ReviewSecretTree` draws them.
    public let secrets: [ReviewSecret]
    public let referenceSetDigest: Data
    /// Present for access and SSH; a sudo or restore-only review releases
    /// nothing to a consumer.
    public let delivery: Delivery?
    public let warnings: [String]
    /// The panel's footnote, e.g. that SSH receives only a signature.
    public let footnote: String?
    public let ssh: SSH?
    public let sudo: Sudo?
    public let restore: Restore?
    /// Present exactly on a settings review. Absent, the review signs exactly
    /// as before it existed.
    public let settings: Settings?
    /// Empty when the approval offers no scope choice.
    public let scopeOptions: [ScopeOption]
    public let defaultScopeID: String?
    /// Lifetime titles in the Mac's menu order; empty when none is offered.
    public let durationOptions: [String]
    public let defaultDurationIndex: UInt16?
    /// A Claude Code request delegated approvals declined: access, SSH and
    /// sudo. Absent, the review signs exactly as before it existed.
    public let delegation: Delegation?
    /// The requesting program's own command line, which csecd read from the
    /// kernel, shown under the headline when that headline is the reason the
    /// program wrote itself (a language client over `csec bridge`, a `csec
    /// get`). Access reviews only. Absent, the review signs exactly as before
    /// it existed.
    public let requesterCommand: String?
    /// When the Mac closes this review if nobody has answered, in Unix
    /// milliseconds on the Mac's clock: a coding agent's request when its
    /// wait lapses, the sudo review just before the PAM module's limit. The
    /// card shows it as the Mac panel does (`ReviewDeadlineText`). Display
    /// only: nothing on the phone refuses, hides or decides by it, and the
    /// request ends when the Mac withdraws it, as every other one does.
    /// Absent for a request that waits as long as it takes (a terminal's, a
    /// restore), which then signs exactly as before it existed.
    public let closesAtMilliseconds: UInt64?
    /// SHA-256 over the exact operation csecd will perform once approved: the
    /// delivery plan for access and SSH, the sudo request for sudo, the listed
    /// rows for a restore, the hooks and rules acknowledged for settings.
    public let operationDigest: Data

    public init(
        kind: Kind,
        headline: String,
        callerDescription: String,
        terminalDescription: String?,
        secrets: [ReviewSecret],
        referenceSetDigest: Data,
        delivery: Delivery?,
        warnings: [String],
        footnote: String?,
        ssh: SSH? = nil,
        sudo: Sudo? = nil,
        restore: Restore? = nil,
        settings: Settings? = nil,
        scopeOptions: [ScopeOption] = [],
        defaultScopeID: String? = nil,
        durationOptions: [String] = [],
        defaultDurationIndex: UInt16? = nil,
        delegation: Delegation? = nil,
        requesterCommand: String? = nil,
        closesAtMilliseconds: UInt64? = nil,
        operationDigest: Data
    ) {
        self.kind = kind
        self.headline = headline
        self.callerDescription = callerDescription
        self.terminalDescription = terminalDescription
        self.secrets = secrets
        self.referenceSetDigest = referenceSetDigest
        self.delivery = delivery
        self.warnings = warnings
        self.footnote = footnote
        self.ssh = ssh
        self.sudo = sudo
        self.restore = restore
        self.settings = settings
        self.scopeOptions = scopeOptions
        self.defaultScopeID = defaultScopeID
        self.durationOptions = durationOptions
        self.defaultDurationIndex = defaultDurationIndex
        self.delegation = delegation
        self.requesterCommand = requesterCommand
        self.closesAtMilliseconds = closesAtMilliseconds
        self.operationDigest = operationDigest
    }

    /// Whether the pairing line shows for this selection: the rule the phone
    /// card draws the line by and csecd accepts a phone's acknowledgement by.
    /// False when the review carries no pairing line.
    public func pairingLineApplies(scopeID: String?, durationIndex: UInt16?) -> Bool {
        guard let pairing = delegation?.pairing else { return false }
        if pairing.isUnscoped { return scopeID == nil && durationIndex == nil }
        return scopeID == pairing.scopeID && durationIndex == pairing.processLifetimeIndex
    }

    public func validate() throws {
        typealias Limit = FieldLimit
        typealias Protocol = RemoteApprovalProtocolV3
        guard bounded(headline, maximum: Limit.headline),
              bounded(callerDescription, maximum: Limit.callerDescription),
              boundedOptional(terminalDescription, maximum: Limit.terminalDescription),
              secrets.count <= Protocol.maximumReferences,
              referenceSetDigest.count == SHA256.byteCount,
              operationDigest.count == SHA256.byteCount,
              warnings.count <= Protocol.maximumWarnings,
              warnings.allSatisfy({ bounded($0, maximum: Limit.warning) }),
              boundedOptional(footnote, maximum: Limit.footnote),
              boundedOptional(requesterCommand, maximum: Limit.requesterCommand) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        try Self.validate(secrets)

        if let delivery {
            guard bounded(delivery.emitterName, maximum: Limit.emitterName),
                  bounded(delivery.emitterPath, maximum: Limit.emitterPath),
                  bounded(delivery.emitterAssurance, maximum: Limit.emitterAssurance),
                  bounded(delivery.recipientDescription, maximum: Limit.recipientDescription),
                  bounded(delivery.deliveryDescription, maximum: Limit.deliveryDescription),
                  bounded(delivery.destinationDescription, maximum: Limit.destinationDescription) else {
                throw RemoteApprovalValidationError.fieldOutOfBounds
            }
        }
        if let ssh { try Self.validate(ssh) }
        if let sudo {
            guard bounded(sudo.command, maximum: Limit.sudoCommand),
                  bounded(sudo.workingDirectory, maximum: Limit.workingDirectory),
                  boundedOptional(sudo.targetUser, maximum: Limit.targetUser) else {
                throw RemoteApprovalValidationError.fieldOutOfBounds
            }
        }
        if let restore {
            guard bounded(restore.header, maximum: Limit.restoreHeader),
                  bounded(restore.footnote, maximum: Limit.footnote),
                  !restore.rows.isEmpty,
                  restore.rows.count <= Protocol.maximumRestoreRows else {
                throw RemoteApprovalValidationError.fieldOutOfBounds
            }
            for row in restore.rows {
                guard bounded(row.kind, maximum: Limit.restoreKind),
                      bounded(row.title, maximum: Limit.restoreTitle),
                      bounded(row.detail, maximum: Limit.restoreDetail),
                      row.secrets.count <= Protocol.maximumReferences else {
                    throw RemoteApprovalValidationError.fieldOutOfBounds
                }
                try Self.validate(row.secrets)
                if let ssh = row.ssh { try Self.validate(ssh) }
            }
        }

        if let settings {
            guard !settings.changes.isEmpty,
                  settings.changes.count <= Protocol.maximumSettingsChanges,
                  settings.changes.allSatisfy({ bounded($0, maximum: Limit.settingsChange) }) else {
                throw RemoteApprovalValidationError.fieldOutOfBounds
            }
        }

        guard scopeOptions.count <= Protocol.maximumScopeOptions,
              scopeOptions.allSatisfy({
                  bounded($0.id, maximum: Limit.choiceID)
                      && bounded($0.title, maximum: Limit.choiceTitle)
                      && bounded($0.detail, maximum: Limit.choiceDetail)
              }),
              Set(scopeOptions.map(\.id)).count == scopeOptions.count,
              durationOptions.count <= Protocol.maximumDurationOptions,
              durationOptions.allSatisfy({ bounded($0, maximum: Limit.choiceTitle) }) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        if scopeOptions.isEmpty {
            guard defaultScopeID == nil else { throw RemoteApprovalValidationError.invalidSelection }
        } else {
            guard let defaultScopeID, scopeOptions.contains(where: { $0.id == defaultScopeID }) else {
                throw RemoteApprovalValidationError.invalidSelection
            }
        }
        if durationOptions.isEmpty {
            guard defaultDurationIndex == nil else { throw RemoteApprovalValidationError.invalidSelection }
        } else {
            guard let defaultDurationIndex, Int(defaultDurationIndex) < durationOptions.count else {
                throw RemoteApprovalValidationError.invalidSelection
            }
        }

        if let delegation {
            guard delegation.note != nil || delegation.pairing != nil,
                  boundedOptional(delegation.note, maximum: Limit.delegationNote) else {
                throw RemoteApprovalValidationError.fieldOutOfBounds
            }
            if let pairing = delegation.pairing, pairing.isUnscoped {
                // Only a review that offers no choice at all has an unscoped
                // line: it applies to the one approval there is.
                guard bounded(pairing.line, maximum: Limit.pairingLine) else {
                    throw RemoteApprovalValidationError.fieldOutOfBounds
                }
                guard pairing.processLifetimeIndex == 0, scopeOptions.isEmpty, durationOptions.isEmpty else {
                    throw RemoteApprovalValidationError.invalidSelection
                }
            } else if let pairing = delegation.pairing {
                guard bounded(pairing.line, maximum: Limit.pairingLine),
                      bounded(pairing.scopeID, maximum: Limit.choiceID) else {
                    throw RemoteApprovalValidationError.fieldOutOfBounds
                }
                guard scopeOptions.contains(where: { $0.id == pairing.scopeID }),
                      Int(pairing.processLifetimeIndex) < durationOptions.count else {
                    throw RemoteApprovalValidationError.invalidSelection
                }
            }
        }

        // Each kind carries exactly its own facts. Only a secret release, an
        // SSH signing or a sudo can carry a delegation block, and only a sudo
        // review's line is unscoped (it offers no scope or lifetime).
        let unscoped = delegation?.pairing?.isUnscoped == true
        guard delegation == nil || ((kind == .access || kind == .ssh) && !unscoped)
                || (kind == .sudo && (delegation?.pairing == nil || unscoped)) else {
            throw RemoteApprovalValidationError.inconsistentKind
        }
        // Only a secret release names a requester's own command line: SSH
        // and sudo name their command in their own facts, a restore none.
        guard requesterCommand == nil || kind == .access else {
            throw RemoteApprovalValidationError.inconsistentKind
        }
        // Only a settings review lists settings changes.
        guard (settings != nil) == (kind == .settings) else {
            throw RemoteApprovalValidationError.inconsistentKind
        }
        // A restore-only panel has no deadline: other waiters may still need
        // it after the one it shows has gone.
        guard closesAtMilliseconds == nil || kind != .restore else {
            throw RemoteApprovalValidationError.inconsistentKind
        }
        let consistent: Bool
        switch kind {
        case .access:
            consistent = !secrets.isEmpty && delivery != nil && ssh == nil && sudo == nil
        case .ssh:
            consistent = !secrets.isEmpty && delivery != nil && ssh != nil
                && sudo == nil && restore == nil
        case .sudo:
            consistent = secrets.isEmpty && delivery == nil && ssh == nil && sudo != nil
                && restore == nil && scopeOptions.isEmpty && durationOptions.isEmpty
        case .restore:
            consistent = secrets.isEmpty && delivery == nil && ssh == nil && sudo == nil
                && restore != nil && scopeOptions.isEmpty && durationOptions.isEmpty
        case .settings:
            // A change to csec's own settings releases nothing, offers no
            // choice and carries no delegation block: the panel draws none.
            consistent = secrets.isEmpty && delivery == nil && ssh == nil && sudo == nil
                && restore == nil && scopeOptions.isEmpty && durationOptions.isEmpty
                && delegation == nil && warnings.isEmpty
        }
        guard consistent else { throw RemoteApprovalValidationError.inconsistentKind }
    }

    private static func validate(_ secrets: [ReviewSecret]) throws {
        typealias Limit = FieldLimit
        for secret in secrets {
            guard boundedOptional(secret.provider, maximum: Limit.secretProvider),
                  boundedOptional(secret.account, maximum: Limit.secretAccount),
                  boundedOptional(secret.container, maximum: Limit.secretContainer),
                  bounded(secret.item, maximum: Limit.secretItem),
                  boundedOptional(secret.field, maximum: Limit.secretField),
                  secret.notes.count <= RemoteApprovalProtocolV3.maximumWarnings,
                  secret.warnings.count <= RemoteApprovalProtocolV3.maximumWarnings,
                  secret.notes.allSatisfy({ bounded($0, maximum: Limit.secretNote) }),
                  secret.warnings.allSatisfy({ bounded($0, maximum: Limit.secretNote) }) else {
                throw RemoteApprovalValidationError.fieldOutOfBounds
            }
        }
    }

    private static func validate(_ ssh: SSH) throws {
        typealias Limit = FieldLimit
        guard ssh.hostNames.count <= RemoteApprovalProtocolV3.maximumHostNames,
              ssh.hostNames.allSatisfy({ bounded($0, maximum: Limit.hostName) }),
              ssh.unknownHost == ssh.hostNames.isEmpty,
              bounded(ssh.hostContext, maximum: Limit.hostContext),
              bounded(ssh.remoteUser, maximum: Limit.remoteUser),
              bounded(ssh.keyLabel, maximum: Limit.keyLabel),
              bounded(ssh.keyAlgorithm, maximum: Limit.keyAlgorithm) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
    }

    fileprivate func appendCanonical(to encoder: inout CanonicalEncoder) throws {
        try validate()
        encoder.string(kind.rawValue)
        encoder.string(headline)
        encoder.string(callerDescription)
        encoder.optionalString(terminalDescription)
        encoder.array(secrets) { encoder, secret in Self.appendCanonical(secret, to: &encoder) }
        encoder.data(referenceSetDigest)
        encoder.optional(delivery) { encoder, delivery in
            encoder.string(delivery.emitterName)
            encoder.string(delivery.emitterPath)
            encoder.string(delivery.emitterAssurance)
            encoder.string(delivery.recipientDescription)
            encoder.string(delivery.deliveryDescription)
            encoder.string(delivery.destinationDescription)
        }
        encoder.strings(warnings)
        encoder.optionalString(footnote)
        encoder.optional(ssh) { encoder, ssh in Self.appendCanonical(ssh, to: &encoder) }
        encoder.optional(sudo) { encoder, sudo in
            encoder.string(sudo.command)
            encoder.string(sudo.workingDirectory)
            encoder.optionalString(sudo.targetUser)
        }
        encoder.optional(restore) { encoder, restore in
            encoder.string(restore.header)
            encoder.string(restore.footnote)
            encoder.uint16(restore.storeCount)
            encoder.array(restore.rows) { encoder, row in
                encoder.string(row.kind)
                encoder.string(row.title)
                encoder.string(row.detail)
                encoder.array(row.secrets) { encoder, secret in Self.appendCanonical(secret, to: &encoder) }
                encoder.optional(row.ssh) { encoder, ssh in Self.appendCanonical(ssh, to: &encoder) }
            }
        }
        encoder.array(scopeOptions) { encoder, option in
            encoder.string(option.id)
            encoder.string(option.title)
            encoder.string(option.detail)
        }
        encoder.optionalString(defaultScopeID)
        encoder.strings(durationOptions)
        encoder.optional(defaultDurationIndex) { encoder, index in encoder.uint16(index) }
        encoder.data(operationDigest)
        // Only when present, under the request's own domain
        // (`RemoteApprovalRequest.signingData`), so a review without it signs
        // exactly as it did before the block existed and an older phone app,
        // which cannot render the line, cannot verify (or approve) one with it.
        if let delegation {
            encoder.optionalString(delegation.note)
            encoder.optional(delegation.pairing) { encoder, pairing in
                encoder.string(pairing.line)
                encoder.string(pairing.scopeID)
                encoder.uint16(pairing.processLifetimeIndex)
            }
        }
        // The settings lines, by the same rule: a phone app that cannot
        // render them cannot verify a settings review.
        if let settings {
            encoder.strings(settings.changes)
        }
        // The same rule for the requester's command line: only when present,
        // under a domain that names it, so a phone app that cannot render it
        // cannot verify a review that carries it.
        if let requesterCommand {
            encoder.string(requesterCommand)
        }
        // And for the deadline, so a phone app that cannot show it cannot
        // verify a review that carries it.
        if let closesAtMilliseconds {
            encoder.uint64(closesAtMilliseconds)
        }
    }

    private static func appendCanonical(_ secret: ReviewSecret, to encoder: inout CanonicalEncoder) {
        encoder.optionalString(secret.provider)
        encoder.string(secret.tint.rawValue)
        encoder.optionalString(secret.account)
        encoder.optionalString(secret.container)
        encoder.string(secret.item)
        encoder.optionalString(secret.field)
        encoder.bool(secret.itemIsIdentifier)
        encoder.strings(secret.notes)
        encoder.strings(secret.warnings)
    }

    private static func appendCanonical(_ ssh: SSH, to encoder: inout CanonicalEncoder) {
        encoder.strings(ssh.hostNames)
        encoder.string(ssh.hostContext)
        encoder.bool(ssh.unknownHost)
        encoder.string(ssh.remoteUser)
        encoder.string(ssh.keyLabel)
        encoder.string(ssh.keyAlgorithm)
    }
}

/// The blinded point a request asks the phone to answer (`RemoteUnlockCrypto`),
/// and the enrollment it belongs to. Present only when the approved operation
/// needs cold storage opened.
public struct RemoteApprovalUnlockChallenge: Codable, Equatable, Sendable {
    public let enrollmentID: String
    /// B = r·E, compressed (33 bytes).
    public let blindedPoint: Data

    public init(enrollmentID: String, blindedPoint: Data) {
        self.enrollmentID = enrollmentID.lowercased()
        self.blindedPoint = blindedPoint
    }

    public func validate() throws {
        guard validUUID(enrollmentID) else { throw RemoteApprovalValidationError.invalidIdentifier }
        guard blindedPoint.count == 33,
              (try? P256.KeyAgreement.PublicKey(compressedRepresentation: blindedPoint)) != nil else {
            throw RemoteApprovalValidationError.invalidUnlockAnswer
        }
    }
}

public struct RemoteApprovalRequest: Codable, Equatable, Sendable {
    public let version: UInt16
    public let requestID: String
    public let macDeviceID: String
    public let macDeviceName: String
    public let createdAtMilliseconds: UInt64
    public let review: RemoteApprovalReview
    public let unlockChallenge: RemoteApprovalUnlockChallenge?

    public init(
        requestID: String = UUID().uuidString.lowercased(),
        macDeviceID: String,
        macDeviceName: String,
        createdAtMilliseconds: UInt64,
        review: RemoteApprovalReview,
        unlockChallenge: RemoteApprovalUnlockChallenge? = nil
    ) {
        self.version = RemoteApprovalProtocolV3.version
        self.requestID = requestID.lowercased()
        self.macDeviceID = macDeviceID.lowercased()
        self.macDeviceName = macDeviceName
        self.createdAtMilliseconds = createdAtMilliseconds
        self.review = review
        self.unlockChallenge = unlockChallenge
    }

    /// `nowMilliseconds` binds the request to this device's clock in one
    /// direction only: a prompt may not claim to come from the future. There is
    /// deliberately no upper bound on age — the Mac withdraws a request it is no
    /// longer waiting on, so an old record is a withdrawal failure to repair,
    /// never a decision a clock should make.
    public func validate(at nowMilliseconds: UInt64) throws {
        guard version == RemoteApprovalProtocolV3.version else {
            throw RemoteApprovalValidationError.invalidVersion
        }
        guard validUUID(requestID), validUUID(macDeviceID) else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard bounded(macDeviceName, maximum: 256) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        guard createdAtMilliseconds
            <= addingClamped(
                nowMilliseconds,
                RemoteApprovalProtocolV3.allowedClockSkewMilliseconds
            ) else {
            throw RemoteApprovalValidationError.invalidTimestamp
        }
        try review.validate()
        // A deadline is measured from the Mac's own clock, as the creation
        // time is, so it is bounded against that rather than this device's.
        // One already past is allowed: the line then says the review is
        // closing, until the Mac's withdrawal takes the card away.
        if let closesAt = review.closesAtMilliseconds {
            guard closesAt <= addingClamped(
                createdAtMilliseconds, RemoteApprovalProtocolV3.maximumDeadlineMilliseconds
            ) else {
                throw RemoteApprovalValidationError.fieldOutOfBounds
            }
        }
        // A settings review releases and opens nothing, so it never asks the
        // phone to open the unlock factor.
        guard unlockChallenge == nil || review.kind != .settings else {
            throw RemoteApprovalValidationError.inconsistentKind
        }
        try unlockChallenge?.validate()
    }

    /// The request domain for a review that carries a delegation block. A
    /// request signed with it cannot be passed off as one without the block
    /// by dropping the field, nor the other way round.
    public static let delegationSigningDomain = "csec.remote-approval.request.v3+delegation"
    /// The domain suffix for a review that carries the requester's command
    /// line, after `+delegation` when it carries both. Like the delegation
    /// domain, it keeps a request with the line from being passed off as one
    /// without it, or as one whose delegation block ends in its bytes.
    public static let requesterCommandDomainSuffix = "+command"
    /// The domain suffix for a settings review, which never also carries a
    /// delegation block or a requester's command line.
    public static let settingsDomainSuffix = "+settings"
    /// The domain suffix for a review that carries a deadline, last of all.
    public static let deadlineDomainSuffix = "+deadline"

    /// The domain `signingData` signs under for `review`.
    public static func signingDomain(for review: RemoteApprovalReview) -> String {
        var domain = review.delegation == nil ? "csec.remote-approval.request.v3" : delegationSigningDomain
        if review.settings != nil { domain += settingsDomainSuffix }
        if review.requesterCommand != nil { domain += requesterCommandDomainSuffix }
        if review.closesAtMilliseconds != nil { domain += deadlineDomainSuffix }
        return domain
    }

    public func signingData() throws -> Data {
        var encoder = CanonicalEncoder(domain: Self.signingDomain(for: review))
        encoder.uint16(version)
        encoder.string(requestID)
        encoder.string(macDeviceID)
        encoder.string(macDeviceName)
        encoder.uint64(createdAtMilliseconds)
        try review.appendCanonical(to: &encoder)
        encoder.optional(unlockChallenge) { encoder, challenge in
            encoder.string(challenge.enrollmentID)
            encoder.data(challenge.blindedPoint)
        }
        return encoder.data
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try signingData()))
    }
}

public struct SignedRemoteApprovalRequest: Codable, Equatable, Sendable {
    public let request: RemoteApprovalRequest
    /// ASN.1 DER representation of an ECDSA P-256 signature.
    public let signatureDER: Data

    public init(request: RemoteApprovalRequest, signatureDER: Data) {
        self.request = request
        self.signatureDER = signatureDER
    }

    public static func signed(
        _ request: RemoteApprovalRequest,
        by privateKey: P256.Signing.PrivateKey
    ) throws -> SignedRemoteApprovalRequest {
        let signature = try privateKey.signature(for: request.signingData())
        return SignedRemoteApprovalRequest(
            request: request,
            signatureDER: signature.derRepresentation
        )
    }

    public func verify(
        macPublicKeyX963: Data,
        at nowMilliseconds: UInt64
    ) throws {
        try request.validate(at: nowMilliseconds)
        try RemoteApprovalCrypto.verify(
            signatureDER: signatureDER,
            data: request.signingData(),
            publicKeyX963: macPublicKeyX963
        )
    }
}

public enum RemoteApprovalDecision: String, Codable, Equatable, Sendable {
    case approve
    case deny
}

public struct RemoteApprovalResponse: Codable, Equatable, Sendable {
    public let version: UInt16
    public let requestID: String
    public let requestDigest: Data
    public let phoneDeviceID: String
    public let decision: RemoteApprovalDecision
    public let decidedAtMilliseconds: UInt64
    /// The scope option the phone selected; set on an approval of a request
    /// that offered a choice, nil otherwise.
    public let selectedScopeID: String?
    /// The lifetime the phone selected, by the request's menu index.
    public let selectedDurationIndex: UInt16?
    /// x(p·B) for the request's blinded point: set on an approval of a request
    /// that carried one, nil otherwise.
    public let unlockAnswer: Data?
    /// The phone app's version, for the Mac's diagnostics.
    public let phoneAppVersion: String
    /// Whether the card showed the request's pairing line when the reader
    /// approved: set exactly on an approval of a request whose review carries
    /// one, nil otherwise. csecd pairs only on `true`, and accepts the answer
    /// only when it equals `pairingLineApplies` for the signed selection.
    public let pairingLineShown: Bool?

    public init(
        requestID: String,
        requestDigest: Data,
        phoneDeviceID: String,
        decision: RemoteApprovalDecision,
        decidedAtMilliseconds: UInt64,
        selectedScopeID: String? = nil,
        selectedDurationIndex: UInt16? = nil,
        unlockAnswer: Data? = nil,
        phoneAppVersion: String,
        pairingLineShown: Bool? = nil
    ) {
        self.version = RemoteApprovalProtocolV3.version
        self.requestID = requestID.lowercased()
        self.requestDigest = requestDigest
        self.phoneDeviceID = phoneDeviceID.lowercased()
        self.decision = decision
        self.decidedAtMilliseconds = decidedAtMilliseconds
        self.selectedScopeID = selectedScopeID
        self.selectedDurationIndex = selectedDurationIndex
        self.unlockAnswer = unlockAnswer
        self.phoneAppVersion = phoneAppVersion
        self.pairingLineShown = pairingLineShown
    }

    /// The response domain for an answer that carries `pairingLineShown`, so
    /// the field cannot be dropped or added without breaking the signature.
    public static let pairingLineSigningDomain = "csec.remote-approval.response.v3+pairing-line"

    public func signingData() throws -> Data {
        guard version == RemoteApprovalProtocolV3.version else {
            throw RemoteApprovalValidationError.invalidVersion
        }
        guard validUUID(requestID), validUUID(phoneDeviceID) else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard requestDigest.count == SHA256.byteCount else {
            throw RemoteApprovalValidationError.invalidDigest
        }
        guard boundedOptional(selectedScopeID, maximum: RemoteApprovalReview.FieldLimit.choiceID),
              unlockAnswer.map({ $0.count == RemoteUnlockCrypto.scalarBytes }) ?? true,
              bounded(phoneAppVersion, maximum: 64) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        var encoder = CanonicalEncoder(
            domain: pairingLineShown == nil ? "csec.remote-approval.response.v3" : Self.pairingLineSigningDomain
        )
        encoder.uint16(version)
        encoder.string(requestID)
        encoder.data(requestDigest)
        encoder.string(phoneDeviceID)
        encoder.string(decision.rawValue)
        encoder.uint64(decidedAtMilliseconds)
        encoder.optionalString(selectedScopeID)
        encoder.optional(selectedDurationIndex) { encoder, index in encoder.uint16(index) }
        encoder.optional(unlockAnswer) { encoder, answer in encoder.data(answer) }
        encoder.string(phoneAppVersion)
        if let pairingLineShown { encoder.bool(pairingLineShown) }
        return encoder.data
    }
}

/// What an accepted approval selected, exactly as the phone signed it and the
/// request offered it.
public struct RemoteApprovalSelection: Equatable, Sendable {
    public let scopeOptionID: String?
    public let durationIndex: Int?
    /// x(p·B), for `RemoteUnlockCrypto.openRemoteKey`.
    public let unlockAnswer: Data?
    /// The phone showed the request's pairing line when the reader approved,
    /// as it signed and as `pairingLineApplies` confirms for the selection.
    public let pairingLineShown: Bool

    public init(scopeOptionID: String?, durationIndex: Int?, unlockAnswer: Data?, pairingLineShown: Bool = false) {
        self.scopeOptionID = scopeOptionID
        self.durationIndex = durationIndex
        self.unlockAnswer = unlockAnswer
        self.pairingLineShown = pairingLineShown
    }
}

public struct SignedRemoteApprovalResponse: Codable, Equatable, Sendable {
    public let response: RemoteApprovalResponse
    /// ASN.1 DER representation of an ECDSA P-256 signature.
    public let signatureDER: Data

    public init(response: RemoteApprovalResponse, signatureDER: Data) {
        self.response = response
        self.signatureDER = signatureDER
    }

    public static func signed(
        _ response: RemoteApprovalResponse,
        by privateKey: P256.Signing.PrivateKey
    ) throws -> SignedRemoteApprovalResponse {
        let signature = try privateKey.signature(for: response.signingData())
        return SignedRemoteApprovalResponse(
            response: response,
            signatureDER: signature.derRepresentation
        )
    }

    /// Binds one decision to one request: same ID, same digest, the pinned
    /// phone, a decision not made before the request existed, a selection the
    /// request offered, an unlock answer exactly when it asked for one, and
    /// that phone's signature over exactly those bytes. There is no upper time
    /// bound — an answer an hour later is the answer, and the single-use
    /// guarantee comes from `RemoteApprovalRequester`'s pending table and
    /// consumed set, not from a clock.
    @discardableResult
    public func verify(
        for request: RemoteApprovalRequest,
        pinnedPhoneDeviceID: String,
        phonePublicKeyX963: Data
    ) throws -> RemoteApprovalSelection? {
        guard response.requestID == request.requestID,
              response.requestDigest == (try request.digest()) else {
            throw RemoteApprovalValidationError.wrongRequest
        }
        guard response.phoneDeviceID == pinnedPhoneDeviceID.lowercased() else {
            throw RemoteApprovalValidationError.wrongDevice
        }
        let lowerBound = subtractingClamped(
            request.createdAtMilliseconds,
            RemoteApprovalProtocolV3.allowedClockSkewMilliseconds
        )
        guard response.decidedAtMilliseconds >= lowerBound else {
            throw RemoteApprovalValidationError.invalidTimestamp
        }
        let selection = try Self.selection(response, for: request)
        try RemoteApprovalCrypto.verify(
            signatureDER: signatureDER,
            data: response.signingData(),
            publicKeyX963: phonePublicKeyX963
        )
        return selection
    }

    /// The approval's selection when it is exactly what the request allows;
    /// nil for a denial, which selects nothing.
    private static func selection(
        _ response: RemoteApprovalResponse,
        for request: RemoteApprovalRequest
    ) throws -> RemoteApprovalSelection? {
        let review = request.review
        switch response.decision {
        case .deny:
            guard response.selectedScopeID == nil, response.selectedDurationIndex == nil,
                  response.pairingLineShown == nil else {
                throw RemoteApprovalValidationError.invalidSelection
            }
            guard response.unlockAnswer == nil else {
                throw RemoteApprovalValidationError.invalidUnlockAnswer
            }
            return nil
        case .approve:
            if review.scopeOptions.isEmpty {
                guard response.selectedScopeID == nil else {
                    throw RemoteApprovalValidationError.invalidSelection
                }
            } else {
                guard let selected = response.selectedScopeID,
                      review.scopeOptions.contains(where: { $0.id == selected }) else {
                    throw RemoteApprovalValidationError.invalidSelection
                }
            }
            if review.durationOptions.isEmpty {
                guard response.selectedDurationIndex == nil else {
                    throw RemoteApprovalValidationError.invalidSelection
                }
            } else {
                guard let index = response.selectedDurationIndex,
                      Int(index) < review.durationOptions.count else {
                    throw RemoteApprovalValidationError.invalidSelection
                }
            }
            if request.unlockChallenge == nil {
                guard response.unlockAnswer == nil else {
                    throw RemoteApprovalValidationError.invalidUnlockAnswer
                }
            } else {
                guard let answer = response.unlockAnswer,
                      answer.count == RemoteUnlockCrypto.scalarBytes,
                      (try? RemoteUnlockCrypto.publicKey(x: answer)) != nil else {
                    throw RemoteApprovalValidationError.invalidUnlockAnswer
                }
            }
            // The acknowledgement is present exactly when the review carries a
            // pairing line, and says what the shared rule says for the signed
            // selection: a phone cannot claim a line it could not have shown,
            // nor approve one with the line without saying so.
            if review.delegation?.pairing == nil {
                guard response.pairingLineShown == nil else {
                    throw RemoteApprovalValidationError.invalidSelection
                }
            } else {
                guard let shown = response.pairingLineShown,
                      shown == review.pairingLineApplies(
                        scopeID: response.selectedScopeID, durationIndex: response.selectedDurationIndex
                      ) else {
                    throw RemoteApprovalValidationError.invalidSelection
                }
            }
            return RemoteApprovalSelection(
                scopeOptionID: response.selectedScopeID,
                durationIndex: response.selectedDurationIndex.map(Int.init),
                unlockAnswer: response.unlockAnswer,
                pairingLineShown: response.pairingLineShown == true
            )
        }
    }
}

public enum RemoteApprovalCrypto {
    public static func verify(
        signatureDER: Data,
        data: Data,
        publicKeyX963: Data
    ) throws {
        let publicKey: P256.Signing.PublicKey
        let signature: P256.Signing.ECDSASignature
        do {
            publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
        } catch {
            throw RemoteApprovalValidationError.invalidPublicKey
        }
        do {
            signature = try P256.Signing.ECDSASignature(derRepresentation: signatureDER)
        } catch {
            throw RemoteApprovalValidationError.invalidSignature
        }
        guard publicKey.isValidSignature(signature, for: data) else {
            throw RemoteApprovalValidationError.invalidSignature
        }
    }
}

/// Request-side key seam. The shipping Mac implementation uses a persistent
/// Secure Enclave key; tests can use a software P-256 key without changing the
/// requester or weakening production selection.
public protocol RemoteApprovalRequestSigner: Sendable {
    func publicKeyX963Representation() async throws -> Data
    func sign(_ data: Data) async throws -> Data
}

/// How a relay classifies a failed operation for a caller that is now waiting
/// indefinitely. A relay throws one of these when it knows which case applies;
/// every other error is treated as a transient blip and waited through, because
/// the local prompt is always live — the cost of waiting through a blip is one
/// more poll, while the cost of giving up is losing the phone surface for the
/// rest of a wait that no longer has a deadline.
public enum RemoteApprovalRelayFailure: Error, Equatable, Sendable {
    /// The relay refused this attempt and named when to try again. Waiting is
    /// the correct response; the request is untouched.
    case throttled(retryAfterNanoseconds: UInt64)
    /// A failure that retrying fixes — the network is not back yet after wake,
    /// a reply was lost, the account is briefly not ready — with no hint of
    /// when. The requester tries again after its ordinary poll interval.
    case transient
    /// This Mac cannot use the relay at all — no iCloud account, no
    /// entitlement, an incompatible or missing container. Polling cannot fix
    /// it, so the mirrored leg stops and the local prompt carries the request.
    case permanentlyUnavailable
    /// The record read does not decode (or is over its size bound): junk
    /// under that name. Reading again returns the same bytes, so the caller
    /// clears the name instead of waiting it out.
    case unreadableRecord
}

/// Value-free mailbox seam. Implementations must not infer authorization from
/// storage ownership or successful delivery; only the signed protocol does so.
///
/// Record names come from `RemoteApprovalMailboxName` and nowhere else. A
/// relay constructs no record ID from a string that name builder refused, so a
/// hostile mailbox record can never make it raise.
public protocol RemoteApprovalRelay: Sendable {
    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws
    /// Save a request this Mac is still waiting on again, so the mailbox's
    /// save time for it moves on (`RemoteApprovalLiveness`). The same signed
    /// envelope, overwriting whatever is under its name: a record deleted by
    /// anything but this Mac is put back while the Mac still waits.
    func refreshRequest(_ request: SignedRemoteApprovalRequest) async throws
    /// The one response record `phoneDeviceID` answers `requestID` in
    /// (`response-<requestID>-<phoneDeviceID>`). The Mac reads only its pinned
    /// phone's record, so nothing another writer leaves for the same request
    /// is read or stands in that phone's way.
    func response(
        for requestID: String,
        phoneDeviceID: String
    ) async throws -> SignedRemoteApprovalResponse?
    /// Delete the record `response(for:phoneDeviceID:)` returned after the Mac
    /// refused it, so the slot is free for the phone's real answer and the Mac
    /// does not read the same junk on every poll.
    func discardResponse(for requestID: String, phoneDeviceID: String) async
    /// The request records in the mailbox. A record whose name is not exactly
    /// `request-<payload requestID>` is dropped here: a signed request copied
    /// under another name is a replay, and a delete by the payload's ID would
    /// not remove the record that carried it.
    func pendingRequests() async throws -> [SignedRemoteApprovalRequest]
    /// Whether the Mac's request record is still in the mailbox. Deleting that
    /// record *is* the withdrawal marker, so a phone that has just collected a
    /// biometric can tell "the Mac stopped waiting" from "the Mac is still
    /// waiting". This is presentation only: the Mac's pending table decides
    /// whether a decision counts.
    func requestIsPending(requestID: String) async throws -> Bool
    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws
    /// Raise the phone's alert for a request already published
    /// (`alert-<requestID>`). It carries no request field: the phone reads and
    /// verifies the request itself. Publishing it again is not an error.
    func publishAlert(requestID: String, macDeviceID: String) async throws
    /// Delete the request record, its alert record and, when the answering
    /// phone is known, that phone's response record. A relay skips a name it
    /// cannot form, and a record already gone counts as deleted. Throws when
    /// any delete did not land, after trying every name, so the caller tries
    /// again (`RemoteApprovalCleanupQueue`).
    func deleteExchange(requestID: String, phoneDeviceID: String?) async throws
    /// The phone's signed confirmation that it pinned this Mac, if it has
    /// published one. Presentation of readiness only: every request is still
    /// verified on its own.
    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation?
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws
    /// The phone's latest signed status (app version, notifications), if any.
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus?
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws
    /// The Mac's offer to `phoneDeviceID` (`pairing-offer-<phoneDeviceID>`),
    /// replacing any earlier one. Convenience only: the phone verifies it,
    /// shows it and pins it under Face ID as it would a pasted Mac code.
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer?
    /// Delete the offer to `phoneDeviceID` if it is the one `macDeviceID`
    /// made, so withdrawing an old pairing's offer never removes a newer
    /// Mac's offer to the same phone. No offer, or another Mac's, is done;
    /// throws when the offer could not be read or deleted.
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async throws
}

extension RemoteApprovalRelay {
    /// A mailbox that keeps no save time has nothing for a refresh to move on.
    public func refreshRequest(_ request: SignedRemoteApprovalRequest) async throws {}
}

public struct RemoteApprovalRequesterConfiguration: Sendable, Equatable {
    public let macDeviceID: String
    public let macDeviceName: String
    public let pinnedPhoneDeviceID: String
    public let pinnedPhonePublicKeyX963: Data
    public let pollIntervalNanoseconds: UInt64
    /// How often a waiting request's record is saved again
    /// (`RemoteApprovalLiveness`). Never longer than the shared interval the
    /// phone's quiet threshold is set against; tests shorten it.
    public let refreshIntervalNanoseconds: UInt64

    public init(
        macDeviceID: String,
        macDeviceName: String,
        pinnedPhoneDeviceID: String,
        pinnedPhonePublicKeyX963: Data,
        pollIntervalNanoseconds: UInt64 = 750_000_000,
        refreshIntervalNanoseconds: UInt64 = RemoteApprovalLiveness.refreshIntervalNanoseconds
    ) {
        self.macDeviceID = macDeviceID.lowercased()
        self.macDeviceName = macDeviceName
        self.pinnedPhoneDeviceID = pinnedPhoneDeviceID.lowercased()
        self.pinnedPhonePublicKeyX963 = pinnedPhonePublicKeyX963
        self.pollIntervalNanoseconds = pollIntervalNanoseconds
        self.refreshIntervalNanoseconds = refreshIntervalNanoseconds
    }

    public func validate() throws {
        guard validUUID(macDeviceID), validUUID(pinnedPhoneDeviceID) else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard bounded(macDeviceName, maximum: 256),
              pollIntervalNanoseconds >= 50_000_000,
              pollIntervalNanoseconds <= 5_000_000_000,
              refreshIntervalNanoseconds >= 50_000_000,
              refreshIntervalNanoseconds <= RemoteApprovalLiveness.refreshIntervalNanoseconds else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        do {
            _ = try P256.Signing.PublicKey(x963Representation: pinnedPhonePublicKeyX963)
        } catch {
            throw RemoteApprovalValidationError.invalidPublicKey
        }
    }
}

public enum RemoteApprovalRequesterResult: Sendable, Equatable {
    /// Relay/configuration unavailable. The local prompt remains authoritative.
    case unavailable
    /// The pinned phone's verified Deny. `receivedAt` is when this Mac accepted
    /// it, taken before the request leaves the pending table and its mailbox
    /// record is deleted. It orders the Deny against the Mac's other requests
    /// and is never compared with the present.
    case denied(receivedAt: ContinuousClock.Instant)
    /// The pinned phone's verified approval, with exactly the scope, lifetime
    /// and unlock answer it signed.
    case approved(RemoteApprovalSelection)
}

/// Outcome of offering one signed phone decision to the requester's acceptance
/// gate. A rejection is never a denial: it means this process is not waiting on
/// that request, or the envelope did not bind to it.
public enum RemoteApprovalAcceptance: Equatable, Sendable {
    /// A verified decision. An approval carries its selection; a denial none.
    case accepted(RemoteApprovalDecision, RemoteApprovalSelection?)
    case rejected(RemoteApprovalValidationError)
}

/// Suspends until the paired phone should be alerted to a request this Mac has
/// just published, returning early when its task is cancelled. The request is
/// on the phone before the gate opens; only the notification waits. csecd's
/// gate holds it while the Mac's own prompt can still be answered at the Mac.
public typealias RemoteApprovalAlertGate = @Sendable () async -> Void

/// Publishes one signed prompt and polls for a signed response from the
/// explicitly pinned phone until it arrives or this leg is withdrawn. Once the
/// alert gate opens it also raises the phone's alert. It holds no reusable
/// approval capability.
///
/// Replay model, now that no request expires: a decision is accepted only for a
/// request that is **currently pending** here — published by this process and
/// still being waited on by the caller that published it — and each request ID
/// is consumed at most once. Withdrawal removes the request from that table
/// *before* its caller is answered and before the mailbox record is deleted, so
/// a decision that arrives after this process stopped waiting is refused:
/// `alreadyConsumed` if that request was the one already answered,
/// `notPending` otherwise.
///
/// The caller never waits on the relay once it stops waiting on the phone. Each
/// request's publish-and-poll loop runs in its own task, and the caller waits on
/// a continuation that `finish` resumes — for a decision, a withdrawal, a
/// cancelled caller, or a revoked pairing — so the local prompt winning costs one
/// actor hop, however slowly a save, a poll, or the mailbox delete returns.
public actor RemoteApprovalRequester {
    /// Consumed IDs are kept only to reject a duplicate delivery of a decision
    /// whose request is still pending. The pending table is the real bound, so
    /// this set never has to grow without limit.
    public static let maximumConsumedRequestIDs = 4_096
    /// A relay's own retry hint is honoured, but not without limit: a wait with
    /// no deadline must not be parked for hours by one server-supplied number
    /// while the user is looking at the phone.
    public static let maximumThrottleDelayNanoseconds: UInt64 = 60_000_000_000

    private let configuration: RemoteApprovalRequesterConfiguration
    private let signer: any RemoteApprovalRequestSigner
    private let relay: any RemoteApprovalRelay
    private let alertGate: RemoteApprovalAlertGate
    /// Where a mailbox delete or sweep that did not land is retried. csecd
    /// shares one across its requesters, so a replaced pairing's cleanup
    /// carries on after its requester is retired.
    private let cleanup: RemoteApprovalCleanupQueue
    /// How long a withdrawal's mailbox delete waits for the exchange's own
    /// relay call to return before deleting anyway (see `finish`).
    private let exchangeDrainNanoseconds: UInt64
    private var pendingRequests: [String: RemoteApprovalRequest] = [:]
    private var consumedRequestIDs: Set<String> = []
    /// The caller waiting on each pending request. `finish` removes and resumes
    /// it, so each is answered exactly once.
    private var waiters: [String: CheckedContinuation<RemoteApprovalRequesterResult, Never>] = [:]
    /// Each pending request's publish-then-poll loop.
    private var exchanges: [String: Task<Void, Never>] = [:]
    /// Set by `revokeAll()`: the pairing this requester speaks for was removed
    /// or replaced, so it never publishes again.
    private var revoked = false

    public init(
        configuration: RemoteApprovalRequesterConfiguration,
        signer: any RemoteApprovalRequestSigner,
        relay: any RemoteApprovalRelay,
        alertGate: @escaping RemoteApprovalAlertGate = {},
        cleanup: RemoteApprovalCleanupQueue = RemoteApprovalCleanupQueue(),
        exchangeDrainNanoseconds: UInt64 = RemoteApprovalBound.readNanoseconds
    ) throws {
        try configuration.validate()
        self.configuration = configuration
        self.signer = signer
        self.relay = relay
        self.alertGate = alertGate
        self.cleanup = cleanup
        self.exchangeDrainNanoseconds = exchangeDrainNanoseconds
    }

    public func requestApproval(
        for review: RemoteApprovalReview,
        unlockChallenge: RemoteApprovalUnlockChallenge? = nil,
        nowMilliseconds: UInt64 = currentTimeMilliseconds()
    ) async -> RemoteApprovalRequesterResult {
        guard !revoked else { return .unavailable }
        let envelope: SignedRemoteApprovalRequest
        do {
            envelope = try await signedRequest(
                for: review,
                unlockChallenge: unlockChallenge,
                nowMilliseconds: nowMilliseconds
            )
        } catch {
            return .unavailable
        }
        // Signing suspended this actor. The pairing may have been revoked, or
        // the caller may have gone, meanwhile; neither may publish.
        guard !revoked, !Task.isCancelled else { return .unavailable }
        let requestID = envelope.request.requestID
        // Pending before published, and so withdrawn even when the save fails:
        // the transport may commit the save and still return an error here.
        pendingRequests[requestID] = envelope.request
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard pendingRequests[requestID] != nil else {
                    continuation.resume(returning: .unavailable)
                    return
                }
                waiters[requestID] = continuation
                exchanges[requestID] = Task { await self.exchange(envelope) }
            }
        } onCancel: {
            // The requesting client went away or the local prompt won: stop
            // waiting now, without waiting for the relay.
            Task { await self.withdraw(requestID: requestID) }
        }
    }

    /// The single gate a phone decision passes through. Public because it *is*
    /// the replay model: single use, then still pending, then the signature
    /// binding this exact response to this exact request.
    public func accept(
        _ envelope: SignedRemoteApprovalResponse
    ) -> RemoteApprovalAcceptance {
        guard !consumedRequestIDs.contains(envelope.response.requestID) else {
            return .rejected(.alreadyConsumed)
        }
        guard let request = pendingRequests[envelope.response.requestID] else {
            return .rejected(.notPending)
        }
        let selection: RemoteApprovalSelection?
        do {
            selection = try envelope.verify(
                for: request,
                pinnedPhoneDeviceID: configuration.pinnedPhoneDeviceID,
                phonePublicKeyX963: configuration.pinnedPhonePublicKeyX963
            )
        } catch let error as RemoteApprovalValidationError {
            return .rejected(error)
        } catch {
            return .rejected(.invalidSignature)
        }
        if consumedRequestIDs.count >= Self.maximumConsumedRequestIDs {
            consumedRequestIDs.removeAll(keepingCapacity: true)
        }
        consumedRequestIDs.insert(request.requestID)
        return .accepted(envelope.response.decision, selection)
    }

    /// Whether this process is still waiting on a decision for `requestID`.
    public func isPending(requestID: String) -> Bool {
        pendingRequests[requestID.lowercased()] != nil
    }

    /// Stop waiting on `requestID`, if this process still is, and take its
    /// prompt off the phone. Its caller gets `.unavailable`.
    public func withdraw(requestID: String) {
        finish(requestID.lowercased(), with: .unavailable)
    }

    /// End every wait this requester has open, for good: the pairing it speaks
    /// for was removed or replaced. Each pending request leaves the table at
    /// once, so a phone decision for it is `notPending`; its caller gets
    /// `.unavailable`, so the local prompt alone carries it; and its mailbox
    /// record is deleted in the background. Nothing is published afterwards.
    public func revokeAll() {
        revoked = true
        for requestID in Set(pendingRequests.keys).union(waiters.keys) {
            finish(requestID, with: .unavailable)
        }
    }

    /// Remove every mailbox record this Mac left behind and is not waiting on.
    /// csecd runs this at startup: a crash or restart must not leave an
    /// approvable prompt on a phone with nothing listening for the answer, and
    /// a stale Approve button is exactly the blind-approval training the design
    /// ethos rejects.
    ///
    /// The mailbox is writable by more than this Mac, so a record is withdrawn
    /// only when it is provably this Mac's: see `isWithdrawable`. A sweep that
    /// could not list the mailbox, or delete everything it found, is tried
    /// again until one pass completes.
    public func withdrawStaleRequests() async {
        await cleanup.run("stale-requests-\(configuration.macDeviceID)") {
            await self.sweepStaleRequests()
        }
    }

    /// One pass of `withdrawStaleRequests`; true when it listed the mailbox
    /// and deleted every stale exchange it found.
    private func sweepStaleRequests() async -> Bool {
        guard let macPublicKey = try? await signer.publicKeyX963Representation(),
              let envelopes = try? await relay.pendingRequests() else { return false }
        var complete = true
        for envelope in envelopes
        where Self.isWithdrawable(
            envelope,
            macDeviceID: configuration.macDeviceID,
            macPublicKeyX963: macPublicKey
        ) {
            // Checked per record, after every suspension: a request this
            // process started waiting on meanwhile is not stale.
            guard pendingRequests[envelope.request.requestID] == nil else { continue }
            do {
                try await relay.deleteExchange(
                    requestID: envelope.request.requestID,
                    phoneDeviceID: configuration.pinnedPhoneDeviceID
                )
            } catch {
                complete = false
            }
        }
        return complete
    }

    /// Remove every mailbox record a *previous* pairing of this Mac left behind.
    /// Pairing again mints a new Mac device ID and the startup sweep covers only
    /// the current one, so the replaced pairing's prompts would otherwise stay
    /// on the phone with no key left to answer them.
    ///
    /// `macPublicKeyX963` is the retired pairing's Mac key and `phoneDeviceID`
    /// its phone, each nil when the retired record could not be read far
    /// enough to know them. Without the key a record is withdrawn on its name
    /// alone (`isWithdrawable`); without the phone only the request record is
    /// deleted, which is what takes the prompt off the phone. Returns true
    /// when it listed the mailbox and deleted every exchange it found, so a
    /// caller retries an incomplete pass (`RemoteApprovalCleanupQueue`).
    @discardableResult
    public static func withdrawRequests(
        fromMacDeviceID macDeviceID: String,
        macPublicKeyX963: Data?,
        phoneDeviceID: String?,
        relay: any RemoteApprovalRelay
    ) async -> Bool {
        guard let envelopes = try? await relay.pendingRequests() else { return false }
        let target = macDeviceID.lowercased()
        var complete = true
        for envelope in envelopes
        where isWithdrawable(envelope, macDeviceID: target, macPublicKeyX963: macPublicKeyX963) {
            do {
                try await relay.deleteExchange(
                    requestID: envelope.request.requestID,
                    phoneDeviceID: phoneDeviceID?.lowercased()
                )
            } catch {
                complete = false
            }
        }
        return complete
    }

    /// Whether a sweep may delete the exchange `envelope` came from: its
    /// request ID is a canonical lowercase UUID (so the record name a delete
    /// forms is the one the relay listed it under — the relay drops any record
    /// whose name is not `request-<requestID>`), it names `macDeviceID`, and,
    /// when the Mac's key is known, that key signed it. A record anything else
    /// wrote is left alone: a sweep never acts on what an unauthenticated
    /// mailbox writer claims.
    public static func isWithdrawable(
        _ envelope: SignedRemoteApprovalRequest,
        macDeviceID: String,
        macPublicKeyX963: Data?
    ) -> Bool {
        let request = envelope.request
        guard RemoteApprovalMailboxName.isCanonicalID(request.requestID),
              request.macDeviceID == macDeviceID.lowercased() else { return false }
        guard let macPublicKeyX963 else { return true }
        do {
            // No clock bound: a record's age or a skewed creation time never
            // decides whether this Mac may clear what it published.
            try envelope.verify(macPublicKeyX963: macPublicKeyX963, at: .max)
            return true
        } catch {
            return false
        }
    }

    private func signedRequest(
        for review: RemoteApprovalReview,
        unlockChallenge: RemoteApprovalUnlockChallenge?,
        nowMilliseconds: UInt64
    ) async throws -> SignedRemoteApprovalRequest {
        try configuration.validate()
        try review.validate()
        let publicKey = try await signer.publicKeyX963Representation()
        _ = try P256.Signing.PublicKey(x963Representation: publicKey)

        let request = RemoteApprovalRequest(
            macDeviceID: configuration.macDeviceID,
            macDeviceName: configuration.macDeviceName,
            createdAtMilliseconds: nowMilliseconds,
            review: review,
            unlockChallenge: unlockChallenge
        )
        try request.validate(at: nowMilliseconds)
        let signature = try await signer.sign(request.signingData())
        // Catch a corrupted or mismatched persistent signer before putting an
        // unverifiable prompt in the relay.
        try RemoteApprovalCrypto.verify(
            signatureDER: signature,
            data: request.signingData(),
            publicKeyX963: publicKey
        )
        return SignedRemoteApprovalRequest(request: request, signatureDER: signature)
    }

    /// Offer the prompt, then wait for the pinned phone's answer while raising
    /// its alert once the gate opens. This runs apart from the caller's task,
    /// so nothing the relay does — a slow save, a poll that ignores
    /// cancellation — holds the caller once it stops waiting.
    ///
    /// The alert leg and the refresh leg are children of this task: an answer
    /// from either surface, a withdrawal or a revoked pairing cancels them, so
    /// a request decided before the gate opens never alerts the phone.
    /// `finish` deletes the mailbox only after this task has returned, so an
    /// alert or refresh save in flight cannot land after the delete and
    /// outlive its request.
    private func exchange(_ envelope: SignedRemoteApprovalRequest) async {
        let requestID = envelope.request.requestID
        guard await publish(envelope) else {
            finish(requestID, with: .unavailable)
            return
        }
        let result = await withTaskGroup(of: RemoteApprovalRequesterResult?.self) { group in
            group.addTask {
                await self.raiseAlert(for: envelope.request)
                return nil
            }
            group.addTask {
                await self.keepRequestFresh(envelope)
                return nil
            }
            group.addTask {
                await self.waitForResponse(to: envelope.request)
            }
            var answer = RemoteApprovalRequesterResult.unavailable
            while let next = await group.next() {
                if let next {
                    answer = next
                    group.cancelAll()
                }
            }
            return answer
        }
        finish(requestID, with: result)
    }

    /// Raise the phone's alert once the gate opens, while the request is still
    /// waited on. It retries through what publishing the request retries
    /// through; a relay this Mac cannot use leaves the request on the phone
    /// without an alert, and the local prompt as it was.
    private func raiseAlert(for request: RemoteApprovalRequest) async {
        await alertGate()
        let requestID = request.requestID
        while isWaiting(on: requestID) {
            var delay = configuration.pollIntervalNanoseconds
            do {
                try await relay.publishAlert(requestID: requestID, macDeviceID: request.macDeviceID)
                return
            } catch RemoteApprovalRelayFailure.permanentlyUnavailable {
                return
            } catch let RemoteApprovalRelayFailure.throttled(retryAfterNanoseconds) {
                delay = throttleDelay(retryAfterNanoseconds)
            } catch {
                // `.transient` or unclassified: retry on the poll interval.
            }
            do {
                try await Task.sleep(nanoseconds: delay)
            } catch {
                return
            }
        }
    }

    /// Save the published request again every refresh interval while it is
    /// waited on, so the phone can tell this Mac is still there
    /// (`RemoteApprovalLiveness`). A save that fails is tried again on the
    /// poll interval, or after a throttle's delay; a relay this Mac cannot use
    /// ends only this leg; the response poll decides what that means for the
    /// wait. While the Mac sleeps nothing is saved, and the next save comes
    /// within an interval of waking.
    private func keepRequestFresh(_ envelope: SignedRemoteApprovalRequest) async {
        let requestID = envelope.request.requestID
        var delay = configuration.refreshIntervalNanoseconds
        while true {
            do {
                try await Task.sleep(nanoseconds: delay)
            } catch {
                return
            }
            guard isWaiting(on: requestID) else { return }
            delay = configuration.refreshIntervalNanoseconds
            do {
                try await relay.refreshRequest(envelope)
            } catch RemoteApprovalRelayFailure.permanentlyUnavailable {
                return
            } catch let RemoteApprovalRelayFailure.throttled(retryAfterNanoseconds) {
                delay = throttleDelay(retryAfterNanoseconds)
            } catch {
                // `.transient` or unclassified: try again soon rather than a
                // whole interval later, so one blip does not cost a refresh.
                delay = configuration.pollIntervalNanoseconds
            }
        }
    }

    /// Stop waiting on `requestID` and answer its caller. The order is the
    /// guarantee: the table entry goes first, so any decision offered after
    /// this is refused; the caller is answered next, before any relay IO; the
    /// mailbox delete runs last, in the background, once a save still in
    /// flight has landed, so the delete cannot run ahead of the record it
    /// removes, and is retried until it lands. A relay call that never
    /// returns must not keep the prompt on the phone, so past
    /// `exchangeDrainNanoseconds` the delete runs anyway, and again once that
    /// call does return, for a save that landed after the first delete. A
    /// second call for the same request does nothing.
    private func finish(_ requestID: String, with result: RemoteApprovalRequesterResult) {
        let wasPending = pendingRequests.removeValue(forKey: requestID) != nil
        let exchange = exchanges.removeValue(forKey: requestID)
        exchange?.cancel()
        let waiter = waiters.removeValue(forKey: requestID)
        if wasPending || waiter != nil {
            let relay = self.relay
            let cleanup = self.cleanup
            let phoneDeviceID = configuration.pinnedPhoneDeviceID
            let drainBound = exchangeDrainNanoseconds
            Task.detached(priority: .utility) {
                let delete: RemoteApprovalCleanupQueue.Job = {
                    (try? await relay.deleteExchange(requestID: requestID, phoneDeviceID: phoneDeviceID)) != nil
                }
                let drained = await RemoteApprovalBound.firstAnswer(within: drainBound, otherwise: false) {
                    await exchange?.value
                    return true
                }
                await cleanup.run("exchange-\(requestID)", delete)
                guard !drained, let exchange else { return }
                await exchange.value
                await cleanup.run("exchange-\(requestID)", delete)
            }
        }
        waiter?.resume(returning: result)
    }

    private func isWaiting(on requestID: String) -> Bool {
        !Task.isCancelled && pendingRequests[requestID] != nil
    }

    /// Keep offering the prompt until the relay takes it. What polling waits
    /// through is waited through here too — throttling, a network that is not
    /// back yet after wake, anything the relay did not classify — because
    /// giving up would lose the phone for the whole of a wait with no deadline.
    /// Only a relay this Mac cannot use at all, or the end of the wait, stops
    /// it. Returns whether the prompt was published while still wanted.
    private func publish(_ envelope: SignedRemoteApprovalRequest) async -> Bool {
        let requestID = envelope.request.requestID
        while isWaiting(on: requestID) {
            var delay = configuration.pollIntervalNanoseconds
            do {
                try await relay.publishRequest(envelope)
                // The relay is reachable: cleanup waiting out a failure can
                // stop waiting.
                await cleanup.retryNow()
                return isWaiting(on: requestID)
            } catch RemoteApprovalRelayFailure.permanentlyUnavailable {
                return false
            } catch let RemoteApprovalRelayFailure.throttled(retryAfterNanoseconds) {
                delay = throttleDelay(retryAfterNanoseconds)
            } catch {
                // `.transient` or unclassified: a blip, not a verdict on the
                // relay. The local prompt is live meanwhile.
            }
            do {
                try await Task.sleep(nanoseconds: delay)
            } catch {
                return false
            }
        }
        return false
    }

    private func waitForResponse(
        to request: RemoteApprovalRequest
    ) async -> RemoteApprovalRequesterResult {
        while isWaiting(on: request.requestID) {
            var delay = configuration.pollIntervalNanoseconds
            do {
                if let envelope = try await relay.response(
                    for: request.requestID,
                    phoneDeviceID: configuration.pinnedPhoneDeviceID
                ) {
                    // A decision that arrives after this request stopped being
                    // waited on — the local prompt won, the caller went, the
                    // pairing was revoked — is not this leg's to apply;
                    // `accept` refuses it as no longer pending. A record in
                    // this request's slot that answers a *different* request
                    // is refused before `accept` sees it: `accept` would bind
                    // it to that other request, and this wait must never end
                    // on a decision made about something else.
                    let acceptance = envelope.response.requestID == request.requestID
                        ? accept(envelope)
                        : .rejected(.wrongRequest)
                    switch acceptance {
                    case let .accepted(decision, selection):
                        // Before the withdrawal `finish` runs next: a Deny is
                        // ordered by when it arrived, not by when this returns.
                        let receivedAt = ContinuousClock.now
                        if decision == .approve, let selection {
                            return .approved(selection)
                        }
                        return .denied(receivedAt: receivedAt)
                    case .rejected(.notPending), .rejected(.alreadyConsumed):
                        // This wait already ended; `finish` deletes the
                        // exchange, response record included.
                        break
                    case .rejected:
                        // An unbindable record in the pinned phone's slot is
                        // not an authorization and not a denial: keep both
                        // prompts live, and clear the slot so the phone's real
                        // answer can land there and the next poll does not
                        // read the same record again.
                        await relay.discardResponse(
                            for: request.requestID,
                            phoneDeviceID: configuration.pinnedPhoneDeviceID
                        )
                    }
                }
            } catch RemoteApprovalRelayFailure.permanentlyUnavailable {
                return .unavailable
            } catch let RemoteApprovalRelayFailure.throttled(retryAfterNanoseconds) {
                delay = throttleDelay(retryAfterNanoseconds)
            } catch RemoteApprovalRelayFailure.unreadableRecord {
                // Junk in the pinned phone's slot is no decision, and reading
                // it again returns the same bytes: clear it so the phone's real
                // answer can land there.
                await relay.discardResponse(
                    for: request.requestID,
                    phoneDeviceID: configuration.pinnedPhoneDeviceID
                )
            } catch {
                // `.transient` or unclassified transport trouble is a blip, not
                // a decision: the user may still be walking back to their phone.
            }
            do {
                try await Task.sleep(nanoseconds: delay)
            } catch {
                return .unavailable
            }
        }
        return .unavailable
    }

    private func throttleDelay(_ requested: UInt64) -> UInt64 {
        min(
            max(requested, configuration.pollIntervalNanoseconds),
            Self.maximumThrottleDelayNanoseconds
        )
    }
}

public func currentTimeMilliseconds(_ date: Date = Date()) -> UInt64 {
    let milliseconds = date.timeIntervalSince1970 * 1_000
    guard milliseconds.isFinite, milliseconds > 0 else { return 0 }
    return UInt64(milliseconds.rounded(.down))
}

struct CanonicalEncoder {
    private(set) var data: Data

    init(domain: String) {
        data = Data()
        string(domain)
    }

    mutating func uint16(_ value: UInt16) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    mutating func uint32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    mutating func uint64(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8((value >> UInt64(shift)) & 0xff))
        }
    }

    mutating func string(_ value: String) {
        let bytes = Data(value.utf8)
        uint32(UInt32(bytes.count))
        data.append(bytes)
    }

    mutating func optionalString(_ value: String?) {
        data.append(value == nil ? 0 : 1)
        if let value { string(value) }
    }

    mutating func bool(_ value: Bool) {
        data.append(value ? 1 : 0)
    }

    mutating func optional<T>(
        _ value: T?,
        encode: (inout CanonicalEncoder, T) -> Void
    ) {
        data.append(value == nil ? 0 : 1)
        if let value { encode(&self, value) }
    }

    mutating func data(_ value: Data) {
        uint32(UInt32(value.count))
        data.append(value)
    }

    mutating func strings(_ values: [String]) {
        array(values) { encoder, value in encoder.string(value) }
    }

    mutating func array<T>(
        _ values: [T],
        encode: (inout CanonicalEncoder, T) -> Void
    ) {
        uint32(UInt32(values.count))
        for value in values { encode(&self, value) }
    }
}

func validUUID(_ value: String) -> Bool {
    UUID(uuidString: value) != nil && value.utf8.count == 36
}

func bounded(_ value: String, maximum: Int) -> Bool {
    !value.isEmpty && value.utf8.count <= maximum && !value.utf8.contains(0)
}

func boundedOptional(_ value: String?, maximum: Int) -> Bool {
    guard let value else { return true }
    return bounded(value, maximum: maximum)
}

private func addingClamped(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let (value, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow ? UInt64.max : value
}

private func subtractingClamped(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    lhs >= rhs ? lhs - rhs : 0
}
