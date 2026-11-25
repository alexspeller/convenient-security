import Foundation

// `csec edit --remove`: deleting whole-file values from csec's native store.
// A whole-file value (what `csec protect` and `csec protect --ssh` import) has
// no editor of its own, and a failed import or a retired SSH key can leave one
// behind that nothing uses. Deleting is setup at this Mac, so it takes one
// Touch ID in csecd's settings panel, which names every value it deletes, and
// it releases nothing.
//
// csecd refuses a value one of its own registrations still uses (the SSH
// agent, the GitHub socket, an automation job), and a value whose sidecar is
// still where the file was protected from. It cannot see every `.csec`
// sidecar or env-file reference on disk: a copy elsewhere stops resolving.

public struct NativeStoreRemovalRequest: Codable, Sendable {
    /// The settings panel shows one change per line; capping a removal at its
    /// line count means the panel names every value the touch deletes.
    public static let maximumReferences = SettingsChangeReviewDetails.maximumChanges

    public let requestID: String
    /// Canonical, distinct `csec://` references, all in one store, so the
    /// deletion is one index write: all of them go, or none.
    public let references: [String]

    public init(references: [String], requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.references = references
    }

    public var isWellFormed: Bool {
        guard UUID(uuidString: requestID) != nil,
              !references.isEmpty,
              references.count <= Self.maximumReferences,
              Set(references).count == references.count else { return false }
        // Canonical as csecd's registrations spell it (`SecretRef` keeps a
        // scheme as written), so the in-use checks match by string.
        let parsed = references.compactMap { raw -> NativeSecretReference? in
            guard let ref = try? SecretRef(raw), let native = try? NativeSecretReference(ref),
                  native.uri == raw else { return nil }
            return native
        }
        return parsed.count == references.count && Set(parsed.map(\.store.value)).count == 1
    }
}

public struct NativeStoreRemovalReply: Codable, Sendable, Equatable {
    public struct Removed: Codable, Sendable, Equatable {
        public let reference: String
        /// Where the file was protected from, as its import recorded it:
        /// relative to the directory `csec protect` ran in, or
        /// `ssh-keys/<name>` for an SSH key. Metadata only.
        public let path: String

        public init(reference: String, path: String) {
            self.reference = reference
            self.path = path
        }
    }

    public let removed: [Removed]
    /// Grants that covered a deleted value, now gone with it.
    public let revokedGrants: Int

    public init(removed: [Removed], revokedGrants: Int) {
        self.removed = removed
        self.revokedGrants = revokedGrants
    }
}

/// csecd's side of `csec edit --remove`.
public actor NativeStoreRemovalService {
    /// What csecd's own registrations use, by canonical reference, each as a
    /// phrase completing "csec://… is …". Throws when it cannot tell, and
    /// then nothing is deleted.
    public typealias Uses = @Sendable () async throws -> [String: String]
    /// The directories a store's files may have been protected from: a
    /// recorded path is relative to the one `csec protect` ran in.
    public typealias ProtectedFromDirectories = @Sendable (NativeStoreName) -> [String]
    /// Everything held for the deleted references (grants, auto-mode
    /// pairings, cached values) is dropped; returns how many grants went.
    public typealias Forget = @Sendable (Set<String>) async -> Int

    private let blobStore: NativeBlobStore
    private let consent: ConsentProvider
    private let terminalInspection: TerminalSessionInspector
    private let uses: Uses
    private let protectedFrom: ProtectedFromDirectories
    private let forget: Forget
    private let record: @Sendable (_ detail: String, _ references: [String]) async -> Void

    public init(
        blobStore: NativeBlobStore,
        consent: ConsentProvider,
        terminalInspection: TerminalSessionInspector,
        uses: @escaping Uses,
        protectedFrom: @escaping ProtectedFromDirectories = { NativeStoreRemovalService.protectedFromDirectories($0) },
        forget: @escaping Forget,
        record: @escaping @Sendable (_ detail: String, _ references: [String]) async -> Void = { _, _ in }
    ) {
        self.blobStore = blobStore
        self.consent = consent
        self.terminalInspection = terminalInspection
        self.uses = uses
        self.protectedFrom = protectedFrom
        self.forget = forget
        self.record = record
    }

    /// The home directory (where `csec setup` protects files from) and the
    /// project root that claimed the store, if one did.
    public static func protectedFromDirectories(_ store: NativeStoreName) -> [String] {
        let home = (NSHomeDirectory() as NSString).resolvingSymlinksInPath
        guard let origin = NativeStoreDirectoryIndex().origin(forStore: store.value),
              NativeStoreOriginMarker.isValidOrigin(origin), origin != home else { return [home] }
        return [home, origin]
    }

    public func handle(_ request: NativeStoreRemovalRequest, caller: CallerInfo) async -> Response {
        let id = request.requestID
        let references = request.references.compactMap { try? NativeSecretReference(SecretRef($0)) }
        guard request.isWellFormed, references.count == request.references.count, let store = references.first?.store else {
            return .failed(
                .invalidRequest,
                message: "name up to \(NativeStoreRemovalRequest.maximumReferences) distinct csec:// references in one store",
                requestID: id
            )
        }

        // Checked before the touch, so a mistake costs no prompt: the
        // registrations, and the index too when this csecd already holds it.
        if let refusal = await registrationRefusal(request.references) {
            return .failed(refusal.code, message: refusal.message, requestID: id)
        }
        if let entries = try? await blobStore.list(store: store, unlock: nil) {
            if let refusal = indexRefusal(references, entries: entries, store: store) {
                return .failed(refusal.code, message: refusal.message, requestID: id)
            }
        } else if await blobStore.presence(store: store, key: references[0].key) == .storeAbsent {
            return .failed(.referenceNotFound, message: Self.notWholeFile(references[0]), requestID: id)
        }

        var shown = caller
        shown.terminal = await terminalInspection.context(forCallerPID: caller.pid)
        let outcome = await consent.approveSettingsChange(Self.change(references), caller: shown)
        guard outcome.isApproved, let unlock = outcome.unlock, unlock.isLocal else {
            outcome.unlock?.invalidate()
            return .failed(.consentDenied, message: "deleting the stored values was denied", requestID: id)
        }
        defer { unlock.invalidate() }

        // Again with the store open, just before the write: a registration
        // made while the panel was up counts too.
        if let refusal = await registrationRefusal(request.references) {
            return .failed(refusal.code, message: refusal.message, requestID: id)
        }
        let removed: [NativeStoreRemovalReply.Removed]
        do {
            let entries = try await blobStore.list(store: store, unlock: unlock)
            if let refusal = indexRefusal(references, entries: entries, store: store) {
                return .failed(refusal.code, message: refusal.message, requestID: id)
            }
            removed = references.compactMap { reference in
                entries[reference.key].map { .init(reference: reference.uri, path: $0.path) }
            }
            _ = try await blobStore.removeBlobs(store: store, keys: references.map(\.key), unlock: unlock)
        } catch {
            let reason = (error as? LocalizedError)?.errorDescription ?? "the native store could not be written"
            return .failed(.nativeStoreUnavailable, message: "\(reason); nothing was removed", requestID: id)
        }
        let revoked = await forget(Set(request.references))
        await record(
            "deleted \(removed.count) whole-file value\(removed.count == 1 ? "" : "s") from native store "
                + "\(store.value); \(revoked) grant\(revoked == 1 ? "" : "s") revoked",
            request.references
        )
        return Response(
            requestID: id,
            nativeStoreRemoval: NativeStoreRemovalReply(removed: removed, revokedGrants: revoked)
        )
    }

    // MARK: - Refusals

    private struct Refusal {
        let code: WireErrorCode
        let message: String
    }

    private func registrationRefusal(_ references: [String]) async -> Refusal? {
        let users: [String: String]
        do {
            users = try await uses()
        } catch {
            return Refusal(code: .internalError, message: "csec could not check what uses these values; nothing was removed")
        }
        let used = references.compactMap { reference in users[reference].map { "\(reference) is \($0)" } }
        guard !used.isEmpty else { return nil }
        return Refusal(code: .policyDenied, message: used.joined(separator: "; ") + "; nothing was removed")
    }

    private func indexRefusal(
        _ references: [NativeSecretReference],
        entries: [String: NativeBlobEntry],
        store: NativeStoreName
    ) -> Refusal? {
        for reference in references {
            guard let entry = entries[reference.key] else {
                return Refusal(code: .referenceNotFound, message: Self.notWholeFile(reference))
            }
            if let sidecar = sidecarUsing(reference, recordedPath: entry.path, store: store) {
                return Refusal(
                    code: .policyDenied,
                    message: "\(reference.uri) is still used by the sidecar \(sidecar); "
                        + "restore or delete that file first; nothing was removed"
                )
            }
        }
        return nil
    }

    /// The sidecar at the place `reference` was protected from, when it still
    /// names `reference`. A sidecar is a plain pointer file anyone may move,
    /// so this finds the common case, not every copy.
    private func sidecarUsing(_ reference: NativeSecretReference, recordedPath: String, store: NativeStoreName) -> String? {
        for directory in protectedFrom(store) {
            let path = (directory as NSString).appendingPathComponent(recordedPath) + ProtectedFileSidecar.suffix
            if case let .success(sidecar)? = ProtectedSidecarScanner.sidecar(atPath: path),
               sidecar.reference.uri == reference.uri {
                return ReviewDisplay.sanitized((path as NSString).abbreviatingWithTildeInPath)
            }
        }
        return nil
    }

    static func notWholeFile(_ reference: NativeSecretReference) -> String {
        "\(reference.uri) is not a whole-file value in csec's native store "
            + "(a document value is removed with `csec edit \(reference.store.value)`); nothing was removed"
    }

    // MARK: - Panel

    static let footnote =
        "Touch ID deletes exactly these values from Convenient Security's native store. No secret is released."

    static func change(_ references: [NativeSecretReference]) -> SettingsChangeReviewDetails {
        SettingsChangeReviewDetails(
            title: references.count == 1 ? "Delete a Stored File" : "Delete \(references.count) Stored Files",
            changes: references.map { "Delete \($0.uri) from csec's native store, with every grant for it" },
            footnote: footnote
        )
    }
}
