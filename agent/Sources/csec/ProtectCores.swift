import Foundation
import ConvenientSecurity
#if canImport(Darwin)
import Darwin
#endif

/// The non-interactive cores behind `csec protect{,--env,--ssh}` and the bulk
/// setup apply. Every function takes its base directory explicitly — never
/// `FileManager.currentDirectoryPath` — so the same guarded code path serves
/// the CWD-scoped commands and a home-wide sweep alike. Each per-file guard
/// (O_NOFOLLOW open, caller-owner check, containment under the base
/// directory, stat-equality before any rewrite or unlink) stays with the
/// file, not the call site.

struct ProtectError: Error {
    let message: String
}

struct ProtectPlannedFile {
    let originalPath: String
    let relativePath: String
    let sidecarPath: String
    let key: String
    let data: Data
    let mode: UInt16
    let info: stat
}

// MARK: - planning

func planProtectedFile(
    rawPath: String,
    baseDirectory: String,
    store: NativeStoreName
) throws -> ProtectPlannedFile {
    let absolute = (rawPath as NSString).isAbsolutePath
        ? rawPath
        : (baseDirectory as NSString).appendingPathComponent(rawPath)
    // Canonicalize the file's parent directory (not the file itself, so a
    // symlinked target is not silently followed) and rejoin the base name.
    let parent = (absolute as NSString).deletingLastPathComponent
    let baseName = (absolute as NSString).lastPathComponent
    guard let canonicalParent = canonicalPath(parent) else {
        throw ProtectError(message: "could not be located")
    }
    let canonicalFile = (canonicalParent as NSString).appendingPathComponent(baseName)
    guard canonicalFile.hasPrefix(baseDirectory == "/" ? "/" : baseDirectory + "/") else {
        throw ProtectError(message: "must be inside \(baseDirectory)")
    }
    let relative = String(canonicalFile.dropFirst(baseDirectory.count).drop(while: { $0 == "/" }))
    guard !relative.isEmpty else {
        throw ProtectError(message: "is the base directory, not a file")
    }
    guard !relative.hasSuffix(ProtectedFileSidecar.suffix) else {
        throw ProtectError(message: "is itself a csec sidecar")
    }

    let (data, info) = try readRegularFile(atPath: canonicalFile)
    let mode = UInt16(info.st_mode & 0o7777)
    guard !data.isEmpty else {
        throw ProtectError(message: "is empty; nothing to protect")
    }
    guard data.count <= NativeBlobStore.maximumBlobBytes else {
        throw ProtectError(message: "is larger than the per-file limit")
    }
    return ProtectPlannedFile(
        originalPath: canonicalFile,
        relativePath: relative,
        sidecarPath: canonicalFile + ProtectedFileSidecar.suffix,
        key: ProtectedFileImportPlanner.storeKey(forRelativePath: canonicalFile),
        data: data,
        mode: mode,
        info: info
    )
}

func planSSHPrivateKey(
    rawPath: String,
    baseDirectory: String,
    agentPins: [SSHConfigAgentPin] = SSHConfigAgentPins.scanLocal(homeDirectory: canonicalHomeDirectory())
) throws -> ProtectPlannedFile {
    let absolute = (rawPath as NSString).isAbsolutePath
        ? rawPath
        : (baseDirectory as NSString).appendingPathComponent(rawPath)
    let parent = (absolute as NSString).deletingLastPathComponent
    let baseName = (absolute as NSString).lastPathComponent
    guard !baseName.isEmpty, baseName != ".", baseName != "..",
          !baseName.hasSuffix(".pub"),
          !baseName.hasSuffix(ProtectedFileSidecar.suffix),
          let canonicalParent = canonicalPath(parent) else {
        throw ProtectError(message: "must name a private-key file, not a public key or sidecar")
    }
    let canonicalFile = (canonicalParent as NSString).appendingPathComponent(baseName)
    let (data, info) = try readRegularFile(atPath: canonicalFile)
    try requireSingleProtectionPath(info, approach: "SSH protection")
    guard !data.isEmpty else { throw ProtectError(message: "is empty; nothing to protect") }
    // csecd registers a batch only if every key in it parses, so a key it would
    // refuse is turned away here, before the review, instead of failing the
    // whole batch after Touch ID and the import.
    if let refusal = SSHKeyFileVerdict.inspect(data).importRefusal {
        throw ProtectError(message: refusal)
    }
    // ssh never asks csec's agent for a key its config pins elsewhere, so
    // moving the file would break every host that uses it.
    if let pin = sshAgentPin(forCanonicalPath: canonicalFile, in: agentPins) {
        throw ProtectError(message: "is used with \(pin.describe(homeDirectory: canonicalHomeDirectory())); "
            + "ssh would not ask csec's agent for it there, so it was left in place")
    }
    return ProtectPlannedFile(
        originalPath: canonicalFile,
        relativePath: "ssh-keys/\(baseName)",
        sidecarPath: canonicalFile + ProtectedFileSidecar.suffix,
        key: ProtectedFileImportPlanner.storeKey(forRelativePath: canonicalFile),
        data: data,
        // If this ordinary blob is ever restored through another delivery path,
        // do not carry forward an accidentally permissive private-key mode.
        mode: 0o600,
        info: info
    )
}

/// The ssh-config pin whose `IdentityFile` names `path` (canonical, as
/// `planSSHPrivateKey` resolves it), comparing through symlinked directories.
func sshAgentPin(forCanonicalPath path: String, in pins: [SSHConfigAgentPin]) -> SSHConfigAgentPin? {
    pins.first { pin in
        let parent = (pin.keyPath as NSString).deletingLastPathComponent
        let name = (pin.keyPath as NSString).lastPathComponent
        let resolved = canonicalPath(parent).map { ($0 as NSString).appendingPathComponent(name) }
        return (resolved ?? pin.keyPath) == path
    }
}

/// The parse-and-guard front half of an env-file protection: containment,
/// hardened read, position-preserving parse. Interactive selection (or the
/// bulk preselection) happens between this and `applyEnvProtection`.
struct EnvFilePlan {
    let document: EnvFileDocument
    let canonicalFile: String
    let relativePath: String
    let originalInfo: stat
}

func planEnvFile(rawPath: String, baseDirectory: String) throws -> EnvFilePlan {
    let absolute = (rawPath as NSString).isAbsolutePath
        ? rawPath
        : (baseDirectory as NSString).appendingPathComponent(rawPath)
    let parent = (absolute as NSString).deletingLastPathComponent
    let baseName = (absolute as NSString).lastPathComponent
    guard let canonicalParent = canonicalPath(parent) else {
        throw ProtectError(message: "could not be located")
    }
    let canonicalFile = (canonicalParent as NSString).appendingPathComponent(baseName)
    guard canonicalFile.hasPrefix(baseDirectory == "/" ? "/" : baseDirectory + "/") else {
        throw ProtectError(message: "must be inside \(baseDirectory)")
    }
    let relative = String(canonicalFile.dropFirst(baseDirectory.count).drop(while: { $0 == "/" }))
    guard !relative.isEmpty else {
        throw ProtectError(message: "is the base directory, not a file")
    }
    guard !relative.hasSuffix(ProtectedFileSidecar.suffix) else {
        throw ProtectError(message: "is a csec sidecar, not an env file")
    }

    let (data, info) = try readRegularFile(atPath: canonicalFile)
    try requireSingleProtectionPath(info, approach: "per-variable rewriting")
    guard !data.isEmpty else {
        throw ProtectError(message: "is empty; nothing to protect")
    }
    let document: EnvFileDocument
    do {
        document = try EnvFileDocument(data: data)
    } catch {
        throw ProtectError(message: "\(error)")
    }
    return EnvFilePlan(
        document: document,
        canonicalFile: canonicalFile,
        relativePath: relative,
        originalInfo: info
    )
}

// MARK: - apply cores

struct WholeFileProtectOutcome {
    struct Item {
        let relativePath: String
        let sidecarPath: String
        let reference: String
        let aliasSidecarPaths: [String]
    }
    let items: [Item]
    let removedPlaintextCount: Int
    /// Paths needing inspection because cleanup saw a change or could not finish.
    let retainedPlaintext: [String]
}

/// Whole-file protection for one already-planned batch sharing one store:
/// durable biometric-gated import first, then a sidecar at the original path
/// *and at every discovered alias*, and only then plaintext removal (each
/// unlink guarded by stat equality). Every hardlink must have been discovered;
/// symlinks remain pointed at the destination and are never cleanup targets.
func commitWholeFiles(
    planned: [ProtectPlannedFile],
    aliasPaths: [String: [String]] = [:],
    store: NativeStoreName,
    origin: String?,
    keepPlaintext: Bool,
    client: AgentClient
) throws -> WholeFileProtectOutcome {
    for item in planned {
        try validateWholeFilePaths(item, aliases: aliasPaths[item.originalPath] ?? [])
    }
    // 1. Durable, biometric-gated import. After this returns, every value is
    //    in the encrypted store; nothing on disk has changed yet.
    let session = try client.beginNativeStoreEdit(
        store: store.value, mode: .onboardingImport, origin: origin)
    let blobs = planned.map {
        ProtectedBlobImport(key: $0.key, data: $0.data, mode: $0.mode, path: $0.relativePath)
    }
    _ = try client.commitNativeStoreBlobs(sessionID: session.sessionID, blobs: blobs)

    // 2. Write every sidecar atomically — original path first, then each
    //    alias. If any fails we stop before removing any plaintext; the
    //    values are safely imported regardless.
    var items: [WholeFileProtectOutcome.Item] = []
    for item in planned {
        let reference = try NativeSecretReference(store: store, key: item.key)
        let sidecar = try ProtectedFileSidecar(reference: SecretRef(reference.uri)).encoded()
        try writeFileAtomically(path: item.sidecarPath, data: sidecar, mode: 0o600)
        var aliasSidecars: [String] = []
        for alias in aliasPaths[item.originalPath] ?? [] {
            let aliasSidecar = alias + ProtectedFileSidecar.suffix
            try writeFileAtomically(path: aliasSidecar, data: sidecar, mode: 0o600)
            aliasSidecars.append(aliasSidecar)
        }
        items.append(WholeFileProtectOutcome.Item(
            relativePath: item.relativePath,
            sidecarPath: item.sidecarPath,
            reference: reference.uri,
            aliasSidecarPaths: aliasSidecars
        ))
    }

    // 3. Only now remove the redundant plaintext.
    var removed = 0
    var retained: [String] = []
    if !keepPlaintext {
        for item in planned {
            let cleanup = removeWholeFilePlaintext(item, aliases: aliasPaths[item.originalPath] ?? [])
            removed += cleanup.removed
            retained += cleanup.retained
        }
    }
    return WholeFileProtectOutcome(
        items: items,
        removedPlaintextCount: removed,
        retainedPlaintext: retained
    )
}

enum EnvApplyError: Error {
    /// Nothing was imported and the file is untouched.
    case importFailed(Error)
    /// The values are durably imported but the file still holds plaintext;
    /// re-running finishes the rewrite.
    case rewriteFailed(ProtectError)
}

/// The commit-then-rewrite back half of an env-file protection. The file is
/// untouched until every selected value is durable at the destination; the
/// rewrite is atomic and refuses to clobber concurrent edits (stat guard).
func applyEnvProtection(
    plan: EnvFilePlan,
    selectedKeys: [String],
    destination: SecretWriteDestination
) throws -> [String: String] {
    do {
        try plan.document.validateRewrite(selectedKeys: Set(selectedKeys))
    } catch {
        throw EnvApplyError.importFailed(error)
    }
    var values: [String: String] = [:]
    let candidatesByKey = Dictionary(
        uniqueKeysWithValues: plan.document.candidates.map { ($0.importKey, $0) })
    for key in selectedKeys {
        guard let candidate = candidatesByKey[key], candidate.kind == .importable else {
            throw EnvApplyError.importFailed(
                ProtectError(message: "selected variable \(key) is not importable"))
        }
        values[key] = candidate.importValue
    }
    let references: [String: String]
    do {
        references = values.isEmpty ? [:] : try destination.commit(values: values)
    } catch {
        throw EnvApplyError.importFailed(error)
    }

    do {
        try writeFileAtomically(
            path: plan.canonicalFile,
            data: try plan.document.rewritten(references: references),
            mode: mode_t(plan.originalInfo.st_mode & 0o7777),
            guardAgainst: plan.originalInfo)
    } catch let error as ProtectError {
        throw EnvApplyError.rewriteFailed(error)
    } catch {
        throw EnvApplyError.rewriteFailed(ProtectError(message: error.localizedDescription))
    }
    return references
}

struct SSHProtectOutcome {
    let keys: [SSHKeyMetadata]
    /// The reference holding each planned file's key, by original path. A
    /// file holding the same key as one earlier in the batch is held by that
    /// file's reference.
    let referenceByPath: [String: String]
    let removedPlaintextCount: Int
    let retainedPlaintext: [String]
}

/// SSH protection for an already-planned batch: one trusted-review session
/// imports every blob and registers catalog entries inside csecd, missing
/// .pub files are recreated from returned public metadata, and the private
/// plaintext is removed only afterwards (stat-guarded).
///
/// csecd's catalog holds one entry per key and refuses a batch that names a
/// key twice, so a second file holding the same key (a copy under another
/// name) is imported and registered once, under the first file's reference.
/// Every copy still has its plaintext removed and keeps a .pub, so an
/// `IdentityFile` naming either file goes on matching the agent's key.
func commitSSHKeys(
    planned: [ProtectPlannedFile],
    references: [SecretRef],
    registrations: [SSHKeyRegistrationIntent],
    keepPlaintext: Bool,
    store: NativeStoreName,
    client: AgentClient
) throws -> SSHProtectOutcome {
    for item in planned { try validateWholeFilePaths(item, aliases: []) }
    var firstWithKey: [Data: Int] = [:]
    let holder: [Int] = planned.indices.map { index in
        guard let publicKey = SSHKeyFileVerdict.publicKeyBlob(planned[index].data) else { return index }
        if let first = firstWithKey[publicKey] { return first }
        firstWithKey[publicKey] = index
        return index
    }
    let imported = planned.indices.filter { holder[$0] == $0 }

    let session = try client.beginNativeStoreEdit(
        store: store.value,
        mode: .sshKeyImport
    )
    let blobs = imported.map {
        ProtectedBlobImport(
            key: planned[$0].key,
            data: planned[$0].data,
            mode: planned[$0].mode,
            path: planned[$0].relativePath
        )
    }
    let result = try client.commitNativeStoreBlobsAndRegisterSSH(
        sessionID: session.sessionID,
        blobs: blobs,
        registrations: imported.map { registrations[$0] }
    )
    let metadataByReference = Dictionary(
        uniqueKeysWithValues: result.keys.map { ($0.reference, $0) }
    )

    // SSH registration itself durably retains the provider-neutral reference,
    // so do not create a second on-disk pointer that can drift from the
    // catalog. A missing .pub is recreated from returned public metadata;
    // existing .pub files are preserved byte-for-byte.
    var referenceByPath: [String: String] = [:]
    for (index, item) in planned.enumerated() {
        let reference = references[holder[index]].uri
        referenceByPath[item.originalPath] = reference
        if let metadata = metadataByReference[reference] {
            try writePublicKeyIfMissing(
                path: item.originalPath + ".pub",
                data: Data(metadata.publicKeyLine.utf8)
            )
        }
    }

    var removed = 0
    var retained: [String] = []
    if !keepPlaintext {
        for item in planned {
            if unlinkIfUnchanged(item) { removed += 1 } else { retained.append(item.originalPath) }
        }
    }
    return SSHProtectOutcome(
        keys: result.keys,
        referenceByPath: referenceByPath,
        removedPlaintextCount: removed,
        retainedPlaintext: retained
    )
}

// MARK: - hardened file plumbing

/// Read a regular, caller-owned, non-symlink file's bytes and its stat record
/// (mode for re-creation, identity/size/mtime for change detection before an
/// in-place rewrite).
func readRegularFile(atPath path: String) throws -> (data: Data, info: stat) {
    let fd = path.withCString { open($0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC) }
    guard fd >= 0 else { throw ProtectError(message: "could not be opened (not a regular file?)") }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0,
          (info.st_mode & S_IFMT) == S_IFREG,
          info.st_uid == getuid() else {
        throw ProtectError(message: "is not a caller-owned regular file")
    }
    guard info.st_size >= 0, info.st_size <= NativeBlobStore.maximumBlobBytes else {
        throw ProtectError(message: "is larger than the per-file limit")
    }
    var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
    var offset = 0
    let total = bytes.count
    while offset < total {
        let count = bytes.withUnsafeMutableBytes { raw in
            Darwin.read(fd, raw.baseAddress!.advanced(by: offset), total - offset)
        }
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { throw ProtectError(message: "could not be read completely") }
        offset += count
    }
    var extra: UInt8 = 0
    var finalInfo = stat()
    guard Darwin.read(fd, &extra, 1) == 0, fstat(fd, &finalInfo) == 0,
          sameProtectFileVersion(finalInfo, info) else {
        throw ProtectError(message: "changed while being read; nothing was imported")
    }
    return (Data(bytes), info)
}

/// Write `data` to `path` atomically: a private temp file in the same directory,
/// fsync'd, then renamed over the destination. When `guardAgainst` carries the
/// stat record the content was derived from, the rename is refused if the file
/// at `path` has changed identity, size, or mtime since — a concurrent editor's
/// work must not be silently overwritten.
func writeFileAtomically(
    path: String, data: Data, mode: mode_t, guardAgainst original: stat? = nil,
    requireMissing: Bool = false, guardParent originalParent: stat? = nil
) throws {
    let directory = (path as NSString).deletingLastPathComponent
    let name = (path as NSString).lastPathComponent
    let directoryFD = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard directoryFD >= 0 else { throw ProtectError(message: "the file parent could not be opened") }
    defer { close(directoryFD) }
    if let originalParent {
        var currentParent = stat()
        guard fstat(directoryFD, &currentParent) == 0,
              currentParent.st_dev == originalParent.st_dev,
              currentParent.st_ino == originalParent.st_ino,
              currentParent.st_uid == originalParent.st_uid,
              currentParent.st_mode == originalParent.st_mode else {
            throw ProtectError(message: "the file parent changed; the original was left untouched")
        }
    }
    let temporary = ".csec-protect-\(UUID().uuidString.lowercased())"
    let fd = temporary.withCString {
        openat(directoryFD, $0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
    }
    guard fd >= 0 else { throw ProtectError(message: "the sidecar could not be created") }
    var keepTemporary = true
    defer {
        close(fd)
        if keepTemporary { temporary.withCString { _ = unlinkat(directoryFD, $0, 0) } }
    }
    var offset = 0
    try data.withUnsafeBytes { raw in
        while offset < raw.count {
            let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw ProtectError(message: "the sidecar could not be written") }
            offset += count
        }
    }
    guard fchmod(fd, mode) == 0, fsync(fd) == 0 else {
        throw ProtectError(message: "the sidecar could not be persisted")
    }
    if let original {
        var current = stat()
        guard name.withCString({ fstatat(directoryFD, $0, &current, AT_SYMLINK_NOFOLLOW) }) == 0,
              sameProtectFileVersion(current, original) else {
            throw ProtectError(message: "the file changed while csec was working; it was left untouched")
        }
    }
    let renamed = temporary.withCString { source in
        name.withCString { destination in
            requireMissing ? renameatx_np(directoryFD, source, directoryFD, destination, UInt32(RENAME_EXCL))
                : renameat(directoryFD, source, directoryFD, destination)
        }
    }
    guard renamed == 0 else { throw ProtectError(message: "the sidecar could not replace the file") }
    keepTemporary = false
    guard fsync(directoryFD) == 0 else {
        throw ProtectError(message: "the updated directory could not be persisted")
    }
}

func sameProtectFileVersion(_ current: stat, _ original: stat) -> Bool {
    sameProtectFileContents(current, original) && current.st_nlink == original.st_nlink
        && current.st_ctimespec.tv_sec == original.st_ctimespec.tv_sec
        && current.st_ctimespec.tv_nsec == original.st_ctimespec.tv_nsec
}

private func sameProtectFileContents(_ current: stat, _ original: stat) -> Bool {
    current.st_mode == original.st_mode && current.st_uid == original.st_uid
        && current.st_dev == original.st_dev && current.st_ino == original.st_ino
        && current.st_size == original.st_size
        && current.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec
        && current.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec
}

/// Rewriting or removing just one name would leave the other names exposed.
/// These mechanisms do not yet migrate a complete alias group.
func requireSingleProtectionPath(_ info: stat, approach: String) throws {
    guard info.st_nlink == 1 else {
        throw ProtectError(message: "\(approach) refuses hardlinks; choose whole-file in setup --protect-files and review every alias")
    }
}

/// Discovery can miss aliases outside its roots or excluded by its filters.
/// Refuse an incomplete or changed group before importing anything.
func validateWholeFilePaths(_ item: ProtectPlannedFile, aliases: [String]) throws {
    let paths = [item.originalPath] + aliases
    guard Set(paths).count == paths.count, Int(item.info.st_nlink) == paths.count else {
        throw ProtectError(message: "not every hardlink was discovered; expand the scan or remove unused aliases before protection")
    }
    for path in paths {
        var current = stat()
        guard lstat(path, &current) == 0, sameProtectFileVersion(current, item.info) else {
            throw ProtectError(message: "a file or hardlink changed while csec was working; plaintext was retained")
        }
    }
}

func writePublicKeyIfMissing(path: String, data: Data) throws {
    let fd = path.withCString {
        open($0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
    }
    if fd < 0, errno == EEXIST { return }
    guard fd >= 0 else { throw ProtectError(message: "the public key could not be created") }
    var complete = false
    defer {
        close(fd)
        if !complete { path.withCString { _ = unlink($0) } }
    }
    var offset = 0
    try data.withUnsafeBytes { raw in
        while offset < raw.count {
            let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw ProtectError(message: "the public key could not be written") }
            offset += count
        }
    }
    guard fchmod(fd, 0o644) == 0, fsync(fd) == 0 else {
        throw ProtectError(message: "the public key could not be persisted")
    }
    complete = true
}

/// Do not unlink a path that changed while the human was reviewing the import.
/// A concurrent replacement remains plaintext, but is never accidentally lost.
func unlinkIfUnchanged(_ item: ProtectPlannedFile) -> Bool {
    var current = stat()
    guard item.originalPath.withCString({ lstat($0, &current) }) == 0,
          sameProtectFileVersion(current, item.info) else {
        return false
    }
    return item.originalPath.withCString { unlink($0) } == 0
}

/// Check the entire group again after consent. Keep an open descriptor so each
/// successful unlink supplies the next expected link count and ctime: our own
/// removals change both, while content changes or a new alias stop cleanup.
/// Every name not removed is reported, including aliases.
private func removeWholeFilePlaintext(
    _ item: ProtectPlannedFile, aliases: [String]
) -> (removed: Int, retained: [String]) {
    let paths = [item.originalPath] + aliases
    do { try validateWholeFilePaths(item, aliases: aliases) }
    catch { return (0, paths) }
    let fd = open(item.originalPath, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { return (0, paths) }
    defer { close(fd) }
    var expected = stat()
    guard fstat(fd, &expected) == 0, sameProtectFileVersion(expected, item.info) else {
        return (0, paths)
    }
    for (index, path) in paths.enumerated() {
        var current = stat()
        guard lstat(path, &current) == 0, sameProtectFileVersion(current, expected),
              unlink(path) == 0 else { return (index, Array(paths[index...])) }
        var next = stat()
        guard fstat(fd, &next) == 0, sameProtectFileContents(next, expected),
              next.st_nlink == expected.st_nlink - 1 else {
            let remaining = Array(paths.dropFirst(index + 1))
            return (index + 1, remaining.isEmpty ? [path] : remaining)
        }
        expected = next
    }
    return (paths.count, [])
}

/// Canonicalize an existing path via realpath(3), resolving symlinks and `..`.
func canonicalPath(_ path: String) -> String? {
    guard let resolved = path.withCString({ realpath($0, nil) }) else { return nil }
    defer { free(resolved) }
    return String(cString: resolved)
}

/// The home directory in the same canonical namespace as `canonicalPath`-ed
/// project directories, so the home-relative store-name derivation strips the
/// prefix reliably. `$HOME` is consulted first: `NSHomeDirectory()` ignores
/// the environment override on macOS, which once let a test sweep escape its
/// synthetic home onto the real one — the override must always win.
func canonicalHomeDirectory() -> String {
    let raw = ProcessInfo.processInfo.environment["HOME"].flatMap {
        $0.hasPrefix("/") ? $0 : nil
    } ?? NSHomeDirectory()
    return canonicalPath(raw) ?? raw
}

/// Human detail for a protect-flow failure, with recovery guidance when the
/// daemon refused a default store name because a different project directory
/// claimed it (or its origin marker failed verification): re-running re-reads
/// the markers and proposes the deterministic disambiguated name, and --store
/// bypasses default resolution entirely.
func protectFailureDetail(_ error: Error, projectDirectory: String) -> String {
    if let error = error as? ProtectError { return error.message }
    guard case AgentClient.ClientError.protocolFailure(.storeOriginConflict, _) = error else {
        return error.localizedDescription
    }
    var detail = "the default store name is claimed by a different project directory; "
        + "re-run to use a disambiguated name"
    if let fallback = try? ProtectedFileImportPlanner.conflictStoreName(
        forProjectDirectory: projectDirectory, homeDirectory: canonicalHomeDirectory()) {
        detail += ", or pass --store \(fallback.value)"
    }
    return detail
}
