import Foundation
import ConvenientSecurity
#if canImport(Darwin)
import Darwin
#endif

/// `csec protect [--store NAME] [--keep-plaintext] [--dry-run] <path>...`
///
/// Imports whole plaintext secret files under the current project directory into
/// the native store's encrypted file/blob tier, replaces each with a tiny
/// `<name>.csec` sidecar pointing at its `csec://store/key` value, and removes the
/// now-redundant plaintext.
///
/// Safe by construction: the batch is committed to the encrypted store (durable,
/// biometric-gated) *before* anything on disk is touched, so the value always
/// exists in the store before its plaintext is unlinked. Sidecars are then written
/// atomically, and only after every sidecar is durable is any plaintext removed.
/// A failure at any point leaves the imported values intact and recoverable.
func runProtect(_ arguments: [String]) -> Never {
    var storeOverride: String?
    var keepPlaintext = false
    var dryRun = false
    var paths: [String] = []

    var index = 0
    while index < arguments.count {
        switch arguments[index] {
        case "--store":
            index += 1
            guard index < arguments.count else { usage() }
            storeOverride = arguments[index]
        case "--keep-plaintext":
            keepPlaintext = true
        case "--dry-run":
            dryRun = true
        case let token where token.hasPrefix("-"):
            usage()
        default:
            paths.append(arguments[index])
        }
        index += 1
    }
    guard !paths.isEmpty else { usage() }

    // Canonicalize the project directory (resolving symlinks such as macOS's
    // /var -> /private/var) so containment checks and relative paths are computed
    // in the same namespace the files themselves resolve into.
    guard let projectDirectory = canonicalPath(FileManager.default.currentDirectoryPath),
          projectDirectory.hasPrefix("/") else {
        protectFail("the current directory could not be determined")
    }

    let store: NativeStoreName
    do {
        store = try storeOverride.map { try NativeStoreName($0) }
            ?? ProtectedFileImportPlanner.storeName(forProjectDirectory: projectDirectory)
    } catch {
        protectFail("invalid store name (\(error.localizedDescription))")
    }

    var planned: [ProtectPlannedFile] = []
    var seenKeys = Set<String>()
    for rawPath in paths {
        let planItem: ProtectPlannedFile
        do {
            planItem = try planProtectedFile(
                rawPath: rawPath, projectDirectory: projectDirectory, store: store)
        } catch let error as ProtectError {
            protectFail("\(rawPath): \(error.message)")
        } catch {
            protectFail("\(rawPath): \(error.localizedDescription)")
        }
        guard seenKeys.insert(planItem.key).inserted else {
            protectFail("\(rawPath): the same file was listed more than once")
        }
        planned.append(planItem)
    }

    if dryRun {
        FileHandle.standardOutput.write(Data(
            "csec protect (dry run): store \(store.value)\n".utf8))
        for item in planned {
            FileHandle.standardOutput.write(Data((
                "  \(item.relativePath)  ->  csec://\(store.value)/\(item.key)"
                    + "  (mode \(String(item.mode, radix: 8)), \(item.data.count) bytes)\n").utf8))
        }
        exit(0)
    }

    let client = makeAgentClient()
    do {
        // 1. Durable, biometric-gated import. After this returns, every value is
        //    in the encrypted store; nothing on disk has changed yet.
        let session = try client.beginNativeStoreEdit(store: store.value, mode: .onboardingImport)
        let blobs = planned.map {
            ProtectedBlobImport(key: $0.key, data: $0.data, mode: $0.mode, path: $0.relativePath)
        }
        _ = try client.commitNativeStoreBlobs(sessionID: session.sessionID, blobs: blobs)

        // 2. Write every sidecar atomically. If any fails we stop before removing
        //    any plaintext — the values are safely imported regardless.
        for item in planned {
            let reference = try NativeSecretReference(store: store, key: item.key)
            let sidecar = try ProtectedFileSidecar(reference: SecretRef(reference.uri)).encoded()
            try writeFileAtomically(path: item.sidecarPath, data: sidecar, mode: 0o600)
        }

        // 3. Only now remove the redundant plaintext.
        var removed = 0
        if !keepPlaintext {
            for item in planned where unlink(item.originalPath) == 0 { removed += 1 }
        }

        FileHandle.standardOutput.write(Data((
            "csec protect: imported \(planned.count) file(s) into csec://\(store.value); "
                + (keepPlaintext
                    ? "plaintext left in place (--keep-plaintext)"
                    : "removed \(removed) plaintext file(s)") + "\n").utf8))
        for item in planned {
            FileHandle.standardOutput.write(Data(
                "  \(item.relativePath)  ->  \((item.sidecarPath as NSString).lastPathComponent)\n".utf8))
        }
        exit(0)
    } catch {
        protectFail(error.localizedDescription)
    }
}

private struct ProtectPlannedFile {
    let originalPath: String
    let relativePath: String
    let sidecarPath: String
    let key: String
    let data: Data
    let mode: UInt16
}

private struct ProtectError: Error {
    let message: String
}

private func planProtectedFile(
    rawPath: String,
    projectDirectory: String,
    store: NativeStoreName
) throws -> ProtectPlannedFile {
    let absolute = (rawPath as NSString).isAbsolutePath
        ? rawPath
        : (projectDirectory as NSString).appendingPathComponent(rawPath)
    // Canonicalize the file's parent directory (not the file itself, so a
    // symlinked target is not silently followed) and rejoin the base name.
    let parent = (absolute as NSString).deletingLastPathComponent
    let baseName = (absolute as NSString).lastPathComponent
    guard let canonicalParent = canonicalPath(parent) else {
        throw ProtectError(message: "could not be located")
    }
    let canonicalFile = (canonicalParent as NSString).appendingPathComponent(baseName)
    guard canonicalFile.hasPrefix(projectDirectory + "/") else {
        throw ProtectError(message: "must be inside the current project directory")
    }
    let relative = String(canonicalFile.dropFirst(projectDirectory.count).drop(while: { $0 == "/" }))
    guard !relative.isEmpty else {
        throw ProtectError(message: "is the project directory, not a file")
    }
    guard !relative.hasSuffix(ProtectedFileSidecar.suffix) else {
        throw ProtectError(message: "is itself a csec sidecar")
    }

    let (data, mode) = try readRegularFile(atPath: canonicalFile)
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
        key: ProtectedFileImportPlanner.storeKey(forRelativePath: relative),
        data: data,
        mode: mode
    )
}

/// Read a regular, caller-owned, non-symlink file's bytes and POSIX mode.
private func readRegularFile(atPath path: String) throws -> (data: Data, mode: UInt16) {
    let fd = path.withCString { open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
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
    return (Data(bytes), UInt16(info.st_mode & 0o7777))
}

/// Write `data` to `path` atomically: a private temp file in the same directory,
/// fsync'd, then renamed over the destination.
private func writeFileAtomically(path: String, data: Data, mode: mode_t) throws {
    let directory = (path as NSString).deletingLastPathComponent
    let temporary = (directory as NSString)
        .appendingPathComponent(".csec-protect-\(UUID().uuidString.lowercased())")
    let fd = temporary.withCString {
        open($0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
    }
    guard fd >= 0 else { throw ProtectError(message: "the sidecar could not be created") }
    var keepTemporary = true
    defer {
        close(fd)
        if keepTemporary { temporary.withCString { _ = unlink($0) } }
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
    let renamed = temporary.withCString { source in
        path.withCString { destination in rename(source, destination) }
    }
    guard renamed == 0 else { throw ProtectError(message: "the sidecar could not replace the file") }
    keepTemporary = false
}

/// Canonicalize an existing path via realpath(3), resolving symlinks and `..`.
private func canonicalPath(_ path: String) -> String? {
    guard let resolved = path.withCString({ realpath($0, nil) }) else { return nil }
    defer { free(resolved) }
    return String(cString: resolved)
}

private func protectFail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("csec protect: \(message)\n".utf8))
    exit(1)
}
