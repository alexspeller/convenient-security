import ConvenientSecurity
import Foundation
import Darwin

/// One npm userconfig planned for splitting, snapshotted before consent. The
/// split rewrites the file in place, so a hardlinked alias would keep the
/// token: refuse links, as the AWS migration does, before anything is stored.
struct NpmSplitFile {
    let path: String
    let data: Data
    let info: stat
    let parentInfo: stat
    let split: NpmUserConfig.Split

    init(path rawPath: String, aliasPaths: [String]) throws {
        guard aliasPaths.isEmpty else {
            throw ProtectError(message: "npm config splitting refuses hardlinks: "
                + "rewriting one name would leave the token in its other links")
        }
        let url = URL(fileURLWithPath: (rawPath as NSString).expandingTildeInPath).standardizedFileURL
        guard let parent = canonicalPath(url.deletingLastPathComponent().path) else {
            throw ProtectError(message: "npm config parent directory does not exist")
        }
        path = (parent as NSString).appendingPathComponent(url.lastPathComponent)
        var parentStat = stat()
        guard lstat(parent, &parentStat) == 0,
              parentStat.st_mode & S_IFMT == S_IFDIR,
              parentStat.st_uid == getuid(), parentStat.st_mode & 0o022 == 0 else {
            throw ProtectError(message: "npm config parent must be a caller-owned directory without group/other write access")
        }
        parentInfo = parentStat
        let read = try readRegularFile(atPath: path)
        guard read.info.st_nlink == 1, read.info.st_mode & 0o022 == 0 else {
            throw ProtectError(message: "npm config splitting refuses hardlinks and group/other-writable files")
        }
        data = read.data
        info = read.info
        do {
            split = try NpmUserConfig.split(read.data)
        } catch let error as NpmUserConfigError {
            throw ProtectError(message: error.localizedDescription)
        }
    }

    /// Replace the file with its kept lines once the auth lines are durable
    /// in the store. Any change since the snapshot leaves the file untouched.
    func rewrite(reference: String) throws {
        var current = stat()
        guard lstat(path, &current) == 0, sameProtectFileVersion(current, info),
              let read = try? readRegularFile(atPath: path), read.data == data,
              sameProtectFileVersion(read.info, info) else {
            throw ProtectError(message: "npm config changed while csec was working; it was left untouched")
        }
        try writeFileAtomically(
            path: path, data: split.rewritten(reference: reference),
            mode: mode_t(info.st_mode & 0o7777),
            guardAgainst: info, guardParent: parentInfo)
    }
}
