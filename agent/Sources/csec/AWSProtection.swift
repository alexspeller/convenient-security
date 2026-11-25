import ConvenientSecurity
import Foundation
import Darwin

/// Snapshot both inputs before the biometric import. Never follow a leaf
/// symlink or rewrite a hardlinked file (which would leave an exposed alias).
struct AWSProtectionFile {
    let path: String
    let data: Data
    let info: stat?
    let parentInfo: stat

    init(path rawPath: String, allowMissing: Bool = false) throws {
        let absolute = (rawPath as NSString).expandingTildeInPath
        let url = URL(fileURLWithPath: absolute).standardizedFileURL
        guard let parent = canonicalPath(url.deletingLastPathComponent().path) else {
            throw ProtectError(message: "AWS file parent directory does not exist")
        }
        path = (parent as NSString).appendingPathComponent(url.lastPathComponent)
        var parentStat = stat()
        guard lstat(parent, &parentStat) == 0,
              parentStat.st_mode & S_IFMT == S_IFDIR,
              parentStat.st_uid == getuid(), parentStat.st_mode & 0o022 == 0 else {
            throw ProtectError(message: "AWS file parent must be a caller-owned directory without group/other write access")
        }
        parentInfo = parentStat
        var current = stat()
        if lstat(path, &current) != 0, errno == ENOENT, allowMissing {
            data = Data()
            info = nil
        } else {
            let read = try readRegularFile(atPath: path)
            guard read.info.st_nlink == 1, read.info.st_mode & 0o022 == 0 else {
                throw ProtectError(message: "AWS migration refuses hardlinks and group/other-writable files")
            }
            data = read.data
            info = read.info
        }
    }

    func validate() throws {
        var parent = stat()
        let directory = (path as NSString).deletingLastPathComponent
        guard lstat(directory, &parent) == 0,
              parent.st_mode & S_IFMT == S_IFDIR,
              parent.st_dev == parentInfo.st_dev, parent.st_ino == parentInfo.st_ino,
              parent.st_uid == getuid(), parent.st_mode & 0o022 == 0 else {
            throw ProtectError(message: "AWS parent directory changed; plaintext was retained")
        }
        var current = stat()
        if let info {
            guard lstat(path, &current) == 0,
                  sameProtectFileVersion(current, info),
                  let read = try? readRegularFile(atPath: path), read.data == data,
                  sameProtectFileVersion(read.info, info) else {
                throw ProtectError(message: "AWS file changed while csec was working; it was left untouched")
            }
        } else {
            guard lstat(path, &current) != 0, errno == ENOENT else {
                throw ProtectError(message: "AWS config appeared while csec was working; it was left untouched")
            }
        }
    }

    func write(_ newData: Data) throws {
        try validate()
        if newData == data, info != nil { return }
        try writeFileAtomically(
            path: path, data: newData, mode: 0o600,
            guardAgainst: info, requireMissing: info == nil, guardParent: parentInfo)
    }
}

struct AWSProtectionPlan {
    let source: AWSProtectionFile
    let config: AWSProtectionFile
    let migration: AWSCredentialMigration

    init(path: String, configPath: String, store: NativeStoreName) throws {
        source = try AWSProtectionFile(path: path)
        config = try AWSProtectionFile(path: configPath, allowMissing: true)
        guard source.path != config.path else {
            throw ProtectError(message: "AWS credentials and config must be different files")
        }
        migration = try AWSCredentialMigration(
            credentialsData: source.data, configurationData: config.data,
            sourcePath: source.path, csecExecutablePath: currentExecutablePath(),
            referenceForKey: { try NativeSecretReference(store: store, key: $0).secretRef })
    }

    func apply(destination: SecretWriteDestination, keepPlaintext: Bool) throws {
        var installedConfig: AWSProtectionFile?
        try migration.apply(
            keepPlaintext: keepPlaintext,
            validateSources: { try source.validate(); try config.validate() },
            commit: destination.commit,
            writeConfiguration: {
                try config.write($0)
                installedConfig = try AWSProtectionFile(path: config.path)
                guard installedConfig?.data == $0 else {
                    throw ProtectError(message: "AWS config changed after installation; plaintext was retained")
                }
            },
            writeCredentials: {
                try installedConfig?.validate()
                try source.write($0)
            })
    }
}

func awsConfigurationPath(override: String? = nil, homeDirectory: String) -> String {
    override ?? ProcessInfo.processInfo.environment["AWS_CONFIG_FILE"]
        ?? (homeDirectory as NSString).appendingPathComponent(".aws/config")
}
