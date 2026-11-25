import ConvenientSecurity
import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - csec fly

/// `csec fly register [<reference> | --remove]` manages the registration;
/// anything else is a fly command line, run with the registered token in
/// `FLY_API_TOKEN` through `csec exec`, so its review and grants apply (a
/// terminal-session grant covers every later fly command in that terminal).
func runFly(_ arguments: [String]) -> Never {
    let configDirectory = FlyCLI.configDirectory(
        environment: ProcessInfo.processInfo.environment, homeDirectory: canonicalHomeDirectory())
    if arguments.first == "register" {
        runFlyRegister(Array(arguments.dropFirst()), configDirectory: configDirectory)
    }
    let registration = readFlyRegistration(configDirectory: configDirectory)
    switch FlyCLI.authAction(arguments) {
    case .login:
        runFlyLogin(arguments, configDirectory: configDirectory, registered: registration?.reference)
    case .logout:
        if registration != nil {
            do {
                try removeFlyRegistration(configDirectory: configDirectory)
                flyNote("forgot the registered Fly token; its value stays in its store and is not revoked. "
                    + "Revoke it in the Fly.io dashboard if you no longer want it to work")
            } catch {
                flyFail("could not remove the registration (\(error.localizedDescription)); fly was not run")
            }
        }
        execFlyWithoutToken(arguments)
    case nil:
        break
    }

    let tokens = try? FlyConfigSnapshot(configDirectory: configDirectory).tokens
    guard let reference = registration?.reference else {
        if tokens?.accessToken != nil {
            flyNote("fly's token is in plaintext in \(displayFlyPath(FlyCLI.configPath(configDirectory: configDirectory))); "
                + "run `csec protect --fly` to move it into csec")
        } else {
            flyNote("no Fly token is registered; sign in with `csec fly auth login`, "
                + "or run `csec fly register <reference>` for a token you already store")
        }
        execFlyWithoutToken(arguments, keepEnvironmentToken: true)
    }
    if tokens?.accessToken != nil {
        flyNote("fly saved a token in plaintext again; run `csec protect --fly` to take it back out")
    }
    if ProcessInfo.processInfo.environment[FlyCLI.isolatedAgentVariable] == nil {
        setenv(FlyCLI.isolatedAgentVariable, "1", 1)
    }
    // A token the shell already sets is the user's explicit choice; csec exec
    // still resolves it when it is a reference.
    let explicit = FlyCLI.tokenVariables.contains { ProcessInfo.processInfo.environment[$0] != nil }
    let delivery = explicit ? [] : ["--set", "\(FlyCLI.tokenVariable)=\(reference.uri)"]
    runExec(delivery + ["--reason", FlyCLI.reason, "--", "fly"] + arguments, warnsAboutEnvironment: false)
}

private func runFlyRegister(_ arguments: [String], configDirectory: String) -> Never {
    let registrationPath = displayFlyPath(FlyCLI.registrationPath(configDirectory: configDirectory))
    switch arguments.count {
    case 0:
        var lines: [String] = []
        if let reference = readFlyRegistration(configDirectory: configDirectory)?.reference {
            lines.append("Fly token:   \(reference.safeInlineURI) (registered in \(registrationPath))")
        } else {
            lines.append("Fly token:   not registered (run `csec protect --fly`)")
        }
        let configPath = displayFlyPath(FlyCLI.configPath(configDirectory: configDirectory))
        switch Result(catching: { try FlyConfigSnapshot(configDirectory: configDirectory).tokens }) {
        case .success(let tokens) where tokens.holdsToken:
            lines.append("config.yml:  \(configPath) holds a plaintext token (run `csec protect --fly`)")
        case .success:
            lines.append("config.yml:  \(configPath) holds no token")
        case .failure:
            lines.append("config.yml:  \(configPath) not readable or not present")
        }
        FileHandle.standardOutput.write(Data((lines.joined(separator: "\n") + "\n").utf8))
        exit(0)
    case 1 where arguments[0] == "--remove":
        do {
            let removed = try removeFlyRegistration(configDirectory: configDirectory)
            FileHandle.standardOutput.write(Data((removed
                ? "Removed the Fly token registration; the value stays in its store. `csec fly` now runs fly without a token.\n"
                : "No Fly token is registered.\n").utf8))
            exit(0)
        } catch {
            flyFail("could not remove \(registrationPath) (\(error.localizedDescription))")
        }
    case 1 where !arguments[0].hasPrefix("-"):
        let reference: SecretRef
        do {
            reference = try SecretRef(arguments[0])
        } catch {
            flyFail("not a secret reference (csec://STORE/KEY, op://VAULT/ITEM/FIELD or another provider's)")
        }
        do {
            try writeFlyRegistration(reference, configDirectory: configDirectory)
        } catch {
            flyFail("could not write \(registrationPath) (\(error.localizedDescription))")
        }
        var output = "Registered \(reference.safeInlineURI) as the token `csec fly` gives fly.\n"
        output += flyAliasGuidance()
        FileHandle.standardOutput.write(Data(output.utf8))
        exit(0)
    default:
        usage("fly")
    }
}

/// `auth login` / `auth signup`: fly signs in and saves a new token in its
/// file, so it runs without the old one, and the new token is then taken out
/// again into the registered reference (or csec's default store).
private func runFlyLogin(_ arguments: [String], configDirectory: String, registered: SecretRef?) -> Never {
    let status = runFlyChild(arguments)
    guard status == 0,
          let snapshot = try? FlyConfigSnapshot(configDirectory: configDirectory),
          snapshot.tokens.accessToken != nil else { exit(status) }
    let target: FlyImportTarget
    do {
        target = try flyImportTarget(storeOverride: nil, destOverride: nil, registered: registered)
    } catch let error as ProtectError {
        flyNote("fly saved its new token in plaintext: \(error.message)")
        exit(status)
    } catch {
        flyNote("fly saved its new token in plaintext: \(error.localizedDescription)")
        exit(status)
    }
    FileHandle.standardError.write(Data(
        "csec fly: moving fly's new token into \(target.display); csec asks to confirm the import.\n".utf8))
    do {
        let result = try protectFlyToken(snapshot: snapshot, target: target, keepPlaintext: false, client: makeAgentClient())
        FileHandle.standardError.write(Data(
            "csec fly: protected the new token as \(result.reference) and removed it from config.yml\n".utf8))
        exit(0)
    } catch let error as FlyProtectionError {
        flyFail(error.message)
    } catch {
        flyFail("fly's new token is still in plaintext: \(error.localizedDescription); run `csec protect --fly`")
    }
}

/// Runs fly as a child (so csec can act after it) with no token from this
/// shell or csec, and returns its exit status.
private func runFlyChild(_ arguments: [String]) -> Int32 {
    guard let path = try? ExecutableInspection.resolve(command: "fly") else {
        flyFail("fly is not on PATH")
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    var environment = ProcessInfo.processInfo.environment
    for name in FlyCLI.tokenVariables { environment.removeValue(forKey: name) }
    process.environment = environment
    do { try process.run() } catch { flyFail("could not run fly (\(error.localizedDescription))") }
    process.waitUntilExit()
    return process.terminationReason == .exit ? process.terminationStatus : 128 + process.terminationStatus
}

private func execFlyWithoutToken(_ arguments: [String], keepEnvironmentToken: Bool = false) -> Never {
    if !keepEnvironmentToken {
        for name in FlyCLI.tokenVariables { unsetenv(name) }
    }
    let argv: [UnsafeMutablePointer<CChar>?] = (["fly"] + arguments).map { strdup($0) } + [nil]
    execvp("fly", argv)
    flyFail("fly: \(String(cString: strerror(errno)))")
}

private func flyNote(_ message: String) {
    FileHandle.standardError.write(Data("csec fly: \(message)\n".utf8))
}

private func flyFail(_ message: String) -> Never {
    csecError("fly", message)
    exit(1)
}

func flyAliasGuidance() -> String {
    "  Run fly through csec from now on; add the line for your shell:\n"
        + FlyCLI.aliasLines().map { "    " + $0 + "\n" }.joined()
}

private func displayFlyPath(_ path: String) -> String {
    ReviewDisplay.sanitized(homeRelativeDisplay(path, home: canonicalHomeDirectory()))
}

// MARK: - csec protect --fly

func runProtectFly(storeOverride: String?, destOverride: String?, keepPlaintext: Bool, dryRun: Bool) -> Never {
    let configDirectory = FlyCLI.configDirectory(
        environment: ProcessInfo.processInfo.environment, homeDirectory: canonicalHomeDirectory())
    let configPath = displayFlyPath(FlyCLI.configPath(configDirectory: configDirectory))
    let snapshot: FlyConfigSnapshot
    do {
        snapshot = try FlyConfigSnapshot(configDirectory: configDirectory)
    } catch let error as ProtectError {
        protectFail("\(configPath): \(error.message)")
    } catch {
        protectFail("\(configPath): \(error.localizedDescription)")
    }
    let registered = readFlyRegistration(configDirectory: configDirectory)?.reference
    guard snapshot.tokens.accessToken != nil else {
        guard let registered else {
            protectFail("fly has no saved token in \(configPath); sign in with `fly auth login` first, "
                + "or run `csec fly register <reference>` for a token you already store")
        }
        if snapshot.tokens.hasMetricsToken, !keepPlaintext, !dryRun {
            do { try snapshot.blank() } catch let error as ProtectError { protectFail(error.message) }
            catch { protectFail(error.localizedDescription) }
        }
        FileHandle.standardOutput.write(Data(
            "csec protect --fly: fly already uses \(registered.safeInlineURI) through `csec fly`; nothing to do.\n".utf8))
        exit(0)
    }
    let target: FlyImportTarget
    do {
        target = try flyImportTarget(storeOverride: storeOverride, destOverride: destOverride, registered: registered)
    } catch let error as ProtectError { protectFail(error.message) }
    catch { protectFail(error.localizedDescription) }

    if dryRun {
        var output = "csec protect --fly (dry run):\n"
        output += "  fly's access_token  ->  \(target.display)  (protect + register for `csec fly`)\n"
        output += keepPlaintext
            ? "  \(configPath) left as it is (--keep-plaintext)\n"
            : "  then empty access_token and metrics_token in \(configPath), keeping every other setting\n"
        output += "  nothing changed (dry run)\n"
        FileHandle.standardOutput.write(Data(output.utf8))
        exit(0)
    }

    let result: FlyProtectionResult
    do {
        result = try protectFlyToken(snapshot: snapshot, target: target, keepPlaintext: keepPlaintext, client: makeAgentClient())
    } catch let error as FlyProtectionError { protectFail(error.message) }
    catch { protectFail("fly is unchanged: \(error.localizedDescription)") }

    var output = "csec protect --fly: protected fly's token as \(result.reference)\n"
    output += keepPlaintext
        ? "  \(configPath) still holds the token (--keep-plaintext); run `csec protect --fly` again to remove it\n"
        : "  emptied access_token and metrics_token in \(configPath)\n"
    if result.agentStopped {
        output += "  stopped fly's background agent, which held the old token\n"
    }
    output += flyAliasGuidance()
    output += "  `csec fly` runs fly with the token in FLY_API_TOKEN after one review per terminal session;\n"
        + "  other processes running as you can read fly's environment while it runs.\n"
    if FlyCLI.tokenVariables.contains(where: { ProcessInfo.processInfo.environment[$0] != nil }) {
        output += "  note: FLY_API_TOKEN or FLY_ACCESS_TOKEN is set in this shell; fly uses it instead. Remove it from your environment.\n"
    }
    output += "  This revokes nothing: a copy of the token taken before now still works until you revoke it.\n"
    FileHandle.standardOutput.write(Data(output.utf8))
    exit(0)
}

// MARK: - Shared with bulk protect

/// fly's config.yml, snapshotted before the review so the rewrite can refuse
/// a file that changed meanwhile. Never follows a leaf symlink or rewrites a
/// hardlinked file, which would leave the token in its other name.
struct FlyConfigSnapshot {
    let path: String
    let data: Data
    let info: stat
    let parentInfo: stat
    let tokens: FlyConfigTokens

    init(configDirectory: String) throws {
        try self.init(path: FlyCLI.configPath(configDirectory: configDirectory))
    }

    init(path rawPath: String) throws {
        let url = URL(fileURLWithPath: (rawPath as NSString).expandingTildeInPath).standardizedFileURL
        guard let parent = canonicalPath(url.deletingLastPathComponent().path) else {
            throw ProtectError(message: "fly's config directory does not exist")
        }
        path = (parent as NSString).appendingPathComponent(url.lastPathComponent)
        var parentStat = stat()
        guard lstat(parent, &parentStat) == 0, parentStat.st_mode & S_IFMT == S_IFDIR,
              parentStat.st_uid == getuid(), parentStat.st_mode & 0o022 == 0 else {
            throw ProtectError(message: "fly's config directory must be yours and not group/other-writable")
        }
        parentInfo = parentStat
        var current = stat()
        guard lstat(path, &current) == 0 else {
            throw ProtectError(message: "fly has no config.yml here; sign in with `fly auth login` first")
        }
        let read = try readRegularFile(atPath: path)
        guard read.info.st_nlink == 1, read.info.st_mode & 0o022 == 0 else {
            throw ProtectError(message: "csec refuses a hardlinked or group/other-writable config.yml")
        }
        data = read.data
        info = read.info
        do {
            tokens = try FlyConfigTokens(read.data)
        } catch let error as FlyConfigError {
            throw ProtectError(message: error.description)
        }
    }

    /// Empties both token lines, unless the file changed since the snapshot.
    func blank() throws {
        var current = stat()
        guard lstat(path, &current) == 0, sameProtectFileVersion(current, info),
              let read = try? readRegularFile(atPath: path), read.data == data else {
            throw ProtectError(message: "config.yml changed while csec was working; it was left untouched")
        }
        try writeFileAtomically(
            path: path, data: tokens.blanked(), mode: mode_t(info.st_mode & 0o7777),
            guardAgainst: info, guardParent: parentInfo)
    }
}

/// Where the token is imported, and under which key or field.
struct FlyImportTarget {
    let spec: SecretDestinationSpec
    let key: String
    /// Replace the value at the registered reference (a new login) rather
    /// than write beside a different one.
    let overwrite: Bool

    var display: String {
        switch spec {
        case .native(let store): return "csec://\(store.value)/\(key)"
        case .onePassword(let vault, let item): return "op://\(vault)/\(item)/\(key)"
        }
    }
}

/// An explicit `--store`/`--dest`; else where the registered reference
/// lives, so a new login replaces it; else csec's `fly` store.
func flyImportTarget(storeOverride: String?, destOverride: String?, registered: SecretRef?) throws -> FlyImportTarget {
    let registeredTarget = registered.flatMap(SecretDestinationSpec.writeTarget(for:))
    let spec: SecretDestinationSpec
    do {
        if let destOverride {
            spec = try SecretDestinationSpec.parse(destOverride, defaultItemTitle: "Fly.io")
        } else if let storeOverride {
            spec = .native(try NativeStoreName(storeOverride))
        } else if let registeredTarget {
            return FlyImportTarget(spec: registeredTarget.spec, key: registeredTarget.key, overwrite: true)
        } else if registered != nil {
            throw ProtectError(message: "the registered Fly token is in a store csec cannot write; "
                + "store the new token there yourself, or choose --store or --dest")
        } else {
            spec = .native(try NativeStoreName(FlyCLI.defaultStore))
        }
    } catch let error as ProtectError {
        throw error
    } catch {
        throw ProtectError(message: "invalid destination (\(error))")
    }
    let overwrite = registeredTarget.map { $0.spec == spec && $0.key == FlyCLI.defaultKey } ?? false
    return FlyImportTarget(spec: spec, key: FlyCLI.defaultKey, overwrite: overwrite)
}

struct FlyProtectionResult {
    let reference: String
    let blanked: Bool
    let agentStopped: Bool
}

struct FlyProtectionError: Error {
    let message: String
}

/// The value is durable at the destination before anything on disk changes:
/// commit, then register, then empty the file's token lines. A failure after
/// the commit leaves the plaintext where it was and says so.
func protectFlyToken(
    snapshot: FlyConfigSnapshot, target: FlyImportTarget, keepPlaintext: Bool, client: AgentClient
) throws -> FlyProtectionResult {
    guard let token = snapshot.tokens.accessToken else {
        throw FlyProtectionError(message: "fly has no saved token to protect")
    }
    let references: [String: String]
    do {
        let destination = try makeSecretWriteDestination(
            spec: target.spec, client: client, overwriteExisting: target.overwrite)
        references = try destination.commit(values: [target.key: token])
    } catch {
        throw FlyProtectionError(message: "fly is unchanged; the import did not complete: \(error.localizedDescription)")
    }
    guard let uri = references[target.key], let reference = try? SecretRef(uri) else {
        throw FlyProtectionError(message: "the import returned no reference; fly is unchanged")
    }
    let configDirectory = (snapshot.path as NSString).deletingLastPathComponent
    do {
        try writeFlyRegistration(reference, configDirectory: configDirectory)
    } catch {
        throw FlyProtectionError(message: "the token is stored as \(reference.uri), but the registration could not be "
            + "written (\(error.localizedDescription)); config.yml is unchanged. Run `csec fly register \(reference.uri)`")
    }
    if !keepPlaintext {
        do {
            try snapshot.blank()
        } catch {
            let detail = (error as? ProtectError)?.message ?? error.localizedDescription
            throw FlyProtectionError(message: "the token is stored and registered as \(reference.uri), but config.yml "
                + "still holds it: \(detail). Run `csec protect --fly` again to finish")
        }
    }
    return FlyProtectionResult(
        reference: reference.uri, blanked: !keepPlaintext,
        agentStopped: stopFlyDaemonAgent(configDirectory: configDirectory))
}

/// The shared daemon agent fly started before keeps the token it was given
/// in memory and serves it on its socket; stop it. Best effort: no fly, or
/// no agent running, is not a failure.
func stopFlyDaemonAgent(configDirectory: String) -> Bool {
    guard let path = try? ExecutableInspection.resolve(command: "fly") else { return false }
    var environment = ProcessInfo.processInfo.environment
    for name in FlyCLI.tokenVariables + [FlyCLI.isolatedAgentVariable] { environment.removeValue(forKey: name) }
    environment["FLY_CONFIG_DIR"] = configDirectory
    environment["FLY_NO_UPDATE_CHECK"] = "1"
    return GitHubCLI.capture(path, ["agent", "stop"], environment: environment).status == 0
}

func readFlyRegistration(configDirectory: String) -> FlyRegistration? {
    guard let (data, _) = try? readRegularFile(atPath: FlyCLI.registrationPath(configDirectory: configDirectory)) else {
        return nil
    }
    return FlyRegistration.decode(data)
}

func writeFlyRegistration(_ reference: SecretRef, configDirectory: String) throws {
    try writeFileAtomically(
        path: FlyCLI.registrationPath(configDirectory: configDirectory),
        data: FlyRegistration(reference: reference).encoded(), mode: 0o600)
}

@discardableResult
func removeFlyRegistration(configDirectory: String) throws -> Bool {
    let path = FlyCLI.registrationPath(configDirectory: configDirectory)
    guard unlink(path) == 0 else {
        if errno == ENOENT { return false }
        throw ProtectError(message: String(cString: strerror(errno)))
    }
    return true
}
