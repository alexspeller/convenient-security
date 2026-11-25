import ConvenientSecurity
import Foundation
#if canImport(Darwin)
import Darwin
#endif

// `csec identity`: this Mac as its own OpenID Connect issuer. csecd holds the
// Secure Enclave key and the catalog; this command manages them and writes
// the public files and tool configuration. Using a sign-in is not done here:
// it is a `csec-identity://` reference, delivered by `csec creds aws`,
// `csec creds google`, `csec exec --env` or `csec get` after the usual review.

private let defaultIdentityName = "default"

func runIdentity(_ arguments: [String]) -> Never {
    guard let action = arguments.first else { usage("identity") }
    let rest = Array(arguments.dropFirst())
    switch action {
    case "status":
        guard rest.isEmpty else { usage("identity") }
        let reply = identityRequest(MachineIdentityRequest(action: .status))
        print(identityStatusReport(reply.status), terminator: "")
        exit(0)
    case "create":
        runIdentityCreate(rest)
    case "remove":
        guard rest.count == 1 else { usage("identity") }
        let reply = identityRequest(MachineIdentityRequest(action: .remove, identity: rest[0]))
        print("Removed the machine identity \(rest[0]); its Secure Enclave key can never sign again.")
        if let revoked = reply.revokedGrants, revoked > 0 { print("Revoked \(revoked) grant(s) for its sign-ins.") }
        print("Remove its key from the published key set and from any cloud that trusts it.")
        exit(0)
    case "target":
        runIdentityTarget(rest)
    case "publish":
        runIdentityPublish(rest)
    case "check":
        guard rest.count <= 1 else { usage("identity") }
        let name = rest.first ?? defaultIdentityName
        guard let report = identityRequest(MachineIdentityRequest(action: .check, identity: name)).issuerReport else {
            identityFail("csecd did not report the issuer check")
        }
        print("\(report.identity) (\(report.issuer)): \(report.summary)")
        if report.compromiseSuspected {
            print("Whoever published those keys can sign in as \(report.identity) to every cloud that trusts this issuer.")
            print("If a key is yours (another Mac of yours), accept it by the thumbprint above: csec identity accept-key \(report.identity) <thumbprint>…")
            print("If it is not, remove it from the published key set now and review the issuer host's access.")
        }
        exit(report.clear ? 0 : 1)
    case "accept-key":
        guard rest.count >= 2 else { usage("identity") }
        _ = identityRequest(MachineIdentityRequest(action: .acceptKeys, identity: rest[0], kids: Array(rest.dropFirst())))
        print("Accepted; csec identity check no longer flags \(rest.count - 1 == 1 ? "that key" : "those keys").")
        exit(0)
    case "setup":
        runIdentitySetup(rest)
    default:
        usage("identity")
    }
}

private func identityFail(_ message: String) -> Never {
    csecError("identity", message)
    exit(1)
}

private func identityRequest(_ request: MachineIdentityRequest) -> MachineIdentityReply {
    do {
        return try makeAgentClient().machineIdentity(request)
    } catch {
        identityFail(error.localizedDescription)
    }
}

/// `<identity>/<target>`, or a whole `csec-identity://` reference.
private func parseTargetPath(_ argument: String) -> (identity: String, target: String)? {
    if argument.contains("://") {
        return (try? SecretRef(argument)).flatMap(MachineIdentityProvider.parse)
    }
    let parts = argument.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    guard parts.count == 2, MachineIdentityName.isValid(parts[0]), MachineIdentityName.isValid(parts[1]) else {
        return nil
    }
    return (parts[0], parts[1])
}

/// Options after positional words: `--name value` pairs and bare flags.
private func identityOptions(
    _ arguments: [String], values: Set<String>, flags: Set<String> = []
) -> (positional: [String], options: [String: String], flags: Set<String>) {
    var positional: [String] = []
    var options: [String: String] = [:]
    var seen: Set<String> = []
    var index = 0
    while index < arguments.count {
        let word = arguments[index]
        if values.contains(word) {
            index += 1
            guard index < arguments.count, options[word] == nil else { usage("identity") }
            options[word] = arguments[index]
        } else if flags.contains(word) {
            seen.insert(word)
        } else if word.hasPrefix("-") {
            usage("identity")
        } else {
            positional.append(word)
        }
        index += 1
    }
    return (positional, options, seen)
}

/// The subject a new identity signs in as by default: this Mac's name, in
/// characters every cloud's subject and member syntax accepts.
private func defaultSubject() -> String {
    let name = (Host.current().localizedName ?? ProcessInfo.processInfo.hostName).lowercased()
    var subject = ""
    for character in name {
        if character.isASCII, character.isLetter || character.isNumber || character == "." {
            subject.append(character)
        } else if !subject.hasSuffix("-") {
            subject.append("-")
        }
    }
    let trimmed = subject.trimmingCharacters(in: CharacterSet(charactersIn: "-."))
    return trimmed.isEmpty ? "mac" : String(trimmed.prefix(64))
}

// MARK: - create

private func runIdentityCreate(_ arguments: [String]) -> Never {
    let parsed = identityOptions(arguments, values: ["--issuer", "--subject"])
    guard parsed.positional.count <= 1, let issuer = parsed.options["--issuer"] else { usage("identity") }
    let name = parsed.positional.first ?? defaultIdentityName
    let subject = parsed.options["--subject"] ?? defaultSubject()
    let reply = identityRequest(MachineIdentityRequest(action: .create, identity: name, issuer: issuer, subject: subject))
    print("Created the machine identity \(name): this Mac signs in as \(subject), issued by \(issuer).")
    if reply.status?.hardwareKeys == false {
        print("This build has no Secure Enclave key: the identity lasts only until csecd restarts.")
    }
    print("Next: add a sign-in with csec identity target add \(name)/<target> …, then csec identity setup aws|google.")
    exit(0)
}

// MARK: - target

private func runIdentityTarget(_ arguments: [String]) -> Never {
    guard let action = arguments.first else { usage("identity") }
    let parsed = identityOptions(
        Array(arguments.dropFirst()), values: ["--audience", "--aws-role", "--region", "--lifetime"]
    )
    guard parsed.positional.count == 1, let path = parseTargetPath(parsed.positional[0]) else { usage("identity") }
    switch action {
    case "add":
        let lifetime: Int?
        if let raw = parsed.options["--lifetime"] {
            guard let seconds = Int(raw) else { usage("identity") }
            lifetime = seconds
        } else {
            lifetime = nil
        }
        let target: MachineIdentityTarget
        if let role = parsed.options["--aws-role"] {
            target = MachineIdentityTarget(
                name: path.target, identity: path.identity, kind: .aws,
                audience: parsed.options["--audience"] ?? MachineIdentityTarget.defaultAWSAudience,
                lifetime: lifetime ?? AWSWebIdentity.maximumDuration,
                roleARN: role, region: parsed.options["--region"] ?? MachineIdentityTarget.defaultAWSRegion
            )
        } else {
            guard let audience = parsed.options["--audience"], parsed.options["--region"] == nil else { usage("identity") }
            target = MachineIdentityTarget(
                name: path.target, identity: path.identity, audience: audience,
                lifetime: lifetime ?? MachineIdentityToken.defaultLifetime
            )
        }
        if let error = target.validationError { identityFail(error.message) }
        _ = identityRequest(MachineIdentityRequest(action: .addTarget, target: target))
        print("Added \(target.reference).")
        switch target.kind {
        case .aws:
            print("Next: csec identity setup aws \(path.identity)/\(path.target)")
        case .google:
            print("Use it with csec gcloud --item \(target.reference) -- <command>.")
        case .token:
            if (try? MachineIdentityGoogleSetup(issuer: "https://x", subject: "x", target: target)) != nil {
                print("Next: csec identity setup google \(path.identity)/\(path.target)")
            } else {
                print("Use it with csec exec --env NAME=\(target.reference) -- <command>, or csec get \(target.reference).")
            }
        }
        exit(0)
    case "remove":
        guard parsed.options.isEmpty else { usage("identity") }
        let reply = identityRequest(MachineIdentityRequest(
            action: .removeTarget, identity: path.identity, targetName: path.target
        ))
        print("Removed csec-identity://\(path.identity)/\(path.target).")
        if let revoked = reply.revokedGrants, revoked > 0 { print("Revoked \(revoked) grant(s) for it.") }
        exit(0)
    default:
        usage("identity")
    }
}

// MARK: - status

private func identityStatusReport(_ status: MachineIdentityStatus?) -> String {
    guard let status, !status.identities.isEmpty else {
        return "No machine identities. Create one with csec identity create --issuer <https-url>.\n"
    }
    var lines: [String] = []
    if !status.hardwareKeys {
        lines.append("Keys are software keys in this development build, kept only until csecd restarts.")
    } else if !status.persistent {
        lines.append("This csecd keeps machine identities only until it restarts.")
    }
    for identity in status.identities {
        lines.append("\(identity.name)")
        lines.append("  issuer:  \(identity.issuer)")
        lines.append("  subject: \(identity.subject)")
        for (index, key) in identity.keys.enumerated() {
            lines.append("  key:     \(key.kid)\(index == 0 ? "" : " (previous)")")
        }
        for kid in identity.acceptedKids {
            lines.append("  accepts: \(kid)")
        }
        let targets = status.targets.filter { $0.identity == identity.name }
        if targets.isEmpty {
            lines.append("  no sign-ins (csec identity target add \(identity.name)/<target> …)")
        }
        for target in targets {
            let minutes = target.lifetime / 60
            let what: String
            switch target.kind {
            case .aws:
                let role = target.roleARN.flatMap(AWSWebIdentity.roleName(ofRole:)) ?? "?"
                let account = target.roleARN.flatMap(AWSWebIdentity.accountID(ofRole:)) ?? "?"
                what = "AWS role \(role) in \(account), \(target.region ?? "?"), \(minutes) min"
            case .token:
                what = "token for \(target.audience), \(minutes) min"
            case .google:
                what = "Google access for \(target.googleServiceAccount ?? identity.subject), \(minutes) min"
            }
            lines.append("  \(target.reference)  \(what)")
        }
    }
    return lines.joined(separator: "\n") + "\n"
}

// MARK: - publish

private func identityStatus() -> MachineIdentityStatus {
    guard let status = identityRequest(MachineIdentityRequest(action: .status)).status else {
        identityFail("csecd did not report its machine identities")
    }
    return status
}

private func outputDirectory(_ option: String?) -> String {
    let path = ((option ?? FileManager.default.currentDirectoryPath) as NSString).expandingTildeInPath
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), isDirectory.boolValue else {
        identityFail("\(path) is not a directory")
    }
    return path
}

/// Public files only: the discovery document, key sets, policies and
/// credential configuration hold no secret.
private func writePublicFile(_ data: Data, named name: String, in directory: String, mode: mode_t = 0o644) -> String {
    let path = (directory as NSString).appendingPathComponent(name)
    do {
        try writeFileAtomically(path: path, data: data, mode: mode)
    } catch {
        identityFail("could not write \(path): \(error.localizedDescription)")
    }
    return path
}

private func writeIssuerFiles(identity name: String, directory: String) {
    let reply = identityRequest(MachineIdentityRequest(action: .publicFiles, identity: name))
    guard let discovery = reply.discoveryDocument, let keySet = reply.keySet else {
        identityFail("csecd did not return the issuer files")
    }
    print("Wrote \(writePublicFile(discovery, named: "openid-configuration", in: directory))")
    print("Wrote \(writePublicFile(keySet, named: "jwks.json", in: directory))")
}

private func printCommands(_ commands: [String]) {
    for command in commands { print("  \(command)") }
}

private func runIdentityPublish(_ arguments: [String]) -> Never {
    let parsed = identityOptions(arguments, values: ["--dir", "--s3-bucket", "--region", "--admin"])
    guard parsed.positional.count <= 1 else { usage("identity") }
    let name = parsed.positional.first ?? defaultIdentityName
    guard let identity = identityStatus().identities.first(where: { $0.name == name }) else {
        identityFail("no machine identity is named \(name)")
    }
    let directory = outputDirectory(parsed.options["--dir"])
    writeIssuerFiles(identity: name, directory: directory)
    if let bucket = parsed.options["--s3-bucket"] {
        guard let admin = parsed.options["--admin"] else {
            identityFail("--s3-bucket needs --admin <role-or-user-arn>: the one principal that may change the issuer")
        }
        let s3: MachineIdentityS3Issuer
        do {
            s3 = try MachineIdentityS3Issuer(
                bucket: bucket, region: parsed.options["--region"] ?? MachineIdentityTarget.defaultAWSRegion,
                administratorARN: admin
            )
        } catch let error as MachineIdentityS3Issuer.SetupError {
            identityFail(error.message)
        } catch {
            identityFail(error.localizedDescription)
        }
        guard s3.issuer == identity.issuer else {
            identityFail("\(name)'s issuer is \(identity.issuer), not \(s3.issuer); create an identity with --issuer \(s3.issuer) to publish it there")
        }
        do {
            print("Wrote \(writePublicFile(try s3.bucketPolicy(), named: "bucket-policy.json", in: directory))")
        } catch {
            identityFail("could not make the bucket policy")
        }
        print("")
        print("Run these in \(directory) as \(admin), with your own AWS credentials.")
        print("Only that principal can then change the issuer: whoever can change jwks.json can sign in as \(name).")
        printCommands(s3.setupCommands())
        print("")
        print("After a key change, publish again with:")
        printCommands(s3.publishCommands())
    } else {
        guard parsed.options["--region"] == nil, parsed.options["--admin"] == nil else { usage("identity") }
        print("")
        print("Serve them at \(identity.issuer)\(MachineIdentityIssuer.discoveryPath) and \(identity.issuer)\(MachineIdentityIssuer.keySetPath).")
        print("Any HTTPS host that serves static files works: an S3 bucket (csec identity publish --s3-bucket …),")
        print("GitHub Pages, Cloudflare Pages or your own web server. Whoever can change jwks.json there can sign in")
        print("as \(name) to every cloud that trusts it, so keep write access to that host to yourself.")
        print("Google Cloud needs no hosting: csec identity setup google uploads the key set instead.")
    }
    print("")
    print("Check what the issuer serves at any time with csec identity check \(name).")
    exit(0)
}

// MARK: - setup

private func runIdentitySetup(_ arguments: [String]) -> Never {
    guard let cloud = arguments.first else { usage("identity") }
    let parsed = identityOptions(
        Array(arguments.dropFirst()), values: ["--profile", "--service-account", "--dir", "--file"]
    )
    guard parsed.positional.count == 1, let path = parseTargetPath(parsed.positional[0]) else { usage("identity") }
    let status = identityStatus()
    guard let identity = status.identities.first(where: { $0.name == path.identity }) else {
        identityFail("no machine identity is named \(path.identity)")
    }
    guard let target = status.targets.first(where: { $0.identity == path.identity && $0.name == path.target }) else {
        identityFail("no target is named \(path.identity)/\(path.target)")
    }
    let directory = outputDirectory(parsed.options["--dir"])
    switch cloud {
    case "aws":
        guard parsed.options["--service-account"] == nil, parsed.options["--file"] == nil else { usage("identity") }
        setupAWS(identity: identity, target: target, profile: parsed.options["--profile"] ?? target.name, directory: directory)
    case "google":
        guard parsed.options["--profile"] == nil else { usage("identity") }
        setupGoogle(
            identity: identity, target: target, serviceAccount: parsed.options["--service-account"],
            file: parsed.options["--file"], directory: directory
        )
    default:
        usage("identity")
    }
}

private func setupAWS(identity: MachineIdentitySummary, target: MachineIdentityTarget, profile: String, directory: String) -> Never {
    let setup: MachineIdentityAWSSetup
    do {
        setup = try MachineIdentityAWSSetup(issuer: identity.issuer, subject: identity.subject, target: target)
    } catch let error as MachineIdentitySetupError {
        identityFail(error.message)
    } catch {
        identityFail(error.localizedDescription)
    }
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let configPath = awsConfigurationPath(homeDirectory: home)
    let configDirectory = (configPath as NSString).deletingLastPathComponent
    do {
        if !FileManager.default.fileExists(atPath: configDirectory) {
            try FileManager.default.createDirectory(
                atPath: configDirectory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]
            )
        }
        let config = try AWSProtectionFile(path: configPath, allowMissing: true)
        let updated = try setup.configuration(config.data, profile: profile, executable: currentExecutablePath())
        if updated.changed {
            try config.write(updated.data)
            print("Added the profile \(profile) to \(config.path): credential_process asks csec for \(target.reference).")
        } else {
            print("The profile \(profile) in \(config.path) already uses \(target.reference).")
        }
    } catch let error as MachineIdentitySetupError {
        identityFail(error.message)
    } catch {
        identityFail("could not update the AWS config: \(error.localizedDescription)")
    }
    do {
        print("Wrote \(writePublicFile(try setup.trustPolicy(), named: "trust-policy.json", in: directory))")
    } catch {
        identityFail("could not make the trust policy")
    }
    writeIssuerFiles(identity: identity.name, directory: directory)
    print("")
    print("In AWS, run these in \(directory) with your own administrator credentials:")
    printCommands(setup.commands())
    print("For a role that already exists, set its trust policy instead:")
    printCommands([setup.updateTrustCommand()])
    print("Then attach the permissions the role should have. The IAM OIDC provider is made once per issuer and account.")
    print("")
    print("AWS fetches the issuer's keys, so publish them first: csec identity publish \(identity.name) (and csec identity check \(identity.name)).")
    print("Then: aws sts get-caller-identity --profile \(profile)")
    print("The first use in each terminal or Claude Code session asks you to approve; the credentials stay out of files.")
    exit(0)
}

private func setupGoogle(
    identity: MachineIdentitySummary, target: MachineIdentityTarget, serviceAccount: String?,
    file: String?, directory: String
) -> Never {
    let setup: MachineIdentityGoogleSetup
    let configuration: Data
    let gcloudTarget: MachineIdentityTarget
    do {
        setup = try MachineIdentityGoogleSetup(issuer: identity.issuer, subject: identity.subject, target: target)
        configuration = try setup.credentialConfiguration(executable: currentExecutablePath(), serviceAccount: serviceAccount)
        gcloudTarget = try setup.gcloudTarget(serviceAccount: serviceAccount)
    } catch let error as MachineIdentitySetupError {
        identityFail(error.message)
    } catch {
        identityFail(error.localizedDescription)
    }
    let environment = ProcessInfo.processInfo.environment
    let gcloudDirectory = environment["CLOUDSDK_CONFIG"]
        ?? (FileManager.default.homeDirectoryForCurrentUser.path as NSString).appendingPathComponent(".config/gcloud")
    let credentialPath = (file.map { path -> String in
        let expanded = (path as NSString).expandingTildeInPath
        return expanded.hasPrefix("/")
            ? expanded
            : (FileManager.default.currentDirectoryPath as NSString).appendingPathComponent(expanded)
    }) ?? (gcloudDirectory as NSString).appendingPathComponent("csec-\(identity.name)-\(target.name).json")
    let credentialDirectory = (credentialPath as NSString).deletingLastPathComponent
    let status = identityStatus()
    if let existing = status.targets.first(where: { $0.identity == gcloudTarget.identity && $0.name == gcloudTarget.name }) {
        guard existing == gcloudTarget else {
            identityFail("\(gcloudTarget.reference) already has a different sign-in; remove that target explicitly or choose a new source target")
        }
    } else {
        _ = identityRequest(MachineIdentityRequest(action: .addTarget, target: gcloudTarget))
    }
    do {
        try FileManager.default.createDirectory(
            atPath: credentialDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
    } catch {
        identityFail("could not make \(credentialDirectory)")
    }
    print("Wrote \(writePublicFile(configuration, named: (credentialPath as NSString).lastPathComponent, in: credentialDirectory, mode: 0o600))")
    let shellFiles: (fish: String, sh: String)
    do {
        shellFiles = try installGcloudShellFunction(reference: gcloudTarget.reference)
    } catch {
        identityFail("could not install the gcloud shell function: \(error.localizedDescription)")
    }
    writeIssuerFiles(identity: identity.name, directory: directory)
    print("")
    print("In Google Cloud, run these in \(directory) with your own administrator credentials.")
    print("The key set is uploaded, so the issuer needs no hosting:")
    printCommands(setup.commands(serviceAccount: serviceAccount).map { "command " + $0 })
    if serviceAccount == nil {
        print("Then grant roles to this Mac directly, for example:")
        printCommands([MachineIdentityShell.command([
            "command", "gcloud", "projects", "add-iam-policy-binding", setup.projectNumber,
            "--member=\(setup.principal)", "--role=roles/viewer",
        ])])
    }
    print("After a key change, upload the key set again:")
    printCommands(["command " + setup.updateKeysCommand()])
    print("")
    print("Google's tools run csec only where \(MachineIdentityGoogleSetup.allowExecutablesVariable)=1 is set:")
    print("  fish:     set -Ux \(MachineIdentityGoogleSetup.allowExecutablesVariable) 1")
    print("  zsh/bash: export \(MachineIdentityGoogleSetup.allowExecutablesVariable)=1   (in ~/.zshrc or ~/.bashrc)")
    print("Point the client libraries at GOOGLE_APPLICATION_CREDENTIALS=\(MachineIdentityShell.quote(credentialPath)).")
    print("Installed gcloud's shell function for fish, zsh and bash. Open a new terminal, or activate it here:")
    print("  fish:     source \(MachineIdentityShell.quote(shellFiles.fish))")
    print("  zsh/bash: . \(MachineIdentityShell.quote(shellFiles.sh))")
    print("Then use gcloud normally. Its first use in each terminal or Claude Code session asks you to approve.")
    print("csecd exchanges the token and keeps it in memory. The wrapper writes no access token or gcloud file log.")
    print("The token is in gcloud's process environment, visible to same-user process inspection; it expires within an hour.")
    print("Use gcloud storage instead of gsutil; use the Google client libraries for BigQuery. Auth/config commands,")
    print("gcloud-side impersonation and commands longer than the token's lifetime are not supported by this wrapper.")
    print("A direct 'command gcloud' bypasses it. Old gcloud/gsutil credentials and cached tokens are left as found.")
    exit(0)
}

/// Public configuration only. Existing startup files are snapshotted and
/// replaced with the same race/symlink guards as other CLI configuration.
private func installGcloudShellFunction(reference: String) throws -> (fish: String, sh: String) {
    let environment = ProcessInfo.processInfo.environment
    let home = environment["HOME"] ?? FileManager.default.homeDirectoryForCurrentUser.path
    let config = environment["XDG_CONFIG_HOME"] ?? (home as NSString).appendingPathComponent(".config")
    let zsh = environment["ZDOTDIR"] ?? home
    guard home.hasPrefix("/"), config.hasPrefix("/"), zsh.hasPrefix("/") else { throw MachineIdentitySetupError.invalidCommand }
    let directory = (config as NSString).appendingPathComponent("csec")
    let fishDirectory = (config as NSString).appendingPathComponent("fish/conf.d")
    for path in [directory, fishDirectory] {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    let shPath = (directory as NSString).appendingPathComponent("gcloud.sh")
    let fishPath = (fishDirectory as NSString).appendingPathComponent("csec-gcloud.fish")
    var changes: [(AWSProtectionFile, Data)] = []
    for (path, fish) in [(shPath, false), (fishPath, true)] {
        let file = try AWSProtectionFile(path: path, allowMissing: true)
        changes.append((file, Data(GcloudCommand.shellFunction(
            executable: currentExecutablePath(), reference: reference, fish: fish
        ).utf8)))
    }
    for path in [(zsh as NSString).appendingPathComponent(".zshrc"),
                 (home as NSString).appendingPathComponent(".bashrc"),
                 (home as NSString).appendingPathComponent(".bash_profile")] {
        let file = try AWSProtectionFile(path: path, allowMissing: true)
        guard let text = String(data: file.data, encoding: .utf8) else { throw MachineIdentitySetupError.invalidCommand }
        changes.append((file, Data(try GcloudCommand.shellStartup(text, sourcePath: shPath).utf8)))
    }
    for (file, data) in changes { try file.write(data) }
    return (fishPath, shPath)
}
