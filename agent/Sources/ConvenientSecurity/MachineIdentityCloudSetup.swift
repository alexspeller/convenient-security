import Foundation

// What `csec identity setup aws|google` writes and prints. csec configures the
// tools on this Mac (an AWS profile, Google's library file and wrapper) and prints the
// cloud-side commands for the human to run with their own administrator
// credentials: csec never holds cloud administrator credentials, and the
// trust it sets up is the human's to grant. Everything here is public
// metadata: issuer URLs, subjects, role ARNs and the csec command line.

// MARK: - Shell quoting for printed commands

public enum MachineIdentityShell {
    /// A word that pastes into bash, zsh and fish unchanged: safe characters
    /// bare, anything else in single quotes. A single quote or backslash is
    /// written outside the quotes, escaped, because fish (unlike bash and zsh)
    /// reads a backslash inside single quotes as an escape.
    public static func quote(_ word: String) -> String {
        let safe = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=@,+%")
        if !word.isEmpty, word.allSatisfy({ safe.contains($0) }) { return word }
        var result = ""
        var run = ""
        func flush() {
            if !run.isEmpty { result += "'" + run + "'" }
            run = ""
        }
        for character in word {
            if character == "'" || character == "\\" {
                flush()
                result += "\\" + String(character)
            } else {
                run.append(character)
            }
        }
        flush()
        return result.isEmpty ? "''" : result
    }

    public static func command(_ words: [String]) -> String {
        words.map(quote).joined(separator: " ")
    }
}

public enum MachineIdentitySetupError: Error, Equatable, Sendable {
    case notAWSTarget
    case notGoogleAudience
    case invalidProfile
    case profileExists(String)
    case invalidCommand
    case invalidServiceAccount
    case invalidGcloudTargetName

    public var message: String {
        switch self {
        case .notAWSTarget:
            return "this is not an AWS target (add one with csec identity target add <identity>/<target> --aws-role <role-arn>)"
        case .notGoogleAudience:
            return "a Google target's audience is its workload identity provider: //iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>"
        case .invalidProfile:
            return "an AWS profile name is 1 to 64 letters, digits, '-', '_' or '.'"
        case let .profileExists(name):
            return "the AWS profile \(name) already has settings of its own; choose another with --profile"
        case .invalidCommand:
            return "the csec path or reference cannot be written into a credential command (no spaces, quotes or backslashes)"
        case .invalidServiceAccount:
            return "a service account looks like name@project.iam.gserviceaccount.com"
        case .invalidGcloudTargetName:
            return "use a target name of at most 57 characters so setup can register its separate -gcloud sign-in"
        }
    }
}

// MARK: - AWS

public struct MachineIdentityAWSSetup: Sendable {
    public let issuer: String
    public let subject: String
    public let target: MachineIdentityTarget
    public let roleARN: String

    public init(issuer: String, subject: String, target: MachineIdentityTarget) throws {
        guard target.kind == .aws, let roleARN = target.roleARN, target.validationError == nil else {
            throw MachineIdentitySetupError.notAWSTarget
        }
        self.issuer = issuer
        self.subject = subject
        self.target = target
        self.roleARN = roleARN
    }

    /// The issuer as IAM names it: host and path, without `https://`. It
    /// prefixes the trust policy's condition keys.
    public var providerName: String { String(issuer.dropFirst("https://".count)) }

    private var partition: String { String(roleARN.split(separator: ":")[1]) }
    private var account: String { AWSWebIdentity.accountID(ofRole: roleARN) ?? "" }
    public var roleName: String { AWSWebIdentity.roleName(ofRole: roleARN) ?? "" }

    /// The role's path: what lies between `role/` and its name, `/` if none.
    private var rolePath: String {
        let afterRole = roleARN.split(separator: ":", maxSplits: 5, omittingEmptySubsequences: false)[5].dropFirst("role/".count)
        let segments = afterRole.split(separator: "/")
        guard segments.count > 1 else { return "/" }
        return "/" + segments.dropLast().joined(separator: "/") + "/"
    }

    public var providerARN: String { "arn:\(partition):iam::\(account):oidc-provider/\(providerName)" }

    /// Admits exactly this Mac's subject and the target's audience, from this
    /// issuer: another Mac publishing to the same issuer gets nothing.
    public func trustPolicy() throws -> Data {
        let policy: [String: Any] = [
            "Version": "2012-10-17",
            "Statement": [[
                "Sid": "SignInAsThisMac",
                "Effect": "Allow",
                "Principal": ["Federated": providerARN],
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": ["StringEquals": [
                    "\(providerName):aud": target.audience,
                    "\(providerName):sub": subject,
                ]],
            ]],
        ]
        return try JSONSerialization.data(withJSONObject: policy, options: [.sortedKeys, .withoutEscapingSlashes, .prettyPrinted])
    }

    /// The commands, for a trust policy written as `trust-policy.json`. The
    /// provider is created once per issuer and account; a second target only
    /// needs its own role.
    public func commands() -> [String] {
        var createRole = ["aws", "iam", "create-role", "--role-name", roleName,
                          "--assume-role-policy-document", "file://trust-policy.json"]
        if rolePath != "/" { createRole += ["--path", rolePath] }
        return [
            MachineIdentityShell.command(["aws", "iam", "create-open-id-connect-provider",
                                          "--url", issuer, "--client-id-list", target.audience]),
            MachineIdentityShell.command(createRole),
        ]
    }

    /// For a role that already exists.
    public func updateTrustCommand() -> String {
        MachineIdentityShell.command(["aws", "iam", "update-assume-role-policy", "--role-name", roleName,
                                      "--policy-document", "file://trust-policy.json"])
    }

    /// The profile `credential_process` line: AWS splits it as argv, never
    /// through a shell.
    public func credentialProcess(executable: String) throws -> String {
        do {
            return try AWSCredentialMigration.command(executable: executable, reference: target.reference)
        } catch {
            throw MachineIdentitySetupError.invalidCommand
        }
    }

    /// `config` with `[profile <name>]` added for this target, or unchanged
    /// when that profile already says exactly this. A profile with settings of
    /// its own is never rewritten.
    public func configuration(_ config: Data, profile: String, executable: String) throws -> (data: Data, changed: Bool) {
        guard (1...64).contains(profile.utf8.count),
              profile.utf8.allSatisfy({ ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a)
                  || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2d || $0 == 0x5f || $0 == 0x2e }) else {
            throw MachineIdentitySetupError.invalidProfile
        }
        let command = try credentialProcess(executable: executable)
        let section = profile == "default" ? "default" : "profile " + profile
        let settings = ["credential_process": command, "region": target.region ?? MachineIdentityTarget.defaultAWSRegion]
        guard let result = try AWSCredentialMigration.configurationAddingSection(config, section: section, settings: settings) else {
            throw MachineIdentitySetupError.profileExists(profile)
        }
        return result
    }
}

// MARK: - Google Cloud

public struct MachineIdentityGoogleSetup: Sendable {
    public static let tokenURL = "https://sts.googleapis.com/v1/token"
    public static let subjectTokenType = "urn:ietf:params:oauth:token-type:jwt"
    /// google-auth's ceiling for an executable source, so a review on the
    /// Mac or the phone has time to be answered (the default is 30 s).
    public static let executableTimeoutMillis = 120_000
    public static let allowExecutablesVariable = "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"

    public let issuer: String
    public let subject: String
    public let target: MachineIdentityTarget
    public let projectNumber: String
    public let pool: String
    public let provider: String

    public init(issuer: String, subject: String, target: MachineIdentityTarget) throws {
        guard target.kind == .token else { throw MachineIdentitySetupError.notGoogleAudience }
        let provider = try GoogleWorkloadIdentityProvider(target.audience)
        self.issuer = issuer
        self.subject = subject
        self.target = target
        projectNumber = provider.projectNumber
        pool = provider.pool
        self.provider = provider.provider
    }

    /// The provider's resource name, as Google's STS takes it.
    public var audience: String {
        "//iam.googleapis.com/projects/\(projectNumber)/locations/global/workloadIdentityPools/\(pool)/providers/\(provider)"
    }

    public var principal: String {
        "principal://iam.googleapis.com/projects/\(projectNumber)/locations/global/workloadIdentityPools/\(pool)/subject/\(subject)"
    }

    static func isServiceAccount(_ email: String) -> Bool {
        let parts = email.split(separator: "@", omittingEmptySubsequences: false)
        return parts.count == 2 && !parts[0].isEmpty && parts[1].hasSuffix(".iam.gserviceaccount.com")
            && email.utf8.count <= 254
            && email.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2d || $0 == 0x2e || $0 == 0x40 }
    }

    /// Keep the libraries' OIDC reference intact. gcloud has its own canonical
    /// reference, so its service account and exchange are part of the grant.
    public func gcloudTarget(serviceAccount: String?) throws -> MachineIdentityTarget {
        guard target.name.utf8.count <= 57 else { throw MachineIdentitySetupError.invalidGcloudTargetName }
        if let serviceAccount, !Self.isServiceAccount(serviceAccount) { throw MachineIdentitySetupError.invalidServiceAccount }
        return MachineIdentityTarget(
            name: target.name + "-gcloud", identity: target.identity, kind: .google,
            audience: target.audience, lifetime: GoogleWebIdentity.lifetime, googleServiceAccount: serviceAccount
        )
    }

    /// The external-account credential file the client libraries
    /// read. Its executable source runs `csec creds google`; there is no
    /// output file, so the token csec prints is never written to disk. The
    /// access token a library exchanges it for stays in its memory. gcloud
    /// instead uses setup's shell wrapper and the separate access-token target.
    public func credentialConfiguration(executable: String, serviceAccount: String?) throws -> Data {
        if let serviceAccount, !Self.isServiceAccount(serviceAccount) { throw MachineIdentitySetupError.invalidServiceAccount }
        func word(_ value: String) throws -> String {
            // Python's google-auth splits the command with shlex, but Go's
            // (the Terraform provider, the Go client libraries) splits it on
            // whitespace with no quoting at all, so every word goes in bare and
            // nothing either would read differently is allowed.
            guard !value.isEmpty, value.unicodeScalars.allSatisfy({
                $0.isASCII && $0.value > 0x20 && $0.value < 0x7f && !"\"'\\#$`".unicodeScalars.contains($0)
            }) else {
                throw MachineIdentitySetupError.invalidCommand
            }
            return value
        }
        guard executable.hasPrefix("/") else { throw MachineIdentitySetupError.invalidCommand }
        let command = try word(executable) + " creds google --item " + word(target.reference)
        var configuration: [String: Any] = [
            "type": "external_account",
            "audience": audience,
            "subject_token_type": Self.subjectTokenType,
            "token_url": Self.tokenURL,
            "credential_source": [
                "executable": ["command": command, "timeout_millis": Self.executableTimeoutMillis],
            ],
        ]
        if let serviceAccount {
            configuration["service_account_impersonation_url"] =
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/\(serviceAccount):generateAccessToken"
        }
        return try JSONSerialization.data(withJSONObject: configuration, options: [.sortedKeys, .withoutEscapingSlashes, .prettyPrinted])
    }

    /// The pool's resource name. gcloud's `iam` commands refuse a project
    /// number in `--project` (they want the ID, which the audience doesn't
    /// carry), but take a resource name with the number in it.
    var poolName: String { "projects/\(projectNumber)/locations/global/workloadIdentityPools/\(pool)" }

    /// The commands, for a key set written as `jwks.json`. The keys are
    /// uploaded, so Google never fetches the issuer: nothing has to be hosted.
    public func commands(serviceAccount: String?) -> [String] {
        var commands = [
            MachineIdentityShell.command(["gcloud", "iam", "workload-identity-pools", "create", poolName,
                                          "--display-name=csec machine identities"]),
            MachineIdentityShell.command(["gcloud", "iam", "workload-identity-pools", "providers", "create-oidc",
                                          "\(poolName)/providers/\(provider)", "--issuer-uri=\(issuer)",
                                          "--allowed-audiences=\(target.audience)",
                                          "--attribute-mapping=google.subject=assertion.sub",
                                          "--jwk-json-path=jwks.json"]),
        ]
        if let serviceAccount {
            commands.append(MachineIdentityShell.command([
                "gcloud", "iam", "service-accounts", "add-iam-policy-binding", serviceAccount,
                "--role=roles/iam.workloadIdentityUser", "--member=\(principal)",
            ]))
        }
        return commands
    }

    /// After a key change: upload the new key set.
    public func updateKeysCommand() -> String {
        MachineIdentityShell.command(["gcloud", "iam", "workload-identity-pools", "providers", "update-oidc",
                                      "\(poolName)/providers/\(provider)", "--jwk-json-path=jwks.json"])
    }
}

// MARK: - Google executable-source reply

/// What `csec creds google` prints: google-auth's executable-source reply,
/// version 1, carrying an OIDC token. No `expiration_time`: there is no output
/// file to cache it in, and the library runs the executable again whenever it
/// needs a new access token.
public enum GoogleExecutableCredential {
    public static let maximumTokenBytes = 16 * 1_024

    public static func render(token: String) throws -> Data {
        guard !token.isEmpty, token.utf8.count <= maximumTokenBytes,
              token.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) else {
            throw SecureDeliveryError.invalidGoogleToken
        }
        let reply: [String: Any] = [
            "version": 1,
            "success": true,
            "token_type": MachineIdentityGoogleSetup.subjectTokenType,
            "id_token": token,
        ]
        var data = try JSONSerialization.data(withJSONObject: reply, options: [.sortedKeys, .withoutEscapingSlashes])
        data.append(0x0a)
        return data
    }
}
