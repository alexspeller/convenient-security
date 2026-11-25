import ConvenientSecurity
import Foundation

func awsCredentialMigrationTests() {
    print("\n# Explicit file protection and complete AWS migration")
    let home = "/synthetic/home"
    // Joined rather than added: a long `+` chain of literals can exceed the
    // type checker's time limit on a heavily loaded Mac.
    let sourceLines: [String] = [
        "# keep header", "[default]",
        "aws_access_key_id = SYNTHETIC", "aws_secret_access_key = synthetic-secret",
        "aws_session_token = synthetic-session", "region = eu-west-1",
        "[work/a]", "aws_access_key_id = SYNTHETIC2", "aws_secret_access_key = synthetic2",
        "[work_a]", "aws_access_key_id = SYNTHETIC3", "aws_secret_access_key = synthetic3",
        "[sso]", "sso_session = session",
        "[role]", "role_arn = arn:synthetic", "source_profile = default",
    ]
    let source = Data(sourceLines.map { $0 + "\r\n" }.joined().utf8)
    let configLines: [String] = [
        "# config comment", "[default]", "region = eu-west-1",
        "s3 =", "    addressing_style = path",
        "[profile other]", "credential_process = /existing/helper",
    ]
    let config = Data(configLines.map { $0 + "\r\n" }.joined().utf8)
    func plan(_ bytes: Data = source, config: Data = Data(), scheme: String = "op") throws -> AWSCredentialMigration {
        try AWSCredentialMigration(
            credentialsData: bytes, configurationData: config,
            sourcePath: home + "/.aws/credentials", csecExecutablePath: "/App With Spaces/csec",
            referenceForKey: { try SecretRef(scheme == "op" ? "op://vault/item/" + $0 : "csec://test/" + $0) })
    }
    do {
        for scheme in ["op", "csec"] {
            let migration = try plan(config: config, scheme: scheme)
            check(migration.importedProfiles == ["default", "work/a", "work_a"]
                  && migration.skippedProfiles == ["sso", "role"],
                  "AWS migration imports static profiles and preserves derived profiles for \(scheme)")
            check(migration.values.count == 3 && migration.references.count == 3,
                  "profile names that sanitize identically retain distinct bundle keys")
            let rewritten = String(decoding: migration.credentials, as: UTF8.self)
            check(!rewritten.contains("synthetic-secret") && !rewritten.contains("aws_session_token")
                  && rewritten.contains("# keep header\r\n[default]\r\nregion = eu-west-1\r\n")
                  && rewritten.contains("[role]\r\nrole_arn = arn:synthetic\r\nsource_profile = default\r\n"),
                  "cleanup removes only migrated static fields, preserving CRLF, comments, settings and roles")
            let configured = String(decoding: migration.configuration, as: UTF8.self)
            check(configured.contains("[default]\r\ncredential_process = \"/App With Spaces/csec\" creds aws --item \"\(scheme)://")
                  && configured.contains("[profile work/a]\r\n")
                  && configured.contains("s3 =\r\n    addressing_style = path\r\n")
                  && configured.contains("[profile other]\r\ncredential_process = /existing/helper\r\n"),
                  "AWS config uses correct section names and quoting, preserving unrelated settings")
            let retry = try plan(config: migration.configuration, scheme: scheme)
            check(retry.configuration == migration.configuration && retry.references == migration.references,
                  "retry after config installation reuses the identical process references")
            let complete = try plan(migration.credentials, config: migration.configuration, scheme: scheme)
            check(complete.values.isEmpty && complete.configuration == migration.configuration
                  && complete.credentials == migration.credentials,
                  "repeating a completed migration changes nothing")

            var steps: [String] = []
            try migration.apply(keepPlaintext: false,
                validateSources: { steps.append("validate") },
                commit: { _ in steps.append("import"); return migration.references },
                writeConfiguration: { _ in steps.append("config") },
                writeCredentials: { _ in steps.append("cleanup") })
            check(steps == ["validate", "import", "validate", "config", "cleanup"],
                  "migration commits storage and config before plaintext cleanup")
            steps = []
            try migration.apply(keepPlaintext: true, validateSources: {},
                commit: { _ in migration.references }, writeConfiguration: { _ in steps.append("config") },
                writeCredentials: { _ in steps.append("cleanup") })
            check(steps == ["config"], "keep-plaintext configures AWS without removing static keys")
        }
        let migration = try plan()
        let indented = try plan(config: Data("[default]\n    region = eu-west-1\n".utf8))
        let indentedRetry = try plan(config: indented.configuration)
        check(indentedRetry.configuration == indented.configuration
              && String(decoding: indented.configuration, as: UTF8.self)
                .contains("\n    credential_process = "),
              "an indented config keeps settings separate from the credential_process argv")
        enum Failure: Error { case injected }
        for failAt in ["validate", "import", "revalidate", "config", "cleanup"] {
            var calls: [String] = []
            func step(_ name: String) throws {
                calls.append(name)
                if failAt == name { throw Failure.injected }
            }
            checkThrows("AWS failure at \(failAt) stops subsequent mutation") {
                try migration.apply(keepPlaintext: false,
                    validateSources: { try step(calls.isEmpty ? "validate" : "revalidate") },
                    commit: { _ in try step("import"); return migration.references },
                    writeConfiguration: { _ in try step("config") },
                    writeCredentials: { _ in try step("cleanup") })
            }
            check(calls.last == failAt, "no AWS stage runs after a \(failAt) failure")
        }
        var wrote = false
        checkThrows("missing or unexpected references prevent every file write") {
            try migration.apply(keepPlaintext: false, validateSources: {}, commit: { _ in [:] },
                writeConfiguration: { _ in wrote = true }, writeCredentials: { _ in wrote = true })
        }
        check(!wrote, "failed reference validation retains both original files")
        check(AWSCredentialMigration.bundleKey(sourcePath: "/a", profile: "b")
              != AWSCredentialMigration.bundleKey(sourcePath: "/b", profile: "b"),
              "AWS bundle keys include the source file identity")
        let roleConfig = Data("[default]\nrole_arn = arn:synthetic\nsource_profile = base\n".utf8)
        let rolePlan = try plan(config: roleConfig)
        check(rolePlan.skippedProfiles.contains("default") && rolePlan.configuration.starts(with: roleConfig),
              "derived markers in the separate config preserve a profile's current behavior")
    } catch { check(false, "AWS migration fixtures succeed (\(error))") }

    for malformed in [
        "[default]\naws_access_key_id=a\naws_access_key_id=b\n",
        "[default]\n[default]\n",
        "[profile wrong]\naws_access_key_id=a\naws_secret_access_key=b\n",
        "[default]\naws_access_key_id=a\n  aws_secret_access_key=b\n",
        "[default]\naws_access_key_id=a\naws_secret_access_key=b\naws_session_token=\n  multiline-token\n",
        "[default]\ninvalid line\n",
    ] {
        checkThrows("ambiguous AWS syntax is rejected before migration") { _ = try plan(Data(malformed.utf8)) }
    }
    for conflicting in [
        "[default]\ncredential_process=/different/helper\n",
        "[default]\naws_access_key_id=other\naws_secret_access_key=other\n",
    ] {
        checkThrows("conflicting AWS config is never overwritten") { _ = try plan(config: Data(conflicting.utf8)) }
    }
    checkThrows("newline-bearing executable paths cannot inject config directives") {
        _ = try AWSCredentialMigration.command(executable: "/csec\nmalicious", reference: "op://v/i/f")
    }
    func classify(_ path: String, data: Data = source, env: [String: String] = [:]) -> CredentialDelivery {
        SecretFileDiscoveryEngine.explicitFile(path: path, data: data, mode: 0o600,
            homeDirectory: home, environment: env).suggestedApproach
    }
    check(classify(home + "/.aws/credentials") == .credsAws,
          "explicit AWS standard path selects the catalog handler")
    check(classify("/elsewhere/custom", env: ["AWS_SHARED_CREDENTIALS_FILE": "/elsewhere/custom"]) == .credsAws,
          "explicit AWS override outside home selects the catalog handler")
    check(classify("/elsewhere/opaque") == .wholeFile,
          "unknown explicit file outside home keeps whole-file protection")
    check(classify("/elsewhere/.env", data: Data("SECRET_TOKEN=synthetic\n".utf8)) == .perVar,
          "explicit dotenv file outside cwd selects per-variable protection")
    check(classify("/elsewhere/staging.env", data: Data("SECRET_TOKEN=synthetic\n".utf8)) == .perVar,
          "explicit <name>.env file selects per-variable protection")
}
