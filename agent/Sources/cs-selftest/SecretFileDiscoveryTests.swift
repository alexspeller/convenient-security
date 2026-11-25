import ConvenientSecurity
import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// File-level discovery (setup bulk-protect Phase A): a synthetic home tree
/// exercises kind classification, catalog probes inside walk-excluded trees,
/// env overrides, keychain-fallback flagging, per-var/whole-file/suppressed
/// env classification, symlink + hardlink dedupe, full traversal, and the no-secret-
/// output discipline (marker values never appear in the report).
func secretFileDiscoveryTests() {
    print("\n# Secret-file discovery (bulk-protect Phase A)")

    let markerValue = "MARKER-cocke-secret-77e0f1"
    let home = NSTemporaryDirectory()
        + "csec-discovery-home-\(UUID().uuidString.lowercased())"
    let fm = FileManager.default
    defer { try? fm.removeItem(atPath: home) }

    func write(_ relative: String, _ content: String, mode: Int16 = 0o600) {
        let path = home + "/" + relative
        try? fm.createDirectory(
            atPath: (path as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true)
        fm.createFile(
            atPath: path, contents: Data(content.utf8),
            attributes: [.posixPermissions: NSNumber(value: mode)])
    }

    // Project-level files reached by the walk.
    write("projects/app/.envrc", "export SECRET_TOKEN=\(markerValue)\nuse_flake\n")
    write("projects/app/.env", "DB_TOKEN=\"$(op read op://v/i/f)\"\n")
    write("projects/app/.env.local", "PORT=3000\nNODE_ENV=test\n")
    write("projects/app/.env.references", "TOKEN=op://v/i/token\n")
    write("projects/app/.env.prefixed", "csec_TOKEN=op://v/i/token\n")
    write("projects/app/.env.example", "SECRET_TOKEN=fill-me-in\n")
    // Per-environment names: `.env.<environment>` and Docker Compose's
    // `<name>.env`, with their templates.
    write("projects/app/.env.staging", "STAGING_TOKEN=xoxb-staging-aaaabbbbccccdddd\n")
    write("projects/app/deploy/staging.env", "DEPLOY_TOKEN=xoxb-deploy-aaaabbbbccccdddd\n")
    write("projects/app/deploy/secrets.env.example", "DEPLOY_TOKEN=fill-me-in\n")
    write("projects/app/deploy/example.env", "DEPLOY_TOKEN=fill-me-in\n")
    write("projects/app/deploy/production.template.env", "DEPLOY_TOKEN=fill-me-in\n")
    write("projects/app/config/master.key", "0123456789abcdef0123456789abcdef\n")
    write("projects/app/certs/server.pem",
          "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    write("projects/app/certs/server.key",
          "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nMIIE\n-----END RSA PRIVATE KEY-----\n")
    write("projects/deep/a/b/c/d/e/f/g/.env", "STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n")
    write("projects/app/.git-credentials", "https://user:\(markerValue)@github.com\n")
    write("projects/app/.npmrc", "//registry.npmjs.org/:_authToken=\(markerValue)\n")
    write("projects/app/plain.npmrc.like/.npmrc", "registry=https://registry.npmjs.org/\n")
    write("projects/app/placeholder/.npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n")
    write("projects/app/mixed/.npmrc", "//one/:_authToken=${NPM_TOKEN}\n//two/:_auth=\(markerValue)\n")
    write("projects/app/comments/.npmrc", "# _authToken=synthetic\n_authToken=\"\"\n")
    // Excluded trees the walk must skip.
    write("projects/app/node_modules/dep/.env", "NM_TOKEN=xoxb-should-not-be-found-1234\n")
    write("go/pkg/mod/dep/.env", "GO_TOKEN=xoxb-should-not-be-found-5678\n")

    // Home-global files reached only by catalog probes (inside excluded trees).
    write(".cache/huggingface/token", "hf_\(markerValue)")
    write(".cache/huggingface/stored_tokens", "{\"tokens\":{}}")
    write("Library/Preferences/netlify/config.json",
          "{\"users\":{\"u\":{\"auth\":{\"token\":\"\(markerValue)\"}}}}")
    write("Library/Application Support/com.vercel.cli/auth.json",
          "{\"token\":\"\(markerValue)\"}")
    write(".aws/credentials",
          "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=\(markerValue)\n")
    write(".kube/config", "clusters: []\nusers:\n- user:\n    client-key-data: abc\n")
    write(".claude/.credentials.json", "{\"claudeAiOauth\":{}}")
    write(".docker/config.json",
          "{\"auths\":{\"registry.example.test\":{\"auth\":\"dXNlcjpwYXNz\"}}}")
    write(".config/gh/hosts.yml", "github.com:\n    oauth_token: gho_\(markerValue)\n")
    write(".gradle/gradle.properties",
          "org.gradle.jvmargs=-Xmx2g\nartifactoryPassword=\(markerValue)\n")
    write(".mylogin.cnf", "\u{01}\u{02}obfuscated-but-reversible")

    // Grafana CLIs. gcx's keychain-backed config holds only `keychain:gcx:…`
    // references and must stay silent; its GCX_KEYCHAIN=off plaintext is a
    // keychain fallback. grafanactl is always plaintext, under adrg/xdg's
    // macOS directory.
    write(".config/gcx/config.yaml", """
        version: 1
        contexts:
          prod:
            grafana:
              server: https://example.grafana.net
              token: keychain:gcx:v2:0123abcd:1
            cloud:
              token: "keychain:gcx:v2:4567ef01:1"
              oauth-token-expires-at: "2026-10-23T00:00:00Z"
        current-context: prod
        """)
    write("Library/Application Support/gcx/config.yaml", """
        contexts:
          dev:
            grafana:
              server: http://localhost:3000
              user: admin
              password: '\(markerValue)'
        """)
    write("Library/Application Support/grafanactl/config.yaml", """
        contexts:
          default:
            grafana:
              server: https://example.grafana.net
              token: glsa_\(markerValue) # service account
        current-context: default
        """)
    write("projects/app/.gcx.yaml",
          "contexts:\n  - name: ci\n    grafana:\n      token: glsa_\(markerValue)\n")
    write("projects/refs/.gcx.yaml", """
        contexts:
          ci:
            grafana:
              token: ${GRAFANA_TOKEN}
              password: ""
              oauth-token: null
              oauth-refresh-token: ~
            # token: glsa_commented-out
            cloud:
              token:
        """)

    // Keychain-default tool whose fallback file is absent: must stay silent.
    // (No ~/.supabase/access-token is written.)

    // Docker-style file with EMPTY auths: the gate suppresses it… but a
    // separate helm file with populated auths passes.
    write(".config/containers/auth.json", "{\"auths\":{}}")
    write("Library/Preferences/helm/registry/config.json",
          "{\"auths\":{\"ghcr.io\":{\"auth\":\"dG9rZW4=\"}}}")

    // Shell rc probes.
    write(".zshrc", "alias ll='ls -al'\nexport GITHUB_TOKEN=ghp_0123456789abcdef0123456789abcdef1234\n")
    write(".bashrc", "alias gs='git status'\n")
    write("zdot/.zshenv", "export NPM_TOKEN=npm_0123456789abcdefghijklmnopqrstuvwxyz12\n")

    // SSH keys: structural probe by content, .pub and config skipped. A key
    // csec's SSH agent cannot use (DSA, wrapped in other text) is encrypted
    // whole instead, and a passphrase-protected one is left alone, so neither
    // fails the SSH batch.
    let usableKey = (try? Ed25519SSHFixture(seed: 41))
        .map { String(decoding: $0.privateKeyPEM, as: UTF8.self) } ?? ""
    let usableRSAKey = (try? generatedRSAPEM(bits: 2_048))
        .map { String(decoding: $0.pem, as: UTF8.self) } ?? ""
    write(".ssh/id_ed25519", usableKey)
    write(".ssh/id_ed25519.pub", "ssh-ed25519 AAAA test\n")
    write(".ssh/config", "Host *\n  AddKeysToAgent yes\n")
    write(".ssh/deploy_key.pem", usableKey)
    write(".ssh/id_dsa", "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKBgQ==\n-----END DSA PRIVATE KEY-----\n")
    write(".ssh/id_rsa_terraform", "<<EOT\n" + usableRSAKey + "EOT\n")
    write(".ssh/id_encrypted",
          "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nMIIE\n"
            + "-----END RSA PRIVATE KEY-----\n")

    // A wallet's recovery words: no TOKEN/KEY/SECRET in the name, and
    // whitespace in the value, so only the name marker can flag it.
    write("projects/wallet/.env", "XDAI_MNEMONIC=\"\(markerValue) abandon ability able\"\n")

    // Env override target for HF_TOKEN_PATH.
    write("custom/hf-token", "hf_override_\(markerValue)")

    // fly: a saved token is a finding; a config whose token csec took out
    // (FLY_CONFIG_DIR points at it) is not.
    write(".fly/config.yml", "access_token: FlyV1 fm2_\(markerValue)\nauto_update: true\n")
    write("custom-fly/config.yml", "access_token: \"\"\nauto_update: true\nmetrics_token: \"\"\n")

    // Symlink alias to a real env file + a hardlink pair + a symlinked dir +
    // a fifo that must be skipped with a warning.
    write("real/.env", "REAL_TOKEN=xoxb-realtoken-aaaabbbbccccdddd\n")
    try? fm.createSymbolicLink(
        atPath: home + "/aliases/.env.alias", withDestinationPath: home + "/real/.env")
    // (createSymbolicLink needs the parent to exist.)
    try? fm.createDirectory(atPath: home + "/aliases", withIntermediateDirectories: true)
    try? fm.createSymbolicLink(
        atPath: home + "/aliases/.env.alias", withDestinationPath: home + "/real/.env")
    write("hard/.envrc", "export HARD_TOKEN=xoxb-hardlink-aaaabbbbccccdddd\n")
    try? fm.createDirectory(atPath: home + "/hard2", withIntermediateDirectories: true)
    _ = (home + "/hard/.envrc").withCString { existing in
        (home + "/hard2/.envrc").withCString { new in link(existing, new) }
    }
    try? fm.createSymbolicLink(
        atPath: home + "/loopdir", withDestinationPath: home + "/projects")
    _ = (home + "/projects/app/.env.fifo").withCString { mkfifo($0, 0o600) }

    let environment = [
        "ZDOTDIR": home + "/zdot",
        "HF_TOKEN_PATH": home + "/custom/hf-token",
        "FLY_CONFIG_DIR": home + "/custom-fly",
    ]
    let report = SecretFileDiscoveryEngine.discover(
        roots: [], homeDirectory: home, environment: environment)

    func find(_ suffix: String) -> DiscoveredSecretFile? {
        report.files.first {
            $0.canonicalPath.hasSuffix(suffix)
                || $0.aliasPaths.contains(where: { $0.hasSuffix(suffix) })
        }
    }
    func byCatalogID(_ id: String) -> [DiscoveredSecretFile] {
        report.files.filter { $0.catalogID == id }
    }

    // Kind classification from the walk.
    check(find("projects/app/.envrc")?.kind == .envrc, "an .envrc classifies as envrc")
    check(find("projects/app/.envrc")?.suggestedApproach == .perVar,
          "an .envrc with an importable secret suggests per-var")
    check(find("projects/app/.env")?.suggestedApproach == .wholeFile,
          "a dotenv whose only secret is command-substituted falls back to whole-file")
    check(find("projects/app/.env")?.notes.contains(
              "per-var cannot rewrite its secrets; whole-file fallback") == true,
          "the fallback is stated on the record, never silent")
    check(find("projects/app/.env.local") == nil, "a secret-free dotenv is suppressed")
    check(find("projects/app/.env.references")?.suggestedApproach == .perVar,
          "reference-only env files remain discoverable for prefix migration")
    check(find("projects/app/.env.prefixed") == nil,
          "already-prefixed reference files need no further protection")
    check(report.suppressedSecretFreeEnvFiles >= 1, "suppressed env files are counted")
    check(find(".env.example") == nil, "example env files are skipped by name")
    check(find("projects/app/.env.staging")?.kind == .dotenv
            && find("projects/app/.env.staging")?.suggestedApproach == .perVar,
          "a .env.<environment> file is a per-var dotenv")
    check(find("projects/app/deploy/staging.env")?.kind == .dotenv
            && find("projects/app/deploy/staging.env")?.suggestedApproach == .perVar,
          "a <name>.env file is a per-var dotenv")
    check(find("deploy/secrets.env.example") == nil && find("deploy/example.env") == nil
            && find("deploy/production.template.env") == nil,
          "<name>.env templates are skipped by name")
    check(find("projects/deep/a/b/c/d/e/f/g/.env")?.kind == .dotenv,
          "the walk reaches files beyond the former six-directory depth cap")
    check(find("config/master.key")?.kind == .keyMaterial,
          "a raw-hex master.key is admitted as key material")
    check(find("certs/server.pem") == nil, "a certificate-only PEM is not a secret")
    check(find("certs/server.key")?.notes.contains("already passphrase-protected") == true,
          "an encrypted private key is admitted and noted as passphrase-protected")
    check(find("projects/app/.git-credentials")?.suggestedApproach == .wholeFile,
          "a project git credential store suggests whole-file")
    check(find("projects/app/.npmrc")?.catalogID == "npm",
          "a project npmrc with an auth token maps onto the npm catalog entry")
    check(find("plain.npmrc.like/.npmrc") == nil,
          "an npmrc without auth material is suppressed by the content gate")
    check(find("placeholder/.npmrc") == nil && find("comments/.npmrc") == nil,
          "npm placeholders, comments and empty auth properties are not plaintext credentials")
    check(find("mixed/.npmrc") != nil,
          "an npm config with both a placeholder and literal auth remains a candidate")
    check(find("node_modules/dep/.env") == nil, "excluded directories are not walked")
    check(find("go/pkg/mod/dep/.env") == nil, "go/pkg is excluded by relative path")

    // Catalog probes reach inside walk-excluded trees, with macOS paths.
    // Both the HF_TOKEN_PATH override and the default location hold real
    // token files here, and both are real findings.
    check(byCatalogID("huggingface-token").contains {
              $0.canonicalPath.hasSuffix("/.cache/huggingface/token") },
          "the HuggingFace token is found under the excluded ~/.cache tree")
    check(byCatalogID("huggingface-token").contains {
              $0.canonicalPath.hasSuffix("custom/hf-token") },
          "HF_TOKEN_PATH is honored as an additional probe location")
    check(byCatalogID("huggingface-token").allSatisfy {
              $0.suggestedApproach == .envToken(variables: ["HF_TOKEN"]) },
          "the HuggingFace token routes to env-token delivery")
    check(byCatalogID("huggingface-stored").first?.suggestedApproach == .wholeFile,
          "HuggingFace stored_tokens routes to whole-file")
    check(byCatalogID("netlify").count == 1,
          "netlify is found at its macOS ~/Library/Preferences path")
    check(byCatalogID("vercel").count == 1,
          "vercel is found at its macOS ~/Library/Application Support path")
    check(byCatalogID("netlify").first.map {
              $0.toolRewritesFile
                  && $0.notes.contains(SecretFileDiscoveryEngine.toolRewritesFileNote) } == true,
          "a token file its tool rewrites is flagged and noted at discovery")
    check(byCatalogID("huggingface-token").allSatisfy { !$0.toolRewritesFile
              && !$0.notes.contains(SecretFileDiscoveryEngine.toolRewritesFileNote) },
          "a token file its tool only reads is neither flagged nor noted")
    // Pinned to a source audit of each tool's save path: these save their file
    // during ordinary commands (refresh, per-run state, project links).
    check(Set(CredentialCatalog.entries.filter(\.toolRewritesFile).map(\.id))
              == ["fly", "stripe", "netlify", "vercel", "wrangler", "pulumi", "railway",
                  "render", "neon", "firebase", "gcx"],
          "exactly the audited rewriting tools are flagged in the catalog")
    check(byCatalogID("fly").count == 1
              && byCatalogID("fly").first?.canonicalPath.hasSuffix("/.fly/config.yml") == true
              && byCatalogID("fly").first?.suggestedApproach == .flyToken
              && byCatalogID("fly").first?.notes.contains(SecretFileDiscoveryEngine.flyTokenNote) == true,
          "fly's saved token is found and routed to the Fly delivery; an emptied config is not")
    check(byCatalogID("aws").first?.suggestedApproach == .credsAws,
          "the AWS shared credentials file routes to creds-aws")
    check(byCatalogID("kubeconfig").first?.suggestedApproach
              == .filePreset(preset: "kubeconfig", pathEnvironmentVariable: "KUBECONFIG"),
          "kubeconfig routes to its file preset")
    check(byCatalogID("gradle").count == 1,
          "a gradle.properties with a secret-keyed property is found under excluded ~/.gradle")
    check(byCatalogID("mylogin").count == 1,
          "the reversibly-encoded .mylogin.cnf is treated as plaintext, not skipped")
    check(byCatalogID("podman").isEmpty,
          "a container auth file with empty auths is suppressed")
    check(byCatalogID("helm").count == 1,
          "a helm registry config with populated auths is found under ~/Library")

    // Keychain-default flagging.
    check(byCatalogID("claude-code").first?.keychainFallback == true,
          "a present keychain-fallback file is flagged")
    check(byCatalogID("claude-code").first?.notes.contains(where: {
              $0.contains("Keychain") }) == true,
          "the degraded-posture note names the Keychain default")
    check(byCatalogID("supabase").isEmpty,
          "an absent keychain-fallback file stays silent")
    check(byCatalogID("docker").first?.keychainFallback == true,
          "a populated Docker auths file is flagged as a keychain fallback")
    check(byCatalogID("gh").count == 1,
          "a gh hosts.yml with a plaintext oauth_token is flagged")

    // Grafana CLIs (gcx login, grafanactl).
    check(find(".config/gcx/config.yaml") == nil,
          "a gcx config holding only keychain references is not a plaintext credential")
    let gcxPlaintext = find("Library/Application Support/gcx/config.yaml")
    check(gcxPlaintext?.catalogID == "gcx",
          "a gcx config with a plaintext password is found under ~/Library/Application Support")
    check(gcxPlaintext?.keychainFallback == true,
          "a plaintext gcx config is flagged as a keychain fallback")
    check(gcxPlaintext?.suggestedApproach
              == .envToken(variables: ["GRAFANA_TOKEN", "GRAFANA_CLOUD_TOKEN"]),
          "gcx routes to env-token delivery with its Grafana variables")
    let grafanactl = byCatalogID("grafanactl")
    check(grafanactl.count == 1 && grafanactl.first?.keychainFallback == false,
          "a grafanactl config with a plaintext token is found and is not a keychain fallback")
    check(find("projects/app/.gcx.yaml")?.catalogID == "gcx",
          "a repository .gcx.yaml with a plaintext token maps onto the gcx entry")
    check(find("projects/refs/.gcx.yaml") == nil,
          "gcx placeholders, empty, null and commented-out credentials are not plaintext")

    // Shell rc probes, including $ZDOTDIR.
    check(find("/.zshrc")?.kind == .shellRc, "the home .zshrc is probed")
    check(find("/.zshrc")?.suggestedApproach == .perVar,
          "a shell rc with an export literal suggests per-var")
    check(find("/.bashrc") == nil, "a secret-free shell rc is suppressed")
    check(find("zdot/.zshenv")?.kind == .shellRc, "$ZDOTDIR zsh files are probed")

    // SSH structural probe.
    check(find(".ssh/id_ed25519")?.suggestedApproach == .sshKey,
          "an SSH private key routes to the SSH agent flow")
    check(find(".ssh/id_ed25519.pub") == nil, "public keys are skipped")
    check(find(".ssh/config") == nil, "ssh config is skipped")
    check(find(".ssh/deploy_key.pem")?.kind == .sshPrivateKey,
          "a private key under ~/.ssh is admitted regardless of its name")
    check(find(".ssh/id_dsa")?.kind == .sshPrivateKey
            && find(".ssh/id_dsa")?.suggestedApproach == .wholeFile
            && find(".ssh/id_dsa")?.notes.contains { $0.hasPrefix("DSA, obsolete") } == true,
          "a DSA key csec's SSH agent cannot use is encrypted whole, with the reason noted")
    check(find(".ssh/id_rsa_terraform")?.suggestedApproach == .wholeFile
            && find(".ssh/id_rsa_terraform")?.notes.contains { $0.hasPrefix("not a readable SSH key") } == true,
          "a key wrapped in other text is encrypted whole, not offered to the SSH agent")
    check(find(".ssh/id_encrypted") == nil
            && report.warnings.contains { $0.contains("id_encrypted") && $0.contains("passphrase-protected") },
          "a passphrase-protected key is left alone with a warning, not put in the SSH batch")

    check(find("projects/wallet/.env")?.suggestedApproach == .perVar,
          "an env file holding only a mnemonic is discovered for per-var protection")

    // Symlink + hardlink dedupe.
    let aliased = find("real/.env")
    check(aliased != nil, "the symlink target is discovered at its canonical path")
    check(aliased?.aliasPaths.isEmpty == true,
          "symlinks are omitted from protection paths")
    check(report.symlinkCount == 1, "candidate symlinks are counted separately")
    check(report.files.filter { $0.canonicalPath.hasSuffix("real/.env") }.count == 1,
          "symlink aliases collapse onto one record")
    let hardlinked = report.files.filter {
        $0.canonicalPath.hasSuffix("hard/.envrc") || $0.canonicalPath.hasSuffix("hard2/.envrc")
    }
    check(hardlinked.count == 1, "hardlinks collapse onto one record by dev/ino")
    check(hardlinked.first.map { $0.aliasPaths.count == 1 } == true,
          "the second hardlink spelling is retained as an alias")
    check(!report.files.contains { $0.canonicalPath.contains("/loopdir/") },
          "symlinked directories are never traversed")
    check(report.warnings.contains { $0.contains(".env.fifo") && $0.contains("not a regular file") },
          "a fifo matching a candidate name is skipped with a warning")

    // No secret value ever appears in the report.
    var reportText = ""
    reportText += report.warnings.joined()
    reportText += report.scannedRootLabels.joined()
    for file in report.files {
        reportText += file.canonicalPath
        reportText += file.aliasPaths.joined()
        reportText += file.displayName ?? ""
        reportText += file.catalogID ?? ""
        reportText += file.notes.joined()
        reportText += file.rootLabel
    }
    check(!reportText.contains(markerValue),
          "no marker secret value appears anywhere in the discovery report")
    check(!reportText.contains("xoxb-"), "no token fragment appears in the report")

    // Root labels.
    check(report.scannedRootLabels == ["~"], "the default sweep labels home as ~")
    check(find("projects/app/.envrc")?.rootLabel == "~",
          "walk records carry the root label")

    // Default exclusions are narrow and reviewable, not blanket dotdir bans.
    let fixtureKey = "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----\n"
    let omitted = [
        ".claude/daemon/control.key", ".vscode/extensions/example/key.pem",
        ".local/share/mise/installs/example/key.pem", ".pyenv/versions/example/key.pem",
        "projects/app/tests/certs/server.key", "projects/app/deps/example/server.key",
    ]
    for path in omitted { write(path, fixtureKey) }
    write("projects/app/.env.enc", "encrypted-data")
    write("projects/app/.env.erb", "SECRET_TOKEN=<%= ENV.fetch('TOKEN') %>\n")
    write("projects/app/tests/.env", "SECRET_TOKEN=\(markerValue)\n")
    write("projects/app/config/credentials/test.key", fixtureKey)
    write("projects/extensions/server.key", fixtureKey)
    let excluded = SecretFileDiscoveryEngine.discover(roots: [], homeDirectory: home)
    check(omitted.allSatisfy { path in !excluded.files.contains { $0.canonicalPath.hasSuffix("/" + path) } },
          "runtime, installed tools, dependency and fixture keys are omitted by default")
    check(!excluded.files.contains { $0.canonicalPath.hasSuffix(".env.enc") || $0.canonicalPath.hasSuffix(".env.erb") },
          "encrypted env files and templates are omitted from protection")
    check(excluded.files.contains { $0.canonicalPath.hasSuffix("tests/.env") }
          && excluded.files.contains { $0.canonicalPath.hasSuffix("config/credentials/test.key") }
          && excluded.files.contains { $0.canonicalPath.hasSuffix("projects/extensions/server.key") }
          && excluded.files.contains { $0.catalogID == "claude-code" },
          "test environment secrets, Rails credentials, project extensions and Claude login credentials remain visible")
    check(excluded.exclusionCounts["app runtime keys"] == 1
          && excluded.exclusionCounts["installed tools/extensions"] == 3
          && excluded.exclusionCounts["test fixture keys"] == 1,
          "excluded paths are counted by reason")
    let included = SecretFileDiscoveryEngine.discover(
        roots: [], homeDirectory: home, includeExcluded: true)
    check(omitted.allSatisfy { path in included.files.contains { $0.canonicalPath.hasSuffix("/" + path) } }
          && included.exclusionCounts.isEmpty,
          "include-excluded makes all default exclusion categories reviewable")

    // A symlink must not smuggle a file outside an explicitly narrowed scan.
    try? fm.createSymbolicLink(atPath: home + "/projects/app/.env.outside",
                              withDestinationPath: home + "/real/.env")
    let contained = SecretFileDiscoveryEngine.discover(roots: [home + "/projects/app"], homeDirectory: home)
    check(!contained.files.contains { $0.canonicalPath.hasSuffix("real/.env") }
          && contained.warnings.contains { $0.contains("outside the scan roots") },
          "out-of-root symlink destinations are warned about and never planned")
    // More symlinks than the former alias cap still yield just one destination.
    for index in 0..<40 {
        try? fm.createSymbolicLink(atPath: home + "/aliases/.env.\(index)",
                                  withDestinationPath: home + "/real/.env")
    }
    let linked = SecretFileDiscoveryEngine.discover(roots: [home + "/aliases", home + "/real"], homeDirectory: home)
    check(linked.files.count == 1 && linked.files[0].aliasPaths.isEmpty && linked.symlinkCount == 41,
          "all symlinks collapse to one destination without an alias cap")

    write("test/active/server.key", fixtureKey)
    let testNamedHome = SecretFileDiscoveryEngine.discover(roots: [], homeDirectory: home + "/test", catalog: [])
    check(testNamedHome.files.count == 1,
          "a home directory named test does not suppress all of its keys")

    // More than the old file and root caps, with overlapping roots. No
    // traversal limit or duplicate walk may silently drop or double-count files.
    for index in 0..<4100 { write("many/\(index)/.env", "SECRET_TOKEN=\(markerValue)\n") }
    let manyRoots = (0..<33).map { home + "/many/\($0)" } + [home + "/many"]
    let complete = SecretFileDiscoveryEngine.discover(
        roots: manyRoots, homeDirectory: home, catalog: [])
    check(complete.files.count == 4100 && complete.scannedRootLabels.count == 34,
          "the scan finishes all roots and files beyond the former caps")
    check(complete.warnings.isEmpty, "a complete scan reports no truncation warnings")

    // A narrowed root labels itself and still finds its files — and, because
    // it does not cover the home directory, the home-global probes (catalog,
    // ~/.ssh, shell rc) must not run at all. Protecting home-global
    // credentials from a scan the user pointed elsewhere is a blast-radius
    // surprise, not coverage.
    let narrowed = SecretFileDiscoveryEngine.discover(
        roots: [home + "/projects/app"], homeDirectory: home,
        environment: environment)
    check(narrowed.scannedRootLabels == ["~/projects/app"],
          "a scan root under home is labeled home-relative")
    check(narrowed.files.contains { $0.kind == .envrc },
          "a narrowed scan still finds the project files")
    check(!narrowed.files.contains { $0.catalogID != nil && $0.rootLabel == "catalog" },
          "a narrowed scan never probes the home-global catalog")
    check(!narrowed.files.contains { $0.rootLabel == "ssh" || $0.rootLabel == "shell" },
          "a narrowed scan never probes ~/.ssh or shell rc locations")

    // A `.ssh` directory the walk reaches inside a narrowed root (a moved
    // `~/.ssh` target such as `~/sensitive/.ssh`, a backup copy) holds keys
    // under arbitrary names, exactly like `~/.ssh` itself: content decides.
    let openSSHKey = usableKey
    write("sensitive/.ssh/plex_key", openSSHKey)
    write("sensitive/.ssh/webos_emul", usableRSAKey)
    write("sensitive/.ssh/legacy.pem", openSSHKey)
    write("sensitive/.ssh/plex_key.pub", "ssh-ed25519 AAAA test\n")
    write("sensitive/.ssh/known_hosts", "github.com ssh-ed25519 AAAA\n")
    write("sensitive/.ssh/config", "Host *\n  IdentitiesOnly yes\n")
    write("sensitive/.ssh/notes", "rotate the plex key next year\n")
    write("sensitive/notes/plex_key", openSSHKey)
    let movedSSH = SecretFileDiscoveryEngine.discover(
        roots: [home + "/sensitive"], homeDirectory: home, environment: environment)
    func moved(_ suffix: String) -> DiscoveredSecretFile? {
        movedSSH.files.first { $0.canonicalPath.hasSuffix("/sensitive/" + suffix) }
    }
    check(moved(".ssh/plex_key")?.kind == .sshPrivateKey
            && moved(".ssh/plex_key")?.suggestedApproach == .sshKey,
          "a walked .ssh directory admits an arbitrarily named OpenSSH key for the SSH agent flow")
    check(moved(".ssh/webos_emul")?.suggestedApproach == .sshKey,
          "a walked .ssh directory admits an arbitrarily named PEM RSA key")
    check(moved(".ssh/legacy.pem")?.kind == .sshPrivateKey,
          "a .pem private key in a walked .ssh directory routes like ~/.ssh's")
    check(moved(".ssh/plex_key.pub") == nil && moved(".ssh/known_hosts") == nil
            && moved(".ssh/config") == nil && moved(".ssh/notes") == nil,
          "public keys, known_hosts, config and non-key files in a walked .ssh directory are skipped")
    check(moved("notes/plex_key") == nil,
          "an arbitrarily named file outside any .ssh directory is still matched by name only")
    check(!movedSSH.files.contains { $0.rootLabel == "ssh" },
          "walking a .ssh directory inside a narrowed root never runs the ~/.ssh probe")

    // A root above home still covers it, so the probes run.
    let covering = SecretFileDiscoveryEngine.discover(
        roots: [home], homeDirectory: home, environment: environment)
    check(covering.files.contains { $0.catalogID != nil },
          "an explicit root covering home keeps the catalog probes")

    secretFileDiscoveryFootprintTests()
}

/// A walk over a whole home (millions of entries under worktrees) must not
/// hold on to every directory listing: each listed entry costs about 4 KB of
/// footprint until an autorelease pool drains, and a command-line run has no
/// run loop to drain one. Without a pool per directory these 20,000 entries
/// grow the footprint by over 100 MB, and `csec setup --protect-files` over ~
/// reaches 19 GB.
private func secretFileDiscoveryFootprintTests() {
    let home = NSTemporaryDirectory()
        + "csec-discovery-footprint-\(UUID().uuidString.lowercased())"
    let fm = FileManager.default
    defer { try? fm.removeItem(atPath: home) }
    for directory in 0..<200 {
        let path = home + "/projects/p\(directory)"
        try? fm.createDirectory(atPath: path + "/sub", withIntermediateDirectories: true)
        for file in 0..<100 {
            fm.createFile(atPath: path + "/f\(file)", contents: nil)
        }
    }

    let before = physicalFootprint()
    let report = SecretFileDiscoveryEngine.discover(
        roots: [home + "/projects"], homeDirectory: home, catalog: [])
    var growth: Int64?
    if let before, let after = physicalFootprint() {
        growth = Int64(after) - Int64(before)
    }
    check(report.visitedEntryCount >= 20_200,
          "the footprint walk visits every synthetic entry")
    check(growth.map { $0 < 16 << 20 } ?? false,
          "a walk over 20,000 entries grows the footprint by under 16 MB "
            + "(grew \(growth.map { "\($0 >> 20) MB" } ?? "unmeasured"))")
}

/// The footprint the kernel charges this process, which counts compressed
/// and swapped pages that resident size leaves out.
private func physicalFootprint() -> UInt64? {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(
        MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
    let status = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
        }
    }
    return status == KERN_SUCCESS ? info.phys_footprint : nil
}
