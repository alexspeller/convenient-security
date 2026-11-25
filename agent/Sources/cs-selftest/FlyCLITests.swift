import ConvenientSecurity
import Foundation

/// Fly's token comes out of flyctl's config.yml and nothing else does: the
/// parser reads only the two token lines in the shapes flyctl writes, blanking
/// keeps every other byte, the registration holds only a canonical reference
/// from any provider, and bulk protect offers this route by default.
func flyCLITests() {
    print("\n# Fly.io token protection")
    let token = "FlyV1 fm2_flySyntheticToken0123456789+/abc=,fm2_secondSyntheticMacaroon=="
    let metrics = "fm2_flySyntheticMetrics0123456789"
    // As flyctl's yaml.v3 encoder writes it: sorted top-level keys, tokens as
    // plain scalars, nested WireGuard state indented four spaces.
    let config = """
        access_token: \(token)
        auto_update: false
        last_login: 2026-10-01T10:00:00Z
        metrics_token: \(metrics)
        send_metrics: true
        wire_guard_state:
            personal:
                localprivate: SYNTHETIC=
                name: interactive-x
                region: lhr

        """
    do {
        let tokens = try FlyConfigTokens(Data(config.utf8))
        check(tokens.accessToken == token && tokens.hasMetricsToken && tokens.holdsToken,
              "the parser reads fly's access token and sees its metrics token")
        let blanked = String(decoding: tokens.blanked(), as: UTF8.self)
        let expected = config
            .replacingOccurrences(of: "access_token: \(token)", with: "access_token: \"\"")
            .replacingOccurrences(of: "metrics_token: \(metrics)", with: "metrics_token: \"\"")
        check(blanked == expected && !blanked.contains("fm2_"),
              "blanking empties both token lines as flyctl writes an empty token and keeps every other byte")
        let again = try FlyConfigTokens(tokens.blanked())
        check(again.accessToken == nil && !again.hasMetricsToken && !again.holdsToken,
              "a blanked config holds no token")
        check(SecretFileDiscoveryEngine.explicitFile(
                  path: "/tmp/fly-test/.fly/config.yml", data: tokens.blanked(), mode: 0o600,
                  homeDirectory: "/tmp/fly-test", environment: [:]).catalogID == "fly",
              "an explicitly named fly config still maps onto the fly catalog entry")
    } catch {
        check(false, "fly's own config shape parses (\(error))")
    }

    for (shape, line) in [
        ("double-quoted", "access_token: \"\(token)\""),
        ("single-quoted", "access_token: '\(token)'"),
        ("quoted key", "\"access_token\": \(token)"),
    ] {
        let tokens = try? FlyConfigTokens(Data("\(line)\nsend_metrics: true\n".utf8))
        check(tokens?.accessToken == token, "a \(shape) token is read")
    }
    for empty in ["access_token:", "access_token: \"\"", "access_token: ''", "access_token: ~", "access_token: null"] {
        let tokens = try? FlyConfigTokens(Data("\(empty)\n".utf8))
        check(tokens != nil && tokens?.accessToken == nil, "`\(empty)` holds no token")
    }
    check((try? FlyConfigTokens(Data("auto_update: true\n".utf8)))?.holdsToken == false,
          "a config without token keys holds no token")
    check((try? FlyConfigTokens(Data("wire_guard_state:\n    access_token: nested\n".utf8)))?.holdsToken == false,
          "only top-level token keys are fly's")
    for (shape, text) in [
        ("block scalar", "access_token: |\n    \(token)\n"),
        ("folded scalar", "access_token: >-\n    \(token)\n"),
        ("continued plain scalar", "access_token: FlyV1\n    fm2_continued\n"),
        ("anchor", "access_token: &t \(token)\n"),
        ("alias", "access_token: *t\n"),
        ("escaped double quotes", "access_token: \"Fly\\u0056\"\n"),
        ("trailing comment", "access_token: \(token) # mine\n"),
        ("repeated key", "access_token: one\naccess_token: two\n"),
    ] {
        check((try? FlyConfigTokens(Data(text.utf8))) == nil, "a \(shape) is refused, not guessed at")
    }

    // The registration: a canonical reference from any provider, never a value.
    for uri in ["csec://fly/FLY_API_TOKEN", "op://Private/Fly.io/FLY_API_TOKEN", "future://vault/fly"] {
        let reference = try? SecretRef(uri)
        let encoded = reference.map { FlyRegistration(reference: $0).encoded() }
        let decoded = encoded.flatMap(FlyRegistration.decode)
        check(decoded?.reference?.uri == uri
                  && String(decoding: encoded ?? Data(), as: UTF8.self)
                      == "{\"token_reference\":\"\(uri)\",\"version\":1}\n",
              "the registration round-trips \(uri.prefix(while: { $0 != ":" }))'s reference")
    }
    check(FlyRegistration.decode(Data("{\"version\":2,\"token_reference\":\"csec://fly/K\"}".utf8)) == nil
              && FlyRegistration.decode(Data("{\"version\":1,\"token_reference\":\"not a reference\"}".utf8)) == nil
              && FlyRegistration.decode(Data(repeating: 0x20, count: FlyRegistration.maximumBytes + 1)) == nil,
          "an unknown version, a non-reference or an oversized registration is ignored")

    // Where a new login's token goes back: the registered reference's own
    // store, for the destinations csec writes; nowhere for others.
    let native = (try? SecretRef("csec://fly-home/FLY_API_TOKEN")).flatMap(SecretDestinationSpec.writeTarget(for:))
    check(native?.spec == .native(try! NativeStoreName("fly-home")) && native?.key == "FLY_API_TOKEN",
          "a native registration is rewritten in its store under its key")
    let onePassword = (try? SecretRef("op://Private/Fly.io/token")).flatMap(SecretDestinationSpec.writeTarget(for:))
    check(onePassword?.spec == .onePassword(vault: "Private", item: "Fly.io") && onePassword?.key == "token",
          "a 1Password registration is rewritten in its item's field")
    check((try? SecretRef("op://Private/Fly.io/section/token")).flatMap(SecretDestinationSpec.writeTarget(for:)) == nil
              && (try? SecretRef("future://vault/fly")).flatMap(SecretDestinationSpec.writeTarget(for:)) == nil,
          "a reference csec cannot write back has no write target")

    // `csec fly` handles only the commands that save or clear fly's token.
    check(FlyCLI.authAction(["auth", "login"]) == .login
              && FlyCLI.authAction(["auth", "signup", "--email"]) == .login
              && FlyCLI.authAction(["--verbose", "auth", "login"]) == .login
              && FlyCLI.authAction(["auth", "logout", "--force"]) == .logout,
          "auth login, signup and logout are recognised")
    check(FlyCLI.authAction(["auth", "token"]) == nil && FlyCLI.authAction(["deploy"]) == nil
              && FlyCLI.authAction(["ssh", "console", "--", "auth", "login"]) == nil
              && FlyCLI.authAction(["auth"]) == nil && FlyCLI.authAction([]) == nil,
          "every other command runs with the registered token")
    check(FlyCLI.configDirectory(environment: [:], homeDirectory: "/Users/u") == "/Users/u/.fly"
              && FlyCLI.configDirectory(environment: ["FLY_CONFIG_DIR": "/tmp/flycfg"], homeDirectory: "/Users/u")
                  == "/tmp/flycfg",
          "fly's config directory is FLY_CONFIG_DIR, else ~/.fly")
    check(FlyCLI.aliasLines().allSatisfy { $0.contains("fly='csec fly'") || $0.contains("fly 'csec fly'") },
          "the printed alias lines route fly through csec fly")

    // Bulk protect offers the Fly route by default, though fly rewrites its file.
    let fly = DiscoveredSecretFile(
        canonicalPath: "/Users/u/.fly/config.yml", aliasPaths: [],
        kind: .toolCredential, catalogID: "fly", displayName: "Fly.io API token",
        mode: 0o600, byteSize: 512, sizeClass: .small, rootLabel: "catalog",
        suggestedApproach: .flyToken, keychainFallback: false, toolRewritesFile: true,
        notes: [SecretFileDiscoveryEngine.flyTokenNote])
    check(SetupProtectPlanner.defaultApproach(for: fly) == .fly,
          "fly's config defaults to the Fly route, not skip")
    let plan = SetupProtectPlanRenderer.render(
        SetupProtectPlanner.assignments(files: [fly], rules: [], homeDirectory: "/Users/u"), homeDirectory: "/Users/u")
    check(plan.hasPrefix("plan: 1 unique file(s) to protect") && plan.contains("takes the token out")
              && !plan.contains("skipped unless whole-file"),
          "the plan protects fly's config and says how")
    check(BulkProtectApproach.parse("fly") == .fly && BulkProtectApproach.fly.displayToken == "fly",
          "the fly approach token parses and renders")
    check(CredentialCatalog.entries.first { $0.id == "fly" }?.delivery == .flyToken,
          "the catalog routes fly's config to the Fly delivery")
}
