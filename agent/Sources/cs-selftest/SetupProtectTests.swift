import ConvenientSecurity
import Foundation

/// The pure bulk-protect layer (setup Phase B): glob matching, rule parsing,
/// planner precedence, and the selection model's transitions and bounded,
/// value-free render.
func setupProtectTests() {
    print("\n# Bulk-protect selection (glob rules + picker model)")

    let home = "/Users/alex"
    func matches(_ pattern: String, _ path: String) -> Bool {
        GlobMatcher.matches(pattern, path: path, homeDirectory: home)
    }

    // GlobMatcher: *, ?, **, ~, anchoring, and no over-match across segments.
    check(matches("*.envrc", "/Users/alex/work/app/.envrc"),
          "* matches the empty prefix of a dotfile name")
    check(matches(".envrc", "/Users/alex/work/app/.envrc"),
          "a bare name floats to any path suffix")
    check(matches("*.env", "/Users/alex/app/prod.env"), "a suffix glob matches within a component")
    check(!matches("*.env", "/Users/alex/app/prod.envx"), "a suffix glob does not over-match")
    check(matches("?.env", "/Users/alex/a.env"), "? matches exactly one character")
    check(!matches("?.env", "/Users/alex/ab.env"), "? never matches two characters")
    check(matches("~/work/**/.env", "/Users/alex/work/a/b/c/.env"),
          "** spans multiple components under ~")
    check(matches("~/work/**/.env", "/Users/alex/work/.env"),
          "** also matches zero components")
    check(!matches("~/work/*/.env", "/Users/alex/work/a/b/.env"),
          "a single * component never crosses a path segment")
    check(matches("/Users/alex/app/.env", "/Users/alex/app/.env"),
          "an anchored literal matches exactly")
    check(!matches("/Users/bob/**", "/Users/alex/app/.env"), "anchoring is real")
    check(matches("work/**", "/Users/alex/work/x/y"), "a floating prefix matches mid-path")
    check(matches("~", home) && matches("~/**", home + "/x"),
          "~ expands to the home directory")
    check(!matches(String(repeating: "a", count: 600), "/a"),
          "over-long patterns are refused, never scanned")

    // Rule parsing: approach tokens, destinations recognized by scheme.
    check(BulkProtectRule.parse("*.envrc=per-var")
              == BulkProtectRule(pattern: "*.envrc", approach: .perVar, destination: nil),
          "a plain approach rule parses")
    check(BulkProtectRule.parse("~/.aws/credentials=creds-aws")?.approach == .credsAws,
          "creds-aws parses")
    check(BulkProtectRule.parse(".npmrc=preset:npm")?.approach
              == .filePreset(preset: "npm", pathEnvironmentVariable: nil),
          "a preset approach carries its preset name")
    check(BulkProtectRule.parse("token=env-token:HF_TOKEN")?.approach
              == .envToken(variables: ["HF_TOKEN"]),
          "an env-token approach carries its variable")
    check(BulkProtectRule.parse("*.env=per-var:csec://work-secrets")
              == BulkProtectRule(
                  pattern: "*.env", approach: .perVar, destination: "csec://work-secrets"),
          "an approach:dest rule splits on the destination scheme")
    check(BulkProtectRule.parse(".npmrc=preset:npm:csec://home")
              == BulkProtectRule(
                  pattern: ".npmrc",
                  approach: .filePreset(preset: "npm", pathEnvironmentVariable: nil),
                  destination: "csec://home"),
          "a preset approach with a destination is unambiguous")
    check(BulkProtectRule.parse("*.env=csec://work")
              == BulkProtectRule(pattern: "*.env", approach: nil, destination: "csec://work"),
          "a destination-only rule keeps the default approach")
    check(BulkProtectRule.parse("*.env=nonsense") == nil, "unknown approaches are refused")
    check(BulkProtectRule.parse("=per-var") == nil, "an empty pattern is refused")

    // Planner: defaults from discovery, later rules win, aliases match.
    func file(
        _ path: String, kind: SecretFileKind, approach: CredentialDelivery,
        aliases: [String] = []
    ) -> DiscoveredSecretFile {
        DiscoveredSecretFile(
            canonicalPath: path, aliasPaths: aliases, kind: kind, catalogID: nil,
            displayName: nil, mode: 0o600, byteSize: 64, sizeClass: .small,
            rootLabel: "~", suggestedApproach: approach, keychainFallback: false,
            notes: [])
    }
    let files = [
        file("/Users/alex/app/.envrc", kind: .envrc, approach: .perVar),
        file("/Users/alex/app/config/master.key", kind: .keyMaterial, approach: .wholeFile),
        file("/Users/alex/real/.env", kind: .dotenv, approach: .perVar,
             aliases: ["/Users/alex/aliases/.env.alias"]),
    ]
    let assignments = SetupProtectPlanner.assignments(
        files: files,
        rules: [
            BulkProtectRule(pattern: "*.key", approach: .skip, destination: nil),
            BulkProtectRule(pattern: ".env.alias", approach: .wholeFile, destination: nil),
            BulkProtectRule(pattern: "master.key", approach: .wholeFile,
                            destination: "csec://keys"),
        ],
        homeDirectory: home)
    check(assignments[0].approach == .perVar && assignments[0].matchedPattern == nil,
          "an unmatched file keeps its discovery default")
    check(assignments[1].approach == .wholeFile
              && assignments[1].destination == "csec://keys"
              && assignments[1].matchedPattern == "master.key",
          "later rules win over earlier ones")
    check(assignments[2].approach == .wholeFile,
          "a glob matching only an alias path still applies")

    let table = SetupProtectPlanRenderer.render(assignments, homeDirectory: home)
    check(table.hasPrefix("plan: 3 unique file(s) to protect\n")
          && table.contains("FILE") && table.contains("TYPE") && table.contains("PROTECTION")
          && table.contains("NOTES") && table.contains("Destination: csec://keys")
          && table.contains("Hardlink") && table.contains("~/aliases/.env.alias"),
          "the plan table shows unique counts, delivery, destinations and separate hardlinks")
    let narrowTable = SetupProtectPlanRenderer.render(assignments, homeDirectory: home, width: 80)
    check(narrowTable.split(separator: "\n").allSatisfy { $0.count <= 80 },
          "plan cells wrap to terminal width")
    let hostile = BulkProtectAssignment(
        file: file(home + "/bad\u{1B}[31m\n|path/.env", kind: .dotenv, approach: .perVar),
        approach: .skip, destination: "op://vault/\u{1B}[31mitem")
    let escapedTable = SetupProtectPlanRenderer.render([hostile], homeDirectory: home)
    check(!escapedTable.contains("\u{1B}") && escapedTable.contains("\\|")
          && escapedTable.hasPrefix("plan: 0 unique file(s) to protect"),
          "plan metadata escapes controls and pipe characters and counts skipped rows correctly")

    // Selection model: preselection, filter-select, subset approach/destination.
    var model = SetupSelectModel(assignments: assignments, homeDirectory: home)
    check(model.effectiveAssignments.count == 3, "non-skip files start selected")
    let skippingModel = SetupSelectModel(
        assignments: SetupProtectPlanner.assignments(
            files: files,
            rules: [BulkProtectRule(pattern: "*.key", approach: .skip, destination: nil)],
            homeDirectory: home),
        homeDirectory: home)
    check(skippingModel.effectiveAssignments.count == 2, "skip rules start unchecked")

    // A token file its tool rewrites during ordinary commands defaults to skip:
    // whole-file is its only file delivery, and the tool would break it or put
    // the plaintext back. A whole-file rule is still the user's to choose.
    let rewritten = DiscoveredSecretFile(
        canonicalPath: home + "/Library/Preferences/netlify/config.json", aliasPaths: [],
        kind: .toolCredential, catalogID: "netlify", displayName: "Netlify auth token",
        mode: 0o600, byteSize: 64, sizeClass: .small, rootLabel: "catalog",
        suggestedApproach: .envToken(variables: ["NETLIFY_AUTH_TOKEN"]),
        keychainFallback: false, toolRewritesFile: true,
        notes: [SecretFileDiscoveryEngine.toolRewritesFileNote])
    let readOnlyToken = DiscoveredSecretFile(
        canonicalPath: home + "/.vault-token", aliasPaths: [],
        kind: .toolCredential, catalogID: "vault", displayName: "HashiCorp Vault token",
        mode: 0o600, byteSize: 64, sizeClass: .small, rootLabel: "catalog",
        suggestedApproach: .envToken(variables: ["VAULT_TOKEN"]),
        keychainFallback: false, notes: [])
    let tokenDefaults = SetupProtectPlanner.assignments(
        files: [rewritten, readOnlyToken], rules: [], homeDirectory: home)
    check(tokenDefaults[0].approach == .skip
              && tokenDefaults[1].approach == .envToken(variables: ["VAULT_TOKEN"]),
          "a token file its tool rewrites defaults to skip; a read-only one keeps env-token")
    check(SetupSelectModel(assignments: tokenDefaults, homeDirectory: home)
              .effectiveAssignments.map(\.file.catalogID) == ["vault"],
          "the picker leaves a rewritten token file unchecked")
    let rewrittenTable = SetupProtectPlanRenderer.render(tokenDefaults, homeDirectory: home)
    check(rewrittenTable.hasPrefix("plan: 1 unique file(s) to protect")
              && rewrittenTable.contains("rewrites this file during ordinary commands"),
          "the plan says why a rewritten token file is skipped")
    check(SetupProtectPlanner.assignments(
              files: [rewritten],
              rules: [BulkProtectRule(pattern: "~/Library/Preferences/netlify/config.json",
                                      approach: .wholeFile, destination: nil)],
              homeDirectory: home).first?.approach == .wholeFile,
          "a whole-file rule still protects a rewritten token file on request")

    // The filter and the bulk keys replace the old one-glob select.
    func press(_ keys: [LineEditKey]) { for key in keys { _ = model.handle(key) } }
    func typed(_ text: String) -> [LineEditKey] { text.map { LineEditKey.insert($0) } }
    press([.insert("n")])
    check(model.selected.isEmpty, "n deselects every file when no filter is set")
    press([.insert("/")] + typed("envrc") + [.submit, .insert("a")])
    check(model.effectiveAssignments.map(\.file.canonicalPath) == ["/Users/alex/app/.envrc"],
          "a selects exactly the files the filter shows")
    model.setApproach(.wholeFile)
    check(model.assignments[0].approach == .wholeFile,
          "an approach applies to the selected subset")
    model.setDestination("csec://override")
    check(model.assignments[0].destination == "csec://override",
          "a destination applies to the selected subset")
    check(model.assignments[2].destination == nil,
          "unselected rows keep their destination")
    press([.cancel, .insert("a")])
    check(model.effectiveAssignments.count == 3,
          "with the filter cleared, a selects every file")
    press([.insert("i")])
    check(model.effectiveAssignments.isEmpty, "i inverts the selection of every file")

    var cursorModel = SetupSelectModel(assignments: assignments, homeDirectory: home)
    check(cursorModel.rows.map(\.label) == ["~/app/", ".envrc", "config/master.key", "~/real/.env"],
          "rows group by folder, a one-file folder shows as its file, and top rows show the whole path")
    for _ in 0..<10 { cursorModel.moveDown() }
    check(cursorModel.cursor == cursorModel.rows.count - 1, "cursor clamps at the bottom")
    cursorModel.toggle()
    check(cursorModel.effectiveAssignments.count == 2, "toggle unchecks under the cursor")

    // Render: bounded window, value-free, home-relative paths.
    let bigAssignments = (0..<200).map { index in
        BulkProtectAssignment(
            file: file("/Users/alex/repo\(index)/.env", kind: .dotenv, approach: .perVar),
            approach: .perVar)
    }
    let bigModel = SetupSelectModel(assignments: bigAssignments, homeDirectory: home)
    let rendered = bigModel.render(color: false, width: 100, height: 20)
    check(rendered.split(separator: "\n").count < 25,
          "the render window is bounded regardless of file count")
    check(rendered.contains("more below"), "truncation in the window is stated, not silent")
    check(rendered.contains("~/repo0/.env"), "paths render home-relative")
    check(!rendered.contains("\u{1B}"), "colorless render has no ANSI escapes")
    check(rendered.contains("0 of 200 selected") && rendered.contains("none is selected yet"),
          "a large find starts with nothing selected, says so, and the footer counts the selection")
}
