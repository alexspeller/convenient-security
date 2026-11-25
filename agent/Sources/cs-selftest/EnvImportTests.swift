import ConvenientSecurity
import Foundation
import OnePasswordAdapter

// Env-file import (`csec protect --env`) building blocks: the name/value
// secret heuristics, the position-preserving env parser + rewriter, and the
// picker selection model. All pure — no TTY, no filesystem, no agent.

func secretHeuristicsTests() {
    // Name heuristic (moved from onboarding; behavior unchanged).
    for name in ["SLACK_TOKEN", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "MY_API_KEY", "OAUTH_CLIENT",
                 "MNEMONIC", "XDAI_MNEMONIC", "wallet-seed-phrase", "LEDGER_SEEDPHRASE"] {
        check(SecretHeuristics.nameLooksSecretLike(name), "name heuristic: \(name) is secret-like")
    }
    for name in ["PORT", "NODE_ENV", "HOME", "EDITOR", "LOG_LEVEL", "RANDOM_SEED", "SEED_DATA"] {
        check(!SecretHeuristics.nameLooksSecretLike(name), "name heuristic: \(name) is not secret-like")
    }
    // An access key ID names its key pair but grants nothing alone, so it is
    // left as plain configuration; its secret half still matches.
    for name in ["AWS_ACCESS_KEY_ID", "aws_access_key_id", "aws-access-key-id",
                 "DEPLOY_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID_PROD"] {
        check(!SecretHeuristics.nameLooksSecretLike(name), "name heuristic: \(name) is an identifier")
    }
    for name in ["AWS_SECRET_ACCESS_KEY", "MINIO_ACCESS_KEY", "ACCESS_KEY", "ACCESS_KEY_IDENTITY_TOKEN",
                 "AWS_ACCESS_KEY_IDX", "ACCESS_KEY_ID_AND_ACCESS_KEY"] {
        check(SecretHeuristics.nameLooksSecretLike(name), "name heuristic: \(name) is still secret-like")
    }

    // Value heuristic: known token shapes.
    for value in [
        "xoxb-synthetic-fixture-aaaabbbbccccdddd",
        "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        "sk-proj-abc123def456ghi789",
        "github_pat_11ABCDEFG0abcdefghijk",
        "AKIAIOSFODNN7EXAMPLEwith/a+longer=tail0123",
        "AIzaSyD-abc123def456ghi789jkl012mno345",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        "-----BEGIN RSA PRIVATE KEY-----",
        "d41d8cd98f00b204e9800998ecf8427ea3f8b1c2d41d8cd9",
        "QmFzZTY0UmFuZG9tRGF0YTEyMzQ1Ng==",
        "q8R2mV5nP9sT3wX7/y1Z4aB6cD8eF0gH2",
        "/q8R2mV5nP9sT3wX7y1Z4aB6cD8eF0gH2",
        "/q8R2mV5nP9sT3wX7/y1Z4aB6cD8eF0gH2",
        "/q8R2mV5nP9sT3wX7/y1Z4aB6cD8eF0gH2==",
        "/tmp/q8R2mV5nP9sT3wX7/y1Z4aB6cD8eF0gH2==",
        "/tmp/q8R2mV5nP9sT3wX7+y1Z4aB6cD8eF0gH2",
        "/tmp/q8R2mV5nP9sT3wX7\0y1Z4aB6cD8eF0gH2",
        "sk-proj-synthetic/token-with-1234567890",
        "/tmp/-----BEGIN RSA PRIVATE KEY-----",
        "postgresql://synthetic-user:synthetic-password@db.example.test/app",
    ] {
        check(SecretHeuristics.valueLooksSecretLike(value), "value heuristic: secret-like accepted")
    }

    // Value heuristic: ordinary configuration stays unflagged.
    for value in [
        "AKIAIOSFODNN7EXAMPLE", "ASIAQ3EGUZ2SRTWVPBNQ", "AKIA2E0A8F3B244C9986",
        "3000", "true", "development", "postgres", "/usr/local/bin",
        "en_US.UTF-8", "hello world this is text", "my-app-name-for-prod-use",
        "sk-x", "http://192.0.2.140:8123",
        "https://service.example.test/a-long-path-with-1234567890",
        "postgresql://synthetic-user@db.example.test/app",
        "postgresql://synthetic-user:@db.example.test/app",
        "/System/Volumes/Data/.Spotlight-V100",
        "/System/Volumes/Data/.Spotlight-V100/Store-V2",
        "/Users/example/projects/build2026/output",
        "/Users/example/Library/Caches/com.example.tool/v2/index.db",
        "/private/var/folders/ab/2cd3ef4gh5ij6kl7mn8op9qr0000st/T",
        "/nix/store/0123456789abcdef0123456789abcdef-tool-2.0/bin/tool",
        "./build/Release-v2/index.db",
        "../assets/Version2026/manifest.json",
        "~/Library/Caches/com.example.tool/v2/index.db",
        "~/Library/Application Support/Example-v2/index.db",
    ] {
        check(!SecretHeuristics.valueLooksSecretLike(value), "value heuristic: plain value rejected (\(value))")
    }

    check(
        !SecretHeuristics.environmentVariableLooksSecretLike(
            name: "HA_URL", value: "http://192.0.2.140:8123"
        ),
        "combined heuristic rejects passwordless URL under an ordinary name"
    )
    check(
        SecretHeuristics.environmentVariableLooksSecretLike(
            name: "DATABASE_URL", value: "postgresql://db.example.test/app"
        ),
        "combined heuristic retains an independently secret-like name"
    )
    check(
        !SecretHeuristics.environmentVariableLooksSecretLike(
            name: "INDEX_PATH", value: "/System/Volumes/Data/.Spotlight-V100"
        ),
        "combined heuristic rejects a filesystem path under an ordinary name"
    )
    check(
        SecretHeuristics.environmentVariableLooksSecretLike(
            name: "API_KEY", value: "/System/Volumes/Data/.Spotlight-V100"
        ),
        "a filesystem path does not override an independently secret-like name"
    )

    // Entropy: repeated bytes are zero; uniform distinct bytes hit log2(n);
    // random-looking text scores above repetitive text.
    check(SecretHeuristics.shannonEntropyBitsPerChar("aaaaaaaa") == 0, "entropy of repeated char is zero")
    check(abs(SecretHeuristics.shannonEntropyBitsPerChar("abcd") - 2.0) < 0.0001, "entropy of 4 distinct chars is 2 bits")
    check(
        SecretHeuristics.shannonEntropyBitsPerChar("q8Zr2Kx9Lp4Tn7Vw")
            > SecretHeuristics.shannonEntropyBitsPerChar("abababababababab"),
        "entropy orders random-looking above repetitive"
    )

    check(SecretHeuristics.isEnvironmentName("SLACK_TOKEN"), "env name accepted")
    check(SecretHeuristics.isEnvironmentName("_private"), "underscore-initial env name accepted")
    check(!SecretHeuristics.isEnvironmentName("9LIVES"), "digit-initial env name rejected")
    check(!SecretHeuristics.isEnvironmentName("A-B"), "hyphenated env name rejected")
}

private func envDoc(_ text: String) -> EnvFileDocument? {
    try? EnvFileDocument(data: Data(text.utf8))
}

private func candidate(_ document: EnvFileDocument?, _ name: String) -> EnvFileDocument.Candidate? {
    document?.candidates.first { $0.name == name }
}

private func candidateByKey(
    _ document: EnvFileDocument?, _ importKey: String
) -> EnvFileDocument.Candidate? {
    document?.candidates.first { $0.importKey == importKey }
}

func envFileDocumentTests() {
    // Byte-exact round trip with no rewrites, across terminator styles,
    // comments, blank lines, and arbitrary shell content.
    for fixture in [
        "A=1\nB=2\n",
        "A=1\r\nB=2\r\n",
        "A=1\nB=2",
        "# comment\n\nPATH_add bin\nif [ -f .env ]; then\n  echo hi\nfi\n",
        "KEY = not-an-assignment\n",
        "",
    ] {
        let document = envDoc(fixture)
        check(document != nil, "env parse succeeds for round-trip fixture")
        check(
            (try? document?.rewritten(references: [:])) == Data(fixture.utf8),
            "round trip is byte-exact with no rewrites"
        )
    }

    // Basic parse and preselection: export prefix tolerated, secret-like name
    // preselected, plain config not.
    do {
        let document = envDoc("export SLACK_TOKEN=xoxb-abc123\nPORT=3000\n")
        let token = candidate(document, "SLACK_TOKEN")
        check(token?.kind == .importable, "export assignment is importable")
        check(token?.importValue == "xoxb-abc123", "export assignment parses the bare value")
        check(token?.preselect == true, "secret-like name is preselected")
        check(document?.assignments.first?.hasExportPrefix == true, "export prefix recorded")
        let port = candidate(document, "PORT")
        check(port?.kind == .importable, "plain config is importable")
        check(port?.preselect == false, "plain config is not preselected")
    }

    // Value heuristic drives preselection when the name is unremarkable.
    check(
        candidate(envDoc("RANDOM_THING=xoxb-123456789\n"), "RANDOM_THING")?.preselect == true,
        "secret-like value preselects an unremarkable name"
    )
    do {
        let document = envDoc("export HA_URL=\"http://192.0.2.140:8123\"\n")
        let homeAssistantURL = candidate(document, "HA_URL")
        check(homeAssistantURL?.secretLike == false, "passwordless URL is not secret-like")
        check(homeAssistantURL?.preselect == false, "passwordless URL is not preselected")
        let (rows, selected) = EnvSelectModel.rows(for: document?.candidates ?? [])
        check(rows.first?.secretLike == false, "picker uses the candidate's centralized verdict")
        check(
            rows.first?.annotation.contains("secret-like") == false,
            "picker omits the secret-like annotation"
        )
        check(selected.isEmpty, "picker leaves a passwordless URL unchecked")
    }
    do {
        let document = envDoc("INDEX_PATH=/System/Volumes/Data/.Spotlight-V100\n")
        let indexPath = candidate(document, "INDEX_PATH")
        check(indexPath?.secretLike == false, "filesystem path is not secret-like")
        check(indexPath?.preselect == false, "filesystem path is not preselected")
        let (rows, selected) = EnvSelectModel.rows(for: document?.candidates ?? [])
        check(rows.first?.secretLike == false, "picker keeps the path verdict")
        check(rows.first?.annotation.contains("secret-like") == false,
              "picker omits the path's secret-like annotation")
        check(selected.isEmpty, "picker leaves a filesystem path unchecked")
    }

    // An AWS key pair imports only its secret half: the access key ID stays
    // in the file as plain configuration, live or commented, unless the user
    // ticks it.
    do {
        let document = envDoc(
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                + "# AWS_ACCESS_KEY_ID=ASIAQ3EGUZ2SRTWVPBNQ\n"
                + "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        let accessKeyID = candidate(document, "AWS_ACCESS_KEY_ID")
        check(accessKeyID?.kind == .importable, "access key ID stays importable by hand")
        check(accessKeyID?.secretLike == false, "access key ID is not secret-like")
        check(accessKeyID?.preselect == false, "access key ID is not preselected")
        check(candidateByKey(document, "AWS_ACCESS_KEY_ID_commented_1") == nil,
              "a commented access key ID is not a candidate")
        check(candidate(document, "AWS_SECRET_ACCESS_KEY")?.preselect == true,
              "the secret access key is preselected")
        let (rows, selected) = EnvSelectModel.rows(for: document?.candidates ?? [])
        check(rows.map(\.name) == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
                  && selected == [1],
              "picker checks only the secret access key")
    }

    // Splicing: every quoting style collapses to a double-quoted reference,
    // with surrounding bytes (indentation, export, trailing comments) intact.
    let reference = ["KEY": "csec://store-ab12/KEY"]
    let splices: [(String, String)] = [
        ("KEY=abc\n", "csec_KEY=\"csec://store-ab12/KEY\"\n"),
        ("KEY=abc  # keep me\n", "csec_KEY=\"csec://store-ab12/KEY\"  # keep me\n"),
        ("KEY='a b c'\n", "csec_KEY=\"csec://store-ab12/KEY\"\n"),
        ("KEY=\"a\\\"b\" # note\n", "csec_KEY=\"csec://store-ab12/KEY\" # note\n"),
        ("  export KEY=abc\nOTHER=1\n", "  export csec_KEY=\"csec://store-ab12/KEY\"\nOTHER=1\n"),
        ("KEY=abc\r\n", "csec_KEY=\"csec://store-ab12/KEY\"\r\n"),
    ]
    for (input, expected) in splices {
        let document = envDoc(input)
        check(
            (try? document?.rewritten(references: reference)) == Data(expected.utf8),
            "splice rewrites the name and value spans"
        )
    }

    // Dedupe: live occurrences collapse onto the name key (last one wins, the
    // shadowed live plaintext is scrubbed by the same reference); a distinct
    // secret-like commented value is its own preselected candidate with its
    // own key, so it is imported rather than silently scrubbed away.
    do {
        let document = envDoc("# TOKEN=old-value\nTOKEN=first9999\nTOKEN=last12345\n")
        let token = candidateByKey(document, "TOKEN")
        check(document?.candidates.count == 2,
              "live occurrences collapse; a distinct commented value stands alone")
        check(token?.importValue == "last12345", "last non-commented occurrence wins")
        check(token?.occurrenceCount == 2, "the live candidate counts its own occurrences")
        check(token?.differingValues == true, "differing duplicate values are flagged")
        check(token?.winningIsCommented == false, "live occurrence marks the name live")
        let commented = candidateByKey(document, "TOKEN_commented_1")
        check(commented?.importValue == "old-value",
              "the commented value keeps its own candidate")
        check(commented?.preselect == true, "the commented secret is preselected")
        check(commented?.name == "TOKEN", "the commented candidate keeps the variable name")
        let rewritten = try? document?.rewritten(references: [
            "TOKEN": "csec://s/TOKEN",
            "TOKEN_commented_1": "csec://s/TOKEN_commented_1",
        ])
        check(
            rewritten == Data(
                "# csec_TOKEN=\"csec://s/TOKEN_commented_1\"\ncsec_TOKEN=\"csec://s/TOKEN\"\ncsec_TOKEN=\"csec://s/TOKEN\"\n"
                    .utf8),
            "each occurrence is scrubbed by its own key's reference; commented stays commented"
        )
        let liveOnly = try? document?.rewritten(references: ["TOKEN": "csec://s/TOKEN"])
        check(
            liveOnly == Data(
                "# TOKEN=old-value\ncsec_TOKEN=\"csec://s/TOKEN\"\ncsec_TOKEN=\"csec://s/TOKEN\"\n".utf8),
            "an unselected commented key is left untouched, never scrubbed by the live reference"
        )
    }

    // The exact shape that nearly left plaintext on disk: a commented token
    // above a live one. Both import, under distinct keys, and the default
    // apply leaves neither plaintext behind.
    do {
        let fixture = "#  alex token\n#  export GITHUB_TOKEN=foo\n# bot token\nexport GITHUB_TOKEN=bar\n"
        let document = envDoc(fixture)
        check(document?.candidates.map(\.importKey) == ["GITHUB_TOKEN", "GITHUB_TOKEN_commented_1"],
              "commented and live token values import under distinct keys")
        check(document?.candidates.allSatisfy(\.preselect) == true,
              "both the live and the commented token are preselected")
        let rewritten = try? document?.rewritten(references: [
            "GITHUB_TOKEN": "csec://s/GITHUB_TOKEN",
            "GITHUB_TOKEN_commented_1": "csec://s/GITHUB_TOKEN_commented_1",
        ])
        let expected = "#  alex token\n#  export csec_GITHUB_TOKEN=\"csec://s/GITHUB_TOKEN_commented_1\"\n"
            + "# bot token\nexport csec_GITHUB_TOKEN=\"csec://s/GITHUB_TOKEN\"\n"
        check(rewritten == Data(expected.utf8),
              "the default apply removes both plaintexts; prose comments stay byte-identical")
        check(rewritten.map { $0.range(of: Data("foo".utf8)) == nil && $0.range(of: Data("bar".utf8)) == nil }
                == true,
              "no plaintext token value survives the rewrite")
    }

    // Commented-only secrets are candidates under their commented key — and
    // now preselected: a commented credential is still a credential on disk.
    do {
        let document = envDoc("# API_KEY=abc12345\n")
        let commented = candidateByKey(document, "API_KEY_commented_1")
        check(commented?.kind == .importable, "commented-only assignment is offered")
        check(commented?.winningIsCommented == true, "commented-only assignment is marked commented")
        check(commented?.preselect == true, "commented-only secret is preselected")
        check(commented?.lineNumber == 1, "line number is 1-based")
        check(candidate(envDoc("# API_KEY=abc12345\n"), "API_KEY")?.importKey == "API_KEY_commented_1",
              "a commented-only name has no live candidate")
    }

    // A duplicate commented value reuses the first key; a commented value
    // equal to the live winning value folds into the name key.
    do {
        let document = envDoc(
            "# SECRET_KEY=dup-value-123\n# SECRET_KEY=dup-value-123\nSECRET_KEY=live-value-456\n")
        check(document?.candidates.map(\.importKey)
                == ["SECRET_KEY", "SECRET_KEY_commented_1"],
              "equal commented values collapse onto one commented key")
        check(candidateByKey(document, "SECRET_KEY_commented_1")?.occurrenceCount == 2,
              "the reused commented key counts both occurrences")
        let rewritten = try? document?.rewritten(references: [
            "SECRET_KEY_commented_1": "csec://s/SECRET_KEY_commented_1",
        ])
        check(rewritten == Data(
                  ("# csec_SECRET_KEY=\"csec://s/SECRET_KEY_commented_1\"\n"
                   + "# csec_SECRET_KEY=\"csec://s/SECRET_KEY_commented_1\"\nSECRET_KEY=live-value-456\n").utf8),
              "both duplicate commented occurrences are scrubbed by the one reference")

        let folded = envDoc("# SECRET_KEY=same-value-789\nSECRET_KEY=same-value-789\n")
        check(folded?.candidates.map(\.importKey) == ["SECRET_KEY"],
              "a commented duplicate of the live value folds into the name key")
        check(candidateByKey(folded, "SECRET_KEY")?.occurrenceCount == 2,
              "the folded duplicate counts toward the live candidate")
        check((try? folded?.rewritten(references: ["SECRET_KEY": "csec://s/SECRET_KEY"]))
                == Data("# csec_SECRET_KEY=\"csec://s/SECRET_KEY\"\ncsec_SECRET_KEY=\"csec://s/SECRET_KEY\"\n".utf8),
              "selecting the name scrubs the commented duplicate too")
    }

    // Non-secret-looking commented lines stay untouched and produce no
    // candidate; a commented reference from a previous run is never re-imported.
    do {
        let plain = envDoc("# EDITOR_MODE=classic\nEDITOR_MODE=modern\n")
        check(plain?.candidates.map(\.importKey) == ["EDITOR_MODE"],
              "a non-secret commented line yields no candidate")
        check((try? plain?.rewritten(references: ["EDITOR_MODE": "csec://s/EDITOR_MODE"]))
                == Data("# EDITOR_MODE=classic\ncsec_EDITOR_MODE=\"csec://s/EDITOR_MODE\"\n".utf8),
              "a non-secret commented line survives the rewrite byte-identical")
        let priorRun = envDoc("# csec_API_TOKEN=\"csec://s/API_TOKEN_commented_1\"\nAPI_TOKEN=live-tok-9\n")
        check(priorRun?.candidates.map(\.importKey) == ["API_TOKEN"],
              "a commented reference from a previous run is not re-imported")
    }

    // Already-reference values are excluded from import.
    check(
        candidate(envDoc("TOKEN=csec://s/TOKEN\n"), "TOKEN")?.kind
            == .alreadyReference(scheme: "csec"),
        "bare csec reference is recognized"
    )
    check(
        candidate(envDoc("TOKEN=\"op://Vault/item/FIELD\"\n"), "TOKEN")?.kind
            == .alreadyReference(scheme: "op"),
        "quoted op reference is recognized"
    )

    // Unsupported values: interpolation, command substitution, mid-word
    // quotes, unterminated strings. Offered as info, never rewritten.
    for fixture in [
        "KEY=\"$HOME/x\"\n", "KEY=`cmd`\n", "KEY=a\"b\"\n", "KEY='unterminated\n",
        "KEY=\"a\\qb\"\n",
    ] {
        check(
            candidate(envDoc(fixture), "KEY")?.kind == .unsupported,
            "uninterpretable value is unsupported: \(fixture.trimmingCharacters(in: .newlines))"
        )
    }
    check(
        (try? envDoc("KEY=\"$HOME/x\"\n")?.rewritten(references: ["KEY": "csec://s/KEY"]))
            == Data("KEY=\"$HOME/x\"\n".utf8),
        "unsupported occurrences are never rewritten"
    )

    // A live parseable occurrence wins over a commented unsupported one, and
    // only the parseable line is rewritten.
    do {
        let document = envDoc("# KEY=\"$OLD\"\nKEY=real1234\n")
        check(candidate(document, "KEY")?.kind == .importable, "live parseable occurrence wins")
        check(
            (try? document?.rewritten(references: ["KEY": "csec://s/KEY"]))
                == Data("# KEY=\"$OLD\"\ncsec_KEY=\"csec://s/KEY\"\n".utf8),
            "unsupported commented twin stays untouched"
        )
    }

    // Empty values are surfaced as empty, not importable, and not rewritten.
    for fixture in ["KEY=\n", "KEY=   # note\n", "KEY=\"\"\n", "KEY=''\n"] {
        check(candidate(envDoc(fixture), "KEY")?.kind == .empty, "empty value kind: \(fixture.trimmingCharacters(in: .newlines))")
        check(
            (try? envDoc(fixture)?.rewritten(references: ["KEY": "csec://s/KEY"])) == Data(fixture.utf8),
            "empty occurrences are never rewritten"
        )
    }

    // A `#` glued to the `=` is a literal value, not a comment.
    check(
        candidate(envDoc("KEY=#literal\n"), "KEY")?.importValue == "#literal",
        "hash without preceding whitespace is a literal bare value"
    )

    // Non-assignment shell lines yield no assignments at all.
    check(envDoc("if [ x = y ]; then\n")?.assignments.isEmpty == true, "shell test line is not an assignment")
    check(envDoc("KEY = spaced\n")?.assignments.isEmpty == true, "whitespace around = is not a live assignment")

    // Limits.
    checkThrows("oversized env file throws") {
        _ = try EnvFileDocument(data: Data(repeating: 0x41, count: EnvFileDocument.maximumBytes + 1))
    }
    checkThrows("NUL byte throws") {
        _ = try EnvFileDocument(data: Data([0x41, 0x00, 0x42]))
    }
    checkThrows("too many assignments throws") {
        let text = (0...EnvFileDocument.maximumAssignments).map { "K\($0)=v" }.joined(separator: "\n")
        _ = try EnvFileDocument(data: Data(text.utf8))
    }
}

func envSelectModelTests() {
    let fixture = """
    SLACK_TOKEN=xoxb-synthetic-fixture-aaaabbbbccccdddd
    PORT=3000
    # DB_PASSWORD=hunter2hunter2
    EXISTING=csec://s/EXISTING
    BAD="$HOME/x"
    EMPTY=
    """
    guard let document = envDoc(fixture) else {
        check(false, "picker fixture parses")
        return
    }
    let (rows, initiallySelected) = EnvSelectModel.rows(for: document.candidates)
    check(rows.map(\.name)
              == ["SLACK_TOKEN", "PORT", "DB_PASSWORD_commented_1", "EXISTING", "BAD", "EMPTY"],
          "rows preserve candidate order and show the commented import key")
    check(rows.map(\.selectable) == [true, true, true, false, false, false],
          "importable rows selectable; reference/unsupported/empty rows are info")
    check(initiallySelected == [0, 2],
          "live and commented secret-like values both start checked")
    check(rows[2].annotation.contains("commented"), "commented row is annotated")
    check(rows[2].secretLike, "commented secret-like name keeps its hint")
    check(rows[3].annotation.contains("already csec://"), "reference row names its scheme")
    check(rows[4].annotation.contains("unsupported"), "unsupported row is annotated")
    check(rows[5].annotation.contains("empty"), "empty row is annotated")

    var model = EnvSelectModel(rows: rows, initiallySelected: initiallySelected)
    check(model.selectedNames == ["SLACK_TOKEN", "DB_PASSWORD_commented_1"],
          "initial selection honored")

    model.moveDown()
    model.toggle()
    check(model.selectedNames == ["SLACK_TOKEN", "PORT", "DB_PASSWORD_commented_1"],
          "toggle selects under cursor")

    model.moveDown(); model.moveDown(); model.moveDown()
    model.toggle()
    check(model.selectedNames == ["SLACK_TOKEN", "PORT", "DB_PASSWORD_commented_1"],
          "toggle is a no-op on info rows")

    model.toggleAll()
    check(model.selectedNames.isEmpty, "toggleAll clears when everything selectable is selected")
    model.toggleAll()
    check(model.selectedNames == ["SLACK_TOKEN", "PORT", "DB_PASSWORD_commented_1"],
          "toggleAll selects only selectable rows")
    model.toggleAll()
    check(model.selectedNames.isEmpty, "a second toggleAll clears the full selection again")

    for _ in 0..<20 { model.moveDown() }
    check(model.cursor == rows.count - 1, "cursor clamps at the bottom")
    for _ in 0..<20 { model.moveUp() }
    check(model.cursor == 0, "cursor clamps at the top")

    let rendered = model.render(color: false, width: 100)
    check(rendered.contains("[ ] SLACK_TOKEN"), "render shows checkbox and name")
    check(rendered.contains("v reveal"), "hidden picker advertises the reveal shortcut")
    check(rendered.contains(" -  EXISTING"), "render shows info glyph for unselectable rows")
    check(!rendered.contains("xoxb-"), "render never shows values")
    check(!rendered.contains("hunter2"), "render never shows commented values")
    check(!rendered.contains("\u{1B}"), "colorless render has no ANSI escapes")
    check(rendered.contains("0 of 3 selected"), "footer counts selectable rows")

    let revealed = model.render(
        color: false,
        width: 100,
        revealedValues: [
            "SLACK_TOKEN": "xoxb-synthetic-fixture-aaaabbbbccccdddd",
            "PORT": "3000",
            "DB_PASSWORD_commented_1": "hunter2hunter2",
        ]
    )
    check(revealed.contains("v hide"), "revealed picker advertises the hide shortcut")
    check(revealed.contains("Values visible"), "revealed picker warns that values are visible")
    check(revealed.contains("\"xoxb-synthetic-fixture-aaaabbbbccccdddd\""),
          "explicit reveal renders a selected value")
    check(revealed.contains("\"3000\""), "explicit reveal also renders an unselected value")
    check(revealed.contains("\"hunter2hunter2\""),
          "explicit reveal renders a commented candidate value")

    let escapedReveal = model.render(
        color: false,
        width: 160,
        revealedValues: ["SLACK_TOKEN": "line\n\u{1B}[31m\u{202E}tail"]
    )
    check(escapedReveal.contains("line\\n\\u{001B}[31m\\u{202E}tail"),
          "revealed values escape newlines, terminal controls, and bidi controls")
    check(!escapedReveal.contains("\u{1B}"), "revealed env content cannot inject ANSI escapes")

    let stray = EnvSelectModel(rows: rows, initiallySelected: [0, 3, 99])
    check(stray.selectedNames == ["SLACK_TOKEN"],
          "initial selection drops info rows and out-of-range indices")
}

func secretDestinationSpecTests() {
    func parsed(_ text: String) -> SecretDestinationSpec? {
        try? SecretDestinationSpec.parse(text, defaultItemTitle: "myproject")
    }
    if case .native(let store)? = parsed("csec://mystore-ab12") {
        check(store.value == "mystore-ab12", "csec:// destination parses the store name")
    } else {
        check(false, "csec:// destination parses the store name")
    }
    if case .native(let store)? = parsed("bare-name") {
        check(store.value == "bare-name", "bare destination is a native store name")
    } else {
        check(false, "bare destination is a native store name")
    }
    check(parsed("op://Employee") == .onePassword(vault: "Employee", item: "myproject"),
          "op:// vault-only destination defaults the item title")
    check(parsed("op://Employee/my item") == .onePassword(vault: "Employee", item: "my item"),
          "op:// destination accepts an explicit item title with spaces")
    check(parsed("op://Employee/item/extra") == nil, "op:// destination rejects extra components")
    check(parsed("op://") == nil, "op:// destination rejects an empty vault")
    check(parsed("op://Emp/loyee\u{07}") == nil, "op:// destination rejects control characters")
    check(parsed("https://example.com") == nil, "unknown destination schemes are rejected")
    check(parsed("csec://not a store") == nil, "invalid native store names are rejected")
    check(
        SecretDestinationSpec.onePassword(vault: "Employee", item: "my item").displayString
            == "op://Employee/my item",
        "display string round-trips the op destination"
    )
}

func onePasswordItemWriteTests() {
    for component in ["Employee", "my project", "convenient-security", "Vault 2"] {
        check(OnePasswordItemWrite.isValidComponent(component), "op component accepted: \(component)")
    }
    for component in ["", "a/b", "a\"b", "a\\b", "a$b", "a`b", " padded", "padded ", "a\u{07}b",
                      String(repeating: "x", count: 129)] {
        check(!OnePasswordItemWrite.isValidComponent(component), "op component rejected")
    }

    check(
        OnePasswordItemWrite.reference(vault: "Employee", title: "myproject", field: "SLACK_TOKEN")
            == "op://Employee/myproject/SLACK_TOKEN",
        "op reference is built from vault/title/field"
    )

    // Create template: parseable Login item, one concealed field per var.
    do {
        let template = try OnePasswordItemWrite.createTemplate(
            title: "myproject",
            fields: [.init(label: "SLACK_TOKEN", value: "xoxb-value")]
        )
        let object = try JSONSerialization.jsonObject(with: template) as? [String: Any]
        check(object?["title"] as? String == "myproject", "template carries the title")
        check(object?["category"] as? String == "LOGIN", "template category is LOGIN")
        let fields = object?["fields"] as? [[String: Any]]
        check(fields?.count == 1, "template has one field")
        check(fields?.first?["type"] as? String == "CONCEALED", "template field is concealed")
        check(fields?.first?["label"] as? String == "SLACK_TOKEN", "template field label is the var name")
        check(fields?.first?["value"] as? String == "xoxb-value", "template field carries the value")
    } catch {
        check(false, "create template threw: \(error)")
    }
    checkThrows("create template rejects an invalid title") {
        _ = try OnePasswordItemWrite.createTemplate(title: "a/b", fields: [])
    }

    // Edit template: existing labels updated in place (ids and purposes kept),
    // new labels appended concealed, unrelated item keys untouched.
    do {
        let existing: [String: Any] = [
            "id": "abc123", "title": "myproject", "version": 3,
            "vault": ["id": "v1", "name": "Employee"],
            "fields": [
                ["id": "username", "label": "username", "purpose": "USERNAME", "type": "STRING", "value": "u"],
                ["id": "f2", "label": "OLD_TOKEN", "type": "CONCEALED", "value": "stale"],
            ],
        ]
        let updated = try OnePasswordItemWrite.updatedItemJSON(
            existingItem: try JSONSerialization.data(withJSONObject: existing),
            fields: [
                .init(label: "OLD_TOKEN", value: "fresh"),
                .init(label: "NEW_KEY", value: "brand-new"),
            ]
        )
        let object = try JSONSerialization.jsonObject(with: updated) as? [String: Any]
        check(object?["id"] as? String == "abc123", "edit template keeps the item id")
        check(object?["version"] as? Int == 3, "edit template keeps unrelated keys")
        let fields = object?["fields"] as? [[String: Any]]
        check(fields?.count == 3, "edit template appends only the new field")
        let old = fields?.first { ($0["label"] as? String) == "OLD_TOKEN" }
        check(old?["value"] as? String == "fresh", "existing label's value is replaced")
        check(old?["id"] as? String == "f2", "existing field keeps its id")
        let new = fields?.first { ($0["label"] as? String) == "NEW_KEY" }
        check(new?["type"] as? String == "CONCEALED", "appended field is concealed")
    } catch {
        check(false, "edit template threw: \(error)")
    }
    checkThrows("edit template rejects non-object item JSON") {
        _ = try OnePasswordItemWrite.updatedItemJSON(existingItem: Data("[]".utf8), fields: [])
    }

    // Field values by label, for the never-overwrite check: a field without a
    // value, or a label used twice, cannot be compared and reads as unknown.
    do {
        let item: [String: Any] = ["id": "abc123", "fields": [
            ["label": "SAME", "value": "a"],
            ["label": "HIDDEN"],
            ["label": "TWICE", "value": "x"],
            ["label": "TWICE", "value": "x"],
            ["value": "no label"],
        ]]
        let values = try OnePasswordItemWrite.fieldValuesByLabel(
            existingItem: try JSONSerialization.data(withJSONObject: item))
        check(values.count == 3, "field reader keeps each labelled field once")
        check(values["SAME"] == .some("a"), "field reader returns a field's value")
        check(values["HIDDEN"] == .some(nil) && values["TWICE"] == .some(nil),
              "a valueless or repeated label reads as present but not comparable")
    } catch {
        check(false, "field reader threw: \(error)")
    }

    // Protect flows never replace a stored value (backend-neutral: the native
    // store and 1Password both pass their existing names through this).
    let placed = NativeStoreImport.collisionFreeKeys(
        for: ["FREE": "1", "SAME": "2", "DIFFERENT": "3", "UNKNOWN": "4", "DIFFERENT_2": "5"],
        existing: ["SAME": "2", "DIFFERENT": "old", "UNKNOWN": nil, "UNKNOWN_2": "other"],
        isValidKey: NativeStoreDocument.isValidKey)
    check(placed["FREE"] == "FREE", "a free name is kept")
    check(placed["SAME"] == "SAME", "a name already holding the identical value is reused")
    check(placed["DIFFERENT_2"] == "DIFFERENT_2" && placed["DIFFERENT"] == "DIFFERENT_3",
          "a different stored value moves the import to the next suffix no other import claims")
    check(placed["UNKNOWN"] == "UNKNOWN_3",
          "a stored value that cannot be compared is never replaced")
    check(Set(placed.values).count == placed.count, "every import gets its own name")
    let unplaceable = NativeStoreImport.collisionFreeKeys(
        for: ["TAKEN": "new"], existing: ["TAKEN": "old"], isValidKey: { _ in false })
    check(unplaceable.isEmpty, "a value with no valid free name is left unplaced, not overwritten")

    // The argv builders carry only metadata; the value travels via stdin.
    let secret = "super-secret-value"
    let argv = OnePasswordItemWrite.getItemArguments(title: "t", vault: "v")
        + OnePasswordItemWrite.createArguments(vault: "v")
        + OnePasswordItemWrite.editArguments(itemID: "abc123")
    check(!argv.joined(separator: " ").contains(secret), "no value ever appears in op argv")
    check(OnePasswordItemWrite.createArguments(vault: "v").last == "-",
          "create reads its template from stdin")
}
