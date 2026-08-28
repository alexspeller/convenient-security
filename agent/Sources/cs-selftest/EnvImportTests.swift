import ConvenientSecurity
import Foundation
import OnePasswordAdapter

// Env-file import (`csec protect --env`) building blocks: the name/value
// secret heuristics, the position-preserving env parser + rewriter, and the
// picker selection model. All pure — no TTY, no filesystem, no agent.

func secretHeuristicsTests() {
    // Name heuristic (moved from onboarding; behavior unchanged).
    for name in ["SLACK_TOKEN", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "MY_API_KEY", "OAUTH_CLIENT"] {
        check(SecretHeuristics.nameLooksSecretLike(name), "name heuristic: \(name) is secret-like")
    }
    for name in ["PORT", "NODE_ENV", "HOME", "EDITOR", "LOG_LEVEL"] {
        check(!SecretHeuristics.nameLooksSecretLike(name), "name heuristic: \(name) is not secret-like")
    }

    // Value heuristic: known token shapes.
    for value in [
        "xoxb-synthetic-fixture-aaaabbbbccccdddd",
        "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        "sk-proj-abc123def456ghi789",
        "github_pat_11ABCDEFG0abcdefghijk",
        "AKIAIOSFODNN7EXAMPLE",
        "AIzaSyD-abc123def456ghi789jkl012mno345",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        "-----BEGIN RSA PRIVATE KEY-----",
        "d41d8cd98f00b204e9800998ecf8427ea3f8b1c2d41d8cd9",
        "QmFzZTY0UmFuZG9tRGF0YTEyMzQ1Ng==",
    ] {
        check(SecretHeuristics.valueLooksSecretLike(value), "value heuristic: secret-like accepted")
    }

    // Value heuristic: ordinary configuration stays unflagged.
    for value in [
        "3000", "true", "development", "postgres", "/usr/local/bin",
        "en_US.UTF-8", "hello world this is text", "my-app-name-for-prod-use",
        "sk-x",
    ] {
        check(!SecretHeuristics.valueLooksSecretLike(value), "value heuristic: plain value rejected (\(value))")
    }

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
            document?.rewritten(references: [:]) == Data(fixture.utf8),
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

    // Splicing: every quoting style collapses to a double-quoted reference,
    // with surrounding bytes (indentation, export, trailing comments) intact.
    let reference = ["KEY": "csec://store-ab12/KEY"]
    let splices: [(String, String)] = [
        ("KEY=abc\n", "KEY=\"csec://store-ab12/KEY\"\n"),
        ("KEY=abc  # keep me\n", "KEY=\"csec://store-ab12/KEY\"  # keep me\n"),
        ("KEY='a b c'\n", "KEY=\"csec://store-ab12/KEY\"\n"),
        ("KEY=\"a\\\"b\" # note\n", "KEY=\"csec://store-ab12/KEY\" # note\n"),
        ("  export KEY=abc\nOTHER=1\n", "  export KEY=\"csec://store-ab12/KEY\"\nOTHER=1\n"),
        ("KEY=abc\r\n", "KEY=\"csec://store-ab12/KEY\"\r\n"),
    ]
    for (input, expected) in splices {
        let document = envDoc(input)
        check(
            document?.rewritten(references: reference) == Data(expected.utf8),
            "splice rewrites only the value span"
        )
    }

    // Dedupe: last non-commented occurrence wins; every occurrence is
    // rewritten so no stale plaintext survives; commented stays commented.
    do {
        let document = envDoc("# TOKEN=old-value\nTOKEN=first9999\nTOKEN=last12345\n")
        let token = candidate(document, "TOKEN")
        check(document?.candidates.count == 1, "duplicate names collapse to one candidate")
        check(token?.importValue == "last12345", "last non-commented occurrence wins")
        check(token?.occurrenceCount == 3, "occurrence count spans commented and live lines")
        check(token?.differingValues == true, "differing duplicate values are flagged")
        check(token?.winningIsCommented == false, "live occurrence marks the name live")
        let rewritten = document?.rewritten(references: ["TOKEN": "csec://s/TOKEN"])
        check(
            rewritten == Data("# TOKEN=\"csec://s/TOKEN\"\nTOKEN=\"csec://s/TOKEN\"\nTOKEN=\"csec://s/TOKEN\"\n".utf8),
            "every occurrence is scrubbed; commented lines stay commented"
        )
    }

    // Commented-only names are candidates but never preselected.
    do {
        let commented = candidate(envDoc("# API_KEY=abc12345\n"), "API_KEY")
        check(commented?.kind == .importable, "commented-only assignment is offered")
        check(commented?.winningIsCommented == true, "commented-only assignment is marked commented")
        check(commented?.preselect == false, "commented-only assignment is not preselected")
        check(commented?.lineNumber == 1, "line number is 1-based")
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
        envDoc("KEY=\"$HOME/x\"\n")?.rewritten(references: ["KEY": "csec://s/KEY"])
            == Data("KEY=\"$HOME/x\"\n".utf8),
        "unsupported occurrences are never rewritten"
    )

    // A live parseable occurrence wins over a commented unsupported one, and
    // only the parseable line is rewritten.
    do {
        let document = envDoc("# KEY=\"$OLD\"\nKEY=real1234\n")
        check(candidate(document, "KEY")?.kind == .importable, "live parseable occurrence wins")
        check(
            document?.rewritten(references: ["KEY": "csec://s/KEY"])
                == Data("# KEY=\"$OLD\"\nKEY=\"csec://s/KEY\"\n".utf8),
            "unsupported commented twin stays untouched"
        )
    }

    // Empty values are surfaced as empty, not importable, and not rewritten.
    for fixture in ["KEY=\n", "KEY=   # note\n", "KEY=\"\"\n", "KEY=''\n"] {
        check(candidate(envDoc(fixture), "KEY")?.kind == .empty, "empty value kind: \(fixture.trimmingCharacters(in: .newlines))")
        check(
            envDoc(fixture)?.rewritten(references: ["KEY": "csec://s/KEY"]) == Data(fixture.utf8),
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
    check(rows.map(\.name) == ["SLACK_TOKEN", "PORT", "DB_PASSWORD", "EXISTING", "BAD", "EMPTY"],
          "rows preserve candidate order")
    check(rows.map(\.selectable) == [true, true, true, false, false, false],
          "importable rows selectable; reference/unsupported/empty rows are info")
    check(initiallySelected == [0], "only the live secret-like var starts checked")
    check(rows[2].annotation.contains("commented"), "commented row is annotated")
    check(rows[2].secretLike, "commented secret-like name keeps its hint")
    check(rows[3].annotation.contains("already csec://"), "reference row names its scheme")
    check(rows[4].annotation.contains("unsupported"), "unsupported row is annotated")
    check(rows[5].annotation.contains("empty"), "empty row is annotated")

    var model = EnvSelectModel(rows: rows, initiallySelected: initiallySelected)
    check(model.selectedNames == ["SLACK_TOKEN"], "initial selection honored")

    model.moveDown()
    model.toggle()
    check(model.selectedNames == ["SLACK_TOKEN", "PORT"], "toggle selects under cursor")

    model.moveDown(); model.moveDown(); model.moveDown()
    model.toggle()
    check(model.selectedNames == ["SLACK_TOKEN", "PORT"], "toggle is a no-op on info rows")

    model.toggleAll()
    check(model.selectedNames == ["SLACK_TOKEN", "PORT", "DB_PASSWORD"],
          "toggleAll selects only selectable rows")
    model.toggleAll()
    check(model.selectedNames.isEmpty, "toggleAll clears when everything selectable is selected")

    for _ in 0..<20 { model.moveDown() }
    check(model.cursor == rows.count - 1, "cursor clamps at the bottom")
    for _ in 0..<20 { model.moveUp() }
    check(model.cursor == 0, "cursor clamps at the top")

    let rendered = model.render(color: false, width: 100)
    check(rendered.contains("[ ] SLACK_TOKEN"), "render shows checkbox and name")
    check(rendered.contains(" -  EXISTING"), "render shows info glyph for unselectable rows")
    check(!rendered.contains("xoxb-"), "render never shows values")
    check(!rendered.contains("hunter2"), "render never shows commented values")
    check(!rendered.contains("\u{1B}"), "colorless render has no ANSI escapes")
    check(rendered.contains("0 of 3 selected"), "footer counts selectable rows")

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

    // The argv builders carry only metadata; the value travels via stdin.
    let secret = "super-secret-value"
    let argv = OnePasswordItemWrite.getItemArguments(title: "t", vault: "v")
        + OnePasswordItemWrite.createArguments(vault: "v")
        + OnePasswordItemWrite.editArguments(itemID: "abc123")
    check(!argv.joined(separator: " ").contains(secret), "no value ever appears in op argv")
    check(OnePasswordItemWrite.createArguments(vault: "v").last == "-",
          "create reads its template from stdin")
}
