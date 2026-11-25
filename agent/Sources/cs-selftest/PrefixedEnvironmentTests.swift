import Foundation
import ConvenientSecurity

func prefixedEnvironmentTests() {
    do {
        let base = ["csec_GITHUB_TOKEN": "op://vault/github/token",
                    "csec_API_KEY": "csec://dev/API_KEY", "PATH": "/usr/bin"]
        let plan = try ExecPlanner.plan(environment: base, explicit: [], knownSchemes: ["op", "csec"])
        check(plan.assignments == ["GITHUB_TOKEN": "op://vault/github/token", "API_KEY": "csec://dev/API_KEY"],
              "prefixed aliases target ordinary names across providers")
        let result = try ExecPlanner.resolvedEnvironment(base: base, plan: plan, values: [
            "op://vault/github/token": Data("synthetic-github".utf8),
            "csec://dev/API_KEY": Data("synthetic-api".utf8),
        ])
        check(result == ["GITHUB_TOKEN": "synthetic-github", "API_KEY": "synthetic-api", "PATH": "/usr/bin"],
              "resolved environment removes source aliases and preserves unrelated names")
        check(base["GITHUB_TOKEN"] == nil, "planning and injection leave parent environment unchanged")

        let override = try ExecPlanner.plan(
            environment: ["TOKEN": "ordinary", "csec_TOKEN": "malformed"],
            explicit: [("csec_TOKEN", "op://chosen/token")], knownSchemes: ["op"])
        check(override.assignments == ["TOKEN": "op://chosen/token"] && override.referenceNames == ["csec_TOKEN"],
              "explicit --set normalizes and overrides both ambient forms")
        let caseSensitive = try ExecPlanner.plan(
            environment: ["CSEC_TOKEN": "op://v/token"], explicit: [], knownSchemes: ["op"])
        check(caseSensitive.assignments == ["CSEC_TOKEN": "op://v/token"], "prefix is case-sensitive")
    } catch { check(false, "prefixed environment planning succeeds: \(error)") }

    for environment in [
        ["TOKEN": "ordinary", "csec_TOKEN": "op://v/token"],
        ["TOKEN": "op://v/one", "csec_TOKEN": "op://v/two"],
        ["csec_TOKEN": "malformed-synthetic-value"],
        ["csec_TOKEN": "unknown://v/token"],
        ["csec_": "op://v/token"],
        ["csec_1TOKEN": "op://v/token"],
        ["csec_csec_TOKEN": "op://v/token"],
    ] {
        checkThrows("ambiguous or invalid prefixed environment is rejected before access") {
            _ = try ExecPlanner.plan(environment: environment, explicit: [], knownSchemes: ["op"])
        }
    }
    do {
        _ = try ExecPlanner.plan(environment: ["csec_TOKEN": "private-synthetic-marker"], explicit: [], knownSchemes: ["op"])
        check(false, "invalid alias fails")
    } catch {
        check(!String(describing: error).contains("private-synthetic-marker"), "invalid alias diagnostic is value-free")
    }

    do {
        let original = "  export GITHUB_TOKEN='op://vault/github/token' # keep\r\nAPI_KEY=csec://dev/API_KEY\r\nPORT=3000"
        let document = try EnvFileDocument(data: Data(original.utf8))
        let migrated = try document.rewritten(references: [:])
        check(migrated == Data("  export csec_GITHUB_TOKEN='op://vault/github/token' # keep\r\ncsec_API_KEY=csec://dev/API_KEY\r\nPORT=3000".utf8),
              "existing references migrate without re-import, preserving quoting, export, comments and CRLF")
        let repeated = try EnvFileDocument(data: migrated)
        check(try repeated.rewritten(references: [:]) == migrated, "prefix migration is idempotent")
        check(repeated.referenceNamesToPrefix.isEmpty, "prefixed references need no further migration")
        let prefixed = try EnvFileDocument(data: Data("csec_TOKEN=synthetic\n".utf8))
        check(try prefixed.rewritten(references: ["csec_TOKEN": "op://v/token"])
              == Data("csec_TOKEN=\"op://v/token\"\n".utf8), "import never adds a second prefix")
        let shadowed = try EnvFileDocument(data: Data("TOKEN=\nTOKEN=synthetic\n".utf8))
        check(try shadowed.rewritten(references: ["TOKEN": "op://v/token"])
              == Data("csec_TOKEN=\ncsec_TOKEN=\"op://v/token\"\n".utf8), "shadowed empty definitions do not leave an unprefixed collision")
        let comment = try EnvFileDocument(data: Data("# csec_TOKEN=op://v/old\nTOKEN=synthetic\n".utf8))
        check(try comment.rewritten(references: ["TOKEN": "op://v/new"])
              == Data("# csec_TOKEN=op://v/old\ncsec_TOKEN=\"op://v/new\"\n".utf8), "commented references do not conflict with live imports")
    } catch { check(false, "reference migration succeeds: \(error)") }

    for text in ["TOKEN=synthetic\ncsec_TOKEN=op://v/token\n",
                 "TOKEN=op://v/token\ncsec_TOKEN=op://v/other\n"] {
        checkThrows("env rename collision is rejected before import") {
            let document = try EnvFileDocument(data: Data(text.utf8))
            try document.validateRewrite(selectedKeys: ["TOKEN"])
        }
    }
}
