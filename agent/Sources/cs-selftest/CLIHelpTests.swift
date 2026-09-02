import ConvenientSecurity
import Foundation

// CLI help catalog + renderer (pure — no TTY, no dispatch). The completeness
// check pins the catalog against the launcher's actual dispatch switch: the
// expected list below is the one place that must be kept in step with the
// `switch command` in csec/main.swift, and a drift in either direction fails.

func cliHelpTests() {
    // The 24 commands the launcher dispatches (csec/main.swift `switch command`).
    let dispatched: Set<String> = [
        "get", "exec", "session", "creds", "exec-fd", "exec-file", "bridge",
        "tool-exec", "hook", "hook-config", "edit", "protect", "setup", "audit",
        "remote", "ssh", "automation", "grants", "revoke", "install", "uninstall",
        "status", "doctor", "root-status",
    ]
    let cataloged = Set(CLICatalog.commands.map(\.name))
    check(cataloged == dispatched,
          "the help catalog has exactly one entry per dispatched command")
    check(CLICatalog.commands.count == 24,
          "the catalog has all 24 commands")
    for name in dispatched {
        check(CLICatalog.command(named: name) != nil,
              "catalog lookup finds dispatched command '\(name)'")
    }

    // Every command has a summary, a synopsis, and a real category.
    for command in CLICatalog.commands {
        check(!command.summary.isEmpty && !command.synopsis.isEmpty,
              "command '\(command.name)' has a summary and synopsis")
    }

    // Per-command rendering: title, options, first synopsis, subactions present.
    for command in CLICatalog.commands {
        let rendered = CLIHelpRenderer.renderCommand(command, color: false, width: 80)
        check(rendered.contains("csec \(command.name)"),
              "rendered '\(command.name)' help names the command")
        if let first = command.synopsis.first {
            check(rendered.contains(first),
                  "rendered '\(command.name)' help shows its first synopsis line")
        }
        for option in command.options {
            check(rendered.contains(option.flags),
                  "rendered '\(command.name)' help lists option \(option.flags)")
        }
        for subaction in command.subactions {
            check(rendered.contains(subaction.name),
                  "rendered '\(command.name)' help lists subaction \(subaction.name)")
        }
    }

    // Color gating: no ESC when color is off, ESC present when on.
    let exec = CLICatalog.command(named: "exec")!
    check(!CLIHelpRenderer.renderCommand(exec, color: false, width: 80).contains("\u{1B}"),
          "command help with color:false emits no ANSI escapes")
    check(CLIHelpRenderer.renderCommand(exec, color: true, width: 80).contains("\u{1B}"),
          "command help with color:true emits ANSI escapes")

    // Global listing: every non-hidden name and every category title, hidden
    // commands filtered out of the listing but still reachable by name.
    let global = CLIHelpRenderer.renderGlobal(color: false, width: 100)
    for command in CLICatalog.commands where !command.hidden {
        check(global.contains(command.name),
              "global help lists non-hidden command '\(command.name)'")
    }
    for category in CLICategory.allCases {
        check(global.contains(category.title),
              "global help shows category heading '\(category.title)'")
    }
    check(!global.contains(" bridge "),
          "global help hides the private 'bridge' command from the listing")
    check(CLICatalog.command(named: "bridge") != nil,
          "the hidden 'bridge' command is still reachable by name")
    check(CLICatalog.command(named: "bridge")?.hidden == true,
          "'bridge' is marked hidden")
    check(!CLIHelpRenderer.renderGlobal(color: false, width: 100).contains("\u{1B}"),
          "global help with color:false emits no ANSI escapes")
    check(CLIHelpRenderer.renderGlobal(color: true, width: 100).contains("\u{1B}"),
          "global help with color:true emits ANSI escapes")

    // "Did you mean?" suggestions within edit distance 2, nil when nothing close.
    check(CLICatalog.suggestion(for: "exce") == "exec", "suggestion: 'exce' -> exec")
    check(CLICatalog.suggestion(for: "statu") == "status", "suggestion: 'statu' -> status")
    check(CLICatalog.suggestion(for: "instal") == "install", "suggestion: 'instal' -> install")
    check(CLICatalog.suggestion(for: "xyzzy-nowhere-near") == nil,
          "suggestion: a far-off token has no suggestion")
    check(CLICatalog.suggestion(for: "bridge") != "bridge" || CLICatalog.command(named: "bridge") != nil,
          "hidden commands are not offered as suggestions")
    check(CLICatalog.suggestion(for: "bridg") == nil,
          "a near-miss of a hidden command ('bridg') is not suggested")

    // Unknown-command rendering sanitizes the user-supplied name (control/bidi
    // characters cannot inject lines) and still shows the global listing.
    let hostile = "ex\u{202e}ec\nDROP"
    let unknown = CLIHelpRenderer.renderUnknownCommand(hostile, color: false, width: 100)
    check(!unknown.contains("\u{202e}") && !unknown.contains("ex\u{202e}ec"),
          "unknown-command rendering strips bidi/control characters from the typed name")
    check(unknown.contains("unknown command"),
          "unknown-command rendering states the command was unknown")
    check(unknown.contains("Usage:"),
          "unknown-command rendering appends the global command listing")
}

func statusRendererTests() {
    let rows = [
        StatusRow(label: "Installed app", value: "installed", state: .ok),
        StatusRow(label: "LaunchAgent", value: "awaiting approval", state: .warn),
        StatusRow(label: "Root helper", value: "unavailable", state: .bad),
        StatusRow(label: "Remote approval", value: "off", state: .neutral),
    ]

    let plain = StatusRenderer.render(
        title: "Convenient Security status", rows: rows,
        overallHealthy: false, color: false, width: 80)
    check(plain.contains("Convenient Security status"), "status render shows the title")
    for row in rows {
        check(plain.contains(row.label) && plain.contains(row.value),
              "status render includes row '\(row.label)' and its value")
    }
    check(plain.contains("needs attention"), "a false verdict renders the 'needs attention' badge")
    check(!plain.contains("\u{1B}"), "status render with color:false emits no ANSI escapes")

    let colored = StatusRenderer.render(
        title: "Convenient Security status", rows: rows,
        overallHealthy: false, color: true, width: 80)
    check(colored.contains("\u{1B}"), "status render with color:true emits ANSI escapes")
    check(colored.contains("●"), "graded status rows render a filled glyph")

    let healthy = StatusRenderer.render(
        title: "S", rows: rows, overallHealthy: true, color: false, width: 80)
    check(healthy.contains("healthy") && !healthy.contains("needs attention"),
          "a true verdict renders the 'healthy' badge")
    let unknown = StatusRenderer.render(
        title: "S", rows: rows, overallHealthy: nil, color: false, width: 80)
    check(!unknown.contains("healthy") && !unknown.contains("needs attention"),
          "a nil verdict renders a neutral badge")

    // A .bad row must be visually distinct from an .ok row under color.
    let okColored = StatusRenderer.render(
        title: "S", rows: [StatusRow(label: "X", value: "v", state: .ok)],
        overallHealthy: nil, color: true, width: 80)
    let badColored = StatusRenderer.render(
        title: "S", rows: [StatusRow(label: "X", value: "v", state: .bad)],
        overallHealthy: nil, color: true, width: 80)
    check(okColored != badColored, "an ok row and a bad row render with distinct color codes")
}
