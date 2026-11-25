import ConvenientSecurity
import Foundation

/// `SSHConfigAgentPins` finds the keys an ssh config uses with no agent or
/// another agent, which protect must leave as files (csec-924: moving
/// `~/.ssh/nimbus-git`, used with `IdentityAgent none`, broke git to nimbus).
func sshConfigAgentPinsTests() {
    let home = "/Users/tester"
    let socket = "/private/var/folders/xx/T/convenient-security-501/ssh-agent.sock"
    func pins(_ files: [String: String], entries: [String: [String]] = [:]) -> [SSHConfigAgentPin] {
        SSHConfigAgentPins.scan(
            homeDirectory: home,
            csecSocketPath: socket,
            readText: { files[$0] },
            directoryEntries: { entries[$0] ?? [] }
        )
    }
    let config = "\(home)/.ssh/config"

    let nimbus = pins([config: """
        Host github.com
          IdentityFile ~/.ssh/id_ed25519

        # The backup remotes: a plain file, no agent prompt.
        Host nimbus-git
          Hostname 192.0.2.10
          IdentityFile ~/.ssh/nimbus-git
          IdentitiesOnly yes
          IdentityAgent none
        """])
    check(nimbus == [SSHConfigAgentPin(
              keyPath: "\(home)/.ssh/nimbus-git", agent: .none, configPath: config, line: 7)],
          "a block's IdentityAgent none pins its IdentityFile, and only that one (\(nimbus))")
    check(nimbus.first?.describe(homeDirectory: home) == "IdentityAgent none at ~/.ssh/config:7",
          "a pin describes itself home-relative, with the IdentityFile line")

    let agents = pins([config: """
        Host a
          IdentityFile ~/.ssh/a
          IdentityAgent SSH_AUTH_SOCK
        Host b
          IdentityFile %d/.ssh/b
          IdentityAgent \(socket)
        Host c
          IdentityFile ${HOME}/.ssh/c
          IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
        Host d
          IdentityFile ~/.ssh/%h
          IdentityAgent none
        """])
    check(agents.map(\.keyPath) == ["\(home)/.ssh/c"] && agents.first?.agent == .other,
          "SSH_AUTH_SOCK and csec's own socket are not pins; another agent's socket is; "
            + "a host-dependent IdentityFile is not guessed (\(agents))")

    let universal = pins([config: """
        Host early
          IdentityFile ~/.ssh/early
          IdentityAgent SSH_AUTH_SOCK
        Host late
          IdentityFile ~/.ssh/late
        Host *
          IdentityAgent none
        """])
    check(universal.map(\.keyPath) == ["\(home)/.ssh/late"],
          "a later Host * supplies the agent only to a block that set none itself (\(universal))")

    let global = pins([config: """
        IdentityAgent none
        Host own
          IdentityFile ~/.ssh/own
          IdentityAgent SSH_AUTH_SOCK
        Match all
          IdentityFile ~/.ssh/everywhere
        """])
    check(Set(global.map(\.keyPath)) == ["\(home)/.ssh/own", "\(home)/.ssh/everywhere"],
          "a value at the top of the file wins over a block's own, as ssh reads the first one (\(global))")

    let syntax = pins([config: """
        HOST quoted
          identityfile="~/.ssh/key two"   # trailing comment
          IDENTITYAGENT=None
        """])
    check(syntax.map(\.keyPath) == ["\(home)/.ssh/key two"],
          "keywords are case-insensitive, '=' and quotes are understood (\(syntax))")

    let included = pins(
        [
            config: "Include config.d/*\nHost other\n  IdentityFile ~/.ssh/other\n",
            "\(home)/.ssh/config.d/nimbus": "Host nimbus-git\n  IdentityFile ~/.ssh/nimbus-git\n  IdentityAgent none\n",
            "\(home)/.ssh/config.d/.hidden": "Host h\n  IdentityFile ~/.ssh/h\n  IdentityAgent none\n",
        ],
        entries: ["\(home)/.ssh/config.d": ["nimbus", ".hidden"]]
    )
    check(included == [SSHConfigAgentPin(
              keyPath: "\(home)/.ssh/nimbus-git", agent: .none,
              configPath: "\(home)/.ssh/config.d/nimbus", line: 2)],
          "an Include glob relative to ~/.ssh is followed, naming the included file (\(included))")

    check(pins([:]).isEmpty, "no ssh config, no pins")
    let loop = [config: "Include config\nHost x\n  IdentityFile ~/.ssh/x\n  IdentityAgent none\n"]
    check(!pins(loop).isEmpty, "a self-including config stops at OpenSSH's Include depth")
}
