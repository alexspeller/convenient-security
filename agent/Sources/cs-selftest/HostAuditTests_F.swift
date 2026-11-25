import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Domain F — Developer attack surface (HA-F01…HA-F13).
//
// Every fixture here is synthetic and value-free: fake bundle-ish ids, fake
// version strings, the harness's synthetic /Users/tester home, and permission
// classes. No real secret, token, host name, or user path is embedded. Each
// check gets a PASS (secure state) and a FAIL (insecure state); the gated /
// privileged HA-F10 additionally gets UNKNOWN cases asserting the honest-coverage
// guarantee (never .pass when the sweep did not complete or was not opted into).

func hostAuditTests_F() async {
    await hostAuditTests_F01()
    await hostAuditTests_F02()
    await hostAuditTests_F03()
    await hostAuditTests_F04()
    await hostAuditTests_F05()
    await hostAuditTests_F06()
    await hostAuditTests_F07()
    await hostAuditTests_F08()
    await hostAuditTests_F09()
    await hostAuditTests_F10()
    await hostAuditTests_F11()
    await hostAuditTests_F12()
    await hostAuditTests_F13()
}

// Home used by the fake file inspector; synthetic, not a real user path.
private let fHome = "/Users/tester"

// MARK: HA-F01 — PATH has no hijackable / early-writable entries

private func hostAuditTests_F01() async {
    // PASS: /usr/bin first (sets sawUsrBin), both entries root-owned 0755 — no
    // relative/empty entry, nothing group/other-writable, nothing user-writable
    // ordered ahead of /usr/bin.
    let cleanPerms = FakeFileInspector(perms: [
        "/usr/bin": HostFilePermissions(mode: 0o755, ownerUID: 0, groupGID: 0),
        "/bin": HostFilePermissions(mode: 0o755, ownerUID: 0, groupGID: 0),
    ])
    await expectStatus("HA-F01", in: DomainF_Developer.checks,
        makeAuditContext(files: cleanPerms, environment: ["PATH": "/usr/bin:/bin"]),
        .pass, "clean absolute PATH -> pass")

    // FAIL: a group-writable dir ordered ahead of /usr/bin (early hijack).
    let earlyWritable = FakeFileInspector(perms: [
        "/opt/tools": HostFilePermissions(mode: 0o775, ownerUID: 0, groupGID: 20),
        "/usr/bin": HostFilePermissions(mode: 0o755, ownerUID: 0, groupGID: 0),
    ])
    await expectStatus("HA-F01", in: DomainF_Developer.checks,
        makeAuditContext(files: earlyWritable, environment: ["PATH": "/opt/tools:/usr/bin"]),
        .fail, "group-writable dir ahead of /usr/bin -> fail")

    // FAIL: a relative (cwd-resolving) PATH entry.
    await expectStatus("HA-F01", in: DomainF_Developer.checks,
        makeAuditContext(files: cleanPerms, environment: ["PATH": "/usr/bin:relative/bin"]),
        .fail, "relative PATH entry -> fail")

    // UNKNOWN: PATH not set in the audit environment (never a pass).
    await expectStatus("HA-F01", in: DomainF_Developer.checks,
        makeAuditContext(environment: [:]),
        .unknown, "PATH unset -> unknown")
}

// MARK: HA-F02 — No global DYLD_* / LD_* dylib-preload injection

private func hostAuditTests_F02() async {
    // PASS: no injector in env, launchctl getenv returns nothing (default
    // fallback is .unavailable), no shell profile mentions one.
    await expectStatus("HA-F02", in: DomainF_Developer.checks,
        makeAuditContext(),
        .pass, "no dylib-preload injector anywhere -> pass")

    // FAIL: a shell profile exports an injector var.
    let profileExports = FakeFileInspector(texts: [
        "\(fHome)/.zshrc": "export DYLD_INSERT_LIBRARIES=/tmp/synthetic.dylib\n",
    ])
    await expectStatus("HA-F02", in: DomainF_Developer.checks,
        makeAuditContext(files: profileExports),
        .fail, "shell profile exports DYLD injector -> fail")

    // FAIL: an injector set via launchctl (non-empty getenv stdout).
    await expectStatus("HA-F02", in: DomainF_Developer.checks,
        makeAuditContext(commands: [
            "launchctl.getenv.DYLD_INSERT_LIBRARIES": ok("/tmp/synthetic.dylib\n"),
        ]),
        .fail, "launchctl setenv injector -> fail")
}

// MARK: HA-F03 — Package managers do not run install lifecycle scripts

private func hostAuditTests_F03() async {
    // PASS: ~/.npmrc sets ignore-scripts=true (lifecycle scripts disabled).
    let npmSecure = FakeFileInspector(texts: [
        "\(fHome)/.npmrc": "ignore-scripts=true\n",
    ])
    await expectStatus("HA-F03", in: DomainF_Developer.checks,
        makeAuditContext(files: npmSecure),
        .pass, "npm ignore-scripts=true -> pass")

    // FAIL: ~/.npmrc leaves ignore-scripts=false (the malicious-postinstall vector).
    let npmInsecure = FakeFileInspector(texts: [
        "\(fHome)/.npmrc": "ignore-scripts=false\n",
    ])
    await expectStatus("HA-F03", in: DomainF_Developer.checks,
        makeAuditContext(files: npmInsecure),
        .fail, "npm ignore-scripts=false -> fail")

    // UNKNOWN: yarn classic (.yarnrc present, no togglable key) is indeterminate.
    let yarnClassic = FakeFileInspector(texts: [
        "\(fHome)/.yarnrc": "registry \"https://registry.example.test\"\n",
    ])
    await expectStatus("HA-F03", in: DomainF_Developer.checks,
        makeAuditContext(files: yarnClassic),
        .unknown, "yarn classic exposes no toggle -> unknown")

    // notApplicable: no JS package manager configuration for this user.
    await expectStatus("HA-F03", in: DomainF_Developer.checks,
        makeAuditContext(),
        .notApplicable, "no package manager config -> notApplicable")
}

// MARK: HA-F04 — Editor extensions have named publishers, no over-broad activation

private func hostAuditTests_F04() async {
    let extRoot = "\(fHome)/.vscode/extensions"

    // PASS: one extension with a named publisher and no "*" activation event.
    let scopedExt = FakeFileInspector(
        texts: [
            "\(extRoot)/vendor.scoped-ext-1.0.0/package.json":
                #"{"name":"scoped-ext","publisher":"vendor","version":"1.0.0","activationEvents":["onLanguage:swift"]}"#,
        ],
        entries: [extRoot: ["vendor.scoped-ext-1.0.0"]],
        directories: [extRoot, "\(extRoot)/vendor.scoped-ext-1.0.0"]
    )
    await expectStatus("HA-F04", in: DomainF_Developer.checks,
        makeAuditContext(files: scopedExt),
        .pass, "scoped extension with named publisher -> pass")

    // FAIL: an extension with "*" activation and a missing publisher.
    let broadExt = FakeFileInspector(
        texts: [
            "\(extRoot)/anon.broad-ext-2.0.0/package.json":
                #"{"name":"broad-ext","version":"2.0.0","activationEvents":["*"]}"#,
        ],
        entries: [extRoot: ["anon.broad-ext-2.0.0"]],
        directories: [extRoot, "\(extRoot)/anon.broad-ext-2.0.0"]
    )
    await expectStatus("HA-F04", in: DomainF_Developer.checks,
        makeAuditContext(files: broadExt),
        .fail, "always-activate ext with missing publisher -> fail")

    // notApplicable: no editor extension directory present.
    await expectStatus("HA-F04", in: DomainF_Developer.checks,
        makeAuditContext(),
        .notApplicable, "no editor extension dir -> notApplicable")
}

// MARK: HA-F05 — No browser extension holds broad-host + session-theft perms

private func hostAuditTests_F05() async {
    let chromeExtRoot = "\(fHome)/Library/Application Support/Google/Chrome/Default/Extensions"

    // PASS: a narrow MV3 extension (no broad host, no theft permission).
    let narrowExt = FakeFileInspector(
        texts: [
            "\(chromeExtRoot)/aaaa/3.0/manifest.json":
                #"{"manifest_version":3,"permissions":["storage"],"host_permissions":["https://example.test/*"]}"#,
        ],
        entries: [
            chromeExtRoot: ["aaaa"],
            "\(chromeExtRoot)/aaaa": ["3.0"],
        ],
        directories: [chromeExtRoot, "\(chromeExtRoot)/aaaa"]
    )
    await expectStatus("HA-F05", in: DomainF_Developer.checks,
        makeAuditContext(files: narrowExt),
        .pass, "narrow MV3 browser extension -> pass")

    // FAIL: broad host access (<all_urls>) combined with cookie access.
    let dangerousExt = FakeFileInspector(
        texts: [
            "\(chromeExtRoot)/bbbb/1.0/manifest.json":
                #"{"manifest_version":3,"permissions":["cookies"],"host_permissions":["<all_urls>"]}"#,
        ],
        entries: [
            chromeExtRoot: ["bbbb"],
            "\(chromeExtRoot)/bbbb": ["1.0"],
        ],
        directories: [chromeExtRoot, "\(chromeExtRoot)/bbbb"]
    )
    await expectStatus("HA-F05", in: DomainF_Developer.checks,
        makeAuditContext(files: dangerousExt),
        .fail, "broad-host + cookies extension -> fail")

    // notApplicable: no browser profile with extensions present.
    await expectStatus("HA-F05", in: DomainF_Developer.checks,
        makeAuditContext(),
        .notApplicable, "no browser profile -> notApplicable")
}

// MARK: HA-F06 — Global git config has no risky credential/hook/rewrite settings

private func hostAuditTests_F06() async {
    // PASS: a clean global config (identity only).
    let cleanGit = FakeFileInspector(texts: [
        "\(fHome)/.gitconfig": "[user]\n\temail = someone@example.test\n\tname = Some One\n",
    ])
    await expectStatus("HA-F06", in: DomainF_Developer.checks,
        makeAuditContext(files: cleanGit),
        .pass, "clean global git config -> pass")

    // FAIL: credential.helper=store (plaintext credential storage).
    let storeHelper = FakeFileInspector(texts: [
        "\(fHome)/.gitconfig": "[credential]\n\thelper = store\n",
    ])
    await expectStatus("HA-F06", in: DomainF_Developer.checks,
        makeAuditContext(files: storeHelper),
        .fail, "credential.helper=store -> fail")

    // FAIL: safe.directory=* (over-broad trust).
    let wildcardSafe = FakeFileInspector(texts: [
        "\(fHome)/.gitconfig": "[safe]\n\tdirectory = *\n",
    ])
    await expectStatus("HA-F06", in: DomainF_Developer.checks,
        makeAuditContext(files: wildcardSafe),
        .fail, "safe.directory=* -> fail")

    // notApplicable: no global ~/.gitconfig present.
    await expectStatus("HA-F06", in: DomainF_Developer.checks,
        makeAuditContext(),
        .notApplicable, "no global gitconfig -> notApplicable")
}

// MARK: HA-F07 — Docker daemon is not exposed over a TCP socket

private func hostAuditTests_F07() async {
    // PASS: docker CLI present, no DOCKER_HOST, no tcp host in daemon.json.
    let localDocker = FakeFileInspector(executables: ["/opt/homebrew/bin/docker"])
    await expectStatus("HA-F07", in: DomainF_Developer.checks,
        makeAuditContext(files: localDocker),
        .pass, "local docker socket only -> pass")

    // FAIL: DOCKER_HOST over tcp:// (talking to an exposed daemon).
    await expectStatus("HA-F07", in: DomainF_Developer.checks,
        makeAuditContext(
            files: localDocker,
            environment: ["PATH": "/usr/bin:/bin", "DOCKER_HOST": "tcp://198.51.100.10:2375"]),
        .fail, "DOCKER_HOST over tcp -> fail")

    // notApplicable: no docker CLI, no DOCKER_HOST, no user daemon.json.
    await expectStatus("HA-F07", in: DomainF_Developer.checks,
        makeAuditContext(),
        .notApplicable, "no docker anywhere -> notApplicable")
}

// MARK: HA-F08 — SSH client directory perms and config are hardened

private func hostAuditTests_F08() async {
    let sshDir = "\(fHome)/.ssh"

    // PASS: ~/.ssh resolves to 0700, config is 0600, no risky directive, no keys.
    let hardenedSSH = FakeFileInspector(
        perms: [
            "\(sshDir)/.": HostFilePermissions(mode: 0o700, ownerUID: 501, groupGID: 20),
            "\(sshDir)/config": HostFilePermissions(mode: 0o600, ownerUID: 501, groupGID: 20),
        ],
        directories: [sshDir]
    )
    await expectStatus("HA-F08", in: DomainF_Developer.checks,
        makeAuditContext(files: hardenedSSH),
        .pass, "0700 ~/.ssh, 0600 config, no risky directive -> pass")

    // FAIL: config enables StrictHostKeyChecking no.
    let looseDirective = FakeFileInspector(
        texts: ["\(sshDir)/config": "Host *\n    StrictHostKeyChecking no\n"],
        perms: [
            "\(sshDir)/.": HostFilePermissions(mode: 0o700, ownerUID: 501, groupGID: 20),
            "\(sshDir)/config": HostFilePermissions(mode: 0o600, ownerUID: 501, groupGID: 20),
        ],
        directories: [sshDir]
    )
    await expectStatus("HA-F08", in: DomainF_Developer.checks,
        makeAuditContext(files: looseDirective),
        .fail, "StrictHostKeyChecking no -> fail")

    // FAIL: ~/.ssh itself is group/other-accessible.
    let looseDir = FakeFileInspector(
        perms: [
            "\(sshDir)/.": HostFilePermissions(mode: 0o777, ownerUID: 501, groupGID: 20),
        ],
        directories: [sshDir]
    )
    await expectStatus("HA-F08", in: DomainF_Developer.checks,
        makeAuditContext(files: looseDir),
        .fail, "group/other-accessible ~/.ssh -> fail")

    // notApplicable: no ~/.ssh directory present.
    await expectStatus("HA-F08", in: DomainF_Developer.checks,
        makeAuditContext(),
        .notApplicable, "no ~/.ssh -> notApplicable")
}

// MARK: HA-F11 — No plaintext SSH private keys in ~/.ssh

private func hostAuditTests_F11() async {
    let sshDir = "\(fHome)/.ssh"
    // Synthetic keys only; the comment marker must never reach the evidence.
    guard let usable = try? Ed25519SSHFixture(seed: 77) else {
        check(false, "HA-F11: synthetic key fixture")
        return
    }
    let usableKey = String(decoding: usable.privateKeyPEM, as: UTF8.self)
    let dsaKey = "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKBgQ==\n-----END DSA PRIVATE KEY-----\n"
    let encryptedKey = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
        + "DEK-Info: AES-128-CBC,00\n\nMIIE\n-----END RSA PRIVATE KEY-----\n"
    let wrappedKey = "<<EOT\n" + usableKey + "EOT\n"

    // PASS: only what csec leaves behind (a .pub and a sidecar), OpenSSH's own
    // files, and a passphrase-protected key.
    let protectedDir = FakeFileInspector(
        texts: [
            "\(sshDir)/id_ed25519.pub": "ssh-ed25519 AAAA test\n",
            "\(sshDir)/id_ed25519.csec": "{\"ref\":\"csec://ssh-keys/k\"}\n",
            "\(sshDir)/config": "Host *\n  IdentitiesOnly yes\n",
            "\(sshDir)/known_hosts": "github.com ssh-ed25519 AAAA\n",
            "\(sshDir)/id_work": encryptedKey,
        ],
        entries: [sshDir: ["id_ed25519.pub", "id_ed25519.csec", "config", "known_hosts", "id_work"]],
        directories: [sshDir]
    )
    let passing = await evaluateAudit("HA-F11", in: DomainF_Developer.checks, makeAuditContext(files: protectedDir))
    check(passing?.status == .pass && passing?.evidence.contains("1 passphrase-protected") == true,
          "HA-F11: a .pub, a sidecar and a passphrase-protected key pass, noting the encrypted key")

    // FAIL: plaintext keys counted by class, value-free.
    let plaintextDir = FakeFileInspector(
        texts: [
            "\(sshDir)/id_ed25519": usableKey,
            "\(sshDir)/plex_key": usableKey,
            "\(sshDir)/id_dsa": dsaKey,
            "\(sshDir)/id_rsa_terraform": wrappedKey,
            "\(sshDir)/id_work": encryptedKey,
            "\(sshDir)/notes": "rotate the plex key next year\n",
        ],
        entries: [sshDir: ["id_ed25519", "plex_key", "id_dsa", "id_rsa_terraform", "id_work", "notes"]],
        directories: [sshDir]
    )
    let failing = await evaluateAudit("HA-F11", in: DomainF_Developer.checks, makeAuditContext(files: plaintextDir))
    let evidence = failing?.evidence ?? ""
    check(failing?.status == .fail
            && evidence.contains("4 plaintext SSH private key(s)")
            && evidence.contains("2 csec can hold")
            && evidence.contains("1 obsolete")
            && evidence.contains("1 not usable as SSH keys")
            && evidence.contains("1 passphrase-protected"),
          "HA-F11: plaintext keys fail, counted as usable, obsolete and unusable (\(evidence))")
    check(!evidence.contains("synthetic-csec-selftest") && !evidence.contains("PRIVATE KEY")
            && !evidence.contains("plex_key") && !evidence.contains("SHA256:"),
          "HA-F11: evidence names no key material, comment, file name or fingerprint")

    // A key ~/.ssh/config uses with IdentityAgent none still fails, but is
    // counted apart: protecting it would break its host.
    let pinnedDir = FakeFileInspector(
        texts: [
            "\(sshDir)/id_ed25519": usableKey,
            "\(sshDir)/nimbus-git": usableKey,
            "\(sshDir)/config": "Host nimbus-git\n  IdentityFile ~/.ssh/nimbus-git\n  IdentityAgent none\n",
        ],
        entries: [sshDir: ["id_ed25519", "nimbus-git", "config"]],
        directories: [sshDir]
    )
    let pinnedFinding = await evaluateAudit("HA-F11", in: DomainF_Developer.checks, makeAuditContext(files: pinnedDir))
    let pinnedEvidence = pinnedFinding?.evidence ?? ""
    check(pinnedFinding?.status == .fail
            && pinnedEvidence.contains("2 plaintext SSH private key(s)")
            && pinnedEvidence.contains("1 csec can hold")
            && pinnedEvidence.contains("1 that ~/.ssh/config uses with IdentityAgent none")
            && !pinnedEvidence.contains("nimbus-git"),
          "HA-F11: a key pinned away from csec's agent fails, counted apart, unnamed (\(pinnedEvidence))")

    // A symlinked entry is not read through; an unreadable regular file is
    // never a pass.
    let unreadableDir = FakeFileInspector(
        perms: ["\(sshDir)/id_ed25519": HostFilePermissions(mode: 0o600, ownerUID: 501, groupGID: 20)],
        entries: [sshDir: ["id_ed25519", "linked"]],
        directories: [sshDir],
        symlinks: ["\(sshDir)/linked"]
    )
    await expectStatus("HA-F11", in: DomainF_Developer.checks,
        makeAuditContext(files: unreadableDir),
        .unknown, "an unreadable file in ~/.ssh -> unknown, never pass")

    await expectStatus("HA-F11", in: DomainF_Developer.checks,
        makeAuditContext(),
        .notApplicable, "no ~/.ssh -> notApplicable")
}

// MARK: HA-F12 — GitHub CLI token is not readable by every process

private func hostAuditTests_F12() async {
    let gh = "\(fHome)/.config/gh"
    let keychainHit: [String: HostCommandResult] = [
        "security.find-generic-password.gh": HostCommandResult(exitCode: 0, standardOutput: "keychain: \"login\"\n    \"acct\"<blob>=\"octocat\"\n"),
    ]
    let keychainMiss: [String: HostCommandResult] = [
        "security.find-generic-password.gh": HostCommandResult(exitCode: 44, standardOutput: ""),
    ]
    let keyring = FakeFileInspector(
        texts: ["\(gh)/hosts.yml": "github.com:\n    users:\n        octocat:\n    user: octocat\n"],
        directories: [gh]
    )
    let failing = await evaluateAudit("HA-F12", in: DomainF_Developer.checks,
        makeAuditContext(commands: keychainHit, files: keyring))
    check(failing?.status == .fail && failing?.evidence.contains("login keychain") == true
            && failing?.evidence.contains("octocat") == false,
          "HA-F12: gh's keychain token fails, without naming the account")

    let plaintext = FakeFileInspector(
        texts: ["\(gh)/hosts.yml": "github.com:\n    oauth_token: gho_SYNTHETICfixture\n    users:\n        octocat:\n            oauth_token: \"gho_SYNTHETICfixture\"\n"],
        directories: [gh]
    )
    let insecure = await evaluateAudit("HA-F12", in: DomainF_Developer.checks,
        makeAuditContext(commands: keychainMiss, files: plaintext))
    check(insecure?.status == .fail && insecure?.evidence.contains("2 plaintext token line(s)") == true
            && insecure?.evidence.contains("gho_") == false,
          "HA-F12: a plaintext hosts.yml token fails, counted, never shown")

    let proxied = FakeFileInspector(
        texts: ["\(gh)/hosts.yml": "github.com:\n    oauth_token: \(GitHubProxyHTTP.placeholderToken)\n    user: octocat\n"],
        directories: [gh]
    )
    let passing = await evaluateAudit("HA-F12", in: DomainF_Developer.checks,
        makeAuditContext(commands: keychainMiss, files: proxied))
    check(passing?.status == .pass && passing?.evidence.contains("csecd's GitHub socket") == true,
          "HA-F12: gh with csec's placeholder and no keychain item passes")

    await expectStatus("HA-F12", in: DomainF_Developer.checks,
        makeAuditContext(commands: keychainMiss, files: FakeFileInspector(
            texts: ["/elsewhere/gh/hosts.yml": "github.com:\n    oauth_token: gho_SYNTHETICfixture\n"],
            directories: ["/elsewhere/gh"]
        ), environment: ["GH_CONFIG_DIR": "/elsewhere/gh"]),
        .fail, "HA-F12: GH_CONFIG_DIR is where gh's hosts.yml is read")
    await expectStatus("HA-F12", in: DomainF_Developer.checks,
        makeAuditContext(commands: keychainMiss),
        .notApplicable, "HA-F12: no gh configuration and no keychain item -> notApplicable")
    await expectStatus("HA-F12", in: DomainF_Developer.checks,
        makeAuditContext(files: FakeFileInspector(directories: [gh])),
        .unknown, "HA-F12: a keychain that cannot be checked is never a pass")
}

// MARK: HA-F09 — Homebrew prefix is owner-only and taps/updates understood

private func hostAuditTests_F09() async {
    // PASS: brew present, prefix owner-only (current user) and not writable.
    // The owner is whoever runs the suite: a developer's own uid, or a CI
    // runner's user.
    let healthyBrew = FakeFileInspector(
        perms: ["/opt/homebrew": HostFilePermissions(mode: 0o755, ownerUID: UInt32(getuid()), groupGID: 20)],
        executables: ["/opt/homebrew/bin/brew"]
    )
    await expectStatus("HA-F09", in: DomainF_Developer.checks,
        makeAuditContext(files: healthyBrew),
        .pass, "owner-only homebrew prefix -> pass")

    // FAIL: prefix is world-writable.
    let worldWritableBrew = FakeFileInspector(
        perms: ["/opt/homebrew": HostFilePermissions(mode: 0o777, ownerUID: 501, groupGID: 20)],
        executables: ["/opt/homebrew/bin/brew"]
    )
    await expectStatus("HA-F09", in: DomainF_Developer.checks,
        makeAuditContext(files: worldWritableBrew),
        .fail, "world-writable homebrew prefix -> fail")

    // notApplicable: Homebrew not installed in a standard prefix.
    await expectStatus("HA-F09", in: DomainF_Developer.checks,
        makeAuditContext(),
        .notApplicable, "no homebrew -> notApplicable")
}

// MARK: HA-F10 — No unexpected SUID/SGID or world-writable files (bounded scan)

private func hostAuditTests_F10() async {
    // The scan roots the bounded find touches.
    let scanRoots = FakeFileInspector(directories: ["/usr/local", "/opt"])

    // UNKNOWN (gated): the sweep is opt-in; without --scan-filesystem it is not
    // run and must report .unknown, never .pass.
    await expectStatus("HA-F10", in: DomainF_Developer.checks,
        makeAuditContext(files: scanRoots, scanFilesystem: false),
        .unknown, "filesystem scan not opted in -> unknown")

    // PASS: opted in, both suid finds and the world-writable find complete with
    // zero results within the logged bound.
    await expectStatus("HA-F10", in: DomainF_Developer.checks,
        makeAuditContext(
            commands: [
                "find.suid./usr/local": ok(""),
                "find.suid./opt": ok(""),
                "find.worldwritable.home": ok(""),
            ],
            files: scanRoots, scanFilesystem: true),
        .pass, "clean bounded scan -> pass")

    // FAIL: an unexpected SUID/SGID file was found within the bound.
    await expectStatus("HA-F10", in: DomainF_Developer.checks,
        makeAuditContext(
            commands: [
                "find.suid./usr/local": ok(""),
                "find.suid./opt": ok("/opt/synthetic/suidbin\n"),
                "find.worldwritable.home": ok(""),
            ],
            files: scanRoots, scanFilesystem: true),
        .fail, "unexpected SUID within bound -> fail")

    // FAIL: a world-writable file was found in $HOME within the bounded depth.
    await expectStatus("HA-F10", in: DomainF_Developer.checks,
        makeAuditContext(
            commands: [
                "find.suid./usr/local": ok(""),
                "find.suid./opt": ok(""),
                "find.worldwritable.home": ok("\(fHome)/synthetic-world-writable\n"),
            ],
            files: scanRoots, scanFilesystem: true),
        .fail, "world-writable file in HOME within bound -> fail")

    // UNKNOWN (partial): a find did not complete (launch failed) and nothing else
    // flagged — coverage is partial, so .unknown, never .pass.
    await expectStatus("HA-F10", in: DomainF_Developer.checks,
        makeAuditContext(
            commands: [
                "find.suid./usr/local": HostCommandResult(exitCode: 1, launchFailed: true),
                "find.suid./opt": ok(""),
                "find.worldwritable.home": ok(""),
            ],
            files: scanRoots, scanFilesystem: true),
        .unknown, "partial bounded scan -> unknown")

    // The logged bound must describe the bound actually enforced. The finds take
    // no time budget of their own, so the only time bound is the audit command
    // runner's per-command cap — quoted from the runner in use, never a literal.
    let clean: [String: HostCommandResult] = [
        "find.suid./usr/local": ok(""),
        "find.suid./opt": ok(""),
        "find.worldwritable.home": ok(""),
    ]
    let timedFinding = await evaluateAudit("HA-F10", in: DomainF_Developer.checks,
        makeAuditContext(commands: clean, files: scanRoots, scanFilesystem: true,
                         commandTimeoutSeconds: Int(SystemCommandRunner.defaultTimeout)))
    let timedNote = timedFinding?.coverageNote ?? ""
    check(timedNote.contains("capped at 25s by the audit's per-command timeout"),
          "HA-F10: coverage note quotes the runner's enforced per-command cap [\(timedNote)]")
    check(!timedNote.contains("20s"),
          "HA-F10: coverage note claims no timeout the sweep does not set [\(timedNote)]")

    // A runner that caps nothing must not have a time bound put in its mouth.
    let untimedFinding = await evaluateAudit("HA-F10", in: DomainF_Developer.checks,
        makeAuditContext(commands: clean, files: scanRoots, scanFilesystem: true))
    let untimedNote = untimedFinding?.coverageNote ?? ""
    check(!untimedNote.contains("timeout"),
          "HA-F10: no per-command cap -> coverage note claims none [\(untimedNote)]")
    check(untimedNote.contains("maxdepth 4"),
          "HA-F10: coverage note still logs the depth bound [\(untimedNote)]")
}
