import ConvenientSecurity
import Foundation

func claudeBuildVerificationTests() {
    typealias Build = ClaudeBuildVerificationReport.Build
    let checked = Build(path: "/synthetic/claude", versionLabel: "forged-version", cdHash: String(repeating: "a", count: 40),
                        checkedVersion: "audited-image", running: true)
    let unchecked = Build(path: "/synthetic/new", versionLabel: "2.1.280", cdHash: String(repeating: "b", count: 40),
                          checkedVersion: nil, running: false)
    let unknown = Build(path: "/synthetic/unknown", versionLabel: "unknown", cdHash: nil, checkedVersion: nil, running: true)
    let report = ClaudeBuildVerificationReport(builds: [checked, unchecked, unknown])
    check(report.isWellFormed && report.uncheckedBuilds == [unchecked, unknown],
          "release inventory: checked identity, unchecked identity and missing identity remain distinct")
    let status = DelegationStatus(state: .on, policyVersion: 1, buildVerification: report)
    check(status.isWellFormed && (try? JSONDecoder().decode(DelegationStatus.self, from: JSONEncoder().encode(status))) == status,
          "release inventory: daemon status round-trips bounded compatibility metadata")
    let old = Data(#"{"state":"on","policyVersion":1,"setClassifyAllShell":false,"trustedBuilds":[],"acknowledgedHooks":[],"discoveredUntrustedBuilds":[],"pairingCount":0,"counters":{"approved":0,"declined":0}}"#.utf8)
    check((try? JSONDecoder().decode(DelegationStatus.self, from: old))?.buildVerification == nil,
          "release inventory: a pre-gate status decodes as unavailable, never as checked")
    check(!ClaudeBuildVerificationReport(builds: [Build(
        path: "/synthetic/bad", versionLabel: "v", cdHash: nil, checkedVersion: "v", running: false)]).isWellFormed
            && !ClaudeBuildVerificationReport(builds: Array(repeating: unchecked, count: 65)).isWellFormed
            && !ClaudeBuildVerificationReport(builds: [], unreadablePaths: ["relative"]).isWellFormed
            && !ClaudeBuildVerificationReport(builds: [], schemaVersion: 2).isWellFormed,
          "release inventory: checked-without-identity, oversized, malformed and unsupported reports fail wire validation")
    let rows = ClaudeDelegationStatusRows.rows(.status(status), displayPath: { $0 })
    check(rows.contains { $0.label == ClaudeDelegationStatusRows.verificationLabel
            && $0.state == .warn && $0.value.contains("delegation paused") && $0.value.contains("Touch ID") },
          "release inventory: status and doctor warn explicitly about the unchecked image's pause")
    let catalog = ClaudeBuildVerification.shipped
    check(catalog.checkedVersion(cdHash: "cb0b92a2ee6314aeadf4303ca2b503a181ad9f7f") == "2.1.325"
            && catalog.checkedVersion(cdHash: "cb0b92a2ee6314aeadf4303ca2b503a181ad9f70") == nil,
          "release catalog: only the audited 2.1.325 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "c3fca2f1fef791c80f93c36ca7b029950614005b") == "2.1.319"
            && catalog.checkedVersion(cdHash: "c3fca2f1fef791c80f93c36ca7b0299506140050") == nil,
          "release catalog: only the audited 2.1.319 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "f9106e5a4887c4904a64d3b9dd15e7154f6120d7") == "2.1.318"
            && catalog.checkedVersion(cdHash: "f9106e5a4887c4904a64d3b9dd15e7154f6120d0") == nil,
          "release catalog: only the audited 2.1.318 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "9fd02acbf815f7259d78c4f779c2930ad33ca9aa") == "2.1.317"
            && catalog.checkedVersion(cdHash: "9fd02acbf815f7259d78c4f779c2930ad33ca9a0") == nil,
          "release catalog: only the audited 2.1.317 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "e49e58a1feeb798a46fcdd8d07bcac4ee5ad1428") == "2.1.316"
            && catalog.checkedVersion(cdHash: "e49e58a1feeb798a46fcdd8d07bcac4ee5ad1420") == nil,
          "release catalog: only the audited 2.1.316 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "0be2f7d3dad265d1ef590ee83623569caab5fcdd") == "2.1.315"
            && catalog.checkedVersion(cdHash: "0be2f7d3dad265d1ef590ee83623569caab5fcd0") == nil,
          "release catalog: only the audited npm-only 2.1.315 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "33bc52834785912c4ff7dd9e2b9e8c1dd38ef9fd") == "2.1.314"
            && catalog.checkedVersion(cdHash: "33bc52834785912c4ff7dd9e2b9e8c1dd38ef9f0") == nil,
          "release catalog: only the audited 2.1.314 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "9d4c442a850897e6cf0e68c0d022b98859161d2e") == "2.1.312"
            && catalog.checkedVersion(cdHash: "9d4c442a850897e6cf0e68c0d022b98859161d20") == nil,
          "release catalog: only the audited 2.1.312 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "a9faecb664dd8b01e19cdfc12af95da1b267f10e") == "2.1.311"
            && catalog.checkedVersion(cdHash: "a9faecb664dd8b01e19cdfc12af95da1b267f100") == nil,
          "release catalog: only the audited 2.1.311 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "62f3298fb35e54f02451657e7bfbcd0b795657c7") == "2.1.310"
            && catalog.checkedVersion(cdHash: "62f3298fb35e54f02451657e7bfbcd0b795657c0") == nil,
          "release catalog: only the audited 2.1.310 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "c17da5ef4bfdb3894ec64fee484b9de17127def8") == "2.1.301"
            && catalog.checkedVersion(cdHash: "c17da5ef4bfdb3894ec64fee484b9de17127def0") == nil,
          "release catalog: only the audited 2.1.301 identity is checked; the mise label and neighboring hash grant nothing")
    check(catalog.checkedVersion(cdHash: "78d6b9ed85da6de5b0847587570cb3ae268a5c96") == "2.1.305"
            && catalog.checkedVersion(cdHash: "78d6b9ed85da6de5b0847587570cb3ae268a5c90") == nil,
          "release catalog: only the audited 2.1.305 identity is checked; its neighbor remains paused")
    check(catalog.checkedVersion(cdHash: "3759f6c69569d1685ffcd6eea1c7e20539c2d4b5") == "2.1.302"
            && catalog.checkedVersion(cdHash: "3759f6c69569d1685ffcd6eea1c7e20539c2d4b0") == nil,
          "release catalog: only the audited 2.1.302 identity is checked; a neighboring signed image stays paused")
    check(catalog.checkedVersion(cdHash: "af5e0f66b9fd8fdc7e615959dc602cd6386d8d11") == "2.1.278"
            && catalog.checkedVersion(cdHash: "af5e0f66b9fd8fdc7e615959dc602cd6386d8d10") == nil,
          "release catalog: only the audited 2.1.278 identity is checked; a neighboring signed image remains paused")
    check(catalog.checkedVersion(cdHash: "aec6b146f0cd2378b1489dd316f69d16e11591aa") == "2.1.282"
            && catalog.checkedVersion(cdHash: "aec6b146f0cd2378b1489dd316f69d16e11591ab") == nil,
          "release catalog: only the audited 2.1.282 image is checked; a neighboring identity stays paused")
    check(catalog.checkedVersion(cdHash: "7bfc0b1005fbcb70382ca4e4dd3ae9f7ff2f119b") == "2.1.295"
            && catalog.checkedVersion(cdHash: "7bfc0b1005fbcb70382ca4e4dd3ae9f7ff2f1190") == nil,
          "release catalog: the audited 2.1.295 image is exact; a neighboring signed image remains unchecked")
    check(catalog.checkedVersion(cdHash: "64a09464023aa47514a78be456da5b89e01b50a6") == nil,
          "release catalog: the custom tweakcc 2.1.257 image is not offered to buyers")
    check(catalog.checkedVersion(cdHash: "21209468e54034262a7f049c21983dca5f06ed09") == "2.1.267"
            && catalog.checkedVersion(cdHash: "a2a0746b3c279794afb4eb104aaa6bb88a252a34") == "2.1.280"
            && catalog.checkedVersion(cdHash: "21209468e54034262a7f049c21983dca5f06ed00") == nil,
          "release catalog: audited 2.1.267 and 2.1.280 identities are exact; a neighboring hash remains unchecked")
    check(ClaudeBuildVerification.isInventoryCandidate("/synthetic/node_modules/@anthropic-ai/claude-code/bin/claude.exe")
            && ClaudeBuildVerification.isInventoryCandidate("/opt/homebrew/Caskroom/claude-code/2.1.325/claude")
            && !ClaudeBuildVerification.isInventoryCandidate("/synthetic/other/claude.exe"),
          "release inventory: npm's and Homebrew's executables are discovered without treating arbitrary exe names as Claude")
    check(CodingAgentIdentity.client(name: "claude.exe",
                                     executablePath: "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe")
            == .claude
            && CodingAgentIdentity.client(name: "claude.exe", executablePath: "/synthetic/other/claude.exe") == nil
            && CodingAgentIdentity.client(name: nil, executablePath: "relative/@anthropic-ai/claude-code/bin/claude.exe") == nil,
          "release inventory: a session started from npm's package is Claude Code, as the native installer's is")
    check(ClaudeBuildVerification.versionLabel(executablePath:
        "/Users/synthetic/.local/share/mise/installs/npm-anthropic-ai-claude-code/2.1.295/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe") == "2.1.295"
            && ClaudeBuildVerification.versionLabel(executablePath: "/opt/homebrew/Caskroom/claude-code/2.1.323/claude") == "2.1.323"
            && ClaudeBuildVerification.versionLabel(executablePath:
                "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe") == "npm install"
            && ClaudeBuildVerification.versionLabel(executablePath: "/synthetic/renamed") == "renamed",
          "release inventory: mise's and Homebrew's versions and npm's route are display metadata; arbitrary filenames remain labels")
    check(!catalog.records.isEmpty && catalog.records.allSatisfy {
        $0.cdHash.count == 40 && $0.cdHash.allSatisfy { "0123456789abcdef".contains($0) }
            && !$0.version.isEmpty && $0.evidence.hasPrefix("docs/claude-release-verification.md")
    } && Set(catalog.records.map(\.cdHash)).count == catalog.records.count,
          "release catalog: shipped records have unique exact identities and durable audit evidence")
}
