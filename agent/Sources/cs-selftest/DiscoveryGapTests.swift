import ConvenientSecurity
import Foundation

func discoveryGapTests() {
    print("\n# Bulk discovery coverage gaps")
    let fm = FileManager.default
    let home = NSTemporaryDirectory() + "csec-discovery-gaps-\(UUID().uuidString)"
    defer { try? fm.removeItem(atPath: home) }
    let marker = "synthetic-credential-7pQxN3aT"
    func write(_ path: String, _ text: String) {
        let url = URL(fileURLWithPath: home).appendingPathComponent(path)
        try? fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Data(text.utf8).write(to: url)
    }

    write(".config/quic/config.json", "{\"auth\":{\"accessToken\":\"\(marker)\"}}")
    write(".config/av/config.yaml", "api_key: '\(marker)'\n")
    write(".config/cb/api.crunchybridge.com", marker)
    write(".runpod/config.toml", "apikey = '\(marker)'\n")
    let keypair = "[" + Array(repeating: "42", count: 64).joined(separator: ",") + "]"
    write(".config/solana/id.json", keypair)
    write("backups/solana/id.json", keypair)
    write("backups/unrelated/id.json", keypair)
    write("backups/invalid/solana/id.json", "{\"theme\":\"dark\"}")
    write("backups/keystore/UTC--synthetic", "{\"version\":3,\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"0123\"}}")
    write("backups/keystore/UTC--unrelated", "{\"theme\":\"dark\"}")
    write("backups/keystore/UTC--invalid", "{\"version\":true,\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"0123\"}}")
    write("backups/fractions/solana/id.json", "[" + Array(repeating: "0.5", count: 64).joined(separator: ",") + "]")
    write("backups/booleans/solana/id.json", "[" + Array(repeating: "true", count: 64).joined(separator: ",") + "]")
    write("packaging/.env", "OP_ACCOUNT=abcdefghijklmnopqrst234567\n")
    write("actual/.env", "OP_ACCOUNT=ghp_syntheticCredential1234567890\n")
    write(".claude.json", #"{"projects":{"sample":{"mcpServers":{"local":{"env":{"API_TOKEN":"\#(marker)"}}}}}}"#)
    write(".gemini/settings.json", #"{"mcpServers":{"local":{"env":{"API_KEY":"\#(marker)"}}}}"#)
    let electrum = ".electrum/wallets/sample.env"
    let bitcoin = "Library/Application Support/Bitcoin/wallets/sample/wallet.dat"
    let gpg = ".gnupg/private-keys-v1.d/sample.key"
    write(electrum, "SECRET_TOKEN=\(marker)")
    write(bitcoin, "synthetic database")
    write(gpg, "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----")
    try? fm.linkItem(atPath: home + "/" + electrum, toPath: home + "/alias.env")

    func scan(_ roots: [String] = []) -> SecretFileDiscoveryReport {
        SecretFileDiscoveryEngine.discover(roots: roots, homeDirectory: home)
    }
    let report = scan()
    for consumer in ["Claude", "Gemini", "Electrum", "Bitcoin", "GnuPG"] {
        check(report.warnings.contains { $0.contains(consumer) },
              "bulk discovery reports the mutable \(consumer) store")
    }
    let mutable = [".claude.json", ".gemini/settings.json", electrum, bitcoin, gpg, "alias.env"]
    let assignments = SetupProtectPlanner.assignments(files: report.files, rules: [
        BulkProtectRule(pattern: "*", approach: .wholeFile, destination: nil)
    ], homeDirectory: home)
    let plannedPaths = assignments.flatMap { [$0.file.canonicalPath] + $0.file.aliasPaths }
    check(!plannedPaths.contains { path in mutable.contains { path.hasSuffix("/" + $0) } },
          "a whole-file glob cannot select a mutable file or any of its hardlinks")
    for id in ["quic", "av", "cb", "runpod"] {
        check(report.files.contains { $0.catalogID == id && $0.suggestedApproach == .wholeFile },
              "the \(id) credential location is discovered with existing whole-file delivery")
    }
    check(report.files.contains { $0.canonicalPath.hasSuffix("/.config/solana/id.json") && $0.kind == .keyMaterial },
          "the standard Solana keypair is discovered as key material")
    check(report.files.contains { $0.canonicalPath.hasSuffix("/backups/solana/id.json") },
          "a Solana keypair in a backup is discovered structurally")
    check(!report.files.contains { $0.canonicalPath.contains("unrelated/id.json") || $0.canonicalPath.contains("invalid/solana") },
          "unrelated id.json files and non-key Solana configs are suppressed")
    check(report.files.contains { $0.canonicalPath.hasSuffix("UTC--synthetic") && $0.kind == .keyMaterial },
          "a UTC keystore with the key JSON structure is discovered")
    check(!report.files.contains { $0.canonicalPath.hasSuffix("UTC--unrelated") },
          "a UTC filename without key structure is suppressed")
    check(!report.files.contains { $0.canonicalPath.hasSuffix("UTC--invalid") || $0.canonicalPath.contains("/fractions/") || $0.canonicalPath.contains("/booleans/") },
          "wallet structure checks reject JSON booleans and fractional keypair bytes")
    check(report.files.first { $0.canonicalPath.hasSuffix("UTC--synthetic") }?.notes.contains(
        "password-encrypted key store; csec adds access gating") == true,
        "an Ethereum key store is identified as already password-encrypted")
    check(!report.files.contains { $0.canonicalPath.hasSuffix("packaging/.env") },
          "a 1Password account UUID alone does not make an env file secret-bearing")
    check(report.files.contains { $0.canonicalPath.hasSuffix("actual/.env") },
          "an actual credential prefix assigned to OP_ACCOUNT remains secret-like")
    let text = report.files.map { "\($0.canonicalPath) \($0.notes.joined())" }.joined()
        + report.warnings.joined()
    check(!text.contains(marker), "discovery reports no synthetic credential content")

    write(".config/quic/config.json", "{\"auth\":{\"accessToken\":\"op://vault/item/token\"}}")
    write(".config/av/config.yaml", "api_key_ref: csec://harbor/API_KEY\n")
    write(".runpod/config.toml", "apikey = ''\n")
    let clean = scan()
    check(!clean.files.contains { ["quic", "av", "runpod"].contains($0.catalogID ?? "") },
          "reference-only and empty tool configs do not become protection candidates")
    write(".config/quic/config.json", "{\"installationId\":\"abcdefghijklmnopqrst234567\"}")
    write(".config/av/config.yaml", "api_key_env: AV_API_KEY\n")
    write(".runpod/config.toml", "apikey = '\u{24}{RUNPOD_API_KEY}'\n")
    check(!scan().files.contains { ["quic", "av", "runpod"].contains($0.catalogID ?? "") },
          "public config identifiers and environment selectors are not literal credentials")
    let narrow = scan([home + "/backups"])
    check(!narrow.warnings.contains { $0.contains("Electrum") || $0.contains("Gemini") || $0.contains("Bitcoin") },
          "a scan of backups does not report mutable files from elsewhere in the home")
    write(".claude.json", #"{"unrelated":{"env":{"API_TOKEN":"sample"}}}"#)
    write(".gemini/settings.json", #"{"mcpServers":{"local":{"env":{"PORT":"1234"}}}}"#)
    let withoutMCP = scan()
    check(!withoutMCP.warnings.contains { $0.contains("Claude") || $0.contains("Gemini") },
          "MCP findings require a credential-shaped field in a server environment")
    let padding = String(repeating: " ", count: 1024 * 1024)
    write(".claude.json", padding + #"{"mcpServers":{"sample":{"env":{"API_KEY":"sample"}}}}"#)
    write(".gemini/settings.json", "{")
    let incomplete = scan()
    check(incomplete.warnings.contains { $0.contains("Claude") && $0.contains("credential-shaped") },
          "the larger Claude global config limit also covers top-level MCP servers")
    check(incomplete.warnings.contains { $0.contains("Gemini") && $0.contains("could not be checked") },
          "invalid MCP JSON is reported as uninspected")
    check(!narrow.files.contains { $0.rootLabel == "catalog" },
          "new home-global probes stay within the established scan-root boundary")
    check(narrow.files.contains { $0.canonicalPath.hasSuffix("/backups/solana/id.json") }
          && narrow.files.contains { $0.canonicalPath.hasSuffix("UTC--synthetic") },
          "a narrowed scan still discovers static wallet keys inside its root")
}
