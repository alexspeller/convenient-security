// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "convenient-security",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ConvenientSecurity", targets: ["ConvenientSecurity"]),
        .executable(name: "csecd", targets: ["csecd"]),
        .executable(name: "csec", targets: ["csec"]),
    ],
    targets: [
        // Low-level C interop: unix sockets, LOCAL_PEERTOKEN peer identity, proc info.
        // libbsm provides audit_token_to_pid (not auto-linked).
        .target(
            name: "CSecuritySupport",
            linkerSettings: [.linkedLibrary("bsm"), .linkedLibrary("util")]
        ),
        // Provider-agnostic core: references, grants, cache, resolver, protocol.
        .target(name: "ConvenientSecurity", dependencies: ["CSecuritySupport"]),
        // All 1Password-specific code lives behind the provider seam.
        .target(name: "OnePasswordAdapter", dependencies: ["ConvenientSecurity"]),
        // The resident agent.
        .executableTarget(name: "csecd", dependencies: ["ConvenientSecurity", "OnePasswordAdapter"]),
        // The signed launcher / CLI.
        .executableTarget(name: "csec", dependencies: ["ConvenientSecurity"]),
        // Framework-free self-checks (`swift run cs-selftest`) — runs without
        // XCTest / full Xcode, so it works under the Command Line Tools too.
        .executableTarget(name: "cs-selftest", dependencies: ["ConvenientSecurity", "OnePasswordAdapter"]),
        // End-to-end check: agent + client over a real socket, no entitlements.
        .executableTarget(name: "cs-e2e", dependencies: ["ConvenientSecurity"]),
        // A long-running fake agent (in-memory demo values, auto-approve) for
        // cross-language client integration tests. Not a production surface.
        .executableTarget(name: "cs-fake-agent", dependencies: ["ConvenientSecurity"]),
        // Synthetic regression fixture: rewrites its original argv area the way
        // modern Ruby process-title support does, with no real environment.
        .executableTarget(name: "cs-process-title-fixture"),
    ]
)
