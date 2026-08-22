// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "convenient-security",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ConvenientSecurity", targets: ["ConvenientSecurity"]),
        .executable(name: "csecd", targets: ["csecd"]),
        .executable(name: "csec", targets: ["csec"]),
        .executable(name: "csec-rootd", targets: ["csec-rootd"]),
    ],
    targets: [
        // Low-level C interop: unix sockets, LOCAL_PEERTOKEN peer identity, proc info.
        // libbsm provides audit_token_to_pid (not auto-linked).
        .target(
            name: "CSecuritySupport",
            linkerSettings: [.linkedLibrary("bsm"), .linkedLibrary("util")]
        ),
        // Value-free launch plans, peer identity, framing, and root wire types.
        // This target deliberately has no AppKit, LocalAuthentication, Keychain,
        // provider, or ServiceManagement implementation.
        .target(name: "CSECRootProtocol", dependencies: ["CSecuritySupport"]),
        // The privileged filesystem/process/socket implementation is separate
        // so csec-rootd does not link the full user-agent module.
        .target(
            name: "CSECRootServer",
            dependencies: ["CSecuritySupport", "CSECRootProtocol"]
        ),
        // Security core plus the native encrypted-file provider.
        .target(
            name: "ConvenientSecurity",
            dependencies: ["CSecuritySupport", "CSECRootProtocol"]
        ),
        // All 1Password-specific code lives behind the provider seam.
        .target(name: "OnePasswordAdapter", dependencies: ["ConvenientSecurity"]),
        // The resident agent.
        .executableTarget(name: "csecd", dependencies: ["ConvenientSecurity", "OnePasswordAdapter"]),
        // The signed launcher / CLI.
        .executableTarget(name: "csec", dependencies: ["ConvenientSecurity"]),
        // Narrow privileged launcher. It has no Keychain/Touch ID/provider
        // dependencies and accepts only the authenticated two-party protocol.
        .executableTarget(
            name: "csec-rootd",
            dependencies: ["CSECRootProtocol", "CSECRootServer"]
        ),
        // Framework-free self-checks (`swift run cs-selftest`) — runs without
        // XCTest / full Xcode, so it works under the Command Line Tools too.
        .executableTarget(
            name: "cs-selftest",
            dependencies: [
                "ConvenientSecurity", "OnePasswordAdapter", "CSecuritySupport",
                "CSECRootServer",
            ]
        ),
        // End-to-end check: agent + client over a real socket, no entitlements.
        .executableTarget(name: "cs-e2e", dependencies: ["ConvenientSecurity"]),
        // A long-running fake agent (in-memory demo values, auto-approve) for
        // cross-language client integration tests. Not a production surface.
        .executableTarget(name: "cs-fake-agent", dependencies: ["ConvenientSecurity"]),
        // Unprivileged functional double for the two-party/root wire protocol.
        // It uses owner-read files and never claims capability-GID isolation.
        .executableTarget(
            name: "cs-fake-rootd",
            dependencies: ["CSECRootProtocol", "CSECRootServer"]
        ),
        // Synthetic regression fixture: rewrites its original argv area the way
        // modern Ruby process-title support does, with no real environment.
        .executableTarget(name: "cs-process-title-fixture"),
        // Synthetic regular-file compatibility fixture. It never receives an
        // expected value in argv/environment and emits only a fixed success line.
        .executableTarget(name: "cs-file-probe"),
        // Synthetic GitHub CLI stand-in for GH_CONFIG_DIR behavior. It never
        // prints the profile or token and is not a production dependency.
        .executableTarget(name: "cs-gh-fixture"),
    ]
)
