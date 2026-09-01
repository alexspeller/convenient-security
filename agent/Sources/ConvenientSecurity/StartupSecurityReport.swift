import Foundation
import Security

public enum SIPStatus: String, Sendable {
    case enabled
    case disabled
    case unknown
}

/// Value-free self-audit emitted before the production daemon binds its socket.
public struct StartupSecurityReport: Sendable {
    public let executablePath: String
    public let identifier: String?
    public let teamIdentifier: String?
    public let signatureValid: Bool
    public let productRequirementMatches: Bool
    public let hardenedRuntime: Bool
    public let dangerousEntitlements: [String]
    public let applicationIdentifierPresent: Bool
    public let keychainAccessGroupPresent: Bool
    public let cloudKitContainerIdentifiers: [String]
    public let sipStatus: SIPStatus

    public var productionReady: Bool {
        signatureValid
            && productRequirementMatches
            && hardenedRuntime
            && dangerousEntitlements.isEmpty
            && applicationIdentifierPresent
            && keychainAccessGroupPresent
            && sipStatus == .enabled
    }

    public static func currentAgent() -> StartupSecurityReport {
        let expectedApplicationID = "\(ProductCodeIdentity.teamIdentifier).\(ProductCodeIdentity.agentIdentifier)"
        var dynamicCode: SecCode?
        let selfStatus = SecCodeCopySelf(SecCSFlags(rawValue: 0), &dynamicCode)
        guard selfStatus == errSecSuccess, let dynamicCode else {
            return unavailable(path: CommandLine.arguments[0], sipStatus: querySIP())
        }

        let dynamicValid = SecCodeCheckValidity(
            dynamicCode,
            SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)),
            nil
        ) == errSecSuccess
        var staticCode: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(
            dynamicCode,
            SecCSFlags(rawValue: 0),
            &staticCode
        )
        guard staticStatus == errSecSuccess, let staticCode else {
            return unavailable(path: CommandLine.arguments[0], sipStatus: querySIP())
        }

        var information: CFDictionary?
        _ = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)),
            &information
        )
        let dictionary = information as? [String: Any]
        let identifier = dictionary?[kSecCodeInfoIdentifier as String] as? String
        let teamIdentifier = dictionary?[kSecCodeInfoTeamIdentifier as String] as? String
        let flags = (dictionary?[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let entitlements = dictionary?[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]

        var pathURL: CFURL?
        _ = SecCodeCopyPath(staticCode, SecCSFlags(rawValue: 0), &pathURL)
        let executablePath = (pathURL as URL?)?.path ?? CommandLine.arguments[0]

        let dangerous = ProductCodeIdentity.forbiddenEntitlements.filter {
            (entitlements[$0] as? Bool) == true
        }
        let applicationIdentifierPresent = entitlements["com.apple.application-identifier"] as? String
            == expectedApplicationID
        let groups = entitlements["keychain-access-groups"] as? [String] ?? []
        let productionCloudKit = entitlements[
            "com.apple.developer.icloud-container-identifiers"
        ] as? [String] ?? []
        let developmentCloudKit = entitlements[
            "com.apple.developer.icloud-container-development-container-identifiers"
        ] as? [String] ?? []
        let cloudKitContainers = Array(
            Set(productionCloudKit + developmentCloudKit)
        ).sorted()

        return StartupSecurityReport(
            executablePath: executablePath,
            identifier: identifier,
            teamIdentifier: teamIdentifier,
            signatureValid: dynamicValid,
            productRequirementMatches: satisfiesAgentRequirement(staticCode),
            hardenedRuntime: flags & 0x0001_0000 != 0, // CS_RUNTIME
            dangerousEntitlements: dangerous,
            applicationIdentifierPresent: applicationIdentifierPresent,
            keychainAccessGroupPresent: groups.contains(expectedApplicationID),
            cloudKitContainerIdentifiers: cloudKitContainers,
            sipStatus: querySIP()
        )
    }

    public func authorizesCloudKitContainer(_ identifier: String) -> Bool {
        cloudKitContainerIdentifiers.contains(identifier)
    }

    public func logLines(
        socketPath: String,
        cacheEnabled: Bool,
        providerPath: String?,
        providerTrusted: Bool
    ) -> [String] {
        [
            "csecd security: executable=\(executablePath)",
            "csecd security: code=\(signatureValid && productRequirementMatches ? "verified product" : "UNVERIFIED") identifier=\(identifier ?? "none") team=\(teamIdentifier ?? "none")",
            "csecd security: hardened-runtime=\(hardenedRuntime ? "on" : "OFF") dangerous-entitlements=\(dangerousEntitlements.isEmpty ? "none" : dangerousEntitlements.joined(separator: ","))",
            "csecd security: application-identifier=\(applicationIdentifierPresent ? "ok" : "MISSING") keychain-group=\(keychainAccessGroupPresent ? "ok" : "MISSING")",
            "csecd security: remote-approval-cloudkit=\(cloudKitContainerIdentifiers.isEmpty ? "off" : "entitled")",
            "csecd security: SIP=\(sipStatus.rawValue) socket=\(socketPath)",
            "csecd security: cache=\(cacheEnabled ? "secure-enclave-keychain" : "memory-only") consent=touch-id",
            "csecd security: 1password-provider=\(providerPath ?? "missing") provider-code=\(providerTrusted ? "verified" : "UNVERIFIED")",
        ]
    }

    private static func satisfiesAgentRequirement(_ code: SecStaticCode) -> Bool {
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(ProductCodeIdentity.teamIdentifier)\" and identifier \"\(ProductCodeIdentity.agentIdentifier)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            text as CFString,
            SecCSFlags(rawValue: 0),
            &requirement
        ) == errSecSuccess,
        let requirement else { return false }
        return SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)),
            requirement
        ) == errSecSuccess
    }

    private static func unavailable(path: String, sipStatus: SIPStatus) -> StartupSecurityReport {
        StartupSecurityReport(
            executablePath: path,
            identifier: nil,
            teamIdentifier: nil,
            signatureValid: false,
            productRequirementMatches: false,
            hardenedRuntime: false,
            dangerousEntitlements: [],
            applicationIdentifierPresent: false,
            keychainAccessGroupPresent: false,
            cloudKitContainerIdentifiers: [],
            sipStatus: sipStatus
        )
    }

    /// `csrutil` is Apple's supported status surface. It is invoked by fixed
    /// absolute path with a scrubbed environment and produces no secret data.
    private static func querySIP() -> SIPStatus {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/csrutil")
        process.arguments = ["status"]
        process.environment = ["LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            let output = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard let text = String(data: output, encoding: .utf8)?.lowercased() else { return .unknown }
            if text.contains("status: enabled") { return .enabled }
            if text.contains("status: disabled") { return .disabled }
            return .unknown
        } catch {
            return .unknown
        }
    }
}
