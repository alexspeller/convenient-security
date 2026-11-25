#if DEBUG && !targetEnvironment(simulator)
import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Development-only probe for csec-vo4.15: can ONE Face ID authorize both a
/// Secure Enclave signature and a Secure Enclave key agreement on two keys?
///
/// The cold-unlock design answers a Mac request with a signature and a blinded
/// key agreement. Whether that costs one Face ID or two depends on whether an
/// evaluated LAContext covers a second key and a second operation. After the
/// single evaluation the context is set to `interactionNotAllowed`, so an
/// operation the evaluation does not cover fails with an error instead of
/// silently raising a second sheet: the printed result is the answer, and the
/// human does not have to count sheets. The keys are ephemeral (never stored)
/// and sign and agree on synthetic bytes only.
enum SecureEnclaveSpike {
    struct Variant {
        let name: String
        let evaluate: (LAContext, SecAccessControl) async throws -> Void
    }

    static let variants: [Variant] = [
        Variant(name: "evaluatePolicy(biometrics)") { context, _ in
            try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Spike: one Face ID for a signature and a key agreement"
            )
        },
        Variant(name: "evaluateAccessControl(.useKeySign)") { context, access in
            try await context.evaluateAccessControl(
                access,
                operation: .useKeySign,
                localizedReason: "Spike: one Face ID for a signature and a key agreement"
            )
        },
    ]

    static func run(_ variant: Variant) async -> String {
        var lines = ["variant: \(variant.name)"]
        guard SecureEnclave.isAvailable else { return "Secure Enclave unavailable" }
        do {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.biometryCurrentSet, .privateKeyUsage],
                &error
            ) else {
                return "access control could not be created"
            }
            let signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
            let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)

            let context = LAContext()
            context.localizedCancelTitle = "Cancel"
            try await variant.evaluate(context, access)
            context.interactionNotAllowed = true
            lines.append("evaluation: ok")

            let signer = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: signing.dataRepresentation,
                authenticationContext: context
            )
            let agreer = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: agreement.dataRepresentation,
                authenticationContext: context
            )
            lines.append(attempt("signature") {
                _ = try signer.signature(for: Data("csec spike".utf8))
            })
            for index in 1...3 {
                let peer = P256.KeyAgreement.PrivateKey().publicKey
                lines.append(attempt("key agreement \(index)") {
                    _ = try agreer.sharedSecretFromKeyAgreement(with: peer)
                })
            }
            lines.append(attempt("second signature") {
                _ = try signer.signature(for: Data("csec spike 2".utf8))
            })
            context.invalidate()
        } catch {
            lines.append("failed before the operations: \(error)")
        }
        return lines.joined(separator: "\n")
    }

    private static func attempt(_ label: String, _ body: () throws -> Void) -> String {
        do {
            try body()
            return "\(label): ok (covered by the one evaluation)"
        } catch {
            return "\(label): FAILED without a new prompt — \(error)"
        }
    }
}
#endif
