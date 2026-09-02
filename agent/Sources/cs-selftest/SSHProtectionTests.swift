import ConvenientSecurity
import CryptoKit
import Darwin
import Foundation
import Security

private enum SSHFixtureError: Error {
    case malformed
    case rsaKeyGeneration
    case rsaPublicKey
    case signatureAlgorithm(expected: String, actual: String)
    case signatureTrailingData
}

private struct SSHFixtureWriter {
    private(set) var data = Data()

    mutating func byte(_ value: UInt8) {
        data.append(value)
    }

    mutating func uint32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    mutating func uint64(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8((value >> UInt64(shift)) & 0xff))
        }
    }

    mutating func string(_ value: Data) {
        uint32(UInt32(value.count))
        data.append(value)
    }

    mutating func string(_ value: String) {
        string(Data(value.utf8))
    }

    mutating func positiveMPInt(_ value: Data) {
        var bytes = [UInt8](value)
        while bytes.first == 0 { bytes.removeFirst() }
        if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
        string(Data(bytes))
    }
}

private struct SSHFixtureReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ data: Data) {
        bytes = Array(data)
    }

    var isAtEnd: Bool { offset == bytes.count }

    mutating func byte() throws -> UInt8 {
        guard offset < bytes.count else { throw SSHFixtureError.malformed }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func uint32() throws -> UInt32 {
        guard bytes.count - offset >= 4 else { throw SSHFixtureError.malformed }
        let value = (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
        offset += 4
        return value
    }

    mutating func string() throws -> Data {
        let count = Int(try uint32())
        guard count <= bytes.count - offset else { throw SSHFixtureError.malformed }
        defer { offset += count }
        return Data(bytes[offset..<(offset + count)])
    }

    mutating func text() throws -> String {
        let value = try string()
        guard let text = String(data: value, encoding: .utf8) else {
            throw SSHFixtureError.malformed
        }
        return text
    }

    mutating func positiveMPInt() throws -> Data {
        var value = [UInt8](try string())
        guard value.first.map({ $0 & 0x80 == 0 }) ?? true else {
            throw SSHFixtureError.malformed
        }
        if value.count > 1, value[0] == 0, value[1] & 0x80 == 0 {
            throw SSHFixtureError.malformed
        }
        if value.first == 0 { value.removeFirst() }
        return Data(value)
    }
}

private func openSSHPrivateKeyPEM(
    publicKeyBlob: Data,
    mismatchedCheckints: Bool = false,
    fields: (inout SSHFixtureWriter) -> Void
) -> Data {
    var privateWriter = SSHFixtureWriter()
    privateWriter.uint32(0x4353_4543)
    privateWriter.uint32(mismatchedCheckints ? 0x4353_4544 : 0x4353_4543)
    fields(&privateWriter)
    var padding: UInt8 = 1
    while privateWriter.data.count % 8 != 0 {
        privateWriter.byte(padding)
        padding &+= 1
    }

    var document = Data("openssh-key-v1\0".utf8)
    var outerWriter = SSHFixtureWriter()
    outerWriter.string("none")
    outerWriter.string("none")
    outerWriter.string(Data())
    outerWriter.uint32(1)
    outerWriter.string(publicKeyBlob)
    outerWriter.string(privateWriter.data)
    document.append(outerWriter.data)
    return pem(label: "OPENSSH PRIVATE KEY", body: document)
}

private func pem(label: String, body: Data) -> Data {
    Data(
        "-----BEGIN \(label)-----\n\(body.base64EncodedString())\n"
            .appending("-----END \(label)-----\n").utf8
    )
}

private func der(_ tag: UInt8, _ contents: Data) -> Data {
    var result = Data([tag])
    if contents.count < 128 {
        result.append(UInt8(contents.count))
    } else {
        var count = contents.count
        var encoded: [UInt8] = []
        while count > 0 {
            encoded.insert(UInt8(count & 0xff), at: 0)
            count >>= 8
        }
        result.append(0x80 | UInt8(encoded.count))
        result.append(contentsOf: encoded)
    }
    result.append(contents)
    return result
}

private func ed25519PKCS8(seed: Data) -> Data {
    let version = der(0x02, Data([0]))
    let algorithm = der(0x30, der(0x06, Data([0x2b, 0x65, 0x70])))
    let privateKey = der(0x04, der(0x04, seed))
    return pem(label: "PRIVATE KEY", body: der(0x30, version + algorithm + privateKey))
}

private func ecSEC1P256(scalar: Data, publicPoint: Data) -> Data {
    let version = der(0x02, Data([1]))
    let privateKey = der(0x04, scalar)
    let curve = der(0xa0, der(0x06, Data([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])))
    let publicKey = der(0xa1, der(0x03, Data([0]) + publicPoint))
    return pem(label: "EC PRIVATE KEY", body: der(0x30, version + privateKey + curve + publicKey))
}

private struct Ed25519SSHFixture {
    let key: Curve25519.Signing.PrivateKey
    let publicKeyBlob: Data
    let privateKeyPEM: Data

    init(seed: UInt8, mismatchedCheckints: Bool = false) throws {
        let seedBytes = Data((0..<32).map { seed &+ UInt8($0) })
        let generatedKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedBytes)
        key = generatedKey

        var publicWriter = SSHFixtureWriter()
        publicWriter.string("ssh-ed25519")
        publicWriter.string(generatedKey.publicKey.rawRepresentation)
        publicKeyBlob = publicWriter.data
        privateKeyPEM = openSSHPrivateKeyPEM(
            publicKeyBlob: publicWriter.data,
            mismatchedCheckints: mismatchedCheckints
        ) { privateWriter in
            privateWriter.string("ssh-ed25519")
            privateWriter.string(generatedKey.publicKey.rawRepresentation)
            privateWriter.string(seedBytes + generatedKey.publicKey.rawRepresentation)
            privateWriter.string("synthetic-csec-selftest")
        }
    }

    func signatureBlob(for message: Data) throws -> Data {
        var writer = SSHFixtureWriter()
        writer.string("ssh-ed25519")
        writer.string(try key.signature(for: message))
        return writer.data
    }

    func verifies(signatureBlob: Data, message: Data) -> Bool {
        do {
            var reader = SSHFixtureReader(signatureBlob)
            let algorithm = try reader.text()
            let signature = try reader.string()
            return algorithm == "ssh-ed25519"
                && reader.isAtEnd
                && key.publicKey.isValidSignature(signature, for: message)
        } catch {
            return false
        }
    }
}

private func ecdsaOpenSSHFixture(
    curve: String,
    scalar: Data,
    publicPoint: Data
) -> (pem: Data, publicKeyBlob: Data) {
    let algorithm = "ecdsa-sha2-\(curve)"
    var publicWriter = SSHFixtureWriter()
    publicWriter.string(algorithm)
    publicWriter.string(curve)
    publicWriter.string(publicPoint)
    let publicKeyBlob = publicWriter.data
    let privateKeyPEM = openSSHPrivateKeyPEM(publicKeyBlob: publicKeyBlob) { writer in
        writer.string(algorithm)
        writer.string(curve)
        writer.string(publicPoint)
        writer.positiveMPInt(scalar)
        writer.string("synthetic-csec-selftest")
    }
    return (privateKeyPEM, publicKeyBlob)
}

private func rawECDSASignature(
    _ signatureBlob: Data,
    algorithm: String,
    scalarBytes: Int
) throws -> Data {
    var outer = SSHFixtureReader(signatureBlob)
    guard try outer.text() == algorithm else { throw SSHFixtureError.malformed }
    let encoded = try outer.string()
    guard outer.isAtEnd else { throw SSHFixtureError.malformed }
    var inner = SSHFixtureReader(encoded)
    let r = try inner.positiveMPInt()
    let s = try inner.positiveMPInt()
    guard inner.isAtEnd, r.count <= scalarBytes, s.count <= scalarBytes else {
        throw SSHFixtureError.malformed
    }
    return Data(repeating: 0, count: scalarBytes - r.count) + r
        + Data(repeating: 0, count: scalarBytes - s.count) + s
}

private func rawSSHSignature(_ signatureBlob: Data, algorithm: String) throws -> Data {
    var reader = SSHFixtureReader(signatureBlob)
    let actualAlgorithm = try reader.text()
    guard actualAlgorithm == algorithm else {
        throw SSHFixtureError.signatureAlgorithm(expected: algorithm, actual: actualAlgorithm)
    }
    let signature = try reader.string()
    guard reader.isAtEnd else { throw SSHFixtureError.signatureTrailingData }
    return signature
}

private func generatedRSAPEM(bits: Int) throws -> (privateKey: SecKey, pem: Data) {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: bits,
    ]
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
          let representation = SecKeyCopyExternalRepresentation(privateKey, &error) as Data?
    else { throw SSHFixtureError.rsaKeyGeneration }
    return (privateKey, pem(label: "RSA PRIVATE KEY", body: representation))
}

private actor SSHFixtureCounter {
    private var value = 0

    func record() { value += 1 }
    func count() -> Int { value }
}

private final class SSHDiagnosticCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?

    func record(_ diagnostic: String) {
        lock.lock()
        value = diagnostic
        lock.unlock()
    }

    func latest() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private struct SSHFixtureProvider: SecretProvider {
    let scheme: String
    let values: [String: Data]
    let counter: SSHFixtureCounter

    var schemes: Set<String> { [scheme] }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        await counter.record()
        guard let value = values[ref.uri] else {
            throw ProviderError.referenceNotFound(ref.uri)
        }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private actor SSHFixtureConsent: ConsentProvider {
    private var count = 0

    func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval,
        policySummary: String?
    ) async -> ConsentOutcome {
        count += 1
        return .approved(unlock: nil)
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        count += 1
        return .approved(unlock: nil)
    }

    func calls() -> Int { count }
}

private actor SSHFixtureReview: PolicyReviewProvider {
    private var count = 0

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        count += 1
        return .approved(AccessPolicyApproval())
    }

    func calls() -> Int { count }
}

private struct SSHDenyFixtureReview: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        .denied
    }
}

private func sshFingerprint(_ publicKeyBlob: Data) -> String {
    let digest = Data(SHA256.hash(data: publicKeyBlob)).base64EncodedString()
        .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    return "SHA256:\(digest)"
}

private func ed25519HostCertificate(
    host: Ed25519SSHFixture,
    certificationAuthority: Ed25519SSHFixture,
    certificateType: UInt32 = 2
) throws -> Data {
    var principals = SSHFixtureWriter()
    principals.string("synthetic.example")

    var certificate = SSHFixtureWriter()
    certificate.string("ssh-ed25519-cert-v01@openssh.com")
    certificate.string(Data(repeating: 0x43, count: 32))
    certificate.string(host.key.publicKey.rawRepresentation)
    certificate.uint64(7)
    certificate.uint32(certificateType)
    certificate.string("synthetic-host-certificate")
    certificate.string(principals.data)
    certificate.uint64(0)
    certificate.uint64(UInt64.max)
    certificate.string(Data()) // critical options
    certificate.string(Data()) // extensions
    certificate.string(Data()) // reserved
    certificate.string(certificationAuthority.publicKeyBlob)

    let signature = try certificationAuthority.signatureBlob(for: certificate.data)
    certificate.string(signature)
    return certificate.data
}

private func userAuthenticationRequest(
    sessionIdentifier: Data,
    remoteUser: String,
    publicKeyBlob: Data,
    hostKeyBlob: Data,
    algorithm: String = "ssh-ed25519",
    hostbound: Bool = true
) -> Data {
    var writer = SSHFixtureWriter()
    writer.string(sessionIdentifier)
    writer.byte(50) // SSH2_MSG_USERAUTH_REQUEST
    writer.string(remoteUser)
    writer.string("ssh-connection")
    writer.string(hostbound ? "publickey-hostbound-v00@openssh.com" : "publickey")
    writer.byte(1)
    writer.string(algorithm)
    writer.string(publicKeyBlob)
    if hostbound { writer.string(hostKeyBlob) }
    return writer.data
}

private func sessionBindMessage(
    host: Ed25519SSHFixture,
    sessionIdentifier: Data,
    forwarding: Bool = false
) throws -> Data {
    var writer = SSHFixtureWriter()
    writer.byte(27) // SSH_AGENTC_EXTENSION
    writer.string("session-bind@openssh.com")
    writer.string(host.publicKeyBlob)
    writer.string(sessionIdentifier)
    writer.string(try host.signatureBlob(for: sessionIdentifier))
    writer.byte(forwarding ? 1 : 0)
    return writer.data
}

private func signRequest(publicKeyBlob: Data, signedData: Data, flags: UInt32 = 0) -> Data {
    var writer = SSHFixtureWriter()
    writer.byte(13) // SSH2_AGENTC_SIGN_REQUEST
    writer.string(publicKeyBlob)
    writer.string(signedData)
    writer.uint32(flags)
    return writer.data
}

func sshProtectionTests() async {
    print("\n# SSH protection (synthetic keys only)")

    do {
        let nativeKey = try Ed25519SSHFixture(seed: 1)
        let providerKey = try Ed25519SSHFixture(seed: 65)
        let hostKey = try Ed25519SSHFixture(seed: 129)
        let parsed = try SSHPrivateKey.parse(nativeKey.privateKeyPEM)

        check(parsed.algorithm == "ssh-ed25519"
              && parsed.publicKeyBlob == nativeKey.publicKeyBlob
              && parsed.comment == "synthetic-csec-selftest",
              "an unencrypted OpenSSH Ed25519 key parses with matching public metadata")

        let probe = Data("synthetic SSH signing probe".utf8)
        let parsedSignature = try parsed.sign(probe, flags: 0)
        check(nativeKey.verifies(signatureBlob: parsedSignature, message: probe),
              "the parsed private key returns a valid SSH signature blob")
        do {
            _ = try parsed.sign(probe, flags: 0x02)
            check(false, "Ed25519 signing rejects RSA agent flags")
        } catch {
            check(true, "Ed25519 signing rejects RSA agent flags")
        }

        let edPKCS8 = try SSHPrivateKey.parse(
            ed25519PKCS8(seed: nativeKey.key.rawRepresentation)
        )
        check(edPKCS8.publicKeyBlob == nativeKey.publicKeyBlob,
              "an Ed25519 PKCS#8 key derives the same public identity")

        let p256Scalar = Data(repeating: 0, count: 31) + Data([7])
        let p256Key = try P256.Signing.PrivateKey(rawRepresentation: p256Scalar)
        let p256Fixture = ecdsaOpenSSHFixture(
            curve: "nistp256",
            scalar: p256Scalar,
            publicPoint: p256Key.publicKey.x963Representation
        )
        let parsedP256 = try SSHPrivateKey.parse(p256Fixture.pem)
        let p256Signature = try P256.Signing.ECDSASignature(rawRepresentation:
            rawECDSASignature(
                try parsedP256.sign(probe, flags: 0),
                algorithm: "ecdsa-sha2-nistp256",
                scalarBytes: 32
            )
        )
        check(parsedP256.publicKeyBlob == p256Fixture.publicKeyBlob
              && p256Key.publicKey.isValidSignature(p256Signature, for: probe),
              "OpenSSH ECDSA P-256 keys parse and sign with canonical SSH mpints")
        let parsedSEC1 = try SSHPrivateKey.parse(ecSEC1P256(
            scalar: p256Scalar,
            publicPoint: p256Key.publicKey.x963Representation
        ))
        check(parsedSEC1.publicKeyBlob == p256Fixture.publicKeyBlob,
              "legacy SEC1 P-256 keys derive the expected SSH public identity")

        let p384Scalar = Data(repeating: 0, count: 47) + Data([9])
        let p384Key = try P384.Signing.PrivateKey(rawRepresentation: p384Scalar)
        let p384Fixture = ecdsaOpenSSHFixture(
            curve: "nistp384",
            scalar: p384Scalar,
            publicPoint: p384Key.publicKey.x963Representation
        )
        let parsedP384 = try SSHPrivateKey.parse(p384Fixture.pem)
        let p384Signature = try P384.Signing.ECDSASignature(rawRepresentation:
            rawECDSASignature(
                try parsedP384.sign(probe, flags: 0),
                algorithm: "ecdsa-sha2-nistp384",
                scalarBytes: 48
            )
        )
        check(parsedP384.publicKeyBlob == p384Fixture.publicKeyBlob
              && p384Key.publicKey.isValidSignature(p384Signature, for: probe),
              "OpenSSH ECDSA P-384 keys parse and sign")

        let p521Scalar = Data(repeating: 0, count: 65) + Data([11])
        let p521Key = try P521.Signing.PrivateKey(rawRepresentation: p521Scalar)
        let p521Fixture = ecdsaOpenSSHFixture(
            curve: "nistp521",
            scalar: p521Scalar,
            publicPoint: p521Key.publicKey.x963Representation
        )
        let parsedP521 = try SSHPrivateKey.parse(p521Fixture.pem)
        let p521Signature = try P521.Signing.ECDSASignature(rawRepresentation:
            rawECDSASignature(
                try parsedP521.sign(probe, flags: 0),
                algorithm: "ecdsa-sha2-nistp521",
                scalarBytes: 66
            )
        )
        check(parsedP521.publicKeyBlob == p521Fixture.publicKeyBlob
              && p521Key.publicKey.isValidSignature(p521Signature, for: probe),
              "OpenSSH ECDSA P-521 keys parse and sign")

        let rsaFixture = try generatedRSAPEM(bits: 2_048)
        let parsedRSA = try SSHPrivateKey.parse(rsaFixture.pem)
        let rsaPublicKey = try SecKeyCopyPublicKey(rsaFixture.privateKey).unwrap(
            or: SSHFixtureError.rsaPublicKey
        )
        let rsaSHA256 = try rawSSHSignature(
            try parsedRSA.sign(probe, flags: 0x02), algorithm: "rsa-sha2-256"
        )
        let rsaSHA512 = try rawSSHSignature(
            try parsedRSA.sign(probe, flags: 0x04), algorithm: "rsa-sha2-512"
        )
        var rsaError: Unmanaged<CFError>?
        let rsa256Valid = SecKeyVerifySignature(
            rsaPublicKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            probe as CFData,
            rsaSHA256 as CFData,
            &rsaError
        )
        rsaError = nil
        let rsa512Valid = SecKeyVerifySignature(
            rsaPublicKey,
            .rsaSignatureMessagePKCS1v15SHA512,
            probe as CFData,
            rsaSHA512 as CFData,
            &rsaError
        )
        check(parsedRSA.algorithm == "ssh-rsa" && rsa256Valid && rsa512Valid,
              "legacy PEM RSA-2048 keys sign only with RSA-SHA2-256/512")
        do {
            _ = try parsedRSA.sign(probe, flags: 0)
            check(false, "RSA/SHA-1 signing is unavailable")
        } catch {
            check(true, "RSA/SHA-1 signing is unavailable")
        }
        let weakRSA = try generatedRSAPEM(bits: 1_024)
        do {
            _ = try SSHPrivateKey.parse(weakRSA.pem)
            check(false, "RSA keys below 2048 bits are rejected")
        } catch let error as SSHProtectionError {
            check(error == .weakRSAKey, "RSA keys below 2048 bits are rejected")
        }

        let badCheckints = try Ed25519SSHFixture(seed: 2, mismatchedCheckints: true)
        do {
            _ = try SSHPrivateKey.parse(badCheckints.privateKeyPEM)
            check(false, "OpenSSH private-key checkint mismatch is rejected")
        } catch {
            check(true, "OpenSSH private-key checkint mismatch is rejected")
        }
        do {
            _ = try SSHPrivateKey.parse(Data(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n"
                    .appending("-----END ENCRYPTED PRIVATE KEY-----\n").utf8
            ))
            check(false, "encrypted private keys are rejected explicitly")
        } catch let error as SSHProtectionError {
            check(error == .encryptedPrivateKey, "encrypted private keys are rejected explicitly")
        }
        do {
            _ = try SSHPrivateKey.parse(Data("not a private-key file\n".utf8) + nativeKey.privateKeyPEM)
            check(false, "a PEM key embedded in unrelated content is rejected")
        } catch {
            check(true, "a PEM key embedded in unrelated content is rejected")
        }

        let sessionIdentifier = Data((0..<32).map { UInt8(200 &+ $0) })
        let hostSignature = try hostKey.signatureBlob(for: sessionIdentifier)
        let binding = try SSHDestinationBinding(
            hostKeyBlob: hostKey.publicKeyBlob,
            sessionIdentifier: sessionIdentifier,
            signature: hostSignature,
            isForwarding: false
        )
        check(binding.hostKeyFingerprint == sshFingerprint(hostKey.publicKeyBlob),
              "the destination binding verifies the host signature over the session identifier")

        var rsaSHA1Error: Unmanaged<CFError>?
        guard let rsaSHA1Signature = SecKeyCreateSignature(
            rsaFixture.privateKey,
            .rsaSignatureMessagePKCS1v15SHA1,
            sessionIdentifier as CFData,
            &rsaSHA1Error
        ) as Data? else {
            throw rsaSHA1Error?.takeRetainedValue() ?? SSHFixtureError.rsaKeyGeneration
        }
        var rsaSHA1SignatureWriter = SSHFixtureWriter()
        rsaSHA1SignatureWriter.string("ssh-rsa")
        rsaSHA1SignatureWriter.string(rsaSHA1Signature)
        let legacyRSAHostBinding = try SSHDestinationBinding(
            hostKeyBlob: parsedRSA.publicKeyBlob,
            sessionIdentifier: sessionIdentifier,
            signature: rsaSHA1SignatureWriter.data,
            isForwarding: false
        )
        check(legacyRSAHostBinding.hostKeyFingerprint == sshFingerprint(parsedRSA.publicKeyBlob),
              "destination binding verifies an RSA/SHA-1 host signature already accepted by SSH")

        let hostCertificateAuthority = try Ed25519SSHFixture(seed: 177)
        let hostCertificate = try ed25519HostCertificate(
            host: hostKey,
            certificationAuthority: hostCertificateAuthority
        )
        let certificateBinding = try SSHDestinationBinding(
            hostKeyBlob: hostCertificate,
            sessionIdentifier: sessionIdentifier,
            signature: hostSignature,
            isForwarding: false
        )
        check(certificateBinding.hostKeyBlob == hostCertificate
              && certificateBinding.hostKeyFingerprint == sshFingerprint(hostKey.publicKeyBlob),
              "a CA-verified OpenSSH host certificate binds the exact certificate and underlying key")

        do {
            var invalidCertificate = hostCertificate
            invalidCertificate[invalidCertificate.index(before: invalidCertificate.endIndex)] ^= 1
            _ = try SSHDestinationBinding(
                hostKeyBlob: invalidCertificate,
                sessionIdentifier: sessionIdentifier,
                signature: hostSignature,
                isForwarding: false
            )
            check(false, "a host certificate with an invalid CA signature is rejected")
        } catch {
            check(true, "a host certificate with an invalid CA signature is rejected")
        }
        do {
            _ = try SSHDestinationBinding(
                hostKeyBlob: ed25519HostCertificate(
                    host: hostKey,
                    certificationAuthority: hostCertificateAuthority,
                    certificateType: 1
                ),
                sessionIdentifier: sessionIdentifier,
                signature: hostSignature,
                isForwarding: false
            )
            check(false, "a user certificate cannot be used as a destination host binding")
        } catch let error as SSHProtectionError {
            check(error == .destinationBindingInvalid,
                  "a user certificate cannot be used as a destination host binding")
        }
        do {
            _ = try SSHDestinationBinding(
                hostKeyBlob: hostKey.publicKeyBlob,
                sessionIdentifier: sessionIdentifier,
                signature: hostSignature,
                isForwarding: true
            )
            check(false, "forwarded agent bindings are rejected")
        } catch let error as SSHProtectionError {
            check(error == .forwardedAgentNotAllowed, "forwarded agent bindings are rejected")
        }
        do {
            var invalidSignature = hostSignature
            invalidSignature[invalidSignature.index(before: invalidSignature.endIndex)] ^= 1
            _ = try SSHDestinationBinding(
                hostKeyBlob: hostKey.publicKeyBlob,
                sessionIdentifier: sessionIdentifier,
                signature: invalidSignature,
                isForwarding: false
            )
            check(false, "a destination binding with an invalid host signature is rejected")
        } catch {
            check(true, "a destination binding with an invalid host signature is rejected")
        }

        let rsaAuthentication = userAuthenticationRequest(
            sessionIdentifier: sessionIdentifier,
            remoteUser: "deploy",
            publicKeyBlob: parsedRSA.publicKeyBlob,
            hostKeyBlob: hostKey.publicKeyBlob,
            algorithm: "rsa-sha2-256"
        )
        let parsedRSAAuthentication = try SSHBoundUserAuthentication.parse(
            signedData: rsaAuthentication,
            binding: binding,
            requestedKeyBlob: parsedRSA.publicKeyBlob,
            flags: 0x02
        )
        check(parsedRSAAuthentication.publicKeyAlgorithm == "rsa-sha2-256",
              "RSA user authentication binds the SHA-2 algorithm to its agent flag")
        do {
            _ = try SSHBoundUserAuthentication.parse(
                signedData: rsaAuthentication,
                binding: binding,
                requestedKeyBlob: parsedRSA.publicKeyBlob,
                flags: 0x04
            )
            check(false, "mismatched RSA algorithm and agent flags are rejected")
        } catch {
            check(true, "mismatched RSA algorithm and agent flags are rejected")
        }
        do {
            _ = try SSHBoundUserAuthentication.parse(
                signedData: userAuthenticationRequest(
                    sessionIdentifier: sessionIdentifier,
                    remoteUser: "deploy",
                    publicKeyBlob: parsedRSA.publicKeyBlob,
                    hostKeyBlob: hostKey.publicKeyBlob,
                    algorithm: "ssh-rsa"
                ),
                binding: binding,
                requestedKeyBlob: parsedRSA.publicKeyBlob,
                flags: 0x02
            )
            check(false, "RSA/SHA-1 user-auth algorithm requests are rejected")
        } catch {
            check(true, "RSA/SHA-1 user-auth algorithm requests are rejected")
        }

        let signedData = userAuthenticationRequest(
            sessionIdentifier: sessionIdentifier,
            remoteUser: "deploy",
            publicKeyBlob: nativeKey.publicKeyBlob,
            hostKeyBlob: hostKey.publicKeyBlob
        )
        let authentication = try SSHBoundUserAuthentication.parse(
            signedData: signedData,
            binding: binding,
            requestedKeyBlob: nativeKey.publicKeyBlob,
            flags: 0
        )
        check(authentication.remoteUser == "deploy",
              "only an exact destination-bound SSH user-authentication packet is accepted")
        do {
            var trailing = signedData
            trailing.append(0)
            _ = try SSHBoundUserAuthentication.parse(
                signedData: trailing,
                binding: binding,
                requestedKeyBlob: nativeKey.publicKeyBlob,
                flags: 0
            )
            check(false, "trailing fields cannot hide a different signing request")
        } catch {
            check(true, "trailing fields cannot hide a different signing request")
        }
        do {
            _ = try SSHBoundUserAuthentication.parse(
                signedData: userAuthenticationRequest(
                    sessionIdentifier: sessionIdentifier,
                    remoteUser: "deploy\nmisleading review",
                    publicKeyBlob: nativeKey.publicKeyBlob,
                    hostKeyBlob: hostKey.publicKeyBlob
                ),
                binding: binding,
                requestedKeyBlob: nativeKey.publicKeyBlob,
                flags: 0
            )
            check(false, "SSH usernames cannot inject or reorder trusted review text")
        } catch {
            check(true, "SSH usernames cannot inject or reorder trusted review text")
        }

        let nativeReference = "csec://synthetic-ssh/key-one"
        let providerReference = "op://Synthetic SSH/Key Two/private key"
        let nativeCounter = SSHFixtureCounter()
        let providerCounter = SSHFixtureCounter()
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(SSHFixtureProvider(
            scheme: "csec",
            values: [nativeReference: nativeKey.privateKeyPEM],
            counter: nativeCounter
        ))
        await resolver.register(SSHFixtureProvider(
            scheme: "op",
            values: [providerReference: providerKey.privateKeyPEM],
            counter: providerCounter
        ))
        let catalog = SSHKeyCatalog(store: InMemorySSHKeyCatalogStore())
        let consent = SSHFixtureConsent()
        let review = SSHFixtureReview()
        let claudePID: pid_t = 91_000
        let firstWrapperPID: pid_t = 91_010
        let firstSSHPID: pid_t = 91_011
        let secondWrapperPID: pid_t = 91_020
        let secondSSHPID: pid_t = 91_021
        let codexPID: pid_t = 92_000
        let otherWrapperPID: pid_t = 92_010
        let otherSSHPID: pid_t = 92_011
        let processStartTimes: [pid_t: UInt64] = [
            claudePID: 1_001,
            firstWrapperPID: 1_002,
            firstSSHPID: 1_003,
            secondWrapperPID: 1_004,
            secondSSHPID: 1_005,
            codexPID: 2_001,
            otherWrapperPID: 2_002,
            otherSSHPID: 2_003,
        ]
        let processParents: [pid_t: pid_t] = [
            firstWrapperPID: claudePID,
            firstSSHPID: firstWrapperPID,
            secondWrapperPID: claudePID,
            secondSSHPID: secondWrapperPID,
            otherWrapperPID: codexPID,
            otherSSHPID: otherWrapperPID,
        ]
        let processNames: [pid_t: String] = [
            claudePID: "2.1.252",
            firstWrapperPID: "zsh",
            firstSSHPID: "ssh",
            secondWrapperPID: "flashyssh",
            secondSSHPID: "ssh",
            codexPID: "codex",
            otherWrapperPID: "zsh",
            otherSSHPID: "ssh",
        ]
        let processPaths: [pid_t: String] = [
            claudePID: "/Users/test/.local/share/claude/versions/2.1.252",
            firstWrapperPID: "/bin/zsh",
            firstSSHPID: "/usr/bin/ssh",
            secondWrapperPID: "/Users/test/project/bin/flashyssh",
            secondSSHPID: "/usr/bin/ssh",
            codexPID: "/opt/codex/bin/codex",
            otherWrapperPID: "/bin/zsh",
            otherSSHPID: "/usr/bin/ssh",
        ]
        let processInspection = SSHProcessInspection(
            startTime: { processStartTimes[$0] },
            parent: { processParents[$0] },
            name: { processNames[$0] },
            executablePath: { processPaths[$0] }
        )
        let service = SSHSigningService(
            resolver: resolver,
            catalog: catalog,
            consent: consent,
            policyReview: review,
            allowUnverifiedCallersForTesting: true,
            processInspection: processInspection
        )
        let caller = CallerInfo(
            pid: firstSSHPID,
            startTime: processStartTimes[firstSSHPID] ?? 0,
            description: "first synthetic Claude SSH client"
        )
        let siblingCaller = CallerInfo(
            pid: secondSSHPID,
            startTime: processStartTimes[secondSSHPID] ?? 0,
            description: "sibling synthetic Claude SSH client"
        )
        let otherSessionCaller = CallerInfo(
            pid: otherSSHPID,
            startTime: processStartTimes[otherSSHPID] ?? 0,
            description: "synthetic Codex SSH client"
        )
        let registrations = try await service.register([
            SSHKeyRegistrationIntent(reference: nativeReference, label: "native fixture"),
            SSHKeyRegistrationIntent(reference: providerReference, label: "provider fixture"),
        ], caller: caller)
        check(Set(registrations.map { (try? SecretRef($0.reference).scheme) ?? "" })
              == Set(["csec", "op"]),
              "the SSH catalog registers canonical references from multiple backend schemes")
        let nativeRegistrationResolutions = await nativeCounter.count()
        let providerRegistrationResolutions = await providerCounter.count()
        check(nativeRegistrationResolutions == 1 && providerRegistrationResolutions == 1,
              "registration resolves each backend through SecretResolver exactly once")
        let listed = try await service.listedSSHKeys()
        check(listed.count == 2
              && listed.allSatisfy { !$0.publicKeyBlob.isEmpty && !$0.fingerprint.isEmpty },
              "the catalog retains public metadata for both backends")

        let nativeMetadata = try registrations.first { $0.reference == nativeReference }
            .unwrap(or: SSHFixtureError.malformed)
        let beforeMalformed = await nativeCounter.count()
        do {
            _ = try await service.signSSHAuthentication(
                publicKeyBlob: nativeMetadata.publicKeyBlob,
                signedData: Data("arbitrary payload".utf8),
                flags: 0,
                binding: binding,
                caller: caller
            )
            check(false, "arbitrary signing input is rejected")
        } catch {
            check(true, "arbitrary signing input is rejected")
        }
        check(await nativeCounter.count() == beforeMalformed,
              "an invalid signing request is rejected before its provider is resolved")

        let serviceSignature = try await service.signSSHAuthentication(
            publicKeyBlob: nativeMetadata.publicKeyBlob,
            signedData: signedData,
            flags: 0,
            binding: binding,
            caller: caller
        )
        check(nativeKey.verifies(signatureBlob: serviceSignature, message: signedData),
              "the provider-neutral signing service returns only a valid signature")
        let reviewsAfterFirstSignature = await review.calls()
        _ = try await service.signSSHAuthentication(
            publicKeyBlob: nativeMetadata.publicKeyBlob,
            signedData: signedData,
            flags: 0,
            binding: binding,
            caller: siblingCaller
        )
        check(await review.calls() == reviewsAfterFirstSignature,
              "sibling SSH wrappers in one coding-agent subtree reuse one review")
        _ = try await service.signSSHAuthentication(
            publicKeyBlob: nativeMetadata.publicKeyBlob,
            signedData: signedData,
            flags: 0,
            binding: binding,
            caller: otherSessionCaller
        )
        check(await review.calls() == reviewsAfterFirstSignature + 1,
              "a different coding-agent process root requires another SSH review")

        let deniedCounter = SSHFixtureCounter()
        let deniedResolver = SecretResolver(cache: NullSecretCache())
        await deniedResolver.register(SSHFixtureProvider(
            scheme: "csec",
            values: [nativeReference: nativeKey.privateKeyPEM],
            counter: deniedCounter
        ))
        let deniedMetadata = SSHKeyMetadata(
            reference: nativeReference,
            fingerprint: sshFingerprint(nativeKey.publicKeyBlob),
            algorithm: "ssh-ed25519",
            publicKeyBlob: nativeKey.publicKeyBlob,
            label: "denied fixture"
        )
        let deniedService = SSHSigningService(
            resolver: deniedResolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [deniedMetadata])),
            consent: consent,
            policyReview: SSHDenyFixtureReview(),
            allowUnverifiedCallersForTesting: true,
            processInspection: processInspection
        )
        do {
            _ = try await deniedService.signSSHAuthentication(
                publicKeyBlob: nativeKey.publicKeyBlob,
                signedData: signedData,
                flags: 0,
                binding: binding,
                caller: caller
            )
            check(false, "a denied SSH policy review stops signing")
        } catch {
            check(true, "a denied SSH policy review stops signing")
        }
        check(await deniedCounter.count() == 0,
              "policy denial occurs before private key resolution")

        let connection = SSHAgentConnection(provider: service, caller: caller)
        let identities = await connection.handle(Data([11]))
        var identitiesReader = SSHFixtureReader(identities)
        check(try identitiesReader.byte() == 12
              && identitiesReader.uint32() == 2,
              "the SSH agent lists only catalog public identities")

        var query = SSHFixtureWriter()
        query.byte(27)
        query.string("query")
        let queryResponse = await connection.handle(query.data)
        var queryReader = SSHFixtureReader(queryResponse)
        check(try queryReader.byte() == 29
              && queryReader.text() == "query"
              && queryReader.text() == "session-bind@openssh.com"
              && queryReader.isAtEnd,
              "the SSH agent advertises only the session-binding extension")

        let unboundConnection = SSHAgentConnection(provider: service, caller: caller)
        check(await unboundConnection.handle(signRequest(
            publicKeyBlob: nativeKey.publicKeyBlob, signedData: signedData
        )) == Data([5]),
        "the SSH wire refuses signing before a verified session binding")

        let diagnosticCapture = SSHDiagnosticCapture()
        let diagnosticConnection = SSHAgentConnection(
            provider: service,
            caller: caller,
            failureReporter: { diagnosticCapture.record($0) }
        )
        var invalidHostSignature = hostSignature
        invalidHostSignature[invalidHostSignature.index(before: invalidHostSignature.endIndex)] ^= 1
        var invalidBinding = SSHFixtureWriter()
        invalidBinding.byte(27)
        invalidBinding.string("session-bind@openssh.com")
        invalidBinding.string(hostKey.publicKeyBlob)
        invalidBinding.string(sessionIdentifier)
        invalidBinding.string(invalidHostSignature)
        invalidBinding.byte(0)
        check(await diagnosticConnection.handle(invalidBinding.data) == Data([5])
              && diagnosticCapture.latest()
                == "message=27 reason=destination_binding_invalid "
                    + "host_key_algorithm=ed25519 host_signature_algorithm=ed25519 "
                    + "forwarding=false already_bound=false",
              "session-binding diagnostics contain only fixed algorithm categories and booleans")

        var untrustedHostKey = SSHFixtureWriter()
        untrustedHostKey.string("unknown\nforged-host-metadata")
        let untrustedDiagnosticConnection = SSHAgentConnection(
            provider: service,
            caller: caller,
            failureReporter: { diagnosticCapture.record($0) }
        )
        var unsupportedBinding = SSHFixtureWriter()
        unsupportedBinding.byte(27)
        unsupportedBinding.string("session-bind@openssh.com")
        unsupportedBinding.string(untrustedHostKey.data)
        unsupportedBinding.string(sessionIdentifier)
        unsupportedBinding.string(hostSignature)
        unsupportedBinding.byte(0)
        _ = await untrustedDiagnosticConnection.handle(unsupportedBinding.data)
        check(diagnosticCapture.latest()?.contains("host_key_algorithm=unsupported") == true
              && diagnosticCapture.latest()?.contains("forged-host-metadata") == false,
              "session-binding diagnostics never echo an untrusted wire algorithm")

        check(await connection.handle(try sessionBindMessage(
            host: hostKey, sessionIdentifier: sessionIdentifier
        )) == Data([6]),
        "the SSH wire accepts one verified, non-forwarded session binding")
        let wireResponse = await connection.handle(signRequest(
            publicKeyBlob: nativeKey.publicKeyBlob, signedData: signedData
        ))
        var wireReader = SSHFixtureReader(wireResponse)
        let wireType = try wireReader.byte()
        let wireSignature = try wireReader.string()
        check(wireType == 14 && wireReader.isAtEnd
              && nativeKey.verifies(signatureBlob: wireSignature, message: signedData),
              "the bound SSH wire request returns a valid signature response")
        check(await connection.handle(try sessionBindMessage(
            host: hostKey, sessionIdentifier: sessionIdentifier
        )) == Data([5]),
        "a connection cannot replace or duplicate its destination binding")

        let forwardedConnection = SSHAgentConnection(provider: service, caller: caller)
        check(await forwardedConnection.handle(try sessionBindMessage(
            host: hostKey, sessionIdentifier: sessionIdentifier, forwarding: true
        )) == Data([5]),
        "the SSH wire fails closed for agent forwarding")
        check(await forwardedConnection.handle(Data([17])) == Data([5]),
              "SSH wire mutation operations cannot change the csec catalog")
    } catch {
        check(false, "SSH protection checks succeed (\(error))")
    }
}

private extension Optional {
    func unwrap(or error: @autoclosure () -> Error) throws -> Wrapped {
        guard let value = self else { throw error() }
        return value
    }
}
