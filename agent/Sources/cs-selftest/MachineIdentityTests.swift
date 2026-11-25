import ConvenientSecurity
import CryptoKit
import Foundation

// Dev-machine OIDC's core: the public key as a JWK and its RFC 7638 kid, the
// ES256 token a cloud's workload identity federation accepts, and the issuer's
// two public documents. A software key stands in for the Secure Enclave, which
// unsigned builds and CI cannot assume; the enclave itself is checked once,
// when this Mac has one.

// RFC 6979 §A.2.5's P-256 key, so the JWK and its thumbprint are fixed
// vectors. The expected thumbprint was computed outside Swift, with Python's
// hashlib over the RFC 7638 canonical JSON.
private let vectorPrivateKey = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
private let vectorX = "YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y"
private let vectorY = "eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk"
private let vectorKid = "DOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0"

private func hexData(_ hex: String) -> Data {
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        data.append(UInt8(hex[index..<next], radix: 16)!)
        index = next
    }
    return data
}

private func segmentJSON(_ token: String, _ index: Int) -> [String: Any]? {
    let parts = token.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3 else { return nil }
    var base64 = String(parts[index]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    base64 += String(repeating: "=", count: (4 - base64.utf8.count % 4) % 4)
    guard let data = Data(base64Encoded: base64) else { return nil }
    return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
}

func machineIdentityTests() async {
    print("\n# Machine identity (dev-machine OIDC)")
    machineIdentityJWKTests()
    machineIdentityTokenTests()
    machineIdentityClaimValidationTests()
    machineIdentityIssuerDocumentTests()
    machineIdentitySecureEnclaveTests()
    await machineIdentityCatalogTests()
    await machineIdentityProviderTests()
    machineIdentityS3IssuerTests()
    await machineIdentityIssuerCheckTests()
    await machineIdentityCloudTests()
}

private func machineIdentityJWKTests() {
    let key = try! P256.Signing.PrivateKey(rawRepresentation: hexData(vectorPrivateKey))
    let jwk = MachineIdentityJWK(publicKey: key.publicKey)
    check(jwk.kty == "EC" && jwk.crv == "P-256" && jwk.alg == "ES256" && jwk.use == "sig",
          "identity JWK is an EC P-256 ES256 signing key")
    check(jwk.x == vectorX && jwk.y == vectorY, "identity JWK coordinates are the key's unpadded base64url x and y")
    check(jwk.kid == vectorKid, "identity JWK kid is the RFC 7638 thumbprint (independently computed vector)")
    check((try? jwk.publicKey())?.x963Representation == key.publicKey.x963Representation,
          "identity JWK round-trips to the same public key")

    let tampered = try! JSONDecoder().decode(
        MachineIdentityJWK.self,
        from: JSONSerialization.data(withJSONObject: [
            "kty": "EC", "crv": "P-256", "x": vectorX, "y": vectorY,
            "kid": "not-the-thumbprint", "alg": "ES256", "use": "sig",
        ])
    )
    check((try? tampered.publicKey()) == nil, "identity JWK whose kid is not its thumbprint is refused")
}

private func machineIdentityTokenTests() {
    let signer = SoftwareIdentitySigner()
    let jwk = MachineIdentityJWK(publicKey: signer.publicKey)
    let issued = Date(timeIntervalSince1970: 1_800_000_000.75)
    let claims = try! MachineIdentityClaims(
        issuer: "https://issuer.example.test/macs",
        subject: "dev-mac",
        audience: "sts.amazonaws.com",
        issuedAt: issued,
        lifetime: 900,
        tokenID: "token-1"
    )
    check(claims.issuedAt.timeIntervalSince1970 == 1_800_000_000, "identity claims keep whole seconds")
    check(claims.expiresAt.timeIntervalSince1970 == 1_800_000_900, "identity claims expire lifetime seconds after issue")

    guard let token = try? MachineIdentityToken.mint(claims, signer: signer) else {
        check(false, "identity token mints")
        return
    }
    let header = segmentJSON(token, 0)
    check(header?["alg"] as? String == "ES256" && header?["typ"] as? String == "JWT"
            && header?["kid"] as? String == jwk.kid,
          "identity token header is ES256 JWT with the key's thumbprint as kid")
    let payload = segmentJSON(token, 1)
    check(payload?["iss"] as? String == "https://issuer.example.test/macs"
            && payload?["sub"] as? String == "dev-mac"
            && payload?["aud"] as? String == "sts.amazonaws.com"
            && payload?["iat"] as? Int == 1_800_000_000
            && payload?["nbf"] as? Int == 1_800_000_000
            && payload?["exp"] as? Int == 1_800_000_900
            && payload?["jti"] as? String == "token-1"
            && payload?.count == 7,
          "identity token payload carries exactly iss, sub, aud, iat, nbf, exp and jti")
    check(!token.contains("="), "identity token segments are unpadded base64url")
    check(!token.contains("\\/"), "identity token JSON does not escape slashes")

    let signature = token.split(separator: ".").last.map(String.init) ?? ""
    check(signature.utf8.count == 86, "identity token signature is the raw 64-byte R||S, not DER")

    let verified = try? MachineIdentityToken.verify(token, keys: [jwk])
    check(verified?.subject == "dev-mac" && verified?.audience == "sts.amazonaws.com"
            && verified?.expiresAt == 1_800_000_900 && verified?.kid == jwk.kid,
          "identity token verifies against its public key")

    let other = MachineIdentityJWK(publicKey: SoftwareIdentitySigner().publicKey)
    checkThrows("identity token is refused by a key set without its key") {
        _ = try MachineIdentityToken.verify(token, keys: [other])
    }

    var parts = token.split(separator: ".").map(String.init)
    let forgedPayload = try! JSONSerialization.data(
        withJSONObject: [
            "iss": "https://issuer.example.test/macs", "sub": "admin-mac", "aud": "sts.amazonaws.com",
            "iat": 1_800_000_000, "nbf": 1_800_000_000, "exp": 1_800_000_900, "jti": "token-1",
        ],
        options: [.sortedKeys]
    )
    parts[1] = forgedPayload.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    checkThrows("identity token with a changed subject fails its signature") {
        _ = try MachineIdentityToken.verify(parts.joined(separator: "."), keys: [jwk])
    }
    checkThrows("identity token verifier refuses a non-JWS") {
        _ = try MachineIdentityToken.verify("not.a-token", keys: [jwk])
    }
}

private func machineIdentityClaimValidationTests() {
    let now = Date()
    func claims(issuer: String = "https://issuer.example.test", subject: String = "mac",
                audience: String = "aud", lifetime: Int = 3_600) throws -> MachineIdentityClaims {
        try MachineIdentityClaims(issuer: issuer, subject: subject, audience: audience, issuedAt: now, lifetime: lifetime)
    }
    check((try? claims()) != nil, "identity claims accept an https issuer, subject and audience")
    check((try? claims(issuer: "https://bucket.s3.eu-west-2.amazonaws.com")) != nil,
          "identity claims accept an S3 website-style issuer")
    for issuer in [
        "http://issuer.example.test", "https://issuer.example.test/", "https://issuer.example.test?x=1",
        "https://issuer.example.test#frag", "https://user:pass@issuer.example.test", "https://",
        "issuer.example.test", "https://issuer.example.test/a b",
    ] {
        checkThrows("identity claims refuse issuer \(issuer)") { _ = try claims(issuer: issuer) }
    }
    checkThrows("identity claims refuse an empty subject") { _ = try claims(subject: "") }
    checkThrows("identity claims refuse a subject with a newline") { _ = try claims(subject: "mac\nother") }
    checkThrows("identity claims refuse a non-ASCII subject") { _ = try claims(subject: "mäc") }
    check((try? claims(subject: String(repeating: "m", count: 127))) != nil, "identity claims accept a 127-byte subject")
    checkThrows("identity claims refuse a subject over Google's 127-byte google.subject limit") {
        _ = try claims(subject: String(repeating: "m", count: 128))
    }
    checkThrows("identity claims refuse an empty audience") { _ = try claims(audience: "") }
    checkThrows("identity claims refuse a lifetime over an hour") { _ = try claims(lifetime: 3_601) }
    checkThrows("identity claims refuse a lifetime under a minute") { _ = try claims(lifetime: 59) }
}

private func machineIdentityIssuerDocumentTests() {
    let issuer = "https://issuer.example.test/macs"
    guard let discoveryData = try? MachineIdentityIssuer.discoveryDocument(issuer: issuer),
          let discovery = try? JSONSerialization.jsonObject(with: discoveryData) as? [String: Any] else {
        check(false, "issuer discovery document builds")
        return
    }
    check(discovery["issuer"] as? String == issuer, "issuer discovery names the issuer exactly")
    check(discovery["jwks_uri"] as? String == "https://issuer.example.test/macs/jwks.json",
          "issuer discovery points jwks_uri at <issuer>/jwks.json")
    check(discovery["id_token_signing_alg_values_supported"] as? [String] == ["ES256"]
            && discovery["response_types_supported"] as? [String] == ["id_token"]
            && discovery["subject_types_supported"] as? [String] == ["public"],
          "issuer discovery advertises ES256 id tokens with public subjects")
    checkThrows("issuer discovery refuses a non-https issuer") {
        _ = try MachineIdentityIssuer.discoveryDocument(issuer: "http://issuer.example.test")
    }

    let first = MachineIdentityJWK(publicKey: SoftwareIdentitySigner().publicKey)
    let second = MachineIdentityJWK(publicKey: SoftwareIdentitySigner().publicKey)
    let a = try? MachineIdentityIssuer.keySet([first, second, first])
    let b = try? MachineIdentityIssuer.keySet([second, first])
    check(a != nil && a == b, "issuer key set is deterministic and drops duplicate kids")
    struct KeySet: Decodable { let keys: [MachineIdentityJWK] }
    let decoded = a.flatMap { try? JSONDecoder().decode(KeySet.self, from: $0) }
    check(decoded?.keys.map(\.kid) == [first.kid, second.kid].sorted(),
          "issuer key set holds each key once, sorted by kid")
    if let a, let text = String(data: a, encoding: .utf8) {
        check(!text.contains("\"d\""), "issuer key set carries no private member")
    }
}

/// The real enclave, when this Mac has one: a key made there signs a token
/// that verifies, and its wrapped handle reloads to the same key.
private func machineIdentitySecureEnclaveTests() {
    guard SecureEnclave.isAvailable else {
        print("skip - Secure Enclave identity key (no Secure Enclave on this Mac)")
        return
    }
    do {
        let (signer, handle) = try SecureEnclaveIdentitySigner.create()
        let claims = try MachineIdentityClaims(
            issuer: "https://issuer.example.test", subject: "enclave", audience: "aud", issuedAt: Date()
        )
        let token = try MachineIdentityToken.mint(claims, signer: signer)
        let jwk = MachineIdentityJWK(publicKey: signer.publicKey)
        check((try? MachineIdentityToken.verify(token, keys: [jwk]))?.subject == "enclave",
              "Secure Enclave identity key signs a token that verifies")
        let reloaded = try SecureEnclaveIdentitySigner(dataRepresentation: handle)
        check(reloaded.publicKey.x963Representation == signer.publicKey.x963Representation,
              "Secure Enclave identity key reloads from its wrapped handle")
    } catch {
        check(false, "Secure Enclave identity key works (\(error))")
    }
    checkThrows("Secure Enclave identity signer refuses a handle that is not one") {
        _ = try SecureEnclaveIdentitySigner(dataRepresentation: Data(repeating: 7, count: 64))
    }
}

// MARK: - Catalog and provider

/// Software keys whose "handle" is the private key itself: test-only, so a
/// restarted catalog can reopen what an earlier one made.
private let softwareKeys = MachineIdentityKeyFactory(
    create: {
        let key = P256.Signing.PrivateKey()
        return (SoftwareIdentitySigner(key: key), key.rawRepresentation)
    },
    open: { SoftwareIdentitySigner(key: try P256.Signing.PrivateKey(rawRepresentation: $0)) }
)

private let fixedClock: @Sendable () -> Date = { Date(timeIntervalSince1970: 1_800_000_000) }

private func machineIdentityCatalogTests() async {
    let backend = InMemoryProtectedItemBackend()
    let catalog = MachineIdentityCatalog(
        store: ProtectedStores.processLocal(backend).store(for: MachineIdentityDocument.self),
        keys: softwareKeys, clock: fixedClock
    )
    await catalog.load()
    do {
        let identity = try await catalog.createIdentity(
            name: "default", issuer: "https://issuer.example.test", subject: "dev-mac"
        )
        check(identity.keys.count == 1 && identity.keys[0].jwk.kid.utf8.count == 43,
              "identity catalog makes one key with a thumbprint kid")
        try await catalog.addTarget(MachineIdentityTarget(name: "aws", identity: "default", audience: "sts.amazonaws.com"))
    } catch {
        check(false, "identity catalog creates an identity and a target (\(error))")
        return
    }
    check(MachineIdentityTarget(name: "aws", identity: "default", audience: "x").reference
            == "csec-identity://default/aws",
          "identity target's reference is csec-identity://<identity>/<target>")

    do {
        _ = try await catalog.createIdentity(name: "default", issuer: "https://issuer.example.test", subject: "x")
        check(false, "identity catalog refuses a second identity with the same name")
    } catch {
        check(error as? MachineIdentityCatalogError == .identityExists("default"),
              "identity catalog refuses a second identity with the same name")
    }
    do {
        try await catalog.addTarget(MachineIdentityTarget(name: "t", identity: "missing", audience: "aud"))
        check(false, "identity catalog refuses a target for an identity it does not have")
    } catch {
        check(error as? MachineIdentityCatalogError == .identityNotFound("missing"),
              "identity catalog refuses a target for an identity it does not have")
    }
    for name in ["", "Default", "-x", ".x", "a/b", "a b", String(repeating: "a", count: 65)] {
        do {
            _ = try await catalog.createIdentity(name: name, issuer: "https://issuer.example.test", subject: "x")
            check(false, "identity catalog refuses the name \"\(name)\"")
        } catch {
            check(error as? MachineIdentityCatalogError == .invalid(.invalidName),
                  "identity catalog refuses the name \"\(name.prefix(12))\"")
        }
    }

    // A restarted csecd reads the same catalog back and mints with the same key.
    let restarted = MachineIdentityCatalog(
        store: ProtectedStores.processLocal(backend).store(for: MachineIdentityDocument.self),
        keys: softwareKeys, clock: fixedClock
    )
    await restarted.load()
    let before = await catalog.snapshot
    let after = await restarted.snapshot
    check(after == before && after.identities.count == 1 && after.targets.count == 1,
          "identity catalog survives a restart unchanged")
    if let minted = try? await restarted.mint(identity: "default", target: "aws"),
       let keys = try? await restarted.publicKeys(identity: "default") {
        let verified = try? MachineIdentityToken.verify(minted.token, keys: keys)
        check(verified?.issuer == "https://issuer.example.test" && verified?.subject == "dev-mac"
                && verified?.audience == "sts.amazonaws.com" && verified?.issuedAt == 1_800_000_000
                && verified?.expiresAt == 1_800_003_600
                && minted.expiresAt == Date(timeIntervalSince1970: 1_800_003_600),
              "identity catalog mints after a restart, with the identity's issuer and subject and the target's audience")
    } else {
        check(false, "identity catalog mints after a restart")
    }

    // A handle that opens to some other key is not the identity's key.
    let swapped = MachineIdentityCatalog(
        store: ProtectedStores.processLocal(backend).store(for: MachineIdentityDocument.self),
        keys: MachineIdentityKeyFactory(create: softwareKeys.create, open: { _ in SoftwareIdentitySigner() }),
        clock: fixedClock
    )
    await swapped.load()
    do {
        _ = try await swapped.mint(identity: "default", target: "aws")
        check(false, "identity catalog refuses a key handle that opens to another key")
    } catch {
        check(error as? MachineIdentityCatalogError == .invalid(.keyUnusable),
              "identity catalog refuses a key handle that opens to another key")
    }

    do {
        try await restarted.removeIdentity(named: "default")
        let emptied = await restarted.snapshot
        check(emptied.identities.isEmpty && emptied.targets.isEmpty,
              "removing an identity removes its targets and key handles")
    } catch {
        check(false, "identity catalog removes an identity (\(error))")
    }

    let orphan = MachineIdentityDocument(
        identities: [], targets: [MachineIdentityTarget(name: "t", identity: "gone", audience: "aud")]
    )
    check(!orphan.isWellFormed, "identity document refuses a target whose identity is missing")
    if let encoded = try? JSONEncoder().encode(before),
       let text = String(data: encoded, encoding: .utf8) {
        check(!text.contains("\"d\""), "identity document stores public JWKs, never a private member")
    }
}

private func machineIdentityProviderTests() async {
    let catalog = MachineIdentityCatalog(store: nil, keys: softwareKeys, clock: fixedClock)
    let provider = MachineIdentityProvider(catalog: catalog)
    do {
        try await catalog.createIdentity(name: "work", issuer: "https://issuer.example.test", subject: "dev-mac")
        try await catalog.addTarget(MachineIdentityTarget(
            name: "gcp", identity: "work",
            audience: "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/macs",
            lifetime: 900
        ))
    } catch {
        check(false, "identity provider fixture (\(error))")
        return
    }
    let ref = try! SecretRef("csec-identity://work/gcp")
    check(provider.schemes == ["csec-identity"], "identity provider claims the csec-identity scheme")
    check(MachineIdentityProvider.parse(ref)! == ("work", "gcp"), "identity provider parses <identity>/<target>")
    for bad in ["csec-identity://work", "csec-identity://work/gcp/extra", "csec-identity://Work/gcp", "csec://work/gcp"] {
        check(MachineIdentityProvider.parse(try! SecretRef(bad)) == nil, "identity provider refuses \(bad)")
    }

    // Through the resolver, as every delivery path reaches a provider: the
    // value is a fresh token and nothing is cached.
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(provider)
    let keys = (try? await catalog.publicKeys(identity: "work")) ?? []
    if let value = try? await resolver.resolve(ref, unlock: nil),
       let token = String(data: value, encoding: .utf8) {
        let verified = try? MachineIdentityToken.verify(token, keys: keys)
        check(verified?.subject == "dev-mac" && verified?.expiresAt == 1_800_000_900
                && verified?.audience.hasPrefix("https://iam.googleapis.com/") == true,
              "identity reference resolves through SecretResolver to a token for the target's audience and lifetime")
        let again = try? await resolver.resolve(ref, unlock: nil)
        let second = again.flatMap { String(data: $0, encoding: .utf8) }
        let firstID = verified?.tokenID
        let secondID = second.flatMap { try? MachineIdentityToken.verify($0, keys: keys) }?.tokenID
        check(firstID != nil && secondID != nil && firstID != secondID,
              "each resolution mints a fresh token (a new jti), never a cached one")
    } else {
        check(false, "identity reference resolves through SecretResolver")
    }
    check(await resolver.resolveWithoutInteraction(ref) != nil,
          "identity reference resolves without interaction: no unlock, prompt or network")
    check(await provider.requiresUnlockToResolve(ref) == false, "identity reference needs no unlock")

    check(await provider.presence(of: ref) == .present, "identity provider reports a catalogued target present")
    if case .absent = await provider.presence(of: try! SecretRef("csec-identity://work/missing")) {
        check(true, "identity provider reports an unknown target absent before any review")
    } else {
        check(false, "identity provider reports an unknown target absent before any review")
    }
    if case .absent = await provider.presence(of: try! SecretRef("csec-identity://other/gcp")) {
        check(true, "identity provider reports an unknown identity absent")
    } else {
        check(false, "identity provider reports an unknown identity absent")
    }
    do {
        _ = try await provider.resolve(try! SecretRef("csec-identity://work/missing"), unlock: nil)
        check(false, "identity provider refuses to mint for an unknown target")
    } catch {
        if case ProviderError.referenceNotFound = error {
            check(true, "identity provider refuses to mint for an unknown target")
        } else {
            check(false, "identity provider refuses to mint for an unknown target (\(error))")
        }
    }

    let description = await provider.reviewDescription(for: ref)
    check(description?.provider == "Machine identity" && description?.account == "this Mac"
            && description?.container == "work" && description?.item == "gcp" && description?.tint == .indigo,
          "identity review names the provider, this Mac, the identity and the target")
    check(description?.notes.contains { $0.contains("dev-mac") && $0.contains("iam.googleapis.com") } == true
            && description?.notes.contains { $0.contains("15 minutes") } == true,
          "identity review says who the token signs in as, for which audience, and for how long")
    let status = await provider.statusSummary()
    check(status?.label == "Machine identity" && status?.detail == "1 identity, 1 target",
          "identity provider's status line counts identities and targets")
}

// MARK: - Issuer hosting and the tamper check

private func machineIdentityS3IssuerTests() {
    let admin = "arn:aws:iam::824489342825:role/aws-reserved/sso.amazonaws.com/eu-west-2/AWSReservedSSO_Administrator_87c3ef022852184a"
    guard let setup = try? MachineIdentityS3Issuer(bucket: "harbor-macs-oidc", region: "eu-west-2", administratorARN: admin) else {
        check(false, "S3 issuer guidance accepts a bucket, region and administrator")
        return
    }
    check(setup.issuer == "https://harbor-macs-oidc.s3.eu-west-2.amazonaws.com",
          "S3 issuer is the bucket's virtual-hosted https URL")
    check(MachineIdentityIssuer.isValid(setup.issuer), "S3 issuer URL is a valid issuer")

    // The bucket policy an existing issuer applied and verified, with csec's Sid.
    let harborPolicy: [String: Any] = [
        "Version": "2012-10-17",
        "Statement": [
            [
                "Sid": "PublicIssuerFiles", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                "Resource": [
                    "arn:aws:s3:::harbor-macs-oidc/.well-known/openid-configuration",
                    "arn:aws:s3:::harbor-macs-oidc/jwks.json",
                ],
            ],
            [
                "Sid": "OnlyTheAdministratorChangesTheIssuer", "Effect": "Deny", "Principal": "*",
                "NotAction": ["s3:Get*", "s3:List*"],
                "Resource": ["arn:aws:s3:::harbor-macs-oidc", "arn:aws:s3:::harbor-macs-oidc/*"],
                "Condition": ["ArnNotEquals": ["aws:PrincipalArn": admin]],
            ],
        ],
    ]
    let generated = (try? setup.bucketPolicy()).flatMap { try? JSONSerialization.jsonObject(with: $0) as? NSDictionary }
    check(generated == (harborPolicy as NSDictionary),
          "S3 bucket policy is av-0.360.15's: public reads of the two files, every change denied but to the administrator")

    let commands = setup.setupCommands()
    let versioning = commands.firstIndex { $0.contains("put-bucket-versioning") && $0.contains("Status=Enabled") }
    let policy = commands.firstIndex { $0.contains("put-bucket-policy") }
    check(versioning != nil && policy != nil && versioning! < policy!,
          "S3 setup turns versioning on before the policy that then denies changing it")
    check(commands.contains { $0.contains("BlockPublicAcls=true,IgnorePublicAcls=true") }
            && commands.contains { $0.contains("BucketOwnerEnforced") },
          "S3 setup blocks public ACLs and disables ACLs")
    check(commands.contains { $0.contains("LocationConstraint=eu-west-2") },
          "S3 setup creates the bucket in its region")
    check(commands.suffix(2) == setup.publishCommands()
            && setup.publishCommands().allSatisfy { $0.contains("--content-type application/json") },
          "S3 setup ends by publishing both files as application/json")
    let east = try? MachineIdentityS3Issuer(bucket: "issuer-test", region: "us-east-1", administratorARN: admin)
    check(east?.setupCommands().first?.contains("LocationConstraint") == false,
          "S3 setup in us-east-1 sends no location constraint (S3 refuses one there)")

    for bucket in ["ab", "Upper", "has.dot", "-lead", "trail-", "xn--punycode", String(repeating: "a", count: 64), "under_score"] {
        check((try? MachineIdentityS3Issuer(bucket: bucket, region: "eu-west-2", administratorARN: admin)) == nil,
              "S3 issuer refuses bucket name \(bucket.prefix(20))")
    }
    for region in ["", "eu", "eu-west", "EU-WEST-2", "eu-west-x"] {
        check((try? MachineIdentityS3Issuer(bucket: "issuer-test", region: region, administratorARN: admin)) == nil,
              "S3 issuer refuses region \"\(region)\"")
    }
    for arn in ["arn:aws:iam::123:role/x", "arn:aws:s3:::bucket", "arn:aws:iam::824489342825:group/admins",
                "arn:aws:iam::824489342825:role/a\"b", "*"] {
        check((try? MachineIdentityS3Issuer(bucket: "issuer-test", region: "eu-west-2", administratorARN: arn)) == nil,
              "S3 issuer refuses administrator \(arn.prefix(30))")
    }
    check((try? MachineIdentityS3Issuer(bucket: "issuer-test", region: "us-gov-west-1",
                                        administratorARN: "arn:aws-us-gov:iam::123456789012:user/publisher")) != nil,
          "S3 issuer accepts a GovCloud region and a user ARN")
}

private func machineIdentityIssuerCheckTests() async {
    let issuer = "https://issuer.example.test"
    let mine = MachineIdentityJWK(publicKey: SoftwareIdentitySigner().publicKey)
    let otherMac = MachineIdentityJWK(publicKey: SoftwareIdentitySigner().publicKey)
    let attacker = MachineIdentityJWK(publicKey: SoftwareIdentitySigner().publicKey)
    let discovery = try! MachineIdentityIssuer.discoveryDocument(issuer: issuer)
    func evaluate(_ keys: [MachineIdentityJWK], accepted: Set<String> = [], discovery: Data? = nil) -> MachineIdentityIssuerFinding {
        MachineIdentityIssuerCheck.evaluate(
            issuer: issuer, discovery: discovery ?? discoveryDoc(), keySet: try! MachineIdentityIssuer.keySet(keys),
            ownKeys: [mine], acceptedKids: accepted
        )
    }
    func discoveryDoc() -> Data { discovery }

    check(evaluate([mine]) == .clear(publishedKeys: 1), "issuer check: only this Mac's key is clear")
    check(evaluate([mine, otherMac], accepted: [otherMac.kid]) == .clear(publishedKeys: 2),
          "issuer check: another key the human accepted is clear")
    check(evaluate([mine, attacker], accepted: [otherMac.kid]) == .unexpectedKeys([attacker.kid]),
          "issuer check: a key nobody accepted is flagged by kid")
    check(evaluate([otherMac], accepted: [otherMac.kid]) == .ownKeyMissing(kid: mine.kid),
          "issuer check: this Mac's key missing is reported, not called clear")

    // The same kid with another key's coordinates is someone else's key.
    let forged = try! JSONSerialization.data(withJSONObject: ["keys": [[
        "kty": "EC", "crv": "P-256", "x": attacker.x, "y": attacker.y, "kid": mine.kid, "alg": "ES256", "use": "sig",
    ]]])
    if case .unexpectedKeys = MachineIdentityIssuerCheck.evaluate(
        issuer: issuer, discovery: discovery, keySet: forged, ownKeys: [mine], acceptedKids: []
    ) {
        check(true, "issuer check: another key published under this Mac's kid is flagged")
    } else {
        check(false, "issuer check: another key published under this Mac's kid is flagged")
    }
    // Any entry counts, an RSA key or one with no kid included.
    let rsa = try! JSONSerialization.data(withJSONObject: ["keys": [
        ["kty": "EC", "crv": "P-256", "x": mine.x, "y": mine.y, "kid": mine.kid],
        ["kty": "RSA", "n": "AQAB", "e": "AQAB"],
    ]])
    check(MachineIdentityIssuerCheck.evaluate(issuer: issuer, discovery: discovery, keySet: rsa, ownKeys: [mine], acceptedKids: [])
            == .unexpectedKeys(["key #2 (not an EC P-256 key)"]),
          "issuer check: a key of another type, without a kid, is flagged too")

    // An accepted key is its key material, not its kid: another key published
    // under the other Mac's kid is a key nobody accepted.
    let swapped = try! JSONSerialization.data(withJSONObject: ["keys": [
        ["kty": "EC", "crv": "P-256", "x": mine.x, "y": mine.y, "kid": mine.kid],
        ["kty": "EC", "crv": "P-256", "x": attacker.x, "y": attacker.y, "kid": otherMac.kid],
    ]])
    check(MachineIdentityIssuerCheck.evaluate(
        issuer: issuer, discovery: discovery, keySet: swapped, ownKeys: [mine], acceptedKids: [otherMac.kid]
    ) == .unexpectedKeys([attacker.kid]),
          "issuer check: a key swapped in under an accepted kid is flagged by its own thumbprint")
    // This Mac's key published under another kid is still this Mac's key.
    let relabelled = try! JSONSerialization.data(withJSONObject: ["keys": [
        ["kty": "EC", "crv": "P-256", "x": mine.x, "y": mine.y, "kid": "renamed"],
    ]])
    check(MachineIdentityIssuerCheck.evaluate(
        issuer: issuer, discovery: discovery, keySet: relabelled, ownKeys: [mine], acceptedKids: []
    ) == .clear(publishedKeys: 1),
          "issuer check: keys are compared by thumbprint, whatever kid the file claims")

    let elsewhere = try! JSONSerialization.data(withJSONObject: [
        "issuer": issuer, "jwks_uri": "https://evil.example.test/jwks.json",
    ])
    if case .discoveryMismatch = evaluate([mine], discovery: elsewhere) {
        check(true, "issuer check: a discovery document pointing jwks_uri elsewhere is flagged")
    } else {
        check(false, "issuer check: a discovery document pointing jwks_uri elsewhere is flagged")
    }
    let otherIssuer = try! MachineIdentityIssuer.discoveryDocument(issuer: "https://other.example.test")
    if case .discoveryMismatch = evaluate([mine], discovery: otherIssuer) {
        check(true, "issuer check: a discovery document naming another issuer is flagged")
    } else {
        check(false, "issuer check: a discovery document naming another issuer is flagged")
    }
    if case .unreachable = MachineIdentityIssuerCheck.evaluate(
        issuer: issuer, discovery: Data("<html>".utf8), keySet: Data(), ownKeys: [mine], acceptedKids: []
    ) {
        check(true, "issuer check: an unreadable document is unknown, never clear")
    } else {
        check(false, "issuer check: an unreadable document is unknown, never clear")
    }

    // Fetching: both files from the issuer's own paths, and a failed fetch
    // is unknown.
    let keySet = try! MachineIdentityIssuer.keySet([mine])
    let fetched = await MachineIdentityIssuerCheck.check(issuer: issuer, ownKeys: [mine], acceptedKids: []) { url in
        switch url.absoluteString {
        case "https://issuer.example.test/.well-known/openid-configuration": return discovery
        case "https://issuer.example.test/jwks.json": return keySet
        default: throw MachineIdentityIssuerCheck.FetchError.status(404)
        }
    }
    check(fetched == .clear(publishedKeys: 1), "issuer check fetches the discovery document and jwks.json from the issuer")
    let failed = await MachineIdentityIssuerCheck.check(issuer: issuer, ownKeys: [mine], acceptedKids: []) { _ in
        throw MachineIdentityIssuerCheck.FetchError.status(403)
    }
    check(failed == .unreachable("HTTP 403"), "issuer check reports a failed fetch as unknown, with its status")

    // Through the catalog: accepting another Mac's key clears it, and an
    // accepted key survives a restart.
    let backend = InMemoryProtectedItemBackend()
    let catalog = MachineIdentityCatalog(
        store: ProtectedStores.processLocal(backend).store(for: MachineIdentityDocument.self), keys: softwareKeys
    )
    guard let identity = try? await catalog.createIdentity(name: "default", issuer: issuer, subject: "dev-mac") else {
        check(false, "issuer check catalog fixture")
        return
    }
    let own = identity.keys[0].jwk
    let published = try! MachineIdentityIssuer.keySet([own, otherMac])
    let serve: @Sendable (URL) async throws -> Data = { url in
        url.path.hasSuffix("jwks.json") ? published : discovery
    }
    check((try? await catalog.checkIssuer(identity: "default", fetch: serve)) == .unexpectedKeys([otherMac.kid]),
          "catalog issuer check flags another Mac's key until it is accepted")
    try? await catalog.acceptKeys(identity: "default", kids: [otherMac.kid, own.kid])
    let restarted = MachineIdentityCatalog(
        store: ProtectedStores.processLocal(backend).store(for: MachineIdentityDocument.self), keys: softwareKeys
    )
    await restarted.load()
    check(await restarted.identity(named: "default")?.acceptedKids == [otherMac.kid],
          "accepting keys records only foreign kids, and survives a restart")
    check((try? await restarted.checkIssuer(identity: "default", fetch: serve)) == .clear(publishedKeys: 2),
          "catalog issuer check is clear once the other Mac's key is accepted")
}
