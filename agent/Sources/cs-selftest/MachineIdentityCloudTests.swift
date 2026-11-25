import ConvenientSecurity
import CryptoKit
import Foundation

// Dev-machine OIDC's sign-ins: AWS targets exchanged with STS inside csecd,
// the management service csecd serves `csec identity` from, and the setup
// csec writes for AWS and Google Cloud. STS is injected, so nothing here
// touches the network or a cloud account; the live exchange is checked on a
// signed build against a real role.

private let cloudTestKeys = MachineIdentityKeyFactory(
    create: {
        let key = P256.Signing.PrivateKey()
        return (SoftwareIdentitySigner(key: key), key.rawRepresentation)
    },
    open: { SoftwareIdentitySigner(key: try P256.Signing.PrivateKey(rawRepresentation: $0)) }
)

private let cloudTestRole = "arn:aws:iam::123456789012:role/dev/csec-admin"

/// A clock a test can move.
private final class MovableClock: @unchecked Sendable {
    private let lock = NSLock()
    private var now: Date
    init(_ start: Date) { now = start }
    func read() -> Date { lock.withLock { now } }
    func advance(_ seconds: TimeInterval) { lock.withLock { now = now.addingTimeInterval(seconds) } }
}

/// STS, scripted: records each request and answers with a fixed reply.
private final class ScriptedSTS: @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [URLRequest] = []
    private var reply: (Data, Int)
    init(reply: (Data, Int)) { self.reply = reply }
    var count: Int { lock.withLock { requests.count } }
    var last: URLRequest? { lock.withLock { requests.last } }
    func answer(with reply: (Data, Int)) { lock.withLock { self.reply = reply } }
    func send(_ request: URLRequest) -> (Data, Int) {
        lock.withLock {
            requests.append(request)
            return reply
        }
    }
}

private func stsSuccess(expiration: String) -> Data {
    Data("""
    <AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
      <AssumeRoleWithWebIdentityResult>
        <SubjectFromWebIdentityToken>dev-mac</SubjectFromWebIdentityToken>
        <Credentials>
          <AccessKeyId>ASIAEXAMPLEEXAMPLE01</AccessKeyId>
          <SecretAccessKey>synthetic/secret+key=</SecretAccessKey>
          <SessionToken>synthetic-session-token</SessionToken>
          <Expiration>\(expiration)</Expiration>
        </Credentials>
      </AssumeRoleWithWebIdentityResult>
    </AssumeRoleWithWebIdentityResponse>
    """.utf8)
}

private func stsError(_ code: String) -> Data {
    Data("""
    <ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
      <Error><Type>Sender</Type><Code>\(code)</Code><Message>No OpenIDConnect provider found for https://issuer.example.test</Message></Error>
    </ErrorResponse>
    """.utf8)
}

/// The form fields of an STS request body.
private func formFields(_ request: URLRequest?) -> [String: String] {
    guard let body = request?.httpBody, let text = String(data: body, encoding: .utf8) else { return [:] }
    var fields: [String: String] = [:]
    for pair in text.split(separator: "&") {
        let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { continue }
        fields[parts[0].removingPercentEncoding ?? parts[0]] = parts[1].removingPercentEncoding ?? parts[1]
    }
    return fields
}

private actor IdentityConsent: ConsentProvider {
    private var approve: Bool
    private(set) var reasons: [String] = []
    /// Each touch's panel title, and the pid it was for.
    private(set) var panels: [(title: String, pid: pid_t)] = []
    /// Bare sheets asked for: never, now that every change takes the panel.
    private(set) var bareSheets = 0
    init(approve: Bool) { self.approve = approve }
    func set(approve: Bool) { self.approve = approve }

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        bareSheets += 1
        reasons.append(reason)
        return approve ? .approved(unlock: nil) : .denied
    }

    func authenticateSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> ConsentAnswer {
        panels.append((change.title, caller.pid))
        reasons.append(reason)
        return approve ? .approved(unlock: nil) : .refused(.unexplained)
    }
}

func machineIdentityCloudTests() async {
    machineIdentityAWSTargetValidationTests()
    machineIdentitySTSWireTests()
    await machineIdentityAWSProviderTests()
    await machineIdentityServiceTests()
    machineIdentityProtocolTests()
    await machineIdentityGrantRevocationTests()
    machineIdentityAWSSetupTests()
    machineIdentityGoogleSetupTests()
    await machineIdentityGoogleExchangeTests()
}

// MARK: - AWS targets

private func machineIdentityAWSTargetValidationTests() {
    func aws(role: String? = cloudTestRole, region: String? = "eu-west-2", lifetime: Int = 3_600) -> MachineIdentityTarget {
        MachineIdentityTarget(
            name: "admin", identity: "default", kind: .aws, audience: "sts.amazonaws.com",
            lifetime: lifetime, roleARN: role, region: region
        )
    }
    check(aws().validationError == nil, "an AWS target with a role ARN, region and an hour is valid")
    check(aws(role: nil).validationError == .invalidRoleARN, "an AWS target needs a role ARN")
    check(aws(role: "arn:aws:iam::123456789012:user/alex").validationError == .invalidRoleARN,
          "an AWS target refuses a user ARN")
    check(aws(role: "arn:aws:iam::12345:role/x").validationError == .invalidRoleARN,
          "an AWS target refuses an account id that is not 12 digits")
    check(aws(role: "arn:aws:iam::123456789012:role/a b").validationError == .invalidRoleARN,
          "an AWS target refuses a role name with a space")
    check(aws(region: nil).validationError == .invalidRegion, "an AWS target needs a region")
    check(aws(region: "Europe").validationError == .invalidRegion, "an AWS target refuses a malformed region")
    check(aws(lifetime: 1_799).validationError == .invalidDuration && aws(lifetime: 1_800).validationError == nil,
          "an AWS session is at least half an hour, so botocore's 15-minute refresh never runs csec on every call")
    check(aws(lifetime: 7_200).validationError == .invalidDuration, "an AWS session lasts at most an hour")
    check(MachineIdentityTarget(name: "t", identity: "default", audience: "aud", roleARN: cloudTestRole).validationError
            == .invalidRoleARN,
          "a token target takes no role ARN")
    check(AWSWebIdentity.isValidRoleARN("arn:aws-us-gov:iam::123456789012:role/path/to/name+x=y,z.@_-"),
          "a role ARN may name a partition and a path with IAM's own characters")
    check(AWSWebIdentity.roleName(ofRole: cloudTestRole) == "csec-admin"
            && AWSWebIdentity.accountID(ofRole: cloudTestRole) == "123456789012",
          "a role ARN's name and account are read from it")
    check(AWSWebIdentity.sessionName(forSubject: "alex's mac (m4)") == "alex-s-mac--m4-",
          "the STS session name keeps only the characters STS accepts")
    check(AWSWebIdentity.sessionName(forSubject: "x") == "csec-machine-identity",
          "a subject too short for a session name gets csec's own")
    check(AWSWebIdentity.sessionName(forSubject: String(repeating: "a", count: 100)).count == 64,
          "the STS session name is at most 64 characters")
}

private func machineIdentitySTSWireTests() {
    guard let request = try? AWSWebIdentity.request(
        roleARN: cloudTestRole, region: "eu-west-2", token: "aaa.b+b/b=.ccc", sessionName: "dev-mac", duration: 3_600
    ) else {
        check(false, "STS request builds")
        return
    }
    check(request.httpMethod == "POST" && request.url?.absoluteString == "https://sts.eu-west-2.amazonaws.com/",
          "STS exchange posts to the region's own endpoint")
    check(request.url?.query == nil, "STS exchange puts nothing (and no token) in the URL")
    check(request.value(forHTTPHeaderField: "Content-Type")?.hasPrefix("application/x-www-form-urlencoded") == true
            && request.value(forHTTPHeaderField: "Authorization") == nil,
          "STS exchange is an unsigned form post")
    let fields = formFields(request)
    check(fields["Action"] == "AssumeRoleWithWebIdentity" && fields["Version"] == "2011-06-15"
            && fields["RoleArn"] == cloudTestRole && fields["RoleSessionName"] == "dev-mac"
            && fields["DurationSeconds"] == "3600",
          "STS exchange names the action, role, session and duration")
    check(fields["WebIdentityToken"] == "aaa.b+b/b=.ccc",
          "STS exchange escapes + = and / in the token so STS reads it unchanged")
    check(AWSWebIdentity.endpoint(region: "cn-north-1")?.absoluteString == "https://sts.cn-north-1.amazonaws.com.cn/",
          "STS exchange uses the China partition's domain for a China region")

    let credentials = try? AWSWebIdentity.parse(stsSuccess(expiration: "2027-01-15T10:00:00Z"), status: 200)
    check(credentials?.accessKeyID == "ASIAEXAMPLEEXAMPLE01" && credentials?.secretAccessKey == "synthetic/secret+key="
            && credentials?.sessionToken == "synthetic-session-token"
            && credentials?.expiration == ISO8601DateFormatter().date(from: "2027-01-15T10:00:00Z"),
          "STS reply's credentials and expiry are read")
    check((try? AWSWebIdentity.parse(stsSuccess(expiration: "2027-01-15T10:00:00.123Z"), status: 200)) != nil,
          "STS reply's expiry may carry fractional seconds")
    do {
        _ = try AWSWebIdentity.parse(stsError("InvalidIdentityToken"), status: 400)
        check(false, "STS refusal is an error")
    } catch let error as AWSWebIdentityError {
        check(error == .refused(code: "InvalidIdentityToken", status: 400), "STS refusal reports its documented code")
        check(!error.message.contains("issuer.example.test") && error.message.contains("InvalidIdentityToken"),
              "STS refusal's message is csec's own, never STS's text")
    } catch {
        check(false, "STS refusal is an AWSWebIdentityError")
    }
    do {
        _ = try AWSWebIdentity.parse(stsError("<script>"), status: 403)
        check(false, "STS refusal with an unknown code is an error")
    } catch let error as AWSWebIdentityError {
        check(error == .refused(code: nil, status: 403), "STS refusal with an undocumented code reports none")
    } catch {
        check(false, "STS refusal with an unknown code is an AWSWebIdentityError")
    }
    check((try? AWSWebIdentity.parse(Data("not xml".utf8), status: 200)) == nil, "an unreadable STS reply is refused")
    check((try? AWSWebIdentity.parse(Data(count: AWSWebIdentity.maximumResponseBytes + 1), status: 200)) == nil,
          "an oversized STS reply is refused")
}

private func machineIdentityAWSProviderTests() async {
    let clock = MovableClock(Date(timeIntervalSince1970: 1_800_000_000))
    let catalog = MachineIdentityCatalog(store: nil, keys: cloudTestKeys, clock: { clock.read() })
    let expiry = ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: 1_800_003_600))
    let sts = ScriptedSTS(reply: (stsSuccess(expiration: expiry), 200))
    let provider = MachineIdentityProvider(catalog: catalog, exchange: { sts.send($0) }, clock: { clock.read() })
    do {
        try await catalog.createIdentity(name: "default", issuer: "https://issuer.example.test", subject: "dev-mac")
        try await catalog.addTarget(MachineIdentityTarget(
            name: "admin", identity: "default", kind: .aws, audience: "sts.amazonaws.com",
            lifetime: 3_600, roleARN: cloudTestRole, region: "eu-west-2"
        ))
        try await catalog.addTarget(MachineIdentityTarget(name: "vault", identity: "default", audience: "vault"))
    } catch {
        check(false, "AWS provider fixture (\(error))")
        return
    }
    let ref = try! SecretRef("csec-identity://default/admin")
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(provider)

    guard let value = try? await resolver.resolve(ref, unlock: nil),
          let bundle = String(data: value, encoding: .utf8) else {
        check(false, "an AWS sign-in resolves through SecretResolver")
        return
    }
    let fields = try? AWSCredentialProcess.fields(fromBundle: bundle)
    check(fields?[AWSCredentialProcess.accessKeyID] == "ASIAEXAMPLEEXAMPLE01"
            && fields?[AWSCredentialProcess.sessionToken] == "synthetic-session-token"
            && fields?[AWSCredentialProcess.expiration] == expiry,
          "an AWS sign-in resolves to the credential_process bundle csec creds aws --item serves")
    check(fields.flatMap { try? AWSCredentialProcess.render(fields: $0) } != nil,
          "the AWS sign-in bundle renders as credential_process output, with its expiry")
    check(!bundle.contains("eyJ"), "the AWS sign-in bundle carries credentials, never the token")

    let sent = formFields(sts.last)
    let keys = (try? await catalog.publicKeys(identity: "default")) ?? []
    let verified = sent["WebIdentityToken"].flatMap { try? MachineIdentityToken.verify($0, keys: keys) }
    check(verified?.audience == "sts.amazonaws.com" && verified?.subject == "dev-mac"
            && verified?.issuer == "https://issuer.example.test"
            && verified.map { $0.expiresAt - $0.issuedAt } == AWSWebIdentity.tokenLifetime,
          "csecd exchanges a 5-minute token for the target's audience, signed as this Mac")
    check(sent["RoleArn"] == cloudTestRole && sent["RoleSessionName"] == "dev-mac" && sent["DurationSeconds"] == "3600",
          "csecd asks STS for the target's role, for its duration, in this Mac's name")

    _ = try? await resolver.resolve(ref, unlock: nil)
    check(sts.count == 1, "csecd reuses AWS credentials it holds while more than 20 minutes remain")
    clock.advance(41 * 60)
    let later = ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: 1_800_002_460 + 3_600))
    sts.answer(with: (stsSuccess(expiration: later), 200))
    _ = try? await resolver.resolve(ref, unlock: nil)
    check(sts.count == 2,
          "csecd exchanges again once 20 minutes or less remain, before botocore's 15-minute refresh would loop")
    check(await resolver.resolveWithoutInteraction(ref) != nil,
          "an AWS sign-in resolves without interaction, so a paired project's auto mode can use it")

    sts.answer(with: (stsError("AccessDenied"), 403))
    clock.advance(60 * 60)
    do {
        _ = try await provider.resolve(ref, unlock: nil)
        check(false, "a refused AWS sign-in is an error")
    } catch let error as MachineIdentityProviderError {
        check(error.boundedReason.contains("AccessDenied") && error.boundedReason.contains("trust policy")
                && !error.boundedReason.contains("eyJ"),
              "a refused AWS sign-in names STS's code and the likely cause, never the token")
    } catch {
        check(false, "a refused AWS sign-in is a bounded provider error (\(error))")
    }

    let shouted = try! SecretRef("CSEC-IDENTITY://default/admin")
    check(MachineIdentityProvider.parse(shouted) == nil,
          "only the canonical lower-case spelling names a sign-in, so no second spelling escapes a revocation")
    if case .absent = await provider.presence(of: shouted) {
        check(true, "a non-canonical sign-in reference is refused as absent before any review")
    } else {
        check(false, "a non-canonical sign-in reference is refused as absent before any review")
    }
    check(await resolver.referencesWithExpiringValues([ref, try! SecretRef("csec://store/key")]) == [ref.uri],
          "a sign-in's values expire soon, so nothing may store them for later")

    let token = try? await resolver.resolve(try! SecretRef("csec-identity://default/vault"), unlock: nil)
    check(token.flatMap { String(data: $0, encoding: .utf8) }?.split(separator: ".").count == 3 && sts.count == 3,
          "a token target still resolves to the token itself, with no exchange")

    let review = await provider.reviewDescription(for: ref)
    check(review?.notes.contains { $0.contains("csec-admin") && $0.contains("123456789012") && $0.contains("dev-mac") } == true
            && review?.notes.contains { $0.contains("60 minutes") } == true,
          "an AWS sign-in's review names the role, account, this Mac's subject and how long the credentials last")
}

// MARK: - Management service

private func machineIdentityServiceTests() async {
    let consent = IdentityConsent(approve: true)
    let catalog = MachineIdentityCatalog(store: nil, keys: cloudTestKeys)
    let revoked = RevokedReferences()
    let published = PublishedIssuer()
    let service = MachineIdentityService(
        catalog: catalog, consent: consent, hardwareKeys: true, persistent: true,
        revokeReferences: { await revoked.add($0) },
        terminalInspection: .unavailable,
        fetch: { try await published.fetch($0) }
    )
    let caller = CallerInfo(pid: 4242, startTime: 42, description: "synthetic csec identity")

    func run(_ request: MachineIdentityRequest) async -> Response {
        await service.handle(request, caller: caller)
    }

    let empty = await run(MachineIdentityRequest(action: .status))
    check(empty.machineIdentity?.status?.identities.isEmpty == true && empty.machineIdentity?.status?.hardwareKeys == true,
          "identity status lists nothing before an identity is made")

    let badIssuer = await run(MachineIdentityRequest(action: .create, identity: "default", issuer: "http://x", subject: "dev-mac"))
    let noPrompt = await consent.reasons.isEmpty
    check(badIssuer.failure?.code == .invalidRequest && noPrompt,
          "identity create refuses a non-HTTPS issuer before asking for Touch ID")

    await consent.set(approve: false)
    let denied = await run(MachineIdentityRequest(
        action: .create, identity: "default", issuer: "https://issuer.example.test", subject: "dev-mac"
    ))
    let noIdentity = await catalog.snapshot.identities.isEmpty
    check(denied.failure?.code == .consentDenied && noIdentity,
          "identity create denied at Touch ID makes no key")
    let createReason = await consent.reasons.last ?? ""
    check(createReason.contains("Create the machine identity default") && createReason.contains("dev-mac"),
          "identity create's Touch ID says what it makes and who it signs in as")

    await consent.set(approve: true)
    let created = await run(MachineIdentityRequest(
        action: .create, identity: "default", issuer: "https://issuer.example.test", subject: "dev-mac"
    ))
    let summary = created.machineIdentity?.status?.identities.first
    check(summary?.name == "default" && summary?.subject == "dev-mac" && summary?.keys.count == 1,
          "identity create makes the identity with one key")
    if let encoded = try? JSONEncoder().encode(created), let text = String(data: encoded, encoding: .utf8) {
        check(!text.contains("handle"), "identity replies carry public keys, never a key handle")
    }

    let target = MachineIdentityTarget(
        name: "admin", identity: "default", kind: .aws, audience: "sts.amazonaws.com",
        lifetime: 3_600, roleARN: cloudTestRole, region: "eu-west-2"
    )
    let added = await run(MachineIdentityRequest(action: .addTarget, target: target))
    check(added.machineIdentity?.status?.targets == [target], "identity target add records the target")
    let addReason = await consent.reasons.last ?? ""
    check(addReason.contains("default/admin") && addReason.contains("csec-admin") && addReason.contains("123456789012"),
          "identity target add's Touch ID names the sign-in, role and account")
    let reasonsBefore = await consent.reasons.count
    let duplicate = await run(MachineIdentityRequest(action: .addTarget, target: target))
    let reasonsAfter = await consent.reasons.count
    check(duplicate.failure?.code == .invalidRequest && reasonsAfter == reasonsBefore,
          "identity target add refuses an existing name without a prompt")
    let invalid = await run(MachineIdentityRequest(action: .addTarget, target: MachineIdentityTarget(
        name: "bad", identity: "default", kind: .aws, audience: "sts.amazonaws.com", roleARN: "nope", region: "eu-west-2"
    )))
    check(invalid.failure?.message == MachineIdentityError.invalidRoleARN.message,
          "identity target add explains what is wrong with a target")

    let files = await run(MachineIdentityRequest(action: .publicFiles, identity: "default"))
    let discovery = files.machineIdentity?.discoveryDocument.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    let keySet = files.machineIdentity?.keySet.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    check(discovery?["issuer"] as? String == "https://issuer.example.test"
            && (keySet?["keys"] as? [[String: Any]])?.first?["kid"] as? String == summary?.keys.first?.kid,
          "identity public files are the issuer's discovery document and its key set")

    // The issuer check, against a scripted host.
    if let discoveryData = files.machineIdentity?.discoveryDocument, let keySetData = files.machineIdentity?.keySet {
        await published.serve(discovery: discoveryData, keySet: keySetData)
    }
    let clear = await run(MachineIdentityRequest(action: .check, identity: "default"))
    check(clear.machineIdentity?.issuerReport?.clear == true
            && clear.machineIdentity?.issuerReport?.compromiseSuspected == false,
          "identity check is clear when the issuer publishes exactly this Mac's key")
    check(await service.suspectedIssuerCompromises().isEmpty, "the daily issuer check is quiet for a clear issuer")
    let stranger = MachineIdentityJWK(publicKey: P256.Signing.PrivateKey().publicKey)
    if let own = summary?.keys.first, let tampered = try? MachineIdentityIssuer.keySet([own, stranger]),
       let discoveryData = files.machineIdentity?.discoveryDocument {
        await published.serve(discovery: discoveryData, keySet: tampered)
    }
    let flagged = await run(MachineIdentityRequest(action: .check, identity: "default"))
    check(flagged.machineIdentity?.issuerReport?.compromiseSuspected == true
            && flagged.machineIdentity?.issuerReport?.unexpectedKids == [stranger.kid],
          "identity check flags a published key this Mac never accepted")
    check(await service.suspectedIssuerCompromises().map(\.identity) == ["default"],
          "the daily issuer check reports an identity whose issuer publishes an unexpected key")
    let accepted = await run(MachineIdentityRequest(action: .acceptKeys, identity: "default", kids: [stranger.kid]))
    let acceptReason = await consent.reasons.last ?? ""
    check(accepted.machineIdentity?.status?.identities.first?.acceptedKids == [stranger.kid]
            && acceptReason.contains("Accept 1 other key"),
          "identity accept-key records the key after one Touch ID that says what it allows")
    let reChecked = await run(MachineIdentityRequest(action: .check, identity: "default"))
    check(reChecked.machineIdentity?.issuerReport?.clear == true, "an accepted key no longer flags the issuer")
    await published.fail()
    let unreachable = await run(MachineIdentityRequest(action: .check, identity: "default"))
    check(unreachable.machineIdentity?.issuerReport?.clear == false
            && unreachable.machineIdentity?.issuerReport?.compromiseSuspected == false,
          "an unreachable issuer is not clear, and not reported as a compromise")

    let reasonsBeforeRemove = await consent.reasons.count
    let removedTarget = await run(MachineIdentityRequest(action: .removeTarget, identity: "default", targetName: "admin"))
    let reasonsAfterRemove = await consent.reasons.count
    check(removedTarget.machineIdentity?.status?.targets.isEmpty == true && reasonsAfterRemove == reasonsBeforeRemove,
          "identity target remove takes access away with no prompt")
    let revokedOnce = await revoked.all
    check(revokedOnce == [["csec-identity://default/admin"]],
          "identity target remove revokes the grants for that sign-in")

    _ = await run(MachineIdentityRequest(action: .addTarget, target: target))
    await consent.set(approve: false)
    let keptIdentity = await run(MachineIdentityRequest(action: .remove, identity: "default"))
    let keptCount = await catalog.snapshot.identities.count
    check(keptIdentity.failure?.code == .consentDenied && keptCount == 1,
          "identity remove denied at Touch ID keeps the key")
    await consent.set(approve: true)
    let removed = await run(MachineIdentityRequest(action: .remove, identity: "default"))
    let lastRevoked = await revoked.all.last
    check(removed.machineIdentity?.status?.identities.isEmpty == true
            && lastRevoked == ["csec-identity://default/admin"],
          "identity remove destroys the identity and revokes its sign-ins' grants")
    let panels = await consent.panels
    let bareSheets = await consent.bareSheets
    check(panels.map(\.title) == [
            "Create a Machine Identity", "Create a Machine Identity", "Add a Machine Identity Sign-In",
            "Accept Published Keys", "Add a Machine Identity Sign-In", "Remove a Machine Identity",
            "Remove a Machine Identity",
          ] && panels.allSatisfy { $0.pid == caller.pid } && bareSheets == 0,
          "every identity change's Touch ID is csecd's settings panel for the csec that asked, never the bare sheet (csec-0.60)")
}

private actor RevokedReferences {
    private(set) var all: [Set<String>] = []
    func add(_ references: Set<String>) -> Int {
        all.append(references)
        return 0
    }
}

private actor PublishedIssuer {
    private var discovery = Data()
    private var keySet = Data()
    private var failing = false
    func serve(discovery: Data, keySet: Data) {
        self.discovery = discovery
        self.keySet = keySet
        failing = false
    }
    func fail() { failing = true }
    func fetch(_ url: URL) throws -> Data {
        if failing { throw MachineIdentityIssuerCheck.FetchError.status(503) }
        return url.path.hasSuffix("jwks.json") ? keySet : discovery
    }
}

private func machineIdentityProtocolTests() {
    let target = MachineIdentityTarget(name: "gcp", identity: "default", audience: "aud", lifetime: 900)
    let requests: [MachineIdentityRequest] = [
        MachineIdentityRequest(action: .status),
        MachineIdentityRequest(action: .create, identity: "default", issuer: "https://issuer.example.test", subject: "dev-mac"),
        MachineIdentityRequest(action: .addTarget, target: target),
        MachineIdentityRequest(action: .removeTarget, identity: "default", targetName: "gcp"),
        MachineIdentityRequest(action: .acceptKeys, identity: "default", kids: ["k1"]),
        MachineIdentityRequest(action: .check, identity: "default"),
        MachineIdentityRequest(action: .publicFiles, identity: "default"),
        MachineIdentityRequest(action: .remove, identity: "default"),
    ]
    for request in requests {
        let decoded = (try? JSONEncoder().encode(Request.configureMachineIdentity(request)))
            .flatMap { try? JSONDecoder().decode(Request.self, from: $0) }
        if case let .configureMachineIdentity(back)? = decoded {
            check(back.requestID == request.requestID && back.action == request.action && back.target == request.target,
                  "configure_machine_identity \(request.action.rawValue) round-trips the wire")
        } else {
            check(false, "configure_machine_identity \(request.action.rawValue) round-trips the wire")
        }
    }
    let malformed: [MachineIdentityRequest] = [
        MachineIdentityRequest(action: .status, identity: "default"),
        MachineIdentityRequest(action: .create, identity: "default", issuer: "https://x"),
        MachineIdentityRequest(action: .remove),
        MachineIdentityRequest(action: .acceptKeys, identity: "default", kids: []),
        MachineIdentityRequest(action: .check, identity: "Not/Valid"),
        MachineIdentityRequest(action: .addTarget, identity: "default", target: target),
    ]
    for request in malformed {
        let decoded = (try? JSONEncoder().encode(Request.configureMachineIdentity(request)))
            .flatMap { try? JSONDecoder().decode(Request.self, from: $0) }
        check(decoded == nil, "configure_machine_identity refuses a malformed \(request.action.rawValue) at decoding")
    }
    let reply = Response(requestID: "r", machineIdentity: MachineIdentityReply(revokedGrants: 2))
    let back = (try? JSONEncoder().encode(reply)).flatMap { try? JSONDecoder().decode(Response.self, from: $0) }
    check(back?.machineIdentity?.revokedGrants == 2, "the machine identity reply round-trips the wire")
}

private func machineIdentityGrantRevocationTests() async {
    let table = GrantTable()
    let identity = "csec-identity://default/admin"
    // Rooted at this live process, so adding one grant does not sweep another.
    let pid = getpid()
    let start = ProcessAncestry.startTime(of: pid) ?? 0
    await table.add(Grant(rootPID: pid, rootStartTime: start, references: [identity], reason: "a"))
    await table.add(Grant(rootPID: pid, rootStartTime: start, references: [identity, "csec://store/key"], reason: "b"))
    await table.add(Grant(rootPID: pid, rootStartTime: start, references: ["csec://store/key"], reason: "c"))
    let removed = await table.revoke(references: [identity])
    let left = await table.revoke(references: ["csec://store/key"])
    check(removed == 2 && left == 1, "revoking by reference drops every grant that covers it, and only those")
    check(await table.revoke(references: []) == 0, "revoking no references drops nothing")
}

// MARK: - Cloud setup

private func machineIdentityAWSSetupTests() {
    let target = MachineIdentityTarget(
        name: "admin", identity: "default", kind: .aws, audience: "sts.amazonaws.com",
        lifetime: 3_600, roleARN: cloudTestRole, region: "eu-west-2"
    )
    guard let setup = try? MachineIdentityAWSSetup(
        issuer: "https://macs.s3.eu-west-2.amazonaws.com", subject: "dev-mac", target: target
    ) else {
        check(false, "AWS setup accepts an AWS target")
        return
    }
    check((try? MachineIdentityAWSSetup(
        issuer: "https://x.test", subject: "s", target: MachineIdentityTarget(name: "t", identity: "default", audience: "a")
    )) == nil, "AWS setup refuses a token target")
    check(setup.providerARN == "arn:aws:iam::123456789012:oidc-provider/macs.s3.eu-west-2.amazonaws.com",
          "AWS setup names the IAM OIDC provider by the issuer's host")
    let policy = (try? setup.trustPolicy()).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    let statement = (policy?["Statement"] as? [[String: Any]])?.first
    let conditions = (statement?["Condition"] as? [String: Any])?["StringEquals"] as? [String: String]
    check(statement?["Action"] as? String == "sts:AssumeRoleWithWebIdentity"
            && (statement?["Principal"] as? [String: String])?["Federated"] == setup.providerARN,
          "AWS trust policy admits web-identity sign-ins from the issuer's provider")
    check(conditions == ["macs.s3.eu-west-2.amazonaws.com:aud": "sts.amazonaws.com",
                         "macs.s3.eu-west-2.amazonaws.com:sub": "dev-mac"],
          "AWS trust policy admits only this Mac's subject and the target's audience")
    let commands = setup.commands()
    check(commands.first == "aws iam create-open-id-connect-provider --url https://macs.s3.eu-west-2.amazonaws.com --client-id-list sts.amazonaws.com",
          "AWS setup creates the OIDC provider for the issuer and audience (IAM fetches the CA thumbprint itself)")
    check(commands.last == "aws iam create-role --role-name csec-admin --assume-role-policy-document file://trust-policy.json --path /dev/",
          "AWS setup creates the role at its path with the trust policy")

    let executable = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    let line = "\"\(executable)\" creds aws --item \"csec-identity://default/admin\""
    let existing = Data("[default]\nregion = us-east-1\n\n[profile other]\nregion = eu-west-1".utf8)
    if let result = try? setup.configuration(existing, profile: "admin", executable: executable),
       let text = String(data: result.data, encoding: .utf8) {
        check(result.changed && text.hasPrefix(String(decoding: existing, as: UTF8.self))
                && text.hasSuffix("\n\n[profile admin]\ncredential_process = \(line)\nregion = eu-west-2\n"),
              "AWS setup appends a profile whose credential_process asks csec for the sign-in, leaving the rest")
        let again = try? setup.configuration(result.data, profile: "admin", executable: executable)
        check(again?.changed == false && again?.data == result.data, "AWS setup run again changes nothing")
    } else {
        check(false, "AWS setup writes the profile")
    }
    check((try? setup.configuration(Data(), profile: "default", executable: executable))
            .map { String(decoding: $0.data, as: UTF8.self) } == "[default]\ncredential_process = \(line)\nregion = eu-west-2\n",
          "AWS setup can write the default profile into an empty config")
    do {
        _ = try setup.configuration(existing, profile: "other", executable: executable)
        check(false, "AWS setup refuses to rewrite a profile with settings of its own")
    } catch {
        check(error as? MachineIdentitySetupError == .profileExists("other"),
              "AWS setup refuses to rewrite a profile with settings of its own")
    }
    check((try? setup.configuration(Data(), profile: "a b", executable: executable)) == nil,
          "AWS setup refuses a profile name with a space")
    check((try? setup.configuration(Data(), profile: "x", executable: "relative/csec")) == nil,
          "AWS setup refuses a csec path that is not absolute")
}

private func machineIdentityGoogleSetupTests() {
    let audience = "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/macs/providers/dev-mac"
    let target = MachineIdentityTarget(name: "gcp", identity: "default", audience: audience)
    guard let setup = try? MachineIdentityGoogleSetup(issuer: "https://issuer.example.test", subject: "dev-mac", target: target) else {
        check(false, "Google setup reads the provider from the target's audience")
        return
    }
    check(setup.projectNumber == "123456789" && setup.pool == "macs" && setup.provider == "dev-mac",
          "Google setup reads the project number, pool and provider from the audience")
    let https = MachineIdentityTarget(name: "gcp", identity: "default", audience: "https:" + audience)
    check((try? MachineIdentityGoogleSetup(issuer: "https://i.test", subject: "s", target: https))?.audience == audience,
          "Google setup accepts the https:// form of the provider name and configures the // form")
    for bad in ["sts.amazonaws.com", "//iam.googleapis.com/projects/abc/locations/global/workloadIdentityPools/macs/providers/dev",
                "//iam.googleapis.com/projects/1/locations/eu/workloadIdentityPools/macs/providers/dev-mac",
                "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/MACS/providers/dev-mac"] {
        check((try? MachineIdentityGoogleSetup(
            issuer: "https://i.test", subject: "s", target: MachineIdentityTarget(name: "g", identity: "default", audience: bad)
        )) == nil, "Google setup refuses the audience \(bad.prefix(40))")
    }
    let executable = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
    let configuration = (try? setup.credentialConfiguration(executable: executable, serviceAccount: "deploy@proj.iam.gserviceaccount.com"))
        .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    let source = (configuration?["credential_source"] as? [String: Any])?["executable"] as? [String: Any]
    check(configuration?["type"] as? String == "external_account" && configuration?["audience"] as? String == audience
            && configuration?["subject_token_type"] as? String == "urn:ietf:params:oauth:token-type:jwt"
            && configuration?["token_url"] as? String == "https://sts.googleapis.com/v1/token",
          "Google credential file is an external account for the provider")
    check(source?["command"] as? String == "\(executable) creds google --item csec-identity://default/gcp"
            && source?["timeout_millis"] as? Int == 120_000 && source?["output_file"] == nil,
          "Google credential file runs csec creds google in bare words (Go splits on spaces), with time for a review and no output file for csec's token")
    check((try? setup.credentialConfiguration(executable: "/Applications/My Tools/csec", serviceAccount: nil)) == nil
            && (try? setup.credentialConfiguration(executable: "/x/\"csec", serviceAccount: nil)) == nil,
          "Google setup refuses a csec path that Go or shlex would split or read differently")
    check((configuration?["service_account_impersonation_url"] as? String)?.hasSuffix(
        "/serviceAccounts/deploy@proj.iam.gserviceaccount.com:generateAccessToken") == true,
          "Google credential file impersonates the service account it was given")
    check((try? setup.credentialConfiguration(executable: executable, serviceAccount: "not-an-account")) == nil,
          "Google setup refuses a malformed service account")
    let commands = setup.commands(serviceAccount: "deploy@proj.iam.gserviceaccount.com")
    check(commands.count == 3 && commands[1].contains("create-oidc ")
            && commands[1].contains("--issuer-uri=https://issuer.example.test")
            && commands[1].contains("--allowed-audiences=\(audience)")
            && commands[1].contains("--attribute-mapping=google.subject=assertion.sub")
            && commands[1].contains("--jwk-json-path=jwks.json"),
          "Google setup's provider uploads the key set and maps the subject")
    check(commands[2].contains("--member=principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/macs/subject/dev-mac")
            && commands[2].contains("roles/iam.workloadIdentityUser"),
          "Google setup lets only this Mac's subject impersonate the service account")
    check(commands[0].contains("'--display-name=csec machine identities'"),
          "printed commands quote a word with a space")
    let poolName = "projects/123456789/locations/global/workloadIdentityPools/macs"
    let keysCommand = setup.updateKeysCommand()
    check(commands[0].contains("workload-identity-pools create \(poolName) ")
            && commands[1].contains("create-oidc \(poolName)/providers/dev-mac ")
            && keysCommand.contains("update-oidc \(poolName)/providers/dev-mac ")
            && !(commands[0] + commands[1] + keysCommand).contains("--project"),
          "Google setup names the pool and provider by resource name: gcloud's iam commands refuse a project number in --project")
    let s3 = try? MachineIdentityS3Issuer(
        bucket: "macs-issuer", region: "eu-west-2", administratorARN: "arn:aws:iam::123456789012:role/publisher"
    )
    check(s3?.setupCommands().contains { $0.hasSuffix("--ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'") } == true,
          "S3 setup quotes the ownership rule, which zsh would glob and fish would brace-expand")
    check(MachineIdentityShell.quote("it's") == "'it'\\''s'" && MachineIdentityShell.quote("") == "''"
            && MachineIdentityShell.quote("a b\\c") == "'a b'\\\\'c'",
          "printed commands escape a quote or backslash outside the quotes, as bash, zsh and fish all read it")

    let reply = (try? GoogleExecutableCredential.render(token: "aaa.bbb.ccc"))
        .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    check(reply?["version"] as? Int == 1 && reply?["success"] as? Bool == true
            && reply?["token_type"] as? String == "urn:ietf:params:oauth:token-type:jwt"
            && reply?["id_token"] as? String == "aaa.bbb.ccc" && reply?["expiration_time"] == nil,
          "csec creds google prints google-auth's version 1 executable reply")
    check((try? GoogleExecutableCredential.render(token: "two words")) == nil,
          "csec creds google refuses a value that is not one token")
}
