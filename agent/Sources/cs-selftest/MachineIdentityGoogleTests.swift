import ConvenientSecurity
import CryptoKit
import Foundation

private let googleAudience = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/fixture-pool/providers/fixture-provider"
private let googleAccount = "fixture@fixture-project.iam.gserviceaccount.com"
private let googleNow = Date(timeIntervalSince1970: 1_800_000_000)
private let googleKeys = MachineIdentityKeyFactory(
    create: {
        let key = P256.Signing.PrivateKey()
        return (SoftwareIdentitySigner(key: key), key.rawRepresentation)
    },
    open: { SoftwareIdentitySigner(key: try P256.Signing.PrivateKey(rawRepresentation: $0)) }
)

private final class GoogleTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var now = googleNow
    func read() -> Date { lock.withLock { now } }
    func advance(_ seconds: TimeInterval) { lock.withLock { now += seconds } }
}

private actor GoogleExchangeFixture {
    let clock: GoogleTestClock
    var status = 200
    var requests: [URLRequest] = []
    init(clock: GoogleTestClock) { self.clock = clock }
    func setStatus(_ status: Int) { self.status = status }
    func send(_ request: URLRequest) throws -> (Data, Int) {
        requests.append(request)
        let fields: [String: Any]
        if status != 200 {
            fields = ["error": ["message": "FIXTURE-RESPONSE-MUST-NOT-BE-DIAGNOSTIC"]]
        } else if request.url?.host == "iamcredentials.googleapis.com" {
            fields = ["accessToken": "FIXTURE-IMPERSONATED", "expireTime": ISO8601DateFormatter().string(from: clock.read() + 3_600)]
        } else {
            fields = ["access_token": "FIXTURE-FEDERATED", "token_type": "Bearer",
                      "issued_token_type": GoogleWebIdentity.accessTokenType, "expires_in": 3_600]
        }
        return (try JSONSerialization.data(withJSONObject: fields), status)
    }
}

func machineIdentityGoogleExchangeTests() async {
    print("\n# Google access-token exchange and gcloud confinement")
    func target(account: String? = nil, audience: String = googleAudience) -> MachineIdentityTarget {
        MachineIdentityTarget(name: "gcloud", identity: "default", kind: .google, audience: audience,
                              lifetime: GoogleWebIdentity.lifetime, googleServiceAccount: account)
    }
    check(target().validationError == nil && target(account: googleAccount).validationError == nil,
          "Google access targets accept direct and pinned service-account federation")
    check(target(account: "x@other.test").validationError == .invalidGoogleTarget
            && target(audience: "https://unrelated.invalid/token").validationError == .invalidGoogleTarget,
          "Google targets refuse malformed accounts and arbitrary endpoints")
    check(MachineIdentityTarget(name: "gcloud", identity: "default", kind: .google, audience: googleAudience,
                               lifetime: 7_200).validationError == .invalidGoogleTarget,
          "Google access targets cannot extend the token beyond an hour")
    let legacy = Data(#"{"name":"old","identity":"default","kind":"token","audience":"vault","lifetime":900}"#.utf8)
    check((try? JSONDecoder().decode(MachineIdentityTarget.self, from: legacy))?.validationError == nil,
          "catalogs written before Google access targets still decode")
    let encoded = try! JSONEncoder().encode(target(account: googleAccount))
    check((try? JSONDecoder().decode(MachineIdentityTarget.self, from: encoded)) == target(account: googleAccount),
          "a Google target's service account survives catalog encoding")

    let direct = try! GoogleWebIdentity.request(audience: googleAudience, token: "fixture.jwt+value=")
    let body = try! JSONSerialization.jsonObject(with: direct.httpBody!) as! [String: String]
    check(direct.url?.absoluteString == MachineIdentityGoogleSetup.tokenURL && direct.url?.query == nil
            && direct.httpMethod == "POST" && direct.value(forHTTPHeaderField: "Authorization") == nil,
          "Google STS receives a POST to its fixed endpoint with no credentials in the URL")
    check(body["subject_token"] == "fixture.jwt+value=" && body["audience"] == googleAudience
            && body["scope"] == GoogleWebIdentity.scope && body["requested_token_type"] == GoogleWebIdentity.accessTokenType,
          "Google STS receives the exact assertion, provider and scope in its JSON body")
    let impersonation = try! GoogleWebIdentity.impersonationRequest(serviceAccount: googleAccount, token: "FIXTURE-FEDERATED")
    check(impersonation.url?.absoluteString == "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/\(googleAccount):generateAccessToken"
            && impersonation.value(forHTTPHeaderField: "Authorization") == "Bearer FIXTURE-FEDERATED",
          "impersonation sends the federated bearer only to the pinned Google service account")
    check((try? GoogleWebIdentity.impersonationRequest(serviceAccount: "x/../../other", token: "fixture")) == nil,
          "impersonation rejects path injection")

    func reply(_ updates: [String: Any] = [:]) -> Data {
        let fields: [String: Any] = ["access_token": "FIXTURE-FEDERATED", "token_type": "Bearer",
                                    "issued_token_type": GoogleWebIdentity.accessTokenType, "expires_in": 3_600]
        return try! JSONSerialization.data(withJSONObject: fields.merging(updates) { _, new in new })
    }
    check((try? GoogleWebIdentity.parse(reply(), status: 200, now: googleNow))?.expiration == googleNow + 3_600,
          "Google STS expiry bounds the in-memory token")
    for fields: [String: Any] in [["access_token": ""], ["access_token": "two words"], ["access_token": "line\nbreak"],
                                  ["expires_in": 0], ["expires_in": 3_601], ["expires_in": true], ["token_type": "Other"],
                                  ["issued_token_type": "other"], ["access_token": String(repeating: "x", count: 16_385)]] {
        check((try? GoogleWebIdentity.parse(reply(fields), status: 200, now: googleNow)) == nil,
              "Google rejects malformed token or expiry metadata")
    }
    check((try? GoogleWebIdentity.parse(Data(count: 65_537), status: 200, now: googleNow)) == nil,
          "Google rejects an oversized response")
    do {
        _ = try GoogleWebIdentity.parse(Data("FIXTURE-ERROR-BODY".utf8), status: 403, now: googleNow)
        check(false, "Google refuses an HTTP error")
    } catch let error as GoogleWebIdentityError {
        check(error == .refused(403) && !error.message.contains("FIXTURE"),
              "Google errors expose only csec-authored metadata, never provider bodies")
    } catch { check(false, "Google error has a bounded diagnostic") }

    let clock = GoogleTestClock()
    let fixture = GoogleExchangeFixture(clock: clock)
    let catalog = MachineIdentityCatalog(store: nil, keys: googleKeys, clock: { clock.read() })
    let resolver = SecretResolver(cache: NullSecretCache())
    let provider = MachineIdentityProvider(catalog: catalog, googleExchange: { try await fixture.send($0) }, clock: { clock.read() })
    await resolver.register(provider)
    let reference = try! SecretRef(target().reference)
    do {
        try await catalog.createIdentity(name: "default", issuer: "https://issuer.invalid", subject: "fixture-mac")
        try await catalog.addTarget(target())
        let first = try await resolver.resolve(reference, unlock: nil)
        _ = try await resolver.resolve(reference, unlock: nil)
        let requests = await fixture.requests
        check(first == Data("FIXTURE-FEDERATED".utf8) && requests.count == 1,
              "a direct Google sign-in resolves through SecretResolver and reuses its token only in csecd memory")
        let sent = try JSONSerialization.jsonObject(with: requests[0].httpBody!) as! [String: String]
        let keys = try await catalog.publicKeys(identity: "default")
        let claims = try MachineIdentityToken.verify(sent["subject_token"]!, keys: keys)
        check(claims.audience == googleAudience && claims.subject == "fixture-mac"
                && claims.expiresAt - claims.issuedAt == 300,
              "Google receives a verified assertion for the catalogued audience, valid only for the exchange")
        if case .noCache = try await provider.resolve(reference, unlock: nil).cacheHint {
            check(true, "Google access tokens explicitly bypass persistent resolver caches")
        } else { check(false, "Google access tokens explicitly bypass persistent resolver caches") }
        clock.advance(3_301)
        _ = try await resolver.resolve(reference, unlock: nil)
        check(await fixture.requests.count == 2, "an expiring Google token is exchanged again without expiring its grant")
        try await catalog.removeTarget(identity: "default", name: "gcloud")
        check((try? await resolver.resolve(reference, unlock: nil)) == nil,
              "a removed target cannot release its previously held Google token")
        try await catalog.addTarget(target(account: googleAccount))
        let impersonated = try await resolver.resolve(reference, unlock: nil)
        let impersonationCount = await fixture.requests.count
        check(impersonated == Data("FIXTURE-IMPERSONATED".utf8) && impersonationCount == 4,
              "a replacement target with an account performs STS and impersonation, never reusing direct credentials")
        let described = await provider.reviewDescription(for: reference)
        check(described?.notes.contains(where: { $0.contains(googleAccount) }) == true,
              "the ordinary access review and its phone mirror name the pinned service account")
        let restarted = MachineIdentityProvider(catalog: catalog, googleExchange: { try await fixture.send($0) }, clock: { clock.read() })
        _ = try await restarted.resolve(reference, unlock: nil)
        check(await fixture.requests.count == 6, "a provider restart retains no exchanged Google token")
        await fixture.setStatus(403)
        clock.advance(3_301)
        do {
            _ = try await restarted.resolve(reference, unlock: nil)
            check(false, "a failed refresh refuses the Google release")
        } catch let error as MachineIdentityProviderError {
            check(!error.boundedReason.contains("FIXTURE") && error.boundedReason.contains("403"),
                  "a failed Google refresh returns a value-free error instead of an expired token")
        }
    } catch { check(false, "Google exchange fixture completes (\(type(of: error)))") }

    for scheme in ["op", "csec"] {
        let ref = "\(scheme)://fixture/google/access-token"
        let plan = try? ExecPlanner.plan(environment: [:], explicit: [(GcloudCommand.tokenVariable, ref)], knownSchemes: [scheme])
        check(plan?.references == [ref], "gcloud's delivery accepts the canonical \(scheme) reference without backend assumptions")
    }
    for arguments in [["auth", "login"], ["auth", "print-access-token"], ["--impersonate-service-account=x", "projects", "list"],
                      ["--flags-file=x"], ["config", "set", "auth/credential_file_override", "x"], ["--access-token-file", "x"], ["--log-http"]] {
        check(!GcloudCommand.accepts(arguments), "gcloud refuses credential/export paths that can reintroduce persistence")
    }
    check(GcloudCommand.accepts(["projects", "list"]) && GcloudCommand.accepts(["storage", "ls"]),
          "gcloud accepts ordinary project and storage API commands")
    check(GcloudCommand.accepts(["projects", "describe", "", "--format=value(projectId)"])
            && !GcloudCommand.accepts(["--impersonate=other"]) && !GcloudCommand.accepts(["--flags=hidden"]),
          "gcloud preserves empty argv values and refuses abbreviated credential flags")
    let source = "/tmp/with spaces/gcloud.sh"
    let startup = try! GcloudCommand.shellStartup("# keep me\n", sourcePath: source)
    check(startup.hasPrefix("# keep me\n") && (try? GcloudCommand.shellStartup(startup, sourcePath: source)) == startup,
          "shell startup installation preserves existing content and is idempotent")
    check((try? GcloudCommand.shellStartup("# >>> csec gcloud >>>\n", sourcePath: source)) == nil,
          "an incomplete managed shell block is left for explicit repair")
}
