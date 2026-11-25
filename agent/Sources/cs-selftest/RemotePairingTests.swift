import CloudKit
import CryptoKit
import CSECRemoteApproval
import CSECRemoteApprovalCloudKit
import ConvenientSecurity
import Foundation
import LocalAuthentication
import Security
import CSECBuildIdentity

/// Pairing v2 as `csec remote enable` / `disable` carry it out: the phone-held
/// unlock factor enrolled under the same Touch ID, the phone's signed
/// confirmation and status, and nothing of the factor outliving the pairing.
func remotePairingTests() async {
    print("\n# Remote pairing (enrollment, confirmation, phone status; synthetic keys only)")
    await pairingEnrollsUnderOneTouch()
    await pairingEnrollmentFailureLeavesNothingPaired()
    await pairingEnrollmentWithoutPairingIsRemovedAtStart()
    await pairingReadinessWithoutReferences()
    await pairingThroughTheLauncher()
    pairingCommandParsesInTheShell()
    pairingAlertStateRecord()
    pairingAlertStateFromCloudKit()
    await pairingAlertStateReachesDoctor()
    pairingStatusLines()
    await pairingOfferSignatures()
    pairingOfferRecordName()
    await pairingOfferLifecycle()
    pairingOfferInstructions()
    await remotePairingFixTests()
}

/// Consent that approves with a local (unevaluated, synthetic) context, the
/// shape BiometricConsent returns after a real Touch ID.
private actor PairingConsent: ConsentProvider {
    private(set) var authentications = 0
    private(set) var reasons: [String] = []
    /// Each touch as csecd's settings panel would show it, and for whom.
    private(set) var panels: [(change: SettingsChangeReviewDetails, caller: CallerInfo)] = []
    /// Bare sheets asked for: never, now that pairing takes the panel.
    private(set) var bareSheets = 0

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        bareSheets += 1
        authentications += 1
        reasons.append(reason)
        return .approved(unlock: CacheUnlock(LAContext()))
    }

    func authenticateSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> ConsentAnswer {
        panels.append((change, caller))
        authentications += 1
        reasons.append(reason)
        return .approved(unlock: CacheUnlock(LAContext()))
    }
}

private actor BackfillSpy {
    private(set) var calls = 0
    private(set) var sawLocalUnlock = false

    func record(_ unlock: CacheUnlock) -> RemoteUnlockBackfillReport {
        calls += 1
        sawLocalUnlock = unlock.isLocal
        return RemoteUnlockBackfillReport(mirrored: 3, failed: 0)
    }
}

private func pairingManager(
    store: V3MemoryConfigurationStore,
    relay: V3MailboxRelay,
    consent: PairingConsent,
    remoteUnlock: RemoteUnlockStore?,
    backfill: BackfillSpy? = nil,
    log: @escaping @Sendable (String) -> Void = { _ in }
) -> RemoteApprovalManager {
    RemoteApprovalManager(
        store: store,
        relay: relay,
        consent: consent,
        cloudKitContainerIdentifier: CloudKitContainerForTests.identifier,
        accountStatus: { .available },
        macKeys: v3SoftwareMacKeys(),
        remoteUnlock: remoteUnlock,
        coverage: { references in
            RemoteUnlockCoverage(needsUnlock: [], coveredRemotely: [])
        },
        backfill: backfill.map { spy in { @Sendable unlock in await spy.record(unlock) } },
        // Cleanup that fails is retried within milliseconds here, not seconds.
        cleanup: RemoteApprovalCleanupQueue(schedule: RemoteApprovalRetrySchedule(
            initialNanoseconds: 5_000_000, maximumNanoseconds: 50_000_000
        )),
        log: log
    )
}

private enum CloudKitContainerForTests {
    static let identifier = CSECBuildIdentity.cloudKitContainer
}

private func signedConfirmation(
    for stored: StoredRemoteApprovalConfiguration,
    phone: SyntheticPhone,
    signer: P256.Signing.PrivateKey? = nil
) throws -> SignedRemoteApprovalPairingConfirmation {
    let confirmation = RemoteApprovalPairingConfirmation(
        macDeviceID: stored.macDeviceID,
        macPublicKeyX963: stored.macPublicKeyX963,
        phoneDeviceID: phone.deviceID,
        phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
        phoneAppVersion: "1.0 (7)",
        createdAtMilliseconds: currentTimeMilliseconds()
    )
    return SignedRemoteApprovalPairingConfirmation(
        confirmation: confirmation,
        signatureDER: try (signer ?? phone.signingKey).signature(for: confirmation.signingData()).derRepresentation
    )
}

private func signedStatus(
    phone: SyntheticPhone,
    notifications: Bool,
    requestAlerts: RemoteApprovalPhoneAlertState? = nil,
    signer: P256.Signing.PrivateKey? = nil
) throws -> SignedRemoteApprovalPhoneStatus {
    let status = RemoteApprovalPhoneStatus(
        phoneDeviceID: phone.deviceID,
        appVersion: "1.0 (7)",
        notificationsAuthorized: notifications,
        requestAlerts: requestAlerts,
        updatedAtMilliseconds: currentTimeMilliseconds()
    )
    return SignedRemoteApprovalPhoneStatus(
        status: status,
        signatureDER: try (signer ?? phone.signingKey).signature(for: status.signingData()).derRepresentation
    )
}

private func pairingEnrollsUnderOneTouch() async {
    let phone = SyntheticPhone()
    let stranger = P256.Signing.PrivateKey()
    let items = InMemoryRemoteUnlockItemBackend()
    let remoteUnlock = RemoteUnlockStore(backend: items, buildIdentity: "build-pairing")
    _ = await remoteUnlock.reconcileEpoch(previousRun: nil)
    let store = V3MemoryConfigurationStore()
    let relay = V3MailboxRelay()
    let consent = PairingConsent()
    let spy = BackfillSpy()
    let manager = pairingManager(
        store: store, relay: relay, consent: consent, remoteUnlock: remoteUnlock, backfill: spy
    )
    do {
        _ = try await manager.enable(phonePairingCode: try phone.pairingCode, caller: setupCaller)
    } catch {
        check(false, "pairing: enable succeeds for a vouched-for phone code (\(error))")
        return
    }
    guard let stored = await store.current() else {
        check(false, "pairing: enable stores the pairing")
        return
    }
    let touches = await consent.authentications
    let reason = await consent.reasons.first ?? ""
    check(touches == 1 && reason.contains("open csec's stored secrets"),
          "pairing: one Touch ID pairs the phone, and its prompt says the phone will open stored secrets")
    let pairPanel = await consent.panels.first
    let bareSheets = await consent.bareSheets
    check(pairPanel?.change.title == "Pair an iPhone for Remote Approval"
            && pairPanel?.change.changes.last == "Its Face ID will approve requests and open csec's stored secrets on this Mac"
            && pairPanel?.caller.pid == setupCaller.pid && bareSheets == 0,
          "pairing: the Touch ID is csecd's settings panel for the csec that asked, never the bare sheet (csec-0.60)")
    let enrollment = await remoteUnlock.enrollment()
    check(enrollment?.macDeviceID == stored.macDeviceID
            && enrollment?.phoneDeviceID == phone.deviceID
            && enrollment?.enrollment.phoneKeyAgreementPublicKey
                == phone.keyAgreementKey.publicKey.x963Representation,
          "pairing: the phone-held unlock factor is enrolled to exactly this pairing's key-agreement key")
    let backfills = await spy.calls
    let local = await spy.sawLocalUnlock
    check(backfills == 1 && local,
          "pairing: the existing stored items are sealed for the phone with the pairing's own local Touch ID")

    var health = await manager.pairingHealth()
    check(health?.confirmed == false && health?.remoteUnlockEnrolled == true,
          "pairing: until the phone confirms, the pairing reads as enrolled but unconfirmed")

    // A confirmation signed by anyone but the pinned phone is ignored.
    do {
        try await relay.publishPairingConfirmation(signedConfirmation(for: stored, phone: phone, signer: stranger))
    } catch {}
    health = await manager.pairingHealth()
    check(health?.confirmed == false, "pairing: a confirmation not signed by the pinned phone is ignored")

    do {
        try await relay.publishPairingConfirmation(signedConfirmation(for: stored, phone: phone))
        try await relay.publishPhoneStatus(signedStatus(phone: phone, notifications: false, signer: stranger))
    } catch {}
    health = await manager.pairingHealth()
    check(health?.confirmed == true, "pairing: the pinned phone's signed confirmation confirms the pairing")
    check(health?.phoneAppVersion == nil && health?.notificationsAuthorized == nil,
          "pairing: a phone status not signed by the pinned phone is ignored")

    do {
        try await relay.publishPhoneStatus(signedStatus(phone: phone, notifications: false))
    } catch {}
    health = await manager.pairingHealth()
    check(health?.phoneAppVersion == "1.0 (7)" && health?.notificationsAuthorized == false,
          "pairing: the pinned phone's signed status reports its app and notification state")

    let wire = RemoteApprovalConfigurationStatus(await manager.status(), health: health)
    let row = RemoteApprovalStatusReport.doctorRow(wire, developmentEndpoint: false)
    check(row.state == .warn && row.value.contains("notifications off"),
          "pairing: doctor warns when the phone cannot show approval alerts")

    // Disabling removes the factor with the pairing.
    do {
        try await manager.disable(caller: setupCaller)
    } catch {
        check(false, "pairing: disable succeeds (\(error))")
    }
    let unpairPanel = await consent.panels.last
    check(await consent.panels.count == 2 && unpairPanel?.change.title == "Turn Off iPhone Remote Approval"
            && unpairPanel?.change.changes.first?.hasPrefix("Unpair ") == true
            && unpairPanel?.change.changes.first?.contains("the paired iPhone") == false
            && unpairPanel?.caller.pid == setupCaller.pid,
          "pairing: unpairing is csecd's settings panel too, naming the pinned phone (csec-0.60)")
    let stillEnrolled = await remoteUnlock.isEnrolled()
    let removed = await store.current() == nil
    check(removed && !stillEnrolled,
          "pairing: disabling removes the phone-held unlock factor along with the pairing")
}

private func pairingEnrollmentFailureLeavesNothingPaired() async {
    let phone = SyntheticPhone()
    let items = InMemoryRemoteUnlockItemBackend()
    await items.failWrites(service: RemoteUnlockStore.service, status: errSecIO)
    let remoteUnlock = RemoteUnlockStore(backend: items, buildIdentity: "build-pairing")
    _ = await remoteUnlock.reconcileEpoch(previousRun: nil)
    let store = V3MemoryConfigurationStore()
    let manager = pairingManager(
        store: store, relay: V3MailboxRelay(), consent: PairingConsent(), remoteUnlock: remoteUnlock
    )
    var refused = false
    do {
        _ = try await manager.enable(phonePairingCode: try phone.pairingCode, caller: setupCaller)
    } catch RemoteApprovalManagerError.remoteUnlockUnavailable {
        refused = true
    } catch {}
    let stored = await store.current()
    let status = await manager.status()
    check(refused && stored == nil && status == .disabled,
          "pairing: when the unlock factor cannot be enrolled nothing is paired, rather than half a pairing")
}

private func pairingEnrollmentWithoutPairingIsRemovedAtStart() async {
    let phone = SyntheticPhone()
    let items = InMemoryRemoteUnlockItemBackend()
    let remoteUnlock = RemoteUnlockStore(backend: items, buildIdentity: "build-pairing")
    _ = await remoteUnlock.reconcileEpoch(previousRun: nil)
    do {
        _ = try await remoteUnlock.enroll(
            phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
            macDeviceID: UUID().uuidString.lowercased(),
            phoneDeviceID: phone.deviceID
        )
    } catch {
        check(false, "pairing: a synthetic enrollment is made for the start-up check (\(error))")
        return
    }
    let manager = pairingManager(
        store: V3MemoryConfigurationStore(), relay: V3MailboxRelay(), consent: PairingConsent(),
        remoteUnlock: remoteUnlock
    )
    await manager.prepare()
    let enrolled = await remoteUnlock.isEnrolled()
    check(!enrolled, "pairing: a remote-unlock enrollment left with no pairing is removed when csecd starts")
}

private func pairingReadinessWithoutReferences() async {
    let phone = SyntheticPhone()
    let macKey = P256.Signing.PrivateKey()
    let stored = StoredRemoteApprovalConfiguration(
        macDeviceID: UUID().uuidString.lowercased(),
        macDeviceName: "Mac",
        macSigningKeyRepresentation: macKey.rawRepresentation,
        macPublicKeyX963: macKey.publicKey.x963Representation,
        phoneDeviceID: phone.deviceID,
        phoneDeviceName: phone.name,
        phonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
        phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
        cloudKitContainerIdentifier: CloudKitContainerForTests.identifier
    )
    let paired = pairingManager(
        store: V3MemoryConfigurationStore(record: stored), relay: V3MailboxRelay(),
        consent: PairingConsent(), remoteUnlock: nil
    )
    await paired.prepare()
    let ready = await paired.remoteReadiness(for: [])
    check(ready == .ready(unlock: .notNeeded),
          "pairing: a review naming no reference (one sudo authentication) can reach a paired phone")
    let unpaired = pairingManager(
        store: V3MemoryConfigurationStore(), relay: V3MailboxRelay(),
        consent: PairingConsent(), remoteUnlock: nil
    )
    await unpaired.prepare()
    let notReady = await unpaired.remoteReadiness(for: [])
    check(notReady == .unavailable, "pairing: with no phone paired nothing is ready, references or not")
}

/// `csec remote enable` end to end below csecd's dispatch: the launcher's
/// `AgentClient` over a real socket to a real manager, so the Mac code the
/// person is shown is the one the manager minted, in the protocol's current
/// version.
private func pairingThroughTheLauncher() async {
    let phone = SyntheticPhone()
    let store = V3MemoryConfigurationStore()
    let remoteUnlock = RemoteUnlockStore(
        backend: InMemoryRemoteUnlockItemBackend(), buildIdentity: "build-launcher"
    )
    _ = await remoteUnlock.reconcileEpoch(previousRun: nil)
    let relay = V3MailboxRelay()
    let manager = pairingManager(
        store: store, relay: relay, consent: PairingConsent(), remoteUnlock: remoteUnlock
    )
    guard let base = pairingSocketDirectory("enable") else { return }
    defer { try? FileManager.default.removeItem(at: base) }
    let path = base.appendingPathComponent("agent.sock").path
    check(startPairingServer(at: path) { request in
        guard case let .configureRemoteApproval(configure) = request,
              configure.action == .enable,
              let code = configure.phonePairingCode else {
            return .failed(.invalidRequest, message: "unexpected request", requestID: nil)
        }
        do {
            let enabled = try await manager.enable(phonePairingCode: code, caller: setupCaller)
            return Response(
                requestID: configure.requestID,
                remoteApprovalStatus: RemoteApprovalConfigurationStatus(
                    state: .enabled, phoneConfirmed: false, remoteUnlockEnrolled: true
                ),
                remoteApprovalMacPairingCode: enabled.macPairingCode,
                remoteApprovalPairingOfferPublished: enabled.pairingOfferPublished
            )
        } catch {
            return .failed(.internalError, message: "\(error)", requestID: configure.requestID)
        }
    }, "pairing via launcher: the socket is listening")

    let phoneCode: String
    do {
        phoneCode = try phone.pairingCode
    } catch {
        check(false, "pairing via launcher: the synthetic phone code encodes (\(error))")
        return
    }
    let outcome = await pairingOffCooperativePool {
        Result { try AgentClient(path: path, serverTrustPolicy: .allowUnverifiedForTesting)
            .enableRemoteApproval(phonePairingCode: phoneCode) }
    }
    guard case let .success(result) = outcome else {
        if case let .failure(error) = outcome {
            check(false, "pairing via launcher: csec remote enable gets the Mac code back (\(error))")
        }
        return
    }
    let stored = await store.current()
    check(result.macPairingCode.hasPrefix(RemoteApprovalPairingCode.macPrefix)
            && result.macPairing.macDeviceID == stored?.macDeviceID
            && result.macPairing.macPublicKeyX963 == stored?.macPublicKeyX963,
          "pairing via launcher: csec remote enable returns the current-version Mac code naming the key the manager pinned")
    check((try? RemoteApprovalPairingCode.decodeMac(result.macPairingCode)) == result.macPairing,
          "pairing via launcher: the code shown decodes, as the phone will, to the pairing returned")
    let offered = try? await relay.pairingOffer(phoneDeviceID: phone.deviceID)?.verifiedMac(
        phoneDeviceID: phone.deviceID,
        phonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
        phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation
    )
    check(result.pairingOfferPublished && offered == result.macPairing,
          "pairing via launcher: csec remote enable reports the offer published, and the phone's offer verifies to the pairing the code names")

    // A csecd from another build that pairs and then answers with a code this
    // launcher cannot read: the person is told the pairing happened and why
    // the code is missing, not that the transport failed.
    guard let staleBase = pairingSocketDirectory("stale") else { return }
    defer { try? FileManager.default.removeItem(at: staleBase) }
    let stalePath = staleBase.appendingPathComponent("agent.sock").path
    check(startPairingServer(at: stalePath) { request in
        guard case let .configureRemoteApproval(configure) = request else {
            return .failed(.invalidRequest, message: "unexpected request", requestID: nil)
        }
        return Response(
            requestID: configure.requestID,
            remoteApprovalStatus: RemoteApprovalConfigurationStatus(state: .enabled),
            remoteApprovalMacPairingCode: "csec-mac-v1:e30"
        )
    }, "pairing via launcher: the other-build socket is listening")
    let stale = await pairingOffCooperativePool {
        Result { try AgentClient(path: stalePath, serverTrustPolicy: .allowUnverifiedForTesting)
            .enableRemoteApproval(phonePairingCode: phoneCode) }
    }
    if case let .failure(error) = stale {
        let message = error.localizedDescription
        check(message.contains("paired the phone") && message.contains("different builds")
                && !message.contains("transport"),
              "pairing via launcher: an unreadable Mac code says the phone was paired and the builds differ")
    } else {
        check(false, "pairing via launcher: an unreadable Mac code is not shown as a success")
    }
}

/// The command the phone copies reaches `csec` as exactly `remote enable
/// <code>` in the shells a Mac runs it in. A code holds no quote or
/// backslash, which is also what keeps fish's single quotes literal.
private func pairingCommandParsesInTheShell() {
    let code: String
    do {
        code = try SyntheticPhone().pairingCode
    } catch {
        check(false, "pairing command: the synthetic phone code encodes (\(error))")
        return
    }
    let command = RemoteApprovalPairingCode.enableCommand(phoneCode: code)
    check(!code.contains("'") && !code.contains("\\"),
          "pairing command: a phone code has nothing a single-quoted shell word would change")
    for shell in [["/bin/zsh", "-f"], ["/bin/bash", "--norc", "--noprofile"]] {
        let words = pairingShellWords(shell: shell, commandLine: command)
        check(words == ["remote", "enable", code],
              "pairing command: \(shell[0]) hands csec exactly remote enable and the whole code")
    }
}

/// The arguments a shell passes `csec` for one command line, with `csec`
/// bound to a function that prints them NUL-separated.
private func pairingShellWords(shell: [String], commandLine: String) -> [String]? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: shell[0])
    process.arguments = Array(shell.dropFirst())
        + ["-c", "csec() { printf '%s\\0' \"$@\"; }; eval \"$1\"", "shell", commandLine]
    process.environment = ["PATH": "/usr/bin:/bin"]
    let output = Pipe()
    process.standardOutput = output
    process.standardError = Pipe()
    process.standardInput = FileHandle.nullDevice
    do {
        try process.run()
    } catch {
        return nil
    }
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return nil }
    return data.split(separator: 0, omittingEmptySubsequences: false).dropLast()
        .map { String(decoding: $0, as: UTF8.self) }
}

/// A short directory under /tmp: a socket path must fit in `sun_path`.
private func pairingSocketDirectory(_ tag: String) -> URL? {
    let base = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("cs-pair-\(tag)-\(UUID().uuidString.prefix(8))", isDirectory: true)
    do {
        try FileManager.default.createDirectory(
            atPath: base.path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return base
    } catch {
        check(false, "pairing via launcher: socket directory setup threw (\(error))")
        return nil
    }
}

private func startPairingServer(
    at path: String,
    _ handle: @escaping @Sendable (Request) async -> Response
) -> Bool {
    let server = SocketServer(path: path, clientTrustPolicy: .allowUnverifiedForTesting) { request, _ in
        await handle(request)
    }
    Thread.detachNewThread { try? server.run() }
    for _ in 0..<400 where !FileManager.default.fileExists(atPath: path) { usleep(10_000) }
    return FileManager.default.fileExists(atPath: path)
}

/// The launcher's client blocks on its socket, so it runs on its own thread
/// and leaves the cooperative pool free for the server's handler.
private func pairingOffCooperativePool<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
    await withCheckedContinuation { continuation in
        Thread.detachNewThread { continuation.resume(returning: body()) }
    }
}

/// The phone status record with and without the alert state. The golden
/// bytes come from an encoder written independently of `CanonicalEncoder`
/// (length-prefixed UTF-8 strings, big-endian integers), so a record signed by
/// a phone app that predates the field is still verified byte for byte.
private func pairingAlertStateRecord() {
    let deviceID = "0b7c3a52-1111-4222-8333-444455556666"
    func status(_ alerts: RemoteApprovalPhoneAlertState?) -> RemoteApprovalPhoneStatus {
        RemoteApprovalPhoneStatus(
            phoneDeviceID: deviceID,
            appVersion: "1.0 (7)",
            notificationsAuthorized: true,
            requestAlerts: alerts,
            updatedAtMilliseconds: 1_790_000_000_000
        )
    }
    func hex(_ data: Data?) -> String? { data.map { $0.map { String(format: "%02x", $0) }.joined() } }
    let v1 = "00000024637365632e72656d6f74652d617070726f76616c2e70686f6e652d7374617475732e7631"
        + "00020000002430623763336135322d313131312d343232322d383333332d343434343535353536363636"
        + "00000007312e3020283729000301000001a0c4506c00"
    let v2 = "00000024637365632e72656d6f74652d617070726f76616c2e70686f6e652d7374617475732e7632"
        + "00020000002430623763336135322d313131312d343232322d383333332d343434343535353536363636"
        + "00000007312e30202837290003010002000001a0c4506c00"
    check(hex(try? status(nil).signingData()) == v1,
          "phone status: without an alert state it signs the original v1 bytes, so an older phone app's record still verifies")
    check(hex(try? status(.subscriptionRefused).signingData()) == v2,
          "phone status: with an alert state it signs under its own v2 domain, the state before the timestamp")

    let key = P256.Signing.PrivateKey()
    let publicKey = key.publicKey.x963Representation
    guard let data = try? status(.subscriptionRefused).signingData(),
          let signature = try? key.signature(for: data).derRepresentation else {
        check(false, "phone status: the v2 record signs")
        return
    }
    func verifies(_ candidate: RemoteApprovalPhoneStatus) -> Bool {
        (try? SignedRemoteApprovalPhoneStatus(status: candidate, signatureDER: signature)
            .verify(phoneDeviceID: deviceID, phonePublicKeyX963: publicKey)) != nil
    }
    check(verifies(status(.subscriptionRefused)), "phone status: a signed alert state verifies")
    check(!verifies(status(nil)),
          "phone status: dropping the alert state from a signed record breaks its signature")
    check(!verifies(status(.ready)),
          "phone status: changing the signed alert state breaks its signature")

    do {
        let decoder = JSONDecoder()
        let older = try decoder.decode(RemoteApprovalPhoneStatus.self, from: Data("""
            {"version":2,"phoneDeviceID":"\(deviceID)","appVersion":"1.0 (7)","protocolVersion":3,
             "notificationsAuthorized":true,"updatedAtMilliseconds":1790000000000}
            """.utf8))
        check(older == status(nil), "phone status: an older app's record, without the field, decodes with no alert state")
        let roundTrip = try decoder.decode(
            RemoteApprovalPhoneStatus.self, from: JSONEncoder().encode(status(.pushRegistrationFailed))
        )
        check(roundTrip == status(.pushRegistrationFailed), "phone status: the alert state crosses the relay intact")
    } catch {
        check(false, "phone status: records decode (\(error))")
    }
}

/// How a failed subscription save becomes the phone's alert state, and the
/// reason the phone shows for it.
private func pairingAlertStateFromCloudKit() {
    let message = "attempting to create a subscription in a production container"
    let refusal = CKError(.invalidArguments, userInfo: [NSLocalizedDescriptionKey: message])
    check(CloudKitRemoteApprovalRelay.alertState(afterSubscriptionFailure: refusal) == .subscriptionRefused,
          "alerts: Production refusing the subscription is a refusal no retry fixes")
    let partial = CKError(.partialFailure, userInfo: [
        CKPartialErrorsByItemIDKey: ["csec-approval-requests-v3": refusal] as [AnyHashable: Error],
    ])
    check(CloudKitRemoteApprovalRelay.alertState(afterSubscriptionFailure: partial) == .subscriptionRefused,
          "alerts: a partial failure is judged by the subscription's own error")
    let delays: [CKError.Code] = [
        .networkUnavailable, .networkFailure, .serverResponseLost, .serviceUnavailable,
        .requestRateLimited, .zoneBusy, .accountTemporarilyUnavailable,
    ]
    check(delays.allSatisfy {
        CloudKitRemoteApprovalRelay.alertState(afterSubscriptionFailure: CKError($0)) == nil
    }, "alerts: a network or throttling delay leaves the reported state as it was")

    let summary = CloudKitRemoteApprovalRelay.failureSummary(partial)
    check(summary == "CloudKit error 12: \(message)",
          "alerts: the reason shown is the code and Apple's message (\(summary))")
    let hostile = CloudKitRemoteApprovalRelay.failureSummary(CKError(.invalidArguments, userInfo: [
        NSLocalizedDescriptionKey: "line\nbreak \u{202E}reversed " + String(repeating: "x", count: 500),
    ]))
    check(!hostile.contains("\n") && !hostile.contains("\u{202E}") && hostile.count <= 230,
          "alerts: the reason is sanitized for display and bounded")
}

/// A phone that reports it is not alerted to requests makes `csec status`
/// and `csec doctor` say so; one that is, or has not said, reads as before.
private func pairingAlertStateReachesDoctor() async {
    let phone = SyntheticPhone()
    let remoteUnlock = RemoteUnlockStore(
        backend: InMemoryRemoteUnlockItemBackend(), buildIdentity: "build-alerts"
    )
    _ = await remoteUnlock.reconcileEpoch(previousRun: nil)
    let store = V3MemoryConfigurationStore()
    let relay = V3MailboxRelay()
    let manager = pairingManager(
        store: store, relay: relay, consent: PairingConsent(), remoteUnlock: remoteUnlock
    )
    do {
        _ = try await manager.enable(phonePairingCode: try phone.pairingCode, caller: setupCaller)
        guard let stored = await store.current() else {
            check(false, "alerts: enable stores the pairing")
            return
        }
        try await relay.publishPairingConfirmation(signedConfirmation(for: stored, phone: phone))
    } catch {
        check(false, "alerts: the phone pairs and confirms (\(error))")
        return
    }

    func report(_ alerts: RemoteApprovalPhoneAlertState?) async -> (StatusRow, [String], RemoteApprovalPhoneAlertState?) {
        do {
            try await relay.publishPhoneStatus(signedStatus(phone: phone, notifications: true, requestAlerts: alerts))
        } catch {
            check(false, "alerts: the phone status publishes (\(error))")
        }
        let health = await manager.pairingHealth()
        let wire = RemoteApprovalConfigurationStatus(await manager.status(), health: health)
        return (
            RemoteApprovalStatusReport.doctorRow(wire, developmentEndpoint: false),
            RemoteApprovalStatusReport.summary(wire).lines,
            health?.requestAlerts
        )
    }

    let (refusedRow, refusedLines, refusedHealth) = await report(.subscriptionRefused)
    check(refusedHealth == .subscriptionRefused, "alerts: the pinned phone's signed alert state reaches pairing health")
    check(refusedRow.state == .warn && refusedRow.value.contains("not alerted to requests"),
          "alerts: doctor warns when iCloud refused the phone's subscription (\(refusedRow.value))")
    check(refusedLines.contains { $0.contains("iCloud refused its notification subscription") },
          "alerts: csec remote status says why the phone is not alerted")

    let (pushRow, _, _) = await report(.pushRegistrationFailed)
    check(pushRow.state == .warn && pushRow.value.contains("push registration failed"),
          "alerts: doctor warns when the phone could not register for pushes")

    let (readyRow, readyLines, _) = await report(.ready)
    check(readyRow.state == .ok && !readyLines.contains { $0.contains("not alerted") },
          "alerts: a phone that is alerted reads as healthy")

    let (silentRow, _, silentHealth) = await report(nil)
    check(silentRow.state == .ok && silentHealth == nil,
          "alerts: a phone that has not reported its alerts is not warned about")

    do {
        let wire = RemoteApprovalConfigurationStatus(
            state: .enabled, phoneName: "P", phoneKeyFingerprint: "0011223344556677",
            phoneConfirmed: true, phoneRequestAlerts: .subscriptionRefused, remoteUnlockEnrolled: true
        )
        let decoded = try JSONDecoder().decode(
            RemoteApprovalConfigurationStatus.self, from: JSONEncoder().encode(wire)
        )
        check(decoded == wire, "alerts: the alert condition crosses the csecd wire intact")
        let future = try JSONDecoder().decode(RemoteApprovalConfigurationStatus.self, from: Data("""
            {"state":"enabled","phoneRequestAlerts":"a_condition_from_later"}
            """.utf8))
        check(future.state == .enabled && future.phoneRequestAlerts == nil,
              "alerts: a condition this client does not know reads as absent, not as a failed reply")
    } catch {
        check(false, "alerts: the wire status round-trips (\(error))")
    }
}

private func pairingStatusLines() {
    typealias Report = RemoteApprovalStatusReport
    let base = RemoteApprovalConfigurationStatus(
        state: .enabled, phoneName: "P", phoneKeyFingerprint: "0011223344556677",
        phoneConfirmed: true, phoneAppVersion: "1.0 (7)", phoneNotificationsAuthorized: true,
        remoteUnlockEnrolled: true
    )
    check(Report.doctorRow(base, developmentEndpoint: false).state == .ok,
          "pairing report: a confirmed, alert-capable, enrolled pairing is healthy")
    let unconfirmed = RemoteApprovalConfigurationStatus(
        state: .enabled, phoneName: "P", phoneKeyFingerprint: "0011223344556677",
        phoneConfirmed: false, remoteUnlockEnrolled: true
    )
    let unconfirmedLines = Report.summary(unconfirmed).lines
    check(Report.doctorRow(unconfirmed, developmentEndpoint: false).state == .warn
            && unconfirmedLines.contains {
                $0.contains("waiting for the iPhone to confirm") && $0.contains("accept this Mac")
                    && $0.contains("App Store") && $0.contains("--only-iphone")
            },
          "pairing report: an unconfirmed pairing says to accept it on the phone, or to update a phone app "
            + "from another csec version")
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let otherProtocol = RemoteApprovalConfigurationStatus(
        state: .enabled, phoneName: "P", phoneKeyFingerprint: "0011223344556677",
        phoneConfirmed: true, phoneAppVersion: "2.0 (9)", phoneNotificationsAuthorized: true,
        remoteUnlockEnrolled: true, phoneProtocolVersion: Int(RemoteApprovalProtocolV3.version) + 1,
        phoneStatusUpdatedAtMilliseconds: 1_800_000_000_000 - 3 * 86_400_000
    )
    let otherRow = Report.doctorRow(otherProtocol, developmentEndpoint: false)
    let otherLines = Report.summary(otherProtocol, now: now).lines
    check(otherRow.state == .warn && otherRow.value.contains("protocol")
            && otherLines.contains { $0.contains("protocol") && $0.contains("Convenient Security package") },
          "pairing report: a newer phone protocol warns and names the Mac update")
    check(otherLines.contains("csec: the iPhone last reported 3 days ago"),
          "pairing report: status says when the phone last reported, as information")
    let sameProtocol = RemoteApprovalConfigurationStatus(
        state: .enabled, phoneName: "P", phoneKeyFingerprint: "0011223344556677",
        phoneConfirmed: true, phoneAppVersion: "1.0 (7)", phoneNotificationsAuthorized: true,
        remoteUnlockEnrolled: true, phoneProtocolVersion: Int(RemoteApprovalProtocolV3.version),
        phoneStatusUpdatedAtMilliseconds: 1_800_000_000_000 - 30_000
    )
    check(Report.doctorRow(sameProtocol, developmentEndpoint: false).state == .ok
            && Report.summary(sameProtocol, now: now).lines.contains("csec: the iPhone last reported just now"),
          "pairing report: a phone app on this Mac's protocol is healthy, and its report age reads plainly")
    check(Report.age(sinceMilliseconds: 1_800_000_000_000 - 5 * 60_000, now: now) == "5 minutes ago"
            && Report.age(sinceMilliseconds: 1_800_000_000_000 - 3_600_000, now: now) == "60 minutes ago"
            && Report.age(sinceMilliseconds: 1_800_000_000_000 - 3 * 3_600_000, now: now) == "3 hours ago"
            && Report.age(sinceMilliseconds: 1_800_000_000_000 - 86_400_000 * 2, now: now) == "2 days ago",
          "pairing report: report ages read in minutes, hours or days")
    let unenrolled = RemoteApprovalConfigurationStatus(
        state: .enabled, phoneName: "P", phoneKeyFingerprint: "0011223344556677",
        phoneConfirmed: true, phoneNotificationsAuthorized: true, remoteUnlockEnrolled: false
    )
    check(Report.doctorRow(unenrolled, developmentEndpoint: false).state == .warn,
          "pairing report: a pairing without the phone-held unlock warns that stored secrets stay on the Mac")
    let older = RemoteApprovalConfigurationStatus(state: .enabled, phoneName: "P", phoneKeyFingerprint: "0011223344556677")
    check(Report.doctorRow(older, developmentEndpoint: false).state == .ok,
          "pairing report: a csecd that reports no pairing health still reads as on")
    let pairingInvalid = RemoteApprovalConfigurationStatus(state: .unavailable, cause: .pairingInvalid, detail: .outdated)
    check(Report.summary(pairingInvalid).lines.contains { $0.contains("csec-phone-v2") },
          "pairing report: re-pairing advice names the current phone code")
    do {
        let data = try JSONEncoder().encode(otherProtocol)
        let decoded = try JSONDecoder().decode(RemoteApprovalConfigurationStatus.self, from: data)
        check(decoded == otherProtocol, "pairing report: the pairing health crosses the csecd wire intact")
    } catch {
        check(false, "pairing report: the pairing health encodes (\(error))")
    }
}

// MARK: - Pairing offer

/// A key from fixed bytes, so an encoding can be pinned.
private func fixedSigningKey(_ byte: UInt8) -> P256.Signing.PrivateKey {
    // Any 32 bytes below the curve order make a valid scalar.
    try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32))
}

private func pairingOffer(
    to phone: SyntheticPhone,
    macKey: P256.Signing.PrivateKey,
    macDeviceID: String = UUID().uuidString,
    name: String = "Alex M4",
    createdAt: UInt64 = 1_790_000_000_000
) -> RemoteApprovalPairingOffer {
    RemoteApprovalPairingOffer(
        mac: RemoteApprovalMacPairing(
            macDeviceID: macDeviceID,
            macDeviceName: name,
            macPublicKeyX963: macKey.publicKey.x963Representation,
            cloudKitContainerIdentifier: CloudKitContainerForTests.identifier
        ),
        phoneDeviceID: phone.deviceID,
        phonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
        phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
        createdAtMilliseconds: createdAt
    )
}

private func offerError(_ body: () throws -> Void) -> RemoteApprovalValidationError? {
    do {
        try body()
        return nil
    } catch let error as RemoteApprovalValidationError {
        return error
    } catch {
        return nil
    }
}

/// The offer proves only that the holder of the offered key made it for this
/// phone: any other phone, phone key or key-agreement key, a renamed Mac, or
/// a key the signer does not hold is refused.
private func pairingOfferSignatures() async {
    let phone = SyntheticPhone()
    let macKey = P256.Signing.PrivateKey()
    let offer = pairingOffer(to: phone, macKey: macKey)
    let signed: SignedRemoteApprovalPairingOffer
    do {
        signed = try await .signed(offer, by: V3SoftwareSigner(key: macKey))
    } catch {
        check(false, "pairing offer: the Mac signs an offer of its own key (\(error))")
        return
    }
    let phoneKey = phone.signingKey.publicKey.x963Representation
    let phoneKeyAgreement = phone.keyAgreementKey.publicKey.x963Representation
    func verify(
        _ candidate: SignedRemoteApprovalPairingOffer,
        deviceID: String? = nil,
        signingKey: Data? = nil,
        keyAgreementKey: Data? = nil
    ) throws -> RemoteApprovalMacPairing {
        try candidate.verifiedMac(
            phoneDeviceID: deviceID ?? phone.deviceID,
            phonePublicKeyX963: signingKey ?? phoneKey,
            phoneKeyAgreementPublicKeyX963: keyAgreementKey ?? phoneKeyAgreement
        )
    }
    check((try? verify(signed)) == offer.mac,
          "pairing offer: an offer signed by the key it offers verifies for the phone it names and gives that Mac pairing")
    check((try? verify(signed, deviceID: phone.deviceID.uppercased())) == offer.mac,
          "pairing offer: the phone's ID matches in either case")
    let carried = (try? JSONEncoder().encode(signed))
        .flatMap { try? JSONDecoder().decode(SignedRemoteApprovalPairingOffer.self, from: $0) }
    check(carried == signed && (try? verify(signed)) == offer.mac,
          "pairing offer: it crosses the mailbox's JSON intact and still verifies")

    let other = SyntheticPhone()
    check(offerError { _ = try verify(signed, deviceID: other.deviceID) } == .wrongDevice,
          "pairing offer: another phone does not take an offer made to this one")
    check(offerError {
              _ = try verify(signed, signingKey: other.signingKey.publicKey.x963Representation)
          } == .wrongDevice,
          "pairing offer: a phone with this ID but another signing key does not take it")
    check(offerError {
              _ = try verify(signed, keyAgreementKey: other.keyAgreementKey.publicKey.x963Representation)
          } == .wrongDevice,
          "pairing offer: a phone whose key-agreement key the Mac did not enroll does not take it")

    let renamed = SignedRemoteApprovalPairingOffer(
        offer: pairingOffer(
            to: phone, macKey: macKey, macDeviceID: offer.mac.macDeviceID,
            name: "Trusted Mac", createdAt: offer.createdAtMilliseconds
        ),
        signatureDER: signed.signatureDER
    )
    check(offerError { _ = try verify(renamed) } == .invalidSignature,
          "pairing offer: a Mac renamed under the original signature is refused")

    let borrowed = P256.Signing.PrivateKey()
    let borrowedOffer = pairingOffer(to: phone, macKey: borrowed)
    var signerRefused = false
    do {
        _ = try await SignedRemoteApprovalPairingOffer.signed(borrowedOffer, by: V3SoftwareSigner(key: macKey))
    } catch RemoteApprovalValidationError.invalidPublicKey {
        signerRefused = true
    } catch {}
    check(signerRefused, "pairing offer: the Mac does not sign an offer of a key it does not hold")
    let forged = SignedRemoteApprovalPairingOffer(
        offer: borrowedOffer,
        signatureDER: (try? macKey.signature(for: borrowedOffer.signingData()).derRepresentation) ?? Data()
    )
    check(offerError { _ = try verify(forged) } == .invalidSignature,
          "pairing offer: an offer of someone else's key, signed by another key, is refused")

    // The bytes the phone and the Mac sign and verify, pinned: a phone app
    // and a csecd from different builds must agree on them.
    let goldenPhone = SyntheticPhone(
        deviceID: "00000000-0000-4000-8000-000000000002",
        signingKey: fixedSigningKey(2),
        keyAgreementKey: try! P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
    )
    let golden = pairingOffer(
        to: goldenPhone, macKey: fixedSigningKey(1),
        macDeviceID: "00000000-0000-4000-8000-000000000001", name: "Mac", createdAt: 1_790_000_000_000
    )
    check((try? golden.signingData())?.map { String(format: "%02x", $0) }.joined() == pairingOfferGoldenHex,
          "pairing offer: the signed encoding matches its golden vector")
}

private let pairingOfferGoldenHex = ""
    + "00000025637365632e72656d6f74652d617070726f76616c2e70616972696e67"
    + "2d6f666665722e7631000200020000002430303030303030302d303030302d34"
    + "3030302d383030302d303030303030303030303031000000034d616300000041"
    + "046ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca"
    + "163c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989cef71c14"
    + "4a0000002a69436c6f75642e636f6d2e616c65787370656c6c65722e636f6e76"
    + "656e69656e742d73656375726974790000002430303030303030302d30303030"
    + "2d343030302d383030302d30303030303030303030303200000020fe00ab0f34"
    + "1901f863a49160cf554588d6928282d531b799addc4123f45ce85a00000020d0"
    + "2c9e7062d4d70c142007e115a13cf40ebe70a48eb7134ddae48d1d8a9deccf00"
    + "0001a0c4506c00"

private func pairingOfferRecordName() {
    let id = "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9"
    check(RemoteApprovalMailboxName.pairingOffer(phoneDeviceID: id) == "pairing-offer-" + id
            && RemoteApprovalMailboxName.pairingOffer(phoneDeviceID: id.uppercased()) == "pairing-offer-" + id,
          "pairing offer: the record is named by the phone it is for, in canonical case")
    check(RemoteApprovalMailboxName.pairingOffer(phoneDeviceID: "") == nil
            && RemoteApprovalMailboxName.pairingOffer(phoneDeviceID: "not-a-uuid") == nil
            && RemoteApprovalMailboxName.pairingOffer(phoneDeviceID: String(repeating: "a", count: 300)) == nil,
          "pairing offer: no record name is formed from anything but a device ID")
}

/// `enable` offers the pairing to the phone it pinned; the offer goes once
/// the phone confirms, when the pairing is disabled, or when a pairing with
/// another phone replaces it; a new pairing with the same phone replaces it,
/// and when that new offer cannot be published the stale one is withdrawn.
private func pairingOfferLifecycle() async {
    let phone = SyntheticPhone()
    let store = V3MemoryConfigurationStore()
    let relay = V3MailboxRelay()
    let manager = pairingManager(store: store, relay: relay, consent: PairingConsent(), remoteUnlock: nil)
    func offeredMac(to target: SyntheticPhone) async -> RemoteApprovalMacPairing? {
        try? await relay.pairingOffer(phoneDeviceID: target.deviceID)?.verifiedMac(
            phoneDeviceID: target.deviceID,
            phonePublicKeyX963: target.signingKey.publicKey.x963Representation,
            phoneKeyAgreementPublicKeyX963: target.keyAgreementKey.publicKey.x963Representation
        )
    }

    let first: RemoteApprovalEnableResult
    do {
        first = try await manager.enable(phonePairingCode: try phone.pairingCode, caller: setupCaller)
    } catch {
        check(false, "pairing offer: enable succeeds (\(error))")
        return
    }
    let firstMac = try? RemoteApprovalPairingCode.decodeMac(first.macPairingCode)
    let offered = await offeredMac(to: phone)
    let pinned = await store.current()
    check(first.pairingOfferPublished && offered != nil && offered == firstMac
            && offered?.macDeviceID == pinned?.macDeviceID,
          "pairing offer: enable leaves the phone an offer of exactly the pairing its printed code names")

    // A confirmation that does not verify leaves the offer where it is.
    if let stored = await store.current() {
        try? await relay.publishPairingConfirmation(
            signedConfirmation(for: stored, phone: phone, signer: P256.Signing.PrivateKey())
        )
    }
    _ = await manager.pairingHealth()
    try? await Task.sleep(nanoseconds: 50_000_000)
    let stillOffered = await offeredMac(to: phone)
    check(stillOffered == firstMac,
          "pairing offer: a confirmation the pinned phone did not sign does not withdraw the offer")

    // A new pairing with the same phone replaces its offer.
    let second: RemoteApprovalEnableResult
    do {
        second = try await manager.enable(phonePairingCode: try phone.pairingCode, caller: setupCaller)
    } catch {
        check(false, "pairing offer: re-pairing the same phone succeeds (\(error))")
        return
    }
    let secondMac = try? RemoteApprovalPairingCode.decodeMac(second.macPairingCode)
    let reoffered = await offeredMac(to: phone)
    check(second.pairingOfferPublished && secondMac?.macDeviceID != firstMac?.macDeviceID
            && reoffered == secondMac,
          "pairing offer: pairing the same phone again replaces its offer with the new Mac key's")

    // The phone's confirmation withdraws it.
    if let stored = await store.current() {
        try? await relay.publishPairingConfirmation(signedConfirmation(for: stored, phone: phone))
    }
    let health = await manager.pairingHealth()
    let withdrawnOnConfirmation = await eventuallyTrue {
        (try? await relay.pairingOffer(phoneDeviceID: phone.deviceID)) == .some(nil)
    }
    check(health?.confirmed == true && withdrawnOnConfirmation,
          "pairing offer: once the phone's confirmation verifies, the offer is withdrawn")

    // Re-pairing the same phone when the new offer cannot be published: the
    // pairing still happens, says it was not offered, and an offer of the
    // replaced Mac key does not linger.
    _ = try? await manager.enable(phonePairingCode: try phone.pairingCode, caller: setupCaller)
    await relay.failOfferPublishes(true)
    let unpublished: RemoteApprovalEnableResult
    do {
        unpublished = try await manager.enable(phonePairingCode: try phone.pairingCode, caller: setupCaller)
    } catch {
        check(false, "pairing offer: pairing succeeds when the offer cannot be published (\(error))")
        return
    }
    await relay.failOfferPublishes(false)
    let staleWithdrawn = await eventuallyTrue {
        (try? await relay.pairingOffer(phoneDeviceID: phone.deviceID)) == .some(nil)
    }
    let repinned = await store.current()
    check(!unpublished.pairingOfferPublished
            && repinned?.macDeviceID
                == (try? RemoteApprovalPairingCode.decodeMac(unpublished.macPairingCode))?.macDeviceID
            && staleWithdrawn,
          "pairing offer: when the offer cannot be published the pairing still lands, says so, and the replaced Mac key's offer is withdrawn")

    // Pairing another phone withdraws the first phone's offer.
    _ = try? await manager.enable(phonePairingCode: try phone.pairingCode, caller: setupCaller)
    let replacement = SyntheticPhone()
    _ = try? await manager.enable(phonePairingCode: try replacement.pairingCode, caller: setupCaller)
    let movedOn = await eventuallyTrue {
        (try? await relay.pairingOffer(phoneDeviceID: phone.deviceID)) == .some(nil)
    }
    let replacementOffer = await offeredMac(to: replacement)
    check(movedOn && replacementOffer != nil,
          "pairing offer: pairing another phone withdraws the first phone's offer and offers the new one")

    // Disabling withdraws the offer, retried while the relay refuses it.
    await relay.failNextOfferWithdrawals(2)
    let attemptsBefore = await relay.offerWithdrawals.count
    do {
        try await manager.disable(caller: setupCaller)
    } catch {
        check(false, "pairing offer: disable succeeds (\(error))")
        return
    }
    let disabledWithdrawn = await eventuallyTrue {
        (try? await relay.pairingOffer(phoneDeviceID: replacement.deviceID)) == .some(nil)
    }
    let disableAttempts = await relay.offerWithdrawals.count - attemptsBefore
    check(disabledWithdrawn && disableAttempts >= 3,
          "pairing offer: disabling remote approval withdraws the offer, retried until the relay takes the delete "
            + "(\(disableAttempts) attempts)")
}

private func pairingOfferInstructions() {
    let key = P256.Signing.PrivateKey().publicKey.x963Representation
    let fingerprint = RemoteApprovalPairingCode.publicKeyFingerprint(key)
    let offered = RemoteApprovalStatusReport.enableInstructions(
        macPairingCode: "csec-mac-v2:abc", macPublicKeyX963: key, pairingOfferPublished: true
    )
    check(offered.first?.contains("now shows this Mac") == true
            && offered.contains { $0.contains(fingerprint) && $0.contains("same key") }
            && offered.last == "csec-mac-v2:abc",
          "pairing offer: enable says the iPhone shows this Mac, to accept only with the same key, and still prints the code")
    let manual = RemoteApprovalStatusReport.enableInstructions(
        macPairingCode: "csec-mac-v2:abc", macPublicKeyX963: key, pairingOfferPublished: false
    )
    check(manual.contains("csec-mac-v2:abc") && manual.contains { $0.contains(fingerprint) }
            && !manual.contains { $0.contains("now shows") },
          "pairing offer: without an offer, enable asks for the code to be pasted and shows the key")
}
