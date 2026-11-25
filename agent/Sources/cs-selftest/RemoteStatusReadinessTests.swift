import CryptoKit
import CSECRemoteApproval
import ConvenientSecurity
import Foundation

// `csec remote status` says whether the paired phone shows Claude Code hook
// and rule acknowledgements as one of shown, not shown, no phone status or not
// reported, in every state and across every boundary: csecd's facts, the
// wire, the client's decode, the lines and `--json`. Only a phone's own signed
// status, verified against the pinned phone, makes it shown; a field an older
// csecd leaves out is never read as a yes (csec-0.93).

func remoteStatusReadinessTests() async {
    print("\n# csec remote status: the phone's settings-review readiness, explicit at every boundary (csec-0.93)")
    remoteStatusReadinessWireTests()
    await remoteStatusReadinessDerivationTests()
    remoteStatusReadinessReportTests()
    await remoteStatusReadinessClientTests()
}

/// The status as csecd builds it and the launcher reads it: encoded as the
/// socket carries it and decoded by this client.
private func overTheWire(_ status: RemoteApprovalConfigurationStatus) -> RemoteApprovalConfigurationStatus? {
    guard let data = try? JSONEncoder().encode(status) else { return nil }
    return try? JSONDecoder().decode(RemoteApprovalConfigurationStatus.self, from: data)
}

/// What csecd answers a status request with (`wireRemoteApprovalStatus` in
/// AgentRuntime.swift), after the client has decoded it.
private func csecdStatus(_ manager: RemoteApprovalManager) async -> RemoteApprovalConfigurationStatus? {
    let status = await manager.status()
    let health = await manager.pairingHealth()
    return overTheWire(RemoteApprovalConfigurationStatus(status, health: health))
}

private func statusDocument(_ status: RemoteApprovalConfigurationStatus?) -> [String: Any]? {
    guard let status, let text = try? RemoteApprovalStatusReport.json(status) else { return nil }
    return (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any]
}

// MARK: - Wire

private func remoteStatusReadinessWireTests() {
    func decoded(_ json: String) -> RemoteApprovalConfigurationStatus? {
        try? JSONDecoder().decode(RemoteApprovalConfigurationStatus.self, from: Data(json.utf8))
    }
    // The bytes csec 9bb6691's csecd sends for a phone that shows settings
    // reviews: the Bool, and nothing else about them.
    let older = decoded("""
        {"state":"enabled","phoneName":"P","phoneKeyFingerprint":"0011223344556677","phoneConfirmed":true,
         "phoneProtocolVersion":3,"phoneStatusUpdatedAtMilliseconds":1790000000000,"phoneShowsSettingsReviews":true}
        """)
    check(older?.phoneSettingsReviews == .notReported && older?.macProtocolVersion == nil
            && older?.phoneShowsSettingsReviews == true,
          "remote status wire: an older csecd's answer, even one whose Bool says yes, reads as not reported")
    let silent = decoded(#"{"state":"enabled","phoneName":"P","phoneKeyFingerprint":"0011223344556677"}"#)
    check(silent?.phoneSettingsReviews == .notReported,
          "remote status wire: an answer with no readiness at all reads as not reported")
    let unknown = decoded(#"{"state":"enabled","phoneSettingsReviews":"shown_later","phoneShowsSettingsReviews":true}"#)
    let mistyped = decoded(#"{"state":"enabled","phoneSettingsReviews":true}"#)
    check(unknown?.phoneSettingsReviews == .notReported && mistyped?.phoneSettingsReviews == .notReported
            && unknown?.state == .enabled && mistyped?.state == .enabled,
          "remote status wire: a readiness this client does not know, or of the wrong type, reads as not "
            + "reported and leaves the rest of the answer readable")
    for value in RemoteApprovalPhoneSettingsReviews.allCases {
        let status = RemoteApprovalConfigurationStatus(state: .enabled, phoneSettingsReviews: value, macProtocolVersion: 3)
        let carried = overTheWire(status)
        check(carried?.phoneSettingsReviews == value && carried?.macProtocolVersion == 3,
              "remote status wire: \(value.rawValue) crosses the socket as itself")
    }
    let unreported = (try? JSONEncoder().encode(RemoteApprovalConfigurationStatus(state: .disabled)))
        .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    check(unreported.map { $0["phoneSettingsReviews"] == nil && $0["macProtocolVersion"] == nil
                              && $0["state"] as? String == "disabled" } == true,
          "remote status wire: not reported is the field's absence, so a status built without csecd's facts "
            + "encodes as an older csecd's does")
    let full = RemoteApprovalConfigurationStatus(
        state: .unavailable, phoneName: "P", phoneKeyFingerprint: "0011223344556677", cause: .keychainUnavailable,
        detail: .recordCorrupt, keychainStatus: -25_300, phoneConfirmed: false, phoneAppVersion: "1.0 (8)",
        phoneNotificationsAuthorized: false, phoneRequestAlerts: .pushRegistrationFailed, remoteUnlockEnrolled: false,
        phoneProtocolVersion: 2, phoneStatusUpdatedAtMilliseconds: 1_790_000_000_000, phoneShowsSettingsReviews: false,
        phoneSettingsReviews: .notShown, macProtocolVersion: 3
    )
    check(overTheWire(full) == full, "remote status wire: every field crosses the socket unchanged")
}

// MARK: - csecd's facts, from the pinned phone's signed status

private func remoteStatusReadinessDerivationTests() async {
    let mac = Int(RemoteApprovalProtocolV3.version)
    let phone = SyntheticPhone()
    let pairing = v3StoredPairing(phone: phone, macKey: P256.Signing.PrivateKey())
    let reported = currentTimeMilliseconds()

    func pairedManager(
        _ relay: V3MailboxRelay, record: StoredRemoteApprovalConfiguration? = nil
    ) async -> RemoteApprovalManager {
        let manager = v3Manager(store: V3MemoryConfigurationStore(record: record ?? pairing), relay: relay)
        await manager.prepare()
        return manager
    }

    do {
        // The phone confirmed this pairing and signed a status listing every
        // kind this build's app shows, settings among them.
        let relay = V3MailboxRelay()
        let confirmation = RemoteApprovalPairingConfirmation(
            macDeviceID: pairing.macDeviceID, macPublicKeyX963: pairing.macPublicKeyX963,
            phoneDeviceID: phone.deviceID,
            phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
            phoneAppVersion: "1.0 (8)", createdAtMilliseconds: reported
        )
        try await relay.publishPairingConfirmation(SignedRemoteApprovalPairingConfirmation(
            confirmation: confirmation,
            signatureDER: try phone.signingKey.signature(for: confirmation.signingData()).derRepresentation
        ))
        try await relay.publishPhoneStatus(settingsPhoneStatus(phone, kinds: settingsPhoneKinds, at: reported))
        let status = await csecdStatus(await pairedManager(relay))
        check(status?.state == .enabled && status?.phoneSettingsReviews == .shown
                && status?.phoneShowsSettingsReviews == true && status?.phoneConfirmed == true
                && status?.macProtocolVersion == mac && status?.phoneProtocolVersion == mac
                && status?.phoneStatusUpdatedAtMilliseconds == reported,
              "remote status facts: a confirmed phone whose signed status lists settings reviews reads as shown, "
                + "with both protocols and when it reported")
        let document = statusDocument(status)
        check(document?["phoneSettingsReviews"] as? String == "shown" && document?["phoneConfirmed"] as? Bool == true
                && document?["macProtocolVersion"] as? Int == mac && document?["phoneProtocolVersion"] as? Int == mac
                && document?["state"] as? String == "enabled" && document?["cause"] is NSNull,
              "remote status facts: --json says so from csecd's answer")
    } catch {
        check(false, "remote status facts: a phone that shows settings reviews (\(error))")
    }

    do {
        // An app that predates settings reviews signs a status without kinds.
        let relay = V3MailboxRelay()
        try await relay.publishPhoneStatus(settingsPhoneStatus(phone, kinds: nil, at: reported))
        let older = await csecdStatus(await pairedManager(relay))
        // One that lists kinds, but not settings.
        let others = V3MailboxRelay()
        try await others.publishPhoneStatus(settingsPhoneStatus(phone, kinds: ["access", "ssh", "sudo"], at: reported))
        let withoutSettings = await csecdStatus(await pairedManager(others))
        check(older?.phoneSettingsReviews == .notShown && older?.phoneShowsSettingsReviews == false
                && withoutSettings?.phoneSettingsReviews == .notShown && older?.phoneStatusUpdatedAtMilliseconds == reported,
              "remote status facts: a signed status that does not list settings reviews reads as not shown")
    } catch {
        check(false, "remote status facts: a phone that does not show settings reviews (\(error))")
    }

    do {
        // Nothing from the phone; then a status listing settings that some
        // other key signed, under the pinned phone's ID.
        let none = await csecdStatus(await pairedManager(V3MailboxRelay()))
        let relay = V3MailboxRelay()
        let impostor = SyntheticPhone(deviceID: phone.deviceID)
        try await relay.publishPhoneStatus(settingsPhoneStatus(impostor, kinds: settingsPhoneKinds, at: reported))
        let forged = await csecdStatus(await pairedManager(relay))
        check(none?.state == .enabled && none?.phoneSettingsReviews == .noPhoneStatus
                && none?.phoneShowsSettingsReviews == nil && none?.phoneStatusUpdatedAtMilliseconds == nil
                && none?.macProtocolVersion == mac,
              "remote status facts: a paired phone that has reported nothing reads as no phone status")
        check(forged?.phoneSettingsReviews == .noPhoneStatus && forged?.phoneProtocolVersion == nil,
              "remote status facts: a status the pinned phone did not sign is ignored, never read as shown")
    } catch {
        check(false, "remote status facts: no verified phone status (\(error))")
    }

    do {
        // A phone app on another remote-approval protocol that lists settings.
        let relay = V3MailboxRelay()
        let status = RemoteApprovalPhoneStatus(
            phoneDeviceID: phone.deviceID, appVersion: "0.9 (3)", protocolVersion: 2, notificationsAuthorized: true,
            requestAlerts: .ready, reviewKinds: settingsPhoneKinds, updatedAtMilliseconds: reported
        )
        try await relay.publishPhoneStatus(SignedRemoteApprovalPhoneStatus(
            status: status, signatureDER: try phone.signingKey.signature(for: status.signingData()).derRepresentation
        ))
        let mismatched = await csecdStatus(await pairedManager(relay))
        let document = statusDocument(mismatched)
        check(mismatched?.phoneProtocolVersion == 2 && mismatched?.macProtocolVersion == mac
                && document?["phoneProtocolVersion"] as? Int == 2 && document?["macProtocolVersion"] as? Int == mac,
              "remote status facts: a phone on another protocol is reported as such beside this Mac's, for the "
                + "reader to compare")
        let lines = mismatched.map { RemoteApprovalStatusReport.summary($0).lines } ?? []
        check(lines.contains { $0.contains("protocol v2") && $0.contains("this Mac v\(mac)") },
              "remote status facts: the lines still warn about the protocol mismatch")
    } catch {
        check(false, "remote status facts: a mismatched protocol (\(error))")
    }

    // No pairing, and a pairing record that cannot be used: no phone status,
    // said explicitly.
    let unpaired = v3Manager(store: V3MemoryConfigurationStore(), relay: V3MailboxRelay())
    await unpaired.prepare()
    let disabled = await csecdStatus(unpaired)
    let corrupt = v3Manager(store: V3MemoryConfigurationStore(raw: Data("not a record".utf8)), relay: V3MailboxRelay())
    await corrupt.prepare()
    let invalid = await csecdStatus(corrupt)
    check(disabled?.state == .disabled && disabled?.phoneSettingsReviews == .noPhoneStatus
            && disabled?.macProtocolVersion == mac,
          "remote status facts: with no phone paired csecd says there is no phone status")
    check(invalid?.state == .unavailable && invalid?.cause == .pairingInvalid
            && invalid?.phoneSettingsReviews == .noPhoneStatus && invalid?.macProtocolVersion == mac,
          "remote status facts: with an unusable pairing csecd says there is no phone status")
    for manager in [
        RemoteApprovalManagerStatus.disabled, .unsupportedBuild, .iCloudAccountUnavailable(.noAccount, phoneName: "P", phoneKeyFingerprint: "f"),
        .pairingInvalid(.macKeyMissing), .keychainUnavailable(status: -25_308),
    ] {
        let status = RemoteApprovalConfigurationStatus(manager, health: nil)
        check(status.phoneSettingsReviews == .noPhoneStatus && status.macProtocolVersion == mac,
              "remote status facts: \(status.state.rawValue)\(status.cause.map { " " + $0.rawValue } ?? "") reports no phone status "
                + "and this Mac's protocol")
    }
    // A phone fact csecd has only for an enabled pairing never leaks into another state.
    let shows = RemoteApprovalPairingHealth(
        confirmed: true, phoneAppVersion: "1.0 (8)", notificationsAuthorized: true, remoteUnlockEnrolled: true,
        phoneProtocolVersion: RemoteApprovalProtocolV3.version, phoneStatusUpdatedAtMilliseconds: reported,
        phoneShowsSettingsReviews: true
    )
    let unavailable = RemoteApprovalConfigurationStatus(.iCloudAccountUnavailable(.noAccount, phoneName: "P", phoneKeyFingerprint: "f"), health: shows)
    check(unavailable.phoneSettingsReviews == .noPhoneStatus,
          "remote status facts: an unavailable pairing is never reported as showing settings reviews")
}

// MARK: - The lines, the row and --json

private func remoteStatusReadinessReportTests() {
    typealias Report = RemoteApprovalStatusReport
    func status(
        _ readiness: RemoteApprovalPhoneSettingsReviews, shows: Bool? = nil, phone: Int? = 3, mac: Int? = 3
    ) -> RemoteApprovalConfigurationStatus {
        RemoteApprovalConfigurationStatus(
            state: .enabled, phoneName: "Alex’s iPhone", phoneKeyFingerprint: "0011223344556677", phoneConfirmed: true,
            phoneAppVersion: "1.0 (8)", phoneNotificationsAuthorized: true, phoneRequestAlerts: .ready,
            remoteUnlockEnrolled: true, phoneProtocolVersion: phone, phoneStatusUpdatedAtMilliseconds: 1_790_000_000_000,
            phoneShowsSettingsReviews: shows, phoneSettingsReviews: readiness, macProtocolVersion: mac
        )
    }
    func settingsLines(_ status: RemoteApprovalConfigurationStatus) -> [String] {
        Report.summary(status).lines.filter { $0.contains("hook and rule acknowledgements") }
    }
    let shown = settingsLines(status(.shown, shows: true))
    let notShown = settingsLines(status(.notShown, shows: false))
    let none = settingsLines(status(.noPhoneStatus))
    let unreported = settingsLines(status(.notReported, shows: true))
    check(shown.count == 1 && shown[0].contains("reported that it shows") && !shown[0].contains("stay on this Mac"),
          "remote status lines: a phone that shows hook acknowledgements says so")
    check(notShown == [
        "csec: the iPhone app has not reported that it shows Claude Code hook and rule "
            + "acknowledgements, so they stay on this Mac. An app that shows them reports it with "
            + "its next Face ID approval. For an App Store or TestFlight install, check for a phone app update there. "
            + "For a source build, run ./packaging/bin/build-and-install.sh --only-iphone from the matching checkout.",
    ], "remote status lines: an older phone app has a repair for each distribution")
    check(none.count == 1 && none[0].contains("no signed status") && none[0].contains("stay on this Mac"),
          "remote status lines: no phone status says the acknowledgements stay on this Mac")
    check(unreported.count == 1 && unreported[0].contains("did not say") && unreported[0].contains("Convenient Security package")
            && !unreported[0].contains("reported that it shows"),
          "remote status lines: an older csecd's silence is said as such, never as a yes, even beside its Bool")
    check(Set([shown, notShown, none, unreported].map { $0.joined() }).count == 4,
          "remote status lines: the four answers print four different lines")
    check(Report.summary(status(.notReported)).succeeded && Report.summary(status(.noPhoneStatus)).succeeded,
          "remote status lines: readiness never changes the command's exit status")

    func row(_ status: RemoteApprovalConfigurationStatus) -> StatusRow {
        Report.doctorRow(status, developmentEndpoint: false)
    }
    let shownRow = row(status(.shown, shows: true))
    check(shownRow.state == .ok && shownRow.value.contains("hook acknowledgements reach the iPhone"),
          "remote status row: the status row says the acknowledgements reach the phone")
    for (readiness, words) in [
        (RemoteApprovalPhoneSettingsReviews.notShown, "hook acknowledgements stay on this Mac"),
        (.noPhoneStatus, "hook acknowledgements stay on this Mac"),
        (.notReported, "csecd did not say whether hook acknowledgements reach the iPhone"),
    ] {
        let said = row(status(readiness))
        check(said.state == .ok && said.value.contains(words) && !said.value.contains("reach the iPhone;")
                && !Report.failsDoctor(status(readiness), developmentEndpoint: false),
              "remote status row: \(readiness.rawValue) is said (\(words)), as information that never fails doctor")
    }
    let unconfirmed = RemoteApprovalConfigurationStatus(
        state: .enabled, phoneName: "P", phoneKeyFingerprint: "0011223344556677", phoneConfirmed: false,
        phoneSettingsReviews: .shown, macProtocolVersion: 3
    )
    check(row(unconfirmed).state == .warn && row(unconfirmed).value.contains("waiting for the iPhone to confirm"),
          "remote status row: a phone that shows them still warns about what does need doing")

    // --json: one object, every field present, nothing that names the phone.
    let mismatched = status(.shown, shows: true, phone: 2)
    check((try? Report.json(mismatched)) == #"{"cause":null,"macProtocolVersion":3,"phoneConfirmed":true,"#
            + #""phoneProtocolVersion":2,"phoneSettingsReviews":"shown","phoneStatusUpdatedAtMilliseconds":1790000000000,"#
            + #""schema":1,"state":"enabled"}"#,
          "remote status --json: the document's exact bytes")
    check(Report.summary(mismatched).lines.contains { $0.contains("protocol v2 and this Mac v3") && $0.contains("App Store") },
          "remote status lines: the protocol line compares the phone with the protocol csecd reported")
    check((try? Report.json(RemoteApprovalConfigurationStatus(state: .disabled))) == #"{"cause":null,"#
            + #""macProtocolVersion":null,"phoneConfirmed":null,"phoneProtocolVersion":null,"#
            + #""phoneSettingsReviews":"not_reported","phoneStatusUpdatedAtMilliseconds":null,"schema":1,"state":"disabled"}"#,
          "remote status --json: what an older csecd did not say is null, and its readiness not_reported")
    let unavailable = RemoteApprovalConfigurationStatus(
        .iCloudAccountUnavailable(.noAccount, phoneName: "Alex’s iPhone", phoneKeyFingerprint: "0011223344556677")
    )
    let unavailableJSON = (try? Report.json(unavailable)) ?? ""
    check(unavailableJSON.contains(#""cause":"icloud_account_unavailable""#)
            && unavailableJSON.contains(#""phoneSettingsReviews":"no_phone_status""#)
            && unavailableJSON.contains(#""state":"unavailable""#),
          "remote status --json: an unavailable state names its cause and no phone status")
    let everything = RemoteApprovalConfigurationStatus(
        state: .enabled, phoneName: "Alex’s iPhone", phoneKeyFingerprint: "0011223344556677",
        cause: .keychainUnavailable, detail: .recordCorrupt, keychainStatus: -25_300, phoneConfirmed: true,
        phoneAppVersion: "1.0 (8)", phoneNotificationsAuthorized: true, phoneRequestAlerts: .ready,
        remoteUnlockEnrolled: true, phoneProtocolVersion: 3, phoneStatusUpdatedAtMilliseconds: 1,
        phoneShowsSettingsReviews: true, phoneSettingsReviews: .shown, macProtocolVersion: 3
    )
    let keys = (try? Report.json(everything))
        .flatMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any] }
        .map { Set($0.keys) }
    check(keys == ["schema", "state", "cause", "phoneConfirmed", "macProtocolVersion", "phoneProtocolVersion",
                   "phoneStatusUpdatedAtMilliseconds", "phoneSettingsReviews"]
            && (try? Report.json(everything)).map { !$0.contains("iPhone") && !$0.contains("0011223344556677")
                                                       && !$0.contains("1.0 (8)") } == true,
          "remote status --json: exactly the documented fields, and never the phone's name, key or app")
}

// MARK: - The launcher's client, over the socket

private func remoteStatusReadinessClientTests() async {
    let base = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("cs-rsr-\(UUID().uuidString.prefix(8))", isDirectory: true)
    do {
        try FileManager.default.createDirectory(
            atPath: base.path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    } catch {
        check(false, "remote status client: socket directory (\(error))")
        return
    }
    defer { try? FileManager.default.removeItem(at: base) }

    func serve(_ name: String, _ handle: @escaping @Sendable (RemoteApprovalConfigurationRequest) -> Response) -> String? {
        let path = base.appendingPathComponent("\(name).sock").path
        let server = SocketServer(path: path, clientTrustPolicy: .allowUnverifiedForTesting) { request, _ in
            guard case let .configureRemoteApproval(configure) = request, configure.action == .status else {
                return .failed(.invalidRequest, message: "unexpected request", requestID: nil)
            }
            return handle(configure)
        }
        Thread.detachNewThread { try? server.run() }
        for _ in 0..<400 where !FileManager.default.fileExists(atPath: path) { usleep(10_000) }
        return FileManager.default.fileExists(atPath: path) ? path : nil
    }
    func read(_ path: String) async -> Result<RemoteApprovalConfigurationStatus, Error> {
        await withCheckedContinuation { continuation in
            Thread.detachNewThread {
                continuation.resume(returning: Result {
                    try AgentClient(path: path, serverTrustPolicy: .allowUnverifiedForTesting).remoteApprovalStatus()
                })
            }
        }
    }

    let health = RemoteApprovalPairingHealth(
        confirmed: true, phoneAppVersion: "1.0 (8)", notificationsAuthorized: true, remoteUnlockEnrolled: true,
        phoneProtocolVersion: RemoteApprovalProtocolV3.version, phoneStatusUpdatedAtMilliseconds: 1_790_000_000_000,
        phoneShowsSettingsReviews: true
    )
    guard let current = serve("now", { configure in
              Response(requestID: configure.requestID, remoteApprovalStatus: RemoteApprovalConfigurationStatus(
                  .enabled(phoneName: "Alex’s iPhone", phoneKeyFingerprint: "0011223344556677"), health: health))
          }),
          let older = serve("old", { configure in
              // An older csecd: the Bool, and no readiness or protocol of its own.
              Response(requestID: configure.requestID, remoteApprovalStatus: RemoteApprovalConfigurationStatus(
                  state: .enabled, phoneName: "Alex’s iPhone", phoneKeyFingerprint: "0011223344556677",
                  phoneConfirmed: true, phoneProtocolVersion: 3, phoneShowsSettingsReviews: true))
          }),
          let empty = serve("empty", { configure in Response(requestID: configure.requestID) }),
          let refusing = serve("fail", { configure in
              .failed(.internalError, message: "status unavailable", requestID: configure.requestID)
          }) else {
        check(false, "remote status client: the sockets are listening")
        return
    }

    let now = await read(current)
    check((try? now.get())?.phoneSettingsReviews == .shown && (try? now.get())?.macProtocolVersion == 3,
          "remote status client: csecd's shown reaches the launcher as shown")
    let old = await read(older)
    check((try? old.get())?.phoneSettingsReviews == .notReported && (try? old.get())?.phoneShowsSettingsReviews == true,
          "remote status client: an older csecd's answer reaches the launcher as not reported")
    if case let .failure(error) = await read(empty) {
        let transport: Bool
        if case .transportFailed? = error as? AgentClient.ClientError { transport = true } else { transport = false }
        check(transport,
              "remote status client: an answer without a status is a transport failure, as before (\(error))")
    } else {
        check(false, "remote status client: an answer without a status is never read as a status")
    }
    if case .failure = await read(refusing) {
        check(true, "remote status client: csecd's failure stays a failure")
    } else {
        check(false, "remote status client: csecd's failure stays a failure")
    }
    if case .failure = await read(base.appendingPathComponent("absent.sock").path) {
        check(true, "remote status client: no csecd is a failure, never a status")
    } else {
        check(false, "remote status client: no csecd is a failure, never a status")
    }
}
