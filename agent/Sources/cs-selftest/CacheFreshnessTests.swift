import ConvenientSecurity
import Foundation
import LocalAuthentication
import OnePasswordAdapter

/// A cacheable provider whose open session the test switches on and off,
/// standing in for 1Password with a bridge csecd already holds open. Its value
/// changes outside csec, as an edit in the 1Password app does.
actor OpenSessionProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["op"]
    private var value: String
    private var open: Bool
    private var openReadDelay: TimeInterval = 0
    private let changesOutsideCsec: Bool
    private var refuses = false
    private(set) var resolveCount = 0
    private(set) var openReadCount = 0

    init(value: String, open: Bool, changesOutsideCsec: Bool = false) {
        self.value = value
        self.open = open
        self.changesOutsideCsec = changesOutsideCsec
    }

    /// The provider's own app refusing, or not answering, its authorization.
    func refuseResolves(_ refusing: Bool) { refuses = refusing }
    nonisolated func valuesChangeOutsideCsec(_ ref: SecretRef) async -> Bool { changesOutsideCsec }

    func setValue(_ newValue: String) { value = newValue }
    func setOpen(_ isOpen: Bool) { open = isOpen }
    func delayOpenReads(by seconds: TimeInterval) { openReadDelay = seconds }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        resolveCount += 1
        if refuses { throw ProviderError.notAuthenticated }
        return ResolvedSecret(value: Data(value.utf8), cacheHint: .cacheable)
    }

    func resolveFromOpenSession(_ ref: SecretRef) async -> ResolvedSecret? {
        openReadCount += 1
        guard open else { return nil }
        // The value is read when the request reaches 1Password; a slow answer
        // carries what was current then.
        let read = value
        if openReadDelay > 0 {
            try? await Task.sleep(nanoseconds: UInt64(openReadDelay * 1_000_000_000))
        }
        return ResolvedSecret(value: Data(read.utf8), cacheHint: .cacheable)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private final class FreshnessClock: @unchecked Sendable {
    private let lock = NSLock()
    private var now = Date(timeIntervalSince1970: 1_700_000_000)
    func date() -> Date { lock.withLock { now } }
    func advance(_ seconds: TimeInterval) { lock.withLock { now = now.addingTimeInterval(seconds) } }
}

private func pause(_ seconds: TimeInterval) async {
    try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
}

/// csec-0.81: a value edited in the 1Password app, outside csec, must reach
/// the next release while csecd holds that account's session open, instead of
/// the cached copy of the old value; and the check must never open a session,
/// authorize or prompt when none is open.
func cacheFreshnessTests() async {
    print("\n# Cache freshness (values edited outside csec)")
    let unlock = CacheUnlock(LAContext())
    let uri = "op://Vault/Item/field"
    let ref = try! SecretRef(uri)

    // MARK: The resolver, against any provider with an open session

    do {
        let provider = OpenSessionProvider(value: "BEFORE", open: false)
        let keychain = FakeKeychainBackend()
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: keychain))
        await resolver.register(provider)

        check(try await resolver.resolve(ref, unlock: unlock) == Data("BEFORE".utf8),
              "freshness: the first release reads the provider")
        await provider.setValue("AFTER")
        check(try await resolver.resolve(ref, unlock: unlock) == Data("BEFORE".utf8),
              "freshness: with no open session the cached copy is served, as before")

        await provider.setOpen(true)
        check(try await resolver.resolve(ref, unlock: nil) == Data("AFTER".utf8),
              "freshness: with the session open, a value edited outside csec reaches the next release")
        check(await provider.resolveCount == 1,
              "freshness: the open-session read is the only provider contact, never an authorizing read")

        // The edited value replaced the cached copy in every tier: a restarted
        // csecd reading its biometric tier with the session closed gets it.
        await provider.setOpen(false)
        let restarted = SecretResolver(cache: KeychainSecretCache(backend: keychain))
        await restarted.register(provider)
        check(try await restarted.resolve(ref, unlock: unlock) == Data("AFTER".utf8),
              "freshness: the at-rest copy was rewritten with the edited value")

        await provider.setValue("DELEGATED")
        await provider.setOpen(true)
        check(await resolver.resolveForDelegation(ref).data == Data("DELEGATED".utf8),
              "freshness: a delegated release also serves the value as edited")
        check(await resolver.resolveWithoutInteraction(ref) == Data("DELEGATED".utf8),
              "freshness: and the warm tier now holds it")

        // A provider that cannot answer from an open session leaves the cache
        // serving exactly as before.
        await provider.setOpen(false)
        await provider.setValue("UNSEEN")
        check(await resolver.resolveForDelegation(ref).data == Data("DELEGATED".utf8),
              "freshness: with the session closed a delegated release gets the cached copy")
    } catch {
        check(false, "freshness: resolver checks threw (\(error))")
    }

    // Alex, csec-0.81.1: with no open session, a release approved at the Mac
    // asks the provider itself before the cached copy; nothing else does.
    do {
        let provider = OpenSessionProvider(value: "BEFORE", open: false, changesOutsideCsec: true)
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: FakeKeychainBackend()))
        await resolver.register(provider)
        _ = try await resolver.resolve(ref, unlock: unlock)
        await provider.setValue("AFTER")
        let inGrant = try await resolver.resolve(ref, unlock: nil)
        let inGrantCount = await provider.resolveCount
        check(inGrant == Data("BEFORE".utf8) && inGrantCount == 1,
              "re-check: a release nobody just approved (in-grant) gets the cached copy and asks nobody")
        let delegated = await resolver.resolveForDelegation(ref).data
        let delegatedCount = await provider.resolveCount
        check(delegated == Data("BEFORE".utf8) && delegatedCount == 1,
              "re-check: auto mode gets the cached copy and asks nobody")
        let approved = try await resolver.resolve(ref, unlock: unlock)
        let approvedCount = await provider.resolveCount
        check(approved == Data("AFTER".utf8) && approvedCount == 2,
              "re-check: a release approved at the Mac asks the provider and serves the edited value")
        check(try await resolver.resolve(ref, unlock: nil) == Data("AFTER".utf8),
              "re-check: and the cached copy now holds it")
        await provider.setValue("UNREACHABLE")
        await provider.refuseResolves(true)
        check(try await resolver.resolve(ref, unlock: unlock) == Data("AFTER".utf8),
              "re-check: a provider that cannot answer leaves the approved release served from the cache")
    } catch {
        check(false, "re-check: resolver checks threw (\(error))")
    }

    // A provider whose values change only through csec is never re-asked.
    do {
        let provider = OpenSessionProvider(value: "ONE", open: false)
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: FakeKeychainBackend()))
        await resolver.register(provider)
        _ = try await resolver.resolve(ref, unlock: unlock)
        _ = try await resolver.resolve(ref, unlock: unlock)
        check(await provider.resolveCount == 1,
              "re-check: only a provider whose values change outside csec is asked at approval")
    } catch {
        check(false, "re-check: unchanged-provider check threw (\(error))")
    }

    // A seed from the open session is neither served nor cached.
    do {
        let provider = OpenSessionProvider(value: "plain", open: false)
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: FakeKeychainBackend()))
        await resolver.register(provider)
        _ = try await resolver.resolve(ref, unlock: unlock)
        await provider.setValue("otpauth://totp/Example:a?secret=JBSWY3DPEHPK3PXP&issuer=Example")
        await provider.setOpen(true)
        check(try await resolver.resolve(ref, unlock: unlock) == Data("plain".utf8),
              "freshness: a seed read from the open session is never served or cached")
    } catch {
        check(false, "freshness: the seed check threw (\(error))")
    }

    // MARK: A slow open-session read never holds a release up

    do {
        let provider = OpenSessionProvider(value: "OLD", open: false)
        let resolver = SecretResolver(
            cache: KeychainSecretCache(backend: FakeKeychainBackend()), revalidationDeadline: 0.2
        )
        await resolver.register(provider)
        _ = try await resolver.resolve(ref, unlock: unlock)
        await provider.setValue("NEW")
        await provider.setOpen(true)
        await provider.delayOpenReads(by: 1)
        let started = Date()
        let served = try await resolver.resolve(ref, unlock: unlock)
        check(served == Data("OLD".utf8) && Date().timeIntervalSince(started) < 0.9,
              "freshness: past the deadline the cached copy is served at once")
        await provider.setOpen(false)
        await pause(1.3)
        check(try await resolver.resolve(ref, unlock: unlock) == Data("NEW".utf8),
              "freshness: the late read still finished and refreshed the cache for the next release")
        check(await provider.resolveCount == 1, "freshness: no authorizing read was needed for that")
    } catch {
        check(false, "freshness: the deadline checks threw (\(error))")
    }

    // An invalidation (csec edit wrote a newer value) while a slow read is in
    // flight: the late read must not write its older value over it.
    do {
        let provider = OpenSessionProvider(value: "V1", open: false)
        let resolver = SecretResolver(
            cache: KeychainSecretCache(backend: FakeKeychainBackend()), revalidationDeadline: 0.1
        )
        await resolver.register(provider)
        _ = try await resolver.resolve(ref, unlock: unlock)
        await provider.setValue("V2")
        await provider.setOpen(true)
        await provider.delayOpenReads(by: 0.6)
        _ = try await resolver.resolve(ref, unlock: unlock)
        await resolver.invalidate(references: [uri])
        await provider.setValue("V3")
        await provider.setOpen(false)
        await pause(0.9)
        check(try await resolver.resolve(ref, unlock: unlock) == Data("V3".utf8),
              "freshness: a read that began before an invalidation never writes over it")
    } catch {
        check(false, "freshness: the invalidation race threw (\(error))")
    }

    // MARK: The real 1Password provider over a fake bridge

    let configuration = OnePasswordConnectionConfiguration(
        keepaliveInterval: 4, sessionIdleWindow: 10, authenticationTimeout: 7
    )
    func provider(
        _ registry: FakeBackendRegistry, clock: FreshnessClock
    ) async -> OnePasswordProvider {
        let runner = FakeOnePasswordCommandRunner()
        await runner.setAccounts([("user-work", "acme.1password.eu")], vaults: [:])
        return OnePasswordProvider(
            cliPath: "/synthetic/op",
            configuration: configuration,
            makeBackend: registry.factory(),
            runCommand: { path, arguments, timeout in
                try await runner.run(path: path, arguments: arguments, timeout: timeout)
            },
            currentDate: { clock.date() }
        )
    }
    func registry() -> FakeBackendRegistry {
        FakeBackendRegistry { _ in
            FakeOnePasswordBackend(
                vaults: [OnePasswordVault(id: "vault-1", name: "Vault")],
                values: [uri: "dead-webhook"]
            )
        }
    }
    func calls(_ registry: FakeBackendRegistry) async -> [FakeOnePasswordBackend.Call] {
        await registry.backend("user-work")?.recordedCalls() ?? []
    }

    let clock = FreshnessClock()
    let keychain = FakeKeychainBackend()
    do {
        let bridges = registry()
        let onePassword = await provider(bridges, clock: clock)
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: keychain))
        await resolver.register(onePassword)

        check(try await resolver.resolve(ref, unlock: unlock) == Data("dead-webhook".utf8),
              "1Password freshness: the first release reads 1Password and caches the value")
        await bridges.backend("user-work")?.setValue("live-webhook", for: uri)
        check(try await resolver.resolve(ref, unlock: unlock) == Data("live-webhook".utf8),
              "1Password freshness: a field edited in the 1Password app reaches the next release")
        check(await calls(bridges) == [.resolve(uri), .resolveOpen(uri)],
              "1Password freshness: over the running bridge only, never a read that could restart it")
        check(bridges.createdAccounts() == ["user-work"],
              "1Password freshness: no second bridge, so no second authorization")

        // A lock or sleep suspends the keepalive: the session could only
        // re-authorize now, so 1Password is not asked.
        await onePassword.suspendKeepalive()
        await bridges.backend("user-work")?.setValue("edited-while-asleep", for: uri)
        let before = await calls(bridges).count
        check(try await resolver.resolve(ref, unlock: nil) == Data("live-webhook".utf8),
              "1Password freshness: while the keepalive is suspended an in-grant fetch gets the cached copy")
        check(await calls(bridges).count == before,
              "1Password freshness: and 1Password is not contacted")
        check(try await resolver.resolve(ref, unlock: unlock) == Data("edited-while-asleep".utf8),
              "1Password re-check: a release approved at the Mac asks 1Password and serves the edit")
        await bridges.backend("user-work")?.setValue("edited-after-wake", for: uri)
        check(try await resolver.resolve(ref, unlock: nil) == Data("edited-after-wake".utf8),
              "1Password re-check: that request resumed the keepalive, so the session confirms later releases")
    } catch {
        check(false, "1Password freshness: checks threw (\(error))")
    }

    // A session not proven within 1Password's idle window is not open.
    do {
        let bridges = registry()
        let onePassword = await provider(bridges, clock: clock)
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: FakeKeychainBackend()))
        await resolver.register(onePassword)
        _ = try await resolver.resolve(ref, unlock: unlock)
        await bridges.backend("user-work")?.setValue("edited", for: uri)
        clock.advance(11)
        let before = await calls(bridges).count
        check(try await resolver.resolve(ref, unlock: nil) == Data("dead-webhook".utf8),
              "1Password freshness: past the idle window an in-grant fetch gets the cached copy")
        check(await calls(bridges).count == before,
              "1Password freshness: and a session that may have lapsed is not asked")
        // The keepalive proves the session again, and the next release is fresh.
        await onePassword.keepaliveTick()
        check(try await resolver.resolve(ref, unlock: nil) == Data("edited".utf8),
              "1Password freshness: once the keepalive holds the session, the edit is served")
    } catch {
        check(false, "1Password freshness: idle-window checks threw (\(error))")
    }

    // A bridge that has exited is never restarted to revalidate.
    do {
        let bridges = registry()
        let onePassword = await provider(bridges, clock: clock)
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: FakeKeychainBackend()))
        await resolver.register(onePassword)
        _ = try await resolver.resolve(ref, unlock: unlock)
        await bridges.backend("user-work")?.setValue("edited", for: uri)
        await bridges.backend("user-work")?.stopRunning()
        check(try await resolver.resolve(ref, unlock: nil) == Data("dead-webhook".utf8),
              "1Password freshness: with the bridge gone an in-grant fetch gets the cached copy")
        check(await calls(bridges) == [.resolve(uri), .resolveOpen(uri)],
              "1Password freshness: and the bridge is not started again to ask")
    } catch {
        check(false, "1Password freshness: exited-bridge checks threw (\(error))")
    }

    // After a restart nothing is open, so the open-session read has nothing
    // to ask; a release approved at the Mac asks 1Password itself, which
    // here holds a different value from csecd's cached copy.
    do {
        let bridges = registry()
        let onePassword = await provider(bridges, clock: clock)
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: keychain))
        await resolver.register(onePassword)
        check(try await resolver.resolve(ref, unlock: unlock) == Data("dead-webhook".utf8),
              "1Password re-check: after a restart a release approved at the Mac asks 1Password, not the old copy")
        check(bridges.createdAccounts() == ["user-work"],
              "1Password re-check: by opening that account's session once")
    } catch {
        check(false, "1Password freshness: restart checks threw (\(error))")
    }
}
