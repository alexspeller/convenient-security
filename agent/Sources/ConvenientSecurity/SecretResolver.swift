import CSECRemoteApproval
import Foundation

/// A reference that cannot resolve, and its owner's value-free reason.
public struct KnownAbsentReference: Sendable, Equatable {
    public let reference: SecretRef
    public let reason: String

    public init(reference: SecretRef, reason: String) {
        self.reference = reference
        self.reason = reason
    }

    /// "csec://harbor/RELAY_TOKEN: the requested key does not exist in the
    /// native store", display-safe on one line.
    public var summary: String { "\(reference.safeInlineURI): \(reason)" }
}

/// Dispatches a `SecretRef` to the provider that owns its scheme, with the
/// SE-gated cache layered above (provider-agnostic, keyed by the canonical URI).
public actor SecretResolver {
    private var providers: [String: SecretProvider] = [:]
    /// Schemes csecd serves whose provider could not start this run.
    private var unavailableSchemes: Set<String> = []
    private let cache: SecretCache
    /// How long a release waits for its provider's open session to confirm
    /// a value (`revalidated`) before serving the cached copy instead. A warm
    /// 1Password read takes about a second; one queued behind other requests
    /// takes longer, and is not worth holding the release for.
    private let revalidationDeadline: TimeInterval
    /// Bumped by every `invalidate`, so a revalidation that read before an
    /// invalidation (a `csec edit` writing a newer value) never writes what
    /// it read over it.
    private var invalidations: [String: UInt64] = [:]

    public init(cache: SecretCache, revalidationDeadline: TimeInterval = 3) {
        self.cache = cache
        self.revalidationDeadline = revalidationDeadline
    }

    public func register(_ provider: SecretProvider) {
        for scheme in provider.schemes {
            providers[scheme] = provider
        }
    }

    /// Mark `scheme` as one csecd serves whose provider could not start, so
    /// its references are never reported absent for want of a provider: the
    /// fault is the daemon's, not the reference's.
    public func registerUnavailable(scheme: String) {
        unavailableSchemes.insert(scheme.lowercased())
    }

    /// The URI schemes currently resolvable, sorted for a stable wire order.
    public func registeredSchemes() -> [String] {
        providers.keys.sorted()
    }

    /// How a review names `ref`: its provider's description made display-safe,
    /// or the whole reference when no provider claims or describes it. Never
    /// consults the cache: a description names the resolution the review is
    /// about to authorize (e.g. which 1Password account), not a value held.
    public func reviewSecret(for ref: SecretRef) async -> ReviewSecret {
        guard let target = await target(for: ref),
              let described = await target.provider.reviewDescription(for: target.reference) else {
            return ReviewDisplay.oneTimeCodeSecret(ReviewDisplay.undescribedSecret(ref), for: ref)
        }
        return ReviewDisplay.oneTimeCodeSecret(ReviewDisplay.displaySafe(described), for: ref)
    }

    /// The provider that serves `ref`, and the reference to ask it for: `ref`
    /// itself, except that a one-time code whose provider cannot make codes
    /// (`makesOneTimeCodes` false) is asked for as its seed reference, and
    /// `seedForCode` says csecd works the code out from what that returns.
    /// Every question about a reference goes through here, so a provider is
    /// never handed a code suffix it does not understand.
    private func target(for ref: SecretRef) async -> ProviderTarget? {
        guard let provider = providers[ref.scheme] else { return nil }
        guard let seed = ref.oneTimeCodeSeedReference, !(await provider.makesOneTimeCodes(ref)) else {
            return ProviderTarget(provider: provider, reference: ref, seedForCode: false)
        }
        return ProviderTarget(provider: provider, reference: seed, seedForCode: true)
    }

    private struct ProviderTarget {
        let provider: SecretProvider
        let reference: SecretRef
        let seedForCode: Bool
    }

    /// `reviewSecret(for:)` for each of `references`, keyed by URI.
    public func reviewSecrets(for references: [SecretRef]) async -> [String: ReviewSecret] {
        var secrets: [String: ReviewSecret] = [:]
        for reference in references where secrets[reference.uri] == nil {
            secrets[reference.uri] = await reviewSecret(for: reference)
        }
        return secrets
    }

    /// Reviewable credentials, one per group, each reference described by its
    /// provider. Use this everywhere a review is built so every consent
    /// surface names a secret the same way.
    public func reviewCredentials(
        for groups: [[SecretRef]]
    ) async -> [PolicyReviewCredential] {
        var credentials: [PolicyReviewCredential] = []
        for group in groups {
            credentials.append(await reviewCredential(for: group))
        }
        return credentials
    }

    /// One reviewable credential, each reference described by its provider.
    public func reviewCredential(for references: [SecretRef]) async -> PolicyReviewCredential {
        var described: [(reference: SecretRef, secret: ReviewSecret)] = []
        for reference in references {
            described.append((reference, await reviewSecret(for: reference)))
        }
        return PolicyReviewCredential(described: described)
    }

    /// Per-provider health lines for `csec status`, in stable scheme order.
    public func providerStatuses() async -> [ProviderStatusSummary] {
        var summaries: [ProviderStatusSummary] = []
        for scheme in providers.keys.sorted() {
            guard let provider = providers[scheme] else { continue }
            if let summary = await provider.statusSummary() {
                summaries.append(summary)
            }
        }
        return summaries
    }

    /// The references of `refs` that cannot resolve whatever a review decides,
    /// each with its owner's value-free reason, in request order. A reference
    /// the cache holds is never among them, since `resolve` serves the cache
    /// first; one of a scheme no provider claims always is, unless csecd
    /// serves that scheme and its provider could not start; any other is its
    /// provider's `presence(of:)` answer, its reason made display-safe and
    /// bounded as a resolution failure's is. Scheme-blind, warm-state only: it
    /// never prompts, never contacts a provider over the network, and reads
    /// no value out of a provider.
    public func referencesKnownAbsent(_ refs: [SecretRef]) async -> [KnownAbsentReference] {
        var absent: [KnownAbsentReference] = []
        var seen: Set<String> = []
        for ref in refs where seen.insert(ref.uri).inserted {
            // A code is never served from the cache, so an entry for one
            // (left by an older csecd) says nothing about whether it resolves.
            if !ref.isOneTimeCode, await cache.holds(ref.uri) { continue }
            guard let target = await target(for: ref) else {
                if unavailableSchemes.contains(ref.scheme) { continue }
                absent.append(KnownAbsentReference(
                    reference: ref, reason: "no provider is registered for its scheme"
                ))
                continue
            }
            if case let .absent(reason) = await target.provider.presence(of: target.reference) {
                absent.append(KnownAbsentReference(
                    reference: ref,
                    reason: ReviewDisplay.fitted(reason, maxBytes: 512)
                ))
            }
        }
        return absent
    }

    /// The references whose resolution with no `unlock` would need a fresh
    /// touch, as their owning providers report it. Never prompts. A reference
    /// of an unregistered scheme fails the same with or without an unlock, so
    /// it never needs one.
    public func referencesRequiringUnlock(_ refs: some Sequence<SecretRef>) async -> Set<String> {
        var cold: Set<String> = []
        for ref in Set(refs) {
            guard let target = await target(for: ref) else { continue }
            if await target.provider.requiresUnlockToResolve(target.reference) {
                cold.insert(ref.uri)
            }
        }
        return cold
    }

    public func requiresUnlock(_ refs: some Sequence<SecretRef>) async -> Bool {
        for ref in Set(refs) {
            guard let target = await target(for: ref) else { continue }
            if await target.provider.requiresUnlockToResolve(target.reference) { return true }
        }
        return false
    }

    /// Open everything `refs` need with one evaluated context: each cold cache
    /// entry is promoted into the warm tier, and each owning provider opens its
    /// own sealed state. Nothing here contacts a provider over the network, so
    /// a touch spent on a restore authorizes exactly the local reads the panel
    /// listed. Failures leave a reference cold, which `requiresUnlock` reports.
    /// A remote unlock works the same way through the remote-unlock mirrors.
    public func warm(_ refs: [SecretRef], unlock: CacheUnlock) async {
        let unique = Array(Set(refs)).sorted { $0.uri < $1.uri }
        for ref in unique where !ref.isOneTimeCode {
            _ = await cachedValue(for: ref.uri, unlock: unlock)
        }
        var byScheme: [String: [SecretRef]] = [:]
        for ref in unique {
            guard let target = await target(for: ref) else { continue }
            byScheme[ref.scheme, default: []].append(target.reference)
        }
        for scheme in byScheme.keys.sorted() {
            guard let provider = providers[scheme], let group = byScheme[scheme] else { continue }
            await provider.warm(group, unlock: unlock)
        }
    }

    /// Resolve `ref` with no interaction at all: a value csecd holds warm in
    /// memory, or else one its provider can serve from state it already holds
    /// open (`SecretProvider.resolveWithoutInteraction`). Never prompts, never
    /// reads the biometric cache tier, never contacts a provider over the
    /// network, and writes nothing. A delegated release resolves the
    /// references it is new to only this way; nil means csecd does not hold
    /// the value, and the request goes to a human.
    ///
    /// A one-time code is never held: each one is made for the request a
    /// person approved. A seed is never released, so it reads as not held.
    public func resolveWithoutInteraction(_ ref: SecretRef) async -> Data? {
        guard !ref.isOneTimeCode else { return nil }
        if let held = await cachedValue(for: ref.uri, unlock: nil) {
            return OneTimeCode.isSeed(held) ? nil : held
        }
        guard let provider = providers[ref.scheme],
              let value = await provider.resolveWithoutInteraction(ref)?.value else { return nil }
        return OneTimeCode.isSeed(value) ? nil : value
    }

    /// The references a restore's touch could reopen: each is one
    /// `resolveWithoutInteraction` cannot serve now (it resolves each to
    /// answer and keeps nothing: the values stay inside this actor and are
    /// dropped at once), and either its provider opens it with a touch's
    /// context (`requiresUnlockToResolve`) or the cache keeps its value at
    /// rest, where that context reads it back (`warm`). Anything else stays
    /// cold whatever the touch, such as a 1Password value csecd never cached
    /// or whose cache entry `invalidate_cached_references` deleted: it is not
    /// worth a restore panel, and a delegated request for it declines as not
    /// held. Never prompts and never reads a value at rest.
    public func referencesRestorable(_ refs: some Sequence<SecretRef>) async -> Set<String> {
        var restorable: Set<String> = []
        for ref in Set(refs) where await isRestorable(ref) {
            restorable.insert(ref.uri)
        }
        return restorable
    }

    /// A delegated release's value for a reference it is new to: one csecd
    /// holds warm, or else, when its provider needs no csec unlock to resolve
    /// it (`requiresUnlockToResolve` false: 1Password, say), fetched from that
    /// provider as a grant's covered reference is. That fetch may contact the
    /// provider, whose own app may ask once, but never raises a csec panel or
    /// reads the biometric cache tier. A reference whose provider needs csec's
    /// touch stays warm-only: nil means csecd does not hold it, and the
    /// restore panel or a human decides. A paired value was already approved
    /// for that project once, so a restart is no reason to ask again.
    public func resolveForDelegation(_ ref: SecretRef) async -> DelegatedValue {
        // Auto mode never releases a code: a person approves each one.
        guard !ref.isOneTimeCode else { return .notHeld(reason: Self.oneTimeCodeNeedsPerson) }
        if let fresh = await revalidated(ref) { return .value(fresh) }
        if let held = await resolveWithoutInteraction(ref) { return .value(held) }
        guard let provider = providers[ref.scheme], !(await provider.requiresUnlockToResolve(ref)) else {
            return .notHeld(reason: nil)
        }
        return await resolveWithoutCsecUnlock(ref)
    }

    /// Fetch now, while a person is at the Mac, each of `refs` that a
    /// delegated release would fetch from its provider (`resolveForDelegation`)
    /// and csecd does not hold: one whose provider needs no csec unlock and
    /// whose values are not made to expire soon. What arrives is cached as a
    /// release's value is, so a later delegated release finds it held and never
    /// asks the provider at an hour when nobody can answer the provider's own
    /// authorization. Each provider gets its references in one batch
    /// (`SecretProvider.fetchAhead`), so it can stop asking a source that
    /// refused. A value its provider marks not cacheable is dropped at once.
    /// One a delegated release can already serve (`resolveWithoutInteraction`:
    /// warm here, or held open by its provider, as a native store is once the
    /// restore's touch opened it) counts as held and is not fetched. The
    /// report's reasons count every failure, past the summary's bounded list.
    /// Scheme-blind; never raises a csec panel or reads the biometric tier.
    public func fetchAhead(_ refs: [SecretRef]) async -> FetchAheadReport {
        var seen: Set<String> = []
        var alreadyHeld = 0
        var schemes: [String] = []
        var byScheme: [String: [SecretRef]] = [:]
        for ref in refs where seen.insert(ref.uri).inserted && !ref.isOneTimeCode {
            guard let provider = providers[ref.scheme],
                  !(await provider.requiresUnlockToResolve(ref)),
                  !(await provider.valuesExpireSoon(ref)) else { continue }
            if await resolveWithoutInteraction(ref) != nil {
                alreadyHeld += 1
                continue
            }
            if byScheme[ref.scheme] == nil { schemes.append(ref.scheme) }
            byScheme[ref.scheme, default: []].append(ref)
        }
        var fetched = 0
        var failures: [FetchAheadSummary.Failure] = []
        for scheme in schemes {
            guard let provider = providers[scheme], let group = byScheme[scheme] else { continue }
            for result in await provider.fetchAhead(group) {
                let uri = result.reference.uri
                switch result.outcome {
                case let .fetched(resolved):
                    guard resolved.cacheHint == .cacheable else {
                        failures.append(.init(reference: uri, reason: "its provider does not let csecd keep the value"))
                        continue
                    }
                    guard !OneTimeCode.isSeed(resolved.value) else {
                        failures.append(.init(reference: uri, reason: OneTimeCodeError.seedRefused.boundedReason))
                        continue
                    }
                    do {
                        try await cache.put(uri, value: resolved.value)
                    } catch {
                        logCache("write", error)
                    }
                    // The warm tier is written before the at-rest one, so a
                    // failed keychain write can still leave the value held.
                    if await cachedValue(for: uri, unlock: nil) != nil {
                        fetched += 1
                    } else {
                        failures.append(.init(reference: uri, reason: "csecd could not keep the value"))
                    }
                case let .failed(reason):
                    failures.append(.init(reference: uri, reason: reason ?? "its provider gave no reason"))
                }
            }
        }
        return FetchAheadReport(
            summary: FetchAheadSummary(fetched: fetched, alreadyHeld: alreadyHeld, failures: failures),
            failures: failures
        )
    }

    /// A person has just approved a csec panel at this Mac, and the request
    /// it approved is about to resolve: every provider hears it
    /// (`SecretProvider.personApprovedAtMac`), so a source that refused may be
    /// asked once more now that someone is there to answer. Scheme-blind.
    public func personApprovedAtMac() async {
        // A provider serving several schemes hears it once per scheme, which
        // it takes as once.
        for provider in providers.values {
            await provider.personApprovedAtMac()
        }
    }

    /// `ref` from its provider with no csec unlock, as a grant's covered
    /// reference is: the value, or why the provider could not serve it.
    public func resolveWithoutCsecUnlock(_ ref: SecretRef) async -> DelegatedValue {
        do {
            return .value(try await resolve(ref, unlock: nil))
        } catch {
            return .notHeld(reason: Self.boundedReason(error))
        }
    }

    /// A provider's own value-free sentence for why it failed, when it has
    /// one (`ProviderDiagnosableError`): never the error's description, which
    /// can carry a tool's stderr.
    static func boundedReason(_ error: any Error) -> String? {
        (error as? any ProviderDiagnosableError)?.boundedReason
    }

    /// The references whose provider resolves them with no csec unlock, so a
    /// delegated release fetches them itself (`resolveForDelegation`) and a
    /// restore panel need not reopen them for auto mode. Never prompts.
    public func referencesResolvableWithoutUnlock(_ refs: some Sequence<SecretRef>) async -> Set<String> {
        var resolvable: Set<String> = []
        for ref in Set(refs) {
            guard let target = await target(for: ref),
                  !(await target.provider.requiresUnlockToResolve(target.reference)) else { continue }
            resolvable.insert(ref.uri)
        }
        return resolvable
    }

    /// The references `resolveWithoutInteraction` cannot serve now: what a
    /// restore that meant to reopen them left cold. Never prompts; each value
    /// read to answer stays inside this actor and is dropped at once.
    public func referencesNotHeld(_ refs: some Sequence<SecretRef>) async -> Set<String> {
        var notHeld: Set<String> = []
        for ref in Set(refs) where await resolveWithoutInteraction(ref) == nil {
            notHeld.insert(ref.uri)
        }
        return notHeld
    }

    /// Which of `refs` a remote unlock (a verified phone approval's opened
    /// remote-unlock key) could serve: `needsUnlock` are those whose provider
    /// reports `requiresUnlockToResolve`, and `coveredRemotely` those among
    /// them that a cache mirror holds or whose provider can open with a
    /// remote unlock (`canResolveWithRemoteUnlock`). A request is
    /// phone-servable exactly when `isComplete`. Scheme-blind: the answer
    /// comes from the owning providers and the cache. Never prompts, never
    /// opens a mirror, and reads no value.
    public func remoteUnlockCoverage(_ refs: some Sequence<SecretRef>) async -> RemoteUnlockCoverage {
        await remoteUnlockCoverage(refs, restoring: [SecretRef]())
    }

    /// Coverage for a review that resolves `request.references` and reopens
    /// `request.restoring` (see `remoteUnlockCoverage(_:restoring:)`).
    public func remoteUnlockCoverage(_ request: RemoteUnlockCoverageRequest) async -> RemoteUnlockCoverage {
        await remoteUnlockCoverage(request.references, restoring: request.restoring)
    }

    /// Coverage for a review that resolves `refs` and reopens `restoring`, a
    /// restore section's references. A restore reopens from local sealed
    /// state only (`warm`), never through a provider, so a restore reference
    /// needs an unlock exactly when `referencesRestorable` lists it: csecd
    /// cannot serve it now, and either its provider needs an unlock or only
    /// the biometric cache holds its value (a 1Password value, say, that its
    /// provider would otherwise fetch under its own authorization). Such a
    /// reference is covered by its cache mirror, or by its provider opening
    /// it with a remote unlock. `refs` keep the release's sense: a provider
    /// that can resolve one with no unlock needs none, though a cache mirror
    /// of its value puts it in `cachedRemotely`, so a phone approval reads
    /// that copy first, as a Mac approval reads the biometric cache, rather
    /// than asking a provider that may be locked. A released reference that
    /// csecd does not hold warm and whose provider would prompt at the Mac now
    /// (`requiresAttendanceToResolve`) is in `needsAttendance`. Never prompts
    /// and never opens a mirror; the values read to judge a restore reference
    /// or a warm copy stay inside this actor, as in `referencesRestorable`.
    public func remoteUnlockCoverage(
        _ refs: some Sequence<SecretRef>,
        restoring: some Sequence<SecretRef>
    ) async -> RemoteUnlockCoverage {
        var needsUnlock: Set<String> = []
        var covered: Set<String> = []
        var cachedRemotely: Set<String> = []
        var needsAttendance: Set<String> = []
        for ref in Set(refs) {
            guard let target = await target(for: ref) else { continue }
            guard await target.provider.requiresUnlockToResolve(target.reference) else {
                if !ref.isOneTimeCode, await cache.holdsRemoteUnlockMirror(ref.uri) {
                    cachedRemotely.insert(ref.uri)
                }
                if await target.provider.requiresAttendanceToResolve(target.reference),
                   await !holdsWarm(ref) {
                    needsAttendance.insert(ref.uri)
                }
                continue
            }
            needsUnlock.insert(ref.uri)
            if await opensWithRemoteUnlock(ref) {
                covered.insert(ref.uri)
            }
        }
        for ref in Set(restoring) where !needsUnlock.contains(ref.uri) {
            guard await isRestorable(ref) else { continue }
            needsUnlock.insert(ref.uri)
            if await opensWithRemoteUnlock(ref) {
                covered.insert(ref.uri)
            }
        }
        return RemoteUnlockCoverage(
            needsUnlock: needsUnlock, coveredRemotely: covered,
            cachedRemotely: cachedRemotely.subtracting(needsUnlock),
            needsAttendance: needsAttendance
        )
    }

    /// csecd holds `ref`'s value warm in memory, so a release serves it with
    /// no provider asked. Never a code, which is made per request. The value
    /// read to answer stays inside this actor.
    private func holdsWarm(_ ref: SecretRef) async -> Bool {
        guard !ref.isOneTimeCode else { return false }
        return await cachedValue(for: ref.uri, unlock: nil) != nil
    }

    /// See `referencesRestorable`. The cheap attribute checks come first, so
    /// a reference no touch could reopen is never resolved just to ask.
    private func isRestorable(_ ref: SecretRef) async -> Bool {
        // Nothing is held for a code, so a restore has nothing to reopen.
        guard !ref.isOneTimeCode else { return false }
        let reopenable: Bool
        if let provider = providers[ref.scheme], await provider.requiresUnlockToResolve(ref) {
            reopenable = true
        } else {
            reopenable = await cache.holds(ref.uri)
        }
        guard reopenable else { return false }
        return await resolveWithoutInteraction(ref) == nil
    }

    /// The references whose values are made per use and expire soon
    /// (`SecretProvider.valuesExpireSoon`): nothing may store them for later.
    public func referencesWithExpiringValues(_ refs: some Sequence<SecretRef>) async -> [String] {
        var expiring: [String] = []
        for ref in refs {
            if let provider = providers[ref.scheme], await provider.valuesExpireSoon(ref) {
                expiring.append(ref.uri)
            }
        }
        return expiring
    }

    /// A cache mirror holds `ref`, or its provider opens it with a remote
    /// unlock. Attributes only.
    private func opensWithRemoteUnlock(_ ref: SecretRef) async -> Bool {
        if !ref.isOneTimeCode, await cache.holdsRemoteUnlockMirror(ref.uri) { return true }
        guard let target = await target(for: ref) else { return false }
        return await target.provider.canResolveWithRemoteUnlock(target.reference)
    }

    /// Write a remote-unlock mirror for everything cold storage holds — the
    /// cache and every registered provider — reading each item with
    /// `localUnlock`, the one evaluated context remote-unlock enrollment
    /// spent. Warm state is left as it was: that touch enrolled the phone, it
    /// approved no use. Counts are value-free.
    public func backfillRemoteUnlockMirrors(localUnlock: CacheUnlock) async -> RemoteUnlockBackfillReport {
        guard localUnlock.isLocal else { return RemoteUnlockBackfillReport(failed: 1) }
        var report = await cache.backfillRemoteUnlockMirrors(localUnlock: localUnlock)
        var visited: [Set<String>] = []
        for scheme in providers.keys.sorted() {
            guard let provider = providers[scheme] else { continue }
            // One provider may own several schemes; back it up once.
            let schemes = provider.schemes
            guard !visited.contains(schemes) else { continue }
            visited.append(schemes)
            report.add(await provider.backfillRemoteUnlockMirrors(localUnlock: localUnlock))
        }
        return report
    }

    /// Drop the cached value of each reference from every cache tier. Returns
    /// the references an at-rest copy of which may remain (each failure is
    /// also logged by the cache).
    @discardableResult
    public func invalidate(references: some Sequence<String>) async -> Set<String> {
        var remaining: Set<String> = []
        for reference in Set(references) {
            invalidations[reference, default: 0] &+= 1
        }
        for reference in Set(references) where !(await cache.invalidate(reference)) {
            remaining.insert(reference)
        }
        return remaining
    }

    /// Resolve to a plaintext value: the owning provider's open session first
    /// when it has one (`revalidated`: a value edited in the provider's own
    /// app is served as edited); else, when a person just approved this
    /// release at the Mac (`unlock` is local) and the provider's values can
    /// change outside csec, the provider itself (`recheckedAtApproval`); then
    /// the SE-cache (a warm hit is free; a cold read folds into `unlock`, the
    /// consent touch), then the owning provider on a miss, persisting per the
    /// provider's cache hint.
    ///
    /// The cache is strictly an optimization: a read or write failure is logged and
    /// treated as a miss / no-op, never propagated — a keychain hiccup must not
    /// break resolution when the provider can still serve the value.
    ///
    /// A one-time code bypasses the cache both ways (`resolveOneTimeCode`). A
    /// seed is never released through an ordinary reference, from the cache
    /// or a provider (`OneTimeCode.isSeed`).
    public func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> Data {
        if ref.isOneTimeCode {
            return try await resolveOneTimeCode(ref, unlock: unlock)
        }
        if let fresh = await revalidated(ref) { return fresh }
        if let fresh = await recheckedAtApproval(ref, unlock: unlock) { return fresh }
        if let cached = await cachedValue(for: ref.uri, unlock: unlock) {
            guard !OneTimeCode.isSeed(cached) else { throw OneTimeCodeError.seedRefused }
            return cached
        }
        guard let provider = providers[ref.scheme] else {
            throw ProviderError.unsupportedScheme(ref.scheme)
        }
        let resolved = try await provider.resolve(ref, unlock: unlock)
        guard !OneTimeCode.isSeed(resolved.value) else { throw OneTimeCodeError.seedRefused }
        if resolved.cacheHint == .cacheable {
            do {
                try await cache.put(ref.uri, value: resolved.value)
            } catch {
                logCache("write", error)
            }
        }
        return resolved.value
    }

    /// The current code for `ref`, fresh from its provider every time and
    /// never kept: from the provider itself when it makes codes, else worked
    /// out here from its seed reference's `otpauth://` value, which goes no
    /// further than this function.
    private func resolveOneTimeCode(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> Data {
        // A csecd that predates codes cached one like any value, with no
        // expiry; that copy is long stale, so it goes.
        if await cache.holds(ref.uri) { _ = await cache.invalidate(ref.uri) }
        guard let target = await target(for: ref) else {
            throw ProviderError.unsupportedScheme(ref.scheme)
        }
        let resolved = try await target.provider.resolve(target.reference, unlock: unlock)
        guard target.seedForCode else {
            guard !OneTimeCode.isSeed(resolved.value) else { throw OneTimeCodeError.seedRefused }
            return resolved.value
        }
        return try OneTimeCode.code(fromSeed: resolved.value)
    }

    /// `ref`'s value as its provider's open session reads it now
    /// (`SecretProvider.resolveFromOpenSession`), written over the cached copy
    /// so every tier serves it from here on; nil when the provider cannot
    /// answer that way, or not within `revalidationDeadline`, and the caller
    /// serves the cached copy as before. A late read still finishes and
    /// refreshes the cache, so the next release has it. Never prompts, never
    /// reads the biometric tier, and says nothing outside this actor about
    /// whether the value changed: that comparison stays here.
    private func revalidated(_ ref: SecretRef) async -> Data? {
        guard !ref.isOneTimeCode, let provider = providers[ref.scheme] else { return nil }
        let read = Task { await self.refreshFromOpenSession(ref, provider: provider) }
        return await Self.value(of: read, within: revalidationDeadline)
    }

    /// With no open session to confirm a cached value, a release a person
    /// just approved at the Mac asks the provider itself (Alex, csec-0.81.1:
    /// re-check at approvals), which may raise the provider's own
    /// authorization once: the person who approved is there to answer it,
    /// and the session it opens confirms the rest of the release
    /// (`revalidated`). Only for a value csecd holds, since a miss asks the
    /// provider anyway, and never for a phone approval, an in-grant fetch or
    /// auto mode, where nobody is at the Mac and the cached copy is served as
    /// before. A failure serves the cached copy too: the provider being
    /// unable to answer is no reason to refuse a value already approved.
    private func recheckedAtApproval(_ ref: SecretRef, unlock: CacheUnlock?) async -> Data? {
        guard unlock?.isLocal == true, !ref.isOneTimeCode,
              let provider = providers[ref.scheme],
              await provider.valuesChangeOutsideCsec(ref),
              await cache.holds(ref.uri) else { return nil }
        let since = invalidations[ref.uri, default: 0]
        let resolved: ResolvedSecret
        do {
            resolved = try await provider.resolve(ref, unlock: unlock)
        } catch {
            logCache("re-check at approval", error)
            return nil
        }
        guard !OneTimeCode.isSeed(resolved.value) else { return nil }
        return await keepFresh(resolved, for: ref, since: since)
    }

    private func refreshFromOpenSession(_ ref: SecretRef, provider: SecretProvider) async -> Data? {
        let since = invalidations[ref.uri, default: 0]
        guard let resolved = await provider.resolveFromOpenSession(ref),
              !OneTimeCode.isSeed(resolved.value) else { return nil }
        return await keepFresh(resolved, for: ref, since: since)
    }

    /// `resolved`, a value just read from `ref`'s provider, written over the
    /// cached copy unless an invalidation since `since` makes it older than
    /// what csec wrote; nil then, so the caller asks again.
    private func keepFresh(_ resolved: ResolvedSecret, for ref: SecretRef, since: UInt64) async -> Data? {
        guard resolved.cacheHint == .cacheable else { return resolved.value }
        guard invalidations[ref.uri, default: 0] == since else {
            // Something newer than this read was written while it ran; the
            // next resolve asks the provider for that.
            return nil
        }
        // Only a value that differs costs a keychain write (and a mirror
        // reseal); a warm miss is written, since only the biometric tier
        // could say whether it differs.
        if await cachedValue(for: ref.uri, unlock: nil) != resolved.value {
            do {
                try await cache.put(ref.uri, value: resolved.value)
            } catch {
                logCache("write", error)
            }
        }
        return resolved.value
    }

    /// `task`'s value, or nil once `seconds` pass first. The task keeps
    /// running either way.
    private static func value(of task: Task<Data?, Never>, within seconds: TimeInterval) async -> Data? {
        let first = FirstResult()
        return await withCheckedContinuation { continuation in
            first.arm(continuation)
            let timer = Task {
                try? await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
                first.resume(nil)
            }
            Task {
                first.resume(await task.value)
                timer.cancel()
            }
        }
    }

    /// Why auto mode, a restore or a fetch ahead never serves a code.
    static let oneTimeCodeNeedsPerson = "one-time codes always need you to approve them"

    private func cachedValue(for uri: String, unlock: CacheUnlock?) async -> Data? {
        do {
            return try await cache.get(uri, unlock: unlock)
        } catch {
            logCache("read", error)
            return nil
        }
    }

    private func logCache(_ operation: String, _ error: Error) {
        FileHandle.standardError.write(Data(
            "csecd: cache \(operation) failed, continuing (\(error))\n".utf8
        ))
    }
}

/// Resumes a continuation with whichever answer arrives first.
private final class FirstResult: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data?, Never>?

    func arm(_ continuation: CheckedContinuation<Data?, Never>) {
        lock.lock()
        self.continuation = continuation
        lock.unlock()
    }

    func resume(_ value: Data?) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
    }
}

/// A delegated release's value for one reference, or (`reason`, when the
/// provider gave one) why csecd could not get it with no interaction.
public enum DelegatedValue: Sendable {
    case value(Data)
    case notHeld(reason: String?)

    public var data: Data? {
        if case let .value(data) = self { return data }
        return nil
    }
}
