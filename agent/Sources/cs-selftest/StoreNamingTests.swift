import ConvenientSecurity
import Foundation
import LocalAuthentication

/// Fixed-map `NativeStoreNameIndexing` so resolution is tested without a store
/// directory: `names` is which store names exist, `origins` which project root
/// each name's marker claims.
struct FakeStoreIndex: NativeStoreNameIndexing {
    var names: Set<String>
    var origins: [String: String]

    func storeExists(_ name: String) -> Bool { names.contains(name) }
    func origin(forStore name: String) -> String? { origins[name] }
}

/// Legible default store names (Phase 0): the pure path→name derivation, the
/// collision-detected resolution against an index, the sealed origin marker,
/// and the provider-side stamping/enforcement in `beginEdit`.
func storeNamingTests() async {
    print("\n# Store naming (legible defaults + origin markers)")

    let home = "/Users/alex"
    func legible(_ path: String) -> String {
        ProtectedFileImportPlanner.legibleStoreName(
            forProjectDirectory: path, homeDirectory: home)
    }

    // Pure derivation: home-relative path as dashes.
    check(legible("/Users/alex/work/WebApp") == "work-WebApp",
          "a home-relative path becomes its dashes form")
    check(legible("/Users/alex/opensource/convenient-security") == "opensource-convenient-security",
          "literal dashes in directory names survive")
    check(legible("/Users/alex") == "home", "the home directory itself gets a fixed name")
    check(legible("/opt/homebrew/foo") == "opt-homebrew-foo",
          "a path outside home uses the absolute path minus the leading slash")
    check(legible("/Users/alex/tmp/weird name!@#") == "tmp-weird-name",
          "punctuation maps to dashes, runs collapse, trailing dashes trim")
    check(legible("/Users/alex/café/x") == "caf-x", "non-ASCII maps to a dash")
    check(legible("/Users/alex/.config") == "config",
          "a leading dot maps to a dash and is trimmed to keep the alnum initial")
    check(legible("/Users/alex/_foo") == "p_foo",
          "a non-alphanumeric initial is prefixed, keeping the name valid")
    check(legible("/Users/alex/my_app") == "my_app", "underscores are preserved")
    check(ProtectedFileImportPlanner.legibleStoreName(
              forProjectDirectory: "/Users/alex/work/WebApp",
              homeDirectory: "/Users/alex/") == "work-WebApp",
          "a trailing slash on the home directory does not break prefix stripping")
    check(legible("/Users/alexandra/app") == "Users-alexandra-app",
          "a sibling directory sharing the home prefix string is not treated as home-relative")
    check(legible("/Users/alex/work/WebApp") == legible("/Users/alex/work/WebApp"),
          "derivation is deterministic")

    // Collision-detected resolution.
    let root = "/Users/alex/work/WebApp"
    let clean = "work-WebApp"
    let expectedSuffix = String(NativeStoreEnvelope.digest(Data(root.utf8)).prefix(8))
    do {
        let fresh = try ProtectedFileImportPlanner.resolveDefaultStore(
            projectRoot: root, homeDirectory: home,
            index: FakeStoreIndex(names: [], origins: [:]))
        check(fresh.value == clean, "no existing store resolves to the clean name")

        let sameRoot = try ProtectedFileImportPlanner.resolveDefaultStore(
            projectRoot: root, homeDirectory: home,
            index: FakeStoreIndex(names: [clean], origins: [clean: root]))
        check(sameRoot.value == clean, "a store already claimed by this root is reused")

        let markerless = try ProtectedFileImportPlanner.resolveDefaultStore(
            projectRoot: root, homeDirectory: home,
            index: FakeStoreIndex(names: [clean], origins: [:]))
        check(markerless.value == clean,
              "a legacy store with no origin marker is adopted under the clean name")

        let conflicted = try ProtectedFileImportPlanner.resolveDefaultStore(
            projectRoot: root, homeDirectory: home,
            index: FakeStoreIndex(names: [clean], origins: [clean: "/Users/alex/other"]))
        check(conflicted.value == "\(clean)-\(expectedSuffix)",
              "a store claimed by a different root resolves to the deterministic suffixed name")
        let conflictedAgain = try ProtectedFileImportPlanner.resolveDefaultStore(
            projectRoot: root, homeDirectory: home,
            index: FakeStoreIndex(names: [clean], origins: [clean: "/Users/alex/other"]))
        check(conflicted == conflictedAgain, "the suffixed resolution is deterministic")

        let suffixedName = "\(clean)-\(expectedSuffix)"
        let ownSuffixed = try ProtectedFileImportPlanner.resolveDefaultStore(
            projectRoot: root, homeDirectory: home,
            index: FakeStoreIndex(
                names: [clean, suffixedName],
                origins: [clean: "/Users/alex/other", suffixedName: root]))
        check(ownSuffixed.value == suffixedName,
              "an already-created suffixed store for this root is reused")
    } catch {
        check(false, "default-store resolution succeeds (\(error))")
    }

    do {
        _ = try ProtectedFileImportPlanner.resolveDefaultStore(
            projectRoot: root, homeDirectory: home,
            index: FakeStoreIndex(
                names: [clean, "\(clean)-\(expectedSuffix)"],
                origins: [
                    clean: "/Users/alex/other",
                    "\(clean)-\(expectedSuffix)": "/Users/alex/third",
                ]))
        check(false, "a clean+suffixed double collision is refused, never shared")
    } catch let error as StoreNameResolutionError {
        check(error == .unresolvableCollision(
                  cleanName: clean, suffixedName: "\(clean)-\(expectedSuffix)"),
              "a clean+suffixed double collision is refused, never shared")
    } catch {
        check(false, "a double collision throws the resolution error (got \(error))")
    }

    // Length cap: an over-long legible part always takes the suffix.
    do {
        let longRoot = "/Users/alex/" + String(repeating: "d/", count: 40) + "leaf"
        let resolved = try ProtectedFileImportPlanner.resolveDefaultStore(
            projectRoot: longRoot, homeDirectory: home,
            index: FakeStoreIndex(names: [], origins: [:]))
        check(resolved.value.utf8.count <= 64, "a long path resolves within the 64-byte bound")
        check(resolved.value.hasSuffix(
                  "-" + String(NativeStoreEnvelope.digest(Data(longRoot.utf8)).prefix(8))),
              "a long path always carries its deterministic suffix")
        let again = try ProtectedFileImportPlanner.resolveDefaultStore(
            projectRoot: longRoot, homeDirectory: home,
            index: FakeStoreIndex(names: [], origins: [:]))
        check(resolved == again, "long-path resolution is deterministic")
    } catch {
        check(false, "long-path resolution succeeds (\(error))")
    }

    // Origin marker: cleartext parse without a key, AEAD verify with one.
    do {
        let store = try NativeStoreName("work-WebApp")
        let keyData = try NativeStoreEnvelope.randomBytes(count: 32)
        let sealed = try NativeStoreOriginMarker.sealed(
            origin: root, store: store, keyData: keyData)
        check(NativeStoreOriginMarker.parseOrigin(fromCleartext: sealed) == root,
              "the origin parses from the cleartext header with no key")
        check(NativeStoreOriginMarker.verifiedOrigin(
                  data: sealed, store: store, keyData: keyData) == root,
              "the origin verifies under the store key")
        let otherStore = try NativeStoreName("other-store")
        check(NativeStoreOriginMarker.verifiedOrigin(
                  data: sealed, store: otherStore, keyData: keyData) == nil,
              "a marker sealed for one store never verifies for another")
        let otherKey = try NativeStoreEnvelope.randomBytes(count: 32)
        check(NativeStoreOriginMarker.verifiedOrigin(
                  data: sealed, store: store, keyData: otherKey) == nil,
              "a marker never verifies under a different key")

        // Tamper with the cleartext path bytes: parse still returns (that is
        // the unverified read), verification refuses.
        var tampered = sealed
        let pathStart = "CSECORG1".utf8.count + 2
        tampered[tampered.startIndex + pathStart + 1] ^= 0x01
        check(NativeStoreOriginMarker.parseOrigin(fromCleartext: tampered) != nil,
              "a tampered header still parses (the cleartext read is unverified)")
        check(NativeStoreOriginMarker.verifiedOrigin(
                  data: tampered, store: store, keyData: keyData) == nil,
              "a tampered header fails AEAD verification")

        check(!NativeStoreOriginMarker.isValidOrigin("relative/path"),
              "a relative origin path is invalid")
        check(!NativeStoreOriginMarker.isValidOrigin("/x\0y"), "a NUL origin path is invalid")
        check(!NativeStoreOriginMarker.isValidOrigin(
                  "/" + String(repeating: "a", count: 1024)),
              "an origin path over the byte bound is invalid")
        check(NativeStoreOriginMarker.fileName(store: store) == "work-WebApp.origin",
              "the marker file name is <store>.origin (never .csec, so hasFiles ignores it)")
    } catch {
        check(false, "origin marker seal/parse/verify succeeds (\(error))")
    }

    // Provider-side stamping and enforcement.
    do {
        let unlock = CacheUnlock(LAContext()) // in-memory backends only; never prompts
        let keyBackend = InMemoryNativeStoreKeyBackend()
        let fileBackend = InMemoryNativeStoreFileBackend()
        let provider = NativeEncryptedFileProvider(
            keyBackend: keyBackend, fileBackend: fileBackend)
        let store = try NativeStoreName("work-WebApp")
        let markerName = NativeStoreOriginMarker.fileName(store: store)
        let callerPID = getpid()
        let callerStart = ProcessAncestry.startTime(of: callerPID) ?? 1

        let first = try await provider.beginEdit(
            store: store, callerPID: callerPID, callerStartTime: callerStart,
            unlock: unlock, origin: root)
        let stamped = await fileBackend.snapshot()[markerName]
        check(stamped != nil, "creating a store with an origin stamps its marker file")
        check(stamped.flatMap(NativeStoreOriginMarker.parseOrigin(fromCleartext:)) == root,
              "the stamped marker names the creating project root")
        await provider.cancelEdit(
            sessionID: first.sessionID, callerPID: callerPID, callerStartTime: callerStart)

        let sameOrigin = try await provider.beginEdit(
            store: store, callerPID: callerPID, callerStartTime: callerStart,
            unlock: unlock, origin: root)
        check(true, "an edit claiming the marker's own root proceeds")
        await provider.cancelEdit(
            sessionID: sameOrigin.sessionID, callerPID: callerPID, callerStartTime: callerStart)

        do {
            _ = try await provider.beginEdit(
                store: store, callerPID: callerPID, callerStartTime: callerStart,
                unlock: unlock, origin: "/Users/alex/other")
            check(false, "an edit claiming a different root is refused")
        } catch NativeStoreError.originConflict {
            check(true, "an edit claiming a different root is refused")
        }

        do {
            _ = try await provider.beginEdit(
                store: store, callerPID: callerPID, callerStartTime: callerStart,
                unlock: unlock, origin: "relative/path")
            check(false, "an invalid origin path is rejected before any store work")
        } catch NativeStoreError.invalidDocument {
            check(true, "an invalid origin path is rejected before any store work")
        }

        // A marker that fails AEAD verification (tampered or replaced) refuses
        // even the marker's own claimed root: the cleartext cannot be trusted.
        let sealedForOtherKey = try NativeStoreOriginMarker.sealed(
            origin: root, store: store,
            keyData: try NativeStoreEnvelope.randomBytes(count: 32))
        await fileBackend.replace(named: markerName, data: sealedForOtherKey)
        do {
            _ = try await provider.beginEdit(
                store: store, callerPID: callerPID, callerStartTime: callerStart,
                unlock: unlock, origin: root)
            check(false, "an unverifiable marker refuses origin-bound edits")
        } catch NativeStoreError.originConflict {
            check(true, "an unverifiable marker refuses origin-bound edits")
        }

        // Origin-free edits (explicit --store, csec edit) ignore markers
        // entirely — the tampered marker must not brick the store.
        let originFree = try await provider.beginEdit(
            store: store, callerPID: callerPID, callerStartTime: callerStart, unlock: unlock)
        check(true, "an origin-free edit ignores marker state")
        await provider.cancelEdit(
            sessionID: originFree.sessionID, callerPID: callerPID, callerStartTime: callerStart)

        // Legacy adoption: a store created with no origin has no marker; the
        // first origin-bound edit stamps it.
        let legacyStore = try NativeStoreName("legacy-store")
        let legacyMarker = NativeStoreOriginMarker.fileName(store: legacyStore)
        let legacyCreate = try await provider.beginEdit(
            store: legacyStore, callerPID: callerPID, callerStartTime: callerStart, unlock: unlock)
        await provider.cancelEdit(
            sessionID: legacyCreate.sessionID, callerPID: callerPID, callerStartTime: callerStart)
        let noMarker = await fileBackend.snapshot()[legacyMarker]
        check(noMarker == nil, "an origin-free creation stamps no marker")
        let adopt = try await provider.beginEdit(
            store: legacyStore, callerPID: callerPID, callerStartTime: callerStart,
            unlock: unlock, origin: "/Users/alex/legacy")
        let adopted = await fileBackend.snapshot()[legacyMarker]
        check(adopted.flatMap(NativeStoreOriginMarker.parseOrigin(fromCleartext:))
                  == "/Users/alex/legacy",
              "the first origin-bound edit adopts a markerless store by stamping it")
        await provider.cancelEdit(
            sessionID: adopt.sessionID, callerPID: callerPID, callerStartTime: callerStart)
    } catch {
        check(false, "provider origin stamping/enforcement succeeds (\(error))")
    }
}
