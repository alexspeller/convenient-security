import Foundation
import ConvenientSecurity

private struct SetupImportRequest {
    let destinationKey: String
    let locator: LocalSecretLocator
}

private struct SetupCommandOptions {
    var apply = false
    var selectedAgents: [AICommandHookClient] = []
    var skipAgents = false
    var replaceCSECHook = false
    var replaceSecret = false
    var includeAuditPrompt = true
    var projectDirectory = FileManager.default.currentDirectoryPath
    var store: NativeStoreName?
    var imports: [SetupImportRequest] = []
}

func runSetup(_ arguments: [String]) -> Never {
    let options: SetupCommandOptions
    do {
        options = try parseSetupOptions(arguments)
    } catch {
        setupFailure(error.localizedDescription, status: 2)
    }

    let environment = ProcessInfo.processInfo.environment
    let homeDirectory = FileManager.default.homeDirectoryForCurrentUser.path
    let detections: [CodingAgentDetection]
    let discovery: LocalSecretDiscovery
    do {
        detections = try CodingAgentSetup.detect(
            homeDirectory: homeDirectory,
            pathEnvironment: environment["PATH"]
        )
        discovery = try LocalSecretDiscoveryEngine.discover(
            projectDirectory: options.projectDirectory,
            environment: environment
        )
    } catch {
        setupFailure(error.localizedDescription, status: 1)
    }

    let chosenDetections: [CodingAgentDetection]
    if options.skipAgents {
        chosenDetections = []
    } else if options.selectedAgents.isEmpty {
        chosenDetections = detections.filter(\.detected)
    } else {
        chosenDetections = options.selectedAgents.compactMap { selected in
            detections.first { $0.client == selected }
        }
    }

    var plans: [CodingAgentConfigurationPlan] = []
    var planErrors: [String] = []
    for detection in chosenDetections {
        do {
            plans.append(try CodingAgentSetup.plan(
                detection: detection,
                csecExecutablePath: currentExecutablePath(),
                replaceExistingCSECHook: options.replaceCSECHook
            ))
        } catch {
            planErrors.append(error.localizedDescription)
        }
    }

    var agentReachable = false
    var providerSchemes: [String] = []
    var nativeStoreAvailable = false
    let agentClient = makeAgentClient()
    do {
        let capabilities = try agentClient.capabilities()
        agentReachable = true
        nativeStoreAvailable = capabilities.features.contains(.nativeEncryptedStore)
        providerSchemes = (try? agentClient.schemes()) ?? []
    } catch {
        // Setup remains useful before the daemon is installed. Import will
        // separately fail closed if it was explicitly requested.
    }

    let rootReachable: Bool
    #if DEBUG
    let rootTrust: RootHelperServerTrustPolicy = .allowUnverifiedForTesting
    #else
    let rootTrust: RootHelperServerTrustPolicy = .requireProductRootHelper
    #endif
    do {
        try RootHelperClient(trustPolicy: rootTrust).health()
        rootReachable = true
    } catch {
        rootReachable = false
    }

    let selectedImports: [(SetupImportRequest, LocalSecretCandidate)]
    do {
        selectedImports = try validateImportRequests(options.imports, discovery: discovery)
    } catch {
        setupFailure(error.localizedDescription, status: 2)
    }

    let launchAgentStatus = LaunchAgentService.status().description
    let sipStatus = StartupSecurityReport.currentAgent().sipStatus
    var auditPrompt: String?
    if options.includeAuditPrompt {
        do {
            auditPrompt = try OnboardingAuditPrompt.generate(facts: OnboardingAuditFacts(
                projectDirectory: options.projectDirectory,
                launchAgentStatus: launchAgentStatus,
                productAgentReachable: agentReachable,
                providerSchemes: providerSchemes,
                rootHelperReachable: rootReachable,
                sipStatus: sipStatus,
                codingAgentPlans: plans,
                discovery: discovery
            ))
        } catch {
            planErrors.append(error.localizedDescription)
        }
    }
    printSetupReport(
        options: options,
        detections: detections,
        chosenDetections: chosenDetections,
        plans: plans,
        planErrors: planErrors,
        discovery: discovery,
        selectedImports: selectedImports,
        launchAgentStatus: launchAgentStatus,
        agentReachable: agentReachable,
        providerSchemes: providerSchemes,
        nativeStoreAvailable: nativeStoreAvailable,
        rootReachable: rootReachable,
        sipStatus: sipStatus
    )

    if let auditPrompt {
        print("\n# Bounded coding-agent security audit prompt\n")
        FileHandle.standardOutput.write(Data(auditPrompt.utf8))
    }

    let blockedPlans = plans.filter { $0.action == .blocked }
    guard planErrors.isEmpty, blockedPlans.isEmpty else {
        FileHandle.standardError.write(Data(
            "csec setup: blocked; resolve the reported configuration issue(s) before applying\n".utf8
        ))
        exit(1)
    }

    guard options.apply else {
        print("\ncsec setup: dry run complete; no files, stores, grants, or providers were changed.")
        print("Re-run the same command with --apply after reviewing this plan.")
        exit(0)
    }

    if !selectedImports.isEmpty, !nativeStoreAvailable {
        setupFailure(
            "selected imports require a reachable signed agent with the native encrypted store",
            status: 1
        )
    }

    // Preflight the sensitive import before changing user configuration. The
    // edit session is exact-caller and Touch-ID gated; it is cancelled on every
    // failure path. Source values are never printed or placed in argv.
    var pendingEdit: NativeStoreEditStart?
    var pendingDocument: Data?
    var selectedValues: [String: String] = [:]
    defer {
        if let pendingEdit {
            agentClient.cancelNativeStoreEdit(sessionID: pendingEdit.sessionID)
        }
        selectedValues.removeAll(keepingCapacity: false)
        if let count = pendingDocument?.count {
            pendingDocument?.resetBytes(in: 0..<count)
        }
    }

    if !selectedImports.isEmpty {
        guard let store = options.store else {
            setupFailure("--store is required with --import", status: 2)
        }
        do {
            for (request, candidate) in selectedImports {
                selectedValues[request.destinationKey] = try LocalSecretDiscoveryEngine.load(
                    candidate,
                    projectDirectory: options.projectDirectory,
                    environment: environment
                )
            }
            let edit = try agentClient.beginNativeStoreEdit(
                store: store.value,
                mode: .onboardingImport
            )
            pendingEdit = edit
            pendingDocument = try NativeStoreImport.merge(
                existingDocument: edit.document,
                selectedValues: selectedValues,
                replaceExisting: options.replaceSecret
            )
        } catch {
            setupFailure("import preflight failed: \(error.localizedDescription)", status: 1)
        }
    }

    var appliedConfigurations: [String] = []
    do {
        for plan in plans {
            try CodingAgentSetup.apply(plan)
            if plan.action == .create || plan.action == .merge {
                appliedConfigurations.append(plan.path)
            }
        }
    } catch {
        let suffix = appliedConfigurations.isEmpty
            ? "no agent configuration was changed"
            : "already updated: \(appliedConfigurations.map(setupSafe).joined(separator: ", "))"
        setupFailure("configuration apply failed (\(suffix)): \(error.localizedDescription)", status: 1)
    }

    var importResult: NativeStoreEditCommit?
    if let edit = pendingEdit, let document = pendingDocument {
        do {
            importResult = try agentClient.commitNativeStoreEdit(
                sessionID: edit.sessionID,
                document: document
            )
            pendingEdit = nil
        } catch {
            let suffix = appliedConfigurations.isEmpty
                ? "agent configuration was unchanged"
                : "agent hook configuration was applied before this failure"
            setupFailure("native-store import failed; \(suffix): \(error.localizedDescription)", status: 1)
        }
    }

    print("\n# Applied")
    if appliedConfigurations.isEmpty {
        print("- coding-agent configuration: no change")
    } else {
        for path in appliedConfigurations {
            print("- updated \(setupSafe(path)) by merging only the csec hook")
        }
    }
    if let store = options.store, let importResult {
        print(
            "- native store \(setupSafe(store.value)): generation \(importResult.generation), "
                + "\(selectedImports.count) selected credential(s) imported "
                + "(\(importResult.secretCount) total keys)"
        )
        for (request, _) in selectedImports {
            print("  - csec://\(setupSafe(store.value))/\(setupSafe(request.destinationKey))")
        }
        print("- original environment/dotenv sources were not modified or deleted")
    }
    if !appliedConfigurations.isEmpty {
        print("- restart each coding agent, inspect its hook UI, and trust the exact new hook before relying on coverage")
    }
    print("csec setup: apply complete")
    exit(0)
}

private func parseSetupOptions(_ arguments: [String]) throws -> SetupCommandOptions {
    var options = SetupCommandOptions()
    var sawProject = false
    var sawStore = false
    var index = 0
    while index < arguments.count {
        switch arguments[index] {
        case "--apply":
            guard !options.apply else { throw SetupOnboardingError.configurationConflict("duplicate --apply") }
            options.apply = true
        case "--agent":
            index += 1
            guard index < arguments.count,
                  let client = AICommandHookClient(rawValue: arguments[index]),
                  !options.selectedAgents.contains(where: { $0 == client }) else {
                throw SetupOnboardingError.configurationConflict(
                    "--agent must be a unique claude or codex selection"
                )
            }
            options.selectedAgents.append(client)
        case "--skip-agents":
            options.skipAgents = true
        case "--replace-csec-hook":
            options.replaceCSECHook = true
        case "--replace-secret":
            options.replaceSecret = true
        case "--no-audit-prompt":
            options.includeAuditPrompt = false
        case "--project":
            index += 1
            guard !sawProject,
                  index < arguments.count,
                  !arguments[index].isEmpty else {
                throw SetupOnboardingError.invalidProjectDirectory
            }
            sawProject = true
            options.projectDirectory = absoluteSetupPath(arguments[index])
        case "--store":
            index += 1
            guard !sawStore, index < arguments.count else {
                throw SetupOnboardingError.configurationConflict("--store requires a native store name")
            }
            sawStore = true
            options.store = try NativeStoreName(arguments[index])
        case "--import":
            index += 1
            guard index < arguments.count else {
                throw SetupOnboardingError.configurationConflict("--import requires DEST=env:NAME or DEST=dotenv:PATH:NAME")
            }
            options.imports.append(try parseImportRequest(arguments[index]))
        default:
            throw SetupOnboardingError.configurationConflict(
                "unknown setup option: \(setupSafe(arguments[index]))"
            )
        }
        index += 1
    }
    guard !(options.skipAgents && !options.selectedAgents.isEmpty) else {
        throw SetupOnboardingError.configurationConflict(
            "--skip-agents cannot be combined with --agent"
        )
    }
    guard !options.replaceSecret || !options.imports.isEmpty else {
        throw SetupOnboardingError.configurationConflict(
            "--replace-secret is meaningful only with --import"
        )
    }
    guard options.imports.isEmpty == (options.store == nil) else {
        throw SetupOnboardingError.configurationConflict(
            "--store and --import must be supplied together"
        )
    }
    let destinations = options.imports.map(\.destinationKey)
    guard Set(destinations).count == destinations.count else {
        throw SetupOnboardingError.configurationConflict(
            "each --import destination key must be unique"
        )
    }
    return options
}

private func parseImportRequest(_ value: String) throws -> SetupImportRequest {
    guard let equals = value.firstIndex(of: "=") else {
        throw SetupOnboardingError.invalidImportSource(setupSafe(value))
    }
    let destination = String(value[..<equals])
    guard NativeStoreDocument.isValidKey(destination) else {
        throw SetupOnboardingError.invalidImportSource(setupSafe(value))
    }
    let source = String(value[value.index(after: equals)...])
    let locator: LocalSecretLocator
    if source.hasPrefix("env:") {
        let name = String(source.dropFirst("env:".count))
        guard !name.isEmpty else {
            throw SetupOnboardingError.invalidImportSource(setupSafe(source))
        }
        locator = .environment(name: name)
    } else if source.hasPrefix("dotenv:") {
        let body = String(source.dropFirst("dotenv:".count))
        guard let separator = body.lastIndex(of: ":") else {
            throw SetupOnboardingError.invalidImportSource(setupSafe(source))
        }
        let path = String(body[..<separator])
        let name = String(body[body.index(after: separator)...])
        guard !path.isEmpty, !name.isEmpty else {
            throw SetupOnboardingError.invalidImportSource(setupSafe(source))
        }
        locator = .dotenv(relativePath: path, name: name)
    } else {
        throw SetupOnboardingError.invalidImportSource(setupSafe(source))
    }
    return SetupImportRequest(destinationKey: destination, locator: locator)
}

private func validateImportRequests(
    _ requests: [SetupImportRequest],
    discovery: LocalSecretDiscovery
) throws -> [(SetupImportRequest, LocalSecretCandidate)] {
    let candidates = Dictionary(
        discovery.candidates.map { ($0.locator.identifier, $0) },
        uniquingKeysWith: { first, _ in first }
    )
    return try requests.map { request in
        guard let candidate = candidates[request.locator.identifier],
              candidate.kind == .plaintextCandidate else {
            throw SetupOnboardingError.invalidImportSource(request.locator.identifier)
        }
        return (request, candidate)
    }
}

private func printSetupReport(
    options: SetupCommandOptions,
    detections: [CodingAgentDetection],
    chosenDetections: [CodingAgentDetection],
    plans: [CodingAgentConfigurationPlan],
    planErrors: [String],
    discovery: LocalSecretDiscovery,
    selectedImports: [(SetupImportRequest, LocalSecretCandidate)],
    launchAgentStatus: String,
    agentReachable: Bool,
    providerSchemes: [String],
    nativeStoreAvailable: Bool,
    rootReachable: Bool,
    sipStatus: SIPStatus
) {
    print("# Convenient Security setup — \(options.apply ? "APPLY" : "DRY RUN")")
    print("project: \(setupSafe(options.projectDirectory))")
    print("SIP: \(sipStatus.rawValue)")
    print("csecd LaunchAgent: \(setupSafe(launchAgentStatus))")
    print("authenticated agent: \(agentReachable ? "reachable" : "unavailable")")
    let displayedSchemes = providerSchemes.sorted().map(setupSafe).joined(separator: ", ")
    print("provider schemes: \(displayedSchemes.isEmpty ? "none reported" : displayedSchemes)")
    print("native encrypted import: \(nativeStoreAvailable ? "available" : "unavailable")")
    print("authenticated root helper: \(rootReachable ? "reachable" : "unavailable")")

    print("\n## Coding agents")
    for detection in detections {
        let executable = detection.executablePath.map(setupSafe) ?? "not found"
        let selected = chosenDetections.contains { $0.client == detection.client }
        print(
            "- \(detection.client.rawValue): \(detection.detected ? "detected" : "not detected"); "
                + "executable \(executable); config \(setupSafe(detection.configurationPath)); "
                + "\(selected ? "selected" : "not selected")"
        )
    }
    if options.skipAgents {
        print("- configuration intentionally skipped by --skip-agents")
    } else if chosenDetections.isEmpty {
        print("- no supported coding agent was auto-detected; use --agent claude or --agent codex to select one explicitly")
    }
    for plan in plans {
        print("- plan \(plan.client.rawValue): \(plan.action.rawValue) — \(setupSafe(plan.detail))")
    }
    for error in planErrors {
        print("- BLOCKED: \(setupSafe(error))")
    }
    if !plans.isEmpty {
        print("- setup never approves hook trust; restart the client and review the exact hook in its hook UI")
        print("\n### Exact managed fragments")
        print("Only these value-free fragments are merged; the complete user configuration is never printed.")
        for plan in plans {
            print("\n\(plan.client.rawValue):")
            if let data = try? AICommandHook.hookConfiguration(
                client: plan.client,
                csecExecutablePath: currentExecutablePath()
            ), let fragment = String(data: data, encoding: .utf8) {
                print(setupDocumentSafe(fragment), terminator: fragment.hasSuffix("\n") ? "" : "\n")
            }
        }
    }

    print("\n## Value-free local source review")
    for source in discovery.sources {
        print(
            "- \(setupSafe(source.source)): \(setupSafe(source.protection)); "
                + "\(source.candidateCount) candidate(s), \(source.unsupportedEntryCount) unsupported entry/entries"
        )
    }
    if discovery.candidates.isEmpty {
        print("- no supported references or secret-named plaintext candidates found within the bounded scan")
    } else {
        for candidate in discovery.candidates {
            var line = "- \(candidate.kind.rawValue): \(setupSafe(candidate.locator.identifier))"
            if let reference = candidate.reference {
                line += " -> \(setupSafe(reference))"
            }
            print(line)
        }
    }
    for warning in discovery.warnings {
        print("- warning: \(setupSafe(warning))")
    }

    print("\n## Explicit import plan")
    if selectedImports.isEmpty {
        print("- none; setup will never import every discovered candidate automatically")
        print("- select one with --store STORE --import DEST=env:NAME or --import DEST=dotenv:PATH:NAME")
    } else if let store = options.store {
        for (request, _) in selectedImports {
            print(
                "- \(setupSafe(request.locator.identifier)) -> "
                    + "csec://\(setupSafe(store.value))/\(setupSafe(request.destinationKey))"
                    + (options.replaceSecret ? " (explicit overwrite allowed)" : " (existing keys protected)")
            )
        }
        print("- imports do not resolve references and do not remove, rewrite, or unset the original source")
    }
}

private func absoluteSetupPath(_ value: String) -> String {
    let url = value.hasPrefix("/")
        ? URL(fileURLWithPath: value)
        : URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(value)
    return url.standardizedFileURL.path
}

private func setupSafe(_ value: String) -> String {
    let bidiControls: Set<UInt32> = [
        0x061c, 0x200e, 0x200f,
        0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
        0x2066, 0x2067, 0x2068, 0x2069,
    ]
    return value.unicodeScalars.map { scalar in
        if CharacterSet.controlCharacters.contains(scalar)
            || CharacterSet.newlines.contains(scalar)
            || bidiControls.contains(scalar.value) {
            return "�"
        }
        return String(scalar)
    }.joined()
}

private func setupDocumentSafe(_ value: String) -> String {
    let bidiControls: Set<UInt32> = [
        0x061c, 0x200e, 0x200f,
        0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
        0x2066, 0x2067, 0x2068, 0x2069,
    ]
    return value.unicodeScalars.map { scalar in
        bidiControls.contains(scalar.value) ? "�" : String(scalar)
    }.joined()
}

private func setupFailure(_ message: String, status: Int32) -> Never {
    FileHandle.standardError.write(Data("csec setup: \(setupSafe(message))\n".utf8))
    exit(status)
}
