import Foundation

/// A value-free error: never interpolate an INI line or credential value.
public enum AWSCredentialMigrationError: Error, LocalizedError {
    case invalidDocument
    case conflictingConfiguration
    case invalidCommand
    case invalidReferences

    public var errorDescription: String? {
        switch self {
        case .invalidDocument:
            return "AWS INI contains duplicate or unsupported syntax; no files were changed"
        case .conflictingConfiguration:
            return "AWS config contains conflicting static credentials or a different credential_process; no files were changed"
        case .invalidCommand:
            return "the csec executable path or reference cannot be safely represented in credential_process"
        case .invalidReferences:
            return "the import did not return the planned canonical references; plaintext was retained"
        }
    }
}

/// Plans the complete migration without I/O. Storage is injected; configuration
/// only records canonical references and works equally with csec:// and op://.
/// Originals stay intact until import and durable config installation succeed.
public struct AWSCredentialMigration {
    public let importedProfiles: [String]
    public let skippedProfiles: [String]
    public let values: [String: String]
    public let references: [String: String]
    public let configuration: Data
    public let credentials: Data

    public init(
        credentialsData: Data, configurationData: Data, sourcePath: String,
        csecExecutablePath: String,
        referenceForKey: (String) throws -> SecretRef
    ) throws {
        let source = try AWSMigrationINI(credentialsData)
        let config = try AWSMigrationINI(configurationData)
        var values: [String: String] = [:]
        var references: [String: String] = [:]
        var imported: [String] = []
        var skipped: [String] = []
        var configCommands: [String: String] = [:]
        var removedLines = Set<Int>()
        let staticKeys: Set<String> = ["aws_access_key_id", "aws_secret_access_key", "aws_session_token"]
        let derivedKeys: Set<String> = [
            "credential_process", "sso_start_url", "sso_session", "sso_account_id",
            "role_arn", "source_profile", "credential_source", "web_identity_token_file",
        ]
        for profile in source.order {
            // Credentials use bare section names. Accepting config-style headings
            // here would silently rename a real profile in some AWS SDKs.
            guard !profile.hasPrefix("profile ") else {
                throw AWSCredentialMigrationError.invalidDocument
            }
            let fields = source.sections[profile] ?? [:]
            let section = profile == "default" ? "default" : "profile " + profile
            let settings = config.sections[section] ?? [:]
            guard derivedKeys.isDisjoint(with: fields.keys),
                  derivedKeys.subtracting(["credential_process"]).isDisjoint(with: settings.keys),
                  let access = fields["aws_access_key_id"], !access.value.isEmpty,
                  let secret = fields["aws_secret_access_key"], !secret.value.isEmpty else {
                skipped.append(profile)
                continue
            }
            let key = Self.bundleKey(sourcePath: sourcePath, profile: profile)
            let reference = try referenceForKey(key).uri
            let command = try Self.command(executable: csecExecutablePath, reference: reference)
            guard staticKeys.isDisjoint(with: settings.keys),
                  settings["credential_process"].map({ $0.value == command }) ?? true else {
                throw AWSCredentialMigrationError.conflictingConfiguration
            }
            var bundle = [AWSCredentialProcess.accessKeyID: access.value,
                          AWSCredentialProcess.secretAccessKey: secret.value]
            if let token = fields["aws_session_token"], !token.value.isEmpty {
                bundle[AWSCredentialProcess.sessionToken] = token.value
            }
            values[key] = try AWSCredentialProcess.renderBundle(fields: bundle)
            references[key] = reference
            imported.append(profile)
            configCommands[section] = command
            for field in staticKeys {
                if let entry = fields[field] { removedLines.insert(entry.line) }
            }
        }
        self.values = values
        self.references = references
        importedProfiles = imported
        skippedProfiles = skipped
        configuration = config.insertingProcesses(configCommands)
        credentials = Data(source.lines.enumerated().filter { !removedLines.contains($0.offset) }
            .map(\.element).joined(separator: "\n").utf8)
    }

    public static func bundleKey(sourcePath: String, profile: String) -> String {
        // Hash metadata only. Delimit unambiguously and retain both source and
        // profile identity, including characters lost by key sanitization.
        ProtectedFileImportPlanner.storeKey(forRelativePath: "aws\u{0}" + sourcePath + "\u{0}" + profile)
    }

    public static func command(executable: String, reference: String) throws -> String {
        guard executable.hasPrefix("/"), (try? SecretRef(reference)) != nil else {
            throw AWSCredentialMigrationError.invalidCommand
        }
        func quote(_ value: String) throws -> String {
            guard !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
                  !value.contains("\""), !value.contains("\\") else {
                throw AWSCredentialMigrationError.invalidCommand
            }
            // AWS parses argv, not a shell command. No shell interpolation.
            return "\"" + value + "\""
        }
        return try quote(executable) + " creds aws --item " + quote(reference)
    }

    /// `config` with `[section]` holding exactly `settings` appended, or
    /// unchanged when the section already holds exactly them; nil when the
    /// section exists with anything else, which is never rewritten. For a
    /// profile csec owns entirely, such as a machine identity's sign-in.
    public static func configurationAddingSection(
        _ config: Data, section: String, settings: [String: String]
    ) throws -> (data: Data, changed: Bool)? {
        let ini = try AWSMigrationINI(config)
        if let existing = ini.sections[section] {
            return existing.mapValues(\.value) == settings ? (config, false) : nil
        }
        guard !section.contains("]"), !section.contains("\n"),
              settings.allSatisfy({ !$0.key.contains("=") && !$0.value.contains("\n") }) else {
            throw AWSCredentialMigrationError.invalidDocument
        }
        let newline = ini.lines.contains(where: { $0.hasSuffix("\r") }) ? "\r\n" : "\n"
        var text = String(decoding: config, as: UTF8.self)
        if !text.isEmpty, !text.hasSuffix("\n") { text += newline }
        if !text.isEmpty { text += newline }
        text += "[\(section)]" + newline
        for key in settings.keys.sorted() { text += "\(key) = \(settings[key]!)" + newline }
        return (Data(text.utf8), true)
    }

    /// Shared ordering, independently testable with failing destinations/writes.
    /// A retry can reuse an already-installed identical credential_process.
    public func apply(
        keepPlaintext: Bool,
        validateSources: () throws -> Void,
        commit: ([String: String]) throws -> [String: String],
        writeConfiguration: (Data) throws -> Void,
        writeCredentials: (Data) throws -> Void
    ) throws {
        guard !values.isEmpty else { return }
        try validateSources()
        guard try commit(values) == references else {
            throw AWSCredentialMigrationError.invalidReferences
        }
        try validateSources()
        try writeConfiguration(configuration)
        if !keepPlaintext { try writeCredentials(credentials) }
    }
}

/// Position-preserving INI reader. Reject ambiguous edits instead of guessing
/// which duplicate or multiline value an AWS client will use. Nested config
/// sections (s3/services) are retained verbatim and never rewritten.
private struct AWSMigrationINI {
    struct Entry { let value: String; let line: Int }
    let lines: [String]
    let order: [String]
    let sections: [String: [String: Entry]]
    let headers: [String: Int]

    init(_ data: Data) throws {
        guard data.count <= AWSSharedCredentialsFile.maximumBytes,
              !data.contains(0), let text = String(data: data, encoding: .utf8) else {
            throw AWSCredentialMigrationError.invalidDocument
        }
        lines = text.components(separatedBy: "\n")
        var order: [String] = []
        var sections: [String: [String: Entry]] = [:]
        var headers: [String: Int] = [:]
        var current: String?
        var nestedIndent: Int?
        var previousIndent: Int?
        for (index, raw) in lines.enumerated() {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("[") {
                guard line.hasSuffix("]") else { throw AWSCredentialMigrationError.invalidDocument }
                let name = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                guard !name.isEmpty, !name.contains("["), !name.contains("]"),
                      !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
                      sections[name] == nil, order.count < AWSSharedCredentialsFile.maximumProfiles else {
                    throw AWSCredentialMigrationError.invalidDocument
                }
                sections[name] = [:]
                headers[name] = index
                order.append(name)
                current = name
                nestedIndent = nil
                previousIndent = nil
                continue
            }
            let indentation = raw.prefix(while: { $0 == " " || $0 == "\t" }).count
            if let nestedIndent, indentation > nestedIndent { continue }
            nestedIndent = nil
            guard previousIndent.map({ indentation <= $0 }) ?? true else {
                throw AWSCredentialMigrationError.invalidDocument
            }
            guard let current, let separator = line.firstIndex(of: "=") else {
                throw AWSCredentialMigrationError.invalidDocument
            }
            let key = line[..<separator].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, sections[current]?[key] == nil else {
                throw AWSCredentialMigrationError.invalidDocument
            }
            sections[current]?[key] = Entry(value: value, line: index)
            previousIndent = indentation
            if value.isEmpty, !key.hasPrefix("aws_"), key != "credential_process" {
                nestedIndent = indentation
            }
        }
        self.order = order
        self.sections = sections
        self.headers = headers
    }

    func insertingProcesses(_ commands: [String: String]) -> Data {
        let newline = lines.contains(where: { $0.hasSuffix("\r") }) ? "\r\n" : "\n"
        var insertions: [Int: String] = [:]
        for (section, command) in commands where sections[section]?["credential_process"] == nil {
            if let line = headers[section] {
                // Match the first setting's indentation. Otherwise an indented
                // region/output line would become a continuation of our argv.
                let firstSetting = sections[section]?.values.min(by: { $0.line < $1.line })
                let indent = firstSetting.map { lines[$0.line].prefix(while: { $0 == " " || $0 == "\t" }) } ?? ""
                insertions[line] = indent + "credential_process = " + command
            }
        }
        var result = ""
        for (index, line) in lines.enumerated() {
            result += line
            if index < lines.count - 1 { result += "\n" }
            if let insertion = insertions[index] {
                if index == lines.count - 1 { result += newline }
                result += insertion + newline
            }
        }
        for section in commands.keys.sorted() where headers[section] == nil {
            if !result.isEmpty, !result.hasSuffix("\n") { result += newline }
            result += "[\(section)]" + newline + "credential_process = " + commands[section]! + newline
        }
        return Data(result.utf8)
    }
}
