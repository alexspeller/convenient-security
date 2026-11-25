import ConvenientSecurity
import Foundation

/// The two Phase D primitives: the npm exec-fd preset and the AWS
/// bundle-import side (`renderBundle` + the shared-credentials ini reader).
func awsImportAndNpmPresetTests() {
    print("\n# AWS bundle import + npm preset (bulk-protect Phase D)")

    check(InheritedFilePreset.npm.environmentName == "NPM_CONFIG_USERCONFIG",
          "the npm preset maps to NPM_CONFIG_USERCONFIG")
    check(InheritedFilePreset(rawValue: "npm") == .npm,
          "exec-fd --preset npm=… parses")
    check((try? InheritedFilePreset.npm.render(
              "//registry.npmjs.org/:_authToken=synthetic")) != nil,
          "the npm preset preserves npmrc bytes")

    // renderBundle: sorted flat JSON, no Version, Expiration refused.
    do {
        let bundle = try AWSCredentialProcess.renderBundle(fields: [
            "SecretAccessKey": "synthetic-secret-key",
            "AccessKeyId": "AKIASYNTHETIC",
        ])
        check(!bundle.contains("Version"), "renderBundle emits no Version field")
        check(bundle.range(of: "AccessKeyId")!.lowerBound
                  < bundle.range(of: "SecretAccessKey")!.lowerBound,
              "renderBundle emits sorted keys")

        // Round trip: bundle -> fields -> credential-process JSON.
        let fields = try AWSCredentialProcess.fields(fromBundle: bundle)
        check(fields == [
            "AccessKeyId": "AKIASYNTHETIC",
            "SecretAccessKey": "synthetic-secret-key",
        ], "renderBundle round-trips through fields(fromBundle:)")
        let process = String(
            decoding: try AWSCredentialProcess.render(fields: fields), as: UTF8.self)
        check(process.contains("\"Version\":1"),
              "the process render adds Version:1 on top of the bundle")
    } catch {
        check(false, "renderBundle round trip succeeds (\(error))")
    }

    checkThrows("renderBundle refuses an Expiration key (bundles are long-lived)") {
        _ = try AWSCredentialProcess.renderBundle(fields: [
            "AccessKeyId": "AKIASYNTHETIC",
            "SecretAccessKey": "synthetic-secret-key",
            "Expiration": "2030-01-01T00:00:00Z",
        ])
    }
    checkThrows("renderBundle refuses a missing secret key") {
        _ = try AWSCredentialProcess.renderBundle(fields: ["AccessKeyId": "AKIA"])
    }
    checkThrows("renderBundle refuses newline-bearing values") {
        _ = try AWSCredentialProcess.renderBundle(fields: [
            "AccessKeyId": "AKIA\nBAD", "SecretAccessKey": "k",
        ])
    }

    // The ini reader: static profiles import, derived ones are skipped with
    // their reason, and a session token rides along.
    let ini = """
    # global comment
    [default]
    aws_access_key_id = AKIADEFAULTSTATIC
    aws_secret_access_key = default-secret-value
    region = eu-west-1

    [with-session]
    AWS_ACCESS_KEY_ID = AKIASESSIONSTATIC
    aws_secret_access_key = session-secret-value
    aws_session_token = session-token-value

    [profile sso-team]
    sso_start_url = https://example.awsapps.com/start
    sso_account_id = 123456789012

    [proc]
    credential_process = /usr/local/bin/creds

    [empty-section]
    region = us-east-1
    """
    do {
        let file = try AWSSharedCredentialsFile(data: Data(ini.utf8))
        check(file.profiles.map(\.name)
                  == ["default", "with-session", "sso-team", "proc", "empty-section"],
              "the ini reader keeps profile order and normalizes 'profile ' headings")
        let outcomes = Dictionary(uniqueKeysWithValues: file.importOutcomes())

        guard case .success(let defaultBundle)? = outcomes["default"] else {
            check(false, "the default profile imports"); return
        }
        check(defaultBundle.contains("AKIADEFAULTSTATIC")
                  && !defaultBundle.contains("Version")
                  && !defaultBundle.contains("region"),
              "a static profile becomes a Version-free bundle without non-secret keys")
        let parsed = try AWSCredentialProcess.fields(fromBundle: defaultBundle)
        check(parsed["SecretAccessKey"] == "default-secret-value",
              "the imported bundle parses back to the ini's static secret")

        guard case .success(let sessionBundle)? = outcomes["with-session"] else {
            check(false, "a session-token profile imports"); return
        }
        check((try? AWSCredentialProcess.fields(fromBundle: sessionBundle))?["SessionToken"]
                  == "session-token-value",
              "case-insensitive keys and the session token ride along")

        check(outcomes["sso-team"]
                  == .failure(.derivedCredentials(keys: ["sso_account_id", "sso_start_url"])),
              "an SSO-only profile is skipped with its derived keys named")
        check(outcomes["proc"]
                  == .failure(.derivedCredentials(keys: ["credential_process"])),
              "a credential_process profile is never imported")
        check(outcomes["empty-section"] == .failure(.missingStaticKeys),
              "a profile with no static keys is skipped, not fabricated")
    } catch {
        check(false, "the ini reader parses the fixture (\(error))")
    }

    checkThrows("content before any section heading is rejected") {
        _ = try AWSSharedCredentialsFile(data: Data("aws_access_key_id=AKIA\n".utf8))
    }
    checkThrows("NUL bytes are rejected") {
        _ = try AWSSharedCredentialsFile(data: Data([0x5B, 0x61, 0x5D, 0x0A, 0x00]))
    }
}
