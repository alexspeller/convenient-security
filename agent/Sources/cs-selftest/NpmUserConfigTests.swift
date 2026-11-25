import ConvenientSecurity
import Foundation

/// The npm userconfig split: only literal auth lines move to the store, every
/// other byte stays in place, the rewritten file is no longer a discovery
/// finding, and `exec-fd --preset npm` puts the lines back at npm's top level.
func npmUserConfigTests() {
    print("\n# npm userconfig split and merge")
    let token = "npm-split-synthetic-token"
    let source = "; my settings\r\n"
        + "min-release-age=7\r\n"
        + "//registry.npmjs.org/:_authToken=\(token)\r\n"
        + "ignore-scripts=true\r\n"
        + "//npm.example.test/:_auth = \"c3ludGhldGlj\"\r\n"
        + "//npm.example.test/:_password=${NPM_PASSWORD}\r\n"
        + "# //registry.npmjs.org/:_authToken=commented-out\r\n"
        + "registry=https://registry.npmjs.org/"

    check(NpmUserConfig.containsLiteralAuth(Data(source.utf8)),
          "the discovery gate finds a token in a CRLF config")
    do {
        let split = try NpmUserConfig.split(Data(source.utf8))
        check(split.authLineCount == 2
              && split.authLines == "//registry.npmjs.org/:_authToken=\(token)\r\n"
                + "//npm.example.test/:_auth = \"c3ludGhldGlj\"\r\n",
              "the split moves exactly the literal auth lines, byte for byte")
        for reference in ["csec://home/NPMRC_AUTH", "op://Private/bulk-protect/NPMRC_AUTH"] {
            let rewritten = String(decoding: split.rewritten(reference: reference), as: UTF8.self)
            check(!rewritten.contains(token) && !rewritten.contains("c3ludGhldGlj"),
                  "the rewritten file holds no credential (\(reference.prefix(4)))")
            check(rewritten == "; my settings\r\n"
                    + "min-release-age=7\r\n"
                    + "; csec: auth lines moved to \(reference); "
                    + "use them with: csec exec-fd --preset npm=\(reference) -- npm <command>\n"
                    + "ignore-scripts=true\r\n"
                    + "//npm.example.test/:_password=${NPM_PASSWORD}\r\n"
                    + "# //registry.npmjs.org/:_authToken=commented-out\r\n"
                    + "registry=https://registry.npmjs.org/",
                  "every other line, placeholder and comment stays in place, with the marker "
                    + "where the first auth line was (\(reference.prefix(4)))")
            check(!NpmUserConfig.containsLiteralAuth(Data(rewritten.utf8)),
                  "the rewritten file no longer passes the npm discovery gate (\(reference.prefix(4)))")
        }

        let trailing = try NpmUserConfig.split(Data("save-exact=true\n_authToken=\(token)".utf8))
        check(trailing.authLines == "_authToken=\(token)\n"
              && String(decoding: trailing.rewritten(reference: "csec://home/K"), as: UTF8.self)
                == "save-exact=true\n; csec: auth lines moved to csec://home/K; "
                    + "use them with: csec exec-fd --preset npm=csec://home/K -- npm <command>\n",
              "an unterminated last auth line is stored terminated and replaced by the marker")
    } catch {
        check(false, "the npm split accepts a mixed userconfig (\(error))")
    }

    func splitError(_ text: String) -> NpmUserConfigError? {
        do { _ = try NpmUserConfig.split(Data(text.utf8)); return nil }
        catch { return error as? NpmUserConfigError }
    }
    check(splitError("[scope]\n//registry.npmjs.org/:_authToken=\(token)\n") == .authInsideSection,
          "an auth line inside an ini section is refused, not moved")
    check(splitError("registry=https://x\n//r/:_authToken=${NPM_TOKEN}\n_auth=\n") == .noAuthLines,
          "a config with only placeholders or empty auth has nothing to split")
    check(splitError("_authToken=a\u{0}b\n") == .notText,
          "a NUL-bearing config is refused")

    do {
        let auth = Data("//registry.npmjs.org/:_authToken=\(token)\n".utf8)
        let sectioned = try NpmUserConfig.merged(
            liveConfig: Data("min-release-age=7\nignore-scripts=true\n[other]\nkey=value\n".utf8),
            authLines: auth)
        check(String(decoding: sectioned, as: UTF8.self)
                == "min-release-age=7\nignore-scripts=true\n"
                    + "//registry.npmjs.org/:_authToken=\(token)\n[other]\nkey=value\n",
              "the merge puts the auth lines after the top-level settings, before the first section")
        let unterminated = try NpmUserConfig.merged(
            liveConfig: Data("min-release-age=7".utf8), authLines: auth)
        check(String(decoding: unterminated, as: UTF8.self)
                == "min-release-age=7\n//registry.npmjs.org/:_authToken=\(token)\n",
              "the merge terminates an unterminated live config before the auth lines")
        check(try NpmUserConfig.merged(liveConfig: nil, authLines: auth) == auth,
              "with no live config the stored lines stand alone (a whole-file value keeps working)")
        check(NpmUserConfig.credentialValues(in: Data(
                "//a/:_authToken=\(token)\n//b/:_auth='second-synthetic'\nregistry=x\n".utf8))
                == [token, "second-synthetic"],
              "each stored credential is offered to output masking on its own")
    } catch {
        check(false, "the npm merge accepts text configs (\(error))")
    }
    check((try? NpmUserConfig.merged(
            liveConfig: Data(repeating: 0x61, count: InheritedFilePreset.maximumFileBytes),
            authLines: Data("_authToken=x\n".utf8))) == nil,
          "the merged config stays within the inherited-file limit")

    check((try? NpmUserConfig.validateLiveConfig(Data("min-release-age=7\n".utf8))) != nil
          && (try? NpmUserConfig.validateLiveConfig(Data("a=b\u{0}\n".utf8))) == nil,
          "a live config is checked as text before the access request")

    let home = "/synthetic/home"
    check(NpmUserConfig.liveConfigPath(environment: [:], homeDirectory: home) == home + "/.npmrc",
          "the live config defaults to ~/.npmrc")
    check(NpmUserConfig.liveConfigPath(
            environment: ["npm_config_userconfig": "/x/lower", "NPM_CONFIG_USERCONFIG": "/x/upper"],
            homeDirectory: home) == "/x/upper",
          "the canonical override spelling wins over another case")
    check(NpmUserConfig.liveConfigPath(
            environment: ["npm_config_userconfig": "/x/lower"], homeDirectory: home) == "/x/lower",
          "npm's lower-case override is honoured")
    check(NpmUserConfig.liveConfigPath(
            environment: ["NPM_CONFIG_USERCONFIG": "/dev/fd/64"], homeDirectory: home) == home + "/.npmrc",
          "an enclosing exec-fd descriptor is never read (it would drain); ~/.npmrc is")
}
