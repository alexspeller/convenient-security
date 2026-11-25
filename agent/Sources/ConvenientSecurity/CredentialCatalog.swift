import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// How a discovered credential file is best protected and delivered. Shared
/// between the credential catalog (each entry's native delivery) and
/// discovery's per-file suggestion, so the two cannot drift.
public enum CredentialDelivery: Sendable, Equatable {
    /// Rewrite secret-like assignments in place to references (`protect --env`).
    case perVar
    /// Encrypt the whole file into the blob tier with a sidecar (`protect`).
    case wholeFile
    /// Import the key and serve signatures via the csec SSH agent
    /// (`protect --ssh`).
    case sshKey
    /// Import the profile as a credential-process bundle (`csec creds aws`).
    case credsAws
    /// Keep the file whole in the store and materialize it at exec time with a
    /// path-bearing environment variable (`exec-fd --preset …`). `preset` names
    /// an existing/planned preset; `pathEnvironmentVariable` documents the
    /// variable for presets that do not exist yet (apply falls back to
    /// whole-file plus a recipe naming the variable).
    case filePreset(preset: String, pathEnvironmentVariable: String?)
    /// A token file whose tool also reads the token from these variables.
    /// No field is extracted yet: the file is protected whole-file, and its
    /// path-bound sidecar materializes it under `csec exec`.
    case envToken(variables: [String])
    /// The Fly.io CLI's config: the token moves into a reference that
    /// `csec fly` delivers in `FLY_API_TOKEN`, and the file keeps everything
    /// else (`protect --fly`).
    case flyToken
}

/// A cheap, value-free-in-effect content gate deciding whether a probed file
/// actually holds credential material (reading the bytes is fine — nothing is
/// displayed or retained; the gate only sets membership).
public enum CredentialContentGate: Sendable, Equatable {
    /// The file's presence is the finding.
    case always
    /// A non-empty first line (single-token files such as HuggingFace's).
    case nonEmptyFirstLine
    /// Case-insensitive substring match on the raw bytes (any of).
    case containsAny([String])
    /// npm auth properties with literal values, excluding ${ENV} placeholders.
    case npmAuth
    /// Docker/Podman-style `auths` map with at least one populated
    /// `auth`/`identitytoken` entry. Base64 is an encoding, not protection.
    case populatedDockerAuths
    /// KEY=VALUE / properties-style lines where some key contains a
    /// password/token/secret/key word and carries a non-empty value.
    case propertiesWithSecretKey
    /// JSON or single-line YAML/TOML assignments with a literal credential,
    /// excluding canonical references and environment-variable placeholders.
    case literalCredentialAssignments
    case solanaKeypair
    case ethereumKeystore
    /// YAML `key: value` lines where one of `keys` (exact, case-insensitive,
    /// at any nesting) carries a literal value. Empty/null values, `${VAR}`
    /// placeholders and values starting with one of `ignoringValuePrefixes`
    /// (a tool's keychain reference, e.g. gcx's `keychain:gcx:…`) are not
    /// plaintext credentials.
    case literalYAMLValues(keys: [String], ignoringValuePrefixes: [String])
}

/// One standard credential location, described as data so covering another
/// tool is a data change, not code. macOS paths are first-class: many CLIs
/// (Go `os.UserConfigDir`, node `env-paths`) resolve to `~/Library/…` on
/// Darwin, not `~/.config`.
public struct KnownCredentialFile: Sendable {
    public let id: String
    public let displayName: String
    /// Home-relative (`~/…`) or absolute path templates, most specific /
    /// most current first. A single `*` component expands one directory level
    /// at probe time.
    public let pathTemplates: [String]
    /// Environment overrides that relocate the file: the variable's value
    /// replaces `$VALUE` in the paired template and takes precedence over
    /// `pathTemplates`.
    public let environmentOverrides: [CredentialPathOverride]
    public let kind: SecretFileKind
    public let delivery: CredentialDelivery
    /// True when the tool keeps its secret in the macOS Keychain by default,
    /// so a *present* plaintext file is a degraded-posture finding — flagged
    /// and offered for protection, never silently expected.
    public let keychainDefaultOnMacOS: Bool
    public let contentGate: CredentialContentGate
    /// True when the tool saves this file during ordinary commands (an OAuth
    /// refresh, a per-run state or telemetry write, a project link), not only
    /// on an explicit login or config command. Whole-file protection cannot
    /// serve such a file: `csec exec` materializes a read-only tmpfs copy
    /// behind a symlink, so the save either fails (breaking the command, and
    /// losing a rotated refresh token) or renames a new file over the link,
    /// putting the plaintext back. Bulk protect therefore skips it unless the
    /// user chooses whole-file. Each flag rests on a source audit of the tool.
    public let toolRewritesFile: Bool
    /// The command names (`argv[0]`'s base name) whose ordinary runs read this
    /// file. `csec exec -- <command>` restores the file's protected copy at its
    /// home path from any directory, so the tool is not left logged out when it
    /// runs from a project. Empty for files no command reads unaided (and for
    /// the `toolRewritesFile` tools, which whole-file protection cannot serve);
    /// `csec exec --with-file` names one by path.
    public let commands: [String]

    public init(
        id: String,
        displayName: String,
        pathTemplates: [String],
        environmentOverrides: [CredentialPathOverride] = [],
        kind: SecretFileKind = .toolCredential,
        delivery: CredentialDelivery,
        keychainDefaultOnMacOS: Bool = false,
        contentGate: CredentialContentGate = .always,
        toolRewritesFile: Bool = false,
        commands: [String] = []
    ) {
        self.id = id
        self.displayName = displayName
        self.pathTemplates = pathTemplates
        self.environmentOverrides = environmentOverrides
        self.kind = kind
        self.delivery = delivery
        self.keychainDefaultOnMacOS = keychainDefaultOnMacOS
        self.contentGate = contentGate
        self.toolRewritesFile = toolRewritesFile
        self.commands = commands
    }
}

public struct CredentialPathOverride: Sendable, Equatable {
    /// Environment variable consulted at probe time.
    public let variable: String
    /// Template the variable's value lands in via `$VALUE` (`"$VALUE"` when
    /// the variable names the file itself, `"$VALUE/config.json"` when it
    /// names a directory).
    public let template: String

    public init(_ variable: String, _ template: String) {
        self.variable = variable
        self.template = template
    }
}

/// The seed catalog: source-verified standard credential files. Probed by
/// absolute path, deliberately bypassing the general walk's exclusions —
/// the only reliable way to reach credentials inside excluded trees
/// (`~/.cache`, `~/Library/**`, `~/.cargo`, `~/.m2`, `~/.gradle`).
/// Tools that are environment-variable-only (OpenAI, Anthropic, Cohere, Groq,
/// Mistral, Together, Perplexity, xAI, DeepSeek, OpenRouter, Fireworks) have
/// no file to probe; their tokens surface through scanned env files instead.
public enum CredentialCatalog {
    public static let entries: [KnownCredentialFile] = [
        // MARK: env-token — token files, protected whole-file until extraction exists
        // `toolRewritesFile` marks the tools that save their file during ordinary
        // commands; they are skipped by default. `commands` name the tools that
        // read the rest, so `csec exec` restores them from any directory.
        KnownCredentialFile(
            id: "huggingface-token", displayName: "Hugging Face token",
            pathTemplates: ["~/.cache/huggingface/token"],
            environmentOverrides: [
                CredentialPathOverride("HF_TOKEN_PATH", "$VALUE"),
                CredentialPathOverride("HF_HOME", "$VALUE/token"),
            ],
            delivery: .envToken(variables: ["HF_TOKEN"]),
            contentGate: .nonEmptyFirstLine,
            commands: ["hf", "huggingface-cli"]
        ),
        KnownCredentialFile(
            id: "vault", displayName: "HashiCorp Vault token",
            pathTemplates: ["~/.vault-token"],
            delivery: .envToken(variables: ["VAULT_TOKEN"]),
            contentGate: .nonEmptyFirstLine,
            commands: ["vault", "vault-client"]
        ),
        // flyctl rewrites config.yml during ordinary commands, so its token is
        // taken out of the file instead; an emptied token is no finding.
        KnownCredentialFile(
            id: "fly", displayName: "Fly.io API token",
            pathTemplates: ["~/.fly/config.yml"],
            environmentOverrides: [CredentialPathOverride("FLY_CONFIG_DIR", "$VALUE/config.yml")],
            delivery: .flyToken,
            contentGate: .literalYAMLValues(keys: ["access_token"], ignoringValuePrefixes: []),
            toolRewritesFile: true
        ),
        KnownCredentialFile(
            id: "stripe", displayName: "Stripe CLI key",
            pathTemplates: ["~/.config/stripe/config.toml"],
            environmentOverrides: [
                CredentialPathOverride("XDG_CONFIG_HOME", "$VALUE/stripe/config.toml"),
            ],
            delivery: .envToken(variables: ["STRIPE_API_KEY"]),
            contentGate: .containsAny(["key ", "key="]),
            toolRewritesFile: true
        ),
        KnownCredentialFile(
            id: "netlify", displayName: "Netlify auth token",
            pathTemplates: [
                "~/Library/Preferences/netlify/config.json",
                "~/.config/netlify/config.json",
            ],
            delivery: .envToken(variables: ["NETLIFY_AUTH_TOKEN"]),
            contentGate: .containsAny(["token"]),
            toolRewritesFile: true
        ),
        KnownCredentialFile(
            id: "vercel", displayName: "Vercel CLI token",
            pathTemplates: [
                "~/Library/Application Support/com.vercel.cli/auth.json",
                "~/.local/share/com.vercel.cli/auth.json",
            ],
            delivery: .envToken(variables: ["VERCEL_TOKEN"]),
            contentGate: .containsAny(["token"]),
            toolRewritesFile: true
        ),
        KnownCredentialFile(
            id: "doctl", displayName: "DigitalOcean doctl token",
            pathTemplates: [
                "~/Library/Application Support/doctl/config.yaml",
                "~/.config/doctl/config.yaml",
            ],
            delivery: .envToken(variables: ["DIGITALOCEAN_ACCESS_TOKEN"]),
            contentGate: .containsAny(["access-token"]),
            commands: ["doctl"]
        ),
        KnownCredentialFile(
            id: "wrangler", displayName: "Cloudflare Wrangler token",
            pathTemplates: [
                "~/Library/Preferences/.wrangler/config/default.toml",
                "~/.wrangler/config/default.toml",
            ],
            environmentOverrides: [
                CredentialPathOverride("WRANGLER_HOME", "$VALUE/config/default.toml"),
            ],
            delivery: .envToken(variables: ["CLOUDFLARE_API_TOKEN"]),
            contentGate: .containsAny(["oauth_token", "api_token"]),
            toolRewritesFile: true
        ),
        KnownCredentialFile(
            id: "pulumi", displayName: "Pulumi access token",
            pathTemplates: ["~/.pulumi/credentials.json"],
            environmentOverrides: [
                CredentialPathOverride("PULUMI_HOME", "$VALUE/credentials.json"),
            ],
            delivery: .envToken(variables: ["PULUMI_ACCESS_TOKEN"]),
            contentGate: .containsAny(["accessToken"]),
            toolRewritesFile: true
        ),
        KnownCredentialFile(
            id: "railway", displayName: "Railway token",
            pathTemplates: ["~/.railway/config.json"],
            delivery: .envToken(variables: ["RAILWAY_TOKEN"]),
            contentGate: .containsAny(["token"]),
            toolRewritesFile: true
        ),
        KnownCredentialFile(
            id: "render", displayName: "Render API key",
            pathTemplates: ["~/.render/cli.yaml"],
            delivery: .envToken(variables: ["RENDER_API_KEY"]),
            contentGate: .containsAny(["apikey", "api_key"]),
            toolRewritesFile: true
        ),
        KnownCredentialFile(
            id: "sentry", displayName: "Sentry auth token",
            pathTemplates: ["~/.sentryclirc"],
            delivery: .envToken(variables: ["SENTRY_AUTH_TOKEN"]),
            contentGate: .containsAny(["token"]),
            commands: ["sentry-cli"]
        ),
        KnownCredentialFile(
            id: "databricks", displayName: "Databricks token",
            pathTemplates: ["~/.databrickscfg"],
            delivery: .envToken(variables: ["DATABRICKS_TOKEN"]),
            contentGate: .containsAny(["token", "password"]),
            commands: ["databricks"]
        ),
        KnownCredentialFile(
            id: "scaleway", displayName: "Scaleway secret key",
            pathTemplates: ["~/.config/scw/config.yaml"],
            delivery: .envToken(variables: ["SCW_SECRET_KEY"]),
            contentGate: .containsAny(["secret_key"]),
            commands: ["scw"]
        ),
        KnownCredentialFile(
            id: "linode", displayName: "Linode CLI token",
            pathTemplates: ["~/.config/linode-cli"],
            delivery: .envToken(variables: ["LINODE_CLI_TOKEN"]),
            contentGate: .containsAny(["token"]),
            commands: ["linode-cli", "linode", "lin"]
        ),
        KnownCredentialFile(
            id: "neon", displayName: "Neon API key",
            pathTemplates: ["~/.config/neonctl/credentials.json"],
            delivery: .envToken(variables: ["NEON_API_KEY"]),
            contentGate: .containsAny(["token", "key"]),
            toolRewritesFile: true
        ),
        KnownCredentialFile(
            id: "hetzner", displayName: "Hetzner Cloud token",
            pathTemplates: ["~/.config/hcloud/cli.toml"],
            delivery: .envToken(variables: ["HCLOUD_TOKEN"]),
            contentGate: .containsAny(["token"]),
            commands: ["hcloud"]
        ),
        KnownCredentialFile(
            id: "firebase", displayName: "Firebase CLI token",
            pathTemplates: ["~/.config/configstore/firebase-tools.json"],
            delivery: .envToken(variables: ["FIREBASE_TOKEN"]),
            contentGate: .containsAny(["tokens", "refresh_token"]),
            toolRewritesFile: true
        ),
        KnownCredentialFile(
            id: "datadog", displayName: "Datadog dogrc keys",
            pathTemplates: ["~/.dogrc"],
            delivery: .envToken(variables: ["DD_API_KEY", "DD_APP_KEY"]),
            contentGate: .containsAny(["apikey", "appkey"]),
            commands: ["dog", "dogshell"]
        ),
        KnownCredentialFile(
            id: "pypi", displayName: "PyPI upload token",
            pathTemplates: ["~/.pypirc"],
            delivery: .envToken(variables: ["TWINE_PASSWORD"]),
            contentGate: .containsAny(["password"]),
            commands: ["twine", "hatch", "flit"]
        ),
        KnownCredentialFile(
            id: "cargo", displayName: "Cargo registry token",
            pathTemplates: ["~/.cargo/credentials.toml", "~/.cargo/credentials"],
            environmentOverrides: [
                CredentialPathOverride("CARGO_HOME", "$VALUE/credentials.toml"),
            ],
            delivery: .envToken(variables: ["CARGO_REGISTRY_TOKEN"]),
            contentGate: .containsAny(["token"]),
            commands: ["cargo"]
        ),
        KnownCredentialFile(
            id: "kaggle", displayName: "Kaggle API credentials",
            pathTemplates: ["~/.kaggle/kaggle.json", "~/.config/kaggle/kaggle.json"],
            environmentOverrides: [
                CredentialPathOverride("KAGGLE_CONFIG_DIR", "$VALUE/kaggle.json"),
            ],
            delivery: .envToken(variables: ["KAGGLE_USERNAME", "KAGGLE_KEY"]),
            contentGate: .containsAny(["key"]),
            commands: ["kaggle"]
        ),
        KnownCredentialFile(
            // Deprecated for gcx, but its config stays behind. Plaintext
            // always; macOS location is adrg/xdg's ~/Library/Application Support.
            id: "grafanactl", displayName: "Grafana CLI (grafanactl) config",
            pathTemplates: [
                "~/Library/Application Support/grafanactl/config.yaml",
                "~/.config/grafanactl/config.yaml",
            ],
            environmentOverrides: [
                CredentialPathOverride("GRAFANACTL_CONFIG", "$VALUE"),
                CredentialPathOverride("XDG_CONFIG_HOME", "$VALUE/grafanactl/config.yaml"),
            ],
            delivery: .envToken(variables: ["GRAFANA_TOKEN"]),
            contentGate: grafanaConfigGate,
            commands: ["grafanactl"]
        ),
        KnownCredentialFile(
            id: "supabase", displayName: "Supabase access token",
            pathTemplates: ["~/.supabase/access-token"],
            delivery: .envToken(variables: ["SUPABASE_ACCESS_TOKEN"]),
            keychainDefaultOnMacOS: true,
            contentGate: .nonEmptyFirstLine,
            commands: ["supabase"]
        ),

        // MARK: file-preset — keep the file whole, deliver via a path variable
        KnownCredentialFile(
            id: "pgpass", displayName: "PostgreSQL password file",
            pathTemplates: ["~/.pgpass"],
            environmentOverrides: [CredentialPathOverride("PGPASSFILE", "$VALUE")],
            delivery: .filePreset(preset: "pgpass", pathEnvironmentVariable: "PGPASSFILE"),
            contentGate: .nonEmptyFirstLine
        ),
        KnownCredentialFile(
            id: "pgservice", displayName: "PostgreSQL service file",
            pathTemplates: ["~/.pg_service.conf"],
            environmentOverrides: [CredentialPathOverride("PGSERVICEFILE", "$VALUE")],
            delivery: .filePreset(preset: "pgservice", pathEnvironmentVariable: "PGSERVICEFILE"),
            contentGate: .containsAny(["password"])
        ),
        KnownCredentialFile(
            id: "kubeconfig", displayName: "kubeconfig",
            pathTemplates: ["~/.kube/config"],
            delivery: .filePreset(preset: "kubeconfig", pathEnvironmentVariable: "KUBECONFIG"),
            contentGate: .containsAny([
                "client-key-data", "client-certificate-data", "token:", "password:",
            ])
        ),
        KnownCredentialFile(
            id: "gcp-adc", displayName: "Google Cloud application default credentials",
            pathTemplates: [
                "~/.config/gcloud/application_default_credentials.json",
                "~/.config/gcloud/legacy_credentials/*/adc.json",
            ],
            environmentOverrides: [
                CredentialPathOverride(
                    "CLOUDSDK_CONFIG", "$VALUE/application_default_credentials.json"),
            ],
            delivery: .filePreset(
                preset: "google-service-account",
                pathEnvironmentVariable: "GOOGLE_APPLICATION_CREDENTIALS"),
            contentGate: .containsAny(["refresh_token", "private_key"])
        ),
        KnownCredentialFile(
            id: "gh", displayName: "GitHub CLI hosts",
            pathTemplates: ["~/.config/gh/hosts.yml"],
            environmentOverrides: [
                CredentialPathOverride("GH_CONFIG_DIR", "$VALUE/hosts.yml"),
            ],
            delivery: .filePreset(preset: "gh-config", pathEnvironmentVariable: nil),
            keychainDefaultOnMacOS: true,
            contentGate: .containsAny(["oauth_token"])
        ),
        KnownCredentialFile(
            id: "npm", displayName: "npm userconfig",
            pathTemplates: ["~/.npmrc"],
            environmentOverrides: [
                CredentialPathOverride("NPM_CONFIG_USERCONFIG", "$VALUE"),
            ],
            delivery: .filePreset(preset: "npm", pathEnvironmentVariable: "NPM_CONFIG_USERCONFIG"),
            contentGate: .npmAuth
        ),
        KnownCredentialFile(
            id: "cloudflared", displayName: "cloudflared tunnel credentials",
            pathTemplates: ["~/.cloudflared/cert.pem", "~/.cloudflared/*.json"],
            delivery: .filePreset(
                preset: "cloudflared", pathEnvironmentVariable: "TUNNEL_ORIGIN_CERT"),
            contentGate: .always
        ),
        KnownCredentialFile(
            id: "oci", displayName: "Oracle Cloud API key",
            pathTemplates: ["~/.oci/*.pem"],
            kind: .keyMaterial,
            delivery: .filePreset(preset: "oci-key", pathEnvironmentVariable: "OCI_CLI_KEY_FILE"),
            contentGate: .containsAny(["private key"])
        ),
        KnownCredentialFile(
            id: "rclone", displayName: "rclone remotes",
            pathTemplates: ["~/.config/rclone/rclone.conf"],
            environmentOverrides: [CredentialPathOverride("RCLONE_CONFIG", "$VALUE")],
            delivery: .filePreset(preset: "rclone", pathEnvironmentVariable: "RCLONE_CONFIG"),
            contentGate: .containsAny(["pass", "token", "key"])
        ),

        // MARK: whole-file — multi-profile / opaque / no clean single variable
        KnownCredentialFile(
            id: "quic", displayName: "Quic credentials",
            pathTemplates: ["~/.config/quic/config.json"],
            delivery: .wholeFile,
            contentGate: .literalCredentialAssignments
        ),
        KnownCredentialFile(
            id: "av", displayName: "av credentials",
            pathTemplates: ["~/.config/av/config.yaml"],
            delivery: .wholeFile,
            contentGate: .literalCredentialAssignments
        ),
        KnownCredentialFile(
            id: "cb", displayName: "Crunchy Bridge CLI credentials",
            pathTemplates: ["~/.config/cb/api.crunchybridge.com"],
            delivery: .wholeFile,
            contentGate: .nonEmptyFirstLine
        ),
        KnownCredentialFile(
            id: "runpod", displayName: "Runpod credentials",
            pathTemplates: ["~/.runpod/config.toml"],
            delivery: .wholeFile,
            contentGate: .literalCredentialAssignments
        ),
        KnownCredentialFile(
            id: "solana", displayName: "Solana keypair",
            pathTemplates: ["~/.config/solana/id.json"],
            kind: .keyMaterial, delivery: .wholeFile,
            contentGate: .solanaKeypair
        ),
        KnownCredentialFile(
            id: "ethereum-keystore", displayName: "Ethereum key store",
            pathTemplates: ["~/Library/Ethereum/keystore/UTC--*", "~/.ethereum/keystore/UTC--*"],
            kind: .keyMaterial, delivery: .wholeFile,
            contentGate: .ethereumKeystore
        ),
        KnownCredentialFile(
            id: "aws", displayName: "AWS shared credentials",
            pathTemplates: ["~/.aws/credentials"],
            environmentOverrides: [
                CredentialPathOverride("AWS_SHARED_CREDENTIALS_FILE", "$VALUE"),
            ],
            delivery: .credsAws,
            contentGate: .containsAny(["aws_secret_access_key"])
        ),
        KnownCredentialFile(
            id: "azure", displayName: "Azure CLI token cache",
            pathTemplates: [
                "~/.azure/msal_token_cache.json",
                "~/.azure/service_principal_entries.json",
            ],
            delivery: .wholeFile
        ),
        KnownCredentialFile(
            id: "docker", displayName: "Docker registry auths",
            pathTemplates: ["~/.docker/config.json"],
            environmentOverrides: [
                CredentialPathOverride("DOCKER_CONFIG", "$VALUE/config.json"),
            ],
            delivery: .wholeFile,
            keychainDefaultOnMacOS: true,
            contentGate: .populatedDockerAuths
        ),
        KnownCredentialFile(
            id: "podman", displayName: "Podman registry auths",
            pathTemplates: ["~/.config/containers/auth.json"],
            environmentOverrides: [
                CredentialPathOverride("REGISTRY_AUTH_FILE", "$VALUE"),
            ],
            delivery: .wholeFile,
            contentGate: .populatedDockerAuths
        ),
        KnownCredentialFile(
            id: "gcloud-db", displayName: "gcloud credential databases",
            pathTemplates: [
                "~/.config/gcloud/credentials.db",
                "~/.config/gcloud/access_tokens.db",
            ],
            environmentOverrides: [
                CredentialPathOverride("CLOUDSDK_CONFIG", "$VALUE/credentials.db"),
            ],
            delivery: .wholeFile
        ),
        KnownCredentialFile(
            id: "huggingface-stored", displayName: "Hugging Face stored tokens",
            pathTemplates: ["~/.cache/huggingface/stored_tokens"],
            environmentOverrides: [
                CredentialPathOverride("HF_HOME", "$VALUE/stored_tokens"),
            ],
            delivery: .wholeFile
        ),
        KnownCredentialFile(
            id: "snowflake", displayName: "Snowflake connections",
            pathTemplates: [
                "~/.snowflake/connections.toml",
                "~/Library/Application Support/snowflake/connections.toml",
            ],
            delivery: .wholeFile,
            contentGate: .containsAny(["password", "token", "private_key"])
        ),
        KnownCredentialFile(
            id: "maven", displayName: "Maven settings",
            pathTemplates: ["~/.m2/settings.xml"],
            delivery: .wholeFile,
            contentGate: .containsAny(["<password", "<passphrase"])
        ),
        KnownCredentialFile(
            id: "gradle", displayName: "Gradle properties",
            pathTemplates: ["~/.gradle/gradle.properties"],
            environmentOverrides: [
                CredentialPathOverride("GRADLE_USER_HOME", "$VALUE/gradle.properties"),
            ],
            delivery: .wholeFile,
            contentGate: .propertiesWithSecretKey
        ),
        KnownCredentialFile(
            id: "netrc", displayName: "netrc",
            pathTemplates: ["~/.netrc"],
            environmentOverrides: [CredentialPathOverride("NETRC", "$VALUE")],
            delivery: .wholeFile,
            contentGate: .containsAny(["password"])
        ),
        KnownCredentialFile(
            id: "git-credentials", displayName: "git credential store",
            pathTemplates: ["~/.git-credentials", "~/.config/git/credentials"],
            delivery: .wholeFile
        ),
        KnownCredentialFile(
            id: "mysql", displayName: "MySQL client config",
            pathTemplates: ["~/.my.cnf"],
            delivery: .wholeFile,
            contentGate: .containsAny(["password"])
        ),
        KnownCredentialFile(
            id: "mylogin", displayName: "MySQL login-path file",
            pathTemplates: ["~/.mylogin.cnf"],
            delivery: .wholeFile
        ),
        KnownCredentialFile(
            id: "rubygems", displayName: "RubyGems API key",
            pathTemplates: ["~/.gem/credentials"],
            delivery: .wholeFile,
            contentGate: .containsAny(["api_key"])
        ),
        KnownCredentialFile(
            id: "bundler", displayName: "Bundler private-source credentials",
            pathTemplates: ["~/.bundle/config"],
            delivery: .wholeFile,
            contentGate: .containsAny(["__"])
        ),
        KnownCredentialFile(
            id: "composer", displayName: "Composer auth",
            pathTemplates: [
                "~/.config/composer/auth.json",
                "~/.composer/auth.json",
            ],
            environmentOverrides: [
                CredentialPathOverride("COMPOSER_HOME", "$VALUE/auth.json"),
            ],
            delivery: .wholeFile,
            contentGate: .containsAny(["token", "password"])
        ),
        KnownCredentialFile(
            id: "nuget", displayName: "NuGet config",
            pathTemplates: ["~/.nuget/NuGet/NuGet.Config"],
            delivery: .wholeFile,
            contentGate: .containsAny(["password", "apikey"])
        ),
        KnownCredentialFile(
            id: "helm", displayName: "Helm registry auths",
            pathTemplates: [
                "~/Library/Preferences/helm/registry/config.json",
                "~/.config/helm/registry/config.json",
            ],
            delivery: .wholeFile,
            contentGate: .populatedDockerAuths
        ),
        KnownCredentialFile(
            id: "uv", displayName: "uv index credentials",
            pathTemplates: [
                "~/Library/Application Support/uv/credentials/credentials.toml",
                "~/.local/share/uv/credentials/credentials.toml",
            ],
            delivery: .wholeFile
        ),
        KnownCredentialFile(
            id: "codex", displayName: "Codex CLI auth",
            pathTemplates: ["~/.codex/auth.json"],
            environmentOverrides: [
                CredentialPathOverride("CODEX_HOME", "$VALUE/auth.json"),
            ],
            delivery: .wholeFile
        ),
        KnownCredentialFile(
            id: "authinfo", displayName: "Emacs authinfo",
            // `.authinfo.gpg` is already encrypted and deliberately not probed.
            pathTemplates: ["~/.authinfo"],
            delivery: .wholeFile,
            contentGate: .containsAny(["password"])
        ),
        KnownCredentialFile(
            id: "ollama", displayName: "Ollama signing key",
            pathTemplates: ["~/.ollama/id_ed25519"],
            kind: .keyMaterial,
            // A signing key with no agent path: whole-file, not the SSH agent.
            delivery: .wholeFile
        ),

        // MARK: keychain-default tools — a present plaintext fallback file is
        // a degraded-posture finding, flagged and offered for protection.
        KnownCredentialFile(
            id: "claude-code", displayName: "Claude Code credentials",
            pathTemplates: ["~/.claude/.credentials.json"],
            delivery: .wholeFile,
            keychainDefaultOnMacOS: true
        ),
        KnownCredentialFile(
            id: "glab", displayName: "GitLab CLI config",
            pathTemplates: ["~/.config/glab-cli/config.yml"],
            delivery: .wholeFile,
            keychainDefaultOnMacOS: true,
            contentGate: .containsAny(["token:"])
        ),
        KnownCredentialFile(
            id: "gemini", displayName: "Gemini CLI oauth cache",
            pathTemplates: ["~/.gemini/oauth_creds.json"],
            delivery: .wholeFile,
            keychainDefaultOnMacOS: true
        ),
        KnownCredentialFile(
            id: "copilot", displayName: "GitHub Copilot CLI hosts",
            pathTemplates: [
                "~/.config/github-copilot/hosts.json",
                "~/.config/github-copilot/apps.json",
            ],
            delivery: .wholeFile,
            keychainDefaultOnMacOS: true,
            contentGate: .containsAny(["oauth_token"])
        ),
        KnownCredentialFile(
            id: "poetry", displayName: "Poetry auth",
            pathTemplates: ["~/Library/Application Support/pypoetry/auth.toml"],
            delivery: .wholeFile,
            keychainDefaultOnMacOS: true
        ),
        KnownCredentialFile(
            // `gcx login` keeps secrets in the Keychain and leaves
            // `keychain:gcx:…` references in the config; plaintext appears
            // only under GCX_KEYCHAIN=off or `credentials.keychain: off`.
            // ~/.config is checked before adrg/xdg's macOS directory. gcx
            // saves this file during ordinary commands (OAuth refresh, cached
            // datasource UIDs and provider settings, legacy-format migration,
            // which first copies the old file beside it), so it is skipped.
            id: "gcx", displayName: "Grafana CLI (gcx) config",
            pathTemplates: [
                "~/.config/gcx/config.yaml",
                "~/Library/Application Support/gcx/config.yaml",
            ],
            environmentOverrides: [
                CredentialPathOverride("GCX_CONFIG", "$VALUE"),
                CredentialPathOverride("XDG_CONFIG_HOME", "$VALUE/gcx/config.yaml"),
            ],
            delivery: .envToken(variables: ["GRAFANA_TOKEN", "GRAFANA_CLOUD_TOKEN"]),
            keychainDefaultOnMacOS: true,
            contentGate: grafanaConfigGate,
            toolRewritesFile: true
        ),
    ]

    /// gcx and grafanactl share one YAML schema for credentials: the
    /// `datapolicy:"secret"` fields plus gcx's keychain-managed `sm-token`.
    /// gcx's keychain references (`keychain:gcx:…`) are not plaintext.
    public static let grafanaConfigGate = CredentialContentGate.literalYAMLValues(
        keys: ["token", "password", "oauth-token", "oauth-refresh-token", "sm-token", "key-data"],
        ignoringValuePrefixes: ["keychain:"])

    /// SSH keys are the one home-global class not in `entries`: `~/.ssh` is
    /// probed structurally (every regular file whose content is a private
    /// key), because key files carry arbitrary names and an existing
    /// `protect --ssh` flow owns their delivery.
    public static let sshDirectory = "~/.ssh"
}
