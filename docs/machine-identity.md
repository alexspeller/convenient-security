# Machine identity: sign in to clouds as this Mac

csec can make this Mac its own OpenID Connect issuer. A key in the Secure
Enclave, held by csecd, signs short-lived tokens, and a cloud's workload
identity federation (an AWS IAM OIDC provider, a Google Cloud workload
identity pool, Vault, Databricks and the like) trusts that key directly. So
the Mac signs in as itself: there is no access key in `~/.aws/credentials`, no
service-account key file, and no SSO session that expires every few hours.

Each sign-in is an ordinary csec reference, `csec-identity://<identity>/<target>`,
reviewed and granted exactly like a stored secret. The first use in a terminal
or a Claude Code session asks you to approve; the grant then lasts for that
session. A paired project's auto mode works as it does for any secret. An
unattended job enrolled with `csec automation` can't use a sign-in yet: a job
keeps the values it was enrolled with, and a sign-in expires within the hour,
so enrolment refuses one rather than store something that will stop working.

What this is not: a defence against something that already runs as you and
waits for you to approve. Once you approve a sign-in for a terminal, anything
in that terminal can use it until the terminal goes, as with any csec grant.
What it does stop is the common case: a trojaned dependency that reads
`~/.aws`, `~/.config/gcloud` or a token file and sends it home. csec puts no
key, refresh token or SSO session there. The gcloud shell function installed
by setup also keeps its exchanged access token off disk. Bypassing the
function, or using gsutil/bq directly, loses that protection (see [Limits](#limits)).

## How it works

- **The key.** `csec identity create` makes a P-256 key in the Secure Enclave.
  It never leaves the enclave. Its handle, which lets a process ask the
  enclave to sign, is kept in csecd's own protected Keychain item
  (`machine-identity`/`catalog-v1`), which no other program can read. That
  matters: a Secure Enclave handle in a file would let any program running as
  you sign with the key.
- **The token.** An ES256 JWT with `iss` (the identity's issuer), `sub` (this
  Mac's subject), `aud` (the target's audience), `iat`, `nbf`, `exp` (at most
  an hour) and a fresh `jti`. The header's `kid` is the key's RFC 7638
  thumbprint. csecd mints a new one for every release and keeps none.
- **AWS.** An `aws` target names one IAM role. csecd mints a five-minute token
  and exchanges it with STS (`AssumeRoleWithWebIdentity`) itself, so the token
  never leaves csecd, and returns the role's temporary credentials to
  `csec creds aws`, which your AWS profile runs as its `credential_process`.
  The AWS CLI, the SDKs and Terraform's AWS provider keep `credential_process`
  output in memory only. csecd reuses credentials it holds while more than 20
  minutes remain, and an AWS
  session lasts at least half an hour, so botocore (which refreshes inside 15
  minutes) doesn't ask on every call. A grant for one role gives that role's
  credentials only.
- **Google Cloud.** Setup installs a gcloud shell function for fish, zsh and
  bash. A separate `google` target pins the provider and optional service
  account. After ordinary review, csecd performs Google's STS exchange and
  optional service-account impersonation, keeping the access token only in
  memory. The wrapper uses `csec exec` to give gcloud that token through
  `CLOUDSDK_AUTH_ACCESS_TOKEN`, which bypasses its token cache, and disables
  file logging. It contains no refresh token. Same-user process inspection
  can read the environment. Client libraries and Terraform retain the
  external-account credential file, whose executable source runs
  `csec creds google` and whose exchanged token stays in library memory.
  Google takes the key set as an upload, so the issuer needs no hosting.
- **Anything else** that accepts an OIDC token: `csec exec --env NAME=csec-identity://…`
  for a tool that reads it from its environment, or `csec get` into a pipe.

## Set it up

### 1. Make the identity

```sh
csec identity create --issuer https://<your-issuer>      # one Touch ID
```

The issuer is a URL you control. AWS fetches the public files from it
(below); Google never does, so a Google-only user can pick any HTTPS URL they
own. `--subject` sets who the tokens say signs in (default: this Mac's name in
lower case). A second identity takes a name: `csec identity create work --issuer …`.

### 2. Publish the issuer (AWS, and anything else that fetches keys)

AWS needs two public files at the issuer: `/.well-known/openid-configuration`
and `/jwks.json`. Any HTTPS host that serves static files will do.

```sh
csec identity publish                       # writes openid-configuration and jwks.json here
```

For an S3 bucket, csec writes the bucket policy and prints every command:

```sh
csec identity create --issuer https://<bucket>.s3.<region>.amazonaws.com
csec identity publish --s3-bucket <bucket> --region <region> --admin arn:aws:iam::<account>:role/<you>
```

**Whoever can change `jwks.json` can sign in as this identity to every role
that trusts it.** The bucket policy csec writes lets anyone read the two files
and denies every change to everyone but the one administrator you name, so an
account's other powerful roles (a PowerUser, a CI role) can't add a key.
Versioning keeps a replaced key set visible. Whatever host you use, keep write access to it to
yourself.

`csec identity check` fetches the published files the way a cloud would and
compares them with this Mac's keys, by each published key's own RFC 7638
thumbprint rather than the `kid` the file claims, so a key swapped in under a
familiar `kid` is still caught. csecd also runs it daily and notifies you if
the key set holds a key this Mac never accepted. If that is your other Mac's
key, accept it once with `csec identity accept-key <identity> <thumbprint>`
(one Touch ID; `check` prints the thumbprint); if it isn't, take it out of the
key set and look at who can write to the host. The daily check stays quiet
while the issuer can't be reached: run `csec identity check` yourself if a
host you rely on goes away.

### 3. Add a sign-in and set the cloud up

**AWS:**

```sh
csec identity target add default/admin --aws-role arn:aws:iam::123456789012:role/admin --region eu-west-2
csec identity setup aws default/admin
```

`setup aws` adds `[profile admin]` to `~/.aws/config` with
`credential_process` pointing at the sign-in (it never rewrites a profile that
already has settings of its own; `--profile` picks another name), writes
`trust-policy.json` and the issuer files, and prints the IAM commands to run
with your own administrator credentials: the OIDC provider (once per issuer
and account) and the role, whose trust policy admits only this Mac's subject
and audience. Then:

```sh
aws sts get-caller-identity --profile admin    # first use in this terminal: one review
```

**Google Cloud:** a target's audience is its workload identity provider's
resource name.

```sh
csec identity target add default/gcp \
  --audience //iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
csec identity setup google default/gcp [--service-account deploy@<project>.iam.gserviceaccount.com]
```

`setup google` writes the libraries' credential file (in gcloud's config
folder by default) and `jwks.json`, and registers `<target>-gcloud` for the
wrapper, with one Touch ID naming its provider and optional service account.
An unchanged setup is idempotent; it refuses to repurpose an existing target
with different settings. To change the service account, explicitly remove
that `-gcloud` target and run setup again, or use a new source target. Removing
it revokes its old grants. The original target name must leave room for the
seven-character suffix (at most 57 characters).

Setup prints the Google commands to create the pool/provider, upload the key
set and bind this Mac's subject to the service account. Run them with your
existing administrator credentials: the printed `command gcloud` explicitly
bypasses the new function. csec creates no cloud resources itself. The pool
and provider are named by resource name, because gcloud's `iam` commands
refuse the project number (all the audience carries) in `--project`.

Google only serves an API that is enabled in the project it charges the call
to, so a call can fail with `SERVICE_DISABLED` even though the sign-in worked.
Enable the API the error names in the project it names (for `gcloud projects
describe`, `gcloud services enable cloudresourcemanager.googleapis.com
--project=<project-id>`).

It installs `gcloud.sh` under `$XDG_CONFIG_HOME/csec` (default `~/.config/csec`),
a fish function under `$XDG_CONFIG_HOME/fish/conf.d`, and a managed source block
in `$ZDOTDIR/.zshrc` (default `~/.zshrc`), `~/.bashrc` and `~/.bash_profile`.
Existing content is preserved; symlinked, hardlinked or concurrently changed
startup files are refused. Open a new terminal, or run the appropriate
`source` command setup prints, then use `gcloud` normally. The last setup
selects the active gcloud target. These public configuration files stay through
`csec uninstall`; to stop using the function, remove its managed startup blocks
and the two function files, then open a new shell. You can also run it explicitly:

```sh
csec gcloud --item csec-identity://default/gcp-gcloud -- projects list
```

The client libraries use `GOOGLE_APPLICATION_CREDENTIALS=<credential-file>`
and `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`. The credential file sets
`timeout_millis` to two minutes (google-auth's maximum) to allow a review,
and omits `output_file`. Do not use `gcloud auth login --cred-file` with it;
that direct path writes access tokens to gcloud's cache.

**Other services:** add a target with the audience the service expects and
pass the token the way it takes one:

```sh
csec identity target add default/vault --audience vault --lifetime 900
csec get csec-identity://default/vault | vault write auth/jwt/login role=dev jwt=-
```

`vault write` reads `jwt=-` from the pipe, so the token never appears in a
command line.

## Commands

| Command | Touch ID | What it does |
| --- | --- | --- |
| `csec identity status` | — | Identities, their keys (by `kid`), accepted keys and sign-ins |
| `csec identity create [<identity>] --issuer <url> [--subject <s>]` | yes | Makes the Secure Enclave key |
| `csec identity remove <identity>` | yes | Destroys the key for good, removes its sign-ins and revokes their grants |
| `csec identity target add <identity>/<target> …` | yes | Adds a sign-in (`--aws-role` for AWS, `--audience` otherwise) |
| `csec identity target remove <identity>/<target>` | — | Removes a sign-in and revokes its grants |
| `csec identity publish [<identity>] [--s3-bucket …]` | — | Writes the issuer's public files and, for S3, the bucket commands |
| `csec identity check [<identity>]` | — | Compares the published key set with this Mac's keys |
| `csec identity accept-key <identity> <kid>…` | yes | Accepts another key in the published key set |
| `csec identity setup aws\|google <identity>/<target>` | Google: once for its new target | Configures the tool and prints the cloud-side commands |
| `csec creds google --item <reference>` | review | The executable source the Google credential file runs |
| `csec gcloud --item <reference> -- …` | review | Runs gcloud with an access token in memory |

Removing a sign-in revokes the grants that covered it and unpairs it from
every Claude Code project, so a target added later under the same name, which
may sign in somewhere else, inherits nothing. A sign-in is named by its
lower-case reference only (`csec-identity://…`): another spelling is refused,
so it can't sit outside a revocation.

## Limits

- **Apple silicon or a T2 Mac.** The key lives in the Secure Enclave. An
  unsigned development build on a Mac without one keeps software keys for the
  life of the process only.
- **ES256 only.** The Secure Enclave holds P-256 keys. Microsoft Entra
  documents RS256 only, so Azure isn't supported.
- **The issuer is yours to keep.** csec writes the files and checks them, but
  the host's access control is the trust root for AWS.
- **One key set per identity.** `publish` and `setup google` write this
  identity's keys only. To share one issuer between Macs, or to rotate, combine
  the `keys` arrays of each `jwks.json` into one file, publish or upload that,
  and accept the other keys on each Mac (`csec identity accept-key`).
  Rotation isn't automatic yet: make a new identity, publish its key beside
  the old one, move the roles over, then remove the old identity.
- **Unattended jobs** can't use a sign-in through `csec automation` yet (see
  above).
- **A grant is a grant.** An approved terminal can use the sign-in until it
  ends; scope the role to what that terminal's work needs.
- **Use the gcloud function.** It bypasses `access_tokens.db`, disables file
  logging and gets a reference reviewed in each independent terminal/session,
  even when csecd already holds its access token. A direct `command gcloud`,
  absolute SDK path, or `gcloud auth login --cred-file` bypasses it and can
  cache a token shared across unapproved terminals. Existing credentials and
  caches are left as found, not migrated or deleted by setup.
- **The token is in the process environment.** Additional gcloud API transports
  reload credentials (including storage transfers), so a single-open inherited
  pipe would be empty on the second read. Environment delivery survives those
  reloads but can be read by same-user process inspection, as with ordinary
  `csec exec`. This is protection against token-file scans, not a boundary
  against malware inside an approved process/session. `bin/test-google-token-cache.py`
  checks the real gcloud and google-auth offline with synthetic values.
- **An hour per command.** gcloud receives an access token, with no refresh
  credential. A command that outlives it must be restarted. The wrapper refuses
  credential management/export (`auth`, `config`), flags files, alternate token
  files, gcloud-side impersonation and HTTP logging. It uses the service account
  pinned in the csec target, not a gcloud configuration's impersonation setting.
- **gsutil and bq are outside the wrapper.** gsutil keeps its own access-token
  copy in `~/.gsutil/credstore2`; use `gcloud storage`, which follows the reviewed
  wrapper. Use the Google client libraries for BigQuery. Standalone bq can
  consume gcloud's old cached credentials and add `~/.bigquery/gcloud_cache.json`.
- **A role assumed from a csec AWS profile is cached.** A profile with
  `role_arn` and `source_profile` naming the profile `setup aws` wrote runs
  csec in memory as usual, but the AWS CLI stores the second role's
  credentials in `~/.aws/cli/cache` until they expire. Give each role its own
  sign-in (`csec identity target add … --aws-role`) instead.
