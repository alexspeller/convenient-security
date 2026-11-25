# The GitHub token proxy

csecd can hold the GitHub CLI's token and put it on `gh`'s requests itself,
so `gh` keeps working while no process on the Mac, `gh` included, ever holds
the token. It does for GitHub what the SSH agent does for keys: the socket
returns GitHub's responses, never the credential.

Without it, `gh auth login` stores its token in the login keychain behind
`/usr/bin/security` (gh's keyring library runs that binary to read and write
it), or in plaintext in `hosts.yml`. Any process running as you can read either
silently, with `gh auth token` or `security find-generic-password -w`. Taking a
GitHub token is how a supply-chain worm publishes itself into your
repositories, so this is squarely csec's adversary.

## Set it up

```sh
csec protect --gh            # one Touch ID
gh api user --jq .login      # first request from this session: one review
```

`csec protect --gh` does, in order:

1. refuses, changing nothing, if `gh` is also signed in to a host other than
   github.com (GitHub Enterprise, `*.ghe.com`): `http_unix_socket` is one
   setting for every host, and csec's socket serves github.com only;
2. asks `gh auth token --hostname github.com` for the token `gh` would use
   (its config, then the keychain; a `GH_TOKEN` in your shell is set aside);
3. imports it into the native store (`csec://github/gh-token` by default;
   `--store NAME` picks another) and registers that reference with csecd's
   GitHub socket, under one review and Touch ID;
4. sets `gh config set http_unix_socket <csec github socket>` and
   `gh config set -h github.com oauth_token csec-github-proxy`, and checks
   that `gh auth token` now gives the placeholder; and only then
5. removes `gh`'s own copies of that account's token: its keychain items
   (`gh:github.com`, for the empty account and for its login; `security -a ""`
   matches only the item with no account) and the account's
   `users.<login>.oauth_token` line in `hosts.yml`.

Up to step 4's check, `gh`'s keychain items and account entry are untouched,
so a failure leaves `gh` able to return to its own token
(`gh config set http_unix_socket ""`, `gh auth switch`). Another github.com
account's token is not csec's import and stays, with a note. `--dry-run`
reports the plan and changes nothing; `--keep-plaintext` stops before step 5,
and running `csec protect --gh` again later finishes it. Once nothing is left
to remove it changes nothing.

Protecting the token revokes nothing: a copy taken before still works until you
revoke it on GitHub (Settings → Applications → Authorized OAuth Apps → GitHub
CLI). After revoking, `gh auth login` and `csec protect --gh` again.

### Any backend

Import and use are separate, as for SSH keys. A token held anywhere csec can
resolve works the same way:

```sh
csec github register 'op://Private/GitHub CLI/token'
csec github register ./github-token.csec      # a generic sidecar's reference
csec github status
csec github remove                            # the value stays in its store
csec github socket
```

`register` shows one value-free review on this Mac (never mirrored to the
phone: it is setup), resolves the reference with that touch, checks the value
is one line of printable ASCII, and records only the canonical reference, in
csecd's protected `github-proxy`/`settings-v1` item. `status` reports the
reference, whether `gh`'s `http_unix_socket` names csec's socket, whether
`hosts.yml` still holds a token other than the placeholder, and how many of
`gh`'s keychain items remain — never a token, and never a comparison with one
other than the public placeholder.

## How gh reaches csecd

`gh`'s `http_unix_socket` setting routes every HTTP request through a Unix
socket. go-gh's `newUnixDomainSocketRoundTripper` dials the socket for both
plain and TLS connections, so Go writes plaintext HTTP/1.1 to it, with
`Host: api.github.com` and the placeholder in `Authorization: token …`. No
certificate, root CA or TLS interception is involved: the TLS connection to
GitHub is csecd's own, verified by the system's trust evaluation.

The socket is `0600` in csec's private runtime directory. Any process of the
current user may connect; who asks is what the review shows and what a grant
is bound to, and the socket itself grants nothing. Tools other than `gh` can use
it too (`curl --unix-socket …`): they get the same review.

## Approval and grants

A request that carries the placeholder for `github.com` or a subdomain is an
ordinary access request for the token's reference, built by csecd from kernel
facts: the requester's executable path and code identity from its audit token,
and its argv, which the review shows and the grant's command digest binds. Its
delivery mechanism is `daemon_proxy` ("used inside Convenient Security, never
released"), which only csecd can put on a plan; a client that sends one is
refused. Everything a secret release has applies:

- the secret-access review, with its terminal tab, command, scope selector and
  lifetime. Its secrets are headed **Secret used, never released**, the line
  beside the sensor reads "let Claude Code and everything it runs use the
  requested value…", and the footnote says the token stays in csec and the
  program receives only GitHub's responses. The phone mirror carries the same
  footnote. The SSH layout and the sudo review never show a daemon-proxy use.
- grants: by default the coding-agent or terminal session above `gh`, so one
  touch covers a session's `gh` commands. A proxy grant is keyed on the
  `daemon_proxy` release shape, so it never covers a release of the token's
  bytes (`csec exec --set GH_TOKEN=…`), and such a release's grant never covers
  proxy use.
- the restore panel after a csecd restart, Deny propagation to identical
  waiting requests, the coding-agent wait limit, and withdrawal when `gh`
  exits (its socket closes or its process incarnation is gone).
- Claude Code auto mode: a `gh` under an approved `csec ai` is a nested request
  (DESIGN.md §Nested requests). Once the token is paired with the project — the
  first panel's pairing line — later `gh` commands auto mode approved use it
  with no panel. That pairing is for csecd's use only (`usedReferences` in the
  pairing item, listed by `csec grants` as "used inside csec, never
  released"): it never lets auto mode release the token's bytes into a
  command's environment, which still asks. A reference paired for release
  covers this use too. The use pairing holds in every project, not only the
  one whose panel paired it (csec-0.46), so after the first `gh` panel no other
  repository asks again; the pairing line says "in every project". csecd, not
  the repository, chooses the reference, and the auto-mode classifier still
  judges each `gh` command (a merge to a deploy branch, `gh secret set`, a
  branch-protection edit still stop there). It holds until every pairing that
  lists it is revoked. A request that can give lasting access is never auto
  mode's, paired or not (below).
- Claude Code's own PR lookup: after a Bash command that mentions a push,
  Claude Code runs `gh pr view [<selector>] [--repo <owner>/<repo>] --json url`
  itself, outside any Bash tool command, to link the session to its PR. That
  exact argv, from an executable named `gh` whose verified parent is the
  Claude Code session, is judged as the session's own request, under the same
  gates and use pairing, so it needs no panel either (csec-0.47). So is its
  daily closed-issues check, exactly `gh issue list -R anthropics/claude-code
  --author @me --state closed --search 'closed:><date>' --json
  number,title,closedAt,stateReason --limit 30` (csec-0.64.10). Any other
  `gh` Claude Code runs this way keeps its panel, which says Claude Code ran it
  itself (`agent_own_command`).

### Requests that can give lasting access

Most of what a grant lets a program do ends with the grant. A few GitHub
requests add access that keeps working afterwards: an SSH key on the account,
a secret a workflow receives, a webhook. Through those, a program inside a
grant could keep the access the proxy stops it taking. So csecd reads each
request it is about to put the token on, and one that can give lasting access
gets its own review every time (csec-0.49):

- no grant covers it, whatever its scope or lifetime, and no restore panel
  reopens one for it;
- Claude Code auto mode never approves it, paired or not: its panel says
  "Auto mode didn't approve this: POST api.github.com/user/keys can give
  access that outlasts any approval…" (`lasting_access`);
- its panel is headed **Lasting GitHub Access Requested**, its warning names the
  request and what it can add ("LASTING ACCESS: POST api.github.com/user/keys
  can add an SSH key to your GitHub account…"), and it offers no wider scope or
  lifetime: "This request only". The phone mirror shows the same warning and
  offers no lifetime either;
- approving it mints no grant and pairs nothing, so the next one asks again,
  while ordinary `gh` use under the session's grant goes on with no panel. A
  Deny refuses only the identical lasting requests waiting with it.

So `gh ssh-key add`, `gh gpg-key add`, `gh secret set`, `gh repo deploy-key add`
and workflow edits through the contents API ask each time, in a session whose
other `gh` commands do not.

What counts (`GitHubLastingAccess`), for `POST`, `PUT` and `PATCH`:

| Adds | Requests |
| --- | --- |
| keys on your account | `/user/keys`, `/user/ssh_signing_keys`, `/user/gpg_keys`, and `/user/emails` (an address you do not hold can reset the password) |
| deploy keys | `/repos/{owner}/{repo}/keys` |
| secrets | any path with a `secrets` segment under `/user`, `/repos`, `/repositories`, `/orgs` or `/enterprises`: Actions, Dependabot, Codespaces and environment secrets, and which repositories an organization secret reaches |
| webhooks | `/repos/{owner}/{repo}/hooks…`, `/orgs/{org}/hooks…` |
| people | `/repos/…/collaborators/…`, `/repos/…/invitations/…`, `/orgs/{org}/memberships/…`, `/orgs/{org}/invitations`, `/orgs/{org}/organization-roles/…`, team memberships and team repositories (also the legacy `/teams/{id}/…`), and approving `/orgs/{org}/personal-access-token-requests` |
| apps and runners | `/user/installations/{id}/repositories/…`, `/app-manifests/{code}/conversions`, `…/actions/runners/registration-token` and `…/generate-jitconfig` for a repository, organization or enterprise |
| what Actions runs | `/repos/…/contents/.github/…` (all of `.github/`, since a local action there runs inside the workflows that use it), and `/repos/…/git/trees` when an entry's path is under `.github` |
| exposure | `PATCH /repos/{owner}/{repo}` that sets `private` to anything but `true` or `visibility` to anything but `private`, and `/repos/…/transfer` |
| GraphQL | a `/graphql` document that names `createCommitOnBranch`, `updateTeamsRepository`, or an enterprise invitation, role, migrator, identity-provider or transfer mutation |

Matching errs towards a panel. The path is matched after percent-decoding
(repeatedly), lowercasing, reading `\` as `/`, dropping empty and `.` segments,
`;` parameters and a leading `/api/v3`, and applying `..`; a method override
(`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, `_method=`)
makes any method a write. A request whose body decides the answer asks when
csecd did not read the body first (over 1 MiB) or cannot parse it: a GraphQL
request, a tree, a repository `PATCH`. A GraphQL request's warning then says
why ("…could not read because its body is not JSON…": over 1 MiB, no body,
not JSON, or no `query` string, as a persisted query sends), and csecd's log
gets one metadata-only line per lasting request,
`csecd: GitHub proxy lasting request (kind=unchecked_graphql unread=not_json pid=…)`,
so the panels can be counted by cause. A GraphQL mutation is found by name
anywhere in the document, so an alias or a fragment on `Mutation` still
counts; words in `variables` are data, not the document. A `DELETE` removes
access and counts only under a method override.

### Resolving the token

The token is resolved through `SecretResolver` for each request after that
decision, checked again for shape (a value with a space or line break could
never reach a header), and registered with the output redactor like any
released value.

## The forwarding boundary

Each client connection carries one request. csecd parses its head strictly
(RFC 9112): origin-form target, CRLF only, no obs-fold or whitespace before a
colon, exactly one `Host` naming port 443 or none, `Content-Length` or
`Transfer-Encoding: chunked` but never both, no chunk extensions or trailers,
no upgrade, no `CONNECT`, at most one `Authorization`, and a head of at most
64 KiB. A refusal is a `400` from csecd, and nothing is forwarded.

csecd then writes a head of its own: the method and target as sent, `Host`, the
token in place of the placeholder, the end-to-end fields as sent, its own body
framing, and `Connection: close`. It is the first thing on a fresh TLS
connection that carries only this request, and the response's `Connection`
headers are replaced with `close` before it reaches `gh`. So a request csecd
frames differently from GitHub cannot smuggle the token-bearing head into a
body GitHub stores: there is no later head on that connection. A body up to
1 MiB is read whole before the request is judged (so a requester that leaves
is seen to leave, and a GraphQL document is read before it is judged), however
it is framed: `gh api --input -` sends a chunked body, since stdin has no
length, and csecd forwards one it read whole with its own `Content-Length`,
so GitHub reads exactly the bytes judged. A larger one streams after
approval, a chunked one re-framed chunk by chunk. The response body is relayed
exactly as GitHub sent it, compressed or not.

Hosts:

| Host | Placeholder | Forwarded |
| --- | --- | --- |
| `github.com`, `api.github.com`, `uploads.github.com`, `codeload.github.com`, `gist.github.com` | replaced by the token, after the review | yes |
| any other `*.github.com`, `*.githubusercontent.com` | removed | yes, no review |
| a host GitHub redirected an authenticated request to (csecd's token or the request's own) | removed | once: a single-use ticket for that host and path, for the `gh` process the redirect was sent to (artifact and log downloads go to Azure storage) |
| anything else | — | no: csecd answers `421` |

The token hosts are the names `gh` sends authenticated github.com requests to.
go-gh's `headerRoundTripper` would put the token on any `*.github.com` name,
but there `gh` chose the host; through the socket any process in a grant's
scope chooses it, so a subdomain served by someone else, or left dangling,
never receives the token.
A request with a credential of its own (`GH_TOKEN` set) is forwarded with that
credential and no review: it is not csec's to guard. GitHub Enterprise hosts
are not served.

csecd answers in GitHub's error shape, so `gh` prints the reason:
`HTTP 403: csec: GitHub access through csec was not approved (…)`, `503` with no
token registered (naming `csec protect --gh`), `502` when GitHub cannot be
reached.

**Network.** This is csecd's only outbound connection of its own. A firewall
such as LuLu needs a rule letting csecd reach port 443; until it has one a
connection waits for its prompt, and csecd answers `502` after 30 seconds
(that bound exists only so `gh` is not left with no answer at all).

**Bounds.** At most 32 connections are served at once; one more is answered
`503` at once. A client or a server that stops sending or reading for 60
seconds is cut off: a request waiting on a human is not, since nothing is
being read or written then. These keep a flood or a stalled peer (a redirect
can lead to a host csecd does not otherwise trust) from holding csecd's
descriptors.

## What it protects, and what it does not

It stops a process from taking the token: nothing outside csecd holds it, so
there is nothing to copy, exfiltrate or reuse elsewhere. What it does not stop
is use: while a grant is live, any process inside the approved scope can make
GitHub requests through the socket (or through `gh`) that the token permits,
the same trade-off every subtree grant makes. That use ends with the grant,
except for requests that add access of their own, and those each ask
([above](#requests-that-can-give-lasting-access)), so a program cannot turn a
session's grant into access of its own without a panel naming the request.

That list is what csecd recognises, not everything that could outlast a grant:

- A request it does not list stays covered by the grant. Some reach the same
  end less directly: a workflow edit pushed over `git` (SSH goes through csec's
  SSH agent and its own review, not this socket), a pull request merged with
  `PUT /repos/…/pulls/{n}/merge` or `mergePullRequest` whose branch already
  holds a workflow, `git/commits` and `git/refs` pointing a branch at a tree
  made earlier, or a script a workflow already runs.
- Code a workflow runs can read the secrets that workflow is given; that is
  GitHub's boundary, not csec's.
- A review is only as good as its reading. The panel names the request and
  what it can add, and approving it is a decision about that request.

A request with a credential of its own, or to a host that gets no token, is
forwarded with no review, so any process of yours can reach GitHub's hosts
through csecd. That is egress a per-program firewall rule for csecd allows,
and it carries no token csec guards.

Interactions:

- **`GH_TOKEN` / `GITHUB_TOKEN`** in an environment take precedence over the
  placeholder, and that token is the environment's to protect.
- **git over HTTPS through `gh auth git-credential`** would now hand git the
  placeholder. Use SSH (csec's SSH agent) or `csec creds git`.
  `csec protect --gh` warns when git is configured that way. Public
  repositories still fetch, because git asks a credential helper only after
  GitHub answers 401; private fetches and every push fail. Check fetch URLs as
  well as push URLs, and remember the HTTPS URLs that tools build for you
  (Bundler's `github:` gems, Go modules, submodules). A rewrite such as
  `git config --global url."git@github.com:ORG/".insteadOf
  "https://github.com/ORG/"` moves a private organisation's repositories to
  SSH in one step, remotes and tool-built URLs alike.
- **Scripts that pass `$(gh auth token)` on**, such as
  `GITHUB_TOKEN=$(gh auth token) yarn` for GitHub Packages, now pass the
  placeholder, which works only through csecd's socket. Give such a tool a
  reference of its own instead (an `.envrc` `csec_GITHUB_TOKEN=…`, or
  `csec exec`).
- **`csec exec-file --gh-config`** refuses to run while `gh` reports any
  ambient token, the placeholder included; the proxy replaces it for `gh`.
- **`gh auth login` / `gh auth refresh`** store a new token in the keychain
  again; run `csec protect --gh` afterwards.
- **Undo:** `gh config set http_unix_socket ""`, `gh auth login`, and
  `csec github remove`.

`csec audit` HA-F12 fails while `gh` keeps a github.com token in the login
keychain (found by its attributes, never read) or in plaintext in `hosts.yml`.

## Tests

`cs-selftest --github-proxy-only` covers the parser's refusals, the host
policy, the connection limit, chunk reframing, response heads, redirect tickets, a live socket
exchange against a recording fake GitHub, the Agent path with references from
two schemes (review, grant reuse, refusal, a forged client plan), and the
installed `gh` end to end against the fake GitHub: `gh api user` and a GraphQL
POST, with GitHub receiving the token and `gh` only the placeholder. `cs-e2e`
drives `csec github` and `csec protect --gh` through the real launcher against a
scripted `gh` and a scripted `security`, so no real keychain item is touched:
the refusal for another host, `--dry-run`, `--keep-plaintext` and the later
run that finishes it, and another account's token left alone.
`cs-selftest --github-proxy-only` also checks every listed lasting request, the
near misses that stay ordinary, the encoded, case-folded, dotted and overridden
spellings that still count, the socket passing the body-dependent verdict to
the authorizer, and the Agent path: its own review under a live grant, no
grant minted, the panel and phone copy, and the marker never on the wire.
`cs-selftest --claude-delegation-only` covers the use-only pairing, and that a
paired use's lasting request still gets a panel with no pairing line.
`cs-review-preview github` draws the panel, `cs-review-preview github-lasting`
a lasting request's.
