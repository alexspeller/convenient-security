# Release versions and the signed release manifest

csec numbers each release, refuses to install over a newer one, and tells you
when a newer one exists. It never downloads or installs a package by itself.

## Versions and builds

- **Version.** The repository's `VERSION` file holds the release being built,
  `MAJOR.MINOR.PATCH` with digits only (semantic versioning without a
  pre-release suffix). A release is tagged `vMAJOR.MINOR.PATCH` on the commit
  it was built from; `bin/ci` refuses a `VERSION` below the newest such tag.
- **Build number.** The commit count of the history being built
  (`git rev-list --count HEAD`), so a later commit on the same line always
  numbers higher. A shallow clone is refused because it counts only what it
  fetched.
- **Stamp.** `packaging/bin/build-agent.sh` links
  `{"version": …, "build": …, "commit": …}` into every release binary as the
  Mach-O section `__TEXT,__csec_stamp` (`ReleaseStamp` reads it), and writes
  the same version and build into the app's `CFBundleShortVersionString` and
  `CFBundleVersion`. It is a section of its own rather than an embedded
  `__info_plist` because an embedded Info.plist would replace the app's for
  `csec` inside the bundle. `csec --version` prints the running binary's own
  stamp, so the bridge copy outside the app reports what it is. A `swift build`
  binary carries no stamp and says it is a development build.
- **Package.** The package's version is `VERSION.BUILD`. Its preinstall
  script compares its own release with the installed app's before anything is
  written, and refuses a lower version, or a lower build of the same version.
  `build-and-install.sh --allow-downgrade` builds the one package that may
  replace a higher release, for a deliberate rollback.

## After the package installs

The installer replaces the app under every logged-in user's running `csecd`,
which would otherwise keep running the old code (and every new csec client
refuses it). Postinstall therefore restarts each running `csecd`
(`launchctl kickstart -k gui/UID/com.alexspeller.convenient-security`), then,
for the user at the Mac, starts `csec doctor --runtime` and `csec restore` in
the background, which raises the one panel that reopens the approvals the
restart locked. None of this can fail the install; `csec doctor` repairs a
`csecd` left on old code, and the first request that needs a reopened approval
raises the restore panel if the background one did not run.

## The manifest

One JSON document at `https://convenientsecurity.app/releases/manifest.json`,
with its signature beside it at `…/manifest.json.sig`:

```json
{
  "schema": 1,
  "sequence": 7,
  "release": {
    "version": "1.0.1",
    "build": 4890,
    "download": "https://convenientsecurity.app/download"
  }
}
```

- `schema` is 1. A higher schema is refused rather than guessed at.
- `sequence` grows with every manifest published. csec keeps the last
  manifest it verified and refuses one numbered below it, or the same number
  with other contents, so a replayed older manifest cannot hide a release.
- `release` announces the newest package: its version and build, and the
  https page where a person downloads it. csec only shows that address.
- `claude_code` lists the Claude Code images whose settings loader has been
  audited ([release verification](claude-release-verification.md)):
  `{"checked": [{"cdhash": "…", "version": "2.1.325"}, …]}`. Each `cdhash`
  is an image's exact 40-character lowercase host-slice code-directory hash,
  each `version` a label of at most 64 letters, digits or `. + _ -`, at most
  1,024 images. One malformed or repeated entry refuses the whole manifest.
  csec adds these to the list compiled into it and never removes a compiled
  one, so the section only ever admits more; leaving an image out of a later
  manifest withdraws only what an earlier manifest added.
- Other top-level sections sit beside these under the same signature. A
  build that does not know a section ignores it. `bin/release-manifest.py
  write` carries every other section of the previous manifest over unchanged.

## Signing

The signature is an OpenSSH file signature (`ssh-keygen -Y sign`,
[PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig))
by an Ed25519 key, in the namespace `release-manifest@convenientsecurity.app`.
Using OpenSSH's format means anyone can check a manifest with stock tools:

```sh
printf 'csec-release namespaces="release-manifest@convenientsecurity.app" %s\n' \
  "ssh-ed25519 AAAA… (a key from ReleaseSigningKeys)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I csec-release \
  -n release-manifest@convenientsecurity.app -s manifest.json.sig < manifest.json
```

The trusted public keys are compiled into csec (`ReleaseSigningKeys.pinned` in
`agent/Sources/ConvenientSecurity/ReleaseManifest.swift`); any one of them may
sign. A manifest signed by another key, for another namespace, or over other
bytes is refused. The private key is kept by a signing service that releases
each signature only after its holder's biometric approval, never as a file on
the release Mac or in its everyday Keychain; a new key reaches buyers only in a
release signed by a key they already trust. Until a key is pinned the list is
empty: csec then checks nothing and `csec doctor` reports the check as off.

Holding the key is power over every csec that trusts it: it can announce a
download page, and it can admit a Claude Code image to auto mode. That image
must still pass csec's identity check, so only an image signed by Anthropic or
one the person at the Mac trusted with `csec setup auto-mode` can be admitted;
what a stolen key buys is skipping the settings-loader audit for such an
image, never running code of the thief's choosing. That is why the key stays
behind its holder's biometric approval and off the release Mac.

Publishing a release:

1. Bump `VERSION`, merge, and tag the release commit `vMAJOR.MINOR.PATCH`.
2. Build the package from that commit.
3. `bin/release-manifest.py write --download https://convenientsecurity.app/download --previous manifest.json manifest.json.next`
4. Have the key's holder sign `manifest.json.next` in the manifest namespace.
5. `bin/release-manifest.py verify manifest.json.next manifest.json.next.sig`
6. Publish the package first, then the signature and the manifest together.

Publishing a newly audited Claude Code image needs no csec release:
`bin/release-manifest.py claude --previous manifest.json manifest.json.next`
writes the next manifest with this checkout's whole compiled catalog
(`ClaudeBuildVerification.shipped`) as `claude_code`, keeping the announced
release, then steps 4 to 6 as above.

## The check

`csecd` checks a few minutes after it starts and then once a day
(`ReleaseUpdateSchedule`, `ReleaseUpdateChecker`). Each check is two plain
HTTPS `GET`s to the fixed addresses above: an ephemeral session with no
cookies, cache or stored credentials, no query string, the fixed `User-Agent`
`ConvenientSecurity` (no version), `Accept-Language: en`, the system's
certificate checks, and no redirect followed. Each file is capped at 256 KiB.

While requests are declining on an unchecked Claude Code image, `csecd` also
checks sooner, at most once every 30 minutes, so an image audited since the
last check delegates again within the hour.

A manifest that verifies and is newer replaces the held copy under
`~/Library/Application Support/ConvenientSecurity/Updates/`. Every read
verifies it again, so a file someone replaced there reads as absent, never as
trusted. The check's own bookkeeping (`state.json`: when it last ran or
succeeded, its last failure, and the release already announced) is not
signed; altering it can at worst repeat or suppress one notification.

Each delegated request reads the held manifest's `claude_code` list again,
verified as above, so a copy someone replaced admits nothing and a newer one
counts from the next request; with no verified copy only the compiled list
counts.

When the held manifest announces a release above the running build, `csecd`
posts one notification for that release, and `csec doctor`'s **Updates** row
shows it with its download address. The row also says when the last check
failed and why, without making the installation unhealthy.
