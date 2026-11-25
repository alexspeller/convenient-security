# Build it yourself

The source is available, so you can build, sign and install csec yourself
instead of buying the package. What you pay for with the package is that
someone else does the Apple signing, notarizing and packaging for you. This
page is the route for doing it yourself. [`packaging/README.md`](../../packaging/README.md)
is the detailed reference for every stage.

Be warned that this is real work: you need your own paid Apple developer
account, two kinds of signing certificate, registered app identifiers and an
App Store Connect API key, and one file in the source names your team instead
of Stateful Ltd's (see [Use your own team and identifiers](#use-your-own-team-and-identifiers)).

## The licence

csec is under the [Functional Source License, Version 1.1, ALv2 Future
License](../../LICENSE.md) (`FSL-1.1-ALv2`). In short, and the licence text
is what counts:

- You may use, copy, modify and redistribute it for any purpose except a
  **Competing Use**: making it available to others in a commercial product or
  service that substitutes for it or offers substantially the same thing.
  Internal use at your company, education, research, and professional
  services for someone who is themselves a licensee are all fine.
- If you redistribute it, modified or not, include the licence (or a link to
  it) and keep the copyright notices.
- It grants no rights to Stateful Ltd's names, including Convenient Security
  and csec, beyond saying where the software comes from. If you hand your
  build to others, give it a name of your own.
- Each released version also becomes available under the Apache License 2.0
  two years after its release.

It is a Fair Source licence, not an OSI-approved open-source one.

## How a build of your own differs

Your build is signed under your Apple team, so to macOS it is a different
app from the official one:

- **Its own Keychain group and stores.** A self-built csec cannot read the
  official build's encrypted stores, saved approvals or settings, and the
  other way round. If you switch, copy your values out first (`csec edit
  <store>`) or keep them in 1Password, which either build can read.
- **Its own CloudKit container.** The iPhone approval app that
  `build-and-install.sh` builds for your phone pairs only with your own Mac
  builds, never with the official ones.
- **Its own update notices, or none.** csec checks a signed release notice at
  a fixed address and trusts only the release keys listed in
  `ReleaseSigningKeys.pinned`
  (`agent/Sources/ConvenientSecurity/ReleaseManifest.swift`). Remove the
  official keys and address and add your own if you want notices for your
  builds ([`docs/release-manifest.md`](../release-manifest.md)); with no key
  pinned, the check is off.

## What you need

**A Mac** with Apple silicon and System Integrity Protection on, with:

- full Xcode (the iPhone app and the Swift toolchain come from it);
- [mise](https://mise.jdx.dev), which runs the pinned tool versions in
  `.tool-versions` and `packaging/.tool-versions` (XcodeGen, Ruby for
  Fastlane, Python);
- Go 1.24 (`mise install go@1.24`), for the 1Password bridge;
- Node.js 22 or later, for the test suite;
- an iPhone with Face ID and Developer Mode on, paired with Xcode, if you
  want the approval app. Without one, pass `--skip-iphone`.

**An Apple Developer Program membership**, and in it:

| Thing | Where | Notes |
|-------|-------|-------|
| Developer ID Application certificate | developer.apple.com → Certificates | Signs the app. Only the account holder can create it. |
| Developer ID Installer certificate | the same | Signs the package. A different certificate from the one above. |
| Apple's Developer ID G2 intermediate | [Apple's certificate authority page](https://www.apple.com/certificateauthority/) | Without it a new certificate shows `0 valid identities`. Check its hash before importing; [`packaging/README.md`](../../packaging/README.md#one-time-prerequisites) shows how. |
| App IDs for the Mac app and the iPhone app and its notification extension | developer.apple.com → Identifiers | With your own reverse-DNS identifiers. Enable iCloud (CloudKit) on all three, with one container you create, and Push Notifications on the iPhone app. |
| An App Store Connect API key | App Store Connect → Users and Access → Integrations | A **Team** key with the Admin role. It fetches the provisioning profile and notarizes the builds. |
| Xcode signed in to the team | Xcode → Settings → Accounts | The iPhone app uses Xcode's automatic signing. |

## Use your own team and identifiers

The team ID and identifier are written in one file, `identity.xcconfig` at
the top of the checkout. Set both to yours:

```
CSEC_TEAM_ID = ABCDE12345
CSEC_IDENTIFIER = com.example.csec
```

`CSEC_TEAM_ID` is your 10-character team ID (developer.apple.com →
Membership details). `CSEC_IDENTIFIER` is a reverse-DNS prefix of your own,
and every other name comes from it:

| Name | Is |
|------|----|
| `CSEC_IDENTIFIER` | the Mac app's App ID and bundle ID |
| `CSEC_IDENTIFIER.approval` | the iPhone app's App ID |
| `CSEC_IDENTIFIER.approval.notifications` | its notification extension's App ID |
| `iCloud.CSEC_IDENTIFIER` | the CloudKit container to create and enable on all three |
| `CSEC_TEAM_ID.CSEC_IDENTIFIER` | the Mac app's Keychain access group |
| `CSEC_IDENTIFIER.csec`, `.rootd`, `.sudo-review`, `.sudo-pam`, `.opbridge`, `.pkg` | the other parts' signing identifiers and the package's |

Register those App IDs and that container under your team before the first
build. You change nothing else: the build scripts, the package's install
scripts, the signing entitlements, the iPhone project and the tests all read
this file, so csec's parts check each other's signatures against your
values. The Swift code reads a copy the build writes,
`agent/Sources/CSECBuildIdentity/BuildIdentity.swift`; `build-and-install.sh`
rewrites it when the file changes, and commit it with your change.

Then run the test suite:

```sh
mise exec -- npm ci --ignore-scripts
bin/ci
```

Before your first build, `bin/ci` fails until the Swift copy is rewritten
and prints the command that does it.

[`docs/development.md`](../development.md) explains what `bin/ci` runs and
what it needs.

## Point the build at your key and certificates

```sh
cp packaging/.env.example packaging/.env
```

`packaging/.env` is ignored by git. In it set:

- `SIGN_IDENTITY` and `INSTALLER_IDENTITY` to your two certificates' names,
  as `security find-identity -v` shows them;
- `OP_ASC_ITEM` to a 1Password item with your API key's ID, issuer ID and
  `.p8` private key in fields named `key_id`, `issuer_id` and `key`, or
  `ASC_KEY_ID_REF`, `ASC_ISSUER_ID_REF` and `ASC_KEY_REF` to a reference for
  each. Your first build needs them in 1Password (see [Your first
  build](#your-first-build)); once csec is installed, any csec reference works;
- `OP_ACCOUNT` to the 1Password account's sign-in address, if your 1Password
  app has more than one account;
- `CSEC_IPHONE_DEVICE` if more than one iPhone is paired.

The build never puts the key in a file of its own, an environment variable
or a command line: csec hands it to each stage through a private descriptor,
after you approve the panel.

### Your first build

On a Mac where csec has never been installed there is no csec to ask, so
`build-and-install.sh` reads the key with 1Password's own CLI instead, into
the same private descriptors. For that you need:

- the key in 1Password, with `op://` references in `packaging/.env` as above;
- [1Password's CLI](https://developer.1password.com/docs/cli/get-started/)
  (`op`) installed, with **Settings → Developer → Integrate with 1Password
  CLI** turned on in the 1Password app, so 1Password asks you to approve
  with Touch ID.

1Password asks once when the build fetches the provisioning profile and
again, unless your approval is still fresh, when it notarizes. The build
does not use a 1Password service account or Connect server for this, even if
your shell has one set up: an admin key is released only with your
approval. Only `build-and-install.sh` does this, and only while
`/Applications/ConvenientSecurity.app` does not exist. Once csec is
installed, every later build asks csec, and a csec that is installed but not
working stops the build rather than falling back to 1Password's CLI.

## Build and install

```sh
packaging/bin/build-and-install.sh --dry-run   # show the whole plan; signs, sends and installs nothing
packaging/bin/build-and-install.sh             # build, sign, notarize, package and install
```

Run it as yourself, not as root. In one go it fetches a provisioning profile
if there is none, builds and signs every part, has Apple notarize the app and
the package, installs the package (through `sudo`, so expect a password
prompt), registers `csecd`, installs the Codex hook and the sudo review,
builds and installs the iPhone app on your phone, and finishes with `csec
doctor`, failing if anything is unhealthy. Notarizing takes a few minutes.

The options you are most likely to need:

| Option | When |
|--------|------|
| `--skip-iphone` | No iPhone, or you do not want the approval app. |
| `--skip-sudo` | Leave the sudo review as it is. |
| `--refresh-profile` | After enabling a capability on an App ID, or when the profile expires. |

It is the only supported way to install from source. Its stages are scripts
in `packaging/bin`, described in [`packaging/README.md`](../../packaging/README.md#the-pipeline),
but they are its parts, not separate install routes.

When the script finishes, the setup on [Install and set up](install.md#2-run-csec-setup)
applies from step 2: run `csec setup` for the parts the script does not do
(Full Disk Access, protecting files, Claude Code auto mode).

To update, pull the new source, keeping your `identity.xcconfig` and the
`BuildIdentity.swift` written from it if the update conflicts with them, and
run the script again. It refuses to install a
checkout that lacks changes the installed build has, unless you pass
`--allow-downgrade` for a deliberate rollback.

## Distributing your build

You may give your build to others within the licence (see
[The licence](#the-licence)). If you do:

- give it your own name, and ship the licence with it;
- sign and notarize it under your own team, as the script does, so macOS
  checks it on their Macs. They can check it is yours with `pkgutil
  --check-signature`, which names your team;
- the package's installer and `csec setup` work for them exactly as on
  [Install and set up](install.md): they need no checkout;
- they get updates only from you, and support only from you.

## Known gaps

These are tracked, and this page will change when they are fixed:

- **The first build needs the key in 1Password.** With no csec installed,
  the script can only read the App Store Connect key through 1Password's CLI
  ([Your first build](#your-first-build)). If you keep the key somewhere
  else, put it in 1Password for the first build.

Building, testing and the iPhone simulator suite are covered in
[`docs/development.md`](../development.md); the internal design is in
[`DESIGN.md`](../../DESIGN.md).
