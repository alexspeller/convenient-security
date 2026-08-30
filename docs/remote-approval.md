# Opt-in iPhone remote approval

## User experience

Remote approval is the same approval mechanism on a second screen, not a new
policy mode:

1. Pair one iPhone once under Touch ID on the Mac and Face ID on the phone.
2. A new 1Password-backed access request opens the ordinary Mac prompt and
   mirrors the exact frozen, value-free review to the paired phone.
3. Touch ID on the Mac or Face ID on the phone can decide it. The first verified
   decision wins and cancels the other surface.
4. A relay failure changes nothing: the local prompt remains usable. With no
   pinned phone, csecd performs no CloudKit request at all.

There is no per-secret enrollment, separate remote policy, reusable approval
token, or server account. Pairing is the only opt-in.

## Pairing

The checked-in iOS app shell lives in `ios/`. Once a CloudKit-capable physical
build is installed:

1. Tap **Set up this iPhone**, then copy its public pairing code.
2. On the Mac, run:

   ```sh
   csec remote enable '<csec-phone-v1:...>'
   ```

   The daemon shows Touch ID with the phone name and public-key fingerprint,
   pins that key in its code-identity-gated Keychain record, and prints a public
   Mac pairing code.
3. Paste that `csec-mac-v1:...` code into the iPhone app and accept it with Face
   ID. Remote approval is active immediately.

Inspect or remove the opt-in with:

```sh
csec remote status
csec remote disable        # Touch ID gated
```

Pairing codes carry device IDs, display names, public P-256 keys, and the
CloudKit container identifier. They contain no credential values or private
keys. The Mac signing key and phone signing key are generated in their
respective Secure Enclaves. Changing enrolled phone biometrics invalidates the
phone key and requires re-pairing.

## Transaction binding

Before either biometric path begins, csecd constructs an immutable remote view
from the same `AccessPolicyReview` used by the local window. It includes:

- sanitized reason, caller, logical credential display, and warning;
- emitter, recipient, delivery mechanism, scope, root, destination, and TTL;
- a digest of the exact canonical reference set; and
- the complete delivery-plan digest already enforced by csecd.

The Mac signs a versioned, length-prefixed canonical representation containing
that review, a fresh request UUID, its pinned device ID, and a 90-second expiry.
The phone verifies the pinned Mac key before rendering anything actionable. On
Approve or Deny, it freezes a response containing the decision, request UUID,
request digest, phone device ID, and decision time; Face ID then authorizes its
Secure Enclave key to sign those exact bytes. The Mac accepts only the pinned
phone key, matching device/request/digest, bounded timestamp, and an unexpired,
single-use request.

CloudKit database ownership is never authorization. Invalid mailbox records are
ignored. A valid signed denial is terminal; missing iCloud, a timeout, or an
invalid response is merely unavailable and leaves the local prompt running.

## Relay and data exposure

`CloudKitRemoteApprovalRelay` uses the current iCloud user's private database in
`iCloud.com.alexspeller.convenient-security`. It stores short-lived signed JSON
envelopes under request/response record IDs. It never stores resolved values,
cache material, native-store ciphertext/keys, command lines, environment
values, or a reusable capability. It does store the value-free review metadata
listed above; opting in explicitly accepts syncing that metadata through the
user's private CloudKit database.

The iPhone installs a query subscription for request creation. A silent push is
only a wake-up hint: the app fetches pending records and verifies the Mac
signature every time. The Mac polls for the one response while the ordinary
local prompt is open, so there is no csec-operated push server or long-lived
internet service.

The first implementation mirrors only requests whose references are all
`op://`. A remote approval cannot produce a Mac `LAContext`, so allowing a cold
`csec://` native-store or biometric Keychain-cache read would show a successful
phone approval and then fail at the separate device-bound unlock. The proactive
1Password desktop connection is what makes the remote path immediately useful
without weakening those local Keychain boundaries.

## Developer provisioning gate

No Apple Developer account or CloudKit production state is mutated by this
repository change.

### Simulator smoke test

A Debug build for an iPhone Simulator has an intentionally insecure test
backend. The compile-time gate is exactly `DEBUG && targetEnvironment(simulator)`:
Release builds and every physical-device build retain the Secure Enclave path,
with no runtime fallback. The simulator stores a software P-256 key in its own
Keychain service, explicitly invokes simulated Face ID before signing, and
shows a permanent orange **SIMULATOR TEST MODE** warning.

The simulator also has a local **Inject signed sample request** action. It
creates a synthetic, value-free review, signs it with an ephemeral simulated
Mac key, verifies that signature before rendering, and verifies the
Face-ID-gated phone response. It neither contacts 1Password nor publishes that
fixture to CloudKit, so this first smoke test needs no Apple portal setup or
iCloud account:

1. Install full Xcode with the iOS platform support and XcodeGen.
2. Run `cd ios && xcodegen generate`, open
   `ConvenientSecurityApproval.xcodeproj`, and run its Debug scheme on an iPhone
   Simulator.
3. In Simulator choose **Features › Face ID › Enrolled**.
4. Tap **Set up this iPhone**, then **Inject signed sample request**.
5. Tap Approve or Deny and, while the biometric sheet is open, choose
   **Features › Face ID › Matching Face**. Repeat with **Non-matching Face** to
   verify that no decision is accepted.

This validates the UI, canonical request/response signatures, expiry, request
binding, and biometric control flow. It does not validate Secure Enclave key
storage, biometric-set invalidation, APNs wakeups, or cross-network CloudKit.

### First physical iPhone test

The lowest-friction end-to-end test uses the CloudKit **Development** database
on both devices. The checked-in iOS development entitlement and
`csecd.remote-approval.development.entitlements` are aligned to that
environment. A physical build requires these explicit one-time steps:

1. Install full Xcode. Generate the checked-in project with `cd ios && xcodegen
   generate`, or create an equivalent iOS app target from `ios/project.yml`.
2. Register `com.alexspeller.convenient-security.approval` and the
   `iCloud.com.alexspeller.convenient-security` container.
3. Associate that container, with CloudKit support, to both the existing Mac App
   ID and the iOS App ID. Enable push notifications for the iOS App ID.
4. Regenerate an Apple Development profile for the Mac and an iOS development
   profile. Enabling iCloud invalidates profiles made from the previous App ID
   configuration. Xcode can register the connected phone and manage the iOS
   profile automatically.
5. Sign into the same iCloud account on the Mac and phone and enable iCloud
   Drive. The relay uses that user's private database, so different accounts do
   not share requests.
6. Connect the phone to Xcode, enable Developer Mode when prompted, select it as
   the run destination, and install the Debug app. The phone must have a
   passcode and Face ID enrolled.
7. Build the Mac app with the matching development profile and certificate:

   ```sh
   CSEC_REMOTE_APPROVAL=1 \
   CSEC_REMOTE_APPROVAL_ENV=development \
   SIGN_IDENTITY='Apple Development: …' \
   PROFILE_PATH='/path/to/development.provisionprofile' \
   packaging/bin/build-agent.sh
   ```

   Install/register that app using the steps printed by the script. The default
   remote-approval environment remains Production for release builds.
8. Pair the phone and Mac using the public codes above. Start an `op://` access
   request on the Mac, then manually refresh once on the phone. The first Mac
   request creates the development request record type; the first phone
   decision creates the response type. Subsequent requests can use the silent
   push subscription.

Before distributing a Developer ID Mac build or a production iOS build, deploy
both record types and their fields from the development CloudKit schema to
Production, create matching production profiles, and use
`packaging/agent/csecd.remote-approval.entitlements` on the Mac. Development and
Production databases are separate and cannot exchange an approval.

The default build keeps the existing, non-CloudKit profile working; an
enrollment attempt reports that the private iCloud relay is unavailable.

The present Command Line Tools environment can compile the shared Mac/CloudKit
targets and parse the selected Debug-simulator source branch, but it cannot
type-check, sign, install, or run the iPhone target. Do not claim the feature as
released until the following physical acceptance checks pass:

- Mac and phone on different networks; local prompt mirrored and Face ID approval
  releases an `op://` request.
- Local Touch ID wins and promptly removes the phone request; remote Face ID wins
  and closes and invalidates the local authentication sheet.
- Signed Deny is terminal; an offline phone, signed-out iCloud, or CloudKit error
  leaves local approval working.
- Wrong Mac/phone key, changed request display/digest, replay, and expiry all fail
  closed.
- Locking 1Password or exceeding its maximum desktop session fails provider
  resolution rather than bypassing 1Password authorization.
- Changing enrolled Face ID invalidates phone signing and requires re-pairing.
