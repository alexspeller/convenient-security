# Convenient Security Approval for iPhone

This is the companion app for the signed protocol in
`agent/Sources/CSECRemoteApproval` (protocol v3, pairing v2). It contains no
secret provider and receives no resolved credential values. It verifies a
pinned Mac signature, renders the frozen value-free review, and answers it with
Face ID: a Secure Enclave signature over one exact Approve or Deny, and — for an
approval of a request that must open csec's locked storage — the Secure Enclave
key agreement that unlocks it. Nothing is actionable before the Mac's signature
verifies, and nothing is signed without Face ID.

## What the app does

**Identity.** Setting up creates two Face-ID-gated Secure Enclave P-256 keys
(`.biometryCurrentSet` + `.privateKeyUsage`, usable only while the iPhone is
unlocked, this device only): a signing key and a key-agreement key. The signing
key signs the key-agreement key (`RemoteApprovalPhonePairing.keyAgreementBindingData`),
so the Mac enrolls only a key the pinned identity vouches for. Setup costs one
Face ID: one evaluated `LAContext` is passed to both key creations, the binding
signature, and one throwaway key agreement that proves the second key works.
Changing Face ID enrollment invalidates both keys; the app then says to set it
up again. An identity from a protocol v2 build (signing key only) is detected
and replaced the same way, since it cannot answer an unlock challenge. A
Keychain read that fails — typically before the first unlock after a restart —
is not a broken identity: the app says the records are not available yet,
offers **Try again**, and reads them again on the next activation or push. Only
an identity that was read and does not decode, or whose keys no longer match,
offers to set up again.

**Pairing.** The app shows, and copies, the whole command to run on the Mac:
`csec remote enable` with a quoted `csec-phone-v2:` code (both public keys,
the binding signature, the app version), built by
`RemoteApprovalPairingCode.enableCommand`, with this iPhone's key fingerprint
under it to compare with the one Touch ID names. While the app is on screen
it reads the Mac's pairing offer (`pairing-offer-<phoneDeviceID>`, which
`csec remote enable` leaves) every two seconds and shows a verified one under
**A Mac asks to pair**; it also accepts the `csec-mac-v2:` code the Mac prints.
Either way, before any Face ID, it shows which Mac it names: the name, with control, format and bidirectional characters neutralized
(`RemoteApprovalDisplayText`), and the key fingerprint `csec remote enable`
printed. When it would replace a pairing it shows the key paired now beside
the new one: for the same Mac (same Mac ID) it says the pairing is replaced
and whether the key changes, and when another pinned Mac has the same name it
shows that Mac's key and offers to replace it or add this one beside it. It
then pins the Mac under Face ID (the
prompt names the Mac and key), and with the same Face ID signs a
`RemoteApprovalPairingConfirmation` for it, which it publishes to CloudKit; the Mac reports the pairing ready only once it verifies
that confirmation. The confirmation is public, so one that could not reach
iCloud is kept and sent later without another Face ID. Its save, like every
CloudKit call the app makes (**iCloud** below), is bounded, here by the 5 s
the Mac gives its offer (`RemoteApprovalBound.readNanoseconds`): the
pairing's outcome waits for the save, so one that does not answer in time
counts as not sent yet. Nothing in csec
deletes a confirmation, but iCloud data can go missing, and a csecd that
restarts then reports the pairing unconfirmed; so once each time the app
becomes active it reads each delivered confirmation back and publishes it
again — no Face ID — if it is gone or holds something the Mac would not
accept as this phone's confirmation of that pairing. A Mac can be unpaired
here (after Face ID); that is local only — `csec remote disable` on the Mac
stops it mirroring requests.

**Deciding.** A card shows the review as its kind lays it out — secret access,
SSH sign-in (host, unknown-host warning, remote user, key), sudo (command,
working directory, target user), reopening approvals after csecd restarted
(the rows it reopens; the refusing button is "Forget these approvals"), a
secret access that also reopens, or a change to csec's settings (the
acknowledgement csecd raises when a Claude Code request declined on a hook or
classifier rules added since the last one: the Mac panel's title, the lines it
lists under "Changes" and its footnote, with no secret, scope or lifetime).
Every card shows the full headline, requester,
terminal, secrets as the Mac panel draws them (account › vault › item › field,
each item a label coloured by its source) with their notes and warnings,
delivery, warnings, footnote, the Mac's name and how long it has been waiting,
and the scope and lifetime choices the Mac panel offers, with its defaults
preselected. A request the Mac closes unanswered (a sudo, a coding agent's)
also says when, in the Mac panel's words, and counts down its last 30 seconds;
the line goes once the card is sent. A request Claude Code auto mode declined also
shows why ("Auto mode didn't approve this: …") and, exactly while the selection
is the one that pairs, the pairing line (`RemoteApprovalReview.pairingLineApplies`);
an approval signs whether that line was on screen, and only then does csecd
pair. Tapping Approve or Deny freezes the card — the verified request
and the selection on screen — before Face ID. One evaluated `LAContext` is then
the authentication context for the signing key and, on an approval that
carries an `unlockChallenge`, for the key-agreement key that answers it
(`RemoteUnlockCrypto.answer`). A denial never computes a key agreement. The
signed response is checked with `SignedRemoteApprovalResponse.verify` — the
Mac's own acceptance rule — before it is published. One decision runs at a
time. The answer goes to this iPhone's own response record,
`response-<requestID>-<phoneDeviceID>`. If that record already exists, the app
reads it: its own valid answer to the same request (an earlier save whose reply
was lost) is kept and reported as the decision the Mac acts on; anything else
there is overwritten. The outcome says what happened: sent, already answered
earlier (and how), the Mac no longer waiting, Face ID cancelled, iCloud
unreachable, or — when iCloud names it — the account problem that kept the
answer from being sent. A card leaves when its request leaves the mailbox. The
Mac deletes the request and then the answer when it accepts an answer or
stops waiting, and only the answer when it refuses one (an answer whose clock
is more than 30 seconds from the Mac's, say); so when a sent card's request is
still there but this iPhone's answer is gone — checked a few times just after
sending and on every refresh — the card opens again, says the answer was not
accepted, and can be decided again. After a save that reported a failure
(its reply may have been lost after it landed), a later tap that finds the
request gone says the earlier answer may have been applied rather than that
nothing was sent. A request this iPhone already answered, or found withdrawn,
is never shown as live again while its record is still there or comes back —
a delete the Mac could not make, or a replay: the Mac never reuses a request
ID. The app keeps
those request IDs, the last 1,024 and nothing else, in a Keychain record
beside the identity and the pinned Macs (`decided-requests-v1`), so a relaunch
remembers them; a new setup clears it. The relay also drops any request
record not stored under `request-<its requestID>`.

**iCloud.** When the mailbox cannot be read, the list keeps the requests this
iPhone last verified and says why under it. At each activation, and after a
mailbox read or a decision fails, the app asks iCloud for the account's state
(`approvalAccountStatus`, bounded), so a signed-out, restricted (Screen Time
or device management) or not-yet-ready account each gets its own line; any
other failure reads as the network. An account problem is not reported as a
refused alert subscription.

Every CloudKit call the app makes is bounded (`ApprovalViewModel.mailboxCall`).
A CloudKit call waits on an iCloud that does not answer for as long as its
operation allows. In an iOS 26.5 Simulator with no iCloud account, reads,
saves and the account status had not returned after minutes, and neither
cancelling the awaiting task nor `CKOperation.Configuration`'s request and
resource timeouts ended them. A decision, a pairing or a refresh that waited
would hold Face ID, or every later refresh, until the app was relaunched.
Reads, subscriptions and the confirmation and status saves get
`RemoteApprovalBound.readNanoseconds` (5 s), the bound the Mac uses. A
decision's save gets 15 s (`decisionSaveNanoseconds`), since a save cut off
costs the reader another Face ID. A call that misses its bound is a transient
failure. A refresh makes no further iCloud call once one of its own has not
answered, so its bounds do not add up, and says it could not reach iCloud
when that left the mailbox unread; a decision says the Mac may not have it.
Pairing's outcome frees Face ID before the refresh that follows it. The call
itself goes on, so a save given up on can still land. A later tap then finds
that earlier answer in this iPhone's slot and reports it, and a request
withdrawn meanwhile says the earlier answer may have been applied.

**Notifications.** After setup the app asks for notification permission and
registers for remote notifications. It saves three CloudKit subscriptions: a
silent one on request creation, which wakes the app so an open app shows the
card at once, a visible one on alert creation — the Mac creates the alert
record 30 seconds after its prompt opened, or at once while the Mac is locked
or asleep — and a silent one on request deletion, which wakes the app to take
a settled request's card, alert and badge count off. The settled one is saved
on its own after the other two: if iCloud refuses it with a failure no retry
fixes, alerts still work and the app says "Answered requests may stay on this
iPhone" with iCloud's reason. The alert push carries the fixed text "A Mac is asking for your
approval" and is mutable. The notification service extension
(`ConvenientSecurityApprovalNotifications`) reads the request the alert names,
checks its Mac signature against a pinned Mac, and only then puts the card's
words in its place — the kind of request, "From" the pinned Mac, the command
and the requester (`RemoteApprovalNotificationText`, shared with the card);
anything it cannot read or verify in time keeps the fixed text. It reads the
pinned Macs through the app's own Keychain access group (the extension's
`keychain-access-groups` names it), from the record `PhoneIdentityStore`
writes `AfterFirstUnlockThisDeviceOnly`, so it works while the iPhone is
locked; `Shared/PinnedMacRecords.swift` is the one definition both targets
compile. Each alert also tidies the ones before it (`RemoteApprovalAlertSweep`),
because iOS runs the extension for every alert but delivers silent pushes only
when it chooses to: the extension reads the request of each csec alert still
delivered (at most 16) by ID, removes those whose request is gone, keeps any
it could not read, and sets the badge to the verified requests still waiting,
from the mailbox query and those reads, only when the query answered. An alert
for a request already gone when it arrives says "no longer waiting", passive
and silent. An existing subscription under any of the three IDs is kept only
if it is exactly that one — no record fields in the push, exactly its alert,
creation (deletion, for the settled one) of its own record type only — and is
replaced otherwise. Every push makes the app fetch
the mailbox and verify every Mac signature. An alert's record name,
`alert-<requestID>`, says which request it is for: tapping it (or the alert
arriving while the app is open) also reads that request by its ID, so a
backlog the mailbox query does not return in full cannot keep it off the
list, verifies it like any other, and keeps reading it on later refreshes
until it leaves the mailbox (at most 16 such requests are followed). A tap
scrolls to that request's card, or says the request is no longer waiting or
was already answered here. With
notifications off, the app says that requests appear only when it is opened
and links to Settings. When iCloud refuses the subscription with a failure no
retry fixes — a Production container whose schema lacks it answers "attempting
to create a subscription in a production container" — the app says requests
won't alert it and shows iCloud's reason, instead of dropping the error; each
refresh tries the save again, and a network or throttling delay changes
nothing.

**Phone status.** The app reports its version, protocol version, whether
notifications are on, and, once it has tried to save the subscription, whether
a request alerts it (`RemoteApprovalPhoneAlertState`: ready, subscription
refused, push registration failed) in a `RemoteApprovalPhoneStatus` signed by
the signing key, for `csec doctor`. It also lists the review kinds the app
shows a card for (`reviewKinds`, every `RemoteApprovalReview.Kind` this build
knows, since the card's switch over them is exhaustive); csecd offers a
settings review only to a phone whose status lists `settings`. A status with
the alert state, or with review kinds, is signed under its own domain, so
neither field can be dropped from a signed record, and one without them keeps
the original encoding that older apps signed. The signing
key needs Face ID, so the status is never a prompt of its own: a change noticed
at launch or in the foreground is signed with the next Face ID the user gives
anyway (pairing or a decision), then published, and retried from storage
without Face ID if iCloud was unreachable.

## Demo

Someone with no Mac to pair (App Review, or anyone deciding whether to set
csec up) would otherwise see an empty app. **Try a demo request**, on the
setup screen and in the empty list of an iPhone with no Mac paired, opens a
demo: three sample cards from a "Demo Mac" — secret access, an SSH sign-in to
an unknown host, and sudo — under a banner that says they were made up on
this iPhone and reach nothing. Approve and Deny freeze the card and raise
Face ID exactly as a real decision does; a passed Face ID then shows what a
Mac would do with the answer, saying nothing was sent. A cancelled or failed
Face ID decides nothing and leaves the card decidable. On an iPhone where
Face ID cannot run (not enrolled, locked out), the demo says the real app
needs it and shows the decision anyway, so it never dead-ends. **Start the
demo again** brings fresh cards. It is in every build, Release included, and
is offered only while no Mac is paired, so a sample is never shown beside a
real request.

It is kept apart from real approvals by construction (`DemoMode.swift`). The
card (`ApprovalCard`) reads its state from, and hands its decision to, the
`ApprovalCardHost` it is given: the paired list gives it the model, which
signs and publishes; the demo gives it `DemoApprovals`, whose decision is one
throwaway `LAContext` evaluation that no key ever sees. Its sample requests
are built on the iPhone with an empty signature, so they could never verify
as a Mac's. `bin/ci` fails if `DemoMode.swift` names the model, the mailbox,
CloudKit, the Keychain, the phone's identity or keys, any signing, or a file
or network API, if its requests are signed, or if the card reads a model from
the environment; and it fails if the demo is missing from the Debug or
Release device build. The UI tests check that deciding every demo card, before
setup and beside a set-up iPhone with the simulated mailbox, makes no
signature with the phone's key and no key agreement, creates no identity, and
leaves the mailbox exactly as it was.

For App Review's notes: the app pairs with a Mac running Convenient Security,
so without one, open **Try a demo request** on the first screen; each sample
card is decided with Face ID, and nothing leaves the iPhone. A video of real
pairing and a real request goes with the notes.

## Installing it

`packaging/bin/build-and-install.sh` builds this app and installs it on your
paired iPhone after the Mac side is installed and verified;
`packaging/bin/build-and-install.sh --only-iphone` does just that part. See the
iPhone stage in [`../packaging/README.md`](../packaging/README.md) for the
prerequisites (Xcode signed into the team, the phone paired and registered) and
what the stage checks.

The installed build is the **Debug** configuration, signed with Apple
Development by Xcode's automatic signing and then re-signed by the installer
without `get-task-allow`, so no debugger can attach to it; the installer refuses
an app that still carries it. (A development-signed app can still be re-signed
and reinstalled from the Mac; TestFlight or App Store distribution would close
that.) It uses the CloudKit **Production**
environment, because a Developer ID Mac can reach only Production and both
sides must share one database, with the **development** push environment, the
only one a development profile allows. **Release** is the App Store build:
CloudKit Production and production push (see "App Store release" below). `bin/ci` keeps both
entitlements files aligned with `packaging/agent/csecd.entitlements`.

The Mac and the phone must run the same protocol version: a v3 app and a v2 Mac
(or the reverse) use different CloudKit record types and never see each
other's requests, so remote approval silently stays local-only until both are
updated.

The Simulator-only test backend described below is compiled only into a Debug
build for the Simulator (`DEBUG && targetEnvironment(simulator)`); a Debug
build for the phone runs the Secure Enclave path.

## App Store release

The app is free and ships through TestFlight and the App Store once App
Review accepts it; the Mac does not wait for it. What the source has to
carry for that is in place, and `bin/ci` checks it on the Release device
build:

- **Privacy manifests.** The app and the notification extension each ship a
  `PrivacyInfo.xcprivacy`: no tracking, no tracking domains, no collected
  data, and no required-reason API. The app has no third-party SDK, and what
  it stores goes to the user's own private CloudKit database, which the
  developer cannot read. `bin/ci` fails if either binary starts calling a
  required-reason API (file timestamps, boot time, disk space, active
  keyboards, `UserDefaults`), so the manifest has to change with the code.
- **Export compliance.** `ITSAppUsesNonExemptEncryption` is `NO`. The app
  signs with Secure Enclave keys, answers a Secure Enclave P-256 key
  agreement that lets the Mac open its locked storage, and reaches CloudKit
  over Apple's TLS. Every one of those operations is Apple's (CryptoKit, the
  Secure Enclave, CloudKit), and the app links no cryptography of its own.
  Apple's key reference says to set `NO` when an app uses only encryption
  exempt from export documentation, and its documentation table lists
  "encryption limited to that within the Apple operating system" as needing
  none, with no French declaration either. The US self-classification report
  (15 CFR 740.17(e)(3)) covers mass-market components and hardware-derived
  executable software, not an app like this one. If the app ever brings its
  own cryptography, revisit this answer before the next upload.
- **Privacy policy in the app.** Guideline 5.1.1(i) wants it in the app as
  well as on the App Store page: the list ends with a **Privacy policy**
  link to `https://convenientsecurity.app/privacy`, before and after setup.

To archive the Release build and upload it to TestFlight:

```sh
packaging/bin/provision.sh testflight
```

It regenerates the project, archives with Xcode's signed-in team account
(`-allowProvisioningUpdates`, which creates the App Store distribution
certificate and profiles the first time), exports for the App Store into
`packaging/build/ios/`, and uploads with the App Store Connect API key the
wrapper delivers on a descriptor. The build number is `CURRENT_PROJECT_VERSION`
followed by the time, as the installer's builds are, so it only grows. The
upload goes to internal testers; external testers need Beta App Review first.

These steps happen in Apple's accounts, not in the source, and each keeps its
own approval:

1. Create the app record in App Store Connect for
   `com.alexspeller.convenient-security.approval`, then run the lane above.
2. Install that TestFlight build on the paired iPhone and confirm a request
   alert arrives: the first proof of production push.
3. Deploy `packaging/cloudkit/remote-approval.ckdb` to CloudKit Production,
   after the phone has saved all three subscriptions
   (`csec-approval-requests-v3`, `csec-approval-alerts-v3`,
   `csec-approval-settled-v3`) in Development from a
   `CSEC_CLOUDKIT_ENVIRONMENT=Development` build (see
   `docs/remote-approval.md`, CloudKit schema). The deploy takes
   every record type in the file as it is on `main`.
4. App Store Connect metadata: the privacy label (the manifest above supports
   "Data Not Collected"), privacy policy and support URLs on
   `convenientsecurity.app`, whose privacy page must describe the iPhone app
   before submission, the EU trader status, the export questions answered as
   the key above says, and the review notes from "Demo" with the pairing
   video.
5. The physical acceptance run on signed installed builds stays its own gate.

## The Xcode project

`project.yml` is the source of the Xcode project. Generate it with the XcodeGen
version pinned in the repository's `.tool-versions`:

```sh
mise exec -- xcodegen generate --spec ios/project.yml
open ios/ConvenientSecurityApproval.xcodeproj
```

The project has the app, its notification service extension, and the UI
tests. The version and build number are set once, in the project-level
settings both targets inherit, and so is `CSEC_CLOUDKIT_ENVIRONMENT`
(Production), which both targets' entitlements name; `bin/ci` fails if a
target overrides any of them.

The generated `.xcodeproj` is not tracked. `ConvenientSecurityApproval/Info.plist`
and `ConvenientSecurityApprovalNotifications/Info.plist` are generator output
that is tracked: change `info.properties` in `project.yml`, regenerate, and
commit the result; `bin/ci` fails when generation does not
reproduce the tracked file. The version and build number are set once, as
`MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` in `project.yml`, and the
installer appends a per-build stamp to the build number.

The app icon's sources are the SVGs in `Artwork/`: the default, and the dark
and tinted appearances iOS 18 and later use. Their PNGs in
`ConvenientSecurityApproval/Assets.xcassets/AppIcon.appiconset` are rendered
from them, opaque as iOS requires; after changing an SVG, render them again
from `ios/`:

```sh
for icon in AppIcon AppIcon-dark AppIcon-tinted; do
  rsvg-convert -w 1024 -h 1024 "Artwork/$icon.svg" |
    magick png:- -alpha off -strip \
      "PNG24:ConvenientSecurityApproval/Assets.xcassets/AppIcon.appiconset/$icon.png"
done
```

`bin/ci` generates the project and builds it, unsigned, for the Simulator and
for a device, checks that the device build carries none of the Simulator test
mode, and runs the UI tests below on a throwaway Simulator.

## Simulator

A Debug Simulator build uses an explicitly insecure backend — software P-256
signing and key-agreement keys, simulated Face ID — under a permanent orange
**SIMULATOR TEST MODE** banner. It needs full Xcode but no Apple portal or
iCloud setup, and it makes no CloudKit call until a real Mac is paired.

**Inject signed sample request** signs synthetic, value-free requests with a
simulated Mac key: one of each kind, or any one of

- secret access with provider notes and warnings on its secrets and scope and lifetime
  choices;
- secret access from a language client over `csec bridge`, whose headline is
  the reason its program wrote and whose card shows that program's command
  line, as the Mac read it, under it;
- SSH sign-in to an unknown host;
- SSH from a script Claude Code auto mode declined, with the decline note and
  a pairing line that offers to pin the script;
- sudo;
- a new Claude Code hook to acknowledge (a settings change);
- reopening approvals after a restart (restore only, with an unlock challenge);
- secret access that also reopens approvals, with an unlock challenge;
- a long secret access and a long SSH sign-in (every field near its bound,
  the most choices and host names a review may carry, U+FFFD where the Mac
  replaced a control character) from a second simulated Mac whose name
  carries a right-to-left override and a newline, which the phone must show
  as U+FFFD.

Deciding one runs the real decision path with simulated Face ID. The simulated
Mac then accepts it with `SignedRemoteApprovalResponse.verify` and reports the
scope and lifetime it received; for a request with an unlock challenge it made
a remote-unlock enrollment against this Simulator identity's key-agreement key
(`RemoteUnlockCrypto.enroll`), blinded a challenge for the request, and opens
the remote key with the phone's answer (`RemoteUnlockCrypto.openRemoteKey`),
so the whole cold-unlock computation runs in the Simulator. In Simulator choose
**Features › Face ID › Enrolled**, then **Matching Face** or **Non-matching
Face** while the Face ID sheet is up. A strip under the list counts, since
launch, the Face ID sheets raised, how many a matching face passed, the key
agreements made to answer an unlock challenge, and the signatures the phone's
signing key made after setup.

Launched with `--csec-simulator-mailbox`, the app talks to a **simulated
mailbox** (`SimulatedMailbox`) in place of the private iCloud database,
through the same `PhoneMailbox` protocol `CloudKitRemoteApprovalRelay` meets,
so the real refresh, decision, confirmation and alert-tap code runs. It keeps
its records in a file in the app's container, so a relaunch finds what the
last run left, and its simulated Macs never withdraw anything: they are the
Mac whose delete failed. The **Simulated mailbox actions** menu at the top of the list then offers a
pairing from a mailbox Mac (or from the last one again with a new key),
posting a signed access, SSH or sudo request (optionally one the mailbox query
leaves out, as a large backlog could), deleting the pairing confirmations,
having the Mac refuse the answers (deleting them and waiting on) or take them
(withdrawing what was answered), losing the reply to the next answer after it
lands, and switching the simulated iCloud account (available, signed out,
restricted, not ready, network down, or not answering, where every call waits
until the account is switched again and then finishes, even one the app
stopped waiting for, as a CloudKit call does); lines under it count what the mailbox
holds and how many cards reached the list.

## UI tests

`ConvenientSecurityApprovalUITests` drives the Simulator test mode and runs
only on a Simulator. It covers, on the smallest Face ID iPhone the runtime
offers:

- setup costing exactly one Face ID and then asking for notification
  permission — with the explanation of what an alert shows under the
  prompt — the Mac command with the pairing code, and a relaunch that needs no
  Face ID;
- an identity from a protocol v2 build, and one that does not decode or whose
  keys do not match, each leading to **Set up this iPhone again**;
- a refused Keychain read leading to **Try again** and never to setup, and the
  same identity back, with no Face ID, once the read works;
- a Mac's offer, and offers that replace pinned Macs: a Mac of the same name
  added beside it or replacing it (**Add as another Mac** / **Replace**), and
  the same Mac with a new key, each showing the key paired now;
- against the simulated mailbox: a request answered before a relaunch not
  shown again while a second, unanswered one is; a tap on the alert for a
  request the mailbox query leaves out bringing that request's card on screen
  and deciding it; a deleted pairing confirmation published again once per
  activation, with no Face ID; a pairing made while iCloud does not answer
  showing its outcome within the save's bound, and its confirmation sent,
  with no Face ID, once iCloud answers; a decision and a refresh while iCloud
  does not answer each finishing within their bounds, with Face ID and Refresh
  free again, and the decision's save landing once iCloud answers, after which
  the next tap reports that answer; a signed-out, restricted and not-ready account
  and a network failure each named under the list, and a decision that could
  not be sent saying why; an answer the Mac refused reopening its card, which
  is decided again (also after a relaunch); after a save whose reply was
  lost, a request the Mac then withdrew saying the earlier answer may have
  been applied; and a request whose Mac stopped saving it again leaving the
  list with no refresh, staying off it while the Mac is quiet, and coming
  back, still answerable, once the Mac saves it again;
- a cold-unlock approval: one Face ID, one key agreement, and the simulated
  Mac opening its remote key with the answer;
- a changed scope and lifetime being exactly what is signed, and the card
  frozen (Approve, Deny and the choices disabled) while Face ID is up;
- the pairing line following the selection (hidden for another scope or a
  lifetime cap, back for the Claude Code session until it exits), and the
  simulated Mac reporting a pairing exactly when the line was on screen at the
  tap;
- **Forget these approvals** on a restore that carries an unlock challenge
  computing no key agreement;
- a non-matching face, then **Cancel** on the Face ID sheet, sending nothing
  and leaving the card decidable;
- an SSH sign-in to an unknown host, denied;
- a new Claude Code hook to acknowledge, showing the Mac panel's title, each
  change line and its footnote with no pairing line, approved with one Face ID
  and no scope or lifetime, and its lines staying within the screen at the
  largest text size;
- a language client's request showing its program's command line under the
  reason headline, within the screen, and a request whose headline is its own
  command showing no second one;
- the largest accessibility text size stacking Approve over Deny, and the long
  fixtures staying within the screen, expanding, neutralizing the lookalike
  Mac's name, and signing their longest choices;
- VoiceOver labels naming the Mac on every decision button, and Xcode's
  accessibility audit (element descriptions and traits) of each card kind.
- the demo, before setup and beside a set-up iPhone with no Mac paired:
  each sample card decided with Face ID (one cancelled first, leaving the
  card decidable), with no phone-key signature, no key agreement, no identity
  created, the simulated mailbox unchanged and no card on the real list; and
  **Start the demo again** bringing the cards back.

The runner simulates Face ID itself: it is a process inside the Simulator, so
the Darwin notifications behind **Features › Face ID** reach the simulated
sensor from it (`com.apple.BiometricKit.enrollmentChanged` with state 1 to
enroll, `com.apple.BiometricKit_Sim.pearl.match` or `.nomatch` for a face). A
face presented while no sheet is up is ignored, so the tests present one every
second until the counter strip shows the sheet passed it; a non-matching face is
presented until the sheet offers **Try Face ID Again**, which stops it
listening, so exactly one face is refused. Every wait is bounded. A wait for
the app's own work to show (a launch, a refresh, a mailbox call) allows 30 s
and returns as soon as it shows, because a Mac running other sessions' builds
and tests can starve the Simulator for seconds; a check that something does
not happen keeps a short window. A tap on the simulated mailbox's menu can be
lost on such a Mac, so the mailbox counts the actions its menu runs (its
line's accessibility value, `N actions run`), and the tests make a tap again
only when the count did not move.

The tests start the app with launch arguments compiled only into the Simulator
test mode: `--csec-simulator-erase-identity` deletes the Simulator's approval
records (the Simulator keeps Keychain items across reinstalls) and the
simulated mailbox; `--csec-simulator-seed-legacy-identity`,
`--csec-simulator-seed-undecodable-identity` and
`--csec-simulator-seed-mismatched-identity` then store a protocol v2
identity, one that does not decode, or one whose keys do not match;
`--csec-simulator-refuse-keychain-reads` refuses every Keychain read with
`errSecInteractionNotAllowed`, as a locked iPhone does, until a Simulator
button lifts it; `--csec-simulator-mailbox` turns on the simulated mailbox,
`--csec-simulator-icloud-signed-out`, `-restricted`, `-not-ready` and
`-unreachable` set its account, and
`--csec-simulator-open-alert-for-hidden-request` opens the app as a tap on
the alert for its latest request the query leaves out. A
Simulator build must be signed, if only ad hoc, for those records: an unsigned
build gets `errSecMissingEntitlement`. To run the tests yourself:

```sh
xcodebuild test -project ios/ConvenientSecurityApproval.xcodeproj \
  -scheme ConvenientSecurityApproval \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM=
```

or **Product › Test** in Xcode. Notification permission can be asked for only
once per install, so a setup must show the prompt exactly when permission was
still undecided before it. The test mode's counters strip says so in its
accessibility value (`notifications unread|undecided|on|off`, as the app read it
from the system, then `; scene active|inactive|background`), and the tests read it before each setup rather than counting setups: xcodebuild
relaunches the test runner after a test times out or crashes, and a relaunched
runner would otherwise expect a prompt the Simulator already answered. On the
Simulator `bin/ci` makes for every run, where the app was never installed, the
run's first setup therefore must ask. The
new one is a clone of a base device that has booted once and never had an
app installed (`bin/ci-ios-simulator.py`), so the run skips a first boot's
data migration, which takes minutes while the Mac is busy. Local CI admits
cold-base bootstrap and the clone's full build/test lifetime separately through
a shared host simulator gate (`CSEC_CI_SIMULATOR_RUN`). It confirms Shutdown before deleting its
clone and preserves live/legacy devices and existing warm bases; see
[development and verification](../docs/development.md). The app-fresh clone,
ad hoc signing, full test set and per-test bounds apply inside that lifetime.

The Simulator does not exercise the Secure Enclave keys, whether one Face ID
covers both of them on a real device (the Diagnostics probe in a Debug device
build answers that), biometric-set invalidation, APNs delivery, cross-network
CloudKit, the notification service extension, or a real Mac withdrawing a
request (the simulated mailbox's Macs never do). Those are covered by the
physical acceptance matrix in
[`../docs/remote-approval.md`](../docs/remote-approval.md#physical-acceptance-matrix).
Do not commit personal provisioning profiles or generated signing state.
