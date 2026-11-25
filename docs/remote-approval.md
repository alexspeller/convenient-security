# iPhone remote approval

## User experience

Remote approval is the same approval mechanism on a second screen, not a new
policy mode:

1. Pair one iPhone once under Touch ID on the Mac and Face ID on the phone.
2. A secret-access, SSH-signing, restore or sudo review, or the rules- and
   hooks-changed acknowledgement csecd raises for a Claude Code request, opens
   the ordinary Mac prompt and mirrors the exact frozen, value-free review to
   the paired phone, whichever provider holds the secrets, as long as a phone
   approval could carry it out (see "What reaches the phone" and "sudo"). The request is on
   the phone at once, so the app shows it when opened, but the phone's
   notification waits until the Mac prompt has been open for 30 seconds: a
   prompt answered at the Mac within that time never alerts the phone. While
   the Mac's screen is locked or its display asleep — nobody can see its
   prompt — or Touch ID is unavailable on it (nothing enrolled, locked out,
   the lid closed with no Touch ID keyboard), so the phone is the only
   approver, the notification goes at once, and a Mac that locks or loses
   Touch ID during the wait sends it then. The notification says what the phone's card says: the
   kind of request, the Mac, the command and the requester, in words the
   phone's notification service extension takes from the request only after
   its Mac signature verifies (see "Notifications").
3. Touch ID on the Mac or Face ID on the phone can decide it. The first verified
   decision wins and cancels the other surface.
4. Neither surface expires. csecd blocks until one of them answers, whether
   that is in ten seconds or in an hour. What ends a wait other than an answer
   is withdrawal — see below. Two of csec's own bounds withdraw a request
   nobody answers: a coding agent's request after its 20-minute wait, and the
   sudo review just before the PAM module's five minutes. Such a request
   carries that moment, and the Mac panel and the phone card both say when it
   closes and count down its last 30 seconds. The phone never acts on it: the
   Mac's withdrawal ends the request, as any other. While it waits, the Mac
   saves its request again every minute, so the phone can tell a Mac that is
   still there from one that stopped for good ("Liveness", below).
5. A relay failure changes nothing: the local prompt remains usable. With no
   pinned phone, csecd performs no CloudKit request at all.

There is no per-secret enrollment, separate remote policy, reusable approval
token, or server account. Pairing is the only opt-in.

## Pairing

The checked-in iOS app shell lives in `ios/`. Once a CloudKit-capable physical
build is installed:

1. Tap **Set up this iPhone**, then **Copy the command for your Mac**. The app
   shows this iPhone's key fingerprint under it.
2. On the Mac, run the copied command:

   ```sh
   csec remote enable '<csec-phone-v2:...>'
   ```

   Both pairing codes are public — identifiers, names and public keys, nothing
   secret — so any channel can carry them (Universal Clipboard, AirDrop, a
   message to yourself). What a channel could do is swap in another phone's
   code, and the fingerprints are what catch that: compare the one Touch ID
   names below with the one the phone shows, and the Mac key the phone shows
   in step 3 with the one this command prints. Damage on the way cannot pin a
   wrong key unnoticed either: a code that no longer decodes is refused, and a
   changed key shows a different fingerprint.

   The daemon shows Touch ID with the phone name and public-key fingerprint,
   saying that the phone's Face ID will approve requests and open csec's
   stored secrets on this Mac. That one touch pins the phone's keys in a
   code-identity-gated Keychain record, enrolls the phone-held unlock factor,
   and seals a copy of every existing native key record and cache entry to it
   (read with that same touch; nothing stays open afterwards). If the factor
   cannot be enrolled, nothing is paired. It then offers the pairing to that
   phone through the private iCloud database (a pairing offer, below), prints
   this Mac's key fingerprint and its public Mac pairing code, and waits.
3. With the app open, the iPhone shows the Mac under **A Mac asks to pair**
   within a couple of seconds, so the Mac code never has to be copied back.
   If it does not — the offer could not be published, which `csec remote
   enable` says, or iCloud is slow — paste the `csec-mac-v2:...` code into the
   app and tap **Check Mac code**. Either way, before anything asks for Face
   ID, the app shows the Mac's name
   (with control, format and bidirectional characters neutralized, as the Mac
   panel does) and the fingerprint of its key, to compare with what
   `csec remote enable` printed. If this Mac is already pinned it says the
   pairing is replaced, shows the key paired now beside the new one, and says
   whether the key changes; if another pinned Mac has the same name it shows
   that Mac's key too and offers to replace it (the same Mac paired again) or
   to add this one beside it. Accept with Face ID; the Face ID prompt names the
   Mac and its key. The phone publishes its signed confirmation of the
   pairing, and `csec remote enable` reports the pairing confirmed. Ctrl-C
   only stops the waiting: the pairing stays, and `csec remote status` says
   when the phone confirms. Each time the app becomes active it reads each
   delivered confirmation back once and, if it has gone missing from iCloud,
   publishes it again without Face ID, so a csecd that restarts later still
   finds it.

The paired-Mac list on the phone shows each Mac's key fingerprint beside its
name, so two Macs with the same name stay distinguishable there and in the
unpair confirmation.

Inspect or remove the opt-in with:

```sh
csec remote status
csec remote disable        # Touch ID gated
```

`disable` removes the pairing and deletes the phone-held unlock factor's
enrollment and every sealed copy; if a copy cannot be deleted then, csecd
removes it at its next start, when it finds an enrollment with no pairing.
Unpairing on the phone only forgets the Mac there; the Mac still needs
`csec remote disable`.

Pairing codes carry device IDs, display names, public P-256 keys, the app
version and the CloudKit container identifier. They contain no credential
values or private keys. The phone's code carries two public keys, both of
Face-ID-gated Secure Enclave keys made with one Face ID at setup: the signing
key that signs every decision, and the key-agreement key the phone-held unlock
factor is wrapped to, with the signing key's signature over it so the Mac pins
only a key-agreement key the phone's identity vouches for. The Mac signing key
is generated in the Mac's Secure Enclave. Changing enrolled phone biometrics
invalidates both phone keys and requires re-pairing.

### Pairing offer

So that the Mac code never has to be copied back to the phone, `csec remote
enable` also saves it, as a pairing offer, in the private iCloud database under
`pairing-offer-<phoneDeviceID>`, the one name the phone can form before it
knows the Mac. The offer holds the Mac pairing (ID, name, public key,
container), the phone's device ID, SHA-256 digests of the phone signing key
and key-agreement key the Mac pinned and enrolled, and its creation time,
signed by the Mac key it offers (domain `csec.remote-approval.pairing-offer.v1`).
csecd publishes it within the five-second relay read bound, best-effort: a
failure leaves the pairing in place, and `csec remote enable` says to paste
the code instead.

While the app is on screen, the phone reads that one record every two seconds.
There is no subscription and no alert: the person is holding the phone while
pairing. The phone shows an offer only once it verifies — made to this phone's
ID and both its keys, and signed by the Mac key it offers — and an offer of a
Mac already pinned with that key not at all. The signature shows only that the
holder of that key made the offer to this phone; anything signed into the same
iCloud account could write one, as anyone could hand over a code to paste.
Which Mac it is, the person checks exactly as for a pasted code: by comparing
the key fingerprint with the one `csec remote enable` printed, before Face ID.
Cancel turns an offer down until the app next starts.

The Mac withdraws its offer once the phone's signed confirmation verifies
(again at each csecd start that finds a confirmation, which sweeps one a
failed delete left), when `csec remote disable` removes the pairing, and when
a pairing with another phone replaces it. A new pairing with the same phone
overwrites the offer; if that new offer cannot be published, the old one is
withdrawn, so the phone never offers a Mac key csecd no longer signs with. A
withdrawal deletes the record only when it reads that Mac's offer there.
CloudKit has no conditional delete, so a newer offer saved in between could
still go, and the printed code covers that case. Nothing about the offer has a
timer.

## Transaction binding

Before either biometric path begins, csecd freezes one value-free review from
the review the Mac panel shows (the `AccessPolicyReview`, or the sudo or
restore review) and builds the phone's copy from it (`RemoteApprovalReview`):

- the kind (secret access, SSH sign-in, sudo, reopening approvals, or a
  settings change) and that kind's facts: the SSH host names or unknown-host
  context, remote user and key; the sudo command, working directory and target
  user; the restore rows; the settings panel's change lines (its title is the
  headline);
- the sanitized headline, requester, terminal, secrets (each as its provider
  describes it: account, vault or store, item, field, label colour, notes and
  warnings, which the phone folds into the same tree the Mac draws), warnings
  and footnote, and a digest of the exact canonical reference set;
- the scope choices the panel offers, each with an ID, and its lifetime
  choices, with the panel's defaults;
- for a Claude Code request delegated approvals declined, a `delegation`
  block: the decline note, and the pairing line with the scope ID and
  lifetime index at which it applies (secret access and SSH), or unscoped on a
  sudo review, which offers no scope or lifetime;
- on a secret-access review whose headline is the reason its program wrote (a
  language client over `csec bridge`, a `csec get`), `requesterCommand`: that
  program's own command line, which csecd read from the kernel, redacted like
  a launcher's argv; the phone shows it under the headline, and the alert
  adds it as a line under the headline. It is signed only when present, under
  a domain with a `+command` suffix (`csec.remote-approval.request.v3+command`,
  or `…v3+delegation+command` with a delegation block), so a review without it
  signs exactly as before and a phone app that cannot render it cannot verify
  one that carries it;
- on a secret-access, SSH or sudo review the Mac closes unanswered,
  `closesAtMilliseconds`: that moment in Unix milliseconds on the Mac's clock
  (the request's `HumanWait` deadline, or the sudo helper's closing moment,
  which csecd keeps only when it is no further ahead than a PAM frame allows).
  The card shows it in the Mac panel's words (`ReviewDeadlineText`), a quiet
  line and then a 30-second countdown, until an answer is sent. It is signed
  only when present, under a `+deadline` suffix after any other
  (`…v3+deadline`, `…v3+delegation+command+deadline`), and the request is
  refused when it lies more than a day after `createdAtMilliseconds`, the
  longest wait csecd allows; a restore carries none. The phone shows it and
  nothing else: it refuses, hides and decides nothing by it, so a skewed phone
  clock moves only the countdown;
- the operation digest: SHA-256 over exactly what csecd will do once approved
  (the delivery plan for access and SSH, the sudo request, the listed restore
  rows, and for a settings change the set of hook and classifier-rule sources
  it acknowledges, each by the digest of its content,
  `ClaudeDelegationService.acknowledgementDigest`).

The Mac signs a versioned, length-prefixed canonical encoding of that review
with a fresh request UUID, its pinned Mac device ID and name, the creation time
and, when the approval may open sealed copies, the unlock challenge (the
enrollment ID and a freshly blinded point). The phone verifies the pinned Mac
key before rendering anything actionable. On Approve or Deny it freezes a
response holding the request UUID and digest, its device ID, the decision and
its time, the scope ID and lifetime index it selected (an approval), the unlock
answer (an approval of a challenged request), whether its card showed the
pairing line (an approval of a request that carries one) and its app version;
Face ID
authorizes its Secure Enclave key to sign exactly those bytes. csecd takes the
scope and the lifetime only from its own lists, by that ID and index, so an
answer can choose among what the panel offered and nothing else.

An outstanding phone approval ends without an answer when the requesting
process exits, when the Mac panel answers first, and when `csec remote
disable` or a new pairing revokes the pairing. After an approval, the release
still fails, minting nothing, if the requester or the chosen scope's root is
no longer the same live process when it runs.

csecd is a per-user LaunchAgent, so after a restart nothing can be approved
from the phone until you log in: there is no csecd to ask. The remote-unlock
copies are `AfterFirstUnlockThisDeviceOnly`, so none opens before the first
unlock after a boot either. A request pending while the Mac sleeps is not lost:
its poll resumes on wake and reads a phone decision made meanwhile.

## No request lifetime

v1 gave every request a 90-second expiry (120 s maximum), inside the signed
canonical encoding on both ends. A prompt that dies while you walk to your desk
is the failure mode this design cares most about: it trains the user to treat
csec dialogs as noise. v2 removed the field outright — not a sentinel value in
a retained field, the field is gone from the wire — and the Mac waits until an
answer arrives; v3 keeps it that way. `createdAtMilliseconds` stays, and with
it the ±30 s clock-skew allowance, but both do one job only: binding messages
to each other. A request may not claim to come from the future, and a decision
may not predate the request it answers by more than the skew. Neither bounds a
wait, and neither does liveness (below): it decides only whether the phone
shows a request, from when the mailbox last saved it, and a request that went
quiet comes back when its Mac saves it again.

`closesAtMilliseconds` is not that field back. It is a fact about the Mac,
not a lifetime of the request: csecd withdraws a coding agent's request at
its wait and the sudo helper closes its review at the PAM limit whether or
not the phone knows, and the field only lets the card warn of it, as the Mac
panel does. Nothing on the phone filters, hides or refuses by it, and a
request without it (a terminal's, a restore) waits exactly as before.

The current exchange is protocol v3 (`RemoteApprovalProtocolV3.version` is 3):
a request says which kind of approval it is and carries that kind's facts, the
phone signs the scope and lifetime it selected, and an approval may answer an
unlock challenge. Each version changes the signed bytes, so each is a version
bump, not a compatible change: the signing domains are
`csec.remote-approval.request.v3` / `…response.v3`, and the CloudKit record
types and subscriptions are `CSECApprovalRequestV3` / `CSECApprovalResponseV3` /
`CSECApprovalAlertV3` (with `CSECPairingConfirmationV3`, `CSECPairingOfferV3`
and `CSECPhoneStatusV3` for pairing) and `csec-approval-requests-v3` /
`csec-approval-alerts-v3`, so builds of different versions never read each
other's mailbox at all. An envelope of another version that does reach v3 code
is rejected as `invalidVersion` rather than parsed. Pairing is its own version
(pairing v2, the `csec-phone-v2:` / `csec-mac-v2:` codes, which add the phone's
key-agreement key); see "Deployment coupling". Within v3, the delegation block
and the pairing-line answer are additions that keep every other message's
bytes: each is encoded only when present, under its own domain
(`csec.remote-approval.request.v3+delegation`,
`csec.remote-approval.response.v3+pairing-line`), so a request or answer
without it signs exactly as before. The requester's command line (`+command`),
a settings review's lines (`+settings`, a kind that never carries a delegation
block or command line) and the deadline (`+deadline`) follow the same rule. A phone app that predates them cannot
verify a request that carries the block and leaves it to the Mac panel.

### What makes a request single-use

With no expiry, replay protection rests on what is actually single-use:

- csecd accepts a decision only for a request **currently pending** in its
  in-memory table — published by this daemon and still being waited on by the
  client that asked for it. A decision for anything else is `notPending`.
- Each request ID is consumed at most once (`alreadyConsumed`), so a duplicate
  delivery of a decision cannot be applied twice.
- The response still has to bind: same request ID, same request digest, the
  pinned phone device ID, a decision not predating the request, and that phone's
  signature over exactly those bytes. A wait reads only its own request's slot
  (below) and ends only on a response to *that* request: a valid answer to
  another pending request, copied into this slot, is refused before the
  acceptance gate sees it, so it neither ends this wait nor uses up the answer
  it really is.
- Withdrawal removes the request from the pending table **before** the mailbox
  record is deleted, so anything that races the delete is refused.

On the phone, a request it has already answered — or found withdrawn while
answering — is never shown as live again while its record is still in the
mailbox or comes back: csecd never publishes a request ID twice, so such a
record is a delete csecd could not make, or an old signed request saved again.
The app keeps the last 1,024 such IDs, and nothing else, in a Keychain record
beside its identity and pinned Macs, so a relaunch remembers them.

csecd deletes an exchange request first and the answer last when it accepts
an answer or stops waiting, and deletes only the answer when it refuses one
(a decision time more than 30 seconds from its clock, say). So when the phone
sees a request it answered still in the mailbox but its own response record
gone — it looks a few times after sending and on every refresh — it forgets
that it answered, opens the card again with a note that the answer was not
accepted, and lets the person decide again. This is presentation only: the
pending table still decides what counts. It cannot tell a refusal from an
acceptance whose request delete failed while the answer's delete worked; a
second answer to a request csecd no longer waits on is simply `notPending`.
After a save that reported a failure, a later tap that finds the request gone
says the earlier answer may have been applied, since the save may have landed
with its reply lost.

Nothing else used the expiry as a control: it filtered the phone's inbox, drove
the phone's countdown, and set an upper bound on `decidedAt` — all display or
housekeeping, all replaced above. The countdown the card shows now is the Mac's
own deadline (`closesAtMilliseconds`), not a lifetime of the request.

### Mailbox records

The mailbox holds six kinds of record, each under one name computed from
canonical identifiers (a UUID in its lowercase 36-character form) by
`RemoteApprovalMailboxName`:

| Record | Name | Written by |
| --- | --- | --- |
| request | `request-<requestID>` | the Mac, and saved again every minute while it waits |
| alert | `alert-<requestID>` (no payload) | the Mac, once the phone should be alerted |
| response | `response-<requestID>-<phoneDeviceID>` | the answering phone |
| pairing confirmation | `pairing-confirmation-<macDeviceID>` | the phone |
| pairing offer | `pairing-offer-<phoneDeviceID>` | the Mac, at `csec remote enable` |
| phone status | `phone-status-<phoneDeviceID>` | the phone |

Anything signed into the same iCloud account can write the private database,
so the mailbox is treated as attacker-writable until a signature binds a
record:

- **No record name from a payload.** `CKRecord.ID` raises an Objective-C
  exception — which Swift cannot catch, so the process aborts — for an empty
  name or one over 255 bytes. The relay forms every record ID through one
  function that checks the name first (non-empty, at most 255 bytes of
  printable ASCII, no leading `_`) and throws a Swift error otherwise, so a
  hostile record cannot crash csecd, let alone at every start.
- **A request is listed only under its own name.** The relay drops a request
  record whose name is not exactly `request-<its payload's requestID>`: a
  signed request copied under another name is a replay, and a delete by the
  payload's ID would not remove the record that carried it.
- **Sweeps act only on this Mac's own records.** The startup and re-pair
  sweeps delete an exchange only when its request ID is canonical and its Mac
  signature verifies with that pairing's Mac key; an upper-cased copy of a live
  request, a forged record in this Mac's name, or a record with an empty or
  oversized ID is left where it is. (A re-pair after a pairing record that
  could not be read, so whose key is unknown, deletes only canonical records
  naming that Mac ID.)
- **One response slot per phone.** The Mac reads only its pinned phone's
  record. Anything another writer leaves for the same request lands under a
  different name, where it neither answers nor blocks. A record in the pinned
  phone's slot that does not bind, or does not decode at all, is deleted by the
  Mac, so the phone's real answer can land there and the next poll does not
  read it again; withdrawing the exchange deletes the pinned phone's response
  record with the request.
- **The phone never mistakes someone else's record for its own answer.** If
  its save finds the slot taken, it reads the record there. If that is its own
  valid, signed answer to the same request (an earlier save whose reply was
  lost), it keeps it and reports exactly what that answer decided, not the new
  tap. Anything else there is overwritten with the new answer.

The phone's subscriptions are checked too: an existing subscription under
`csec-approval-requests-v3`, `csec-approval-alerts-v3` or
`csec-approval-settled-v3` is kept only if it is exactly the one the app would
save — its record type, every record, on creation only (on deletion only, for
the settled subscription), no record field copied into the push (no
`desiredKeys`, no localization arguments, no badge), and exactly its alert:
none for the request and settled subscriptions, the fixed text, mutable, for
the alert subscription. Anything else under any of those IDs is deleted and
replaced, and a failed check is retried on
the next refresh; a refusal no retry fixes is shown on the phone and reported
to `csec doctor` (see "Status and recovery"). Any other query subscription on
a csec record type is deleted: the container is csec's alone, so one is either
an older version's or one another client saved, perhaps to copy request
fields into its pushes. The replacement happens only when
the app runs, so after an update that changes a subscription the first request
can still be announced the old way; that push's wake-up is what runs the app and
replaces it.

### Withdrawal

A request with no expiry would otherwise sit on the phone forever, and a stale
Approve button is exactly the blind-approval training the design ethos rejects.
csecd deletes the mailbox records (the request and the pinned phone's response)
when:

- the local window answers first — the losing phone prompt is removed as part of
  cancelling that leg;
- the requesting client is cancelled or goes away, which cancels the review;
- `csec remote disable` or pairing again revokes every request the old pairing
  has in flight; pairing again also sweeps the records the previous pairing
  left behind;
- csecd starts up, for any request record this Mac signed that it is not
  currently waiting on, as soon as the iCloud account is available. A crash or
  restart cannot leave an approvable prompt behind.

Both sweeps delete only records provably this Mac's (see "Mailbox records").

#### Liveness

None of that runs on a Mac that stops for good: one that crashes and never
runs csecd again, or is wiped or lost. Its request record would stay in the
mailbox, and on the phone, as a card "Waiting for 3 days" whose Approve
nothing is listening for. Approving it would do nothing, but it is a stale
Approve button all the same. So while csecd waits on a request it saves the
record again every minute (`RemoteApprovalLiveness.refreshIntervalNanoseconds`,
the requester's refresh leg beside its poll and alert), with the same signed
envelope, and CloudKit stamps each save with the server's modification date.
The phone shows, badges and alerts a request only while the mailbox saved it
within the last ten minutes (`RemoteApprovalLiveness.quietAfterSeconds`); a
record not saved for longer is from a Mac that has gone quiet.

This is not an expiry. Nothing about the request runs out, and the phone
neither answers, forgets nor deletes a quiet request: it takes the card off
(the two-second watch, every refresh, and the notification service
extension's tidy, which removes its delivered alert and leaves it out of the
badge; an alert for one says it is no longer waiting), and a tapped alert for
one says the Mac has not been in touch and may be asleep, offline or no longer
running csec. A Mac that comes back saves the record again within a minute,
and the next refresh brings the card back, still answerable. The Mac's pending
table still decides whether an answer counts, as it always did.

- The save time is the mailbox's own (CloudKit's `modificationDate`, a system
  field, so the schema needs nothing new), compared with the phone's clock.
  The Mac's clock plays no part. A save time ahead of the phone's clock never
  makes a request quiet; a phone clock set far ahead would hide every request,
  as one set behind already refuses them (the 30-second skew).
- Ten minutes is ten refresh intervals: more than a save delayed by the
  longest throttle (60 s), a few failed attempts (each retried on the poll
  interval) or a network that is slow to come back.
- A Mac asleep, or offline, for longer than that also goes quiet, so its card
  leaves the phone until it wakes or reconnects. Nothing is lost: an answer
  given meanwhile could only be read once the Mac was back, and the Mac's own
  panel is in front of the person who wakes it.
- The record is not signed again: the save time only decides whether the
  phone shows a request, never what an answer means, and anything that could
  keep a dead Mac's record looking fresh could already put an old signed
  request back. The refresh overwrites whatever is under the request's name,
  so one deleted by anything but this Mac is put back while the Mac still
  waits; the request subscription fires on creation only, so a refresh wakes
  no phone. `finish` deletes the mailbox only after the refresh leg returns,
  as it does for an alert save, so a refresh in flight cannot outlive the
  withdrawal.

Deleting the request record fires the phone's settled subscription, a silent
push that wakes the app. After every mailbox read the app removes the
delivered alerts of requests it can no longer answer and sets the badge to the
requests still waiting, so the lock screen holds no Approve that leads
nowhere. iOS delivers a silent push only when it chooses to: it throttles them
(Apple asks for no more than two or three an hour), keeps only the newest, and
drops them for an app the user force-quit. So two more paths do the same
work. While the app is on screen it reads each unanswered card's request by ID
every two seconds and drops the card whose request has left the mailbox. And
the notification service extension, which iOS runs for every alert, tidies
before each new alert: it reads the request of each csec alert still
delivered (at most 16) by ID, removes those whose request is gone (a failed
read keeps the alert), and sets the new alert's badge to the verified requests
still waiting, from the mailbox query and those reads, when the query answers
(`RemoteApprovalAlertSweep`). An alert whose own request is already gone when
it arrives says "no longer waiting", delivered passive and silent, and the
next wake removes it. A settled alert can therefore stay on a phone whose
silent pushes iOS is holding back until the app opens or the next alert
arrives, never under a new one. Silencing that last case needs Apple's
notification-filtering entitlement (csec-vo4.26).
Every delete, sweep and pairing-offer withdrawal that does not land (the
network not back yet after wake, a throttled relay) is kept and tried again,
two seconds later and then on a doubling delay up to five minutes, for as long
as csecd runs; it is tried at once when the iCloud account comes back or a
request publishes. A record already gone counts as deleted. A Mac that loses
the network just as you answer at the Mac therefore takes the card off the
phone as soon as it is back, rather than at its next start.

The order is the guarantee. The request leaves the pending table first, so any
decision offered afterwards is refused; the waiting caller is answered next,
before any relay IO, so the local window winning costs one actor hop however
slowly CloudKit responds; the mailbox delete runs last, in the background, once
a save still in flight has landed. When both surfaces approve at once, the
losing local approval is cancelled, which invalidates its Touch ID context and
closes the window. A local Touch ID failure ends the phone leg too, on purpose:
the Mac panel is the one surface the person at the Mac can see and cancel.

The phone drops a request that has left the mailbox. If Face ID was already
open, the phone checks that the record still exists before publishing and
reports "no decision was sent" instead. That check is presentation only: the
Mac's pending table is what decides whether a decision counts, so a failed check
does not stop the phone from answering.

### Waiting versus giving up

The Mac polls for the response every 750 ms. A relay error that polling can fix
is waited through, not converted into a failure — when publishing the request
as much as when polling for the answer: rate limiting and a busy or briefly
unreachable server delay the next attempt (honouring CloudKit's `retryAfter`,
capped at 60 s so one server-supplied number cannot park the wait), a network
that is not back yet after wake, a lost server reply and an account that is
briefly not ready are transient, and an unrecognised transport error is treated
the same way. A query on a field that is not indexed (`invalidArguments`) is a
schema problem and stays permanent. Only a
condition no amount of polling can fix — no iCloud account, a managed-account
restriction, a permission failure, a bad/missing container or database, a
missing entitlement, an incompatible version, or an exceeded quota — makes the
mirrored leg unavailable, at which point the ordinary local prompt carries the
request exactly as it does today for an unpaired Mac.

CloudKit database ownership is never authorization. Invalid mailbox records are
ignored (and one in the pinned phone's response slot is deleted). A valid signed
denial is terminal; missing iCloud or an invalid response is merely unavailable
and leaves the local prompt running.

### Status and recovery

`csec remote status` names the actual cause instead of one "unavailable", with
advice for that cause, and `csec doctor` / `csec status` show the same row:

| Status | Meaning | Advice | Doctor |
| --- | --- | --- | --- |
| not paired | no phone is paired | — | ok |
| enabled | paired, record and Mac key usable, iCloud available | — | ok |
| unsupported build | this csecd lacks the CloudKit container entitlement | reinstall the current Convenient Security package, or rebuild from your source checkout | fail |
| iCloud unavailable | no account, restricted, not ready, or status unreadable | cause-specific; the last two clear on their own | warn |
| pairing invalid | the record is corrupt, names another container, or this Mac's Secure Enclave key is gone or different | `csec remote disable`, then pair again | fail |
| Keychain unavailable | the Keychain refused the read just now | transient; csecd reads again | warn |

While paired, the row also says what csecd knows about the phone: whether it
has confirmed the pairing (warn until it has), the app version from its latest
signed status, whether it may show notifications (warn when not: requests then
appear only when the app is opened), whether a request alerts it at all (warn
when iCloud refused its subscription or it could not register for pushes;
reported once the phone has tried, and carried to the Mac with the next Face
ID it takes), and whether the phone-held unlock is
enrolled (warn when not: requests that need stored secrets opened stay on the
Mac). Both the row and `csec remote status` also say whether Claude Code hook
and rule acknowledgements reach the phone, always in so many words: they do
(the phone's signed status lists them); they stay on the Mac because that
status does not (an app that predates them, or one that has not taken a Face
ID since it was updated); they stay on the Mac because csecd has no signed
status from the phone; or csecd did not say (one older than this csec, and
`csec remote status` names the installer). A missing answer never reads as a
yes. The row says it as information, never a warning, since the Mac still
decides every such request. A phone
app that reports another remote-approval protocol than this
Mac's warns and names the update for the older side. For an older phone app,
use its original channel (App Store or TestFlight), or run
`packaging/bin/build-and-install.sh --only-iphone` for a source build.
The unconfirmed warning also mentions the phone update, because a phone app from
another csec version reads other record types and never confirms at all.
`csec remote status` also says how long ago the phone last reported, by its
own clock: information only, never a timeout, since an app nobody opens
reports nothing and is still paired. These come from records the pinned phone
signs; one signed by anything else is ignored, and none of them authorizes
anything.

Reading the status (`csec remote status`, with or without `--json`, and the
row in `csec status` and `csec doctor --check`) shows no panel, asks for no
Touch ID and never repairs, pairs, or changes trust or policy. It is not free
of writes, though: it runs the same refresh csecd runs for a request, so it can
re-read a record the Keychain refused, sweep prompts this Mac left in the
mailbox (the first time iCloud is available after a start or a sign-in), and
withdraw this Mac's pairing offer once the phone's confirmation verifies.
Cleanup that failed earlier keeps being retried by csecd's queue as usual.

Nothing in this diagnosis deletes or replaces the pinned record; only `enable`
and `disable`, each behind Touch ID, do. A record that failed to read, and the
iCloud account, are checked again on every status check, every request, and
every iCloud account change. `disable` asks for Touch ID only when a record may
exist. The account-status read is bounded at 5 s so a wedged system account
service cannot hang these commands; running out of time reports "could not
determine", which is transient.

The phone draws the same line. A Keychain read that fails — typically
`errSecInteractionNotAllowed` because the iPhone has not been unlocked since it
restarted — or any failure while the phone's protected data is unavailable,
shows "not available yet" with **Try again**, and is read again on the next
activation or push; nothing is re-created because of it. Only an identity that
was read and does not decode, or whose keys no longer match, offers **Set up
this iPhone again**, as does one from an earlier format.

Every string on the phone review is sanitized and then cut to its wire bound
with the ellipsis inside the budget, so a long or multi-line command is
shortened rather than keeping the request off the phone. A review the phone
format cannot carry at all (more than 64 references) stays on
the Mac and csecd logs why.

#### `csec remote status --json`

For a program that has to know, rather than infer from a missing warning,
that the phone is ready: one JSON object on one line, sorted keys, every field
present, `null` where csecd did not say. It carries no phone name, key
fingerprint, device ID or other identifier, and nothing secret. The exit
status is the text command's (non-zero for a build without the relay, a
pairing to redo, or an unavailable state csecd gave no cause for); a csecd
that cannot be reached, or that answers without a status, prints nothing on
standard output and exits 1, as the text command does.

```json
{"cause":null,"macProtocolVersion":3,"phoneConfirmed":true,"phoneProtocolVersion":3,"phoneSettingsReviews":"shown","phoneStatusUpdatedAtMilliseconds":1790000000000,"schema":1,"state":"enabled"}
```

| Field | Meaning |
| --- | --- |
| `schema` | `1`; a new number means a field changed meaning or went away |
| `state` | `enabled`, `disabled` or `unavailable` |
| `cause` | why it is `unavailable` (`unsupported_build`, `icloud_account_unavailable`, `pairing_invalid`, `keychain_unavailable`), else `null` |
| `phoneConfirmed` | the phone published a signed confirmation of this pairing; `null` with no usable pairing or from an older csecd |
| `macProtocolVersion` | the remote-approval protocol csecd speaks, as csecd reports it; `null` from an older csecd |
| `phoneProtocolVersion` | the protocol in the phone's latest signed status; `null` without one |
| `phoneStatusUpdatedAtMilliseconds` | when the phone wrote that status, by its own clock (information, never a timeout); `null` without one |
| `phoneSettingsReviews` | `shown`, `not_shown`, `no_phone_status` or `not_reported`, as below |

`phoneSettingsReviews` is csecd's own reading of the pinned phone's latest
status, the one that decides whether a hooks- or rules-changed acknowledgement
is offered to the phone: `shown` when that status, verified against the pinned
phone's key, lists `settings`; `not_shown` when it does not; `no_phone_status`
when csecd has verified no status from the phone or has no usable pairing
(every state but `enabled`). `not_reported` is this client's reading of an
answer without the field, from a csecd older than it or with a value it does
not know; csecd never sends it. Only `shown` is a yes. csecd still sends the
older `phoneShowsSettingsReviews` Bool on the socket for an older `csec`.

### Deployment coupling

The Mac agent and the iPhone app must be updated together. `csecd` publishes and
accepts only v3, in v3 record types; the shipped app speaks only v3.
`packaging/bin/build-and-install.sh` rebuilds and reinstalls the iPhone app in
the same run as the Mac build. If only one side is updated across a protocol
version, each subscribes to and publishes its own version's record types, so
no prompt appears on the phone and every request is decided locally; an
envelope of the other version reaching either side any other way is refused as
`invalidVersion`. Either way the failure is "remote approval degrades to
local-only", never a mis-parsed prompt, and `csec doctor` warns (see "Status
and recovery").

For a source build, upgrading and rolling back use the same command:
`packaging/bin/build-and-install.sh`, run from the tree you want, newer or
older, rebuilds and reinstalls the Mac side and the iPhone app together. Both
directions keep the pairing record and the phone-held unlock enrollment on the
Mac, and the phone's identity, pinned Macs and answered-request list in its
Keychain. The sealed remote-unlock copies do not survive a run of a build that
does not keep them: the next start of one that does drops them, and they come
back as each value is next opened at the Mac. A rollback across a pairing
format change reads the pairing as invalid: `csec remote disable`, then pair
again. `--skip-iphone` and `--only-iphone` update one side only; across a
protocol change that leaves remote approval at the Mac panel until the other
side is updated.

The per-phone response name (`response-<requestID>-<phoneDeviceID>`) replaced a
shared `response-<requestID>` within v3, without a record-type change. An app
older than that change answers under the old name, which the Mac no longer
reads: its decision is never seen, and the Mac's own prompt decides. Update
both together.

## Relay and data exposure

`CloudKitRemoteApprovalRelay` uses the current iCloud user's private database in
`iCloud.com.alexspeller.convenient-security`. It stores signed JSON envelopes
under the record names in "Mailbox records", for as long as a Mac is waiting
on them — the Mac deletes the exchange when it stops waiting and sweeps its
own leftovers at startup. A Mac that never runs csecd again leaves its last
request there, off the phone once it goes quiet ("Liveness"), until another
pairing of that Mac sweeps it or the record is deleted from iCloud. It never stores resolved values,
cache material, native-store ciphertext/keys, environment values, or a reusable
capability. It does store the value-free review metadata listed above, and the
review's headline is the command line the Mac panel shows, when the request has
one: the launcher's full argv, passed through csecd's output redaction,
newlines kept, and fitted to the headline's 2,048-byte wire bound (a sudo
review's command has the same bound). A request with no argv of its own whose
requester csecd could read carries that requester's redacted command line in
`requesterCommand`, under the same 2,048-byte bound. A settings review carries
the Mac panel's change lines as the panel shows them: each new hook's name and
source, what its handlers run as its settings or plugin file writes them (a
command and its arguments, or any other handler's JSON, which can hold a
literal header value), a hooks module's file and SHA-256, and classifier rule
text. They come from files csecd reads, not from values it released, so output
redaction, which covers released values, has nothing to remove from them.
Opting in explicitly accepts syncing that metadata, command lines and hook
definitions included, through the user's private CloudKit database while a
request is pending.

The iPhone installs three query subscriptions, and replaces one under any of
their IDs that is not exactly it (see "Mailbox records"): a silent one for
request creation, which wakes the app so an open app shows the card at once, a
visible one for alert creation, and a silent one for request deletion, which
wakes the app to clear what is no longer waiting (see "Withdrawal"). The Mac
creates the alert record when the phone should be alerted (see
"Notifications"). No push carries a request field; each is only a wake-up hint, and the app fetches pending records and
verifies the Mac signature every time. The Mac polls for
its pinned phone's one response record while the ordinary local prompt is open,
so there is no csec-operated push server or long-lived internet service.

### Notifications

The request record reaches the phone as soon as the review opens; the alert is
a separate record, `alert-<requestID>`, which csecd's requester creates once
its alert gate opens (`RemoteApprovalAlertTiming`): after the Mac prompt has
been open for 30 seconds, or at once while the Mac's screen is locked, its
main display asleep or Touch ID unavailable on it, re-checked every half
second during the wait. Touch ID is probed on a fresh context, as the panels
probe it, and only while the Mac reads unlocked and awake. A sudo panel
without Touch ID still takes the password at the Mac, so a sudo answered that
way may buzz the phone too; the phone is the only approver that takes a
touch then, so the alert goes at once rather than late. An answer
on either surface, a withdrawal or a revoked pairing cancels the wait, so a
request decided first never alerts the phone, and the alert record is deleted
with the request. The wait delays a notification; it bounds nothing — the
request has no lifetime, and the phone may decide it from its card before the
alert. The same requester serves secret access, SSH, restore and sudo, so all
four are timed the same way.

The alert push carries only the fixed text "A Mac is asking for your approval"
and is mutable. The phone's notification service extension reads the request
the alert names from the private database, finds the pinned Mac it claims,
verifies its signature, and only then replaces the text: the card's heading
(Secret access / SSH sign-in / sudo requested, or reopening approvals), "From"
the pinned Mac's name, and the review's headline, its requester's command line
when it carries one, and requester, sanitized and bounded (`RemoteApprovalNotificationText`, shared with the card). A request it
cannot read or verify in time keeps the fixed text; one already gone says it is
no longer waiting. It reads the pinned Macs through the app's own Keychain
access group, from a record readable after the first unlock, so it works while
the iPhone is locked. What the lock screen shows of the text follows the
iPhone's Show Previews setting.

Tapping the alert opens the app on that request: the app reads the request
the alert's record name gives by its ID, as the extension does, verifies it
like any other, and scrolls to its card — so a backlog larger than the mailbox
query reads cannot keep it off the list — and keeps reading it by ID on later
refreshes until it leaves the mailbox. A request that is gone says it is no
longer waiting. Push delivery is best-effort: an alert can be late or never
come, and the Mac's own prompt and opening the app remain the way to see what
is waiting.

### What reaches the phone

Which reviews are mirrored does not depend on where the secrets are stored.
Before publishing, csecd asks the owning providers, through the resolver,
whether a phone approval could carry the review out: a reference that needs no
unlock (a warm store, a 1Password value csecd can fetch) is fine, and one that
needs an unlock is fine only when the phone-held unlock factor covers it (a
sealed copy of its store's key record or cache entry exists for the enrolled
phone). A reference whose provider would first raise its own authorization at
the Mac (`requiresAttendanceToResolve`: for 1Password, any reference whose
account csecd holds no open, recently proven session for) is fine only when
csecd holds its value warm or the phone-held factor opens a sealed copy of it.
Its value would otherwise wait on a prompt nobody away from the Mac can answer.
A one-time code is never cached, so it reaches the phone only while csecd holds
its account's session (csec-0.65.5). If every reference passes, the review goes to the phone; if the answer
needs cold storage opened, the request also carries a blinded unlock
challenge, and the phone's approval answers it with the key agreement only its
Face ID unlocks. Otherwise the review stays on the Mac.

A reference its provider can fetch with no unlock still gets the challenge
when csecd holds a sealed copy of its cached value for the enrolled phone. A
phone approval then reads that copy first, as a Mac approval reads the
biometric cache, so a 1Password value csecd has cached is released even while
1Password is locked along with the Mac. When the provider could answer without
anyone at the Mac, an approval whose answer does not open the factor still
stands, and the provider is asked under its own authorization, as it would be
with no challenge. When the provider would prompt at the Mac, the copy is the
only way to deliver, so the challenge is required: an approval that does not
open it is no decision, and the Mac's prompt still carries the request. No scheme is named
anywhere in that decision, so a newly registered provider takes part by
answering it. A restore section's rows are judged the way a restore reopens
them, not the way a release resolves them: a reference whose value a restore
can bring back only from the biometric cache (a 1Password value csecd cached,
for example) counts as needing an unlock, covered only by that entry's sealed
copy. The restore-only panel and a release panel with a restore section are
mirrored when the phone's approval could reopen every row, and a restore
reports as reopened only the rows it actually opened.

A phone approval opens only what its one request needs: the remote unlock is
dropped when that release, signature or restore finishes, successful or not,
and it can read storage but never write it.

Several things stay on the Mac by design:

- **Setup done at the Mac.** Enrolling unattended automation, editing or
  importing into a native store, and registering an SSH key are reviewed only
  locally: they are done at the Mac, and native writes need the Mac's own
  Touch ID.
- **Changes to csec's settings, but one.** Turning on auto-mode approvals,
  trusting a build, `csec setup`'s acknowledgements, pairing and the other
  setup steps are done at the Mac's terminal and decided there
  (`AccessPolicyReview.macOnly`). The exception is the rules- and
  hooks-changed acknowledgement csecd raises itself when a Claude Code
  request declines on hooks or classifier rules added since the last one: the
  person may be away from the Mac, so it is answerable on either surface
  (av-rcqg). It is mirrored as a `settings` review when the pairing is usable
  (it names no reference and opens nothing) and the phone's latest signed
  status lists `settings` among the review kinds it shows: an app that
  predates them drops such a request unread, so until its status says so the
  change stays at the Mac, and `csec remote status` says why. The phone's copy
  has the Mac panel's title, lines and footnote, and its operation digest
  binds the approval to exactly the sources the panel acknowledges: a source
  that changes has another digest and needs another approval. Only a panel
  that lists every source whole reaches the phone; one that leaves hooks or
  rules to `csec setup auto-mode`, or cuts a line short (the panel's own line
  bound, or the settings gate's shorter bounds on a command, a module path, a
  matcher or a source's name), or shows a command handler without a setting
  that might change what it runs, stays at the Mac, since the phone could not
  show the rest. A hooks module is listed with its entry file's path and
  SHA-256, so either surface can tell which file acknowledging it trusts,
  though neither shows what that code does or checks the files it imports.
  While the Mac's screen is
  locked it is raised only when the phone can decide it. The approval selects
  nothing, a settings request never carries an unlock challenge, and it is
  single-use like every request. Recording it writes only the delegation
  settings item, which carries no biometric ACL (csecd's mutation path is the
  gate), so a phone approval can complete it as a Mac one does.
- **Claude Code delegated approvals** never reach the phone. csecd judges them
  before the consent queue, so a release auto mode approved publishes nothing
  and withdraws nothing.
- **A request delegation declined carries its note and pairing line to the
  phone.** The frozen review gains a `delegation` block: the decline note
  ("Auto mode didn't approve this: …") and the pairing line with the scope
  option and lifetime index at which it applies. It is in the signed request
  only when present, under its own signing domain
  (`csec.remote-approval.request.v3+delegation`), so every other request signs
  exactly as before. The card draws the line exactly while that selection is
  made, by `RemoteApprovalReview.pairingLineApplies`. A sudo review's line is
  unscoped (an empty scope ID and index 0, `Delegation.Pairing.unscoped`),
  valid only on a review that offers no scope or lifetime, and applies to the
  one approval there is, which selects nothing.
- **A phone approval pairs only when its card showed the line.** The signed
  response then carries `pairingLineShown` (encoded only when present, under
  `csec.remote-approval.response.v3+pairing-line`), and csecd accepts an
  approval of such a request only when that answer is present and equals the
  shared rule for the signed scope and lifetime. A line too long for the wire
  is left off the review, so the phone shows none and its approval cannot
  pair. An older phone app cannot verify a request that carries the block, so
  it never shows one: those requests are answered on the Mac.

The phone offers the same scope and lifetime choices as the Mac panel, with the
same default preselected, and signs the one chosen; csecd accepts only an
option it offered. The grant is minted only once the release (or signature)
succeeded, from either surface: an approval whose resolution fails mints
nothing, so the next identical request is reviewed again. The decision log
records a phone approval with outcome `phone_approved` and decider
`human_phone` (a phone Deny: `denied`, `human_phone`), and a release that
failed after approval as a `delivery_failed` record following the approval. A
pairing or an acknowledgement a phone approval wrote is a `settings` record
with decider `human_phone`, as is a phone Deny of a settings change.

### sudo

The sudo review is drawn by `csec-sudo-review`, the helper the PAM module
spawns as the login user, not by csecd. The helper opens its panel and, at the
same moment, sends csecd one `sudo_remote_review` request with the facts the
panel shows (the redacted command, working directory, tty and terminal tab;
see [protocol](protocol.md#sudo-review-on-the-paired-phone)). Both ends
authenticate each other's live code identity first: csecd answers only the
helper as the product team signed it (`build-and-install.sh` signs it with the
Developer ID), and the helper takes csecd's answer, which ends a root
authentication, only from the product agent. csecd mirrors a review of kind
`sudo` whenever the pairing is usable; it needs no unlock, offers no scope or
lifetime, mints no grant and opens nothing. Before any of this the helper asks
csecd whether Claude Code auto mode's approval stands in for the review
(`sudo_delegation`); an approved sudo opens no panel and reaches no phone. For
one delegation declined, the mirrored review carries csecd's own note and,
when approving would let auto mode run sudo in the project, its unscoped
pairing line; a phone approval whose signed acknowledgement says the card
showed it pairs sudo with that project. The first verified answer wins:

- Touch ID on the panel approves; the phone's copy is withdrawn (the helper's
  connection closes and csecd's peer-exit watch withdraws it).
- The phone's approval approves; the panel closes and its LAContext is
  invalidated, exactly as a phone decision closes the access and SSH panels.
- Use Password on the panel, or the phone's Deny, lets sudo fall back to its
  password prompt.
- No csecd, no paired phone, or relay trouble: the panel alone decides, with no
  added delay, exactly as before remote approval.
- Touch ID unavailable on the Mac (nothing enrolled, locked out after failed
  attempts, the lid closed): the panel cannot approve, so it is up only while
  the phone may still decide, saying to approve on the iPhone or use the
  password. When the phone cannot decide either, at the start or later, the
  helper ends the review unsuccessful at once, with no panel if it never
  showed one, and sudo goes on to Apple's prompt
  (`SudoReviewWithoutTouchID`). If Touch ID comes back first (the lid
  opened), the panel arms it and no longer closes when the phone gives up.
  If Touch ID goes away while the panel has it armed (the lid closed with an
  external display), the panel carries on the same way rather than falling to
  the password while the phone may still decide
  (`ReviewTouchIDUnavailable.afterFailure`).

The secret-access and SSH panels (and the restore panel) behave the same way
on a Mac that cannot take a touch, except that they stay up when no phone can
decide: there is no other prompt to hand over to. `MirroredPolicyReview`
tells the local panel about its phone leg (`ReviewPhoneStatus.current`), so
the panel says "Approve on your iPhone." while the phone may decide and
"cannot be authorized" once the phone leg gives up or when the review was
never mirrored. Touch ID going away under an armed panel leaves it up in the
same state, so the phone can still approve, rather than ending the review.

A phone-decided sudo is logged (surface `sudo`, decider `human_phone`) by
csecd itself; a sudo decided on the Mac panel, or ended by its deadline or its
sudo exiting, is logged from the helper's report of it (`sudo_review_end`),
which the helper does not send for a phone decision.

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

This validates the UI, canonical request/response signatures, request binding,
and biometric control flow. It does not validate Secure Enclave key storage,
biometric-set invalidation, APNs wakeups, cross-network CloudKit, or withdrawal
(the injected fixture never reaches a mailbox).

### First physical iPhone test

Both devices use the CloudKit **Production** database: a Developer ID Mac app
may use CloudKit only in Production, and the phone must share the Mac's
mailbox. Every Mac build is signed with `packaging/agent/csecd.entitlements`,
which carries the container; holding the entitlement turns nothing on, and
csecd makes no CloudKit request until a phone is paired. The iPhone app is the
Debug configuration, dev-signed by Xcode's automatic signing, with CloudKit
Production and the development push environment (the only one a development
profile allows).

Development signing always gives an app `get-task-allow`, which would let a
debugger — driven from this Mac, where same-user malware lives, through the
paired phone's developer tunnel — attach to the approval app while it holds a
Face ID-evaluated context. `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO` does not
remove it from an iOS device build (the development profile's value is merged
in regardless), and Xcode refuses an entitlements file that sets it false. So
the installer re-signs the built app with the same Apple Development identity
and exactly the entitlements Xcode computed, minus `get-task-allow`, and
refuses to install an app whose signature still carries it. What remains: a
development-signed app can still be re-signed and reinstalled from this Mac by
something that holds the developer identity and the paired phone's trust —
including with `get-task-allow` put back — and the phone would run it.
Distribution through TestFlight or the App Store, which Apple signs, closes
that only with Developer Mode turned off on the phone afterwards: Developer
Mode is what lets a development-signed build install and run, so while it is
on, this Mac can still put one over the distributed app. Neither is done yet
(csec-vo4.14).

One-time steps:

1. In the Apple Developer portal, create the `iCloud.com.<owner>.convenient-security`
   container, enable iCloud (CloudKit) with it on the Mac App ID, and register
   `com.<owner>.convenient-security.approval` with iCloud (the same container)
   and Push Notifications. Enabling iCloud invalidates the current Developer ID
   profile.
2. Deploy the record types and indexes to the container's Production schema
   (see "CloudKit schema" below).
3. Sign into the same iCloud account on the Mac and the phone. The relay uses
   that user's private database, so different accounts never share requests.
4. Pair the phone with Xcode once (Window › Devices and Simulators), with
   Developer Mode on, a passcode and Face ID enrolled.
5. Run `packaging/bin/build-and-install.sh --refresh-profile`. `build-agent.sh`
   refuses to sign unless the refreshed profile authorizes every restricted
   entitlement csecd carries; the installer checks the installed csecd's
   CloudKit signature, then builds the iPhone app, installs it on the paired
   phone with `devicectl`, and reads its stamped build number back.
   `--only-iphone` reruns just the phone stage; `--skip-iphone` leaves it out.
6. Pair the phone and Mac using the public codes above.

### CloudKit schema

The phone lists pending requests with a query, which CloudKit serves only when
the record type's `recordName` is indexed as queryable; every other read, the
phone's of a pairing offer included, fetches by ID, and the Mac saves,
fetches by ID and deletes, and queries the request records only for its
startup and re-pair sweeps. Production creates no record type or index on the
fly, and the Mac can only use Production, so the schema is deployed before
anything runs. It lives in `packaging/cloudkit/remote-approval.ckdb`, and
`bin/ci` fails if it misses a record type the relay uses, its `payload` or
`deviceID` field, or the request type's queryable index. With a CloudKit
management token saved once (`xcrun cktool save-token --type management`, which
prompts for it):

```sh
xcrun cktool validate-schema --team-id 8RS6GD89Y7 \
  --container-id iCloud.com.alexspeller.convenient-security \
  --environment development --file packaging/cloudkit/remote-approval.ckdb
xcrun cktool import-schema --team-id 8RS6GD89Y7 \
  --container-id iCloud.com.alexspeller.convenient-security \
  --environment development --validate --file packaging/cloudkit/remote-approval.ckdb
```

then, in the CloudKit Console under the Stateful Ltd team, choose the container,
**Deploy Schema Changes…**, and Deploy. `cktool export-schema --environment
production` shows what Production has. Development and Production databases
never exchange an approval.

The phone's subscriptions (`csec-approval-requests-v3`, silent,
`csec-approval-alerts-v3`, which raises the alert, and
`csec-approval-settled-v3`, silent, on deletion) are not in the `.ckdb`: the
schema language cannot express a subscription, and Production refuses to
create one its schema has never seen —
`Invalid Arguments`, "attempting to create a subscription in a production
container" (`CKSubscription.h`: create subscriptions in Development first, then
promote them). So a new container, a new record type a subscription watches,
or a changed subscription needs the phone app to save it in Development once,
before a schema deploy. From the
repository root, with the phone paired, unlocked and connected:

```sh
mise exec -- xcodegen generate --spec ios/project.yml
xcodebuild -project ios/ConvenientSecurityApproval.xcodeproj -scheme ConvenientSecurityApproval \
  -configuration Debug -destination generic/platform=iOS -derivedDataPath /tmp/ck-dev-dd \
  -allowProvisioningUpdates CSEC_CLOUDKIT_ENVIRONMENT=Development build
xcrun devicectl device install app --device <the phone's identifier> \
  /tmp/ck-dev-dd/Build/Products/Debug-iphoneos/ConvenientSecurityApproval.app
```

`CSEC_CLOUDKIT_ENVIRONMENT` is the build setting both iPhone targets'
entitlements name; `ios/project.yml` sets it to Production, and `bin/ci` fails
if a target overrides it. Open the app for a few seconds: it saves all three
subscriptions in Development
(`sudo log collect --device-udid <UDID>` shows its `CKModifySubscriptionsOperation`
finishing with no error). Then **Deploy Schema Changes…** as above: the Console
lists no changes, because it does not show subscriptions, but deploying is what
carries the subscription to Production. Put the ordinary build back with
`packaging/bin/build-and-install.sh --only-iphone`; the phone then saves the
subscription in Production and no longer shows "Requests won't alert this
iPhone".
While this build is installed the phone reads the Development database, so the
Mac's requests do not reach it. Until Production has the subscription, the
phone shows "Requests won't alert this iPhone" with iCloud's reason, and
`csec doctor` warns once the phone has reported it with a Face ID. The settled
subscription is saved apart from the other two, so Production refusing it
alone leaves alerts working: the phone says "Answered requests may stay on
this iPhone" with iCloud's reason, the extension still tidies before each new
alert, and each refresh tries the save again. That refusal stays on the phone;
it is not part of the signed phone status.

### Physical acceptance matrix

`bin/ci` generates the iPhone project and builds it, unsigned, for the Simulator
and for a device, and `cs-selftest` covers every case below with synthetic keys
and in-memory relays. Neither reaches the Secure Enclave, real Face ID, APNs and
the notification service extension, cross-network CloudKit, a real 1Password,
or a real Mac panel closing when the phone wins. So the feature is not claimed
as released until this matrix passes on the signed installed build, with
a Face ID iPhone and the Mac on different networks (the phone on cellular, its
Wi-Fi off). Development and Production CloudKit are not interchangeable: run it
against the build the release ships.

**How it runs.** A session at the Mac drives the Mac side and records evidence;
the human gives a Face ID, a touch or a phone setting change when a row asks
for one. The rows are in two sittings. The first changes nothing beyond csec;
the second changes the whole phone (its iCloud account, its enrolled Face ID,
its biometric lockout) or csec's pairing, so it is run only when that cost is
wanted, for a release.

**Synthetic records only.** Create disposable records once, in destinations
kept for testing, and remove them afterwards:

- a native value, `csec://acceptance/VALUE` (`csec edit csec://acceptance/VALUE`,
  any throwaway text);
- a native blob: a throwaway file in a scratch directory imported with
  `csec protect`, delivered back through its sidecar with `csec exec`;
- a 1Password field in a vault kept for testing, `op://<test vault>/<item>/<field>`;
- an SSH key held by csec (`csec ssh register`) authorized on a test host.

A child proves delivery without printing anything derived from a value:
`csec exec --set X=<reference> -- sh -c '[ -n "$X" ] && echo delivered'`, or
`test -s <path> && echo delivered` for the blob. An SSH row passes when `ssh`
authenticates to the test host.

**Evidence, value-free.** Record, before the first row: the source revision
(`git rev-parse HEAD` and the installed
`plutil -extract CSECSourceCommit raw /Applications/ConvenientSecurity.app/Contents/Info.plist`),
macOS and iOS versions, the phone app's build (`csec remote status`, and the
installer's `iPhone approval app installed and verified` line), the CloudKit
environment (`codesign -d --entitlements -` on csecd and the phone app), and
`csec doctor`. `csec doctor` does not compare the phone's build number with
the Mac's; the installer pins it. For each row record the time, what was done,
and the outcome from `csec log --since <time> --json` (`phone_approved`,
`human` denials, withdrawals), `csec grants` (a phone grant's origin), and what
the phone and Mac showed. A failure is filed as a bug under the remote-approval
epic with the same evidence and blocks the release until fixed and re-run.

**Everyday use counts.** A row whose pass condition the decision log shows
from real use needs no staged run: `csec log --json` records every phone
decision (`decider` `human_phone`) with its surface, references and outcome,
`csec log --kind reuse --json` the grant reuses after it, and `restart`
records date each build. Count a row only from records on the build under
test, or say which builds they span; the phone side of a row (a card leaving,
an alert's text) is not in the Mac's log, so it passes on what the human saw.

Restart csecd for a cold row with
`launchctl kickstart -k gui/$UID/com.alexspeller.convenient-security`; restored
grants then raise the restore panel, itself a row.

#### First sitting: no change beyond csec

| # | Case | Mac side | Human | Passes when |
| --- | --- | --- | --- | --- |
| 1 | Cold native value | restart csecd, then the delivery check on `csec://acceptance/VALUE` | Face ID on the phone, nothing on the Mac | delivered; log `phone_approved`; no second local biometric |
| 2 | Cold native blob | restart csecd, then `csec exec` in the protected scratch directory | Face ID on the phone | delivered |
| 3 | 1Password | delivery check on the test `op://` reference | Face ID on the phone; 1Password's own prompt if it asks | delivered; a 1Password sign-in is reported, never bypassed |
| 4 | Mixed references | one `csec exec` with the native and `op://` references | one Face ID | both delivered by one decision |
| 5 | SSH signature | restart csecd, then `ssh` to the test host | Face ID on the phone | authenticates; phone review showed the host and user |
| 6 | sudo | `sudo -k; sudo true` | Face ID on the phone (its alert comes after 30 s) | succeeds; the Mac sudo panel closes |
| 7 | Restore panel | restart csecd with a live grant | Face ID on the phone | the grant is restored |
| 8 | Automation stays on the Mac | a `csec automation` registration | none on the phone | the phone never shows it |
| 9 | Grant reuse | repeat row 1's command in the same tree | none | no panel, no phone review |
| 10 | Local wins | any request | wait for the phone card, then touch Touch ID at the Mac | delivered; the phone card leaves |
| 11 | Phone wins | any request | Face ID on the phone while the Mac panel is up | delivered; the Mac panel closes and its Touch ID no longer answers |
| 12 | Deny is terminal | any request | Deny on the phone | refused; identical requests already waiting are refused too; a later Approve does nothing |
| 13 | Simultaneous decisions | any request | Face ID on the phone and Touch ID on the Mac together | it acts once; the log has one decision |
| 14 | Caller interrupted | a request, then Ctrl-C | none | the phone card leaves; a late phone Approve says none was sent |
| 15 | Caller killed | a request, then `kill` its process | none | as row 14; nothing is released |
| 16 | Mac locked or without Touch ID | a request, then lock the Mac; again with the lid closed on an external display (or Touch ID locked out) | Face ID on the phone | the phone alerts at once, not after 30 s; delivered |
| 17 | Mac asleep | a request, then `pmset sleepnow` | Face ID on the phone within ten minutes, while the Mac sleeps; then wake it | the answer is taken after wake and delivered; nothing is lost or released twice |
| 18 | Phone offline | a request with the phone in airplane mode | Touch ID at the Mac; then airplane mode off | local approval works; the phone shows nothing to answer |
| 19 | Mac offline, reconnect | Wi-Fi off on the Mac, a request, Wi-Fi on | Face ID once it reaches the phone | delayed, not ended; delivered |
| 20 | Notifications off | turn off csec's notifications in iOS Settings, then `csec remote status` | turn them back on afterwards | status and doctor warn; requests show when the app is opened |
| 21 | 1Password locked | lock 1Password, then row 3 | Face ID on the phone | fails in the provider, unless csecd holds a sealed cached copy, which is then released without 1Password |
| 22 | App in background | any request | Face ID from the notification | the alert names the Mac, kind and command |
| 23 | App force-quit | force-quit the app, then a request | open from the alert | the alert arrives; the card is there |
| 24 | Phone locked | a request with the phone locked | Face ID from the lock screen | as row 22; a settled request's alert is removed |
| 25 | Phone restarted | restart the phone and leave it locked, then a request | unlock, then open the app | the pending list shows; never "set up again" |
| 26 | Face ID fails or is cancelled | any request | a non-matching face, then Cancel | nothing is sent; the Mac panel stays answerable |
| 27 | Long wait | a request from a terminal, not a coding agent, left unanswered for over an hour (a coding agent's request is withdrawn after `CodingAgentApprovalWaitMinutes`, 20 by default) | Face ID on the phone | still approvable; delivered |
| 27a | Mac gone quiet | a request from a terminal, then `kill -STOP` csecd's process (its panel freezes too); after eleven minutes `kill -CONT` it | watch the phone | the card leaves the phone about ten minutes after csecd stopped, and its alert comes off; it comes back, still answerable, within a minute of csecd resuming |
| 28 | Not debuggable | `codesign -d --entitlements -` on the built phone app | none | no `get-task-allow` |

#### Second sitting: changes the phone or the pairing

| # | Case | Mac side | Human | Passes when |
| --- | --- | --- | --- | --- |
| 29 | Face ID lockout | any request | fail Face ID until it locks out, then the passcode | the phone says Face ID is locked and sends nothing; after the passcode Face ID approves again |
| 30 | Signed out of iCloud | `csec remote status`, then a request | sign the phone out of iCloud, and back in afterwards | status names the cause; local approval works |
| 31 | Changed enrolled Face ID | `csec remote status`, then a request | add or reset a Face ID appearance | the phone says its approval key could not be used and to set up again and re-pair; nothing is approved; local approval works |
| 32 | Revocation | `csec remote disable` with a request waiting | Touch ID | the waiting request leaves the phone; nothing reaches the phone after |
| 33 | Re-pair | `csec remote enable <code>` | accept the offer on the phone with Face ID | row 1 passes again; requests from before are withdrawn |

**Evidenced by `cs-selftest` alone**, because no shipped tool can drive them on
the installed build: decisions signed by the wrong Mac or phone key, a changed
request display or digest, replay (`RemoteApprovalTests`, the V3 and mailbox
suites); hostile record names, empty or oversized request IDs and junk in the
phone's response slot (mailbox suite); and the provider-neutral adapter, since
shipped csecd registers only `csec` and `op` (the `RemoteCoverageFixtureProvider`
and `keyring://` tests, and `bin/ci`'s neutrality guard). Cite the suite run on
the same revision.
