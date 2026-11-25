<!-- Full text of an AGENTS.md topic, moved unchanged; paths and links in it are relative to the repository root. AGENTS.md keeps a summary and says when to read this file; where they differ, this file wins. -->

## Design ethos — "more secure, conveniently"

Optimize for **more security at low UX cost**, not minimal privilege and not
maximal hardening:

- If csec can make the machine more secure than the macOS default automatically,
  at low UX cost, that ships **on by default** — after one confirmation. Do not
  avoid a capability (e.g. Full Disk Access) when acquiring it buys the user real
  security they would otherwise never configure by hand. There is **no
  "minimal-footprint" goal for csec's own privileges.**
- Same-user malware is **not fully solvable**. The thesis: blocking ~80% of
  real-world attacks at low UX cost beats a "perfect" tool that gets turned off.
  Judge every feature on (security delivered × likelihood the user leaves it on).
- The adversary is the **automated, opportunistic supply-chain attack** — a
  trojaned dependency / postinstall / extension / CLI hitting easy, widespread
  targets — **not** a targeted operator studying csec. Prioritize controls by how
  much they frustrate that attacker; don't over-invest against a bespoke one.
- **Strong defaults, few commands.** Prefer a small number of commands that each
  do as much as possible automatically after a single confirmation, choosing a
  secure-but-convenient tradeoff over perfect convenience or perfect security.
- **Confirm each thing exactly once — as far as possible.** A prompt must mean
  "something *new* is asking for authorization," never "reconfirm a decision you
  made hours ago and have since forgotten." Re-authentication with no fresh
  context adds **zero** security — a prompt approved without reading is not a
  decision — and it actively *costs* security by training the user to dismiss
  csec dialogs blindly. So a grant lives for the lifetime of the process or
  session it was granted to, with **no wall-clock cap**; a resolved value stays
  cached until something real invalidates it (rotation, explicit invalidation,
  daemon restart), not until a clock runs out. A **time-based expiry is
  presumptively wrong** and must earn its place by preventing a concrete harm —
  a hang, a runaway unattended job, a clickjack, an unbounded at-rest exposure —
  never as periodic re-verification for its own sake. A timer that merely
  duplicates a bound already enforced another way (a cache TTL sitting on top of
  a grant that already gates access) is redundant: remove it. Weigh a re-prompt
  as one of the most expensive things csec can ask — it arrives hours or days
  later, with no context, and every needless one erodes the meaning of the next.
