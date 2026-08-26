# `csec audit` — implementation plan

Implements the host posture audit specified in
[`host-audit-catalog.md`](host-audit-catalog.md). Every design decision is
resolved (see that doc's *Decisions*); this plan has no open items. It is grounded
in the current codebase: the CLI dispatch and dry-run→apply model in
`Sources/csec/SetupCommand.swift`, the minimal allow-listed `RootHelperRequest`
enum in `Sources/CSECRootProtocol` + `Sources/CSECRootServer`, the
`TrustedAccessReviewSession` trusted Touch-ID window, `LaunchAgentService`
(`SMAppService`), `StartupSecurityReport` as the check precedent, and the
`cs-selftest` `check()` harness.

## Ground rules (invariants, enforced by tests)

- **Value-free.** No finding, evidence string, log line, or report field ever
  contains a credential value. Reuse `ReviewDisplay.sanitized` / the
  `safeMetadata`/`boundedMetadata` helpers for every interpolated path,
  identifier, or command fragment.
- **Read-only first.** Detection never mutates. Mutations happen only through the
  batched remediation review (one Touch ID) or an explicit guided helper.
- **No arbitrary root.** New privileged operations are a fixed, allow-listed set
  of enum variants in the root protocol — never a generic "run this command as
  root." This preserves `csec-rootd`'s current property of exposing only bounded,
  audited actions.
- **Honest coverage.** An `X`/`F`-unavailable check reports `unknown`, never a
  pass; bounded scans log their bound. (Catalog "Detection-feasibility summary".)
- **Full catalog in the first release** (Decision 9): domains A–K all ship. The
  milestone order below is a construction sequence, not a phased ship.

## 1. Core model — `Sources/ConvenientSecurity/HostAudit/Model.swift`

Typed, `Sendable`, `Codable` value types (no I/O):

```
public enum HostSeverity: String, Codable, Sendable { case high, medium, low, info }

public enum DetectionTier: String, Codable, Sendable {
    case runtimeReadable          // R
    case runtimePrivileged        // R! (root-helper hop)
    case fullDiskAccess           // F
    case unverifiable             // X
}

public enum RemediationClass: String, Codable, Sendable {
    case auto                     // in-process, reversible
    case autoPrivileged           // via csec-rootd hostApply
    case guided                   // interactive helper
    case advise                   // surface + link, never mutate
    case none
}

public enum FindingStatus: String, Codable, Sendable {
    case pass, fail, unknown, expectedSelf, notApplicable
}

public struct HostFinding: Codable, Sendable, Equatable {
    public let id: String              // "HA-C01" — stable, from the catalog
    public let title: String
    public let severity: HostSeverity
    public let tier: DetectionTier
    public let status: FindingStatus
    public let onThesis: Bool          // ★ tier-1 grouping
    public let evidence: String        // value-free, already sanitized
    public let anchor: String          // path / Settings pane / command
    public let remediation: RemediationClass
    public let remediationKey: String? // opaque key into the remediation registry
}

public struct HostAuditReport: Codable, Sendable {
    public let findings: [HostFinding]         // severity-ordered, ★ first
    public let unverifiable: [String]          // ids reported unknown and why
    public let coverageNotes: [String]         // logged bounds (e.g. HA-F10)
    public let verdict: String                 // overall posture summary
    public let generatedAtHint: String?        // stamped by the caller, not the model
}
```

`Date.now()`-free by construction; timestamps are stamped by the CLI/agent caller
(consistent with the codebase's existing avoidance of ambient clock reads in pure
types).

## 2. Detection context (dependency injection for testability)

`Sources/ConvenientSecurity/HostAudit/Context.swift`:

```
public protocol CommandRunning: Sendable {            // bounded, allow-listed reads
    func run(_ tool: HostReadTool) async -> HostReadResult
}
public protocol PrivilegedHostOps: Sendable {         // wraps RootHelperClient
    func read(_ query: HostRootRead) async throws -> HostReadResult
    func apply(_ change: HostRootChange, digest: String) async throws -> HostApplyResult
}
public protocol TCCReading: Sendable {                // reads the two TCC.db files
    func grantees(_ service: TCCService) async -> TCCReadOutcome  // .rows / .noFDA
}
public struct HostAuditContext: Sendable {
    let commands: CommandRunning
    let privileged: PrivilegedHostOps
    let tcc: TCCReading
    let files: FileInspecting
    let environment: [String: String]
    let baseline: BaselineStore
    let selfIdentity: ProductCodeIdentity   // to mark HA-D01 expected-self
}
```

Production impls wrap real `Process`/syscalls; tests pass fakes returning captured
synthetic fixture output. `HostReadTool`/`HostRootRead`/`HostRootChange` are
**closed enums** — the allow-list of exactly which commands/ops the audit may run,
which is what keeps the privileged surface bounded.

## 3. Check registry — `Sources/ConvenientSecurity/HostAudit/Checks/`

One file per catalog domain (`DomainA_Platform.swift` … `DomainK_Coverage.swift`).
Each check is a small value implementing:

```
protocol HostCheck: Sendable {
    var id: String { get }               // "HA-A01"
    var meta: HostCheckMeta { get }       // title, severity, tier, onThesis, remediation
    func evaluate(_ ctx: HostAuditContext) async -> HostFinding
}
```

A `HostCheckRegistry.all` assembles every check. `evaluate` does the parsing and
returns a value-free `HostFinding`. Notable per-domain wiring:

- **A/B/C runtime reads** (`csrutil`, `nvram boot-args`, `spctl`, `socketfilterfw`,
  `systemextensionsctl`, `kmutil`, `softwareupdate -l`, `scutil`, `lsof`,
  `security dump-trust-settings`) go through `CommandRunning`; each has a dedicated
  parser with a fixture test.
- **HA-K03** reuses/extends `StartupSecurityReport.currentAgent()` — the existing
  self-audit becomes one host finding (agent + helpers healthy) rather than only a
  daemon log line.
- **R! reads** (sharing services, sudoers metadata, `profiles list`, launchd
  overrides, `tmutil destinationinfo`) go through `PrivilegedHostOps.read`,
  batched into as few root round-trips as possible.
- **F reads** (all of domain D + BTM login items HA-E02) go through `TCCReading`;
  on `.noFDA` the check yields `status: .unknown` with a Settings-pane anchor.
  **HA-D01** marks any grantee whose code identity equals `ctx.selfIdentity` as
  `status: .expectedSelf` (Decision 8), never a finding.
- **HA-F10** SUID/world-writable scan takes an explicit time/observation budget and
  appends its bound to `coverageNotes`.

## 4. Privileged ops — extend the root protocol (the security-sensitive change)

Add to `Sources/CSECRootProtocol` two new `RootHelperRequest` cases, mirroring the
existing `nonce`+`digest` gating:

```
case hostRead(id: String, query: HostRootRead)                       // value-free metadata
case hostApply(id: String, change: HostRootChange, digest: String)   // reversible mutation
```

- `HostRootRead` / `HostRootChange` are **closed enums**. Each variant maps, in
  `RootHelperServer.serve`, to one fixed, audited command/syscall — e.g.
  `.enableApplicationFirewall`, `.setSharingService(Service, enabled: false)`,
  `.removeAutoLoginUser`, `.disableRootAccount`, `.installSudoLocalTouchID`,
  `.enableNetworkTime`, `.setSoftwareUpdateFlag(Flag, true)`,
  `.clearBootArgsToken(KnownDangerousToken)`. No free-form string is executed.
- `requiredRole(for:)` returns `.agent` for both (only the verified agent may call).
- `hostApply` requires `digest` to equal the digest of the reviewed batch (§6),
  exactly as `.approve` binds to a plan digest today.
- Server code stays in `CSECRootServer` and links **no** provider/Keychain/Touch-ID
  deps (preserves the current minimal-helper constraint in `Package.swift`).
- `RootHelperClient` gains `hostRead(...)` / `hostApply(...)`; `PrivilegedHostOps`
  in the agent wraps them. `cs-fake-rootd` gains matching handlers for tests.

## 5. CLI surface — `Sources/csec/AuditCommand.swift`

`runAudit(_ arguments:)`, dispatched from `csec/main.swift` and added to `usage()`:

- **`csec audit`** — evaluate all checks → print the value-free report
  (severity-ordered, ★ grouped first) → present the batched remediation review
  (§6) → launch any opted-in guided helpers (§7).
- **`--report-only`** — report, no remediation proposal (CI / AI-agent consumer).
- **`--json`** — the `HostAuditReport` as stable JSON (ids are the contract).
- **`--scan-filesystem`** — opt into the bounded HA-F10 sweep (off by default;
  logs its bound).
- **Integration (Decision 1):** at the end of `runSetup(...)`, after the existing
  report/apply, call `runAudit` so setup always finishes with a host posture pass.
  Setup and audit share the coverage code for domain K (one source of truth for
  "is redaction active in this agent"): `CodingAgentSetup` exposes the check that
  HA-K01/K02 consume.

The report renderer mirrors `printSetupReport` in `SetupCommand.swift` (same
`setupSafe`/document-safe sanitization discipline).

## 6. Batched remediation — one review, one Touch ID (Decision 5)

- Collect fixable findings (`.auto` / `.autoPrivileged`) into a
  `HostRemediationBatch` of value-free change descriptors.
- Present a new `HostRemediationReviewSession` (sibling to
  `TrustedAccessReviewSession`, reusing its window chrome, banner/card helpers, and
  `configureAuthentication()` Touch-ID activation): each change is a **default-on
  checklist row** the user can deselect. One Touch ID authorizes the selected set.
- On approval, compute `digest` over the selected change set. Apply:
  - `.auto` in-process (e.g. `defaults` writes, `/etc/pam.d/sudo_local` create);
  - `.autoPrivileged` via `PrivilegedHostOps.apply(change, digest:)`.
  Application is **atomic per target**, results collected per change; a failure
  reports completed changes and is safe to re-run (mirrors setup's multi-target
  semantics). No implicit cross-target transaction.
- Print an applied/skipped/failed summary.

## 7. Guided helpers (Decision 4) — `Sources/csec/Guided/`

- **FileVault (HA-G03)** — drive `fdesetup enable`; capture the recovery key,
  **display it once**, and offer to import it into a chosen `csec://` store
  (never silently escrow to iCloud); prompt the restart. Fully interactive.
- **Santa (HA-B08)** — link to the official signed North Pole Security package
  (never silently download-and-exec), then write a **MONITOR-mode** starter config
  with a bounded starting ruleset. The helper never sets LOCKDOWN; the user
  tightens later.
- LuLu / Little Snitch (HA-C03) stay advise + doc-link (Decision 4).

## 8. Full Disk Access acquisition (Decision 2)

- At `csec setup` / first run, csec requests FDA: open the
  `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`
  deep-link with instructions. Whether csec currently holds FDA is probed by a
  bounded read of `~/Library/Application Support/com.apple.TCC/TCC.db` (a
  FDA-gated path); the probe reads only existence/openability, no rows beyond the
  audit's own value-free enumeration.
- With FDA, domain D + HA-E02 run automatically; without it they degrade to
  `unknown` + pane deep-links (never a pass). HA-D01 renders csec as
  `expectedSelf`.

## 9. Periodic re-audit + regression (Decision 6) — in `csecd`

- The resident agent schedules a value-free re-audit on a **dispatch timer,
  default cadence daily** (configurable via the agent's settings). Reuses the same
  registry with `--report-only` semantics; no mutation.
- **Baseline store:** `~/Library/Application Support/ConvenientSecurity/host-audit-baseline.json`
  — value-free `{id: {status, acceptedAtHint}}`. `BaselineStore` in the context.
- Each run diffs current vs baseline. A `pass → fail` transition on a
  previously-accepted control is a **regression** → post a `UNUserNotification`
  from `csecd` naming the finding id/title. **Notify-only**: no background
  mutation. The user re-runs `csec audit` to remediate.
- The baseline advances (`fail → pass`, or accepting a new state) only through an
  interactive `csec audit` run where the user accepts — unreviewed drift keeps
  notifying.

## 10. Version currency offline (Decision 7)

- HA-B03/B05 read raw XProtect/OS versions locally; HA-B06 derives the actionable
  verdict from `softwareupdate -l`. On an unreachable catalog, the parser yields
  `status: .unknown` with the **last successful check timestamp** (persisted next
  to the baseline). Never a pass, never a bundled/fetched "latest" floor.

## 11. Test matrix (`cs-selftest`, `cs-e2e`, fixtures)

Using the existing `check(condition, label)` harness (value-free assertions):

- **Per-check unit tests** — evaluate each check against a fake `HostAuditContext`
  with captured synthetic command output; assert id/severity/tier/status for
  pass, fail, unknown, expected-self, and not-applicable paths.
- **Parser fixtures** — `csrutil`, `nvram`, `spctl`, `socketfilterfw`,
  `systemextensionsctl`, `kmutil`, `softwareupdate -l` (incl. offline),
  `security dump-trust-settings`, `profiles`, `lsof`, and TCC.db rows across at
  least two macOS schema shapes → tolerant parse or `unknown`.
- **Remediation** — digest computation, checklist selection → digest binding,
  `hostApply` dispatch against `cs-fake-rootd`, atomic-per-target, re-run safety.
- **Root protocol** — new `hostRead`/`hostApply` variants over the framed socket
  with peer-trust + `.agent` role gating; a fake/unverified peer is rejected;
  digest mismatch fails closed.
- **Regression** — baseline diff: `pass→fail` notifies; `fail→pass` advances only
  on accept; offline currency → `unknown`.
- **Guided helpers** — FileVault/Santa flows with fakes (no real `fdesetup`);
  recovery-key display-once + optional store-import path.
- **Value-free guarantee** — extend the existing redaction tests: assert no
  finding/evidence/report field can contain a secret-shaped value, and that
  `HA-D01` never emits a grantee's private data.
- **Integration (`cs-e2e`)** — `csec setup` runs the audit at the end; domain-K
  coverage reflects a removed/disabled redaction hook.

## 12. Packaging, entitlements, docs

- FDA is a user-granted TCC permission (no entitlement change), but requires the
  signed `.app` to be launchable to receive the grant — documented in the setup
  flow and `packaging/README.md`.
- New `csec-rootd` `hostRead`/`hostApply` variants ship in the signed root helper;
  re-sign + re-notarize. **No new dangerous entitlements** (preserves
  `StartupSecurityReport.productionReady`).
- `UNUserNotification` posting from `csecd` uses the existing app bundle identity.
- Docs: add `csec audit` to `README.md` (a new "Audit host posture" section next
  to onboarding), to `DESIGN.md` Components/`csec` command list, and cross-link
  the catalog + this plan.

## 13. Construction order (single release, all domains)

1. Core model + context + registry scaffold (§1–3) with domain-A checks + tests.
2. Runtime `R` checks for B/C/F/G/I/J/K + parsers + fixtures.
3. Root-protocol `hostRead` + R! checks (C05, E03, G04/G07/G10, I01, J02) +
   `cs-fake-rootd` handlers + tests.
4. FDA path + TCC reader + domain D + E02 (§8) + expected-self.
5. CLI `csec audit` + report renderer + `--report-only`/`--json` + setup
   integration (§5).
6. Root-protocol `hostApply` + batched remediation review (§4, §6).
7. Guided helpers: FileVault, Santa (§7).
8. Periodic re-audit + baseline + regression notifications (§9) + offline
   currency (§10).
9. Value-free guarantee tests, e2e, docs, re-notarize (§11–12).

## Risks

- **Root-helper surface growth** is the main risk; mitigated by closed-enum
  allow-listed ops (no generic exec) and digest/role gating identical to the
  existing approve path.
- **TCC.db schema drift** across macOS versions → parser tolerates versions and
  degrades to `unknown`.
- **csec holding FDA** raises its value as a target; accepted per the ethos
  ("more secure, conveniently"), and the FDA read path stays strictly read-only
  and value-free.
