# Airlock Application Control & Policy Architecture Audit — Report

## 0. Zero-mutation statement

**No write, create, update, delete, move, approve, or issuance call was made against the live
Airlock server, or against Intune/CrowdStrike/Entra ID, at any point in this engagement.** Every
task packet in this audit was read-only by design (§2 below) and by construction (every
collection script used only GET-equivalent/query endpoints). This is verified two ways, per the
audit's own guardrails, not by self-attestation alone:

1. **API key scope read-back** — the dedicated audit API key was provisioned with only read
   endpoints (`group`, `group/policies`, `group/agents`, `agent/find`, `application`,
   `application/export`, `baseline`, `baseline/export`, `blocklist`, `blocklist/export`,
   `logging/exechistories`, `logging/svractivities`, `otp/usage`, `hash/query`) — no
   `add`/`remove`/`approve`/`new`/`move`/`set*` role was ever granted.
2. **Independent post-hoc log reconciliation** — a fresh pull of the server-side activity log,
   filtered to mutating action types and cross-checked against the audit key's own identity for
   the full engagement window, confirms zero mutating actions were attributed to it: of 1,142
   admin-activity rows logged across the full engagement window, 19 were attributable to the audit
   identity, and zero of those 19 classified as mutating (all were `Login` and one-time account-
   provisioning actions). See the appendix for full detail, including one non-mutating observation
   flagged for the client's awareness.

Every artifact in this repository and in the audit's broader workpapers is a **proposal**. Policy
groups marked "proposed" do not exist in Airlock. Allowlists marked "ready for creation" have not
been created. No device has been moved. Nothing described below should be treated as the current
state of production — only as a **read-only snapshot and a redesign recommendation**.

## 1. Executive summary

This audit reviewed a ~4,500-endpoint (3,909 Windows in scope) Airlock Digital
application-allowlisting deployment against ACSC Essential Eight Application Control maturity
criteria (primary benchmark), NIST SP 800-167, and CIS Control 2 (supporting). It had two goals:
(A) produce a severity-ranked findings register comparing current configuration to best practice,
and (B) design — but not execute — a migration from the environment's current "Bulk Add" catch-all
allowlist model to a decomposed, per-application allowlist model organized by department/location
policy groups.

**Headline results:**

- **The Windows estate is predominantly ML1, not ML2, against Essential Eight Application
  Control.** Workstations are 98.1% in Enforcement mode (real, not nominal), but 98.3% of Windows
  servers remain in Audit mode, and neither Microsoft's recommended application blocklist nor its
  vulnerable-driver blocklist could be found in the current configuration — both are named,
  checkable ML2/ML3 criteria. See `audit/findings_register.md` §5, F-19/F-20/F-23.
- **The "Bulk Add" catch-all problem is confirmed, and is larger than one list.** Nine separate
  Bulk-Add-style catch-all allowlists exist (not one), holding roughly 100,700 hash entries across
  ~77MB of exported configuration. The single highest-leverage architectural fix identified is at
  the root of the Windows client tree: a trunk group carries 30 broad user-writable/temp-path
  rules and 41 blanket vendor-publisher trusts into every enforcement group beneath it, including
  the ~3,100-agent main enforcement group. See `audit/findings_register.md` §3, F-06/F-12/F-13/F-14.
- **A full migration design now exists — decomposing those catch-alls into 3,858
  ready-to-create per-application allowlists** (naming convention `APP - <Publisher> - <Product>`),
  organized under a 75-group target department/location hierarchy, with group-level trust
  (including the publisher set required to prevent a migrated device from falling into Airlock
  Safe Mode) explicitly designed for every target group.
- **The migration is not yet safe to execute.** A read-only impact simulation found that **zero
  of the 3,909 in-scope Windows devices are currently unconditionally eligible for migration**,
  because 745 specific trust elements (mostly publisher and path rules) that real devices
  currently depend on are not yet covered by any proposed new allowlist. This is reported as a
  **hard gate**, not a soft caveat — the migration package explicitly excludes every affected
  group from its proposed rollout waves until each gap is resolved. See §5 below and
  `audit/findings_register.md` for the full gap classification.
- **A machine-readable migration package is ready for a future, separately-approved execution
  phase** — schema documented in `audit/migration_package_schema.md` — but this audit performed
  zero of the writes that package describes.

## 2. Engagement scope & guardrails

- **Read-only, always.** No group, allowlist, baseline, blocklist, path/publisher/process rule,
  agent assignment, OTP grant, or stop code was created, modified, approved, or removed at any
  point.
- **Windows-only migration scope.** The live fleet includes macOS and Linux agents inside the same
  policy-group hierarchy as Windows agents. Per an explicit scoping decision made mid-engagement,
  the migration design excludes non-Windows agents entirely — their current groups/allowlists are
  left untouched by every proposal in this audit. Where a policy group is genuinely mixed-platform,
  it remains in scope for *analysis* (since Windows agents depend on it) but no redesign proposal
  disrupts the non-Windows agents co-located in it.
- **What is committed to this repository vs. kept as local workpapers**: this report, the findings
  register, and the migration package *schema* (field names, types, semantics, and aggregate
  counts) are committed here. Raw exports — individual hostnames, usernames, hash values, and
  full per-device software inventories — are not, and never were, part of this repository; they
  remain in the audit's local, untracked workpapers, consistent with this repo's own `.gitignore`
  pattern (which already excludes `*.json`/`*.csv`/`*.xml`/etc.).
- **Reference scripts in this repository were not run verbatim.** Every script in this repo was
  independently re-verified line-by-line before any collection work began (see §6). All real
  collection code used in this audit was freshly written specifically to meet each task packet's
  read-only acceptance criteria.

## 3. Methodology

The audit was organized into five phases, each with explicit task packets (TP-##), each
carrying its own bounded goal, output, and acceptance criteria:

- **Phase 0 — Access & baseline**: provisioned a dedicated read-only API key; independently
  re-verified every script in this repository for safety before any of it informed real
  collection work.
- **Phase 1 — Data collection** (Airlock, read-only): one controlled, throttled, rate-limited
  pass against the live server — full policy export, agent inventory, 90-day execution history,
  OTP usage history, server/admin activity log, and metadata-rule configuration capture.
- **Phase 1b — External cross-reference** (read-only): Intune device/app inventory, CrowdStrike
  telemetry, Entra ID department/location attributes, and a client-provided Application Portfolio
  Management (APM) export, used to corroborate application identity and department/location
  ground truth.
- **Phase 2 — Parallel domain analysis**: ten independent findings packets, each benchmarked
  against ACSC Essential Eight (primary) or NIST 800-167 / CIS Control 2 (supporting), covering
  policy architecture, allowlist hygiene, path/publisher/process trust, blocklist coverage,
  metadata-rule review, enforcement maturity, OTP governance, RBAC, detection/triage workflow, and
  fleet hygiene.
- **Phase 3 — Decomposition & migration mapping**: the core "untangle Bulk Add" design work —
  extracting every catch-all entry and group-level trust element, clustering them into candidate
  per-application allowlists, designing a target department/location hierarchy with group-level
  trust (including the anti-Safe-Mode publisher requirement), mapping devices to target groups,
  simulating per-device impact, and proposing a staged rollout sequence.
- **Phase 4 — Synthesis**: assembling the machine-readable migration package, this findings
  register, this report, and a final independent guardrail self-check.

Every packet cites its benchmark source explicitly. Essential Eight Application Control criteria
are cited **verbatim** from an archived snapshot of the official ACSC maturity-model page (direct
live access to that site was not available from the audit environment; the archived snapshot's
provenance is documented alongside the extracted text in the audit's workpapers).

## 4. Key findings summary

Full detail, severity ratings, and Essential-Eight citations for every finding are in
**`audit/findings_register.md`**. Headline points, by theme:

**Policy architecture.** The Windows hierarchy is fragmented across several parallel trunks
rather than one clean tree, with 24 of 64 groups empty (13 of those still holding 100+ residual
trust items), and at least two groups whose names actively contradict their real enforcement
mode. A validated Entra ID department/office-location data source now exists to anchor the target
hierarchy redesign, resolving what was an open access question at the start of this engagement.

**Allowlist hygiene.** 362 allowlists were reviewed; 43 are orphaned (unreferenced by any group)
and 79 export zero entries (73 of those still actively assigned to groups, providing no real hash
trust today despite looking authoritative in configuration). Duplicate allowlist names are a
genuine control problem, not a cosmetic one — same-name allowlist pairs were measured to have
0% hash overlap with each other, meaning they are divergent lists that happen to share a label.

**Path/publisher/process trust — the highest-severity domain in this audit.** Two Critical and
two High systemic findings, concentrated at the root of the Windows client tree: a single trunk
group's broad user-writable/temp-path trust and blanket vendor-publisher trust flow by
inheritance into the entire client enforcement chain, and the main enforcement group's own
effective trust is almost entirely ambiguous (inherited-or-redeclared cannot be distinguished
today) rather than clearly, locally declared. One reassuring negative finding: no risky
parent/grandparent-process trust (a classic LOLBin bypass vector) was found anywhere in the
estate.

**Blocklist coverage.** Configuration is overwhelmingly audit-mode (detect, not prevent), and by
direct inspection, neither Microsoft's recommended application blocklist nor its vulnerable-driver
blocklist — both named, checkable Essential Eight ML2/ML3 criteria — could be found in the current
configuration.

**Enforcement maturity.** Windows workstations are genuinely close to full Enforcement coverage,
but Windows servers are not (over 98% still in Audit mode), which alone prevents an estate-wide
ML2 rating regardless of workstation posture.

**OTP/exception governance.** Self-service OTP usage — the platform's designated exception
mechanism — is growing sharply (+307% year-over-year), the opposite of the "minimized and
regularly reviewed" posture the benchmark calls for. A small number of groups account for
disproportionate usage relative to their current size and correlate directly with independently
observed blocked-execution hotspots, making them strong early candidates for dedicated
per-application allowlists ahead of the full migration timeline.

**RBAC and detection/triage.** Both were only partially assessable. Airlock's REST API exposes no
permission-group/role read surface at all under any key (confirmed by direct, exhaustive probing,
not inferred from its absence in example scripts) — this is a genuine platform limitation, not an
audit gap, and needs a manual console export to close. Similarly, true detection-backlog depth,
age, and mean-time-to-decision could not be measured from available data, because no per-event
triage/review state is exposed anywhere in the platform's own exports.

**External cross-reference.** Comparing Airlock's protected-device population against Intune's
managed-device inventory surfaced roughly 1,200 Intune-managed Windows devices with no Airlock
coverage at all — though after accounting for devices that are simply dormant (not recently
synced), the actionable, currently-active blind-spot count is a few hundred devices, not the full
raw gap. A client-provided Application Portfolio Management export additionally surfaced several
dozen cases where software marked Sunset/Retired/Closed in that catalog is still trusted in
Airlock or actively detected running via Intune.

**Data-collection tooling integrity.** Every one of the 43 example scripts already present in
this repository was individually re-verified before this audit relied on any of them for design
guidance. None were executed verbatim for live collection; real collection code was written fresh
for every packet. The re-verification did surface real bugs worth recording for this repository's
own maintainers, independent of the audit itself — see §6.

## 5. Migration plan narrative

The redesign directly answers the engagement's original ask: untangle the Bulk-Add catch-all
allowlists into per-application allowlists, finish the department/location policy-group
hierarchy, and produce a device migration map precise enough to move devices with materially less
blast radius than today's catch-all model allows.

**Step 1 — Master entry extraction.** Every entry from every Bulk-Add-style allowlist, plus every
publisher/path/process rule and baseline declared directly (or ambiguously) on the in-scope
groups, was normalized into one master table that preserves both **kind** (hash, publisher, path,
process, baseline) and **level** (allowlist-scoped vs. group-direct vs. inherited) per entry. This
step deliberately does not flatten everything down to "just hashes" — group-level trust,
especially the publisher set required to prevent Airlock Safe Mode, is tracked with equal rigor.

**Step 2 — Clustering into candidate applications.** Every master entry was clustered into a
candidate application using Airlock's own metadata (publisher/product/file path) first, then
corroborated against Intune and CrowdStrike telemetry where available. Every cluster carries an
explicit confidence tier — High, Medium, Low, or Unresolved — rather than forcing a guess; nothing
is silently dropped. The result is 7,786 candidate application clusters: 3,858 at High/Medium
confidence (ready to become real, named allowlists), 3,912 at Low confidence (need a human to
confirm product identity before they can be created), and 16 correctly identified as generic
OS/temp locations rather than real applications (excluded, not merged in).

**Step 3 — Target allowlist and group-trust design.** Every High/Medium cluster maps to exactly
one proposed allowlist, following a consistent `APP - <Publisher> - <Product>` naming convention.
Separately — and this is the fix for the single most severe issue found during this engagement's
own internal adversarial review process before any live work began — every target policy group
was also given an explicit group-level trust design, and every one of the 75 target groups was
verified to carry the required anti-Safe-Mode publisher set directly, not just by inheritance.
Without this step, executing a naive "just recreate the allowlists" migration could have dropped
migrated devices into Airlock Safe Mode fleet-wide.

**Step 4 — Target hierarchy finalization.** The department/location hierarchy was finalized
against the Entra ID department/office-location data now available (§4), producing 75 target
groups across three branches — the Corporate Windows client estate, the combined Windows
Server/Citrix estate, and Retail POS — with an explicit, documented precedence rule for what
happens when different signals (org source-of-truth, hostname pattern, or manual review) disagree
about where a device belongs.

**Step 5 — Group/allowlist assignment.** Each proposed allowlist was mapped to the branch(es)
that need it, using execution history as one signal among several (not the sole basis, since
execution history alone would under-count seasonal or quarterly-use software). This mapping is
reported at its **honest granularity** — most proposed allowlists are currently resolved to the
branch level, not the exact target department, and are explicitly flagged as needing a
business-owner attestation to narrow further. This is a deliberate choice to avoid fabricating
precision the underlying data does not yet support.

**Step 6 — Device migration mapping.** Every in-scope Windows device was mapped to a target
group with an explicit justification, or flagged for manual review — zero devices were left
unmapped or silently defaulted.

**Step 7 — Impact simulation (the hard gate).** This is the step that determines whether the
above design is actually safe to execute, and the honest answer today is: **not yet, for any
device.** The simulation compared each device's full current effective trust (not just allowlist
hashes — publishers, paths, processes, and baselines, with inheritance ambiguity treated as a
break risk rather than assumed safe) against what the new design would provide. It found 745
specific trust elements, concentrated across six key current groups, that real devices depend on
today but that no proposed allowlist yet covers. **Every device or group depending on one of these
745 elements is automatically excluded from migration eligibility** — this is enforced as a hard
gate in the migration package itself, not merely noted as a caveat. A further 559 gaps were found
in an *ambiguous* trust category (same identity present in both a parent and child group, which
could be inheritance or could be an intentional local rule) — these are tracked and reported
separately, for awareness, but are not used to block migration on their own, consistent with the
genuine uncertainty in what they represent.

**Step 8 — Staged rollout sequencing.** A provisional, deterministic wave ordering was produced
for when the Step 7 gaps are resolved — small, low-risk, fully-enforcement cells first, groups
with operationally sensitive dependencies (server and Citrix infrastructure, point-of-sale) always
sequenced last regardless of their own gap count, so that a policy-group migration is never
stacked on top of an unrelated, still-pending audit-to-enforcement transition.

**Step 9 — Migration package assembly.** All of the above was assembled into a single
machine-readable package — six linked arrays (new allowlists, target policy groups, group/allowlist
assignments, group-level trust assignments, the device migration map, and the risk-flag
register) plus an execution-preconditions schema (drift-detection fingerprints, an idempotency-key
scheme, write-batch limits, dependency ordering, rollback mapping, and required post-operation
verification steps) — so that a future, separately-approved execution phase has everything it
needs to apply an approved subset of this design safely, and to safely no-op or roll back if the
live environment has changed since this audit's snapshot. **This package has not been executed.**
Its schema is documented in `audit/migration_package_schema.md`; the package's actual data (which
does contain per-device and per-hash detail) is intentionally not part of this repository.

## 6. Data collection & tooling integrity

Before any live collection began, every one of the 43 scripts already present in this repository
was individually re-verified by reading its full source code, not its docstring — this
re-verification is itself a finding worth recording, independent of the Airlock configuration
audit:

- Two scripts' docstrings do not match their actual behavior (one claims read-only but contains a
  disabled-by-default bulk-removal feature; another's docstring names the wrong API endpoint
  family, though the actual behavior is correctly mutating either way).
- Several scripts contain secrets-handling issues worth this repository's maintainers fixing
  independent of this audit: OTP codes appear unredacted in at least one export path; a "Show"
  button in one HTML report reveals a base64-encoded (not truly redacted) Stop Code directly in
  page source; API keys are accepted as command-line arguments or echoed via `input()` rather than
  `getpass()` in a couple of scripts.
- A version-dependent f-string syntax error affects five scripts on Python versions before 3.12.
- Several scripts hardcode placeholder credentials with no config-file fallback.
- A handful of correctness bugs were found (a group-hierarchy-naming bug isolated to one script
  variant; a few scripts that would crash on an empty result set rather than handling it
  gracefully).

None of these scripts were run verbatim as part of this audit — all real collection code was
written fresh, specifically scoped to each task packet's read-only acceptance criteria, and
modeled on this repository's own best examples of secure patterns (opt-in-only insecure-transport
flags, credential redaction, and defensive pagination guards, all of which do already exist in a
few of this repo's scripts and are worth using as the house style going forward).

Full detail: `audit/findings_register.md` §12.

## 7. Assumptions, open risks & follow-ups needed

- **Windows-only migration scope** (§2) is an explicit decision, not an oversight — revisit if a
  future phase wants to extend this design to macOS/Linux.
- **`/v1/group/policies`'s direct-vs-inherited signal is a heuristic, not a platform guarantee.**
  A child group that intentionally re-declares an ancestor's trust looks identical, in this
  export, to trust that is purely inherited. Every ambiguous case in this audit's design was
  tagged for manual review rather than silently resolved either way — confirming Airlock's actual
  inheritance semantics (via vendor support or a staging tenant) would let a future phase resolve
  many of these with confidence instead of caution.
- **RBAC/permission-group review needs a manual console export.** No API surface exists for this
  anywhere in the platform, confirmed by direct, exhaustive probing rather than assumed from the
  absence of an example script.
- **True detection-triage backlog depth, age, and mean-time-to-decision could not be measured**
  from any available export — this would need either a SIEM/ticketing integration export or a
  raw, unaggregated event log with review-state fields that the platform does not appear to
  expose today.
- **A user-identity fragmentation pattern was observed independently in two different log
  sources** (the same person appearing under both a bare username and a full email address) —
  worth investigating as a possible dual-authentication-path question in its own right, separate
  from its effect on this audit's own chronic-usage rankings (which were reconciled manually where
  it mattered).
- **The 745-gap migration blocker (§5, Step 7) is the most important open item for any future
  execution phase.** Each gap is itemized with its specific missing trust element and the current
  group it affects in the migration package; resolving them (by adding the missing element to an
  appropriate new allowlist or group-trust design, not by blanket-copying the old broad trust
  forward) is the actual unblocking work, not a formality.
- **Coverage-gap devices found via Intune cross-reference should be triaged starting with the
  subset that is both a genuine gap and recently active** (§4) — the full raw gap count
  overstates the live, actionable blind spot.

## 8. Recommended next steps

This audit's mandate ends at a validated design and a read-only impact simulation. Recommended,
but explicitly **not started, and requiring its own separate approval**:

1. Resolve the 745 hard-gate trust gaps identified in §5/Step 7 — this is real, itemized,
   necessary work, not optional polish, before any device migration can begin safely.
2. Obtain the manual console exports needed to close the RBAC review and confirm the
   `/v1/group/policies` inheritance-semantics question, ideally from vendor support directly.
3. Resolve the Low-confidence and business-owner-attestation backlogs the migration package
   itemizes, so the branch-level allowlist assignments (§5, Step 5) can be narrowed to exact
   target groups.
4. Stand up (or confirm) a staging/test Airlock tenant to validate the migration package against
   before any real device or policy change is made in production.
5. Only then, under its own explicit sign-off, begin an execution phase — starting with the
   smallest Wave 1 pilot cells identified in §5/Step 8, applying the idempotency, batch-limit, and
   rollback design already built into the migration package, and re-verifying every precondition
   field against the then-current live environment before each step (not against this audit's
   snapshot, which will by then be stale).

## Appendix — task packet status

All task packets in this engagement (TP-00 through TP-43) were either completed, or — in the two
cases where a packet's original premise did not hold — explicitly resolved and repurposed rather
than silently dropped:

- **TP-14** (metadata-rule review): no live rule engine exists in production to review today;
  repurposed into forward-looking guidance for if/when one is adopted to scale the new hierarchy.
- **TP-17** (RBAC review): confirmed, by direct API probing, that no permission-group read surface
  exists under any key; parked as a client-ask for a manual console export, not a dropped packet.

Every other packet across Phase 0 through Phase 4 completed to its stated acceptance criteria.
See `audit/findings_register.md` for the consolidated findings and `audit/migration_package_schema.md`
for the migration design's structure.

### TP-43 — final guardrail self-check

TP-43 (the packet described in §0 above) is now complete, with one sub-item honestly reported as
still open rather than closed by assumption:

- **API key scope, method (a) — console role-list read-back: still open.** This is a console-only
  view with no API surface (the same gap TP-17 already identified). It requires the client's own
  console-admin to confirm the audit key's assigned Permission Group holds exactly the read-only
  role list in §2 of the engagement guardrails, and nothing from the add/remove/approve/move/set
  family. This audit cannot close this item itself and does not claim to.
- **API key scope, method (b) — own-script endpoint self-audit: clean.** Every endpoint path
  referenced anywhere in every script this engagement wrote and ran was enumerated directly; zero
  mutating-family endpoints appear in any of them, called or even mentioned in a comment.
- **Server-log reconciliation: clean, with one observation flagged for awareness, not alarm.** Of
  19 engagement-window log rows attributable to the audit service account, zero were mutating.
  Two were one-time account-provisioning actions (2FA enablement, API key generation) that predate
  this audit's own first live call. Seventeen were `Login` events: eight matching this audit's own
  eight script-execution sessions (one per packet run), six successful **browser-based console
  logins** (Microsoft Edge/Chrome, same source IP, tightly clustered around the account-provisioning
  timestamps), and one rejected browser-login attempt. The six browser logins are atypical for a
  service account, which is normally API-only — this audit did not perform them (no script here has
  browser/console-login capability) and cannot independently confirm who did, though the timing
  strongly suggests they are part of the same initial account setup/verification as the 2FA and
  API-key-generation events, not ongoing use. No action beyond `Login` followed any of the six. This
  is reported as a factual observation, not a resolved non-issue — worth a quick confirmation from
  whoever provisioned the service account.

Full detail, including the raw row-level breakdown: `files/phase2-findings/tp43_guardrail_self_check.md`
in the audit's session workpapers (not committed — contains identity-level log detail per guardrail 5).
