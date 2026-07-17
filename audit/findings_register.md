# Master Findings Register — Airlock Application Control Audit

**Read-only audit artifact. No production mutation of any kind was performed to produce this
register — see `audit/report.md` §0 for the full zero-mutation statement and how it was
verified.** Consolidates all Phase 2 domain-analysis packets (policy architecture, allowlist
hygiene, path/publisher/process trust, blocklist coverage, enforcement maturity, OTP governance,
RBAC, detection/triage, fleet hygiene, external cross-reference) and the audit's own
data-collection tooling-integrity review into one severity-ranked register mapped to ACSC
Essential Eight Application Control (primary benchmark) and Restrict Administrative Privileges
(secondary, RBAC section only) maturity criteria.

This register cites internal task-packet IDs (TP-##) as evidence pointers for traceability
within the audit's own workpapers; the underlying raw per-packet exports are not part of this
repository (see `audit/report.md` §2 for the guardrails governing what is/isn't committed).

## Scope and method

- Every finding below cites its source task packet (evidence pointer) and, where an Essential
  Eight criterion is directly engaged, the verbatim maturity-level bullet it maps to (source:
  `files/essential-eight-application-control-verbatim.md`, an archived-snapshot verbatim copy of
  the official ACSC page — see that file for full provenance). Findings not directly mapped to a
  specific EE bullet (e.g. hygiene/tooling issues) cite NIST 800-167 / CIS Control 2 general
  principles instead, per plan.md §1.
- Severity definitions used consistently below:
  - **Critical** — actively undermines the core control today, at scale, on the group(s) that
    matter most (the primary Windows enforcement chain), or would create fleet-wide impact if
    acted on incorrectly.
  - **High** — a systemic gap or a direct, named Essential Eight ML2/ML3 criterion failure.
  - **Medium** — a real hygiene/governance gap that increases risk or blast radius but is
    localized or already partially mitigated.
  - **Low** — a hygiene/cleanup item with limited security consequence on its own.
  - **Info** — a positive/reassuring finding, or context needed to correctly interpret another
    finding (not itself actionable).
- This register **consolidates and de-duplicates** — it does not reproduce the full per-row
  detail of the 64-group, 362-allowlist, or 176-trust-rule tables. Each row below cites the
  originating packet's memo for full row-level detail.
- Findings are grouped by theme, then severity-ordered within each theme. §8 gives a pure
  severity-sorted index across the whole register for triage convenience.

---

## 1. Policy architecture & hierarchy (TP-10)

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-01 | **High** | `Windows Client Enforcement` remains the dominant legacy catch-all: 3,101 agents, 1,293 TP-01 inheritance-ambiguity hits. The Windows hierarchy is fragmented across parallel trunks (`1 Windows Clients`, `Windows Workstations`, `Retail POS`, `DH VDI`) instead of one clean tree. | ML1/2/3: "restricts execution... to an organisation-approved set" — a fragmented tree with heavy ambiguous inheritance cannot be confidently shown to meet this at the group level. | TP-10 full report (64-row table); TP-01 `tp01_summary.json` | This is the structural problem Phase 3 (TP-30–37) exists to fix. No independent remediation needed beyond the migration program itself. |
| F-02 | **High** | Naming/mode drift: `Global Audit` is actually in **Enforcement** mode; `Workstation Servers Enforcement` is actually in **Audit** mode. Group names actively lie about their real mode. | CIS Control 2 (accurate software/config inventory); general change-management hygiene. | TP-10 report | Rename both groups to reflect true mode immediately (low-risk, config-only would normally be a quick fix, but per this audit's own guardrails, no mutation was performed — flag for the client's own admins as an immediate, near-zero-risk correction, independent of the larger migration). |
| F-03 | **Medium** | 24 empty groups (36% of all 64); 13 of those still retain 100+ trust items each — pure hygiene debt, not active config. | CIS Control 2. | TP-10 report | Retire or consolidate empty groups once Phase 3's new hierarchy supersedes them; don't carry stale empty groups into the new design. |
| F-04 | **Medium** | Dept/location fidelity is mixed: sensible `Windows Workstations` children exist, but generic buckets (`General`, `APAC`, `Self Service`) weaken deterministic device placement. | MS App Control business-group planning methodology (named-purpose groups, not generic buckets). | TP-10 report | TP-33's target hierarchy must replace generic buckets with named-purpose groups wherever a real department/location signal exists (TP-09b's Entra data now supplies this signal — see F-19). |
| F-05 | **Info** | No true Windows+macOS/Linux **mixed-platform** groups found in mapped TP-02 data (only 3 groups with a few blank/unknown-OS records) — the mixed-platform migration risk flagged in plan.md §6 does not materialize in practice. | — | TP-10 report, cross-checked against TP-02 | Simplifies TP-33/35 design; no special mixed-platform handling needed beyond the 3 edge-case groups. |

## 2. Allowlist design & hygiene (TP-11)

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-06 | **High** | **9 separate Bulk-Add-style catch-all allowlists** confirmed (not just one): ~100,700 entries / 76.9MB combined XML, dominant hygiene risk. Active, not dead weight — decomposition, not deletion, is the correct move. | NIST 800-167 (narrow, maintainable allowlisting); CIS Control 2 (per-application inventory, not catch-all). | TP-01/TP-11 reports; `tp11_allowlist_metrics.json` | This is the audit's core deliverable — TP-30–37/40 directly address it. No separate remediation needed beyond the migration program. |
| F-07 | **High** | **Duplicate-name allowlist collisions are systemic and hide materially different content**: 5 exact-name clusters (4× `Windows Client Bulk Add`, 4× `2021`, plus `Boxx`/`CrowdStrike`/`Git` pairs). Same-name pairs measured at **0.00–0.00% hash overlap** — these are not harmless duplicates, they are divergent lists that happen to share a name. | CIS Control 2 (unambiguous software inventory). | TP-11 report | Resolve naming collisions **before** any migration mapping references an allowlist by name — always resolve by allowlist ID. TP-30/31/40 already do this correctly (cluster IDs, not names). |
| F-08 | **Medium** | **43 orphaned allowlists (11.9%)**, some large (e.g. `BoxxApps` 8,988 hashes, `Windows Python Devish` 4,298) — need owner triage, not blind deletion (some may be intentional IR/reserve lists, e.g. `Bloodhound`, `Cyber IR Tools`). | CIS Control 2. | TP-11 report | Route to owner confirmation queue: retire / keep-as-reserve / repurpose. Do not delete unilaterally. |
| F-09 | **Medium** | **79 allowlists export zero entries, 73 of which are still actively assigned to groups** — these currently provide no real hash trust at all despite looking authoritative in the group's configuration. | CIS Control 2; general config-drift hygiene. | TP-11 report | Owner decision required per empty-but-referenced allowlist: populate, retire, or explicitly confirm intentional placeholder status. |
| F-10 | **Medium** | The interview's own examples of "already-good" per-app allowlists (`Python`, `PortlandLab`, `Footwear Cost Sourcing Python`) are **not actually good target-state models** — still too broad (e.g. `Python` spans 42 groups, 3,568 entries under one unsigned bucket); `Windows Python Devish` is both broad and orphaned. | NIST 800-167 (narrow allowlisting). | TP-11 report | Do not use these as literal design templates in Phase 3 — TP-32's clustering logic supersedes them with a tighter definition of "per-application." |
| F-11 | **Low** | Many non-Bulk-Add allowlists are shared across 30–46 groups each — broad blast radius already exists outside Bulk Add too. | CIS Control 2. | TP-11 report | Make ownership explicit before Phase 3 reuses any shared allowlist; don't assume broad-sharing today implies broad-sharing is correct going forward. |

## 3. Path / publisher / process trust (TP-12) — highest-severity domain in Phase 2

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-12 | **Critical** | `1 Windows Clients` (a high-level trunk group) directly declares **30 broad user-writable/temp paths**, flowing by inheritance into everything beneath it — including `Windows Client Enforcement`'s 3,102 enforcement agents. | ML1 verbatim: "Application control is applied to user profiles and temporary folders used by operating systems, web browsers and email clients" — broad trust *in* those exact locations is the specific failure mode this criterion exists to prevent. | TP-12 report, "Highest-risk groups" table | Tighten or eliminate broad user-writable/temp path trust at this trunk group; this is the single highest-leverage fix in the whole audit — it currently undermines ML1 for the entire Windows client estate at once. |
| F-13 | **Critical** | `1 Windows Clients` also directly declares **41 blanket vendor-publisher trusts**, again flowing into the entire client enforcement chain. | ML1/2/3: "restricts execution... to an organisation-approved set" — a blanket publisher trust approves far more than a named organizational need. | TP-12 report | Same remediation path as F-12 — resolve at the trunk, not per-child; Phase 3's `group_trust_assignments[]` design (TP-32/40) already excludes broad ambiguous-inherited trust from the new design rather than copying it forward. |
| F-14 | **Critical** | `Windows Client Enforcement`'s effective trust is **almost entirely ambiguously-inherited, not directly-declared**: 229/229 paths, 930/951 publishers, 5/5 parent-process rules, 113/128 allowlists, 4/4 baselines all flagged ambiguous. The group the user most cares about cannot be confidently attributed without deeper investigation. | Same ML1-3 criterion as F-12/13 — ambiguity at this scale means the effective approved-set for the estate's largest single group is not verifiably known today. | TP-12 report; TP-01 `_resolution.json` ambiguity flags | Resolve `/v1/group/policies` inheritance semantics authoritatively (plan.md §3.15) before treating any ambiguous entry as safe to drop or safe to keep; TP-30/36 already treat ambiguous entries as break-risk, not assumed-safe, pending this resolution. |
| F-15 | **High** | `Windows Workstations` repeats the same broad-path/broad-publisher pattern across 386 enforcement + 15 audit agents (7 broad paths, 11 blanket publishers). | Same ML1-3 criterion. | TP-12 report | Same remediation category as F-12/13, scoped to this smaller subtree. |
| F-16 | **High** | `Infra Windows Server Audit` directly trusts **literal `C:\`** on all 347 audit servers in that group — as broad as path-based trust can possibly get. | ML2/3: "Application control is applied to all locations other than user profiles and temporary folders" — a whole-drive trust is the direct opposite of this criterion, even though the group is currently audit-mode (not yet enforcing it). | TP-12 report | Must be resolved before this group is ever considered for a flip to Enforcement (see also F-22 in §5, TP-15). |
| F-17 | **Medium** | `1 Windows Servers` (8 broad paths + 27 blanket publishers) and `Retail POS` (7 broad paths + 25 blanket publishers) repeat the same anti-pattern at lower current exposure. | Same ML1-3 criterion. | TP-12 report | Lower priority than F-12/13/15/16 but must not be used as a template for the new server/POS branch design in TP-33/34. |
| F-18 | **Info** (positive) | **No risky LOLBin-style parent/grandparent process trust found anywhere.** Only 5 narrow installer-specific parent-process rules exist fleet-wide; zero grandparent-process rules exist at all. | ML1-3 (approved-set criterion) — this specific bypass vector is not present. | TP-12 report | No remediation needed; this is a genuine strength to preserve in the new design (don't introduce broad parent-process trust while redesigning everything else). |

## 4. Blocklist coverage (TP-13)

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-19 | **High** | By name/content inspection, **no evidence of Microsoft's recommended application blocklist** anywhere among the 24 blocklists. | ML2 verbatim: "Microsoft's recommended application blocklist is implemented." Direct, named criterion failure. | TP-13 report, full 24-row table | Implement Microsoft's published recommended application blocklist as a distinct, identifiable blocklist object — this is a checkable, binary gap, not a maturity judgment call. |
| F-20 | **High** | By name/content inspection, **no evidence of Microsoft's vulnerable-driver blocklist** anywhere among the 24 blocklists. | ML3 verbatim: "Microsoft's vulnerable driver blocklist is implemented." Direct, named criterion failure. | TP-13 report | Same remediation category as F-19, for the driver-specific blocklist. |
| F-21 | **Medium** | Blocklist posture is overwhelmingly **audit-mode, not enforced**: 412 audit vs 52 enforced group-assignments (88.8% audit); corroborated at the runtime level (104,765 audit hits vs 254 enforced blocks over 90 days, ~412:1). Coverage is dominated by app-specific deny rules (WhatsApp ~101,857 audit hits alone), not a broad LOLBin/malware strategy. No canonical Windows LOLBin (certutil, mshta, regsvr32, rundll32, msbuild, installutil, bitsadmin, wmic, PowerShell) has explicit coverage. | General detect-vs-prevent design principle; complements F-19/20. | TP-13 report | Treat blocklist enforcement as a distinct, lower-urgency workstream from the allowlist migration — the WhatsApp-scale audit volume suggests a real business decision is needed (block vs. accept) before flipping to enforce. |
| F-22 | **Low** | 8/24 blocklists orphaned, 6 of those completely empty; one legacy 2021 list still does most of the enforced work; no sign of an automated/threat-intel-fed blocklist despite an in-repo capability (`import_cs_ioc_to_ald_blocklist.py`) already existing for it. | CIS Control 2. | TP-13 report | Hygiene cleanup; low urgency relative to F-19/20/21. |

## 5. Enforcement maturity scorecard (TP-15)

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-23 | **High** | **Overall rating: predominantly ML1 for Windows workstations; not ML2 estate-wide.** Workstations are 98.1% Enforcement (real, not nominal), but **98.3% of Windows servers are still in Audit mode (351/357)** — this alone blocks ML2/ML3 server criteria fleet-wide. | ML2 verbatim: "Application control is implemented on internet-facing servers." Direct criterion failure for the server estate. | TP-15 full scorecard | Server-estate enforcement is a distinct, high-value workstream — arguably higher priority than workstation-side Bulk-Add decomposition for moving the *overall* ML rating, since workstations are already close to ML1 in practice. |
| F-24 | **High** | Top-5 blockers to a higher rating (consolidated): (1) server estate still mostly audit-only [F-23], (2) Bulk Add/broad-trust dependency in the Windows Client branch [F-06/F-12-14], (3) missing Microsoft app + vulnerable-driver blocklists [F-19/20], (4) large blocked-execution hotspots even in already-enforced groups (533,289 Windows blocked executions/90d) [see F-27 below], (5) TP-01 inheritance ambiguity limits confidence in exact effective trust per group [F-14]. | ML1-3, multiple bullets (see individual findings). | TP-15 report | This is the audit's own priority-ranked remediation roadmap; TP-42's narrative report should present this list prominently as the executive-level "what to fix first" answer. |

## 6. OTP / exception governance (TP-16)

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-25 | **High** | OTP usage (the platform's exception mechanism) is **rising sharply, not stabilizing**: +154% YoY overall, and **+307% YoY in self-service OTPs specifically** — self-elevation-around-a-block is becoming more common over time. | Verbatim (Implementation/exceptions philosophy): "the need for any exceptions... should be monitored and reviewed on a regular basis" — a rising trend is the opposite of a reviewed-and-shrinking exception set. | TP-16 report | Treat OTP trend as its own tracked metric going forward, not just a one-time snapshot; the redesign's success should be measurable in this number turning downward post-migration. |
| F-26 | **Medium** | Two specific host/user pairs (`UA1B199146`/`zhuang3`, `UA101MBL225000C`/`jfield`) repeatedly receive the **maximum possible (7-day) OTP grant duration** — a distinct, higher-priority governance red flag vs. ordinary chronic use (repeatedly granting the longest possible exception window to the same identity). | Same verbatim exceptions-review criterion as F-25. | TP-16 report | Named line item for direct owner follow-up — investigate why the longest-duration exception is being repeatedly granted to the same two identities specifically. |
| F-27 | **Medium** | Highest normalized OTP hotspots (per current endpoint in that group): `Client Engineering` (80.9/agent), `Creative Self Service` (71.2/agent), `Developers` (43.5/agent), `Self Service` (30.3/agent) — concrete allowlist-remediation candidates, corroborated by TP-03's independent `Developers`↔`Razer USA Ltd.` blocked-execution finding (226,904 blocked events) and TP-04's chronic-host findings. | Same exceptions criterion. | TP-16 report; TP-03/TP-04 cross-reference | These 4 groups are strong candidates for early, high-value per-app allowlist creation (e.g. a Razer/gaming-peripheral allowlist for Developers) independent of the full migration timeline. |
| F-28 | **Medium** | User-identity format fragmentation (same person recorded as both a bare AD username and a full email address, e.g. `opendarvis` + `opendarvis@underarmour.com`) is confirmed **independently in both TP-04 (OTP log) and TP-05 (server-activity log)** with matching name pairs — likely two different auth paths into the console/API. Understates true per-person chronic-OTP concentration until reconciled. | CIS Control 2 / general identity-hygiene principle; also relevant to TP-17 RBAC review (see §7). | TP-04/05/16 reports | Reconcile identity formats (already done manually for TP-16's own ranking — 109 raw strings → 95 true identities) before finalizing any per-person chronic-use remediation list; investigate root cause (SSO vs. legacy/local login) as a possible standalone finding in its own right. |

## 7. RBAC & change management (TP-17) — could not be fully assessed

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-29 | **Info / blocked** | Airlock's REST API **genuinely exposes no RBAC/permission-group/console-user read surface at all** — confirmed directly (20 plausible endpoint probes, all clean 404s), not merely inferred from repo-script absence. This packet cannot be completed via API under any key. | Restrict Administrative Privileges ML1: "Requests for privileged access... are validated when first requested" — cannot be verified at all without console access. | `files/tp17_rbac_endpoint_probe.py`; SQL todo `tp-17-rbac-console-review` | **Client-ask, not an audit gap**: needs a manual console screenshot/export of Settings → Permission Groups (or equivalent) to proceed at all. Not blocking any other packet. |
| F-30 | **Medium** | The same dual-identity fragmentation from F-28 is directly relevant here: if the console/API supports two different login paths for the same person, this is itself a privileged-access-governance question (e.g., could a console-side lockout be bypassed via the API-side identity, or vice versa?) worth a dedicated follow-up once F-29's console export is available. | Restrict Administrative Privileges ML1-2. | TP-04/05 cross-reference | Include as a named question for the client alongside the F-29 console-export request. |

## 8. Detection & triage workflow (TP-18) — honest partial

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-31 | **Medium** | True untriaged-backlog depth, backlog age distribution, SIEM/email/ticket forwarding coverage, and mean-time-to-decision **could not be measured** from available cached data — no per-event triage state, review timestamps, or integration/ticket evidence exists in any exported artifact. | ML2 verbatim: "Allowed and blocked application control events are centrally logged" — logging existence (TP-03/05) is evidenced, but *central, reviewed* logging is not provably confirmed either way. | TP-18 report | Concrete client-asks (already itemized in TP-18): SIEM ingestion evidence, email-forwarder config/logs, review-ownership confirmation for `Infra Windows Server Audit` specifically, ticket/case exports with timestamps, or raw Windows-only timestamp buckets if deeper analysis is wanted. |
| F-32 | **Medium** | Using the observable proxy (recent `Untrusted Execution [Audit]` volume), the Windows-relevant subset is ~85,057 events/day if the 3-day sample is representative, **99.6% of which sits in `Infra Windows Server Audit` alone** — a single group's audit-mode noise dominates the entire in-scope triage workload. | Same ML2 criterion context. | TP-18 report; TP-03 cross-reference | Any future triage-capacity conversation should focus on `Infra Windows Server Audit` specifically — fixing that one group's audit-mode noise (or flipping it toward enforcement per F-16/23) would resolve the overwhelming majority of the measurable workload signal. |

## 9. Agent fleet hygiene (TP-19)

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-33 | **Medium** | **485 agents (11.1%) haven't checked in for 90+ days**; Windows-specifically, 393/3,909 (10.1%), with the single largest cleanup cluster being 309 stale records inside `Infra Windows Server Audit`. | CIS Control 2 (accurate, current inventory). | TP-19 report | Stale-device cleanup should run in parallel with, not block, the migration — TP-35/36 already exclude/flag stale devices appropriately; a fleet-hygiene pass (decommission or re-enroll) is a separate, complementary workstream. |
| F-34 | **Low** | 4 hostnames each have 2 distinct agent records (including two Citrix hosts with one online/one offline record apiece) — re-enrollment hygiene issue, not a true `clientid` collision (which requires longitudinal observation this single snapshot cannot provide). | CIS Control 2. | TP-19 report | Recommend weekly TP-02-style exports for 4–8 weeks specifically to enable true longitudinal collision detection; not urgent on its own. |
| F-35 | **Low** | 4 stale `airlock-application-trust-capture` sentinel agents (329–550 days stale, anomalous `policyversion = v0.`) never assigned to a real policy group — carried forward from TP-02. | CIS Control 2. | TP-02/TP-19 reports | Low-priority cleanup candidate; confirm these are intentional reference machines before any removal. |
| F-36 | **Low** | Client-version tail lags the dominant `6.1.3.0` build (46 agents on `4.8.7.0`, 22 on `5.3.6.0`, 20 on `6.0.4.0`, 14 on `4.8.1.0`) — no data-derived way to confirm what the "current" required version should be. | General patch/version hygiene (not an Essential Eight Application Control criterion directly). | TP-19 report | Confirm the client's own target agent version with the vendor/console admin before treating this as an actionable gap. |

## 10. External cross-reference (TP-07/08/09/09b)

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-37 | **High** | **1,194 Intune-managed Windows devices have zero Airlock coverage** — the headline cross-reference gap. 90.5% match real end-user hardware (not servers); 71.4% already flagged noncompliant by Intune independently. Critically, only **~419–663 of these are both a real gap AND recently-active** (64.9% haven't synced with Intune in 30+ days, 44.5% in 90+ days) — the live blind-spot count is much smaller than the raw 1,194 figure suggests. | CIS Control 2 (complete inventory coverage); ML1 ("Application control is implemented on workstations") — these devices have zero application control at all. | TP-07 report | Prioritize the ~419–663 recently-active, uncovered devices for Airlock enrollment — this is a genuine, currently-unprotected-endpoint finding, independent of the Bulk-Add migration. |
| F-38 | **Medium** | 583 Airlock-only hostnames (protected by Airlock, no Intune match) — heavy naming-convention overlap with servers/infra, consistent with Intune primarily managing client OS; not a data-quality problem, but worth a light confirmation pass. | CIS Control 2. | TP-07 report | Low-urgency; confirm during TP-31/34 triage rather than as a standalone workstream. |
| F-39 | **Medium** | **35 governance-drift candidates** (33 after confidence-tiering) found by cross-referencing the client-provided Application Portfolio Management (APM) catalog against Airlock's trusted-publisher universe and Intune's detected-apps telemetry: apps marked Sunset/Retired/Closed in APM that are still trusted in Airlock or actively detected running in Intune. | CIS Control 2 (software inventory should reflect actual approved/current state, not stale approvals). | TP-09 report | Reconcile each High/Medium-confidence drift candidate with the application's actual owner before Phase 3 either builds a new allowlist for it or explicitly retires its trust — don't silently carry forward trust for an app APM says is retired. |
| F-40 | **Info** | TP-09b resolved plan.md §3.8's open item: Entra ID department/office-location data is now a validated source of truth for the department/location redesign — 94% populated in spot sample, 78.8% end-to-end device-to-department match rate once joined through the Intune device fleet. | MS App Control business-group planning methodology (org-aligned group design). | TP-09b report | TP-33 already consumes this; no further action needed beyond what Phase 3 already does. |
| F-41 | **Info** | A raw-substring name-matching bug was found and fixed during TP-09 (false positives like "Celonis"↔"NI"); the fix (token/word-boundary-aware matching with a minimum-specificity guard) is the correct pattern for any future automated app-name clustering. | — | TP-09 report | Already carried into TP-31's clustering design; flagged here so the lesson isn't lost if clustering logic is ever reimplemented. |

## 11. Metadata dynamic-assignment rules (TP-14) — repurposed finding

| # | Sev | Finding | Essential Eight / benchmark citation | Evidence | Recommendation |
|---|---|---|---|---|---|
| F-42 | **Info** | **No live metadata-based dynamic-assignment rule engine currently exists in production** to review — `rules_based_policy_group_assignment.py` (or equivalent) is not scheduled or running (user-confirmed). TP-14's original "review current rules" scope does not apply; repurposed as forward-looking guidance instead. | — | TP-06/TP-14 SQL todo description | If Phase 3/4 recommends adopting this mechanism to scale device-to-group assignment beyond manual admin capacity across ~4,500 endpoints, it must ship with: `simulation_mode: true` for an initial observation period, a default/catch-all category so no agent is silently orphaned, monitoring/alerting on its move-log, conservative batch-size/throttle tuning, and explicit owner sign-off before flipping to live mode. |

---

## 12. Tooling & data-collection integrity (TP-00b)

Per plan.md's requirement that this section document every script bug found during TP-00b so it
isn't lost, even though none of these scripts were used verbatim for live collection (all real
collection code was freshly written per §2.7):

| # | Sev | Finding | Evidence |
|---|---|---|---|
| T-01 | **High** | **OTP codes are present in raw API responses** (`export_otpusage.py` line 56, `row['otpcode']`) — any reuse of this script's pattern without explicit redaction would leak live self-elevation codes into exported files. | TP-00b memo §3.3 |
| T-02 | **High** | **Stop Code "masking" in `dump_policies.py` is not real redaction**: the raw JSON save has zero redaction, and the HTML report's "Show" button reveals a base64-encoded copy of the real code directly in page source — visible via View Source without even clicking "Show." | TP-00b memo §3.4 |
| T-03 | **Medium** | **Secrets exposure via CLI arguments and `input()`**: `dump_policies.py` requires `--api-key` as a command-line argument (visible in shell history/process listings); `export_agents.py` uses `input()` instead of `getpass()` for its API-key prompt (echoes to terminal scrollback). `export_airlock_docs.py` does this correctly with `getpass()`. | TP-00b memo §3.5/3.6 |
| T-04 | **Medium** | **F-string quote-nesting `SyntaxError` bug in 5 scripts** (`export_server_activity.py`, `print_otp_activity.py`, `move_publishers.py`, `merge_allowlists.py`, `issue_otp_code.py`) — fails outright on Python <3.12. Two of the five are in the "approved" reference list. | TP-00b memo §3.1 |
| T-05 | **Medium** | **Hardcoded placeholder credentials, no config-file fallback, in 7 scripts** including one on the approved list (`agent_counts_by_mode.py`) — systemic pattern, not a one-off. | TP-00b memo §3.2 |
| T-06 | **Medium** | **Docstring/reality mismatches**: `agentid_collission_finder.py` claims read-only but contains a fully-implemented, disabled-by-default (`enable_remediation = False`) batch `agent/remove` feature — must be treated as mutating/excluded despite its docstring. `merge_allowlists.py`'s docstring names the wrong endpoint family (still correctly classified mutating either way, but confirms the docstring-vs-code gap is systemic, not isolated). | TP-00b memo §1 |
| T-07 | **Low** | **Group-hierarchy-naming bug isolated to `export_agents_with_summary.py`** (lines 108–115): parent-prefix assignment indented one level too shallow, applies only to the last group processed. `export_agents.py`'s identical logic is correctly indented, confirming this is a regression in the `_with_summary` variant only. | TP-00b memo §3.7 |
| T-08 | **Low** | **Empty-list-indexing crashes (IndexError/NameError) if zero rows returned**: `move_list_of_agents.py`, `export_server_activity.py`, `export_offline_agents_to_csv.py`. Contrast with `export_events_to_xlsx.py`, which correctly guards with `if len(events) > 0`. | TP-00b memo §3.8 |
| T-09 | **Info** | `enforcement_readiness.py` confirmed (by line citation, 367–368) to explicitly filter out Enforcement-mode groups — proves TP-15's finding that this script's method only ever covers Audit-mode readiness, never the already-enforced majority of the estate. Not a bug — a scope limitation worth stating precisely. | TP-00b memo §3.9 |
| T-10 | **Info** | `rules_based_policy_group_assignment.py` (the potential live mover) has a `simulation_mode` flag (default `False`) that, if `True`, logs but never calls `agent/move` — worth confirming which mode production would run in if ever activated; not currently relevant since the user confirmed it isn't scheduled anywhere. | TP-00b memo §3.10 |
| T-11 | **Info** | Dead-but-dangerous code: `import_cs_ioc_to_ald_blocklist.py` defines (never calls) `remove_from_all_allowlists()` — a `hash/application/remove/all` call that would strip a hash from every allowlist server-wide. Flagged so it is never copy-pasted as if inert. | TP-00b memo §3.11 |
| T-12 | **Info** (positive) | Positive reference scripts worth citing as a quality bar: `move_path_to_children.py` (best-written in the repo — opt-in `--insecure` flag defaulting secure, API-key redaction, `raise_for_status()`), `event_summary_exporter.py`, `dump_policies.py`'s pagination guard pattern, `export_events_to_xlsx.py`'s bounded-lookback/guard pattern. | TP-00b memo §4 |

---

## 13. Severity-sorted index (cross-reference for triage)

**Critical (3):** F-12, F-13, F-14

**High (14):** F-01, F-02, F-06, F-07, F-15, F-16, F-19, F-20, F-23, F-24, F-25, F-37, T-01, T-02

**Medium (17):** F-03, F-04, F-08, F-09, F-10, F-17, F-21, F-26, F-27, F-28, F-30, F-31, F-32, F-33, F-38, F-39, T-03, T-04, T-05, T-06

*(note: Medium count above is 20 including T-03/04/05/06 — kept together since remediation
owners differ between audit findings (F-series) and tooling findings (T-series); see the two
tables above for the authoritative per-series severity.)*

**Low (7):** F-11, F-22, F-34, F-35, F-36, T-07, T-08

**Info (9, incl. positive findings):** F-05, F-18, F-29, F-40, F-41, F-42, T-09, T-10, T-11, T-12

## 14. Rollup by Essential Eight area

| Area | Findings |
|---|---|
| Application Control ML1 (workstation approved-set, user-writable/temp paths) | F-01, F-06, F-12, F-13, F-14, F-15, F-23, F-37 |
| Application Control ML2 (servers, all-locations, MS app blocklist, annual validation, central logging) | F-16, F-19, F-21, F-23, F-31, F-32 |
| Application Control ML3 (non-internet servers, driver restriction, MS vulnerable-driver blocklist) | F-16, F-20 |
| Exceptions philosophy (OTP governance) | F-25, F-26, F-27 |
| Restrict Administrative Privileges (RBAC) | F-29, F-30 |
| General inventory/CIS Control 2 hygiene (not EE-specific) | F-03, F-04, F-07, F-08, F-09, F-10, F-11, F-17, F-22, F-28, F-33, F-34, F-35, F-36, F-38, F-39 |

## 15. What this register deliberately does not include

- Full per-row detail for all 64 groups, 362 allowlists, or 176 individual broad-trust rules —
  see TP-10/11/12's own memos for that.
- Any finding from Phase 3 (TP-30–37) or Phase 4 (TP-40) — those are migration-design
  deliverables, not audit findings, and are reported separately (see `audit/report.md`, TP-42).
- Any resolved/superseded item once its replacement packet closed it out (e.g. TP-14's original
  scope, TP-17's original API-driven scope) — the resolution itself is recorded here (F-29, F-42)
  but the original unresolved framing is not repeated.

## Outputs

- This file: `audit/findings_register.md` (committed).
- Full per-row detail (all 64 groups, 362 allowlists, 176 individual trust rules) lives in the
  audit's internal workpapers, not in this repository — this register is the consolidated,
  severity-ranked summary of that detail.
- See `audit/report.md` for the executive summary, methodology, migration plan narrative, and
  zero-mutation verification this register feeds into.
