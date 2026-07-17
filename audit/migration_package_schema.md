# Airlock Policy & Allowlist Migration Package — Schema Reference

**Status: design/proposal artifact. No part of this schema, and no data package built
against it, has been executed against the live Airlock server. Zero write API calls have
been made at any point in the audit that produced this document.**

This document describes the *shape* of the machine-readable migration package produced by
task packet TP-40 of the Airlock allowlisting & policy architecture audit. It intentionally
contains **no raw data** — no hostnames, agent/device IDs, hash values, or usernames. The
actual data package (built to this schema) is regenerated locally by
`tp40_migration_package_assembly.py` and is **not** committed to this repository, per the
audit's guardrail that raw exports stay local/untracked (this repo's own `.gitignore`
already excludes `*.json`/`*.csv`/etc. for exactly this reason).

## 1. Purpose

The package exists so a **future, separately-approved execution phase** can translate an
approved subset of it into real Airlock write API calls (`group/new`, `application/new`,
`hash/application/add`, `group/application/approve`, `agent/move`, `group/publisher/add`,
`group/path/add`, `group/process/add`). It is a proposal and a set of preconditions, not an
execution plan — nothing in it should be applied without a human re-approving that specific
step, re-verifying the relevant precondition fields below against the *then-current* live
server state, and following the dependency ordering and abort conditions in §8.

## 2. The six top-level arrays

### 2.1 `new_allowlists[]`

One row per candidate per-application allowlist decomposed out of the legacy "Bulk Add"
catch-all lists (see the audit's Phase 3 findings for full context on why this
decomposition is the core redesign goal).

| Field | Type | Notes |
|---|---|---|
| `cluster_id` | string | Stable, **name-independent** ID (`CLU-` + 16 hex chars). Derived from a hash of `(cluster_key_type, publisher, productname, path_prefix)`, not from the display name — survives name collisions and covers rows that never get a name (Low/Unresolved tiers) |
| `proposed_allowlist_name` | string \| null | Human-facing name (`APP - <Publisher> - <Product>` convention), only populated for `READY_FOR_CREATION` rows |
| `confidence_tier` | enum | `High` \| `Medium` \| `Low` \| `Unresolved` |
| `readiness_status` | enum | `READY_FOR_CREATION` — safe to create now; `MANUAL_TRIAGE_REQUIRED_BEFORE_CREATION` — needs a human to confirm product identity first; `EXCLUDED_JUNK_DRAWER_NOT_AN_APPLICATION` — generic OS/temp location, not a real application, deliberately excluded |
| `cluster_key_type` | enum | `pubprod` (publisher+product match, highest confidence) \| `pub` (publisher only) \| `path` (path-prefix fallback for unsigned/generic entries) |
| `publisher`, `productname`, `path_prefix` | string \| null | The clustering key's own fields — whichever apply to `cluster_key_type` |
| `entry_count`, `distinct_paths` | int | Size of the underlying hash-entry population |
| `source_allowlists` | string[] | Which legacy Bulk-Add list(s) this was decomposed from |
| `spans_multiple_source_allowlists` | bool | True if the same app was found duplicated across more than one Bulk-Add list |
| `intune_signal` | bool \| null | Whether Intune's discovered-apps data corroborates this as a real installed application |
| `sample_paths` | string[] | Up to 5 representative file paths (not the full list — see `new_allowlists_full_hash_membership.jsonl`) |
| `triage_note` | string \| null | Present for Low/Unresolved rows — guidance for the human triage step |
| `full_hash_membership_available` | bool | True only for `READY_FOR_CREATION` rows — points to the side file below |

**Side file — `new_allowlists_full_hash_membership.jsonl`** (one JSON object per line, only
for `READY_FOR_CREATION` clusters): `{cluster_id, proposed_allowlist_name,
expected_entry_count, actual_rederived_entry_count, count_matches, hash_entries: [{sha256,
path, publisher, productname, description, source_allowlist_name, source_allowlist_id}]}`.
This is the literal payload a `hash/application/add` call would need. The
`count_matches` field is a self-check: it must be `true` for every row (re-verified by the
assembly script against the original clustering output — 0 mismatches found across all
3,858 rows in the run that produced this schema).

### 2.2 `policy_groups[]`

One row per proposed target policy group in the new department/location hierarchy.

| Field | Type | Notes |
|---|---|---|
| `target_group_id` | string | Deterministic synthetic ID, e.g. `corp::<region>::<department>` or `retailpos::<site>` or `server::<name>` — **not** a real Airlock `groupid` (the group doesn't exist yet) |
| `branch` | enum | `Corporate-Windows-Client` \| `Windows-Server-or-Citrix` \| `Retail-POS` |
| `region`, `department` | string \| null | Populated for Corporate-branch groups |
| `current_group_name_if_1to1` | string \| null | Populated where this target group maps 1:1 from an existing current group (mostly Server/Retail-POS groups) |
| `current_windows_device_count` | int | How many Windows agents would land here today |
| `provisional_wave` | string \| null | Cross-reference to the staged-rollout design (Wave 1 Pilot → Wave 4 Operationally-sensitive) — **provisional, not executable**, see §7 |
| `max_direct_gaps_among_feeder_groups` | int | How many unresolved trust gaps (see `risk_flags[]`) block this group's real-world readiness |
| `status` | string | Always `"PROPOSED - NOT YET CREATED IN AIRLOCK"` in this package |

### 2.3 `group_allowlist_assignments[]`

One row per (proposed allowlist, target branch) pair — **branch-level granularity**, not
resolved down to the exact `target_group_id`. This is an honest limitation, not an
oversight: the source analysis has no per-application device-to-department join available,
so most rows need a business-owner attestation to narrow from "used somewhere in this
branch" to "assign to this specific department's target group."

| Field | Type | Notes |
|---|---|---|
| `cluster_id` | string | Cross-references `new_allowlists[].cluster_id` |
| `proposed_allowlist_name` | string | Denormalized for readability |
| `target_branch` | string | Which branch this allowlist is assigned to |
| `assignment_granularity` | string | Always `"BRANCH_LEVEL_ONLY"` in this package |
| `assignment_tier` | enum | `Common-Shared` (broadly needed, safe to assign branch-wide) \| `Department-Candidate-NeedsAttestation` (narrow signal — needs a human confirmation before being scoped to one specific department) |
| `assignment_note` | string | Explains the reasoning / what's needed to finalize |
| `intune_device_count` | int \| null | Corroborating signal strength, where available |

### 2.4 `group_trust_assignments[]`

One row per target policy group (75 total) describing group-*level* trust (not
allowlist-scoped) — the minimal, deliberately-narrow set that should live at the group
level rather than inside a per-app allowlist.

| Field | Type | Notes |
|---|---|---|
| `target_group_id` | string | Cross-references `policy_groups[].target_group_id` |
| `direct_publishers_required` | string[] | **Hard gate**: `Microsoft Corporation`, `Microsoft Windows`, `Microsoft Windows Publisher` — must be declared **directly** (not inherited) on every target group, or migrated agents risk Airlock Safe Mode. Verified present in all 75 rows |
| `hard_gate` | string | Human-readable statement of the above rule and its consequence |
| `group_level_trust_kept` | string[] | The narrow, justified exceptions kept at group level (OS-vendor baselines pending content review; 5 narrow installer-specific parent-process rules already confirmed not a LOLBin risk) |
| `group_level_trust_explicitly_NOT_carried_forward` | string[] | The broad ambiguous-inherited publisher/path trust that must NOT be blanket-copied into the new design — each item needs individual reconciliation against `new_allowlists[]`, not wholesale re-declaration |

### 2.5 `device_migration_map[]`

One row per Windows agent (3,909 total in the source fleet at audit time).

| Field | Type | Notes |
|---|---|---|
| `agentid` | string | Airlock agent ID |
| `hostname` | string | *(raw data file only — redact before any wider sharing)* |
| `current_group_id`, `current_group_name` | string | Where the device sits today |
| `current_mode` | enum | `enforcement` \| `audit` |
| `target_group_id` | string | Cross-references `policy_groups[].target_group_id`, or a `NEEDS_TRIAGE::<reason>` sentinel if no department/POS/server signal could resolve one |
| `resolution_tier` | string | Which resolution mechanism produced the target (org source-of-truth, hostname pattern, manual-review default, etc.) |
| `justification` | string | Human-readable reasoning for the specific assignment |
| `conflict` | string \| null | Set when more than one signal disagreed and had to be resolved by the documented precedence rule |
| `eligible_for_migration` | bool \| null | `true` only if the device's *current* group has zero unresolved direct-resolution trust gaps; `null` if the current group falls outside the trust-gap analysis's scope |
| `n_direct_gating_entries` | int \| null | How many blocking gaps, if any |
| `blocking_reason` | string \| null | Human-readable explanation |
| `provisional_wave` | string \| null | Cross-reference to the staged-rollout design |
| `expected_current_group_id_precondition` | string | **Precondition**: an execution agent must re-fetch this device and confirm its live `current_group_id` still matches this value immediately before moving it — if not, skip and flag, do not force |
| `rollback_target_group_id` | string | Where to move the device back to if a rollback is needed (= its audit-time current group) |
| `idempotency_key` | string | Deterministic key for this specific proposed move — see §8 |
| `snapshot_captured_at` | string \| null | ISO-8601 timestamp of the source inventory snapshot this row is based on |

### 2.6 `risk_flags[]`

One row per specific trust element that is currently relied upon (directly or ambiguously)
by a group in scope, but is **not yet** covered by any `READY_FOR_CREATION`/`Medium`+
proposed allowlist.

| Field | Type | Notes |
|---|---|---|
| `group_name`, `group_id` | string | Which current group this gap applies to |
| `kind` | enum | `publisher` \| `path` |
| `name` | string | The specific publisher name or path pattern that's missing coverage |
| `gap_status` | enum | `TRUE_ORPHAN_NOT_FOUND_IN_ANY_CLUSTER` \| `COVERED_BY_PROPOSED_ALLOWLIST_Low` \| `COVERED_BY_PROPOSED_ALLOWLIST_Unresolved` |
| `resolution` | enum | `direct` (genuinely declared on this exact group) \| `ambiguous_same_identity_in_ancestor` (could be inherited noise or intentional re-declaration — unresolved by design, see the audit's findings on this ambiguity) |
| `severity` | enum | `BLOCKING_HARD_GATE` (direct-resolution gaps — these gate migration eligibility for every device currently in that group) \| `INFORMATIONAL_AMBIGUOUS_NOT_GATING` (ambiguous-resolution gaps — listed for awareness and future resolution, but not currently blocking) |
| `corroborated_recently_executing_tp03` | bool | Best-effort, non-exhaustive signal only — `false` must **not** be read as "safe to ignore" |

## 3. Readiness / status vocabulary (used consistently across all arrays)

- `READY_FOR_CREATION` / `PROPOSED - NOT YET CREATED IN AIRLOCK` — designed, not yet real.
- `MANUAL_TRIAGE_REQUIRED_BEFORE_CREATION` — needs a human decision before it can be designed further.
- `EXCLUDED_JUNK_DRAWER_NOT_AN_APPLICATION` — deliberately out of scope, not a gap.
- `BLOCKING_HARD_GATE` — must be resolved before the affected group's devices can migrate.
- `INFORMATIONAL_AMBIGUOUS_NOT_GATING` — tracked, not currently blocking.
- `NEEDS_TRIAGE::<reason>` (as a `target_group_id` value) — no device should ever be
  silently defaulted into a real target group when this applies.

## 4. Cross-reference keys

```
new_allowlists[].cluster_id  <-->  group_allowlist_assignments[].cluster_id
                                          |
                                          v
policy_groups[].target_group_id  <-->  group_trust_assignments[].target_group_id
        ^                                       ^
        |                                       |
device_migration_map[].target_group_id   device_migration_map[].current_group_id (join to risk_flags[].group_id for "is this device currently exposed to a known gap")
```

## 5. Why there is no native "policy version" field

Airlock's REST API (`/v1/group`) exposes only `groupid`, `hidden`, `name`, and `parent` for
a group object — no version, ETag, or last-modified timestamp of any kind (confirmed by
direct inspection, not assumed). Anywhere this package needs to detect drift between the
audit snapshot and a possibly-changed live server, it uses a **self-computed SHA-256
fingerprint** of the sorted set of that group's captured direct/inherited trust entries —
explicitly documented as a substitute integrity check, not an Airlock-native value. A
mismatch at execution time means "re-verify this group's analysis before touching it," not
"this package is broken."

## 6. What is deliberately NOT resolved by this package

- The manual-triage backlog for `MANUAL_TRIAGE_REQUIRED_BEFORE_CREATION` clusters.
- The `Department-Candidate-NeedsAttestation` tier's narrowing from branch-level to exact
  target-group assignment (needs business-owner attestation).
- Every `BLOCKING_HARD_GATE` risk flag (these are exactly the audit's "must resolve before
  execution" backlog, deliberately itemized rather than silently carried forward or
  dropped).

## 7. Staged rollout / wave design

Wave assignment throughout this package (`provisional_wave` fields) is **provisional and
not currently executable** — at the time this package was built, zero devices were
unconditionally eligible for migration (every in-scope current group had at least one
unresolved `BLOCKING_HARD_GATE` risk flag). Waves represent a pre-computed, deterministic
ordering that becomes real only as each group's specific blocking risk flags are resolved.
Operationally-sensitive branches (`Windows-Server-or-Citrix`, `Retail-POS`) are always
sequenced into the final wave regardless of their own gap-count, to avoid stacking a group
migration on top of an unrelated, still-pending audit-to-enforcement transition.

## 8. Execution preconditions (`execution_preconditions.json`)

See that file's own contents for the full, current text (batch limits, abort conditions,
7-step dependency ordering, rollback mapping, required post-operation verification, and
the idempotency-key scheme: `SHA-256(action_type|object_id|target_state)`, truncated to 16
hex chars, checked against an execution agent's own applied-actions log before applying
anything, so a resumed or retried run cannot double-apply a change). That file contains no
raw device/hostname/hash data — only the schema-level design — so it is safe to keep
alongside this document for reference; it is intentionally described here rather than
duplicated verbatim, since it is regenerated by the same script that regenerates the raw
data package and the two should never drift apart silently.

## 9. Non-goals of this document

This is a schema reference, not a findings report. For severity-ranked findings, the
narrative migration rationale, and the audit's methodology, see `audit/report.md`. For raw
counts and per-domain analysis, see the audit's Phase 2/3 findings memos (not committed to
this repository — local audit artifacts only).
