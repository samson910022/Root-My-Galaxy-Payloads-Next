# Feed / Manifest / Tooling Compatibility Checklist (Phase 1)

Canonical target repo: `samson910022/Root-My-Galaxy-Payloads-Next` (branch `migrate/merge-our-customizations`, rushiranpise 98260/DDZJB baseline preserved).

## 1. Canonical catalog/support files

| File | Role | Notes |
|---|---|---|
| `support/targets-v3.json` | Primary v3 payload catalog consumed by newer app flows. Top-level `{ "schemaVersion": 3, "payloads": [...] }`. | Authoritative for Phase 1 profile additions (dm3q FZG1, e1q DZG1). Must preserve existing entries including DDZJB CVE-2026-98260 profiles. |
| `support/targets-v2.json` | Legacy/v2 catalog compatibility. | Must remain schema-consistent with existing tooling/apps that still read v2; add mirrored entries only when v2 representation is required and fields map cleanly. |
| `support/kernelsu-generic.json` | Generic KernelSU loader catalog (shared/fallback artifacts). | Not modified in Phase 1 unless a new generic asset is introduced. |
| `support/kernelsu-generic-susfs.json` | Generic KernelSU+SuSFS catalog variants. | Not modified in Phase 1. |
| `support/susfs-v1.json` | SuSFS module/catalog metadata. | Not modified in Phase 1. |

## 2. v3 payload entry schema (observed in baseline)

Required/common fields per payload object:
- `payloadId` (string, stable unique id; may include flavor suffix e.g. `-ksun341`, `-rsksu420`, `-cve-2026-98260-ksu`)
- `displayName` (string, human-readable device/kernel/variant label)
- `models` (array of model strings, e.g. `SM-S9180`, `SM-S9210`)
- `kernelVersions` (array of kernel version strings as published for matching)
- `exploit` (object): `url` (raw URL), `size` (integer bytes), optional `sha256`
- `kernelsu` (object): `url`, `size`, optional `sha256`, optional `version`

Optional/common fields observed:
- `flavor` (e.g. `kernelsu-next`, `resukisu`) for non-default variants
- `requiresFreshP0Session` (boolean) for profiles requiring fresh P0/session semantics
- DDZJB 98260 entries use full kernel build string in `kernelVersions` and include `sha256` for exploit and kernelsu

**Consistency rules:**
- `url` must point to an existing raw artifact path/blob in the intended repo/branch.
- `size` must equal actual file size in bytes; `sha256` (when present) must match file contents.
- Model/kernel matching strings must align with device reporting used by the app (no ad-hoc normalization in feed).
- Preserve existing URL ownership for untouched upstream entries (rushiranpise/BuSung) to avoid breaking provenance/availability; use `samson910022/Root-My-Galaxy-Payloads-Next` URLs for artifacts newly added/mirrored in this repo.

## 3. v2 catalog considerations

- v2 (`targets-v2.json`) may use an older structure/field set expected by legacy consumers and `tools/update_feed.py`.
- **Sync policy for Phase 1:** keep v2 valid and non-regressive. Add mirrored entries for newly ported profiles only if the v2 schema supports them without inventing incompatible fields; otherwise document v3-only addition and leave v2 unchanged except formatting-preserving non-breaking edits.
- Any v2 change must be validated with the repo's feed update/tooling expectations and JSON validity.

## 4. Tooling inventory (compatibility impact)

| Tool | Purpose (repo-local) | Phase 1 impact |
|---|---|---|
| `tools/update_feed.py` | Updates/generates feed entries (v2-oriented workflow in legacy usage). | Review before v2 edits; ensure added profiles don't violate assumptions (field names, ordering, URL/size/hash handling). |
| `tools/update_exploit_feed.py` | Updates exploit/feed metadata for payload artifacts. | Use/check when touching exploit URLs/sizes/hashes; keep schema consistent. |
| `tools/susfs_feed.py` | Maintains SuSFS catalog (`susfs-v1.json`). | No Phase 1 changes expected. |
| `tools/generate_p0_fingerprint.pl` | Generates P0 fingerprint data for targets (custom tooling present in our forks). | Ported as custom addition if absent/divergent; no feed schema change but relevant to target provenance. |
| `tools/kernel_stack_slots.py`, `tools/kernelfunc_disasm.py` | Analysis/helpers used in custom target research (present in our forks). | Ported as custom additions when valuable and non-conflicting. |
| `tools/patches/helper-marker-removal.patch`, `tools/helper-reproducibility.md` | Reproducibility/hardening notes and patch provenance (fork). | Ported for documentation/provenance; `su_daemon.c` adaptation recorded in src matrix. |

## 5. Ported profile representation (Phase 1)

| Profile | Artifacts/kernelsu (source of truth) | Feed placement | URL/provenance decision | Notes |
|---|---|---|---|---|
| `dm3q-S9180ZHS8FZG1` (SM-S9180, kernel 5.15.189) | `artifacts/dm3q-S9180ZHS8FZG1/cve-2026-43499-app.so` (+ existing root helper as applicable), `kernelsu/ksud-dm3q-S9180ZHS8FZG1-kdp` (device-validated v3.3.0/32601, preferred) | `targets-v3.json` (and `targets-v2.json` only if compatible) | Point to `samson910022/Root-My-Galaxy-Payloads-Next` raw paths for files added to this repo. | FZG1-specific ksud selected per fork reconciliation/proven docs over historical S918B reuse ambiguity; include size/hash/version where available. |
| `e1q-S9210ZHS6DZG1` (SM-S9210, kernel 6.1.145) | `artifacts/e1q-S9210ZHS6DZG1/cve-2026-43499-app.so`, `kernelsu/ksud-e1q-S9210ZHS6DZG1-kdp` | `targets-v3.json` (and v2 mirror if compatible) | Prefer `samson910022/Root-My-Galaxy-Payloads-Next` raw paths for ported artifacts present here; keep metadata (`size`, `requiresFreshP0Session`) consistent with proven entry. | Preserve PI-guard artifact lineage as documented in source repos/docs. |

## 6. Validation checklist (Phase 1)

- [ ] `support/targets-v3.json` parses as JSON and retains all pre-existing DDZJB/98260 entries unchanged in meaning/content (except intentional non-breaking ordering not required).
- [ ] `support/targets-v2.json` parses as JSON and remains compatible with existing consumers/tooling expectations.
- [ ] Added entries: `payloadId` unique, `models`/`kernelVersions` correct, `url/size/(sha256)` match on-disk files.
- [ ] No EZIF stable feed entry added in Phase 1 (candidate reserved for Phase 2).
- [ ] Artifact and kernelsu files referenced by new entries exist at the declared repo paths.
- [ ] Tooling scripts still parse/run for basic help/syntax where feasible (`python3 -m py_compile tools/*.py`).

## 7. Open/follow-up items

- Confirm whether v2 requires mirrored dm3q FZG1/e1q DZG1 entries for all consumers or if v3-only is acceptable in this branch's integration scope.
- If app-side strict hash verification is enforced for all profiles, backfill `sha256`/`version` consistently across added entries (Phase 1 populates known values from source artifacts).
- Revisit EZIF candidate signaling fields/representation in Phase 2 per migration plan open questions.

## Phase 2 addendum (e1q-S9210ZHU6EZIF, candidate / experimental)

### v3 entry added (`support/targets-v3.json`)

| Field | Value / decision |
|---|---|
| `payloadId` | `e1q-S9210ZHU6EZIF` |
| `displayName` | `Galaxy S24 (SM-S9210) | S9210ZHU6EZIF (CANDIDATE/EXPERIMENTAL) | Kernel 6.1.162` (explicit candidate signaling in human-readable label; **no schema field added**) |
| `models` | `["SM-S9210"]` |
| `kernelVersions` | `["6.1.162"]` (matches target firmware/kernel family as documented) |
| `exploit.url` | `https://raw.githubusercontent.com/samson910022/Root-My-Galaxy-Payloads-Next/main/artifacts/e1q-S9210ZHU6EZIF/cve-2026-43499-app.so` |
| `exploit.size` | `104128` |
| `exploit.sha256` | `efc8b49caa9129539645689479eaa55b7aa0059e621997beee375a8a1a86a538` |
| `kernelsu.url` | `https://raw.githubusercontent.com/samson910022/Root-My-Galaxy-Payloads-Next/main/kernelsu/ksud-e1q-S9210ZHU6EZIF-kdp` (v3.3.1-candidate lineage, best-recorded set) |
| `kernelsu.size` | `5065680` |
| `kernelsu.sha256` | `fde99b5a129e5714fe6f598cf8276c76d2cbaf1a7f4e6ce9ae69d5ebca0abe61` |
| `kernelsu.version` | `3.3.1` |
| `requiresFreshP0Session` | `true` (consistent with physical P0/oracle-style flow and DZG1 precedent) |

**Dual KSU assets provisioned:** v3.3.1-candidate pair (`ksud-e1q-S9210ZHU6EZIF-kdp`, `android14-6.1_kernelsu-e1q-S9210ZHU6EZIF-kdp.ko`) and v3.3.0 fallback pair (`*-v3.3.0-kdp`) added under `kernelsu/` with hashes recorded in `artifacts/e1q-S9210ZHU6EZIF/README.md`. Only the primary (v3.3.1-candidate) loader is referenced by the feed entry.

### Candidate/experimental representation (chosen)

- **Schema/tooling:** unchanged. No new fields introduced in `targets-v3.json`/`targets-v2.json` and no changes required to `tools/update_feed.py`, `tools/update_exploit_feed.py`, or `tools/susfs_feed.py` for this entry format.
- **Signaling:** explicit in `displayName` ("CANDIDATE/EXPERIMENTAL") plus `requiresFreshP0Session=true`; detailed status/limitations/provenance documented in `docs/SM-S9210-S9210ZHU6EZIF.md`, `docs/SM-S9210-EZIF-validation-20261102.md`, and `artifacts/e1q-S9210ZHU6EZIF/README.md`.
- **App-side gating assumption:** consuming apps should treat this profile as opt-in/experimental based on labeling/provenance and any app-side policy (exact-release/profile selection/candidate UX per Next migration plan §4.4). This payload repo does not enforce UI gating.

### v2 / related catalogs

- `support/targets-v2.json`: **unchanged** (remains valid; no mirrored EZIF entry added, consistent with v2's limited legacy set and to avoid inventing incompatible representation).
- `support/kernelsu-generic*.json`, `support/susfs-v1.json`: **unchanged**.

### Phase 2 validation checklist

- [x] `support/targets-v3.json` parses as JSON and pre-existing entries (including DDZJB/CVE-2026-98260, DZG1, FZG1) remain present/unchanged in meaning.
- [x] `support/targets-v2.json` parses as JSON and unchanged.
- [x] EZIF v3 entry fields consistent with schema: unique `payloadId`, correct `models`/`kernelVersions`, exploit/kernelsu `url`/`size`/`sha256` match on-disk files.
- [x] Candidate signaling explicit via `displayName`; no schema-breaking fields added.
- [x] Referenced artifact and primary kernelsu loader exist at declared paths; fallback KSU pair included for provenance.
- [x] Docs/reconciliation updated to reflect EZIF additions, src deferrals, and limitations.

**Known limitation (integration):** consumer behavior for candidate/opt-in gating depends on app-side policy/UX in Root-My-Galaxy-Next; payload feed alone provides labeling and metadata, not enforcement.

## Phase 3 addendum (pa3q-S938NKSUACZF1 / closed upstream PR rushiranpise/Root-My-Galaxy-Payloads#1)

Date: 2026-11-18. Scope: record the disposition of the feed-related review
feedback on closed upstream PR #1 ("Add pa3q-S938NKSUACZF1 payload profile",
CLOSED unmerged 2026-08-08) for this fork. **No feed entry was added or
removed.** The PR's added standalone entry was rejected; the shared v3 entry
remains the only v3 match for SM-S938N / 6.6.98 (the legacy v2 catalog's
pre-existing standalone profile is acknowledged below and kept unchanged).
See also `docs/SM-S938N-S938NKSUACZF1.md`.

### Disposition

| Field | Shared entry (kept) | PR #1's added entry (rejected) |
|---|---|---|
| `payloadId` | `galaxy-s25-series-2026-06-07` | `pa3q-S938NKSUACZF1` |
| `displayName` | `Galaxy S25 series \| Kernel 6.6.98` | `Galaxy S25 Ultra \| Kernel 6.6.98` |
| `models` | 30 models: `SM-S9310/B/N/Q/U/U1/W/Z` + `SC-51F`/`SCG31`, `SM-S936B/N/U/U1/W`, `SM-S937B/N/U/U1/W`, `SM-S9380/B/N/Q/U/U1/W/Z`, `SC-52F`/`SCG32` — including `SM-S938N` | `["SM-S938N"]` |
| `kernelVersions` | `["6.6.98"]` | `["6.6.98"]` |
| exploit | `.../rushiranpise/Root-My-Galaxy-Payloads/main/artifacts/pa3q-S938NKSUACZF1/cve-2026-43499-app.so` (rushiranpise raw path, per preserved provenance) size 104128 | `.../BuSung-dev/Root-My-Galaxy-Payloads/main/artifacts/pa3q-S938NKSUACZF1/cve-2026-43499-app.so` size 104128 |
| KernelSU | `.../BuSung-dev/.../kernelsu/ksud-s25u-kdp` (6407096 B; sha256 `fa3edcc7d168637394877b30cb1f909d762dda788ec14051f4ae79edd6562d63` on this branch's on-disk copy) | same loader, same size |

Both entries reference the same shared exploit artifact family and the same
KernelSU loader. In `support/targets-v3.json`, the `pa3q-S938NKSUACZF1`
exploit is referenced 4x and `ksud-s25u-kdp` 4x (the legacy v2 catalog
references them once and twice respectively — see below). The PR's entry
would have created two matches for `(SM-S938N, 6.6.98)` with no compensating
difference. The exploit URLs differ only by owner (`rushiranpise` vs
`BuSung-dev`); byte-identity across the two raw hosts is **unverified** from
this tree — only this branch's on-disk copy is hashed (`a2f4ea22…`,
104128 B) and the PR-side artifact cannot be hashed from here. `targets-v3.json`
contains no `pa3q-S938NKSUACZF1` payloadId; the duplicate pair existed only
in the PR's hunk (`@@ -162,6 +208,24 @@` of the PR diff).

### Legacy v2 catalog (`support/targets-v2.json`)

The v2 catalog (schemaVersion 2, for released older clients) **already
carries** a standalone `pa3q-S938NKSUACZF1` profile: `profileId`
`pa3q-S938NKSUACZF1`, model `SM-S938N`, kernel release
`6.6.98-android15-8-pd6ff1cd-abogkiS938NKSUACZF1-4k`, exploit pointing at the
`BuSung-dev/Root-My-Galaxy-Payloads/main/artifacts/pa3q-S938NKSUACZF1/cve-2026-43499-app.so`
raw URL (104128 B), KernelSU `ksud-s25u-kdp` (6407096 B, KMI `android15-6.6`),
full `buildDisplay`/`buildFingerprint` records. This is pre-existing, not
added or modified by this change, targets released v2 clients only, and is
**kept unchanged** (v2's limited legacy set; the v3 catalog is authoritative
for newer app flows). It is not evidence of hardware validation either —
it is profile metadata only. The "no standalone entry" statements in this
addendum are scoped to `support/targets-v3.json`.

### Why (policy)

- One entry per shared artifact: `support/README.md` ("one entry for each
  shared exploit and KernelSU payload"); `docs/PORTING.md` §8
  ("Add the artifact once to `support/targets-v3.json`").
- If a standalone S25 Ultra profile is ever to ship, it must point at
  target-specific artifacts and have validation evidence (see
  `docs/SM-S938N-S938NKSUACZF1.md` §3-§4) — not at byte-identical shared
  artifacts. CodeRabbit's remedy on the PR (drop `SM-S938N` from the series
  entry **and** use target-specific artifact URLs) is the only acceptable
  shape; until then the shared entry stands.
- The consuming application is out-of-tree; its selection behavior on a
  multi-match is unspecified in this repository. `tools/update_feed.py:458`
  notes that with two candidate matches "only the first is used" (exact-tuple
  duplicate guard only).

### Tooling note (follow-up, not implemented here)

`tools/update_feed.py` rejects only exact
`(flavor, tuple(models), tuple(kernelVersions))` duplicates; a model-subset
entry (`["SM-S938N"]`) vs the 30-model series entry is **not** caught — the
same class as the pre-existing `(SM-S938U1, 6.6.98)` collision listed above.
Candidate follow-ups: (a) extend the guard to flag model-subset overlaps
(warn or `--strict`); (b) decide the `(SM-S938U1, 6.6.98)` collision
resolution with the `pa3q-S938USQSCCZF9` profile owners (upstream PR #18);
(c) document app-side multi-match precedence. Deliberately out of scope for
this change.

### Checks (this branch)

- [x] `jq empty` passes for all five `support/*.json` (v2, v3, kernelsu-generic, kernelsu-generic-susfs, susfs-v1).
- [x] `support/targets-v3.json` parses; no `payloadId` equal to `pa3q-S938NKSUACZF1` exists; `SM-S938N` appears only in `galaxy-s25-series-2026-06-07` (exploit size 104128 matches on-disk artifact; shared `ksud-s25u-kdp` = 6407096 B). The legacy `support/targets-v2.json` standalone profile is acknowledged and kept unchanged (see above).
- [x] Referenced shared artifacts exist at declared paths and sizes (above).
- [x] Duplicate scan (model x kernel mapping >1 payloadId) reports 30 multi-match keys: 27 clean KernelSU / KernelSU-Next / ReSukiSU flavour triples, and **3 same-flavour (default KernelSU) collisions** — `(SM-F966U, 6.6.98)` `q7q-F966USQU9BZDN`/`q7q-F966USQSBBZG3`, `(SM-S9180, 5.15.189)` `dm3q-S9180ZHS8FZF5`/`dm3q-S9180ZHS8FZG1`, `(SM-S938U1, 6.6.98)` `galaxy-s25-series-2026-06-07`/`pa3q-S938USQSCCZF9-ksu330`. No SM-S938N collision: `(SM-S938N, 6.6.98)` maps only to `galaxy-s25-series-2026-06-07`. The `(SM-S938U1, 6.6.98)` case is the same defect class as the rejected PR entry; it is **noted for a follow-up decision, not changed by this addendum**.
- [ ] Standalone entry for `pa3q-S938NKSUACZF1` in the v3 catalog: **deferred** until rows 1-8 of `docs/SM-S938N-S938NKSUACZF1.md` §3 clear (offset sources, P0 fingerprint, tracefs event ID, worker caller offset, pselect word shift, KernelSU audit, hardware validation — see that file §4 for the firmware-acquisition steps). The legacy v2 profile stays as-is.
