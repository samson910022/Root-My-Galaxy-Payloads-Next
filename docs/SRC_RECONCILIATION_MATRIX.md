# Source Reconciliation Matrix (Phase 1)

**Scope:** Payloads migration to `samson910022/Root-My-Galaxy-Payloads-Next` on branch `migrate/merge-our-customizations` (base `rushiranpise/main@1b2c78c`, includes DDZJB / CVE-2026-98260 timer payload support).

**Sources compared (read-only):**
- Baseline (this repo/HEAD): `rushiranpise/Root-My-Galaxy-Payloads` line @ `1b2c78c` (+ DDZJB follow-ups present in branch)
- BuSung-dev-line: `/mnt/nvme_2TB/Users/samso/projects/Root-My-Galaxy-Payloads` `main@5f21482` (`feature/e1q-S9210ZHU6EZIF-port` also inspected for EZIF-only context, not ported as stable in Phase 1)
- Phase-integrated fork: `/mnt/nvme_2TB/Users/samso/projects/Root-My-Galaxy-Payloads-fork` `main@8cf29d9` (adds helper marker-removal hardening, reconciled dm3q FZG1 ksud/docs, EZIF validation/docs/tooling provenance)

**Method:** `diff -u` of target vs BuSung for core `src/*` files, commit inspection for PI-guard and helper-hardening changes, and manual review of DDZJB-specific additions (`src/kernelsnitch/*`, `src/targets/pa3q-S938U1UEUDDZJB/*`, timer/98260 flow in baseline). Because BuSung/fork diverged before DDZJB/timer payload integration, most core-file differences are **upstream-98260/DDZJB-required baseline deltas on the target side** rather than our custom regressions to drop.

## Summary

| File/area | Observed divergence (target vs BuSung/fork) | Classification | Action (Phase 1) | Validation targets / evidence | Notes |
|---|---|---|---|---|---|
| `src/common.h` | Target adds kernelsnitch includes/helpers and DDZJB-era structures/macros (`KERNELSNITCH`, timer payload support, expanded FOPS/probe declarations, etc.); BuSung has earlier pselect/slide/FOPS-era layout and different retry/diagnostic defaults in places. | **upstream-98260-DDZJB-required** (dominant) with **conflicting/mixed** pockets | **Keep target baseline.** Do not import BuSung wholesale. Any future merge of BuSung-side diagnostics/retry tweaks must be re-evaluated against 98260 flow. | Static/build compile checks for touched targets; DDZJB target build must remain intact. Evidence: target-only `kernelsnitch/*`, DDZJB target headers/call sites. | Wholesale replacement would remove 98260/DDZJB interfaces. Deferred: selective diff of non-DDZJB utility additions if proven target-neutral. |
| `src/fops.c` | Large structural divergence: target includes DDZJB/CVE-98260 FOPS handling, oracle/probe paths, and hardening aligned to current baseline; BuSung reflects pre-98260 behavior plus some diagnostics in its history. | **upstream-98260-DDZJB-required / conflicting-mixed** | **Keep target baseline.** Defer selective porting. | DDZJB FOPS/oracle behavior preserved by no-op in this phase; compile checks. | PI-guard/core safety fixes that touched FOPS in our line need per-hunk rebase onto DDZJB baseline before adoption. |
| `src/main.c` | Large divergence: target integrates 98260/timer trigger flow, kernelsnitch/trace paths, DDZJB route handling; BuSung has consumer-delay/env diagnostics and pre-98260 trigger structure. | **upstream-98260-DDZJB-required / conflicting-mixed** | **Keep target baseline.** Defer selective diagnostics ports. | DDZJB runtime flow unchanged; compile checks. | BuSung-only `CONSUMER_START_DELAY_USEC` and similar knobs are not ported here to avoid perturbing 98260 timing-sensitive paths without validation. |
| `src/pipe.c` | Differs between target and BuSung. | **conflicting-mixed** (needs per-hunk review) | **Keep target baseline for Phase 1; defer.** | Static review only. | No isolated, proven-safe custom hunk identified that is independent of DDZJB-era pipe behavior. |
| `src/preload.c` | Differs between target and BuSung. | **conflicting-mixed** | **Keep target baseline; defer.** | Static review only. | Defer to avoid regressions in loader/preload sequencing used by newer baseline. |
| `src/root.c` | Differs between target and BuSung. | **conflicting-mixed** | **Keep target baseline; defer.** | Static review only. | Any su/root flow changes must be validated with 98260 and legacy 43499 targets. |
| `src/slide.c` | Very large divergence: target contains 98260/kernelsnitch-era slide logic and DDZJB support; BuSung contains earlier tracefs/slide implementation and PI-related evolution history. | **upstream-98260-DDZJB-required / conflicting-mixed** | **Keep target baseline; defer per-hunk PI-guard reconciliation.** | Preserve DDZJB slide behavior; compile checks. | PI-guard improvements from our forks are not blindly ported because equivalent code regions differ substantially after 98260 integration. |
| `src/slide_app.c` | BuSung/fork commits add PI-guard hardening: skip `sched_setattr` when waiter `tid <= 0` (`be9fc39`) and gate sched fire/fired logs behind `SLIDE_SCHED_DIAG` (`a8d0841`). Target baseline has materially different 98260-aware slide/consumer flow. | **ours custom (intent) but currently conflicting-mixed against DDZJB baseline** | **Defer code port; document as follow-up.** Apply only after rebasing hunks onto current `slide_app.c` and validating on affected devices (e1q FZG1/DZG1/EZIF candidates) without impacting DDZJB. | N/A in Phase 1 runtime. Evidence: BuSung commits `be9fc39`, `a8d0841`. | Safety fix intent is valuable (avoid invalid `sched_setattr` target / reduce hot-path logging perturbation) but line-level patch does not apply cleanly to 98260 baseline. |
| `src/su_daemon.c` | Target includes bootstrap marker config/path support (`BOOTSTRAP_MARKER_CONFIG`, `load_bootstrap_marker_config`, marker write, 4th `umh_main` arg handling) and simple `late-load --ephemeral` exec path. BuSung/fork remove marker feature and add late-load retry/fallback logic (fork `8cf29d9` / `helper-marker-removal.patch`). | **conflicting-mixed:** marker path appears **baseline/consumer-protocol dependent** on target side; late-load retry is **ours custom/valuable** but currently coupled to marker-removal in source form. | **Keep target marker behavior and DDZJB-compatible interface. Port late-load retry hardening in-place (adapted) without removing marker support.** | Syntax/build checks for `su_daemon.c`; functional validation required on devices using ephemeral-only/strict ksud loaders and on DDZJB flow (follow-up). Evidence: `tools/patches/helper-marker-removal.patch`, fork `8cf29d9`, target grep for `bootstrap_marker`. | Marker removal deferred because target currently wires marker config and write; removing it could regress app/daemon readiness signaling. Adapted patch preserves `bootstrap_marker_*`/4th-arg handling and only hardens loader verification/retry. |
| `src/util.c` | Differs between target and BuSung. | **conflicting-mixed** | **Keep target baseline; defer.** | Static review only. | No safe isolated custom hunk selected in Phase 1. |
| `src/kernelsnitch/*`, `src/offset.h` (newer baseline areas) | Present/extended in target for 98260/timer payload support; absent or different in BuSung. | **upstream-98260-DDZJB-required** | **Keep/preserve.** | Must remain in tree and build inputs. | Not part of BuSung custom migration set. |
| `src/targets/pa3q-S938U1UEUDDZJB/*` (+ DDZJB feed/artifact refs) | DDZJB/CVE-2026-98260 target payload/profile in baseline. | **upstream-98260-DDZJB-required** | **Keep/preserve untouched.** | Feed/manifest references and files must remain intact. | Explicitly preserved per Phase 1 constraints. |
| `src/targets/dm3q-S9180ZHS8FZG1/*` | Present in BuSung/fork; absent in target baseline. | **ours custom / device-specific target addition** | **Add (ported).** | Target sources copied; feed/docs/artifacts/kernelsu aligned. | S23 Ultra FZG1 custom target. |
| `src/targets/e1q-S9210ZHS6DZG1/*` | Present in BuSung/fork; absent in target baseline. | **ours custom / device-specific target addition** | **Add (ported).** | Target sources copied; feed/docs/artifacts/kernelsu aligned. | S24 China DZG1 custom target. |
| `src/targets/e1q-S9210ZHU6EZIF/*` | Present in BuSung/fork feature lines and fork main artifacts/docs; Phase 2 candidate per plan. | **ours custom / candidate (defer stable inclusion)** | **Do not add as stable Phase 1 profile.** (No src target import in this phase.) | N/A | EZIF remains Phase 2 candidate; avoid premature stable feed/src inclusion. |

## Applied vs deferred (src)

### Applied in Phase 1
- **`src/su_daemon.c` (adapted):** added late-load verification/retry hardening (ephemeral attempt + control check + plain retry fallback, final control verify) while **preserving** existing bootstrap marker config/load/write behavior and 3/4-arg `umh_main` compatibility required by current target baseline.
- **Added target sources:** `src/targets/dm3q-S9180ZHS8FZG1/{target.h,p0_fingerprint.h}` and `src/targets/e1q-S9210ZHS6DZG1/{target.h,p0_fingerprint.h}` from our proven source line.

### Deferred (with rationale)
- **PI-guard `slide_app.c` hunks** (`tid <= 0` skip, `SLIDE_SCHED_DIAG` gating): valuable, but **not safely applicable** onto 98260-reworked slide/consumer code without rebase and device validation; deferring avoids DDZJB regression risk.
- **Bulk core-file ports** (`common.h`, `fops.c`, `main.c`, `pipe.c`, `preload.c`, `root.c`, `slide.c`, `util.c`): BuSung/fork versions predate or conflict with DDZJB/98260 structures; wholesale import would drop required functionality.
- **Full helper marker-removal behavior** (`bootstrap_marker_*` removal / strict 3-arg umh): conflicts with marker support present in target baseline; deferred pending protocol/consumer confirmation.
- **EZIF-specific source/target integration:** Phase 2 candidate scope.

## Risk notes
- **DDZJB/CVE-2026-98260 preservation:** no deletions/modifications to `src/targets/pa3q-S938U1UEUDDZJB/*`, `src/kernelsnitch/*`, or 98260-related baseline logic beyond untouched files; DDZJB feed entries preserved.
- **`su_daemon.c` adaptation risk:** retry logic changes loader flow but retains prior success condition via control verification; requires device validation on targets relying on marker signaling and on ksud variants with `--ephemeral` quirks.
- **Feed/source provenance:** newly added custom profile artifacts are referenced to `samson910022/Root-My-Galaxy-Payloads-Next` where added in this repo; existing upstream/rushiranpise/BuSung references were not rewritten except where necessary for added content consistency.

## Evidence pointers
- Target vs BuSung diffs: `diff -u src/{common,fops,main,pipe,preload,root,slide,slide_app,su_daemon,util}.c ...`
- PI-guard commits (BuSung): `be9fc39` (skip sched_setattr on unpublished waiter tid), `a8d0841` (gate sched fire/fired logs)
- Helper hardening (fork): `8cf29d9`, `tools/patches/helper-marker-removal.patch`, `tools/helper-reproducibility.md`
- dm3q/e1q provenance: `docs/SM-S9180-S9180ZHS8FZG1.md`, `docs/SM-S9210-S9210ZHS6DZG1.md`, `artifacts/dm3q-S9180ZHS8FZG1/README.md`, `kernelsu/README.md`, `kernelsu/REBUILD-dm3q-v3.3.0.md`

## Phase 2 addendum (e1q-S9210ZHU6EZIF, candidate / experimental)

**Goal:** Port EZIF custom payload work as **candidate/experimental** without regressing DDZJB/CVE-2026-98260, DZG1, or FZG1.

**Sources compared (read-only, EZIF):**
- `/mnt/nvme_2TB/Users/samso/projects/Root-My-Galaxy-Payloads` `feature/e1q-S9210ZHU6EZIF-port@75a26a9` (integrated `8cf29d9`; includes EZIF adoption/validation commits e.g. `d467222`, `45c9741`, `bdfe377`, timing/retry experiments and reverts)
- `/mnt/nvme_2TB/Users/samso/projects/Root-My-Galaxy-Payloads-fork` `main@8cf29d9` and `origin/feature/e1q-S9210ZHU6EZIF-port` (artifact/doc parity verified)
- `/mnt/nvme_2TB/Users/samso/projects/Root-My-Galaxy-S24` validation docs/provenance context (`SM-S9210-EZIF-validation-20261102.md` lineage)

### Summary (Phase 2)

| File/area | Observed EZIF divergence / intent | Classification | Action (Phase 2) | Validation targets / evidence | Notes |
|---|---|---|---|---|---|
| `src/targets/e1q-S9210ZHU6EZIF/{target.h,p0_fingerprint.h}` | EZIF-specific offsets/fingerprint, timing knobs, `APP_FOPS_FRESH_PAGE_ATTEMPTS=5`, `APP_FOPS_SINGLE_PATH_RETRY 0` (disabled per PR #10 review/P1 rationale), `SLIDE_PSELECT_TIMEOUT_NSEC=500000000L`, etc. | **ours custom / device+firmware-specific, candidate** | **Add (ported).** | Hash-matched to source; build/compat relies on baseline support for `APP_FOPS_FRESH_PAGE_ATTEMPTS` and existing deferred/readback flows. | No stable promotion; target is firmware/kernel-specific (`SM-S9210`, `S9210ZHU6EZIF`, kernel `6.1.162`). |
| `src/main.c` (EZIF adaptations in BuSung/fork history) | History includes EZIF-gated fresh-FOPS retry loop (`APP_FOPS_SINGLE_PATH_RETRY`, later **disabled to 0**), per-attempt `CONSUMER_START_DELAY_USEC` env tuning, `CONSUMER_MAX_CALLS==0` handling, deferred alias readback lifecycle tweaks, `CFI_FORCE_DIAG` override, and `probe_fops_and_production_touch`-based postwrite diagnostics (commits such as `380ffb9`, `19418fc`, `f5a05aa`, `d924c4e`, `158dfd6`, `a687ea9`, `bdfe377`). | **ours custom intent but conflicting-mixed against 98260/DDZJB baseline** | **Defer core code ports; no `main.c` edits applied.** Ported EZIF target config does not require `APP_FOPS_SINGLE_PATH_RETRY` (0) and uses knobs already supported by current baseline (`APP_FOPS_FRESH_PAGE_ATTEMPTS`). | Static review of diffs/history; DDZJB/98260 `main.c` behavior preserved unchanged. Runtime validation on EZIF hardware remains follow-up. | Env diagnostics (`CONSUMER_START_DELAY_USEC`, `CFI_FORCE_DIAG`) and `probe_fops_and_production_touch` are not present in baseline and would require careful rebase/testing; deferred to avoid perturbing 98260 timing-sensitive paths. **Risk:** EZIF may need further guarded adaptations if baseline flow differs from BuSung-era behavior under real conditions. |
| `src/fops.c`, `src/slide_app.c`, `src/slide.c`, `src/pipe.c` (EZIF/PI-guard-adjacent history) | PI-guard hardening/diagnostic commits exist in source lines (e.g. `be9fc39`, `a8d0841`) and EZIF bring-up experiments; baseline diverges substantially post-98260. | **conflicting-mixed** | **Defer.** | N/A (no code changes). | Same rationale as Phase 1: rebase + device validation required before safe adoption. |
| `artifacts/e1q-S9210ZHU6EZIF/cve-2026-43499-app.so` | Candidate app payload (104128 bytes, sha256 `efc8b49…6538`). | **ours custom / candidate artifact** | **Add (ported, hash-matched).** | Hash/size verified vs source repos. | Historical validation records may reference earlier snapshot hash `7b68f38d…` (`58a6772` lineage); this repo carries the ported current-source artifact above — lineage documented. |
| `kernelsu/android14-6.1_kernelsu-e1q-S9210ZHU6EZIF-*-kdp.ko`, `kernelsu/ksud-e1q-S9210ZHU6EZIF-*-kdp` | Dual pairs: v3.3.1-candidate (primary feed ref) and v3.3.0 fallback. | **ours custom / candidate support assets** | **Add both pairs (ported).** | Hash/size verified vs source repos; validation docs record v3.3.1-candidate usage. | Feed references v3.3.1 ksud as best-recorded set; v3.3.0 retained for provenance/fallback testing. |
| `docs/SM-S9210-S9210ZHU6EZIF.md`, `docs/SM-S9210-EZIF-validation-20261102.md`, `artifacts/e1q-S9210ZHU6EZIF/README.md` | Porting record, validation evidence, limitations, provenance. | **ours custom docs / evidence** | **Add (ported) with explicit candidate banners and limitation/provenance notes.** | Cross-referenced to source commits/branches and recorded artifacts. | Clearly states: experimental status, repeatability not established, reboot persistence not expected for volatile root, daemon byte-identity caveats, app-vs-adb/diagnostic differences, and artifact lineage distinctions. |

### Applied vs deferred (Phase 2 src)

**Applied:** `src/targets/e1q-S9210ZHU6EZIF/*` only (target headers + fingerprint). No shared/core `src/*.c` or `src/*.h` logic changes.

**Deferred (with rationale):**
- EZIF-era `main.c` diagnostic/tuning/retry hunks from BuSung line (including env overrides and production-touch probe): incompatible with or risky against 98260/DDZJB baseline without rebase and validation; final EZIF target currently disables single-path retry and can leverage baseline-supported attempt/defer mechanisms.
- PI-guard and slide/FOPS/pipe core refinements: require 98260-aware rebase and multi-target validation.

**Regression posture:** `src/targets/pa3q-S938U1UEUDDZJB/*`, `src/kernelsnitch/*`, DDZJB feed entries, and existing DZG1/FZG1 profiles/artifacts untouched by this phase.
