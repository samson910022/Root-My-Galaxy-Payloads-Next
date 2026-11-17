# Galaxy S25 Ultra SM-S938N / S938NKSUACZF1 port record

Status: **documentation-only reconciliation for a profile carried by this repository; no device-side validation evidence exists in this tree. NOT cleared for production, not cleared for feed registration.**
Date: 2026-11-18. Scope: record the pinned firmware identity and the validation status of the `pa3q-S938NKSUACZF1` profile, and reconcile the review feedback on closed upstream PR rushiranpise/Root-My-Galaxy-Payloads#1 ("Add pa3q-S938NKSUACZF1 payload profile", closed unmerged). No firmware was acquired, nothing was rebuilt, no audit was run, no device was tested for this record.

## 1. Firmware identity (pinned by this repository)

| Field | Value | Source |
| --- | --- | --- |
| Profile | `pa3q-S938NKSUACZF1` | `src/targets/pa3q-S938NKSUACZF1/`; `support/targets-v2.json` |
| Model / device codename | `SM-S938N` / `pa3q` | `support/targets-v2.json` (`model`, `device`) |
| Region | `KOO` (as recorded in closed upstream PR #1; not corroborated by any other artifact in this repository) | upstream PR #1 (closed); otherwise unverified |
| PDA / build | `S938NKSUACZF1` | `support/targets-v2.json` (`buildDisplay` `BP4A.251205.006.S938NKSUACZF1`); `src/targets/pa3q-S938NKSUACZF1/target.h:11` (`BUILD_FINGERPRINT`) |
| Kernel release | `6.6.98-android15-8-pd6ff1cd-abogkiS938NKSUACZF1-4k` | `support/targets-v2.json` (`kernelRelease`) |
| Kernel banner | `#1 SMP PREEMPT Mon Jun  1 08:35:51 UTC 2026` (Android `11368308`, clang 18.0.0 based on r510928, LLD 18.0.0, `kleaf@build-host`) | `support/targets-v2.json` (`kernelVersion`) |
| Build fingerprint | `samsung/pa3qksx/pa3q:16/BP4A.251205.006/S938NKSUACZF1_OKRACZF1:user/release-keys` | `target.h:11`; `support/targets-v2.json` |
| Android / SDK / page size | 16 / SDK 36 / 4096-byte pages; ABI `arm64-v8a` | `support/targets-v2.json` |
| Vendor | not recorded for this build in this repository | — |
| Four-part versions (`S938NKSUACZF1/...`) | **NOT recorded in this repository** | — |
| Raw kernel size | **NOT recorded in this repository** | — |
| Raw kernel SHA-256 | **NOT recorded in this repository** | — |
| Firmware retrieval date | **NOT recorded in this repository**; the kernel banner is dated 2026-06-01, so any retrieval must post-date 2026-06-01 | — |
| Raw kernel / vmlinux.elf / Module.symvers | **absent from this working tree** (no Image, no symbols, no BTF for this profile) | tree-wide `find` for `Image`/`vmlinux.elf`/`Module.symvers` returns nothing |

`Samsung version: latest` (the value used by the closed PR) is non-reproducible and has been replaced above by the pinned build identifier. A retrieval date cannot be recorded because none exists anywhere in this repository; it is left as **not recorded** rather than invented.

## 2. Provenance and claims rejected from closed upstream PR #1

Upstream PR #1 was closed unmerged by the author: it mixed a then-latest S938NKSSBCZG3 firmware's derived constants into the existing `pa3q-S938NKSUACZF1` profile and, in the author's words, "rewrote the shared S25 support feed entry" (the PR's actual diff hunk in that shared entry was formatting-only; its substantive feed change was the added standalone entry). This record explicitly reconciles each of its material claims against this repository:

| Claim in PR #1 | Status here | Reason |
| --- | --- | --- |
| `Samsung version: latest` (`docs/SM-S938N-latest.md` line 10 in the PR) | **rejected; corrected to `S938NKSUACZF1`** (§1) | non-reproducible; repo pins the build above |
| `Kernel release: 6.6.98` | **rejected as written; corrected to full `6.6.98-android15-8-pd6ff1cd-abogkiS938NKSUACZF1-4k`** (§1) | feed match string only; full release string is the reproducible identity |
| Raw kernel `38849024` B / SHA-256 `25a811c5158caf9cdf03cc3c62b25aa6e41a30e17c2efd69d9853b20fd886e0b` | **not adopted** | Neither value is recorded **for this profile** anywhere in this repository. Per the author's close comment the image was then-latest **S938NKSSBCZG3** firmware — foreign to the pinned ACZF1 profile. The only profile with size `38849024` exists on the **unmerged `device-port/pa3q-S938USQSCCZF9` branch** (commit `e6e5092`, upstream PR #18; absent from this working tree, though its objects are fetchable): it is the sibling `pa3q-S938USQSCCZF9` (SM-S938U1, region TFN; Image SHA-256 `13752120bac4e917047709bba707c803295e88c85d00784419524dacf5b51d83`, per `git show e6e5092:docs/SM-S938U1-S938U1UESCCZF9.md`), a different model and build. |
| `p0_fingerprint.h` word change at slide `0x0c0000`: `913dc821d000b321` → `913e0021d000b321` | **not adopted; value kept at `913dc821d000b321`** | The replacement word is byte-identical to the word in the `pa3q-S938USQSCCZF9` table on the unmerged `device-port/pa3q-S938USQSCCZF9` branch (`git show e6e5092:src/targets/pa3q-S938USQSCCZF9/p0_fingerprint.h`, SM-S938U1 / SCCZF9; absent from this working tree). The ACZF1 table was added wholesale in commit `ca20540` and never modified since. Applying a foreign build's adrp/add pair without a derivation from the ACZF1 Image would corrupt the slide selector. See §3 row 2. |
| New standalone `pa3q-S938NKSUACZF1` entry in `support/targets-v3.json` (SM-S938N + 6.6.98) | **not adopted** | Duplicates the shared `galaxy-s25-series-2026-06-07` entry (same exploit artifact and `ksud-s25u-kdp` KernelSU loader, same sizes) for the same `(model, kernel)` pair. The consuming application's selection behavior on a multi-match is not specified in this repository (the app is out-of-tree; `tools/update_feed.py:458` notes that with two candidate matches "only the first is used"), and the established feed policy is one entry per shared artifact (`support/README.md:3`, "one entry for each shared exploit and KernelSU payload"; `docs/PORTING.md:434`, "Add the artifact once to `support/targets-v3.json`"). See §3 row 9. |
| Replacement `artifacts/pa3q-S938NKSUACZF1/cve-2026-43499-app.so` | **not adopted** | Content unverified; in this repository the artifact is 104128 bytes, SHA-256 `a2f4ea22c066764f0283afec69f8d9b181980cb2fc1fef8834975fc6274567f5` (§3 row 6). |
| New `docs/SM-S938N-latest.md` filename / `latest` naming | **superseded by this file** `docs/SM-S938N-S938NKSUACZF1.md` | house convention `docs/SM-<MODEL>-<BUILD>.md` |

## 3. Validation status (against the pinned S938NKSUACZF1 firmware)

Every item is recorded as **passed** (evidence retained in-tree), **recorded** (evidence exists in-tree but was not re-verified for this record), or **blocked / not run** (cannot be evidenced here). Nothing below is inferred from PR #1.

| # | Item | Status | Evidence / reason |
| --- | --- | --- | --- |
| 1 | Offset sources for `target.h` constants (KASLR inputs, waiter layout, memory geometry) | **blocked — not derivable here** | no ACZF1 `Image`/`vmlinux.elf` in this working tree; derivation provenance not recorded; values unverified |
| 2 | P0 fingerprint table (`p0_fingerprint.h`) | **unverifiable here** | generator `tools/generate_p0_fingerprint.pl` requires the raw Image as first argument (absent); table added wholesale in `ca20540`; the `0x0c0000` word never changed in any ref; PR #1's `913e0021…` is the SCCZF9 value and was rejected (§2) |
| 3 | tracefs `sched_blocked_reason` event ID (`SLIDE_TRACEFS_EVENT_ID 109`) | **borrowed, never confirmed on ACZF1** | inline comment cites an on-device observation on `6.6.98-android15-8` **(S938USQSCCZF9, a different build)** (`target.h:24-28`); that sibling port's own `port-report.md` marks the event ID as scaffolded (per upstream PR #18 review), so even the donor's provenance is not on-device-confirmed; must be re-read from `/sys/kernel/tracing/events/sched/sched_blocked_reason/id` on ACZF1 |
| 4 | worker caller offset (`SLIDE_TRACEFS_WORKER_CALLER_OFF 0x000d97ec`) | **blocked — unverified** | no comment/derivation in-tree (`target.h:23`); cannot be re-derived without the ACZF1 Image |
| 5 | pselect word shift (`SLIDE_PSELECT_WORD_SHIFT`) | **blocked — undefined for this target** | not defined by this target; `src/slide_app.c` silently defaults to `0` (`src/slide_app.c:15-16`); other targets define it explicitly; never derived from the ACZF1 Image |
| 6 | Build output | **recorded (CI provenance), not rebuilt for this record** | `artifacts/pa3q-S938NKSUACZF1/cve-2026-43499-app.so`: 104128 bytes, SHA-256 `a2f4ea22c066764f0283afec69f8d9b181980cb2fc1fef8834975fc6274567f5`; matches feed sizes in `support/targets-v3.json`; committed by the Exploit workflow (`e99bf42`, "Built by the Exploit workflow from 4350c7c"); local rebuild/re-verification not performed |
| 7 | KernelSU audit | **not run** | `kernelsu/README.md:33-34` lists `ksud-s25u-kdp` / `android15-6.6_kernelsu-s25u-kdp.ko` as the "Standalone reference module from the previously deployed S25U build"; no symbol check / relocation / CRC audit record exists for ACZF1 (audits are documented for other targets only); no `vmlinux.elf`/`Module.symvers` available |
| 8 | Authorized hardware validation (owned or explicitly authorized S938N unit) | **blocked — not run** | no S938N unit available or authorized for this record; the repository contains **zero hash-bound validation records** for this profile (no dated `su -c id` receipt, no `uname`, no Manager status) |
| 9 | Feed registration | **deliberately not registered as standalone** | SM-S938N/6.6.98 is served only by the shared `galaxy-s25-series-2026-06-07` entry; standalone registration rejected pending rows 1-8 |

## 4. Required manual review before any production claim

1. Acquire the exact SM-S938N firmware for the `KOO` region (as recorded in closed PR #1; not corroborated in this repository) with `samloader check-update`; verify PDA `S938NKSUACZF1`; compute the raw kernel size and SHA-256; record the date of retrieval (the gap CodeRabbit flagged on the closed PR).
2. Re-derive or re-verify the P0 fingerprint table from that raw Image via `tools/generate_p0_fingerprint.pl`; record size/SHA-256/probe/stride/verification output in this file (replacing rows §3 row 2 and §1).
3. Confirm `SLIDE_TRACEFS_EVENT_ID` on the ACZF1 unit itself (`/sys/kernel/tracing/events/sched/sched_blocked_reason/id`); derive `SLIDE_TRACEFS_WORKER_CALLER_OFF` and define `SLIDE_PSELECT_WORD_SHIFT` from the ACZF1 Image; update `target.h` only with recorded derivations.
4. Audit the exact KernelSU module against the recovered `vmlinux.elf` (host-side `check_symbol` — external tool, not in-tree — plus `kernelsu/tools/audit_module_against_target.py` and `kernelsu/tools/extract_target_symvers.py`); record zero-missing/zero-`__versions` results.
5. Build and audit the exact KernelSU module and `ksud`; record artifact hashes.
6. Run hardware validation on an owned or explicitly authorized S938N; record date, `uname`, and `su -c id` result; repeatability ≥ 3 runs.
7. Only then consider a standalone feed entry (§3 row 9); until then, the shared `galaxy-s25-series-2026-06-07` entry remains the only supported match.

## 5. What this record does not establish

- No evidence of exploit success, root, or any on-device result exists in this tree for S938NKSUACZF1. Inline comments in `target.h` and commit messages contain author-side claims (e.g. "rooted on the device", `target.h:207`); they are not dated or hash-bound and are **not adopted as validation evidence**.
- The `S938USQSCCZF9` sibling port (different model, different build, upstream PR #18) is not evidence for ACZF1.
- `docs/SM-S938N-latest.md` (added by the closed PR) was never part of this repository and is superseded by this file.
- This record does not claim the profile is safe, supported, or shippable. It records what is pinned, what was reviewed, and what remains unverified.
