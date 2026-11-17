# dm3q-S9180ZHU8GZIF — unsupported research target

**This target's payload recipes do not build, are not built by CI, are not served by any feed, and must not be flashed, published, or treated as a working payload.** (`su_daemon.c`, the generic root helper, carries no target constants and builds independently; it is untouched by this gate.) The build gate in `target.h` (`DM3Q_GZIF_UNSUPPORTED_TARGET`) stops every payload-variant build with an `#error` unless a builder deliberately defines `DM3Q_GZIF_UNSUPPORTED_TARGET_OK`. Defining it does **not** make the target complete — it only lifts the gate. Most constants the payload references are absent.

## Why it exists

Static derivation from the raw kernel Image of `S9180ZHU8GZIF`
(5.15.197-android13-8-34343818, built 2026-09-28, SPL 2026-10-05) was performed
on 2026-11-17 as research for the CVE-2026-43284 ("Dirty Frag") feasibility
study. Nothing has been validated on device. There is no working payload built
from this profile or from this repository for this build — this target has never
compiled. A hardware-validated root chain for this exact build does exist in the
out-of-tree DFRoot-GZIF fork via the `dfroot.ko` crash-bridge + Samsung-patched
late-load (see `docs/GZIF-validation-summary-20261117.md` §6 and `docs/SM-S9180-S9180ZHU8GZIF.md` §6.5–§6.8) — it does not use this target header or this
repository's payload. See `docs/SM-S9180-S9180ZHU8GZIF.md` and `docs/GZIF-validation-summary-20261117.md`.

## Known missing / unproven pieces

- `P0_FINGERPRINT_HEADER` is never defined. Every app-oracle target defines it;
  `src/pipe.c` executes `#include P0_FINGERPRINT_HEADER`, so the APP variant
  fails at preprocessing. (A `p0_fingerprint.h` whose provenance is an offline
  BTF/nm derivation exists in this directory, but it is only the fingerprint
  table, not the slot/bank layout.)
- Oracle gate/probe slot layout (`P0_ORACLE_*`), bank layout (`SLIDE_BANK_*`),
  `FAKE_WAITER_*`/`FAKE_TASK_*` offsets, `STRUCT_PAGE_*`, pipe-buffer
  constants, and other symbols used by `src/slide_app.c` / `src/fops.c` /
  `src/util.c` / `src/root.c` are absent; the shared common-header defaults do
  not cover them. Both build variants fail to compile (verified 2026-11-18
  with NDK r28c).
- `ASHMEM_MISC_FOPS_OFF` and `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` are
  deliberately left undefined in `target.h` — do not fill them by copying a
  sibling build's values.
- `SLIDE_TRACEFS_EVENT_ID` (108) and `SLIDE_TRACEFS_WORKER_CALLER_OFF` are
  static derivations only; no on-device readback exists for this build. The
  payload's tracefs path requires the exact runtime id
  (`src/slide_app.c`); see the preflight probe (`tools/dm3q_gzif_preflight.c`).
- `SLIDE_P0_FORCE_ALIGN` / `SLIDE_P0_FORCE_MAX` describe this target's 0x8000
  candidate grid; `SLIDE_P0_OFFSET` forcing works on that grid, not the classic
  0x10000 one.
- The two weakest fingerprint rows (`0x1f0000`, `0x1f8000`) agree in 7 of 8
  qwords; pipe scoring rejects a best/runner-up tie. See the audit recorded in
  `docs/SM-S9180-S9180ZHU8GZIF.md` (or `docs/GZIF-validation-summary-20261117.md`).

## What it would take to make this a real target

1. Acquire the exact Image for this build and record its size and SHA-256.
2. Derive **every** missing constant from that Image (no sibling-build values);
   update the gate only with a clean
   `make TARGET=dm3q-S9180ZHU8GZIF all` plus the publish recipe passing.
3. Re-derive the fingerprint table with `tools/generate_p0_fingerprint.pl`,
   run the pairwise-distance audit, and record the results. The re-derived
   table must also eliminate the degenerate zero-qword exposure: row
   `0x1e8000` carries two committed zero qwords, so an all-zero sampled
   page is admissible under the default scorer (best=2, second=0) — see
   `python3 tools/p0_fingerprint_audit.py` output and the §5 record in
   `docs/SM-S9180-S9180ZHU8GZIF.md`. A generator-side nonzero-mask or
   best_score≥4 rule would close the class.
4. On-device verification of `SLIDE_TRACEFS_EVENT_ID`, `worker caller`,
   pselect shift, and the full pipe-oracle flow on an owned or explicitly
   authorized unit, recorded hash-bound and dated.
5. Only then consider registration in `support/targets-v3.json` (this profile
   is deliberately not registered, and the feed does not serve it).

Until every step above is complete and recorded, the correct state of this
directory is exactly what it is today: an unsupported research record with a
build gate.
