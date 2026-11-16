# Helper reproducibility notes

This note captures reusable provenance and verification practices migrated from
the app-side tooling in `Root-My-Galaxy-S24` / `Root-My-Galaxy-S23U` (`tools/build-helper.sh`,
`tools/sync-payloads.sh`) for the CVE-2026-43499 bootstrap helper (`src/su_daemon.c` /
`cve-2026-43499-root` / `libcve43499root.so`).

The original app scripts are **app-repository-specific** (they target
`app/src/main/jniLibs/...`, `app/src/main/assets/builtin-targets.json`, bundled asset
paths, and device/profile-specific manifest entries) and are therefore not copied
here as drop-in scripts. The parts worth preserving in the payloads repository are
the hardening/reproducibility rules below.

## Hardened helper patch

- `tools/patches/helper-marker-removal.patch` (adopted from S24, preferred because it
  includes the Apache-2.0 §4(b) modification notice) removes the bootstrap readiness
  marker feature from `src/su_daemon.c`. In this fork, the patch is **applied in-tree**
  to `src/su_daemon.c`; the patch file is retained as provenance/reference for the
  hardening delta.
- Rationale recorded in the patch: upstream/readiness-marker behavior read a path from
  `/data/local/tmp/cve43499-root-marker-path` and created that path as root without
  validation (a root-write primitive the app flow does not need). The patch restores
  `umh_main`'s original three-argument check and deletes marker config/write/load code.
- When building or auditing a helper binary, verify the marker symbols/config path are
  absent (for example, `grep -q 'bootstrap_marker_path\|BOOTSTRAP_MARKER_CONFIG' src/su_daemon.c`
  must fail). When comparing against upstream source, use the patch as the reviewed delta.

## Reproducible helper build discipline (from `build-helper.sh`)

Valuable practices to preserve for any helper build pipeline:

- **Pin source by immutable commit and blob**, not a moving ref: fetch
  `src/su_daemon.c` from the exact payloads commit/SHA, verify the git blob id and
  source SHA-256 before building.
- **Pin and verify the local patch**: keep the divergence from upstream reviewable as a
  checked-in patch file; verify patched-source SHA-256 after `patch` applies.
- **No hidden local includes**: the helper build should assume a self-contained source
  file (fail if `#include "..."` local headers appear unexpectedly).
- **Deterministic toolchain/flags**: record NDK package/version, API level, compiler path,
  and build flags (the app build used `aarch64-linux-android<API>-clang -fPIE -pie -O2 -g0 -Wall -Wextra ... -ldl`).
- **Verify binary contracts**: confirm required runtime strings/behaviors still exist in
  the produced binary (e.g. loader/logcat paths and helper mode/contract strings such as
  `--run-payload`, `--late-load`, `--ephemeral` where applicable to the build variant).
- **Verify binary properties and digests**: check ELF kind (PIE, AArch64), load segment
  alignment as required by targets, unpacked size, and SHA-256 against recorded
  provenance; verify before replacing committed artifacts.
- **Fail closed**: never touch committed outputs until all source, patch, contract, and
  binary checks pass.

## Payload/artifact sync discipline (from `sync-payloads.sh`)

`sync-payloads.sh` in the app repo refreshes bundled assets from pinned payload
commits and is tightly coupled to app asset layout/manifest profiles. Reusable ideas:

- Fetch artifacts by **immutable commit** (raw URL pinned to commit SHA), never by
  branch/ref name.
- Treat the manifest/provenance record as the **trust anchor** and require script pins,
  manifest digests/sizes, and on-disk bytes to agree.
- Verify size and SHA-256 of every downloaded file before install; verify both worktree
  and staged/index bytes when checking committed state.
- Fetch/verify everything to a temp area before mutating committed trees so partial
  failures do not silently ship wrong bytes.
- Keep profile-specific source provenance explicit (which repo/commit each artifact came
  from), especially when exploit and KernelSU artifacts are sourced from different
  commits.

## Scope note

App-specific paths, manifest schemas (`builtin-targets.json`), per-profile asset names,
device-local ADB pulls, and package-manager strip/install semantics belong in the app
repository. This payloads repository should carry source, patches, profile docs, and
artifact provenance appropriate to each payload/profile.
