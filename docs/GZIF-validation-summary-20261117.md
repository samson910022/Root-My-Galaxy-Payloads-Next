# GZIF Validation Summary — SM-S9180 / S9180ZHU8GZIF (2026-11-17)

Status: **hardware-validated root via DFRoot + Samsung-patched KernelSU (classic and Next). Volatile (late-load) root only; not boot-persistent; no One UI 9 upstream support yet.**
Primary record: `docs/SM-S9180-S9180ZHU8GZIF.md` (§6.5–6.8). Unit serial intentionally withheld. No `boot.img` flash was performed at any stage.

## 1. Firmware identity (device-confirmed 2026-11-17)

| Field | Value |
| --- | --- |
| Model | `SM-S9180` (`dm3q`, `dm3qzhx`) |
| PDA (four-part) | `S9180ZHU8GZIF/S9180OZS8GZIF/S9180ZCU8GZIF/S9180ZHU8GZIF` (BRI, Taiwan; OZS/TGY multi-CSC) |
| Fingerprint (SYSTEM) | `samsung/dm3qzhx/qssi:17/CP2A.260605.016/S9180ZHU8GZIF:user/release-keys` (`fota/SYSTEM_build.prop`; the `dm3q:17` form appearing in an early session transcript was a transcription error — no retained artifact supports it) |
| Display build | `CP2A.260605.016.S9180ZHU8GZIF` |
| Android / SDK / One UI | 17 / SDK 37 / One UI 9.0 (`ro.build.version.oneui=90000`); vendor Android 13 (SDK 33) |
| `ro.build.changelist` | 34344539 (kernel.common changelist 34343818) |
| SPL | 2026-10-05 (`fota_info.txt` + build.prop) |
| Kernel | `5.15.197-android13-8-34343818-abS9180ZHU8GZIF`, clang 14.0.7 (r450784e), `#1 SMP PREEMPT Mon Sep 28 06:37:13 UTC 2026` |
| Build date / type | 2026-09-28 / user, release-keys |
| Kernel size / boot.img | `0x2cb0a00` (46,860,800 B); `boot.img` 100,663,296 B, header v4, kernel at `0x1000` |

## 2. Acquisition & image hashes

- FUS via `samloader 2.2.0 check-update --model SM-S9180 --region BRI` (2026-11-17): **Latest Stable at the time = GZIF** (four-part above). 12 GB zip downloaded to the host-side `GZIF_work/` scratch dir (zip kept for provenance; AP tar NOT fully extracted; images streamed via `unzip -p | tar -xf -`).
- Hashes: `boot.img` SHA-256 `6df858ed65dad6f2a087de34a0f28f8843ec50ac2a33368d7bf98e5d78304ffa` · `boot.img.lz4` `c3590ac387bd178f17351a935d8d5fc42efc3c20d3ecd484e7d65330d023acad` · kernel `d8eb9556f58376eafcc962a1c68d914dde472f838519d6b533487007e987a69e`.
- `/proc/config.gz` pulled from the unit and byte-identical to the Image-extracted config — firmware→running-kernel attestation. IKCONFIG shows `CONFIG_INET_ESP=y`, `CONFIG_INET6_ESP=y`, `# CONFIG_USER_NS is not set`, `CONFIG_NET_NS=y`, `CONFIG_XFRM_USER=y`.

## 3. CVE disposition (binary-verified against the GZIF Image, 2026-11-17)

| CVE | Route | Verdict |
| --- | --- | --- |
| CVE-2026-43499 | "GhostLock" rtmutex/futex-PI UAF | **PATCHED** — both upstream fix hunks present (`remove_waiter()` NULL-`waiter->task` early-return + `pi_lock`/`pi_blocked_on` handling; `rt_mutex_start_proxy_lock()` `ret<0` gate ≡ `40a25d59e85b`). Do not port. |
| CVE-2026-98260 | POSIX-CPU-timer exec-path UAF | **OPEN** (bug present: `begin_new_exec()` call order unchanged; `fs/exec.c` identical v5.15.197↔v5.15.212; fix only in 6.1.171/6.6.158). Unported to dm3q; layouts unmeasured; not port-ready. |
| CVE-2026-43284 | "Dirty Frag" ESP page-cache write | **OPEN, but route-gated.** Both built-in ESP fast paths (`esp_input` @ `0xffffffc009489c20`, `esp6_input` @ `0xffffffc00954c888`) lack the `skb_has_shared_frag()` guard. Classic userns→netlink-XFRM route is dead (`CONFIG_USER_NS` unset; shell domain has zero `netlink_xfrm` rules; esp6 app-unreachable). Viable paper route: untrusted-app `IpSecManager` transport-mode IPv4 (netd installs SA as root) — on-device C0–C5 dry-run cleared all gates (SPI alloc, encap socket, transform build, SA apply/remove). Exploit-stage RKP/KDP/DEFEX behavior still unmeasured. |

## 4. The DFRoot port (public fork: `samson910022/DFRoot-GZIF`; local working copy formerly `GZIF-port/DFRoot-fzg1/`)

Forked `diabl0w/DFRoot @ 7a6513a` (upstream mirror at host-side `GZIF-port/DFRoot/`). Local changes vs upstream:

1. `ko_target` → present `/vendor/lib64/AIAwbModel_v2.2.tflite` (never executed; size and `vendor_file` label unverified — no retained `stat`/`ls -Z` evidence).
2. LKM `dfroot-android13-5.15.ko` built in `ghcr.io/ylarod/ddk-min:android13-5.15-20260828` (llvm-objcopy-stripped, 13,504 B; `module_layout` CRC from android13-5.15 KMI).
3. `compileSdk/targetSdk` 37→36; AGP 9.4.0→9.5.0; only the android13-5.15 KMI baked in.
4. `ExploitRunner.java` `stageAssets()` — dual-mode: `com.rifsxd.ksunext` → bundled `libksudnext.so`; otherwise bundled `libksud.so` (Samsung-patched, FZG1-validated classic); manager APK's `libksud.so` only as fallback. `stageBin()` copies to `<files>/ksud`.
5. `bootstrap.c` — before `late-load`, `mkdir /data/adb` + `cp /data/user_de/0/df.root/ksud /data/local/tmp/.ksud-stage` (matches the FZG1 loader staging protocol; clears `/dev/dfme2` staging failure mode).
6. GZIF-specific KMI verification: runtime KMI = **`android13-5.15`**; bundled `libksudnext.so` (`ksud-next-generic-kdp` 3.4.2, sha256 `679504dd…`) asset table contains `android13-5.15_kernelsu.ko` (plus 5.10/6.1/6.6) — confirmed via `strings` and by the successful 17:53 load. Classic `libksud.so` (`ksud-dm3q-S9180ZHS8FZG1-kdp` 3.3.0, sha256 `aab76943…`) embeds the same `android13-5.15_kernelsu.ko`.

## 5. Failure that produced the classic+Next Samsung-patched solutions

- **Manager-independent panic at `init_module()` for vanilla modules.** Run2 (15:34, classic `me.weishu.kernelsu`, KSU 3.3.0) and run3 (15:49, `com.rifsxd.ksunext`, KSU-Next 3.4.2) both died inside `ksud::late_load` → `kernelsu.ko` load window (~0.1–0.2 s, microsecond-identical), regardless of manager ABI. Panic text absent from all captures (XBL-only KP in dropbox); exact trap class undetermined. Cause class: stock live text-patching vs Samsung RKP/KDP/DEFEX/NO_PATCH_TEXT.
- **Repo Next daemon packaging bug.** After the panic fix, the repo's `ksud-next-dm3q-S9180ZHS8FZF5-kdp` (Next 3.4.1, "test" tier) bundled **only** `android13-5.15.189_kernelsu.ko`, while GZIF runtime KMI detection yields `android13-5.15`. The 17:00 run exited ~52 ms before any module load (`/dev/dfme2` set; no panic) — an asset-lookup failure, not a crash. Fix: bundle `ksud-next-generic-kdp` (3.4.2, embeds all four KMIs incl. `android13-5.15_kernelsu.ko`) — 17:53 run succeeded.

## 6. Hardware validation (2026-11-17, unit serial intentionally withheld)

- **Classic (run6, 16:49):** `ksud-dm3q-S9180ZHS8FZG1-kdp` (KernelSU **3.3.0**) — `ksud::late_load: kernelsu.ko loaded successfully!` (pid 20296, uid=0, `u:r:ksu:s0`, Seccomp: 0); sepolicy rules applied for `zygisk_lsposed`, `zygisksu`, `tricky_store`; 6 features applied; `ksud start: SUCCESS`; `/dev/dfm6` present.
  - `su -c id` → `uid=0(root) … u:r:ksu:s0` · `su -v` → `3.3.0:KernelSU` — session transcript, not retained as an artifact. (SELinux: the transcript printed `getenforce = Enforcing`; a ~17:00 retained capture printed `Permissive` — mechanism and caveats in the campaign doc §6.7.)
- **Next (run8, 17:53):** `ksud-next-generic-kdp` (KernelSU-Next **3.4.2**) — same chain, `kernelsu.ko loaded successfully!` / `ksud start: SUCCESS`; `su -c id` → `uid=0(root)…u:r:ksu:s0` · `su -v` → `3.4.2:KernelSU` · `/dev/dfm6` present — session transcript, not retained as an artifact.
- Modules staged under `/data/adb/modules/` on the unit: `zygisk_lsposed`, `zygisksu`, `tricky_store` (sepolicy rules applied at late-load).

## 7. Unverified / ephemeral / open items

- **Reboot persistence: none.** KernelSU late-load is runtime-only; every reboot wipes root — re-run DFRoot (LAUNCH ROOT, or Start on Boot).
- **Start on Boot / Auto Soft Reboot: untested.** The 15:34 death on this build was a kernel panic in the `kernelsu.ko` `init_module()` window (retained dropbox KMSG_194 entries), not the soft-reboot path — the soft-reboot path itself has not been observed to run here, and the two must not be conflated. Do not enable either without direct testing; root is wiped by any reboot regardless.
- **No `boot.img` / `init_boot.img` flash**; nothing was signed or written to boot images; exploit is file-patch + late-load only.
- **No One UI 9 upstream support yet**: GZIF is not registered in `support/targets-v3.json` / feeds, no pair exists; `git log` shows no GZIF artifacts; repo Next row is test-tier.
- Exploit-stage RKP/KDP/DEFEX behavior unmeasured; on-device stability unknown; 43284 route is dry-run-cleared but unported; 98260 unported; panic trap class undetermined; `com.gzif.preflight` diagnostic APK remains installed (`adb uninstall com.gzif.preflight` if unwanted).

## 8. Pointers (logs are large — do NOT commit verbatim)

- Campaign record: `docs/SM-S9180-S9180ZHU8GZIF.md` (§1–8; §6.5 preflight/dry-run, §6.6 first full chain, §6.7 classic root, §6.8 Next root). Predecessor: `docs/SM-S9180-S9180ZHS8FZG1.md` (FZG1, One UI 8.5). Feed policy: `support/targets-v3.json` (GZIF absent by design until feed registration).
- `docs/research/`: `cve-2026-43284-triage.md`, `cve-2026-43499-triage.md`, `cve-2026-98260-triage.md`, `dirtyfrag-trigger-requirements.md`, `selinux-preconditions.md`, `source-drop-crosscheck.md`, `vendor-policy-neverallows.md`, `vendor-sepolicy-extract.md`.
- Host-side `GZIF-port/`: `DFRoot/` (upstream mirror), `DFRoot-GZIF` local copy (dual-mode fork, app v4.8-gzif), plus third-party release APKs used only for ABI comparison; analyses `crash-analysis-run2.md`, `manager-compat-analysis.md`, `next-failure-analysis.md`, `next-failure-evidence.txt`, `next-loader-codepath.md`, `oneui9-rooting-landscape.md`, `rmgnext-feasibility.md`, `samsung-lateload-forensics.md`; raw logs `run2/3/4/5/6/8_logcat.txt`, `dropbox_all.txt`, `kmsg_195.txt` (~61 MB of `.txt`; run4–run8 alone are 9–20 MB each). Full logs contain verbose device output and **must not be committed verbatim**; hashes and key excerpts above suffice.
- Local build evidence (not for commit): `build/dm3q_gzif_preflight`; host-side `GZIF_work/` scratch dir.

## 12-line summary of this file

1. Identity: SM-S9180 (`dm3q`), PDA `S9180ZHU8GZIF`, SPL 2026-10-05, kernel 5.15.197-android13-8-34343818, One UI 9.0, fingerprint recorded.
2. Firmware was FUS Latest Stable (BRI) at acquisition; work dir: host-side `GZIF_work/`; SHA-256s for `boot.img`/`boot.img.lz4`/kernel recorded.
3. CVE-2026-43499 PATCHED (binary-verified, both fix hunks); do not port.
4. CVE-2026-98260 OPEN (unpatched ordering; no 5.15 fix known) but unported and unmeasured.
5. CVE-2026-43284 OPEN in code (esp4/esp6 unguarded); the DFRoot chain (DirtyFrag-class in-place CBC page-cache writes staged via the IpSecManager-triggered splice path) is ported and hardware-validated end-to-end on this unit (§6), volatile-only.
6. DFRoot was forked (`diabl0w/DFRoot@7a6513a`) with Samsung-patched `dfroot-android13-5.15.ko`, tflite `ko_target`, dual-mode `stageAssets()`, and the `.ksud-stage` bootstrap fix.
7. GZIF KMI is `android13-5.15`; generic Next 3.4.2 and classic FZG1 3.3.0 loaders embed `android13-5.15_kernelsu.ko` — verified in binary strings and by load.
8. Vanilla modules panicked at `init_module()` regardless of manager ABI; repo Next 3.4.1 daemon failed pre-load (`android13-5.15.189` asset vs `android13-5.15` runtime KMI).
9. Fix = Samsung-patched loaders bundled in the APK: classic `ksud-dm3q-S9180ZHS8FZG1-kdp` (3.3.0) and Next `ksud-next-generic-kdp` (3.4.2).
10. Hardware-verified 2026-11-17: both paths loaded `kernelsu.ko`, `su -c id` → uid=0, `u:r:ksu:s0`, SELinux transcripts conflict (see §6 above and campaign doc §6.7 for the `selinux_state` mechanism), `/dev/dfm6`, modules `zygisk_lsposed`/`zygisksu`/`tricky_store`.
11. Ephemeral: no reboot persistence; the 15:34 death was a kernel panic (Auto Soft Reboot path itself untested); no boot.img flash; no One UI 9 upstream feed/pair yet.
12. Pointers: `docs/SM-S9180-S9180ZHU8GZIF.md`, `docs/research/*.md`, host-side `GZIF-port/` (large raw logs not to be committed).
