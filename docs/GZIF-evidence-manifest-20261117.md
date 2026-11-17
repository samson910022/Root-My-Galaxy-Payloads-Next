# GZIF (SM-S9180 / S9180ZHU8GZIF) — privacy-safe evidence manifest (2026-11-17)

Scope: the minimal, redacted set of hashes and identities that make the
2026-11-17 hardware-validation claims auditable **without** committing raw
logs, device identifiers, or PII. Addresses the "evidence gap" finding of the
independent deep review (repo `samson910022/Root-My-Galaxy-Payloads-Next`,
PR #1 issue comment 6959518195, finding 8).

**Outcome classification.** Everything here is **author-attested /
hardware-tested, not independently re-verified** by any other party and not
reproducible from this repository alone. The on-device transcripts were **not
retained**; the hashes and identities below are the only auditable handles.
Raw logs (~61 MB, `run2..run8_logcat.txt`, `dropbox_all.txt`, `kmsg_195.txt`)
stay off-repo by policy and must never be committed. No serial numbers, SSIDs,
IPs, accounts, or names appear in this manifest or in the tree.

## Firmware identity (device-confirmed 2026-11-17)

| Field | Value | Source |
| --- | --- | --- |
| Model / device | `SM-S9180` (`dm3q`, `dm3qzhx`) | `docs/GZIF-validation-summary-20261117.md` §1 |
| PDA (four-part) | `S9180ZHU8GZIF/S9180OZS8GZIF/S9180ZCU8GZIF/S9180ZHU8GZIF` (BRI, Taiwan; OZS/TGY multi-CSC) | same |
| SYSTEM fingerprint | `samsung/dm3qzhx/qssi:17/CP2A.260605.016/S9180ZHU8GZIF:user/release-keys` | same (`fota/SYSTEM_build.prop`) |
| Display build | `CP2A.260605.016.S9180ZHU8GZIF` | same |
| SPL / kernel | 2026-10-05 / `5.15.197-android13-8-34343818-abS9180ZHU8GZIF` (clang 14.0.7, built 2026-09-28) | same |
| Acquisition | samloader 2.2.0 FUS, `--model SM-S9180 --region BRI`, 2026-11-17 ("Latest Stable at the time = GZIF"); 12 GB zip kept host-side | same §2 |
| `boot.img` SHA-256 | `6df858ed65dad6f2a087de34a0f28f8843ec50ac2a33368d7bf98e5d78304ffa` | computed at analysis time |
| `boot.img.lz4` SHA-256 | `c3590ac387bd178f17351a935d8d5fc42efc3c20d3ecd484e7d65330d023acad` | computed at analysis time |
| kernel SHA-256 | `d8eb9556f58376eafcc962a1c68d914dde472f838519d6b533487007e987a69e` | computed at analysis time |
| Firmware→running-kernel attestation | unit `/proc/config.gz` byte-identical to Image-extracted config (`CONFIG_USER_NS` unset, `CONFIG_NET_NS=y`, `CONFIG_XFRM_USER=y`, `CONFIG_INET_ESP=y`) | same §2/§3 |

## DFRoot port chain

| Component | Identity / hash | Source |
| --- | --- | --- |
| Upstream base | `diabl0w/DFRoot @ 7a6513a` — "Fall back to libbase when libc++ hook selection fails (#185)", 2026-11-06 | public upstream; base of the fork |
| GZIF fork | `samson910022/DFRoot-GZIF`, public; `master` @ `bd8f8143b746bdfce65342f2fbf7c27c3e25accc` (2026-11-17T10:27:54Z, "feat: port to SM-S9180 S9180ZHU8GZIF (Android 17 / One UI 9.0)"); docs commit `a616148` (2026-11-17T10:27:49Z) | GitHub API, verified 2026-11-18 |
| Fork legal layer | `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `PORTING-GZIF.md`, `CHANGELOG.md`, `README.md` present at `master` | GitHub tree listing, verified 2026-11-18 |
| LKM source | `lkm/dfroot.c` SHA-256 `fc1cdb216b3364bd408acd76bb7943bcb6f5f257ec134962df96ac97b6b460be` (7,088 B); `lkm/Makefile` SHA-256 `3e0ea67d2bcc80c1ac6e9b5c9c6e30f90cedfdba53422f21592f2100e7cd849e` | fork tree; raw files re-downloaded and hashed 2026-11-18 |
| Embedded late-load binary (classic) | `app/src/main/jniLibs/arm64-v8a/libksud.so`, 5,101,488 B, SHA-256 `aab769430467e5a9f723c1bc8a3180e6fb0b0b82c52fba7b99887199407fc940` — matches the recorded prefix `aab76943…` (`ksud-dm3q-S9180ZHS8FZG1-kdp`, KernelSU 3.3.0, same `android13-5.15_kernelsu.ko` inside) | fork tree; raw file re-downloaded and hashed 2026-11-18 |
| Embedded late-load binary (Next) | `app/src/main/jniLibs/arm64-v8a/libksudnext.so`, 4,717,248 B, SHA-256 `679504dd4e104dc1a296ed4ec795b5a5f3e808c2bd345a7ecfa201b40f1dca1d` — matches the recorded prefix `679504dd…` (`ksud-next-generic-kdp`, KernelSU-Next 3.4.2) | fork tree; raw file re-downloaded and hashed 2026-11-18 |
| Built module `dfroot-android13-5.15.ko` | 13,504 B (per this repository's records: validation-summary §4, campaign §6.6, port-review); built in `ghcr.io/ylarod/ddk-min:android13-5.15-20260828`; **full SHA-256 never recorded** — an 8-hex prefix `94f8be98…` is recorded in the historical port review (`docs/research/gzif-port-review-20261117.md`); the fork CHANGELOG confirms the file's removal and gitignore but records no byte count; the binary is committed nowhere (the fork gitignores `lkm/dfroot.ko`; this repository carries no dfroot/GZIF `.ko` — the pre-existing `kernelsu/`/`susfs/` module history is unrelated to this campaign); host-side retention disposition is unverifiable from this tree | author-attested; see summary §4 |
| Diagnostic APK `com.gzif.preflight` | **Digest NOT recorded** (not published; not retained in-tree) | author-attested |
| DFRoot 4.8-gzif release APK | **NOT available / NOT recorded** — the fork publishes no GitHub release and no tags (verified via GitHub API 2026-11-18); APKs stay off-repo | this manifest |

## Run records (2026-11-17)

| Run | Loader | Outcome (author-attested; transcripts not retained) |
| --- | --- | --- |
| run6, 16:49 | `ksud-dm3q-S9180ZHS8FZG1-kdp` (KernelSU 3.3.0), classic manager | `ksud::late_load: kernelsu.ko loaded successfully!` (pid 20296, uid=0, `u:r:ksu:s0`, Seccomp: 0); `su -c id` → `uid=0(root) … u:r:ksu:s0`; `su -v` → `3.3.0:KernelSU`; `/dev/dfm6` present |
| run8, 17:53 | `ksud-next-generic-kdp` (KernelSU-Next 3.4.2), Next manager | same chain; `su -v` → `3.4.2:KernelSU`; modules staged at `/data/adb/modules/` |
| Everything else | — | No boot.img/init_boot.img was flashed; reboot wipes root; no module binary from this GZIF campaign is committed to this repository or published by the fork (the repository's pre-existing `kernelsu/`/`susfs/` module history is unrelated to this campaign) |

## What this manifest does **not** establish

- It is not proof the exploit works on any other unit or build.
- It does not make the on-device outcomes independently reproducible: the
  transcripts are not retained, the built `.ko` full digest is not recorded
  (8-hex prefix `94f8be98…` only), and the APK digests are not recorded
  because nothing was published.
- The evidence trail for the `/proc/config.gz` attestation rests on the same
  author session that ran the tests.
- Session attestation is labelled as such everywhere in the two companion
  docs; this manifest changes nothing about that.

## What would settle it

1. Retain a build log and the built `.ko` SHA-256 from a fresh fork build
   (`ghcr.io/ylarod/ddk-min:android13-5.15-20260828`).
2. Publish the fork's APK (or a reproducible Gradle build recipe) with its
   digest, and smoke-test on a test unit.
3. Commit a dated, hash-bound on-device transcript excerpt (redacted) for one
   run.
