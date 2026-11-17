# GZIF port review — 2026-11-17

> **HISTORICAL / SUPERSEDED — read this first.**
> This review is a point-in-time snapshot (2026-11-17 ~18:10 local) taken
> *before* the GZIF docs were scrubbed and committed to this repository and
> before the DFRoot GZIF fork was cleaned and published. Its "do not push"
> verdict applied to the unredacted state examined here; it is not a statement
> about the current state of either repository.
>
> What landed since (both verified 2026-11-18):
>
> - this repository: the GZIF docs are committed with device identifiers
>   withheld and un-retained evidence labeled session-attested; the current
>   state lives in `docs/SM-S9180-S9180ZHU8GZIF.md` (campaign record) and
>   `docs/GZIF-validation-summary-20261117.md`.
> - fork: `samson910022/DFRoot-GZIF` (master `bd8f814`, 2026-11-17), now
>   carrying `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`,
>   `PORTING-GZIF.md`, and `CHANGELOG.md`. This repository carries the
>   campaign's provenance manifest at
>   `docs/GZIF-evidence-manifest-20261117.md`.
>
> The checklist and verdicts below are retained for the record. Where they
> name defects, treat each item as open unless it is recorded as fixed in the
> two docs above or in the fork. The PII-scan item was corrected in place — the
> original example regex matched only this file's own redaction placeholders.

Read-only review of the GZIF (SM-S9180 / S9180ZHU8GZIF) port artifacts and candidate docs.
Nothing outside this file was created, edited, moved, or deleted. No `adb` was run, no git
operation was performed on any repository. All citations are `file:line` against the working
trees as of 2026-11-17 ~18:10 local.

Note: identifiers quoted in this review are redacted to placeholders (`<SERIAL>`, `<SSID>`, `<LAN-IP>`,
`<mail>`, `<name-zh>`, `<account-id>`, `<ims-uri>`). The raw values were readable in the host-side
logs only and are not reproduced here.

Artifacts reviewed:

- `Root-My-Galaxy-Payloads-Next/docs/SM-S9180-S9180ZHU8GZIF.md` (untracked, to be committed)
- `Root-My-Galaxy-Payloads-Next/docs/GZIF-validation-summary-20261117.md` (untracked, to be committed; created 18:00 today, §1–12)
- `Root-My-Galaxy-Payloads-Next/docs/research/*.md` (8 untracked docs, to be committed)
- `Root-My-Galaxy-Payloads-Next/src/targets/dm3q-S9180ZHU8GZIF/{target.h,p0_fingerprint.h}`, `tools/dm3q_gzif_preflight.c`
- Host-side fork `host-side `GZIF-port/` DFRoot-fzg1/` vs upstream `…/DFRoot/` (diabl0w/DFRoot @ 7a6513a)
- Host logs `host-side `GZIF-port/` {run2..run8}_logcat.txt`, `dropbox_all.txt`, `kmsg_195.txt`, `next-failure-*`, `crash-analysis-run2.md`
- Firmware-analysis scratch `host-side scratch `GZIF_work/`GZIF_work/{kernel,boot.img,*.asm,proc_config,gzif_ikconfig,fota/}` and `device/libc++.so`

`PORTING-GZIF.md` (named in the review task) does **not exist** in either copy — no porting
note accompanies the fork (see §5/§7). `docs/GZIF-validation-summary-20261117.md` does exist.

## 0. Verdict up front

The engineering work is real and largely internally consistent; the docs are not yet safe to
publish. The fork is two local patches away from being legally publishable, but it currently
embeds 9.8 MB of un-attributed binaries, has no provenance notes, and points `git push` at
upstream's repository. The to-be-committed docs leak one device serial and a folder of
absolute host paths; the host logs (correctly not tracked) are full of unrecoverable PII and
must never be committed anywhere. Several §6-era claims are contradicted by retained logcat
and by the fork's own evidence files.

---

## 1. What checks out (verified during this review)

- Firmware identity: kernel banner re-read from `…/GZIF_work/kernel` — `5.15.197-android13-8-34343818-abS9180ZHU8GZIF … #1 SMP PREEMPT Mon Sep 28 06:37:13 UTC 2026`, clang 14.0.7 r450784e — matches §1 of the campaign doc. `fota_info.txt` (`2026-10-05` SPL, `34344539`) matches. `ro.system.build.fingerprint` is `…/qssi:17/…` (see F10).
- SHA-256s match: `boot.img 6df858ed…`, `boot.img.lz4 c3590ac3…`, `kernel d8eb9556…` (recomputed locally). Kernel size `46860800 = 0x2cb0a00` ✓. `boot.img` 100663296 B ✓.
- IKCONFIG claims (§3): `CONFIG_INET_ESP=y`, `CONFIG_INET6_ESP=y`, `# CONFIG_USER_NS is not set`, `CONFIG_NET_NS=y`, `CONFIG_XFRM_USER=y`, `CONFIG_IKCONFIG_PROC=y`, no ESPINTCP — all present in both `gzif_ikconfig` and `proc_config`.
- `esp4_input.asm` (fast-path dump) is consistent with §3's esp4 claim: `ldrb w10,[x19,#0x7e]; tbz w10,#0`, `ldr w8,[x19,#0x74]; cbz w8`, `ldrb w8,[x8,#2]; add w22,w8,#1`, `bl 0xffffffc00926b8a4` (skb_cow_data), **no `BIT(1)`/`skb_has_shared_frag` test**. (Note: the dump covers only the first ~0xFC bytes of the function — the fast path, not the whole function; see A4.)
- `run6_logcat.txt` confirms §6.7: engine `I/KernelSU(20296)` KMI `android13-5.15`, `kernelsu.ko loaded successfully!` `:26590`, `[after load_module] pid=20296 … u:r:ksu:s0` `:26592`, three `sepolicy.rule` loads `:26694/:26794/:26923`, `Applied 6 features` `:26953`, `ksud start: SUCCESS` `:26980`.
- `run8_logcat.txt` confirms §6.8 kernel side: `I/KernelSU Next(22531) … Detected KMI: android13-5.15` `:8973`, `kernelsu.ko loaded successfully!` `:9739`, `Applied 5 features` `:9853`, `ksud start: SUCCESS` `:9881`.
- `libksud.so` (fork `app/src/main/jniLibs/arm64-v8a/`) is sha256 `aab769430467…` — byte-identical to repo artifact `kernelsu/ksud-dm3q-S9180ZHS8FZG1-kdp` (git-committed). `libksudnext.so` is `679504dd4e10…` — identical to `kernelsu/ksud-next-generic-kdp`. Strings confirm: classic embeds only `android13-5.15_kernelsu.ko` + `3.3.0 (uapi: 2)`; Next embeds `android12-5.10/android13-5.15/android14-6.1/android15-6.6_kernelsu.ko` + `3.4.2`.
- `lkm/dfroot.ko` and `app/src/main/jni/ko/dfroot-android13-5.15.ko` are byte-identical (sha256 `94f8be98…`). `MODULE_LICENSE("GPL")` present (`lkm/dfroot.c:7`).
- Fork diff vs upstream base `7a6513a` is limited to the 8 files shown by `git diff --stat` plus untracked `app/src/main/jniLibs/` and `lkm/dfroot.ko`. No exploit logic was altered (only `stageAssets()` staging and the `.ksud-stage` path).
- Fork contains no committed secrets: `signing.properties` present but gitignored (checked with `git check-ignore`), no keystores, no `.git` leakage of credentials; `exp.c`/`bootstrap.c`/`MainActivity.java` contain no URLs/tokens/analytics.
- `support/targets-v3.json` does **not** register GZIF (`grep GZIF` empty) — consistent with feed policy and validation-summary §7.
- `dfroot_screen.png` (host-side) shows only the app UI + status bar; no PII.
- Firmware work dir `host-side scratch `GZIF_work/`GZIF_work/` contains `gzif-debug.jks` (debug keystore for the `com.gzif.preflight` diagnostic APK) — fine to keep host-side; **must not** be committed (see §5/§6).

---

## 2. Private data (committed or to be committed)

**P1 — Device serial `<SERIAL>` in four to-be-committed repo files.** It is a unique,
device-identifying hardware serial; it does not need to be in a public document. Occurrences:

| File | Lines |
| --- | --- |
| `docs/SM-S9180-S9180ZHU8GZIF.md` | 121 (§6.5 heading), 143 (§6.6), 213 (§6.7) |
| `docs/research/dirtyfrag-trigger-requirements.md` | 443 |
| `docs/GZIF-validation-summary-20261117.md` | 4 (§lead), 51 (§6 heading) |

Recommend: replace all with `an SM-S9180 GZIF unit (serial intentionally withheld)` and keep
the rest of the text. No other Samsung identifiers (IMEI, PIN, PUK) were found in the
candidate files.

**P2 — Host logs contain full identity data and must never be committed.** `host-side `GZIF-port/` *.txt` (~61 MB) currently includes:

- WiFi SSID `<SSID>` and LAN IP `<LAN-IP>` (unmasked): `run2_logcat.txt` (SSID ×12, IP ×6), `run4_logcat.txt` (`:201`, `:225`, `:231`, …; SSID ×147, IP ×75), `run5_logcat.txt` (SSID ×98, IP ×50), `run6_logcat.txt` (`:11910`, `:11922`, `:11924`, `:11926`, `:11927`, `:12192`, `:14284`; SSID ×96, IP ×51), `run8_logcat.txt` (SSID ×84, IP ×45).
- Personal mailboxes, unmasked: `<mail>` (e.g. `run6_logcat.txt:2189`, `:23753`), `<mail>`, `<mail>`, `<mail>` (×35 in run6 alone), `<mail>`, `<mail>`, `<mail>`, `<mail>`, `<mail>` — ~260 hits across `run4/6/8_logcat.txt` (run4: 100, run6: 106, run8: 55). WorkSource/job lines embed them verbatim (`run4_logcat.txt:48688`, `:48689`, `:48706`, …).
- Phone-number-derived IMS identity: `<ims-uri>` (`run4_logcat.txt:102618`, `:102853`, `:102972`, `:102973`); `impu` assignment logged at `:102853`.
- **The user's real name in Chinese** and account IDs in Samsung cloud-sync lines: `<name-zh> 的 S23 Ultra`, `<name-zh> 的 Watch5`, `<name-zh>的「WH-1000XM4」`, `<name-zh>的「Beosound A1 2nd Gen」`, `<name-zh>的「Redmi Buds 6」`, owner ID `<account-id>` (e.g. `run3_logcat.txt:406`, `:430`, `:581`, `:786`; `run6_logcat.txt:14284`, `:67331`, `:67334`, `:67526`, `:68233`, `:69114`, `:69154`, `:69202`, `:66930`; `run8_logcat.txt:30405`; `run6_logcat.txt:67331`). This is the most sensitive item found anywhere in the review.
- SmartTag device IDs and geolocation-state lines (`run5_logcat.txt:27109`, `:50418`, …; `run6_logcat.txt:14250`, `:14255`, `:14284`), Bluetooth device names/MACs of the user's peripherals, account-push registration lines (`run6_logcat.txt:2189`).
- App-private data paths and Crash dumps: `dropbox_all.txt:1998` (`/data/app/~~<install-suffix>/me.weishu.kernelsu-…/lib/arm64/libksud.so`), `dropbox_all.txt` (≈1.2 MB; SYSTEM_LAST_KMSG 191–195 KP entries), `kmsg_195.txt` (bootloader/XBL MIPI dumps, `Bootloader: S9180ZHU8GZIF`, `Radio: S9180ZCU8GZIF`).

`run3_logcat.txt` and `next-failure-evidence.txt` additionally show the phone was repeatedly hard-reset (5× kernel panics: `dropbox_all.txt:11766`, `:12880`, `:13994`, `:17902`; `kmsg_195.txt:8`).

**The logs are not in any git repo today and must stay that way.** If the user ever wants a
committed evidence pack, it must be a redacted excerpt file produced with an allow-list, e.g.:
strip everything matching `<SSID>|<LAN-IP>|([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|@(gmail|ntnu\.edu\.tw|cpu\.edu\.tw|ims\.taiwanmobile\.com|gms\.subscribedfeeds)|<name-zh>|<name-zh>|<account-id>|AccessToken|challenge=|impu|SmartTag` and keep only the `I/KernelSU|I/dfroot` tag lines plus hashes. Recommend: do not commit logs at all; keep them host-side, and have the repo carry only hashes + short redacted quotes (which is what the validation summary already does — keep that pattern).

**P3 — Absolute host paths with the username in to-be-committed docs.** Mild but unnecessary:

- `docs/GZIF-validation-summary-20261117.md:35`, `:70`, `:86` (and `(§1–8…)` refs)
- `docs/research/vendor-policy-neverallows.md:5` (`host-side `GZIF-vendor-work/` …`)
- `docs/research/vendor-sepolicy-extract.md:12`, `:99`, `:211`, `:306`, `:316`

(Pre-existing repo docs already carry similar paths, e.g. `docs/SM-S9210-S9210ZHU6EZIF.md:151` — so this is a known, low-severity pattern, not a blocker.)

**P4 — Embedded build-host paths inside the to-be-committed binaries.**
`app/src/main/jniLibs/arm64-v8a/libksud.so` embeds a build-host cargo-registry path (`$HOME/.cargo/registry/…`, build-user home) (224 occurrences). `libksudnext.so` embeds `/home/runner/work/Root-My-Galaxy-Payloads/…` (CI path — not personal, repo name is public). Note `libksud.so` (sha `aab76943…`) is **already committed** in this repo as `kernelsu/ksud-dm3q-S9180ZHS8FZG1-kdp`, so these paths are already public. Still recommended: rebuild with `RUSTFLAGS="--remap-path-prefix=$HOME=/build"` (or equivalent) before the next artifact refresh; and document in the fork's NOTICE that the binaries carry such paths.

**P5 — `com.gzif.preflight` debug keystore (`…/GZIF_work/dryrun/gzif-debug.jks`)** signs the on-device diagnostic APK. Host-side only; if the diagnostic source is ever published, do not commit this keystore.

**P6 — `/data/user_de/0/df.root/…`, `/data/adb/…`, marker paths `/dev/dfm*`** appear in fork sources (`bootstrap.c:12-15`) — fine; same strings appear in every upstream DFRoot build.
**No tokens/keys/passwords were found in any text file in the review scope** (the two GZIF docs and 8 research docs). `signing.properties` holds a keystore password but is gitignored; it never entered the candidate tree.

---

## 3. Factually wrong or overstated claims in the docs (vs logcat / disasm)

**F1 (must fix). Campaign-doc header is stale and contradicts its own §6.5–6.8.**
`docs/SM-S9180-S9180ZHU8GZIF.md:3-5` still says "Status: **S1 — … Hardware validation NOT done. No port exists yet.**" and "Scope NOT executed: offset derivation, payload build, KernelSU build, flashing, on-device testing." §6.5–6.8 (same file) document a full port, two full hardware root successes, and module loading. This must be rewritten before commit (e.g. "Hardware-validated (run6 classic, run8 Next); see §6.7/§6.8; validation summary: docs/GZIF-validation-summary-20261117.md").

**F2 (must fix). §6.6 "FULL CHAIN SUCCESS" is contradicted by logcat and by the author's own forensics.**

- `:143-145` "with the **KernelSU-Next manager selected**" — false. `run2_logcat.txt:1673` shows `ksud::cli: command: LateLoad … package_name: "me.weishu.kernelsu"` (classic). The KernelSU-Next attempt was run3 (15:49).
- `:147-166` evidence block — as printed, it matches `run2_logcat.txt:1220-1620` line-for-line through the patch steps and the first five bootstrap lines, **but the final claim `ksud start: SUCCESS ✓ /dev/dfm6 — ksud late-load loaded KernelSU` is not supported**: `run2_logcat.txt` contains only `:1688 I/KernelSU(29659): ksud::late_load: Loading kernelsu.ko for KMI android13-5.15...` and **never** `loaded successfully!`; the capture ends at 15:34:23.349 (1851 lines) with the device gone. `dfroot` printed `ksud start: SUCCESS` at `:1679` — **11 ms before** the `Loading kernelsu.ko` line (`:1688`) — i.e. the marker was observed before the module load even began (the ksud CLI parent exits 0 before its forked late-load child finishes; the marker is a false-positive for "module loaded").
- `:168-171` "Outcome: **root chain works on GZIF end-to-end** … (esp4 primitive → … → KernelSU-Next ksud late-load → `ksud` exits 0 → marker `/dev/dfm6`)" — false on three counts: run2 did not complete the chain, run2 used the classic manager, and root did not exist after run2. The first actual root was **run6 (§6.7, 16:49)**.
- `:173-176` "The phone then **hard-rebooted** (bootstrap's soft-reboot path; user had enabled Auto Soft Reboot, which on this build is a full kernel reboot …)" — contradicted by `crash-analysis-run2.md` (same author, updated after run3), which attributes the death to a kernel panic in the `kernelsu.ko` `init_module()` window (~0.1–0.2 s), **not** to the soft-reboot path. Corroborating: `dropbox_all.txt:11766/:12880/:13994/:17902` (`SYSTEM_LAST_KMSG_191…194_KP`) and `kmsg_195.txt:8` (`SYSTEM_LAST_KMSG_195_20261117_155035_KP`, panic text absent — XBL/ABL-only dump) and `kmsg_195.txt:403` (`PonReason.HARD_RESET = 1`). The soft-reboot path could not have executed — bootstrap is blocked in `late_load_running()` (bootstrap.c:231) waiting for the load that the kernel panicked during. Validation-summary §7 (`:61`) repeats this unverified attribution — fix both places.
- The "cleanup" claim (`:168` `=== cleanup === ✓ (libc++ restored)`) is supported (`run2_logcat.txt:1681-1685`) ✓.

**F3 (must fix). §6.7 evidence block is mis-transcribed.** `:218-226` shows `I/KernelSU( 6104)` — but `run6_logcat.txt` uses pid **20296** throughout (`:25748`, `:25767`, `:26590`, `:26592`, `:26980`). pid 6104 appears in `run4_logcat.txt:30359-30367` (a different, failed run). Content lines match run6 otherwise. Re-copy the block verbatim from `run6_logcat.txt:25748-26980` (or trim pids to `I/KernelSU(…)` for brevity) and cite line numbers.

**F4 (must fix). §6.7 "SELinux hiding" explanation is wrong as a mechanism and contradicted by retained evidence.**
`:241` claims "SELinux remains **Enforcing** … `getenforce` reads `ksud`'s state, not the raw kernel `selinux_state`". Nothing about `getenforce` involves ksud (it reads selinuxfs from the kernel). More importantly:
- `lkm/dfroot.c:103` does `WRITE_ONCE(*selinux_state, false)` unconditionally at module init, and `:106-110` only re-asserts it if the kernel refuses — the global flips to permissive on **every** DFRoot run; there is no restore path in this codebase.
- `next-failure-evidence.txt:3` prints `Permissive` (captured ~17:00, after the 16:49 classic run — i.e. not before the loader ran), directly contradicting the "it stays Enforcing" claim. Within the same session, §6.7 reports Enforcing at ~16:52 and §6.8 at 17:53; neither capture is retained in a log artifact I could find (they are shell transcripts only — see A3).
- `selinux_hide` is indeed default-off here, but then AVC checks consult the patched `selinux_state`, not "ksud's state". Correct mechanism to document: "`dfroot.ko` writes `false` to the kernel's `selinux_state` at load; whether `getenforce` prints `Enforcing` depends on which flag selinuxfs reports on this build; we have conflicting captures (Enforcing at 16:52/17:53, Permissive at 17:00) — do not claim Enforcing persistence; verify with `cat /sys/fs/selinux/enforce` + AVC denial checks before relying on it."

**F5 (fix). §6.6 bullet — libc++ symbol offset stated as file offset is wrong.**
`:192` "`libc++.so` retains `_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_` @ file offset `0xb8ae4`". `0xb8ae4` is the symbol's **vaddr** (readelf on `device/libc++.so`); the RX LOAD segment maps vaddr `0x07fa80` → file `0x07ba80` (delta `0x4000`), so the **file offset is `0xb4ae4`** — consistent with `hook=0xb4ae8`, `shellcode=0x10faa8`, trampoline block at `0xb4ae0` (`run2_logcat.txt:1617`, `:1621`, `:1683`, `:1685`; `run6_logcat.txt:24563`, `:24569`). Suggest: "symbol at vaddr `0xb8ae4` → file offset `0xb4ae4`; hook `0xb4ae8` after BTI/PAC +4".

**F6 (fix). Duplicate/missing section numbering.** `## 7. Next steps` (`:194`) is followed by `## 7. Provenance of key binary facts` (`:202`); sections 6.2–6.4 never existed; §6.5–6.8 are appended after §7. Renumber (e.g. §6.9 Provenance, §7 Next steps) and fix cross-refs. **Broken cross-reference**: `:83` "See §10 for implication" — no §10 exists. Also `:107` "needs the GZIF S9180 unit (not attached)" — stale (unit attached from §6.5 on); `:111` "(d) SA-validity + SELinux at runtime unverified until the device runs it" — superseded by §6.5 C1–C5. `:87` "It is the only one of the three" fine. §5 (`:63-68`, esp. `:68`) is stale for the same reasons (USER_NS and SELinux rules were measured in §6.5; the effective policy was decoded in `selinux-preconditions.md`).

**F7 (fix). §4 bullet (d) is stale/wrong.**
`:61` "decide esp6 (built-in) vs esp4 (kmod) path" — both are built-in (`CONFIG_INET_ESP=y`, `CONFIG_INET6_ESP=y`; IKCONFIG re-verified), and §6.1 already concluded esp4-vs-esp6-by-reachability. Should read "esp4 (built-in, IPv4 IpSecManager route) chosen; esp6 built-in but app-unreachable" — or simply be deleted in favour of §6.1.

**F8 (fix). `dirtyfrag-trigger-requirements.md:19` is stale.** It states "`esp4_input` bug presence is **UNVERIFIED** (the GZIF binary check covered `esp6_input` only)". `esp4_input.asm` (fast-path dump, present in `GZIF_work/`) covers exactly the unpatched fast path (`:38-64` — the same `!skb_cloned`/`dataref`/`!skb_is_nonlinear`/`frag_list`/`nr_frags` logic §3 attributes to esp4, with **no** shared-frag test). The research doc predates the dump; either update it, or keep esp6-only phrasing there and cite the dump. Do not leave contradictory verdicts between `docs/research/dirtyfrag-trigger-requirements.md` and `docs/SM-S9180-S9180ZHU8GZIF.md` §3/§6.1 — a public reader will read both.

**F9 (fix). `selinux-preconditions.md` "the two attached phones are not Samsung and were not touched"** (~line 360) — stale: the GZIF unit was attached later the same day (§6.5; preflight + dry-run ran). One-word fix.

**F10 (fix). Fingerprint mismatch between committed `target.h` and the two docs.**
`src/targets/dm3q-S9180ZHU8GZIF/target.h:29` has `BUILD_FINGERPRINT = "samsung/dm3qzhx/qssi:17/CP2A.260605.016/S9180ZHU8GZIF:user/release-keys"` — this matches `ro.system.build.fingerprint` in the fota SYSTEM build.prop (verified) and One UI 9 fingerprint style (cf. S9210 `qssi_64`). Both to-be-committed docs claim `samsung/dm3qzhx/dm3q:17/…` (`SM-S9180-S9180ZHU8GZIF.md:123`; `GZIF-validation-summary-20261117.md:12`). The vendor build.prop carries the *different* fingerprint `samsung/dm3qzhx/dm3q:13/…` — the docs probably conflated it with the system one. Reconcile to one value and cite the exact prop file; if the unit's `getprop ro.build.fingerprint` really prints the `dm3q` form, cite that command output instead. Do not guess.

**F11 (minor). `target.h` is internally flagged, keep as-is but respect it.** `SEL_STATE_OFF/SELINUX_ENFORCING` marked "FZF5-style +4 NOT used" with BTF note (`:69-72`) — that's honest. `ashmem_misc_fops` deliberately undefined (`:79-81`) ✓ honest. `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` `:139-142` says "do not guess" ✓. Fine for commit with its headers; do not publish artifacts built from it (§7 feed policy already covers this).

**F12 (minor). §6.6 "Port adaptations" unverifiable claims.**
- `:180-181` "tflite (**530 KB**, never executed); verified present + `vendor_file` label on GZIF": file presence is proven by the successful splice patch (`run2_logcat.txt:1614`, `run6_logcat.txt:24560`), but **530 KB is unverifiable from host** (vendor.img was never extracted; `fota/VENDOR` holds only `build.prop`) and **no `ls -Z` / label evidence is retained anywhere** (grep across logs + scratch found none). Tag the label claim UNVERIFIED or drop it; keep "verified present" only.
- `:181-184` "LKM bundled … `module_layout` CRC from KMI → satisfies `same_magic` under modversions — version prefix ignored, only post-space compare": the rationale is speculative, and `modinfo lkm/dfroot.ko` reports **vermagic `5.15.202-android13-5.15.202_r00-dirty`** while the running GZIF kernel is `5.15.197-android13-8-34343818-abS9180ZHU8GZIF`. It loaded on the unit (markers printed), so it is *tolerated on this build* — say exactly that; do not generalise "version prefix ignored, only post-space compare" as a kernel rule. Recommend rewording to: "DDK build (5.15.202) with android13-5.15 KMI loaded on the 5.15.197 GZIF unit — tolerated there (full chain ran); mechanism unverified; rebuild against the exact KMI for any other target."
- `:185` "AGP 9.4.0→9.5.0 (cached artifact)" — fine (build succeeded).

**F13 (minor). Campaign doc itself notes §6.1/§6.5 ambiguities — good, keep.**
`:87-111` correctly labels the esp4 route as "paper-viable", §6.5 says exploitation success is unproven, §6.6 says root wiped by reboot. Only fix the specific items above; do not rewrite the whole file.

---

## 4. Files that reference unverified or non-existent artifacts as fact

**A1. `PORTING-GZIF.md` — absent.** The fork ships no porting note; the only documentation of the port's design is this campaign doc. A public fork must state provenance/design in-repo (see §7).

**A2. `docs/GZIF-validation-summary-20261117.md` (exists; new).** Its §5 is the *correct* narrative (run2/run3 panic at `init_module()` regardless of manager ABI; 17:00 run died pre-load on a missing `android13-5.15_kernelsu.ko` asset). Its cross-checkable claims pass (§1 SHAs, §4 item 6 asset-table strings — re-verified here, §6 run6/run8 lines match logcat). But:
- `:4`, `:51` embed the device serial (P1).
- `:3` "Volatile (late-load) root only" ✓ accurate. `:12` fingerprint — F10.
- `:61` "Auto Soft Reboot on this build triggers a full kernel reboot (bootstrap soft-reboot path)" — F2/F12 contradiction: cause of the 15:34/15:49/15:30 reboots was the panic in `init_module()`, not soft-reboot; the attribution is unattested and contradicted by `crash-analysis-run2.md` and the KP dropbox entries. Also `:85` repeats it.
- `:84` "SELinux Enforcing" — F4 contradiction.
- `:70` "raw logs … **must not be committed verbatim**" — correct and appreciated; keep it, and make the fork READMEs match.
- `:68` says "§1–8; §6.5 preflight/dry-run, §6.6 first full chain" — implies §6.6 was a success; after F2 is corrected, retarget this phrase.

**A3. Shell-output evidence with no retained artifact.** The captured "`su -c id` → uid=0 … `su -v` → 3.3.0:KernelSU / 3.4.2:KernelSU / `getenforce` → Enforcing / `/proc/uptime` 157.69" blocks (`SM-S9180-S9180ZHU8GZIF.md:231-239`, `:269-278`; `GZIF-validation-summary-20261117.md:54-55`) have **no corresponding retained artifact** (no log, no screenshot, no transcript file). They may be accurate; as written they are attestations of the author only. Either attach/point to a retained transcript or label them "shell transcript, not retained". Same for §6.5's C1–C5 dry-run block (`:129-137`, tag `GZIF001`): **no retained log contains `GZIF001`** (grep over all `*.txt` empty) — the block is copied from a session transcript, not from a stored artifact. Note it as such, or retain the artifact. Same for `com.gzif.preflight` APK — exists host-side (`GZIF_work/dryrun/gzif-preflight.apk`) but no installed-app evidence or uninstall record is retained.

**A4. §3's esp4 verdict is stronger than the artifact dump.** `esp4_input.asm` covers the first ~64 instructions (fast path). Claims like "BOTH implement the unpatched fast path verbatim … **no `skb_has_shared_frag()` test anywhere** in either function" are, for esp4, verified for the fast path only — there is no complete function dump retained (esp6's 1662 lines are complete enough; esp4's 120 are partial). Label: "fast path verified; remainder of esp_input not disassembled in retained artifacts" — or keep the claim and note the dump covers the `skip_cow` region only.

**A5. `docs/research/selinux-preconditions.md`** — internally consistent (recovery-ramdisk policy analysis; shell domain has zero xfrm rules). Stale attachment line (F9). Its "compiled policy from recovery ramdisk" is described as "a full vendor policy … 0 neverallow rules" — analysis claim, plausible, not re-verifiable here; keep as-is (it is labelled as analysis, not as binary fact).

**A6. `docs/research/source-drop-crosscheck.md`** — consistent with itself; records read-only scraping of Samsung's OSS portal including POSTs to the site's own `downSrcMPop`/`downAnnMPop` endpoints with the page's anonymous CSRF token. The claims are careful ("UNVERIFIED against Samsung source"). Worth noting publicly: the file documents protocol-level interaction with opensource.samsung.com; ensure nothing in it enables misuse (it doesn't — no credentials, no session cookies captured). Keep.

**A7. Referenced artifacts that exist** — `dfroot-lkm/README.md`/`dirtyfrag.c` ✓, `docs/research/*.md` ✓ (all 8), `support/targets-v3.json` ✓ (no GZIF entries), `kernelsu/ksud-dm3q-S9180ZHS8FZG1-kdp` ✓, `kernelsu/ksud-next-generic-kdp` ✓ (sha256 match). Referenced artifact that does **not** exist: `docs/GZIF-validation-summary-20261117.md` previously did not (the task anticipated this); it now does (18:00 today). Nothing else dangling was found; `PORTING-GZIF.md` absent (A1).

**A8. `tools/dm3q_gzif_preflight.c`** — clean: read-only, correct kernel-string pin, no telemetry. It *comments* honestly that it "performs NO privilege escalation". Commit as-is (after P1-style re-read — it is clean).
`src/targets/dm3q-S9180ZHU8GZIF/p0_fingerprint.h` — generated table, marked "Generated from the exact raw Image … VERIFIED" consistent with §6 header ✓. `target.h` — see F10/F11.

---

## 5. License / provenance mismatch in the DFRoot-fzg1 fork (upstream diabl0w vs local patches)

**L1 — Upstream base identity.** `origin = https://github.com/diabl0w/DFRoot.git` (`git remote -v`), HEAD `7a6513a69ce4c1a90b68d857c26347bf166ffe10` ("Fall back to libbase when libc++ hook selection fails (#185)", redzrush101, 2026-11-06). `DFRoot/` (sibling copy) is pristine at the same commit. The LICENSE is **GPL-2.0-only** (no "or later" anywhere: LICENSE §2 text only, no SPDX in sources; README has no "or later" phrasing). `MODULE_LICENSE("GPL")` in `lkm/dfroot.c:7`.

**L2 — The fork makes 8 tracked file modifications with no change notice.** GPL-2.0 §2(a) requires modified files to carry "prominent notices stating that you changed the files and the date of any change". None do. Affected files:

- `app/build.gradle.kts` (compileSdk/targetSdk 37→36; signing config unchanged; `versionCode = 407`, `versionName = "4.7"` **unchanged** — a GPL work distributed as "DFRoot FZG1" with upstream's version identity collides with upstream releases and confuses attribution/audit)
- `app/src/main/AndroidManifest.xml` (label → "DFRoot FZG1")
- `app/src/main/java/df/root/ExploitRunner.java` (`stageAssets()` dual-mode bundled-loader staging; ksud vs ksudnext)
- `app/src/main/jni/CMakeLists.txt` (KO_FILES reduced to android13-5.15 only)
- `app/src/main/jni/exp.c` (KO `.incbin` reduced to `dfroot-android13-5.15.ko`; `KO_TARGET_CANDIDATES` reduced to `/vendor/lib64/AIAwbModel_v2.2.tflite`)
- `app/src/main/jni/bootstrap.c` (adds `mkdir /data/adb` + `cp …/ksud/.ksud-stage` staging protocol; comment "the FZG1 ksud renames it…")
- `app/src/main/jni/libcxx.S` (`ko_target` string)
- `gradle/libs.versions.toml` (AGP 9.4.0→9.5.0)

plus untracked `app/src/main/jniLibs/` (2 Samsung-patched loader binaries, 9.8 MB) and `lkm/dfroot.ko` (13,504 B; duplicate of `app/src/main/jni/ko/dfroot-android13-5.15.ko`, sha256 `94f8be98…`).

**L3 — Bundled binaries carry the wrong licence posture for a GPL-2.0-only app.** The two `libksud*.so` are Samsung-patched builds of KernelSU / KernelSU-Next userspace (`ksud-dm3q-S9180ZHS8FZG1-kdp` 3.3.0; `ksud-next-generic-kdp` 3.4.2). Upstream licensing (both projects): `kernel/` = **GPL-2.0-only**; everything else = **GPL-3.0-or-later**. A GPL-2.0-**only** derivative may not absorb GPL-3.0 components; distributing them as an "aggregate" is defensible only if the NOTICE says so explicitly and the components' licenses are shipped. The fork today: no NOTICE, no THIRD_PARTY list, no source offer, no copy of the component licenses, no list of what the binaries are. Under GPL-3.0 §6, conveying the APK obligates the conveyor to provide (or offer) the complete corresponding source for the GPL-3.0 userspace components — the sources exist (this repo builds them via `kernelsu/patches/KernelSU-Next-v3.4.2-…patch` + pinned upstream commits), but the fork gives a recipient no way to learn that.

**L4 — No provenance documentation for the binaries in the fork.** Nothing in the fork says: built from which KernelSU(-Next) commit, with which patch, by whom, reproducible how, sha256 of the two binaries (they are `aab76943…` and `679504dd…`), and where the sources live (this repo's `kernelsu/` + upstream). For a public repo this is mandatory both legally (attribution) and practically (audit/panic triage).

**L5 — What the fork should carry (minimum):**
1. `LICENSE` unchanged (GPL-2.0-only, verbatim). Keep.
2. `NOTICE` or `THIRD_PARTY_NOTICES.md` stating:
   - Upstream baseline "diabl0w/DFRoot @ 7a6513a (GPL-2.0-only)" + link to upstream repo/license;
   - The Samsung-patched loaders: versions, source pins (upstream repo + tag/commit), patch files (`kernelsu/patches/KernelSU-Next-v3.4.2-samsung-kdp-rkp-defex.patch`, `kernelsu/patches/KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch`), build recipe pointer (`.github/workflows/ksu-build.yml`, `kernelsu/README.md`, `REBUILD-dm3q-v3.3.0.md`), sha256 of both binaries;
   - Per-component licences: KernelSU/KernelSU-Next kernel module = GPL-2.0-only; userspace (ksud/ksuinit/manager-of-origin) = GPL-3.0-or-later; DFRoot = GPL-2.0-only; repo `susfs` artifacts = GPL-2.0-only (not bundled here);
   - Explicit aggregation statement: "The APK aggregates DFRoot (GPL-2.0-only) with two independent executables; each component remains under its own licence."
3. `CHANGELOG.md` / fork section in `README.md` enumerating the 8 file-level diffs (dates, rationale: SM-S9180 GZIF One UI 9 validation), plus safety/limits (works only on S9180 GZIF with stock modules → panic; loaders are Samsung-patched; volatile-only; not for other builds).
4. Per-file change headers on the 8 modified files (GPL-2.0 §2(a)) — even one-line `// Modified 2026-11-17: <what> (DFRoot-FZG1)` satisfies the requirement; top-of-file notice preferred.
5. `versionCode`/`versionName` bump (e.g. 407→408, 4.7→4.8-fzg1) to keep attribution/feed expectations sane.
6. `versionName` in `reportDeviceInfo()` (ExploitRunner.java) will surface automatically via `BuildConfig.VERSION_NAME` ✓ no other change needed.
7. A stated contributor path back to upstream (README already asks for PRs — keep; ideally offer the GZIF port as an upstream PR; at minimum link it).

**L6 — Not a fork-of-upstream legally if you change the app id; aggregation caveat stands regardless.** Keeping `applicationId = "df.root"` is the cheapest correct option (bootstrap.c:12 hardcodes `/data/user_de/0/df.root/...`; changing id breaks staging). If you ever change it, update `PREFS_PATH`, `KSUD_STAGE`, `KSUD`, `MODULES_DIR` consumers consistently. Keep attribution `"@diabl0w"` credits in the app UI (it is still there).

---

## 6. Large generated artifacts that should not be committed as-is

| Artifact | Size | Disposition |
| --- | --- | --- |
| `…/GZIF-port/KernelSU_Next_v3.4.2_33355-release.apk` | 16.7 MB | Third-party release binary; **never** commit/redistribute unmodified without the upstream grant; not needed for the port. Delete or quarantine. |
| `…/GZIF-port/run{2,3,4,5,6,8}_logcat.txt` | 0.28 / 0.24 / 19.9 / 12.1 / 20.0 / 9.9 MB | **Never commit** (PII, P2). Keep host-side; publish only redacted excerpts. |
| `…/GZIF-port/dropbox_all.txt` | 1.24 MB | **Never commit** (app crash data, install paths, KP dumps). |
| `…/GZIF-port/kmsg_195.txt` | 66 KB | **Never commit** (bootloader/XBL dump, full device config). |
| `…/GZIF-port/*.md` (analyses) | 27–52 KB each, ~300 KB total | Fine to keep host-side; do not paste verbatim into repo without PII scan (they contain username-bearing host paths; no SSID/emails found by grep). If copied in, relativize paths first. |
| `…/DFRoot-fzg1/app/build/outputs/apk/release/DFRoot_4.7.apk` | 5.88 MB | Gitignored ✓ (`.gitignore:9 app/build/`) — keep it that way. Never commit. |
| `…/DFRoot-fzg1/lkm/dfroot.ko` | 13.5 KB | **Would be committed as-is today** (untracked, NOT gitignored); it is byte-identical to `app/src/main/jni/ko/dfroot-android13-5.15.ko` which IS gitignored. Add `lkm/dfroot.ko` to `.gitignore` and drop it from the tree. |
| `…/DFRoot-fzg1/app/src/main/jni/ko/dfroot-android13-5.15.ko` | 13.5 KB | Gitignored ✓ (upstream design: CI/`make` rebuilds it). **Fresh public clone cannot `./gradlew assembleRelease` without it** (exp.c `.incbin`) — document `make` (podman + DDK) or fetch it from this repo's CI artifacts; do not silently commit a local untracked copy without also committing its provenance. |
| `…/DFRoot-fzg1/app/src/main/jniLibs/arm64-v8a/{libksud.so,libksudnext.so}` | 5.10 + 4.72 MB | Untracked, would be committed. The fork *needs* them for a fresh build — decide: commit them deliberately with NOTICE + sha256 manifest (acceptable, they're already public here), or gitignore + fetch-at-build-time. Do **not** commit them anonymously/quietly. |
| `…/DFRoot-fzg1/app/src/main/jni/splicehelper` | 1.4 KB | Gitignored ✓ (generated by CMake from `splicehelper.c`) — correct. |
| `…/DFRoot-fzg1/lkm/*.{cmd,o,lto.o,mod,mod.c,lds}`, `modules.order`, `Module.symvers` | 240 KB | Gitignored ✓ (upstream pattern) — correct. |
| `…/GZIF_work/dryrun/gzif-debug.jks` | debug keystore | Never commit anywhere; regenerates trivially. |
| `…/GZIF_work/*.img`, `vmlinux.elf` … | ~5 GB | Host-side only (already); out of scope for any repo. The doc already says so (§2 `(host-side)`). |
| `dfroot_screen.png` | 111 KB | Host-side; fine to attach to a bug report after eyeballing ✓ (it shows only the app). |

Repo (`Root-My-Galaxy-Payloads-Next`) large files are all intentional committed build artifacts by design; nothing in the GZIF candidate set is >5 MB. `docs/GZIF-validation-summary-20261117.md` says logs "must not be committed" — enforced by nothing today; make it a checklist item, not a promise.

---

## 7. Concrete checklist before pushing the fork to a public repo

Do these in order; stop at the first failure and fix it.

1. **Retarget the remote.** `git remote -v` currently prints `origin = https://github.com/diabl0w/DFRoot.git`. Create/choose your public repo and `git remote set-url origin <new-url>`. Never `git push` from this directory before that (or you will attempt to write to upstream). Disable upstream auto-track: `git branch --unset-upstream` if needed.
2. **Decide scope of the public artifact**: `DFRoot-fzg1` fork **only**, or also the S9180 docs? Do not bundle raw logs, `.apk` outputs, or the signed `DFRoot_4.7.apk` anywhere in it.
3. **Housekeeping before first commit:** `make clean` in the fork (removes `lkm/*.o`, `lkm/*.cmd`, `lkm/dfroot.ko`, `app/src/main/jni/splicehelper`, `app/build`, `.gradle`); then `git status --porcelain` must show only intentional files. Add `lkm/dfroot.ko` and (if you choose not to bundle them) `app/src/main/jniLibs/` to `.gitignore`. Verify `git ls-files | grep -E '\.(apk|jks|ko|keystore)$'` prints nothing unintended.
4. **Decide `jniLibs`**: either (a) commit the two Samsung-patched loaders deliberately — with a sha256 manifest, NOTICE entries, and README section explaining who built them and how to reproduce (`kernelsu/README.md`, REBUILD notes, `KernelSU-Next-v3.4.2-samsung-kdp-rkp-defex.patch`); or (b) gitignore them and document the exact fetch/place step (fresh-clone `gradlew` then works; CI/release path unaffected if you document copying `kernelsu/ksud-dm3q-S9180ZHS8FZG1-kdp` → `app/src/main/jniLibs/arm64-v8a/libksud.so` and the Next equivalent). Option (a) matches how this repo ships ksud binaries; option (b) matches upstream DFRoot's no-binaries posture.
5. **`ko/dfroot-android13-5.15.ko`**: fresh public clones cannot build without running `make` (podman + DDK, network pull of `ghcr.io/ylarod/ddk-min`) or CI. Add a README section "Building" describing both, and note the `.incbin` requirement. Do not commit a mysterious `.ko` without its provenance (build image tag, KMI, date).
6. **Add the legal layer** (§5.L5): NOTICE/THIRD_PARTY_NOTICES (upstream baseline, loader binaries + their licence split, source offer, aggregation statement), CHANGELOG with the 8 diffs, GPL-2.0 §2(a) per-file notices, bump `versionCode`/`versionName`.
7. **Attribution & honesty in README**: keep upstream credits; add "DFRoot FZG1 (Samsung S9180 GZIF build)" section; state exactly what was tested (S9180 GZIF only; run6 classic + run8 Next evidence; stock kernels panic at `init_module` — do not ship stock loaders); mark everything else untested; **do not** claim support for any other build.
8. **Signing hygiene**: never ship the `SIGN_PASS := df-ksu` default in a public release; create your own keystore (do it outside the repo); `signing.properties` must never be tracked (it is gitignored — keep it so). CI (`build.yml`) already expects `KEYSTORE` secret — fine; keep the workflow but review whether to keep the `df-ksu` fallback for local `make` runs (change it to require explicit `SIGN_PASS`/`SIGN_ALIAS` env or fail otherwise).
9. **PII/secret scan on the final tree**: do NOT use a placeholder-matching grep (`grep -E '<SERIAL>|<SSID>|<LAN-IP>|<name-zh>|<account-id>|ims\.taiwanmobile|<mail>' .`) — it matches only the redaction placeholders used in this file, so an empty result proves nothing (and this document's own text demonstrates the false assurance). Use a real scanner instead — `gitleaks detect --source .` or `trufflehog filesystem .` — plus regexes that match actual device data you must exclude (e.g. `\b\d{15}\b` for IMEIs, the literal serial from `getprop ro.serialno`, email addresses, IPv4/IPv6 addresses), plus manual review of every committed hunk. Also scan for keystores/tokens: `grep -riE 'KEYSTORE_PASSWORD|BEGIN .*PRIVATE KEY|ghp_[0-9A-Za-z]{36}|AIza[0-9A-Za-z_-]{35}' .`
10. **Commit identity**: if you publish commits, either accept your GitHub identity in them or set `git config user.name/user.email` to a noreply address; check `git log --format='%an <%ae>'` before pushing. (`redzrush101@users.noreply.github.com` is fine; your choice.)
11. **BFG/filter check**: since the jniLibs and `lkm/dfroot.ko` would be the only "new large blobs", they are intentional — but if you ever pushed a private artifact by accident, remove it from history (`git filter-repo`), not just with a later commit.
12. **License-consistency check on the aggregate**: state explicitly in README that DFRoot source = GPL-2.0-only; bundled/executable components = their own licences (kernel GPL-2.0-only; userspace GPL-3.0-or-later); repo artifacts (this payloads repo) ship under Apache-2.0 except `susfs/*` (GPL-2.0-only, already marked) and the ksud binaries (their own licences). Do not let the Apache-2.0 top-level LICENSE be read as covering the kernel/userspace binaries.
13. **Feed policy**: do not add GZIF to `support/targets-v3.json` or any feed; §7 of the campaign doc says so and this review agrees — nothing in the hardware validation proves an *exploit* works for GZIF (and the port that does work is volatile-only and panics on stock modules). No pair exists; no artifact exists; nothing to publish.
14. **Evidence redaction pack** (if you want any on-device proof in README): use only `run6_logcat.txt:26590`, `:26980` (already PII-free) and `run8_logcat.txt:9739`, `:9881`, framed as quotes — never whole files. Both lines contain no SSID/emails/name data ✓.
15. **Build from clean clone** as the final gate: fresh clone → (document/create) jniLibs → `make` or CI → install → **smoke-test on a test device before tagging a release**; if any step requires your personal machine's paths, fix the docs until it doesn't.
16. **If in doubt**, make the fork private until steps 2–12 are done; a public fork that ships your private loaders with no provenance is worse than no fork.
17. **Docs ordering**: push the redacted docs first (serial removed), or at least in the same PR; do not push `SM-S9180-S9180ZHU8GZIF.md` with the serial and then "fix later" (it stays in history forever otherwise).
18. **Tell upstream** (`diabl0w/DFRoot`) about the GZIF port — as a courtesy and for PR #185+ hygiene; it also gives you a clean provenance narrative for the fork's existence.

---

## 8. Suggested corrections to the repo docs (NOT applied — read-only review)

`SM-S9180-S9180ZHU8GZIF.md`:
1. Rewrite the status header (`:3-5`): "Hardware-validated (run6 classic, run8 Next); volatile-only; not for other builds."
2. Rewrite §6.6 (`:141-176`) to the true story: run2 = classic `me.weishu.kernelsu`, died during `kernelsu.ko` `init_module()` (~200 ms after "SUCCESS", which is a false-positive marker), reboot was a kernel panic (KMSG_194), not soft-reboot; first real root was run6 (§6.7).
3. Fix §6.7 pids (`:218-226` → 20296), fix the SELinux claim (`:241`) per F4, keep `getenforce=Enforcing` only if a retained artifact shows it at that time (otherwise drop).
4. Fix `@ file offset` (`:192` → `0xb4ae4`; vaddr `0xb8ae4`).
5. Renumber duplicate §7; delete or repair "See §10" (`:83`); mark §5 stale items resolved; fix "(d) esp4 (kmod)" (`:61`); retarget stale "unit not attached" (`:107`); drop or tag UNVERIFIED the "530 KB/vendor_file label" (`:180-181`); reword the vermagic paragraph (`:182-184`) per F12.
6. Replace `<SERIAL>` (`:121`, `:143`, `:213`) with withheld-serial wording.
7. Keep §6.7/§6.8 evidence as the canonical success record; only §6.6 needs rewriting.

`GZIF-validation-summary-20261117.md`: serial (`:4`, `:51`); soft-reboot attribution (`:61`, `:85`); "Enforcing" (`:54`, `:55`, `:84`) per F4; fingerprint (`:12`) per F10; retarget "§6.6 first full chain" (`:68`) after F2 lands.

`docs/research/dirtyfrag-trigger-requirements.md:19` (esp4 verdict), `docs/research/selinux-preconditions.md:360` (stale "not attached"), `docs/research/vendor-sepolicy-extract.md` + `vendor-policy-neverallows.md` (relativize absolute paths), `docs/research/cve-2026-*` (fine as-is; they are careful).

`src/targets/dm3q-S9180ZHU8GZIF/target.h:29` — align `BUILD_FINGERPRINT` with the doc value chosen in F10.
`tools/dm3q_gzif_preflight.c` — fine as-is.

---

## 9. 12-line summary

1. Four to-be-committed repo docs carry the device serial `<SERIAL>` (SM-S9180-S9180ZHU8GZIF.md:121/143/213; dirtyfrag-trigger-requirements.md:443; GZIF-validation-summary-20261117.md:4/51) — remove before any push.
2. Host logs (run2–run8, dropbox_all, kmsg_195; ~61 MB) are full of unrecoverable PII — WiFi SSID `<SSID>`, LAN IP `<LAN-IP>`, personal mailboxes, IMS number-derived identity, the user's name (<name-zh>) in Samsung-cloud lines — never commit, never paste; the docs' "do not commit" line is good, enforce it.
3. §6.6 "FULL CHAIN SUCCESS" is false on the retained evidence: run2 used `me.weishu.kernelsu` (not KernelSU-Next), `kernelsu.ko` died in `init_module()` (KP, KMSG_194), `ksud start: SUCCESS` printed 11 ms before the load even began; the reboot was not "soft-reboot".
4. First real root was run6 (§6.7); §6.7's quoted pid (6104) is run4's, not run6's (20296).
5. §6.7/§6.8 "SELinux Enforcing" is contradicted by `next-failure-evidence.txt:3` (Permissive) and by `lkm/dfroot.c:103` (unconditional `selinux_state=false`); the "getenforce reads ksud's state" sentence is not a thing.
6. §6.5 dry-run (`GZIF001`) and the `su -c id` blocks have no retained artifacts — label them session-attested only.
7. libc++ symbol: vaddr `0xb8ae4`, file offset `0xb4ae4` (doc says 0xb8ae4-as-file-offset — wrong); hook `0xb4ae8` confirmed in logs.
8. Fingerprint contradiction: `target.h` says `…/qssi:17/…` (matches SYSTEM build.prop); both docs say `…/dm3q:17/…` — reconcile and cite.
9. Fork legal layer is missing: GPL-2.0-only base + Samsung-patched GPL-3.0-or-later ksud binaries bundled with no NOTICE/source-offer/licence split/change notices/versionCode bump; `git push` would target upstream (`origin = diabl0w/DFRoot`).
10. `lkm/dfroot.ko` (13.5 KB, byte-identical to the gitignored `ko/` twin) will be committed by accident; jniLibs (9.8 MB) are unmarked bundles — decide commit-with-NOTICE or gitignore+fetch.
11. Several docs are stale/self-contradictory (§3 esp4 verdict vs research doc line 19; "unit not attached" post-6.5; duplicate §7; missing §10; "esp4 (kmod)"; "530 KB"; vermagic rationale; top "Status: no port exists yet") — all fixable in one pass.
12. Safe to push **after** addressing §7's checklist (serial/PII scrub, docs made honest, legal layer added, remote retargeted, jniLibs decision, signing hygiene) — as it stands today, do **not** push either the fork or the four GZIF docs.
