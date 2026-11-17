# Galaxy S23 Ultra SM-S9180 / S9180ZHU8GZIF port campaign record

Status: **S3 — DFRoot port complete and hardware-validated (2026-11-17; classic Samsung-patched ksud 3.3.0 at 16:49, Next Samsung-patched ksud 3.4.2 at 17:53). Volatile (late-load) root only; no reboot persistence; no boot.img flash; no upstream feed registration.**
Date: 2026-11-17. Scope executed: firmware acquisition, binary patch-status triage, DFRoot port + build, two on-device root validations.
Volatile-only; the tooling and target headers are committed for traceability, not as a supported feed entry. Do not claim support for any other build.

## 1. Firmware identity (verified)

| Field | Value | Source |
| --- | --- | --- |
| Model | `SM-S9180` (`dm3q`, `dm3qzhx`) | build.prop |
| Four-part / PDA | `S9180ZHU8GZIF/S9180OZS8GZIF/S9180ZCU8GZIF/S9180ZHU8GZIF` | `samloader check-update` (Latest Stable, BRI); FUS |
| Region | BRI (Taiwan); OZS multi-CSC (TGY Hong Kong shares the PDA) | FUS listing; `meta-data/fota.zip` (`pub_SM-S9180_CHN_TGY_QKEY2.pem`) |
| Android / SDK / One UI | 17 / SDK 37 / One UI 9.0 (`ro.build.version.oneui=90000`, `sep=180000`) | `SYSTEM/build.prop` |
| Vendor | Android 13 (`TP1A.220624.014/S9180ZHU8GZIF`, SDK 33) | `VENDOR/build.prop` |
| Display build | `CP2A.260605.016.S9180ZHU8GZIF` (same build ID family as S9210ZHU6EZIF) | `ro.build.display.id` |
| `ro.build.changelist` | 34344539 | `SYSTEM/build.prop` |
| Security patch level | 2026-10-05 | `fota_info.txt` + build.prop |
| Build date / type | 2026-09-28 (kernel `#1 SMP PREEMPT Mon Sep 28 06:37:13 UTC 2026`) / user, release-keys | kernel banner + build.prop |
| Kernel release | **`5.15.197-android13-8-34343818-abS9180ZHU8GZIF`** (kernel.common changelist 34343818) | `strings kernel` |
| Kernel compiler | Android clang 14.0.7 (r450784e) | kernel banner |
| Kernel size | `0x2cb0a00` (46860800) — identical size to FZF5/FZG1 images | boot header |
| `boot.img` | 100663296 bytes, header v4; kernel at `0x1000` | boot header parse |
| boot.img SHA-256 | `6df858ed65dad6f2a087de34a0f28f8843ec50ac2a33368d7bf98e5d78304ffa` | computed |
| boot.img.lz4 SHA-256 | `c3590ac387bd178f17351a935d8d5fc42efc3c20d3ecd484e7d65330d023acad` | computed |
| kernel SHA-256 | `d8eb9556f58376eafcc962a1c68d914dde472f838519d6b533487007e987a69e` | computed |
| Work dir | `/mnt/240G_SSD/opencode_tmp/GZIF_work/` (zip 12 GB kept for provenance; AP tar NOT extracted — images streamed via `unzip -p … \| tar -xf -`) | local |

## 2. Acquisition log

1. `samloader 2.2.0 check-update --model SM-S9180 --region BRI --all --verbose` → Latest Stable = GZIF four-part above.
2. `samloader download … --out-file …/SM-S9180_BRI_GZIF.zip` → 12 GB; member list: `AP_…MULTI_CERT_meta_OS17.tar.md5` (13.9 GB), `BL_…`, `CP_…`, `CSC_OZS_…`, `HOME_CSC_OZS_…`.
3. AP member scan: all images are `.lz4` frames (`04 22 4d 18`); extracted `boot.img.lz4`, `vendor_boot.img.lz4`, `init_boot.img.lz4`, `meta-data/fota.zip` via streaming tar (no full AP extract).
4. LZ4 frame decompress (python `lz4.frame`) → images; kernel sliced at `0x1000` (size from boot header `kernel_size`).
5. `vmlinux-to-elf kernel vmlinux.elf` (base `0xffffffc008000000`) → `nm` → 126,451 symbols; BTF recovered: `vmlinux.btf` [0x21f39dc, 0x27c4953), 6,098,807 B; `vmlinux-btf.raw` / `.h` via `bpftool btf dump`.
6. `meta-data/fota.zip` → `SYSTEM/VENDOR/ramdisk build.prop`, `fota_info.txt`, `OTA/android-info.txt` (board=kalama), APEX layout. (`MAP/system.map` in fota.zip is an OTA file→line map, NOT a kernel symbol map.)

## 3. CVE route patch-status matrix (binary-verified 2026-11-17)

| CVE | Route | Verdict | Decisive evidence |
| --- | --- | --- | --- |
| CVE-2026-43499 | "GhostLock" rtmutex/futex-PI UAF (repo `dm3q-S9180ZHS8FZF5/FZG1` IonStack route) | **PATCHED** | Both fix hunks confirmed in binary: `remove_waiter()` at `0xffffffc0096f7474` loads `waiter->task` from `waiter+0x30` (BTF: `rt_mutex_waiter.task` bits_offset 384 = 0x30), early-returns on NULL (`cbz x20 → epilogue 0xffffffc0096f77d0`), locks `waiter_task->pi_lock` (BTF: `task_struct.pi_lock` bits_offset 17440 = 0x884; `add x22, x20, #0x884` + CASA), clears `pi_blocked_on` at `+0x8b0` (BTF bits_offset 17792 = 0x8b0) instead of `current->…` (sp_el0). Wrapper `rt_mutex_start_proxy_lock()` at `0xffffffc0096f9464`: only negative returns reach `remove_waiter()` (`tbz w21, #0x1f, …` sign-bit skip before `bl 0xffffffc0096f7474`) ≡ upstream fix `40a25d59e85b` (`if (ret < 0)`). Upstream fixes `3bfdc63936dd` + `40a25d59e85b` (Apr/May 2026); Samsung integrated them by GZIF. |
| CVE-2026-98260 | POSIX-CPU-timer exec-path UAF ("timer payload"; only pa3q-S938U1UEUDDZJB exists today) | **OPEN (bug present) — port unproven** | `begin_new_exec()` at `0xffffffc0084cabd4` decodes to exactly the unpatched 5.15.197 source ordering: `zap_other_threads/de_thread path → exchange_tids (0xffffffc008113004) → release_task (0xffffffc0080d89e8) → io_uring_cancel_generic → unshare_files (0xffffffc0080cf338) → set_mm_exe_file → would_dump → exec_mmap (0xffffffc0084cb840) → _raw_spin_lock_irq → posix_cpu_timers_exit (0xffffffc00820a52c) → _raw_spin_unlock_irq → exit_itimers → flush_itimer_signals → unshare_sighand`. Fix = move `posix_cpu_timers_exit()` before `unshare_files`/`exec_mmap`; it is NOT moved → vulnerable. Also confirmed: `fs/exec.c` identical between v5.15.197 and v5.15.212 (diff = 0) → no 5.15 stable fix exists; fix only reached 6.1.171/6.6.158 (2026-10-03) — 5.15 has no backported fix anywhere known. Caveats: never ported to dm3q; `k_itimer` layout unmeasured for 5.15; KASLR/tracefs-shell gate unverified on dm3q; pa3q-proven path is 6.6-only. |
| CVE-2026-43284 | "Dirty Frag" xfrm ESP page-cache write (no in-repo work) | **OPEN in code — route-gated** | `esp6_input()` at `0xffffffc00954c888` and **`esp_input()` (esp4) at `0xffffffc009489c20`** BOTH implement the unpatched fast path verbatim (`!skb_cloned` via `skb->cloned` byte 0x7e bit0 + `shinfo->dataref & 0xffff != 1`; `!skb_is_nonlinear` (`ldr w8,[x19,#0x74]; cbz`) → nfrags=1; `!skb_has_frag_list` (`ldr x9,[x8,#8]; cbz`) → nr_frags+1 (`ldrb w8,[x8,#2]; add w22,w8,#1`)); **no `skb_has_shared_frag()` test (`flags & BIT(1)`) anywhere** in either function before `skip_cow`. `skb_cow_data` is `0xffffffc00926b8a4`. Both are **built-in** (IKCONFIG: `CONFIG_INET_ESP=y`, `CONFIG_INET6_ESP=y`, `CONFIG_INET_ESPINTCP` not set, `CONFIG_AF_RXRPC` not set — see below). Embedded IKCONFIG also shows **`# CONFIG_USER_NS is not set`** — desktop PoC userns route is dead at kernel level; `CONFIG_NET_NS=y`, `CONFIG_XFRM_USER=y`, `CONFIG_IKCONFIG_PROC=y`. App-reachable candidate = IPv4/esp4 via Android's `android.net.ipsec.manager.IpSecManager` (netd installs the SA as root; apps need no permission for transport-mode transforms) — see `dirtyfrag-trigger-requirements.md`. esp6 is app-unreachable (no IPv6 encap socket without `NETWORK_SETTINGS`). |

## 4. Verdicts and recommendation

- **43499 route: dead on GZIF.** Both upstream fix hunks are binary-confirmed present. Do not port.
  (This also invalidates the one "probably still open" prior from public bulletin bookkeeping — the Samsung
  kernel itself was decisive.)
- **98260 route: bug present (binary-verified), but not port-ready.** No 5.15 port exists anywhere;
  layouts unmeasured; exploit primitive (`k_itimer` spray + freed-node reclaim) unverified on dm3q hardware;
  success path requires Samsung shell-domain tracefs.
- **43284 route: bug present (binary-verified on esp6), highest-value candidate.** It is the only one of the
  three with a public PoC shape and an upstream fix GZIF provably lacks. Remaining feasibility work before any
  port claim: (a) confirm end-to-end app-domain/shell trigger preconditions on dm3q (ESP via netlink XFRM from
  app/shell or via IpSecManager; udp_esp encapsulation; `SKBFL_SHARED_FRAG` spray via `vmsplice`/`sendfile`),
  (b) SELinux policy check for `untrusted_app`/shell (`netlink_xfrm`, `udp_socket`, `splice`/`vmsplice`),
  (c) kernel source drop cross-check (Samsung msm-kernel Kalama 5.15.197 tag) for any out-of-band backport of
  the 2-line input-path guard — binary already says none, source drop would corroborate,
  (d) decide between the built-in esp4 and esp6 paths (IKCONFIG: `CONFIG_INET_ESP=y`, `CONFIG_INET6_ESP=y`; there is no esp4 kmod — the IpSecManager route is esp4, the app-reachable IPv4 path).
  All four gates were cleared on 2026-11-17 (see §6.5–§6.8).

## 5. What this document establishes, and what it does not

- **P0 fingerprint discriminability (audited 2026-11-18, offline).** The committed GZIF table (`src/targets/dm3q-S9180ZHU8GZIF/p0_fingerprint.h`, 64 rows) was audited with `tools/p0_fingerprint_audit.py`. Result: the only weak pair is `0x1f0000` / `0x1f8000` — **7 of 8 qwords identical** (all-NOP tail), and only qword 0 differs. Under the `src/pipe.c` scoring rule (exact qword equality; a best/runner-up tie rejects the reading), a single corrupted/misread qword 0 turns a legitimate `0x1f8000` (or `0x1f0000`) hit into a tie (reading discarded — fail-closed) — or, if the misread qword 0 lands exactly on the sibling row's value, into a silently accepted **wrong** slide (fail-open; the one edge the tie rule cannot catch). The single-word-corruption simulation (qword→0x0) over the whole table reports 2 tie (reject) and 0 beaten (wrong-slide) cases, all confined to those two rows. The sibling tables `dm3q-S9180ZHS8FZG1` and `dm3q-S918BXXSAFZF5` report the same 7/8 pair and the same 2 tie / 512 statistic (audited 2026-11-18 with this tool); their docs predate this audit. No new/offline fix is possible without re-deriving from the exact Image: any replacement table must be generated with `tools/generate_p0_fingerprint.pl` from that Image, then re-audited (`python3 tools/p0_fingerprint_audit.py …`); a second independent signature window would also work but is equally Image-bound. Any future probe-offset choice must avoid pairing two rows that differ only in qword 0 of a NOP tail. **Do not treat the `0x1f8000` probe or this table as validated until the Image-derived re-audit is recorded here.**
- Firmware acquisition, binary patch-status triage and static derivation are established facts (§1–§6.1); the DFRoot port itself was built and hardware-validated on 2026-11-17 (§6.5–§6.8; see `docs/GZIF-validation-summary-20261117.md`).
- DirtyFrag "OPEN" verdicts are **static-binary facts about the bug's presence**, not exploit reliability claims. The 43284 route's exploit stage (block-wise CBC staging, RKP/KDP coexistence of the fake-cred path) is still unmeasured — the DFRoot chain below works through `dfroot.ko` + late-load, not through a novel ESP primitive, and it is verified end-to-end on hardware.
- `CONFIG_USER_NS` is unset (IKCONFIG, re-verified on-device in §6.5); the classic parent-PoC route is dead on this build. Effective SELinux rules for the IpSecManager IPv4 route were modeled (`docs/research/selinux-preconditions.md`, `docs/research/vendor-policy-neverallows.md`) and the route was dry-run-cleared on the unit (§6.5, IpSecManager C1–C5).

## 6. Static derivation deliverables (2026-11-17, S2)

| Artefact | Path | Status |
| --- | --- | --- |
| dm3q-S9180ZHU8GZIF target header | `src/targets/dm3q-S9180ZHU8GZIF/target.h` | VERIFIED-STATIC (values derived from this Image's nm/BTF/disasm; nothing validated on device). FZF5/FZG1-parity tuning marked as such. `ashmem_misc_fops` and `SLIDE_TRACEFS_VFORK_CALLER_OFF` deliberately left undefined (symbol absent / not derived) |
| P0 fingerprint table | `src/targets/dm3q-S9180ZHU8GZIF/p0_fingerprint.h` | GENERATED (64 rows, stride 0x8000, probe 0x1f8000; 512 qwords checked by generator) — discriminability audit recorded in §5: one 7/8 pair (`0x1f0000`/`0x1f8000`), not device-validated |
| Read-only precondition probe | `tools/dm3q_gzif_preflight.c` | COMPILED (NDK r28c, arm64, Android 35). Diagnostic only: uname (checked; release-string match is **not** binary attestation)/uid/SELinux context/enforce/userns sysctls/no-new-privs+caps/seccomp mode+filter count (full `/proc/self/status` read to EOF)/netlink_xfrm open+close/`/proc/config.gz` presence (never decompressed)/tracefs `sched_blocked_reason` id read-only report (`--strict` gates exit on id==108). Exit 0 = release string matches `5.15.197-android13-8-34343818-abS9180ZHU8GZIF`; `--strict` additionally requires id==108; exit 2 = unknown argument. No escalation. Use on the GZIF unit when attached |
| Symbol/BTF evidence | host-side `GZIF_work/` scratch (not committed; see `docs/research/vendor-sepolicy-extract.md` for the vendor-policy staging conventions) | host-side only, not committed |

Binary-verified facts recap (same session as §3): `remove_waiter` waiter->task shape; `rt_mutex_start_proxy_lock` `ret<0` gate; `begin_new_exec` call order (exec_mmap → posix_cpu_timers_exit); `esp6_input` fast path without `skb_has_shared_frag()` guard; ftrace table `__ftrace_events` 1160 entries, `event_sched_blocked_reason` index 88 → `SLIDE_TRACEFS_EVENT_ID = 108`; worker_thread blocking `schedule` at `0xffffffc00810ddf8` → `SLIDE_TRACEFS_WORKER_CALLER_OFF = 0x0010ddfc`; `nfnetlink_log` string at Image `0x01d609e9`; `nfulnl_logger` file offset `0x02a91e50`.

Source-drop status (opensource.samsung.com, `docs/research/source-drop-crosscheck.md`): no S9180 GZIF drop yet; sibling `SM-S918B_17_Opensource.zip` (S918BXXUAGZIF, same SPL, built 2026-09-28, 641 MB, same dm3q platform) EXISTS but is served only after an inline "Agree" click-through — needs a manual browser download to `GZIF_work/src-drop/` before source-level cross-check can be done.

SELinux precondition analysis (recovery-ramdisk full policy, `docs/research/selinux-preconditions.md`): **shell domain has ZERO netlink_xfrm_socket rules — the classic shell→userns→netlink-XFRM route for CVE-2026-43284 is SELinux-denied on this build.** untrusted_app*/sec_untrusted_app/priv_app/system_app: no xfrm rules either. Only `system_server`, `netd`, `network_stack`, `vendor_netmgrd`, `charon`, `dumpstate` (create-only) contexts can use XFRM. UDP create IS allowed for app domains. Policy is the full vendor policy (service information `SEPF_SM-S9180_13_0001`, dated 2026-09-28), MLS v30, 0 neverallow rules, default-deny. See `docs/research/dirtyfrag-trigger-requirements.md` for the on-device implication (shell cannot drive netlink XFRM; the app-facing route is IpSecManager/netd).

## 6.1 Final verdicts (corrected 2026-11-17)

**CVE-2026-43284 ("Dirty Frag"): NOT closed — but exactly one route is viable on paper.**
The vulnerable code is in BOTH built-in ESP input paths (esp4 `esp_input` @ `0xffffffc009489c20`,
esp6 `esp6_input` @ `0xffffffc00954c888`) — both binary-confirmed unguarded (no
`skb_has_shared_frag` test). The classic userns+netlink PoC route is dead (`CONFIG_USER_NS`
not set; desktop PoC cannot run on GZIF at all). The viable path is the **Android
`android.net.ipsec.manager.IpSecManager` transport-mode IPv4 route**: an untrusted app can,
without any permission, (1) open an ESP-in-UDP encapsulation socket (`UDP_ENCAP_ESPINUDP`),
(2) allocate an SPI, (3) build a transport-mode `IpSecTransform` with an IPv4-encapsulation
template; netd (root, SELinux-allowed) installs the IPv4 ESP-in-UDP transport SA; loopback
traffic then flows `xfrm4_udp_encap_rcv` → `xfrm_input` → `esp_input` → in-place decrypt over
splice'd page-cache-backed skb frags — the exploitable primitive.

SELinux verdict detail (compiled policy + vendor/plat CIL): app domains are `neverallow`-ed
direct `netlink_xfrm_socket` use, but the IpSecManager route never uses it from the app —
netd does all XFRM work as root. UDP-encap loopback has no policy-blocked stage. Details:
`docs/research/dirtyfrag-trigger-requirements.md` (requires on-device C1/C2 dry-run) and
`docs/research/vendor-policy-neverallows.md` (neverallow decode, esp4.ko does not exist as a
module — irrelevant, since `CONFIG_INET_ESP=y` is built-in).

Remaining gates for 43284: (a) **on-device dry-run** C1/C2 (SPI alloc + transport transform
build) — cleared on-device (§6.5 C1–C5) and applied; (b) esp4 block-write staging payload
(16-byte AES-CBC full-block writes, one block per splice — the kernel primitive is the
DFRoot-style block patch, not the desktop exploit's seq_hi/ESN trick); (c) full port
(weeks): GZIF-specific offsets, RKP/KDP coexistence, volatile-only KernelSU late-load
hand-off — done since (see §6.7/§6.8); (d) SA-validity + SELinux at runtime was dry-run-cleared
on the unit (§6.5; IpSecManager SA apply/remove OK from untrusted_app).

**CVE-2026-98260: the only complete-but-unported candidate.** Bug binary-confirmed present
(§3); no public 5.15 fix exists (`fs/exec.c` identical v5.15.197↔v5.15.212); never ported to
dm3q (pa3q/6.6-only in this project); k_itimer layout/spray unmeasured for 5.15. A full new
payload project (offsets→layout→spray→hardware validation).

**CVE-2026-43499: PATCHED** (§3). As of 2026-11-17 no *CVE-2026-43499* route exists; the DirtyFrag-class (CVE-2026-43284) DFRoot port is complete and hardware-validated (§6.7 classic, §6.8 Next).

## 6.5 Hardware verification log (2026-11-17, GZIF unit attached — serial intentionally withheld)

> Privacy-safe evidence manifest for the whole campaign: `docs/GZIF-evidence-manifest-20261117.md`.

Device identity: `uname -a` (from the attached unit) = `5.15.197-android13-8-34343818-abS9180ZHU8GZIF #1 SMP PREEMPT Mon Sep 28 06:37:13 UTC 2026`, SPL 2026-10-05, Android 17 / One UI 9.0, arm64, SELinux Enforcing at capture time, shell `u:r:shell:s0`. The firmware SYSTEM image carries `ro.system.build.fingerprint=samsung/dm3qzhx/qssi:17/CP2A.260605.016/S9180ZHU8GZIF:user/release-keys` (`fota/SYSTEM_build.prop`, verified). An earlier session transcript transcribed the fingerprint with a `…/dm3q:17/…` component; no retained artifact shows that string — the firmware-verified value is `qssi:17`, and the on-device `getprop ro.build.fingerprint` output was not re-checked against a retained capture. Treat the `dm3q:17` form as a transcription error.

- `build/dm3q_gzif_preflight` (read-only) pushed to `/data/local/tmp/` and run **(session transcript, not retained)**:
  `KERNEL MATCH`; `enforce=1`; `max_user_namespaces` → errno 13; `unprivileged_userns_clone` absent; `socket(AF_NETLINK, NETLINK_XFRM)` → **errno 13** (policy-denied, as decoded).
- `/proc/config.gz` pulled from device and **byte-identical** to the config extracted from the kernel Image (`cmp` clean) — full firmware→running-kernel attestation. (Host-side scratch; the comparison was performed in-session; the pulled file is not committed.)
- IpSecManager dry-run (`com.gzif.preflight`, minimal diagnostic APK, INTERNET permission only; tag GZIF001 in logcat; SA applied then immediately removed; process is not persistent). **Evidence status: session transcript, not retained in any stored artifact** (no capture containing `GZIF001` was kept) — the pass/fail values below are attested by the session but cannot be re-audited from the host:
  ```
  C0-GETSERVICE ipsec -> android.net.IpSecManager
  C1-SPI-OK spi=185348075           (untrusted_app CAN allocate an SPI)
  C2-ENCAP-OK port=49341 fd-valid=true   (UDP_ENCAP_ESPINUDP socket handed to the app)
  C3-TRANSFORM-OK IpSecTransform{resourceId=5}   (transport-mode IPv4 ESP transform built)
  C4-APPLY-OK                      (netd installed the SA; applied to a loopback UDP socket)
  C4-REMOVE-OK / C5-CLEANUP-OK     (SA removed; everything closed)
  RESULT: DRYRUN-COMPLETE
  ```
- Interpretation: every gate identified for the CVE-2026-43284 IpSecManager route is now cleared on the real GZIF unit — esp4 (`esp_input`) and esp6 unguarded (§3), config measured, SELinux modeled and consistent with policy, and the SA-installation primitive functions end-to-end from an untrusted app. The RKP/KDP/DEFEX behavior of the *exploit-stage* code path (fake creds, block-wise CBC staging, KernelSU late-load) is still unmeasured, and nothing about on-device stability or exploit success is yet proven.
- The installed diagnostic app (`com.gzif.preflight`, ~12 KB) remains on the device; uninstall with `adb uninstall com.gzif.preflight` if not wanted. It contains no exploit logic.

## 6.6 Hardware validation — 15:34 run, classic manager; device panicked at `kernelsu.ko` load (2026-11-17 15:34–15:35)

DFRoot (ported, built 15:0x) was run on the GZIF unit with the **classic `me.weishu.kernelsu` manager selected** (the Next manager was exercised at 15:49; see §6.8). Complete logcat capture retained at host-side `run2_logcat.txt`. The run reached every DFRoot stage but produced **no root**:

```
patch: crash_dump64 <- splicehelper (1408 bytes)           ✓ patched
Using KMI: android13-5.15
patch: /vendor/lib64/AIAwbModel_v2.2.tflite <- dfroot.ko (13504 bytes)  ✓ patched
Finding symbol offsets for /system/lib64/libc++.so:
BTI/PAC preamble at hook site, advancing +4
Found: hook=0xb4ae8 shellcode=0x10faa8 len=464
patch: libc++.so <- shellcode (464 bytes)                 ✓ patched
patch: libc++.so <- trampoline (16 bytes)                 ✓ patched
=== init ===
Triggering hook...
libc++: loading custom module                              ✓ hook fired (init, tid=1)
kernel module: launching bootstrap                         ✓ dfroot.ko loaded (via insmod → vendor_modprobe)
bootstrap: loading app preferences file                    ✓
bootstrap: cloning zygote env                              ✓
bootstrap: setting partitions ro                           ✓
bootstrap: starting SU daemon                              ✓
ksud start: SUCCESS                                        (printed ~11 ms BEFORE the module load began — see below)
=== cleanup ===                                            ✓ (libc++ restored)
```

What actually happened, per the retained capture (`run2_logcat.txt`, timestamps ~15:34:23):

- `ksud start: SUCCESS` is a **false-positive marker**: the `dfroot` payload prints it when the `ksud` CLI parent exits 0, before its forked late-load child has finished. The capture contains `ksud::late_load: Loading kernelsu.ko for KMI android13-5.15...` and **never** `kernelsu.ko loaded successfully!`. The marker printed ~11 ms before the module-load line was logged.
- The device **kernel-panicked during `kernelsu.ko` `init_module()`** (~0.1–0.2 s after the marker; `SYSTEM_LAST_KMSG_194_KP` era dropbox entries retained host-side; panic text absent — XBL-only dump). This was **not** the bootstrap soft-reboot path. `crash-analysis-run2.md` (host-side) has the full attribution. The 15:49 run (`run3`, `com.rifsxd.ksunext`) died the same way at the same stage; the 17:00 run (repo Next daemon, 3.4.1 "test" tier) failed *earlier*, pre-load, on a KMI asset-lookup miss (`android13-5.15.189_kernelsu.ko` vs runtime KMI `android13-5.15`) — no panic.
- The full chain therefore did **not** work on this attempt; the first actual root was **run6 (§6.7, 16:49)**. The Samsung-patched loaders bundled in the fork were the decisive ingredient — see §6.7.

Port adaptations made to the upstream source (diabl0w/DFRoot @ 7a6513a):
- `ko_target` changed from missing `/vendor/lib64/libbinderdebug.so` family to the present
  `vendor_file` `/vendor/lib64/AIAwbModel_v2.2.tflite` (never executed). File presence is proven
  by the successful splice patch (`run2_logcat.txt`, `run6_logcat.txt`); the file size (530 KB)
  and the `vendor_file` label claim are **unverified** — no `ls -Z`/stat evidence was retained.
- LKM bundled: `dfroot-android13-5.15.ko` built in `ghcr.io/ylarod/ddk-min:android13-5.15-20260828`
  (llvm-objcopy stripped, 13,504 B). `modinfo` reports vermagic `5.15.202-android13-5.15.202_r00-dirty`
  while the running GZIF kernel is `5.15.197-android13-8-…`. The module loaded and the full chain ran
  on the unit — tolerated there; why is unverified (mechanism not generalised — rebuild against the
  exact target's KMI for any other device/build).
- `compileSdk/targetSdk` 37→36 (this host SDK tops at 36); AGP 9.4.0→9.5.0 (cached artifact);
  only-android13-5.15 KMI baked in.
- `/vendor/bin/insmod` (→`toybox_vendor`) exists and is `vendor_toolbox_exec` → transitions into
  vendor_modprobe as designed; `/apex/com.android.runtime/bin/crash_dump64` = `crash_dump_exec` ✓;
  all required kallsyms present (`kallsyms_lookup_name`, `aarch64_insn_patch_text`,
  `task_defex_enforce`, `task_defex_user_exec`, `kern_path`, `invalidate_inode_pages2`,
  `path_put`, `avc_has_perm(noaudit)`, ...).
- `libc++.so` retains `_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_` at
  **vaddr `0xb8ae4`**, i.e. **file offset `0xb4ae4`** (RX segment vaddr→file delta `0x4000`);
  the hook lands at `0xb4ae8` (BTI/PAC preamble `+4`).

## 6.7 Hardware validation — FULL ROOT ACHIEVED (2026-11-17 16:49)

DFRoot GZIF (this fork, built from upstream Diabl0w DFRoot with two local patches) was run on the GZIF unit (serial intentionally withheld). Outcome: **root success, KernelSU loaded, modules staged**.

Evidence (logcat `run6_logcat.txt` lines ~16:49:50–16:49:51):

```
I/KernelSU( 20296): ksud::late_load: Loading kernelsu.ko for KMI android13-5.15...
I/KernelSU( 20296): ksud::late_load: kernelsu.ko loaded successfully!
I/KernelSU( 20296): ksud::late_load: [after load_module] pid=20296, uid=0, gid=0, selinux=u:r:ksu:s0 , Seccomp: 0
I/KernelSU( 20296): ksud::module: load policy: /data/adb/modules/zygisk_lsposed/sepolicy.rule
I/KernelSU( 20296): ksud::module: load policy: /data/adb/modules/zygisksu/sepolicy.rule
I/KernelSU( 20296): ksud::module: load policy: /data/adb/modules/tricky_store/sepolicy.rule
I/KernelSU( 20296): ksud::feature: Applied 6 features successfully
I/dfroot          : ksud start: SUCCESS
```

(Evidence: `run6_logcat.txt`, ~16:49:50–16:49:51; the quoted `pid=20296` in the `[after load_module]` line is the loader's own attestation. `I/dfroot` marker printed after the load completed — unlike the 15:34 run.)

On-device verification (uid=2000 shell via adb) — **session transcript, not retained as an artifact**:

```
$ su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
$ su -v
3.3.0:KernelSU
$ getenforce
Enforcing
$ cat /proc/uptime
157.69 463.61
```

`/dev/dfm6` present (success marker), `/dev/dfme2` absent (no late-load failure). SELinux state is **not settled by these captures**: the session transcript printed `getenforce = Enforcing` (~16:52 and again ~17:53), while a ~17:00 capture (`next-failure-evidence.txt:3`, retained host-side, i.e. after the 16:49 run) printed `Permissive`. Mechanism: `dfroot.ko` unconditionally writes `false` to the kernel global `selinux_state` at module init (`lkm/dfroot.c` ~line 103; no restore path exists). AVC behaviour from DFRoot onward consults that patched flag; selinuxfs may or may not reflect it depending on build. **Do not claim "SELinux stays Enforcing"** — verify per-build with `cat /sys/fs/selinux/enforce` plus AVC-denial checks before relying on either.

### Root cause of prior panics

Earlier runs panicked inside `init_module()` for the stock `kernelsu.ko` (android13-5.15 KMI from KernelSU-Next release APK, and from the tiann v3.3.0 classic build). The Samsung-patched rebuild (`ksud-dm3q-S9180ZHS8FZG1-kdp`, Samsung `KDP/RKP/DEFEX/NO_PATCH_TEXT` kretprobe strategy, `kprobe` IP-redirection, no `.text` writes) loads cleanly and is fully functional on this build.

### DFRoot GZIF fork patches

1. `ExploitRunner.java` — `stageAssets()` now prefers the bundled Samsung-patched loader (`app/src/main/jniLibs/arm64-v8a/libksud.so`, copied from repo artifact `kernelsu/ksud-dm3q-S9180ZHS8FZG1-kdp`) over the manager APK's `libksud.so`.
2. `bootstrap.c` — before invoking `.ksud-stage late-load`, it creates `/data/adb/` and copies `/data/user_de/0/df.root/ksud` → `/data/local/tmp/.ksud-stage`. This matches FZG1 loader's staging protocol (it renames `.ksud-stage` → `/data/adb/ksud` itself).

Both changes are additive; no exploit logic was altered.

### Volatility reminder

Root is **not persistent across reboot** (KernelSU late-load is runtime-only). To re-root after a reboot, open DFRoot GZIF and press LAUNCH ROOT again. "Start on Boot" / auto-soft-reboot behaviour on this build is untested — the 15:34 death (§6.6) was a kernel panic in the `init_module()` window, not the soft-reboot path, so the interaction of those settings with this build has not been measured. Do not enable them without direct testing.

## 6.8 KernelSU-Next variant — FULL ROOT ACHIEVED (2026-11-17 17:53)

Dual-mode DFRoot GZIF (bundled `ksud-next-generic-kdp` as `libksudnext.so`, selected when spinner = `com.rifsxd.ksunext`) completed the full chain on the same GZIF device without a panic:

```
I/KernelSU Next: ksud::late_load: kernelsu.ko loaded successfully!
I/dfroot         : ksud start: SUCCESS
```

On-device verification (uid=2000 shell) — **session transcript, not retained as an artifact**:

```
$ su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
$ su -v
3.4.2:KernelSU
$ getenforce
Enforcing
$ su -c 'ls /dev/dfm6'
/dev/dfm6
```

This is the same GZIF firmware (5.15.197-android13-8-34343818-abS9180ZHU8GZIF, SPL 2026-10-05, CP2A.260605.016, One UI 9.0), with the Samsung-patched no-patch-text/kretprobe KSU-Next loader. The earlier failure was the repo's per-firmware Next daemon embedding only `android13-5.15.189_kernelsu.ko` while the device reports KMI `android13-5.15`; the generic 3.4.2 Samsung-patched loader embeds `android13-5.15_kernelsu.ko` and succeeded.

Both root modes are now available in the same APK:

- `me.weishu.kernelsu` selected → bundled Samsung-patched classic loader (`ksud-dm3q-S9180ZHS8FZG1-kdp`, **3.3.0**, FZG1 device-validated).
- `com.rifsxd.ksunext` selected → bundled Samsung-patched Next loader (`ksud-next-generic-kdp`, **3.4.2**, verified on hardware 2026-11-17).

## 6.9 Provenance of key binary facts

- `vmlinux-to-elf` base `0xffffffc008000000`; `_text @ 0xffffffc008000000`, `esp6_input @ 0xffffffc00954c888`, `remove_waiter @ 0xffffffc0096f7474`, `__rt_mutex_start_proxy_lock @ 0xffffffc0096f93f0`, `rt_mutex_start_proxy_lock @ 0xffffffc0096f9464`, `begin_new_exec @ 0xffffffc0084cabd4`, `posix_cpu_timers_exit @ 0xffffffc00820a52c`, `exec_mmap @ 0xffffffc0084cb840`, `unshare_files @ 0xffffffc0080cf338`, `exit_itimers @ 0xffffffc008209974`, `flush_itimer_signals @ 0xffffffc0080f6ba8`, `skb_cow_data @ 0xffffffc00926b8a4`, `__pskb_copy_fclone @ 0xffffffc009269fa8`.
- BTF member offsets (raw): `rt_mutex_waiter.task` 0x30; `task_struct.pi_lock` 0x884; `task_struct.pi_blocked_on` 0x8b0; `sk_buff` head 0xD0 / end 0xCC / data_len 0x74 / cloned bit byte 0x7E bit0; `skb_shared_info.flags` 0x0 / `nr_frags` 0x2 / `frag_list` 0x8 / `dataref` 0x20; `SKBFL_SHARED_FRAG` = `BIT(1)`.
- Reference sources fetched (read-only): stable trees `v5.15.197` / `v5.15.205` / `v5.15.212` (`rtmutex.c`, `exec.c`, `esp6.c`, `skbuff.h`), upstream fix commits `3bfdc63936dd`, `40a25d59e85b`.
- `fs/exec.c` is byte-identical between v5.15.197 and v5.15.212 (no 5.15 stable fix for 98260 exists).
- `esp6.c` differing hunks between v5.15.197 and v5.15.205 include exactly the `skip_cow` input guard; the output-side espintcp hunk is unrelated.

## 7. Next steps (if the user wants to proceed)

1. 98260 stays parked unless 43284 fails.
2. Upstream engagement: notify `diabl0w/DFRoot` of the GZIF port (courtesy, and for provenance hygiene — see `docs/research/gzif-port-review-20261117.md`, whose top banner marks it HISTORICAL/SUPERSEDED as of 2026-11-18).
3. Artifact hygiene: rebuild `dfroot-android13-5.15.ko` against the exact GZIF target KMI before any wider release; consider rebuilding ksud with `RUSTFLAGS="--remap-path-prefix=$HOME=/build"` so shipped binaries carry no build-host paths.
4. Keep `support/targets-v3.json` untouched until a feed decision is made with hardware-proven artifacts and an explicit signed risk review — GZIF is intentionally absent today.
5. Hardening / measurement debt: exploit-stage RKP/KDP behaviour (fake creds, block CBC staging, late-load) remains unmeasured on this build; any public support claim requires repeat-run stability data from the GZIF unit.
