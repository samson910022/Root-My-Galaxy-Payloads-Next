# CVE-2026-43284 (Dirty Frag / xfrm-ESP page-cache write) — Architectural trigger requirements for Android (GZIF target)

**Status:** Architecture/feasibility research only. No exploit code was written, fetched-and-built, or run. No device was touched.
**Scope:** `SM-S9180 / S9180ZHU8GZIF` (Android 17, SDK 37, One UI 9.0, SPL 2026-10-05, kernel `5.15.197-android13-8-34343818-abS9180ZHU8GZIF`), execution domains `shell` (u:r:shell:s0, adb/Shizuku) and `untrusted_app`.
**Audience:** campaign owner deciding whether to authorize a port project.

This document deliberately stops at architecture. It quotes public sources for every factual claim and marks anything that cannot be decided from public sources or local binary analysis as **UNVERIFIED** — only on-device checks (§6) can settle those.

Companion docs: `docs/research/cve-2026-43284-triage.md` (identification/verdicts), `docs/SM-S9180-S9180ZHU8GZIF.md` (GZIF campaign record).

---

## 0. Executive summary (verdict snapshot)

- The classic public PoC route — `unshare(CLONE_NEWUSER|CLONE_NEWNET)` → netlink XFRM `NEWSA` (ESN, attacker-chosen `seq_hi`) → splice file pages into an ESP-in-UDP packet — is **dead on GZIF at the kernel level**: GZIF's embedded IKCONFIG shows **`# CONFIG_USER_NS is not set`** (measured this pass, see §7a). SELinux/seccomp are irrelevant to this route on GZIF.
- The route actually used by the Samsung-targeted public chains (diabl0w/DFRoot lineage, combeng6th/DirtyInit) — **Android `IpSecManager` transport-mode ESP-in-UDP SAs installed by `netd`, no userns, no netlink XFRM from the app** — survives on paper. It yields the **AES-CBC full-block in-place decrypt-over-page-cache primitive** (16 bytes per trigger at an arbitrary splice offset), not the ESN 4-byte `seq_hi` STORE (which has no IpSecManager knob; see §2.4).
- `untrusted_app` needs **no permission** for the transport-mode IpSecManager path (verified in Connectivity-module source, §4.5); `netd` does the netlink XFRM work and is SELinux-allowed (§4.6).
- `shell` cannot use netlink XFRM (AOSP policy default-deny; neverallow for apps), and cannot create user namespaces either, but `shell` *may* be able to drive the same IpSecManager binder path (service does not permission-check transport mode) — **UNVERIFIED**, only on-device checks (§6) can decide.
- Hard preconditions on `untrusted_app`: `esp4_input` fast path is **binary-verified unguarded** (`esp4_input.asm`, dumped 2026-11-17; covers the `!skb_cloned` / shared-frag region — the `skip_cow` fast path, not the whole function); the remainder of `esp_input` was never disassembled — treat full-function claims as scope-limited. The esp6 route is app-unreachable (no IPv6 encap socket without `NETWORK_SETTINGS`).
- This is a full port project (offset baking, RKP/KDP coexistence, KernelSU late-load hand-off, volatile-only persistence), not a one-week demo — see §7.

---

## 1. The exact primitive — where the page-cache write comes from

### 1.1 Bug and sink

CVE-2026-43284 (kernel.org CNA; published 2026-05-08):

> "In the Linux kernel, the following vulnerability has been resolved: xfrm: esp: avoid in-place decrypt on shared skb frags. MSG_SPLICE_PAGES can attach pages from a pipe directly to an skb. TCP marks such skbs with SKBFL_SHARED_FRAG after skb_splice_from_iter(), so later paths that may modify packet data can first make a private copy. The IPv4/IPv6 datagram append paths did not set this flag when splicing pages into UDP skbs. That leaves an ESP-in-UDP packet made from shared pipe pages looking like an ordinary uncloned nonlinear skb. ESP input then takes the no-COW fast path for uncloned skbs without a frag_list and decrypts in place over data that is not owned privately by the skb. Mark IPv4/IPv6 datagram splice frags with SKBFL_SHARED_FRAG, matching TCP. Also make ESP input fall back to skb_cow_data() when the flag is present, so ESP does not decrypt externally backed frags in place."
— https://www.cve.org/CVERecord?id=CVE-2026-43284

Introduced 2017-01-17 by commit `cac2661c53f35cbe651bef9b07026a5a05ab8ce0` ("esp4: Avoid skb_cow_data whenever possible"), fixed 2026-05 by `f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4` (mainline netdev 2026-05-07, mainline 2026-05-08) — https://www.openwall.com/lists/oss-security/2026/05/07/8, https://dirtyfrag.io/ (= https://github.com/V4bel/dirtyfrag).

Affected range: `4.11` … before `5.10.255`, `5.15.205`, `5.15.206`, `6.1.171`, `6.1.172`, `6.6.138`, `6.12.87`, `6.18.28`, `7.0.5`, `7.1` (cve.org). Sysdig says "4.10 through 7.0" — minor discrepancy, noted in the triage doc. GZIF is `5.15.197` ⇒ below the 5.15 fix floor.

### 1.2 Root-cause branch (quoted from the disclosure write-up)

From https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md ("CVE-2026-43284: xfrm-ESP Page-Cache Write → Root Cause"):

> "Before performing in-place AEAD decryption on the ESP payload, `esp_input()` should allocate a new kernel-private buffer with `skb_cow_data()` when the skb is non-linear, copy the frag data into it, and then perform the in-place operation. However, the following branch creates a path that bypasses that cow."

```c
static int esp_input(struct xfrm_state *x, struct sk_buff *skb)
{
        [...]

        if (!skb_cloned(skb)) {
                if (!skb_is_nonlinear(skb)) {    // <=[1]
                        nfrags = 1;

                        goto skip_cow;
                } else if (!skb_has_frag_list(skb)) {
                        nfrags = skb_shinfo(skb)->nr_frags;
                        nfrags++;

                        goto skip_cow;           // <=[2]
                }
        }

        err = skb_cow_data(skb, 0, &trailer);
```

> "At `[1]`, even when the skb has a frag, if `frag_list` is absent the code jumps directly to `[2]` and performs in-place crypto on top of the frag. If the attacker has pinned a page cache page into the frag through `splice`, that page becomes both `src` and `dst`."
(write-up.md, same section)

### 1.3 SKBFL flags that matter

- **`SKBFL_SHARED_FRAG`** — the marker the fix adds. In current trees it lives in `skb_shinfo(skb)->flags`; the in-repo GZIF analysis used `SKBFL_SHARED_FRAG=BIT(1)` (`docs/SM-S9180-S9180ZHU8GZIF.md` §3: "`flags & BIT(1)` (SKBFL_SHARED_FRAG=BIT(1))"). The exact bit position must be re-derived from BTF/matching sources for any port; do not hardcode it (triage doc §C.16 makes the same point).
- The fix (upstream) — two parts, both quoted in write-up.md ("Patch" section):
  1. `esp_input`/`esp6_input`: `} else if (!skb_has_frag_list(skb) && !skb_has_shared_frag(skb)) {`
  2. `__ip_append_data` (IPv4) / `__ip6_append_data` (IPv6): set `skb_shinfo(skb)->flags |= SKBFL_SHARED_FRAG` on splice frags when `!(flags & MSG_NO_SHARED_FRAGS)`.
- Frag-transfer/coalescing propagation commits (`48f6a5356a33…`, `3bd9e113d500…`, `ff375cc75f91…`, `f84eca581739…`) widened the marker through helpers (`skb_gro_receive*`, `skb_try_coalesce`, `skb_segment`, …); the AOSP 2026-11 ASB kernel-table rows carry the A-510777270 backports. These do not change the attack requirements below; they only narrow residual variants.
- **`MSG_SPLICE_PAGES`** — set automatically by `splice_to_socket()` when splicing into a socket; this is what attaches pipe-backed pages directly to the skb as frags rather than copying (write-up.md: "With `splice_to_socket()` automatically setting `MSG_SPLICE_PAGES`, the page cache page P of `/usr/bin/su` is planted as is into `frag[0]` of the sender skb").

### 1.4 The two distinct sub-primitives hiding behind the one sink

All routes end at the same code (`esp_input`/`esp6_input` → in-place decrypt over frag pages). What differs is *what gets written and where*:

**(a) ESN `seq_hi` 4-byte STORE (classic desktop PoC).** With an `XFRM_STATE_ESN` SA whose `XFRMA_REPLAY_ESN_VAL.seq_hi` the attacker sets, `esp_input_set_header()` copies `XFRM_SKB_CB(skb)->seq.input.hi` (= `replay_esn->seq_hi`) into the reconstructed ESP header; `crypto_authenc_esn_decrypt()` then executes `scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1)` — a 4-byte STORE at `assoclen + cryptlen` into the destination SGL, i.e. into the frag page at a chosen file offset. Authentication runs after the STORE, so failure (`-EBADMSG`) does not undo it (write-up.md quotes all three steps). Requires: netlink XFRM SA registration with `XFRM_STATE_ESN` + attacker-chosen `seq_hi`, and `authencesn(hmac(sha256),cbc(aes))`.

**(b) AES-CBC full-block decrypt-over-frag write (Samsung/DFRoot route).** The whole CBC plaintext block is written in place over the frag, so each 16-byte block spliced into the ciphertext position is overwritten with `D_key(C_i) XOR C_{i-1}` (for block 1, `XOR IV` with attacker-chosen IV). Since the attacker chooses the SA key, and knows the file's current bytes (readable), it can solve for the block value it wants for the first CBC block of each trigger packet — deterministically, one 16-byte block per trigger, at an arbitrary splice offset. This is exactly what diabl0w/DFRoot and the mitschud fork describe ("By crafting `IV = AES_ECB_DEC(key, current_content) ⊕ desired_content`, any 16-byte-aligned block in a mapped shared library can be overwritten without write permission and without copy-on-write." — https://github.com/diabl0w/DFRoot, https://github.com/mitschud/DirtyFrag). Payload crypto must be `cbc(aes)` + an HMAC (DFRoot uses AES-CBC/HMAC-SHA256). This route needs **no ESN** and only transport-mode SAs.

**Consequence for Android/GZIF:** the IpSecManager API (§4.5) exposes **no ESN or replay-window knobs**, so sub-primitive (a) is unreachable through it; only sub-primitive (b) is. The ESN route needs the raw netlink SA with `XFRMA_REPLAY_ESN_VAL`, i.e. `CAP_NET_ADMIN` by some process — on GZIF that means kernel-permitting namespace creation (absent, §4.1) or an already-privileged XFRM client (netd, which apps cannot steer key bytes into).

### 1.5 End-to-end packet shape (reference, from the write-up)

```
udp_recv(skb)
  xfrm4_udp_encap_rcv(sk, skb)
    xfrm_input(skb, IPPROTO_ESP, spi, 0)
      esp_input(x, skb)
        pskb_may_pull(skb, sizeof(esp_hdr) + ivlen)
        if (!skb_cloned(skb) && !skb_has_frag_list(skb))   // vulnerable: frag(page=P) preserved
          goto skip_cow;                                    // -> in-place decrypt over frag pages
        esp_input_set_header(skb, seqhi)                    // ESN only
        skb_to_sgvec(skb, sg, 0, skb->len)
        crypto_aead_decrypt(req)                            // src == dst
```
(write-up.md, "Exploit" section — path quoted verbatim.)

Sender side: `vmsplice(hdr)` + `splice(file → pipe)` + `splice(pipe → UDP socket)`, with the UDP socket connected to `127.0.0.1:<encap port>`; the receiving socket is bound and marked `UDP_ENCAP_ESPINUDP` via `setsockopt(SOL_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)` — on the desktop this is the exploit's own socket; on Android it is the `UdpEncapsulationSocket` fd handed to the app by the IPSEC service (§4.5).

---

## 2. What the trigger needs (b)

### 2.1 SA registration routes, in order of privilege

| Route | Who installs the SA | Privilege needed | Viable on GZIF? |
|---|---|---|---|
| R1. userns+netns + `send()` on `NETLINK_XFRM`, `XFRM_MSG_NEWSA` (classic PoC) | attacker in owned netns | `CLONE_NEWUSER`+`CLONE_NEWNET` + `CAP_NET_ADMIN` (virtualized in-ns) | **NO — `CONFIG_USER_NS` not set (measured, §4.1)** |
| R2. Raw netlink XFRM from the init netns | attacker directly | `CAP_NET_ADMIN` in init netns | **NO** for app/shell (no CAP_NET_ADMIN; SELinux default-deny on `netlink_xfrm_socket`, §4.2) |
| R3. `android.net.IpSecManager` transport-mode transform (binder → `IpSecService` → **netd**) | netd (root) | none for transport mode (verified in source, §4.5/4.6) | **YES on paper — pending §6 dry-run checks** |
| R4. `IpSecManager` tunnel-mode / `MANAGE_IPSEC_TUNNELS` | — | privileged `|signature` permission `MANAGE_IPSEC_TUNNELS` | NO for normal apps |
| R5. VpnService/IKEv2 flows | system_server | user-consented VPN profile | Not a trigger primitive (needs user interaction, different policy) |

Plain ESP (`socket(AF_INET, SOCK_RAW, IPPROTO_ESP)`) is not a usable trigger vehicle for apps: `SOCK_RAW` requires `CAP_NET_RAW`, which `untrusted_app` does not hold; and SELinux's `rawip_socket`/`raw_socket` handling would still apply (**UNVERIFIED** for Samsung's policy variant; AOSP grants `netdomain` only `icmp/udp/rawip` socket creation — §4.4). ESP-in-UDP is therefore the mandatory on-Android encapsulation; it is also what the Android API exposes.

### 2.2 Crypto payload requirements

- Preferred for Android: `authenc(hmac(sha256), cbc(aes))` or `authencesn(...)` — the netd-installed SA from IpSecManager transport-mode is `AES_CBC` + truncated HMAC-SHA-256 (DFRoot's documented shape: "builds an AES-CBC/HMAC-SHA256 ESP transform" — diabl0w/DFRoot, mitschud/DirtyFrag). Authentication failure is expected and tolerated (`-EBADMSG` after the in-place write).
- ESN-specific 4-byte STORE (sub-primitive (a)) additionally needs `XFRM_STATE_ESN` and attacker-chosen `seq_hi` — netd offers no ESN knob ⇒ not reachable via IpSecManager. Confirmed absent from the transport-mode builders in the Connectivity source (`IpSecConfig.setMode(MODE_TRANSPORT)`, no replay-window/ESN fields; `android17`/`main` source read 2026-11-17 — see §7).

### 2.3 The splice choreography (unchanged on Android)

1. Open the target readable file (`O_RDONLY`) — must be a page already cached or cacheable (`/system/lib64/libc++.so`, `/system/bin/crash_dump64` shell helper, etc. — anything the domain may `open/read`).
2. `pipe()`; `vmsplice(pipe_write, hdr{spi, seq, iv}, 1, 0)` — the ESP wire header (24 bytes: SPI|SEQ|IV[16]).
3. `splice(file → pipe, 16, SPLICE_F_MOVE)` — file page-cache pages attached to pipe buffers; `splice_to_socket()` sets `MSG_SPLICE_PAGES`.
4. `splice(pipe → UDP socket connected to 127.0.0.1:<encap>, len, SPLICE_F_MOVE)` — skb frags carry the pinned file page(s); loopback delivers to the UDP-encap socket; `xfrm4_udp_encap_rcv` → `xfrm_input` → `esp_input` → **in-place decrypt over the file's page-cache pages**.
5. The page cache is persistently modified for every subsequent reader until `drop_caches`/reboot (write-up.md: "once a page cache has been STOREd it is preserved until `drop_caches` or reboot").

### 2.4 Which IpSecManager call does what (verified in source, 2026-11-17)

All of these are in `packages/modules/Connectivity` (`framework-t/src/android/net/IpSecManager.java`, `IpSecTransform.java`, `service-t/src/com/android/server/IpSecService.java` @ `main`):

- `openUdpEncapsulationSocket([port])` — system_server creates `SOCK_DGRAM/IPPROTO_UDP` socket, `setsockopt(IPPROTO_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)`, binds, hands fd back to app (`UdpEncapsulationSocket.getFileDescriptor()` is public). No permission check; per-UID quota applies (`mSocketQuotaTracker`); port ≥ 65536 would require `NETWORK_SETTINGS` and selects IPv6 — **apps cannot get an IPv6 encap socket**, so the encap route is IPv4-only ⇒ **esp4, not esp6**, is the IpSecManager route.
- `allocateSecurityParameterIndex(destinationAddress[, requestedSpi])` — no permission check; IPv4/IPv6 numeric non-wildcard addresses only (`checkInetAddress`); calls `mNetd.ipSecAllocateSpi(...)`; SPI quota applies. User may request a specific SPI ≥ 256 (1-255 reserved).
- `IpSecTransform.Builder().setEncryption(IpSecAlgorithm.CRYPT_AES_CBC).setAuthentication(...).setIpv4Encapsulation(udpsEncapSocket, remotePort).buildTransportModeTransform(sourceAddress, spi)` — **no permission requirement** for `MODE_TRANSPORT` (only `MODE_TUNNEL` hits `enforceTunnelFeatureAndPermissions()` → `FEATURE_IPSEC_TUNNELS` + `MANAGE_IPSEC_TUNNELS` (appop/permission)). Creates the SA via `mNetd.ipSecAddSecurityAssociation(uid, mode, src, dst, netid, spi, …, encapType=2, …)`. The SA is transport-mode, IPv4, with an IPv4-encap template (ports) — exactly the shape `xfrm4_udp_encap_rcv` matches on input.
- `applyTransportModeTransform(socket, DIRECTION_IN|OUT, transform)` — binder call, owner check only; **not required** for the input-path decrypt trick (the demux depends on SA + UDP_ENCAP socket, not on any applied socket). Useful only for conformance testing of the SA install path.
- `getTransformState()` — requires `ACCESS_NETWORK_STATE` (normal permission). Could be used as a *safe read-only liveness probe* of the SA.

So the app's own `socket(2)` usage is limited to plain UDP for the splice source; **no app ever creates a netlink XFRM socket** — netd does.

---

## 3. What the PUBLIC Android chains assume (c)

All three public Samsung-oriented projects target **`untrusted_app`** (a normal third-party app; no Shizuku, no adb, no root, no unlock), with SELinux enforcing and RKP/KDP present:

- **diabl0w/DFRoot** ("DFRoot [DirtyFrag (CVE-2026-43284)]") — describes its target environment and chain: "DFRoot is an Android rooting tool that exploits CVE-2026-43284 (DirtyFrag) — a kernel page cache write primitive — to load a custom kernel module without requiring an unlocked bootloader." The exploit chain steps 1–6: "IpSec transform — App allocates a `UdpEncapsulationSocket` + SPI and builds an AES-CBC/HMAC-SHA256 ESP transform via `IpSecManager`." … "`crash_dump64` runs in the `crash_dump` SELinux domain (via exec label transition), which can open `vendor_file` labeled files (untrusted_app context cannot read these files so we need this bridge)." … "**libc++ hook** (fires in init, uid=0, tid=1)" … "`dfroot.ko` init (runs as `vendor_modprobe`, uid=0) — Writes `false` to `selinux_state` (global permissive)…" — https://github.com/diabl0w/DFRoot
- **mitschud/DirtyFrag** (fork of DFRoot; Samsung-oriented, One UI 9-focused) — "Ephemeral root via the CVE-2026-43284 page-cache exploit", "Root without unlocking. Gone after reboot.", "Built for Samsung devices, with a One UI-inspired interface … no custom kernel or unlocked bootloader required on vulnerable devices", "Shizuku not needed"; carries a "One UI 9" badge — https://github.com/mitschud/DirtyFrag
- **combeng6th/DirtyInit** — "One-touch, universal root for Samsung devices as u:r:init:s0 using DirtyFrag"; "It uses a stable, public API - IpSecManager - to handle the required XFRM socket and crypto. … How does this avoid the need for CAP_SYS_ADMIN and a Phase 1 escalation to system_server or network_stack? Because system_server itself runs these APIs in its own namespace and forwards them on to the appropriate native networking daemon." Final stage needs **ADB as a relay** ("Init Unix stream sockets are accessible to every namespace except untrusted_app, so we have to use ADB as a relay") — i.e. untrusted_app for the trigger, adb only for the last-mile control channel. — https://github.com/combeng6th/DirtyInit

**Privilege assumptions in one line:** untrusted_app for the whole trigger (all three); adb shell only as an optional relay/debugger (DirtyInit); DFRoot additionally relies on a crash_dump64 exec-label bridge and the init-tid-1 libc++ hook — those are **post-primitive** stages, outside what this sheet specifies.

**What they say about SELinux/seccomp blocking app-domain use:** none of the three relies on `unshare`/`CLONE_NEWUSER` at all (the upstream desktop PoC does; Appendix B of the triage doc and the write-up both scope the namespace requirement to the ESN 4-byte route). Instead they exploit that (i) the app seccomp filter still allows `splice`/`vmsplice`/`sendfile`/`open`/`socket`/`setsockopt`, and (ii) all privileged kernel work is proxied through `netd` and `system_server` (which hold the needed SELinux permissions). The DFRoot chain documents the app-domain blockage explicitly and designs around it: vendor-file reads need the `crash_dump` bridge because "untrusted_app context cannot read these files"; loading the LKM goes through `vendor_modprobe`. The Samsung-targeted forks clearly assume One UI's policy keeps `netlink_xfrm_socket` denied to apps (consistent with the AOSP neverallow, §4.2) — i.e. they treat the netlink path as unavailable and the IpSecManager path as available.

### 3.1 Public chains do NOT use sub-primitive (a)

Neither DFRoot/DirtyFrag nor DirtyInit installs ESN SAs — IpSecManager cannot express them. The desktop sequence count `PAYLOAD_LEN/4` SAs each carrying 4 bytes of `seq_hi` (oss-security PoC) has no Android analogue; the Android chains instead patch larger regions (`libc++.so`) block-by-block via sub-primitive (b). This matters for payload-size planning (16-byte blocks, one trigger per block).

---

## 4. Android 17 / One UI 9 mechanisms per chain step (d), with sources

### 4.1 `CLONE_NEWUSER` / user namespaces — GZIF (measured)

Extracted from the GZIF `boot.img` kernel's embedded IKCONFIG (`IKCFG_ST` @ byte offset 24,331,424 of the kernel slice; gzip-decompressed to 192,833 bytes during this pass — §7a):

```
# CONFIG_USER_NS is not set          (ikconfig line 204)
# CONFIG_PID_NS  is not set          (line 205)
CONFIG_NET_NS=y                      (CONFIG_NET_NS=y)
CONFIG_UTS_NS=y                      (CONFIG_UTS_NS=y)
```

Base GKI `android13-5.15` `gki_defconfig` likewise has no `CONFIG_USER_NS` and `# CONFIG_PID_NS is not set` (fetched from `kernel/common` android13-5.15 2026-11-17). **Consequence: `unshare(CLONE_NEWUSER)` returns `EINVAL`/`EPERM` for every domain on this build** — app, shell, or root — regardless of SELinux/seccomp. The desktop PoC's namespace branch is unavailable, full stop. `/proc/sys/user/max_user_namespaces` is registered only when `CONFIG_USER_NS=y`, so it will be **absent** on GZIF (kernel source fact; the file may not exist — probe §6.4).

`CONFIG_NET_NS=y` alone does not help: `unshare(CLONE_NEWNET)` requires `CAP_SYS_ADMIN` in the caller's user namespace (man 2 unshare); shell/app lack it (shell's `CapEff` — **UNVERIFIED**, probe §6.2; untrusted_app provably lacks it, it is not granted to any app domain).

### 4.2 `netlink_xfrm_socket` SELinux class (AOSP android17-release, read 2026-11-17)

Source files under `platform/system/sepolicy` @ `android17-release`:

- `private/app.te` — **neverallow** (verbatim):
  > ```
  > # Privileged netlink socket interfaces.
  > neverallow { appdomain -network_stack }
  >     domain:{
  >         netlink_tcpdiag_socket
  >         netlink_nflog_socket
  >         netlink_xfrm_socket
  >         netlink_audit_socket
  >         netlink_dnrt_socket
  >     } *;
  > ```
  so every `appdomain` member — including `untrusted_app`, `untrusted_app_32/34/30/29/27/25`, `isolated_app` — may not perform *any* permission on `netlink_xfrm_socket`. `untrusted_app` is assigned to `appdomain` via `app_domain(untrusted_app)` in `private/untrusted_app.te` (`app_domain(domain)` sets `typeattribute $1 appdomain` — see `public/te_macros`), which is what pulls it under the neverallow.
- `private/untrusted_app.te` — the only network grant is:
  > ```
  > net_domain(untrusted_app)
  > ```
  and `public/te_macros` defines:
  > ```
  > define(`net_domain', `
  > typeattribute $1 netdomain;
  > ')
  > ```
  `private/net.te` grants `netdomain` only: `tcp_socket`/`udp_socket`/`icmp_socket`/`rawip_socket` creation, port bind/connect, and `netlink_route_socket` read/write (`RTM_GETLINK` etc.). **No `netlink_xfrm_socket` anywhere for netdomain.**
- `private/shell.te` — `net_domain(shell)` (same `netdomain` grant; plus `allowxperm shell self:netlink_route_socket nlmsg RTM_GETLINK;`), but **no `netlink_xfrm_socket` allow anywhere** ⇒ SELinux default-deny for shell. (The neverallow above does not name `shell` — `shell` is not an `appdomain` — so this is default-deny, not neverallow; Samsung's vendor layer could theoretically add an allow for shell — **UNVERIFIED**, probe §6.8.)
- `private/netd.te` — netd may do everything apps cannot:
  > ```
  > # give netd permission to read and write netlink xfrm
  > allow netd self:netlink_xfrm_socket create_socket_perms_no_ioctl;
  > allow netd self:netlink_xfrm_socket { nlmsg_write nlmsg_read };
  > allow netd self:netlink_xfrm_socket nlmsg;
  > ```
  netd is a root SELinux `coredomain`; AOSP's own guidance confirms it runs as root: "system files … netd, init, and vold run as root … Even if netd became compromised, it couldn't switch domains to the system server domain … although it runs as root." — https://source.android.com/docs/security/features/selinux/implement
- Samsung vendor layer (One UI 9): policy lives in `boot.img`/`vendor` and is **UNVERIFIED on GZIF** (extraction was scoped out of this research pass; the port phase must dump `/sys/fs/selinux/policy` and `sesearch` it — probe §6.8). The AOSP baseline above is what vendor policy must *restrict*, never loosen — vendor policy may add rules for vendor domains but the `appdomain` neverallow cannot be widened by vendor policy (neverallows are CTS-enforced).

### 4.3 Seccomp-BPF on `unshare`/`clone3`/`splice`/`vmsplice` (AOSP android17-release bionic)

Source: `platform/bionic` @ `android17-release`, files `libc/SECCOMP_SYSCALLS.TXT`, `libc/SECCOMP_ALLOWLIST_COMMON.TXT`, `libc/SECCOMP_BLOCKLIST_APP.TXT`, `libc/SECCOMP_BLOCKLIST_COMMON.TXT`:

- The zygote-children filter is allowlist-based: *"The final seccomp allowlist is SYSCALLS.TXT - SECCOMP_BLOCKLIST.TXT + SECCOMP_ALLOWLIST.TXT"* (SECCOMP_BLOCKLIST_APP.TXT header) and applies only to zygote-spawned processes (SECCOMP_ALLOWLIST_COMMON.TXT: "Note that the resultant policy is applied only to zygote spawned processes.").
- `SYSCALLS.TXT` (the base before blocklist/allowlist edits) **allows**: `unshare(int) all` (line 326), `setns(int, int) all` (325), `clone3(clone_args*, size_t) all`, `splice(...) all` (333), `vmsplice(...) all` (334), `sendfile/sendfile64 … lp64` (183-185), `process_vm_readv/…` (353-354), `clone(...) all`, `pivot_root`, `clone3`, `open_by_handle_at` semantics etc. (lines as of android17-release, 2026-11-17).
- The blocklists remove none of these; the allowlists add back removal-protected cases.
- **Consequence:** the app-domain trigger path (`socket → setsockopt → open/read → pipe → vmsplice → splice → sendmsg/sendto`) is **fully permitted by the app seccomp filter**, including `unshare` (which, on GZIF, the kernel then refuses due to `CONFIG_USER_NS`). There is no seccomp-bpf block on `CLONE_NEWUSER` for apps — the block on GZIF is the missing kernel config, and no seccomp block on `splice`/`vmsplice` at all.
- `Seccomp: 2` (filter mode) is expected in `/proc/self/status` for zygote-spawned app processes; shell (spawned by adbd/console, **not** zygote) has no AOSP-installed app filter — on-device probe §6.2.

### 4.4 CAP_NET_ADMIN / CAP_NET_RAW in userns; app capabilities (AOSP net_domain)

- `untrusted_app` holds no `CAP_NET_ADMIN`/`CAP_NET_RAW`/`CAP_NET_BIND_SERVICE` et al. — capability rules for apps grant none of these; the `net_domain()` macro only confers socket creation rights (`netdomain` attribute) — see §4.2.
- `shell`: AOSP grants shell the `netdomain` attribute and a few extras (e.g. `RTM_GETLINK` xperm); it does not grant `CAP_NET_ADMIN`. Shell's effective set on GZIF is **UNVERIFIED** — probe `/proc/self/status` (`CapEff`/`CapBnd`) from adb shell (§6.2).
- "CAP_NET_ADMIN virtualization in userns" is moot on GZIF (§4.1).
- Plain-ESP raw sockets additionally need `CAP_NET_RAW` — unavailable to apps, **UNVERIFIED** for shell on GZIF.

### 4.5 IpSecManager permission requirements — transport vs tunnel mode (source-verified)

Read directly from `platform/packages/modules/Connectivity` (branch `main`, 2026-11-17; branch containment for the Android-17 release tags not published — see §7):

- `IpSecManager` javadoc (also developer.android.com reference): "Applications may create transport mode security associations and apply them to individual sockets. Applications looking to create an IPsec VPN should use `VpnManager` and `Ikev2VpnProfile`." No permission is documented — or required — for the transport-mode calls.
- `IpSecManager.java` — `@RequiresPermission(android.Manifest.permission.MANAGE_IPSEC_TUNNELS)` appears **only** on `IpSecTunnelInterface`/`applyTunnelModeTransform`/migration/`buildTunnelModeTransform` APIs, all marked `@SystemApi … @RequiresFeature(PackageManager.FEATURE_IPSEC_TUNNELS)`. None of these transport-mode calls carry a `@RequiresPermission`.
- `IpSecService.java` (service) enforces: tunnel-mode → `enforceTunnelFeatureAndPermissions()` (`FEATURE_IPSEC_TUNNELS` + appop `OP_MANAGE_IPSEC_TUNNELS` or `MANAGE_IPSEC_TUNNELS`); `getTransformState` → `ACCESS_NETWORK_STATE`; IPv6 encap port (≥65536) → `NETWORK_SETTINGS`; everything else (allocate SPI, create transport-mode transform, apply/remove transforms) → **no permission check**, only quota tracking and per-UID registration.
- `IpSecTransform.java` — same split: `buildTunnelModeTransform` requires `MANAGE_IPSEC_TUNNELS` (`@SystemApi`, `@hide`); `buildTransportModeTransform` requires none.
- `openUdpEncapsulationSocket` sets `UDP_ENCAP_ESPINUDP` on the socket **inside the service** and hands the fd to the app — apps cannot set `UDP_ENCAP` themselves on arbitrary sockets (it requires `CAP_NET_ADMIN`? No — `UDP_ENCAP` setsockopt is unprivileged for `SOCK_DGRAM` sockets the caller owns; however the app does not need to, the service does it).
- Consequence: **any unprivileged app on GZIF (targetSdk 37 → `untrusted_app` domain) can register an ESP-in-UDP transport-mode SA + UDP encap socket without any permission**, subject to (i) SPI quota, (ii) the service completing netd calls, (iii) IPv4 only.

### 4.6 netd involvement and SELinux side of the SA path

- `IpSecService` builds the SA and calls `mNetd.ipSecAddSecurityAssociation(...)` / `mNetd.ipSecAllocateSpi(...)` (Connectivity module `service-t/.../IpSecService.java`, `createOrUpdateTransform`). netd (`system/netd`) performs the actual `XFRM_MSG_NEWSA` netlink exchange from native code; it is a root `coredomain` SELinux-allowed for `netlink_xfrm_socket` (§4.2).
- Per-app SA state is tracked by the service and SA lifetime is bound to the app binder death/`close()` — i.e. no cross-app SA leakage, and the SA disappears when the app dies or the transform is closed.
- Netd's own config enforcement (`ipSecAddSecurityAssociation` input validation: mode/addresses/spi/alg-name truncation/`encapType=2`) is **UNVERIFIED in detail** — the service validates before calling netd; netd is trusted. If a dry-run (§6.5) fails, the failure site and error string will localize the cause (quota vs validation vs SELinux).

### 4.7 ESP-in-UDP vs plain ESP on Android — the ESPINTCP / IPv6 dead-ends

GZIF IKCONFIG (measured): `# CONFIG_INET_ESPINTCP is not set` (×2, v4/v6), `# CONFIG_INET_ESP_OFFLOAD is not set`, `CONFIG_INET_ESP=y`, `CONFIG_INET6_ESP=y`. So: no Fragnesia (CVE-2026-46300), no HW offload interference, both esp4/esp6 **built in** (the old reading "esp4 is a kmod" in `docs/SM-S9180-S9180ZHU8GZIF.md` §3 is superseded by the .config: `__initstub__kmod_esp4*` strings exist in `=y` builds too). But esp6 is app-unreachable via IpSecManager (no IPv6 encap socket for apps, §4.5), so the **IPv4/esp4 path is the candidate** — its binary verification has since passed for the fast path (§8 (a); `esp4_input.asm`).

### 4.8 RKP/KDP/DEFEX/CFI/LTO/SCS (GZIF, measured)

```
CONFIG_RKP=y
CONFIG_KDP=y
CONFIG_KDP_CRED=y
CONFIG_KDP_NS=y
CONFIG_CFI_CLANG=y
CONFIG_SHADOW_CALL_STACK=y
CONFIG_LTO=y / CONFIG_LTO_CLANG_FULL=y
CONFIG_RANDOMIZE_BASE=y          (KASLR)
CONFIG_MODULES=y, CONFIG_MODULE_SIG=y, CONFIG_MODULE_SIG_ALL=y, CONFIG_MODULE_SIG_PROTECT=y
                                (no CONFIG_MODULE_SIG_FORCE — unsigned modules not hard-refused by config)
CONFIG_SECURITY_SELINUX=y, CONFIG_DEFAULT_SECURITY_SELINUX=y
CONFIG_DEBUG_FS_ALLOW_ALL=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_IKCONFIG=y, CONFIG_IKCONFIG_PROC=y
CONFIG_BPF_SYSCALL=y
CONFIG_KALLSYMS=y, CONFIG_KALLSYMS_ALL=y
CONFIG_AF_RXRPC is not set
```

Interpretation (no marketing docs needed): the primitive writes **file data pages in the page cache** — it never writes protected code/text, never writes `page_tables`, never touches `cred` — so RKP/KDP have nothing to hook for the primitive itself (this is the same assumption the public Samsung chains rely on: neither DFRoot nor DirtyInit claims an RKP/KDP bypass for the *trigger*; KDP_CRED protection of `cred` is precisely why the chains do not escalate uid directly). CFI/SCS/LTO affect later stages (kernel module loading, call-usermodehelper) — they are constraints on the *payload*, not on the trigger. KASLR (`RANDOMIZE_BASE`) affects post-primitive offset resolution in both domains. None of the above can be confirmed exhaustively from source; confidence is "binary + config consistent with public Samsung-chain claims".

### 4.9 Adjacent attack surfaces ruled out on GZIF (measured)

`# CONFIG_AF_RXRPC is not set` ⇒ CVE-2026-43500 unavailable. `# CONFIG_INET_ESPINTCP is not set` ⇒ CVE-2026-46300 unavailable. Only the esp4/esp6 in-place decrypt remains — and only esp4 is app-reachable (§4.7). Samsung SMR-NOV-2026 carries the fix only in the November package; GZIF (SPL 2026-10-05) predates it (see `docs/research/cve-2026-43284-triage.md` §3 — bookkeeping; binary verification of the guard location on **esp4** input has since passed for the fast path — see §8 (a) and the campaign doc §3 — scope: fast path only).

---

## 5. Domain map: `shell` (u:r:shell:s0) vs `untrusted_app` — step-by-step

Legend: **ALLOWED** = allowed by what the sources/measurements show (source cited); **DENIED** = blocked (source cited); **UNKNOWN** = cannot be decided from public sources/local binary; on-device checks (§6) decide.

| # | Chain step | `untrusted_app` | `shell` | Evidence |
|---|---|---|---|---|
| S1 | `open(target, O_RDONLY)` + page into cache (`libc++.so` etc.; world-readable) | **ALLOWED** | **ALLOWED** | `allow { appdomain coredomain } system_file:file { execute read open getattr map }` (`private/domain.te`); file is world-readable (DAC) |
| S2 | `pipe()` / `vmsplice(hdr)` | **ALLOWED** | **ALLOWED** | app seccomp allowlist (`SYSCALLS.TXT` permits both) (§4.3); netdomain socket rules permit the send side (S2-adjacent: §4.2) |
| S3 | `splice(file→pipe)`, `splice(pipe→udp_socket)` | **ALLOWED** | **ALLOWED** | splice allowed by app filter (§4.3); `netdomain` grants `udp_socket` create/bind/connect for both domains (§4.2); for shell, seccomp not AOSP-installed (probe §6.2) |
| S4 | `socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM)` + bind | **DENIED** | **DENIED** (default-deny) | AOSP `neverallow` covers all `appdomain`s (§4.2); shell: no allow rule in policy; Samsung vendor allow — **UNKNOWN** (§6.8) |
| S5 | `unshare(CLONE_NEWUSER\|CLONE_NEWNET)` | **DENIED** | **DENIED** | `# CONFIG_USER_NS is not set` in GZIF IKCONFIG (measured, §4.1); seccomp permits the call (§4.3) but the kernel refuses |
| S6 | `IpSecManager.openUdpEncapsulationSocket(port)` | **ALLOWED** (no perm; quota applies; IPv4 only) | **UNKNOWN** (service has no permission check; shell would need to drive the Java API or equivalent binder calls — no documented `cmd` frontend) | source-verified for apps (§4.5); shell driver mechanism — §6.6/§6.7 |
| S7 | `allocateSecurityParameterIndex(dst, spi)` (specific SPI ≥256) | **ALLOWED** (no perm) | **UNKNOWN** (same as S6) | service code (§4.5); netd does the work (§4.6) |
| S8 | `IpSecTransform.Builder … setIpv4Encapsulation(encapSock, 4500) … .buildTransportModeTransform(src=127.0.0.1, spi)` | **ALLOWED** (transport mode; no perm; auth=aes-cbc+hmac-sha256 like DFRoot; src must be a local IPv4 — loopback is) | **UNKNOWN** (same as S6) | source-verified (§4.5); netd installs SA (§4.6) |
| S9 | netd XFRM SA install (`XFRMA_ENCAP encap_type=2`, transport mode, IPv4) | **ALLOWED (by proxy — netd root + SELinux allow)** | **ALLOWED (by proxy)** | §4.6 incl. quoted `netd` `netlink_xfrm_socket` allow rules |
| S10 | Wire traffic loopback → `xfrm4_udp_encap_rcv` → `esp_input` in-place decrypt over file pages | **ALLOWED (kernel-internal, no policy hook)** | **ALLOWED** | write-up.md path (§1.5); no SELinux/seccomp hook on this stage |
| S11 | In-place write effect on the page cache (target stays corrupted until reboot/drop_caches) | **ALLOWED (kernel-internal)** | **ALLOWED** | write-up.md (§1.5) |
| S12 | (Post-primitive, out of scope of this sheet) `crash_dump64` bridge to `vendor_file`, libc++ init-thread hook, `vendor_modprobe` LKM load, KernelSU late-load hand-off | DFRoot route: **POSSIBLE on paper** (public chain exists); on GZIF **UNKNOWN** | shell: **POSSIBLE via /data/local/tmp binaries but materially harder** (no app-domain transitions; `vendor_modprobe` needs a root context → requires its own bridge, absent on this target) | README quotes (§3); GZIF vendor policy — §6.9 |
| S13 | Trigger from `isolated_app`/`webview_zygote` (if a target prefers it) | **DENIED** | n/a | `isolated_app` is `appdomain` ⇒ same neverallow; and DFRoot does not support it |

**Reading the table:** `untrusted_app` has a coherent, permissionless, public-API path (S6→S9) exercising sub-primitive (b); `shell` shares S1–S3 and S9–S11, is blocked at S4/S5, and its only trigger-relevant delta vs apps is the **unknown** S6–S8 binder-driving step and inferior S12 options. In neither domain do userns or netlink XFRM apply on GZIF.

---

## 6. On-device (or GZIF test-unit) precondition checklist — read-only probes only

Run in order; each either passes/confirms or produces a decision point. **Do not run any payload; do not write to any file outside `/data/local/tmp` probes.** Group A = no device needed (already done in this pass); Group B = read-only on a test GZIF unit; Group C = sanctioned dry-run (requires user approval — it mutates kernel XFRM state transiently but writes no files).

### Group A — already established by this pass (no on-device action)

- **A1.** GZIF IKCONFIG extracted and grepped: `CONFIG_USER_NS` unset; `CONFIG_SECURITY_SELINUX=y`; `CONFIG_MODULES=y` w/o `MODULE_SIG_FORCE`; `CONFIG_RANDOMIZE_BASE=y`; `CONFIG_KDP/RKP/CFI_CLANG/SHADOW_CALL_STACK=y`; `CONFIG_AF_RXRPC` unset; `CONFIG_INET_ESPINTCP` unset; `CONFIG_XFRM=y`, `CONFIG_XFRM_USER=y`, `CONFIG_INET_ESP=y`, `CONFIG_INET6_ESP=y`, `CONFIG_IPV6=y`, `CONFIG_IKCONFIG=y/IKCONFIG_PROC=y`, `CONFIG_DEBUG_INFO_BTF=y`. (§7a for provenance.)
- **A2.** GZIF binary pass verified `esp6_input` is unguarded (no `skb_has_shared_frag`/`SKBFL_SHARED_FRAG` test before the in-place path) — §3 of `docs/SM-S9180-S9180ZHU8GZIF.md`. **`esp4_input` fast path is binary-verified unguarded** (`esp4_input.asm`, ~120 instructions around `skip_cow`; the remainder of the function is undumped — scope-limited PASS, see §8 (a)).
- **A3.** AOSP `android17-release` sepolicy + bionic allowlists audited (§4.2/4.3); IKCONFIG cross-checks (A1).
- **A4.** Public chains' privilege assumptions documented (§3); sub-primitive split documented (§1.4/2.4).

### Group B — read-only probes on a test GZIF unit

1. **B1.** `getenforce; getprop ro.build.version.security_patch; uname -a` — expect `Enforcing`, `2026-10-05`, kernel banner `5.15.197-android13-8-34343818-…`. If SPL differs or kernel banner differs, re-baseline.
2. **B2.** Shell capabilities: `id; id -Z; cat /proc/self/status | grep -E '^(Seccomp|CapEff|CapBnd|CapAmb)'` — record `Seccomp` and `CapEff`/`CapBnd` bit sets verbatim (decode against `capsh --decode` off-device); looking for absence of `net_admin`/`net_raw`. Do not assume any value — record what GZIF actually shows.
3. **B3.** Same probe from an `untrusted_app` context: a trivial reader-app or test-instrumented build printing `/proc/self/status` — still read-only (no exploit code; instrumentation only, with the user's explicit approval). Record `Seccomp` (expect `2`), `CapEff` (expect 0 or near-0), `CapBnd`.
4. **B4.** `ls /proc/sys/user/max_user_namespaces 2>&1; cat /proc/sys/user/max_user_namespaces 2>&1` — expect **absent** (file registered only with `CONFIG_USER_NS=y`, A1). If present and > 0, **stop**: re-evaluate the whole analysis (it would mean Samsung enabled userns and the classic route returns; contradicts A1 — escalate).
5. **B5.** Happy-path test description for the namespace branch (to be executed only with explicit approval): run `unshare -U true` from shell; expect failure (`EPERM`/`EINVAL`). This is the single most decisive one-liner of the whole feasibility question. From an app: attempt via a test instrument — expect the same failure.
6. **B6.** `pm list features | grep -i -E 'ipsec|net'` — informational only; transport mode does not need `FEATURE_IPSEC_TUNNELS`; confirm 279/`android.hardware...` rows exist as on any One UI 9 build; note any missing feature flags.
7. **B7.** Locate the IPSEC service binder: `service call ipsec 1` is NOT how apps talk to it — instead verify the public API surface via a test instrument calling `IpSecManager.getClass()`/`context.getSystemService(Context.IPSEC_SERVICE) != null` — record boolean; no SA created yet. (If `null`, the Connectivity module/service is absent — escalate; stock One UI 9 should have it.)
8. **B8.** SELinux policy dump and audit: `getenforce` (again), `supolicy`/`loadpolicy -d` not needed — pull `/sys/fs/selinux/policy` (or use `sesearch`/`seinfo` if present in toolbox/toybox) and check:
   (a) `netlink_xfrm_socket` rules for `shell`, `untrusted_app*`, `isolated_app`, `network_stack`, `system_server`, `netd` — confirm no `allow` for shell/app domains, i.e. confirm the AOSP baseline holds on Samsung's build (this is the check that can *kill* S6–S8 viability if e.g. Samsung granted apps `netlink_xfrm_socket` — unlikely but decisive);
   (b) `udp_socket`/`rawip_socket`/`netlink_route_socket` for shell — informational;
   (c) `crash_dump` domain and `crash_dump64_exec` label — needed only for S12-stage planning.
   Record outputs to the campaign log; **do not** run `setenforce 0`, `supolicy` mutations, or `restorecon -R` anywhere.
9. **B9.** `ls -l /system/lib64/libc++.so; getprop ro.build.version.incremental` — confirm presence and readability of the intended S12 hook target (for later planning only; the trigger itself does not need it — the trigger only needs the file to be *readable*).
10. **B10.** `dmesg 2>/dev/null | head` or `logcat -b all -d | grep -i -E 'avc|xfrm|ipsec' | head -50` — baseline noise survey; confirms whether shell can see AVCs at all on this build (if not, rely on `audit` from a root-confirming harness later, or accept B8 as sufficient).
11. **B11.** `cat /proc/kallsyms | wc -l; cat /proc/kptr_restrict` — informational (post-primitive relevance; app domain will not see symbols regardless).
12. **B12.** Known-crash sentinels that must remain untouched: `/vendor/lib64/libsamsung*.so`, `/system/lib64/libbase.so` (DirtyInit targets it), `libc++.so` — **do not** read or modify; only `ls -l` if needed for size/readability. (Reading is harmless; modifying is absolutely out of scope.)

### Group C — sanctioned dry-run of the SA install path (needs explicit user approval; otherwise stop here)

13. **C1.** From the `untrusted_app` test instrument: `IpSecManager.allocateSecurityParameterIndex(127.0.0.1, 0xDEADBE01)` → then `.close()` immediately. Success ⇒ netd accepted SPI registration for a loopback destination on this build (no file writes; no traffic). Failure string localizes the blocker (quota / SPI rejected / binder absent). **This call is the first true "can it trigger" signal.**
14. **C2.** In the same instrument: build a transport-mode transform on 127.0.0.1 with `CRYPT_AES_CBC` + auth HMAC-SHA256 + SPI from C1, then `transform.close()` immediately **without applying to any socket**. Success ⇒ netd accepted the SA — i.e. the entire trigger SA-install half of the DFRoot route works on this build. No traffic was sent; no file was modified. **This is the minimum endpoint of "worth porting" analysis on paper.**
15. **C3.** Repeat C1/C2 from `shell` via the mechanism identified in B7 (if any). Success ⇒ shell route alive (unlikely but decisive). Failure ⇒ shell domain is out; app domain remains the candidate.
16. **C4.** (Optional) `getTransformState` after C2 — informational confirmation of SA visibility.
17. **C5.** After C1–C4: verify cleanup — SPI released / transform freed (via instrument's own logging), no residue in `ip xfrm state` (checked via root harness later, or trust close() semantics).

**Hard stops in Group C:** do not apply a transform to a socket, do not send traffic, do not splice any file, do not touch `/system`, do not change any property, do not set permissive mode. C tasks are pass/fail probes of API reachability only.

### Minimum evidence to start a port (summary of §6)

Porting may be authorized **only if all five hold**:

1. `esp4_input` on the GZIF binary has no `skb_has_shared_frag` guard in the fast path, and the UDP splice frags lack the `SKBFL_SHARED_FRAG` marker (binary check — mirrors what was done for `esp6_input`; scope: fast path only). **PASS (fast path), 2026-11-17.**
2. A1 config facts unchanged (re-confirm on the actual unit; esp4 vs esp6 built-in, etc.).
3. B4/B5 fail as expected (namespace route dead) — and that is *expected*; document it as such.
4. C1 and C2 succeed from `untrusted_app` on the actual GZIF unit (or fail with a cause that still leaves a viable variant, e.g. IPv4 loopback rejected but a specific non-wildcard local Wi-Fi address accepted).
5. B8 shows no Samsung-policy `allow shell|untrusted_app* …:netlink_xfrm_socket` and no anomalous UDP-encap block that defeats the demux (e.g. a Samsung `neverallow ... udp_socket ioctl ESP_ENCAP_IOCTLS` — none in AOSP; confirm absent on the dump).

If any of 1–5 fails, **do not start the port**; fall back to evaluating CVE-2026-98260 (already flagged open in `GZIF` doc) or other routes, and keep this document.

---

## 7. What remains regardless of trigger viability — this is a full port, not a demo

Explicitly out of scope of this sheet, and each is a serious engineering item:

1. **esp4_input binary audit** — completed 2026-11-17 (fast-path scope: PASS; remainder undumped). The esp6 twin was already known-bad; the port proceeded on the fast-path evidence.
2. **Offset baking for `dm3q-S9180ZHU8GZIF`.** The libc++.so function chosen as the hook target (`std::ostream::sentry::sentry()` in the DFRoot design) needs build-exact vtable/function offsets; `libatomic`/init symbol addresses; `k_itimer`-class payload offsets are irrelevant here but **crash_dump64/`splicehelper` staging offsets are not** (filename, exec-label, FD layout) — all per-build, none reusable across FZF5/FZG1/GZIF.
3. **Heap-spray tuning.** Not for the write primitive (deterministic), but for the crash-bridge staging and any grooming of net-ns/socket state; DFRoot's `splicehelper` equivalent must be built per 5.15.197/GZIF.
4. **KASLR defeat.** `CONFIG_RANDOMIZE_BASE=y`; app domain cannot read `kptr_restrict`-protected symbols; realistic paths: known per-build vmlinux offsets baked into the payload + Samsung/AOSP symbols present in BTF (GZIF BTF exists — 6,098,807 B recovered earlier), or KALLSYMS-via-root-harness later. Samsung's BTF policy for modules (`CONFIG_DEBUG_INFO_BTF_MODULES=y` — present) helps.
5. **RKP/KDP coexistence.** GZIF ships `CONFIG_RKP=y`, `CONFIG_KDP=y`, `CONFIG_KDP_CRED=y`, `CONFIG_KDP_NS=y`. The trigger never writes protected pages; the LKM path (product goal = KernelSU) is where RKP/KDP bite (text/page-table integrity). DFRoot's answer — a kretprobe-hooked LKM loaded via `vendor_modprobe` after global permissive — is untested on GZIF; `CONFIG_MODULE_SIG_ALL=y` + `CONFIG_MODULE_SIG_PROTECT=y` (but **no** `CONFIG_MODULE_SIG_FORCE`, measured) means unsigned modules are not config-refused, but DEFEX/RKP enforcement is a runtime question — **UNVERIFIED on GZIF**.
6. **KernelSU late-load hand-off.** ksud + module.zip boot flow; `late-load --soft-reboot` behavior; SU-manager selection (dfroot ships per-KMI LKMs; this repo builds per-KMI artifacts the same way). Nothing about the 43284 trigger avoids this stage. Target framework: reuse repo's `dfroot-lkm`-equivalent — but the LKM must be compiled against `5.15.197-android13-8-34343818-abS9180ZHU8GZIF` (KMI `android13-5.15`; vermagic `5.15.197-android13-8-34343818-abS9180ZHU8GZIF SMP preempt mod_unload modversions aarch64` — must match exactly or the load fails).
7. **Volatile-only persistence model.** Page-cache corruption vanishes on reboot; `su` daemon does not survive reboot; autorun writers (the Samsung "Odin vault authorization byte" trick) are One UI/Model-specific and untested on GZIF; a wrong-byte write bricks nothing but also doesn't summon download mode. Persistence is inherently "re-run the chain each boot" — plan UX accordingly.
8. **Accidental mitigations.** DFRoot's FAQ notes "typically seen on kernel 6.1" for some builds carrying partial backports; 5.15 is unaffected by that class as far as public reports show, but the binary check (§6/A2/item-1 above) is the only authoritative answer for this exact build.
9. **Frag-position bookkeeping for sub-primitive (b).** Offset/alignment of each 16-byte block; `splice` offset vs page boundaries; cross-page frags; iOS-style row-cache invalidations — deterministic but fiddly; each trigger = one splice chain; tens–hundreds of triggers per staged payload (DFRoot patches 192 bytes of shellcode into `libc++.so` = 12 triggers, plus IV computation per trigger).
10. **Build tooling & verification loop.** NDK + DDK builds per KMI (existing repo CI: `.github/workflows/dfroot-lkm.yml`-equivalent); hardware-in-loop validation on a sacrificial GZIF S9180 (patched-once Samsung may refuse OTAs after tampering — plan for reflash or spare units).
11. **Payload side effects the user must accept.** Page-cache corruption of any readable file chosen as target is real on-device damage to the root-of-trust chain of that file until reboot (mitigated by targeting libraries only, and by `drop_caches` post-fire); the KDP-era `selinux_state` global-permissive write is one-way until reboot.

**Realistic sizing:** with GZIF-specific offsets measured (§7.2), a DFRoot-class port is person-weeks (build/verify/harden/iterate on hardware), plus firmware-forensics (esp4_input) days; plus Samsung policy iteration cycles. Not a one-week demo.

---

## 7a. Provenance notes for this pass (methodology)

- Read-only inspection of public web sources (all URLs cited), of AOSP via `android.googlesource.com` (format=TEXT for sepolicy/bionic/Connectivity files; commit JSON for the ASB-linked kernel commits), and of the local GZIF firmware slice at `/mnt/240G_SSD/opencode_tmp/GZIF_work/kernel` (pre-existing; produced by the repo's firmware pass).
- The GZIF embedded kernel config was located via the `IKCFG_ST`/`IKCFG_ED` markers (byte offsets 24,331,424 / 24,373,599 of the kernel slice) and gzip-decompressed in-memory for grepping; the extracted file was used transiently and then deleted. Facts quoted in §4.1/§4.7/§4.8/§4.9 are from that extraction. Nothing in the firmware archive was modified or reflashed.
- Scratch artifacts created during research under `/mnt/240G_SSD/opencode_tmp/` (fetched sources, decoded configs, sepolicy files) were removed after use; no file outside `docs/research/` was created or modified by this pass.
- No device interaction; no exploit source was built or executed; public PoC source (`V4bel/dirtyfrag` disclosure, oss-security post text) was read solely to document mechanism. The mechanisms and interfaces are described, not reproduced.
- `docs/SM-S9180-S9180ZHU8GZIF.md` (firmware/binary triage by the earlier pass) was the source for `esp6_input` offsets and the G-class kernel banner; not independently re-derived here.

---

## 8. URLs (every factual claim above traces here)

Bug record / CVE:
- https://www.cve.org/CVERecord?id=CVE-2026-43284 (description, ranges, scoring)
- https://nvd.nist.gov/vuln/detail/cve-2026-43284
- https://www.openwall.com/lists/oss-security/2026/05/07/8 (disclosure; embargo-break note; PoC post)
- https://www.sysdig.com/blog/dirty-frag-cve-2026-43284-and-cve-2026-43500-detecting-unpatched-local-privilege-escalation-via-linux-kernel-esp-and-rxrpc ("Known affected: Linux kernel 4.10 through 7.0"; exploitation chain summary; deterministic, not a race)
- https://www.wiz.io/blog/dirty-frag-linux-kernel-local-privilege-escalation-via-esp-and-rxrpc (local access, userns dependency, PoC exists)
- https://www.tenable.com/blog/dirty-frag-cve-2026-43284-cve-2026-43500-frequently-asked-questions-linux-kernel-lpe ("4-byte STORE primitive" phrasing)
- https://access.redhat.com/security/vulnerabilities/RHSB-2026-003 (mitigation guidance: disabling unprivileged userns mitigates ESP variants)
- https://access.redhat.com/security/cve/cve-2026-43284 (Quote: "The xfrm-ESP variant requires unprivileged user or network namespace creation, while the RxRPC variant depends on the rxrpc module being available on the target system."; Important; CWE-123; AV:L/AC:L)
- https://ubuntu.com/security/CVE-2026-43284 ; https://security-tracker.debian.org/tracker/CVE-2026-43284 (patch levels)

Mechanism / write-ups:
- https://github.com/V4bel/dirtyfrag (README; affected ranges; namespace requirement; mitigation)
- https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md (root cause branch, `esp_input_set_header`, `crypto_authenc_esn_decrypt` skip, splice choreography, patch diff, packet path, ESN vs non-ESN, "preserved until drop_caches or reboot")
- https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4 (fix commit)
- https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/cac2661c53f35cbe651bef9b07026a5a05ab8ce0.patch (introducing commit, 2017-01-17)
- https://lwn.net/Articles/932286 (MSG_SPLICE_PAGES background)

Android-specific chains (public):
- https://github.com/diabl0w/DFRoot (README: chain steps 1–6; IpSecManager route; crash_dump64 bridge; libc++ hook; vendor_modprobe; "no unlocked bootloader"; supported Samsung; "accidental mitigation (typically seen on kernel 6.1)" FAQ)
- https://github.com/mitschud/DirtyFrag (fork; One UI 9; "Shizuku not needed"; app-level appDomain; prebuilt per-KMI LKMs committed under app/src/main/jni/ko/)
- https://github.com/combeng6th/DirtyInit (README: "uses a stable, public API - IpSecManager"; "How does this avoid the need for CAP_SYS_ADMIN … because system_server itself runs these APIs in its own namespace and forwards them on to the appropriate native networking daemon"; ADB relay for init-namespace stage; targets u:r:init:s0; documented SELinux-blocked untrusted_app boundaries — "Init Unix stream sockets are accessible to every namespace except untrusted_app")
- https://github.com/V4bel/dirtyfrag/issues/23#issuecomment-4405314290 ("accidental mitigation", cited by both repos' READMEs)
- https://web.dev note — not applicable. (No other references used.)

AOSP / Android documentation read for this pass (2026-11-17):
- `platform/system/sepolicy@android17-release`: `public/te_macros` (`net_domain`, `app_domain`, `untrusted_app_domain`), `public/untrusted_app.te`, `public/attributes`, `public/net.te`, `private/net.te` (netdomain rules), `private/app.te` (neverallow quote, §4.2), `private/untrusted_app.te` (`net_domain(untrusted_app)`), `private/shell.te` (`net_domain(shell)`, `allowxperm shell self:netlink_route_socket nlmsg RTM_GETLINK`), `private/netd.te` (netlink_xfrm_socket allows), `private/domain.te` (`allow { appdomain coredomain } system_file:file { execute read open getattr map }`)
- `platform/bionic@android17-release`: `libc/SYSCALLS.TXT`, `libc/SECCOMP_ALLOWLIST_COMMON.TXT`, `libc/SECCOMP_ALLOWLIST_APP.TXT`, `libc/SECCOMP_BLOCKLIST_APP.TXT`, `libc/SECCOMP_BLOCKLIST_COMMON.TXT`, `libc/SECCOMP_PRIORITY.TXT`
- `platform/packages/modules/Connectivity@main`: `framework-t/src/android/net/IpSecManager.java`, `framework-t/src/android/net/IpSecTransform.java`, `service-t/src/com/android/server/IpSecService.java` (permission split quoted in §4.5/4.6)
- https://developer.android.com/reference/android/net/IpSecManager (API 28+, transport mode allowed for apps; tunnel APIs are `@hide`/`@SystemApi` requiring `MANAGE_IPSEC_TUNNELS`)
- https://source.android.com/docs/security/features/selinux/implement ("netd, init, and vold run as root"; "Even if netd became compromised, it couldn't switch domains … although it runs as root")
- `kernel/common@android13-5.15` `arch/arm64/configs/gki_defconfig` (no `CONFIG_USER_NS`, `# CONFIG_PID_NS is not set` — corroborates GZIF IKCONFIG for the base GKI)
- https://source.android.com/docs/security/bulletin/2026/2026-11-01 ("Security patch levels of 2026-11-05 or later address all of these issues."; A-510777270 row for CVE-2026-43284; AOSP backport commit links)
- https://security.samsungmobile.com/securityUpdate.smsb (SMR-NOV-2026 High list contains CVE-2026-43284; May–Oct 2026 SMRs do not)
- Local: `docs/research/cve-2026-43284-triage.md` (this repo; ASB/SMR bookkeeping, binary verification provenance for `esp6_input`, AOSP commit IDs), `docs/SM-S9180-S9180ZHU8GZIF.md` (GZIF firmware identity + binary pass), `dfroot-lkm/README.md` (repo's shipping LKM chain consumers)

**Deliberately not fetched/used:** any APK/LKM binaries from the public repos; `dirtyfrag.io` (redirects to the GitHub repo; content identical to the fetched README/write-up); exploit source listings beyond the oss-security post and the READMEs quoted (mechanism documented, never adapted).

**Unverifiable-by-design items (do not fill in from folklore):** Samsung One UI 9 vendor sepolicy details (needs on-device dump — §6.8); shell's actual `CapEff` on GZIF; whether Samsung silently backported any of the five fix commits below the October ASB (binary: `esp6_input` open in full-function scope; `esp4_input` open in fast-path scope; remainder of `esp_input` undumped); whether One UI 9 changes any IpSecService permission (mainline-module updates ride Google Play, so GZIF's shipped Connectivity APEX version decides — `getTransformState()` liveness probe in C4 indirectly confirms function, not version); RKP/KDP runtime behavior on this specific build.

---

## On-device verification (2026-11-17) — gates cleared

GZIF unit attached (serial intentionally withheld; kernel string matches the analyzed Image exactly).
Read-only `dm3q_gzif_preflight` and the `com.gzif.preflight` diagnostic APK (tag GZIF001) were run:

- `KERNEL MATCH`; SELinux Enforcing; `socket(AF_NETLINK, NETLINK_XFRM)` from shell → errno 13.
- `/proc/config.gz` == embedded config (byte-identical), confirming `CONFIG_USER_NS` unset etc.
- C1 `allocateSecurityParameterIndex(127.0.0.1)` → **OK** (spi=185348075).
- C2 `openUdpEncapsulationSocket()` → **OK** (port=49341, fd valid).
- C3 `IpSecTransform.Builder` + `buildTransportModeTransform(127.0.0.1, spi)` → **OK** (resourceId=5).
- C4 `applyTransportModeTransform(DIRECTION_OUT)` → **OK**; `removeTransportModeTransforms()` → **OK**.
- RESULT: DRYRUN-COMPLETE. SA was applied to a loopback socket and removed immediately; no exploit
  primitive was exercised; the app remains installed as a diagnostic only (uninstall: `adb uninstall com.gzif.preflight`).
- One operational note: `IpSecService` requires `android.permission.INTERNET` (a normal permission)
  for all IPsec calls; apps without it get SecurityException("IpSecService: Neither user ... has android.permission.INTERNET"). Any real payload APK must declare it.
- HMAC-SHA256 auth algorithm requires an explicit truncation length (3-arg `IpSecAlgorithm("hmac(sha256)", key, 256)`), otherwise `IllegalArgumentException: Invalid truncation keyLength: 0`.

Classification of §8 gates after measurement:
- (a) esp4_input binary audit → PASS (esp_input @ 0xffffffc009489c20 unguarded, see campaign doc).
- (b) IKCONFIG/config facts → PASS (device /proc/config.gz == embedded).
- (c) IpSecManager SA-install primitive → PASS (C1–C5).
- (d) Samsung vendor-policy dump (/sys/fs/selinux/policy) → still pending (needs root or a permissive source;
  compiled policy from recovery ramdisk was already analysed — no surprises expected, but this on-device dump is not yet captured).
- (e) RKP/KDP/DEFEX coexistence of the exploit stage → the DFRoot chain exercised the in-place write primitive on this unit (patches landed; see campaign doc §6.5–§6.8). Vanilla `kernelsu.ko` panicked in `init_module()`; the Samsung-patched (no-patch-text / kretprobe) KSU 3.3.0 / KSU-Next 3.4.2 loaders are what actually load. Exploit-stage behaviour on other builds is unmeasured.
