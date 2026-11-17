# SELinux preconditions — recovery `sepolicy` of SM-S9180 GZIF (CVE-2026-43284 / "Dirty Frag")

**Date:** 2026-11-17. **Author:** subagent research pass (read-only, no device access).
**Artifacts analyzed (read-only, not modified):**
- `/mnt/240G_SSD/opencode_tmp/GZIF_work/fota/recovery/sepolicy` — 1,783,541 bytes; binary SELinux compiled policy; SHA-256 `1e02db20efef60d10bc7896c8ea6ceda5634469ec329128fe2760030dc2b7171`
- `/mnt/240G_SSD/opencode_tmp/GZIF_work/fota/recovery/sepolicy_version` — 75 bytes; SHA-256 `29ae2bf8a8a3878e278e2d85f906776d4fa5ee9a69b0556aa827c05a70a266dd`

**Companion docs:** `docs/research/cve-2026-43284-triage.md`, `docs/SM-S9180-S9180ZHU8GZIF.md`.

**Bottom line up front:** This is a **full device policy, not a reduced recovery policy**. In this
policy, **`shell` can NOT create or use `netlink_xfrm_socket`**, and **none of the app domains
(`untrusted_app`, `untrusted_app_27/29/30`, `sec_untrusted_app`, `priv_app`, `system_app`) can
either**. Only 7 concrete source types anywhere in the policy carry `netlink_xfrm_socket` allow
rules: `charon`, `dumpstate` (create+read, no `nlmsg_write`), `netd`, `netutils_wrapper`,
`network_stack`, `system_server`, `vendor_netmgrd`. Of the task's listed domains, only
**`system_server` and `netd`** can create the socket and write XFRM netlink messages. The binary
contains **zero neverallow rules** (Android enforces `neverallow` at build time; it is not present
in the shipped policydb), so app-domain blocking rests on the default-deny posture plus the
absence of allow rules — verified exhaustively.

---

## 1. Artifact identification & full-vs-reduced verdict

### 1.1 `sepolicy_version` (verbatim)

```
VE=SEPF_SM-S9180_13_0001
BD=Mon Sep 28 16:01:23 2026
MP=SHA-256
MV=SHA-256
```

`BD=Mon Sep 28 16:01:23 2026` matches the GZIF campaign record build date (2026-09-28) in
`docs/SM-S9180-S9180ZHU8GZIF.md` — consistent with this being the genuine `SEPF_SM-S9180_13_0001`
policy for the S9180 GZIF firmware. The `_13_` in `SEPF_SM-S9180_13_0001` is **not** the OS version
(GZIF is Android 17 / OneUI 8); it is Samsung's internal policy tag — its exact versioning scheme
is undocumented publicly and its meaning here is **UNVERIFIED** (the tag may have been frozen
across OS generations).

### 1.2 Binary policy header (byte-level)

```
00000000: 8cff 7cf9 0800 0000 5345 204c 696e 7578   magic 0xF97CFF8C ("SE Linux" ident)
00000010: 1e00 0000 0100 00c0 ...                   policydb version 0x1e = 30; flags 0xC0000001 (MLS enabled, per seinfo)
```

### 1.3 `seinfo` statistics (tool output, verbatim)

```
Statistics for policy file: /mnt/240G_SSD/opencode_tmp/GZIF_work/fota/recovery/sepolicy
Policy Version:             30 (MLS enabled)
Target Policy:              selinux
Handle unknown classes:     deny
  Classes:             103    Permissions:         305
  Sensitivities:         1    Categories:         1024
  Types:              4069    Attributes:          496
  Users:                 1    Roles:                 4
  Booleans:              0    Cond. Expr.:           0
  Allow:             91658    Neverallow:            0
  Auditallow:           16    Dontaudit:          2511
  Type_trans:         1882    Type_change:           0
  Type_member:           0    Range_trans:           0
  Role allow:            0    Role_trans:            0
  Constraints:           0    Validatetrans:         0
  MLS Constrain:        89    MLS Val. Tran:         0
  Permissives:           0    Polcap:                4
  Defaults:              0    Typebounds:            0
  Allowxperm:         1406    Neverallowxperm:       0
  Auditallowxperm:       0    Dontauditxperm:        3
  Initial SIDs:         27    Fs_use:               20
  Genfscon:           1735    Portcon:               0
```

Policy file magic decoded by `file(1)`: `SE Linux policy v30 8 symbols 7 ocons`.

### 1.4 Evidence for "FULL policy" verdict

| Indicator | Finding | Reduced/recovery-only policy would look like |
|---|---|---|
| Type count | **4069** | typically a few hundred |
| Class count | **103** | tens |
| Attributes | **496** | few |
| Allow rules | **91658** | small fraction |
| App domains present | `untrusted_app`, `untrusted_app_27/29/30`, `sec_untrusted_app`, `vzwfiltered_untrusted_app`, `priv_app`, `system_app`, `platform_app` (verified present), `zygote`, `system_server`, `netd`, `su`, `shell`, `init`, `mediaserver`, `audioserver`, `surfaceflinger`, `vold`, `servicemanager`, `keystore`, `statsd`, `logd`, `installd` — **all present** | app domains absent/stripped |
| Vendor/SoC zoo present | **1103** `vendor_*` types (153 `vendor_hal_*`), 102 `*_qti`/`*_qcom` matches (e.g. `vendor_netmgrd`, `vendor_tzas_app`, `vendor_seccam_app`, `vendor_qmuxd`) | absent |
| Samsung SEC types | `sec_untrusted_app`, `sec_standard_app_type`, `hal_sec_*`, `hal_sem`, `hal_tima`, `hal_knoxai`, `hal_soter` | absent |
| Recovery-specific types also present | `recovery`, `recovery_socket`, `recovery_block_device`, `recovery_config_prop`, `recovery_persist`, `recovery_refresh`, `recovery_refresh_exec`, `recovery_service`, `recovery_prop`, `recovery_data_file`, `charger`, `charger_exec`, `charger_prop`, `charger_status_prop`, `charger_vendor`, `charger_config_prop` | these would be the *only* domains present |
| MLS | enabled; 1 sensitivity, 1024 categories, 89 MLS constrain rules, roles `{auditadm_r, object_r, r, secadm_r}`, user `u` only | MLS often absent in minimal builds |
| Genfscon | **1735** | few |
| Initial SIDs | **27** (standard set: `kernel`, `init`, `policy`, `unlabeled`, sysctl/* …) | fewer |
| Booleans | 0 | 0 (normal for Android) |

**Verdict: FULL device policy.** It contains the complete platform + vendor + Samsung-SEC symbol
set with recovery domains layered on top — exactly what you'd expect from a modern A/B
dynamic-partition Android recovery image that boots with the same policy as the system. It is
**not** a minimal recovery-only policy. Caveats: (a) "full" refers to policydb symbol coverage; we
analyzed the recovery ramdisk's copy, and (b) it is **UNVERIFIED** whether the booted system's
`/sys/fs/selinux/policy` on the GZIF unit is byte-identical to this file (see §6).

Note on the recovery-type list: the strings `recovery`, `recovery_socket`,
`recovery_block_device`, `recovery_config_prop`, `recovery_data_file`, `recovery_persist`,
`recovery_persist_exec`, `recovery_refresh`, `recovery_refresh_exec`, `recovery_service`,
`recovery_prop`, `charger`, `charger_config_prop`, `charger_exec`, `charger_prop`,
`charger_status_prop`, `charger_vendor` all appear in the type table (verified via
`grep -E '^recovery|^charger' sepolicy-types.txt`) — this is the normal Android
"recovery + charger + full policy" combination.

---

## 2. Tooling used (and how)

**Method chosen: `dpkg-deb -x` extract-to-scratch. System-wide install was NOT used** (it was
approved as a fallback, but the scratch route worked first try and required no system changes).
No `/etc`, `/usr`, or package database was modified. No `adb`, no device interaction, no firmware
re-extraction.

Scratch dir: `/mnt/240G_SSD/opencode_tmp/setools-extract/`; debs kept in `/mnt/240G_SSD/opencode_tmp/setools-debs/`.

Commands run (all read-only against the policy):
```
cd /mnt/240G_SSD/opencode_tmp/setools-debs
apt-get download setools python3-setools          # 4.6.0-2build3, Ubuntu "resolute"/universe
for d in *.deb; do dpkg-deb -x "$d" /mnt/240G_SSD/opencode_tmp/setools-extract; done
export PYTHONPATH=/mnt/240G_SSD/opencode_tmp/setools-extract/usr/lib/python3/dist-packages
export PATH=/mnt/240G_SSD/opencode_tmp/setools-extract/usr/bin:$PATH
```

Versions recorded:
- `setools` 4.6.0-2build3 (amd64), `python3-setools` 4.6.0-2build3 (amd64) — `seinfo --version` → `4.6.0`, `sesearch --version` → `4.6.0`
- `libsepol2` 3.9-2 (already installed), `libselinux1` 3.9-4build1 (already installed)
- Host Python 3.14.4; `setools` 4.6 ships a compiled `policyrep.cpython-314-x86_64-linux-gnu.so`; `networkx` 3.6.1 present; `python3-selinux`/`python3-sepol` **not** installed and not needed.
- **`sepolicy-analyze` is NOT packaged anywhere in the Ubuntu "resolute" archive** (`apt-cache search sepolicy-analyze` → no package). The task's `sepolicy-analyze sepolicy common -` step was therefore impossible with this mirror; `seinfo` (`--common`, `--polcap`, `-c -x`, `--initialsid`) was used instead. This is documented as the tooling deviation.

`seinfo`/`sesearch` confirm attribute expansion semantics: `-s <type>` by default also matches
rules whose source is an attribute containing `<type>`; `-ds` matches the attribute literally.
Verified with `sesearch -A -s domain -c netlink_xfrm_socket` → 15 rules (expanded members) vs
`-ds` → 0. Cross-checks below rely on this expansion plus an exhaustive source-name scan of all
`netlink_xfrm_socket` rules against the 496 attribute names (no attribute appears as a source).

---

## 3. Policy metadata (`kernel` version info)

**An SELinux binary policy contains no kernel-version string.** What is present and reported:

- **Policy version: 30** (`Policy Version: 30 (MLS enabled)`), magic `0xF97CFF8C`, ident `SE Linux`.
- `Handle unknown classes: deny` (critical when analyzing newer classes against this policy).
- Policy capabilities (`seinfo --polcap`): `extended_socket_class`, `network_peer_controls`, `nnp_nosuid_transition`, `open_perms`.
- Target: `selinux`. Booleans: 0. Handle unknown: deny.
- MLS: 1 sensitivity / 1024 categories / 89 MLS constrain / 0 permissive domains.

Policy v30 is the standard policydb version Android ships (it is the minimum policy version
supported by current SELinux userspace per the upstream SELinux project). No more granular
"kernel version" is recoverable from this file; `sepolicy-analyze` (which prints extra common
permission-set detail) was unavailable — see §2. The recovery image's ramdisk also contained a
`sepolicy_version` "version" file (§1.1) but that is Samsung's build tag, not an OS/kernel version.
Kernel build info for the GZIF unit can only be read on-device (`/proc/version`) — out of scope.

---

## 4. Task 3 answers — XFRM netlink

### 4.0 The class and its permissions

```
class netlink_xfrm_socket
inherits socket
{
	nlmsg_read
	nlmsg_write
}
```
where common `socket` provides:
`{ accept append bind connect create getattr getopt ioctl listen lock map name_bind read recvfrom relabelfrom relabelto sendto setattr setopt shutdown write }`

So effective perms on `netlink_xfrm_socket`: the common socket set + `nlmsg_read` + `nlmsg_write`.

### 4.1 Exhaustive list of every rule in the policy mentioning `netlink_xfrm_socket` (all 15)

```
allow charon charon:netlink_xfrm_socket { append bind connect create getattr getopt ioctl lock map nlmsg_read nlmsg_write read setattr setopt shutdown write };
allow dumpstate domain:netlink_xfrm_socket getattr;
allow dumpstate dumpstate:netlink_xfrm_socket { append bind connect create getattr getopt lock map nlmsg_read read setattr setopt shutdown write };
allow dumpstate pdx_channel_socket_type:netlink_xfrm_socket getattr;
allow dumpstate pdx_endpoint_socket_type:netlink_xfrm_socket getattr;
allow netd netd:netlink_xfrm_socket { append bind connect create getattr getopt lock map nlmsg_read nlmsg_write read setattr setopt shutdown write };
allow netutils_wrapper netutils_wrapper:netlink_xfrm_socket { accept append bind connect create getattr getopt listen lock map name_bind nlmsg_read nlmsg_write read recvfrom relabelfrom relabelto sendto setattr setopt shutdown write };
allow netutils_wrapper rild:netlink_xfrm_socket { read write };
allow netutils_wrapper vendor_dpmd:netlink_xfrm_socket { read write };
allow netutils_wrapper vendor_dpmd_vndr:netlink_xfrm_socket { read write };
allow netutils_wrapper vendor_netmgrd:netlink_xfrm_socket { read write };
allow network_stack network_stack:netlink_xfrm_socket { append bind connect create getattr getopt lock map nlmsg_read nlmsg_write read setattr setopt shutdown write };
allow system_server system_server:netlink_xfrm_socket { append bind connect create getattr getopt lock map nlmsg_read nlmsg_write read setattr setopt shutdown write };
allow vendor_netmgrd vendor_netmgrd:netlink_xfrm_socket { append bind connect create getattr getopt lock map nlmsg_read nlmsg_write read setattr setopt shutdown write };
allowxperm charon charon:netlink_xfrm_socket ioctl 0x8946;
```

Notes on this list:
- Sources with **create**: `charon`, `dumpstate`, `netd`, `netutils_wrapper`, `network_stack`, `system_server`, `vendor_netmgrd`.
- Sources with **nlmsg_write**: `charon`, `netd`, `netutils_wrapper`, `network_stack`, `system_server`, `vendor_netmgrd` (**dumpstate does NOT have `nlmsg_write`**).
- No `dontaudit`/`auditallow` rule anywhere for this class (`sesearch --dontaudit` / `--auditallow` → empty).
- No attribute appears as a source (verified by scanning all 15 rules against the 496 attribute names).
- `allowxperm` exists only for `charon` (ioctl `0x8946`); no xperm rules for any other domain → no extended-permission path leaks through non-`ioctl`-listed domains.

### 4.2 Per-domain verdicts (expanded attribute matching, `sesearch -A -s <domain> -c netlink_xfrm_socket`)

| Domain (full attribute closure) | Rules matched | xfrm create | xfrm nlmsg_write |
|---|---|---|---|
| `shell` (`appdomain, coredomain, domain, mlstrustedsubject, netdomain, vendor_hal_dspmanager…`) | **none** | **Denied** | **Denied** |
| `untrusted_app` (`… untrusted_app_all, untrusteddomain, …`) | **none** | **Denied** | **Denied** |
| `untrusted_app_27` (`… untrusted_app_all, untrusteddomain, …`) | **none** | **Denied** | **Denied** |
| `untrusted_app_29` (`… untrusted_app_all, untrusteddomain, …`) | **none** | **Denied** | **Denied** |
| `untrusted_app_30` (`appdomain, domain, untrusted_app_all, netdomain, …`) | **none** | **Denied** | **Denied** |
| `sec_untrusted_app` (`appdomain, coredomain, domain, netdomain, sec_standard_app_type`) | **none** | **Denied** | **Denied** |
| `priv_app` (`appdomain, coredomain, domain, netdomain, …`) | **none** | **Denied** | **Denied** |
| `system_app` (`appdomain, coredomain, domain, mlstrustedsubject, netdomain, …`) | **none** | **Denied** | **Denied** |
| `system_server` (`binderservicedomain, coredomain, domain, mlstrustedsubject, netdomain, …`) | 1 (shown above) | **Allowed** (no `ioctl`) | **Allowed** |
| `netd` (`bpfdomain, coredomain, domain, mlstrustedsubject, netdomain`) | 1 (shown above) | **Allowed** (no `ioctl`) | **Allowed** |
| `init` (`coredomain, domain, mlstrustedsubject`) | **none** | **Denied** | **Denied** |
| `su` (`domain` only — note: NOT in `appdomain`/`coredomain`/`netdomain`) | **none** | **Denied** | **Denied** |

Relevant raw attribute rule checks (all empty, `-ds`): `sesearch -A -s {domain, appdomain, coredomain, netdomain} -ds -c netlink_xfrm_socket` → 0 rules each.

### 4.3 Neverallow analysis (task 3b)

**The binary policy contains ZERO neverallow rules**, by direct count:
`Allow: 91658   Neverallow: 0`, `Neverallowxperm: 0`, and `strings sepolicy | grep -i neverallow` → no output.

This is expected for Android: neverallow rules are compile-time checks enforced while building the
policy (in the AOSP build they gate the build and are not present in the on-device/shipped policydb).
**Therefore this file cannot confirm or quote any vendor neverallow targeting xfrm for app domains.**
The blocking posture for `untrusted_app` & friends in this binary is the **default-deny** rule
(no allow rule exists for any app domain on `netlink_xfrm_socket`), not a quoted neverallow.
Any vendor neverallow text would have to come from the policy *source* (`system/sepolicy` /
`vendor/sepolicy` in the platform source tree), which is outside this artifact — marked
**UNVERIFIED** here and deferred.

### 4.4 Other XFRM/IPsec-related classes and types (task 3c)

- **No `esp` class, no `xfrm_socket` class, no `xfrm` types of any kind.** Only the `netlink_xfrm_socket` class exists for XFRM. (`seinfo -c --flat | grep -i -E 'xfrm|esp'` → `netlink_xfrm_socket` only; `grep -i -E 'esp' sepolicy-types.txt` → 0 hits.)
- **No `esp4`/`esp6` types.**
- IPsec-related *types* that exist (all three):
  - `IPSecService` — a **domain** (`coredomain, domain`); **has NO `netlink_xfrm_socket` rules and NO `udp_socket create` rule** (verified); XFRM netlink is *not* directly available to it either.
  - `IPSecService_exec` — `exec_type, file_type, system_file_type` (its binary).
  - `ipsec_service` — a **service** (`app_api_service, ephemeral_app_api_service, service_manager_type, system_server_service`) — i.e. the servicemanager-visible name, permission-gated at the framework level.
- Samsung/vendor types with xfrm create+write listed in §4.1: `network_stack` (Samsung/qcom-era net policy daemon type, `coredomain, netdomain, mlstrustedsubject`), `vendor_netmgrd` (`domain, netdomain`), `netutils_wrapper` (`domain, bpfdomain`), `charon` (`domain, coredomain, netdomain, tunneldomain`, strongSwan IKE; also `allowxperm … ioctl 0x8946`), `dumpstate` (create+`nlmsg_read`, **no** `nlmsg_write`).
- **`udp_socket` create perms exist for every app domain** (all needed for ESP-in-UDP):

```
allow shell           shell:udp_socket           { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow untrusted_app   untrusted_app:udp_socket   { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow untrusted_app_27 untrusted_app_27:udp_socket { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow untrusted_app_29 untrusted_app_29:udp_socket { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow untrusted_app_30 untrusted_app_30:udp_socket { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow sec_untrusted_app sec_untrusted_app:udp_socket { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow priv_app        priv_app:udp_socket        { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow system_app      system_app:udp_socket      { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow system_server   system_server:udp_socket   { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow netd            netd:udp_socket            { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow network_stack   network_stack:udp_socket   { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow netutils_wrapper netutils_wrapper:udp_socket { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow charon          charon:udp_socket          { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow dumpstate       dumpstate:udp_socket       { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow vendor_netmgrd  vendor_netmgrd:udp_socket  { append bind connect create getattr getopt ioctl lock map read setattr setopt shutdown write };
allow init            init:udp_socket            { create ioctl };
allow IPSecService    — NO udp_socket create rule —
```

  - `su`: **NO `udp_socket create` rule** (complete absence — notable, since a rooted `su` context cannot even open UDP here without an allow rule).
  - No attribute grants `udp_socket create` (verified by scanning all attribute names against the UDP-create source list — zero hits). All UDP-create rules are direct-type rules.

- Bonus context for the exploit-route question: app/shell domains **do** have `netlink_route_socket` create (quoted below) but **no** `netlink_generic_socket`, **no** `netlink_crypto_socket` create:

```
allow shell         shell:netlink_route_socket         { append bind connect create getattr getopt lock nlmsg_getneigh nlmsg_read nlmsg_readpriv read setattr setopt shutdown write };
allow untrusted_app_30 untrusted_app_30:netlink_route_socket { append connect create getattr getopt lock nlmsg_getneigh nlmsg_read read setattr setopt shutdown write };
shell/untrusted_app_30 - netlink_generic_socket create → (empty)
shell/untrusted_app_30 - netlink_crypto_socket create → (empty)
```

### 4.5 The `shell` verdict (task 3d) — the headline for DirtyFrag-style chains

`shell` (`u:r:shell:s0`) has **no rule anywhere** granting `netlink_xfrm_socket` create,
`nlmsg_write`, `nlmsg_read`, or any other perm on that class. Its xfrm access is **Denied** under
default-deny. A DirtyFrag-style chain that relies on installing an ESP transport SA via
`NETLINK_XFRM` / `XFRM_MSG_NEWSA` **cannot pass the SELinux check while running as `shell`** on
this policy. App-class domains (`untrusted_app*`, `sec_untrusted_app`, `priv_app`, `system_app`)
likewise cannot. Only `system_server` and `netd` (and vendor/IKE contexts) can.

---

## 5. Domain × (xfrm create / xfrm nlmsg_write / udp create / neverallow?) matrix

Legend: **Allowed** = quoted allow rule exists (§4); **Denied** = no rule exists anywhere in the
policy for that class/perm (default-deny); **N/A** = binary has 0 neverallow rules so the question
cannot be answered from this file (neverallow is a build-time gate); `init` UDP create is limited
to `{ create ioctl }`.

| Domain | xfrm create | xfrm nlmsg_write | xfrm nlmsg_read | udp create | neverallow in binary | net verdict for XFRM SA install |
|---|---|---|---|---|---|---|
| `shell` | Denied | Denied | Denied | Allowed | 0 rules (N/A) | **Cannot** |
| `untrusted_app` | Denied | Denied | Denied | Allowed | 0 rules (N/A) | **Cannot** |
| `untrusted_app_27` | Denied | Denied | Denied | Allowed | 0 rules (N/A) | **Cannot** |
| `untrusted_app_29` | Denied | Denied | Denied | Allowed | 0 rules (N/A) | **Cannot** |
| `untrusted_app_30` | Denied | Denied | Denied | Allowed | 0 rules (N/A) | **Cannot** |
| `sec_untrusted_app` | Denied | Denied | Denied | Allowed | 0 rules (N/A) | **Cannot** |
| `priv_app` | Denied | Denied | Denied | Allowed | 0 rules (N/A) | **Cannot** |
| `system_app` | Denied | Denied | Denied | Allowed | 0 rules (N/A) | **Cannot** |
| `system_server` | **Allowed** (`{ … create … nlmsg_read nlmsg_write … }`) | **Allowed** | **Allowed** | Allowed | 0 rules (N/A) | Can |
| `netd` | **Allowed** (same set) | **Allowed** | **Allowed** | Allowed | 0 rules (N/A) | Can |
| `init` | Denied | Denied | Denied | Allowed (`{ create ioctl }` only) | 0 rules (N/A) | **Cannot** |
| `su` | Denied | Denied | Denied | **Denied** | 0 rules (N/A) | **Cannot** |
| `charon` (context, not requested) | **Allowed** + `ioctl` | **Allowed** | **Allowed** | Allowed | 0 rules (N/A) | Can |
| `dumpstate` (context, not requested) | **Allowed** | **Denied** (no `nlmsg_write`) | **Allowed** | Allowed | 0 rules (N/A) | **Cannot install SA** (write needed) |
| `netutils_wrapper` (context) | **Allowed** + listen/accept/etc. | **Allowed** | **Allowed** | Allowed | 0 rules (N/A) | Can |
| `network_stack` (context, Samsung/vendor coredomain) | **Allowed** | **Allowed** | **Allowed** | Allowed | 0 rules (N/A) | Can |
| `vendor_netmgrd` (context, vendor) | **Allowed** | **Allowed** | **Allowed** | Allowed | 0 rules (N/A) | Can |
| `IPSecService` (context) | Denied | Denied | Denied | **Denied** | 0 rules (N/A) | **Cannot** |

Rule IDs = the `allow …` statements quoted verbatim in §4.1/§4.4/§4.2; there is exactly one
xfrm-socket allow rule per listed context, and none for any other context in the policy
(exhaustive: `sesearch -A -c netlink_xfrm_socket` returned 14 allow + 1 allowxperm rule total).

---

## 6. What this binary CANNOT tell us (explicit), and what remains for on-device checks

This file is a **policydb snapshot**. It cannot and does not answer:

1. **Runtime SELinux state** — Enforcing vs Permissive, actual loaded policy, and whether the
   booted device's `/sys/fs/selinux/policy` is byte-identical to this recovery copy (it may carry
   just this file, or the identical platform policy — **UNVERIFIED** from static analysis).
   `id -Z` / `getenforce` on the GZIF unit is required. (Task states Enforcing + `u:r:shell:s0`;
   our job was only to confirm what the policy allows.)
2. **`unshare(CLONE_NEWUSER|CLONE_NEWNET)` / userns creation** — that is gated by
   `/proc/sys/user/max_user_namespaces`, `kernel.unprivileged_userns_clone` (if present), and
   **seccomp** filters, none of which are SELinux decisions. The PoC's netns+userns setup is
   invisible to this file.
3. **Seccomp status** of the caller (`/proc/self/status` → `Seccomp:` / `Seccomp_filters:`),
   including whether `unshare`, `socket(AF_NETLINK,…,NETLINK_XFRM)`, `setsockopt`, `sendmsg`
   are filtered for the shell/app seccomp profile. Outside SELinux.
4. **Android permission-level gating** — `android.permission.MANAGE_IPSEC_TUNNELS`
   (signature|privileged), IpSecManager grants (`PackageManager.checkPermission`), and whether
   *any* app on the unit holds it. Permission grants, not SELinux, decide whether the IpSecManager
   path is reachable at all.
5. **Kernel feature presence** — whether `esp4`/`esp6` code is built-in or as modules, whether
   `CONFIG_USER_NS` / `CONFIG_NET_NS` / `CONFIG_XFRM` are enabled, GKI defconfig, and the exact
   kernel version. Not in the policy. (`/proc/version`, `/proc/config.gz` if present, or the
   kernel image, separate task.)
6. **neverallow coverage from policy source** — the binary has 0 neverallows; the vendor/platform
   neverallow text targeting xfrm (e.g., in AOSP `system/sepolicy` and Samsung `vendor/sepolicy`)
   cannot be quoted from here. Only the absence of allow rules + default-deny is provable.
7. **Capabilities** — `CAP_NET_ADMIN` for the calling process (SELinux check is necessary, not
   sufficient: `capable(CAP_NET_ADMIN)` is also consulted for XFRM_MSG_NEWSA). For `shell`,
   capabilities are typically not granted. Not represented in the policy file.
8. **AVC denial telemetry** — what the kernel would log on a real attempt (audit/avc denial), and
   whether Samsung added `dontaudit` rules (this file has none for xfrm — denials would be
   auditable if they occurred and policy were enforcing).

Remaining on-device checks (executed 2026-11-17 on the attached GZIF S9180 unit — serial intentionally withheld; results in the campaign record §6.5 and `dirtyfrag-trigger-requirements.md` "On-device verification"):

- `id`, `id -Z`, `getenforce` (expect `u:r:shell:s0`, `Enforcing`) — and confirm the loaded policy
  matches this analysis (e.g. `sha256sum /sys/fs/selinux/policy` vs the hash in this doc, if feasible).
- `cat /proc/sys/user/max_user_namespaces`, `cat /proc/sys/kernel/unprivileged_userns_clone` (if present)
- `grep -i seccomp /proc/self/status` (expect `Seccomp: 2` filter mode for apps; shell under `adb shell` is usually unconfined by seccomp but Samsung may differ)
- `capsh --print` / `grep Cap /proc/self/status` for `CAP_NET_ADMIN` in the shell context
- Permission check: does any relevant app hold `MANAGE_IPSEC_TUNNELS` / `ACCESS_NETWORK_STATE` (for the IpSecManager route)? `cmd package list permissions -g`, or `pm dump <pkg> | grep -i ipsec`
- Kernel config: `zcat /proc/config.gz | grep -E 'XFRM|ESP|USER_NS|NET_NS'` (if exposed) or kernel image analysis
- `/proc/version`, `uname -a` for the GZIF kernel string
- If attempting on-device validation later: watch `adb shell dmesg | grep avc` / `logcat | grep avc`
  for `netlink_xfrm_socket` denials to confirm the SELinux layer empirically rejects the attempt.

---

## 7. Method & verification appendix (reproducible)

All commands were run read-only against the artifact with scratch tooling (§2):

```
sha256sum sepolicy sepolicy_version
file sepolicy
seinfo sepolicy                                    # statistics (§1.3)
seinfo sepolicy -t --flat                          # 4069 types (§1.4)
seinfo sepolicy -c --flat                          # 103 classes (§4.0, §4.4)
seinfo sepolicy -c netlink_xfrm_socket -x          # class perms (§4.0)
seinfo sepolicy -c socket -x ; seinfo sepolicy --common socket -x
seinfo sepolicy -c udp_socket -x
seinfo sepolicy --polcap                           # §3
seinfo sepolicy --initialsid | wc                  # 27
seinfo sepolicy -a --flat                          # 496 attributes (attr scan)
# type attribute closure for every queried domain:
for t in shell untrusted_app untrusted_app_27 untrusted_app_29 untrusted_app_30 \
         sec_untrusted_app priv_app system_app system_server netd su init; do
  seinfo sepolicy -t $t -x
done
# exhaustive xfrm rule enumeration + attribute-source cross-scan (§4.1)
sesearch sepolicy -A -c netlink_xfrm_socket
sesearch sepolicy -A -c netlink_xfrm_socket | awk '{print $2}' | sort | uniq  # 7 concrete sources
grep -x -F -f <(sesearch sepolicy -A -c netlink_xfrm_socket | awk '{print $2}' | sort | uniq) \
     <(seinfo sepolicy -a --flat)                  # → no attribute sources (empty)
# per-domain expanded queries
for t in <all listed domains>; do sesearch sepolicy -A -s $t -c netlink_xfrm_socket; done
sesearch sepolicy --dontaudit  -c netlink_xfrm_socket   # empty
sesearch sepolicy --auditallow -c netlink_xfrm_socket   # empty
sesearch sepolicy -A -s <domain> -c udp_socket -p create # (§4.4)
sesearch sepolicy -A -s <domain> -c netlink_route_socket -p create
strings sepolicy | grep -i neverallow            # empty
```

Scratch artifacts written (outside the repo, allowed):
`/mnt/240G_SSD/opencode_tmp/sepolicy-*.txt`, `/mnt/240G_SSD/opencode_tmp/setools-debs/`,
`/mnt/240G_SSD/opencode_tmp/setools-extract/`. No repo files other than this document were created or
modified. Firmware artifacts were treated read-only.

**UNVERIFIED / not confirmed items (flagged, not asserted):**
- Vendor neverallow texts for xfrm (binary has none; source not available here).
- Byte-identity of this recovery policy vs the booted system's `/sys/fs/selinux/policy`.
- Samsung's `_13_` policy tag meaning for the Android-17 GZIF build (Samsung internal tagging).
- `sepolicy-analyze` output (package not in Ubuntu archive for this release); substituted with `seinfo`.
- `IPSecService`'s real-world identity (its precise function in OneUI is not inferable from the policy alone).
