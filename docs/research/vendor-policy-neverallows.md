# Vendor/platform CIL neverallow & xfrm decode (2026-11-17)

Scope: the vendor SELinux sources shipped in the GZIF firmware's vendor partition
(`vendor_sepolicy.cil`, `plat_pub_versioned.cil`), extracted read-only from
`vendor.img` (EROFS; staging `host-side GZIF-vendor-work/vendor_selinux/`).
The compiled full policy was already analysed from `fota/recovery/sepolicy`
(see `selinux-preconditions.md`); this file decodes the **source-side neverallows**,
which the binary analysis could only assume.

Hashes: `vendor_sepolicy.cil` = sha `13811d6b…`; `plat_pub_versioned.cil` = `f4538aac…`;
`vendor_sepolicy_version` == `SEPF_SM-S9180_13_0001` (byte-identical to `fota/recovery/sepolicy_version`).

## 1. The governing neverallow (platform policy, verbatim)

```
6746:(neverallow base_typeattr_201_33_0 domain (netlink_tcpdiag_socket …))
6747:(neverallow base_typeattr_201_33_0 domain (netlink_nflog_socket …))
6748:(neverallow base_typeattr_201_33_0 domain (netlink_xfrm_socket (ioctl read write create getattr setattr lock relabelfrom relabelto append map bind connect listen accept getopt setopt shutdown recvfrom sendto name_bind nlmsg_read nlmsg_write)))
6749:(neverallow base_typeattr_201_33_0 domain (netlink_audit_socket …))
6750:(neverallow base_typeattr_201_33_0 domain (netlink_dnrt_socket …))
6751:(neverallow base_typeattr_201_33_0 domain (netlink_kobject_uevent_socket (write append)))
13812:(typeattribute base_typeattr_201_33_0)
13813:(typeattributeset base_typeattr_201_33_0 (and (appdomain) (not (network_stack_33_0))))
```

`base_typeattr_201_33_0` = **`appdomain` minus `network_stack_33_0`** ⇒ every app domain
(untrusted_app*, sec_untrusted_app, priv_app, system_app, …) is compile-time
**forbidden** `netlink_xfrm_socket` in every form. Samsung cannot loosen this per-build
(neverallows are enforced at policy build time), and user namespaces do not interact
with SELinux: an app holding CAP_NET_ADMIN inside a new net ns is still denied the
socket at the LSM hook.

Also present:

```
7441:(neverallowx domain domain (ioctl netlink_xfrm_socket (0x8905)))
```

## 2. Who CAN use netlink_xfrm_socket (all allow rules found)

| Domain | Rules (CIL line refs) | Notes |
| --- | --- | --- |
| `dumpstate_33_0` | PLAT:8111-8126, 8183, 8240 (and VENDOR:6704 create/read, no nlmsg_write) | create/open only; **cannot nlmsg_write** → cannot install an SA |
| `charon_33_0` | VENDOR:9895, 9939, 9940 (+ `allowx … (0x8946)`) | strongSwan IKE; full XFRM incl. one allowxperm |
| `vendor_netmgrd` | VENDOR:20672 | Samsung vendor net manager; full create/nlmsg_write |
| `netutils_wrapper_33_0` | VENDOR:20726 (rw to vendor_netmgrd), 21162 (rw to rild), 22024/22069 (rw to vendor_dpmd*) | proxy wrapper, not directly creatable by apps |
| `netd_33_0` | PLAT:11242 (self create + nlmsg_write/read) | Google netd |
| `network_stack_33_0` | exempt from the appdomain neverallow at 6748 | mainline network stack APEX (not app-reachable) |
| `system_server` | allow rule lives in platform **private** policy (not in the public CIL; confirmed in compiled recovery policy: create + nlmsg_write/read) | the XFRM executor behind the IPsecManager binder API |

Vendor CIL contains **zero** allow rules for shell/untrusted_app*/priv_app/system_app —
matching the compiled-policy analysis (default-deny).

## 3. esp4.ko: ABSENT

vendor_dlkm contains 367 `.ko`; **no `esp*`, `xfrm*`, `ipsec*` module and zero hits in
`modules.alias/.dep/.load/.softdep/.blocklist`**. esp4 is built-in only as a kmod
**stub** (`__initstub__kmod_esp4…` in vmlinux); ESP input actually lives in built-in
`esp6_input` (see campaign doc §3). The ESP-in-UDP-unprivileged path referenced by the
public PoC relies on the same XFRM SA-installation primitive (§1), so it is equally
unreachable from app domains — independently of esp4/esp6.

## 4. Bottom line (superseded 2026-11-17 by the IKCONFIG/esp4 pass)

The neverallow analysis above stands, but it does NOT close 43284 on GZIF — the
**untrusted_app → netd-proxied SA install (IpSecManager transport-mode ESP-in-UDP)** route
never exercises the app-domain netlink_xfrm permission at all; netd performs all XFRM work
as root with the allow rules quoted in §2. Measured since this file was first written:

- GZIF embedded IKCONFIG: `CONFIG_INET_ESP=y`, `CONFIG_INET6_ESP=y`,
  **`# CONFIG_USER_NS is not set`** (kills the desktop/userns PoC route),
  `CONFIG_XFRM_USER=y`, `CONFIG_INET_ESPINTCP` not set (kills the ESPINTCP/Fragnesia variant),
  `CONFIG_AF_RXRPC` not set;
- `esp4` is **built-in** (`esp_input` @ `0xffffffc009489c20`), binary-verified **unguarded**
  (no `skb_has_shared_frag` test) — same shape as `esp6_input`;
- `esp4.ko` does not exist as a module, which is irrelevant (built-in `=y`).

So the state of 43284: app domains cannot do XFRM themselves (this file), userns is gone
(IKCONFIG), but the IpSecManager route is NOT gated by either. Verdict lives in
`docs/SM-S9180-S9180ZHU8GZIF.md` §6.1 — do not cite this file for "closed".
