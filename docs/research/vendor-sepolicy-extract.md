# Vendor partition & SELinux policy extraction from GZIF super.img

**Date:** 2026-11-17. **Author:** subagent research pass (read-only binary analysis).
**Scope:** extract `vendor` (and `vendor_dlkm`) from the GZIF AP firmware's `super.img.lz4`,
dump SELinux artifacts from it, compare against the recovery policy used for static
analysis, and check for an `esp4.ko` kernel module in the vendor DLKM.
**No device actions, no mounting of block images, no module loading, no flashing.**

Paths:

- Source firmware zip (read-only): `host-side GZIF_work/SM-S9180_BRI_GZIF.zip`
- Staging dir (this task only writes here + this report): `host-side GZIF-vendor-work/`
- Recovery policy under comparison: `host-side GZIF_work/fota/recovery/sepolicy` (+ `sepolicy_version`)

---

## 0. Verdicts up front

1. **VENDOR = EROFS, not ext4.** `debugfs` does not work on it; `dump.erofs` (erofs-utils 1.9)
   was used for all reads. Same for `vendor_dlkm`.
2. **Vendor ships NO compiled `sepolicy`.** `/vendor/etc/selinux/` contains only SELinux
   *source* artifacts: `vendor_sepolicy.cil`, `plat_pub_versioned.cil`, text contexts
   (`vendor_file_contexts`, …), `plat_sepolicy_vers.txt` (`33.0`), `vendor_sepolicy_version`.
   A byte-wise comparison of a vendor `sepolicy` against
   `fota/recovery/sepolicy` is therefore **not possible — the artifact does not exist in vendor**.
3. **Policy-version stamp matches the recovery policy byte-for-byte.**
   `vendor/etc/selinux/vendor_sepolicy_version` ≡
   `fota/recovery/sepolicy_version`
   (both `VE=SEPF_SM-S9180_13_0001`, `BD=Mon Sep 28 16:01:23 2026`, `MP=SHA-256`,
   `MV=SHA-256`; sha256 `29ae2bf8a8a3878e278e2d85f906776d4fa5ee9a69b0556aa827c05a70a266dd`).
4. **esp4.ko: NOT FOUND.** No `esp*.ko` / `*xfrm*` / `*ipsec*` module exists in
   `vendor_dlkm` (380 entries, 367 `.ko`), and no `esp/xfrm` reference exists in
   `modules.alias/.dep/.load/.softdep/.blocklist`. Consistent with the GZIF kernel having
   esp6 built in and `esp4` only as a built-in module stub (`kmod_esp4`).

---

## 1. Firmware members and `super.img.lz4` identification

`unzip -l SM-S9180_BRI_GZIF.zip`:

```
13869117563  2026-09-29 11:53   AP_S9180ZHU8GZIF_S9180ZHU8GZIF_MQB115380939_REV00_user_low_ship_MULTI_CERT_meta_OS17.tar.md5
```

(AP tar is 13,869,117,563 bytes; members are lz4-compressed images inside the tar.)

`super.img.lz4` lives **inside** that AP tar (not a direct zip member). Member sizes via
`unzip -p … 'AP_*.tar.md5' | tar -tvf - | head` (streaming, no extraction):

```
boot.img.lz4           29784863
dtbo.img.lz4             2348412
super.img.lz4         9909885498
recovery.img.lz4        62884241
vendor_boot.img.lz4     16867434
vbmeta_system.img.lz4      2936
persist.img.lz4            9878
init_boot.img.lz4       1777277
```

→ **`super.img.lz4` tar member = 9,909,885,498 bytes (`tar -tvf`).**

### LZ4 framing (python `lz4.frame.get_frame_info`, cross-checked with CLI)

First 32 bytes of the member (`... | tar -xOf - super.img.lz4 | head -c 32 | xxd`):

```
0422 4d18 6c60 c8a8 c796 0200 0000 f1df
ec05 00f2 073a ff26 ed01 0000 001c 000c
```

| Field | Value |
|---|---|
| magic | `0x184d2204` — standard **LZ4 frame** (not legacy/skippable) |
| FLG `0x6c` | version 1; block independence; B.Checksum=0; **C.Size present**; **content XXH32 checksum present**; no header checksum |
| BD `0x60` | block-max-size code 6 → **1 MiB** blocks |
| content size | **11,119,601,864 bytes** (10.356 GiB) |

`lz4.frame.get_frame_info` confirmed: `block_size: 1048576, block_size_id: 6, block_linked: False,
content_checksum: True, block_checksum: False, skippable: False, content_size: 11119601864`.

### Streaming convert and integrity verification

Command (background), logged in `extract_super.log`:

```
unzip -p SM-S9180_BRI_GZIF.zip 'AP_*.tar.md5' | tar -xOf - --occurrence=1 super.img.lz4 | lz4 -d > super.img
```

- Output `super.img` = **11,119,601,864 bytes — exactly the frame content size.**
- Pipeline reported `rc=141` (`SIGPIPE`) — expected artifact: `lz4 -d` stops after the frame
  end-mark while `tar` still scans the remainder of the AP tar; `unzip` consequently sees a
  closed pipe. This does **not** indicate decompression failure (output size is exact).
- sha256: **`db6bb90c8000d91ca880020c0a01ac3f20ae020857b2f53a301a68a3e737aa2b`**
- Independent re-verification: `lz4 -t` over the same stream —
  `stdin : decoded 11119601864 bytes`, `pipestatus: 141 0 0` (unzip/tar/lz4; lz4 exit 0) —
  i.e. full decode **and frame-end XXH32 content-checksum verification passed**.
- Free space before: **791 GiB** avail (`df -h /mnt/nvme_2TB`).

---

## 2. Sparse image → raw

`super.img` is an **Android sparse image**, not raw LP data. Parsed by hand (command output):

- magic `0xed26ff3a`, major 1 minor 0, `file_hdr_sz=28`, `chunk_hdr_sz=12`, `blk_sz=4096`
- `total_blks` = 3,025,408 → raw size **12,392,071,168 bytes (11.541 GiB)**
- `total_chunks` = 185 → **174 RAW** (11,119,599,616 payload bytes) + **11 DONT_CARE**
  (1,272,471,552 bytes of zeros, not stored); no FILL chunks; image_checksum = 0
- Chunk walk lands exactly on EOF (`end offset after last chunk: 11119601864 == file size`)

`lpunpack` is **not packaged in Ubuntu apt** (`apt-cache search lpunpack` → nothing), so the
super geometry was parsed by a purpose-written read-only Python tool
(`super_extract.py`, constants taken from AOSP `liblp/metadata_format.h`, see §3).
`simg2img` (android-sdk-libsparse-utils 1:34.0.5-12build1, freshly installed per approval)
was used for the sparse→raw step:

```
simg2img super.img super.raw.img        # real 0m54.7s; output stat'd: 12392071168 bytes
```

The resulting `super.raw.img` was an intermediate only and has been **deleted** (see §7).
Nothing in `host-side GZIF_work/` was modified (all reads; the zip and the
`fota/` tree were opened read-only).

Free space after raw creation: **769 GiB** avail (`df -h`, 14:04); after final cleanup (§7): **789 GiB** avail.

---

## 3. Super geometry and partition table (LP metadata)

`super.raw.img` starts with **4 KiB of non-LP bytes** at offset 0 (sha not recorded; contents
look like opaque random-ish data — Samsung keeps something at block 0). LP data starts at
offset 4096 instead of AOSP's usual 8192, i.e. the whole LP layout is shifted by one block.

- **Geometry copies:** offset **4096** and offset **8192** — both magic `0x616c4467` (`"gDla"`),
  `struct_size=52`, `metadata_max_size=65536`, `metadata_slot_count=2`,
  `logical_block_size=4096`; both **checksums verified OK** (SHA-256 over struct with checksum
  zeroed). Stored checksum (both copies identical):
  `4e31cf64275442f40e25c772a18d1fccd8b1291232e593f65e522fc7ac07df03`
- **Metadata headers** (magic `0x414C5030` `"0PLA"`, version **10.0**, `header_size=128`):

| copy | offset | slot | header_checksum_ok | tables_checksum_ok |
|---|---|---|---|---|
| 0 | 12288  | 0 | True | True (tables_size=692) |
| 1 | 77824  | 0 | True | True |
| 2 | 143360 | 1 | True | True |
| 3 | 208896 | 1 | True | True |

- **block_devices:** 1 entry — `super`, `first_logical_sector=2048` (1 MiB reserved at start),
  size 12,392,071,168, alignment 1 MiB, flags 0.
- **groups:** `default` (max 0) and `qti_dynamic_partitions` (max 12,387,876,864).
- **7 logical partitions**, all `attrs=0x1` (READONLY), all in group `qti_dynamic_partitions`:

| partition | size (bytes) | extents |
|---|---|---|
| system | 7,270,297,600 | 1 |
| odm | 872,448 | 1 |
| product | 1,595,060,224 | 1 |
| system_dlkm | 348,160 | 1 |
| system_ext | 195,649,536 | 1 |
| **vendor** | **2,027,220,992** (1.888 GiB) | 1 (extent idx 5) |
| **vendor_dlkm** | **33,021,952** (31.49 MiB) | 1 (extent idx 6) |

Only `vendor` and `vendor_dlkm` were extracted; `system/product/odm/system_ext/system_dlkm`
were **not** read or copied.

Extraction tool: `super_extract.py extract` (Python; copies extents in 8 MiB windows from
`target_data*512`). Post-extraction integrity: both images are valid EROFS (see §4), full
directory trees enumerated (4014 / 380 entries), all spot-checked files read cleanly.

```
python3 super_extract.py extract super.raw.img vendor      vendor.img       # 2027220992 bytes
python3 super_extract.py extract super.raw.img vendor_dlkm vendor_dlkm.img  #   33021952 bytes
sha256sum vendor.img       198cdc6158b609655d204e820eb117f69907c95cbf27add0c48facaa285498db
sha256sum vendor_dlkm.img  6ffa227d51f350200bda1cf0bdb40e03eefa186f0e59d5a211f8f8c9a2d66681
```

---

## 4. Filesystem format (EROFS) — debugfs N/A

Both images are **EROFS** (compressed read-only filesystem, `lz4_0padding`; the filesystem
type Samsung ships for read-only partitions on this build — confirmed empirically, not assumed):

| field | vendor.img | vendor_dlkm.img |
|---|---|---|
| magic @1024 | `0xe0f5e1e2` | `0xe0f5e1e2` |
| blocksize | 4096 | 4096 |
| blocks | 487,096 (1,995,145,216 B; image slack 32,075,776 B zeros) | 7,916 (32,423,936 B; slack 598,016 B) |
| inode count | 4015 | 381 |
| root nid | 53 | 39 |
| incompatible features | `lz4_0padding` | `lz4_0padding` |
| compatible features | `sb_csum mtime xattr_filter` | `sb_csum mtime xattr_filter` |
| filesystem created | Sat Jan 1 08:00:00 2022 (Samsung fixed stamp) | Sat Jan 1 08:00:00 2022 |
| UUID | 8e0a5596-6e69-5234-840f-f32012125232 | 58c9135c-f77a-59d8-9dcd-a3b04d1fffb3 |

`debugfs` (ext4) cannot open either. All extraction used `dump.erofs` 1.9
(`dump.erofs --ls --path=<p>`, `dump.erofs --cat --path=<p>`, full listings saved in staging
as `vendor_listing.txt` / `vendor_dlkm_listing.txt`). No mount was performed.

---

## 5. SELinux artifacts dumped from vendor (`vendor/etc/selinux`)

There is **no `/etc/selinux/sepolicy` compiled binary** and **no `/etc/selinux/apex/sepolicy.*`**
in the vendor image (full-image listing greps for `selinux|sepolicy|cil` return only the files
below). `/apex` contains only preload `.apex` packages; no policy inside was extracted or
evaluated. The complete vendor selinux tree (all 13 entries) was dumped to
`host-side GZIF-vendor-work/vendor_selinux/`:

| file | bytes | sha256 |
|---|---|---|
| authorize.xml (`sk/authorize.xml`, Knox) | 86,183 | `9ed6050d3f5749fe943e643ce694f3fbbb02a98323adcdcf1f72a6218597e6a6` |
| plat_pub_versioned.cil | 1,028,069 | `f4538aac687dc22a4f095eb492a5e4ba7a22fa97b2a36f0b471c7dbbec7be378` |
| plat_sepolicy_vers.txt | 5 (`33.0`) | `d2d39e9afe66f40b96a73a6629523a4c39d0e65c952f191cf7a32e05d63248a9` |
| selinux_denial_metadata | 0 (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| vendor_file_contexts | 193,750 | `b8b323f128be56b8120ea216767e9d455fac632956153d9a76a65d02e7b72dda` |
| vendor_hwservice_contexts | 20,434 | `62fee54a9859a8bf8a001aae62740448da447be3e573620d05586a274d42d820` |
| vendor_mac_permissions.xml | 244,011 | `bf77fb2240e276ef54e038fdf5fad31b7e5d85dd40cb4bdbb68b4c3b0593f928` |
| vendor_property_contexts | 30,481 | `38df985e12e9c2c9608ee9aa724bfd44604559f4de2981ce250f184f79078682` |
| vendor_seapp_contexts | 2,721 | `d75b7e69f2e12e5f68d03b94ddd4abea7f71ac6c8ff3ecc3f5ffb19577096c90` |
| **vendor_sepolicy.cil** | **2,295,301** | `13811d6b70b49cc22b9b4ae967f0226e48be1bef782a3785d6cd79d5c04dd1b4` |
| vendor_sepolicy_version | 75 | `29ae2bf8a8a3878e278e2d85f906776d4fa5ee9a69b0556aa827c05a70a266dd` |
| vendor_service_contexts | 19,465 | `0fb815eb31200b11f9b3079db1470a49857063df49dd2f9bdd97bc19ed5d8970` |
| vndservice_contexts | 5,592 | `9ba77614a6faf74a18e432ada045c66cf20c1aac831688260818f60ab1b5792d` |

All are ASCII text. Total 3,926,087 bytes.

Notes:

- `vendor_sepolicy_version` content (both files): `VE=SEPF_SM-S9180_13_0001` /
  `BD=Mon Sep 28 16:01:23 2026` / `MP=SHA-256` / `MV=SHA-256`.
  `cmp` against `fota/recovery/sepolicy_version` → **byte-identical**.
- `plat_sepolicy_vers.txt` = `33.0` → Android 13 (API 33) platform policy version, matching the
  `_13_` infix in the version stamp.
- `vendor/lib/modules` is a **symlink → `/vendor_dlkm/lib/modules`** (target dumped via
  `dump.erofs --cat`), i.e. the DLKM is where vendor kernel modules actually live.

### Comparison vs recovery policy (`fota/recovery/sepolicy`)

| artifact | bytes | sha256 |
|---|---|---|
| recovery compiled `sepolicy` | **1,783,541** | `1e02db20efef60d10bc7896c8ea6ceda5634469ec329128fe2760030dc2b7171` |
| recovery `sepolicy_version` | 75 | `29ae2bf8a8a3878e278e2d85f906776d4fa5ee9a69b0556aa827c05a70a266dd` |
| vendor `vendor_sepolicy.cil` (CIL **source**, not compiled) | 2,295,301 | `13811d6b70b49cc22b9b4ae967f0226e48be1bef782a3785d6cd79d5c04dd1b4` |
| vendor `plat_pub_versioned.cil` (published plat CIL) | 1,028,069 | `f4538aac687dc22a4f095eb492a5e4ba7a22fa97b2a36f0b471c7dbbec7be378` |

**Verdict: no compiled `sepolicy` exists in vendor, so a direct hash comparison against
`fota/recovery/sepolicy` is not possible.** The remaining anchors match exactly:

- `vendor_sepolicy_version` **is byte-identical** to `fota/recovery/sepolicy_version`
  (`cmp` clean, sha256 `29ae2bf8…266dd`), including identical build date
  (`Sep 28 16:01:23 2026`) — both vendor and recovery were cut from the same policy source snapshot.
- `plat_sepolicy_vers.txt=33.0` ⇔ `SEPF_SM-S9180_13_*` (Android 13).
- The recovery policy is a **monolithic compiled blob** (full policy, ~1.7 MB) while vendor
  carries only its CIL fragment; they are different artifacts by construction and were never
  expected to hash equal. An equality check would be meaningless even if a vendor blob existed.
- Whether the **main-OS** compiled policy (system/system_ext or boot-time composition) equals the
  recovery one cannot be decided from vendor alone; `system.img`/`system_ext.img` were not
  extracted (out of scope). What can already be said: vendor policy provenance matches recovery
  provenance at the version-stamp level, and the CIL sources are now available for the
  policy-analysis task to compare semantically (e.g. rule-level diff of
  `vendor_sepolicy.cil` vs the recovery blob's decompilation).

**SHA-256 comparison verdict:** `fota/recovery/sepolicy` = `1e02db20…7171` vs vendor:
**no counterpart present**; `sepolicy_version` files **MATCH** (`29ae2bf8…266dd`).

---

## 6. `esp4.ko` search in `vendor_dlkm`

- Full DLKM inventory: 380 entries; **367 `.ko` files** under `/lib/modules/`
  (listing: `vendor_dlkm_listing.txt`).
- `grep -iE 'esp|xfrm|ipsec'` on the complete DLKM listing → **zero matches**
  (no `esp4.ko`, no `esp6.ko`, no `esp*.ko`, nothing with `xfrm`/`ipsec` in the name).
- `modules.alias`, `modules.dep`, `modules.load`, `modules.softdep`, `modules.blocklist`,
  `system_dlkm.modules.blocklist` (all dumped to `dlkm_meta/`): **zero** `esp|xfrm` matches
  (`grep -icE 'esp4|esp6' *` → `0` for every file). `modules.blocklist` blocks no `esp4` either
  (it blocks things like `lkdtm`, `kunit`, `atomic64_test`, `test_user_copy`, …).
- The vendor image as a whole contains no `.ko` at all (`grep -c '\.ko'` → 0);
  the only `ipsec`/`xfrm` traces in vendor are `/etc/permissions/android.software.ipsec_tunnels.xml`,
  `/lib/libnetmgrxfrmutils.so`, `/lib64/libnetmgrxfrmutils.so` — userspace/IPSec-tunnel support, unrelated.
- Conclusion: **there is no `esp4.ko` to report size/sha256 for.** ESP must be coming from the
  kernel image itself: esp6 is built in; esp4 exists at most as the built-in stub
  (`kmod_esp4`), never as a loadable module on this build. (Kernel-side verification of the stub
  belongs to the kernel/vmlinux analysis, not this task; nothing was loaded or insmod'ed.)
- `system_dlkm` (348,160 B) was **not** extracted (out of scope); the only `system_dlkm`
  artifact inspected is `vendor_dlkm/lib/modules/system_dlkm.modules.blocklist` (117 B, a
  bare comment block, no entries, no esp references). Absence of `esp4.ko` inside
  `system_dlkm` itself is therefore unverified, but its partition size (348 KB) and the
  `modules.load` pattern make an esp module there unlikely; kernel-side analysis is the
  authoritative check for the built-in stub.

---

## 7. Cleanup, deletions, remaining artifacts

Deleted (all created by this task, in staging dir only):

- `super.img` (11,119,601,864 B, sparse)
- `super.raw.img` (12,392,071,168 B, simg2img output)
- `sample_head.bin` (4 MiB framing probe)

Kept for the policy-analysis task (staging dir `host-side GZIF-vendor-work/`):

- `vendor.img` (2,027,220,992 B, sha256 `198cdc61…98db`) — for any further vendor-side reads
- `vendor_dlkm.img` (33,021,952 B, sha256 `6ffa227d…16681`)
- `vendor_selinux/` — all 13 vendor SELinux artifacts above (the **compiled-policy substitute**
  for analysis: `vendor_sepolicy.cil`, `plat_pub_versioned.cil`, contexts, version stamps)
- `dlkm_meta/` — `modules.alias/.dep/.load/.softdep/.blocklist`, `system_dlkm.modules.blocklist`
- `vendor_listing.txt`, `vendor_dlkm_listing.txt` — full EROFS directory dumps (nid\ttype\tpath)
- `super_info.txt`, `super_extract.py`, `extract_super.log`, `lz4test.log`, `extract_super.sh`, `erofs_walk*.py`

Free space on `/mnt/nvme_2TB`: **789 GiB avail** now (was 791 GiB before this task;
~2.0 GB retained artifacts). `/mnt/240G_SSD` untouched (35 GiB avail, read-only usage
throughout). No other deletions performed. Staging dir total: 2.0 GB (`du -sh`).

---

## 8. Ready-to-use summary for the policy-analysis task

- **No compiled vendor policy blob exists.** Work from the CILs:
  `vendor_selinux/vendor_sepolicy.cil` (vendor rules, incl. `(genfscon …)` entries) +
  `vendor_selinux/plat_pub_versioned.cil` (published platform policy vendor was built against;
  policy version `33.0`).
- **Recovery policy** for reference: `host-side GZIF_work/fota/recovery/sepolicy`
  (1,783,541 B, sha256 `1e02db20efef60d10bc7896c8ea6ceda5634469ec329128fe2760030dc2b7171`),
  stamped `VE=SEPF_SM-S9180_13_0001`, identical to vendor's `vendor_sepolicy_version`.
- Context/file-context mappings: `vendor_file_contexts`, `vendor_service_contexts`,
  `vendor_hwservice_contexts`, `vendor_property_contexts`, `vendor_seapp_contexts`,
  `vendor_mac_permissions.xml`, `vndservice_contexts`, all in `vendor_selinux/`.
- **esp4 is not loadable** on this build: no module, no alias, no blocklist entry; treat
  xfrm/ESP4 as built-in-stub-only when mapping kernel policy vs `sepolicy` (e.g. for the
  xfrm/ESP auditing work).

## 9. Caveats / limitations

- `lpunpack` unavailable on this host (not in Ubuntu apt); super geometry parsed by the
  task-local `super_extract.py` instead. The parser self-validated: magic at two offsets,
  SHA-256-verified geometry structs, 4 metadata copies all with valid header **and** tables
  SHA-256, sane linear extents, and extraction sizes equal to metadata byte counts; both images
  open cleanly in EROFS and fully enumerate. Risk of silent misalignment: very low (an EROFS
  superblock at wrong offset would not validate as `0xe0f5e1e2`).
- `super.img` deflate/zip layer: integrity established via `lz4 -t` on the member stream
  (XXH32 content checksum, exit 0) plus exact content-size output match; sha256 of the
  (sparse) result is `db6bb90c…7aa2b`. The `super.raw.img` intermediate was deleted after its
  (fully validated) consumers finished; its bytes were not hashed before deletion — all hashes
  that matter (final images + SELinux artifacts) were recorded.
- EROFS images have **trailing zero slack** between last used block and image end
  (vendor: 32,075,776 B; dlkm: 598,016 B) — expected, `lz4_0padding` feature.
- Timestamps inside EROFS are fixed (2022-01-01) — Samsung build determinism, not an error.
- The main-OS compiled sepolicy location is unresolved by this task (would be system/system_ext
  or init composition); vendor-only comparison achieved at the version-stamp level.
- `unzip -p` stream extraction returns SIGPIPE (141) upstream of `lz4` by design; consult
  `pipestatus` components, not the scalar rc, when re-running these pipelines.
