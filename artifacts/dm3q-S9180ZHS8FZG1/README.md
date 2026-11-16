# Galaxy S23 Ultra SM-S9180 (S9180ZHS8FZG1) payload

Exact firmware profile for the Galaxy S23 Ultra (Taiwan / Hong Kong / China, `dm3q` / `dm3qzhx`) on firmware
`S9180ZHS8FZG1` (`samsung/dm3qzhx/dm3q:16/BP4A.251205.006/S9180ZHS8FZG1`),
kernel `5.15.189-android13-8-33413713-abS9180ZHS8FZG1`.

## Hardware evidence

The full chain completed on real hardware: tracefs KASLR discovery, controlled
32-object `mm_struct` collection, shaped order-3 SKB reclaim, the MCAST waiter writer,
fake ashmem fops, configfs arbitrary read/write, pipe physical read/write (physrw),
root usermode helper, and KernelSU late-load. The run reported
`done=1 root=1 uid=2000->0`, KernelSU loaded and verified, and `su -c id` returned
`uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0` with SELinux Enforcing.

## Files

| File | SHA-256 | Notes |
| --- | --- | --- |
| `cve-2026-43499-app.so` | `04d9e0e4b5c547791c0035a85cc89b58bba60f673a8f759e8f5f106ab4023690` | PI-guard rebuild (`make TARGET=dm3q-S9180ZHS8FZG1`, Android NDK r29), 137544 bytes |
| `cve-2026-43499-root` | `c49a655708bed646441f6a7d848c5a400e6fb444f7fcf05fcb0704e547ddcd55` | Root helper, 27264 bytes |
| `../../kernelsu/ksud-dm3q-S9180ZHS8FZG1-kdp` | `aab769430467e5a9f723c1bc8a3180e6fb0b0b82c52fba7b99887199407fc940` | Preferred/proven FZG1-specific KernelSU loader, 5101488 bytes |

## KernelSU loader

Preferred loader: `kernelsu/ksud-dm3q-S9180ZHS8FZG1-kdp` (SHA-256
`aab769430467e5a9f723c1bc8a3180e6fb0b0b82c52fba7b99887199407fc940`, 5101488 bytes).
This is a device-validated FZG1-specific v3.3.0 loader sourced from the validated
Root-My-Galaxy-S23U bundle/device capture for SM-S9180 `S9180ZHS8FZG1`
(`su -v` = `3.3.0:KernelSU`, `su -V` = `32601`, `ksud 3.3.0 (uapi: 2)`).

Historical context: earlier FZG1 bring-up/validation reused the S918B 5.15 loader
`kernelsu/ksud-dm3q-S918BXXSAFZF5-kdp`
(SHA-256 `5da5818d36da2d589496f91016078a43f50489e5c98b319db4eaa5ee475b86bd`)
and documented that no independent FZG1 ksud had been published at the time.
That reuse record remains historically accurate, but the FZG1-specific v3.3.0 loader
above is now the proven/preferred artifact for this firmware profile.

## Build

```sh
make TARGET=dm3q-S9180ZHS8FZG1 ANDROID_NDK_HOME=/path/to/android-ndk-r29
```

## Usage notes

- Run soon after boot (ideally after uptime reaches 120s for the boot quiet window).
- Uses shaped order-3 SKB slab reclaim and controlled 32-object mm_struct collection
  (`S918_KSNITCH_FULL_COLLISIONS 4`), single-attempt per boot.
- Temporary root is volatile; all changes disappear cleanly upon reboot.
