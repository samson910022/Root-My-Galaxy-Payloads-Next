# Galaxy S24 SM-S9210 (S9210ZHU6EZIF) payload — CANDIDATE / EXPERIMENTAL

> **Status: candidate / experimental. Not promoted to stable/production-ready.**
> This profile is ported for validation/testing use with explicit opt-in expectations at the app/feed consumer layer. Do not treat as broadly validated.

Exact firmware profile for the Galaxy S24 (China, `e1q` / `e1qzhx`) on firmware
`S9210ZHU6EZIF` (`samsung/e1qzhx/qssi_64:17/CP2A.260605.016/S9210ZHU6EZIF:user/release-keys`),
kernel `6.1.162-android14-11-34343818-abS9210ZHU6EZIF`.

## Provenance (ported artifacts)

Ported from our validated custom payload work (read-only sources, compared for canonical/best artifacts):
- `samson910022/Root-My-Galaxy-Payloads` branch `feature/e1q-S9210ZHU6EZIF-port` @ `75a26a9` (includes integrated `8cf29d9`, EZIF adoption/validation commits such as `d467222`, `45c9741`, etc.)
- `samson910022/Root-My-Galaxy-Payloads-fork` `main@8cf29d9` and `origin/feature/e1q-S9210ZHU6EZIF-port` (artifact/doc parity verified; hashes identical for ported files)

Artifact identity in this repo matches the source snapshot above (no rebuild performed in this migration phase).

## Files

| File | Size (bytes) | SHA-256 | Notes |
| --- | ---: | --- | --- |
| `cve-2026-43499-app.so` | 104128 | `efc8b49caa9129539645689479eaa55b7aa0059e621997beee375a8a1a86a538` | EZIF app payload (`TARGET=e1q-S9210ZHU6EZIF`, NDK r29 lineage per docs) |
| `../../kernelsu/ksud-e1q-S9210ZHU6EZIF-kdp` | 5065680 | `fde99b5a129e5714fe6f598cf8276c76d2cbaf1a7f4e6ce9ae69d5ebca0abe61` | Primary feed loader (KernelSU v3.3.1 candidate lineage as recorded in validation docs) |
| `../../kernelsu/android14-6.1_kernelsu-e1q-S9210ZHU6EZIF-kdp.ko` | 432656 | `af640cdae6a9414dfe7b2eebe60e0d3e428b8f26862c14c7348f88e7a3863e4a` | Paired v3.3.1-candidate KDP module |
| `../../kernelsu/ksud-e1q-S9210ZHU6EZIF-v3.3.0-kdp` | 4993656 | `bc7399a38f4e78471f32f7bded3c9788f26132b22768051c5a783ef7501903e8` | Fallback loader (v3.3.0 lineage), retained for provenance/rollback testing |
| `../../kernelsu/android14-6.1_kernelsu-e1q-S9210ZHU6EZIF-v3.3.0-kdp.ko` | 406160 | `3f3e558ba808eb67566fd97fa5a70aaed50f4739fc5c75d124d5447b011872bc` | Paired v3.3.0 fallback KDP module |

## KernelSU pairing

- **Feed/default reference in this port:** `kernelsu/ksud-e1q-S9210ZHU6EZIF-kdp` (v3.3.1-candidate line used in recorded EZIF validation). Matching `.ko` is provided in-repo.
- **Fallback retained:** `kernelsu/ksud-e1q-S9210ZHU6EZIF-v3.3.0-kdp` (+ paired `.ko`) for provenance and controlled fallback experiments; not referenced by the primary feed entry.

## Validation scope and known limitations (summary)

Evidence is **limited and device/boot-context sensitive**; do not infer broad reliability.

- Historical/partial validation records exist (see `docs/SM-S9210-S9210ZHU6EZIF.md`, `docs/SM-S9210-EZIF-validation-20261102.md`), but **repeatability is not established** as a stable success rate across conditions.
- **Reboot persistence:** not expected/persistent for RAM-only/LKM-style temporary root paths; post-reboot root absence was observed in recorded checks (expected). Re-exploitation after reboot is required.
- **Daemon/byte-identity caveats:** recorded validations note unresolved or non-provable byte-identity between APK-bundled/staged/on-device daemon bytes in some runs (version strings/packages alone do not prove executing bytes). Treat provenance carefully.
- **Diagnostics/UI/app-vs-adb differences:** investigation history includes panic/clean-miss analysis and differing behaviors across app transports/contexts in some records; full matrix pending.
- **Artifact lineage:** source history distinguishes snapshot vs later heads in places; this repo ports the artifact set above with hashes recorded here. Validation docs may reference earlier snapshot hashes (e.g. `58a6772`-era exploit) — read as historical context, not as this repo's current artifact hash.

## Usage notes

- Target is firmware/kernel-specific: SM-S9210 `S9210ZHU6EZIF`, kernel `6.1.162-android14-11-34343818-abS9210ZHU6EZIF`.
- Treat as experimental; require explicit user opt-in/candidate gating in consuming apps where supported.
- Temporary root behavior and volatility follow the underlying exploit/runtime model; verify on-device with appropriate safeguards.
