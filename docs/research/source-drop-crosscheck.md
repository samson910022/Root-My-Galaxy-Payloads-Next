# SM-S9180 (GZIF) Samsung OSS source-drop cross-check — 2026-11-17

**Task:** Locate Samsung's public OSS kernel drop matching the GZIF build of
`SM-S9180` (`S9180ZHU8GZIF`, kernel `5.15.197-android13-8-34343818-abS9180ZHU8GZIF`,
built 2026-09-28, SPL 2026-10-05, CL 34344539) and cross-check `net/ipv6/esp6.c`
(`skb_has_shared_frag` guard in the input fast path), `kernel/locking/rtmutex.c`
(`remove_waiter()`), and `fs/exec.c` (`begin_new_exec()` ordering) against the binary
triage in `docs/SM-S9180-S9180ZHU8GZIF.md`.

**Bottom line (2026-11-17):** There is **no GZIF drop for SM-S9180** (HKTW or CHN) on
opensource.samsung.com. The **GZIF-wave international drop for the same dm3q device,
`SM-S918B_17_Opensource.zip` (build `S918BXXUAGZIF`, 641.37 MB), IS published** and is the
closest thing to a GZIF kernel source that exists today. It was **not downloaded or
extracted** because the site vends files only behind an inline legal-agreement
"Agree" click-through, which exceeds this task's hard constraint (read-only GETs only).
The three source-level checks therefore remain **UNVERIFIED against Samsung source**;
the binary evidence from `docs/SM-S9180-S9180ZHU8GZIF.md` §3 stands alone.

---

## 1. Search evidence (Task 1)

All site access below was performed 2026-11-17 with `curl` (Linux, from this host).
The site sits behind Cloudflare; anonymous `GET` works with a browser User-Agent.
Two modal endpoints (`/downSrcMPop`, `/downAnnMPop`) are POST-only XHRs that the
browser itself issues on "Source"/"Announcement" click; they were queried exactly as
the site's own JavaScript does (same CSRF token as the page; session cookie; no
credentials). Pagination (`page=2`) likewise requires the site's form POST; the
plain GET serves page 1 only. These were used **read-only**: no forms were submitted,
no agreement was accepted, nothing was uploaded or created server-side.

### 1.1 `GET https://opensource.samsung.com/uploadSearch?searchValue=SM-S9180`

HTTP 200, "14 of results found" (10 on page 1, 4 on page 2 — `gotoPage('2')` submits
the search form POST with `page=2`; result page saved verbatim in session scratch
`/mnt/240G_SSD/opencode_tmp/oss_search_s9180.html` / `oss_p2.html`; search string
results identical to what the live page shows):

| uploadId | Version(s) | File(s) — size |
| --- | --- | --- |
| **14326** | S9180ZHU7FZDP, S9180ZHS8FZE3, S9180ZHS8FZF5, **S9180ZHS8FZG1** | `SM-S9180_HKTW_16_Opensource.zip` — 639.10 MB (670,141,198 B; attachId 48412); `…_S9180ZHS8FZH3.zip` — 16.31 KB (16,699 B; attachId 48413); `…_S9180ZHS8FZI1.zip` — 250.22 KB (256,224 B; attachId 48414); site total 639.36 MB |
| **14323** | S9180ZCU7FZDP, S9180ZCS8FZE3, S9180ZCS8FZF5, **S9180ZCS8FZG1** | `SM-S9180_CHN_16_Opensource.zip` — 639.30 MB; `…_S9180ZCS8FZH3.zip` — 16.30 KB; `…_S9180ZCS8FZI1.zip` — 250.20 KB; `…_S9180ZCS8FZJ1.zip` — 345.02 KB (CHN-only delta); site total 639.89 MB |
| 13465 | S9180ZHU6EYI5 | `SM-S9180_HKTW_16_Opensource.zip` — 637.29 MB; deltas EYJ5/EYK3/EYL1 (4.18 KB), EZA1 (191.59 KB), EZB6 (321.09 KB), EZC1 (391.23 KB), EZCI (404.86 KB); total 638.57 MB |
| 13466 | S9180ZCU6EYI6 | `SM-S9180_CHN_16_Opensource.zip` — 637.02 MB; same EY/EZ deltas; total 638.30 MB |
| 13039 | S9180ZHU6DYD9, S9180ZHS6DYDB, S9180ZHS6DYF1 | `SM-S9180_HKTW_15_Opensource.zip` — 635.28 MB; deltas DYG1/DYG5/DYI3; total 635.53 MB |
| 13103 | S9180ZCU6DYDA, S9180ZCS6DYDB, S9180ZCS6DYF1 | `SM-S9180_CHN_15_Opensource.zip` — 635.14 MB; deltas DYG1/DYH4; total 635.24 MB |
| 14307 | S9180ZHU5CXK1 | `SM-S9180_HKTW_14_Opensource.zip` + deltas CXL1/CYA1, CYB1, CYC1 |
| 14306 | S9180ZHU2CXCF, S9180ZHS2CXD1 | `SM-S9180_HKTW_14_Opensource.zip` + deltas CXE3, CXF1, CXG2, CXH2 |
| 12760 | S9180ZHU4CXI1 | `SM-S9180_HKTW_14_Opensource.zip` + delta CXJ1 |
| 12064 | S9180ZHU2BWK7, S9180ZHS2BWL1 | `SM-S9180_HKTW_14_Opensource.zip` + deltas BXA1, BXAF |
| 14299 | S9180ZCU5CXK1 | `SM-S9180_CHN_14_Opensource.zip` + deltas CXL1/CXL2, CYB2, CYC1 |
| 14294 | S9180ZCU4CXI2 | `SM-S9180_CHN_14_Opensource.zip` + delta CXJ1 |
| 12397 | S9180ZCU2CXCF, S9180ZCS2CXD1 | `SM-S9180_CHN_14_Opensource.zip` + deltas CXE3, CXG2, CXH2 |
| 12062 | S9180ZCU2BWK7, S9180ZCS2BWL1 | `SM-S9180_CHN_14_Opensource.zip` + delta BXA2/BXA4 |

**No entry for `S9180ZHU8GZIF`, `S9180ZCU8GZIF`, `S9180OZS8GZIF`, `FZG1`-superseding
`GZ*`, or any `_17_` SM-S9180 release exists.** The newest SM-S9180 PDA referenced
anywhere on the site is `S9180ZCS8FZJ1` (CHN delta of uploadId 14323) and
`S9180ZHS8FZI1` (HKTW delta of uploadId 14326).

Companion searches (plain GET, 2026-11-17):

- `searchValue=S9180ZHU8GZIF` → "0 of results found"
- `searchValue=S9180ZHU8` → "0 of results found"
- `searchValue=SM-S9180_17` → "0 of results found"
- `searchValue=GZIF` → "3 of results found" (international GZIF wave only, see §1.2)

### 1.2 The GZIF wave *is* on the site — for the international (B-series) models

`searchValue=GZIF` returns exactly three uploads (all Android 17 / One UI 9.0, SPL
2026-10-05, firmware built 2026-09-28, the same GZIF wave as the target build):

| uploadId | Model | Version | File | Size | Announcement attachId |
| --- | --- | --- | --- | --- | --- |
| **14348** | SM-S918B | **S918BXXUAGZIF** | `SM-S918B_17_Opensource.zip` — attachId 48675 | **641.37 MB** (672,530,285 B) | 48676 |
| 14349 | SM-S916B | S916BXXUAGZIF | `SM-S916B_17_Opensource.zip` — attachId 48678 | 641.16 MB (672,301,288 B) | (not fetched) |
| 14350 | SM-S911B | S911BXXUAGZIF | `SM-S911B_17_Opensource.zip` — attachId 48681 | 641.42 MB (672,580,936 B) | (not fetched) |

`SM-S918B` is the **same dm3q / Snapdragon 8 Gen 2 (kalama) hardware** as SM-S9180;
only the regional PDA/CSC assignment differs (B = international, BRI/TGY = HK/TW/CN).
Evidence that S918BXXUAGZIF is the same GZIF wave: third-party firmware trackers list it
as Android 17 / One UI 9.0, SPL **2026-10-05**, built **2026-09-28** — the exact SPL and
build date as the target S9180ZHU8GZIF (samdb.org model page, release 2026-10-02;
sammobile.com SKZ entry "built on 28 September 2026, carries the 2026-10-05 Android [SPL]";
samfirms.com lists 2026-10-20..25 dates; samfrew.com shows "Kernel 5.15.197-…" for the
S9180 GZIF firmware). The `SM-S918B_17_Opensource.zip` filename is also identical in
shape to the SM-S9180 `_16_` drops that covered the same platform.

This is the only GZIF-wave kernel source published for the dm3q platform right now, but
it is **not** the S9180 S9180ZHU8GZIF build's own drop; whether its kernel is
bit-identical to S9180ZHU8GZIF's `5.15.197-…-34343818-abS9180ZHU8GZIF` (same common-kernel
CL 34343818, or a sibling CL) is **UNVERIFIED** — the drop cannot be opened without
downloading it (§2).

Publication dates are **not shown anywhere** on the site (no date column in results;
the announcement modal contains only a `NOTICE.html` file — 9.97 MB for uploadId 14326 —
with no dates; verified for 14326 via `/downAnnMPop`). Drop dates are therefore
**UNVERIFIED** throughout; only firmware release dates are third-party confirmed.

### 1.3 Drop naming and layout of the newest S9180 drops (FZG1/FZF5-era, for cadence)

Pattern observed on the site: one **base** `SM-S9180_<region>_<android>_Opensource.zip`
per platform/major-Android generation, plus one **delta** zip per subsequent build
(`<base>_<PDA>.zip`, tens–hundreds of KB). Deltas contain the per-build kernel and
defconfig/Kconfig changes. The FZG1 build (`S9180ZHS8FZG1`, SPL 2026-07-05, device-verified
in this repo 2026-09-29) is itself inside the HKTW_16 base drop — i.e., Samsung did
**not** publish a separate drop per build; base drops accumulate multiple builds.

Caveats/gaps observed:
- The **CHN** line carries one delta (FZJ1) that **HKTW** does not (HKTW latest delta = FZI1) — China shipped a newer build earlier.
- The HKTW_16 drop lists base versions `S9180ZHU7FZDP, S9180ZHS8FZE3, S9180ZHS8FZF5, S9180ZHS8FZG1` — its kernel version is **UNVERIFIED** (drop not downloaded); the public BuSung-dev issue tracker pins `S9180ZCS8FZE3` at `5.15.189-android13-8-3251900-abS9180ZCS8FZE3` (github.com/BuSung-dev/Root-My-Galaxy issue #24, fetched 2026-11-17), so the base is likely ≥ 5.15.189 and pre-dates GZIF's 5.15.197.

### 1.4 Exact URLs (record copies)

- Search (page 1): `https://opensource.samsung.com/uploadSearch?searchValue=SM-S9180` — HTTP 200
- Search (page 2): same endpoint, `page=2` form field (POST; site pagination) — HTTP 200
- `https://opensource.samsung.com/uploadSearch?searchValue=GZIF` — HTTP 200, 3 results
- `https://opensource.samsung.com/uploadSearch?searchValue=S9180ZHU8GZIF` / `SM-S9180_17` — 0 results
- File listing modal (XHR the browser fires on "Source" click): `POST https://opensource.samsung.com/downSrcMPop` (form field `uploadId`) — returns file list + sizes; anonymous, session-CSRF-bound
- File download entry: `POST https://opensource.samsung.com/downSrcCode` (form `attachIds` + `downloadPurpose` + `_csrf`) after the user clicks **Agree** on the inline license — **not performed** (see §2)
- Release-center listing: `https://opensource.samsung.com/uploadList?menuItem=mobile`
- Announcement modal (NOTICE attach): `POST https://opensource.samsung.com/downAnnMPop` (fields `uploadId`, `attachId=48676` for SM-S918B GZIF)
- Third-party firmware confirmations: samdb.org/model/SM-S9180 (GZIF released 2026-09-29); samfirms.com/firmware/SM-S9180/TWN (2026-10-25); samfrew.com (kernel 5.15.197…, Android 17, SPL 2026-10-05); xdaforums.com BeyondROM v7.0 thread ("[3/11/2026]-[GZIF] … S91xBXXUAGZIF … OneUI9 … October 2026 Patch"); samfirm.shop October 2026 bulletin (SM-S9180 GZIF, 2026-10-22)

Total files per download must be ≤ 1 GB ("Total downloads must not exceed 1GB", printed
in the modal); the 641 MB S918B drop is fine.

---

## 2. Task 2 — download and source-level verification: NOT DONE (blocked, by constraint)

**What exists:** one GZIF-matching source drop — `SM-S918B_17_Opensource.zip`
(641.37 MB ≤ 3 GB) — see §1.2. No `SM-S9180`-specific GZIF drop exists at all, so the
S9180-matching criterion of Task 2 is unmet outright.

**Why the S918B drop was not downloaded:** opensource.samsung.com does not publish
direct GET URLs for the files. The only documented path is:

1. `POST /downSrcMPop` (modal listing — done, read-only), then
2. `POST /downSrcCode` with `attachIds`, `downloadPurpose`, `_csrf` — submitted **only
   after the user clicks "Agree"** on the inline Samsung OSS legal agreement (the modal
   shows the license text and an optional "purpose" radio list).

Step 2 is (a) a non-GET action and (b) a legal assent entered on the user's behalf.
Both exceed this task's hard constraints ("read-only GETs only; no uploads. No
credentials.") and the authorization I was given. It is also the kind of act a user
should perform themselves (and, if they intend to redistribute the extracted files or
patches, may have license implications they should choose to accept).

**What was verified instead (upstream baselines, already fetched into this host's
reference tree `/mnt/240G_SSD/opencode_tmp/GZIF_work/ref/`):**

### (a) `net/ipv6/esp6.c` — input fast-path `skb_has_shared_frag` guard

Upstream `v5.15.197` (`ref/esp6_5197.c:961-972`) — the guard is **ABSENT**:

```c
961  if (!skb_cloned(skb)) {
962      if (!skb_is_nonlinear(skb)) {
963          nfrags = 1;
965          goto skip_cow;
966-     } else if (!skb_has_frag_list(skb)) {
967          nfrags = skb_shinfo(skb)->nr_frags;
968          nfrags++;
970          goto skip_cow;
971      }
972  }
```

Upstream `v5.15.205` and `v5.15.212` (`ref/esp6_5205.c:971-972`, `ref/esp6_5212.c:971-972`)
— identical except the fixed condition:

```c
971      } else if (!skb_has_frag_list(skb) &&
972             !skb_has_shared_frag(skb)) {
```

Samsung's GZIF binary has **no** `skb_has_shared_frag` test on this path (binary
evidence: `docs/SM-S9180-S9180ZHU8GZIF.md` §3, CVE-2026-43284 row — `esp6_input` at
`0xffffffc00954c888`). Consistent with the 5.15.197 upstream baseline it was built
from, and with SMR bookkeeping (43284 fixed only in SMR-NOV-2026, after GZIF was cut).
**Samsung-drop verdict: UNVERIFIED** (expected ABSENT — i.e. vulnerable; would fully
corroborate the binary if confirmed).

### (b) `kernel/locking/rtmutex.c` — `remove_waiter()`

Upstream `v5.15.197` (`ref/rtmutex_5197.c:1504-1516`) — **pre-fix** shape (`current->pi_lock`,
no `waiter->task` load, no NULL early return):

```c
1504  static void __sched remove_waiter(struct rt_mutex_base *lock,
1505                                    struct rt_mutex_waiter *waiter)
...
1513      raw_spin_lock(&current->pi_lock);
1514      rt_mutex_dequeue(lock, waiter);
1515      current->pi_blocked_on = NULL;
1516      raw_spin_unlock(&current->pi_lock);
```

Upstream `v5.15.212` (`ref/rtmutex_5212.c:1506-1522`) — **fixed** shape Samsung's binary shows:

```c
1506  static void __sched remove_waiter(struct rt_mutex_base *lock,
1507                                    struct rt_mutex_waiter *waiter)
1508  {
1511      struct task_struct *waiter_task = waiter->task;
1514      lockdep_assert_held(&lock->wait_lock);
1515
1516      if (!waiter_task) /* never enqueued */
1517          return;
1519      raw_spin_lock(&waiter_task->pi_lock);
1520      rt_mutex_dequeue(lock, waiter);
1521      waiter_task->pi_blocked_on = NULL;
1522      raw_spin_unlock(&waiter_task->pi_lock);
```

(Binary: `remove_waiter` at `0xffffffc0096f7474` loads `waiter->task` at +0x30,
early-returns on NULL, locks `waiter_task->pi_lock` at +0x884 — CVE-2026-43499 is
**patched** in GZIF, i.e. Samsung backported the upstream fix into this kernel
regardless of the 5.15.197 base tag.)
**Samsung-drop verdict: UNVERIFIED** (expected PRESENT, fixed — corroborating binary).

### (c) `fs/exec.c` — `begin_new_exec()` ordering

Identical between `v5.15.197` and `v5.15.212` (`ref/exec_5197.c`, `ref/exec_5212.c`;
campaign doc verified diff = 0). Quoted from `v5.15.197` (`ref/exec_5197.c:1293-1303`):

```c
1293  retval = exec_mmap(bprm->mm);      /* exec_mmap @ line 976 */
1294  if (retval)
1295      goto out;
1297  bprm->mm = NULL;
1299  #ifdef CONFIG_POSIX_TIMERS
1300      spin_lock_irq(&me->sighand->siglock);
1301      posix_cpu_timers_exit(me);      /* AFTER exec_mmap — pre-fix ordering */
1302      spin_unlock_irq(&me->sighand->siglock);
       …
1309  retval = unshare_sighand(me);
```

Fixed ordering (posix_cpu_timers_exit before exec_mmap) exists only in ≥ 6.1.171/6.6.158
(2026-10-03); **no 5.15 stable fix exists**. Binary (`begin_new_exec` at
`0xffffffc0084cabd4`) shows `exec_mmap` → `posix_cpu_timers_exit` — vulnerable ordering.
**Samsung-drop verdict: UNVERIFIED** (expected AFTER exec_mmap, i.e. vulnerable —
corroborating binary).

### Not checked / not downloaded

- `net/ipv4/esp4.c` — not present to check (no download). (Binary notes `esp4` is a kmod
  in GZIF; `esp6` is built-in, which is what §3 of the campaign doc triages.)
- `.config` / `include/config/kernel.release` / `utsrelease.h` of the Samsung tree —
  would confirm the exact release string `5.15.197-android13-8-34343818-abS918BXXUAGZIF`
  (expected sibling) or `…-abS9180ZHU8GZIF` — UNVERIFIED.
- Any out-of-band Samsung cherry-picks (e.g. for 43284 or 98260) — undetectable without
  the drop.

`/mnt/240G_SSD/opencode_tmp/GZIF_work/src-drop/` was **not created**; zero bytes of
Samsung source were downloaded. A partial download does not exist.

---

## 3. Task 3 — no GZIF-matching SM-S9180 drop exists: explicit statement + newest drops

**Explicit: as of 2026-11-17 there is no Samsung OSS release for `S9180ZHU8GZIF` (nor
`S9180ZCU8GZIF`) on opensource.samsung.com.** The newest SM-S9180 kernel/source drops are:

1. `SM-S9180_HKTW_16_Opensource.zip` (+ FZH3/FZI1 deltas) — uploadId **14326** — covers
   PDA `S9180ZHU7FZDP, S9180ZHS8FZE3, S9180ZHS8FZF5, S9180ZHS8FZG1`; 639.10/16.31 KB/250.22 KB;
   site total 639.36 MB. URL: `https://opensource.samsung.com/uploadSearch?searchValue=SM-S9180`
   (page 1, first row) / modal `POST /downSrcMPop` with `uploadId=14326`.
2. `SM-S9180_CHN_16_Opensource.zip` (+ FZH3/FZI1/**FZJ1** deltas) — uploadId **14323** — covers
   PDA `S9180ZCU7FZDP, S9180ZCS8FZE3, S9180ZCS8FZF5, S9180ZCS8FZG1`; total 639.89 MB.
3. (Previous cycle) `SM-S9180_HKTW_15_Opensource.zip` (uploadId 13039, 635.53 MB;
   DYD9/DYDB/DYF1) and `SM-S9180_CHN_15_Opensource.zip` (uploadId 13103, 635.24 MB).
4. The GZIF wave exists only as the **international B-series** drops: `SM-S918B_17_Opensource.zip`
   (uploadId **14348**, 641.37 MB, build `S918BXXUAGZIF`), `SM-S916B_17_Opensource.zip`
   (14349, 641.16 MB, `S916BXXUAGZIF`), `SM-S911B_17_Opensource.zip` (14350, 641.42 MB,
   `S911BXXUAGZIF`). These are the same GZIF wave, same dm3q/Snapdragon-8-Gen-2 platform,
   same SPL 2026-10-05, built 2026-09-28 — but **not** the S9180 BRI/CHN regional build.

**Observed publication cadence** (all dates UNVERIFIED on Samsung's side; site shows no
dates — only third-party-confirmed firmware dates):

- GZIF (Android 17 / One UI 9.0) firmware built 2026-09-28; regional releases ran
  ~2026-10-02 (samdb, S918B) through ~2026-10-25 (samfirms TWN S9180ZHU8GZIF; samfirm.shop
  2026-10-22). OSS drop for that wave landed for **B-series within ≤ ~6 weeks** (it is live
  as of 2026-11-17); the **HKTW/CHN (S9180) GZIF drop has NOT landed yet**, ~3–7 weeks
  after the firmwares — consistent with Samsung's usual weeks-to-months OSS lag, and with
  the per-build delta pattern (base drop published first, later builds as small delta zips).
- One generation earlier: One UI 8/8.5 (HKTW_16) drop covers FZDP→FZG1 as base plus deltas
  FZH3 (HK/TW) / FZJ1 (CHN) — China got its newer FZJ1 delta earlier than HK/TW got FZI1's
  successor; lags are region-dependent.
- Two generations earlier: One UI 7-era (HKTW_15, DYD9→DYF1 + DYG1/DYG5/DYI3 deltas).
- Repo precedent: `SM-S911B_15_Opensource.zip` (DYF1-era base; doc
  `docs/SM-S911U1-S911U1UES6DYI3.md` §"KernelSU compatibility").

Pattern conclusion: **expect `SM-S9180_HKTW_17_Opensource.zip` (base) plus delta(s) for
GZIF/S9180ZHU8GZIF to appear within weeks, likely first under the HKTW line for the BRI
build and CHN for ZCU8GZIF.** Until it appears (or the S918B_17 drop is fetched), the
binary patch-status triage in `docs/SM-S9180-S9180ZHU8GZIF.md` §3 is the only
build-specific evidence and must stand alone.

---

## 4. Task 4 — mismatch analysis vs. the binary

No Samsung-source comparison was possible, so a mismatch verdict is **not determinable**.
What is determinable:

| Check | Binary (GZIF) | Upstream baselines (fetched; in-repo `GZIF_work/ref/`) | Samsung drop |
| --- | --- | --- | --- |
| esp6 input fast-path guard `!skb_has_shared_frag(skb)` | **ABSENT** (vulnerable) — `docs/SM-S9180-S9180ZHU8GZIF.md` §3 | ABSENT in v5.15.197; PRESENT in v5.15.205/5212 | UNVERIFIED |
| rtmutex `remove_waiter()` — `waiter->task` + NULL early-return | **PRESENT** (43499 fix integrated) | ABSENT in v5.15.197; PRESENT in v5.15.212 | UNVERIFIED |
| `fs/exec.c` `posix_cpu_timers_exit()` **AFTER** `exec_mmap()` | **AFTER** (98260 vulnerable) | AFTER in v5.15.197 and v5.15.212 (no 5.15 fix exists) | UNVERIFIED |

Mismatch / risk notes:

1. **rtmutex fix in binary vs. plain upstream 5.15.197 lacking it** = direct in-binary proof
   that Samsung merge-point releases of `android13-5.15` integrate selected upstream fixes
   out-of-band (expected: the android13-8 common log carries the 43499 fixes `3bfdc63936dd`
   + `40a25d59e85b`; labeled as campaign-doc finding). Samsung therefore *could* have
   cherry-picked the 43284 5.15.205 guard as well — the binary says it did **not**. The
   source drop is corroboration, not the primary evidence, for 43284.
2. If the S918B_17 (or an eventual S9180_17) drop shows the esp6 guard present while the
   binary lacks it → Samsung backported post-GA or the region/build diverges → re-triage
   required; either direction is a "silent backport" signal to investigate.
3. If the drop shows `posix_cpu_timers_exit` before `exec_mmap` (pre-fix) → consistent with
   binary; confirms no 5.15.y stable fix propagated.
4. If the drop shows rtmutex pre-fix while the binary shows fixed → binary would be
   unexplainable by source (impossible in practice; would invalidate the base ELF
   provenance — watch for CL mismatch).
5. Nothing about 98260/43284 in the drop could have been "fixed by a 5.15 point release
   after 5.15.197": the 5.15 line never received the 98260 fix, and 43284 fixed only from
   5.15.205 — after GZIF's 5.15.197 tag and after the 2026-09-28 build date. Any guard
   presence would be a Samsung-specific backport, not a stable-tree artifact.

---

## 5. What this changes for the campaign

**Nothing, today.** No new source evidence exists for the S9180-specific build; the binary
verdicts in `docs/SM-S9180-S9180ZHU8GZIF.md` remain authoritative and unchanged:

- 43499 (rtmutex): dead on GZIF — binary-verified present fix; source drop not needed.
- 98260 (exec/timer): present, binary-verified vulnerable, unported — source drop would add
  nothing material (no 5.15.y fix exists anywhere).
- 43284 (esp6): present, binary-verified vulnerable — the source cross-check would only
  harden the "no silent Samsung backport" claim; it remains a *should-do* before any port
  claim that cites source, not a blocker for static triage.

**Two independent routes to close it:**

- **Fast (recommended):** user downloads
  `https://opensource.samsung.com/uploadSearch?searchValue=GZIF` → row `SM-S918B |
  S918BXXUAGZIF` → "Source" → tick `SM-S918B_17_Opensource.zip` → **Agree** → save into
  `/mnt/240G_SSD/opencode_tmp/GZIF_work/src-drop/` (641 MB). Then extract only
  `net/ipv6/esp6.c`, `net/ipv4/esp4.c`, `kernel/locking/rtmutex.c`, `fs/exec.c`
  (`unzip -l … | grep -E 'esp6.c|esp4.c|rtmutex.c|exec.c'` then `unzip -p`) and re-run
  checks (a)/(b)/(c) above. Caveat to record: it is the international regional sibling
  (S918BXXUAGZIF), not S9180ZHU8GZIF; treat any divergence accordingly (diff
  `include/config/kernel.release` + `utsrelease.h` against `5.15.197-android13-8-34343818-abS9180*`).
- **Slow (authoritative for the exact build):** wait for `SM-S9180_HKTW_17_Opensource.zip`
  (+ GZIF deltas) — same checks afterward. Expected within weeks; absence today is expected.

Neither route is required for the next engineering step that was already pending
(SELinux/`netlink_xfrm` precondition extraction on a test unit), but both should complete
before any device-verified claim or feed publication cites the source.

---

## 6. Provenance & reproducibility

- Site reads (2026-11-17, this host): saved verbatim under `/mnt/240G_SSD/opencode_tmp/`:
  `oss_main.html` (portal), `oss_search_s9180.html`, `oss_p1.html`, `oss_p2.html` (page 2
  via the site's `page=2` POST), `oss_search_s9180_p2.html`, `oss_q_GZIF.html`,
  `oss_q_S9180ZHU8GZIF.html`, `oss_q_S9180ZHU8.html`, `oss_q_SM-S9180_17.html`, `oss_pop_14326b.html`,
  `oss_pop_14323.html`, `oss_pop_13465.html`, `oss_pop_13466.html`, `oss_pop_13039.html`,
  `oss_pop_13103.html`, `oss_pop_14348.html`, `oss_pop_14349.html`, `oss_pop_14350.html`,
  `oss_ann_14326.html`, `s4_p1.html`, `uploadList.html`.
- Modal calls used the page's own anonymous CSRF token (from the corresponding GET) and the
  session cookie; no credentials, no captcha solved, no forms submitted, no agreements
  accepted; `POST /downSrcCode` and `/downAnnFile` (the actual file transfers) were **not
  executed**.
- Upstream references in-repo: `/mnt/240G_SSD/opencode_tmp/GZIF_work/ref/{esp6_5197.c,
  esp6_5205.c, esp6_5212.c, exec_5197.c, exec_5212.c, rtmutex_5197.c, rtmutex_5212.c}`
  (linux-stable v5.15.197/v5.15.205/v5.15.212; fetched by the campaign 2026-11-17 per
  `docs/SM-S9180-S9180ZHU8GZIF.md` §7).
- Binary symbol addresses and verdicts: `docs/SM-S9180-S9180ZHU8GZIF.md` §3/§7 (unchanged).
- Wall-clock of site reads: `date` header Tue, 17 Nov 2026 (e.g. `cf-ray: a5bc7babbdb0332d-TPE`,
  `server-timing` stamps 05:54–06:05 UTC).
- Nothing in this report asserts content of any Samsung-published drop; all Samsung-source
  claims are labeled UNVERIFIED/expected, never observed.
