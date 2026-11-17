#!/usr/bin/env python3
"""p0_fingerprint_audit.py — pairwise discriminability audit for P0 fingerprint tables.

A target's slide selector scores, in a default build, every committed fingerprint row by counting
exactly-equal qwords and rejects a best/runner-up tie (src/pipe.c). Two rows
that agree in 7 of 8 qwords are one noisy/corrupted-word away from being
indistinguishable on-device. This tool measures exactly that, offline,
before a table is trusted.

Scope and model notes:
- Models the DEFAULT scoring path (src/pipe.c: exact qword equality, accept
  on best_score > second_score with changed_pages == 1 and best_score >= 2,
  reject on a tie). Targets built with
  APP_S928_STABLE_RACE (the three e3q-S928 stable tables) score differently
  (zero words ignored; best_score >= 4 and best_score*2 >= best_significant
  required) — reported counts for those tables do not reflect on-device
  scoring.
- The single-corruption simulation flips ONE qword to 0x0 as a representative
  misread. It captures the fail-closed class (tie => the reading is rejected)
  and the strictly-beaten class (another row wins => pipe.c *silently accepts
  the wrong slide*, not a rejection). It does not enumerate all 2^64
  misread values; a misread that lands exactly on the sibling row's qword 0
  is the fail-open edge.
- Degenerate all-zero sampled page: rows containing committed zero qwords
  (exact Image bytes) are individually reported, and the all-zero page is
  scored against every row. Under the DEFAULT scorer an all-zero page can
  satisfy the acceptance floor (best_score >= 2, best > second) when some
  row's zeros are the table's unique best score — reported as a WARNING
  class, never gated here (nearly all historical tables trip it; the GZIF
  re-derivation checklist tracks it).

Usage:
  python3 tools/p0_fingerprint_audit.py P0_FINGERPRINT_H [--fail-at N] [--top K] [--warn-at N] [--github]

Defaults: --fail-at 8 (fail only on byte-identical rows; a 7/8 pair is reported
as a WARNING), --top 8, --warn-at 7.
--github emits GitHub Actions ::warning annotations for all pairs at/above
--warn-at (so the weak-pair class shows up in the PR UI; exit status is
unchanged).

Exit status: 0 = audit ran and no pair reached --fail-at; 1 = a pair reached
--fail-at, a duplicate slide row with different words was found, or the
input could not be parsed/audited (message printed); 2 = usage error
(out-of-range --fail-at).
"""
import argparse
import re
import sys

ROW_RE = re.compile(r"\{\s*0x([0-9a-fA-F]+)ULL\s*,\s*\{([^}]*)\}\s*\}")
QWORD_RE = re.compile(r"0x([0-9a-fA-F]+)ULL")

_GH_PROP = str.maketrans({'%': '%25', '\r': ' ', '\n': ' ', ':': '%3A', ',': '%2C'})


def _gh_prop(value):
    return str(value).translate(_GH_PROP)

NOP_QWORD = 0xd503201fd503201f  # two aarch64 NOPs packed little-endian


def load_table(path):
    try:
        text = open(path).read()
    except (OSError, UnicodeDecodeError) as e:
        detail = getattr(e, 'strerror', None) or str(e)
        sys.exit(f"error: cannot read {_gh_prop(path)}: {_gh_prop(detail)}")
    rows = []
    for m in ROW_RE.finditer(text):
        slide = int(m.group(1), 16)
        words = [int(w, 16) for w in QWORD_RE.findall(m.group(2))]
        rows.append((slide, words))
    if not rows:
        sys.exit(f"no fingerprint rows parsed from {path}")
    if len(rows) < 2:
        sys.exit(f"need at least 2 rows in {path}, got {len(rows)}")
    width = {len(w) for _, w in rows}
    if len(width) != 1:
        sys.exit(f"inconsistent word-count per row in {path}: {sorted(width)}")
    return rows, width.pop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("p0_fingerprint_h")
    ap.add_argument("--fail-at", type=int, default=8,
                    help="equal-qword count at which a pair fails the audit (default 8)")
    ap.add_argument("--top", type=int, default=8, help="how many closest pairs to print")
    ap.add_argument("--warn-at", type=int, default=7,
                    help="equal-qword count reported as a weak pair (default 7)")
    ap.add_argument("--github", action="store_true",
                    help="emit GitHub Actions ::warning annotations for pairs at/above --warn-at")
    args = ap.parse_args()
    if args.fail_at < 1:
        print("error: --fail-at must be >= 1", file=sys.stderr)
        return 2

    rows, width = load_table(args.p0_fingerprint_h)
    if args.fail_at > width:
        print(f"error: --fail-at {args.fail_at} exceeds the table width ({width} qwords)", file=sys.stderr)
        return 2
    n = len(rows)
    print(f"table: {args.p0_fingerprint_h}")
    print(f"rows: {n}, qwords per row: {width}")

    # Duplicate-slide check: same slide, different words is an unambiguous
    # table bug and always fails the audit.
    seen = {}
    for slide, words in rows:
        prev = seen.get(slide)
        if prev is not None and prev != words:
            print(f"FAIL: duplicate slide 0x{slide:06x} with different words")
            return 1
        seen[slide] = words

    nop_rows = sum(1 for _, w in rows if all(x == NOP_QWORD for x in w))
    print(f"all-NOP rows (unusable as slide evidence): {nop_rows}")

    zero_rows = [(slide, w) for slide, w in rows if any(x == 0 for x in w)]
    print(f"rows containing committed zero qwords: {len(zero_rows)}")
    for slide, w in zero_rows:
        zeros = sum(1 for x in w if x == 0)
        print(f"  0x{slide:06x}: {zeros} zero qword(s)")

    # Degenerate all-zero sampled page against the DEFAULT scorer: any row
    # with enough zero qwords can satisfy the acceptance floor
    # (best_score >= 2, best > second). Report-only; never gated here.
    print("\ndegenerate all-zero sampled page (default scorer):")
    zero_page = [0] * width
    scores = [sum(1 for a, b in zip(zero_page, w) if a == b) for _, w in rows]
    best = max(scores)
    others = sorted(scores, reverse=True)
    second = others[1] if len(others) > 1 else 0
    if best >= 2 and best > second:
        winners = sorted({rows[i][0] for i, s in enumerate(scores) if s == best})
        print(f"  all-zero page WOULD BE ACCEPTED as slide(s) {', '.join(f'0x{s:06x}' for s in winners)} (best={best}, second={second})")
        print("  warning: committed zero qwords make an all-zero sample admissible — track in the target's re-derivation checklist")
    else:
        print(f"  all-zero page rejected (best={best}, second={second})")

    pairs = []
    for i in range(n):
        for j in range(i + 1, n):
            eq = sum(1 for a, b in zip(rows[i][1], rows[j][1]) if a == b)
            pairs.append((eq, rows[i][0], rows[j][0]))
    pairs.sort(reverse=True)

    print(f"\nclosest pairs (top {args.top}):")
    for eq, a, b in pairs[: args.top]:
        flag = "FAIL" if eq >= args.fail_at else ("WARN" if eq >= args.warn_at else "ok")
        print(f"  [{flag}] 0x{a:06x} vs 0x{b:06x}: {eq}/{width} qwords equal")

    weak = [p for p in pairs if p[0] >= args.warn_at]
    print(f"\nweak pairs (>= {args.warn_at} equal qwords): {len(weak)}")
    if args.github:
        for eq, a, b in weak:
            print(f"::warning file={_gh_prop(args.p0_fingerprint_h)},title=Weak P0 fingerprint pair::0x{a:06x} vs 0x{b:06x} agree in {eq}/{width} qwords")

    # Single-word corruption model: a lone qword read is flipped to 0x0 (a
    # representative misread). For each row and each corruptible position,
    # the corrupted row now competes against all other rows. Two failure
    # classes result:
    #   tie    (true_score == others_best): pipe.c rejects on a best/runner-up
    #          tie -> the reading is discarded (fail-closed);
    #   beaten (true_score  < others_best): pipe.c silently accepts the WRONG
    #          slide (fail-open).
    print("\nsingle-corrupted-word ambiguity (flip qword to 0x0):")
    total_tie, total_beaten, total_cases = 0, 0, 0
    for i, (slide, words) in enumerate(rows):
        tie_losses, beaten_losses = 0, 0
        for pos in range(width):
            corrupted = list(words)
            corrupted[pos] = 0
            scores = [sum(1 for a, b in zip(corrupted, w) if a == b) for _, w in rows]
            true_score = scores[i]
            others_best = max(s for k, s in enumerate(scores) if k != i)
            if true_score == others_best:
                tie_losses += 1
            elif true_score < others_best:
                beaten_losses += 1
        total_tie += tie_losses
        total_beaten += beaten_losses
        total_cases += width
        if tie_losses or beaten_losses:
            print(f"  0x{slide:06x}: {tie_losses} tie (reading rejected) + {beaten_losses} beaten (wrong slide accepted) / {width} corruptions")
    print(f"table-wide: {total_tie} tie (discarded) + {total_beaten} beaten (silently wrong slide) / {total_cases} single-word corruptions")

    fails = [p for p in pairs if p[0] >= args.fail_at]
    print(f"\nverdict: {'FAIL' if fails else 'PASS'} (--fail-at {args.fail_at}); "
          f"{len(weak)} pair(s) at >= {args.warn_at}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
