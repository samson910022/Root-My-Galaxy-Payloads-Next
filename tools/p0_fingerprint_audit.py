#!/usr/bin/env python3
"""p0_fingerprint_audit.py — pairwise discriminability audit for P0 fingerprint tables.

A target's slide selector scores every committed fingerprint row by counting
exactly-equal qwords and rejects a best/runner-up tie (src/pipe.c). Two rows
that agree in 7 of 8 qwords are one noisy/corrupted-word away from being
indistinguishable on-device: the reading becomes a tie and is thrown away.
This tool measures exactly that, offline, before a table is trusted.

Usage:
  python3 tools/p0_fingerprint_audit.py TARGET_HEADER_P0_FINGERPRINT_H [--fail-at N] [--top K]

Defaults: --fail-at 8 (fail only on byte-identical rows; a 7/8 pair is reported
as a WARNING), --top 8.

Exit status: 0 unless any pair reaches --fail-at equal qwords (then 1).
"""
import argparse
import re
import sys

ROW_RE = re.compile(r"\{\s*0x([0-9a-fA-F]+)ULL\s*,\s*\{([^}]*)\}\s*\}")
QWORD_RE = re.compile(r"0x([0-9a-fA-F]+)ULL")

NOP_QWORD = 0xd503201fd503201f  # two aarch64 NOPs packed little-endian


def load_table(path):
    text = open(path).read()
    rows = []
    for m in ROW_RE.finditer(text):
        slide = int(m.group(1), 16)
        words = [int(w, 16) for w in QWORD_RE.findall(m.group(2))]
        rows.append((slide, words))
    if not rows:
        sys.exit(f"no fingerprint rows parsed from {path}")
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
    args = ap.parse_args()

    rows, width = load_table(args.p0_fingerprint_h)
    n = len(rows)
    print(f"table: {args.p0_fingerprint_h}")
    print(f"rows: {n}, qwords per row: {width}")

    nop_rows = sum(1 for _, w in rows if all(x == NOP_QWORD for x in w))
    print(f"all-NOP rows (unusable as slide evidence): {nop_rows}")

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

    # Single-word corruption model: a lone qword read is flipped to 0x0 (or
    # any value that cannot equal the committed one). For each row and each
    # corruptible position, count how often the true row no longer wins
    # outright against the corrupted table (the pipe.c tie rule throws the
    # reading away).
    print("\nsingle-corrupted-word ambiguity:")
    total_losses, total_cases = 0, 0
    for i, (slide, words) in enumerate(rows):
        losses = 0
        for pos in range(width):
            corrupted = list(words)
            corrupted[pos] = 0
            scores = [sum(1 for a, b in zip(corrupted, w) if a == b) for _, w in rows]
            true_score = scores[i]
            others_best = max(s for k, s in enumerate(scores) if k != i)
            # pipe.c rejects the reading on a best/runner-up tie, so a row
            # that only ties the best other row is unusable evidence.
            if true_score <= others_best:
                losses += 1
        total_losses += losses
        total_cases += width
        if losses:
            print(f"  0x{slide:06x}: {losses}/{width} single-word corruptions make it ambiguous or unusable")
    print(f"table-wide: {total_losses}/{total_cases} single-word corruptions leave the true row ambiguous")

    fails = [p for p in pairs if p[0] >= args.fail_at]
    print(f"\nverdict: {'FAIL' if fails else 'PASS'} (--fail-at {args.fail_at}); "
          f"{len(weak)} pair(s) at >= {args.warn_at}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
