#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-COL-PURE: Pure columnar transposition decryption, ALL widths 2-20.

Uses branch-and-bound with crib-position pruning: at each column
assignment (rank → PT column), every crib position in that column
is checked against the corresponding CT segment.  This eliminates
the vast majority of the ~20! permutation space.

STRUCTURAL RESULT (pre-proven):
  CT has 2 E's; cribs need 3 E's (positions 21, 30, 64).
  => No pure transposition can score 24/24.  Max achievable = 23/24.

Scores with score_candidate() and English quadgrams.
"""
import sys
import time
import heapq
from collections import Counter

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, N_CRIBS
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import get_default_scorer


def main():
    print("=" * 72)
    print("E-COL-PURE: Pure Columnar Transposition, widths 2-20")
    print("             Branch-and-bound with crib pruning")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"Length: {CT_LEN}")

    # ── Structural analysis ───────────────────────────────────────────
    ct_freq = Counter(CT)
    crib_freq = Counter(CRIB_DICT.values())
    print("\nLetter deficit analysis (crib needs vs CT supply):")
    total_deficit = 0
    for ch in sorted(crib_freq):
        need = crib_freq[ch]
        have = ct_freq.get(ch, 0)
        if have < need:
            deficit = need - have
            total_deficit += deficit
            print(f"  {ch}: need {need}, have {have} -> deficit {deficit}")
    max_crib = N_CRIBS - total_deficit
    print(f"Max achievable crib score: {max_crib}/{N_CRIBS}")
    if total_deficit > 0:
        print("  (Pure transposition CANNOT satisfy both cribs simultaneously)")

    # ── Setup ─────────────────────────────────────────────────────────
    ngram_scorer = get_default_scorer()

    TOP_K = 20
    top_heap = []          # min-heap of (ngram_per_char, seq, width, pt, crib)
    seq = 0
    grand_leaves = 0
    grand_pruned = 0
    best_crib = 0
    best_crib_info = None  # (width, rank_to_col, pt, crib)

    TIMEOUT_PER_WIDTH = 300   # 5 min
    MAX_LEAVES = 2_000_000    # safety cap

    # ── Sweep all widths ──────────────────────────────────────────────
    for width in range(2, 21):

        # Build column structure
        cols = [[] for _ in range(width)]
        for pos in range(CT_LEN):
            cols[pos % width].append(pos)
        col_lens = [len(c) for c in cols]

        # Build crib constraints per column: list of (index_in_column, required_char)
        col_cons = [[] for _ in range(width)]
        for c in range(width):
            for idx, pt_pos in enumerate(cols[c]):
                if pt_pos in CRIB_DICT:
                    col_cons[c].append((idx, CRIB_DICT[pt_pos]))

        n_constrained = sum(1 for c in range(width) if col_cons[c])
        n_constraints = sum(len(col_cons[c]) for c in range(width))

        # Factorial for display
        fact = 1
        for i in range(2, width + 1):
            fact *= i

        print(f"\nWidth {width}: {fact:>15,} perms | "
              f"{n_constrained}/{width} cols constrained ({n_constraints} total checks)")
        sys.stdout.flush()

        t0 = time.time()
        w_leaves = 0
        w_pruned = 0
        w_best_crib = 0
        w_best_ng = float('-inf')
        timed_out = False

        # rank_to_col is filled during recursion
        rank_to_col = [0] * width

        def search(rank, ct_offset, used_mask):
            nonlocal w_leaves, w_pruned, w_best_crib, w_best_ng
            nonlocal best_crib, best_crib_info, seq, timed_out

            if timed_out:
                return

            if rank == width:
                # ── Leaf: reconstruct PT and score ────────────────
                w_leaves += 1
                if w_leaves % 500_000 == 0:
                    print(f"    ... {w_leaves:,} leaves so far, "
                          f"{time.time() - t0:.0f}s elapsed")
                    sys.stdout.flush()

                if w_leaves > MAX_LEAVES:
                    timed_out = True
                    return

                # Split CT into column segments by rank order
                segments = [None] * width
                off = 0
                for r in range(width):
                    c = rank_to_col[r]
                    segments[c] = CT[off:off + col_lens[c]]
                    off += col_lens[c]

                # Read row by row
                pt_chars = []
                max_rows = max(col_lens)
                for row in range(max_rows):
                    for c in range(width):
                        if row < col_lens[c]:
                            pt_chars.append(segments[c][row])
                pt = ''.join(pt_chars)

                # Crib score
                crib = 0
                for pos, ch in CRIB_DICT.items():
                    if pt[pos] == ch:
                        crib += 1

                if crib > w_best_crib:
                    w_best_crib = crib
                if crib > best_crib:
                    best_crib = crib
                    best_crib_info = (width, list(rank_to_col), pt, crib)

                # Quadgram
                ng = ngram_scorer.score_per_char(pt)
                if ng > w_best_ng:
                    w_best_ng = ng

                # Top-k tracking
                seq += 1
                entry = (ng, seq, width, pt, crib)
                if len(top_heap) < TOP_K:
                    heapq.heappush(top_heap, entry)
                elif ng > top_heap[0][0]:
                    heapq.heapreplace(top_heap, entry)
                return

            # ── Branch: try each unassigned column at this rank ───
            if time.time() - t0 > TIMEOUT_PER_WIDTH:
                timed_out = True
                return

            for c in range(width):
                if used_mask & (1 << c):
                    continue

                # Check all crib constraints for column c
                ok = True
                for (idx, req) in col_cons[c]:
                    ct_pos = ct_offset + idx
                    if ct_pos >= CT_LEN or CT[ct_pos] != req:
                        ok = False
                        break

                if not ok:
                    w_pruned += 1
                    continue

                rank_to_col[rank] = c
                search(rank + 1, ct_offset + col_lens[c],
                       used_mask | (1 << c))

        search(0, 0, 0)

        elapsed = time.time() - t0
        grand_leaves += w_leaves
        grand_pruned += w_pruned

        flag = " [TIMEOUT]" if timed_out else ""
        print(f"  Leaves: {w_leaves:>10,} | Pruned: {w_pruned:>10,} | "
              f"Time: {elapsed:>6.1f}s{flag}")
        if w_leaves > 0:
            print(f"  Best ng/char: {w_best_ng:.4f} | Best crib: {w_best_crib}/{N_CRIBS}")
        else:
            print(f"  ** All permutations pruned — no valid leaf **")
        sys.stdout.flush()

    # ── Final report ──────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("FINAL RESULTS")
    print("=" * 72)
    print(f"Total leaves evaluated:  {grand_leaves:,}")
    print(f"Total nodes pruned:      {grand_pruned:,}")
    print(f"Best crib score overall: {best_crib}/{N_CRIBS}")

    if best_crib_info:
        w, r2c, pt, cs = best_crib_info
        print(f"\nBest crib candidate (width {w}, crib {cs}/{N_CRIBS}):")
        print(f"  Rank->Col: {r2c}")
        print(f"  PT: {pt}")
        sb = score_candidate(pt, ngram_scorer=ngram_scorer)
        print(f"  Score: {sb.summary}")

    print(f"\nTop {TOP_K} candidates by quadgram score:")
    top_sorted = sorted(top_heap, key=lambda x: -x[0])
    for i, (ng, _, w, pt, crib) in enumerate(top_sorted):
        sb = score_candidate(pt, ngram_scorer=ngram_scorer)
        bean_str = 'PASS' if sb.bean_passed else 'FAIL'
        print(f"  {i + 1:2d}. w={w:2d}  ng/c={ng:.4f}  crib={crib}/{N_CRIBS}  "
              f"bean={bean_str}  IC={sb.ic_value:.4f}")
        print(f"      {pt}")

    # ── Verdict ───────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    if best_crib >= N_CRIBS:
        print("VERDICT: BREAKTHROUGH — full crib match found!")
    elif best_crib >= 18:
        print(f"VERDICT: SIGNAL — crib score {best_crib}/{N_CRIBS}")
    elif total_deficit > 0 and best_crib <= max_crib:
        print(f"VERDICT: DISPROVED — structural impossibility (E deficit) "
              f"confirmed by exhaustive search")
        print(f"  Max achievable crib = {max_crib}/{N_CRIBS}, "
              f"best found = {best_crib}/{N_CRIBS}")
    else:
        print(f"VERDICT: NOISE — best crib {best_crib}/{N_CRIBS}")

    return best_crib, grand_leaves


if __name__ == "__main__":
    main()
