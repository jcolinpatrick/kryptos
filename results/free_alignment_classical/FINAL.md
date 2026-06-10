# FINAL — f_free_alignment_classical_2026_06_10

**Verdict: CLEAN_NULL** (all six arms; frozen rule: zero configs with
kernel-verified free crib_score ≥ 11).

Pre-reg: `docs/campaigns/free_alignment_classical_2026_06_10.md`
(thresholds frozen before any config ran; A4/A5/A6 addenda registered
before those arms ran). Runner:
`scripts/campaigns/f_free_alignment_classical_2026_06_10.py`.
Git HEAD at run: `ceb8e02`. Real dispatcher
(`kryptosbot.job_dispatcher.execute`), kernel-verified scores only,
`crib_alignment="free"` → `score_candidate_free` (`scoring_mode="free"`),
G-1 free-matched null annotation active (`p_value_status=ok_free_matched`
on additive arms).

## What was tested

First free-alignment campaign in the repo (exhaustion_log had ZERO
free-alignment entries). Question: does ANY decrypt in these universes
contain EASTNORTHEAST or BERLINCLOCK as a contiguous substring ANYWHERE
in the 97-char output — i.e. cribs displaced from canonical positions,
which every historical anchored sweep would have scored as noise?

| Arm | Universe | Configs | Best free crib | Hits ≥11 |
|---|---|---|---|---|
| A1 | additive {vig,beau,varbeau} × {AZ,KA} × thematic 339 (sha e244232b…) | 2,034 | 0 | 0 |
| A2 | Quagmire III diagonal: 6 tableaus × 27 periods × {K,A,R} | 486 | 0 | 0 |
| A4 | 52 hash-locked routes (7a9ac673…) × additive × {AZ,KA} × thematic | 105,768 | 0 | 0 |
| A3 | additive × {AZ,KA} × english 4–11 (742,705 words, sha 8e6c84e9…), 450 shards | 4,456,230 | 0 | 0 |
| A5 | columnar(kw) × additive, BOTH peel orders × {AZ,KA} × thematic² | 1,378,808* | 0 | 0 |
| A6 | 52 routes × QIII diagonal matrix (the 2026-06-09 universe), free re-lens | 25,272 | 0 | 0 |

Total: **5,968,842 configs, 0 errors, 0 admissibility rejections.**
(*12 specs × 114,921 = 1,379,052 enumerated; 1,378,808 counted after the
runner's total field — per-spec tested counts are authoritative in
`summary.json`.) Main run wall 794 s; addendum 240 s (after the
dispatcher spec_hash hoist fix, 83× speedup).

## Controls (all passed before arms ran)

- C1 kernel: displaced-crib PT → free crib 24, canonical_positions=False.
- C2 worker fn: `_evaluate_one` on synthetic CT (vig/PALIMPSEST encrypt of
  displaced-crib PT) → kernel-verified 24, scoring_mode=free.
- C3 standing: zoo fixture F9 end-to-end `execute()` free solve (committed
  suite, green at HEAD).

## Statistical status

Under the G-1 free-matched nulls the expected number of hits ≥ 11 across
all ~5.97M configs is ≈ 1.4e-7 (additive uniform model; permutation
arms stricter — free 24 exactly impossible there by CT multiset). The
observed zero is exactly the H0 expectation. No p-value gymnastics are
needed for a clean null; per-arm best-candidate `p_value_vs_null = 1.0`
(best score 0).

## Scope closed (exactly)

Detection-level closure: no decrypt in the six hashed universes contains
either disclosed crib as a contiguous substring anywhere in its 97-char
output. This closes the "right inner system, displaced cribs" escape
hatch for these universes — the displaced-crib variant of every
corresponding anchored closure.

## Scope NOT closed

PT length ≠ 97 (null-extraction/variable-length); keywords outside the
hashed lists; non-keyword keys (random/numeric); key_tape / running-key
inners; quagmire_iv / non-diagonal tableaus / KA-layer quagmire; routes
outside the 52; ≥3-layer pipelines; mechanisms dispersing cribs
non-contiguously (substitution-then-transposition encrypt order scatters
crib letters — only the A5 sub_first arm's contiguous-output case is
covered); fragment-level presence (<full-crib).

## Repro

```bash
PYTHONPATH=src python3 -u scripts/campaigns/f_free_alignment_classical_2026_06_10.py \
    --arms A1,A2,A4,A3 --out results/free_alignment_classical
PYTHONPATH=src python3 -u scripts/campaigns/f_free_alignment_classical_2026_06_10.py \
    --arms A5,A6 --out results/free_alignment_classical_addendum
```

Artifacts: `results/free_alignment_classical{,_addendum}/summary.json` +
per-spec `jobs/*/result.json` (all_results per config).
