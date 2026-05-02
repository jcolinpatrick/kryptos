# CT-Perturbation Stage A Coverage Audit

Date: 2026-05-01

Stage A tests H0 plus Hamming-1 substitution variants of the 97-character carved K4 ciphertext under direct positional crib alignment. It does not test insertions, deletions, reading-order errors, source-text branches, running-key, Stage B, or Stage C.

## Position-Class Effect

Under the implemented H1/direct positional crib mapping, known crib positions are fixed at 0-indexed positions 21-33 and 63-73.

Therefore:

- H1 substitutions at crib positions can change crib-derived keystream values and Bean feasibility.
- H1 substitutions outside crib positions cannot change crib_score or Bean constraints.
- Non-crib substitutions can affect downstream plaintext/ngram quality only after a candidate survives the crib/Bean gates.

Counts for the full Stage-A H1 universe:

| Class | Count |
|---|---:|
| Crib-position H1 substitutions | 600 |
| Non-crib-position H1 substitutions | 1,825 |
| H0 baseline | 1 |
| Total with H0 | 2,426 |

If `bean_pass_total == 0`, the strongest negative is for H0 plus H1 substitutions at the 24 crib positions. The 1,825 non-crib H1 variants are still enumerated, but they are redundant at the crib/Bean gate unless a survivor reaches downstream scoring.

## Coverage Matrix

| Hypothesis | Covered? | Evidence | Caveat |
|---|---:|---|---|
| H0 canonical additive keyword | yes, when `--include-h0-baseline` is passed | H0 variant `H0_canonical` is included separately from H1 | Limited to direct positional cribs and keyword list |
| H1 substitution at crib position | yes | 24 crib positions x 25 substitutions = 600 full-H1 variants | Full coverage requires no H1 cap |
| H1 substitution outside crib position affecting Bean | no | Bean uses only fixed crib CT/PT positions | Non-crib CT changes cannot alter crib/Bean gates |
| H1 substitution outside crib position affecting ngram after survivor | partial | 73 non-crib positions x 25 substitutions = 1,825 full-H1 variants | Meaningful only if crib/Bean survivor exists |
| H1 insertion/deletion | no | Variant generator performs substitution only | Not Stage A |
| Reading-order/transcription reorder error | no | CT coordinate order is fixed | Requires a separate positional model |
| Public crib placement wrong | no | Crib positions are fixed | Would invalidate direct positional mapping |
| Sanborn error in plaintext clue disclosure | no | Crib text is treated as canonical | Out of Stage-A scope |
| H2 archive-anchored substitution | no | No Hamming-2 enumerator is exposed | Stage B only |
| Independent period 1-26 | no | Period policy is `keyword_length` | Period-expanded search not implemented |
| Keyword outside curated list | no | Keyword universe is the normalized/deduped loaded file | Negative applies only to that list |
| Non-keyword-periodic key | no | Keys are repeated finite keywords | Running-key remains out of scope |
| Outer transposition before direct cribs | no | No transposition layer is applied | A transposition could invalidate fixed crib coordinates |

## Null Status

At audit time, `ngram_score__random_text__AZ__n97` is present and `ngram_score__random_text__KA__n97` is missing. This does not affect a Bean-layer negative with `bean_pass_total == 0`, but it does affect alert semantics: a KA candidate with missing ngram null must not produce solution-grade `alert`; it may only be emitted as `watchlist_null_unavailable`.

The deterministic command path for KA ngram calibration is:

```bash
PYTHONPATH=src python3 - <<'PY'
from kryptosbot.null_baselines import build_null_distribution, save_to_cache
dist = build_null_distribution(
    scorer_name="ngram_score",
    method="random_text",
    n_chars=97,
    alphabet="KA",
    n_samples=50000,
    seed=42,
)
print(save_to_cache(dist))
PY
```

Do not fake this cache. Use `--require-null` for solution-grade alert runs once KA is calibrated.
