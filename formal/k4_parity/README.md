# K4 parity anomaly: Lean 4 formalisation

Kernel-checked proofs about one regularity in the K4 cribs and its interaction with the
Stehle Δ5 run. Lean 4.33.1 + Mathlib v4.33.1.

**The observation.** Number letters A=0…Z=25 and positions from 1. At every crib position
take (cipher value + position). Every plaintext letter that occurs more than once in the cribs
gives the same parity at every occurrence: 13 of 13 same-letter pairs, 11 independent checks.

## Reproduce

One command, from anywhere in a clone of the repository:

```bash
bash formal/k4_parity/reproduce.sh
```

It runs `lake exe cache get` (prebuilt Mathlib for v4.33.1; never build Mathlib from source),
`lake build` (checks every proof), `lake env lean AxiomAudit.lean` (prints the axioms each
headline theorem depends on) and `parity_figures.py` (the exact counts that are not Lean proofs).

Requires [elan](https://github.com/leanprover/elan) and Python 3.11+; `lean-toolchain` pins the
compiler. Allow about 11 GB of disk for the toolchain and Mathlib.
Every theorem in `AxiomAudit.lean` depends on at most `propext`, `Classical.choice` and
`Quot.sound` (Lean's standard axioms). None uses `sorryAx` (an unproved step) or
`Lean.ofReduceBool` (a step trusted to compiled code instead of the kernel). The ciphertext and
cribs in `K4Parity/Data.lean` are checked against `src/kryptos/kernel/constants.py` by
`tests/test_lean_k4_parity_constants.py`.

## What is proved

Status labels follow the repo's truth taxonomy. Everything below is **[DERIVED FACT]**: a
deterministic consequence of the public ciphertext and cribs, reproducible by the commands
above. The modelling assumptions are stated as hypotheses inside each theorem.

| Claim | Theorem | File |
|---|---|---|
| 13 of 13 same-letter pairs agree; 11 independent checks | `parity_consistent`, `sameLetterPairs_length`, `independent_checks` | `Data` |
| Classes {B,E,H,I,O,R,S} odd, {A,C,K,L,N,T} even | `class_table` | `Data` |
| 4 of the independent checks cross the two crib blocks | `cross_block_pairs` | `Data` |
| C[i+4] − C[i] ≡ 5 for i = 56..60, and the run is maximal | `stehle_run`, `stehle_run_maximal` | `Data` |
| Under Vigenère, Beaufort and Variant Beaufort, par(k+i) = par(C+i) + par(P), so the observation is about the key | `par_key_add_pos`, `key_parity_by_letter` | `Invariance` |
| Independent of A=0/A=1 numbering and 0/1-based positions | `agree_add_const`, `parity_consistent_any_offset` | `Invariance` |
| Holds under any cipher-alphabet relabeling that preserves or flips parity, including the non-affine A↔C swap | `parity_consistent_relabel`, `swap_parityUniform`, `swap_not_affine` | `Invariance` |
| KRYPTOS-keyed cipher numbering: 6 of 13 | `ka_agreeing_pairs` | `Invariance` |
| Under every numbering: the R pair always agrees (Bean's equality), and the S check passes iff the T check (29, 34) does | `bean_pair_any_numbering`, `s_check_iff_t_check` | `Invariance` |
| Model C = σ(P) + k with par(k+i) constant gives eq. (1); lag-4 key differences are even | `eq1`, `key_diff_parity` | `Model` |
| At a Stehle step: eq. (2), eq. (3), d ≠ 5, P[i+4] ≠ P[i]; σ need not be injective | `stehle_step`, `k4_stehle` | `Model` |
| Window: P60 is not in the odd class, P56 is not in the even class, (57,61), (58,62), (59,63) straddle | `k4_window` | `Model` |
| **For fixed σ, a plaintext is realizable by some key iff it passes one parity bit per position** | `realizable_iff` | `Model` |
| Stehle adds nothing beyond that bit | `stehle_from_filter` | `Model` |
| An explicit σ (a bijection), c, plaintext and key satisfy the model at all 97 positions with both cribs | `k4_model_satisfiable`, `σ₀_injective` | `Model` |
| Add-then-substitute can be structural only with identity-parity classes, which K4 refutes (E and R share a class) | `add_then_sub_forces_uniform`, `add_then_sub_refuted` | `Order` |
| Two additive layers merge; a trailing transposition adds par(τ(i)+i); odd-width columnar keeps it constant per column | `additive_layers_merge`, `transposition_last`, `columnar_odd_width` | `Order` |
| Random crib cipher letters: exactly 2^13 · 13^24 of 26^24 assignments agree, a chance of exactly 2⁻¹¹ | `card_consistent`, `k4_card_consistent`, `k4_chance` | `Counting` |
| 3432 of the C(26,13) odd-letter sets split the two classes: 1 in 3030.48 | `sigma_split_count`, `sigma_split_chance` | `Counting` |

## Corrections the formalisation surfaced

1. **Cipher alphabet.** The data do not pin the cipher alphabet to "standard order up to
   x ↦ ax + b, a odd". They pin only its odd/even split. Any relabeling that preserves or flips
   parity keeps 13 of 13. There are 2 · 13!² ≈ 7.8 × 10¹⁹ such alphabets, and 312 of them are
   affine. `swap_not_affine` gives a concrete non-affine one.
2. **Random-alphabet null.** Under every numbering of the alphabet, 2 of the 11 checks pass
   automatically: the R pair (enciphered by P both times, Bean's equality) and the duplicate
   S/T check (cipher letters R and S in the same roles at 24/33 and 29/34). So 9 checks are free
   coins. The exact chance of 13/13 under a uniformly random cipher alphabet is
   24,024 / 10,400,600 = 1 in 432.9 (exact enumeration in `parity_figures.py`; Lean proves the
   two automatic checks, not the final count). The earlier Monte Carlo figure of 1 in 457 is
   within sampling error of it. Likewise the shuffle figure (K4's 97 letters rearranged at
   random) is exactly 55,182,400 / 110,152,823,931 = 1 in 1,996.2, replacing a sampled 1 in 2,012.
3. **σ need not be injective** for "no lag-4 repeat at a Stehle step": any function will do.
4. **What the model predicts.** `realizable_iff` is the exact content of the parity model: one
   bit per position, no key values. Both anomalies are jointly satisfiable, and neither narrows
   the plaintext beyond that bit.
5. **"Structural" is a hypothesis.** The order theorem assumes the parity law holds for every
   key value allowed by par(k+i) = c, not just the values that happen to occur.

## Exact counts that are not Lean proofs

`parity_figures.py` (standard library only, about 3 seconds) computes, exactly:

- the shuffle chance, 1 in 1,996.2, by summing over the 2^13 consistent odd/even patterns;
- the random cipher-alphabet chance, 1 in 432.9;
- the KRYPTOS-keyed numbering, 6 of 13 pairs;
- the plaintext-alphabet class split, 1 in 3,030.5 (also proved in Lean);
- the columnar count: 38,805 of the 409,112 keys of width 2 to 9 keep par(tau(i)+i) constant on
  the cribs, read at ciphertext positions.

The Stehle run's own chance (about 1 in 205 for a run of five equal differences at any lag 1 to
30) is `scripts/crib_analysis/e_crib_34_stehle_null.py`.

## Not formalised

- The look-elsewhere correction (how many statistics were tried first). That is a judgement
  about the search, not a theorem.
- English-entropy search-space estimates.
- The reduction from a uniformly random bijection sigma to a uniformly random 13-letter odd set
  (standard; each set arises from 13! * 13! bijections).
