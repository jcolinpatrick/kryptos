import K4Parity.Basic

/-!
# K4 data and the observed facts

Positions are **1-based** here because the parity claim was stated that way; the kryptos
kernel is 0-based. Shifting every position by one flips every parity at once, so
pairwise agreement is unchanged (`K4Parity.Invariance.agree_shift`).

The ciphertext literal must equal `kryptos.kernel.constants.CT`, and the crib strings and
offsets must equal `CRIB_DICT`; `tests/test_lean_k4_parity_constants.py` enforces that, so
this file cannot drift from the single source of truth.

Every theorem in this file is a finite computation checked by the Lean kernel
(`decide +kernel`), so it introduces no axioms beyond Lean's own.
-/

namespace K4Parity

/-- K4 as carved: 97 letters. -/
def ctStr : String :=
  "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

/-- `A = 0, …, Z = 25`. -/
def letterVal (c : Char) : ZMod 26 := ((c.toNat - 65 : ℕ) : ZMod 26)

/-- Ciphertext letter at 1-based position `i`. -/
def ctChar (i : ℕ) : Char := ctStr.toList.getD (i - 1) '?'

/-- Ciphertext value at 1-based position `i`. -/
def ct (i : ℕ) : ZMod 26 := letterVal (ctChar i)

/-- The released cribs as `(position, plaintext letter)`, 1-based:
EASTNORTHEAST at 22–34 and BERLINCLOCK at 64–74. -/
def cribs : List (ℕ × Char) :=
  ("EASTNORTHEAST".toList.zipIdx 22).map (fun p => (p.2, p.1)) ++
  ("BERLINCLOCK".toList.zipIdx 64).map (fun p => (p.2, p.1))

theorem ct_length : ctStr.length = 97 := by decide +kernel
theorem cribs_length : cribs.length = 24 := by decide +kernel

/-- Unordered pairs of crib positions carrying the same plaintext letter. -/
def sameLetterPairs : List ((ℕ × Char) × (ℕ × Char)) :=
  (cribs.flatMap fun p => cribs.map fun q => (p, q)).filter
    fun pq => decide (pq.1.1 < pq.2.1) && pq.1.2 == pq.2.2

/-- 13 same-letter pairs. -/
theorem sameLetterPairs_length : sameLetterPairs.length = 13 := by decide +kernel

/-- 13 distinct crib letters over 24 positions: a letter seen `n` times contributes
`n − 1` independent checks, so there are `24 − 13 = 11`. -/
theorem independent_checks : cribs.length - (cribs.map (·.2)).dedup.length = 11 := by
  decide +kernel

/-! ## The parity observation -/

/-- **The observation.** Every same-letter pair agrees on the parity of
(cipher value + position): 13 of 13. -/
theorem parity_consistent :
    ∀ pq ∈ sameLetterPairs, par (ct pq.1.1 + pq.1.1) = par (ct pq.2.1 + pq.2.1) := by
  decide +kernel

/-- Equivalent pointwise form, over all ordered pairs of crib positions. -/
theorem parity_consistent' :
    ∀ p ∈ cribs, ∀ q ∈ cribs, p.2 = q.2 → par (ct p.1 + p.1) = par (ct q.1 + q.1) := by
  decide +kernel

/-- The two classes the data induce. -/
def oddClass : List Char := ['B', 'E', 'H', 'I', 'O', 'R', 'S']
def evenClass : List Char := ['A', 'C', 'K', 'L', 'N', 'T']

/-- The class table: each crib letter's (cipher value + position) is odd exactly when the
letter is in `oddClass`, and even exactly when it is in `evenClass`. -/
theorem class_table :
    ∀ p ∈ cribs, (p.2 ∈ oddClass ∧ par (ct p.1 + p.1) = 1) ∨
                 (p.2 ∈ evenClass ∧ par (ct p.1 + p.1) = 0) := by
  decide +kernel

/-! ## Cross-block agreement

Of the 11 independent checks, 4 link the two crib blocks: E (22 or 31 with 65),
N (26, 69), O (27, 72), R (28, 66). They are among the 13 pairs above. -/

theorem cross_block_pairs :
    (sameLetterPairs.filter fun pq => decide (pq.1.1 ≤ 34) && decide (64 ≤ pq.2.1)).map
      (fun pq => (pq.1.1, pq.2.1)) = [(22, 65), (26, 69), (27, 72), (28, 66), (31, 65)] := by
  decide +kernel

/-! ## The Stehle run -/

/-- **Stehle Δ5.** `C[i+4] − C[i] = 5 (mod 26)` for the five consecutive `i = 56..60`. -/
theorem stehle_run : ∀ i ∈ [56, 57, 58, 59, 60], ct (i + 4) - ct i = 5 := by
  decide +kernel

/-- The run is maximal: it does not extend to 55 or 61. -/
theorem stehle_run_maximal : ct (55 + 4) - ct 55 ≠ 5 ∧ ct (61 + 4) - ct 61 ≠ 5 := by
  decide +kernel

/-! ## Repeated cipher letters inside the cribs

These hold for the carved text under *every* numbering of the alphabet; see
`K4Parity.Invariance`. -/

/-- QQ at 26–27, SS at 33–34, TT at 68–69. -/
theorem adjacent_doubles : ctChar 26 = ctChar 27 ∧ ctChar 33 = ctChar 34 ∧ ctChar 68 = ctChar 69 := by
  decide +kernel

/-- The R pair (28, 66) is enciphered by the same letter P both times: Bean's equality. -/
theorem bean_pair : ctChar 28 = 'P' ∧ ctChar 66 = 'P' := by decide +kernel

/-- The S pair (24, 33) and the T pair (29, 34) are enciphered by the same two cipher
letters, R and S, in the same roles. -/
theorem rs_shared : ctChar 24 = 'R' ∧ ctChar 33 = 'S' ∧ ctChar 29 = 'R' ∧ ctChar 34 = 'S' := by
  decide +kernel

end K4Parity
