import K4Parity.Data

/-!
# Why the observation is a statement about the key, and what it is invariant under

* `par_key_add_pos`: under Vigenère, Beaufort and Variant Beaufort alike,
  `par (k + i) = par (C + i) + par P`. Within a same-letter pair `P` cancels, so the
  observation says exactly that `par (kᵢ + i)` is a function of the plaintext letter.
* `agree_add_const`: adding one constant to every value-plus-position (A = 1 numbering,
  0-based positions) never changes pairwise agreement.
* `agree_relabel`: renumbering the cipher alphabet by any map that preserves or flips parity
  uniformly never changes agreement. Odd-multiplier affine maps are such maps, but so are
  `2 · 13!²` bijections in all; `swap_not_affine` exhibits a non-affine one (A ↔ C) under
  which K4 still gives 13 of 13.
* Under **every** numbering of the alphabet, the carved repeats make two of the 11 checks
  automatic (`bean_pair_any_numbering`, `s_check_iff_t_check`), and force three
  cross-letter class splits (`doubles_force_opposite`).
-/

namespace K4Parity

/-! ## Variant independence -/

/-- The three additive variants, as maps (ciphertext, plaintext) ↦ key. -/
inductive Variant
  | vigenere     -- k = C − P
  | beaufort     -- k = C + P
  | varBeaufort  -- k = P − C
  deriving DecidableEq

def keyOf : Variant → ZMod 26 → ZMod 26 → ZMod 26
  | .vigenere, C, P => C - P
  | .beaufort, C, P => C + P
  | .varBeaufort, C, P => P - C

/-- **Key parity identity.** For every variant, `par (k + i) = par (C + i) + par P`. -/
theorem par_key_add_pos (v : Variant) (C P i : ZMod 26) :
    par (keyOf v C P + i) = par (C + i) + par P := by
  cases v <;> simp only [keyOf, map_add, map_sub] <;>
    (generalize par C = a; generalize par P = b; generalize par i = c
     revert a b c; decide)

/-- `k − i` and `k + i` have the same parity. -/
theorem par_sub_pos_eq_add_pos (k i : ZMod 26) : par (k - i) = par (k + i) := by
  rw [par_sub, map_add]

/-- Within a same-letter pair, cipher-side agreement is key-side agreement. -/
theorem agree_iff_key_agree (v : Variant) (C₁ C₂ P i j : ZMod 26) :
    par (C₁ + i) = par (C₂ + j) ↔ par (keyOf v C₁ P + i) = par (keyOf v C₂ P + j) := by
  rw [par_key_add_pos, par_key_add_pos, add_left_inj]

/-- **K4, key form.** Under every variant, the crib-derived key satisfies:
`par (kᵢ + i)` is the same at every occurrence of a plaintext letter. -/
theorem key_parity_by_letter (v : Variant) :
    ∀ p ∈ cribs, ∀ q ∈ cribs, p.2 = q.2 →
      par (keyOf v (ct p.1) (letterVal p.2) + p.1) =
      par (keyOf v (ct q.1) (letterVal q.2) + q.1) := by
  intro p hp q hq h
  rw [h, ← agree_iff_key_agree]
  exact parity_consistent' p hp q hq h

/-! ## Conventions -/

/-- Adding a constant to every value-plus-position (A = 1 numbering adds 1 to every value;
0-based positions subtract 1 from every position) leaves agreement unchanged. -/
theorem agree_add_const (x y a : ZMod 26) : par (x + a) = par (y + a) ↔ par x = par y := by
  simp only [map_add, add_left_inj]

theorem parity_consistent_any_offset (a : ZMod 26) :
    ∀ p ∈ cribs, ∀ q ∈ cribs, p.2 = q.2 →
      par (ct p.1 + p.1 + a) = par (ct q.1 + q.1 + a) := by
  intro p hp q hq h
  rw [agree_add_const]
  exact parity_consistent' p hp q hq h

/-! ## Relabeling the cipher alphabet -/

/-- A relabeling that preserves parity, or flips it, uniformly. -/
def ParityUniform (φ : ZMod 26 → ZMod 26) : Prop := ∃ e : ZMod 2, ∀ x, par (φ x) = par x + e

theorem agree_relabel (φ : ZMod 26 → ZMod 26) (hφ : ParityUniform φ) (x y i j : ZMod 26) :
    par (φ x + i) = par (φ y + j) ↔ par (x + i) = par (y + j) := by
  obtain ⟨e, he⟩ := hφ
  simp only [map_add, he]
  clear he
  generalize par x = a; generalize par y = b
  generalize par i = c; generalize par j = d
  revert a b c d e; decide

/-- Odd-multiplier affine maps are parity-uniform. -/
theorem affine_odd_parityUniform (u b : ZMod 26) (hu : par u = 1) :
    ParityUniform (fun x => u * x + b) :=
  ⟨par b, fun x => by rw [map_add, par_mul_odd u x hu]⟩

/-- The reversed alphabet `x ↦ 25 − x` is odd-affine. -/
theorem reversed_parityUniform : ParityUniform (fun x => 25 * x + 25) :=
  affine_odd_parityUniform 25 25 (by decide)

/-- The A ↔ C swap preserves parity... -/
theorem swap_parityUniform : ParityUniform (Equiv.swap (0 : ZMod 26) 2) :=
  ⟨0, by decide⟩

/-- ...but it is not affine: no `u, b` make `x ↦ u x + b` agree with it everywhere. -/
theorem swap_not_affine : ∀ u b : ZMod 26, ∃ x : ZMod 26, Equiv.swap (0 : ZMod 26) 2 x ≠ u * x + b := by
  decide

/-- **K4 under any parity-uniform relabeling still gives 13 of 13**, in particular under the
non-affine A ↔ C swap. So the parity data pin the cipher alphabet down to its odd/even
split, not to "standard order up to `x ↦ a x + b`, `a` odd". -/
theorem parity_consistent_relabel (φ : ZMod 26 → ZMod 26) (hφ : ParityUniform φ) :
    ∀ p ∈ cribs, ∀ q ∈ cribs, p.2 = q.2 →
      par (φ (ct p.1) + p.1) = par (φ (ct q.1) + q.1) := by
  intro p hp q hq h
  rw [agree_relabel φ hφ]
  exact parity_consistent' p hp q hq h

/-- The KRYPTOS-keyed alphabet. -/
def kaStr : String := "KRYPTOSABCDEFGHIJLMNQUVWXZ"
def kaVal (c : Char) : ZMod 26 := ((kaStr.toList.idxOf c : ℕ) : ZMod 26)

/-- Numbering the cipher letters in KRYPTOS order: 6 of the 13 pairs agree. -/
theorem ka_agreeing_pairs :
    (sameLetterPairs.filter fun pq =>
      par (kaVal (ctChar pq.1.1) + pq.1.1) == par (kaVal (ctChar pq.2.1) + pq.2.1)).length = 6 := by
  decide +kernel

/-! ## Facts that hold under every numbering of the alphabet -/

/-- QQ at 26–27, SS at 33–34 and TT at 68–69 put the plaintext letters N/O, S/T and I/N on
opposite sides, whatever the numbering. -/
theorem doubles_force_opposite (φ : Char → ZMod 26) :
    par (φ (ctChar 26) + 26) ≠ par (φ (ctChar 27) + 27) ∧
    par (φ (ctChar 33) + 33) ≠ par (φ (ctChar 34) + 34) ∧
    par (φ (ctChar 68) + 68) ≠ par (φ (ctChar 69) + 69) := by
  obtain ⟨h1, h2, h3⟩ := adjacent_doubles
  rw [← h1, ← h2, ← h3]
  refine ⟨?_, ?_, ?_⟩ <;> simp only [map_add] <;>
    (generalize par (φ _) = a; revert a; decide)

/-- The R pair is enciphered by P at both positions (Bean's equality), and 28 ≡ 66 (mod 2):
this check passes under every numbering, so it is never a coin flip. -/
theorem bean_pair_any_numbering (φ : Char → ZMod 26) :
    par (φ (ctChar 28) + 28) = par (φ (ctChar 66) + 66) := by
  obtain ⟨h1, h2⟩ := bean_pair
  rw [h1, h2]; simp only [map_add]; rfl

/-- The S check (24, 33) and the T check (29, 34) use the same two cipher letters R and S, so
under every numbering one passes exactly when the other does. -/
theorem s_check_iff_t_check (φ : Char → ZMod 26) :
    par (φ (ctChar 24) + 24) = par (φ (ctChar 33) + 33) ↔
    par (φ (ctChar 29) + 29) = par (φ (ctChar 34) + 34) := by
  obtain ⟨h1, h2, h3, h4⟩ := rs_shared
  rw [h1, h2, h3, h4]; simp only [map_add]
  generalize par (φ 'R') = a; generalize par (φ 'S') = b
  revert a b; decide

end K4Parity
