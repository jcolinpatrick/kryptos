import K4Parity.Model

/-!
# What the parity observation says about the order of operations

* `sub_then_add_structural`: substitute-then-add makes `par (C + i)` a function of the
  plaintext letter for **every** admissible key, by construction.
* `add_then_sub_forces_uniform`: add-then-substitute, `C = σ (P + k)`, can do the same only if
  `σ` preserves or flips parity uniformly, and then the classes are the identity's parity
  classes, up to a constant.
* `add_then_sub_refuted`: K4's classes are not identity parity classes (E = 4 and R = 17 share
  a class), so add-then-substitute cannot make the observation structural.

What "structural" means is a modelling choice and is stated as a hypothesis: the parity law
holds for every key value consistent with `par (k + i) = c`, at every position. A law that
held only for the particular key values that occur would not be a property of the method.

* `additive_layers_merge`: two additive layers collapse into one, so no statistic of `C` and
  `P` can order them.
* `transposition_last`: a trailing transposition contributes `par (τ i + i)`.
* `columnar_odd_width`: for an odd-width columnar, `par (τ i + i)` is constant down each column,
  which is why parity cannot place a transposition relative to the additive layer.
-/

namespace K4Parity

/-- Lift a bit to a letter value: `0 ↦ 0`, `1 ↦ 1`. -/
def liftBit (b : ZMod 2) : ZMod 26 := (b.val : ZMod 26)

lemma par_liftBit (b : ZMod 2) : par (liftBit b) = b := by
  revert b; decide

private lemma z2_aux3 (a b c : ZMod 2) : a = b + (a + (b + c) + c) := by revert a b c; decide
private lemma z2_aux4 (a b c : ZMod 2) : a + (b + c) + c = a + b := by revert a b c; decide

/-- Substitute-then-add is structural by construction: whatever the key, as long as
`par (k + i) = c`, the parity of `C + i` depends on the plaintext letter alone. -/
theorem sub_then_add_structural (σ : ZMod 26 → ZMod 26) (c : ZMod 2) (P k i : ZMod 26)
    (hk : par (k + i) = c) : par (σ P + k + i) = par (σ P) + c := by
  rw [add_assoc, map_add, hk]

/-- **Add-then-substitute.** If `par (σ (P + k) + i)` is a function `g` of `P` for every key
and position with `par (k + i) = c`, then `σ` is parity-uniform and `g` is identity parity
plus a constant. (`σ` may be any function.) -/
theorem add_then_sub_forces_uniform (σ : ZMod 26 → ZMod 26) (g : ZMod 26 → ZMod 2) (c : ZMod 2)
    (h : ∀ P k i : ZMod 26, par (k + i) = c → par (σ (P + k) + i) = g P) :
    ParityUniform σ ∧ ∀ P, g P = par P + g 0 := by
  -- For any x, take P = 0, k = x, i = x + liftBit c.
  have hσ : ∀ x, par (σ x) = par x + (g 0 + c) := by
    intro x
    have hk : par (x + (x + liftBit c)) = c := by
      rw [← add_assoc, map_add, map_add, zmod2_add_self, zero_add, par_liftBit]
    have := h 0 x (x + liftBit c) hk
    rw [zero_add, map_add, map_add, par_liftBit] at this
    rw [← this]
    exact z2_aux3 _ _ _
  refine ⟨⟨g 0 + c, hσ⟩, fun P => ?_⟩
  -- Now take k = 0, i = liftBit c.
  have hk : par (0 + liftBit c) = c := by rw [zero_add, par_liftBit]
  have := h P 0 (liftBit c) hk
  rw [add_zero, map_add, hσ, par_liftBit] at this
  rw [← this]
  exact z2_aux4 _ _ _

/-- **K4 refutes add-then-substitute as a structural explanation.** Any `g` matching the
observed crib parities would put E (value 4) and R (value 17) in one class, but identity parity
separates them. -/
theorem add_then_sub_refuted (σ : ZMod 26 → ZMod 26) (g : ZMod 26 → ZMod 2) (c : ZMod 2)
    (h : ∀ P k i : ZMod 26, par (k + i) = c → par (σ (P + k) + i) = g P)
    (hdata : ∀ p ∈ cribs, g (letterVal p.2) = par (ct p.1 + p.1)) : False := by
  obtain ⟨_, hg⟩ := add_then_sub_forces_uniform σ g c h
  have hE := hdata (22, 'E') (by decide +kernel)
  have hR := hdata (28, 'R') (by decide +kernel)
  rw [hg] at hE hR
  have e1 : par (ct 22 + (22 : ℕ)) = 1 := by decide +kernel
  have e2 : par (ct 28 + (28 : ℕ)) = 1 := by decide +kernel
  have vE : par (letterVal 'E') = 0 := by decide +kernel
  have vR : par (letterVal 'R') = 1 := by decide +kernel
  simp only at hE hR
  rw [e1, vE] at hE
  rw [e2, vR] at hR
  rw [← hR] at hE
  generalize g 0 = b at hE
  revert b hE; decide

/-! ## Orders that parity cannot distinguish -/

/-- Two additive layers are one additive layer with the summed key, in either order. -/
theorem additive_layers_merge (x k k' : ZMod 26) :
    (x + k) + k' = x + (k + k') ∧ (x + k) + k' = (x + k') + k := by
  constructor <;> ring

/-- A trailing transposition `τ` (gather convention: output `i` takes input `τ i`) adds the
term `par (τ i + i)`. -/
theorem transposition_last (σ : ZMod 26 → ZMod 26) (P k : ℕ → ZMod 26) (τ : ℕ → ℕ) (c : ZMod 2)
    (hk : ∀ j, par (k j + j) = c) (i : ℕ) :
    par (σ (P (τ i)) + k (τ i) + i) = par (σ (P (τ i))) + c + par ((τ i + i : ℕ) : ZMod 26) := by
  have h := hk (τ i)
  simp only [map_add, Nat.cast_add] at h ⊢
  rw [← h]
  generalize par (σ (P (τ i))) = a; generalize par (k (τ i)) = b
  generalize par ((τ i : ℕ) : ZMod 26) = x; generalize par ((i : ℕ) : ZMod 26) = y
  revert a b x y; decide

/-- **Odd-width columnar.** Write the text in rows of width `w` and read column `j` as a block
starting at output index `s`: its `r`-th letter is output `s + r` and came from input
`r * w + j`. If `w` is odd, `τ i + i` has the same parity all the way down the column. -/
theorem columnar_odd_width (w j s r : ℕ) (hw : w % 2 = 1) :
    (r * w + j + (s + r)) % 2 = (j + s) % 2 := by
  obtain ⟨m, rfl⟩ : ∃ m, w = 2 * m + 1 := ⟨w / 2, by omega⟩
  have : r * (2 * m + 1) + j + (s + r) = (j + s) + 2 * (r * m + r) := by ring
  rw [this, Nat.add_mul_mod_self_left]

end K4Parity
