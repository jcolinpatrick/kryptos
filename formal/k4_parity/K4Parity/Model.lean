import K4Parity.Invariance

/-!
# The substitute-then-add model, and what Stehle adds to it

Model, at every position `i`:

    C i = σ (P i) + k i        and        par (k i + i) = c

with `σ : ZMod 26 → ZMod 26` **any function** (injectivity is never used below), `k` the
keystream and `c : ZMod 2` a constant.

* `eq1`: `par (C i + i) = par (σ (P i)) + c`, at every position, plaintext known or not.
* `key_diff_parity`: `par (k (i+L) − k i) = par L`; in particular lag-4 key differences
  are even.
* `stehle_step`: at a Stehle position (`C (i+4) − C i = 5`) the plaintext-side difference is
  `5 − d` (eq. 2), it is odd (eq. 3), the key difference `d` is not 5, and `P (i+4) ≠ P i`.
* `realizable_iff`: **the model's whole empirical content.** For a fixed `σ` and `c`, a
  plaintext is realizable by some key if and only if it passes one parity bit per position.
* `stehle_from_filter`: that per-position bit already implies eq. 3, so Stehle adds nothing
  to the parity model.
* `k4_model_satisfiable`: an explicit `σ`, `c`, plaintext and key satisfying the model at all
  97 positions, agreeing with both cribs, so all of the above are jointly consistent.
-/

namespace K4Parity

/-- The substitute-then-add model at position `i`. -/
def SubThenAdd (σ : ZMod 26 → ZMod 26) (P k C : ℕ → ZMod 26) (c : ZMod 2) (i : ℕ) : Prop :=
  C i = σ (P i) + k i ∧ par (k i + i) = c

section General

variable {σ : ZMod 26 → ZMod 26} {P k C : ℕ → ZMod 26} {c : ZMod 2}

/-- **(1)** -/
theorem eq1 {i : ℕ} (h : SubThenAdd σ P k C c i) : par (C i + i) = par (σ (P i)) + c := by
  obtain ⟨hC, hk⟩ := h
  rw [hC, add_assoc, map_add, hk]

/-- Equivalently, the plaintext-side parity is read off the ciphertext. -/
theorem sigma_par {i : ℕ} (h : SubThenAdd σ P k C c i) : par (σ (P i)) = par (C i + i) + c := by
  rw [eq1 h, add_assoc, zmod2_add_self, add_zero]

/-- Key differences at lag `L` have the parity of `L`. -/
theorem key_diff_parity {i L : ℕ} (h₀ : par (k i + i) = c) (hL : par (k (i + L) + (i + L : ℕ)) = c) :
    par (k (i + L) - k i) = par (L : ZMod 26) := by
  rw [par_sub]
  simp only [map_add, Nat.cast_add] at h₀ hL
  exact z2_key_diff _ _ _ _ _ h₀ hL

/-- **The Stehle step under the model.** If `C (i+4) − C i = 5` then
(2) `σ (P (i+4)) − σ (P i) = 5 − d` with `d = k (i+4) − k i`, `d` is even, (3) the two
plaintext-side values have opposite parity, `d ≠ 5`, and `P (i+4) ≠ P i`. -/
theorem stehle_step {i : ℕ} (h₀ : SubThenAdd σ P k C c i) (h₄ : SubThenAdd σ P k C c (i + 4))
    (hC : C (i + 4) - C i = 5) :
    σ (P (i + 4)) - σ (P i) = 5 - (k (i + 4) - k i) ∧
    par (k (i + 4) - k i) = 0 ∧
    par (σ (P (i + 4))) = par (σ (P i)) + 1 ∧
    k (i + 4) - k i ≠ 5 ∧
    P (i + 4) ≠ P i := by
  have e2 : σ (P (i + 4)) - σ (P i) = 5 - (k (i + 4) - k i) := by
    linear_combination hC - h₄.1 + h₀.1
  have hd : par (k (i + 4) - k i) = 0 := by
    have := key_diff_parity (L := 4) h₀.2 h₄.2
    rw [this]; rfl
  have e3 : par (σ (P (i + 4))) = par (σ (P i)) + 1 := by
    have := congrArg par e2
    rw [par_sub, par_sub, hd] at this
    have h5 : par (5 : ZMod 26) = 1 := rfl
    rw [h5] at this
    generalize par (σ (P (i + 4))) = a at *; generalize par (σ (P i)) = b at *
    revert a b; decide
  refine ⟨e2, hd, e3, ?_, ?_⟩
  · intro h5
    rw [h5] at hd
    exact absurd hd (by decide)
  · intro hP
    rw [hP] at e3
    generalize par (σ (P i)) = a at e3
    revert a e3; decide

/-- **Model content.** For fixed `σ` and `c`, a plaintext `P` is realizable on positions
`< N` by *some* keystream if and only if it passes one parity bit per position. The model
supplies no key values; it filters plaintext by exactly that bit. -/
theorem realizable_iff (σ : ZMod 26 → ZMod 26) (C P : ℕ → ZMod 26) (c : ZMod 2) (N : ℕ) :
    (∃ k : ℕ → ZMod 26, ∀ i < N, SubThenAdd σ P k C c i) ↔
      (∀ i < N, par (σ (P i)) = par (C i + i) + c) := by
  constructor
  · rintro ⟨k, hk⟩ i hi
    exact sigma_par (hk i hi)
  · intro h
    refine ⟨fun i => C i - σ (P i), fun i hi => ⟨by ring, ?_⟩⟩
    have := h i hi
    rw [sub_add_eq_add_sub, par_sub, this]
    exact z2_add_add_cancel _ _

/-- **Stehle adds nothing beyond the per-position bit.** If a plaintext passes the parity
filter at `i` and `i + 4`, and `C (i+4) − C i = 5`, then eq. (3) holds automatically. -/
theorem stehle_from_filter {i : ℕ}
    (h₀ : par (σ (P i)) = par (C i + i) + c)
    (h₄ : par (σ (P (i + 4))) = par (C (i + 4) + (i + 4 : ℕ)) + c)
    (hC : C (i + 4) - C i = 5) :
    par (σ (P (i + 4))) = par (σ (P i)) + 1 := by
  have hC' : C (i + 4) = C i + 5 := by rw [← hC]; ring
  have hshift : par (C i + 5 + ((i + 4 : ℕ) : ZMod 26)) = par (C i + i) + 1 := by
    rw [map_add, map_add, par_pos_add_four, map_add]
    have h5 : par (5 : ZMod 26) = 1 := rfl
    rw [h5]
    generalize par (C i) = a; generalize par (i : ZMod 26) = b
    revert a b; decide
  rw [h₄, h₀, hC', hshift]
  ring

end General

/-! ## K4 instance -/

section K4

variable {σ : ZMod 26 → ZMod 26} {P k : ℕ → ZMod 26} {c : ZMod 2}

/-- One crib occurrence of each classed letter. (Stated as explicit lists: asking the kernel
to *search* `cribs` for a witness is needlessly expensive.) -/
def oddWit : List (ℕ × Char) := [(64, 'B'), (22, 'E'), (30, 'H'), (68, 'I'), (27, 'O'), (28, 'R'), (24, 'S')]
def evenWit : List (ℕ × Char) := [(23, 'A'), (70, 'C'), (74, 'K'), (67, 'L'), (26, 'N'), (25, 'T')]

theorem oddWit_ok : ∀ p ∈ oddWit, p ∈ cribs ∧ par (ct p.1 + p.1) = 1 := by decide +kernel
theorem evenWit_ok : ∀ p ∈ evenWit, p ∈ cribs ∧ par (ct p.1 + p.1) = 0 := by decide +kernel
theorem oddWit_letters : oddWit.map Prod.snd = oddClass := by decide
theorem evenWit_letters : evenWit.map Prod.snd = evenClass := by decide

theorem odd_class_witness :
    ∀ l ∈ oddClass, ∃ p ∈ cribs, p.2 = l ∧ par (ct p.1 + p.1) = 1 := by
  intro l hl
  rw [← oddWit_letters, List.mem_map] at hl
  obtain ⟨p, hp, rfl⟩ := hl
  exact ⟨p, (oddWit_ok p hp).1, rfl, (oddWit_ok p hp).2⟩

theorem even_class_witness :
    ∀ l ∈ evenClass, ∃ p ∈ cribs, p.2 = l ∧ par (ct p.1 + p.1) = 0 := by
  intro l hl
  rw [← evenWit_letters, List.mem_map] at hl
  obtain ⟨p, hp, rfl⟩ := hl
  exact ⟨p, (evenWit_ok p hp).1, rfl, (evenWit_ok p hp).2⟩

/-- Under the model, the substitution sends every odd-class crib letter to parity `1 + c`
and every even-class one to parity `c`. -/
theorem class_sigma (hM : ∀ i, SubThenAdd σ P k ct c i)
    (hcrib : ∀ p ∈ cribs, P p.1 = letterVal p.2) :
    (∀ l ∈ oddClass, par (σ (letterVal l)) = 1 + c) ∧
    (∀ l ∈ evenClass, par (σ (letterVal l)) = c) := by
  constructor
  · intro l hl
    obtain ⟨p, hp, rfl, hpar⟩ := odd_class_witness l hl
    rw [← hcrib p hp, sigma_par (hM p.1), hpar]
  · intro l hl
    obtain ⟨p, hp, rfl, hpar⟩ := even_class_witness l hl
    rw [← hcrib p hp, sigma_par (hM p.1), hpar, zero_add]

/-- **Stehle × parity on K4.** Under the model, at each of the five Stehle steps the
plaintext-side parity flips, the key difference is even and is not 5, and the plaintext does
not repeat at lag 4. -/
theorem k4_stehle (hM : ∀ i, SubThenAdd σ P k ct c i) :
    ∀ i ∈ [56, 57, 58, 59, 60],
      par (σ (P (i + 4))) = par (σ (P i)) + 1 ∧ par (k (i + 4) - k i) = 0 ∧
      k (i + 4) - k i ≠ 5 ∧ P (i + 4) ≠ P i := by
  intro i hi
  obtain ⟨_, hd, e3, hne, hP⟩ := stehle_step (hM i) (hM (i + 4)) (stehle_run i hi)
  exact ⟨e3, hd, hne, hP⟩

/-- **The window constraints.** Anchored at `P 64 = B`: `P 60` is not an odd-class letter,
`P 56` is not an even-class letter, and the pairs (57, 61), (58, 62), (59, 63) straddle the
two parities. Letters outside the 13 classed ones are unconstrained. -/
theorem k4_window (hM : ∀ i, SubThenAdd σ P k ct c i)
    (hcrib : ∀ p ∈ cribs, P p.1 = letterVal p.2) :
    (∀ l ∈ oddClass, P 60 ≠ letterVal l) ∧
    (∀ l ∈ evenClass, P 56 ≠ letterVal l) ∧
    (∀ i ∈ [57, 58, 59], par (σ (P (i + 4))) ≠ par (σ (P i))) := by
  obtain ⟨hodd, heven⟩ := class_sigma hM hcrib
  have hB : P 64 = letterVal 'B' := hcrib (64, 'B') (by decide +kernel)
  have s60 := (k4_stehle hM 60 (by decide)).1
  have s56 := (k4_stehle hM 56 (by decide)).1
  rw [hB, hodd 'B' (by decide)] at s60
  have h60 : par (σ (P 60)) = c := z2_eq_of_add_one _ _ s60
  refine ⟨?_, ?_, ?_⟩
  · intro l hl h
    rw [h, hodd l hl] at h60
    -- h60 : 1 + c = c
    revert h60; generalize c = x; revert x; decide
  · intro l hl h
    rw [h, heven l hl, h60] at s56
    exact z2_ne_add_one c s56
  · intro i hi h
    rw [(k4_stehle hM i (by simp at hi ⊢; omega)).1] at h
    exact z2_add_one_ne _ h

/-- A substitution realizing the parity classes with `c = 0`: the identity with four
transpositions (E↔L, I↔N, O↔T, S↔D) so that E, I, O, S land on odd values and L, N, T on
even ones; B, H, R and A, C, K already have the right parity. Given as a lookup table. -/
def σ₀table : List ℕ := [0, 1, 2, 18, 11, 5, 6, 7, 13, 9, 10, 4, 12, 8, 19, 15, 16, 17, 3, 14,
  20, 21, 22, 23, 24, 25]

def σ₀ (x : ZMod 26) : ZMod 26 := ((σ₀table.getD x.val 0 : ℕ) : ZMod 26)

/-- `σ₀` is a genuine substitution alphabet: a bijection of the 26 letters. -/
theorem σ₀_injective : Function.Injective σ₀ := by decide +kernel

/-- `σ₀` puts every odd-class crib letter on an odd value and every even-class one on an
even value (letter values: B1 E4 H7 I8 O14 R17 S18 and A0 C2 K10 L11 N13 T19). -/
theorem σ₀_classes : (∀ x ∈ ([1, 4, 7, 8, 14, 17, 18] : List (ZMod 26)), par (σ₀ x) = 1) ∧
    (∀ x ∈ ([0, 2, 10, 11, 13, 19] : List (ZMod 26)), par (σ₀ x) = 0) := by decide +kernel

/-- A 97-letter plaintext that agrees with both cribs and, elsewhere, uses A or B according
to the parity bit. It is deliberately not English: the point is that the model accepts it. -/
def witnessPlain (i : ℕ) : ZMod 26 :=
  match cribs.find? (fun p => p.1 == i) with
  | some p => letterVal p.2
  | none => if par (ct i + i) = 0 then 0 else 1

theorem witness_agrees_with_cribs : ∀ p ∈ cribs, witnessPlain p.1 = letterVal p.2 := by
  decide +kernel

theorem witness_passes_filter :
    ∀ i ∈ List.range' 1 97, par (σ₀ (witnessPlain i)) = par (ct i + i) + 0 := by
  decide +kernel

/-- **Joint satisfiability.** There is a substitution, a constant and a keystream under which
the model holds at all 97 positions with a plaintext agreeing with both cribs. Together with
`k4_stehle` and `k4_window` this shows the two anomalies are consistent with the model and
with each other, while `realizable_iff` shows they constrain only one bit per position. -/
theorem k4_model_satisfiable :
    ∃ (σ : ZMod 26 → ZMod 26) (c : ZMod 2) (P k : ℕ → ZMod 26),
      (∀ p ∈ cribs, P p.1 = letterVal p.2) ∧ ∀ i, 1 ≤ i → i ≤ 97 → SubThenAdd σ P k ct c i := by
  refine ⟨σ₀, 0, witnessPlain, fun i => ct i - σ₀ (witnessPlain i), witness_agrees_with_cribs, ?_⟩
  intro i h1 h97
  refine ⟨by ring, ?_⟩
  have hf := witness_passes_filter i (by simp only [List.mem_range'_1]; omega)
  rw [sub_add_eq_add_sub, par_sub, hf, add_zero, zmod2_add_self]

end K4

end K4Parity
