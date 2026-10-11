import K4Parity.Data

/-!
# Exact chance figures

* `card_consistent`: for any positions grouped by plaintext letter, the number of ways to
  assign cipher letters so that every group agrees on parity is `2^#groups · 13^#positions`.
* `k4_card_consistent`, `k4_chance`: for K4's 24 crib positions and 13 crib letters, that is
  `2^13 · 13^24` of the `26^24` assignments, a fraction of exactly `2⁻¹¹ = 1/2048`. This is
  the null "each crib cipher letter independent and uniform".
* `card_superset_disjoint`, `sigma_split_count`, `sigma_split_chance`: of the `C(26,13)`
  ways to choose which 13 letters a substitution sends to odd values, exactly `3432` separate
  {B,E,H,I,O,R,S} from {A,C,K,L,N,T} (either way round): 1 in 3030.48. (A uniformly random
  bijection `σ` makes every 13-set equally likely to be `σ⁻¹(odd)`, each from `13!·13!`
  bijections; that reduction is standard and not formalised here.)

What is **not** formalised: the look-elsewhere correction (how many statistics were tried
before this one was noticed). That is a judgement about the search, not a theorem.
-/

namespace K4Parity

open Finset

/-- For each shift and bit, exactly 13 of the 26 letters land on that parity. -/
theorem card_par_fiber (a : ZMod 26) (b : ZMod 2) :
    (univ.filter fun x : ZMod 26 => par (x + a) = b).card = 13 := by
  revert a b; decide +kernel

/-- **Counting theorem.** Positions `S`, a surjective grouping `g : S → G` (by plaintext
letter), and position offsets `p`. The assignments `f : S → ZMod 26` under which every group
agrees on `par (f s + p s)` number exactly `2^|G| · 13^|S|`. -/
theorem card_consistent {S G : Type*} [Fintype S] [DecidableEq S] [Fintype G] [DecidableEq G]
    (g : S → G) (hg : Function.Surjective g) (p : S → ZMod 26) :
    (univ.filter fun f : S → ZMod 26 =>
        ∀ s t, g s = g t → par (f s + p s) = par (f t + p t)).card =
      2 ^ Fintype.card G * 13 ^ Fintype.card S := by
  classical
  let B : (G → ZMod 2) → Finset (S → ZMod 26) :=
    fun b => univ.filter fun f => ∀ s, par (f s + p s) = b (g s)
  have hunion : (univ.filter fun f : S → ZMod 26 =>
      ∀ s t, g s = g t → par (f s + p s) = par (f t + p t)) = univ.biUnion B := by
    ext f
    simp only [mem_filter, mem_univ, true_and, mem_biUnion, B]
    constructor
    · intro hf
      exact ⟨fun x => par (f (Function.surjInv hg x) + p (Function.surjInv hg x)),
        fun s => hf s _ (Function.surjInv_eq hg (g s)).symm⟩
    · rintro ⟨b, hb⟩ s t hst
      rw [hb s, hb t, hst]
  have hdisj : ((univ : Finset (G → ZMod 2)) : Set (G → ZMod 2)).PairwiseDisjoint B := by
    intro b₁ _ b₂ _ hne
    rw [Function.onFun, Finset.disjoint_left]
    intro f hf₁ hf₂
    simp only [mem_filter, mem_univ, true_and, B] at hf₁ hf₂
    apply hne
    funext x
    obtain ⟨s, rfl⟩ := hg x
    rw [← hf₁ s, hf₂ s]
  have hcard : ∀ b, (B b).card = 13 ^ Fintype.card S := by
    intro b
    have h1 : (B b).card = Fintype.card {f : S → ZMod 26 // ∀ s, par (f s + p s) = b (g s)} := by
      rw [Fintype.card_subtype]
    rw [h1, Fintype.card_congr
      (@Equiv.subtypePiEquivPi S (fun _ => ZMod 26) (fun s x => par (x + p s) = b (g s))),
      Fintype.card_pi]
    simp only [Fintype.card_subtype, card_par_fiber, prod_const, card_univ]
  rw [hunion, card_biUnion hdisj]
  simp only [hcard, sum_const, card_univ, Fintype.card_fun, ZMod.card, smul_eq_mul]

/-! ## K4 instance -/

/-- Crib entry `s`, for `s = 0..23`. -/
def cribAt (s : Fin 24) : ℕ × Char := cribs.getD s.val (0, '?')

/-- The 13 crib letters in order of first appearance. -/
def cribAlpha : List Char := ['E', 'A', 'S', 'T', 'N', 'O', 'R', 'H', 'B', 'L', 'I', 'C', 'K']

theorem cribAlpha_complete : ∀ s ∈ List.finRange 24, (cribAt s).2 ∈ cribAlpha := by decide +kernel

/-- Group index of crib entry `s`. -/
def letterIdx (s : Fin 24) : Fin 13 :=
  ⟨cribAlpha.idxOf (cribAt s).2 % 13, Nat.mod_lt _ (by norm_num)⟩

/-- A first occurrence of each letter, so the grouping is onto. -/
def firstOcc (y : Fin 13) : Fin 24 :=
  ([0, 1, 2, 3, 4, 5, 6, 8, 13, 16, 17, 19, 23] : List (Fin 24)).getD y.val 0

theorem letterIdx_firstOcc' : ∀ y ∈ List.finRange 13, letterIdx (firstOcc y) = y := by decide +kernel

theorem letterIdx_firstOcc (y : Fin 13) : letterIdx (firstOcc y) = y :=
  letterIdx_firstOcc' y (List.mem_finRange y)

theorem letterIdx_surjective : Function.Surjective letterIdx :=
  fun y => ⟨firstOcc y, letterIdx_firstOcc y⟩

theorem letterIdx_eq_iff' : ∀ s ∈ List.finRange 24, ∀ t ∈ List.finRange 24,
    (letterIdx s = letterIdx t ↔ (cribAt s).2 = (cribAt t).2) := by
  decide +kernel

theorem letterIdx_eq_iff (s t : Fin 24) : letterIdx s = letterIdx t ↔ (cribAt s).2 = (cribAt t).2 :=
  letterIdx_eq_iff' s (List.mem_finRange s) t (List.mem_finRange t)

/-- **Exact count for K4's crib pattern.** Of the `26^24` ways to put cipher letters at the
24 crib positions, exactly `2^13 · 13^24` make every repeated plaintext letter agree. -/
theorem k4_card_consistent :
    (univ.filter fun f : Fin 24 → ZMod 26 =>
        ∀ s t, (cribAt s).2 = (cribAt t).2 →
          par (f s + (cribAt s).1) = par (f t + (cribAt t).1)).card = 2 ^ 13 * 13 ^ 24 := by
  have h := card_consistent letterIdx letterIdx_surjective (fun s => ((cribAt s).1 : ZMod 26))
  simp only [Fintype.card_fin] at h
  convert h using 3 with f
  simp only [letterIdx_eq_iff]

/-- The carved ciphertext is one of them. -/
theorem k4_is_consistent :
    ∀ s ∈ List.finRange 24, ∀ t ∈ List.finRange 24, (cribAt s).2 = (cribAt t).2 →
      par (ct (cribAt s).1 + (cribAt s).1) = par (ct (cribAt t).1 + (cribAt t).1) := by
  decide +kernel

/-- **The chance is exactly `2⁻¹¹`.** -/
theorem k4_chance :
    ((2 ^ 13 * 13 ^ 24 : ℕ) : ℚ) / (Fintype.card (Fin 24 → ZMod 26) : ℚ) = 1 / 2 ^ 11 := by
  rw [Fintype.card_fun, ZMod.card, Fintype.card_fin]
  norm_num

/-! ## The plaintext-alphabet split -/

/-- Subsets of size `k` of `U` that contain `A` and avoid `B` correspond to subsets of size
`k − |A|` of what is left. -/
theorem card_superset_disjoint {α : Type*} [DecidableEq α] (U A B : Finset α) (k : ℕ)
    (hA : A ⊆ U) (hAB : Disjoint A B) (hk : A.card ≤ k) :
    ((U.powersetCard k).filter fun O => A ⊆ O ∧ Disjoint B O).card =
      (U \ (A ∪ B)).card.choose (k - A.card) := by
  rw [← card_powersetCard]
  apply card_nbij' (fun O => O \ A) (fun T => T ∪ A)
  · intro O hO
    rw [mem_coe, mem_filter, mem_powersetCard] at hO
    rw [mem_coe, mem_powersetCard]
    obtain ⟨⟨hOU, hOk⟩, hAO, hBO⟩ := hO
    refine ⟨fun x hx => ?_, ?_⟩
    · rw [mem_sdiff] at hx ⊢
      refine ⟨hOU hx.1, fun h => ?_⟩
      rcases mem_union.1 h with h | h
      · exact hx.2 h
      · exact Finset.disjoint_left.1 hBO h hx.1
    · rw [card_sdiff_of_subset hAO, hOk]
  · intro T hT
    rw [mem_coe, mem_powersetCard] at hT
    rw [mem_coe, mem_filter, mem_powersetCard]
    obtain ⟨hTU, hTk⟩ := hT
    have hTA : Disjoint T A := by
      rw [Finset.disjoint_left]; intro x hx hxA
      exact (mem_sdiff.1 (hTU hx)).2 (mem_union_left _ hxA)
    have hBT : Disjoint B T := by
      rw [Finset.disjoint_left]; intro x hxB hx
      exact (mem_sdiff.1 (hTU hx)).2 (mem_union_right _ hxB)
    refine ⟨⟨union_subset (fun x hx => (mem_sdiff.1 (hTU hx)).1) hA, ?_⟩,
      subset_union_right, disjoint_union_right.2 ⟨hBT, hAB.symm⟩⟩
    rw [card_union_of_disjoint hTA, hTk]; omega
  · intro O hO
    rw [mem_coe, mem_filter] at hO
    exact sdiff_union_of_subset hO.2.1
  · intro T hT
    rw [mem_coe, mem_powersetCard] at hT
    have hTA : Disjoint T A := by
      rw [Finset.disjoint_left]; intro x hx hxA
      exact (mem_sdiff.1 (hT.1 hx)).2 (mem_union_left _ hxA)
    exact union_sdiff_cancel_right hTA

/-- Letter values of the two classes: B1 E4 H7 I8 O14 R17 S18 and A0 C2 K10 L11 N13 T19. -/
def oddVals : Finset (ZMod 26) := {1, 4, 7, 8, 14, 17, 18}
def evenVals : Finset (ZMod 26) := {0, 2, 10, 11, 13, 19}

theorem oddVals_eq : oddVals = (oddClass.map letterVal).toFinset := by decide +kernel
theorem evenVals_eq : evenVals = (evenClass.map letterVal).toFinset := by decide +kernel

/-- **3432** of the 13-letter "odd" sets split the classes, either way round. -/
theorem sigma_split_count :
    ((univ.powersetCard 13).filter fun O : Finset (ZMod 26) =>
      (oddVals ⊆ O ∧ Disjoint evenVals O) ∨ (evenVals ⊆ O ∧ Disjoint oddVals O)).card = 3432 := by
  rw [filter_or, card_union_of_disjoint]
  · rw [card_superset_disjoint _ _ _ _ (subset_univ _) (by decide) (by decide),
        card_superset_disjoint _ _ _ _ (subset_univ _) (by decide) (by decide)]
    have h1 : (univ \ (oddVals ∪ evenVals)).card = 13 := by decide +kernel
    have h2 : (univ \ (evenVals ∪ oddVals)).card = 13 := by decide +kernel
    have h3 : oddVals.card = 7 := by decide
    have h4 : evenVals.card = 6 := by decide
    rw [h1, h2, h3, h4]
    decide
  · rw [Finset.disjoint_left]
    intro O h₁ h₂
    simp only [mem_filter] at h₁ h₂
    have h1 : (1 : ZMod 26) ∈ O := h₁.2.1 (by decide)
    exact Finset.disjoint_left.1 h₂.2.2 (by decide : (1 : ZMod 26) ∈ oddVals) h1

theorem sigma_split_chance :
    ((3432 : ℕ) : ℚ) / ((univ : Finset (ZMod 26)).powersetCard 13).card = 3432 / 10400600 := by
  rw [card_powersetCard, card_univ, ZMod.card, Nat.choose_eq_factorial_div_factorial (by norm_num)]
  norm_num [Nat.factorial]

end K4Parity
