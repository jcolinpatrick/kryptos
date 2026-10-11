import Mathlib

/-!
# Parity on `ZMod 26`

Letters are numbered `A = 0, …, Z = 25` and live in `ZMod 26`. Because `2 ∣ 26`,
reduction mod 2 is a well-defined ring homomorphism `ZMod 26 →+* ZMod 2`. That single
fact is what lets a parity statement survive the mod-26 wrap-around of every additive
classical cipher, and every lemma below is a consequence of it.
-/

namespace K4Parity

/-- Parity of a letter value: the ring homomorphism `ZMod 26 → ZMod 2`. -/
def par : ZMod 26 →+* ZMod 2 := ZMod.castHom (by norm_num) (ZMod 2)

@[simp] lemma par_natCast (n : ℕ) : par (n : ZMod 26) = (n : ZMod 2) := map_natCast par n

/-- In characteristic 2, subtraction is addition. -/
lemma zmod2_sub_eq_add (a b : ZMod 2) : a - b = a + b := by
  revert a b; decide

lemma zmod2_add_self (a : ZMod 2) : a + a = 0 := by
  revert a; decide

/-- Parity of a difference is the sum of parities. -/
lemma par_sub (x y : ZMod 26) : par (x - y) = par x + par y := by
  rw [map_sub, zmod2_sub_eq_add]

lemma par_neg (x : ZMod 26) : par (-x) = par x := by
  rw [map_neg]; revert x; intro x; generalize par x = a; revert a; decide

/-- An odd multiplier does not change parity. -/
lemma par_mul_odd (u x : ZMod 26) (hu : par u = 1) : par (u * x) = par x := by
  rw [map_mul, hu, one_mul]

/-! ## Small facts about `ZMod 2`, each closed by finite check -/

lemma z2_add_add_cancel (a c : ZMod 2) : a + (a + c) = c := by revert a c; decide
lemma z2_ne_add_one (x : ZMod 2) : x ≠ x + 1 := by revert x; decide
lemma z2_eq_of_add_one (x c : ZMod 2) (h : 1 + c = x + 1) : x = c := by revert x c; decide
lemma z2_add_one_ne (x : ZMod 2) : x + 1 ≠ x := by revert x; decide
lemma z2_key_diff (a b x y c : ZMod 2) (h₀ : b + x = c) (hL : a + (x + y) = c) : a + b = y := by
  revert a b x y c; decide
lemma z2_flip (a b : ZMod 2) (h : a + 1 = b + 0 + 1 + 1) : a = b + 1 := by revert a b; decide

/-- Shifting a position by 4 does not change its parity. -/
lemma par_pos_add_four (i : ℕ) : par ((i + 4 : ℕ) : ZMod 26) = par (i : ZMod 26) := by
  rw [par_natCast, par_natCast, Nat.cast_add]
  generalize (i : ZMod 2) = a; revert a; decide

end K4Parity
