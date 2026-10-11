import K4Parity

/-! Run with `lake env lean AxiomAudit.lean`. Every line must report a subset of
`[propext, Classical.choice, Quot.sound]`; `sorryAx` would mean an unproved step and
`Lean.ofReduceBool` a step trusted to the compiler rather than the kernel. -/

open K4Parity
-- Data
#print axioms parity_consistent
#print axioms sameLetterPairs_length
#print axioms independent_checks
#print axioms class_table
#print axioms cross_block_pairs
#print axioms stehle_run
#print axioms stehle_run_maximal
-- Invariance
#print axioms par_key_add_pos
#print axioms key_parity_by_letter
#print axioms parity_consistent_any_offset
#print axioms parity_consistent_relabel
#print axioms swap_parityUniform
#print axioms swap_not_affine
#print axioms ka_agreeing_pairs
#print axioms doubles_force_opposite
#print axioms bean_pair_any_numbering
#print axioms s_check_iff_t_check
-- Model
#print axioms eq1
#print axioms key_diff_parity
#print axioms stehle_step
#print axioms realizable_iff
#print axioms stehle_from_filter
#print axioms k4_stehle
#print axioms k4_window
#print axioms σ₀_injective
#print axioms k4_model_satisfiable
-- Order
#print axioms sub_then_add_structural
#print axioms add_then_sub_forces_uniform
#print axioms add_then_sub_refuted
#print axioms additive_layers_merge
#print axioms transposition_last
#print axioms columnar_odd_width
-- Counting
#print axioms card_consistent
#print axioms k4_card_consistent
#print axioms k4_chance
#print axioms card_superset_disjoint
#print axioms sigma_split_count
#print axioms sigma_split_chance
