#!/usr/bin/env python3
"""Build the canonical experiment ledger from all available sources.

Cross-references:
  - scripts/*.py (actual files on disk)
  - framework_inventory.json (agent-generated catalog)
  - results/*.json (structured result artifacts)
  - artifacts/*.json (structured artifact files)
  - reports/*.summary.json (report summary JSONs)
  - reports/*.md + memory/ (prose-only verdicts, manually coded below)

Output:
  - data/experiment_ledger.json (machine-readable, one entry per script)
  - data/experiment_ledger.csv (human-readable table)

Usage:
    python3 scripts/build_experiment_ledger.py
"""

import csv
import json
import os
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# 1. Collect all actual script files
# ---------------------------------------------------------------------------

def get_all_scripts() -> list[str]:
    """Return sorted list of all .py scripts in scripts/."""
    scripts_dir = PROJECT_ROOT / "scripts"
    return sorted(f for f in os.listdir(scripts_dir) if f.endswith(".py"))


# ---------------------------------------------------------------------------
# 2. Load framework_inventory.json
# ---------------------------------------------------------------------------

def load_framework_inventory() -> dict[str, dict]:
    """Load the agent-generated inventory. Returns {name: entry}."""
    inv_path = PROJECT_ROOT / "framework_inventory.json"
    if not inv_path.exists():
        return {}
    with open(inv_path) as f:
        data = json.load(f)
    return {s["name"]: s for s in data.get("scripts", [])}


# ---------------------------------------------------------------------------
# 3. Scan results/ and artifacts/ for machine-readable outputs
# ---------------------------------------------------------------------------

def scan_result_files() -> dict[str, str]:
    """Map script base names to result file paths."""
    mapping: dict[str, str] = {}
    for results_dir in ("results", "artifacts"):
        rdir = PROJECT_ROOT / results_dir
        if not rdir.exists():
            continue
        for item in os.listdir(rdir):
            path = rdir / item
            # Direct JSON files
            if item.endswith(".json") and path.is_file():
                base = item.replace(".json", "")
                mapping[base] = f"{results_dir}/{item}"
            # Subdirectories with summary.json
            elif path.is_dir():
                for sub in os.listdir(path):
                    if sub.endswith(".json"):
                        mapping[item] = f"{results_dir}/{item}/{sub}"
                        break
    # Also scan reports/*.summary.json
    reports_dir = PROJECT_ROOT / "reports"
    if reports_dir.exists():
        for item in os.listdir(reports_dir):
            if item.endswith(".summary.json"):
                base = item.replace(".summary.json", "")
                mapping[base] = f"reports/{item}"
    return mapping


# ---------------------------------------------------------------------------
# 4. Prose-sourced verdicts (from MEMORY.md, eliminations.md, reports/)
#    This is the manual reconciliation layer — each entry was extracted from
#    documented prose with experiment IDs, config counts, and verdicts.
# ---------------------------------------------------------------------------

# fmt: off
PROSE_VERDICTS: dict[str, dict] = {
    # ── E-CFM series (from MEMORY.md tables) ──
    "e_cfm_00_drusilla_hypothesis": {"verdict": "NOISE", "best_score": "5/24", "configs": "~8K", "evidence": "report+json", "category": "e_cfm"},
    "e_cfm_01_running_key_foreign": {"verdict": "NOISE", "best_score": "5/24", "configs": "~12K", "evidence": "report+json", "category": "e_cfm"},
    "e_cfm_02_mono_running_constrain": {"verdict": "UNDERDETERMINED", "best_score": "—", "configs": "100K", "evidence": "report+json", "category": "e_cfm"},
    "e_cfm_03_null_extraction": {"verdict": "NOISE", "best_score": "0/24", "configs": "~358K", "evidence": "report+json", "category": "e_cfm"},
    "e_cfm_04_homophonic_partition": {"verdict": "ELIMINATED", "best_score": "—", "configs": "~9.4K", "evidence": "report+json", "category": "e_cfm"},
    "e_cfm_05_nomenclator_model": {"verdict": "ELIMINATED", "best_score": "—", "configs": "~6K", "evidence": "report+json", "category": "e_cfm"},
    "e_cfm_06_east_constraint": {"verdict": "NOISE+TOOL", "best_score": "0/24", "configs": "4M", "evidence": "report+json", "category": "e_cfm"},
    "e_cfm_07_k3_rotational": {"verdict": "NOISE", "best_score": "4/24", "configs": "~1K", "evidence": "report+json", "category": "e_cfm"},
    "e_cfm_08_trans_key_scoring": {"verdict": "UNDERDETERMINED", "best_score": "—", "configs": "28M", "evidence": "report+json", "category": "e_cfm"},
    "e_cfm_09_gutenberg_east_scan": {"verdict": "NOISE", "best_score": "0/24", "configs": "47.4M chars", "evidence": "report+json", "category": "e_cfm"},
    "e_cfm_10_medusa_rule": {"verdict": "UNCERTAIN", "best_score": "—", "configs": "—", "evidence": "none", "category": "e_cfm"},
    "e_cfm_11_anomaly_key_derivation": {"verdict": "UNCERTAIN", "best_score": "—", "configs": "—", "evidence": "none", "category": "e_cfm"},

    # ── E-EGYPT series ──
    "e_egypt_00_corpus_pipeline": {"verdict": "NOISE", "best_score": "0/24", "configs": "113.9M", "evidence": "report+json", "category": "e_egypt"},
    "e_egypt_01_columnar_sweep": {"verdict": "NOISE", "best_score": "0/24", "configs": "1.19B", "evidence": "report+json", "category": "e_egypt"},

    # ── E-SPLIT series ──
    "e_split_00_installation_key_split": {"verdict": "NOISE", "best_score": "6/24", "configs": "51,534", "evidence": "report+json", "category": "e_split"},

    # ── E-FRAC series (from frac_final_synthesis.md) ──
    "e_frac_01_w9_structural": {"verdict": "NOISE", "best_score": "14/24", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_02b_colprog_baseline": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_05_mixed_alphabets": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_06_w11w13_structural": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_07_bimodal_w9": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_08_bimodal_multiwidth": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_09_bimodal_structure": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_10_strip_bimodal": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_11_bimodal_validity": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_12_w9_strict_reeval": {"verdict": "NOISE", "best_score": "14/24", "configs": "362K", "evidence": "report", "category": "e_frac"},
    "e_frac_13_ic_analysis": {"verdict": "NOT_SIGNIFICANT", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_14_autocorrelation": {"verdict": "NOT_SIGNIFICANT", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_15_linear_key": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_16_key_distribution": {"verdict": "RETRACTED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_17_beaufort_running_key": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_18_crib_sensitivity": {"verdict": "CONFIRMED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_19_pre_ene_analysis": {"verdict": "ARTIFACT", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_20_residue_conflict_map": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_21_fractionation_structural_proofs": {"verdict": "ELIMINATED", "best_score": "—", "configs": "10 families", "evidence": "report+json", "category": "e_frac"},
    "e_frac_22_null_cipher_intervals": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_23_beaufort_key_reconstruction": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_24_running_key_profile": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_25_transposition_entropy": {"verdict": "RETRACTED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_26_w9_quadgram": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_27_bean_width_profile": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_28_w9_bean_key_sa": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_29_w6w8_crib_scoring": {"verdict": "NOISE", "best_score": "—", "configs": "~600K", "evidence": "report", "category": "e_frac"},
    "e_frac_30_w10_w15_crib_scoring": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_31_bean_random_perms": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_32_simple_transposition_sweep": {"verdict": "NOISE", "best_score": "13/24", "configs": "14,035", "evidence": "report", "category": "e_frac"},
    "e_frac_33_fitness_landscape": {"verdict": "UNDERDETERMINED", "best_score": "24/24(30%)", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_33b_perperiod_fix": {"verdict": "UNDERDETERMINED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_34_multi_objective_oracle": {"verdict": "TOOL", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_35_bean_period_impossibility": {"verdict": "PROOF", "best_score": "—", "configs": "universal", "evidence": "report", "category": "e_frac"},
    "e_frac_36_period8_bean_hillclimb": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_37_autokey_arbitrary_transposition": {"verdict": "ELIMINATED", "best_score": "21/24 max", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_38_bean_key_model_constraints": {"verdict": "ELIMINATED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_39_running_key_bipartite": {"verdict": "UNDERDETERMINED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_40_carter_quadgram_screen": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_40b_random_key_control": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_41_word_discriminator": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_42_refined_discriminator": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_43_bigram_discriminator": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_44_information_theoretic": {"verdict": "PROOF", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_45_grid_reading_orders": {"verdict": "NOISE", "best_score": "12/24", "configs": "3,888", "evidence": "report", "category": "e_frac"},
    "e_frac_46_double_columnar": {"verdict": "NOISE", "best_score": "15/24", "configs": "2,958,400", "evidence": "report", "category": "e_frac"},
    "e_frac_47_myszkowski": {"verdict": "NOISE", "best_score": "15/24", "configs": "226,390", "evidence": "report", "category": "e_frac"},
    "e_frac_48_amsco_disrupted": {"verdict": "NOISE", "best_score": "14/24", "configs": "361,280", "evidence": "report", "category": "e_frac"},
    "e_frac_49_running_key_columnar": {"verdict": "NOISE", "best_score": "0/24", "configs": "8.4B checks", "evidence": "report", "category": "e_frac"},
    "e_frac_50_running_key_all_families": {"verdict": "NOISE", "best_score": "0/24", "configs": "8.8B checks", "evidence": "report", "category": "e_frac"},
    "e_frac_51_english_key_detection": {"verdict": "ELIMINATED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_52_three_layer": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_53_mono_inner_periodic": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_frac"},
    "e_frac_54_mono_running_key_detection": {"verdict": "UNDERDETERMINED", "best_score": "—", "configs": "1,500+", "evidence": "report", "category": "e_frac"},
    "e_frac_55_bean_surviving_periods": {"verdict": "NOISE", "best_score": "14/24(p8)", "configs": "—", "evidence": "report", "category": "e_frac"},

    # ── E-ANTIPODES series ──
    "e_antipodes_01_hill_transposition": {"verdict": "ELIMINATED", "best_score": "0", "configs": "2.7M", "evidence": "report", "category": "e_antipodes"},
    "e_antipodes_02_mono_fixed_running_key": {"verdict": "ELIMINATED", "best_score": "—", "configs": "3.5M", "evidence": "report", "category": "e_antipodes"},
    "e_antipodes_03_k3k4_continuity": {"verdict": "NOISE", "best_score": "9/24", "configs": "14.9M", "evidence": "report", "category": "e_antipodes"},
    "e_antipodes_04_sculpture_running_key": {"verdict": "NOISE", "best_score": "6/24", "configs": "17,238", "evidence": "report+json", "category": "e_antipodes"},
    "e_antipodes_05_gromark_vimark_trans": {"verdict": "ELIMINATED", "best_score": "0", "configs": "864K", "evidence": "report", "category": "e_antipodes"},
    "e_antipodes_06_tableau_path_key": {"verdict": "NOISE", "best_score": "7/24", "configs": "60,792", "evidence": "report", "category": "e_antipodes"},
    "e_antipodes_07_yar_block_cipher": {"verdict": "NOISE", "best_score": "6/24", "configs": "14,250", "evidence": "report", "category": "e_antipodes"},
    "e_antipodes_08_stream_context": {"verdict": "NOISE", "best_score": "6/24", "configs": "2,727", "evidence": "report+json", "category": "e_antipodes"},
    "e_antipodes_09_layertwo_trim": {"verdict": "NOISE", "best_score": "7/24", "configs": "12,692", "evidence": "report", "category": "e_antipodes"},
    "e_antipodes_10_coordinate_grid": {"verdict": "NOISE", "best_score": "6/24", "configs": "915", "evidence": "report", "category": "e_antipodes"},

    # ── E-CHART series ──
    "e_chart_01_running_key": {"verdict": "ELIMINATED", "best_score": "6/24", "configs": "840K", "evidence": "report+json", "category": "e_chart"},
    "e_chart_02_autokey": {"verdict": "ELIMINATED", "best_score": "9/24", "configs": "25.2M", "evidence": "report+json", "category": "e_chart"},
    "e_chart_03_misspelling_tableau": {"verdict": "ELIMINATED", "best_score": "8/24", "configs": "364K", "evidence": "report+json", "category": "e_chart"},
    "e_chart_03b_reduced_misspelling": {"verdict": "ELIMINATED", "best_score": "8/24", "configs": "366K", "evidence": "report", "category": "e_chart"},
    "e_chart_04_morse_pattern": {"verdict": "ELIMINATED", "best_score": "6/24", "configs": "726K", "evidence": "report", "category": "e_chart"},
    "e_chart_05_antipodes_misspelling": {"verdict": "ELIMINATED", "best_score": "7/24", "configs": "~200K", "evidence": "report", "category": "e_chart"},
    "e_chart_06_herbert": {"verdict": "ELIMINATED", "best_score": "7/24", "configs": "968K", "evidence": "report", "category": "e_chart"},
    "e_chart_07_width9_cc": {"verdict": "ELIMINATED", "best_score": "10/24 FP", "configs": "14M+", "evidence": "report", "category": "e_chart"},
    "e_chart_08_noise_analysis": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_chart"},
    "e_chart_09_boundary_sweep": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_chart"},
    "e_chart_10_w9_sub": {"verdict": "ELIMINATED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_chart"},
    "e_chart_11_rotation": {"verdict": "ELIMINATED", "best_score": "6/24", "configs": "44.7K", "evidence": "report", "category": "e_chart"},

    # ── E-BESPOKE series ──
    "e_bespoke_01_misspelling_mods": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_bespoke"},
    "e_bespoke_02_abscissa_linear": {"verdict": "NOISE", "best_score": "5/24", "configs": "—", "evidence": "report+json", "category": "e_bespoke"},
    "e_bespoke_03_shift_values": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_bespoke"},
    "e_bespoke_04_t20_retest": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_bespoke"},
    "e_bespoke_05_98chars": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_bespoke"},
    "e_bespoke_06_doubles_cc": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_bespoke"},
    "e_bespoke_07_1indexed_params": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_bespoke"},
    "e_bespoke_08_t_alphabet": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_bespoke"},
    "e_bespoke_09_99chars_cc": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_bespoke"},
    "e_bespoke_10_rotation_grid": {"verdict": "ELIMINATED", "best_score": "6/24", "configs": "444K", "evidence": "report+json", "category": "e_bespoke"},
    "e_bespoke_11_tableau_extraction": {"verdict": "ELIMINATED", "best_score": "4/24", "configs": "1.2K", "evidence": "report", "category": "e_bespoke"},
    "e_bespoke_12_dryad_lookup": {"verdict": "ELIMINATED", "best_score": "6/24", "configs": "38K", "evidence": "report", "category": "e_bespoke"},

    # ── E-OPGOLD ──
    "e_opgold_01_keywords": {"verdict": "ELIMINATED", "best_score": "7/24", "configs": "2.3M", "evidence": "report+json", "category": "e_opgold"},
    "e_opgold_02_progressive": {"verdict": "ELIMINATED", "best_score": "5/24", "configs": "1.2K", "evidence": "report", "category": "e_opgold"},
    "e_opgold_03_british": {"verdict": "ELIMINATED", "best_score": "9/24", "configs": "10.7M", "evidence": "report+json", "category": "e_opgold"},

    # ── E-ROMAN ──
    "e_roman_01_comprehensive": {"verdict": "NOISE", "best_score": "4/24", "configs": "—", "evidence": "report+json", "category": "e_roman"},
    "e_roman_02_exhaustive": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_roman"},
    "e_roman_03_triple_trans": {"verdict": "ELIMINATED", "best_score": "8/24", "configs": "2.56M", "evidence": "report", "category": "e_roman"},
    "e_roman_03b_abscissa_coords": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_roman"},
    "e_roman_04_3d_grid": {"verdict": "ELIMINATED", "best_score": "8/24", "configs": "1.28M", "evidence": "report", "category": "e_roman"},
    "e_roman_04b_abscissa_coords": {"verdict": "ELIMINATED", "best_score": "7/24", "configs": "348K", "evidence": "report", "category": "e_roman"},
    "e_roman_05_anomaly_params": {"verdict": "ELIMINATED", "best_score": "6/24", "configs": "226.8K", "evidence": "report", "category": "e_roman"},

    # ── E-REF ──
    "e_ref_00_8row_grid": {"verdict": "NOISE", "best_score": "0/24", "configs": "4.5M", "evidence": "report+json", "category": "e_ref"},
    "e_ref_01_carter_chapterX": {"verdict": "NOISE", "best_score": "0/24", "configs": "—", "evidence": "report", "category": "e_ref"},
    "e_ref_02_strip_cipher": {"verdict": "NOISE", "best_score": "0/24", "configs": "86.5M", "evidence": "report+json", "category": "e_ref"},

    # ── E-HYBRID ──
    "e_hybrid_01_k3struct_extended": {"verdict": "NOISE", "best_score": "8/24", "configs": "408,480", "evidence": "report+json", "category": "e_hybrid"},

    # ── Notable E-S legacy with documented verdicts ──
    "e_s_06_double_columnar": {"verdict": "NOISE", "best_score": "15/24", "configs": "441M", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_09_bifid_algebraic": {"verdict": "ELIMINATED", "best_score": "—", "configs": "—", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_14_crib_perturbation": {"verdict": "CONFIRMED", "best_score": "+1 max", "configs": "—", "evidence": "report", "category": "e_s_legacy"},
    "e_s_18_turning_grille": {"verdict": "NOISE", "best_score": "16/24", "configs": "2M MC", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_19_double_columnar": {"verdict": "NOISE", "best_score": "16/24", "configs": "34.6M", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_22_amsco_disrupted": {"verdict": "NOISE", "best_score": "15/24", "configs": "—", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_27_bean_algebraic_proof": {"verdict": "RETRACTED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_s_legacy"},
    "e_s_28_bean_redundancy_proof": {"verdict": "PROOF", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_s_legacy"},
    "e_s_33_double_columnar": {"verdict": "ELIMINATED", "best_score": "0", "configs": "50.8M", "evidence": "report", "category": "e_s_legacy"},
    "e_s_33b_mixed_double_columnar": {"verdict": "ELIMINATED", "best_score": "0", "configs": "1B+", "evidence": "report", "category": "e_s_legacy"},
    "e_s_36_gronsfeld_p7": {"verdict": "ELIMINATED", "best_score": "0", "configs": "—", "evidence": "report", "category": "e_s_legacy"},
    "e_s_39_myszkowski": {"verdict": "ELIMINATED", "best_score": "—", "configs": "47,293", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_41_hill_transposition": {"verdict": "ELIMINATED", "best_score": "0", "configs": "—", "evidence": "report", "category": "e_s_legacy"},
    "e_s_42_bifid6x6_extended": {"verdict": "ELIMINATED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_s_legacy"},
    "e_s_42b_trifid_extended": {"verdict": "ELIMINATED", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_s_legacy"},
    "e_s_44_trifid_p16": {"verdict": "ELIMINATED", "best_score": "—", "configs": "—", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_49_word_segmentation_sa": {"verdict": "UNDERDETERMINED", "best_score": "24/24", "configs": "—", "evidence": "report", "category": "e_s_legacy"},
    "e_s_52_carter_columnar_running_key": {"verdict": "ELIMINATED", "best_score": "11/24", "configs": "7B", "evidence": "report", "category": "e_s_legacy"},
    "e_s_53_keyword_columnar_sweep": {"verdict": "ELIMINATED", "best_score": "0", "configs": "15,756", "evidence": "report", "category": "e_s_legacy"},
    "e_s_55_grid_route_sweep": {"verdict": "ELIMINATED", "best_score": "11/24", "configs": "16,224", "evidence": "report", "category": "e_s_legacy"},
    "e_s_88_redefence": {"verdict": "ELIMINATED", "best_score": "3/24", "configs": "rails 2-20", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_134_weltzeituhr_ddr_era": {"verdict": "NOISE", "best_score": "4/24", "configs": "—", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_145_dryad_matrix": {"verdict": "UNDERDETERMINED", "best_score": "3/24", "configs": "~65", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_151_hill_w9_yart": {"verdict": "ELIMINATED", "best_score": "0", "configs": "40.6M", "evidence": "report+json", "category": "e_s_legacy"},
    "e_s_152_nato_protocol": {"verdict": "NOISE", "best_score": "9/24", "configs": "—", "evidence": "report+json", "category": "e_s_legacy"},

    # ── Dragnet ──
    "dragnet_v4": {"verdict": "ELIMINATED", "best_score": "0", "configs": "667B", "evidence": "report+json", "category": "infrastructure"},

    # ── KryptosBot agent-generated scripts ──
    "e_ka_01_keyed_tableau_systematic": {"verdict": "NOISE", "best_score": "0", "configs": "5,040+", "evidence": "json", "category": "misc"},
    "e_ledger_01_systematic_elimination": {"verdict": "TOOL", "best_score": "—", "configs": "—", "evidence": "json", "category": "misc"},
    "e_poly_01_polyalphabetic_analysis": {"verdict": "ELIMINATED", "best_score": "—", "configs": "—", "evidence": "json", "category": "misc"},
    "e_s_berlin_extend": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "json", "category": "misc"},
    "e_stat_01_missing_tests": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "misc"},

    # ── Infrastructure / meta scripts ──
    "build_experiment_ledger": {"verdict": "TOOL", "best_score": "—", "configs": "—", "evidence": "self", "category": "infrastructure"},

    # ── E-TEAM (Operation Final Vector + earlier) ──
    "e_team_anomaly_extraction": {"verdict": "NOISE", "best_score": "—", "configs": "~500", "evidence": "json", "category": "e_team"},
    "e_team_artifact_cross": {"verdict": "NOISE", "best_score": "7/24", "configs": "~1,500", "evidence": "json", "category": "e_team"},
    "e_team_artifact_keys": {"verdict": "NOISE", "best_score": "5/24", "configs": "~500", "evidence": "json", "category": "e_team"},
    "e_team_book_cipher": {"verdict": "NOISE", "best_score": "5/24", "configs": "~800", "evidence": "json", "category": "e_team"},
    "e_team_cardan_grille": {"verdict": "NOISE", "best_score": "4/24", "configs": "~400", "evidence": "json", "category": "e_team"},
    "e_team_coding_chart": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "json", "category": "e_team"},
    "e_team_french_scan": {"verdict": "NOISE", "best_score": "0/24", "configs": "—", "evidence": "json", "category": "e_team"},
    "e_team_german_scan": {"verdict": "NOISE", "best_score": "0/24", "configs": "4.5M chars", "evidence": "json", "category": "e_team"},
    "e_team_homo_contradiction_search": {"verdict": "ELIMINATED", "best_score": "—", "configs": "—", "evidence": "json", "category": "e_team"},
    "e_team_homophonic_trans": {"verdict": "NOISE", "best_score": "—", "configs": "1.6M perms", "evidence": "json", "category": "e_team"},
    "e_team_i_position": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_team"},
    "e_team_italian_spanish_scan": {"verdict": "NOISE", "best_score": "0/24", "configs": "—", "evidence": "json", "category": "e_team"},
    "e_team_layered_nomenclator_verify": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "json", "category": "e_team"},
    "e_team_mono_trans_sa": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "json", "category": "e_team"},
    "e_team_narrative_pt": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_team"},
    "e_team_narrative_pt_v2": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "report", "category": "e_team"},
    "e_team_nomenclator_super": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "json", "category": "e_team"},
    "e_team_physical_transpositions": {"verdict": "NOISE", "best_score": "6/24", "configs": "~2,000", "evidence": "json", "category": "e_team"},
    "e_team_targeted_homo_trans": {"verdict": "NOISE", "best_score": "—", "configs": "—", "evidence": "json", "category": "e_team"},
    "e_team_weltzeituhr_procedural": {"verdict": "NOISE", "best_score": "3/24", "configs": "~300", "evidence": "json", "category": "e_team"},
    "e_team_whats_the_point": {"verdict": "NOISE", "best_score": "2/24", "configs": "~200", "evidence": "json", "category": "e_team"},
}
# fmt: on

# ---------------------------------------------------------------------------
# 5. Categorize scripts by prefix
# ---------------------------------------------------------------------------

CATEGORY_MAP = {
    "e_s_": "e_s_legacy",
    "e_frac_": "e_frac",
    "e_team_": "e_team",
    "e_cfm_": "e_cfm",
    "e_chart_": "e_chart",
    "e_bespoke_": "e_bespoke",
    "e_antipodes_": "e_antipodes",
    "e_egypt_": "e_egypt",
    "e_roman_": "e_roman",
    "e_explorer_": "e_explorer",
    "e_novel_": "e_novel",
    "e_opgold_": "e_opgold",
    "e_audit_": "e_audit",
    "e_ref_": "e_ref",
    "e_nsa_": "e_nsa",
    "e_rerun_": "e_rerun",
    "e_split_": "e_split",
    "e_hybrid_": "e_hybrid",
    "e_tableau_": "e_tableau",
    "e_webster_": "e_webster",
    "e_card_": "e_card",
    "e_disproof_": "e_disproof",
    "e_sa_": "e_sa",
    "e_recurrence_": "e_recurrence",
    "e_wtz_": "e_wtz",
    "k4_": "k4_early",
    "k3_": "infrastructure",
    "agent_k4_": "agent",
    "corpus_": "infrastructure",
    "dragnet_": "infrastructure",
    "hill_": "infrastructure",
    "solve_": "infrastructure",
    "card_": "infrastructure",
    "build_": "infrastructure",
}


def categorize(name: str) -> str:
    for prefix, cat in CATEGORY_MAP.items():
        if name.startswith(prefix):
            return cat
    return "misc"


# ---------------------------------------------------------------------------
# 6. Build the ledger
# ---------------------------------------------------------------------------

def build_ledger() -> list[dict]:
    all_scripts = get_all_scripts()
    inventory = load_framework_inventory()
    result_files = scan_result_files()

    ledger: list[dict] = []

    for script in all_scripts:
        base = script.replace(".py", "")
        inv_entry = inventory.get(script, {})
        prose = PROSE_VERDICTS.get(base, {})

        # Category
        category = prose.get("category") or inv_entry.get("category") or categorize(script)

        # Verdict — prefer prose (hand-verified) > inventory > "UNVERIFIED"
        verdict = prose.get("verdict", "")
        if not verdict:
            inv_summary = inv_entry.get("result_summary", "")
            if "ELIMINATED" in inv_summary.upper():
                verdict = "ELIMINATED"
            elif "NOISE" in inv_summary.upper():
                verdict = "NOISE"
            elif "UNDERDETERMINED" in inv_summary.upper():
                verdict = "UNDERDETERMINED"
            elif inv_summary:
                verdict = "DOCUMENTED"
            else:
                verdict = "UNVERIFIED"

        # Best score
        best_score = prose.get("best_score", "—")

        # Execution status
        has_json = False
        artifact_path = ""
        # Check result_files mapping (various name patterns)
        for key in (base, base.replace("e_cfm_", "e_cfm_").rstrip("_"),):
            if key in result_files:
                has_json = True
                artifact_path = result_files[key]
                break
        # Also check exact base name variations
        for rkey, rpath in result_files.items():
            if base in rkey or rkey in base:
                has_json = True
                artifact_path = rpath
                break

        has_result = inv_entry.get("has_results", False) or has_json
        evidence_type = prose.get("evidence", "")
        if not evidence_type:
            if has_json:
                evidence_type = "json"
            elif verdict != "UNVERIFIED":
                evidence_type = "inferred"
            else:
                evidence_type = "none"

        if verdict == "UNVERIFIED":
            status = "unverified"
        elif has_json or "json" in evidence_type:
            status = "ran_with_artifact"
        elif evidence_type in ("report", "report+json", "inferred"):
            status = "ran_no_artifact"
        else:
            status = "unverified"

        # Machine-readable result?
        machine_readable = "yes" if has_json else "no"

        # Re-run recommended?
        rerun = "no"
        rerun_reason = ""
        if verdict == "UNVERIFIED":
            rerun = "audit"
            rerun_reason = "No execution evidence found; verify if hypothesis is covered elsewhere before re-running"
        elif verdict == "UNDERDETERMINED":
            rerun = "no"
            rerun_reason = "Underdetermined by design (too many DOF); new constraints needed, not re-runs"
        elif verdict in ("NOISE", "ELIMINATED", "PROOF", "RETRACTED", "CONFIRMED", "TOOL", "NOT_SIGNIFICANT", "ARTIFACT", "NOISE+TOOL"):
            rerun = "no"
            rerun_reason = f"Verdict is final: {verdict}"
        elif verdict == "UNCERTAIN":
            rerun = "audit"
            rerun_reason = "No evidence found; may represent unique hypothesis"
        elif verdict == "DOCUMENTED":
            rerun = "no"
            rerun_reason = "Documented in inventory but no formal verdict"

        ledger.append({
            "script": script,
            "category": category,
            "status": status,
            "evidence_type": evidence_type,
            "verdict": verdict,
            "best_score": best_score,
            "configs_tested": prose.get("configs", "—"),
            "artifact_path": artifact_path,
            "machine_readable": machine_readable,
            "rerun_recommended": rerun,
            "reason": rerun_reason,
        })

    return ledger


# ---------------------------------------------------------------------------
# 7. Write outputs
# ---------------------------------------------------------------------------

def write_ledger(ledger: list[dict]) -> None:
    data_dir = PROJECT_ROOT / "data"
    data_dir.mkdir(exist_ok=True)

    # JSON
    json_path = data_dir / "experiment_ledger.json"
    output = {
        "metadata": {
            "generated": "2026-03-01",
            "total_scripts": len(ledger),
            "by_verdict": {},
            "by_status": {},
            "by_category": {},
            "notes": [
                "Canonical experiment ledger — one row per script in scripts/",
                "Verdicts: NOISE, ELIMINATED, UNDERDETERMINED, PROOF, TOOL, CONFIRMED, RETRACTED, NOT_SIGNIFICANT, ARTIFACT, UNCERTAIN, UNVERIFIED, DOCUMENTED",
                "Status: ran_with_artifact, ran_no_artifact, unverified",
                "Re-run: 'no' (verdict is final), 'audit' (check if hypothesis unique before re-running)",
                "[USER POLICY 2026-03-01] K4 uses a MASK before encryption; English IC is therefore mute as a discriminator",
            ],
        },
        "entries": ledger,
    }

    # Compute summary stats
    from collections import Counter
    output["metadata"]["by_verdict"] = dict(Counter(e["verdict"] for e in ledger).most_common())
    output["metadata"]["by_status"] = dict(Counter(e["status"] for e in ledger).most_common())
    output["metadata"]["by_category"] = dict(Counter(e["category"] for e in ledger).most_common())

    with open(json_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"  JSON ledger: {json_path} ({len(ledger)} entries)")

    # CSV
    csv_path = data_dir / "experiment_ledger.csv"
    fieldnames = [
        "script", "category", "status", "evidence_type", "verdict",
        "best_score", "configs_tested", "artifact_path",
        "machine_readable", "rerun_recommended", "reason",
    ]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ledger)
    print(f"  CSV ledger:  {csv_path} ({len(ledger)} entries)")


# ---------------------------------------------------------------------------
# 8. Print summary
# ---------------------------------------------------------------------------

def print_summary(ledger: list[dict]) -> None:
    from collections import Counter

    print("\n" + "=" * 70)
    print("EXPERIMENT LEDGER SUMMARY")
    print("=" * 70)

    print(f"\nTotal scripts: {len(ledger)}")

    verdicts = Counter(e["verdict"] for e in ledger)
    print("\nBy verdict:")
    for v, c in verdicts.most_common():
        print(f"  {v:25s} {c:4d}")

    statuses = Counter(e["status"] for e in ledger)
    print("\nBy execution status:")
    for s, c in statuses.most_common():
        print(f"  {s:25s} {c:4d}")

    reruns = Counter(e["rerun_recommended"] for e in ledger)
    print("\nRe-run recommended:")
    for r, c in reruns.most_common():
        print(f"  {r:25s} {c:4d}")

    categories = Counter(e["category"] for e in ledger)
    print("\nBy category:")
    for cat, c in categories.most_common():
        print(f"  {cat:25s} {c:4d}")

    # List unverified scripts that might need audit
    unverified = [e for e in ledger if e["verdict"] == "UNVERIFIED"]
    if unverified:
        print(f"\nUNVERIFIED scripts ({len(unverified)}) — audit needed:")
        for e in unverified[:20]:
            print(f"  {e['script']}")
        if len(unverified) > 20:
            print(f"  ... and {len(unverified) - 20} more")

    uncertain = [e for e in ledger if e["verdict"] == "UNCERTAIN"]
    if uncertain:
        print(f"\nUNCERTAIN scripts ({len(uncertain)}) — may represent unique hypotheses:")
        for e in uncertain:
            print(f"  {e['script']}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Building canonical experiment ledger...")
    ledger = build_ledger()
    write_ledger(ledger)
    print_summary(ledger)
