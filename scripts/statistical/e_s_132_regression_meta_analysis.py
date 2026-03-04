#!/usr/bin/env python3
"""
Cipher: statistical analysis
Family: statistical
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-132: Multiple Linear Regression Meta-Analysis of All K4 Experiments.

Encodes all 130+ experiments as feature vectors, runs MLR with crib_matches
as the dependent variable, computes entropy measures, and identifies which
cipher strategy features contribute most/least to score.

Uses ONLY stdlib (no numpy/sklearn) — implements OLS regression from scratch.
"""
import json
import math
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ── Experiment Catalog ──────────────────────────────────────────────────────
# Each entry: (experiment_id, best_crib_score, configs_tested, features_dict)
# Features are binary or numeric indicators of cipher strategy characteristics.

# Feature definitions:
# SUBSTITUTION FAMILIES (one-hot)
#   periodic_sub: periodic polyalphabetic (Vig/Beau/VB)
#   autokey: PT or CT autokey
#   running_key: running key from text
#   hill: Hill cipher
#   bifid: Bifid (5x5 or 6x6)
#   trifid: Trifid 3x3x3
#   playfair: Playfair/Two-Square/Four-Square
#   nihilist: Nihilist cipher
#   porta: Porta cipher
#   gronsfeld: Gronsfeld (digit-only)
#   gromark: Gromark/Vimark
#   quagmire: Quagmire I-IV
#   monoalpha: monoalphabetic substitution
#   mixed_alpha: mixed/keyword alphabet
#   affine: affine polyalphabetic
#   polynomial_key: polynomial/recurrence key generation
#   nonlinear_rec: non-linear recurrence keystream
#
# TRANSPOSITION FAMILIES (one-hot)
#   columnar: single columnar transposition
#   double_columnar: double columnar
#   myszkowski: Myszkowski transposition
#   grille: turning grille
#   route: route/grid cipher
#   amsco: AMSCO/disrupted columnar
#   decimation: decimation/skip cipher
#
# STRUCTURAL FEATURES (binary)
#   has_transposition: any transposition layer present
#   has_substitution: any substitution layer present
#   multi_layer: 2+ layers
#   three_layer: 3 layers
#   uses_sa: uses simulated annealing
#   uses_quadgrams: uses quadgram scoring
#   thematic_key: key derived from sculpture/theme
#   progressive_key: key from K0-K3 progressive solve
#   self_keying: CT/PT-derived key
#   width_7: tests width-7 transposition
#   algebraic_elim: algebraic/constraint elimination (vs statistical)
#
# NUMERIC FEATURES
#   log_configs: log10(configs_tested)
#   min_period: minimum period tested (0 if N/A)
#   max_period: maximum period tested (0 if N/A)

EXPERIMENTS = [
    # Session 4: Linear Recurrence
    ("S4-linrec", 6, 1000, {"polynomial_key": 1, "has_substitution": 1, "algebraic_elim": 1}),
    ("S4-compound", 12, 8_000_000, {"periodic_sub": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 1, "max_period": 22}),
    ("S4-running", 5, 1000, {"running_key": 1, "has_substitution": 1}),

    # Session 6: Substitution Ciphers
    ("S6-quagI", 6, 100_000, {"quagmire": 1, "has_substitution": 1, "algebraic_elim": 1, "min_period": 2, "max_period": 14}),
    ("S6-quagII-III", 6, 10_000, {"quagmire": 1, "has_substitution": 1, "uses_sa": 1, "min_period": 7, "max_period": 7}),
    ("S6-porta", 6, 10_000, {"porta": 1, "has_substitution": 1, "algebraic_elim": 1}),
    ("S6-digraphic", 6, 204_000, {"playfair": 1, "has_substitution": 1}),
    ("S6-vig+trans", 6, 6_233, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1}),
    ("S6-carter-rk", 10, 26_800_000, {"running_key": 1, "has_substitution": 1, "thematic_key": 1}),
    ("S6-famous-rk", 7, 21, {"running_key": 1, "has_substitution": 1, "thematic_key": 1}),

    # Session 7: E-01 through E-06
    ("E-01", 5, 100, {"thematic_key": 1, "progressive_key": 1}),
    ("E-02", 4, 100, {"thematic_key": 1}),
    ("E-03", 6, 1000, {"thematic_key": 1}),
    ("E-04", 6, 157_248, {"hill": 1, "has_substitution": 1, "algebraic_elim": 1}),
    ("E-05", 6, 10_000, {"periodic_sub": 1, "hill": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 2, "max_period": 5}),
    ("E-06", 6, 10_000, {"autokey": 1, "has_substitution": 1}),

    # Session 8: NSA Document
    ("S8-w7col+per", 10, 1_390_000, {"periodic_sub": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "min_period": 7, "max_period": 7}),
    ("S8-insertion", 6, 2_548, {"has_transposition": 1}),
    ("S8-7x14grid", 6, 25_700_000, {"route": 1, "has_transposition": 1}),
    ("S8-stride", 6, 434_000, {"has_transposition": 1}),

    # Session 9: Grid Transpositions
    ("S9-route", 6, 29, {"route": 1, "has_transposition": 1}),
    ("S9-railfence", 6, 100, {"has_transposition": 1}),
    ("S9-rowperm", 0, 100, {"has_transposition": 1, "algebraic_elim": 1}),
    ("S9-doublecol", 0, 100, {"double_columnar": 1, "has_transposition": 1, "algebraic_elim": 1}),

    # Session 10: Fractionation
    ("S10-hill234", 6, 9, {"hill": 1, "has_substitution": 1, "algebraic_elim": 1}),
    ("S10-trifid", 6, 1000, {"trifid": 1, "has_substitution": 1, "algebraic_elim": 1, "min_period": 2, "max_period": 8}),
    ("S10-bifid6", 6, 1000, {"bifid": 1, "has_substitution": 1, "algebraic_elim": 1, "min_period": 2, "max_period": 11}),

    # Session 11: E-S-06 through E-S-17
    ("E-S-06", 6, 441_000_000, {"periodic_sub": 1, "double_columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 2, "max_period": 14}),
    ("E-S-08", 15, 100, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "uses_sa": 1, "uses_quadgrams": 1, "min_period": 3, "max_period": 7}),
    ("E-S-09", 6, 1000, {"bifid": 1, "has_substitution": 1, "algebraic_elim": 1}),
    ("E-S-10", 6, 10_000, {"has_substitution": 1}),
    ("E-S-11", 11, 100_000, {"running_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),
    ("E-S-12", 6, 102, {"route": 1, "has_transposition": 1}),
    ("E-S-13", 6, 5_700, {"columnar": 1, "double_columnar": 1, "has_transposition": 1, "thematic_key": 1}),
    ("E-S-14", 6, 24, {"algebraic_elim": 1}),  # crib perturbation
    ("E-S-15", 6, 287, {"thematic_key": 1}),
    ("E-S-16", 24, 100, {"has_transposition": 1, "has_substitution": 1, "uses_sa": 1, "uses_quadgrams": 1}),  # SA artifact
    ("E-S-17", 6, 100, {}),  # null cipher extraction
    ("E-S-18", 16, 2_000_000, {"periodic_sub": 1, "grille": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 7, "max_period": 8}),

    # Session 12: E-S-19, E-S-20
    ("E-S-19", 16, 34_600_000, {"periodic_sub": 1, "double_columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 3, "max_period": 8}),
    ("E-S-20", 6, 1000, {"algebraic_elim": 1}),  # constraint propagation proof
    ("E-S-21", 24, 1000, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "uses_sa": 1, "uses_quadgrams": 1, "min_period": 7, "max_period": 7}),
    ("E-S-22", 15, 100_000, {"periodic_sub": 1, "amsco": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 7, "max_period": 8}),

    # Session 12 continued
    ("E-S-23", 9, 100, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "uses_sa": 1, "min_period": 7, "max_period": 7}),
    ("E-S-24", 0, 29_000, {"thematic_key": 1, "has_substitution": 1}),

    # Session 13: Bean Analysis
    ("E-S-25", 6, 1, {"algebraic_elim": 1}),  # structural analysis
    ("E-S-26", 0, 1000, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "uses_sa": 1, "min_period": 7, "max_period": 7}),
    ("E-S-27", 6, 1, {"algebraic_elim": 1}),  # retracted proof
    ("E-S-28", 6, 1, {"algebraic_elim": 1}),  # Bean redundancy

    # Session 14: Double Columnar, Mixed Alphabet
    ("E-S-29", 6, 1, {}),  # W-separator
    ("E-S-30", 6, 161_000, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "three_layer": 1, "thematic_key": 1}),
    ("E-S-31", 10, 10_000_000, {"running_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "thematic_key": 1}),
    ("E-S-32", 6, 43, {"thematic_key": 1}),
    ("E-S-33", 0, 50_800_000, {"periodic_sub": 1, "double_columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "min_period": 7, "max_period": 7}),
    ("E-S-33b", 0, 1_000_000_000, {"periodic_sub": 1, "double_columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 2, "max_period": 14}),
    ("E-S-34", 6, 92_000, {"uses_quadgrams": 1}),
    ("E-S-35", 6, 100, {}),  # null cipher
    ("E-S-36", 0, 100_000, {"gronsfeld": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "min_period": 2, "max_period": 14}),
    ("E-S-37", 6, 5_040, {"mixed_alpha": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "min_period": 5, "max_period": 9}),
    ("E-S-38", 6, 277_000, {"periodic_sub": 1, "mixed_alpha": 1, "has_substitution": 1, "uses_quadgrams": 1}),
    ("E-S-39", 0, 47_293, {"periodic_sub": 1, "myszkowski": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 2, "max_period": 14}),
    ("E-S-40", 6, 10_000, {"running_key": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "uses_sa": 1}),
    ("E-S-41", 0, 1_000, {"hill": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "algebraic_elim": 1}),
    ("E-S-42", 0, 1_000, {"bifid": 1, "has_substitution": 1, "algebraic_elim": 1, "min_period": 2, "max_period": 97}),
    ("E-S-42b", 0, 1_000, {"trifid": 1, "has_substitution": 1, "algebraic_elim": 1, "min_period": 2, "max_period": 97}),
    ("E-S-43", 6, 10_196, {"thematic_key": 1}),

    # Session 15-16: Fractionation + Lag-7
    ("E-S-44", 0, 1, {"trifid": 1, "has_substitution": 1, "algebraic_elim": 1}),
    ("E-S-45", 9, 10_000, {"periodic_sub": 1, "has_substitution": 1, "min_period": 7, "max_period": 7}),  # lag-7 analysis
    ("E-S-46", 5, 11_000, {"mixed_alpha": 1, "has_substitution": 1}),
    ("E-S-47", 24, 7_400_000_000, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 7, "max_period": 7}),  # underdetermined
    ("E-S-48", 24, 100, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "uses_sa": 1, "uses_quadgrams": 1, "min_period": 7, "max_period": 7}),
    ("E-S-49", 24, 100, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "uses_sa": 1, "min_period": 7, "max_period": 7}),

    # Session 17: Underdetermination
    ("E-S-50", 8, 532_610, {"nonlinear_rec": 1, "has_substitution": 1}),
    ("E-S-51", 24, 100, {"running_key": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "uses_sa": 1}),
    ("E-S-52", 11, 7_000_000_000, {"running_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1}),

    # Session 18: Constrained Transposition
    ("E-S-53", 6, 15_756, {"periodic_sub": 1, "columnar": 1, "myszkowski": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "thematic_key": 1}),
    ("E-S-54", 6, 1, {"algebraic_elim": 1}),  # pre-ENE analysis
    ("E-S-55", 11, 16_224, {"periodic_sub": 1, "route": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1}),
    ("E-S-56", 13, 100_000, {"affine": 1, "has_substitution": 1, "min_period": 7, "max_period": 7}),
    ("E-S-57b", 24, 1, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 7, "max_period": 7}),  # constraint enum, underdetermined

    # Session 19: K3 Analysis
    ("E-S-58", 6, 100_000, {"running_key": 1, "has_substitution": 1, "thematic_key": 1}),
    ("E-S-59", 9, 20_160, {"columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),

    # Session 20-21: Width-7 Model B
    ("E-S-62", 0, 15_120, {"periodic_sub": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "algebraic_elim": 1, "min_period": 2, "max_period": 14}),
    ("E-S-63", 6, 76_000, {"periodic_sub": 1, "has_substitution": 1, "thematic_key": 1, "min_period": 7, "max_period": 7}),
    ("E-S-64", 6, 100_000, {"autokey": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),
    ("E-S-65", 6, 1, {"algebraic_elim": 1}),  # key bigram
    ("E-S-66", 9, 230_000_000, {"running_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1}),
    ("E-S-67", 6, 100_000, {"gromark": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),
    ("E-S-68", 8, 35_000_000, {"polynomial_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),
    ("E-S-69", 6, 50_000, {"autokey": 1, "has_substitution": 1, "algebraic_elim": 1}),

    # Session 22: Autokey, Polynomial, Three-Layer
    ("E-S-71", 8, 24_000_000, {"polynomial_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),
    ("E-S-72", 12, 100, {"periodic_sub": 1, "grille": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "uses_sa": 1}),
    ("E-S-73", 24, 5_040, {"mixed_alpha": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "uses_sa": 1, "uses_quadgrams": 1}),
    ("E-S-74", 6, 100, {"thematic_key": 1}),
    ("E-S-76", 0, 370_000, {"mixed_alpha": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1, "algebraic_elim": 1}),
    ("E-S-80", 0, 1000, {"mixed_alpha": 1, "has_substitution": 1, "algebraic_elim": 1}),  # Latin square
    ("E-S-81", 1, 100_000, {"quagmire": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1}),
    ("E-S-83", 7, 100_000, {"autokey": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),
    ("E-S-84", 8, 100_000, {"polynomial_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),
    ("E-S-85", 7, 100_000, {"autokey": 1, "has_substitution": 1}),
    ("E-S-86", 13, 453_000, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "three_layer": 1, "min_period": 7, "max_period": 7}),
    ("E-S-87", 24, 100_000, {"periodic_sub": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "min_period": 7, "max_period": 7}),  # underdetermined

    # Session 23: Autokey, Decimation, Systematic
    ("E-S-88", 6, 100, {"has_transposition": 1}),  # redefence
    ("E-S-89", 8, 100_000, {"polynomial_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),
    ("E-S-90", 4, 100_000, {"polynomial_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),
    ("E-S-91", 0, 15_120, {"periodic_sub": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "algebraic_elim": 1, "min_period": 7, "max_period": 7}),
    ("E-S-92", 2, 100, {"thematic_key": 1}),  # community proposals
    ("E-S-93", 9, 1_000_000, {"autokey": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1}),
    ("E-S-94", 0, 15_120, {"periodic_sub": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "algebraic_elim": 1, "min_period": 2, "max_period": 14}),
    ("E-S-95", 6, 100_000, {"gromark": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1}),
    ("E-S-96", 9, 1_000_000, {"autokey": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1}),
    ("E-S-97", 6, 100_000, {"decimation": 1, "periodic_sub": 1, "autokey": 1, "monoalpha": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1}),
    ("E-S-98", 8, 100_000, {"running_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1}),
    ("E-S-99", 0, 100_000, {"monoalpha": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "algebraic_elim": 1}),

    # Session 24-25: Final Classical
    ("E-S-100", 0, 100_000, {"porta": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "algebraic_elim": 1}),
    ("E-S-101", 6, 1, {"algebraic_elim": 1}),  # statistical transposition
    ("E-S-102", 0, 100_000, {"polynomial_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "algebraic_elim": 1}),
    ("E-S-103", 6, 100_000, {"running_key": 1, "has_substitution": 1, "thematic_key": 1}),
    ("E-S-104", 0, 1, {"grille": 1, "has_transposition": 1, "algebraic_elim": 1}),  # structurally impossible
    ("E-S-105", 8, 25_400_000, {"self_keying": 1, "double_columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1}),
    ("E-S-106", 8, 100_000, {"periodic_sub": 1, "has_substitution": 1, "multi_layer": 1, "thematic_key": 1}),  # K3 outer layer
    ("E-S-107", 0, 370_000, {"mixed_alpha": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "algebraic_elim": 1}),
    ("E-S-108", 6, 1, {"algebraic_elim": 1}),  # column statistics
    ("E-S-109", 24, 5_040, {"has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "uses_sa": 1, "uses_quadgrams": 1}),
    ("E-S-110", 8, 605_000, {"periodic_sub": 1, "has_substitution": 1, "multi_layer": 1}),  # keyword interleaving

    # Session 26: Progressive Solve
    ("E-S-112", 5, 3_973, {"progressive_key": 1, "thematic_key": 1}),
    ("E-S-117", 5, 45_360, {"columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1, "progressive_key": 1}),
    ("E-S-119", 6, 3_240, {"route": 1, "has_transposition": 1, "thematic_key": 1, "progressive_key": 1}),
    ("E-S-120", 6, 48_195, {"thematic_key": 1, "progressive_key": 1}),
    ("E-S-121", 7, 88_464, {"columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1, "progressive_key": 1}),
    ("E-S-122", 6, 1_224, {"thematic_key": 1, "progressive_key": 1}),
    ("E-S-123", 6, 24_564, {"thematic_key": 1, "progressive_key": 1}),
    ("E-S-124", 7, 5_155, {"running_key": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1, "progressive_key": 1}),
    ("E-S-125", 6, 38_148, {"thematic_key": 1, "progressive_key": 1}),
    ("E-S-127", 6, 20_000, {"has_transposition": 1, "thematic_key": 1, "progressive_key": 1}),
    ("E-S-128", 7, 341_840, {"columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1, "progressive_key": 1}),
    ("E-S-129", 8, 996_661, {"columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1}),
    ("E-S-130", 6, 123_832_800, {"periodic_sub": 1, "columnar": 1, "has_transposition": 1, "has_substitution": 1, "multi_layer": 1, "width_7": 1, "thematic_key": 1, "min_period": 7, "max_period": 7}),

    # E-S-131 (point crib sweep — if it exists, approximate)
    ("E-S-131", 6, 100_000, {"periodic_sub": 1, "has_substitution": 1}),
]


# ── All feature names ───────────────────────────────────────────────────────

FEATURE_NAMES = [
    # Substitution families
    "periodic_sub", "autokey", "running_key", "hill", "bifid", "trifid",
    "playfair", "nihilist", "porta", "gronsfeld", "gromark", "quagmire",
    "monoalpha", "mixed_alpha", "affine", "polynomial_key", "nonlinear_rec",
    "self_keying",
    # Transposition families
    "columnar", "double_columnar", "myszkowski", "grille", "route", "amsco",
    "decimation",
    # Structural
    "has_transposition", "has_substitution", "multi_layer", "three_layer",
    "uses_sa", "uses_quadgrams", "thematic_key", "progressive_key",
    "width_7", "algebraic_elim",
    # Numeric
    "log_configs", "min_period", "max_period",
]


# ── Linear Algebra (stdlib only) ───────────────────────────────────────────

def mat_transpose(A):
    """Transpose a matrix (list of lists)."""
    m = len(A)
    n = len(A[0])
    return [[A[i][j] for i in range(m)] for j in range(n)]


def mat_mul(A, B):
    """Multiply two matrices."""
    m = len(A)
    n = len(B[0])
    p = len(B)
    C = [[0.0] * n for _ in range(m)]
    for i in range(m):
        for j in range(n):
            s = 0.0
            for k in range(p):
                s += A[i][k] * B[k][j]
            C[i][j] = s
    return C


def mat_vec_mul(A, v):
    """Multiply matrix by vector."""
    m = len(A)
    n = len(A[0])
    result = [0.0] * m
    for i in range(m):
        s = 0.0
        for j in range(n):
            s += A[i][j] * v[j]
        result[i] = s
    return result


def solve_linear(A, b):
    """Solve Ax = b using Gaussian elimination with partial pivoting.

    Returns x vector or None if singular.
    """
    n = len(A)
    # Augmented matrix
    M = [row[:] + [b[i]] for i, row in enumerate(A)]

    for col in range(n):
        # Partial pivoting
        max_val = abs(M[col][col])
        max_row = col
        for row in range(col + 1, n):
            if abs(M[row][col]) > max_val:
                max_val = abs(M[row][col])
                max_row = row
        if max_val < 1e-12:
            return None  # singular
        M[col], M[max_row] = M[max_row], M[col]

        # Eliminate below
        for row in range(col + 1, n):
            factor = M[row][col] / M[col][col]
            for j in range(col, n + 1):
                M[row][j] -= factor * M[col][j]

    # Back substitution
    x = [0.0] * n
    for i in range(n - 1, -1, -1):
        s = M[i][n]
        for j in range(i + 1, n):
            s -= M[i][j] * x[j]
        if abs(M[i][i]) < 1e-12:
            return None
        x[i] = s / M[i][i]
    return x


# ── OLS Regression ─────────────────────────────────────────────────────────

def ols_regression(X, y):
    """Ordinary Least Squares via normal equations: beta = (X'X)^{-1} X'y.

    Returns (coefficients, r_squared, adj_r_squared, residuals, se_coefs, t_stats, p_approx).
    """
    n = len(y)
    p = len(X[0])  # includes intercept

    Xt = mat_transpose(X)
    XtX = mat_mul(Xt, X)
    Xty = mat_vec_mul(Xt, y)

    beta = solve_linear(XtX, Xty)
    if beta is None:
        return None

    # Predictions and residuals
    y_hat = mat_vec_mul(X, beta)
    residuals = [y[i] - y_hat[i] for i in range(n)]

    # R-squared
    y_mean = sum(y) / n
    ss_tot = sum((yi - y_mean) ** 2 for yi in y)
    ss_res = sum(r ** 2 for r in residuals)

    r_squared = 1 - ss_res / ss_tot if ss_tot > 0 else 0
    adj_r_squared = 1 - (1 - r_squared) * (n - 1) / (n - p) if n > p else 0

    # Standard errors of coefficients
    mse = ss_res / (n - p) if n > p else ss_res
    # Invert XtX for variance-covariance matrix
    # Use solve_linear with identity columns
    XtX_inv = []
    for j in range(p):
        ej = [1.0 if i == j else 0.0 for i in range(p)]
        col = solve_linear([row[:] for row in XtX], ej)
        if col is None:
            return None
        XtX_inv.append(col)
    # XtX_inv is stored column-wise, transpose it
    XtX_inv = mat_transpose(XtX_inv)

    se_coefs = []
    t_stats = []
    for j in range(p):
        var_j = mse * XtX_inv[j][j]
        se = math.sqrt(max(var_j, 0))
        se_coefs.append(se)
        t = beta[j] / se if se > 1e-12 else 0.0
        t_stats.append(t)

    # Approximate p-values using t-distribution approximation
    # For large n, t ~ N(0,1), use 2*(1 - Phi(|t|))
    df = n - p
    p_values = [approx_t_pvalue(abs(t), df) for t in t_stats]

    return {
        "beta": beta,
        "r_squared": r_squared,
        "adj_r_squared": adj_r_squared,
        "residuals": residuals,
        "se_coefs": se_coefs,
        "t_stats": t_stats,
        "p_values": p_values,
        "mse": mse,
        "n": n,
        "p": p,
    }


def approx_t_pvalue(t_abs, df):
    """Approximate two-tailed p-value for t-statistic.

    Uses the approximation: for df > 30, t ~ N(0,1).
    For smaller df, use a rough correction.
    """
    # Standard normal CDF approximation (Abramowitz & Stegun 26.2.17)
    x = t_abs
    if x > 8:
        return 0.0
    # Rational approximation
    b1 = 0.319381530
    b2 = -0.356563782
    b3 = 1.781477937
    b4 = -1.821255978
    b5 = 1.330274429
    p_const = 0.2316419
    t_val = 1.0 / (1.0 + p_const * x)
    phi = (1.0 / math.sqrt(2 * math.pi)) * math.exp(-x * x / 2)
    cdf = 1.0 - phi * (b1 * t_val + b2 * t_val**2 + b3 * t_val**3 + b4 * t_val**4 + b5 * t_val**5)
    p_val = 2 * (1 - cdf)

    # Correction for small df (t-distribution has heavier tails)
    if df < 30 and df > 0:
        correction = 1.0 + (1.0 / (4 * df))  # rough Satterthwaite-like
        p_val = min(1.0, p_val * correction)
    return max(0.0, p_val)


# ── Entropy Measures ───────────────────────────────────────────────────────

def shannon_entropy(values):
    """Shannon entropy of a discrete distribution (in bits)."""
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    n = len(values)
    H = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            H -= p * math.log2(p)
    return H


def normalized_entropy(values, max_val=None):
    """Entropy normalized to [0, 1] by dividing by log2(num_unique)."""
    H = shannon_entropy(values)
    unique = len(set(values))
    if unique <= 1:
        return 0.0
    H_max = math.log2(unique)
    return H / H_max


def ct_letter_entropy():
    """Shannon entropy of K4 ciphertext letter distribution."""
    from kryptos.kernel.constants import CT
    return shannon_entropy(list(CT))


def keystream_entropy(keystream):
    """Shannon entropy of derived keystream values."""
    return shannon_entropy(list(keystream))


# ── Feature Matrix Construction ────────────────────────────────────────────

def build_feature_matrix(experiments, feature_names):
    """Build X matrix and y vector from experiment catalog.

    Excludes known SA/underdetermination artifacts (score=24 from SA).
    """
    X = []
    y = []
    ids = []
    excluded = []

    for exp_id, best_score, configs, features in experiments:
        # Flag SA artifacts: experiments that score 24 purely from underdetermination
        is_sa_artifact = (best_score == 24 and features.get("uses_sa", 0) == 1)
        is_underdetermined = (exp_id in ("E-S-47", "E-S-57b", "E-S-87"))

        if is_sa_artifact or is_underdetermined:
            excluded.append((exp_id, best_score, "SA/underdetermination artifact"))
            continue

        row = []
        for fname in feature_names:
            if fname == "log_configs":
                row.append(math.log10(max(configs, 1)))
            elif fname in ("min_period", "max_period"):
                row.append(float(features.get(fname, 0)))
            else:
                row.append(float(features.get(fname, 0)))
        # Add intercept
        row.append(1.0)
        X.append(row)
        y.append(float(best_score))
        ids.append(exp_id)

    return X, y, ids, excluded


# ── Main Analysis ──────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-132: Multiple Linear Regression Meta-Analysis")
    print("=" * 70)
    print(f"Total experiments in catalog: {len(EXPERIMENTS)}")

    # Build feature matrix
    X, y, ids, excluded = build_feature_matrix(EXPERIMENTS, FEATURE_NAMES)
    n = len(y)
    p = len(FEATURE_NAMES) + 1  # +1 for intercept

    print(f"Experiments included: {n}")
    print(f"Excluded (SA/underdetermination artifacts): {len(excluded)}")
    for eid, score, reason in excluded:
        print(f"  {eid}: score={score} ({reason})")
    print(f"Features: {len(FEATURE_NAMES)} + intercept = {p}")
    print()

    # ── Descriptive Statistics ──────────────────────────────────────────
    print("-" * 70)
    print("DESCRIPTIVE STATISTICS")
    print("-" * 70)

    scores = [s for s in y]
    score_mean = sum(scores) / len(scores)
    score_var = sum((s - score_mean)**2 for s in scores) / len(scores)
    score_std = math.sqrt(score_var)
    score_entropy = shannon_entropy([int(s) for s in scores])

    print(f"Score distribution: mean={score_mean:.2f}, std={score_std:.2f}, "
          f"min={min(scores):.0f}, max={max(scores):.0f}")
    print(f"Score entropy: {score_entropy:.3f} bits "
          f"(normalized: {normalized_entropy([int(s) for s in scores]):.3f})")
    print()

    # Score histogram
    from collections import Counter
    score_counts = Counter(int(s) for s in scores)
    print("Score histogram:")
    for score_val in sorted(score_counts.keys()):
        bar = "#" * score_counts[score_val]
        print(f"  {score_val:3d}/24: {bar} ({score_counts[score_val]})")
    print()

    # ── CT and Keystream Entropy ────────────────────────────────────────
    print("-" * 70)
    print("ENTROPY MEASURES")
    print("-" * 70)

    from kryptos.kernel.constants import (
        CT, VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
        BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC, IC_K4, IC_RANDOM, IC_ENGLISH
    )

    ct_H = shannon_entropy(list(CT))
    max_H = math.log2(26)
    print(f"K4 CT letter entropy: {ct_H:.4f} bits (max={max_H:.4f}, ratio={ct_H/max_H:.4f})")
    print(f"K4 IC: {IC_K4:.4f} (random={IC_RANDOM:.4f}, English={IC_ENGLISH:.4f})")

    # CT entropy is related to IC: H ≈ log2(26) - (IC - 1/26) * 26 * log2(e) / 2
    # But let's just compute directly
    ct_freq = Counter(CT)
    print(f"CT letter frequency range: {min(ct_freq.values())}-{max(ct_freq.values())} "
          f"({len(ct_freq)} unique letters)")

    vig_key_all = list(VIGENERE_KEY_ENE) + list(VIGENERE_KEY_BC)
    beau_key_all = list(BEAUFORT_KEY_ENE) + list(BEAUFORT_KEY_BC)
    print(f"Vigenere keystream entropy (24 values): {keystream_entropy(vig_key_all):.4f} bits")
    print(f"Beaufort keystream entropy (24 values): {keystream_entropy(beau_key_all):.4f} bits")
    print(f"Max entropy for 24 values from mod-26: {math.log2(26):.4f} bits")
    print()

    # ── Feature Frequency ──────────────────────────────────────────────
    print("-" * 70)
    print("FEATURE PREVALENCE (how many experiments use each feature)")
    print("-" * 70)

    feature_counts = {}
    for fname_idx, fname in enumerate(FEATURE_NAMES):
        if fname in ("log_configs", "min_period", "max_period"):
            continue
        count = sum(1 for row in X if row[fname_idx] > 0)
        feature_counts[fname] = count
    for fname, count in sorted(feature_counts.items(), key=lambda x: -x[1]):
        pct = 100 * count / n
        print(f"  {fname:25s}: {count:3d}/{n} ({pct:5.1f}%)")
    print()

    # ── Check for collinearity before regression ───────────────────────
    # Remove features with zero variance (all same value)
    active_features = []
    active_names = []
    for j, fname in enumerate(FEATURE_NAMES):
        col_vals = [X[i][j] for i in range(n)]
        col_var = sum((v - sum(col_vals)/n)**2 for v in col_vals) / n
        if col_var > 1e-10:
            active_features.append(j)
            active_names.append(fname)
        else:
            print(f"  Dropped zero-variance feature: {fname}")

    # Rebuild X with only active features + intercept
    X_active = []
    for i in range(n):
        row = [X[i][j] for j in active_features] + [1.0]  # intercept last
        X_active.append(row)

    p_active = len(active_names) + 1
    print(f"\nActive features after variance filter: {len(active_names)}")
    print()

    # ── Run OLS Regression ─────────────────────────────────────────────
    print("-" * 70)
    print("MULTIPLE LINEAR REGRESSION: best_score ~ features")
    print("-" * 70)

    result = ols_regression(X_active, y)

    if result is None:
        print("ERROR: Singular matrix — features are collinear. Trying stepwise...")
        # Try removing features one by one to find non-singular subset
        # For now, just report the issue
        return

    print(f"R-squared:     {result['r_squared']:.4f}")
    print(f"Adj R-squared: {result['adj_r_squared']:.4f}")
    print(f"MSE:           {result['mse']:.4f}")
    print(f"RMSE:          {math.sqrt(result['mse']):.4f}")
    print(f"N:             {result['n']}")
    print(f"Features:      {result['p'] - 1} + intercept")
    print()

    # ── Feature Importance Table ───────────────────────────────────────
    print("-" * 70)
    print("FEATURE COEFFICIENTS (sorted by |t-statistic|)")
    print("-" * 70)
    print(f"{'Feature':30s} {'Coef':>8s} {'SE':>8s} {'t-stat':>8s} {'p-value':>8s} {'Sig':>4s}")
    print("-" * 70)

    feature_data = []
    for j in range(len(active_names)):
        feature_data.append({
            "name": active_names[j],
            "coef": result["beta"][j],
            "se": result["se_coefs"][j],
            "t": result["t_stats"][j],
            "p": result["p_values"][j],
        })
    # Intercept
    feature_data.append({
        "name": "(intercept)",
        "coef": result["beta"][-1],
        "se": result["se_coefs"][-1],
        "t": result["t_stats"][-1],
        "p": result["p_values"][-1],
    })

    # Sort by |t-statistic| descending
    feature_data.sort(key=lambda x: abs(x["t"]), reverse=True)

    for fd in feature_data:
        sig = ""
        if fd["p"] < 0.001:
            sig = "***"
        elif fd["p"] < 0.01:
            sig = "**"
        elif fd["p"] < 0.05:
            sig = "*"
        elif fd["p"] < 0.1:
            sig = "."
        print(f"{fd['name']:30s} {fd['coef']:8.3f} {fd['se']:8.3f} "
              f"{fd['t']:8.3f} {fd['p']:8.4f} {sig:>4s}")
    print()

    # ── Strategy Rankings ──────────────────────────────────────────────
    print("-" * 70)
    print("STRATEGY RANKINGS")
    print("-" * 70)

    # Separate into positive and negative contributions
    positive = [(fd["name"], fd["coef"], fd["p"]) for fd in feature_data
                if fd["coef"] > 0 and fd["name"] != "(intercept)"]
    negative = [(fd["name"], fd["coef"], fd["p"]) for fd in feature_data
                if fd["coef"] < 0 and fd["name"] != "(intercept)"]

    positive.sort(key=lambda x: x[1], reverse=True)
    negative.sort(key=lambda x: x[1])

    print("\nFEATURES THAT INCREASE SCORE (positive coefficients):")
    print("  (Higher score does NOT mean better — most 'high' scores are artifacts)")
    for name, coef, pv in positive:
        sig = "*" if pv < 0.05 else ""
        print(f"  {name:30s}: +{coef:.3f}  (p={pv:.4f}) {sig}")

    print("\nFEATURES THAT DECREASE SCORE (negative coefficients):")
    print("  (Lower score = more constrained = more decisive elimination)")
    for name, coef, pv in negative:
        sig = "*" if pv < 0.05 else ""
        print(f"  {name:30s}: {coef:.3f}  (p={pv:.4f}) {sig}")

    # ── Cipher Family Average Scores ───────────────────────────────────
    print()
    print("-" * 70)
    print("CIPHER FAMILY MEAN SCORES (empirical, not regression)")
    print("-" * 70)

    cipher_families = [
        "periodic_sub", "autokey", "running_key", "hill", "bifid", "trifid",
        "playfair", "porta", "gronsfeld", "gromark", "quagmire",
        "monoalpha", "mixed_alpha", "polynomial_key", "nonlinear_rec",
        "columnar", "double_columnar", "myszkowski", "grille", "route",
        "amsco", "decimation", "thematic_key", "progressive_key",
        "self_keying", "uses_sa", "uses_quadgrams", "width_7",
        "algebraic_elim", "multi_layer", "has_transposition", "has_substitution",
    ]

    family_stats = {}
    for fname in cipher_families:
        if fname in ("log_configs", "min_period", "max_period"):
            continue
        fname_idx = FEATURE_NAMES.index(fname) if fname in FEATURE_NAMES else -1
        if fname_idx < 0:
            continue
        scores_with = [y[i] for i in range(n) if X[i][fname_idx] > 0]
        scores_without = [y[i] for i in range(n) if X[i][fname_idx] == 0]
        if len(scores_with) > 0:
            mean_with = sum(scores_with) / len(scores_with)
            entropy_with = shannon_entropy([int(s) for s in scores_with]) if len(scores_with) > 1 else 0
        else:
            mean_with = 0
            entropy_with = 0
        if len(scores_without) > 0:
            mean_without = sum(scores_without) / len(scores_without)
        else:
            mean_without = 0
        family_stats[fname] = {
            "n": len(scores_with),
            "mean": mean_with,
            "mean_without": mean_without,
            "delta": mean_with - mean_without,
            "entropy": entropy_with,
        }

    print(f"{'Family':25s} {'N':>4s} {'Mean':>6s} {'w/o':>6s} {'Delta':>7s} {'H(bits)':>8s}")
    print("-" * 60)
    for fname, stats in sorted(family_stats.items(), key=lambda x: x[1]["delta"]):
        print(f"{fname:25s} {stats['n']:4d} {stats['mean']:6.2f} "
              f"{stats['mean_without']:6.2f} {stats['delta']:+7.2f} {stats['entropy']:8.3f}")

    # ── Entropy Analysis: Which strategies produce most predictable results?
    print()
    print("-" * 70)
    print("ENTROPY ANALYSIS: Score predictability by strategy")
    print("-" * 70)
    print("Low entropy = highly predictable outcome (concentrated at one score value)")
    print("High entropy = spread across many score values (unpredictable)")
    print()

    entropy_ranking = [(fname, stats["entropy"], stats["n"])
                       for fname, stats in family_stats.items() if stats["n"] >= 3]
    entropy_ranking.sort(key=lambda x: x[1])

    print(f"{'Strategy':25s} {'H(bits)':>8s} {'N':>4s} {'Interpretation':>30s}")
    for fname, H, count in entropy_ranking:
        if H < 0.5:
            interp = "Very predictable (noise floor)"
        elif H < 1.5:
            interp = "Somewhat predictable"
        elif H < 2.5:
            interp = "Moderate spread"
        else:
            interp = "High variability (artifact risk)"
        print(f"  {fname:25s} {H:8.3f} {count:4d} {interp:>30s}")

    # ── Final Recommendations ──────────────────────────────────────────
    print()
    print("=" * 70)
    print("CONCLUSIONS AND RECOMMENDATIONS")
    print("=" * 70)
    print()

    # Identify least important (should STOP testing)
    print("LEAST IMPORTANT — STOP TESTING THESE:")
    print("(Negative regression coefficient + low mean + high N = well-eliminated)")
    stop_candidates = []
    for fd in feature_data:
        if fd["name"] == "(intercept)":
            continue
        fname = fd["name"]
        if fname in family_stats and family_stats[fname]["n"] >= 3:
            stop_candidates.append((fname, fd["coef"], family_stats[fname]["mean"],
                                    family_stats[fname]["n"], fd["p"]))
    stop_candidates.sort(key=lambda x: x[1])  # most negative first
    for fname, coef, mean, count, pv in stop_candidates[:10]:
        print(f"  {fname:25s}: coef={coef:+.3f}, mean={mean:.1f}/24, N={count}, p={pv:.3f}")

    print()
    print("MOST IMPORTANT — CONTINUE INVESTIGATING:")
    print("(Positive coefficient OR low coverage OR structural significance)")
    # Least tested features that aren't structurally eliminated
    undertested = [(fname, stats["n"]) for fname, stats in family_stats.items()
                   if stats["n"] < 5 and fname not in ("nihilist", "affine", "nonlinear_rec")]
    undertested.sort(key=lambda x: x[1])
    for fname, count in undertested:
        print(f"  {fname:25s}: only {count} experiments — UNDERTESTED")

    print()
    print("KEY INSIGHT: The regression R-squared tells us how much of the score")
    print("variance is explained by cipher strategy choice alone. If R-squared is")
    print("low, it means score is dominated by OTHER factors (configs tested, SA")
    print("artifacts, underdetermination) rather than the cipher family itself.")
    print(f"  => R-squared = {result['r_squared']:.4f}")
    if result['r_squared'] < 0.3:
        print("  => LOW: Cipher strategy choice explains LITTLE of score variance.")
        print("     This confirms the underdetermination wall — most strategies")
        print("     converge to the same noise floor regardless of family.")
    elif result['r_squared'] < 0.6:
        print("  => MODERATE: Some strategies reliably outperform others,")
        print("     but much variance remains unexplained.")
    else:
        print("  => HIGH: Strategy choice strongly predicts score.")

    # ── Save results ───────────────────────────────────────────────────
    elapsed = time.time() - t0
    print()
    print(f"Analysis completed in {elapsed:.2f}s")

    # Save to artifacts
    os.makedirs("artifacts", exist_ok=True)
    artifact = {
        "experiment": "E-S-132",
        "description": "Multiple Linear Regression Meta-Analysis",
        "n_experiments": n,
        "n_excluded": len(excluded),
        "n_features": len(active_names),
        "r_squared": result["r_squared"],
        "adj_r_squared": result["adj_r_squared"],
        "mse": result["mse"],
        "coefficients": {active_names[j]: result["beta"][j] for j in range(len(active_names))},
        "p_values": {active_names[j]: result["p_values"][j] for j in range(len(active_names))},
        "t_stats": {active_names[j]: result["t_stats"][j] for j in range(len(active_names))},
        "family_stats": family_stats,
        "score_entropy": score_entropy,
        "ct_entropy": ct_H,
        "vig_keystream_entropy": keystream_entropy(vig_key_all),
        "beau_keystream_entropy": keystream_entropy(beau_key_all),
        "elapsed_seconds": round(elapsed, 2),
    }
    artifact_path = "artifacts/e_s_132_regression.json"
    with open(artifact_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"Results saved to {artifact_path}")


if __name__ == "__main__":
    main()
