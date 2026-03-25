#!/usr/bin/env python3
"""
Phase 3 Stego Analysis: Stehle delta4=5 and width-21 bigram interaction.

Tests whether the delta4=5 anomaly (constant-difference window at lag 4,
positions 55-63) and the width-21 bigram anomaly share the same null
insertion mechanism.

Cipher: statistical analysis / stego layer
Family: analysis
Status: active
Keyspace: analytical + Monte Carlo (100K samples for T3.3)
Last run: never
Best score: N/A

Three tests:
  T3.1 - Width-21 null value forcing: which palette letters at null
          positions create repeated width-21 bigrams?
  T3.2 - Joint constraint check: do positions 58/59 (Stehle window)
          have constraints from BOTH delta4=5 AND width-21?
  T3.3 - MC joint optimality: is the actual null assignment near-optimal
          for BOTH criteria simultaneously?
"""
import sys
import os
import json
import random
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

# Bootstrap: scripts/analysis/ is 2 levels deep from root
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN

# ========================================================================
# SETUP
# ========================================================================
assert CT_LEN == 97
CT97 = CT
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH_IDX = {c: i for i, c in enumerate(ALPH)}
ct_nums = [ALPH_IDX[c] for c in CT97]

CONSENSUS_NULLS = sorted([0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85])
NULL_SET = frozenset(CONSENSUS_NULLS)
PALETTE = frozenset("BGIKOWZ")
PALETTE_NUMS = sorted(ALPH_IDX[c] for c in PALETTE)

NON_NULL_POS = sorted(p for p in range(97) if p not in NULL_SET)

timestamp = datetime.now(timezone.utc).isoformat()
results = {
    "experiment": "E-STEHLE-WIDTH21-INTERACTION",
    "description": "Phase 3: Stehle delta4=5 and width-21 bigram interaction analysis",
    "timestamp": timestamp,
    "null_positions": CONSENSUS_NULLS,
    "palette": sorted(PALETTE),
}

print("=" * 80)
print("PHASE 3: STEHLE delta4=5 AND WIDTH-21 BIGRAM INTERACTION")
print(f"Timestamp: {timestamp}")
print(f"CT: {CT97}")
print(f"Null positions (17): {CONSENSUS_NULLS}")
print(f"Palette: {sorted(PALETTE)}")
print("=" * 80)


# ========================================================================
# HELPER FUNCTIONS
# ========================================================================
def count_vertical_repeated_bigrams(text, width):
    """Count distinct vertical bigrams that appear more than once at given width.
    Vertical bigram at position i = (text[i], text[i+width]).
    """
    n = len(text)
    bigrams = Counter()
    for i in range(n - width):
        bg = text[i] + text[i + width]
        bigrams[bg] += 1
    repeated = sum(1 for bg, cnt in bigrams.items() if cnt > 1)
    return repeated, bigrams


def find_repeated_bigram_positions(text, width):
    """Return dict: bigram -> list of positions where it occurs."""
    n = len(text)
    bg_positions = defaultdict(list)
    for i in range(n - width):
        bg = text[i] + text[i + width]
        bg_positions[bg].append(i)
    # Only keep repeated ones
    return {bg: positions for bg, positions in bg_positions.items() if len(positions) > 1}


def max_constant_diff_window(nums, lag):
    """Find the maximum length of a constant-difference window at given lag.
    Window: consecutive positions i, i+lag, i+2*lag, ... where
    nums[i+lag] - nums[i] is the same constant for all consecutive pairs.
    Returns (max_length, best_start, best_delta).
    """
    n = len(nums)
    if lag >= n:
        return 0, -1, 0

    best_len = 0
    best_start = -1
    best_delta = 0

    i = 0
    while i + lag < n:
        delta = (nums[i + lag] - nums[i]) % 26
        run_len = 2  # positions i and i+lag
        j = i + lag
        while j + lag < n and (nums[j + lag] - nums[j]) % 26 == delta:
            run_len += 1
            j += lag
        if run_len > best_len:
            best_len = run_len
            best_start = i
            best_delta = delta
        i += 1

    return best_len, best_start, best_delta


# ========================================================================
# T3.1: WIDTH-21 NULL VALUE FORCING
# ========================================================================
print("\n" + "=" * 80)
print("T3.1: WIDTH-21 NULL VALUE FORCING")
print("=" * 80)

# Find all repeated width-21 bigrams in CT97
repeated_w21 = find_repeated_bigram_positions(CT97, 21)
print(f"\nRepeated width-21 bigrams in CT97: {len(repeated_w21)}")

t31_results = {
    "repeated_bigrams_count": len(repeated_w21),
    "bigrams": {},
    "null_involved_bigrams": [],
}

for bg, positions in sorted(repeated_w21.items()):
    null_involved_positions = []
    for p in positions:
        top_is_null = p in NULL_SET
        bot_is_null = (p + 21) in NULL_SET
        if top_is_null or bot_is_null:
            null_involved_positions.append({
                "position": p,
                "top_pos": p,
                "bot_pos": p + 21,
                "top_char": CT97[p],
                "bot_char": CT97[p + 21],
                "top_is_null": top_is_null,
                "bot_is_null": bot_is_null,
            })

    t31_results["bigrams"][bg] = {
        "positions": positions,
        "count": len(positions),
        "any_null": len(null_involved_positions) > 0,
    }

    print(f"\n  Bigram '{bg}': appears at positions {positions}")
    for p in positions:
        top_null = "NULL" if p in NULL_SET else "    "
        bot_null = "NULL" if (p + 21) in NULL_SET else "    "
        print(f"    pos {p:2d} [{top_null}] -> CT[{p}]='{CT97[p]}'  |  "
              f"pos {p+21:2d} [{bot_null}] -> CT[{p+21}]='{CT97[p+21]}'")

    if null_involved_positions:
        t31_results["null_involved_bigrams"].append({
            "bigram": bg,
            "details": null_involved_positions,
        })

# For each repeated bigram involving null positions, determine which
# palette letters at the null position(s) would create that repetition
print("\n--- Null forcing analysis ---")
print("For each repeated bigram with null involvement:")
print("Which palette letters at the null position(s) would create the repetition?\n")

t31_forcing = []
for bg, positions in sorted(repeated_w21.items()):
    for i, p1 in enumerate(positions):
        for p2 in positions[i+1:]:
            # Check if any of the 4 positions involved are null
            involved = {p1, p1 + 21, p2, p2 + 21}
            null_involved = involved & NULL_SET
            if not null_involved:
                continue

            # The bigram at p1 is (CT[p1], CT[p1+21])
            # The bigram at p2 is (CT[p2], CT[p2+21])
            # For them to match: CT[p1]=CT[p2] AND CT[p1+21]=CT[p2+21]
            # If a null position is involved, it could take any palette value

            # Determine what values the null positions MUST take to create this match
            constraints = {}
            # Top pair: CT[p1] must equal CT[p2]
            if p1 in NULL_SET and p2 in NULL_SET:
                # Both null: they must be equal, any palette letter works
                constraints["top"] = f"CT[{p1}]=CT[{p2}] (both null, must be equal, any palette letter)"
                top_valid = sorted(PALETTE)
            elif p1 in NULL_SET:
                # p1 is null, must equal CT[p2]
                needed = CT97[p2]
                constraints["top"] = f"CT[{p1}] must be '{needed}' (= CT[{p2}])"
                top_valid = [needed] if needed in PALETTE else []
            elif p2 in NULL_SET:
                needed = CT97[p1]
                constraints["top"] = f"CT[{p2}] must be '{needed}' (= CT[{p1}])"
                top_valid = [needed] if needed in PALETTE else []
            else:
                constraints["top"] = f"CT[{p1}]='{CT97[p1]}', CT[{p2}]='{CT97[p2]}' (both fixed)"
                top_valid = ["FIXED"] if CT97[p1] == CT97[p2] else []

            # Bottom pair: CT[p1+21] must equal CT[p2+21]
            bp1, bp2 = p1 + 21, p2 + 21
            if bp1 in NULL_SET and bp2 in NULL_SET:
                constraints["bot"] = f"CT[{bp1}]=CT[{bp2}] (both null, must be equal, any palette letter)"
                bot_valid = sorted(PALETTE)
            elif bp1 in NULL_SET:
                needed = CT97[bp2]
                constraints["bot"] = f"CT[{bp1}] must be '{needed}' (= CT[{bp2}])"
                bot_valid = [needed] if needed in PALETTE else []
            elif bp2 in NULL_SET:
                needed = CT97[bp1]
                constraints["bot"] = f"CT[{bp2}] must be '{needed}' (= CT[{bp1}])"
                bot_valid = [needed] if needed in PALETTE else []
            else:
                constraints["bot"] = f"CT[{bp1}]='{CT97[bp1]}', CT[{bp2}]='{CT97[bp2]}' (both fixed)"
                bot_valid = ["FIXED"] if CT97[bp1] == CT97[bp2] else []

            feasible = (len(top_valid) > 0 and len(bot_valid) > 0)
            entry = {
                "bigram": bg,
                "p1": p1, "p2": p2,
                "null_positions_involved": sorted(null_involved),
                "constraints": constraints,
                "top_valid_palette": top_valid,
                "bot_valid_palette": bot_valid,
                "feasible": feasible,
            }
            t31_forcing.append(entry)

            print(f"  Bigram '{bg}' at p1={p1}, p2={p2}:")
            print(f"    Null positions involved: {sorted(null_involved)}")
            print(f"    Top: {constraints['top']}")
            print(f"    Bot: {constraints['bot']}")
            print(f"    Valid palette (top): {top_valid}")
            print(f"    Valid palette (bot): {bot_valid}")
            print(f"    Feasible: {feasible}")

t31_results["forcing_analysis"] = t31_forcing
results["T3.1"] = t31_results


# ========================================================================
# T3.2: JOINT CONSTRAINT CHECK
# ========================================================================
print("\n" + "=" * 80)
print("T3.2: JOINT CONSTRAINT CHECK (delta4=5 AND width-21 at positions 58, 59)")
print("=" * 80)

# Delta4=5 window: positions 55-63 at lag 4
# The window is: CT[55], CT[59], CT[63] and CT[56], CT[60], CT[64], etc.
# Constant difference: (CT[i+4] - CT[i]) % 26 = 5 for i in {55,56,57,58,59}
# i.e., positions 55-59 each satisfy (CT[i+4] - CT[i]) % 26 = 5

print("\nDelta4=5 window verification:")
stehle_positions = []
for i in range(55, 60):
    d = (ct_nums[i + 4] - ct_nums[i]) % 26
    is_null_i = i in NULL_SET
    is_null_ip4 = (i + 4) in NULL_SET
    stehle_positions.append({
        "i": i, "i+4": i + 4,
        "CT[i]": CT97[i], "CT[i+4]": CT97[i + 4],
        "delta": d,
        "i_is_null": is_null_i,
        "i+4_is_null": is_null_ip4,
    })
    null_str_i = " [NULL]" if is_null_i else ""
    null_str_ip4 = " [NULL]" if is_null_ip4 else ""
    print(f"  i={i}: CT[{i}]='{CT97[i]}'{null_str_i}, CT[{i+4}]='{CT97[i+4]}'{null_str_ip4}, "
          f"delta = ({ct_nums[i+4]} - {ct_nums[i]}) mod 26 = {d}")

# Constraints from delta4=5 on positions 58, 59
print("\n--- Delta4=5 constraints on null positions 58, 59 ---")
d4_constraints = {}

# Position 58: participates in delta4=5 as:
#   (CT[62] - CT[58]) % 26 = 5
#   Also: (CT[58] - CT[54]) % 26 = 5
# Position 59: participates as:
#   (CT[63] - CT[59]) % 26 = 5
#   Also: (CT[59] - CT[55]) % 26 = 5

for null_pos in [58, 59]:
    constraints_for_pos = []

    # As the lower position: (CT[null_pos + 4] - CT[null_pos]) % 26 = 5
    upper = null_pos + 4
    if upper < 97 and upper not in NULL_SET:
        required_val = (ct_nums[upper] - 5) % 26
        constraints_for_pos.append({
            "type": f"CT[{upper}] - CT[{null_pos}] = 5 mod 26",
            "required_value": required_val,
            "required_char": ALPH[required_val],
            "in_palette": ALPH[required_val] in PALETTE,
        })
        print(f"\n  Position {null_pos} from (CT[{upper}] - CT[{null_pos}]) = 5:")
        print(f"    CT[{upper}] = '{CT97[upper]}' = {ct_nums[upper]}")
        print(f"    Required CT[{null_pos}] = ({ct_nums[upper]} - 5) mod 26 = {required_val} = '{ALPH[required_val]}'")
        print(f"    In palette: {ALPH[required_val] in PALETTE}")

    # As the upper position: (CT[null_pos] - CT[null_pos - 4]) % 26 = 5
    lower = null_pos - 4
    if lower >= 0 and lower not in NULL_SET:
        required_val = (ct_nums[lower] + 5) % 26
        constraints_for_pos.append({
            "type": f"CT[{null_pos}] - CT[{lower}] = 5 mod 26",
            "required_value": required_val,
            "required_char": ALPH[required_val],
            "in_palette": ALPH[required_val] in PALETTE,
        })
        print(f"\n  Position {null_pos} from (CT[{null_pos}] - CT[{lower}]) = 5:")
        print(f"    CT[{lower}] = '{CT97[lower]}' = {ct_nums[lower]}")
        print(f"    Required CT[{null_pos}] = ({ct_nums[lower]} + 5) mod 26 = {required_val} = '{ALPH[required_val]}'")
        print(f"    In palette: {ALPH[required_val] in PALETTE}")

    # Check consistency
    required_values = [c["required_value"] for c in constraints_for_pos]
    consistent = len(set(required_values)) <= 1
    if len(required_values) > 1:
        print(f"\n  Position {null_pos}: delta4 constraints require values {required_values} "
              f"({'CONSISTENT' if consistent else 'CONFLICTING'})")

    d4_constraints[null_pos] = {
        "constraints": constraints_for_pos,
        "consistent": consistent,
        "actual_char": CT97[null_pos],
        "actual_value": ct_nums[null_pos],
    }

# Width-21 constraints on positions 58, 59
print("\n--- Width-21 constraints on null positions 58, 59 ---")
w21_constraints = {}

for null_pos in [58, 59]:
    constraints_for_pos = []

    # Position null_pos participates in width-21 bigrams at:
    # As top: (CT[null_pos], CT[null_pos + 21]) if null_pos + 21 < 97
    # As bottom: (CT[null_pos - 21], CT[null_pos]) if null_pos >= 21
    # For a REPEATED bigram, the same pair must appear at another position

    # Check as top of bigram
    if null_pos + 21 < 97:
        partner = null_pos + 21
        partner_null = partner in NULL_SET
        bg = CT97[null_pos] + CT97[partner]
        # Find all other positions with the same bigram at width 21
        for i in range(97 - 21):
            if i == null_pos:
                continue
            other_bg = CT97[i] + CT97[i + 21]
            if other_bg == bg:
                constraints_for_pos.append({
                    "role": "top",
                    "partner": partner,
                    "matching_pos": i,
                    "bigram": bg,
                    "note": f"CT[{null_pos}]+CT[{partner}] = CT[{i}]+CT[{i+21}] = '{bg}'",
                })

    # Check as bottom of bigram
    if null_pos >= 21:
        partner = null_pos - 21
        partner_null = partner in NULL_SET
        bg = CT97[partner] + CT97[null_pos]
        for i in range(97 - 21):
            if i == partner:
                continue
            other_bg = CT97[i] + CT97[i + 21]
            if other_bg == bg:
                constraints_for_pos.append({
                    "role": "bottom",
                    "partner": partner,
                    "matching_pos": i,
                    "bigram": bg,
                    "note": f"CT[{partner}]+CT[{null_pos}] = CT[{i}]+CT[{i+21}] = '{bg}'",
                })

    # What values would this null position need to CREATE additional w21 repetitions?
    forcing = []
    if null_pos + 21 < 97:
        partner_char = CT97[null_pos + 21]
        for pal_c in sorted(PALETTE):
            test_bg = pal_c + partner_char
            # Count occurrences of this bigram at width 21 (excluding null_pos itself)
            count = 0
            for i in range(97 - 21):
                if i == null_pos:
                    continue
                if CT97[i] + CT97[i + 21] == test_bg:
                    count += 1
            if count > 0:
                forcing.append({
                    "role": "top",
                    "palette_char": pal_c,
                    "bigram": test_bg,
                    "matching_count": count,
                })

    if null_pos >= 21:
        partner_char = CT97[null_pos - 21]
        for pal_c in sorted(PALETTE):
            test_bg = partner_char + pal_c
            count = 0
            for i in range(97 - 21):
                if i == null_pos - 21:
                    continue
                if CT97[i] + CT97[i + 21] == test_bg:
                    count += 1
            if count > 0:
                forcing.append({
                    "role": "bottom",
                    "palette_char": pal_c,
                    "bigram": test_bg,
                    "matching_count": count,
                })

    w21_constraints[null_pos] = {
        "current_repetitions": constraints_for_pos,
        "forcing_options": forcing,
    }

    print(f"\n  Position {null_pos} (current char = '{CT97[null_pos]}'):")
    if constraints_for_pos:
        for c in constraints_for_pos:
            print(f"    Current repetition: {c['note']}")
    else:
        print(f"    No current w21 bigram repetitions involving this position")

    if forcing:
        print(f"    Palette values that would CREATE w21 repetitions:")
        for f in forcing:
            print(f"      '{f['palette_char']}' as {f['role']} -> bigram '{f['bigram']}' "
                  f"matches {f['matching_count']}x elsewhere")
    else:
        print(f"    No palette value would create w21 repetitions")

# JOINT: Do positions 58/59 have constraints from BOTH systems?
print("\n--- JOINT CONSTRAINTS ---")
t32_joint = {}
for null_pos in [58, 59]:
    has_d4 = len(d4_constraints[null_pos]["constraints"]) > 0
    has_w21 = (len(w21_constraints[null_pos]["current_repetitions"]) > 0 or
               len(w21_constraints[null_pos]["forcing_options"]) > 0)

    # The delta4 forces a specific value; does that value also appear in w21 forcing?
    d4_required = set()
    for c in d4_constraints[null_pos]["constraints"]:
        d4_required.add(c["required_char"])

    w21_forcing_chars = set()
    for f in w21_constraints[null_pos]["forcing_options"]:
        w21_forcing_chars.add(f["palette_char"])

    overlap = d4_required & w21_forcing_chars
    actual_char = CT97[null_pos]
    actual_in_d4 = actual_char in d4_required
    actual_in_w21 = actual_char in w21_forcing_chars

    t32_joint[null_pos] = {
        "has_delta4_constraint": has_d4,
        "has_width21_constraint": has_w21,
        "delta4_required_chars": sorted(d4_required),
        "width21_forcing_chars": sorted(w21_forcing_chars),
        "overlap": sorted(overlap),
        "actual_char": actual_char,
        "actual_satisfies_delta4": actual_in_d4,
        "actual_satisfies_width21_forcing": actual_in_w21,
    }

    print(f"\n  Position {null_pos} (actual = '{actual_char}'):")
    print(f"    Delta4=5 required: {sorted(d4_required)} | Actual satisfies: {actual_in_d4}")
    print(f"    Width-21 forcing options: {sorted(w21_forcing_chars)} | Actual in set: {actual_in_w21}")
    print(f"    Overlap (chars satisfying BOTH): {sorted(overlap)}")

results["T3.2"] = {
    "stehle_window": stehle_positions,
    "delta4_constraints": {str(k): v for k, v in d4_constraints.items()},
    "width21_constraints": {str(k): {
        "current_repetitions_count": len(v["current_repetitions"]),
        "forcing_options": v["forcing_options"],
    } for k, v in w21_constraints.items()},
    "joint": {str(k): v for k, v in t32_joint.items()},
}

# Also check ALL 17 null positions for joint constraints
print("\n--- ALL 17 NULL POSITIONS: delta4 + width21 joint constraints ---")
all_null_joint = {}
for null_pos in CONSENSUS_NULLS:
    # Delta4 constraints
    d4_vals = set()
    for offset in [-4, 4]:
        partner = null_pos + offset
        if 0 <= partner < 97 and partner not in NULL_SET:
            if offset == 4:
                # (CT[partner] - CT[null_pos]) = 5 => CT[null_pos] = CT[partner] - 5
                val = (ct_nums[partner] - 5) % 26
            else:
                # (CT[null_pos] - CT[partner]) = 5 => CT[null_pos] = CT[partner] + 5
                val = (ct_nums[partner] + 5) % 26
            d4_vals.add(ALPH[val])

    # Width-21 forcing
    w21_vals = set()
    for offset in [-21, 21]:
        partner = null_pos + offset
        if 0 <= partner < 97:
            if offset == 21:
                partner_char = CT97[partner]
                for pal_c in sorted(PALETTE):
                    test_bg = pal_c + partner_char
                    for i in range(97 - 21):
                        if i == null_pos:
                            continue
                        if CT97[i] + CT97[i + 21] == test_bg:
                            w21_vals.add(pal_c)
                            break
            else:
                partner_char = CT97[partner]
                for pal_c in sorted(PALETTE):
                    test_bg = partner_char + pal_c
                    for i in range(97 - 21):
                        if i == partner:
                            continue
                        if CT97[i] + CT97[i + 21] == test_bg:
                            w21_vals.add(pal_c)
                            break

    overlap = d4_vals & w21_vals
    actual = CT97[null_pos]
    has_both = len(d4_vals) > 0 and len(w21_vals) > 0

    all_null_joint[null_pos] = {
        "d4_required": sorted(d4_vals),
        "w21_forcing": sorted(w21_vals),
        "overlap": sorted(overlap),
        "actual": actual,
        "has_both": has_both,
    }

    if has_both:
        marker = " <<<" if actual in overlap else ""
        print(f"  pos {null_pos:2d} [actual='{actual}']: "
              f"d4={sorted(d4_vals)}, w21={sorted(w21_vals)}, "
              f"overlap={sorted(overlap)}{marker}")

results["T3.2"]["all_null_joint"] = {str(k): v for k, v in all_null_joint.items()}
dual_constrained = [p for p, v in all_null_joint.items() if v["has_both"]]
print(f"\n  Positions with BOTH delta4 and width21 constraints: {dual_constrained}")
results["T3.2"]["dual_constrained_positions"] = dual_constrained


# ========================================================================
# T3.3: MONTE CARLO JOINT OPTIMALITY
# ========================================================================
print("\n" + "=" * 80)
print("T3.3: MONTE CARLO JOINT OPTIMALITY")
print("=" * 80)

N_MC = 100_000
SEED = 20260325

# Actual values for the 17 null positions
actual_null_chars = [CT97[p] for p in CONSENSUS_NULLS]
print(f"\nActual null characters: {''.join(actual_null_chars)}")

# (a) Compute actual max constant-difference window length at any lag
def max_const_diff_any_lag(text_nums):
    """Max constant-difference window across all lags 1..25."""
    n = len(text_nums)
    best = 0
    best_lag = 0
    best_delta = 0
    best_start = 0
    for lag in range(1, 26):
        length, start, delta = max_constant_diff_window(text_nums, lag)
        if length > best:
            best = length
            best_lag = lag
            best_delta = delta
            best_start = start
    return best, best_lag, best_delta, best_start


# (b) Compute actual width-21 repeated bigrams
def count_w21_repeated(text):
    n = len(text)
    bigrams = Counter()
    for i in range(n - 21):
        bg = text[i] + text[i + 21]
        bigrams[bg] += 1
    return sum(1 for cnt in bigrams.values() if cnt > 1)


actual_w21 = count_w21_repeated(CT97)
actual_cdw, actual_cdw_lag, actual_cdw_delta, actual_cdw_start = max_const_diff_any_lag(ct_nums)

print(f"\nActual CT97 metrics:")
print(f"  Max constant-difference window: length={actual_cdw} at lag={actual_cdw_lag}, "
      f"delta={actual_cdw_delta}, start={actual_cdw_start}")
print(f"  Width-21 repeated bigrams: {actual_w21}")

# Monte Carlo: sample random palette-letter assignments for the 17 null positions
print(f"\nMonte Carlo: {N_MC} random palette-letter assignments at null positions...")
t0 = time.time()
rng = random.Random(SEED)

mc_cdw = []
mc_w21 = []
mc_joint_better = 0  # count of samples >= actual on BOTH metrics

palette_list = sorted(PALETTE)

for trial in range(N_MC):
    # Random palette assignment at null positions
    test_text = list(CT97)
    test_nums = list(ct_nums)
    for p in CONSENSUS_NULLS:
        c = rng.choice(palette_list)
        test_text[p] = c
        test_nums[p] = ALPH_IDX[c]

    test_str = ''.join(test_text)

    # (a) Max constant-difference window
    cdw_len, _, _, _ = max_const_diff_any_lag(test_nums)
    mc_cdw.append(cdw_len)

    # (b) Width-21 repeated bigrams
    w21_count = count_w21_repeated(test_str)
    mc_w21.append(w21_count)

    # Joint
    if cdw_len >= actual_cdw and w21_count >= actual_w21:
        mc_joint_better += 1

    if (trial + 1) % 10000 == 0:
        elapsed = time.time() - t0
        print(f"  {trial+1}/{N_MC} done ({elapsed:.1f}s)")

elapsed_total = time.time() - t0
print(f"  MC complete in {elapsed_total:.1f}s")

# Statistics
mc_cdw_mean = sum(mc_cdw) / N_MC
mc_w21_mean = sum(mc_w21) / N_MC
p_cdw = sum(1 for v in mc_cdw if v >= actual_cdw) / N_MC
p_w21 = sum(1 for v in mc_w21 if v >= actual_w21) / N_MC
p_joint = mc_joint_better / N_MC

# Distribution summaries
cdw_counter = Counter(mc_cdw)
w21_counter = Counter(mc_w21)

print(f"\n--- Results ---")
print(f"  Actual max CDW: {actual_cdw} (lag={actual_cdw_lag}, delta={actual_cdw_delta})")
print(f"  MC CDW mean: {mc_cdw_mean:.2f}")
print(f"  MC CDW distribution: {dict(sorted(cdw_counter.items()))}")
print(f"  p(CDW >= {actual_cdw}): {p_cdw:.6f}")

print(f"\n  Actual width-21 repeated: {actual_w21}")
print(f"  MC W21 mean: {mc_w21_mean:.2f}")
print(f"  MC W21 distribution: {dict(sorted(w21_counter.items()))}")
print(f"  p(W21 >= {actual_w21}): {p_w21:.6f}")

print(f"\n  p(JOINT: CDW >= {actual_cdw} AND W21 >= {actual_w21}): {p_joint:.6f}")
print(f"  If independent, expected joint p: {p_cdw * p_w21:.6f}")
independence_ratio = p_joint / max(p_cdw * p_w21, 1e-10) if p_cdw * p_w21 > 0 else float('inf')
print(f"  Ratio (observed/expected): {independence_ratio:.2f}")

if independence_ratio > 2:
    joint_verdict = "CORRELATED - joint occurrence much more likely than independence predicts"
elif independence_ratio < 0.5:
    joint_verdict = "ANTI-CORRELATED - joint occurrence less likely than independence predicts"
else:
    joint_verdict = "CONSISTENT WITH INDEPENDENCE"
print(f"  Verdict: {joint_verdict}")

# Is actual NEAR-OPTIMAL for both?
cdw_rank = sum(1 for v in mc_cdw if v > actual_cdw)
w21_rank = sum(1 for v in mc_w21 if v > actual_w21)
print(f"\n  CDW rank: {cdw_rank}/{N_MC} ({100*cdw_rank/N_MC:.2f}% are better)")
print(f"  W21 rank: {w21_rank}/{N_MC} ({100*w21_rank/N_MC:.2f}% are better)")

optimality_verdict = "NEAR-OPTIMAL" if p_cdw < 0.01 and p_w21 < 0.01 else "NOT NEAR-OPTIMAL"
if p_joint < 0.001:
    optimality_verdict += " (joint p < 0.001 -- SIGNIFICANT)"
print(f"  Joint optimality: {optimality_verdict}")

results["T3.3"] = {
    "n_mc": N_MC,
    "seed": SEED,
    "elapsed_s": round(elapsed_total, 1),
    "actual_cdw_length": actual_cdw,
    "actual_cdw_lag": actual_cdw_lag,
    "actual_cdw_delta": actual_cdw_delta,
    "actual_cdw_start": actual_cdw_start,
    "actual_w21_repeated": actual_w21,
    "mc_cdw_mean": round(mc_cdw_mean, 2),
    "mc_w21_mean": round(mc_w21_mean, 2),
    "mc_cdw_distribution": {str(k): v for k, v in sorted(cdw_counter.items())},
    "mc_w21_distribution": {str(k): v for k, v in sorted(w21_counter.items())},
    "p_cdw_ge_actual": round(p_cdw, 6),
    "p_w21_ge_actual": round(p_w21, 6),
    "p_joint": round(p_joint, 6),
    "p_independent_expected": round(p_cdw * p_w21, 8),
    "independence_ratio": round(independence_ratio, 2),
    "joint_verdict": joint_verdict,
    "cdw_rank_pct": round(100 * cdw_rank / N_MC, 2),
    "w21_rank_pct": round(100 * w21_rank / N_MC, 2),
    "optimality_verdict": optimality_verdict,
}


# ========================================================================
# SUMMARY
# ========================================================================
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"\nT3.1: {len(repeated_w21)} repeated width-21 bigrams found")
null_involved_count = len(t31_results["null_involved_bigrams"])
print(f"  {null_involved_count} involve at least one null position")

print(f"\nT3.2: {len(dual_constrained)} null positions have BOTH delta4 and width21 constraints")
for p in dual_constrained:
    j = all_null_joint[p]
    print(f"  pos {p}: d4={j['d4_required']}, w21={j['w21_forcing']}, "
          f"overlap={j['overlap']}, actual='{j['actual']}'")

print(f"\nT3.3: Joint MC optimality:")
print(f"  p(CDW >= actual): {p_cdw:.6f}")
print(f"  p(W21 >= actual): {p_w21:.6f}")
print(f"  p(JOINT):         {p_joint:.6f}")
print(f"  Verdict: {joint_verdict}")
print(f"  Optimality: {optimality_verdict}")

# Overall verdict
if p_joint < 0.001:
    overall = "SIGNIFICANT INTERACTION - null values appear jointly optimized for both anomalies"
elif p_joint < 0.01:
    overall = "MODERATE INTERACTION - some evidence of joint optimization"
elif len(dual_constrained) > 0 and any(all_null_joint[p]["actual"] in all_null_joint[p]["overlap"] for p in dual_constrained):
    overall = "WEAK INTERACTION - dual constraints exist and actual values satisfy them"
else:
    overall = "NO SIGNIFICANT INTERACTION"

print(f"\nOVERALL VERDICT: {overall}")
results["overall_verdict"] = overall

# Save artifact
output_path = os.path.join(_ROOT, "results", "stehle_width21_interaction.json")
with open(output_path, 'w') as f:
    json.dump(results, f, indent=2)
print(f"\nArtifact saved: {output_path}")
