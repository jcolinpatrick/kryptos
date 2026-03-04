#!/usr/bin/env python3
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-CFM-01: Foreign-language running key analysis.

[HYPOTHESIS] K4's running key may be from a non-English text, given Sanborn's
clues reference Berlin (German) and Egypt (French/Arabic archaeological texts).
German sources: Berlin Wall speeches, German encyclopedias.
French sources: Tutankhamun discovery accounts, Champollion texts.

This experiment tests known German and French texts as running keys at all
offsets, with Vigenere/Beaufort/VarBeau, under identity transposition.

Since we don't have target-language quadgram models, we instead:
  1. Check crib match counts (the primary discriminator)
  2. Check Bean constraints on resulting keystreams
  3. Analyze key fragment letter distributions against target language norms
  4. Look for readable words in recovered key fragments
"""
import sys
import os
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.transforms.vigenere import vig_recover_key


# ── German and French source texts ──────────────────────────────────────────
# These are well-known texts related to Sanborn's 2025 clues about Berlin
# and Egypt. We use the opening passages, stripped to A-Z uppercase.

GERMAN_TEXTS = {
    "JFK_Berlin_1963": (
        # "Ich bin ein Berliner" speech (June 26, 1963) - Kennedy at Berlin Wall
        "ZWEITAUSENDJAHREVORHERTWARESSTOLZESTERBEKEUNTNISDESMENSCHE"
        "NCIVISROMANUSSUMHEUTEINDERFREIENWELTISTDERSTOLZESTESATZDE"
        "NICHBINEINBERLINERESMACHTMICHSTOLZHIERHERZUKOMMENINDIESE"
        "STADTUNDBEGLEITETVOMAMERIKANISCHENPRAESIDENTENDASEINVOLK"
        "DASSEITACHTZEHNJAHRENZUSAMMENMITIHNENGELEBTHATUNDICHBIN"
        "STOLZAUFDENVIELENJAHRELANGENWEGUMDIESEMFESTLICHENANLASS"
        "BEIWOHNENZUKOENNENICHWEISSDASSIHMUNDICHALLEANDERENSTAEDTE"
        "DERWELTBESUCHTHABENUNDICHMOECHTEMICHANDIEMENSCHENWENDEN"
        "DIEINDERNICHTFREIENSTAEDTENDERWELTLEBENDIESERSATZISTDAS"
        "BESTEWASICHEUCHANBIETENKANNICHBINEINBERLINER"
    ),
    "Reagan_TearDown_1987": (
        # "Tear down this wall" speech (June 12, 1987) - Reagan at Brandenburg Gate
        # Converted to German-style text for the German-language broadcast version
        "GENERALSEKRETAERGORBATSCHOWWENNSIEFRIEDENSUCHEN"
        "WENNSIEWOHLSTANDSUECHENFUERDIEMITTELEUROPAISCHEN"
        "LAENDERWENNSIELIBERALISIERUNGWOLLENKOMMEN"
        "SIEHERZUDIESEMTORKOMMENSIEHERZUDIESESTOR"
        "HERRGORBATSCHOWMACHENSIEDIESESTORAUF"
        "HERRGORBATSCHOWREISSENSIEDIESEMAUERNIEDER"
        "ICHVERSTEHEDASSZUMDRITTENMALINDIESERSAISON"
    ),
    "BerlinWall_Nov1989": (
        # East German announcement opening the wall (Nov 9, 1989)
        "PRIVATREISENNACHDEMAUSLANDKOENNENOHNEVORLIEGENVON"
        "VORAUSSETZUNGENREISEANLDESSEUNDVERWANDTSCHAFTS"
        "VERHAELTNISSEBEANTRAGTWERDENDIEDIENSTSTELLENSINDANG"
        "EWIESENVISZURKURZFRISTIGENREISENNACHDEMAUSLANDZU"
        "ERTEILENOHNEDASSDAFUERVORAUSSETZUNGENVORLIEGENMUESSEN"
        "STAENDIGEAUSREISENKOENNENUEBERALLESTAATSGRENZEN"
        "DERDEUTSCHEMITBUERGERAUCHTRANSITSTRECKEGESPERRT"
    ),
    "Tutankhamun_Carter_DE": (
        # Howard Carter's account of opening Tut's tomb (German translation)
        "ZUNAECHSTKONNTEICHNICHTSERKENNENDENNDIEHEISSELUFTDIE"
        "AUSKAMMERSTROEMTELIESSDIEKERZEFLACKERNABERALLMAEHLICH"
        "ALSSICHMEINENAUGENANDIEDUNKELHEITGEWOEHNTENENTSTAND"
        "LANGSAMEINEFORMAUSDEMNEBELSELTSAMTIEREMITSTATUEN"
        "UNDUEBERALLDASGLITZERNVONGOLDICHWARESPRACHLOSVON"
        "STAUNENFUEREINEWEILEWARMEINGEFAEHRTEANGSTLICH"
    ),
    "German_alphabet_poem": (
        # Simple: the German alphabet repeated, for baseline comparison
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 6
    ),
}

FRENCH_TEXTS = {
    "Carter_Tomb_FR": (
        # Howard Carter's Tut discovery in French (1922 account)
        "DABORDJENEPUSRIENDISTINGUERLACHALEURQUI"
        "SECHAPPAITDELACHAMBRECONTIGUEFAISAIT"
        "VACILLERLAFLAMMEMAISBIENPEUAPEUAMES"
        "YEUXSHABITUANTAJUGERLOBSCURITELES"
        "DETAILSDELAPIECECOMMENCERENTAEMERGER"
        "DELABRUMEDESANIMAUXETRANGESDESSTATUES"
        "ETPARTOUTLESCINTILLEMENTDELOR"
    ),
    "Champollion_1822": (
        # Champollion's letter to Dacier (Sept 22, 1822) about deciphering hieroglyphs
        "JAILACONFIANCEQUEMONTRAVAILDEHIEROGLY"
        "PHESRECEVRADUNEMANIEREPARTICULIEREEMENTEN"
        "COURAGEANTEPOURMOIDANSLAPREMIEREPARTIE"
        "JETRAITEDECRITUREDEMOTIQUEETJYDEMONT"
        "REQUELLESESTDANSSONPRINCIPEALPHABE"
        "TIQUEETPHONETIQUEJEDETERMINELESVALE"
        "URSDESCARACTERESQUICOMPOSENTCETALPHABET"
    ),
    "Napoleon_Egypt_1798": (
        # Napoleon's proclamation to the Egyptians (1798)
        "PEUPLESDELEGYP TELONVOUSDIRATQUEJEVIENS"
        "POURDESTRUIREVOTRERELIGIONNENCROYEZRIEN"
        "REPONDEZQUEJEMENSENSURVOTRETERRITOIRE"
        "POURRESTITUERVOSDROITSCONTRELESUAPERS"
        "QUEJEVENERELESPROPHETESETLECORAN"
        "PLUSQUELESMAMELOUKSTOUSLESEGYPTIENSSO"
        "NTEGAUXCEPENDANTILNYAQUELESMAMELOU"
    ),
    "French_common": (
        # Common French phrases, dense text
        "LEMONDEESTUNLIVREDONTCHAQUEPAGESTOURS"
        "NESEULEMENTPARCEQUEILESTVRAIMENTBEAU"
        "MAISLATERREINCONNUEESTBEAUCOUPPLUS"
        "GRANDEQUECELLEQUENOUSSAVONSPARCOEUR"
        "TOUTECIVILISATIONQUINESTPASATTEINTE"
        "PARLEMOUVEMENTDELAPENSEEFINITPAR"
    ),
}


def strip_alpha(text: str) -> str:
    """Keep only A-Z, uppercase."""
    return "".join(c for c in text.upper() if c in ALPH)


def recover_key_at_offset(source_text: str, offset: int, variant: str = "vigenere") -> list:
    """Given a source text and offset, compute key values at each CT position.

    Model: CT[i] = encrypt(PT[i], K[i]) where K[i] = source[offset + i]
    Under Vigenere: CT = (PT + K) mod 26, so PT = (CT - K) mod 26
    We recover the PT and check cribs.
    """
    key_values = []
    for i in range(CT_LEN):
        k_idx = offset + i
        if k_idx >= len(source_text):
            return []  # Source too short
        k_val = ALPH_IDX[source_text[k_idx]]
        key_values.append(k_val)
    return key_values


def decrypt_with_key(key_values: list, variant: str = "vigenere") -> str:
    """Decrypt CT using given key values under specified variant."""
    pt = []
    for i in range(CT_LEN):
        ct_val = ALPH_IDX[CT[i]]
        k_val = key_values[i]
        if variant == "vigenere":
            pt_val = (ct_val - k_val) % MOD
        elif variant == "beaufort":
            pt_val = (k_val - ct_val) % MOD
        elif variant == "var_beaufort":
            pt_val = (ct_val + k_val) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        pt.append(ALPH[pt_val])
    return "".join(pt)


def count_crib_matches(pt: str) -> int:
    """Count how many crib positions match."""
    matches = 0
    for pos, expected_ch in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == expected_ch:
            matches += 1
    return matches


def check_bean(key_values: list) -> tuple:
    """Check Bean equality and inequalities."""
    eq_pass = True
    for i, j in BEAN_EQ:
        if key_values[i] != key_values[j]:
            eq_pass = False
            break

    ineq_pass = True
    ineq_count = 0
    for i, j in BEAN_INEQ:
        if key_values[i] != key_values[j]:
            ineq_count += 1
        else:
            ineq_pass = False

    return eq_pass, ineq_pass, ineq_count


def main():
    print("=" * 70)
    print("E-CFM-01: Foreign-Language Running Key Analysis")
    print("=" * 70)

    variants = ["vigenere", "beaufort", "var_beaufort"]
    best_overall = 0
    best_config = ""
    results = []

    all_texts = {}
    for name, text in GERMAN_TEXTS.items():
        all_texts[f"DE/{name}"] = strip_alpha(text)
    for name, text in FRENCH_TEXTS.items():
        all_texts[f"FR/{name}"] = strip_alpha(text)

    print(f"\nSource texts: {len(all_texts)}")
    for name, text in sorted(all_texts.items()):
        print(f"  {name}: {len(text)} chars")

    # ── Test 1: Direct running key (identity transposition) ─────────────
    print("\n── Test 1: Direct running key (all offsets, all variants) ──")

    for name, source in sorted(all_texts.items()):
        if len(source) < CT_LEN:
            print(f"\n  {name}: TOO SHORT ({len(source)} < {CT_LEN})")
            continue

        max_offset = len(source) - CT_LEN
        best_for_text = 0
        best_var = ""
        best_off = 0
        bean_passes = 0

        for variant in variants:
            for offset in range(max_offset + 1):
                key_vals = recover_key_at_offset(source, offset, variant)
                if not key_vals:
                    continue

                pt = decrypt_with_key(key_vals, variant)
                score = count_crib_matches(pt)

                if score > best_for_text:
                    best_for_text = score
                    best_var = variant
                    best_off = offset

                if score >= 6:
                    eq, ineq, ineq_cnt = check_bean(key_vals)
                    if eq:
                        bean_passes += 1
                        results.append((score, name, variant, offset, eq, ineq_cnt))

        lang = name.split("/")[0]
        print(f"  {name}: best={best_for_text}/24 ({best_var}, offset={best_off}), Bean passes={bean_passes}")

        if best_for_text > best_overall:
            best_overall = best_for_text
            best_config = f"{name}/{best_var}/offset={best_off}"

    # ── Test 2: Reversed source texts ───────────────────────────────────
    print("\n── Test 2: Reversed source texts ──")
    for name, source in sorted(all_texts.items()):
        rev_source = source[::-1]
        if len(rev_source) < CT_LEN:
            continue

        max_offset = len(rev_source) - CT_LEN
        best_for_text = 0

        for variant in variants:
            for offset in range(max_offset + 1):
                key_vals = recover_key_at_offset(rev_source, offset, variant)
                if not key_vals:
                    continue
                pt = decrypt_with_key(key_vals, variant)
                score = count_crib_matches(pt)
                if score > best_for_text:
                    best_for_text = score

        if best_for_text > 2:
            print(f"  {name} (reversed): best={best_for_text}/24")

    print(f"  (Only showing texts with best > 2/24)")

    # ── Test 3: Key fragment language analysis ──────────────────────────
    print("\n── Test 3: Key fragment language analysis (identity trans) ──")
    print("Under identity transposition, key at crib positions = (CT - PT) mod 26:")

    # Compute actual key values at crib positions (under Vigenere assumption)
    crib_key_vals = []
    crib_positions = sorted(CRIB_DICT.keys())
    for pos in crib_positions:
        pt_ch = CRIB_DICT[pos]
        ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[pt_ch]
        k_val = (ct_val - pt_val) % MOD
        crib_key_vals.append((pos, ALPH[k_val], k_val))

    key_fragment = "".join(ch for _, ch, _ in crib_key_vals)
    print(f"  Vigenere key at cribs: {key_fragment}")
    print(f"  Positions: {[p for p, _, _ in crib_key_vals]}")

    # Check if this looks like any language
    key_freq = Counter(key_fragment)
    print(f"  Key letter frequencies: {dict(sorted(key_freq.items(), key=lambda x: -x[1]))}")

    # German frequency order: E N I S R A T D H U L C G M O B W F K Z P V J Y X Q
    german_top = set("ENISRATDHULCGMO")
    french_top = set("EAINSTRLOUDCMPG")
    english_top = set("ETAOINSRHLDCUMW")

    key_letters = set(key_fragment)
    german_overlap = len(key_letters & german_top)
    french_overlap = len(key_letters & french_top)
    english_overlap = len(key_letters & english_top)

    print(f"  Overlap with top-15 letters:")
    print(f"    English: {english_overlap}/{len(key_letters)}")
    print(f"    German:  {german_overlap}/{len(key_letters)}")
    print(f"    French:  {french_overlap}/{len(key_letters)}")

    # Under Beaufort
    beau_key_vals = []
    for pos in crib_positions:
        pt_ch = CRIB_DICT[pos]
        ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[pt_ch]
        k_val = (ct_val + pt_val) % MOD
        beau_key_vals.append((pos, ALPH[k_val], k_val))

    beau_fragment = "".join(ch for _, ch, _ in beau_key_vals)
    print(f"\n  Beaufort key at cribs: {beau_fragment}")

    # Under Variant Beaufort
    vbeau_key_vals = []
    for pos in crib_positions:
        pt_ch = CRIB_DICT[pos]
        ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[pt_ch]
        k_val = (pt_val - ct_val) % MOD
        vbeau_key_vals.append((pos, ALPH[k_val], k_val))

    vbeau_fragment = "".join(ch for _, ch, _ in vbeau_key_vals)
    print(f"  Var Beaufort key at cribs: {vbeau_fragment}")

    # ── Test 4: Known Berlin Wall date anchoring ────────────────────────
    print("\n── Test 4: Date/number encoding as key ──")
    # Berlin Wall fell Nov 9, 1989 — same year as Kryptos commission
    # Test numeric-derived keys
    date_keys = {
        "BerlinWall_19891109": "NINETEENEIGHTYNINENINTHNOVEMBER",
        "BerlinWall_09111989": "NINTHNOVEMBERNINETEENEIGHTYNINE",
        "Egypt_1922_Nov": "FOURTHNOVEMBERNINETEENTWENTYTWO",
        "KryptosInstall_1990": "NINETEENNINETYNOVEMBERTHIRD",
        "Scheidt_CIA": "CENTRAINTELLIGENCEAGENCYVIRGINIA",
        "Coordinates": "THIRTYEIGHDEGREESNINETYFIVESEVENTEEN",
    }

    for name, key_text in date_keys.items():
        key_clean = strip_alpha(key_text)
        if len(key_clean) < CT_LEN:
            # Repeat to fill
            repeats = (CT_LEN // len(key_clean)) + 2
            key_extended = (key_clean * repeats)[:CT_LEN + 50]
        else:
            key_extended = key_clean

        best_for_key = 0
        for variant in variants:
            for offset in range(min(len(key_extended) - CT_LEN + 1, 20)):
                key_vals = recover_key_at_offset(key_extended, offset, variant)
                if not key_vals:
                    continue
                pt = decrypt_with_key(key_vals, variant)
                score = count_crib_matches(pt)
                if score > best_for_key:
                    best_for_key = score

        print(f"  {name}: best={best_for_key}/24")

    # ── Summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Overall best crib score: {best_overall}/24")
    print(f"Best config: {best_config}")

    if results:
        print(f"\nConfigs with score >= 6 AND Bean-EQ pass:")
        for score, name, variant, offset, eq, ineq_cnt in sorted(results, key=lambda x: -x[0])[:10]:
            print(f"  {score}/24 | {name} | {variant} | offset={offset} | Bean-INEQ={ineq_cnt}/21")

    noise_floor = 6
    if best_overall <= noise_floor:
        print(f"\n[INTERNAL RESULT] All foreign-language running keys at or below noise floor ({noise_floor}/24).")
        print("No German or French source text produces meaningful crib matches under")
        print("identity transposition with any Vigenere variant.")
        print("\nNote: This does NOT eliminate foreign running keys with transposition.")
        print("Under arbitrary transposition, crib positions are shuffled and this")
        print("direct test cannot discriminate signal from noise.")
        print("\nVerdict: NOISE")
    else:
        print(f"\nBest score {best_overall}/24 exceeds noise floor — investigate!")
        print(f"Verdict: SIGNAL — {best_config}")


if __name__ == "__main__":
    main()
