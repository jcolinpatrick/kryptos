#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-42: Refined Word Discriminator — Non-Crib Words + Multi-Threshold

Refines E-FRAC-41's finding that word detection is a WEAK discriminator by:
  1. Excluding crib-derived words from the count (NORTHEAST, BERLIN, CLOCK, EAST, NORTH, etc.)
  2. Testing multiple word-length thresholds (4, 5, 6, 7, 8 chars)
  3. Computing separation statistics (Cohen's d, overlap coefficient)
  4. Testing combined metrics (non-crib words + coverage + quadgram proxy)

The key question: does excluding crib words make word counting a STRONG
discriminator, or is SA gibberish still too close to real English?
"""
import json
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import ALPH_IDX, MOD

BASE = os.path.dirname(os.path.dirname(__file__))

# Words that appear because of the 24 known crib letters — exclude these
# EASTNORTHEAST (positions 21-33) and BERLINCLOCK (positions 63-73)
CRIB_WORDS = {
    'EAST', 'NORTH', 'NORTHEAST', 'EASTNORTHEAST',
    'BERLIN', 'CLOCK', 'BERLINCLOCK',
    # Substrings that are common dictionary words
    'LINER', 'LINE', 'LOCK', 'BLOC',
    'STERN', 'ASTER', 'ASTERN',
    'RLIN', 'ORTH',
}


def load_wordlist(min_length=4, max_length=15):
    """Load dictionary words from wordlist."""
    words = set()
    path = os.path.join(BASE, 'wordlists', 'english.txt')
    with open(path) as f:
        for line in f:
            w = line.strip().upper()
            if min_length <= len(w) <= max_length and w.isalpha():
                words.add(w)
    return words


def find_words(text, dictionary, min_len=4, max_len=15):
    """Find all dictionary words in unspaced text. Return list of (pos, word)."""
    text = text.upper()
    found = []
    for length in range(max_len, min_len - 1, -1):
        for i in range(len(text) - length + 1):
            substr = text[i:i + length]
            if substr in dictionary:
                found.append((i, substr))
    return found


def filter_non_crib_words(found, crib_words=CRIB_WORDS):
    """Remove words that are substrings of the crib plaintext or crib-derived."""
    return [(pos, word) for pos, word in found if word not in crib_words]


def word_coverage(text, found):
    """Fraction of text covered by found words (greedy, non-overlapping)."""
    covered = [False] * len(text)
    for pos, word in sorted(found, key=lambda x: (-len(x[1]), x[0])):
        overlap = any(covered[pos + i] for i in range(len(word)))
        if not overlap:
            for i in range(len(word)):
                covered[pos + i] = True
    return sum(covered) / len(text) if text else 0


def cohens_d(group1, group2):
    """Cohen's d effect size between two groups."""
    if not group1 or not group2:
        return 0.0
    n1, n2 = len(group1), len(group2)
    m1, m2 = sum(group1) / n1, sum(group2) / n2
    var1 = sum((x - m1) ** 2 for x in group1) / max(n1 - 1, 1)
    var2 = sum((x - m2) ** 2 for x in group2) / max(n2 - 1, 1)
    pooled_std = math.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / max(n1 + n2 - 2, 1))
    if pooled_std == 0:
        return float('inf') if m1 != m2 else 0.0
    return (m1 - m2) / pooled_std


def overlap_coefficient(group1, group2):
    """Fraction of group1 values that fall within group2's range."""
    if not group1 or not group2:
        return 0.0
    min2, max2 = min(group2), max(group2)
    return sum(1 for x in group1 if min2 <= x <= max2) / len(group1)


def analyze_segment(text, dictionary, min_len=4):
    """Analyze a text segment, returning all-words and non-crib-words counts."""
    found_all = find_words(text, dictionary, min_len=min_len)
    found_noncrib = filter_non_crib_words(found_all)

    unique_all = {w for _, w in found_all}
    unique_noncrib = {w for _, w in found_noncrib}

    cov_all = word_coverage(text, found_all)
    cov_noncrib = word_coverage(text, found_noncrib)

    return {
        'all_words': len(unique_all),
        'noncrib_words': len(unique_noncrib),
        'cov_all': round(cov_all, 3),
        'cov_noncrib': round(cov_noncrib, 3),
        'all_word_list': sorted(unique_all, key=lambda w: -len(w))[:8],
        'noncrib_word_list': sorted(unique_noncrib, key=lambda w: -len(w))[:8],
    }


def main():
    t0 = time.time()
    random.seed(42)

    print("=" * 70)
    print("E-FRAC-42: Refined Word Discriminator — Non-Crib Words + Multi-Threshold")
    print("=" * 70)

    print(f"\nCrib words excluded from 'non-crib' count:")
    for w in sorted(CRIB_WORDS, key=lambda x: -len(x)):
        print(f"  {w}")

    # ---- Build test corpora ----

    # Real English (K1-K3 + Carter)
    k1k3 = (
        "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
        "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHS"
        "MAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTO"
        "ANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUT"
        "THERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEX"
        "THIRTYEIGHTNORTHLATITUDESIXTYSEVENWESTLONGITUDEXTWOTIMESXLAYERTWO"
        "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
        "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINY"
        "BREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLE"
        "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
        "CAUSEDTHEFLAMETOFLICKERBUTSOONDETAILSOFTHEROOMWITHINEMERGED"
        "FROMTHEMISTXCANYOUSEEANYTHINGQ"
    )

    english_segments = []
    for start in range(0, len(k1k3) - 96, 20):
        english_segments.append(k1k3[start:start + 97])

    carter_path = os.path.join(BASE, 'reference', 'carter_gutenberg.txt')
    if os.path.exists(carter_path):
        with open(carter_path) as f:
            carter_raw = f.read().upper()
        carter_alpha = ''.join(c for c in carter_raw if c.isalpha())
        for start in range(0, min(len(carter_alpha) - 96, 2000), 50):
            english_segments.append(carter_alpha[start:start + 97])

    # SA gibberish from E-FRAC-40
    sa_plaintexts = [
        "RLEDIENTHESARESHALLYSEASTNORTHEASTICHTICALLYGENTOUSPORTEADONIAMBERLINCLOCKSINTSEPUTRIFOSEOFASTFRU",
        "SPREASTNORTHEASTRANNANTABERLINCLOCKEFESTINGLYMANDIATIONTRINALLYCLATERSOUREDATOREFORMANDEPELLSATMU",
        "ICHEASTNORTHEASTEDSTATTABERLINCLOCKLEDECOLLMANISSULATEENTONDINGLYCOMINATIONDANDATPOREHESEACHSMORE",
        "ALCEASTNORTHEASTSGLTHEBERLINCLOCKRISTIONEDESCHAUNDERLANTSOMICATELIBELLATHERTREMACHINISTERALLYSOME",
        "SPREASTNORTHEASTINTIMBERLINCLOCKCHESTRATIONEDANSPIRATEDLYTHEMANDATELLONEDISCOTEDUNIFORMEDBALLYSET",
        "ESBEASTNORTHEAISTERLABBERLINCLOCKMORTALLEYISHEDITIONALDISCOVENTIATEDLYSMANDIFORMENTEDSCHOPATTRESS",
        "EAGEASTNORTHEASTHUOUSTBERLINCLOCKTRALLYDISCOLLATERAINMENTICATESINTERMANDISTINGUISHEDPATTERNEDSOME",
        "ASMEASTNORTHEASTITITEBERLINCLOCKSNOTCHELLABORATORYINTEDEDLYMANDICATIONSTRUMENTEDALLYTHESCHOPPRESS",
        "CKIEASTNORTHEASTHEECABERLINCLOCKATERNATIONEDDIRECTLYMANDICATEDISTINGUISHEDSOLVEDPATTERNMENTCHOKES",
        "MBLEASTNORTHEASTACALEBERLINCLOCKSPENTEDLYDISCHOLARMENTEDICATEDINSTALLYMANDIFORMENTEDSCHEMESORTED",
        "UEKEFORENTRALENTONIALEASTNORTHEASTHMAESSINTELLYCARIONTSOMINDEDISCABRATEDORMALLYCHESTRATISHOPMENT",
        "KGORICTARINGIBIDAEGALEASTNORTHEASTENDEPESTATIONREDISCHANDLEDALLYPORMENTEREDICALLYSOMETHINGRESTFUL",
        "SNASTROVINTRIOUSILSOMEASTNORTHEASTSINKYSTALLEDMANDICATEDISTINGUISHEDLOCALLYFORMENTERSTRUMENTEDALL",
        "IDGERENSCITEDLESONGBREASTNORTHEASTORIGUSTALLEDMENTALLYDISCHOLAREDICATEDINSTANTLYREFORMESOMEQUAINT",
        "GSUPPORATITARISONADAMEASTNORTHEASTNOODISTINCTLYMENTIONEDDISCOVEREDALLYSOMETHINGPATTERNESCHOLARSO",
        "GTLTOSPRIENDSEXIOLOCUEASTNORTHEASTINTEVERESODEBIEDIATEETLYUSRUMBERLINCLOCKBREDTHALAITETELARCICENO",
        "UGELWERESEEDEULMOUTHEEASTNORTHEASTRONIMENSUETEESOGUIBRANEDMITURBERLINCLOCKTHERLOONTRETELAGSOREMAD",
        "EOILEDDICIDBEERCUMMISEASTNORTHEASTIORTMIDRICALLMOPYTENYCOMOTINGBERLINCLOCKUMIANESBUTHSERRELICSCOU",
        "HSBISHDRIVARCIANIDADDEASTNORTHEASTIPRAYAKHUMMMERCONITECATIVENDHBERLINCLOCKESSEMBLYTONTRENTIRETASV",
        "ORELPHUITYNACEASTHATWEASTNORTHEASTERCEWILIANITATEYFINEUSACERACEBERLINCLOCKASHLYSNAVECRUMEGILLBEND",
    ]

    # ---- Phase 1: Multi-threshold analysis (word lengths 4-8) ----
    print("\n" + "=" * 70)
    print("PHASE 1: Multi-Threshold Analysis")
    print("=" * 70)

    results_by_threshold = {}

    for min_len in [4, 5, 6, 7, 8]:
        dictionary = load_wordlist(min_length=min_len)
        print(f"\n--- Word length ≥{min_len} (dictionary: {len(dictionary)} words) ---")

        eng_all = []
        eng_noncrib = []
        sa_all_list = []
        sa_noncrib = []

        for seg in english_segments:
            r = analyze_segment(seg, dictionary, min_len=min_len)
            eng_all.append(r['all_words'])
            eng_noncrib.append(r['noncrib_words'])

        for pt in sa_plaintexts:
            r = analyze_segment(pt, dictionary, min_len=min_len)
            sa_all_list.append(r['all_words'])
            sa_noncrib.append(r['noncrib_words'])

        # Statistics
        eng_all_mean = sum(eng_all) / len(eng_all)
        eng_nc_mean = sum(eng_noncrib) / len(eng_noncrib)
        sa_all_mean = sum(sa_all_list) / len(sa_all_list)
        sa_nc_mean = sum(sa_noncrib) / len(sa_noncrib)

        d_all = cohens_d(eng_all, sa_all_list)
        d_noncrib = cohens_d(eng_noncrib, sa_noncrib)

        overlap_all = overlap_coefficient(sa_all_list, eng_all)
        overlap_nc = overlap_coefficient(sa_noncrib, eng_noncrib)

        print(f"  All words:     English mean={eng_all_mean:.1f} [{min(eng_all)}-{max(eng_all)}], "
              f"SA mean={sa_all_mean:.1f} [{min(sa_all_list)}-{max(sa_all_list)}], "
              f"Cohen's d={d_all:.2f}, overlap={overlap_all:.2f}")
        print(f"  Non-crib only: English mean={eng_nc_mean:.1f} [{min(eng_noncrib)}-{max(eng_noncrib)}], "
              f"SA mean={sa_nc_mean:.1f} [{min(sa_noncrib)}-{max(sa_noncrib)}], "
              f"Cohen's d={d_noncrib:.2f}, overlap={overlap_nc:.2f}")

        # Perfect separation check
        eng_nc_min = min(eng_noncrib)
        sa_nc_max = max(sa_noncrib)
        gap = eng_nc_min - sa_nc_max
        if gap > 0:
            print(f"  *** PERFECT SEPARATION at threshold ≥{sa_nc_max + 1} non-crib words ***")
        else:
            print(f"  No perfect separation (English min={eng_nc_min}, SA max={sa_nc_max})")

        results_by_threshold[min_len] = {
            'dictionary_size': len(dictionary),
            'english': {
                'all_mean': round(eng_all_mean, 1),
                'all_range': [min(eng_all), max(eng_all)],
                'noncrib_mean': round(eng_nc_mean, 1),
                'noncrib_range': [min(eng_noncrib), max(eng_noncrib)],
            },
            'sa_gibberish': {
                'all_mean': round(sa_all_mean, 1),
                'all_range': [min(sa_all_list), max(sa_all_list)],
                'noncrib_mean': round(sa_nc_mean, 1),
                'noncrib_range': [min(sa_noncrib), max(sa_noncrib)],
            },
            'cohens_d_all': round(d_all, 2),
            'cohens_d_noncrib': round(d_noncrib, 2),
            'overlap_all': round(overlap_all, 2),
            'overlap_noncrib': round(overlap_nc, 2),
            'gap_noncrib': gap,
        }

    # ---- Phase 2: Detailed non-crib word analysis at best threshold ----
    print("\n" + "=" * 70)
    print("PHASE 2: Detailed Non-Crib Word Analysis (≥6 chars)")
    print("=" * 70)

    dictionary6 = load_wordlist(min_length=6)

    print("\n  Top SA gibberish — non-crib words found:")
    for i, pt in enumerate(sa_plaintexts[:10]):
        r = analyze_segment(pt, dictionary6, min_len=6)
        print(f"    SA-{i}: {r['noncrib_words']} non-crib words, "
              f"cov={r['cov_noncrib']:.3f}, "
              f"words={r['noncrib_word_list'][:6]}")

    print("\n  Sample English segments — non-crib words found:")
    for i, seg in enumerate(english_segments[:10]):
        r = analyze_segment(seg, dictionary6, min_len=6)
        print(f"    Eng-{i}: {r['noncrib_words']} non-crib words, "
              f"cov={r['cov_noncrib']:.3f}, "
              f"words={r['noncrib_word_list'][:6]}")

    # ---- Phase 3: Composite scoring ----
    print("\n" + "=" * 70)
    print("PHASE 3: Composite Scoring")
    print("=" * 70)

    # Try composite: non-crib word count + non-crib coverage
    # (since these are correlated, we can't just add them, but let's see if
    # combining improves separation)

    dictionary6 = load_wordlist(min_length=6)

    eng_composites = []
    sa_composites = []

    for seg in english_segments:
        r = analyze_segment(seg, dictionary6, min_len=6)
        # Composite: non-crib words * coverage
        composite = r['noncrib_words'] * (1 + r['cov_noncrib'])
        eng_composites.append(composite)

    for pt in sa_plaintexts:
        r = analyze_segment(pt, dictionary6, min_len=6)
        composite = r['noncrib_words'] * (1 + r['cov_noncrib'])
        sa_composites.append(composite)

    d_composite = cohens_d(eng_composites, sa_composites)
    overlap_composite = overlap_coefficient(sa_composites, eng_composites)

    eng_comp_mean = sum(eng_composites) / len(eng_composites)
    sa_comp_mean = sum(sa_composites) / len(sa_composites)

    print(f"\n  Composite (noncrib_words * (1 + noncrib_coverage)):")
    print(f"    English: mean={eng_comp_mean:.1f} [{min(eng_composites):.1f}-{max(eng_composites):.1f}]")
    print(f"    SA:      mean={sa_comp_mean:.1f} [{min(sa_composites):.1f}-{max(sa_composites):.1f}]")
    print(f"    Cohen's d={d_composite:.2f}, overlap={overlap_composite:.2f}")

    comp_gap = min(eng_composites) - max(sa_composites)
    if comp_gap > 0:
        print(f"    *** PERFECT SEPARATION with composite metric ***")
    else:
        print(f"    No perfect separation (eng min={min(eng_composites):.1f}, "
              f"sa max={max(sa_composites):.1f})")

    # ---- Phase 4: Word-length distribution analysis ----
    print("\n" + "=" * 70)
    print("PHASE 4: Word-Length Distribution")
    print("=" * 70)

    dictionary4 = load_wordlist(min_length=4)

    # For each category, collect the lengths of non-crib words found
    eng_word_lengths = []
    sa_word_lengths = []

    for seg in english_segments:
        found = find_words(seg, dictionary4, min_len=4)
        noncrib = filter_non_crib_words(found)
        lengths = [len(w) for _, w in noncrib]
        if lengths:
            eng_word_lengths.append(max(lengths))
        else:
            eng_word_lengths.append(0)

    for pt in sa_plaintexts:
        found = find_words(pt, dictionary4, min_len=4)
        noncrib = filter_non_crib_words(found)
        lengths = [len(w) for _, w in noncrib]
        if lengths:
            sa_word_lengths.append(max(lengths))
        else:
            sa_word_lengths.append(0)

    eng_maxlen_mean = sum(eng_word_lengths) / len(eng_word_lengths) if eng_word_lengths else 0
    sa_maxlen_mean = sum(sa_word_lengths) / len(sa_word_lengths) if sa_word_lengths else 0

    print(f"\n  Longest non-crib word per segment:")
    print(f"    English: mean={eng_maxlen_mean:.1f} [{min(eng_word_lengths)}-{max(eng_word_lengths)}]")
    print(f"    SA:      mean={sa_maxlen_mean:.1f} [{min(sa_word_lengths)}-{max(sa_word_lengths)}]")

    d_maxlen = cohens_d(eng_word_lengths, sa_word_lengths)
    print(f"    Cohen's d={d_maxlen:.2f}")

    maxlen_gap = min(eng_word_lengths) - max(sa_word_lengths)
    if maxlen_gap > 0:
        print(f"    *** PERFECT SEPARATION on max word length ***")
    else:
        print(f"    No perfect separation (eng min={min(eng_word_lengths)}, "
              f"sa max={max(sa_word_lengths)})")

    # ---- Summary ----
    total_time = time.time() - t0
    print("\n" + "=" * 70)
    print("SUMMARY: Best Discriminators")
    print("=" * 70)

    # Find the best threshold
    best_d = 0
    best_config = ""
    for min_len, data in results_by_threshold.items():
        if data['cohens_d_noncrib'] > best_d:
            best_d = data['cohens_d_noncrib']
            best_config = f"non-crib words ≥{min_len} chars"

    print(f"\n  Best automated metric: {best_config} (Cohen's d = {best_d:.2f})")
    print(f"  Composite metric: Cohen's d = {d_composite:.2f}")
    print(f"  Max word length: Cohen's d = {d_maxlen:.2f}")

    # Interpretation of Cohen's d
    if best_d >= 0.8:
        d_interp = "LARGE effect"
    elif best_d >= 0.5:
        d_interp = "MEDIUM effect"
    elif best_d >= 0.2:
        d_interp = "SMALL effect"
    else:
        d_interp = "NEGLIGIBLE effect"
    print(f"  Effect size interpretation: {d_interp}")

    # Check if any metric achieves perfect separation
    any_perfect = False
    for min_len, data in results_by_threshold.items():
        if data['gap_noncrib'] > 0:
            any_perfect = True
            print(f"\n  PERFECT SEPARATION at ≥{min_len}-char non-crib words "
                  f"(threshold: >{data['sa_gibberish']['noncrib_range'][1]})")

    if comp_gap > 0:
        any_perfect = True
        print(f"  PERFECT SEPARATION with composite metric")

    if maxlen_gap > 0:
        any_perfect = True
        print(f"  PERFECT SEPARATION on max non-crib word length")

    if any_perfect:
        verdict = ("IMPROVED_DISCRIMINATOR — excluding crib words creates separation. "
                   f"Best metric: {best_config} (d={best_d:.2f})")
    elif best_d >= 0.5:
        verdict = (f"MODERATE_DISCRIMINATOR — non-crib words improve separation "
                   f"(d={best_d:.2f}) but overlap remains. "
                   f"Still requires semantic evaluation for final candidates.")
    else:
        verdict = (f"STILL_WEAK — excluding crib words does NOT sufficiently improve "
                   f"discrimination (d={best_d:.2f}). "
                   f"Semantic coherence remains the ONLY reliable discriminator.")

    print(f"\n  VERDICT: {verdict}")
    print(f"  Total runtime: {total_time:.1f}s")

    # Save results
    summary = {
        'experiment': 'E-FRAC-42',
        'description': 'Refined word discriminator: non-crib words + multi-threshold',
        'total_time_seconds': round(total_time, 1),
        'verdict': verdict,
        'crib_words_excluded': sorted(CRIB_WORDS),
        'thresholds': results_by_threshold,
        'composite': {
            'english_mean': round(eng_comp_mean, 1),
            'sa_mean': round(sa_comp_mean, 1),
            'cohens_d': round(d_composite, 2),
            'overlap': round(overlap_composite, 2),
            'gap': round(comp_gap, 1),
        },
        'max_word_length': {
            'english_mean': round(eng_maxlen_mean, 1),
            'sa_mean': round(sa_maxlen_mean, 1),
            'cohens_d': round(d_maxlen, 2),
            'gap': maxlen_gap,
        },
        'best_metric': best_config,
        'best_cohens_d': round(best_d, 2),
    }

    results_dir = os.path.join(BASE, 'results', 'frac')
    os.makedirs(results_dir, exist_ok=True)
    outpath = os.path.join(results_dir, 'e_frac_42_refined_discriminator.json')
    with open(outpath, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Results saved to: {outpath}")

    print("\n" + "=" * 70)
    print("RESULT: " + verdict)
    print("=" * 70)


if __name__ == '__main__':
    main()
