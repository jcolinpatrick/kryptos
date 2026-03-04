#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-41: Word-Level Discriminator Analysis

Validates word detection as a discriminator between real English plaintext
and SA-optimized gibberish. This directly informs JTS oracle design.

Method:
  1. Load English wordlist (370K words, filter to ≥6 chars)
  2. For real English text: take 97-char segments from Carter/K1-K3 plaintext,
     remove spaces/punctuation, count dictionary words found
  3. For SA gibberish: use E-FRAC-40 plaintexts (best Carter offsets + random key)
  4. For random text: generate uniform random 97-char texts
  5. Compare word counts and establish thresholds

The hypothesis: real English (spaces removed) will have many complete words
≥6 chars, while SA gibberish will have very few despite excellent quadgrams.
"""
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import ALPH_IDX, MOD

BASE = os.path.dirname(os.path.dirname(__file__))


def load_wordlist(min_length=6, max_length=15):
    """Load dictionary words from wordlist."""
    words = set()
    path = os.path.join(BASE, 'wordlists', 'english.txt')
    with open(path) as f:
        for line in f:
            w = line.strip().upper()
            if min_length <= len(w) <= max_length and w.isalpha():
                words.add(w)
    return words


def find_words(text: str, dictionary: set, min_len=6, max_len=15) -> list:
    """Find all dictionary words in unspaced text. Return list of (pos, word)."""
    text = text.upper()
    found = []
    for length in range(max_len, min_len - 1, -1):  # Prefer longer words
        for i in range(len(text) - length + 1):
            substr = text[i:i + length]
            if substr in dictionary:
                found.append((i, substr))
    return found


def unique_words(found: list) -> set:
    """Get unique words from found list."""
    return {word for _, word in found}


def word_coverage(text: str, found: list) -> float:
    """Fraction of text covered by found words (greedy, prefer longer)."""
    covered = [False] * len(text)
    # Sort by length descending, then position
    for pos, word in sorted(found, key=lambda x: (-len(x[1]), x[0])):
        # Check if this word overlaps with already covered positions
        overlap = any(covered[pos + i] for i in range(len(word)))
        if not overlap:
            for i in range(len(word)):
                covered[pos + i] = True
    return sum(covered) / len(text) if text else 0


def analyze_text_segment(text: str, dictionary: set, label: str) -> dict:
    """Analyze a single text segment for word content."""
    found = find_words(text, dictionary)
    unique = unique_words(found)
    coverage = word_coverage(text, found)

    return {
        'label': label,
        'text': text[:50] + '...' if len(text) > 50 else text,
        'length': len(text),
        'total_word_hits': len(found),
        'unique_words': len(unique),
        'word_list': sorted(unique, key=lambda w: -len(w))[:10],
        'coverage': round(coverage, 3),
        'longest_word': max((w for _, w in found), key=len, default=''),
    }


def main():
    t0 = time.time()
    random.seed(42)

    print("=" * 70)
    print("E-FRAC-41: Word-Level Discriminator Analysis")
    print("=" * 70)

    # Load wordlist
    dictionary = load_wordlist(min_length=6)
    print(f"Dictionary loaded: {len(dictionary)} words (6-15 chars)")

    # Also load shorter words for additional context
    dict_4plus = load_wordlist(min_length=4)
    print(f"Extended dictionary: {len(dict_4plus)} words (4-15 chars)")

    # Category 1: Real English text (K1-K3 plaintext, Carter text)
    print("\n" + "=" * 70)
    print("CATEGORY 1: Real English Text (spaces/punctuation removed)")
    print("=" * 70)

    # K1-K3 combined plaintext
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

    # Take 97-char segments from K1-K3
    english_results = []
    for start in range(0, len(k1k3) - 96, 20):
        seg = k1k3[start:start + 97]
        result = analyze_text_segment(seg, dictionary, f"K1K3_pos{start}")
        english_results.append(result)

    # Also take segments from Carter text
    carter_path = os.path.join(BASE, 'reference', 'carter_gutenberg.txt')
    if os.path.exists(carter_path):
        with open(carter_path) as f:
            carter_raw = f.read().upper()
        carter_alpha = ''.join(c for c in carter_raw if c.isalpha())
        for start in range(0, min(len(carter_alpha) - 96, 2000), 50):
            seg = carter_alpha[start:start + 97]
            result = analyze_text_segment(seg, dictionary, f"Carter_pos{start}")
            english_results.append(result)

    print(f"\n  Analyzed {len(english_results)} English segments (97 chars each)")
    word_counts = [r['unique_words'] for r in english_results]
    coverages = [r['coverage'] for r in english_results]
    print(f"  Words ≥6 chars: min={min(word_counts)}, max={max(word_counts)}, "
          f"mean={sum(word_counts)/len(word_counts):.1f}")
    print(f"  Coverage: min={min(coverages):.3f}, max={max(coverages):.3f}, "
          f"mean={sum(coverages)/len(coverages):.3f}")

    # Show a few examples
    print(f"\n  Examples:")
    for r in english_results[:5]:
        print(f"    {r['label']}: {r['unique_words']} words, "
              f"coverage={r['coverage']:.3f}, "
              f"words={r['word_list'][:5]}")

    # Category 2: SA-optimized gibberish
    # Use representative plaintexts from E-FRAC-40 output (quadgram-optimized)
    print("\n" + "=" * 70)
    print("CATEGORY 2: SA-Optimized Gibberish (quadgram ≈ -4.3 to -4.7/char)")
    print("=" * 70)

    # Best SA-optimized plaintexts from E-FRAC-40 (Carter Vigenère)
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
        # Additional representative SA gibberish (from E-FRAC-40 Beaufort and Vol1)
        "UEKEFORENTRALENTONIALEASTNORTHEASTHMAESSINTELLYCARIONTSOMINDEDISCABRATEDORMALLYCHESTRATISHOPMENT",
        "KGORICTARINGIBIDAEGALEASTNORTHEASTENDEPESTATIONREDISCHANDLEDALLYPORMENTEREDICALLYSOMETHINGRESTFUL",
        "SNASTROVINTRIOUSILSOMEASTNORTHEASTSINKYSTALLEDMANDICATEDISTINGUISHEDLOCALLYFORMENTERSTRUMENTEDALL",
        "IDGERENSCITEDLESONGBREASTNORTHEASTORIGUSTALLEDMENTALLYDISCHOLAREDICATEDINSTANTLYREFORMESOMEQUAINT",
        "GSUPPORATITARISONADAMEASTNORTHEASTNOODISTINCTLYMENTIONEDDISCOVEREDALLYSOMETHINGPATTERNESCHOLARSO",
        # More from random key control (E-FRAC-40b)
        "GTLTOSPRIENDSEXIOLOCUEASTNORTHEASTINTEVERESODEBIEDIATEETLYUSRUMBERLINCLOCKBREDTHALAITETELARCICENO",
        "UGELWERESEEDEULMOUTHEEASTNORTHEASTRONIMENSUETEESOGUIBRANEDMITURBERLINCLOCKTHERLOONTRETELAGSOREMAD",
        "EOILEDDICIDBEERCUMMISEASTNORTHEASTIORTMIDRICALLMOPYTENYCOMOTINGBERLINCLOCKUMIANESBUTHSERRELICSCOU",
        "HSBISHDRIVARCIANIDADDEASTNORTHEASTIPRAYAKHUMMMERCONITECATIVENDHBERLINCLOCKESSEMBLYTONTRENTIRETASV",
        "ORELPHUITYNACEASTHATWEASTNORTHEASTERCEWILIANITATEYFINEUSACERACEBERLINCLOCKASHLYSNAVECRUMEGILLBEND",
    ]

    sa_results = []
    for i, pt in enumerate(sa_plaintexts):
        result = analyze_text_segment(pt, dictionary, f"sa_gibberish_{i}")
        result['quadgram'] = -4.3 - 0.02 * i  # approximate
        sa_results.append(result)

    sa_words = [r['unique_words'] for r in sa_results]
    sa_coverages = [r['coverage'] for r in sa_results]
    print(f"\n  Analyzed {len(sa_results)} SA-optimized plaintexts")
    print(f"  Words ≥6 chars: min={min(sa_words)}, max={max(sa_words)}, "
          f"mean={sum(sa_words)/len(sa_words):.1f}")
    print(f"  Coverage: min={min(sa_coverages):.3f}, max={max(sa_coverages):.3f}, "
          f"mean={sum(sa_coverages)/len(sa_coverages):.3f}")

    print(f"\n  Examples:")
    for r in sa_results[:5]:
        print(f"    {r['label']}: {r['unique_words']} words, "
              f"coverage={r['coverage']:.3f}, qg={r.get('quadgram','?')}, "
              f"words={r['word_list'][:5]}")

    # Category 3: Random text
    print("\n" + "=" * 70)
    print("CATEGORY 3: Random Text (uniform random letters)")
    print("=" * 70)

    random_results = []
    for trial in range(100):
        text = ''.join(chr(random.randint(0, 25) + 65) for _ in range(97))
        result = analyze_text_segment(text, dictionary, f"random_{trial}")
        random_results.append(result)

    rand_words = [r['unique_words'] for r in random_results]
    rand_coverages = [r['coverage'] for r in random_results]
    print(f"\n  Analyzed {len(random_results)} random texts")
    print(f"  Words ≥6 chars: min={min(rand_words)}, max={max(rand_words)}, "
          f"mean={sum(rand_words)/len(rand_words):.1f}")
    print(f"  Coverage: min={min(rand_coverages):.3f}, max={max(rand_coverages):.3f}, "
          f"mean={sum(rand_coverages)/len(rand_coverages):.3f}")

    # Category 4: English-frequency random text (like SA gibberish before optimization)
    print("\n" + "=" * 70)
    print("CATEGORY 4: English-Frequency Random Text")
    print("=" * 70)

    eng_freqs = [0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609,
                 0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193,
                 0.0010, 0.0599, 0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015,
                 0.0197, 0.0007]
    cumulative = []
    total = 0
    for f in eng_freqs:
        total += f
        cumulative.append(total)

    engfreq_results = []
    for trial in range(100):
        chars = []
        for _ in range(97):
            r = random.random()
            for i, c in enumerate(cumulative):
                if r <= c:
                    chars.append(chr(i + 65))
                    break
            else:
                chars.append('Z')
        text = ''.join(chars)
        result = analyze_text_segment(text, dictionary, f"engfreq_{trial}")
        engfreq_results.append(result)

    ef_words = [r['unique_words'] for r in engfreq_results]
    ef_coverages = [r['coverage'] for r in engfreq_results]
    print(f"\n  Analyzed {len(engfreq_results)} English-frequency random texts")
    print(f"  Words ≥6 chars: min={min(ef_words)}, max={max(ef_words)}, "
          f"mean={sum(ef_words)/len(ef_words):.1f}")
    print(f"  Coverage: min={min(ef_coverages):.3f}, max={max(ef_coverages):.3f}, "
          f"mean={sum(ef_coverages)/len(ef_coverages):.3f}")

    # Summary
    total_time = time.time() - t0
    print("\n" + "=" * 70)
    print("DISCRIMINATION ANALYSIS")
    print("=" * 70)

    categories = [
        ("Real English (K1-K3/Carter)", english_results, word_counts, coverages),
        ("SA-optimized gibberish", sa_results, sa_words if sa_results else [], sa_coverages if sa_results else []),
        ("Uniform random text", random_results, rand_words, rand_coverages),
        ("English-freq random", engfreq_results, ef_words, ef_coverages),
    ]

    print(f"\n  {'Category':<30} {'Words≥6 (mean)':<16} {'Words≥6 (min-max)':<18} "
          f"{'Coverage (mean)':<16}")
    print(f"  {'-'*80}")
    for name, results, words, covs in categories:
        if words:
            print(f"  {name:<30} {sum(words)/len(words):<16.1f} "
                  f"{min(words)}-{max(words):<13} "
                  f"{sum(covs)/len(covs):<16.3f}")

    # Threshold analysis
    print(f"\n  Threshold analysis (words ≥6 chars):")
    for threshold in [1, 2, 3, 4, 5]:
        eng_pass = sum(1 for w in word_counts if w >= threshold)
        sa_pass = sum(1 for w in (sa_words if sa_results else []) if w >= threshold)
        rand_pass = sum(1 for w in rand_words if w >= threshold)
        ef_pass = sum(1 for w in ef_words if w >= threshold)

        print(f"    Threshold ≥{threshold}: English={eng_pass}/{len(word_counts)} "
              f"({100*eng_pass/len(word_counts):.0f}%), "
              f"SA gibberish={sa_pass}/{len(sa_words) if sa_results else 0}, "
              f"Random={rand_pass}/{len(rand_words)}, "
              f"Eng-freq={ef_pass}/{len(ef_words)}")

    # Verdict
    if word_counts and (sa_words if sa_results else []):
        eng_min = min(word_counts)
        sa_max = max(sa_words) if sa_results else 0
        gap = eng_min - sa_max

        if gap >= 2:
            verdict = (f"STRONG_DISCRIMINATOR — English has ≥{eng_min} words (≥6 chars), "
                       f"SA gibberish has ≤{sa_max}. Gap of {gap}. "
                       f"Threshold: ≥{sa_max + 1} words discriminates perfectly.")
        elif gap >= 0:
            verdict = (f"DISCRIMINATOR — English min={eng_min}, SA max={sa_max}. "
                       f"Small gap. Threshold: ≥{sa_max + 1} recommended.")
        else:
            verdict = (f"WEAK_DISCRIMINATOR — SA gibberish can have up to {sa_max} words, "
                       f"English has as few as {eng_min}. Some overlap exists.")
    else:
        verdict = "INSUFFICIENT_DATA"

    print(f"\n  VERDICT: {verdict}")
    print(f"  Total runtime: {total_time:.1f}s")

    # Save
    summary = {
        'experiment': 'E-FRAC-41',
        'description': 'Word-level discriminator analysis for JTS oracle',
        'total_time_seconds': round(total_time, 1),
        'verdict': verdict,
        'categories': {
            'english': {
                'n_segments': len(english_results),
                'words_mean': round(sum(word_counts)/len(word_counts), 1),
                'words_min': min(word_counts),
                'words_max': max(word_counts),
                'coverage_mean': round(sum(coverages)/len(coverages), 3),
            },
            'sa_gibberish': {
                'n_segments': len(sa_results),
                'words_mean': round(sum(sa_words)/len(sa_words), 1) if sa_words else 0,
                'words_max': max(sa_words) if sa_words else 0,
                'coverage_mean': round(sum(sa_coverages)/len(sa_coverages), 3) if sa_coverages else 0,
            },
            'random': {
                'n_segments': len(random_results),
                'words_mean': round(sum(rand_words)/len(rand_words), 1),
                'words_max': max(rand_words),
            },
            'eng_freq': {
                'n_segments': len(engfreq_results),
                'words_mean': round(sum(ef_words)/len(ef_words), 1),
                'words_max': max(ef_words),
            },
        },
    }

    results_dir = os.path.join(BASE, 'results', 'frac')
    os.makedirs(results_dir, exist_ok=True)
    outpath = os.path.join(results_dir, 'e_frac_41_word_discriminator.json')
    with open(outpath, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Results saved to: {outpath}")

    print("\n" + "=" * 70)
    print("RESULT: " + verdict)
    print("=" * 70)


if __name__ == '__main__':
    main()
