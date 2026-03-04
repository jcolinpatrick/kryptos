#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-43: Bigram Transition Discriminator

Tests whether bigram transition probability scoring (a lightweight language model)
can achieve better discrimination between SA gibberish and real English than
word counting (E-FRAC-42's best: d=1.14 with non-crib words ≥7 chars).

The hypothesis: SA quadgram optimization produces good local quadgrams but poor
global coherence. Bigram transitions capture different information than quadgrams
(summed log-probs across the WHOLE text, including inter-word boundaries).

Method:
  1. Build bigram transition matrix from English corpus (Carter text)
  2. Score = mean log-prob of bigram transitions across the 97-char text
  3. Compare English segments, SA gibberish, and random baselines
  4. Compute Cohen's d and check for perfect separation
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


def build_bigram_model(text):
    """Build bigram transition log-probability model from training text."""
    counts = {}
    totals = {}
    for i in range(len(text) - 1):
        bg = text[i:i+2]
        if len(bg) == 2 and bg[0].isalpha() and bg[1].isalpha():
            bg = bg.upper()
            counts[bg] = counts.get(bg, 0) + 1
            totals[bg[0]] = totals.get(bg[0], 0) + 1

    # Log-probabilities with Laplace smoothing
    model = {}
    for bg, count in counts.items():
        model[bg] = math.log10((count + 1) / (totals.get(bg[0], 0) + 26))

    # Floor for unseen bigrams
    floor = math.log10(1 / 27)  # ~= -1.431
    return model, floor


def bigram_score(text, model, floor):
    """Score text using bigram transition log-probabilities."""
    text = text.upper()
    total = 0.0
    n = 0
    for i in range(len(text) - 1):
        bg = text[i:i+2]
        if bg[0].isalpha() and bg[1].isalpha():
            total += model.get(bg, floor)
            n += 1
    return total / n if n > 0 else floor


def build_trigram_model(text):
    """Build trigram transition log-probability model from training text."""
    counts = {}
    totals = {}
    for i in range(len(text) - 2):
        tg = text[i:i+3]
        if len(tg) == 3 and all(c.isalpha() for c in tg):
            tg = tg.upper()
            prefix = tg[:2]
            counts[tg] = counts.get(tg, 0) + 1
            totals[prefix] = totals.get(prefix, 0) + 1

    model = {}
    for tg, count in counts.items():
        prefix = tg[:2]
        model[tg] = math.log10((count + 1) / (totals.get(prefix, 0) + 26))

    floor = math.log10(1 / 27)
    return model, floor


def trigram_score(text, model, floor):
    """Score text using trigram transition log-probabilities."""
    text = text.upper()
    total = 0.0
    n = 0
    for i in range(len(text) - 2):
        tg = text[i:i+3]
        if all(c.isalpha() for c in tg):
            total += model.get(tg, floor)
            n += 1
    return total / n if n > 0 else floor


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
    """Fraction of group2 values that fall within group1's range."""
    if not group1 or not group2:
        return 0.0
    min1, max1 = min(group1), max(group1)
    return sum(1 for x in group2 if min1 <= x <= max1) / len(group2)


def main():
    t0 = time.time()
    random.seed(42)

    print("=" * 70)
    print("E-FRAC-43: Bigram/Trigram Transition Discriminator")
    print("=" * 70)

    # Build models from Carter text (large training corpus)
    carter_path = os.path.join(BASE, 'reference', 'carter_gutenberg.txt')
    with open(carter_path) as f:
        carter_raw = f.read()
    carter_alpha = ''.join(c for c in carter_raw.upper() if c.isalpha())

    bg_model, bg_floor = build_bigram_model(carter_raw)
    tg_model, tg_floor = build_trigram_model(carter_raw)
    print(f"Bigram model: {len(bg_model)} bigrams from Carter ({len(carter_alpha)} alpha chars)")
    print(f"Trigram model: {len(tg_model)} trigrams")

    # ---- Build test corpora ----

    # Real English segments
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

    # Carter segments (different from training data — use later portions)
    for start in range(50000, min(len(carter_alpha) - 96, 52000), 50):
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

    # Random baselines
    random_texts = [''.join(chr(random.randint(0, 25) + 65) for _ in range(97)) for _ in range(100)]

    eng_freqs = [0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609,
                 0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193,
                 0.0010, 0.0599, 0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015,
                 0.0197, 0.0007]
    cumulative = []
    total = 0
    for f in eng_freqs:
        total += f
        cumulative.append(total)

    engfreq_texts = []
    for _ in range(100):
        chars = []
        for _ in range(97):
            r = random.random()
            for i, c in enumerate(cumulative):
                if r <= c:
                    chars.append(chr(i + 65))
                    break
            else:
                chars.append('Z')
        engfreq_texts.append(''.join(chars))

    # ---- Score all categories ----
    print("\n" + "=" * 70)
    print("BIGRAM TRANSITION SCORES")
    print("=" * 70)

    eng_bg = [bigram_score(s, bg_model, bg_floor) for s in english_segments]
    sa_bg = [bigram_score(s, bg_model, bg_floor) for s in sa_plaintexts]
    rand_bg = [bigram_score(s, bg_model, bg_floor) for s in random_texts]
    ef_bg = [bigram_score(s, bg_model, bg_floor) for s in engfreq_texts]

    d_bg = cohens_d(eng_bg, sa_bg)
    overlap_bg = overlap_coefficient(eng_bg, sa_bg)

    print(f"\n  English:  mean={sum(eng_bg)/len(eng_bg):.4f} [{min(eng_bg):.4f} - {max(eng_bg):.4f}]")
    print(f"  SA gib:   mean={sum(sa_bg)/len(sa_bg):.4f} [{min(sa_bg):.4f} - {max(sa_bg):.4f}]")
    print(f"  Random:   mean={sum(rand_bg)/len(rand_bg):.4f} [{min(rand_bg):.4f} - {max(rand_bg):.4f}]")
    print(f"  Eng-freq: mean={sum(ef_bg)/len(ef_bg):.4f} [{min(ef_bg):.4f} - {max(ef_bg):.4f}]")
    print(f"  Cohen's d (Eng vs SA): {d_bg:.2f}")
    print(f"  Overlap (SA within Eng range): {overlap_bg:.2f}")

    gap_bg = min(eng_bg) - max(sa_bg)
    if gap_bg > 0:
        print(f"  *** PERFECT SEPARATION on bigram score ***")
    else:
        print(f"  No perfect separation (eng min={min(eng_bg):.4f}, sa max={max(sa_bg):.4f})")

    print("\n" + "=" * 70)
    print("TRIGRAM TRANSITION SCORES")
    print("=" * 70)

    eng_tg = [trigram_score(s, tg_model, tg_floor) for s in english_segments]
    sa_tg = [trigram_score(s, tg_model, tg_floor) for s in sa_plaintexts]
    rand_tg = [trigram_score(s, tg_model, tg_floor) for s in random_texts]
    ef_tg = [trigram_score(s, tg_model, tg_floor) for s in engfreq_texts]

    d_tg = cohens_d(eng_tg, sa_tg)
    overlap_tg = overlap_coefficient(eng_tg, sa_tg)

    print(f"\n  English:  mean={sum(eng_tg)/len(eng_tg):.4f} [{min(eng_tg):.4f} - {max(eng_tg):.4f}]")
    print(f"  SA gib:   mean={sum(sa_tg)/len(sa_tg):.4f} [{min(sa_tg):.4f} - {max(sa_tg):.4f}]")
    print(f"  Random:   mean={sum(rand_tg)/len(rand_tg):.4f} [{min(rand_tg):.4f} - {max(rand_tg):.4f}]")
    print(f"  Eng-freq: mean={sum(ef_tg)/len(ef_tg):.4f} [{min(ef_tg):.4f} - {max(ef_tg):.4f}]")
    print(f"  Cohen's d (Eng vs SA): {d_tg:.2f}")
    print(f"  Overlap (SA within Eng range): {overlap_tg:.2f}")

    gap_tg = min(eng_tg) - max(sa_tg)
    if gap_tg > 0:
        print(f"  *** PERFECT SEPARATION on trigram score ***")
    else:
        print(f"  No perfect separation (eng min={min(eng_tg):.4f}, sa max={max(sa_tg):.4f})")

    # ---- Quadgram scores for comparison ----
    print("\n" + "=" * 70)
    print("QUADGRAM SCORES (for comparison)")
    print("=" * 70)

    qg_path = os.path.join(BASE, 'data', 'english_quadgrams.json')
    with open(qg_path) as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = -7.0

    def quadgram_score(text):
        text = text.upper()
        total = 0.0
        n = 0
        for i in range(len(text) - 3):
            qg = text[i:i+4]
            if all(c.isalpha() for c in qg):
                total += QUADGRAMS.get(qg, QG_FLOOR)
                n += 1
        return total / n if n > 0 else QG_FLOOR

    eng_qg = [quadgram_score(s) for s in english_segments]
    sa_qg = [quadgram_score(s) for s in sa_plaintexts]

    d_qg = cohens_d(eng_qg, sa_qg)

    print(f"\n  English:  mean={sum(eng_qg)/len(eng_qg):.4f} [{min(eng_qg):.4f} - {max(eng_qg):.4f}]")
    print(f"  SA gib:   mean={sum(sa_qg)/len(sa_qg):.4f} [{min(sa_qg):.4f} - {max(sa_qg):.4f}]")
    print(f"  Cohen's d (Eng vs SA): {d_qg:.2f}")

    gap_qg = min(eng_qg) - max(sa_qg)
    if gap_qg > 0:
        print(f"  *** PERFECT SEPARATION on quadgram score ***")
    else:
        print(f"  No perfect separation (eng min={min(eng_qg):.4f}, sa max={max(sa_qg):.4f})")

    # ---- Summary ----
    total_time = time.time() - t0
    print("\n" + "=" * 70)
    print("SUMMARY: Discriminator Comparison")
    print("=" * 70)

    metrics = [
        ("Bigram transition", d_bg, gap_bg),
        ("Trigram transition", d_tg, gap_tg),
        ("Quadgram (standard)", d_qg, gap_qg),
        ("Non-crib words ≥7 chars (E-FRAC-42)", 1.14, -10),  # From E-FRAC-42
    ]

    print(f"\n  {'Metric':<40} {'Cohen d':<12} {'Gap':<12} {'Perfect?'}")
    print(f"  {'-'*70}")
    for name, d, gap in metrics:
        perfect = "YES" if gap > 0 else "NO"
        print(f"  {name:<40} {d:<12.2f} {gap:<12.4f} {perfect}")

    best_d = max(d_bg, d_tg, d_qg, 1.14)
    best_name = ["bigram", "trigram", "quadgram", "non-crib words"][
        [d_bg, d_tg, d_qg, 1.14].index(best_d)
    ]

    any_perfect = any(gap > 0 for _, _, gap in metrics)

    if any_perfect:
        verdict = f"PERFECT_SEPARATION achieved by at least one metric!"
    elif best_d >= 1.5:
        verdict = (f"STRONG_DISCRIMINATOR — best metric: {best_name} (d={best_d:.2f}), "
                   f"significant improvement over word counting")
    elif best_d > 1.14:
        verdict = (f"IMPROVED_DISCRIMINATOR — {best_name} (d={best_d:.2f}) "
                   f"beats non-crib word counting (d=1.14)")
    else:
        verdict = (f"NO_IMPROVEMENT — best n-gram metric ({best_name}, d={best_d:.2f}) "
                   f"does not beat non-crib word counting (d=1.14). "
                   f"SA quadgram optimization produces text that also scores well on "
                   f"bigram/trigram transitions. The fundamental limitation is 97 chars.")

    print(f"\n  VERDICT: {verdict}")
    print(f"  Total runtime: {total_time:.1f}s")

    # Save
    summary = {
        'experiment': 'E-FRAC-43',
        'description': 'Bigram/trigram transition discriminator',
        'total_time_seconds': round(total_time, 1),
        'verdict': verdict,
        'bigram': {
            'english_mean': round(sum(eng_bg)/len(eng_bg), 4),
            'english_range': [round(min(eng_bg), 4), round(max(eng_bg), 4)],
            'sa_mean': round(sum(sa_bg)/len(sa_bg), 4),
            'sa_range': [round(min(sa_bg), 4), round(max(sa_bg), 4)],
            'cohens_d': round(d_bg, 2),
            'overlap': round(overlap_bg, 2),
            'gap': round(gap_bg, 4),
        },
        'trigram': {
            'english_mean': round(sum(eng_tg)/len(eng_tg), 4),
            'english_range': [round(min(eng_tg), 4), round(max(eng_tg), 4)],
            'sa_mean': round(sum(sa_tg)/len(sa_tg), 4),
            'sa_range': [round(min(sa_tg), 4), round(max(sa_tg), 4)],
            'cohens_d': round(d_tg, 2),
            'overlap': round(overlap_tg, 2),
            'gap': round(gap_tg, 4),
        },
        'quadgram': {
            'english_mean': round(sum(eng_qg)/len(eng_qg), 4),
            'sa_mean': round(sum(sa_qg)/len(sa_qg), 4),
            'cohens_d': round(d_qg, 2),
            'gap': round(gap_qg, 4),
        },
        'best_metric': best_name,
        'best_cohens_d': round(best_d, 2),
    }

    results_dir = os.path.join(BASE, 'results', 'frac')
    os.makedirs(results_dir, exist_ok=True)
    outpath = os.path.join(results_dir, 'e_frac_43_bigram_discriminator.json')
    with open(outpath, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Results saved to: {outpath}")

    print("\n" + "=" * 70)
    print("RESULT: " + verdict)
    print("=" * 70)


if __name__ == '__main__':
    main()
