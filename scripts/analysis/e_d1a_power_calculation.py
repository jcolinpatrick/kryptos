#!/usr/bin/env python3 -u
"""
Cipher:   n/a (scoring research, not a decryption attempt)
Family:   analysis
Status:   active
Keyspace: n/a — statistical power calculation
Last run: 2026-04-09
Best score: n/a

============================================================================
D1a POWER CALCULATION
============================================================================

Pre-implementation power analysis for experiment D1a (junction-coherence
scorer) as specified in docs/scoring_research_direction_2026_04_09.md §5
and wounded by red-team-disprover in §10.

The red-team WOUND identified the variance budget as an order-of-magnitude
concern. This script computes the actual numbers so the decision to build
D1a is empirical, not hand-waved:

    1. Fit a 6-gram model to a representative English corpus.
    2. Estimate sigma_6gram (std dev of per-character 6-gram log-prob) on
       a held-out portion of the same corpus.
    3. Compute the minimum detectable effect (MDE) for a 3-beta Gumbel
       separation under:
         - N = 4  (one 6-gram per junction window, 4 junctions)
         - N = 12 (three overlapping 6-grams per window, 4 junctions)
    4. Compare the MDE against the theoretical signal bound
       KL(Markov-5 || Markov-3) <= 0.3 nats/char (per red-team analysis).
    5. Output a verdict: BUILD (MDE < signal) or KILL (MDE >= signal).

If KILL: do not implement D1a. Skip to D1b or abandon bin D1 until a
scorer with better noise characteristics is proposed.

Corpora used:
    reference/carter_vol1.txt                     (~437 KB)
    reference/running_key_texts/kahn_codebreakers_1967.txt  (~3.9 MB)

Total ~4.3 MB, well below the ideal ~10 MB but sufficient for an
order-of-magnitude sigma estimate.  The final D1a implementation (if
BUILD) would need a larger corpus per red-team item #5.

This script is deliberately standalone and does not depend on any of the
kernel's cipher logic.  It is pure statistics.
"""
from __future__ import annotations

import math
import os
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

# Standalone bootstrap
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CORPORA = [
    Path(_ROOT) / "reference" / "carter_vol1.txt",
    Path(_ROOT) / "reference" / "running_key_texts" / "kahn_codebreakers_1967.txt",
]

NGRAM_ORDER = 6

# Test sample: sliding-window evaluation positions per sample.
# For the actual junction scoring we have ~4 windows, but for the
# sigma estimate we use a longer strip because sigma stabilizes with
# sample count.
STRIP_LEN = 97        # K4 length
N_STRIPS = 2000        # independent English strips for the sigma estimate
HELDOUT_FRAC = 0.10

# Gumbel 3-beta requirement: tau = mu + k*beta where k ~= 3 for alpha ~= 0.01
K_SIGMA = 3.0

# The red-team's theoretical upper bound on the D1a signal.
# This comes from KL(Markov-5 || Markov-3) restricted to crib-adjacent
# positions on general English, which they estimated at <= 0.3 nats/char.
SIGNAL_UPPER_BOUND = 0.3

SEED = 0xD1A


def load_and_normalize() -> str:
    """Concatenate corpora, strip to uppercase A-Z, return one long string."""
    text_parts: List[str] = []
    for path in CORPORA:
        if not path.is_file():
            print(f"WARN: corpus missing: {path}", file=sys.stderr)
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        text_parts.append(raw)
    combined = "".join(text_parts).upper()
    normalized = re.sub(r"[^A-Z]", "", combined)
    return normalized


def split_train_test(text: str, frac: float, seed: int) -> Tuple[str, str]:
    """Split into train/test.  We take the test as a contiguous 10% slice
    from a randomly-chosen offset so the held-out distribution is a
    genuine sample from the corpus, not a shuffled artifact."""
    rng = random.Random(seed)
    n = len(text)
    test_len = int(n * frac)
    start = rng.randint(0, n - test_len - 1)
    test = text[start:start + test_len]
    train = text[:start] + text[start + test_len:]
    return train, test


def build_ngram_log_prob(
    text: str, order: int, alpha: float = 0.1
) -> Dict[str, float]:
    """Build a Laplace-smoothed n-gram log-probability table.

    Returns {ngram -> natural log P(ngram_last | ngram_prefix)}.
    We use add-alpha smoothing over the 26-letter alphabet.

    Note: Laplace is the *wrong* smoothing for production but is the
    safest for a decision calculation because it over-estimates the
    probability of unseen n-grams, which maximizes the noise floor and
    is thus conservative toward BUILD.  If Laplace says KILL, the
    verdict survives any smoothing upgrade."""
    n_total = len(text)
    if n_total <= order:
        return {}

    # Conditional counts: prefix (order-1 chars) -> next char counts
    prefix_counts: Dict[str, Counter] = defaultdict(Counter)
    total_prefix: Dict[str, int] = defaultdict(int)
    for i in range(n_total - order + 1):
        gram = text[i:i + order]
        prefix = gram[:-1]
        last = gram[-1]
        prefix_counts[prefix][last] += 1
        total_prefix[prefix] += 1

    log_probs: Dict[str, float] = {}
    V = 26  # alphabet size
    for prefix, counts in prefix_counts.items():
        denom = total_prefix[prefix] + alpha * V
        for last in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            c = counts.get(last, 0)
            p = (c + alpha) / denom
            gram = prefix + last
            log_probs[gram] = math.log(p)
    # We also need a fallback for unseen prefixes (prefix not in training).
    # Use uniform log(1/V) = -log(26) for those, computed at query time.
    return log_probs


def score_window(
    text: str, log_probs: Dict[str, float], order: int
) -> float:
    """Mean per-character log-probability of `text` under the n-gram model.

    Positions 0..order-2 fall back to uniform because we have no
    conditioning.  Positions order-1..n-1 use the n-gram model.
    Returns nats/char."""
    n = len(text)
    if n < order:
        return -math.log(26)
    uniform = -math.log(26)
    total = uniform * (order - 1)  # first (order-1) chars uncondtional
    count = (order - 1)
    for i in range(n - order + 1):
        gram = text[i:i + order]
        lp = log_probs.get(gram, uniform)
        total += lp
        count += 1
    return total / count


def sample_english_strips(
    test_text: str, n_strips: int, strip_len: int, seed: int
) -> List[str]:
    """Cut n_strips random substrings of length strip_len from the
    held-out text.  These are independent real-English samples."""
    rng = random.Random(seed)
    strips: List[str] = []
    max_start = len(test_text) - strip_len
    if max_start <= 0:
        return [test_text]
    for _ in range(n_strips):
        start = rng.randint(0, max_start)
        strips.append(test_text[start:start + strip_len])
    return strips


def compute_sigma(scores: List[float]) -> Tuple[float, float]:
    """Return (mean, std dev) of a list of per-char log-probs."""
    n = len(scores)
    if n < 2:
        return (0.0, 0.0)
    m = sum(scores) / n
    var = sum((s - m) ** 2 for s in scores) / (n - 1)
    return (m, math.sqrt(var))


def mde_for_n_samples(
    sigma: float, n_samples: int, k_sigma: float
) -> float:
    """Minimum detectable effect size for a k-sigma Gumbel gap.

    The junction scorer averages log-probs over `n_samples` 6-grams.
    The mean under H0 (no signal) has std dev sigma / sqrt(n_samples).
    To separate H1 from H0 by k standard deviations of the H0 mean
    distribution, we need the H1-H0 mean gap to exceed
    k * sigma / sqrt(n_samples).

    This is a Gaussian approximation to the Gumbel tail for the
    decision-level SNR analysis; under a real Gumbel fit the constant
    differs slightly but the order of magnitude is the same."""
    return k_sigma * sigma / math.sqrt(n_samples)


def main() -> int:
    print("=" * 72)
    print("D1a POWER CALCULATION")
    print("=" * 72)
    print()

    # Load corpora
    print("Loading corpora ...")
    text = load_and_normalize()
    print(f"  combined normalized corpus: {len(text):,} chars")
    print()

    # Split
    train, test = split_train_test(text, HELDOUT_FRAC, SEED)
    print(f"  train: {len(train):,} chars")
    print(f"  test:  {len(test):,} chars")
    print()

    # Build n-gram model
    print(f"Building {NGRAM_ORDER}-gram model from train (Laplace alpha=0.1) ...")
    log_probs = build_ngram_log_prob(train, NGRAM_ORDER, alpha=0.1)
    print(f"  n-gram table: {len(log_probs):,} entries")
    print()

    # Score held-out strips
    print(f"Scoring {N_STRIPS} random English strips of length {STRIP_LEN} ...")
    strips = sample_english_strips(test, N_STRIPS, STRIP_LEN, SEED + 1)
    scores = [score_window(s, log_probs, NGRAM_ORDER) for s in strips]
    mean_english, sigma_english = compute_sigma(scores)
    print(f"  mean per-char log-prob (English):  {mean_english:+.4f} nats/char")
    print(f"  sigma (per-char, strip-length-{STRIP_LEN}): {sigma_english:.4f} nats/char")
    print()

    # The sigma above is for a ~97-char strip average.  For junction
    # scoring we care about the sigma of a much shorter average (~4 to
    # ~12 samples).  Under the central limit theorem:
    #     sigma(avg of N samples) = sigma_single / sqrt(N)
    # and conversely:
    #     sigma_single = sigma(avg of N samples) * sqrt(N)
    # For a 97-length strip the effective number of 6-grams is (97-6+1)=92
    # So sigma_single = sigma_english * sqrt(92)
    n_6grams_per_strip = STRIP_LEN - NGRAM_ORDER + 1
    sigma_single = sigma_english * math.sqrt(n_6grams_per_strip)
    print(f"  back-solved sigma_single (one 6-gram): {sigma_single:.4f} nats/char")
    print()

    # MDE calculations
    print("Minimum detectable effect (MDE) for 3-sigma Gumbel separation:")
    print(f"  (signal upper bound per red-team: {SIGNAL_UPPER_BOUND} nats/char)")
    print()
    verdicts = []
    for n_samples in (4, 12):
        mde = mde_for_n_samples(sigma_single, n_samples, K_SIGMA)
        status = "BUILD" if mde < SIGNAL_UPPER_BOUND else "KILL"
        margin = mde / SIGNAL_UPPER_BOUND
        verdicts.append((n_samples, mde, status))
        print(
            f"  N={n_samples:>2}: MDE = {mde:.3f} nats/char "
            f"(signal bound / MDE = {1/margin:.3f}x) -> {status}"
        )
    print()

    # Final verdict
    both_kill = all(v[2] == "KILL" for v in verdicts)
    both_build = all(v[2] == "BUILD" for v in verdicts)
    print("=" * 72)
    if both_kill:
        print("VERDICT: KILL D1a")
        print("-" * 72)
        print("Under both window-counting conventions (N=4 center and N=12")
        print("overlapping), the minimum detectable effect exceeds the theoretical")
        print("signal upper bound. The scorer cannot achieve a 3-sigma separation")
        print("between real English and conditionally-sampled Markov-3 surrogates")
        print("at any sample-count choice the memo allows. D1a is statistically")
        print("dead on arrival.")
        print()
        print("Recommended next step: do NOT implement D1a. Move to D1b")
        print("(composite junction + word-boundary density) and run the same")
        print("power calculation against its noise floor before implementing.")
    elif both_build:
        print("VERDICT: BUILD D1a (survives under both N choices)")
    else:
        print("VERDICT: MIXED (survives at N=12 but dies at N=4)")
        print("-" * 72)
        print("Pre-register N=12 (overlapping 6-grams per window) as the")
        print("window-counting choice before implementing. Verify once more")
        print("with a larger training corpus (>=10M chars) per red-team item #5.")
    print("=" * 72)
    print()

    # Caveats
    print("CAVEATS:")
    print(f"  - Corpus is only {len(text):,} chars (red-team wants >=10M).")
    print("  - Laplace alpha=0.1 smoothing is conservative (over-smooths)")
    print("    which INFLATES sigma and thus MDE. A Kneser-Ney LM with more")
    print("    training data would reduce sigma somewhat, but not by an")
    print("    order of magnitude.")
    print("  - The 0.3 nats/char signal bound is the red-team's upper estimate")
    print("    of KL(Markov-5 || Markov-3) at crib-adjacent positions. The")
    print("    ACTUAL signal is likely smaller.")
    print("  - A KILL verdict under these favorable-to-BUILD assumptions is")
    print("    strongly robust. A BUILD verdict would require independent")
    print("    confirmation with better data before committing to code.")
    print()

    return 0 if both_kill or both_build else 1


if __name__ == "__main__":
    sys.exit(main())
