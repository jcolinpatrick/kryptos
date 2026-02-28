"""
Configuration for KryptosBot.

Contains K4 ciphertext, known plaintext cribs, hypothesis categories,
and runtime tuning parameters. Edit DEFAULT_CONFIG or pass overrides
to the orchestrator at launch time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# K4 Ciphertext & Known Plaintext
# ---------------------------------------------------------------------------

K4_CIPHERTEXT = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFB"
    "NYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
K4_LENGTH = len(K4_CIPHERTEXT)  # 97

# Sansom / Scheidt confirmed cribs (0-indexed positions)
KNOWN_CRIBS: dict[str, tuple[int, int]] = {
    "BERLIN": (63, 69),   # positions 64-69 in 1-indexed
    "CLOCK": (69, 74),    # positions 70-74 in 1-indexed
}

# K1-K3 solution methods (for cross-referencing / inspiration)
PRIOR_METHODS = {
    "K1": "Vigenère (keyword PALIMPSEST)",
    "K2": "Vigenère (keyword ABSCISSA)",
    "K3": "Transposition + Vigenère (keyword KRYPTOS)",
}


# ---------------------------------------------------------------------------
# Hypothesis Status Lifecycle
# ---------------------------------------------------------------------------

class HypothesisStatus(str, Enum):
    """Tracks where a hypothesis sits in the investigation pipeline."""
    QUEUED = "queued"
    RUNNING = "running"
    PROMISING = "promising"      # partial plaintext or statistical signal
    DISPROVED = "disproved"      # conclusively eliminated
    INCONCLUSIVE = "inconclusive"  # no signal but not fully eliminated
    SOLVED = "solved"            # full plaintext recovered


# ---------------------------------------------------------------------------
# Attack Strategy Taxonomy
# ---------------------------------------------------------------------------

class StrategyCategory(str, Enum):
    """Top-level cipher family or analytical approach."""
    TRANSPOSITION = auto()
    SUBSTITUTION = auto()
    POLYALPHABETIC = auto()
    HYBRID = auto()
    STATISTICAL = auto()
    KNOWN_PLAINTEXT = auto()
    LATERAL = auto()          # non-standard / creative approaches
    DISPROOF = auto()         # systematic elimination runs


# ---------------------------------------------------------------------------
# Strategy Definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Strategy:
    """A single cryptanalytic approach to attempt against K4."""
    name: str
    category: StrategyCategory
    description: str
    prompt_template: str          # Agent SDK prompt — may contain {ciphertext}, {cribs}
    priority: int = 5             # 1 = highest priority
    estimated_minutes: int = 30   # rough budget per worker
    disproof_criteria: str = ""   # what constitutes conclusive elimination
    tags: tuple[str, ...] = ()

    def render_prompt(self, **kwargs: Any) -> str:
        """Interpolate runtime values into the prompt template."""
        defaults = {
            "ciphertext": K4_CIPHERTEXT,
            "length": K4_LENGTH,
            "cribs": KNOWN_CRIBS,
            "prior_methods": PRIOR_METHODS,
        }
        defaults.update(kwargs)
        return self.prompt_template.format(**defaults)


# ---------------------------------------------------------------------------
# Built-in Strategy Library
# ---------------------------------------------------------------------------

BUILTIN_STRATEGIES: list[Strategy] = [
    # ---- TRANSPOSITION family ----
    Strategy(
        name="columnar_transposition_brute",
        category=StrategyCategory.TRANSPOSITION,
        description="Exhaustive columnar transposition with key widths 2-20, scoring against English bigram/trigram frequency and crib placement.",
        prompt_template=(
            "You are a cryptanalyst. The Kryptos K4 ciphertext is:\n"
            "{ciphertext}\n\n"
            "Known plaintext: BERLIN at positions 64-69, CLOCK at positions 70-74 (1-indexed).\n\n"
            "Task: Write and execute a Python script that performs columnar transposition "
            "decryption for ALL key widths from 2 through 20. For each width, try every "
            "permutation of columns. Score each candidate against English quadgram statistics "
            "and check whether BERLINCLOCK appears at the correct positions. "
            "Report the top 20 candidates by score. If any candidate places the known "
            "plaintext correctly, flag it immediately.\n\n"
            "Use itertools.permutations with early-exit pruning: if partial columns "
            "cannot produce 'B' at position 64, skip that permutation."
        ),
        priority=2,
        estimated_minutes=60,
        disproof_criteria="All permutations for a given key width exhausted with no crib match.",
        tags=("transposition", "brute-force", "crib-drag"),
    ),

    Strategy(
        name="route_transposition",
        category=StrategyCategory.TRANSPOSITION,
        description="Route cipher variants: spiral, diagonal, boustrophedon reads on rectangular grids.",
        prompt_template=(
            "You are a cryptanalyst working on Kryptos K4.\n"
            "Ciphertext ({length} chars): {ciphertext}\n"
            "Known plaintext: BERLIN at positions 64-69, CLOCK at 70-74.\n\n"
            "Task: Write and execute Python code that arranges the ciphertext into every "
            "rectangular grid where rows*cols >= {length} (pad with X if needed) for "
            "dimensions up to 20x20. For each grid, read off plaintext using these routes: "
            "row-major, column-major, spiral-CW, spiral-CCW, diagonal, boustrophedon. "
            "Score each against English quadgram frequencies and crib placement. "
            "Report the top 10 results per route type."
        ),
        priority=3,
        estimated_minutes=45,
        disproof_criteria="No grid dimension + route combination produces crib alignment.",
        tags=("transposition", "route-cipher", "grid"),
    ),

    # ---- POLYALPHABETIC family ----
    Strategy(
        name="vigenere_kasiski_ic",
        category=StrategyCategory.POLYALPHABETIC,
        description="Vigenère attack using Kasiski examination + Index of Coincidence for key length, then frequency analysis per column.",
        prompt_template=(
            "You are a cryptanalyst. Kryptos K4 ciphertext:\n{ciphertext}\n\n"
            "K1 used keyword PALIMPSEST, K2 used ABSCISSA, K3 used KRYPTOS.\n"
            "Known plaintext: BERLIN at 64-69, CLOCK at 70-74.\n\n"
            "Task: Write Python code to perform full Kasiski examination on K4. "
            "Compute the Index of Coincidence for key lengths 1-30. For each "
            "candidate key length, perform frequency analysis on each column and "
            "attempt key recovery. Also try the known K1-K3 keywords and common "
            "Kryptos-related words (KRYPTOS, PALIMPSEST, ABSCISSA, SANBORN, SCHEIDT, "
            "SHADOW, LUCID, MEMORY, DYAHR, VIRTUALLY, INVISIBLE). "
            "Verify each candidate against the known crib positions. "
            "Output IC values, top key candidates, and decrypted text for each."
        ),
        priority=1,
        estimated_minutes=30,
        disproof_criteria="IC for all key lengths is flat (near 0.038), indicating non-polyalphabetic.",
        tags=("polyalphabetic", "vigenere", "kasiski", "ic"),
    ),

    Strategy(
        name="autokey_vigenere",
        category=StrategyCategory.POLYALPHABETIC,
        description="Autokey Vigenère: key is seed + plaintext feedback. Try seed lengths 1-15 with known crib bootstrapping.",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n"
            "Known: BERLIN at pos 64-69, CLOCK at 70-74.\n\n"
            "Task: Implement autokey Vigenère decryption in Python. In autokey mode, "
            "the key = seed keyword concatenated with the recovered plaintext itself. "
            "Try seed lengths 1 through 15. For each seed length, use the known "
            "plaintext at positions 64-74 to back-derive seed characters and extend "
            "decryption bidirectionally. Score results with English quadgram statistics. "
            "Report any candidate where the crib appears at the correct positions."
        ),
        priority=2,
        estimated_minutes=40,
        disproof_criteria="No seed length produces coherent English extending from known plaintext region.",
        tags=("polyalphabetic", "autokey", "crib-bootstrap"),
    ),

    # ---- SUBSTITUTION family ----
    Strategy(
        name="simple_substitution_sa",
        category=StrategyCategory.SUBSTITUTION,
        description="Simple monoalphabetic substitution solved via simulated annealing with quadgram scoring.",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n"
            "Known: BERLIN at 64-69, CLOCK at 70-74.\n\n"
            "Task: Write a simulated annealing solver for simple substitution cipher. "
            "Use English quadgram log-probabilities as the fitness function. "
            "Pin the known plaintext mappings from the crib (e.g., position 64 ciphertext "
            "letter maps to 'B', etc.) as constraints. Run 50,000 iterations with "
            "temperature schedule starting at 1.0 and cooling factor 0.9999. "
            "Repeat 10 times with different random seeds. Report the best decryption "
            "and its score. Also compute the IoC of the ciphertext to assess whether "
            "monoalphabetic substitution is even plausible (English IoC ≈ 0.0667)."
        ),
        priority=3,
        estimated_minutes=30,
        disproof_criteria="IoC of ciphertext is significantly below English monographic IoC.",
        tags=("substitution", "monoalphabetic", "simulated-annealing"),
    ),

    Strategy(
        name="homophonic_substitution",
        category=StrategyCategory.SUBSTITUTION,
        description="Homophonic substitution analysis — frequency flattening check and hill-climbing solver.",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n\n"
            "Task: Analyze the letter frequency distribution of K4. Compare it to: "
            "(a) English plaintext, (b) typical Vigenère output, (c) typical homophonic "
            "substitution output. Compute chi-squared goodness-of-fit against each. "
            "If homophonic substitution is plausible, implement a hill-climbing solver "
            "that maps ciphertext letters to plaintext with multiple homophones per "
            "high-frequency letter. Use the BERLINCLOCK crib as anchor points. "
            "Report statistical analysis and top decryption candidates."
        ),
        priority=4,
        estimated_minutes=45,
        disproof_criteria="Frequency distribution is NOT flat (rejects homophonic hypothesis).",
        tags=("substitution", "homophonic", "frequency-analysis"),
    ),

    # ---- HYBRID family ----
    Strategy(
        name="transposition_then_vigenere",
        category=StrategyCategory.HYBRID,
        description="K3-style hybrid: transposition followed by Vigenère, testing K3 parameters and variations.",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n"
            "K3 was solved with transposition + Vigenère (keyword KRYPTOS).\n"
            "Known K4 plaintext: BERLIN at 64-69, CLOCK at 70-74.\n\n"
            "Task: Implement a hybrid decrypt: first reverse a columnar transposition "
            "(try key widths 2-15), then apply Vigenère decryption with candidate "
            "keywords from the Kryptos context (KRYPTOS, PALIMPSEST, ABSCISSA, SANBORN, "
            "SCHEIDT, plus all K4 clue words). For each transposition width, test all "
            "column orderings using the crib constraint: after both operations, BERLIN "
            "must appear at positions 64-69. Use this to prune the search space "
            "dramatically. Report any candidates with readable English."
        ),
        priority=1,
        estimated_minutes=90,
        disproof_criteria="No combination of transposition width + Vigenère keyword produces crib alignment.",
        tags=("hybrid", "k3-style", "transposition", "vigenere"),
    ),

    Strategy(
        name="vigenere_then_transposition",
        category=StrategyCategory.HYBRID,
        description="Reverse hybrid: Vigenère first, then transposition. Opposite order from K3.",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n\n"
            "Task: Implement a hybrid decrypt where Vigenère is applied FIRST, then "
            "columnar transposition. Try Vigenère keywords from Kryptos context and "
            "key lengths 4-12. For each Vigenère result, attempt columnar transposition "
            "reversal with widths 2-15. Score against English quadgrams and verify "
            "crib placement. This is the reverse order of K3's method — we need to "
            "either confirm or eliminate this possibility."
        ),
        priority=2,
        estimated_minutes=90,
        disproof_criteria="Exhaustive keyword × width combinations produce no crib match.",
        tags=("hybrid", "reverse-k3", "vigenere", "transposition"),
    ),

    # ---- KNOWN PLAINTEXT attacks ----
    Strategy(
        name="crib_drag_extended",
        category=StrategyCategory.KNOWN_PLAINTEXT,
        description="Extend known plaintext bidirectionally using crib-dragging and frequency constraints.",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n"
            "Known: BERLINCLOCK at positions 64-74 (1-indexed).\n\n"
            "Task: Using the known plaintext at positions 64-74, attempt to extend "
            "the solution in both directions. For each assumed cipher type "
            "(Vigenère, Beaufort, autokey, running key), compute what the key stream "
            "must be at positions 64-74. Then check if that key stream pattern extends "
            "coherently (repeating, autokey feedback, or dictionary-word running key) "
            "to produce English at adjacent positions. Try extending 5 characters in "
            "each direction. Report any key stream that produces readable English "
            "when extended. Also try XOR-based ciphers with the same approach."
        ),
        priority=1,
        estimated_minutes=40,
        disproof_criteria="No cipher model produces a key stream that extends coherently.",
        tags=("known-plaintext", "crib-drag", "key-recovery"),
    ),

    # ---- STATISTICAL analysis ----
    Strategy(
        name="statistical_profile",
        category=StrategyCategory.STATISTICAL,
        description="Comprehensive statistical profiling: IoC, entropy, digraph distribution, autocorrelation, chi-squared tests.",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n\n"
            "Task: Perform a comprehensive statistical analysis of K4:\n"
            "1. Letter frequency distribution + chi-squared vs English\n"
            "2. Index of Coincidence (monographic and digraphic)\n"
            "3. Shannon entropy\n"
            "4. Autocorrelation for periods 1-50\n"
            "5. Digraph and trigraph frequency analysis\n"
            "6. Kappa test for periodic polyalphabetic ciphers\n"
            "7. Bulge test for transposition detection\n"
            "8. Contact chart analysis\n"
            "9. Compare all metrics against reference distributions for: "
            "   random text, English, Vigenère output, transposition output, "
            "   simple substitution output\n\n"
            "Present results as a structured report with clear conclusions about "
            "which cipher families are consistent with the observed statistics "
            "and which can be RULED OUT."
        ),
        priority=1,
        estimated_minutes=30,
        disproof_criteria="N/A — this is a profiling task that informs other strategies.",
        tags=("statistical", "profiling", "ioc", "entropy"),
    ),

    # ---- DISPROOF strategies ----
    Strategy(
        name="disprove_caesar_rot",
        category=StrategyCategory.DISPROOF,
        description="Conclusively eliminate all 25 Caesar/ROT shifts.",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n\n"
            "Task: Decrypt K4 with all 25 Caesar shifts (ROT-1 through ROT-25). "
            "For each, check: (a) does BERLINCLOCK appear at positions 64-74? "
            "(b) does the output resemble English (quadgram score)? "
            "Present all 25 results with scores. This is a DISPROOF task — "
            "we expect to conclusively eliminate simple Caesar cipher."
        ),
        priority=1,
        estimated_minutes=5,
        disproof_criteria="None of the 25 shifts produce crib match or readable English.",
        tags=("disproof", "caesar", "exhaustive"),
    ),

    Strategy(
        name="disprove_affine",
        category=StrategyCategory.DISPROOF,
        description="Exhaustively eliminate all 312 affine cipher keys (12 × 26).",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n\n"
            "Task: Test all valid affine cipher keys (a*x + b mod 26 where "
            "gcd(a, 26) = 1). There are 12 valid 'a' values × 26 'b' values = 312 keys. "
            "Decrypt with each, check crib placement, score with English quadgrams. "
            "Present results sorted by score. This is a DISPROOF task."
        ),
        priority=1,
        estimated_minutes=5,
        disproof_criteria="All 312 keys exhausted with no crib match.",
        tags=("disproof", "affine", "exhaustive"),
    ),

    Strategy(
        name="disprove_playfair",
        category=StrategyCategory.DISPROOF,
        description="Statistical test for Playfair cipher characteristics, plus keyword-based attempts.",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n\n"
            "Task: Test whether K4 could be a Playfair cipher:\n"
            "1. Check if the ciphertext length is even (Playfair produces pairs)\n"
            "2. Check for repeated digraphs — Playfair has characteristic patterns\n"
            "3. Check if any letter appears doubled within a digraph (Playfair forbids this)\n"
            "4. Attempt Playfair decryption with keywords from Kryptos context\n"
            "5. Use hill-climbing on the 25-letter Playfair square if statistical "
            "   tests don't rule it out\n"
            "Present statistical evidence for or against Playfair. This is primarily "
            "a DISPROOF task."
        ),
        priority=2,
        estimated_minutes=30,
        disproof_criteria="Ciphertext properties are inconsistent with Playfair output characteristics.",
        tags=("disproof", "playfair", "digraphic"),
    ),

    # ---- LATERAL approaches ----
    Strategy(
        name="masonic_cipher_check",
        category=StrategyCategory.LATERAL,
        description="Test Masonic/Pigpen cipher mapping given Sanborn's interest in secret societies.",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n\n"
            "Jim Sanborn, the sculptor of Kryptos, has acknowledged interest in "
            "codes used by secret societies. Task: Consider whether K4 could involve "
            "a Masonic cipher (Pigpen) or similar geometric substitution, possibly "
            "as an intermediate step. Map each letter to its Pigpen equivalent, "
            "look for patterns. Also consider that the LETTER positions on the sculpture "
            "might encode geometric shapes. This is exploratory — document your "
            "analysis thoroughly even if results are negative."
        ),
        priority=5,
        estimated_minutes=30,
        disproof_criteria="No Masonic mapping produces meaningful patterns.",
        tags=("lateral", "masonic", "pigpen", "exploratory"),
    ),

    Strategy(
        name="keyed_alphabet_matrix",
        category=StrategyCategory.LATERAL,
        description="Matrix-based cipher using Kryptos tableau (the modified Vigenère table on the sculpture).",
        prompt_template=(
            "Kryptos K4 ciphertext: {ciphertext}\n\n"
            "The Kryptos sculpture contains a modified Vigenère tableau where the "
            "alphabet is keyed with KRYPTOS (KRYPTOSABCDEFGHIJLMNQUVWXZ). "
            "Task: Use this EXACT keyed alphabet as the basis for:\n"
            "1. Standard Vigenère with the keyed alphabet (try multiple keywords)\n"
            "2. Beaufort cipher with the keyed alphabet\n"
            "3. Variant Beaufort with the keyed alphabet\n"
            "4. Two-square / Four-square with the keyed alphabet\n"
            "Verify each against BERLINCLOCK crib. The keyed tableau is a physical "
            "part of the sculpture and almost certainly relevant to K4."
        ),
        priority=1,
        estimated_minutes=60,
        disproof_criteria="No keyed-alphabet variant produces crib alignment.",
        tags=("lateral", "keyed-alphabet", "tableau", "sculpture"),
    ),
]


# ---------------------------------------------------------------------------
# Runtime Configuration
# ---------------------------------------------------------------------------

@dataclass
class KryptosBotConfig:
    """Runtime settings for the orchestrator."""

    # Parallelism
    max_workers: int = 28
    worker_timeout_minutes: int = 120  # kill stuck agents after this

    # Agent SDK settings
    allowed_tools: list[str] = field(
        default_factory=lambda: ["Read", "Write", "Edit", "Bash", "Glob", "Grep"]
    )
    permission_mode: str = "bypassPermissions"  # headless operation

    # Paths
    project_root: Path = Path(".")        # your existing crypto framework
    results_db_path: Path = Path("kryptosbot_results.db")
    log_dir: Path = Path("logs")
    quadgram_file: Path = Path("english_quadgrams.txt")  # for scoring

    # Session management
    resume_on_restart: bool = True        # pick up where we left off
    session_store_path: Path = Path("sessions.json")

    # Scheduling
    strategy_names: list[str] | None = None   # None = run all
    priority_cutoff: int = 10                  # skip strategies above this
    repeat_disproved: bool = False             # re-run already disproved?

    # System prompt prefix injected into every agent
    system_prompt_prefix: str = (
        "You are KryptosBot, an expert cryptanalyst working to decipher "
        "Kryptos K4. You write and execute Python code to perform "
        "cryptanalytic attacks. Always show your work, explain your "
        "reasoning, and be explicit about what has been PROVED or DISPROVED. "
        "When a hypothesis is eliminated, state the evidence clearly."
    )


DEFAULT_CONFIG = KryptosBotConfig()
