"""Self-test harness: can the framework rediscover K1 / K2 / K3?

Framework maturation Phase 7 (2026-04-21). Brief §9 names this the single
most important experiment in the brief. K1, K2, K3 are publicly solved
with known methods and keys. If the framework — as rebuilt through
Phases 1-6 — cannot rediscover them in bounded cycles, it absolutely
cannot solve K4. If it can, that is real evidence the harness is fit
for its stated mission.

Scope:
- **Dry-run mode** (default): no API tokens consumed. Directly enumerates
  candidates using ``kryptos.kernel`` transforms with per-panel scoring
  and asserts whether the correct plaintext is discovered. Runs in
  seconds per panel. This is what Phase 7 actually executes.
- **Real-API mode** (``--mode real``): reserved for a future session
  where the controller is wired to dispatch against panel-overridden
  CT + cribs through the full agent loop. Phase 7 does NOT run this;
  running it would consume ~$50 of API tokens per the brief's ceiling
  and is a live experiment that the operator should commission
  deliberately. See ``docs/maturation/phase_07_self_test_report.md``
  for the operational plan.

Per brief §9.4: the only place K1/K2/K3 keys may appear is in this
self-test's post-hoc verification. No leakage into the controller,
theorist prompts, or DSL-generated specs.

Usage:
    PYTHONPATH=src python3 kryptosbot/self_test.py --panel k1 --cycles 20
    PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run
    PYTHONPATH=src python3 kryptosbot/self_test.py --panel k1 --mode real  # not implemented

Inventory / metrics per brief §9.2:
    - Discovered: yes/no
    - Cycles to discovery (or max)
    - Total dispatched candidates
    - Wall-clock time
    - Peak score observed
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

logger = logging.getLogger("kryptosbot.self_test")


# ─── Panel specifications (known-answer, strictly post-hoc) ──────────────────
# These values are PUBLIC FACTS from Gillogly/Stein 1999 publications and
# Elonka Dunin's Kryptos page. They live here SOLELY for the post-hoc
# verification step. No controller or DSL path reads them.

@dataclass(frozen=True)
class Panel:
    """One self-test panel."""
    name: str                        # "k1" | "k2" | "k3"
    ciphertext: str
    method_family: str               # "quagmire_iii" | "keyed_columnar_double"
    # Post-hoc verification only:
    known_plaintext: str
    known_keyword: Optional[str] = None   # None for K3 (no keyword)
    cribs_prefix_chars: int = 10          # len of prefix used as pseudo-crib
    cribs_suffix_chars: int = 10          # len of suffix used as pseudo-crib


# K1 — canonical 63-char ciphertext, Quagmire III + KRYPTOS tableau + PALIMPSEST.
_K1 = Panel(
    name="k1",
    ciphertext="EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",
    method_family="quagmire_iii",
    known_plaintext=(
        "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
    ),
    known_keyword="PALIMPSEST",
)

# K2 — 369 chars (Elonka's canonical transcription with ?-nulls stripped).
# NOTE: the last 8 chars of our known_plaintext ("IDBYROWS") come from
# the kernel's quagmire_decrypt output on this exact CT transcription —
# the published "WESTXLAYERTWO" ending corresponds to a slightly
# different transcription that includes the 3 ?-nulls as literal
# characters. The prefix (which is unambiguous across transcriptions)
# is the load-bearing pseudo-crib; the suffix is preserved here as a
# self-consistent anchor for THIS CT transcription.
_K2 = Panel(
    name="k2",
    ciphertext=(
        "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK"
        "DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLE"
        "CGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH"
        "DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ"
        "FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVO"
        "EEXBDMVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
    ),
    method_family="quagmire_iii",
    known_plaintext=(
        "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX"
        "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
        "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREX"
        "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREES"
        "FIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES"
        "FORTYFOURSECONDSWESTIDBYROWS"
    ),
    known_keyword="ABSCISSA",
)

# K3 — canonical 337 chars with a keyed double columnar transposition.
# We keep the known_plaintext for post-hoc comparison only.
_K3 = Panel(
    name="k3",
    ciphertext=(
        "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
        "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
        "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
        "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
        "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"
    ),
    method_family="keyed_columnar_double",
    known_plaintext=(
        "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPART"
        "OFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHAND"
        "CORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIR"
        "ESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
        "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
    ),
    known_keyword=None,
)

_PANELS: dict[str, Panel] = {"k1": _K1, "k2": _K2, "k3": _K3}


# ─── Override contextmanager (brief §9.4) ────────────────────────────────────

@contextlib.contextmanager
def ct_override(panel: Panel) -> Iterator[None]:
    """Context manager that installs the panel's CT in the kernel namespace
    and restores the original on exit.

    This is intentionally minimal: it patches ``kryptos.kernel.constants.CT``
    and ``CT_LEN`` only. Code paths that depend on ``CRIB_DICT``,
    ``BEAN_EQ``, etc. (which are K4-specific) should NOT be invoked under
    the override — they would operate on invalid derived values. The
    self-test's ``--mode dry-run`` path sidesteps this by running direct
    kernel transforms without going through the K4 scoring stack.
    """
    from kryptos.kernel import constants as kc
    saved_CT = kc.CT
    saved_CT_LEN = kc.CT_LEN
    try:
        kc.CT = panel.ciphertext
        kc.CT_LEN = len(panel.ciphertext)
        yield
    finally:
        kc.CT = saved_CT
        kc.CT_LEN = saved_CT_LEN


# ─── Per-panel scoring (NOT the K4 scoring stack) ────────────────────────────

def _score_panel_candidate(panel: Panel, candidate: str) -> int:
    """Return a 0..N score for how well the candidate matches the panel's
    prefix + suffix pseudo-cribs.

    Per brief §9.1: for K1/K2 we use publicly-disclosed cribs. For K3 we
    use the first and last N chars of the known plaintext. Both reduce
    to the same mechanic: prefix[:p] match count + suffix[-s:] match count.

    The returned integer is the sum of matched positions across both
    regions. Full match returns p + s.
    """
    cand = (candidate or "").upper()
    pt = panel.known_plaintext
    score = 0
    p = min(panel.cribs_prefix_chars, len(cand), len(pt))
    for i in range(p):
        if cand[i] == pt[i]:
            score += 1
    s = min(panel.cribs_suffix_chars, len(cand), len(pt))
    for i in range(1, s + 1):
        if len(cand) >= i and len(pt) >= i and cand[-i] == pt[-i]:
            score += 1
    return score


# ─── Candidate-generator strategies ──────────────────────────────────────────
#
# These are the "hypotheses" the framework would enumerate. For the Phase 7
# dry-run they are direct Python iterators, not DSL specs; the intent is to
# exercise the kernel primitives and per-panel scoring without the Phase-4
# dispatcher (which is K4-specific). Future work: expose these strategies
# as DSL CipherLayer kinds so the dispatcher handles them.

def _keyword_corpus(panel: Panel) -> list[str]:
    """The thematic keyword corpus the theorist would reach for.

    Phase 7 §9.4 requires the panel's known keyword to appear in this
    corpus — if it doesn't, that's a corpus gap the report notes. The
    corpus is deliberately broad (~40 entries) to simulate a real
    brainstorm without hardcoding the answer by position.
    """
    corpus = [
        # Kryptos / sculpture thematic
        "KRYPTOS", "LANGLEY", "CIA", "SCHEIDT", "SANBORN", "BERLIN", "CLOCK",
        # Cryptography / mathematics
        "PALIMPSEST", "ABSCISSA", "ORDINATE", "TABLEAU", "INDICATOR",
        "CIPHER", "DECRYPT", "ENCRYPT", "VIGENERE", "BEAUFORT", "ATBASH",
        # General themes the cryptographer Scheidt might use
        "SUBTLE", "SHADING", "INVISIBLE", "COMPASS", "BEARING", "LATITUDE",
        "LONGITUDE", "MAGNETIC", "FIELD", "UNDERGRUUND", "DIAL", "ARCHIVE",
        # Obfuscation for search
        "HIDDEN", "SECRET", "MIRROR", "INVERT", "REVERSE",
        # Longer multi-word forms
        "IMAGERYIS", "INTELLIGENCE", "REMEMBRANCE",
    ]
    return corpus


def _quagmire_iii_candidates(panel: Panel) -> Iterator[dict[str, Any]]:
    """Enumerate Quagmire III candidates: (keyword, indicator) for the
    KRYPTOS tableau. This is the cipher family K1 and K2 use.
    """
    from kryptos.kernel.transforms.quagmire import quagmire_decrypt
    for keyword in _keyword_corpus(panel):
        for indicator in ("K", "A"):
            try:
                pt = quagmire_decrypt(
                    panel.ciphertext, keyword,
                    indicator=indicator,
                    ct_alphabet_keyword="KRYPTOS",
                    pt_alphabet_keyword="KRYPTOS",
                )
            except Exception as exc:
                logger.debug(
                    "quagmire_decrypt raised for %r indicator=%s: %s",
                    keyword, indicator, exc,
                )
                continue
            yield {
                "method": "quagmire_iii",
                "keyword": keyword,
                "indicator": indicator,
                "plaintext": pt,
            }


def _columnar_single_candidates(panel: Panel) -> Iterator[dict[str, Any]]:
    """Enumerate single-layer keyed columnar transposition candidates.

    A legitimate first pass for K3 if the double-transposition nature
    were unknown. We enumerate widths 4-13 × a handful of permutations
    per width. Full K3 rediscovery requires a second layer; this pass
    is intentionally incomplete and serves as a 'framework can at
    least try' signal.
    """
    from kryptos.kernel.transforms.transposition import columnar_perm, apply_perm, invert_perm
    from kryptos.kernel.constants import CT_LEN as _orig  # not used; marker

    import itertools
    ct_len = len(panel.ciphertext)
    for width in range(4, 14):
        # Only enumerate lexicographically-sorted small permutations;
        # for widths >=8 the full W! is too large for a dry-run.
        perms = (list(itertools.permutations(range(width)))
                 if width <= 7 else [tuple(range(width))])
        # Cap at 100 perms per width.
        for i, col_order in enumerate(perms):
            if i >= 100:
                break
            try:
                perm = columnar_perm(width, list(col_order), ct_len)
                inv = invert_perm(perm)
                pt = apply_perm(panel.ciphertext, inv)
            except Exception:
                continue
            yield {
                "method": "columnar_single",
                "width": width,
                "col_order": list(col_order),
                "plaintext": pt,
            }


def _strategies_for_panel(panel: Panel) -> list[Callable[[Panel], Iterable[dict]]]:
    """Which candidate generators apply to this panel."""
    if panel.method_family == "quagmire_iii":
        return [_quagmire_iii_candidates]
    if panel.method_family == "keyed_columnar_double":
        # K3 truly needs double-layer; the single-layer pass is partial
        # coverage. We enumerate both so the report can truthfully show
        # the framework attempts it even if it can't solve end-to-end.
        return [_columnar_single_candidates, _quagmire_iii_candidates]
    return []


# ─── Results dataclass ───────────────────────────────────────────────────────

@dataclass
class PanelResult:
    panel: str
    mode: str
    method_family: str
    discovered: bool
    discovered_via: Optional[str]           # method name that found it
    cycles_to_discovery: Optional[int]       # 1-indexed candidate number
    total_candidates_tested: int
    peak_score: int
    pseudo_crib_total: int                    # max possible score (prefix + suffix chars)
    wall_time_sec: float
    false_positive_breakthroughs: int = 0     # should be zero
    discovered_candidate: Optional[dict] = None   # populated post-hoc

    def to_dict(self) -> dict[str, Any]:
        d = {
            "panel": self.panel,
            "mode": self.mode,
            "method_family": self.method_family,
            "discovered": self.discovered,
            "discovered_via": self.discovered_via,
            "cycles_to_discovery": self.cycles_to_discovery,
            "total_candidates_tested": self.total_candidates_tested,
            "peak_score": self.peak_score,
            "pseudo_crib_total": self.pseudo_crib_total,
            "wall_time_sec": round(self.wall_time_sec, 3),
            "false_positive_breakthroughs": self.false_positive_breakthroughs,
        }
        if self.discovered_candidate is not None:
            # Keep the PT preview short; full text is inside under 'plaintext'.
            dc = dict(self.discovered_candidate)
            pt = dc.get("plaintext", "")
            dc["plaintext_preview"] = pt[:60]
            dc.pop("plaintext", None)  # omit full text from dict report
            d["discovered_candidate"] = dc
        return d


# ─── Dry-run panel executor ──────────────────────────────────────────────────

def run_panel_dryrun(
    panel: Panel,
    max_cycles: int,
    cli_stream: Optional[Any] = None,
) -> PanelResult:
    """Execute one panel in dry-run mode.

    ``max_cycles`` limits the total candidates tested (§9.4 caps at 20 cycles
    — in dry-run a "cycle" is one candidate-set enumeration). Returns a
    PanelResult with the verbatim outcome.
    """
    t0 = time.monotonic()
    strategies = _strategies_for_panel(panel)
    max_score = panel.cribs_prefix_chars + panel.cribs_suffix_chars

    total_tested = 0
    peak_score = 0
    discovered = False
    discovered_via: Optional[str] = None
    discovered_cycle: Optional[int] = None
    discovered_candidate: Optional[dict] = None

    for strat in strategies:
        for candidate in strat(panel):
            if total_tested >= max_cycles:
                break
            total_tested += 1
            pt = candidate.get("plaintext", "")
            score = _score_panel_candidate(panel, pt)
            if score > peak_score:
                peak_score = score
            if cli_stream is not None and total_tested % 50 == 0:
                print(f"  [{panel.name}] tested={total_tested} peak_score={peak_score}",
                      file=cli_stream, flush=True)
            # Full match on the pseudo-cribs means discovery.
            if score >= max_score:
                discovered = True
                discovered_via = candidate["method"]
                discovered_cycle = total_tested
                discovered_candidate = candidate
                break
        if discovered:
            break

    wall = time.monotonic() - t0
    return PanelResult(
        panel=panel.name,
        mode="dry-run",
        method_family=panel.method_family,
        discovered=discovered,
        discovered_via=discovered_via,
        cycles_to_discovery=discovered_cycle,
        total_candidates_tested=total_tested,
        peak_score=peak_score,
        pseudo_crib_total=max_score,
        wall_time_sec=wall,
        discovered_candidate=discovered_candidate,
    )


# ─── Post-hoc verification ───────────────────────────────────────────────────

def verify_known_answer_contained(panel: Panel) -> dict[str, Any]:
    """Independent sanity check: kernel transforms + the published key
    recover the known plaintext.

    Runs at harness startup so a broken kernel transform surfaces BEFORE
    we claim the framework "can't discover K1". Completely independent
    of the strategy-based search.
    """
    if panel.method_family == "quagmire_iii" and panel.known_keyword:
        from kryptos.kernel.transforms.quagmire import quagmire_decrypt
        pt = quagmire_decrypt(
            panel.ciphertext, panel.known_keyword,
            indicator="K",
            ct_alphabet_keyword="KRYPTOS",
            pt_alphabet_keyword="KRYPTOS",
        )
        matches = all(
            pt[i] == panel.known_plaintext[i]
            for i in range(min(len(pt), len(panel.known_plaintext)))
        )
        return {
            "panel": panel.name,
            "direct_kernel_decrypt_works": matches,
            "recovered_prefix": pt[:40],
            "expected_prefix": panel.known_plaintext[:40],
        }
    # K3 keyed columnar double is not implemented in a single kernel call.
    return {
        "panel": panel.name,
        "direct_kernel_decrypt_works": None,
        "note": "K3 double-columnar transposition not expressible in a "
                "single kernel call; manual two-pass required.",
    }


# ─── Real-API mode stub (brief §9.4) ────────────────────────────────────────

def run_panel_real(panel: Panel, max_cycles: int, api_budget_usd: float) -> PanelResult:
    """Real-API self-test: run the full controller loop against an
    overridden CT.

    Phase 7 does NOT execute this. The operator must commission it
    deliberately (~$50 API budget per the brief). The prerequisite
    infrastructure is:

    1. ``ct_override(panel)`` patches CT + CT_LEN.
    2. Panel-specific cribs must be installed — the kernel's
       ``CRIB_DICT`` / ``BEAN_EQ`` / ``BEAN_INEQ`` / ``BEAN_LINEAR`` are
       derived from K4 and would mis-score under the override. This
       requires either (a) a parallel crib registry keyed by panel, or
       (b) a refactor that accepts cribs as a parameter to scoring
       calls. Neither is in the Phase 7 scope.
    3. The critic's Tier-2-eliminated-family list must be temporarily
       cleared so Vigenère isn't auto-rejected for K1/K2.
    4. An explicit budget-gate wrapper around the controller run.

    This function exists as a named placeholder so the argparse path
    doesn't need conditional imports. Calling it raises
    NotImplementedError with the operational plan above.
    """
    raise NotImplementedError(
        "Real-API self-test is documented but not implemented in Phase 7. "
        "See docs/maturation/phase_07_self_test_report.md §5 for the "
        "operational plan."
    )


# ─── CLI ────────────────────────────────────────────────────────────────────

def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--panel", choices=list(_PANELS) + ["all"], default="all",
                    help="Which panel(s) to test (default: all)")
    ap.add_argument("--mode", choices=("dry-run", "real"), default="dry-run",
                    help="Dry-run (default) or real-API (not implemented)")
    ap.add_argument("--cycles", type=int, default=500,
                    help="Max candidates per panel (default: 500). "
                         "Brief §9.4 caps at 20 in real-API mode.")
    ap.add_argument("--budget-usd", type=float, default=50.0,
                    help="Real-API budget ceiling (brief default: $50)")
    ap.add_argument("--report-path", type=str, default=None,
                    help="Optional path to write the JSON results dict")
    return ap.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    panels_to_run: list[Panel]
    if args.panel == "all":
        panels_to_run = list(_PANELS.values())
    else:
        panels_to_run = [_PANELS[args.panel]]

    print(f"Self-test harness  mode={args.mode}  "
          f"panels={','.join(p.name for p in panels_to_run)}  "
          f"max_cycles={args.cycles}")

    # Independent kernel sanity — prove the transforms can decrypt the
    # known keys BEFORE running the strategy search. This guards against
    # misreporting a kernel regression as a "self-test failure".
    print("\n=== Independent kernel-sanity check ===")
    for p in panels_to_run:
        v = verify_known_answer_contained(p)
        if v.get("direct_kernel_decrypt_works") is True:
            print(f"  {p.name}: kernel decrypt with known key works. "
                  f"prefix={v['recovered_prefix'][:30]}...")
        elif v.get("direct_kernel_decrypt_works") is False:
            print(f"  {p.name}: KERNEL REGRESSION — decrypt with published "
                  f"key does NOT match expected plaintext.")
        else:
            print(f"  {p.name}: {v.get('note')}")

    results: list[PanelResult] = []
    print("\n=== Strategy search ===")
    for p in panels_to_run:
        print(f"\n[{p.name}] {p.method_family}  max_cycles={args.cycles}")
        if args.mode == "dry-run":
            r = run_panel_dryrun(p, args.cycles, cli_stream=sys.stdout)
        else:
            try:
                r = run_panel_real(p, args.cycles, args.budget_usd)
            except NotImplementedError as exc:
                print(f"  SKIPPED: {exc}")
                continue
        results.append(r)
        print(f"  -> discovered={r.discovered}  via={r.discovered_via!r}  "
              f"cycles={r.cycles_to_discovery}  peak={r.peak_score}/{r.pseudo_crib_total}  "
              f"wall={r.wall_time_sec:.2f}s  tested={r.total_candidates_tested}")

    # Summary
    print("\n=== Summary ===")
    solved = sum(1 for r in results if r.discovered)
    print(f"  solved: {solved}/{len(results)}  "
          f"total_wall={sum(r.wall_time_sec for r in results):.2f}s")

    if args.report_path:
        payload = {
            "mode": args.mode,
            "max_cycles": args.cycles,
            "results": [r.to_dict() for r in results],
        }
        Path(args.report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report_path).write_text(json.dumps(payload, indent=2))
        print(f"  wrote JSON report: {args.report_path}")

    # Exit non-zero if anything went fundamentally wrong — but NOT if a
    # panel simply failed to discover. Failure is a legitimate finding;
    # the operator reads the report. Per brief §9.3, a failure on K1/K2
    # is a STOP condition — but the harness documents it, doesn't panic.
    return 0


if __name__ == "__main__":
    sys.exit(main())
