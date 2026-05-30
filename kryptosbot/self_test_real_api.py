"""Real-API self-test runner (loop-lite).

Round 2 Phase R2-5 (2026-04-21). This is a MINIMAL agent loop that
exercises the theorist → dispatcher → kernel subset of the framework
against K1. It is NOT the full controller's persona-routed + red-team
+ stat-audit + synthesis chain — those are K4-oriented and wiring them
through self_test_mode is deeper than R2-5's scope allowed.

What this runner DOES exercise:
  - Claude API call with a theorist-equivalent prompt.
  - Kernel-verified decryption via the R2-2 DSL (vigenere on KA + cribs).
  - Panel-specific crib scoring (R2-5 PanelCribs).
  - Hard USD ceiling (R2-5 TokenAccountant).

What this runner does NOT exercise:
  - Persona routing (escape-room / keystream-forensics / etc.).
  - Critic stage (the prompt encodes the minimal constraints inline).
  - Red-team-disprover sibling call.
  - Stat-audit gate / lead-pursuit / synthesis.
  - Multi-cycle dynamics.

This is intentionally a stripped-down experiment. The question it
answers is narrow but load-bearing:

    "Given K1's challenge (CT + 20 pseudo-cribs + framework capability
    summary), can Claude produce a DSL hypothesis spec that, when
    dispatched through our existing infrastructure, decrypts K1?"

A successful run proves the DSL + dispatcher + scoring chain can
solve a known-answer Kryptos panel end-to-end. A failed run tells us
which stage broke down. Per brief §6.2: ONE PASS, NO RETRIES on
non-infrastructure failure.

Usage (requires ANTHROPIC_API_KEY in env or kryptosbot/.env):

    PYTHONPATH=src python3 -u kryptosbot/self_test_real_api.py \\
        --panel k1 --report-path results/self_test/r2_5_real_k1.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("kryptosbot.self_test_real_api")

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


# ─── Prompt construction ────────────────────────────────────────────────────

_THEORIST_SYSTEM = """\
You are a cryptanalyst evaluating a classical cipher. You will be shown
a short ciphertext and a few plaintext anchors (first 10 and last 10
characters of the plaintext are known). Your job is to identify the
cipher family + key that decrypts the ciphertext.

The framework you are working with supports these cipher kinds (each
taking a keyword or column-order):
  - vigenere      (C = (P + K) mod 26; keyword required)
  - beaufort      (C = (K - P) mod 26; keyword required)
  - variant_beaufort  (C = (P - K) mod 26; keyword required)
  - columnar      (transposition; width + col_order required)

Each substitution kind supports three alphabets:
  - "AZ"            standard A-Z
  - "KA"            KRYPTOSABCDEFGHIJLMNQUVWXZ (Kryptos tableau)
  - "keyword_mixed" arbitrary keyword-mixed alphabet (keyword supplied)

Emit your answer as a single JSON object with this schema:

{
  "family": "vigenere" | "beaufort" | "variant_beaufort" | "columnar",
  "alphabet": "AZ" | "KA" | "keyword_mixed",
  "keyword": "<string>",                 # for substitution kinds
  "alphabet_keyword": "<string>",         # only for alphabet='keyword_mixed'
  "reasoning": "<one paragraph>"
}

Do NOT include any other prose outside the JSON. Do not use markdown
fences. The JSON must be the entire output.
"""


def _theorist_user_prompt(panel_id: str, ct: str, cribs: dict[int, str]) -> str:
    crib_lines = "\n".join(
        f"  PT[{pos}] = {ch}" for pos, ch in sorted(cribs.items())
    )
    return f"""\
Panel: {panel_id.upper()}
Ciphertext ({len(ct)} chars): {ct}

Known plaintext positions (0-indexed):
{crib_lines}

Propose the single most likely cipher family + key that maps this
ciphertext to the known plaintext. If the cipher is a classical
Quagmire III with a KRYPTOS-keyed tableau, that reduces to a plain
Vigenère cipher on the KA alphabet (alphabet=\"KA\") — our framework
expresses it that way.
"""


# ─── Response parsing ───────────────────────────────────────────────────────

def _extract_json(text: str) -> Optional[dict]:
    """Find a single JSON object in the response text.

    Tolerates accidental leading prose or a markdown fence — but never
    returns a partial or ambiguous parse. Returns None on any parse
    failure."""
    text = text.strip()
    # Try direct parse first.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Fenced block fallback.
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass
    # Greedy {...} match fallback.
    brace_match = re.search(r"(\{.*\})", text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(1))
        except json.JSONDecodeError:
            pass
    return None


# ─── Dispatch ───────────────────────────────────────────────────────────────

def _build_spec_from_response(
    parsed: dict, panel_id: str,
) -> Any:
    """Convert the theorist's JSON into a HypothesisSpec.

    Raises ValueError if required fields are missing or unrecognizable.
    """
    from kryptosbot.hypothesis_dsl import (
        CipherLayer, HypothesisSpec, ParamRange,
    )

    family = parsed.get("family")
    alphabet = parsed.get("alphabet", "AZ")
    if family not in ("vigenere", "beaufort", "variant_beaufort", "columnar"):
        raise ValueError(f"unknown family {family!r}")

    params: list[ParamRange] = []
    if family in ("vigenere", "beaufort", "variant_beaufort"):
        keyword = parsed.get("keyword")
        if not isinstance(keyword, str) or not keyword:
            raise ValueError(
                f"{family} requires a string keyword; got {keyword!r}"
            )
        params.append(ParamRange(name="keyword", values=[keyword.upper()]))
        if alphabet == "keyword_mixed":
            alph_kw = parsed.get("alphabet_keyword")
            if not isinstance(alph_kw, str) or not alph_kw:
                raise ValueError(
                    "alphabet='keyword_mixed' requires alphabet_keyword"
                )
            params.append(
                ParamRange(name="alphabet_keyword", values=[alph_kw.upper()])
            )
    elif family == "columnar":
        width = parsed.get("width")
        col_order = parsed.get("col_order")
        if not (isinstance(width, int) and width >= 2):
            raise ValueError(f"columnar requires width>=2; got {width!r}")
        if not isinstance(col_order, list) or sorted(col_order) != list(range(width)):
            raise ValueError(f"columnar col_order invalid: {col_order!r}")
        params.append(ParamRange(name="width", values=[width]))
        params.append(ParamRange(name="col_order", values=[col_order]))

    spec = HypothesisSpec(
        hypothesis_id=f"SELF-TEST-{panel_id}-R2-5",
        pipeline=[CipherLayer(kind=family, alphabet=alphabet, params=params)],
        notes=f"R2-5 real-API self-test panel={panel_id}.",
    )
    errs = spec.validate()
    if errs:
        raise ValueError(f"spec invalid: {errs}")
    return spec


# ─── Main runner ────────────────────────────────────────────────────────────

@dataclass
class RealApiResult:
    panel_id: str
    api_call_ok: bool
    raw_response: str
    parsed_response: Optional[dict]
    spec_constructed: bool
    spec_error: str
    dispatched: bool
    dispatch_error: str
    recovered_plaintext: str
    pseudo_crib_score: int
    pseudo_crib_max: int
    discovered: bool
    wall_time_sec: float
    token_summary: dict

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        # Truncate the raw response for the saved artifact.
        d["raw_response_preview"] = (d.pop("raw_response") or "")[:500]
        d["recovered_plaintext_preview"] = d.pop("recovered_plaintext")[:80]
        return d


def run_real_api_panel(
    panel_id: str,
    model: str = "claude-opus-4-8",
    max_usd: float = 5.00,
    api_key: Optional[str] = None,
) -> RealApiResult:
    """Run one real-API self-test pass against the named panel.

    Raises ImportError if anthropic SDK isn't installed.
    Returns a RealApiResult on any non-API error (parse / dispatch fail).
    Only infrastructure failures (API auth, network) bubble up.
    """
    import anthropic

    from kryptos.kernel.transforms.compose import (
        PipelineConfig, TransformConfig, TransformType, build_pipeline,
    )
    from kryptosbot.job_dispatcher import _build_pipeline_config
    from kryptosbot.panel_cribs import (
        load_panel_cribs, score_candidate_against_panel,
    )
    from kryptosbot.token_accountant import TokenAccountant

    t0 = time.monotonic()
    panel = load_panel_cribs(panel_id)
    accountant = TokenAccountant(max_usd=max_usd)

    # API call.
    client = anthropic.Anthropic(api_key=api_key)
    user_prompt = _theorist_user_prompt(panel_id, panel.ct, panel.crib_dict)
    try:
        resp = client.messages.create(
            model=model,
            max_tokens=2048,
            system=_THEORIST_SYSTEM,
            messages=[{"role": "user", "content": user_prompt}],
        )
    except anthropic.APIError as exc:
        raise RuntimeError(f"infra failure (API): {exc}") from exc

    # Account usage.
    usage = getattr(resp, "usage", None)
    if usage is not None:
        accountant.charge(
            model=model,
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        )

    # Extract text.
    raw_text = ""
    for block in resp.content:
        if getattr(block, "type", None) == "text":
            raw_text += block.text

    parsed = _extract_json(raw_text)
    result = RealApiResult(
        panel_id=panel_id,
        api_call_ok=True,
        raw_response=raw_text,
        parsed_response=parsed,
        spec_constructed=False,
        spec_error="",
        dispatched=False,
        dispatch_error="",
        recovered_plaintext="",
        pseudo_crib_score=0,
        pseudo_crib_max=panel.n_cribs(),
        discovered=False,
        wall_time_sec=0.0,
        token_summary=accountant.summary(),
    )

    if parsed is None:
        result.spec_error = "theorist response did not contain parseable JSON"
        result.wall_time_sec = time.monotonic() - t0
        return result

    # Build spec.
    try:
        spec = _build_spec_from_response(parsed, panel_id)
        result.spec_constructed = True
    except ValueError as exc:
        result.spec_error = f"spec construction failed: {exc}"
        result.wall_time_sec = time.monotonic() - t0
        return result

    # Bind single-value params to a deterministic binding tuple.
    bindings: list[tuple[str, Any]] = []
    layer = spec.pipeline[0]
    for p in layer.params:
        values = p.enumerate() if hasattr(p, "enumerate") else list(p.values)
        bindings.append((f"layer0.{p.name}", values[0]))

    # Execute pipeline with CT_LEN overridden to the panel's CT length.
    import kryptos.kernel.constants as kc
    saved_CT_LEN = kc.CT_LEN
    try:
        kc.CT_LEN = len(panel.ct)
        pipeline_dict = _build_pipeline_config(spec, tuple(bindings))
        steps = tuple(
            TransformConfig(
                transform_type=TransformType(s["type"]),
                params=dict(s.get("params", {})),
                description=s.get("description", ""),
            )
            for s in pipeline_dict["steps"]
        )
        pipeline = PipelineConfig(
            name=f"R2-5-{panel_id}-real-api",
            steps=steps,
            direction="decrypt",
        )
        fn = build_pipeline(pipeline)
        recovered = fn(panel.ct)
        result.dispatched = True
        result.recovered_plaintext = recovered
    except Exception as exc:
        result.dispatch_error = f"{type(exc).__name__}: {exc}"
        result.wall_time_sec = time.monotonic() - t0
        return result
    finally:
        kc.CT_LEN = saved_CT_LEN

    result.pseudo_crib_score = score_candidate_against_panel(
        result.recovered_plaintext, panel,
    )
    result.discovered = result.pseudo_crib_score >= panel.n_cribs()
    result.token_summary = accountant.summary()
    result.wall_time_sec = time.monotonic() - t0
    return result


def _load_api_key() -> Optional[str]:
    """Try env, then kryptosbot/.env, then .env in repo root."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    for env_path in (_REPO_ROOT / "kryptosbot" / ".env", _REPO_ROOT / ".env"):
        if not env_path.exists():
            continue
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--panel", choices=("k1", "k2", "k3"), default="k1")
    ap.add_argument("--model", default="claude-opus-4-8")
    ap.add_argument("--max-usd", type=float, default=5.00)
    ap.add_argument("--report-path", type=str, default=None)
    args = ap.parse_args(argv)

    api_key = _load_api_key()
    if api_key is None:
        print("ERROR: ANTHROPIC_API_KEY not found in env or .env files.",
              file=sys.stderr)
        return 2

    print(f"R2-5 real-API self-test: panel={args.panel} model={args.model} "
          f"cap=${args.max_usd:.2f}")
    try:
        result = run_real_api_panel(
            panel_id=args.panel,
            model=args.model,
            max_usd=args.max_usd,
            api_key=api_key,
        )
    except RuntimeError as exc:
        print(f"INFRA FAILURE: {exc}", file=sys.stderr)
        return 3

    # Human-readable summary.
    print()
    print(f"api_call_ok        : {result.api_call_ok}")
    print(f"parsed_response    : "
          f"{'yes' if result.parsed_response else 'NO — parse failed'}")
    if result.parsed_response:
        print(f"  family           : {result.parsed_response.get('family')}")
        print(f"  alphabet         : {result.parsed_response.get('alphabet')}")
        print(f"  keyword          : {result.parsed_response.get('keyword')}")
    print(f"spec_constructed   : {result.spec_constructed}")
    if result.spec_error:
        print(f"  spec_error       : {result.spec_error}")
    print(f"dispatched         : {result.dispatched}")
    if result.dispatch_error:
        print(f"  dispatch_error   : {result.dispatch_error}")
    if result.dispatched:
        print(f"recovered_prefix   : {result.recovered_plaintext[:60]}")
        print(f"pseudo_crib_score  : "
              f"{result.pseudo_crib_score}/{result.pseudo_crib_max}")
        print(f"discovered         : {result.discovered}")
    print(f"usd_spent          : ${result.token_summary['total_usd']:.4f}")
    print(f"wall_time_sec      : {result.wall_time_sec:.2f}")

    if args.report_path:
        Path(args.report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report_path).write_text(json.dumps(result.to_dict(), indent=2))
        print(f"\nreport written to {args.report_path}")

    return 0 if result.discovered else 1


if __name__ == "__main__":
    sys.exit(main())
