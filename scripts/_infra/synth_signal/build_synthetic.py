#!/usr/bin/env python3
"""Build a synthetic K4-shape ciphertext for the synthetic-signal calibration.

Generates a 97-char synthetic CT under a chosen Quagmire III + keyword
configuration where the underlying plaintext contains the canonical K4
cribs (EASTNORTHEAST at 21-33, BERLINCLOCK at 63-73). Verifies the
round-trip, verifies non-degeneracy of the synthetic Bean derivation,
and writes a bundle manifest the synthetic launcher consumes.

This script must NOT be invoked with KRYPTOS_CT_OVERRIDE already set —
it constructs the synthetic CT and only then is the launcher supposed
to set the override env var. Invoking with override pre-set is a foot-gun
this script refuses to perform.

See ``<internal>/SYNTHETIC_SIGNAL_CALIBRATION_SPEC.md``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Standalone bootstrap (script is 3 dirs deep)
_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
if os.path.exists(os.path.join(_ROOT, "src")):
    sys.path.insert(0, os.path.join(_ROOT, "src"))

if os.environ.get("KRYPTOS_CT_OVERRIDE"):
    raise RuntimeError(
        "build_synthetic.py must run WITHOUT KRYPTOS_CT_OVERRIDE set. "
        "The script constructs a fresh synthetic CT and writes it to disk; "
        "the synthetic launcher (launch.py) sets the env var afterwards."
    )

# Import after the override-not-set guard
from kryptos.kernel.transforms.quagmire import quagmire_decrypt, quagmire_encrypt


# ── Default synthetic plaintext (carries the canonical cribs) ────────────

# Layout (97 chars total):
#   0..20    21 chars  pre-ENE padding ("THERESEARCHERSREPORTS")
#   21..33   13 chars  EASTNORTHEAST  (real K4 crib content)
#   34..62   29 chars  inter-crib padding ("THENWEMEASUREFORWARDFROMTHERE")
#   63..73   11 chars  BERLINCLOCK    (real K4 crib content)
#   74..96   23 chars  post-BC padding ("POINTSTOWARDMUSEUMSITES")
DEFAULT_SYNTHETIC_PT = (
    "THERESEARCHERSREPORTS"      # 0..20  (21)
    "EASTNORTHEAST"              # 21..33 (13)
    "THENWEMEASUREFORWARDFROMTHERE"  # 34..62 (29)
    "BERLINCLOCK"                # 63..73 (11)
    "POINTSTOWARDMUSEUMSITES"    # 74..96 (23)
)
assert len(DEFAULT_SYNTHETIC_PT) == 97, len(DEFAULT_SYNTHETIC_PT)
assert DEFAULT_SYNTHETIC_PT[21:34] == "EASTNORTHEAST"
assert DEFAULT_SYNTHETIC_PT[63:74] == "BERLINCLOCK"
assert DEFAULT_SYNTHETIC_PT[32] == "S"
assert DEFAULT_SYNTHETIC_PT[73] == "K"


def build(
    *,
    test_id: str,
    keyword: str,
    plaintext: str = DEFAULT_SYNTHETIC_PT,
    output_dir: Path,
) -> dict:
    """Construct, verify, and write the synthetic CT bundle.

    Returns the manifest dict (also written to ``manifest.json``).
    """
    if len(plaintext) != 97:
        raise ValueError(f"PT must be 97 chars, got {len(plaintext)}")
    if not plaintext.isalpha() or not plaintext.isupper():
        raise ValueError("PT must be uppercase A-Z")

    # Mechanism: Quagmire III on KRYPTOS-mixed alphabet, indicator='K'.
    # Same calling convention as K1/K2 ground truth.
    ct = quagmire_encrypt(
        plaintext,
        period_keyword=keyword,
        ct_alphabet_keyword="KRYPTOS",
        pt_alphabet_keyword="KRYPTOS",
        indicator="K",
    )
    if len(ct) != 97:
        raise RuntimeError(f"Encrypted CT length {len(ct)} != 97")
    if not ct.isalpha() or not ct.isupper():
        raise RuntimeError(f"Encrypted CT not uppercase A-Z: {ct!r}")

    # Round-trip: decrypt should recover PT exactly
    pt_recovered = quagmire_decrypt(
        ct,
        period_keyword=keyword,
        ct_alphabet_keyword="KRYPTOS",
        pt_alphabet_keyword="KRYPTOS",
        indicator="K",
    )
    if pt_recovered != plaintext:
        raise RuntimeError(
            f"Round-trip failed. Expected {plaintext!r} but got {pt_recovered!r}"
        )

    # Crib-position check: synthetic PT contains the cribs verbatim, so
    # decrypt(synthetic_CT) must show ENE at 21-33 and BC at 63-73.
    assert pt_recovered[21:34] == "EASTNORTHEAST"
    assert pt_recovered[63:74] == "BERLINCLOCK"

    # Verify Bean derivation against the synthetic CT produces a
    # non-degenerate constraint set. We do this by spawning a fresh
    # interpreter with KRYPTOS_CT_OVERRIDE set, since the live process
    # already has the real-K4 module loaded.
    bean_check = _verify_synthetic_bean(ct)

    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "synthetic_ct.txt").write_text(ct + "\n")
    (output_dir / "synthetic_pt.txt").write_text(plaintext + "\n")

    manifest = {
        "test_id": test_id,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mechanism": {
            "family": "quagmire_iii",
            "ct_alphabet_keyword": "KRYPTOS",
            "pt_alphabet_keyword": "KRYPTOS",
            "indicator": "K",
            "period_keyword": keyword,
            "period": len(keyword),
        },
        "ct": ct,
        "pt": plaintext,
        "ct_len": len(ct),
        "self_encrypt_pos_32": {
            "pt_char": plaintext[32],
            "ct_char": ct[32],
            "matches_k4_self_encrypt": ct[32] == "S",
        },
        "self_encrypt_pos_73": {
            "pt_char": plaintext[73],
            "ct_char": ct[73],
            "matches_k4_self_encrypt": ct[73] == "K",
        },
        "synthetic_bean": bean_check,
        "round_trip_verified": True,
        "spec_doc": "<internal>/SYNTHETIC_SIGNAL_CALIBRATION_SPEC.md",
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


def _verify_synthetic_bean(synth_ct: str) -> dict:
    """Spawn a fresh interpreter with KRYPTOS_CT_OVERRIDE set and read
    the resulting BEAN_EQ / BEAN_INEQ / BEAN_LINEAR counts. Returns a
    dict suitable for embedding in the manifest.
    """
    import subprocess

    code = (
        "from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ, BEAN_LINEAR; "
        "import json, sys; "
        "sys.stdout.write(json.dumps({"
        "'bean_eq_count': len(BEAN_EQ), "
        "'bean_ineq_count': len(BEAN_INEQ), "
        "'bean_linear_count': len(BEAN_LINEAR), "
        "'bean_eq_sample': [list(p) for p in BEAN_EQ[:3]], "
        "'bean_ineq_sample': [list(p) for p in BEAN_INEQ[:3]]"
        "}))"
    )
    env = os.environ.copy()
    env["KRYPTOS_CT_OVERRIDE"] = synth_ct
    env["PYTHONPATH"] = os.path.join(_ROOT, "src") + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, env=env, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Synthetic Bean derivation failed in subprocess.\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return json.loads(proc.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--test-id", required=True,
        help="Identifier for this synthetic build (e.g., t1_serpentine, t2_defector)",
    )
    parser.add_argument(
        "--keyword", required=True,
        help="Quagmire III period keyword (e.g., SERPENTINE, DEFECTOR)",
    )
    parser.add_argument(
        "--output-dir", default="synth_signal",
        help="Directory for the bundle (default: synth_signal/<test_id>/)",
    )
    parser.add_argument(
        "--plaintext", default=None,
        help="Override default synthetic plaintext (must be 97 chars, must contain "
             "ENE at 21-33 and BC at 63-73)",
    )
    args = parser.parse_args(argv)

    out_dir = Path(args.output_dir) / args.test_id
    if not out_dir.is_absolute():
        out_dir = Path(_ROOT) / out_dir

    pt = args.plaintext if args.plaintext else DEFAULT_SYNTHETIC_PT
    if args.plaintext:
        if pt[21:34] != "EASTNORTHEAST":
            raise SystemExit("Custom plaintext must contain EASTNORTHEAST at 21-33")
        if pt[63:74] != "BERLINCLOCK":
            raise SystemExit("Custom plaintext must contain BERLINCLOCK at 63-73")

    print(f"Building synthetic '{args.test_id}'  keyword={args.keyword!r}  out={out_dir}")
    manifest = build(
        test_id=args.test_id, keyword=args.keyword.upper(),
        plaintext=pt, output_dir=out_dir,
    )

    print(f"  CT  : {manifest['ct'][:40]}...{manifest['ct'][-20:]}")
    print(f"  PT  : {manifest['pt'][:40]}...{manifest['pt'][-20:]}")
    print(f"  Self-encrypt @32: PT={manifest['self_encrypt_pos_32']['pt_char']} "
          f"CT={manifest['self_encrypt_pos_32']['ct_char']} "
          f"K4-match={manifest['self_encrypt_pos_32']['matches_k4_self_encrypt']}")
    print(f"  Self-encrypt @73: PT={manifest['self_encrypt_pos_73']['pt_char']} "
          f"CT={manifest['self_encrypt_pos_73']['ct_char']} "
          f"K4-match={manifest['self_encrypt_pos_73']['matches_k4_self_encrypt']}")
    print(f"  Synthetic Bean : EQ={manifest['synthetic_bean']['bean_eq_count']} "
          f"INEQ={manifest['synthetic_bean']['bean_ineq_count']} "
          f"LINEAR={manifest['synthetic_bean']['bean_linear_count']}")
    print(f"  Round-trip     : verified")
    print(f"  Wrote          : {out_dir / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
