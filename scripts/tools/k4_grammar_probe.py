#!/usr/bin/env python3
"""
Cipher: none (language tool)
Family: tools/language
Status: active
Keyspace: n/a
Last run:
Best score: n/a
"""
"""k4_grammar_probe — CLI for the constrained grammar prior.

Soft-prior ranking of short phrases around K4 anchors. NOT a decoder.
See src/kryptos/language/README.md for full context.
"""
import argparse
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
while not os.path.exists(os.path.join(_ROOT, "src")):
    parent = os.path.dirname(_ROOT)
    if parent == _ROOT:
        break
    _ROOT = parent
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.language import (
    RegisterStyle,
    left_context_candidates, right_context_candidates,
    compare_anchor_phrases, score_sequence,
    entries_by_length_and_pos, entries_by_pos, entries_by_length,
    all_templates,
)


DISCLAIMER = (
    "Grammar prior is a soft signal only. It does NOT identify plaintext. "
    "Do not promote any candidate to crib status without independent "
    "cryptanalytic support."
)


def _fmt_breakdown(sb) -> str:
    lines = [
        f"  phrase: {sb.candidate!r}",
        f"    template: {sb.template_id}  register: {sb.register}",
        f"    aggregate: {sb.aggregate:.3f}",
        f"    components:",
        f"      slot_length_compat              = {sb.slot_length_compat:.3f}",
        f"      pos_compat                      = {sb.pos_compat:.3f}",
        f"      template_fit                    = {sb.template_fit:.3f}",
        f"      anchor_context_plausibility     = {sb.anchor_context_plausibility:.3f}",
        f"      register_plausibility           = {sb.register_plausibility:.3f}",
        f"      article_suppression_consistency = {sb.article_suppression_consistency:.3f}",
        f"      semantic_coherence              = {sb.semantic_coherence:.3f}",
    ]
    if sb.notes:
        lines.append(f"    notes: {sb.notes}")
    return "\n".join(lines)


def _print_results(results, fmt: str):
    if fmt == "json":
        if isinstance(results, dict):
            payload = {k: v.to_dict() for k, v in results.items()}
        elif isinstance(results, list):
            payload = [r.to_dict() for r in results]
        else:
            payload = results.to_dict()
        print(json.dumps(payload, indent=2))
    else:
        if isinstance(results, dict):
            iterable = results.values()
        elif isinstance(results, list):
            iterable = results
        else:
            iterable = [results]
        for sb in iterable:
            print(_fmt_breakdown(sb))
            print()


def _cmd_left_context(args):
    reg = RegisterStyle(args.register) if args.register else None
    results = left_context_candidates(
        anchor=args.anchor, slot_length=args.slot_length,
        role=args.role, register=reg, top_k=args.top_k,
    )
    print(f"# left-context ranking (grammatical prior) for word + {args.anchor}")
    _print_results(results, args.format)


def _cmd_right_context(args):
    reg = RegisterStyle(args.register) if args.register else None
    results = right_context_candidates(
        anchor=args.anchor, slot_length=args.slot_length,
        role=args.role, register=reg, top_k=args.top_k,
    )
    print(f"# right-context ranking (grammatical prior) for {args.anchor} + word")
    _print_results(results, args.format)


def _cmd_compare(args):
    results = compare_anchor_phrases(args.phrases, anchor=args.anchor or "")
    print(f"# anchor phrase comparison (grammatical prior)")
    # sort by aggregate descending
    ordered = dict(sorted(results.items(), key=lambda kv: kv[1].aggregate, reverse=True))
    _print_results(ordered, args.format)


def _cmd_sequence(args):
    reg = RegisterStyle(args.register) if args.register else None
    sb = score_sequence(args.text, register=reg)
    print(f"# sequence grammatical prior")
    _print_results(sb, args.format)


def _cmd_slot_fill(args):
    # pattern "[N] ANCHOR" or "ANCHOR [N]"
    parts = args.pattern.split()
    if len(parts) != 2:
        print("slot-fill pattern must be '[N] ANCHOR' or 'ANCHOR [N]'", file=sys.stderr)
        sys.exit(2)
    reg = RegisterStyle(args.register) if args.register else None
    if parts[0].startswith("[") and parts[0].endswith("]"):
        n = int(parts[0][1:-1])
        anchor = parts[1]
        results = left_context_candidates(anchor, n, register=reg, top_k=args.top_k)
    elif parts[1].startswith("[") and parts[1].endswith("]"):
        n = int(parts[1][1:-1])
        anchor = parts[0]
        results = right_context_candidates(anchor, n, register=reg, top_k=args.top_k)
    else:
        print("could not parse pattern", file=sys.stderr)
        sys.exit(2)
    print(f"# slot-fill ranking (grammatical prior)")
    _print_results(results, args.format)


def _cmd_inventory(args):
    if args.pos and args.length:
        entries = entries_by_length_and_pos(args.length, args.pos)
    elif args.pos:
        entries = entries_by_pos(args.pos)
    elif args.length:
        entries = entries_by_length(args.length)
    else:
        from kryptos.language import all_entries
        entries = all_entries()
    if args.format == "json":
        print(json.dumps(
            [{"word": e.word, "pos": e.pos, "length": e.length,
              "priors": e.priors, "notes": e.notes} for e in entries],
            indent=2,
        ))
    else:
        print(f"# inventory ({len(entries)} entries)")
        for e in entries:
            print(f"  {e.word:<14} {e.pos:<12} len={e.length}  {e.notes}")


def main(argv=None):
    p = argparse.ArgumentParser(description="K4 grammar prior probe (soft prior only).")
    p.add_argument("--query", required=True,
                   choices=["left-context", "right-context", "compare",
                            "sequence", "slot-fill", "inventory"])
    p.add_argument("--anchor", default="")
    p.add_argument("--slot-length", type=int, default=2)
    p.add_argument("--role", default=None,
                   help="filter by POS tag (PREP, VERB_OP, ...)")
    p.add_argument("--register", default=None,
                   choices=["directive", "status_report", "telegraphic", "hybrid"])
    p.add_argument("--top-k", type=int, default=20)
    p.add_argument("--phrases", nargs="+", default=[])
    p.add_argument("--text", default="")
    p.add_argument("--pattern", default="")
    p.add_argument("--pos", default=None)
    p.add_argument("--length", type=int, default=None)
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv)

    dispatch = {
        "left-context": _cmd_left_context,
        "right-context": _cmd_right_context,
        "compare": _cmd_compare,
        "sequence": _cmd_sequence,
        "slot-fill": _cmd_slot_fill,
        "inventory": _cmd_inventory,
    }
    dispatch[args.query](args)
    print()
    print(f"# {DISCLAIMER}")


if __name__ == "__main__":
    main()
