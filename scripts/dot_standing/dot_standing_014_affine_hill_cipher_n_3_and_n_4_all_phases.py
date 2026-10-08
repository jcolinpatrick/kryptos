#!/usr/bin/env python3
"""
Cipher: Affine Hill cipher n=3 and n=4, all phases
Family: dot_standing
Status: exhausted
Keyspace: 28 configurations (frozen scope: reproductions/dot_standing/records/dot_standing_014/spec.json)
Last run: 2026-10-05
Best score: n/a (exact crib-compatibility test, 0 survivors)
"""
# DOT-STANDING-014. Re-runs the frozen search from the private cryptolab standing campaign
# dot-standing-014 and checks the result against the published record. How the replay works,
# and what is frozen, redacted or shimmed: reproductions/dot_standing/README.md.
# Needs numpy and pydantic: pip install -r reproductions/dot_standing/requirements.txt

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "reproductions", "dot_standing"))

from reproduce import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["DOT-STANDING-014", *sys.argv[1:]]))
