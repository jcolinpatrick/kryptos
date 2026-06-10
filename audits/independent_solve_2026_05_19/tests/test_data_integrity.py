"""Cross-check the audit-local k4.json against the kernel constants.

If this fails, the kernel and the audit disagree on the inputs themselves
— halt immediately; no downstream conclusion is trustworthy.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# kernel import is allowed in tests/ as a comparator — but NOT in src/
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(ROOT)), "src"))
from kryptos.kernel.constants import (
    CT as KERNEL_CT,
    CT_LEN as KERNEL_CT_LEN,
    CRIB_DICT as KERNEL_CRIB_DICT,
    SELF_ENCRYPTING as KERNEL_SELF_ENCRYPTING,
    BEAN_EQ as KERNEL_BEAN_EQ,
    BEAN_INEQ as KERNEL_BEAN_INEQ,
    BEAN_LINEAR as KERNEL_BEAN_LINEAR,
)


def main():
    with open(os.path.join(ROOT, "data", "k4.json")) as f:
        data = json.load(f)

    failures = []

    # Ciphertext identity
    if data["ciphertext"] != KERNEL_CT:
        failures.append(f"CT mismatch: audit={data['ciphertext']!r}, kernel={KERNEL_CT!r}")
    if data["length"] != KERNEL_CT_LEN:
        failures.append(f"length mismatch: audit={data['length']}, kernel={KERNEL_CT_LEN}")

    # Crib alignment
    audit_crib_map = {}
    for c in data["cribs"]:
        for o, ch in enumerate(c["plaintext"]):
            audit_crib_map[c["start"] + o] = ch
    if audit_crib_map != dict(KERNEL_CRIB_DICT):
        diff_kernel = {k: v for k, v in dict(KERNEL_CRIB_DICT).items() if audit_crib_map.get(k) != v}
        diff_audit = {k: v for k, v in audit_crib_map.items() if dict(KERNEL_CRIB_DICT).get(k) != v}
        failures.append(f"crib map mismatch: kernel-only={diff_kernel}, audit-only={diff_audit}")

    # Self-encrypting
    audit_self_enc = {p["position"] for p in data["self_encrypting_positions"]}
    if audit_self_enc != set(KERNEL_SELF_ENCRYPTING):
        failures.append(f"self-enc mismatch: audit={audit_self_enc}, kernel={set(KERNEL_SELF_ENCRYPTING)}")

    # Bean counts
    if data["bean"]["equality"] != [list(pair) for pair in KERNEL_BEAN_EQ]:
        failures.append(f"Bean equality mismatch: audit={data['bean']['equality']}, kernel={[list(p) for p in KERNEL_BEAN_EQ]}")
    if data["bean"]["inequality_count"] != len(KERNEL_BEAN_INEQ):
        failures.append(f"Bean inequality count mismatch: audit={data['bean']['inequality_count']}, kernel={len(KERNEL_BEAN_INEQ)}")
    if data["bean"]["linear_constraint_count"] != len(KERNEL_BEAN_LINEAR):
        failures.append(f"Bean linear count mismatch: audit={data['bean']['linear_constraint_count']}, kernel={len(KERNEL_BEAN_LINEAR)}")

    if failures:
        print("DATA INTEGRITY: FAIL")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("DATA INTEGRITY: PASS")
    print(f"  CT length:   {data['length']}")
    print(f"  cribs:       {len(audit_crib_map)} crib positions match kernel")
    print(f"  self-enc:    {sorted(audit_self_enc)} match kernel")
    print(f"  Bean:        1 eq, {data['bean']['inequality_count']} ineq, {data['bean']['linear_constraint_count']} linear match kernel")


if __name__ == "__main__":
    main()
