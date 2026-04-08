# C7 Archive — Running-Key Scripts Rejected by Corpus Policy

**Archived:** 2026-04-08
**Campaign:** C7 (final-honest-search-window bin C, per `docs/exhaustion_audit_2026_04_08.md`)
**Tool that flagged them:** `scripts/campaigns/f_admissibility_elimination_v1.py`
**Policy:** `src/kryptos/admissibility/corpus_policy.py` — allowlist = {k1/k2/k3_plaintext, carter_tomb_vol1, kahn_codebreakers}

These scripts were flagged `ASSUMPTION_UNMET` (16 total). After manual provenance review, 7 of the 16 were
archived here because their hypothesis depends on a source that has no artist/creator statement, archive
evidence, or clue-surface justification. The other 9 were amended in place (see git history on the
`scripts/running_key/` directory for the same date).

Rejection reasons (one line per script):

| Script | Reason |
|---|---|
| `e_antipodes_04_sculpture_running_key.py` | Already marked DEPRECATED in header. Sculpture-text hypothesis is covered by `e_sculpture_row_aligned_ka_vig.py` (retained, pending `ka_tableau` license proposal) |
| `e_cfm_01_running_key_foreign.py` | Hardcoded JFK-Berlin, Reagan, Kennedy German/French speech texts. No artist statement for any of these. "Foreign running key" was E-FRAC-51's sibling guess and carries the same provenance vacuum |
| `e_digraph_running_key_02.py` | Unbounded scan over `/data/tmp/gutenberg_cache/*.txt` + wordlist dir. Classic guess-a-book pattern, exactly what the policy is designed to reject |
| `e_digraph_running_key_03.py` | Same pattern as `_02` (duplicate architecture) |
| `e_s_135_berlin_wall_running_key.py` | Reagan/JFK/CIA Charter/UDHR/NSA Act as running keys. None on allowlist; no specific Sanborn/Scheidt attestation for any of them |
| `e_team_book_cipher.py` | Mixes 1 allowlisted source (`carter_vol1.txt`) with 6 unlicensed (`jfk_berlin`, `reagan_berlin`, `udhr`, `cia_charter`, `nsa_act_1947`, `carter_gutenberg`). The carter_vol1 path is already covered by `e_carter_tomb_deep_02.py` etc. (retained + amended). Splitting this script is not worth the engineering |
| `e_wtz_00_cities_runkey.py` | Weltzeituhr (World Time Zone clock) cities as key. The K4 crib is BERLINCLOCK = Berlin Clock (Mengenlehreuhr), *not* WTZ. No Sanborn statement ties WTZ to K4 |

## Reversal procedure

These scripts are archived, not deleted. If a new artist statement or archive discovery makes one of these
hypotheses admissible, the reversal is:

1. Propose a new `CorpusLicense` entry in `src/kryptos/admissibility/corpus_policy.py::DEFAULT_ALLOWLIST`
   with `justification`, `provenance_uri`, and at least one `evidence_ref`.
2. `git mv scripts/archive/c7_rejected/<name>.py scripts/running_key/`
3. Add a matching test to `tests/test_admissibility.py::TestCorpusPolicy`.
4. Re-run `scripts/campaigns/f_admissibility_elimination_v1.py` to verify the script now passes the gate.

See `docs/admissibility_architecture.md` for the full policy and `docs/exhaustion_audit_2026_04_08.md`
§6.1 for the reasoning behind the final-honest-search-window framing.
