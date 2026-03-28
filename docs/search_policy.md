# Short Layered Ciphertext Search Policy

Applies whenever the target ciphertext is short (roughly <= 120 chars), partially masked, or plausibly multi-layer.

## Core rule

For short layered ciphertexts, early statistics are **advisory only**.
IC peaks, Kasiski repeats, autocorrelation peaks, DFT peaks, hill-climber optima, and n-gram improvements may be artifacts of:
- an outer transposition layer
- padding geometry
- null insertion/removal assumptions
- wrong layer order
- wrong alphabet convention
- short-text variance

Do **not** treat these signals as structural proof.

## Mandatory search behavior

- Never hard-prune a branch solely because final-ciphertext IC, period detection, or repeated-fragment evidence is weak, absent, or points elsewhere.
- Always consider heterogeneous layering, including:
  - transposition + periodic substitution
  - transposition + digraphic substitution
  - Polybius-derived layer + substitution/transposition
  - mixed alphabets / keyed tableaux
- For any two-layer hypothesis, test **both peel orders**:
  1. undo transposition first, then test substitution/polyalphabetic families
  2. undo substitution/polyalphabetic first, then test transposition families
- Do not assume final-ciphertext period evidence reflects the real key period if transposition may still be present.
- Do not assume absence of obvious digraphic signal rules out Playfair / Two-Square / Four-Square.
- Preserve multiple structurally distinct branches in parallel.

## Beam preservation policy

Retain a diverse beam across:
- layer order
- cipher family
- transposition width / rectangle shape
- key length
- alphabet convention
- padding / null assumptions

Do not let one statistic dominate the beam prematurely.

## Structural-first policy

Separate **structural search** from **keyword search**.

1. First search for plausible decompositions:
   - number of layers
   - family combinations
   - peel order
   - transposition geometry
   - masking / padding assumptions

2. Only then spend major compute on keyword dictionaries inside the strongest structural branches.

Do not burn compute on large keyword sweeps inside branches whose structure is still weakly supported.

## Scoring policy

Score candidates at three levels:
- **family-likeness** — does the intermediate resemble the expected residue of a cipher family?
- **plaintext-likeness** — does it resemble normalized English?
- **context coherence** — does it fit public Kryptos/Sanborn constraints without overclaiming?

A branch may remain alive if family-likeness improves sharply even when plaintext-likeness is still poor.

## Failure-report policy

When no solution is found, report:
- which structural branches were tested
- which were pruned and why
- which signals may have been deceptive
- which family/order combinations remain underexplored
- what concrete next campaigns should run

Do not give shallow "no signal" conclusions for short layered texts.
On short ciphertexts, signal suppression is expected and is not evidence against a hand-executable multi-layer design.
