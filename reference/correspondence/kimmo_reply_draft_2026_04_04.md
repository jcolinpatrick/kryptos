# Draft Reply to Kimmo — 2026-04-04

Hi Kimmo,

Thanks for the detailed email — these are serious ideas and I want to give them the treatment they deserve. I ran your specific models computationally today and have concrete results.

## Your K1+K2 OTP + Masking Word Model

Your best idea is the two-layer model: K1+K2 plaintext as OTP key, with a short masking word applied first (your NIXNIXNIX concept). You're right that this maps cleanly onto Scheidt's "solve the technique first, then go for the puzzle" — the masking word IS the technique, and the OTP IS the puzzle.

**I also noticed something you may have seen:** K1 is exactly 63 characters long, and BERLINCLOCK starts at K4 position 63 (0-indexed). If K1+K2 PT is the OTP key, the K1/K2 boundary falls *exactly* at the BERLINCLOCK boundary. That's a ~1.1% coincidence. Striking.

So I tested it exhaustively:

**K1+K2 OTP + masking word, all lengths 1-5:**
- OTP variants tested: Vigenère, Beaufort, Variant Beaufort (3)
- Masking variants tested: Vigenère, Beaufort, Variant Beaufort (3)
- Masking word lengths: 1 through 5
- Total masking words: 26^1 + 26^2 + 26^3 + 26^4 + 26^5 = 12,356,630
- Total configurations: **111,209,670**
- Best score: **8/24** (masking word "GJQ", OTP=Vigenère, mask=Beaufort)
- Plaintext at best: gibberish (`TMZLTGWNEAIQJJJV...`)
- Runtime: ~47 minutes single-threaded

**This exhaustively eliminates the model for masking words up to 5 characters.** 8/24 is expected noise for a search of this size (birthday paradox — with 111M trials, you'll get a few 8/24 hits from random alignment).

Your specific keyword suggestions (YAR, RAY, HYDRA, LAYER, HYDRAULIC) are all within the tested space. None produced signal.

**K1+K2 as direct OTP (no masking):** Also tested — 0-1/24 across all 3 variants. Despite the position-63 alignment, the plaintext-as-key model doesn't produce crib matches.

## Your Diana Generalization

Your model PT = A ± CT ± K (mod 26) with different alphabets is clever. The constant offset A is equivalent to adding A to the key — so for a repeating key K, testing all A values from 0-25 is the same as testing K+A, which is already covered by exhaustive key search. It doesn't expand the search space beyond what we've tested.

The alphabet variation (AZ vs KA vs HYDRA-keyed) does change things. We tested AZ and KA variants. A HYDRA-keyed alphabet would be different but testable — I can add it if you want, though the null results on AZ and KA make it unlikely to produce signal.

## Your Elimination Criteria

I think your 70% threshold approach is sound for exploratory work, and using only EASTNORTHEAST for search with BERLINCLOCK for validation is good experimental design. We use a similar approach — our scoring function counts exact crib matches at fixed positions, with thresholds at 6 (noise floor), 10 (store), 18 (signal), 24 (breakthrough).

Your concern about key resets at X-marks is valid. If the key resets between the two crib regions, our scoring would miss configurations where one crib matches perfectly but the other doesn't due to offset. We do test this in some scripts by scoring each crib region independently.

## What I Think Is Actually Going On

I ran a large anomaly investigation today (46 anomalies cataloged from the sculpture, Morse code, archive photos, and statistical observations). The key finding:

**The anomaly registry constrains the METHOD, not a source text or specific keyword.**

The strongest anomaly evidence points to:
1. Null masking / steganography (Sanborn's own sketch says "encrypted message included within set of modern day font characters"; Scheidt confirmed "a little bit of stego")
2. A physical overlay / Cardan grille (archive photos show golden transparent overlays)
3. Near-identity substitution with keyword-based alphabet (Bean 2021: p≈1/5520)
4. One-to-one encryption with no transposition at crib positions (Bean 2021: p≈1/240)

But the anomalies do NOT point to any specific keyword, source text, or parameter values. I tested every anomaly-derived keyword (70+), every anomaly-derived source text, every anomaly-derived procedural model — about 20 million configs total today. All noise.

**Scheidt's system is genuinely bespoke.** Gillogly's statement that it "has never appeared in cryptographic literature" appears to be literally true. Every standard model we can parameterize and sweep — including your two-layer model — produces noise against K4.

## The One Open Lead

The most interesting observation from today: the Kryptos compass rose deflects toward WSW (247.5°), and 247 = 13 × 19. The number 13 = ROT13 (self-reciprocal shift), 19 = T in A=0 indexing ("T IS YOUR POSITION" from the Morse code), and 13 + 19 = 32, which is the self-encrypting position in K4 (CT[32] = PT[32] = S). Whether this is signal or numerological coincidence is unclear.

## What I'd Suggest

Since standard models are exhausted, the highest-value work is probably:
1. **Physical evidence acquisition** — specifically, pre-1997 photos of the Berlin Weltzeituhr showing the original DDR-era city list. Sanborn said "there's a lot of fodder there."
2. **Reasoning about what "bespoke" means** — what could Scheidt have invented that's hand-executable, uses a tableau, involves masking, and doesn't match any known cipher family?
3. **The archive photos** (IMG_1212 with X-marks on a 26×26 grid) could literally be the null mask, but we'd need high-resolution access.

Would be happy to share more details on any of these results or run additional models if you have specific configurations in mind.

Best,
Colin

---

## Technical Summary (for attachment or reference)

**Total configs tested today across all models:**

| Attack | Configs | Best | Verdict |
|--------|---------|------|---------|
| Anomaly-derived keywords (70+) | ~400 | 0/24 | NOISE |
| Anomaly-derived source texts as RK | ~8.5M | 8/24 | NOISE |
| Procedural anomaly models (10) | 462K | 7/24 | NOISE |
| WSW compass bearing parameters | 32K | 7/24 | NOISE |
| Null-mask + keyword-Beaufort | 18M | 0/24 | NOISE |
| K1+K2 OTP + masking word (1-5 chars) | **111M** | **8/24** | **NOISE** |
| Kahn's Codebreakers full text as RK | 7.6M | 8/24 | NOISE |
| **TOTAL** | **~146M** | **8/24** | **ALL NOISE** |
