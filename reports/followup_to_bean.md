Dr. Bean,

A brief follow-up to my earlier message with two corrections and one new result:

**Correction 1:** The palette p-value should be 7.5×10⁻⁵ (1M trial MC), not 6.5×10⁻⁵ as stated in the proof. The Bayes factor (9.0) is from the larger run.

**Correction 2:** The DEFECTOR uniqueness claim requires qualification. PALIMPSEST:AZ_beau+col7 reaches 15/24 at 78% of SA restarts (39/50) versus DEFECTOR at 6% (3/50), using different SA-optimized null masks. Both are false signals per the autokey impossibility proof (Theorem 3), but PALIMPSEST is actually the more consistent generator. The 15/24 ceiling is a structural property of the autokey+col7 MODEL, not specific to any keyword.

**New result:** The lag-7 autocorrelation in the raw 97-char ciphertext (z=3.28, which originally motivated the col7 transposition) completely DISAPPEARS on the null-extracted 73-char text (z=-0.30). It is a stego layer artifact — 7 of 9 lag-7 matches involve null positions. The real cipher-layer autocorrelation signals are at lags 1, 6, 23, and 34 (all z>2.9 on CT73).

This means col7 may have been chasing a stego artifact rather than a cipher property. The autokey impossibility proof eliminates the col7 model regardless, but the autocorrelation result independently confirms it was the wrong transposition.

The three theorems in the attached proof remain correct as stated. The palette, the BCL keystream enrichment, and the autokey impossibility are all verified by independent audit (zero mathematical errors across 23+ scripts checked).

Best regards,
Colin Patrick
kryptosbot.com

r.bean1@uq.edu.au
