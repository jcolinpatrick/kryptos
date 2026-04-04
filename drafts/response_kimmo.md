# Draft Response to Kimmo

---

Hi Kimmo,

Thanks for the detailed email — you've clearly done serious work on this, and several of your observations check out mathematically. I'll go through each point.

**1. Transposition + keyed substitution**

This is one of the most important areas we've investigated. We tested every standard transposition method (columnar grids at all widths, rail fence, spiral, zigzag, route ciphers, double columnar, and more — 14 different families, over 1.2 billion combinations) paired with keyed substitution. None produced a solution.

Beyond brute-force testing, we also have a mathematical proof that for 17 of the 25 possible key lengths, no transposition whatsoever — not just the structured ones, but any of the 97! possible letter rearrangements — can produce K4's known plaintext with a repeating-key cipher. The remaining 8 key lengths were tested exhaustively with columnar transpositions and produced nothing meaningful.

You're absolutely right that testing all possible transpositions is computationally impossible. What remains open is the combination of a non-repeating key (like a passage from a book) with a transposition we haven't identified — that's actually one of our leading hypotheses.

**2. Using the sculpture itself as a key — OBKR with QRLG**

This is a genuinely interesting observation. I verified the math: OBKR decrypted with key QRLG under the Kryptos mixed alphabet (KA) Vigenère does produce EACH — and this only works with the KA alphabet (standard A-Z gives gibberish). Since K1-K3 all used KA, this is the right alphabet to try.

We did test the sculpture text as a running key (experiment E-ANTIPODES-04), but that test used sequential offsets with the standard alphabet — it didn't test your specific row-aligned pairing with KA. So this particular alignment model is genuinely untested.

After verifying the OBKR→EACH result, I went ahead and tested the full hypothesis exhaustively. I tried every possible pairing of the 28 cipher panel rows with each of the 4 K4 rows — that's 7.5 million configurations across KA and AZ alphabets, Vigenère, Beaufort, and Variant Beaufort, with both end-aligned and start-aligned key extraction for the short first row.

The result: **best score was 6/24 across all 7.5 million configurations — noise.** No row pairing under any alphabet or cipher variant came close to matching the known plaintext. The 513 configurations that scored 6/24 are statistically expected at this search size.

So while the OBKR→EACH result is real, it appears to be a coincidence. The same row-alignment principle doesn't extend to the rest of K4. The full results are published in our repo as experiment E-SCULPTURE-ROW-ALIGNED if you'd like to verify.

**3. Diana cryptosystem**

The Diana cryptosystem is mechanically identical to a Beaufort cipher — both compute C = (K - P) mod 26. The trigraphic table used in Diana is a field-convenience format for doing Beaufort by hand; it doesn't change the underlying encryption. So yes, Diana is fully covered by our Beaufort eliminations: Beaufort with any repeating key (periods 1-26) is mathematically proven impossible for K4, and Beaufort with running keys from 60,000+ public texts produced zero signal.

If you're thinking of a Diana variant that departs from standard Beaufort arithmetic (like a non-standard table or modified procedure), that would be worth specifying — but standard Diana is eliminated.

**4. The keystream / MYLORD observation**

I verified both claims: the KA Vigenère keystream at the EASTNORTHEAST crib is indeed RDUMRIYWOYNKY, and decrypting MYLORD with key KRYPTO under KA Vigenère does produce MRIYWO, which sits at positions 3-8 of that keystream. The math checks out.

I have to be straightforward about the significance though. When I systematically tested 21 thematic keywords against every substring of the keystream using a standard dictionary, I found zero hits at the EAST crib — and we'd statistically expect about 3 by chance at 4-letter length alone. The MYLORD find required choosing a specific alphabet (KA), a specific cipher direction (Vigenère), a specific key (KRYPTO), a specific 6-character window, and accepting a compound word not found in standard dictionaries. With that many degrees of freedom, finding one suggestive result is probable rather than surprising.

That said, the broader idea — that K4's key is itself meaningful text encrypted with a thematic keyword — is a legitimate hypothesis. If you have a theory about what the full key-text might say (not just 6 characters), that would narrow the search considerably.

**5. The Smithsonian archive snippet / double encryption**

I verified all three steps of your chain — the math is correct. The KA-position-to-AZ mapping of DEARWW → KLHBXX, the Vigenère composition with NIXNIX to get the effective key NSFRGV, and the final encryption of SHADOW producing ZQNEMN all check out perfectly.

There's an important algebraic point worth noting: this double-encryption scheme simplifies to a single KA Vigenère with a combined key. Since Vigenère is additive, encrypting with Key1 and then Key2 is the same as encrypting once with (Key1 + Key2). So the "layers" don't add cryptographic complexity — the effective key is just one different key.

For K4 specifically: if both keys repeat (like NIXNIXNIX and DEARWW), the effective key also repeats with a period equal to the least common multiple of the two key lengths. We've mathematically proven that all repeating keys at every period are impossible for K4. If one of the keys is non-repeating (an OTP or running key), then the combined key is also non-repeating — which maps to our open running key hypothesis.

That said, I'm very interested in the Smithsonian archive snippet you're referencing (SHADOW IN THE / NIXNIXNIX / ZQ...). We don't have that specific image in our archive. Could you share it? Any working notes from Sanborn that demonstrate his actual encryption process would be extremely valuable for the community — even if this particular scheme simplifies algebraically, seeing how Sanborn worked through the problem could reveal important clues about his approach to K4.

**Summary**

I verified every mathematical claim in your email — all the arithmetic checks out, which tells me you've been doing careful work. The sculpture row-alignment idea (#2) was the most promising lead, but after exhaustive testing (7.5 million configurations) it came back as noise. The OBKR→EACH result under KA Vigenère is real but appears to be a coincidence that doesn't extend to the rest of K4.

The one thing I'd most like to follow up on is the Smithsonian archive image showing the SHADOW/NIXNIXNIX/ZQ snippet. Even though the double-encryption scheme simplifies algebraically, any working notes from Sanborn that show his actual encryption process would be extremely valuable for the community. If you could share that image, it would be a real contribution.

You can check any of these results yourself — everything is open source at github.com/jcolinpatrick/kryptos, and the full elimination database is browsable at kryptosbot.com/browse.

Best,
Colin
