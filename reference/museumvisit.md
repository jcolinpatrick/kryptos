# National Cryptologic Museum — Material Culture Brief for K4 Analysis

**Compiled:** February 27, 2026  
**Source:** Photographic survey by Colin Patrick, NCM visit Feb 2026  
**Purpose:** Claude Code project context — grounds computational cryptanalysis in the physical/historical tradition that produced K4's creators and their methods

---

## Why This Document Exists

Kryptos K4 was created by sculptor Jim Sanborn working with retired CIA crypto chief Ed Scheidt. Both men come from traditions where cryptography is a **physical, manual, tactile process** — not a mathematical abstraction. This document catalogs artifacts from the National Cryptologic Museum that illustrate those traditions, organized by what each artifact teaches about how K4 might work.

The NCM is located at Fort Meade, adjacent to NSA headquarters — literally the institutional home of the people who have also been trying to solve K4 for 35+ years.

---

## Part 1: The Polyalphabetic Substitution Lineage

### 1.1 Trithemius — *Polygraphiae Libri Sex* (1518)

**What it is:** The first printed cryptologic work. The pages on display show the "Quarta figura" and "Quinta figura" (4th and 5th expansion tables) of the tabula recta — the first known square table for polyalphabetic substitution.

**What it teaches for K4:**
- Polyalphabetic substitution was conceived as a **physical lookup process**: run your finger down the left column to find the key letter, across to the plaintext letter, read the ciphertext at the intersection.
- Sanborn's Kryptos tableau (on the sculpture itself) IS a tabula recta. It is not decorative — it is the encryption tool.
- The exhibit label notes Trithemius "was suspected of witchcraft" for his work in "secret languages." Sanborn has similarly cultivated an aura of mystery around his methods.

**Computational implication:** Any cipher model for K4 should be expressible as a series of tableau lookups. If a proposed method cannot be performed by looking things up in the Kryptos tableau, it is less likely to be correct.

### 1.2 Riverbank Publication No. 21 — "Methods for the Reconstruction of Primary Alphabets" (1918)

**What it is:** William Friedman's foundational paper on recovering keyword-mixed alphabets from secondary alphabets. The displayed copy shows a modified Vigenère table built from keyword "Stenography" — the PRIMARY ALPHABET (keyword-mixed row) generates all SECONDARY ALPHABETS as cyclic shifts. Example encipherment uses keyword CARGO on plaintext "General Pershing has..."

**Friedman's handwritten inscription (1 September 1962) in the copy given to David Kahn via Donald D. Millikin reads:** "This is a copy of the very first piece I wrote on the subject of cryptology. It was published anonymously — Colonel Fabyan [R.I.P.] didn't believe in giving credit for authorship..." He identifies it as "the first paper in cryptologic literature dealing with the subject of reconstructing primary alphabets by a study of the spatial relationships existing among the letters of the secondary alphabets."

**What it teaches for K4:**
- **Keyword-mixed alphabets are the norm, not the exception** in the American classical tradition. A straight A-Z alphabet is the special case. The Kryptos tableau uses KRYPTOSABCDEFGHIJLMNQUVWXZ — a keyword-mixed alphabet.
- Friedman's method exploits that all secondary alphabets are cyclic shifts of the same primary. This is exactly the structure of Quagmire-family ciphers.
- With 24 known plaintext-ciphertext pairs, Friedman's method should be applicable to K4 **if we get the transposition layer right first**. The spatial relationships between letters at known positions can reveal the primary alphabet.

**Computational implication:** Always test keyword-mixed alphabets first. Never assume standard A-Z. The Kryptos alphabet (with its I/J collapse to 25 letters, or its specific 26-letter ordering) is the default hypothesis for K4.

### 1.3 The 25-Letter Alphabet Convention

**What the Riverbank "General Directions" sheet shows:** Standard letter forms ABCDEFGHIJKLMNOPQRSTUVWXYZ and 1234567890 for cipher work. The Friedman school treated these as canonical.

**What it teaches for K4:**
- The I/J collapse (treating I and J as one letter, yielding a 25-letter alphabet) is standard in classical American military cryptography.
- The Kryptos alphabet appears to collapse I/J into a single position. Any cipher implementation should handle this correctly.
- Lowercase letters "are rarely used in cipher work, if ever." Kryptos uses all uppercase.

---

## Part 2: Strip Ciphers and Physical Transposition

### 2.1 Friedman's Strip Cipher Patent (1946)

**Evidence:** In a letter to David Kahn dated September 1947, Friedman mentions "the patent issued me in 1946 (not 1947) on a strip cipher device" and responds to Kahn's suggestions about more complicated usage. Friedman notes these devices are "not available for purchase, rental or loan" and suggests Kahn could "make one yourself."

**What it teaches for K4:**
- Strip ciphers are the **bridge between substitution and transposition**. They perform both simultaneously through physical manipulation.
- A strip cipher works by: (1) writing plaintext across strips bearing mixed alphabets, (2) aligning strips so plaintext reads correctly, (3) reading a different row as ciphertext.
- If the strips are also physically rearranged (shuffled), this adds a transposition layer on top of substitution.
- Scheidt, as CIA's former Chief of Cryptographic Programs, would certainly know about Friedman's strip cipher work. Sanborn has mentioned using "strips" in his process.

**Computational implication:** The two-layer hypothesis (transposition + substitution) may not be decomposable into independent sequential operations. A strip cipher performs both layers as a single physical process. The correct framing might be: find the strip arrangement that satisfies both layers simultaneously, rather than searching for transposition first, then substitution.

---

## Part 3: Cipher Machines — What Scheidt Knew

### 3.1 Enigma (3-rotor Wehrmacht and 4-rotor Kriegsmarine M4)

**What's displayed:** A standard 3-rotor Enigma with QWERTZUIO keyboard layout, and a 4-rotor M4 variant (serial #212) with handwritten rotor settings on tape.

**What it teaches for K4:**
- Enigma's core operation is polyalphabetic substitution with irregular stepping. Each keypress advances the rightmost rotor, with "double-stepping" of middle rotors at notch positions.
- The alphabet is **self-reciprocal** due to the reflector — pressing A might light B, and pressing B will light A. This is NOT the case for standard Vigenère, but IS a property of Beaufort ciphers.
- Enigma was broken through cribs (known plaintext), which is exactly our approach to K4. The crib-based constraint method is historically validated for attacking polyalphabetic systems.

### 3.2 Kryha Cipher Machine (1920s–1950s)

**What's displayed:** Alexander von Kryha's rotary device with keyword "HYDRAULIC" set on the outer ring.

**What it teaches for K4:**
- The Kryha uses **variable-step advancement** — the inner wheel advances by different amounts depending on pin positions. This produces a non-periodic, non-uniform keystream from a mechanical device that is nonetheless deterministic and keyword-initialized.
- K4's anomalously low Index of Coincidence (0.0361) is consistent with a cipher producing near-uniform ciphertext distribution. A Kryha-like variable-step substitution would explain why periodic analysis fails while remaining keyword-based.
- However, Kryha's mechanical complexity contradicts Sanborn's "pencil and paper" constraint.

### 3.3 KL-7 ADONIS (1952)

**What's displayed:** TSEC/KL-7, code-named ADONIS. 8 rotors, 7 moving in a complex pattern, one non-moving rotor in the middle of the stack. This particular unit was captured by the Viet Cong during the Vietnam War, turned over to the Soviets, analyzed in Poland, and returned to NSA by Polish officials in 2000.

**What it teaches for K4:**
- The KL-7's irregular stepping motion was designed to defeat cryptanalytic attack. Complex stepping produces non-periodic keystreams — conceptually similar to what Gromark/Vimark recurrences attempt to model.
- Scheidt's career at CIA overlapped with the KL-7 era. He would have been intimately familiar with irregular-stepping rotor machines and their properties.
- The KL-7's design principle — making the stepping pattern itself the primary source of security — is relevant to understanding what Scheidt might have taught Sanborn about "making codes."

### 3.4 Japanese RED Cipher Analog (1930s)

**What's displayed:** The first hand-operated analog used by SIS to decrypt the Japanese Type-A diplomatic cipher machine. Brass disk device with rotating wheels.

**What it teaches for K4:**
- SIS (Friedman's organization) solved RED by building a functional analog of the cipher machine from intercepted traffic analysis alone — without ever seeing the actual device.
- This is methodologically parallel to what we're attempting with K4: reconstructing the encryption method from ciphertext and cribs without knowing the actual process.

### 3.5 Soviet Machines — Fialka and M-105

**What's displayed:** A Soviet Fialka cipher machine (with Cyrillic keyboard showing dual-character keycaps) and an M-105 captured by the 82nd Airborne at the "Calliste" Cuban base camp during the Grenada invasion (28 Oct 1983, captured by LTC Flynn, G2 82nd ABN).

**What it teaches for K4:**
- The M-105 capture illustrates the "material exploitation" mindset of Cold War SIGINT — Scheidt's professional world. The exhibit label: "Getting your hands on an adversary's cipher is a great way to learn how to defeat their technology."
- The Fialka's Cyrillic dual-character keyboard shows that cipher machines can operate on non-Latin alphabets and character sets. K4's known plaintext includes "BERLIN" and "CLOCK" — the German/Cold War thematic connection runs deep.

### 3.6 Nuclear Command and Control Crypto

**What's displayed:**
- **TSEC/KI-22:** First cryptographic system for Minuteman III ICBM communications
- **KI-21/Z-AEM/TSEC:** Airborne Launch Control Center (ALCC) code processor for nuclear launch orders
- **Permissive Action Link (PAL):** Nuclear weapon access control — combination split between two team members
- **KG-84 DLED:** Adopted after Walker spy ring compromised multiple US crypto systems

**What it teaches for K4:**
- The PAL's **split-knowledge design** (combination divided between two team members, neither having the complete code) is architecturally parallel to Sanborn and Scheidt each contributing separate steps to K4.
- These devices represent the absolute highest-stakes application of the cryptographic tradition Scheidt came from. K4 was designed by someone who understood that the strength of a cipher depends on the process being correct at every step.

---

## Part 4: Operational SIGINT History

### 4.1 Civil War Signal Intelligence

**What's displayed:**
- **Signal Corps, U.S.A. messages from Kensaw Mountain** (June 1864): Field intelligence transmitted by flag signal
- **Army Signals by Myer**: The foundational American military signaling manual
- **Confederate letter from Charles Marshall (Lt. Col., aide to Gen. Lee) to Lt. Gen. Jubal Early, 31 August 1864:** "General Lee directs me to enclose the enemy's Signal alphabet as deciphered by some of our signal Corps here. We read their messages with facility, and the General thinks it may be of service to you — but advises that care be taken to conceal the fact of our Knowledge of the alphabet. The enemy also reads our messages, and the General suggests that your signal men be put on their guard to prevent the enemy obtaining information by that means."

**What it teaches for K4:**
- The Marshall letter is the earliest documented American example of **protecting a SIGINT source** — knowing the enemy's cipher but concealing that knowledge. This is the operational security principle that runs through everything from Ultra to modern capabilities, and it's the world Scheidt lived in.
- Both sides reading each other's signals — mutual cryptanalysis — shows that even simple flag-signal systems create a cat-and-mouse dynamic. K4 was designed with awareness that cryptanalysts would attack it.

### 4.2 The American Black Chamber — Manuscript

**What's displayed:** Herbert O. Yardley's original typed chapter list for *The American Black Chamber* with handwritten word counts in margins. Chapters cover the State Department Code Room, Secret Inks, Soviet Spies, Japanese Secret Codes, the Washington Naval Conference.

**What it teaches for K4:**
- Yardley's book (published 1931) was the first public exposé of American codebreaking. It caused a scandal and led to legislation criminalizing publication of classified cryptologic information.
- The tension between secrecy and public knowledge is the same tension that Kryptos embodies: a cipher on the grounds of the CIA, meant to be solved by the public. Sanborn is operating in Yardley's tradition of making the secret visible.

### 4.3 Bible Collection (Codebreaking Reference Library)

**What's displayed:** Bibles in multiple languages (Amharic, Bislama, Russian, Portuguese, Malagasy, Hinigaunon) used as reference material for codebreakers working on foreign-language intercepts.

**What it teaches for K4:**
- Codebreakers need reference texts in the target language to verify decryptions and identify plaintext patterns. For K4, the "target language" is English, and the known plaintext fragments ("EAST NORTHEAST," "BERLIN CLOCK") establish both language and thematic domain (Cold War geography/intelligence).

### 4.4 Norwegian One-Time Tape Machine

**What's displayed:** A tape-based cipher device presented to NSA's Cryptologic Museum by Norway's Chief of Defense Security, BRIG Hans Dramstad, 02 May 1996. Features KEYBD/CIPHER/SEND selector and a large reel of punched tape.

**What it teaches for K4:**
- One-time tape systems represent the theoretically unbreakable end of the cipher spectrum. K4 is NOT a one-time pad (it uses a keyword-based method that is "simple and memorable").
- However, the physical tape format — a long strip with punched holes — is conceptually related to strip ciphers and to the way text might be written on physical strips for transposition.

---

## Part 5: German Naval Cryptography (The Berlin Connection)

### 5.1 Kriegsmarine Signal Book and Corrections

**What's displayed:**
- **"Abzeichen bei Tage"** (Daytime Insignia): Naval signal reference showing flag meanings for letters A-Z, numerals, and special signals
- **October 1944 correction sheets** (Deckblätter Nr. 1-8, Handschriftliche Berichtigungen Nr. 1-52) for the Marineliste des Signalbuches, M.Dv. Nr. 150a
- **Page 32a:** Flag-signal designations V701-V745 mapping to three-letter codes (OLA through OMR)

**What it teaches for K4:**
- The codebook format — structured lookup tables mapping signals to meanings — is conceptually parallel to how the Kryptos tableau functions.
- The correction sheets show how codebooks were maintained in the field: handwritten amendments, numbered replacement pages, verification checksums. This is the operational context for "coding charts" like the ones sold at auction from Sanborn's archives.
- The three-letter code structure (OLA, OLB, OLC...) shows systematic code construction. The Kryptos tableau similarly has systematic structure.
- **The BERLIN connection is explicit.** K4's known plaintext contains "BERLIN" and "CLOCK" — the Weltzeituhr (World Time Clock) in Berlin's Alexanderplatz. German naval crypto is part of the same thematic universe.

---

## Part 6: Key Principles for Claude Code K4 Work

### 6.1 Physical-Process Primacy
Every artifact in this museum demonstrates that pre-computer cryptography was a physical, manual, tactile process. Ciphers were designed around what human hands and eyes could do with paper, pencils, strips, disks, and grilles. K4 was created by a sculptor and a retired CIA officer working together physically. **Any proposed K4 method must be executable by hand with simple physical tools.**

### 6.2 The 25/26 Letter Alphabet
The I=J collapse is standard in the American classical tradition (Riverbank onward). The Kryptos alphabet KRYPTOSABCDEFGHIJLMNQUVWXZ may use either 25 or 26 letters depending on interpretation. Always test both.

### 6.3 Keyword-Mixed Alphabets Are Default
Every Riverbank publication, every Friedman method, assumes keyword-mixed alphabets as the standard operating case. A straight A-Z alphabet is the special case. **Always test keyword-mixed alphabets first.**

### 6.4 Strip Ciphers Bridge Substitution and Transposition
This is the single most important conceptual insight for K4. A strip cipher is not "substitution then transposition" as two separate operations — it is a single physical process that achieves both simultaneously. If K4 uses something strip-like, the two-layer decomposition may need to search both layers jointly.

### 6.5 Crib-Based Attack Is Historically Validated
From Enigma to PURPLE to the present day, known-plaintext attacks are the standard method for breaking polyalphabetic systems. K4's 24 known positions are a rich crib set — more than enough to constrain most classical cipher families, if the positional correspondence is correct.

### 6.6 Split Knowledge = Two-Layer Architecture
The PAL's split-knowledge design (code divided between two people) maps directly to the Sanborn/Scheidt collaboration model. Each contributed a separate step. Neither person alone holds the complete method. This supports the two-layer cipher hypothesis.

### 6.7 The Adversary Has Professional Resources
K4 was installed at CIA headquarters. NSA has been working on it. Sanborn told us "The NSA tried many layered systems on it." Whatever K4's method is, it has resisted professional cryptanalytic attack for 35 years. The solution is either genuinely novel, uses an unusual combination of known techniques, or relies on a physical/visual process that computational approaches have difficulty modeling.

---

## Artifact Index

| # | Artifact | Date | K4 Relevance |
|---|---------|------|-------------|
| 1 | Trithemius *Polygraphiae Libri Sex* | 1518 | First tabula recta; ancestor of Kryptos tableau |
| 2 | Riverbank "General Directions" | ~1917 | Standard alphabet forms; I/J convention |
| 3 | Riverbank Cipher Problems No. 3–4 | ~1917 | Training exercises in transposition |
| 4 | Friedman → Kahn letters | Sep–Oct 1947 | Strip cipher patent; Riverbank Publications |
| 5 | Riverbank Pub. No. 21 | 1918 | Primary alphabet reconstruction from secondary |
| 6 | Friedman inscription | 1 Sep 1962 | First paper on spatial relationships in alphabets |
| 7 | Army Signals (Myer) | Civil War | Origins of American military SIGINT |
| 8 | Civil War Signal Corps messages | Jun 1864 | Field cipher in operational use |
| 9 | Marshall → Early letter | 31 Aug 1864 | Earliest US source protection doctrine |
| 10 | Yardley *American Black Chamber* MS | ~1930 | Secrecy vs. public knowledge tension |
| 11 | Bible collection | Various | Codebreaking reference library |
| 12 | Enigma (3-rotor and M4) | WWII | Crib-based attack methodology |
| 13 | Kryha cipher machine | 1920s | Variable-step keyword-based device |
| 14 | Japanese RED analog | 1930s | Reconstructing method from traffic alone |
| 15 | Kriegsmarine signal book | 1944 | Codebook structure; Berlin connection |
| 16 | Soviet Fialka | Cold War | Cyrillic dual-alphabet machine |
| 17 | Soviet M-105 (Grenada capture) | Oct 1983 | Material exploitation; Scheidt's era |
| 18 | KL-7 ADONIS | 1952 | Irregular stepping; Scheidt's world |
| 19 | KG-84 DLED | 1983 | Post-Walker crypto transition |
| 20 | TSEC/KI-22 | Cold War | Minuteman III ICBM crypto |
| 21 | KI-21/Z-AEM | 1970s | ALCC nuclear launch crypto |
| 22 | Permissive Action Link (PAL) | 1960s–80s | Split-knowledge design → two-layer K4 |
| 23 | Norwegian one-time tape machine | 1996 gift | Tape/strip physical format |

---

*This document should be included in Claude Code project context for any K4 analysis session. It provides the physical and historical grounding that purely algorithmic descriptions lack.*
