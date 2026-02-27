# People, Organizations & Milestones in Hand-Cipher History

## How to Use This Timeline

A chronological reference of the people, organizations, and milestones that shaped pencil-and-paper cryptography from the Renaissance through the Cold War. Each entry notes K4 relevance and references elimination status in `docs/elimination_tiers.md` where applicable. For Kryptos-specific facts, see `docs/kryptos_ground_truth.md`. For cipher mechanics, see `20_cipher_catalog.md`.

---

## Timeline

### Era: Renaissance Origins

---

### ~1466 -- Leon Battista Alberti: The Cipher Disk

[PUBLIC FACT] Alberti described the first polyalphabetic cipher in *De componendis cifris* (~1466). His cipher disk used two concentric alphabets rotated at *irregular, encipherer-chosen* intervals -- aperiodic switching, not fixed-period like later Vigenere.

**Why it matters:** The cipher disk is the ancestor of all polyalphabetic systems. Alberti's aperiodic design is structurally closer to running-key ciphers than to periodic ones.

**K4 relevance:** [HYPOTHESIS] If K4 uses non-periodic substitution (as Bean constraints demand under additive models -- see `docs/invariants.md`), the operational concept traces to Alberti's aperiodic switching.

---

### 1518 -- Johannes Trithemius: Tabula Recta

[PUBLIC FACT] Trithemius published *Polygraphiae* (1518), the first printed cryptography book, introducing the tabula recta -- the 26x26 grid of shifted alphabets underlying Vigenere, Beaufort, and all keyed-tableau systems.

**Why it matters:** The Kryptos sculpture contains a Vigenere tableau (KA alphabet). Every tableau-based hand cipher descends from this.

**K4 relevance:** [DERIVED FACT] The Kryptos tableau has been exhaustively tested for non-standard usage across 23 experiments (E-TABLEAU-01 through E-TABLEAU-23). All eliminated. See `docs/elimination_tiers.md`, Tier 4.

---

### 1563 -- Giovanni Battista della Porta: Digraphic Ciphers

[PUBLIC FACT] Della Porta's *De Furtivis Literarum Notis* (1563) described improved polyalphabetic ciphers and the first digraphic cipher -- substituting letter *pairs* rather than individuals. Ancestor of Playfair, Four-Square, Two-Square.

**Why it matters:** Digraphic ciphers entangle adjacent letters for stronger diffusion, executable with a 5x5 grid.

**K4 relevance:** [DERIVED FACT] Standard digraphic ciphers require 25-letter alphabets (I/J merged). K4 CT contains all 26 letters (ALPHA-26), structurally eliminating these families (E-FRAC-21; `docs/elimination_tiers.md`, Tier 1). [HYPOTHESIS] Non-standard 26-letter digraphic systems remain untested as a multi-layer component.

---

### Era: Enlightenment & Early American Cryptography

---

### ~1790s -- Thomas Jefferson: The Wheel Cipher

[PUBLIC FACT] Jefferson designed a 26-disk cipher device where each disk bore a scrambled alphabet. Align one row to plaintext, transmit another row. Never deployed; rediscovered ~1920. The principle became the U.S. Army M-94 (1922-1943).

**Why it matters:** The cylinder cipher is hand-operable, polyalphabetic, and resistant to frequency analysis. Standard U.S. military equipment through WWII.

**K4 relevance:** [HYPOTHESIS] Cylinder ciphers produce periodic output (period = number of disks). All periodic substitutions are eliminated at discriminating periods (E-FRAC-35). Relevant only if combined with a transposition layer.

---

### ~1817 -- Decius Wadsworth: Non-Reciprocal Cipher Device

[PUBLIC FACT] Wadsworth designed a device with two disks of *unequal* size (26 outer, 33 inner). Unequal sizes produce irregular advancement -- an early non-reciprocal stepping mechanism, predating rotor machines.

**Why it matters:** Unequal-size alphabets create an effective period equal to the LCM of disk sizes. For co-prime sizes >97, every K4 position gets a unique key value -- functionally a running key.

**K4 relevance:** [HYPOTHESIS] Consistent with K4's non-periodic key constraint. No specific Wadsworth-type model has been tested.

---

### 1860s -- Albert J. Myer: Wig-Wag and the Signal Corps

[PUBLIC FACT] Myer founded the U.S. Army Signal Corps and developed "wig-wag" visual signaling. His organizational contribution created the institutional lineage: Signal Corps (1860) -> SIS (1930) -> ASA (1945) -> NSA (1952). CIA cryptographic capability developed in parallel from the same Cold War talent pool.

**Why it matters:** The Signal Corps tradition shaped American field-cipher culture: practical, device-oriented, emphasizing operational security over theoretical elegance.

**K4 relevance:** [PUBLIC FACT] Scheidt served in CIA, not the military signals lineage, but both communities shared doctrine and training. The "field cipher culture" is K4's operational context.

---

### 1861-1865 -- Confederate Ciphers in the American Civil War

[PUBLIC FACT] Confederates used Vigenere-based ciphers with short keywords and brass cipher disks. Union forces preferred route ciphers and transposition grids. Confederate ciphers were broken repeatedly due to short keys and poor discipline.

**Why it matters:** The Civil War demonstrated the substitution-vs-transposition duality and the lesson that combining both is stronger than either alone.

**K4 relevance:** [HYPOTHESIS] Substitution + transposition layering was standard doctrine by the 1860s. Sanborn's "two separate systems" aligns with this historical pattern.

---

### 1883 -- Auguste Kerckhoffs: Kerckhoffs' Principle

[PUBLIC FACT] Kerckhoffs published "La cryptographie militaire" (1883), establishing that a cipher must be secure even if everything except the key is public.

**Why it matters:** The foundational principle of all cryptographic design. Security resides in the key, not the algorithm.

**K4 relevance:** [PUBLIC FACT] Sanborn: "kryptos is available to all." The tableau is visible on the sculpture. [HYPOTHESIS] If Kerckhoffs' principle was followed, the method is deducible from public information; only the key is secret. This argues against entirely bespoke methods. Counterpoint: Sanborn is an artist, not a cryptographer.

---

### ~1890s -- Etienne Bazeries: The Bazeries Cylinder

[PUBLIC FACT] Bazeries reinvented the cylinder cipher (~1891), independent of Jefferson. His design became the basis for the M-94. He also broke the Great Cipher of Louis XIV by recognizing its code numbers represented syllables, not letters.

**Why it matters:** The cylinder/strip family (Jefferson, Bazeries, M-94, M-138) is a major hand-cipher branch used through WWII. Breaking the Great Cipher demonstrated that identifying the structural assumption is the key to cryptanalysis.

**K4 relevance:** [INTERNAL RESULT] Strip transposition variants tested at widths 7-13 with periodic and running-key substitution (E-JTS-09/10/11). All eliminated. See `docs/elimination_tiers.md`.

---

### Era: WWI & Professionalization

---

### 1910s-1920s -- Riverbank Laboratories

[PUBLIC FACT] George Fabyan's Riverbank Labs in Geneva, Illinois became the de facto U.S. cryptanalytic training center during WWI. William and Elizebeth Friedman began their careers there, producing the "Riverbank Publications" -- among the first systematic English-language cryptanalytic texts.

**Why it matters:** Established quantitative methods (frequency analysis, contact analysis, probable-word testing) as the standard toolkit. Every elimination in this project descends methodologically from this tradition.

**K4 relevance:** [PUBLIC FACT] The Riverbank-to-SIS-to-NSA lineage is the institutional ancestry of CIA cryptographic training. Scheidt's knowledge base includes the Friedman corpus.

---

### 1917-1929 -- Herbert O. Yardley / MI-8 (The American Black Chamber)

[PUBLIC FACT] Yardley led MI-8 (WWI) and the State Department's Cipher Bureau (1920s), breaking Japanese diplomatic codes. Shut down by Stimson in 1929. Yardley's 1931 tell-all book *The American Black Chamber* scandalized the intelligence community and led to Espionage Act amendments.

**Why it matters:** Established that nation-state hand-cipher and codebook systems could be broken systematically. The political fallout created the secrecy culture surrounding cryptanalytic capabilities.

**K4 relevance:** [PUBLIC FACT] The secrecy culture Yardley violated is the culture Scheidt operated within at CIA.

---

### 1920s-1940s -- Agnes Meyer Driscoll

[PUBLIC FACT] Navy cryptanalyst from 1918 into the 1940s. Broke the Japanese "Red Book" code (1920s), contributed to "Blue Book" and early machine cipher attacks. Trained the Navy cryptanalysts who later worked JN-25.

**Why it matters:** Her career demonstrates that hand-cipher analysis (codebooks, additive systems, transposition) was the primary cryptanalytic discipline through the 1930s. Her technique of "stripping additives" to expose underlying code exemplifies the layered-analysis approach.

**K4 relevance:** The layered-analysis approach (peel off one cipher layer to expose the next) is exactly what K4's multi-layer structure demands.

---

### 1920s-1950s -- William & Elizebeth Friedman

[PUBLIC FACT] William Friedman introduced the Index of Coincidence (1920), founded the Army's SIS (1930), and led the PURPLE break (1940). Elizebeth Friedman independently broke rumrunner and espionage ciphers and contributed to breaking Enigma variants used by South American Axis agents in WWII.

**Why it matters:** Friedman's IC remains the foundational statistical test for cipher classification. The Friedmans' analytic corpus (Kappa test, IC, symmetry of position) defines the discipline.

**K4 relevance:** [INTERNAL RESULT] K4's IC (~0.0361) is below random (0.0385) but NOT statistically significant for n=97 (z=-0.84, 21.5th percentile; E-FRAC-13). [POLICY] Do not use IC alone as a K4 discriminator.

---

### 1918-1920s -- Edward Hebern: The Rotor Machine

[PUBLIC FACT] Hebern built the first U.S. rotor cipher machine (~1918; patented 1921). The rotor concept was independently invented by Damm, Koch, and Scherbius in the same period. Rotor machines automated polyalphabetic substitution with irregular stepping and very long effective periods.

**Why it matters:** Rotor machines made hand ciphers obsolete for high-volume traffic. Post-rotor, hand ciphers survived only for low-volume, emergency, or covert use.

**K4 relevance:** [HYPOTHESIS] A hand-cipher analogue of rotor stepping (e.g., tableau with position-dependent offsets) could produce a non-periodic key -- structurally equivalent to a running key from a deterministic process. This remains an open hypothesis class.

---

### 1920s -- Alexander von Kryha: The Kryha Machine

[PUBLIC FACT] Kryha marketed elegant clockwork cipher machines from the 1920s with variable-speed gear advancement. Despite mechanical sophistication, the cryptographic security was poor -- Friedman reportedly broke a Kryha message in under three hours. Widely sold despite weakness.

**Why it matters:** A cautionary example: mechanical/procedural complexity does not equal cryptographic strength. Small effective key space = vulnerability regardless of how complex the process appears.

**K4 relevance:** [HYPOTHESIS] If K4's method is complex-looking but has a small effective key space, it may be more vulnerable than expected.

---

### Era: WWII

---

### 1943-1944 -- Thomas Flowers and Colossus

[PUBLIC FACT] Flowers built Colossus at Bletchley Park (operational February 1944) -- the first large-scale programmable electronic computer, built to break the Lorenz SZ40/42 ("Tunny"). Classified until the 1970s; ten machines built by war's end.

**Why it matters:** Machine-speed cryptanalysis made complex hand ciphers vulnerable. Cipher designers had to assume adversaries could test millions of keys.

**K4 relevance:** [HYPOTHESIS] Scheidt, with CIA clearances, would have known the classified history of computational cryptanalysis. K4's design may account for computational attack.

---

### 1943-1945 -- SIGSALY "Green Hornet"

[PUBLIC FACT] First truly secure voice system. Developed at Bell Labs, used one-time pad on vinyl phonograph records to encrypt digitized speech. Each 40-minute key record destroyed after single use.

**Why it matters:** SIGSALY demonstrated information-theoretic security in practice. Hand-cipher systems approximate this with running keys from long texts -- non-repeating, hard to reconstruct.

**K4 relevance:** [HYPOTHESIS] Running key from unknown text is the closest hand-cipher analogue to a one-time pad, and the only structured key model surviving Bean constraints (E-FRAC-38). See `docs/elimination_tiers.md`, Tier 2.

---

### Era: Cold War

---

### 1940s-1960s -- M-325 "SIGFOY"

[PUBLIC FACT] Compact, portable rotor-based cipher machine used by the U.S. State Department and Foreign Service. Designed for non-specialist operators. Smaller key space than military-grade machines.

**Why it matters:** Embodies the "field-grade" cipher philosophy: simple enough for one person to operate, secure enough for routine traffic. The same trade-off governs hand-cipher design.

**K4 relevance:** [HYPOTHESIS] Scheidt's CIA training included familiarity with field-grade devices and their hand-cipher fallbacks. The "operationally simple, adequately secure" philosophy likely influenced K4's design.

---

### 1940s-1960s -- SIGABA / ECM / TSEC/KL-7 "ADONIS"

[PUBLIC FACT] SIGABA: primary U.S. high-grade WWII cipher machine (15 rotors, 3 banks, irregular stepping). Never broken. KL-7 "ADONIS": NATO Cold War successor (1952-1983). Compromised by the Walker spy ring (key theft, not cryptanalysis).

**Why it matters:** SIGABA proved irregular stepping defeats even top adversaries. The Walker compromise proved key management is typically the weakest link -- echoing Kerckhoffs.

**K4 relevance:** [PUBLIC FACT] Scheidt served during active KL-7/SIGABA era. His cryptographic worldview reflects rotor-machine principles (irregular stepping, layered substitution) and the lesson that method security is secondary to key security.

---

### 1967 -- David Kahn: *The Codebreakers*

[PUBLIC FACT] Kahn published the first comprehensive public history of cryptography. The U.S. government attempted suppression before publication. It remains the standard pre-computer cryptographic reference.

**Why it matters:** Made cipher families publicly accessible. Anyone designing a cipher puzzle in the 1980s-90s would likely have consulted it.

**K4 relevance:** [PUBLIC FACT] Sanborn consulted published sources. [HYPOTHESIS] *The Codebreakers* is a plausible reference for both Sanborn and Scheidt -- consistent with "kryptos is available to all."

---

### Cold War Era -- Permissive Action Links (PALs)

[PUBLIC FACT] Coded-switch security devices integrated into nuclear weapons to prevent unauthorized use. Developed early 1960s under Kennedy; implemented progressively across the U.S. arsenal. Conceptually a challenge-response authentication protocol, not message encryption.

**Why it matters:** Demonstrates cryptographic principles applied to physical access control, bridging encryption and physical security.

**K4 relevance:** [PUBLIC FACT] Scheidt's career overlapped with PAL-era security culture. [HYPOTHESIS] The concept of a code controlling a physical system resonates with Kryptos as a physical encrypted object.

---

### Historical Reference Corpus -- *Dictionnaire Egyptien*

[PUBLIC FACT] Running-key ciphers use a passage from a prearranged text as key material. Historical sources include the Bible, dictionaries, and literary works. The *Dictionnaire Egyptien* (Wallis Budge) exemplifies large, publicly available reference texts suitable as running-key sources. Both parties need only agree on book, edition, and starting position.

**Why it matters:** Running-key ciphers are among the strongest hand-executable systems -- non-repeating keys with minimal distribution overhead. Their weakness (natural-language statistics) is minimal at 97 characters.

**K4 relevance:** [PUBLIC FACT] Sanborn's 2025 clues reference his 1986 Egypt trip and 1989 Berlin Wall fall. [HYPOTHESIS] A reference text related to Egypt or Berlin could be a running-key source. Running key from unknown text is the only structured model surviving Bean constraints (E-FRAC-38). Known texts eliminated (E-FRAC-49/50, E-JTS-12); unknown sources remain open. See `docs/elimination_tiers.md`, Tier 2.

---

### 1988-1990 -- Ed Scheidt, Jim Sanborn, and Kryptos

[PUBLIC FACT] Kryptos was created 1988-1990 by sculptor Jim Sanborn with cryptographic consultation from Ed Scheidt, retired Chairman of the CIA Cryptographic Center.

For full details, see `docs/kryptos_ground_truth.md`. [POLICY] All Kryptos-specific facts maintained there to avoid duplication.

---

## Era Summaries

**Renaissance to Enlightenment (1466-1800):** Foundational concepts established -- polyalphabetic substitution (Alberti), tabula recta (Trithemius), digraphic ciphers (della Porta), cylinder devices (Jefferson). All core hand-cipher ideas in place by 1800.

**19th Century (1800-1900):** Institutionalization. Wadsworth and Myer built American military crypto infrastructure. Civil War demonstrated substitution-vs-transposition duality and operational failure modes. Kerckhoffs formalized design principles. Bazeries bridged invention and professional cryptanalysis.

**WWI Era (1910-1930):** Professionalization. Riverbank trained the first Americans. Yardley proved codebreaking's intelligence value. The Friedmans introduced statistical rigor. Hebern and Kryha began the machine transition.

**WWII (1939-1945):** Industrial scale. Colossus introduced electronic computation. SIGSALY achieved information-theoretic voice security. Rotor machines (Enigma, SIGABA) dominated.

**Cold War (1945-1990):** Institutional secrecy. KL-7 and M-325 served NATO/diplomatic needs. PALs applied crypto to nuclear security. Kahn's *Codebreakers* (1967) breached the classification wall. Scheidt trained and served within this environment.

---

## Cross-References

- **Cipher mechanics and diagnostics:** `20_cipher_catalog.md`
- **K4 constraint mapping:** `30_k4_mapping_matrix.md`
- **Elimination proofs:** `docs/elimination_tiers.md`
- **Kryptos-specific facts:** `docs/kryptos_ground_truth.md`
- **Verified invariants:** `docs/invariants.md`
- **Ciphertext and cribs:** `kryptos.kernel.constants` (canonical source)

---

*Created: 2026-02-27 | Part of the Kryptos K4 Crypto Field Manual*
*Truth taxonomy: all statements labeled per CLAUDE.md policy*
