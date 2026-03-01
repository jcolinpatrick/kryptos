# Edward M. Scheidt — Comprehensive Dossier

**Compiled**: 2026-03-01
**Sources**: Smithsonian oral history (ajax.pdf), kryptosfan.wordpress.com, WIRED (Kim Zetter 2005), Intel Today, Brother Martin alumni magazine, TecSec website, patent records, Great Big Story (2019), museum research, direct Sanborn correspondence.

---

## 1. BIOGRAPHY

### Early Life & Education
- **Born**: July 20, 1939
- **High school**: Cor Jesu High School (now Brother Martin High School), New Orleans, LA — graduated 1957
- **B.A.**: University of Maryland
- **M.S.**: George Washington University
- Scheidt later reflected on Kryptos: "It took me back to the math days of Cor Jesu... the math principles were fundamentally the same as we heard over 50 years ago." [Brother Martin alumni magazine, Oct 2010]

### CIA Career (1963–1989)
- Joined CIA in **1963**, served 26 years in the **Office of Communications**
- Rose to become **Chairman of the CIA Cryptographic Center** — nicknamed "The Wizard of Codes"
- Final title: **Head of Cryptographic Programs**
- Career overlapped with: KL-7 ADONIS era, Cold War SIGINT operations, Fialka/M-105 machine exploitation, nuclear PAL systems
- Professional world: material exploitation of adversary ciphers, split-knowledge designs, operational security, source protection
- Retired **December 1989** — the same month Sanborn wrote his letter to CIA employees (Dec 15, 1989)
- Served under DCI **William H. Webster** (May 1987–Aug 1991), the "WW" referenced in K2

### Post-CIA Career
- Co-founded **TecSec, Inc.** in 1990, immediately after retirement
- TecSec HQ: Vienna, Virginia (later McLean, VA)
- Title at TecSec: **Co-Founder, Chairman of the Board**
- TecSec focus: **Constructive Key Management (CKM®)** — a patented approach where encryption keys are created at the time of encryption, destroyed, and reconstructed at the time of decryption using multiple independent "key splits"
- Developed **VEIL®** encryption technology
- Developed **P2 Algorithm** — TecSec's proprietary high-performance cryptographic algorithm
- **36 patents** in cryptographic technologies (1993–2015), primarily "Cryptographic Key Split Combiner" variants

### Key Patent Concepts (TecSec)
The patents reveal Scheidt's post-CIA cryptographic thinking:

| Patent | Title | Core Concept |
|--------|-------|-------------|
| US6542608B2 | Cryptographic Key Split Combiner | Key splits from seed data, combined with randomizer |
| US6608901B2 | Cryptographic Key Split Combiner | Multiple key split generators + randomizer + digital signature |
| US7095851B1 | Voice and Data Encryption Using Key Split Combiner | Key splits applied to voice/data streams |
| US7738660B2 | Cryptographic Key Split Binding Process | Binding process linking splits to identity/authorization |
| US8712046B2 | Cryptographic Key Split Combiner | Plurality of generators + split randomizer + signature generator |
| US20090097657A1 | Constructive Channel Key | D-H key agreement, ephemeral keys, shared value → 4-block split |

**Core TecSec principle**: A single encryption key is never stored or transmitted whole. It is **split** into independent components from different sources, combined at encryption time, and reconstructed from the splits at decryption time. The splits themselves come from different "generators" — some identity-based, some random, some derived from organizational hierarchy.

**Relevance to K4**: The split-knowledge architecture of CKM is conceptually parallel to the Sanborn/Scheidt collaboration where neither party holds the complete solution alone. It also resonates with Scheidt's ACA talk statement about "receiver identity protection built into the process."

---

## 2. RELATIONSHIP WITH SANBORN AND KRYPTOS

### How They Connected
- CIA's General Services Administration art contract required "buy American" expertise
- Sanborn: "Who better to stump the chumps than a former stumper? ..... Enter Edward Scheidt." [Smithsonian archive, p.25-26]
- "Ed had retired from the Agency to start his own crypto based security company." [Smithsonian archive]
- Sanborn initially wanted an outside cryptographer (MI5/MI6, Mossad, etc.) but the GSA contract required US expertise

### The Teaching Sessions
- **Only 2-3 meetings** between Scheidt and Sanborn [Smithsonian oral history, ajax.pdf p.45]
- Met at secret locations: "We met on secret occasions... I didn't like going to his office." [Sanborn, ajax.pdf p.44]
- Sanborn: "Ed basically gave me a primer of ancient encoding systems. And he also gave me some ideas for contemporary coding systems, more sophisticated systems, **systems that didn't necessarily depend on mathematics**." [ajax.pdf p.45]
- "He told me about **matrix codes** and things like that... **coding systems that I could then modify in a myriad of ways**." [ajax.pdf p.45]
- Scheidt to WIRED (2005): "I provided the cryptographic process as well as worked with him with what he was looking to do as far as the story (the sculpture would tell). We came up with a methodology using some of the **known cryptographic solutions (at the time)**."
- Brother Martin magazine: Scheidt taught Sanborn "**substitution, shifting matrices, transposition, etc.**"

### Split Knowledge — Who Knows What
- Sanborn: "I made that very clear that I didn't want him to be able to decipher what's going on." [WIRED 2005]
- Scheidt: "I know what the message _was_ to be. (But) since he's the one who had the chisel in his hands, there could be some changes." [WIRED 2005]
- Scheidt expressed surprise that he might not know the full solution — "he hadn't heard Sanborn make such claims before"
- Scheidt (Intel Today, 2019): "After Jim finished the sculpture, I never went back to check the code."
- **Implication**: Scheidt designed the METHOD but Sanborn chose the PARAMETERS (keywords, specific settings). Scheidt could decrypt IF he had the parameters, but he never received them.

### The Kryptos Dedication (November 3, 1990)
- Sanborn: "There are two systems of enciphering the bottom text. No one really asked me if there are two systems to encipher the bottom text until today at sort of the eleventh hour, and yes, there are **two separate systems** and that is **a major clue in itself**, apparently." [Oral history transcript, kryptosfan findings]

---

## 3. SCHEIDT'S DIRECT STATEMENTS ABOUT K4

### On the Masking Technique (WIRED 2005, Kim Zetter)
> "The first three processes were designed so that a person could... have access to the English language... And the last process, **I masked the English language so it's more of a challenge now**."

> "I disguise that. So... **you need to solve the technique first and then go for the puzzle**."

**Interpretation**: K1-K3 allow frequency analysis to detect English through the cipher. K4's masking layer **destroys the frequency signature** of English, requiring solvers to identify and remove the mask before standard cryptanalysis can work.

### On Frequency Analysis
> "Frequency analysis and competence with the English language are aids to K1-3 but **will not help a solver with K4**." [kryptosfan methods page]

### On Medieval Guilds (ACA Banquet, Oct 2013)
- Discussed how medieval guilds protected trade secrets using "**code circles/rings** that were fixed in place"
- Keywords enabled authorized guild members to decrypt materials
- **Scheidt's mental model**: physical devices with fixed structures + keyword-based access
- This may be the conceptual basis for K4's "bespoke" system

### On IDBYROWS vs LAYERTWO (ACA Banquet, Oct 2013)
> "May not have been a mistake after all. **Sometimes in spycraft you deliberately do these things.**"

**Interpretation**: The physical sculpture's reading (IDBYROWS) vs Sanborn's stated intent (XLAYERTWO) could be a deliberate divergence — a "duress indicator" or intentional ambiguity built into the system.

### On Receiver Identity (ACA Banquet, Oct 2013)
> "After part IV is decrypted, the next thing to figure out is **how the receiver's identity is kept hidden**. Ed said that **this was built into the process**, but gave no clues as to how it is done."

**Interpretation**: K4's encryption method contains an authentication/identity layer — the cipher doesn't just encrypt a message, it also conceals WHO the message is for. This is consistent with CKM's identity-binding key split architecture.

### On Whether K4 Uses a Known System (ACA Convention, Oct 2013)
- Elonka Dunin reminded Scheidt that "he once told her that **Kryptos uses a system unknown to anyone on the planet**"
- Scheidt: "didn't recall that conversation, and back-pedaled out of saying anything more"
- When asked if K4 was a "one-off": Scheidt looked to Sanborn and said "well Jim, how are we going to answer that one?" Sanborn: "we don't answer it."

### On NSA Attempts
- Sanborn (via direct correspondence, Feb 2026): "I generally don't answer method questions, suffice it to say the **NSA tried many layered systems on it**."
- **Implication**: Standard multi-layer approaches (the kind NSA would try systematically) have FAILED. Whatever Scheidt's "invention" is, it's not a standard composition of known layers.

---

## 4. THE GILLOGLY REVELATION

Jim Gillogly (co-solver of K1-K3, 1999), responding to fan questions on kryptosfan:

> **"K4 employs an invention by creator Ed Scheidt that has never appeared in cryptographic literature."**

This is the single most important external statement about K4's nature:
1. The method is **BESPOKE** — not found in any published cipher taxonomy
2. It was **INVENTED by Scheidt** specifically for Kryptos
3. It **explains** why all 370+ experiments testing standard cipher families produce noise
4. It does NOT mean the method is computationally complex — it could be a novel combination or application of known principles that Scheidt assembled in an unprecedented way

Gillogly also raised the possibility that K4 might incorporate **duress cipher principles** — allowing multiple valid decryptions yielding credible plaintext.

---

## 5. WHAT SCHEIDT TAUGHT SANBORN — SYNTHESIS

From all sources, Scheidt's curriculum for Sanborn included:

| Topic | Source | Relevance to K4 |
|-------|--------|-----------------|
| Vigenère tableau | ajax.pdf p.45, 1989 letter | Used for K1/K2; tableau physically present on sculpture |
| Substitution ciphers | Brother Martin magazine | Foundation of polyalphabetic systems |
| Transposition ciphers | Brother Martin magazine | K3 uses transposition |
| "Shifting matrices" | Brother Martin magazine | Matrix-based operations (grid transpositions?) |
| "Matrix codes" | ajax.pdf p.45 | Unspecified matrix-based system |
| "Systems that didn't depend on mathematics" | ajax.pdf p.45 | Physical/procedural methods |
| "Coding systems that could be modified in myriad ways" | ajax.pdf p.45 | Parameterizable frameworks |
| Medieval guild code circles/rings | ACA talk 2013 | Fixed physical device + keyword access |
| Masking/steganography | WIRED 2005, kryptosfan | K4 specifically: mask that hides English frequency |
| Strip cipher principles | Museum visit analysis | Bridge between substitution and transposition |
| Duress indicators / spycraft | ACA talk 2013 | IDBYROWS, misspellings as deliberate signals |
| Receiver identity protection | ACA talk 2013 | Authentication layer "built into the process" |
| Key split / split knowledge | TecSec patents, PAL parallels | Neither Scheidt nor Sanborn holds complete solution |

---

## 6. SCHEIDT'S CRYPTOGRAPHIC PHILOSOPHY

### Core Principles (derived from all sources)

1. **Split knowledge is fundamental**: No single party should hold the complete key. This is the architecture of CKM, PAL nuclear codes, and the Sanborn/Scheidt collaboration itself.

2. **Process over mathematics**: "Systems that didn't necessarily depend on mathematics" — Scheidt valued procedural/physical cryptographic methods alongside mathematical ones.

3. **Masking defeats frequency analysis**: The explicit purpose of K4's design is to make English language statistics invisible. This isn't just encryption — it's a deliberate pre-processing step.

4. **Authentication is embedded**: "Receiver identity protection was built into the process" — the cipher does more than encrypt; it authenticates.

5. **Physical devices inspire method**: Guild code circles, strip ciphers, shifting matrices — Scheidt thinks in terms of physical manipulations that can be performed by hand.

6. **Known principles, novel combination**: "Known cryptographic solutions (at the time)" assembled in a way that "has never appeared in cryptographic literature" — familiar building blocks, unprecedented architecture.

7. **Deliberate ambiguity as tradecraft**: "In spycraft you deliberately do these things" — errors, contradictions, and divergences may be intentional signals, not mistakes.

---

## 7. IMPLICATIONS FOR K4 SOLVING

### What Scheidt's bespoke system likely IS:
- A **novel combination** of known primitives (substitution + transposition + masking) assembled in an unprecedented way
- **Hand-executable** — Sanborn performed it with a chisel and working notes on a yellow legal pad
- Involves a **masking pre-processing step** that destroys English frequency signature BEFORE encryption
- Incorporates **identity/authentication** in the cipher process itself
- Uses **keywords** (plural) as the primary parameterization
- Can be described conceptually as a "**code circle/ring fixed in place with keyword access**"

### What Scheidt's system likely IS NOT:
- Any single standard cipher family (all exhaustively tested, all NOISE)
- A purely mathematical construction (Scheidt: "didn't depend on mathematics")
- Something requiring computers (1989 design, hand-executed)
- A standard multi-layer composition (NSA tested those, per Sanborn)

### The two-step model:
1. **MASKING**: Pre-process the plaintext to destroy English frequency characteristics (vowel removal? phonetic respelling? null insertion? character substitution? — specific method unknown)
2. **ENCRYPTION**: Apply a cipher to the masked text using the Vigenère tableau or a matrix-based method with keyword(s)

This matches Scheidt's WIRED statement: "you need to **solve the technique first** [unmask] and then **go for the puzzle** [decrypt]."

### Critical constraints from Scheidt:
- Frequency analysis will NOT help
- The system is "unknown to anyone on the planet" (per Elonka's recollection, which Scheidt declined to confirm or deny)
- "Known cryptographic solutions at the time" — pre-1989 methods, manually executable
- "Matrix codes" and "systems that could be modified in myriad ways" — parameterizable grid/matrix operations
- Two separate systems (Sanborn's confirmation)
- Receiver identity protection built in

---

## 8. OPEN QUESTIONS

1. **What specific "matrix codes" did Scheidt teach Sanborn?** — The term could refer to Hill cipher matrices, Polybius squares, grid transpositions, or something else entirely.

2. **What is the "guild code circle/ring" model concretely?** — Is this a cipher disk? A tabula recta variant? A physical device concept?

3. **How does "receiver identity protection" manifest in 97 characters?** — Is there a verification checksum? A second valid decryption? A hidden address?

4. **Did Scheidt's TecSec "key split" thinking influence K4?** — CKM was developed 1990+ (after K4), but the conceptual framework of splitting keys into independent components predates TecSec.

5. **What masking technique specifically destroys English frequency?** — Vowel removal, phonetic encoding, null cipher, character mapping? Each has different computational signatures.

6. **What is the relationship between K4's method and the $962,500 auction "coding charts"?** — The charts show "the process" but we haven't seen them. The auction buyer is anonymous.

7. **Does Scheidt still confirm the solution as originally designed?** — He said "I never went back to check the code" after Sanborn finished. Did Sanborn change something?

---

## 9. SOURCE INDEX

| Source | Date | Key Content |
|--------|------|-------------|
| Smithsonian oral history (ajax.pdf, pp.44-45, 52, 79) | 2009 | "Matrix codes," "systems not depending on math," 2-3 meetings, split knowledge |
| Smithsonian archive memoir (smithsonian_archive.md) | 2009 | "Enter Edward Scheidt," "former stumper," John Le Carré attempted |
| Sanborn 1989 CIA letter (letter1.jpg + letter2.jpg) | Dec 15, 1989 | "Potentially challenging encoding system," "prominent fiction writer" |
| Sanborn oral history transcript (Letter_1.jpg) | ~Nov 1990 | "Two separate systems," "a major clue in itself," four copper sheets |
| Kim Zetter, WIRED (via kryptosfan) | Jan 21, 2005 | "I masked the English language," "solve the technique first" |
| ACA Convention Q&A (kryptosfan) | Oct 28, 2013 | "System unknown to anyone on the planet" (Elonka recall), "we don't answer it" |
| ACA Banquet Talk (kryptosfan) | Oct 30, 2013 | Medieval guilds, code circles, IDBYROWS deliberate, receiver identity, no recording |
| Brother Martin alumni magazine | Oct 2010 | "Substitution, shifting matrices, transposition," Cor Jesu math connection |
| Intel Today | Nov 2019 | "I don't know the answer," "never went back to check the code" |
| Great Big Story (YouTube) | Jul 2019 | Sanborn: "It's a real code, it's a real cipher. It's solvable." |
| TecSec website | Current | 36 patents, CKM, VEIL, P2 algorithm, key split architecture |
| Patent records (Google Patents) | 1993-2015 | Key split combiners, binding processes, constructive channel keys |
| Sanborn direct correspondence (Feb 2026) | Feb 14, 2026 | "NSA tried many layered systems on it," "kryptos is available to all" |
| Jim Gillogly (kryptosfan) | ~2013 | "Invention by Ed Scheidt never appeared in cryptographic literature" |
| kryptosfan methods/masking pages | 2013-2014 | "Frequency analysis will not help with K4," masking vs English analysis |
| Museum visit analysis (museumvisit.md) | 2026 | Strip ciphers, KL-7, PAL split-knowledge parallels |

---

*This dossier represents the most comprehensive compilation of publicly available information about Edward M. Scheidt's role in the Kryptos encryption. Last updated: 2026-03-01.*
