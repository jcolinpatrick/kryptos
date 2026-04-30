# CIA Public Affairs Kryptos Memo — December 1996

**Epistemic status:** Tier-3 hearsay. This is a 1996 CIA Public Affairs
handout mailed in response to an ACA inquiry. It is not a Sanborn /
Scheidt statement and not a declassified internal NSA/CIA document. Its
claims about the four encryption systems are the CIA Public Affairs
office's best-effort summary c. 1996 and include at least one objectively
incorrect diagnosis (K1 labelled "Digraphic" when it is in fact a
Quagmire III polyalphabetic). Treat every cipher-system claim below as
community hearsay with a known-wrong track record, per
`feedback_sanborn_epistemic_weight.md`.

**Provenance chain:**
- An ACA-er called the CIA Public Affairs office c. late 1996 and asked
  for any information on the Kryptos sculpture.
- Two pages arrived in the mail. The ACA-er transcribed them and posted
  the transcription to `und.nodak.edu`'s cryptography archive.
- That transcription was re-posted by Jim Gillogly to cypherpunks in
  June 1999 and has been mirrored repeatedly since.
- The version used here is the transcription archived in
  `doranchak/kryptos` repo at
  `info-and-articles/cia-art-kryptos.txt` (retrieved 2026-04-21). See
  `MEMORY.md` under "Reference" and this file's provenance block.

**Why it's worth preserving anyway:**
1. It is contemporaneous (1996) with K1's solve and pre-dates every
   modern Sanborn/Scheidt clue. So its errors are informative as a
   baseline of what was known/guessed before the solves.
2. It confirms that at least one CIA office believed K4 was a
   "one-time-pad" system in 1996. This is pre-solve speculation and
   should NOT be cited as a Sanborn/Scheidt statement, but it shows
   the OTP hypothesis was in circulation inside CIA in 1996.
3. It lists the Morse-code phrases on the metal sheets. These are
   physical-installation anchors and match the canonical Morse
   inventory in `docs/anomaly_registry.md`.

---

## Transcription

> Dec 1996
> from: (through US postal channels)
>      CIA
>      Public Affairs
>      Washington, DC 20505
>
>      phone number (703)-482-1100
>  they won't discuss it over the phone!
>  just ask for "available information on KRYPTOS sculpture"

### SANBORN SCULPTURE — The Art of Cryptography

KRYPTOS, that peculiar sculpture in the courtyard area of the headquarters
complex, has raised many eyebrows and questions ever since its installation.
Undoubtedly its most intriguing aspect is the riddle of its hidden message.
What could it be?

Though few persons other than the author know the answer for certain, many
have contemplated the question. We would like to pass on what knowledge we
have gained from our cryptanalysis regarding the message.

It is probable, from analysis of the letter distribution, that **at least four
separate systems of encryption have been employed: Digraphic, Poly-alphabetic,
Transposition, and One-Time-Pad.**

**System 1 — Digraphic** (guessed to apply "EMUFPH..." to "...GWHKK?"):
"This method substitutes two letters for one letter, or even a whole syllable
or word (e.g., JK=g, or FE=ible)."

> **Note 2026-04-21:** This diagnosis is wrong. K1 is a Quagmire III
> polyalphabetic with keyword KRYPTOS and cycleword PALIMPSEST,
> confirmed by Stein (Feb 1999) and Gillogly (Jun 1999). Logging the
> error here because it's the primary reason the CIA-memo claims
> about K2/K3/K4 must also be treated as pre-solve speculation.

**System 2 — Polyalphabetic** (from approximately "DQMCPF..." up to
"...JLLAETG"): "In this system, multiple alphabets (we suspect four or
eight) are used to substitute different letters for the same letters in the
original text."

> **Note:** The "four or eight alphabets" guess is wrong — K2 uses a
> Quagmire III with the same KRYPTOS-mixed tableau as K1, cycleword
> ABSCISSA (period 8). So "eight" was close but the mechanism was
> misidentified as plain Vigenère-style polyalphabetic rather than
> Quagmire III.

**System 3 — Transposition** ("ENDYAHR..." through "TVDOHW?"): "Often, the
message is arranged into a matrix, say, reading left to right; then, the
message is output reading down the columns. Perhaps a matrix system in which
the length of the columns are multiples of eleven or thirteen has been used
for this section of the message."

> **Note:** K3 is a double columnar transposition, widths 24 and 8 (not
> 11 or 13). Another pre-solve miss.

**System 4 — One-Time-Pad** ("OBKRUO..." to the end): "Essentially, every
character in the original message is encrypted using its own unique
alphabet. This is a very secure cryptographic system, because if the
alphabets used are selected at random, there is no pattern to follow for
anyone trying to break the code."

> **Note:** This is the claim currently under live investigation via
> the keystream-review track. It is *NOT* confirmed by anything
> Sanborn or Scheidt has said publicly. The CIA-memo author in 1996
> was extrapolating from (a) the observed absence of polyalphabetic
> structure in K4 and (b) the prior belief, evidently common inside
> CIA PA, that OTP was the "correct" endgame for a high-security
> cipher. The three other system diagnoses in this same memo were
> wrong in specifics. Weight accordingly.

"The other half of the sculpture may provide a clue as to which alphabets
are used, however. It is an arrangement of the alphabet, known as a Vigenere
Square, in which each successive row is shifted one place to the left (In
this case, some of the letters are shifted in position to spell the word
KRYPTOS), with reference alphabets along the top, bottom, and side."

### Morse code inventory

"You may have noted the dots and dashes on the metal sheets between the
granite slabs in front of the NHB (New Headquarters Building?) entrance;
this is Morse Code, and there are five phrases:

- DIGE TAL INTERPRETATU
- T IS YOUR POSITION
- VIRTUALLY INVISIBLE
- SHADOW FORCES
- LUCID MEMORY

Also to be found are the letter combinations SOS and RQ."

> **Note:** This inventory matches the canonical Morse phrases
> recorded in the community, subject to whitespace/spelling drift.
> Compare to `docs/anomaly_registry.md` before citing.

### K2 ciphertext in the memo

The memo included its own transcription of the full sculpture text (K1+K2+K3+K4).
The K2 section in that transcription differs in a handful of characters from
the modern canonical transcription (e.g. `PFXHQRLG` in the memo vs.
`PFXHORGL` in the modern canonical). These are known pre-correction
transcription errors — the K2 PT at rows with `Q` vs `O`, `L` vs `LG` is
affected. When citing the CIA memo text directly, ALWAYS also cite the
modern canonical transcription for the same region.

---

## How to cite this memo in this project

- In text: "CIA Public Affairs handout, c. December 1996, Tier-3 hearsay".
- Classification per CLAUDE.md truth taxonomy: `[PUBLIC FACT]` that the
  memo exists and says what it says. **Not** `[PUBLIC FACT]` that K4
  uses OTP — the memo's cipher-system claims are pre-solve speculation
  that was wrong on 3 of 4 panels it tried to diagnose.
- When a hypothesis rests on "the CIA said K4 is OTP," cite this file
  and note the three documented misdiagnoses above.

## Source file

Full verbatim transcription mirror lives at
`external/doranchak-kryptos/cia-art-kryptos.txt` if/when that repo is
vendored. Until then, the transcription was read from
`/tmp/external_repos/kryptos/info-and-articles/cia-art-kryptos.txt` on
2026-04-21; this Markdown file is the durable copy.
