# Known K-sections (for reference verification)

Used to verify the independent reference can reproduce K1, K2, K3. If
the reference fails, the reference is wrong — not the K-section data.

## K1 — Keyed Vigenère, key = PALIMPSEST

- Ciphertext: `EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD`
  (63 chars; carved with line breaks but treated as a single string).
- Plaintext: `BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION`
- Note misspelling: `IQLUSION` (intentional).
- Method: Vigenère using the Kryptos tableau (rows and columns both keyed
  on `KRYPTOS`), key = `PALIMPSEST`.

## K2 — Keyed Vigenère, key = ABSCISSA

- Ciphertext: `VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH?DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ`
  (Sanborn-public; question mark is the misprint where K3 begins). Treat
  segments only up to the carved length.
- Plaintext (post-2006 errata): `IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE? THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS? THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION? ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST X LAYER TWO`
- Misspellings: `UNDERGRUUND` (intentional), `DESPARATLY` not in K2.
- Method: Vigenère using the Kryptos tableau, key = `ABSCISSA`.

## K3 — Transposition

- Ciphertext: 336 characters; located after K2's question mark in the
  carved string (post-K1+K2 portion of the sculpture).
- Plaintext (Howard Carter / Tutankhamun, capped with "CAN YOU SEE
  ANYTHING Q"): `SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q`
- Misspelling: `DESPARATLY` (intentional).
- Method: keyed columnar / route transposition (community-documented;
  exact route is publicly known but reproducing it here is a fairness
  check on the reference's transposition primitives).

## K4

- Public; this whole project exists to solve it. Not a "known section"
  for verification purposes.
