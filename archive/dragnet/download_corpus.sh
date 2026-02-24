#!/bin/bash
# Download a large running-key corpus for DRAGNET Phase 1
# Focus on pre-1990 English texts that Sanborn might have used
#
# Usage: bash scripts/download_corpus.sh
# Files go to: corpus/  (gitignored)

set -euo pipefail
CORPUS_DIR="$(dirname "$0")/../corpus"
mkdir -p "$CORPUS_DIR"
cd "$CORPUS_DIR"

echo "=== DRAGNET Corpus Downloader ==="
echo "Target directory: $(pwd)"
echo ""

# ── Project Gutenberg top texts (pre-1990, English) ─────────────────
# These are the most commonly referenced English texts.
# Sanborn was an artist interested in espionage, archaeology, ancient history.

declare -A BOOKS=(
    # Spy/Intelligence themed
    ["pg35"]=35       # H.G. Wells - The Time Machine
    ["pg11"]=11       # Alice in Wonderland
    ["pg1661"]=1661   # Sherlock Holmes
    ["pg98"]=98       # A Tale of Two Cities (London/Paris — Cold War resonance)
    ["pg1342"]=1342   # Pride and Prejudice
    ["pg84"]=84       # Frankenstein
    ["pg46"]=46       # A Christmas Carol
    ["pg2701"]=2701   # Moby Dick
    ["pg74"]=74       # Tom Sawyer
    ["pg76"]=76       # Huckleberry Finn
    ["pg1232"]=1232   # The Prince (Machiavelli)
    ["pg2600"]=2600   # War and Peace
    ["pg1260"]=1260   # Jane Eyre
    ["pg174"]=174     # Picture of Dorian Gray
    ["pg345"]=345     # Dracula
    ["pg5200"]=5200   # Metamorphosis (Kafka)
    ["pg219"]=219     # Heart of Darkness
    ["pg1080"]=1080   # A Modest Proposal
    ["pg244"]=244     # A Study in Scarlet (first Holmes)
    ["pg2852"]=2852   # The Hound of the Baskervilles

    # Archaeology / Ancient history (Carter, Egypt — K3 connection)
    ["pg86"]=86       # The Egyptian Book of the Dead (Budge)
    ["pg14400"]=14400 # The Tomb of Tutankhamun (Carter, Vol 1)
    ["pg17321"]=17321 # The Tomb of Tutankhamun (Carter, Vol 2)
    ["pg694"]=694     # Herodotus - The Histories

    # Cold War / Berlin / Espionage era
    ["pg1400"]=1400   # Great Expectations
    ["pg768"]=768     # Wuthering Heights
    ["pg158"]=158     # Emma
    ["pg161"]=161     # Sense and Sensibility
    ["pg16328"]=16328 # Beowulf
    ["pg4300"]=4300   # Ulysses (Joyce)

    # Cryptography / Codes / Mathematics
    ["pg28233"]=28233 # The Gold Bug (Poe — famous cipher story!)
    ["pg2147"]=2147   # Les Misérables
    ["pg1952"]=1952   # The Yellow Wallpaper
    ["pg43"]=43       # Jekyll and Hyde
    ["pg514"]=514     # Little Women

    # Shakespeare (Sanborn is known to reference literary works)
    ["pg1524"]=1524   # Hamlet
    ["pg1533"]=1533   # Macbeth
    ["pg1513"]=1513   # Romeo and Juliet
    ["pg1532"]=1532   # King Lear
    ["pg1519"]=1519   # The Tempest

    # Philosophy / Reference
    ["pg1497"]=1497   # Republic (Plato)
    ["pg10"]=10       # Bible (KJV)
    ["pg8700"]=8700   # Quran (English)
    ["pg7370"]=7370   # The Art of War (Sun Tzu)
    ["pg2680"]=2680   # Meditations (Marcus Aurelius)
)

echo "Downloading ${#BOOKS[@]} Project Gutenberg texts..."
DOWNLOADED=0
FAILED=0

for name in "${!BOOKS[@]}"; do
    id="${BOOKS[$name]}"
    outfile="${name}_${id}.txt"
    if [ -f "$outfile" ]; then
        echo "  [skip] $outfile (already exists)"
        ((DOWNLOADED++))
        continue
    fi

    # Try mirror URL format
    url="https://www.gutenberg.org/cache/epub/${id}/pg${id}.txt"
    if curl -sL --fail --max-time 30 "$url" -o "$outfile" 2>/dev/null; then
        size=$(wc -c < "$outfile")
        echo "  [ok]   $outfile (${size} bytes)"
        ((DOWNLOADED++))
    else
        # Try alternate format
        url2="https://www.gutenberg.org/files/${id}/${id}-0.txt"
        if curl -sL --fail --max-time 30 "$url2" -o "$outfile" 2>/dev/null; then
            size=$(wc -c < "$outfile")
            echo "  [ok]   $outfile (${size} bytes)"
            ((DOWNLOADED++))
        else
            echo "  [FAIL] $outfile (could not download PG #${id})"
            rm -f "$outfile"
            ((FAILED++))
        fi
    fi

    # Be polite to Gutenberg servers
    sleep 1
done

echo ""
echo "=== Gutenberg download complete: $DOWNLOADED ok, $FAILED failed ==="
echo ""

# ── CIA / Intelligence documents from public sources ────────────────
echo "Downloading public intelligence/historical documents..."

# CIA World Factbook entry for Germany (Berlin connection)
if [ ! -f "cia_factbook_germany.txt" ]; then
    curl -sL --fail --max-time 30 \
        "https://www.cia.gov/the-world-factbook/countries/germany/" \
        -o "cia_factbook_germany.html" 2>/dev/null && \
        # Strip HTML tags for plain text
        sed 's/<[^>]*>//g' cia_factbook_germany.html > cia_factbook_germany.txt && \
        rm -f cia_factbook_germany.html && \
        echo "  [ok]   cia_factbook_germany.txt" || \
        echo "  [skip] cia_factbook_germany.txt (download failed)"
fi

echo ""

# ── Summary ─────────────────────────────────────────────────────────
TOTAL_FILES=$(ls -1 *.txt 2>/dev/null | wc -l)
TOTAL_SIZE=$(du -sh . 2>/dev/null | cut -f1)

echo "=== CORPUS READY ==="
echo "Files: $TOTAL_FILES"
echo "Total size: $TOTAL_SIZE"
echo "Location: $(pwd)"
echo ""
echo "To run DRAGNET with this corpus:"
echo "  PYTHONPATH=src python3 -u scripts/dragnet.py --phase all --workers 16 2>&1 | tee results/dragnet_output.log"
